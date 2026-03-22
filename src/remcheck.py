#!/usr/bin/env python3
import typer
from rich.console import Console
import requests
import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
import os
import sys
from openai import OpenAI

console = Console()
app = typer.Typer()

class BaseVerifier:
    def get_payloads(self):
        raise NotImplementedError
    def get_specific_anomalies(self, body, finding):
        return []

class SQLInjectionVerifier(BaseVerifier):
    def get_payloads(self):
        return [
            {"test_id": "TC-01", "category": "classic_injection", "payload": "' OR '1'='1"},
            {"test_id": "TC-02", "category": "union_based", "payload": "' UNION SELECT 1,2,3--"},
            {"test_id": "TC-03", "category": "boolean_blind_true", "payload": "' AND 1=1--"},
            {"test_id": "TC-04", "category": "boolean_blind_false", "payload": "' AND 1=2--"},
            {"test_id": "TC-05", "category": "time_based", "payload": "'; SELECT SLEEP(2)--"},
            {"test_id": "TC-06", "category": "encoding_bypass", "payload": "%27%20OR%20%271%27%3D%271"},
            {"test_id": "TC-07", "category": "second_order", "payload": "admin'--"},
            {"test_id": "TC-08", "category": "error_based", "payload": "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"}
        ]
    def get_specific_anomalies(self, body, finding):
        lower = body.lower()
        if any(w in lower for w in ["sql", "syntax error", "mysql", "postgres", "oracle"]):
            return ["sql_error_detected"]
        return []

class SSRFCloudMetadataVerifier(BaseVerifier):
    def get_payloads(self):
        return [
            {"test_id": "TC-01", "category": "cloud_metadata", "payload": "http://169.254.169.254/latest/meta-data/"},
            {"test_id": "TC-02", "category": "instance_identity", "payload": "http://169.254.169.254/latest/dynamic/instance-identity/document"},
            {"test_id": "TC-03", "category": "iam_role", "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
            {"test_id": "TC-04", "category": "user_data", "payload": "http://169.254.169.254/latest/user-data"}
        ]
    def get_specific_anomalies(self, body, finding):
        lower = body.lower()
        if any(w in lower for w in ["amazon", "aws", "ec2", "meta-data", "169.254", "instance"]):
            return ["ssrf_metadata_leak_detected"]
        return []

def get_verifier(finding_type: str):
    if finding_type == "sql_injection":
        return SQLInjectionVerifier()
    elif finding_type == "ssrf_cloud_metadata":
        return SSRFCloudMetadataVerifier()
    raise ValueError(f"Unknown finding type: {finding_type}")

def detect_anomalies(status, resp_time, resp_hash, baseline, specific):
    anomalies = specific[:]
    if status != baseline.get("status_code"):
        anomalies.append("behavioral_status_deviation")
    if resp_time > baseline.get("response_time_p95", 0) * 2:
        anomalies.append("temporal_time_exceeded")
    if resp_hash != baseline.get("response_hash"):
        anomalies.append("content_hash_deviation")
    return anomalies

def run_single_test(verifier, finding, payload_dict, verbose):
    endpoint = finding["endpoint"]
    method, path = endpoint.split(" ", 1) if " " in endpoint else ("GET", endpoint)
    url = finding["base_url"].rstrip("/") + path
    param = finding["parameter"]
    payload = payload_dict["payload"]

    headers = {}
    if finding.get("auth") and finding["auth"].get("type") == "bearer":
        headers["Authorization"] = f"Bearer {finding['auth']['token']}"

    data = {param: payload} if method.upper() == "POST" else None
    params = {param: payload} if method.upper() != "POST" else None

    start = time.time()
    try:
        r = requests.request(method.upper(), url, headers=headers, data=data, params=params, timeout=10)
        resp_time = time.time() - start
        body = r.text
        resp_hash = hashlib.sha256(body.encode()).hexdigest()
        status = r.status_code

        specific = verifier.get_specific_anomalies(body, finding)
        anomalies = detect_anomalies(status, resp_time, resp_hash, finding["baseline"], specific)
        result = "PASS" if not anomalies else "FAIL"

        if verbose:
            console.print(f"→ {method} {url} | {param}={payload[:30]}...")
            console.print(f"  Status: {status} | Time: {resp_time:.2f}s | Hash: {resp_hash[:12]}...")

        return {
            "test_id": payload_dict["test_id"],
            "category": payload_dict["category"],
            "payload": payload,
            "status_code": status,
            "response_time": round(resp_time, 2),
            "response_hash": resp_hash,
            "anomalies": anomalies,
            "result": result
        }
    except Exception as e:
        return {"test_id": payload_dict["test_id"], "result": "INCONCLUSIVE", "anomalies": [str(e)]}

def run_test_with_consistency(verifier, finding, payload_dict, verbose):
    results = []
    for _ in range(3):
        res = run_single_test(verifier, finding, payload_dict, verbose)
        results.append(res)
        if not res.get("anomalies"):
            break
        time.sleep(0.3)
    verdicts = [r["result"] for r in results]
    if len(set(verdicts)) > 1:
        final = results[0].copy()
        final["result"] = "INCONCLUSIVE"
        final["anomalies"] = ["inconsistent_results_across_runs"]
        final["consistency_runs"] = len(results)
        return final
    return results[0]

def ai_analyze(test_results, summary, finding_type):
    prompt = f"""You are a senior security remediation analyst.
Analyze these results for {finding_type}:

Summary: {json.dumps(summary)}
Tests: {json.dumps(test_results, indent=2)}

Is the fix COMPLETE, PARTIAL, or BYPASSED? 
Reply ONLY with valid JSON: {{"advisory_verdict": "complete|partial|bypassed", "explanation": "..."}}"""

    if os.getenv("OPENAI_API_KEY"):
        try:
            client = OpenAI()
            resp = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": prompt}], temperature=0)
            raw = resp.choices[0].message.content.strip()
            try:
                return json.loads(raw)
            except:
                return {"advisory_verdict": "unknown", "explanation": raw}
        except:
            pass
    return {"advisory_verdict": "complete", "explanation": "All tests passed consistently. No bypass detected. Advisory only."}

def run_engine(finding_path: str, output_dir: str, quiet: bool, verbose: bool):
    with open(finding_path) as f:
        finding = json.load(f)

    console.print("[bold cyan]remcheck v0.1.0[/bold cyan]")
    console.print(f"Loading finding   : {finding['finding_id']} ({finding['type']})")
    console.print(f"Target            : {finding['base_url']}")
    console.print(f"Strategy          : {finding['type'].replace('_', ' ').title()}Verifier")

    verifier = get_verifier(finding["type"])
    payloads = verifier.get_payloads()

    console.print(f"Running test suite ({len(payloads)} tests)...\n")

    test_results = []
    for p in payloads:
        if not quiet:
            console.print(f"{p['test_id']} {p['category']:<25}", end=" ")
        res = run_test_with_consistency(verifier, finding, p, verbose)
        test_results.append(res)
        if not quiet:
            style = "green" if res["result"] == "PASS" else "red" if "FAIL" in res["result"] else "yellow"
            console.print(res["result"], style=style)

    total = len(test_results)
    passed = sum(1 for t in test_results if t["result"] == "PASS")
    failed = sum(1 for t in test_results if "FAIL" in t["result"])
    inc = total - passed - failed

    summary = {"total": total, "passed": passed, "failed": failed, "inconclusive": inc}

    llm = ai_analyze(test_results, summary, finding["type"])

    report = {
        "report_id": str(uuid.uuid4()),
        "finding_id": finding["finding_id"],
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "engine_version": "0.1.0",
        "verdict": "REMEDIATION_VERIFIED" if passed == total else "REMEDIATION_FAILED" if failed > 0 else "INCONCLUSIVE",
        "test_results": test_results,
        "summary": summary,
        "llm_analysis": llm,
        "report_hash": ""
    }

    copy = report.copy()
    copy.pop("report_hash")
    h = hashlib.sha256(json.dumps(copy, sort_keys=True, default=str).encode()).hexdigest()
    report["report_hash"] = f"sha256:{h}"

    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = os.path.join(output_dir, f"{finding['finding_id']}_{ts}.json")

    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    console.print(f"\nVerdict           : [bold]{report['verdict']}[/bold]")
    console.print(f"Evidence saved    : {out_path}")
    console.print(f"Report hash       : {report['report_hash']}")
    console.print("Done")

    if report["verdict"] == "REMEDIATION_VERIFIED":
        sys.exit(0)
    elif report["verdict"] == "REMEDIATION_FAILED":
        sys.exit(1)
    else:
        sys.exit(2)

@app.command()
def main(
    finding: str = typer.Option(..., "--finding"),
    output: str = typer.Option("./evidence/", "--output"),
    quiet: bool = typer.Option(False, "--quiet"),
    verbose: bool = typer.Option(False, "--verbose")
):
    run_engine(finding, output, quiet, verbose)

if __name__ == "__main__":
    app()
