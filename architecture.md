# Part A - System Architecture Document

## 1. Routing logic
The engine uses a clean registry pattern in `get_verifier(finding_type)`.  
It inspects the `"type"` field in the input JSON and returns the matching strategy class (`SQLInjectionVerifier` or `SSRFCloudMetadataVerifier`).  
To add any new finding type, create a new subclass and register it — **no changes needed to the core engine, CLI, report builder, or AI layer**.

## 2. Evidence model
The output strictly follows the challenge JSON schema.  
A SHA-256 hash is computed over the entire report (excluding the `report_hash` field itself) and embedded.  
This makes every report **tamper-evident** and fully auditable.  
All raw test data, timestamps, consistency runs, and LLM advisory are preserved for chain-of-custody.

## 3. Anomaly detection
**Common signals** (applied to every finding):  
- Behavioural: status_code deviation from baseline  
- Temporal: response_time > 2× baseline p95  
- Content: response_hash mismatch  

**Finding-specific signals**:  
- SQL Injection: database error keywords  
- SSRF Cloud Metadata: AWS/EC2 metadata strings  

Handled in each Verifier subclass for clean separation.

## 4. Inconsistent results
Any test showing anomalies is automatically re-run up to 3 times.  
If verdicts differ across runs → final result is `INCONCLUSIVE` with flag `"inconsistent_results_across_runs"`.

## Component Diagram
![remcheck Architecture](architecture.png)

**Legend**  
Purple = Common signals  
Green = Finding-specific signals
