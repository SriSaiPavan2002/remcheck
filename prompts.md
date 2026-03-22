# prompts.md - AI Integration (Option 2: Result Analyzer)

## Prompt used (sent to gpt-4o-mini)
"""
You are a senior security remediation analyst.
Analyze these results for {finding_type}:

Summary: {summary}
Tests: {test_results}

Is the fix COMPLETE, PARTIAL, or BYPASSED? 
Reply ONLY with valid JSON: {"advisory_verdict": "complete|partial|bypassed", "explanation": "..."}
"""

## Example of raw LLM output
{
  "advisory_verdict": "complete",
  "explanation": "All 8 tests passed consistently with no anomalies detected. No bypass possible. This is advisory only and does not override the deterministic verdict."
}

## Validation logic (between LLM and engine)
- Always attempt `json.loads()` on the response.
- If parsing fails or keys are missing → store raw text in `llm_analysis` and set `advisory_verdict: "unknown"`.
- **LLM output is advisory only** — it never changes the deterministic verdict from test results.

## Example where I caught and corrected a bad LLM output
During testing, the LLM once returned "bypassed" because one test had a temporary network timeout (status 404).  
I logged the raw output but **ignored it** and kept the verdict as `REMEDIATION_VERIFIED` because all deterministic checks passed.  
This demonstrates the required safety guard: LLM never overrides the engine.
