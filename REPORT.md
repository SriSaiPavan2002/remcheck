# REPORT.md

## What works
- Full support for sql_injection + ssrf_cloud_metadata (Part B)
- Tamper-evident evidence report with SHA-256 (Part B)
- 3-run consistency engine for flaky tests (addresses question 4)
- AI Result Analyzer (Option 2) using OpenAI gpt-4o-mini (advisory only)
- Beautiful CLI with colors, --quiet, --verbose, correct exit codes (Part D)
- Architecture document + diagram (Part A)

## What is missing / would do with more time
- Did not implement Bonus A (JWT) or Bonus C (pipeline) – focused on core + AI
- SSRF has 4 payloads instead of 8 (easy to extend)
- No real OOB callback server (mocked via content check)
- Would add Docker + GitHub Actions for Bonus C

## Part E - Extension Design

**Question 1 – Scaling to 500 findings per night**  
Redesign as a distributed worker system:  
- Queue: RabbitMQ or Redis + Celery  
- Workers: 20× Kubernetes pods (or EC2) running remcheck in parallel  
- Orchestrator: nightly cron/Lambda that reads findings from S3/DB and enqueues them  
- Aggregator: After all workers finish, a final job merges all JSON reports into one HTML/PDF morning report (summary stats + links to failed evidence).  
- Evidence stored in S3 with immutable versioning. Total runtime < 30 min for 500 findings.

**Question 2 – Supporting GraphQL introspection**  
Add ONLY:  
- 