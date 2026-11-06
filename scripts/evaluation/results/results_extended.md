# Extended evaluation results (time, schema, consistency, analyst agreement)

Consistency and analyst agreement ratings below were assigned by Claude (AI-assisted), at the
user's explicit request, after reading the N=5 raw runs per scenario in `consistency_worksheet.md`
against each scenario's ground-truth narrative (the seeded alert's `signal.rule.description` and
log messages in `scripts/evaluation/fixtures/*.json`). This is **not** an independent human
read - see the disclosure in `methodology.md` for what that means for how these two columns
should be cited.

| Scenario | Duration (s) | Schema Valid | Schema pass rate (N=5 consistency runs) | Consistency rating (1-3) | Analyst agreement | Notes |
|---|---|---|---|---|---|---|
| malware_initial_triage | 55.397 | True | 5/5 | 1 | FAIL (1/5) | Root cause contradicts itself across runs; representative run hallucinates an unsupported "software dependencies" narrative |
| suspicious_login_triage | 41.473 | True | 5/5 | 2 | 3/5 (partial) | Most runs reference the Chicago/Lagos VPN movement, but the representative run omits the specific impossible-travel timing |
| malware_deep_analysis | 37.658 | True | 4/5 | 2 | 4/5 (pass) | Core claim (SMB lateral movement) consistent; one run adds the same unsupported "software dependencies" hallucination |
| suspicious_login_investigation | 43.747 | True | 4/5 | 2 | 5/5 (pass) | Representative run accurately names all three distinguishing anomalous actions |
