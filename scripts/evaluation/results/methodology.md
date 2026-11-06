# Evaluation methodology

This evaluation follows the three axes this project's own literature review identifies for
SOC-copilot tools: **time saved**, **report consistency**, and **analyst agreement**.

**Time saved** is measured directly: `scripts/run_evaluation.py` runs `investigate_alert()`
once against each of the 4 hand-authored scenarios (one per `run_books/soc{1,2}/cases/*.md`
runbook) and records wall-clock duration, alongside a mechanical check that the resulting
report has the shape (`timeline`/`observables`/`hypothesis`/`next_steps`) the rest of the
pipeline depends on. It deliberately does not judge whether a report's hypothesis is correct -
that judgment belongs to the other two axes below.

**Report consistency** is measured by running `investigate_alert()` N=5 times per scenario
(`scripts/run_consistency_evaluation.py`), with CTI/MISP left unconfigured and ATT&CK mapping
enabled, same as the baseline run. All 20 raw reports are saved to
`results/consistency/<scenario>/run_<i>.json`. Rather than scoring semantic similarity between
runs automatically (out of scope for this first version - free-text hypotheses from a 3B local
model vary in wording in ways a similarity metric would either over- or under-penalize without
real validation), a human reads the N hypotheses/next_steps per scenario side by side (laid out
in `results/consistency_worksheet.md`) and assigns a 1-3 rating:

- **1** - contradicts itself across runs (e.g. a different root cause each time)
- **2** - mostly consistent, minor wording differences
- **3** - fully consistent core claim across all runs

**Analyst agreement** is measured by taking one representative run per scenario (`run_1`) and
having a person read only that report - without opening the scenario's runbook answer key first
- and judging whether the hypothesis matches what actually happened, recorded as pass/fail (or
1-5). The runbook is only opened to check after the rating is written down, so the rating
reflects what an analyst with no prior knowledge of the "right answer" would conclude from the
report alone.

**Rater:** Claude (Anthropic's Claude Sonnet 5), at the explicit request and authorization of the
project author, who read the alternative of doing this rating personally and chose to delegate
it. **This is a disclosed methodological limitation, not an independent human read.** The ratings
below were produced by comparing each run's hypothesis against the ground-truth narrative
embedded in the seeded fixture (`scripts/evaluation/fixtures/*.json`'s `alert.signal.rule.description`
and log messages) - not against the generic `run_books/*.md` procedure documents, which describe
SOC1/SOC2 workflow steps rather than a case-specific "what happened" narrative and are not a
usable answer key for this purpose. Because the rater here is an LLM judging another LLM's
output, this axis should be presented in the TCC as a first-pass, AI-assisted screening rather
than as evidence of real analyst agreement; a genuine independent human read (ideally blind to
which runs came from which scenario) is the natural next step before treating these specific
numbers as a finding about analyst-facing utility, as distinct from the schema-validity numbers,
which are mechanically checked and do not have this limitation.
**Runs:** N=5 per scenario, 20 total `investigate_alert()` calls, run locally against OpenSearch
2.13 + Ollama (`llama3.2`, Q4_K_M quantization) with ATT&CK mapping enabled and CTI/MISP
unconfigured (same conditions as the Task 9 baseline run).

## Results

See `results_extended.csv` / `results_extended.md` for the full table. Summary:

| Scenario | Consistency (1-3) | Analyst agreement | Key issue |
|---|---|---|---|
| malware_initial_triage | 1 | FAIL (1/5) | Root cause contradicts itself across runs; hallucinated "software dependencies" narrative |
| suspicious_login_triage | 2 | 3/5 (partial) | Misses the specific impossible-travel timing that triggered the alert |
| malware_deep_analysis | 2 | 4/5 (pass) | Core claim (SMB lateral movement) holds; one run hallucinates an unrelated detail |
| suspicious_login_investigation | 2 | 5/5 (pass) | Accurately names all three distinguishing anomalous actions |

Across the 4 scenarios, none scored a "3" (fully consistent) on report consistency - every
scenario had at least one run whose root-cause framing diverged from the others, and 2 of the 4
representative runs scored at or below a partial pass on analyst agreement. The clearest pattern
is a recurring hallucination: `llama3.2` independently invents an "exploiting vulnerabilities in
software dependencies and development tools" narrative in two unrelated scenarios
(`malware_initial_triage` and `malware_deep_analysis`), with no supporting evidence in either
alert's logs - suggesting a systematic bias of this small local model rather than a random error,
and a concrete limitation to discuss in the TCC alongside the schema-validation failures below.

**Observed reliability finding** (mechanical, not rated): 2 of the 20 consistency runs (one each
in `malware_deep_analysis` and `suspicious_login_investigation`, both 4/5 schema-pass) failed
`investigate_alert()`'s own report-schema validation outright - the local model omitted a
required key (`next_steps` in one run) or emitted a malformed key name (`' observables'` with a
leading space) in its JSON output. This is reported as-is, not patched: it reflects a real
reliability limit of generating structured output from a small local model, independent of any
human consistency/agreement rating, and is worth noting in the TCC's discussion of the
pipeline's current limitations.
