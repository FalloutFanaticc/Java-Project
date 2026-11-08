# Manual test plan

Use a Java 17+ runtime. Run each case from the repository root and inspect both console output and report output.

| Case | Input/scenario | Expected result |
|---|---|---|
| Baseline | `data/sample_events.csv` | Jordan receives a HIGH repeated-failure alert; account lockout is separately reported; events are chronological. Alex's successful login alone does not alert. |
| Below threshold | One or two failures for an account inside five minutes | No repeated-failure alert. |
| Time boundary | Three failures spanning no more than five minutes, then repeat with more than five minutes | First set alerts; second set does not. |
| Bad timestamp/columns | Add a malformed row or invalid timestamp | Row is skipped, warning includes its line number, analysis continues. |
| Missing input | Use a nonexistent CSV path | Clear file error and nonzero exit. |
| Filter | `--user jordan` or `--type LOGIN_FAILURE` | Event listing honors the filter; alerts remain prioritized and severity summary reflects selected severity only. |
| Severity filter | `--min-severity HIGH` | Only HIGH and CRITICAL alerts appear. |
| Empty log | Header only | Zero events and alerts; valid report is saved. |

Known limitation: rules are deliberately simple and use username plus event timestamps. They do not establish whether activity is malicious, correlate changing IPs, or account for time zones. Risk values prioritize review and are not probabilities.
