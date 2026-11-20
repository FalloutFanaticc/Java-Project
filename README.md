
# Cyber Defense Analyzer

A defensive Java console application for analyzing fictional security event logs. It reads CSV, validates rows, detects a small set of documented patterns, prioritizes alerts, and saves a text report. It operates only on supplied local data; sample usernames and documentation-only IP addresses are synthetic.

## Requirements and run

Java 17 or newer is required (records and modern stream APIs are used). No external libraries or build tool are needed.

```sh
mkdir -p out
javac -d out src/main/java/cyberdefense/*.java
java -cp out cyberdefense.Main
```

To open the optional desktop GUI instead, run:

```sh
java -cp out cyberdefense.CyberDefenseGui
```

In the window, choose a CSV file (or keep the sample path), click **Analyze logs**, then click **Save report…** to export the displayed results.

By default the program reads `data/sample_events.csv` and writes `reports/security_report.txt`. Supply input and output paths as the first two arguments:

```sh
java -cp out cyberdefense.Main data/sample_events.csv reports/review.txt --user jordan --min-severity HIGH
```

Options: `--type EVENT_TYPE`, `--user USERNAME`, and `--min-severity LOW|MEDIUM|HIGH|CRITICAL`. Filters affect the displayed event list and/or alert queue as applicable.

## CSV format

Header: `timestamp,username,event_type,source_ip`. Timestamp uses ISO local date-time, such as `2026-03-10T09:02:00`. Quoted CSV fields and doubled quotes are supported. Empty or malformed rows are skipped and recorded as warnings. Missing files produce a clear error.

## Detection rules

| Rule | Severity | Score | Rationale and response |
|---|---:|---:|---|
| Three or more `LOGIN_FAILURE` events for one username within a five-minute window | HIGH | 80 | Repeated authentication failures can indicate guessing or a user having trouble signing in. Verify through an approved channel and review source activity. |
| `ACCOUNT_LOCKED` event | HIGH | 75 | Lockout warrants review of preceding failures and confirmation it was expected. |
| `FILE_ACCESS_DENIED` event | MEDIUM | 35 | A denied access may be benign or merit access review; it is not alone proof of compromise. |
| `UNUSUAL_NETWORK_ACTIVITY` event | MEDIUM | 40 | The supplied event classification calls for contextual review. |

Ordinary successful logins and isolated failures do not generate alerts. A maximum of one repeated-failure alert is emitted per username. Scores are rule-based prioritization aids, not probabilities.

## Design

- `LogEvent`: immutable parsed event.
- `LogReader`: file ingestion, CSV parsing, validation, malformed-row collection.
- `ThreatAnalyzer`: rule evaluation, grouping, chronological sorting, severity and score assignment.
- `SecurityReport`: filtering, summary counts, prioritized report formatting, file export.
- `Main`: command-line coordination and error handling.
<img width="3095" height="5247" alt="diagram" src="https://github.com/user-attachments/assets/f1a573b5-8a63-4f11-8622-50ac4c00e005" />

## Manual verification and limitations

See [docs/manual-test-plan.md](docs/manual-test-plan.md) for threshold, malformed-input, filtering, and missing-file scenarios. The tool uses simple username-based rules; it does not correlate identities across accounts or IPs, infer intent, or support timezone offsets. Results require human review.

## Safety and classroom use

Use synthetic logs, fictional identities, and documentation-only IPs. This project performs local defensive log analysis; it does not scan, connect to, or test real systems. 
