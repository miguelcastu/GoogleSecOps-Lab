# Verification report

Executed with CPython 3.12.14 on Windows and Terraform 1.14.8 with the locked Google provider. Local execution used synthetic telemetry.

| Component | Status | Evidence |
| --- | --- | --- |
| Local package, ingestion and normalization | IMPLEMENTED · TESTED | Locked installation and 13 source fixtures. Rejection paths cover invalid JSON, oversized records, wrong types, missing fields, non-finite values and sensitive keys. |
| Replay and alerting | IMPLEMENTED · TESTED | 86 accepted events, 22 local alerts, 21 cases and 39/39 scenario checks. At the scenario/rule pair level, 21 true positives, 1 deliberate false positive and 0 false negatives produced 95.45% fixture precision. |
| Case management and dashboard | IMPLEMENTED · TESTED | Pytest starts the loopback server, opens the overview, case and health routes, checks escaping of analyst notes and verifies the 404 path. The browser origin gate prevented capture of a dashboard screenshot in this session. |
| Rule sources | IMPLEMENTED · STRUCTURAL CHECKED | 19 generated YARA-L sources checked for drift and rule sections. Native Google SecOps compiler and native detections are **PENDING**. |
| Python QA | TESTED | 52 passed, 0 failed. Ruff lint and formatting, mypy and deterministic content checks passed. |
| Terraform | IMPLEMENTED · TESTED WITH MOCK PROVIDER | Format and configuration validation, plus 3 passing mock plans for defaults, explicit opt-in and invalid project input. |
| Pub/Sub and Chronicle transports | IMPLEMENTED · MOCKED | Tests verify commit-before-ack and rollback, duplicate delivery, ingestion payloads, write gates, rule verification, deployment and investigation paths. |
| Real Google Cloud deployment and event flow | BLOCKED | ADC unavailable and no approved lab project or billing authorization was provided. No GCP resources were provisioned and no live events were collected. |
| Google SecOps tenant integration | BLOCKED | A licensed instance and scoped authentication are required for native compilation, imports, deployment and investigations. |
| Cloud resource spend | €0 incurred by this work | Cloud usage estimates and assumptions appear in the [deployment runbook](cloud.md). |

See the [README](../README.md) for commands. Use **secops-lab demo** to regenerate the SQLite data and JSON and Markdown reports. The test report is also produced by the repository CI when GitHub Actions runs.

## IAM investigation

The local IAM demo ingests four synthetic audit entries and records three alerts, including one GSL020 investigation. The independent corpus checks 20 expected outcomes and compares false positives, false negatives, precision and recall with GSL001. Automated coverage includes a lost Pub/Sub acknowledgment, duplicate delivery, late activity, a late revocation, and case continuity after a threshold crossing changes. [Run the investigation](iam-investigation.md)
