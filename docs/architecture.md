# Architecture and operational controls

The main data unit is an event envelope. Source and provenance stay outside UDM. The envelope holds an event ID, normalized UTC timestamp, accepted raw record, adapter projection and protobuf JSON-style UDM record. A source-scoped identity plus time and provenance drives deduplication. When a source lacks an identifier, the raw document provides the fallback. Raw and parsed data stay in the local database.

JSONL intake limits each invocation to 5,000 records and each record to 64 KiB. Structural checks reject invalid source records and common credential fields before storage. Rejection rows retain a source, filename, record number and reason. Inspect and redact approved inputs before ingesting real exports. The filter catches common secrets and cannot classify all personal data or free-text credentials. Use a separate protected database for real input and keep database files and reports outside Git.

The replay evaluator sorts accepted records by UTC event time and stable ID. Correlation uses trailing windows and requires a strictly later event for ordered rules. Synthetic and real streams are isolated for correlation. The generic evaluator applies a 15-minute hold-down per rule, origin and correlation key. If a late event moves a generic threshold crossing, the replay extends the existing alert when the rule, subject and evidence overlap. Disjoint evidence can open a new alert. IAM findings key on the grant event and binding, so earlier observed use can extend the same case. Later contradictory evidence changes the assessment to **Needs review** while preserving the original evidence and notes. The local limit is 25,000 stored events per replay. Native YARA-L uses the engine's window scheduling and compilation semantics. [IAM investigation](iam-investigation.md)

SQLite serializes replay and case edits. A Pub/Sub collector commits accepted events and rejection metadata before acknowledging the batch. A retry after a failed acknowledgment deduplicates accepted events. Retry attempts still count in ingestion metrics. The local dashboard opens SQLite read-only and binds to IPv4 loopback. It reports recorded pipeline metrics, case evidence and fixture outcomes. Stop it with Ctrl+C. To reset a disposable run, stop the dashboard and move the demo database and its SQLite sidecars out of the configured path, then rerun the demo.

Cases group alerts by playbook, subject, UTC date and telemetry provenance. Confidence uses the evidence count and number of contributing sources. Risk combines rule severity with confidence. Six playbooks give analyst steps in dry-run mode. IP and domain context is local, and reserved test addresses are explicitly labeled as fixtures.

## Maintenance

Edit the rule catalog and scenario generator together. Regenerate YARA-L source, docs and fixtures with **python scripts/sync_content.py**. Run **pytest** and review the fixture report before committing. Tune detections against representative sanitized data and audit policy diffs before upgrading a heuristic to an incident signal.

Useful future work includes per-source watermarks and retention partitions for larger datasets, and comparison of local threshold behavior with the licensed engine on the same sanitized fixture set.
