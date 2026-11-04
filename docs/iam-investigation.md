# Investigate a sensitive IAM grant

GSL020 follows an observed sensitive role grant through a subsequent successful Cloud Storage operation by the beneficiary. It links the two audit entries in a case and exposes the reason for the alert in the dashboard. The example uses synthetic identities, object names and audit records. It makes no cloud API calls.

```powershell
uv run --no-sync secops-lab --db var/iam.sqlite iam-demo --out var/iam-demo
uv run --no-sync secops-lab --db var/iam.sqlite dashboard --port 8766
```

Open [the IAM dashboard](http://127.0.0.1:8766/) and follow the beneficiary under **IAM grant investigations**. The CLI also prints the case path and exports **investigation.md**, **investigation.json**, **evaluation.json** and the input **events.jsonl** under the output directory. To score the evaluation corpus independently, run **uv run --no-sync secops-lab --db var/iam.sqlite evaluate-iam**.

The suspicious example grants **roles/storage.objectAdmin** on project **gsl-iam-demo** to a named external user. Four minutes later the same user reads an object in **finance-archive**. The case links the grant actor, member, role, scope, permission, object and timestamps. The routine example grants **roles/storage.objectViewer** to a deployment service account, which reads a build artifact. The generic GSL001 rule records both IAM changes. GSL020 creates one investigation for the sensitive grant with observed use.

## What the rule checks

- A successful **SetIamPolicy** contains an observed **ADD** binding under **serviceData.policyDelta.bindingDeltas** or **metadata.policyDelta.bindingDeltas**. Requested policies and undocumented fields do not establish a granted binding. The parser preserves the action, member, role and condition together. [IAM allow policy history](https://docs.cloud.google.com/iam/docs/review-iam-policy-history)
- The binding grants a monitored role unconditionally to a named user or service account. The role list covers Owner, Editor, Storage Admin and Storage Object Admin. Grant scopes are project IDs and exact Cloud Storage buckets. Group, federated principal, project-number aliases, custom roles and CEL conditions need separate coverage.
- The beneficiary completes a monitored Storage get, list or delete operation strictly after the grant and within 30 minutes. The audit entry must record the matching permission as granted and identify a resource within the observed project or bucket. The sequence indicates observed activity after a grant. Existing bindings can independently authorize the activity. [Cloud Storage audit logs](https://docs.cloud.google.com/storage/docs/audit-logging)
- A matching revocation cancels the candidate. If it arrives after an alert was created and changes the replay result, the case keeps earlier evidence and analyst notes, shows the revocation and marks the correlation **Needs review**.

GSL020 runs in the Python evaluator. Native GSL001 remains a separate, broader rule in the YARA-L catalog. This investigation requires event relationships and policy details beyond the existing native rule's condition.

## Evaluation

The packaged [evaluation corpus](../src/secops_lab/iam_evaluation.json) has 20 labeled synthetic scenarios separate from the demo events. Each scenario has ground truth and an expected GSL020 result. CI checks for changes to the expected results, while the report measures results against ground truth and records a dataset fingerprint.

| Rule | True positives | False positives | False negatives | True negatives | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| GSL001 · IAM policy change | 7 | 10 | 1 | 2 | 41.18% | 87.50% |
| GSL020 · Sensitive grant followed by use | 6 | 1 | 2 | 11 | 85.71% | 75.00% |

The approved emergency access scenario still triggers because change approval is outside the audit evidence. Conditional access and use after the window are deliberate blind spots in this corpus. These measurements describe the synthetic sample.

Live investigation would require both IAM Admin Activity and the relevant Storage Data Access logs. The default Terraform sink routes selected Admin Activity events. Keep the demo local to avoid provisioning or additional audit logging costs. [Cloud runbook](cloud.md)
