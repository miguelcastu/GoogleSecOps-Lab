# Licensed Google SecOps integration

The regional Chronicle adapter exposes raw log and UDM event import, rule text verification, rule creation and deployment, rule detection retrieval and case reads. Each API call is tested with a mock transport. Native compilation, historical replay, live detections and case reads remain pending a licensed tenant.

## Configure a tenant

1. Obtain a licensed SecOps instance and record its Google Cloud project, Chronicle region and instance ID. Verify the regional endpoint and enable **chronicle.googleapis.com** on the associated project.
2. Use Application Default Credentials. For CI, configure a Workload Identity Federation pool and a GitHub OIDC provider. Restrict trust to the exact repository and reviewed main ref or protected environment, and grant the federated principal **roles/iam.workloadIdentityUser** on a dedicated service account. Do not use a long-lived key.
3. Grant only the Chronicle permissions needed for the operation. Verification uses **chronicle.rules.verifyRuleText**. Creation and activation use **chronicle.rules.create** and **chronicle.ruleDeployments.update**. Import needs **chronicle.logs.import** or **chronicle.events.import** and log type lookup uses **chronicle.logTypes.list**. Give investigators **chronicle.cases.list**, **chronicle.cases.get** and the case detections permission if required. Rule-level detection search uses the documented **legacies.legacySearchDetections** migration method on the regional Chronicle API. Confirm exact permissions and data access scope in the method reference for the tenant. [Chronicle IAM reference](https://docs.cloud.google.com/chronicle/docs/reference/feature-rbac-permissions-roles) · [Migration mapping for detections](https://docs.cloud.google.com/chronicle/docs/reference/parity/rule/list-detections) · [Chronicle REST API](https://docs.cloud.google.com/chronicle/docs/reference/rest)

Set **GSL_ENABLE_CHRONICLE=1** and **GSL_CHRONICLE_PROJECT**, **GSL_CHRONICLE_LOCATION**, **GSL_CHRONICLE_INSTANCE** in the process environment. Set **GSL_CHRONICLE_WRITE=1** only for an authorized import, creation or deployment. ADC and the switches are read only when explicitly constructing a Chronicle client.

```sh
uv sync --locked --python 3.12 --extra cloud
uv run --no-sync python -m secops_lab.chronicle verify detections/yara_l/GSL001_iam_policy_change.yaral
```

For raw import use **Chronicle.import_raw(log_type, [(event_timestamp, record_text)])** with a log type from your tenant. For UDM use **Chronicle.import_udm([event.udm])**. Verify a small, authorized, current-time fixture with the platform before increasing volume. The synthetic dataset has fixed historic timestamps for reproducibility. Rebase time on a copy if the tenant's import retention window requires it. Use **Chronicle.create_rule** to verify before creating a rule. Preserve the returned resource ID, review the tenant deployment settings, then use **Chronicle.deploy_rule(rule_id, enabled=True)** only when explicitly authorized. Read rule detections and cases with **detections**, **cases**, **case** and **case_detections**. Follow returned page tokens for paginated calls. [Chronicle ingestion methods and payloads](https://docs.cloud.google.com/chronicle/docs/reference/ingestion-methods) · [Native rule verification](https://docs.cloud.google.com/chronicle/docs/reference/rest/v1/projects.locations.instances/verifyRuleText)

## GitHub staging

Configure the protected **chronicle** GitHub environment, the **CHRONICLE_PROJECT**, **CHRONICLE_LOCATION**, **CHRONICLE_INSTANCE**, **CHRONICLE_WIF_PROVIDER** and **CHRONICLE_SERVICE_ACCOUNT** variables and required reviewers before setting the repository variable **ENABLE_CHRONICLE_RULE_WORKFLOW=true**. The manual workflow accepts one catalog ID and either verifies or creates its rule. Enable live deployment only after a tenant-side test with the actual native parser or a verified UDM feed. [GitHub OIDC with Google Cloud](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-google-cloud-platform)
