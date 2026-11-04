# Google Cloud deployment and teardown

The cloud path uses Google Cloud Logging to route a narrow set of Cloud Audit Logs to Pub/Sub. It sends one pull batch at a time to the local parser and database. The provisioning path assumes a pre-existing, isolated project that you approve for this lab. Terraform keeps the project itself outside the state. Every command targets an explicit project with a **gsl-** prefix and the label **application=googlesecops-lab**.

## Billing and safety

Local mode provisions zero cloud resources. The optional cloud stack uses no servers or public endpoints. The sink starts disabled. The configuration routes selected Admin Activity operations only and leaves Data Access logging unchanged. Admin Activity logs are stored in the project **_Required** bucket. The lab adds no custom log bucket or extended retention. Pub/Sub uses a single persistence region, one-hour unacknowledged retention and a three-day inactivity expiry. The collector has no schedule, accepts at most 20 messages per invocation and uses a subscription-scoped role. Application limits bound lab-generated traffic and collection. The routing filter does not impose a hard cloud throughput cap. [Cloud Audit Logs](https://docs.cloud.google.com/logging/docs/audit) · [Logging routing](https://docs.cloud.google.com/logging/docs/routing/overview)

| Item | Estimate for a brief smoke test | Billing details |
| --- | --- | --- |
| Cloud Logging | $0 for routed Admin Activity under this design | Logging pricing exempts storage in **_Required** and lists the first 50 GiB per project per month for eligible log storage. |
| Pub/Sub Basic delivery | About 2 MiB for 100 events at 10 KiB each across publish and pull | The first 10 GiB per billing account per month is free for Message Delivery Basic. If already exhausted, 2 MiB is about $0.00008 at $40/TiB, before networking and applicable request overhead. |
| Pub/Sub storage and transfer | $0 expected for a brief same-region smoke with the default retention | Retained acknowledged messages, long backlog and eligible data transfer can add costs. Check geographic transfer pricing when pulling from outside the selected region. |
| SCC Standard | No charge if available and explicitly selected | Optional, separately managed. Review any underlying services before activation. |
| Budget | Optional project-level alert thresholds at 50% and 100% | Uses the billing account currency. A notification can be delayed and does not cap spending. |

Review usage across the billing account before any apply. Select SCC **Standard** only if the project or organization offers it and activation is approved. Check the inherited tier first. SCC and Monitoring are outside this Terraform stack. The default configuration enables neither extra log categories nor Data Access logging. [Logging pricing](https://cloud.google.com/logging/pricing) · [Pub/Sub pricing](https://cloud.google.com/pubsub/pricing) · [SCC pricing](https://cloud.google.com/security-command-center/pricing) · [Cloud Billing budgets](https://cloud.google.com/billing/docs/how-to/budgets)

## Prepare and review

Install [Google Cloud CLI](https://docs.cloud.google.com/sdk/docs/install) and Terraform 1.9 or later. Authenticate from your terminal. Use your own authorized identity, without a downloaded service account key. Confirm project scope and billing in the console before enabling any resources. The provisioning identity needs permissions for Service Usage, project Logging configuration, Pub/Sub administration and service-account IAM in the lab. Optional budget creation also needs billing account permissions and the Cloud Billing Budget API.

```sh
gcloud auth login --update-adc
gcloud projects describe gsl-YOUR-ID
gcloud billing projects describe gsl-YOUR-ID
uv sync --locked --python 3.12 --extra cloud
```

Replace **gsl-YOUR-ID** with the dedicated project ID. Set its label in the project console. Copy **infrastructure/lab.example.tfvars** to **infrastructure/lab.tfvars**, update the ID, and supply the authorized **operator_member** when using impersonation. Set **billing_account** only after approval. Keep **route_audit=false** while inspecting the first plan. Use the same variable file for every plan, including teardown.

```sh
uv run --no-sync python scripts/cloud_ops.py plan gsl-YOUR-ID --var-file infrastructure/lab.tfvars
terraform -chdir=infrastructure show ../var/cloud/gsl-YOUR-ID-plan.tfplan
uv run --no-sync python scripts/cloud_ops.py apply gsl-YOUR-ID --authorized
uv run --no-sync python scripts/cloud_ops.py verify gsl-YOUR-ID
```

After approval, set **route_audit=true** and repeat plan, review and apply. The operator IAM binding grants impersonation only on the dedicated subscriber service account. An authorized operator can acquire impersonated ADC for the pull path. The verification script reads the sink, topic policy and subscription, while the smoke script uses the active gcloud account for the label update and log read.

```sh
gcloud auth application-default login --impersonate-service-account=gsl-audit-collector@gsl-YOUR-ID.iam.gserviceaccount.com
uv run --no-sync python scripts/cloud_ops.py smoke gsl-YOUR-ID --authorized
uv run --no-sync secops-lab --db var/cloud.sqlite cloud-pull --project gsl-YOUR-ID --authorized
uv run --no-sync secops-lab --db var/cloud.sqlite replay
```

The smoke test updates a verification label on the existing topic once, then checks a matching audit insert ID in Cloud Logging and SQLite. It uses at most four bounded pull attempts and enforces a one-minute local interval between invocations. It creates no intentionally insecure resource. Route or IAM propagation may delay delivery. Run **verify** and inspect the relevant audit log if the event is absent. Never upload a real cloud database or evidence report.

## Stop or tear down

The collector and smoke test end automatically. Stop future delivery while retaining infrastructure by creating and reviewing a **stop-plan**. To remove the resources tracked in Terraform, create and review a **destroy-plan**.

```sh
uv run --no-sync python scripts/cloud_ops.py stop-plan gsl-YOUR-ID --var-file infrastructure/lab.tfvars
uv run --no-sync python scripts/cloud_ops.py apply gsl-YOUR-ID --kind stop-plan --authorized
uv run --no-sync python scripts/cloud_ops.py destroy-plan gsl-YOUR-ID --var-file infrastructure/lab.tfvars
terraform -chdir=infrastructure show ../var/cloud/gsl-YOUR-ID-destroy-plan.tfplan
uv run --no-sync python scripts/cloud_ops.py apply gsl-YOUR-ID --kind destroy-plan --authorized
```

After teardown, use explicit project commands to check that **gsl-audit-routing**, **gsl-audit**, **gsl-audit-pull** and **gsl-audit-collector** are absent. Check the billing console if a budget was managed. Enabled APIs and the pre-existing project are outside the destroy scope. An authorized administrator can retire the isolated project separately after inspecting its contents. Terraform state, plans and ADC configuration belong outside Git.
