# Detection library

Native Google SecOps validation is **PENDING** for every rule. The checked-in YARA-L source and the Python evaluator use a shared detection specification. Passing fixture checks establishes Python behavior on those inputs.

The rules target the laboratory UDM profile. Compare product names, event classifications and identity fields against the native default parser before deploying a rule.

## GSL001 · Cloud IAM policy change

- [YARA-L source](../detections/yara_l/GSL001_iam_policy_change.yaral) · **high**
- ATT&CK: T1098
- Sources: gcp_iam
- Fields: 'metadata.event_type', 'metadata.product_event_type', 'metadata.product_name', 'security_result.action'
- Behavior: Policy updates can grant privilege or introduce new principals.
- False positives: Approved infrastructure deployments routinely change policy.
- Tuning: Baseline deployment identities and correlate the policy delta before escalation.
- Fixtures: [scenario index](../scenarios/catalog.json) · iam_policy
- Expected: Positive fixture alerts and nearby negative fixture remains quiet.
- Validation: Python fixture tests and structural source check. Native status PENDING.

## GSL002 · Service account key creation

- [YARA-L source](../detections/yara_l/GSL002_service_account_key.yaral) · **high**
- ATT&CK: T1098.001
- Sources: gcp_iam
- Fields: 'metadata.event_type', 'metadata.product_event_type', 'metadata.product_name', 'security_result.action'
- Behavior: New user-managed keys can provide durable access.
- False positives: Legacy workloads may rotate keys legitimately.
- Tuning: Allowlist documented exceptions and prefer workload identity.
- Fixtures: [scenario index](../scenarios/catalog.json) · service_key
- Expected: Positive fixture alerts and nearby negative fixture remains quiet.
- Validation: Python fixture tests and structural source check. Native status PENDING.

## GSL003 · Logging sink modification

- [YARA-L source](../detections/yara_l/GSL003_logging_sink_change.yaral) · **high**
- ATT&CK: T1562.008
- Sources: gcp_audit
- Fields: 'metadata.event_type', 'metadata.product_event_type', 'metadata.product_name', 'security_result.action'
- Behavior: Changing routing can hide future activity from security monitoring.
- False positives: Platform maintenance may change sink filters.
- Tuning: Review the destination and filter diff against change tickets.
- Fixtures: [scenario index](../scenarios/catalog.json) · sink
- Expected: Positive fixture alerts and nearby negative fixture remains quiet.
- Validation: Python fixture tests and structural source check. Native status PENDING.

## GSL004 · Cloud firewall rule change

- [YARA-L source](../detections/yara_l/GSL004_firewall_change.yaral) · **medium**
- ATT&CK: T1562.007
- Sources: gcp_audit
- Fields: 'metadata.event_type', 'metadata.product_event_type', 'metadata.product_name', 'security_result.action'
- Behavior: A rule change may widen the reachable network surface.
- False positives: Approved rule updates are common.
- Tuning: Review source ranges, target tags and change approvals.
- Fixtures: [scenario index](../scenarios/catalog.json) · firewall
- Expected: Positive fixture alerts and nearby negative fixture remains quiet.
- Validation: Python fixture tests and structural source check. Native status PENDING.

## GSL005 · AWS role policy attachment

- [YARA-L source](../detections/yara_l/GSL005_aws_role_policy.yaral) · **high**
- ATT&CK: T1098.003
- Sources: cloudtrail
- Fields: 'metadata.event_type', 'metadata.product_event_type', 'metadata.product_name', 'security_result.action'
- Behavior: A new policy attachment may expand the permissions of a role.
- False positives: IaC deployments can legitimately attach policies.
- Tuning: Compare against the AWS change record and inspect policy permissions.
- Fixtures: [scenario index](../scenarios/catalog.json) · aws_role
- Expected: Positive fixture alerts and nearby negative fixture remains quiet.
- Validation: Python fixture tests and structural source check. Native status PENDING.

## GSL006 · AWS bucket policy change

- [YARA-L source](../detections/yara_l/GSL006_aws_bucket_policy.yaral) · **medium**
- ATT&CK: T1530
- Sources: cloudtrail
- Fields: 'metadata.event_type', 'metadata.product_event_type', 'metadata.product_name', 'security_result.action'
- Behavior: A policy update can broaden object access.
- False positives: Routine remediation and deployment may change policies.
- Tuning: Inspect the new policy and block-public-access configuration.
- Fixtures: [scenario index](../scenarios/catalog.json) · aws_bucket
- Expected: Positive fixture alerts and nearby negative fixture remains quiet.
- Validation: Python fixture tests and structural source check. Native status PENDING.

## GSL007 · Repeated login failures

- [YARA-L source](../detections/yara_l/GSL007_repeated_failures.yaral) · **medium**
- ATT&CK: T1110.001
- Sources: workspace, entra, windows, linux
- Fields: 'metadata.event_type', 'metadata.product_name', 'security_result.action', 'target.user.userid'
- Behavior: Repeated failures for one identity can indicate password guessing.
- False positives: Expired secrets and typing errors can produce repeated failures.
- Tuning: Baseline service identities and tune threshold by authentication provider.
- Fixtures: [scenario index](../scenarios/catalog.json) · failures
- Expected: Positive fixture alerts and nearby negative fixture remains quiet.
- Validation: Python fixture tests and structural source check. Native status PENDING.

## GSL008 · Password spray from one IP

- [YARA-L source](../detections/yara_l/GSL008_password_spray.yaral) · **high**
- ATT&CK: T1110.003
- Sources: workspace, entra, windows, linux
- Fields: 'metadata.event_type', 'metadata.product_name', 'principal.ip', 'security_result.action', 'target.user.userid'
- Behavior: One IP failing against multiple identities can indicate password spraying.
- False positives: NAT or a misconfigured proxy can aggregate unrelated attempts.
- Tuning: Baseline shared egress and require more distinct users in noisy segments.
- Fixtures: [scenario index](../scenarios/catalog.json) · spray
- Expected: Positive fixture alerts and nearby negative fixture remains quiet.
- Validation: Python fixture tests and structural source check. Native status PENDING.

## GSL009 · Login success after repeated failures

- [YARA-L source](../detections/yara_l/GSL009_fail_then_success.yaral) · **high**
- ATT&CK: T1110.001
- Sources: workspace, entra, windows, linux
- Fields: 'metadata.event_timestamp', 'metadata.event_type', 'metadata.product_name', 'security_result.action', 'target.user.userid'
- Behavior: A successful sign-in after repeated failures may indicate credential compromise.
- False positives: A legitimate user can eventually enter the correct password.
- Tuning: Confirm device, MFA and source IP with the identity owner.
- Fixtures: [scenario index](../scenarios/catalog.json) · fail_success
- Expected: Positive fixture alerts and nearby negative fixture remains quiet.
- Validation: Python fixture tests and structural source check. Native status PENDING.

## GSL010 · Rapid sign-ins from different countries

- [YARA-L source](../detections/yara_l/GSL010_rapid_country_change.yaral) · **medium**
- ATT&CK: T1078
- Sources: entra
- Fields: 'metadata.event_type', 'metadata.product_name', 'principal.location.country_or_region', 'security_result.action', 'target.user.userid'
- Behavior: A principal signing in from different countries rapidly may indicate account misuse.
- False positives: VPN exits and IP geolocation errors are common.
- Tuning: Use known VPN ranges and managed-device context.
- Fixtures: [scenario index](../scenarios/catalog.json) · countries
- Expected: Positive fixture alerts and nearby negative fixture remains quiet.
- Validation: Python fixture tests and structural source check. Native status PENDING.

## GSL011 · Encoded PowerShell invocation

- [YARA-L source](../detections/yara_l/GSL011_encoded_powershell.yaral) · **high**
- ATT&CK: T1059.001
- Sources: sysmon, falcon
- Fields: 'metadata.event_type', 'metadata.product_name', 'target.process.command_line'
- Behavior: Encoded arguments can conceal a script payload.
- False positives: Deployment tooling also uses encoded commands.
- Tuning: Inspect the process tree and decode the payload offline.
- Fixtures: [scenario index](../scenarios/catalog.json) · powershell
- Expected: Positive fixture alerts and nearby negative fixture remains quiet.
- Validation: Python fixture tests and structural source check. Native status PENDING.

## GSL012 · Office application spawning a shell

- [YARA-L source](../detections/yara_l/GSL012_office_shell.yaral) · **high**
- ATT&CK: T1204.002
- Sources: sysmon
- Fields: 'metadata.event_type', 'metadata.product_name', 'principal.process.file.full_path', 'target.process.file.full_path'
- Behavior: A shell launched by Office can indicate malicious document execution.
- False positives: Some legacy macros invoke approved command-line tools.
- Tuning: Check file provenance and allowlist signed workflow tools.
- Fixtures: [scenario index](../scenarios/catalog.json) · office
- Expected: Positive fixture alerts and nearby negative fixture remains quiet.
- Validation: Python fixture tests and structural source check. Native status PENDING.

## GSL013 · Windows Run key modification

- [YARA-L source](../detections/yara_l/GSL013_run_key.yaral) · **medium**
- ATT&CK: T1547.001
- Sources: sysmon
- Fields: 'metadata.event_type', 'metadata.product_name', 'target.registry.registry_key'
- Behavior: A Run key value can establish logon persistence.
- False positives: Installers and legitimate startup software create Run values.
- Tuning: Inspect the registry value, writing process and signer.
- Fixtures: [scenario index](../scenarios/catalog.json) · registry
- Expected: Positive fixture alerts and nearby negative fixture remains quiet.
- Validation: Python fixture tests and structural source check. Native status PENDING.

## GSL014 · Remote SMB connection

- [YARA-L source](../detections/yara_l/GSL014_smb_lateral.yaral) · **medium**
- ATT&CK: T1021.002
- Sources: sysmon
- Fields: 'metadata.event_type', 'metadata.product_name', 'target.port'
- Behavior: An endpoint reaching TCP/445 can indicate remote service activity.
- False positives: File servers and administrative tooling use SMB routinely.
- Tuning: Baseline approved file servers and verify destination and process.
- Fixtures: [scenario index](../scenarios/catalog.json) · smb
- Expected: Positive fixture alerts and nearby negative fixture remains quiet.
- Validation: Python fixture tests and structural source check. Native status PENDING.

## GSL015 · Repeated long DNS labels

- [YARA-L source](../detections/yara_l/GSL015_dns_long_labels.yaral) · **medium**
- ATT&CK: T1071.004
- Sources: dns
- Fields: 'metadata.event_type', 'metadata.product_name', 'network.dns.questions.name', 'principal.ip'
- Behavior: Repeated long labels can carry encoded data.
- False positives: Telemetry and CDNs may use long labels.
- Tuning: Baseline domains and inspect entropy and query volume.
- Fixtures: [scenario index](../scenarios/catalog.json) · long_dns
- Expected: Positive fixture alerts and nearby negative fixture remains quiet.
- Validation: Python fixture tests and structural source check. Native status PENDING.

## GSL016 · Repeated traffic to alternate C2 port

- [YARA-L source](../detections/yara_l/GSL016_repeated_alt_port.yaral) · **medium**
- ATT&CK: T1571
- Sources: fortigate
- Fields: 'metadata.event_type', 'metadata.product_name', 'network.direction', 'principal.ip', 'security_result.action', 'target.ip', 'target.port'
- Behavior: Repeated permitted outbound sessions to port 4444 warrant investigation.
- False positives: Authorized diagnostic tools can use the same port.
- Tuning: Inspect destinations and baseline approved services. Check periodicity separately.
- Fixtures: [scenario index](../scenarios/catalog.json) · c2
- Expected: Positive fixture alerts and nearby negative fixture remains quiet.
- Validation: Python fixture tests and structural source check. Native status PENDING.

## GSL017 · Large permitted outbound transfer

- [YARA-L source](../detections/yara_l/GSL017_large_egress.yaral) · **high**
- ATT&CK: T1048
- Sources: fortigate
- Fields: 'metadata.event_type', 'metadata.product_name', 'network.direction', 'network.sent_bytes', 'security_result.action'
- Behavior: A single outbound session over 100 MiB can indicate bulk transfer.
- False positives: Backups and artifact publishing may transfer large objects.
- Tuning: Baseline traffic by source and destination. Verify whether data was authorized.
- Fixtures: [scenario index](../scenarios/catalog.json) · egress
- Expected: Positive fixture alerts and nearby negative fixture remains quiet.
- Validation: Python fixture tests and structural source check. Native status PENDING.

## GSL018 · Burst of cloud object reads

- [YARA-L source](../detections/yara_l/GSL018_cloud_object_reads.yaral) · **medium**
- ATT&CK: T1530
- Sources: gcp_audit, cloudtrail
- Fields: 'metadata.event_type', 'metadata.product_name', 'principal.user.userid', 'security_result.action'
- Behavior: A burst of object reads by one identity may precede exfiltration.
- False positives: Batch ETL and backups often read many objects.
- Tuning: Tune to workload baselines and correlate with egress.
- Fixtures: [scenario index](../scenarios/catalog.json) · reads
- Expected: Positive fixture alerts and nearby negative fixture remains quiet.
- Validation: Python fixture tests and structural source check. Native status PENDING.

## GSL019 · Sign-in followed by IAM change

- [YARA-L source](../detections/yara_l/GSL019_login_then_iam.yaral) · **high**
- ATT&CK: T1078
- Sources: entra, workspace, gcp_iam
- Fields: 'metadata.event_timestamp', 'metadata.event_type', 'metadata.product_event_type', 'metadata.product_name', 'principal.user.userid', 'security_result.action', 'target.user.userid'
- Behavior: An authentication followed by a cloud policy update can reveal abuse of a federated identity.
- False positives: Operators may sign in just before an approved change.
- Tuning: Match canonical identity across providers and check ticket, MFA and policy delta.
- Fixtures: [scenario index](../scenarios/catalog.json) · cross
- Expected: Positive fixture alerts and nearby negative fixture remains quiet.
- Validation: Python fixture tests and structural source check. Native status PENDING.
