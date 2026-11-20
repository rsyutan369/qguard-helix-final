# Telemetry audit implementation report

Scope covers TLS Telemetry, PKI Visibility, Protocol Analytics, Encryption Monitoring, and TLS Orchestrator. The audit traced the dashboard code, APIs, their account-scoped data reads, and the migration workflow. No production migration or customer infrastructure change was made.

## Issues and corrections

| Area | Root cause | Correction |
| --- | --- | --- |
| Evidence coverage | Several source reads supplied a row limit without a total. The database API could stop before that limit, leaving the dashboard unaware that its figures were partial. | Read stable, bounded pages, capture the first page's exact total, and record unavailable or truncated sources. Dashboard figures apply to the retrieved evidence window. |
| Asset coverage | TLS listeners were subtracted from the number of registered assets. One asset with several listeners could cause the dashboard to undercount unmeasured assets. | Count distinct, registered asset IDs for coverage. Continue to use listeners as the denominator for listener posture. |
| TLS and Protocol Analytics | SSH inventory could reach the TLS classifier. The Protocol Analytics page had no view of evidence already persisted by the SSH metadata scanner. | Show stored banners, advertised key exchanges, and advertised host keys with their observation timestamps. Preserve independent TLS distributions and distinguish runtime, scanner, and inventory evidence. |
| PKI Visibility | Legacy imports could put a certificate signature in the generic algorithm field. Certificate investigation included findings matched to the listener, which could belong to a different certificate. | Prefer explicit public-key and signature fields. Recognize historical signature identifiers and leave the leaf key unknown when absent. Match certificate findings to the modeled certificate ID. |
| Encryption Monitoring and TLS health | Status substring matching admitted negative states and queued scans. A stored online label could outlive the most recent heartbeat. | Reuse one status counter for both models, require a recent heartbeat, and use exact connector and scan states. The evidence watermark follows relevant observations and findings. |
| TLS Orchestrator | Several listeners could count a queued asset more than once. Simulated jobs entered operational figures, older validation results could inflate success, and the headline used a bounded job list. | Deduplicate queued assets, exclude simulation jobs, count active jobs before slicing, and take each job's latest validation. Count a verified operation only when an eligible completed job has an explicit passing result. An endpoint-scoped failed validation appears as failed in the remediation worklist. |
| Live delivery | REST and SSE could treat the same snapshot as separate updates. Changes outside the initial list could leave paged results stale, while a drawer could keep the originally loaded detail indefinitely. | Use consistent content fingerprints, include full model inventory revisions, share per-account in-flight builds, and trigger detail and table reads on accepted snapshot changes. Failed detail and list requests expose retry states. |
| Scope and inspection | The five pages lacked a common asset comparison workflow. | Allow search and selection of one to four registered assets on every page. Show TLS, SSH, PKI, data protection, findings, and measured configuration changes for the exact selected IDs. Display scope, evidence timestamps, and data coverage. |

## Data and access paths

- The TLS model joins the canonical asset portfolio and readiness snapshot with tenant-filtered runtime observations, scanner evidence, inventory, certificates, scan results, and findings. TLS Telemetry, Protocol Analytics, PKI Visibility, TLS Orchestrator, and Trust Fabric consume that model. TLS runtime negotiation and scanner acceptance use different evidence labels.
- Encryption Monitoring sources data protection from cryptographic inventory, runtime and scanner evidence, recorded key inventory, vault records, and related findings. Transport evidence alone provides no measurement of storage or application encryption.
- TLS Orchestrator uses the recorded asset queue, plans, jobs, security events, and job-linked validation logs. Existing controls call Migration Planner for queue edits and plan submission. Plan submission creates pending approval. Queue prioritization applies to the shared planner queue.
- The page hooks fetch REST and SSE with bearer authorization. The server checks snapshots on an interval and sends compact acknowledgements for unchanged content. Existing Supabase Realtime subscriptions filter on the account ID and nudge refreshes, with SSE and polling available during subscription gaps. The comparison uses its own SSE projection and verifies all selected IDs against the authenticated account on every build.
- Table and drawer reads abort when account, selection, or query scope changes. The comparison verifies the exact selected ID set on receipt. The new routes reuse the authenticated Supabase client and explicitly filter assets by the current account ID. The repository's RLS policies for owned records were reviewed.

## Verification

| Check | Result |
| --- | --- |
| TypeScript and production build | Run against the workspace. See the final task status for the exact outcomes. |
| TLS, PKI, Trust, and telemetry regression suite | Controls cover handshake versus probe evidence, listener and certificate identity, expiry and trust, distinct asset coverage, SSH advertising, signature attribution, source status, bounded pagination, selected asset isolation, migration results, and SSE fingerprints and cleanup. |
| Browser behavior | Chromium desktop and mobile fixture runs exercised bearer requests, one- and two-asset selection, SSE-driven row updates, evidence switching, and clearing the comparison. |
| Local API authentication | All five snapshot paths, all five stream paths, and the three new asset picker and comparison paths returned HTTP 401 without credentials. |
| Authenticated tenant and operational checks | No authenticated test tenant or isolated migration target was available for this audit. A live tenant reconciliation, database RLS enforcement across two real accounts, live WebSocket delivery, production-scale timings, and controlled migration execution remain unverified. |

The comparison retains up to 25 recent rows for each selected asset and evidence type. It uses the existing bounded evidence and canonical inventory windows. Empty results describe the available assessment evidence in those windows. Real-time displays depend on the collector or scan recording an observation and the backend publishing the next snapshot.
