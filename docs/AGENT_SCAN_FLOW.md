# Agent scan progress and results

Scan actions in Downloads, agent details, collector details and Quick Start submit
the same tenant-authenticated scan command. An accepted request opens
`/dashboard/live-migration?agentId=…&commandId=…#agent-workflow`.

The requested-scan receipt follows that command, not the newest scan happening on
the host. It distinguishes queued, running, completed, completed with publishing
errors, failed and interrupted progress. Its start and finish times and counts
come from the persisted command acknowledgements and heartbeat phases. Repeated
clicks reuse an outstanding command. Reloading the page reads the same receipt.
The agent retains its latest 50 command outcomes; an older receipt explicitly
reports when it has fallen out of retained history.

The fleet canvas shows each agent's latest cycle. In watch mode, agents continue
scheduled collection according to policy (currently 30–60 seconds after a cycle
finishes). Starting a later scheduled cycle does not reset the requested-scan
receipt. A completed scan does not automatically authorize a patch or migration;
those roles follow their existing job and approval controls.

## Persisted evidence

| Table | Purpose |
| --- | --- |
| `scanner_agents.metadata.commandQueue` / `commandHistory` | Requested command, delivery, start, outcome and accepted counts |
| `agent_heartbeats` | Scan stages, progress, terminal phases and host identity |
| `scanner_evidence` | Accepted observations and original source context |
| `runtime_crypto_events` | Accepted runtime cryptographic observations |
| `pqc_scan_sessions` / `pqc_scan_results` | Evidence-batch history and classified results |
| `assets` | Observed targets, source attribution and measurement timestamps |
| `crypto_inventory` | Classified cryptographic inventory / CBOM |
| `crypto_exposures` / `scanner_alerts` | Evidence-backed exposure and alert records |

Assets are materialized for accepted observations even when no rule generates a
finding. By default an installed agent writes to **one device profile**, named
for its reported hostname. Certificates, keys, libraries and original paths are
subjects inside that profile rather than separate machines in the asset count.
Explicit application bindings remain supported. Missing cryptographic evidence remains **Not measured**, never a claim
that the asset is secure or PQC-ready. Existing bound/grouped attribution and
tenant boundaries are preserved.

The receipt links to `/dashboard/assets?agentId=…`, showing assets attributed to
that agent across its retained evidence. The source filter distinguishes device,
VM, cloud, Kubernetes, web and repository evidence. Counts on the receipt are
records accepted for that scan, not distinct assets. Source labels and collector
identity are available in asset details.

## One device profile

The device's **Needs action**, **All components**, and **Configuration findings**
tabs contain its observations. Components retain original certificate subjects
and file paths; two certificates sharing an algorithm remain separate components,
while repeated observations of the same certificate are grouped. Needs action
includes unclassified components for review and actionable configuration findings.
An observed certificate without algorithm evidence is unclassified, never assumed
safe or vulnerable. A profile with only unclassified evidence has no risk score.

Legacy split assets can be consolidated with
`tools/consolidate-agent-device-profile.ts --agent-id <uuid> --apply` (omit
`--apply` for a dry run). The operation is tenant-scoped and idempotent. It keeps
evidence and finding IDs, changes current inventory attribution to the profile,
and retains the old asset rows as archived audit aliases. Operational asset
counts and pickers exclude those aliases. Explicitly unrelated or shared assets
are not claimed by a device simply because their names look similar.

This behavior is applied by the server; an agent reinstall is not required.

## Device identity

Agent **1.6.1** adds bounded, cached system manufacturer/model reporting. Windows
uses CIM; Linux uses DMI files. Recognized virtualization models allow a VM label;
unavailable identity remains unknown. A host name containing `VM` is insufficient.
Remote endpoints retain their own source classification rather than inheriting
the collector's virtualization status. Upgrade an existing 1.6.0 installation
with a newly generated installer to report this additional identity evidence.

## Windows agents sharing one host

For coexistence across all four roles, use **1.6.3+** and follow
[Multiple agents on one host or asset](AGENT_COEXISTENCE.md). That release adds
shared writer locks, atomic job claims and concurrent metadata protection.

Agent **1.6.2** gives each installed agent its own directory
`C:\ProgramData\QGuardHelix\Agents\<agent-id>` and startup task
`QGuardHelixAgent-<agent-id>`. The task selects its own configuration using
`watch --config <absolute-path>`. Collector and Scanner can run concurrently;
reinstalling one identity stops and replaces only that identity's process.

Earlier Windows installers shared `QGuardHelix\Agent` and `QGuardHelixAgent`.
Updating that task's definition did not stop its running process. A second role
could overwrite the configuration while the original role kept running with
credentials already loaded into memory. The task appeared Running even though
the newly installed agent never sent a heartbeat.

Generate fresh Windows installers for the **existing agent identities** and run
them as Administrator. If the original one-time token is no longer held in the
page, rotate that agent's token before generating its installer. The new
installer retires the legacy shared task only when its configuration names the
identity being installed. It preserves that identity's existing signing key and
leaves legacy files for recovery. When a second role already overwrote the shared
configuration, rerun both roles' new installers once to restore both services.
Other identities' private keys are never copied into an agent's private slot.

Startup diagnostics are stored in the slot's `agent.log`, accessible only to
SYSTEM and Administrators. Logs redact the enrollment token and rotate at 2 MiB
with one backup. Verification waits up to two minutes for a signed heartbeat
carrying the current launch ID, reports a failure when it cannot verify that
launch, and prints the exact log and task commands. The wizard surfaces reported
failures and flags a task with no connection after two minutes as Needs attention.

## Verification

- `npx tsx tools/live-agent-workflow-check.ts`
- `npx tsx tools/asset-register-check.ts`
- `npx tsx tools/scan-observability-live-check.ts` (isolated QA tenants, Chrome,
  real scoped local scans and cleanup)
- `npx tsx tools/agent-transport-security-check.ts`
- `npx tsx tools/agent-startup-check.ts`
- `npx tsx tools/agent-windows-startup-live-check.ts` (Windows PowerShell, real
  local runtime/HTTP, test adapters for Scheduler, ACL and PowerShell HTTP cmdlets)
