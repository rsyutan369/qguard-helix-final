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
finding. Missing cryptographic evidence remains **Not measured**, never a claim
that the asset is secure or PQC-ready. Existing bound/grouped attribution and
tenant boundaries are preserved.

The receipt links to `/dashboard/assets?agentId=…`, showing assets attributed to
that agent across its retained evidence. The source filter distinguishes device,
VM, cloud, Kubernetes, web and repository evidence. Counts on the receipt are
records accepted for that scan, not distinct assets. Source labels and collector
identity are available in asset details.

## Device identity

Agent **1.6.1** adds bounded, cached system manufacturer/model reporting. Windows
uses CIM; Linux uses DMI files. Recognized virtualization models allow a VM label;
unavailable identity remains unknown. A host name containing `VM` is insufficient.
Remote endpoints retain their own source classification rather than inheriting
the collector's virtualization status. Upgrade an existing 1.6.0 installation
with a newly generated installer to report this additional identity evidence.

## Verification

- `npx tsx tools/live-agent-workflow-check.ts`
- `npx tsx tools/asset-register-check.ts`
- `npx tsx tools/scan-observability-live-check.ts` (isolated QA tenants, Chrome,
  real scoped local scans and cleanup)
- `npx tsx tools/agent-transport-security-check.ts`
