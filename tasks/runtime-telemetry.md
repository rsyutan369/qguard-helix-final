# Runtime Telemetry — Refactor, Wire, Synchronize & Enhance

Guideline: `Qguard_Wiki/Observability_Refactor`
Page: `/dashboard/runtime-telemetry` (Elite tier, Observability group)

## Audit — two findings, one of them structural

### 1. Three dashboards, one payload

`buildObservabilitySnapshot(kind, …)` accepts the mode discriminator and then
**never reads it**. Verified against the live API: `/runtime-telemetry`,
`/certificate-telemetry` and `/multi-cloud-telemetry` return byte-identical
`metrics`. Three separately-named Elite dashboards were showing exactly the same
data under different titles.

### 2. The figures are fabricated

Every metric is `signals.length`, where `signals` is one flattened array built
from ~25 tables. On a tenant with **2 assets, 0 generated keys, 0 connector
accounts, 3 certificates and 108 runtime events**, the page published:

| Published | Reality |
|---|---|
| `totalSignals: 786`, `runtimeEvents: 723` | 108 rows in `runtime_crypto_events` |
| `certificates: 459` | 3 distinct certificates |
| `keys: 593` (`activeKeys: 46`, `weakKeys: 384`) | **0** generated keys |
| `cloudProviders: 3`, `cloudRegions: 4`, `cloudAssets: 279` | **0** connector accounts |
| `assetsCovered: 90` | 2 assets — the set counts hostnames, process names and finding titles |
| `activeProcesses: 86`, `anomalies: 448`, `apiEvents: 356` | derived the same way |

## Scope — why this is NOT Runtime Crypto Intelligence

`/dashboard/runtime-crypto-intel` already answers *"what cryptography is running
and is it quantum-safe"*. Rebuilding this page to answer the same question would
be the duplicate data model the brief forbids.

Runtime Telemetry owns the layer beneath that: **is the telemetry pipeline
itself healthy, complete and trustworthy?** It is the page every other
dashboard's freshness indicator and provenance footer points back to. It answers
*"can I trust what the other dashboards are telling me?"*

Concretely, and all from real rows:

* **Collector fleet** — per-agent status, platform, last seen, heartbeats
  received, events contributed, silence duration.
* **Ingestion lag** — measured `created_at - observed_at` per event. Real values
  on this tenant: 1.17s, 1.45s, 5.48s. Never surfaced anywhere before.
* **Throughput** — events per day per source, from real timestamps.
* **Source freshness** — per-table last event, age, and an explicit staleness
  threshold, so "0" is always attributable.
* **Signal quality** — unattributed events (no `asset_id`), unattributable
  events (no `agent_id`), duplicate ingestion, missing algorithm.
* **Blast radius** — which dashboards consume which source, so a stale source
  shows what it degrades.

### Data-quality facts this tenant already exhibits

* `runtime_crypto_events.agent_id` is **NULL** on every row despite
  `source_type: 'local-agent'` — events cannot be attributed to a collector.
* `asset_id` is **NULL** on the sampled rows — events are unattributed.
* Identical `(observed_at, created_at, event_type)` rows appear more than once —
  duplicate ingestion.
* `agent_heartbeats` is **empty** and the one registered collector has
  `last_seen_at: null` and `status: 'offline'` — yet 108 events arrived from
  `local-agent`. Events are arriving from a source no registered collector
  accounts for.

These are exactly the things a telemetry console exists to show, and the old
page showed none of them.

## Steps

- [x] `src/lib/telemetry-pipeline/types.ts`
- [x] `src/lib/telemetry-pipeline/intelligence.ts` — pure engine
- [x] `src/api-server/runtime-telemetry.ts` — cache + routes + SSE + paging
- [x] `src/hooks/use-runtime-telemetry.ts`
- [x] Rewrite the page on the shared observability primitives
- [x] Leave `ObservabilityDashboard` in place for certificate/multi-cloud
      telemetry (still its consumers) and drop only the runtime mode
- [x] Typecheck + build + live-tenant verification

## Result on the same tenant

Every count now matches its table exactly: `runtime_crypto_events` 108,
`scanner_evidence` 104, `scanner_alerts` 109, `crypto_inventory` 72,
`pqc_scan_results` 66, `crypto_exposures` 68, `certificates` 3,
`generated_keys` 0, `agent_heartbeats` 0, `assets` 2.

Pipeline health **46/100 — stale**, and the page explains exactly why:

* **Ingestion lag measured for the first time**: p50 1.8s, p95 6.0s, max 6.5s
  over 212 samples, broken down per source.
* **Collector silent**: 1 registered, 0 heartbeats ever, 0 attributed events —
  measured health `silent` against a stored status of `offline`.
* **Attribution gap**: 108 events arrived from `local-agent`, a source matching
  no registered collector, none carrying an `agent_id`.
* **45% duplicate ingestion** across runtime events.
* **3 sources produced nothing** (`generated_keys`, `agent_heartbeats`,
  `vault_files`), each naming the dashboards it leaves unmeasured.
* **Runtime crypto events stale** — 15h old against a 6h window.

## Defect found in a shared module, fixed at source

The workflow rail on 10+ dashboards claimed **"Runtime telemetry live — posture
is continuously monitored"** because `runtimeMeasured = runtimeEvents.length > 0`
— any event, of any age. On this tenant the newest runtime event was 15 hours
old and no collector had ever sent a heartbeat, so the rail directly
contradicted the page built here from the same evidence.

Fixed additively:

* `quantum-readiness.ts` now publishes `telemetry.latestRuntimeEventAt`.
* `quantum-remediation.ts` derives a separate `runtimeFresh` measure (newest
  runtime observation within 6 hours).
* `migration-workflow.ts` claims "live" only when fresh; otherwise "Runtime
  telemetry stale" with a pointer to this page.

The Quantum Readiness SCORE is deliberately unchanged — see the open question
below.

## Open question for the platform owner

`quantum-readiness.ts` also grants full `runtimeVisibility = 100` (15% of the
readiness blend) on the same `runtimeEvents.length > 0` test. By the argument
above that is too generous: a tenant with one stale event scores the same
runtime-visibility credit as one with live streaming telemetry.

This was NOT changed here. The readiness score is the platform's canonical
number — reproduced on the QR pages, Migration Planner, every page in this
suite, the reports and the certification engine — so re-weighting it is a
product decision with real downstream consequences, not a bug fix to make in
passing.

## Non-negotiables

* Counts are of ROWS in a named table, never of a flattened cross-table array.
* Lag, throughput and freshness come from real timestamps; nothing is modelled.
* A source with no rows is reported as absent, with what it would have fed.
* This page must not restate Runtime Crypto Intelligence's conclusions — it
  links to them and reports the confidence they can be held with.
