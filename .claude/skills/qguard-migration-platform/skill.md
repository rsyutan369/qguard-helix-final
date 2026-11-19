---
name: qguard-migration-platform
description: Implementation knowledge for the QGuard Helix migration platform — Migration Planner, Migration Sandbox, Live Migration, the workflow state layer, orchestration, snapshots, rollback and dependency analysis. Use when working on migration planning, simulation, execution, remediation pipelines or the workflow rail.
priority: high
owner: qguard-helix
version: 1.0
---

# Migration Platform

Domain judgement lives in the `migration-engineer` role skill. This is how the
code is built and what has already gone wrong.

## Surfaces and their sources

| Surface | Route | Source of truth |
|---|---|---|
| Migration Planner | `/dashboard/migration-planner` | QR snapshot + report model + `asset-intelligence.ts` |
| Migration Ops Center | `/dashboard/migration-timeline` | derived from 3 shared hooks — no new data |
| PQC Automation Center | `/dashboard/pqc-orchestration` | the **same** 3 hooks, so numbers match Ops |
| Migration Sandbox | `/dashboard/migration-sandbox` | `sandbox-twin.ts` pure engine |
| Live Migration | `/dashboard/live-migration` | workflow + orchestrator + real agent pipeline |

**The rule that keeps them consistent:** operations surfaces are *pure
derivations over shared hooks*, not independent queries. When two ops pages
disagree, someone added a query.

**Units the Planner and Sandbox must share with Assets / CBOM / QR (issue #71):**

- *Components* — `partitionAssetInventory(rows, algorithmFamily)`. Raw
  `crypto_inventory` rows include scanner findings and per-scan repeats.
- *Severity counts* — `dedupeGradedObservations`, one per (algorithm, asset).
- *Per-asset risk* — the Planner shows the QR engine's risk ("QR risk"); the
  Asset Inventory shows the scanner's ("Scanner risk"). Two measurements, each
  labelled — do not substitute one for the other.
- *Stage status* — "In Progress" needs a record of work; data alone is "Ready".
- *Simulations vs migrations* — split `migration_jobs` with `isSimulationJob`.

Live proof: `npx tsx tools/discovery-migration-consistency-check.ts`.

## Workflow layer

An 11-stage state-driven lifecycle drives `WorkflowRail` across ~10 dashboards,
served by `/api/v1/migration-workflow` behind a 30 s cache.

Schema facts that have cost time:
- `migration_plans` has **no `name` column**.
- The asset queue is itself a `migration_queue` plan row — **exclude it from plan
  counts** or every total is off by one.

## Snapshot contract — abort, never fabricate

Mid-run "simulations disappear and reappear" traced to two causes: error-swallowed
empty snapshots, and a write-on-read realtime feedback loop.

The contract:

- A snapshot that cannot be produced returns **503 `SNAPSHOT_UNAVAILABLE`**. It
  never returns an empty object that the UI renders as "nothing here".
- Reads never write. A read that mutates creates a realtime echo that re-triggers
  the read.
- Guard on `generatedAt`; throttle advance.

This generalises: **an unavailable result must be distinguishable from an empty
result.** Same principle as `qguard-data-integrity` Rule 3.

## Orchestration

Postgres-backed distributed scheduling with priority, lease, backoff,
back-pressure, dead-letter and node recovery. State lives in
`migration_jobs.metadata` — no schema change required to extend it.

Rules:
- An unhandled rejection in a scheduler **kills the server**. Wrap and log.
- Foreign keys are real: a missing `plan_id` crashes the pipeline. Validate
  before enqueue.
- Remediation must target the mandatory PQC stack profile — not an arbitrary
  algorithm choice.

## Snapshots, validation and rollback

Pre-migration crypto-state backups with SHA3-256 integrity, plus auto and manual
rollback. Every execution records before-state, after-state, verification
(`migrationSuccessful`, `certificateValid`, `serviceReachable`,
`rollbackRequired`), and restores automatically on validation failure.

Never mark a migration successful without an after-state measurement. "The command
returned 0" is not validation.

## Asset prioritisation

`asset-intelligence.ts` is the shared posture engine — the QR snapshot calls it
too. Prioritisation reads exposure, blast radius and dependency depth from the
shared snapshot rather than re-deriving risk, so the planner and the readiness
engine cannot disagree about which asset is worst.

## Certification readiness

Live Migration shows a Certification Readiness band computed from the same
criteria as the certification engine (`useMigrationWorkflow`), so the migration
surface and the certification surface stay in lock-step.

Table-name collision to remember: certificates for the trust engine live in
**`quantum_trust_certificates`** (with `not_after`), not `certificates` — that
name was already taken by the scanner.

## Checklist

- [ ] New surface derives from existing hooks; no new aggregation.
- [ ] Unavailable ≠ empty; 503 rather than a hollow success.
- [ ] Reads do not write.
- [ ] Scheduler work cannot raise an unhandled rejection.
- [ ] `migration_queue` excluded from plan counts.
- [ ] Before/after state captured; rollback path tested.
- [ ] Numbers cross-checked against Ops and Automation surfaces.
- [ ] Component and severity counts use the shared rules above; the live
      consistency check passes.
- [ ] No stage, tile or chain claims work, blockage or topology without a record.
