# Migration Snapshot Management™

Implements `Qguard_Wiki/Snapshot_Management`: before any migration/remediation
runs, QGuard Helix captures a complete, integrity-verified snapshot of the
target asset's cryptographic + configuration state, so every change is fully
reversible. Added to the Live Migration Operations module.

## Components

| Piece | Path |
| --- | --- |
| DB schema | `supabase/migration-snapshots-schema.sql` (migration_snapshots + migration_snapshot_audit, RLS, indexes, realtime) |
| Types | `src/types/migration-snapshot.ts` |
| Backend | `src/api-server/migration-snapshots.ts` → `/api/v1/migration-snapshots` (Pro+) |
| Hook | `src/hooks/use-migration-snapshots.ts` (fetch + header-auth SSE + realtime + actions) |
| UI | `src/app/dashboard/live_migration_ops/_snapshots.tsx` (dashboard card + management drawer) |
| Offline check | `npx tsx tools/snapshot-check.ts` |

## What it does

- **Automatic pre-migration snapshots**: every migration job entering execution
  gets a snapshot capturing its asset's REAL crypto state (algorithms, TLS
  version + cipher suites, PKI issuers, certificate metadata, key metadata,
  config paths) pulled from `crypto_inventory` / `certificates` /
  `generated_keys` / job metadata. Manual and scheduled snapshots also supported.
- **Integrity**: SHA3-256 hash over the canonical (sorted-key) crypto-state.
  Restore recomputes and compares the hash — a tampered snapshot is refused
  (409 INTEGRITY_FAILED). Verified offline: capture, determinism, and
  tamper-detection across 16 checks.
- **Rollback integration**: the toolbar **Rollback** button opens the snapshot
  drawer focused on the selected job's asset (view → select → preview → confirm
  → restore, which drives the existing job rollback path). A new **Snapshots**
  button sits immediately beside it for full management.
- **Automatic rollback**: when a migration job enters a failed/validation-failed
  state and has a restorable pre-migration snapshot, the latest valid snapshot
  is restored automatically, the job flipped to `rolled_back`, and the event
  audited (`auto_rollback`).
- **Management drawer**: view / search / filter (status) / compare two snapshots
  (side-by-side crypto-state diff) / download metadata (JSON) / restore /
  verify integrity / delete (retention-gated) + an Audit Log tab.
- **Dashboard card** (in the Live Migration page): Total / Restorable / Auto
  Rollbacks / Manual Rollbacks / Storage Used / Integrity Verified / Latest /
  Restored — plus an Auto-rollback indicator.

## Metadata captured (per the guide)

Snapshot ID, asset name/type/environment, timestamp, migration job id, current
cryptographic algorithms, configuration version, certificate metadata, TLS
configuration, PKI metadata, key metadata, created-by, size, retention period,
integrity verification status. Coverage spans TLS/SSL/PKI/SSH/VPN/libraries/
KMS/HSM/LB/CDN/database/etc. via the asset's real crypto inventory. **Only
metadata is stored — never plaintext secrets/keys.**

## Security & compliance

- Tenant-isolated via RLS (a snapshot is only visible to its owner).
- RBAC: Pro+ tier gate (Starter → 403), owner always.
- Integrity: SHA3-256 hash, verified on restore.
- Retention: `retention_days` (default 90) + `expires_at`; restorable snapshots
  are protected from deletion until expiry unless force-deleted.
- Encrypted at rest (Postgres storage encryption).
- Every create / restore / auto-rollback / verify / delete is written to
  `migration_snapshot_audit` (actor, timestamp, asset, snapshot id, job id,
  reason, approval, validation, restoration, integrity status).
- Graceful degradation: `schemaReady:false` with a setup notice until the SQL
  is applied (no 500s).

## Verification (2026-07-17)

- `tsc --noEmit` clean; `vite build` clean.
- Tier gating: Starter → 403, Pro/owner → 200 with `schemaReady:false` and the
  full summary contract (live probe).
- `tools/snapshot-check.ts` — 16/16: real crypto-state capture, deterministic
  key-order-stable SHA3-256, tamper detection on 4 fields (restore gate), and
  honest empty state.
- Authenticated render: Snapshot Management drawer (Snapshots/Audit tabs,
  search, filter, Compare) + the toolbar Snapshots button + setup notice.

## PENDING USER

Run `supabase/migration-snapshots-schema.sql` in the Supabase SQL Editor
(idempotent, safe re-run) to provision the snapshot + audit tables and realtime.
Snapshots begin capturing automatically once a migration job runs.
