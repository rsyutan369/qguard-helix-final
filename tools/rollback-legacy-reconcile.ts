/**
 * One-shot reconciliation of rollback records written before the executor gate.
 *
 * The previous implementation had two writers that asserted a rollback had
 * happened without any executor touching the asset:
 *
 *   • `autoRollbackFailedJobs()` flipped every FAILED migration job to
 *     `rolled_back`, marked its snapshot `restored`, and wrote an audit line
 *     reading "Restored <asset> from <snapshot>" with
 *     `restoration_status: 'completed'`. It ran on a GET and on every 20-second
 *     SSE tick, so it fired for any tenant who opened the Snapshots panel.
 *   • `POST /:snapshotId/restore` did the same the moment ANY active agent or
 *     connector row existed for the tenant.
 *
 * Those rows are still in the database and still read as completed rollbacks.
 * They are compliance records asserting a cryptographic change that was never
 * applied, so they cannot be left standing — and they cannot simply be deleted
 * either, because deleting audit history to hide an error is worse than the
 * error. This CORRECTS them the way an audit system should:
 *
 *   • the snapshot returns to `restorable` (its captured state is still valid)
 *     with the original unverified claim preserved under
 *     `metadata.legacyUnverifiedRestore`;
 *   • the job returns to `failed`, which is the state it was in before the
 *     fabricated rollback (the old writer only ever ran on failed jobs);
 *   • a `restore_correction` audit row is appended explaining what happened.
 *     Nothing is deleted.
 *
 * A record is only touched when it carries NO executor evidence
 * (`metadata.rollback` absent) — i.e. it can only have come from the old
 * writers. Anything the new path produced is left alone.
 *
 * Dry run (default):  npx tsx tools/rollback-legacy-reconcile.ts
 * Apply:              npx tsx tools/rollback-legacy-reconcile.ts --apply
 */
import { createClient } from '@supabase/supabase-js'
import fs from 'node:fs'

const APPLY = process.argv.includes('--apply')

const env = Object.fromEntries(
  fs.readFileSync(new URL('../.env', import.meta.url), 'utf8')
    .split(/\r?\n/)
    .filter((line) => line.includes('=') && !line.startsWith('#'))
    .map((line) => {
      const i = line.indexOf('=')
      return [line.slice(0, i).trim(), line.slice(i + 1).trim().replace(/^["']|["']$/g, '')]
    }),
)

const admin = createClient(env.VITE_SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } })

function rec(v: unknown): Record<string, unknown> {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {}
}

async function main() {
  console.log(`\nLegacy rollback reconciliation — ${APPLY ? 'APPLY' : 'DRY RUN (pass --apply to write)'}\n`)
  const now = new Date().toISOString()

  /* ---- snapshots claiming a restore with no executor evidence ---- */
  const { data: snapshots, error: snapError } = await admin
    .from('migration_snapshots')
    .select('id, user_id, snapshot_id, asset_name, status, restored_at, migration_job_id, metadata')
    .eq('status', 'restored')
  if (snapError) throw new Error(`snapshot read: ${snapError.message}`)

  const orphaned = (snapshots || []).filter((s) => !rec(s.metadata).rollback)
  console.log(`snapshots marked "restored" with no executor record: ${orphaned.length}`)

  for (const snap of orphaned) {
    const meta = rec(snap.metadata)
    console.log(`  · ${snap.snapshot_id} (${snap.asset_name}) restored_at=${snap.restored_at}`)
    if (!APPLY) continue

    await admin.from('migration_snapshots').update({
      status: 'restorable',
      restored_at: null,
      metadata: {
        ...meta,
        legacyUnverifiedRestore: {
          claimedRestoredAt: snap.restored_at,
          correctedAt: now,
          note: 'Marked restored by the pre-executor-gate code path. No executor ever applied this snapshot to the asset, so the claim is withdrawn. The captured state is unchanged and the snapshot remains restorable.',
        },
      },
      updated_at: now,
    }).eq('id', snap.id)

    await admin.from('migration_snapshot_audit').insert({
      user_id: snap.user_id,
      snapshot_id: snap.snapshot_id,
      migration_job_id: snap.migration_job_id,
      action: 'restore_correction',
      actor: 'platform-reconciliation',
      reason: 'Rollback record written without executor confirmation',
      detail: `The earlier "restored" status on ${snap.snapshot_id} (${snap.asset_name}) asserted a change to the asset that no agent or connector performed. The status has been corrected to restorable; the original claim is preserved in metadata.legacyUnverifiedRestore. Nothing on the asset was ever modified by that record.`,
      approval_status: 'n/a',
      validation_result: 'unverified',
      restoration_status: 'withdrawn',
      integrity_status: 'verified',
    })
  }

  /* ---- jobs flipped to rolled_back by the same writer ---- */
  const { data: jobs, error: jobError } = await admin
    .from('migration_jobs')
    .select('id, user_id, name, status, metadata')
    .eq('status', 'rolled_back')
  if (jobError) throw new Error(`job read: ${jobError.message}`)

  const fabricated = (jobs || []).filter((j) => {
    const meta = rec(j.metadata)
    return meta.autoRolledBack === true && !meta.rollbackDisposition
  })
  console.log(`\nmigration jobs marked "rolled_back" with no rollback disposition: ${fabricated.length}`)

  for (const job of fabricated) {
    const meta = rec(job.metadata)
    console.log(`  · ${job.name} (from ${String(meta.rolledBackFrom || 'unknown snapshot')})`)
    if (!APPLY) continue

    await admin.from('migration_jobs').update({
      /* The old writer only ran on jobs already in a failed state, so `failed`
         is the state this job was actually in. */
      status: 'failed',
      metadata: {
        ...meta,
        autoRolledBack: false,
        rollbackDisposition: 'not-performed',
        legacyUnverifiedRollback: {
          claimedAt: meta.rolledBackAt || null,
          claimedFrom: meta.rolledBackFrom || null,
          correctedAt: now,
          note: 'Marked rolled_back by the pre-executor-gate code path. No executor performed the rollback; the job is returned to its real state (failed).',
        },
      },
      updated_at: now,
    }).eq('id', job.id)

    await admin.from('migration_events').insert({
      user_id: job.user_id,
      migration_id: job.id,
      event_type: 'rollback-record-corrected',
      severity: 'warning',
      message: `The "rolled back" status on ${job.name} was recorded without any executor performing the rollback. The job has been returned to its real state (failed).`,
      metadata: { correctedAt: now, claimedFrom: meta.rolledBackFrom || null },
      created_at: now,
    })
  }

  /* ---- the audit lines those writers left ---- */
  const { data: audit } = await admin
    .from('migration_snapshot_audit')
    .select('id, snapshot_id, action, restoration_status, detail')
    .in('action', ['auto_rollback'])
    .eq('restoration_status', 'completed')
  console.log(`\nlegacy audit rows asserting restoration_status='completed': ${(audit || []).length}`)
  for (const row of audit || []) {
    console.log(`  · ${row.snapshot_id}: ${String(row.detail || '').slice(0, 90)}`)
  }
  console.log(
    (audit || []).length
      ? '\n  These rows are KEPT as history. The restore_correction rows written above\n  sit alongside them and state that no change was applied.'
      : '',
  )

  console.log(`\n${APPLY ? 'Applied.' : 'Dry run complete — nothing was written.'}\n`)
}

main().catch((error) => {
  console.error('reconciliation failed:', error?.message || error)
  process.exitCode = 1
})
