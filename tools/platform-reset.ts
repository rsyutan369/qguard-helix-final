/**
 * Operational reset — clear the agent fleet and everything it produced, so the
 * platform can be re-onboarded from scratch with new tenants and assets.
 *
 * WHAT IT DELETES
 *   the agent fleet, its policies, heartbeats, commands and evidence; every
 *   alert and runtime event; the whole migration layer (plans, jobs, events,
 *   executions, telemetry, validations, queues, packages, tasks, snapshots and
 *   snapshot audit); the discovery layer (assets, crypto inventory,
 *   certificates, generated keys, scan sessions and results, relationships);
 *   and the operational history (security events, audit logs, copilot threads).
 *
 * WHAT IT KEEPS — deliberately, and this is the important half:
 *   • `auth.users`, profiles and identities. Deleting a Supabase auth user
 *     detaches its billing subscription, orphans the messaging device keyring
 *     and breaks vault key wrapping for that account. A fresh ESTATE does not
 *     require fresh LOGINS.
 *   • billing / subscription rows — agent role entitlement is resolved from
 *     these, so wiping them would leave every tenant unable to enrol a Patcher
 *     or Migration Operator.
 *   • vault and messaging data, which are a different product surface.
 *
 * ORDER
 *   Children before parents, because `migration_jobs` is referenced by four
 *   dispatch tables and `assets` by most of the discovery layer. A delete in the
 *   wrong order does not silently skip — it fails on the foreign key, which is
 *   why the order below is explicit rather than alphabetical.
 *
 * Dry run (default):  npx tsx tools/platform-reset.ts
 * Apply:              npx tsx tools/platform-reset.ts --apply
 * One tenant only:    npx tsx tools/platform-reset.ts --user <uuid> [--apply]
 */
import { createClient } from '@supabase/supabase-js'
import fs from 'node:fs'

const APPLY = process.argv.includes('--apply')
const userFlag = process.argv.indexOf('--user')
const ONLY_USER = userFlag >= 0 ? process.argv[userFlag + 1] : null

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

/**
 * Deletion order. Every entry is `[table, tenantColumn]`.
 *
 * `tenantColumn` is the column holding the owning user, so a single-tenant
 * reset can be scoped. A table without one is deleted wholesale only in a
 * full reset.
 */
const ORDER: Array<[string, string | null]> = [
  // ── migration dispatch bookkeeping (FK → migration_jobs) ─────────────
  ['execution_queues', 'user_id'],
  ['orchestration_jobs', 'user_id'],
  ['deployment_packages', 'user_id'],
  ['migration_tasks', 'user_id'],
  ['migration_validations', 'user_id'],
  ['migration_telemetry', 'user_id'],
  ['migration_executions', 'user_id'],
  ['migration_events', 'user_id'],
  // ── snapshots (reference jobs by id, not FK, but are their evidence) ──
  ['migration_snapshot_audit', 'user_id'],
  ['migration_snapshots', 'user_id'],
  // ── the jobs and the plans that own them ─────────────────────────────
  ['migration_jobs', 'user_id'],
  ['migration_plans', 'user_id'],
  // ── agent output ─────────────────────────────────────────────────────
  ['scanner_alerts', 'user_id'],
  ['runtime_crypto_events', 'user_id'],
  ['scanner_evidence', 'user_id'],
  ['agent_heartbeats', 'user_id'],
  ['agent_events', 'user_id'],
  ['agent_install_events', 'user_id'],
  ['agent_operator_actions', 'user_id'],
  ['operator_actions', 'user_id'],
  ['remediation_jobs', 'user_id'],
  // ── the fleet itself (policies FK → scanner_agents) ──────────────────
  ['scanner_agent_policies', 'user_id'],
  ['scanner_agents', 'user_id'],
  ['connector_accounts', 'user_id'],
  // ── discovery output (FK → assets / scan sessions) ───────────────────
  ['pqc_scan_results', 'user_id'],
  ['pqc_scan_sessions', 'user_id'],
  ['asset_relationships', 'user_id'],
  ['crypto_inventory', 'user_id'],
  ['certificates', 'user_id'],
  ['generated_keys', 'user_id'],
  ['scan_findings', 'user_id'],
  ['cbom_components', 'user_id'],
  ['exposure_history', 'user_id'],
  ['exposure_snapshots', 'user_id'],
  // ── downstream engines ───────────────────────────────────────────────
  ['quantum_certifications', 'user_id'],
  ['certification_evidence', 'user_id'],
  ['remediation_playbooks', 'user_id'],
  ['drift_events', 'user_id'],
  ['drift_baselines', 'user_id'],
  ['telemetry_events', 'user_id'],
  ['trust_scores', 'user_id'],
  ['compliance_findings', 'user_id'],
  ['governance_findings', 'user_id'],
  ['identity_assets', 'user_id'],
  ['pqauth_tokens', 'user_id'],
  ['key_inventory', 'user_id'],
  ['vendor_assessments', 'user_id'],
  ['sandbox_simulations', 'user_id'],
  ['workflow_states', 'user_id'],
  ['report_records', 'user_id'],
  ['service_records', 'user_id'],
  // ── the assets everything above hung off ─────────────────────────────
  ['assets', 'user_id'],
  // ── operational history ──────────────────────────────────────────────
  ['security_events', 'user_id'],
  ['audit_logs', 'user_id'],
  ['copilot_messages', 'user_id'],
  ['copilot_sessions', 'user_id'],
]

/** Never touched. Listed so the intent is explicit rather than implied by omission. */
const PRESERVED = [
  'auth.users', 'profiles', 'user_profiles',
  'billing_subscriptions', 'subscriptions', 'paypal_subscriptions', 'play_billing_purchases',
  'vault_files', 'vault_shares', 'vault_recovery',
  'messaging_*', 'conversations', 'device_keys', 'prekeys',
  'qkms_keys (platform trust anchor)',
  'cost_assumptions (tenant configuration, not evidence)',
]

async function countOf(table: string, tenantColumn: string | null): Promise<number | null> {
  let q = admin.from(table).select('*', { count: 'exact', head: true })
  if (ONLY_USER && tenantColumn) q = q.eq(tenantColumn, ONLY_USER)
  const { count, error } = await q
  if (error) return null
  return count || 0
}

async function purge(table: string, tenantColumn: string | null): Promise<{ deleted: number; error?: string }> {
  const before = await countOf(table, tenantColumn)
  if (before === null) return { deleted: 0, error: 'table not present' }
  if (before === 0) return { deleted: 0 }
  if (!APPLY) return { deleted: before }

  /* PostgREST refuses an unfiltered DELETE, so a full reset is expressed as
     "every row whose id is not the impossible one" rather than a bare delete. */
  let q = admin.from(table).delete()
  if (ONLY_USER && tenantColumn) q = q.eq(tenantColumn, ONLY_USER)
  else if (tenantColumn) q = q.not(tenantColumn, 'is', null)
  else q = q.not('id', 'is', null)

  const { error } = await q
  if (error) {
    /* A table keyed on something other than user_id still needs clearing — in a
       FULL reset only. A tenant-scoped reset must never widen to every tenant's
       rows, so it reports the error instead of retrying without the filter. */
    if (ONLY_USER) return { deleted: 0, error: error.message }
    const { error: fallbackError } = await admin.from(table).delete().not('id', 'is', null)
    if (fallbackError) return { deleted: 0, error: error.message }
  }
  const after = await countOf(table, tenantColumn)
  return { deleted: before - (after ?? 0) }
}

async function main() {
  console.log(`\nQGuard platform reset — ${APPLY ? 'APPLY' : 'DRY RUN (pass --apply to delete)'}`)
  console.log(ONLY_USER ? `scope: tenant ${ONLY_USER}\n` : 'scope: ALL tenants\n')

  let total = 0
  const skipped: string[] = []
  for (const [table, tenantColumn] of ORDER) {
    const result = await purge(table, tenantColumn)
    if (result.error === 'table not present') { skipped.push(table); continue }
    if (result.error) {
      console.log(`  ${'ERR'.padStart(7)}  ${table}  — ${result.error.slice(0, 70)}`)
      continue
    }
    if (result.deleted > 0) {
      console.log(`  ${String(result.deleted).padStart(7)}  ${table}`)
      total += result.deleted
    }
  }

  console.log(`\n  ${String(total).padStart(7)}  rows ${APPLY ? 'deleted' : 'would be deleted'}`)
  if (skipped.length) console.log(`\n  not present in this schema: ${skipped.join(', ')}`)
  console.log('\n  preserved:')
  for (const item of PRESERVED) console.log(`    · ${item}`)

  if (APPLY) {
    console.log('\n  Verifying the estate is empty…')
    const residual: string[] = []
    for (const [table, tenantColumn] of ORDER) {
      const count = await countOf(table, tenantColumn)
      if (count) residual.push(`${table}=${count}`)
    }
    console.log(residual.length ? `  RESIDUAL ROWS: ${residual.join(', ')}` : '  clean — every listed table is empty.')

    const { data: users } = await admin.auth.admin.listUsers()
    console.log(`  auth accounts preserved: ${(users?.users || []).length}`)
  }
  console.log('')
}

main().catch((error) => {
  console.error('reset failed:', error?.message || error)
  process.exitCode = 1
})
