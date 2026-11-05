import type { SupabaseClient } from '@supabase/supabase-js'

/** Remove only an explicitly provisioned QA tenant's rows; do not rely on FK cascades. */
export async function cleanupQaTenant(db: SupabaseClient, userId: string) {
  for (const table of ['scanner_alerts', 'runtime_crypto_events', 'agent_heartbeats', 'scanner_agent_policies', 'crypto_exposures', 'crypto_inventory', 'pqc_scan_results', 'vulnerabilities', 'certificates', 'scanner_evidence', 'pqc_scan_sessions', 'security_events', 'audit_logs', 'scanner_agents', 'assets', 'billing_subscriptions']) {
    const { error } = await db.from(table).delete().eq('user_id', userId)
    if (error && !/42P01|42703|PGRST204|PGRST205/.test(String(error.code || ''))) throw new Error(`QA cleanup failed in ${table}: ${error.message}`)
  }
  for (const table of ['assets', 'scanner_agents', 'scanner_evidence']) {
    const { count, error } = await db.from(table).select('id', { head: true, count: 'exact' }).eq('user_id', userId)
    if (error || count) throw new Error(`QA records remain in ${table}`)
  }
  for (let attempt = 0; attempt < 3; attempt++) {
    const removed = await db.auth.admin.deleteUser(userId)
    if (!removed.error || /not found/i.test(removed.error.message)) return
    if (attempt === 2 || (removed.error.status && removed.error.status < 500)) throw new Error(`QA account deletion failed (${removed.error.status || 'unknown status'}): ${removed.error.message}`)
    await new Promise((resolve) => setTimeout(resolve, 500 * (attempt + 1)))
  }
}
