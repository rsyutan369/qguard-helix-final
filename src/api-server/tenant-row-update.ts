import type { SupabaseClient } from '@supabase/supabase-js'

type CoordinatedTable = 'assets' | 'scanner_agents' | 'migration_jobs'

/** Compare-and-set retries merge into fresh state; concurrent agents cannot erase each other's metadata. */
export async function updateTenantRow(
  client: SupabaseClient,
  table: CoordinatedTable,
  userId: string,
  id: string,
  change: (current: any) => Record<string, unknown> | null,
): Promise<any | null> {
  for (let attempt = 0; attempt < 12; attempt++) {
    const { data: current, error: readError } = await client.from(table).select('*').eq('user_id', userId).eq('id', id).maybeSingle()
    if (readError) throw new Error(`Unable to read ${table} for coordinated update: ${readError.message}`)
    if (!current) throw new Error(`Tenant record not found in ${table}`)
    const patch = change(current)
    if (!patch) return null
    const previousTime = Date.parse(current.updated_at || '')
    const updatedAt = new Date(Math.max(Date.now(), Number.isFinite(previousTime) ? previousTime + 1 : 0)).toISOString()
    let write = client.from(table).update({ ...patch, updated_at: updatedAt }).eq('user_id', userId).eq('id', id)
    write = current.updated_at ? write.eq('updated_at', current.updated_at) : write.is('updated_at', null)
    const { data: saved, error: writeError } = await write.select('*').maybeSingle()
    if (writeError) throw new Error(`Unable to update ${table}: ${writeError.message}`)
    if (saved) return saved
  }
  throw new Error(`Concurrent ${table} updates did not settle; retry the operation`)
}
