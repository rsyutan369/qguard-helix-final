import type { Row } from '@/lib/migration/asset-intelligence'
import type { SourceLedger } from './source-ledger'

/** Read a bounded evidence window while respecting the API's per-request row limit. */
export function readTelemetrySource(
  ledger: SourceLedger,
  client: any,
  table: string,
  columns: string,
  limit: number,
  configure: (query: any) => any,
) {
  return ledger.read(client, table, table.replace(/_/g, ' '), limit, async (source) => {
    const rows = new Map<unknown, Row>()
    let count: number | null = null
    let offset = 0
    while (offset < limit && (count === null || offset < count)) {
      const first = offset === 0
      const query = configure(source.select(columns, first ? { count: 'exact' } : {}))
        .order('id').range(offset, Math.min(offset + 999, limit - 1))
      const result = await query
      if (result.error) return { error: result.error }
      if (first) count = result.count ?? null
      if (!result.data?.length) break
      for (const row of result.data as Row[]) rows.set(row.id, row)
      offset += result.data.length
    }
    return { data: [...rows.values()], count }
  })
}
