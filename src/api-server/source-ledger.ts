/**
 * Source-read ledger for the Intelligence & Operations routers.
 *
 * Each router used to wrap its Supabase reads in a `safeRows` that turned a
 * failed query into `[]` — so a missing column or an RLS refusal rendered as
 * "no events", "no drift", "no jobs" (common-issues #16, #63). The ledger
 * still degrades a failed read to an empty list, so one broken table never
 * takes the whole page down, but it RECORDS the outcome. The router publishes
 * the records as `sources`, and the page shows them in the shared
 * `SourceHealth` strip: a failed read is labelled "could not be read", never
 * shown as zero.
 */
import type { Row } from '@/lib/migration/asset-intelligence'
import type { SourceRead, SourceReadState } from '@/lib/source-read'

export type { SourceRead, SourceReadState }

export interface SourceLedger {
  /** Read one table; a failure returns `[]` AND is recorded as `unavailable`. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  read(client: any, table: string, label: string, limit: number | null, build: (query: any) => any): Promise<Row[]>
  /** Record a source that is not a direct table read (an upstream model). */
  note(key: string, label: string, state: SourceReadState, rows: number, detail: string): void
  /** The outcomes, in the order the reads were issued. */
  readonly reads: SourceRead[]
}

export function createSourceLedger(scope: string): SourceLedger {
  const reads: SourceRead[] = []
  const order: string[] = []
  const record = (entry: SourceRead) => {
    const at = order.indexOf(entry.key)
    if (at >= 0) reads[at] = entry
    else {
      order.push(entry.key)
      reads.push(entry)
    }
  }
  return {
    reads,
    note(key, label, state, rows, detail) {
      record({ key, label, state, rows, limit: null, detail })
    },
    async read(client, table, label, limit, build) {
      // Reserve the slot now so the published order is the issue order, not
      // the order the parallel reads happen to finish in.
      if (!order.includes(table)) {
        order.push(table)
        reads.push({ key: table, label, state: 'empty', rows: 0, limit, detail: 'Pending.' })
      }
      const fail = (message: string): Row[] => {
        console.warn(`${scope}: ${table} query failed:`, message)
        record({ key: table, label, state: 'unavailable', rows: 0, limit, detail: 'The query failed — figures that depend on it are incomplete, not zero.' })
        return []
      }
      try {
        const { data, error } = await build(client.from(table))
        if (error) return fail(error.message || String(error))
        const rows = (data as Row[]) || []
        const state: SourceReadState = limit !== null && rows.length >= limit ? 'truncated' : rows.length ? 'ok' : 'empty'
        record({
          key: table,
          label,
          state,
          rows: rows.length,
          limit,
          detail: state === 'truncated'
            ? `Read capped at ${limit} rows (most recent first) — older rows are not included.`
            : state === 'ok' ? `${rows.length} row(s) read.` : 'Read — no rows recorded.',
        })
        return rows
      } catch (error) {
        return fail((error as Error)?.message || String(error))
      }
    },
  }
}
