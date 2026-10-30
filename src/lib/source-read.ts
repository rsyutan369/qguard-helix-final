/**
 * The outcome of one evidence read, as published by the Intelligence &
 * Operations routers (`createSourceLedger`) and rendered by the shared
 * `SourceHealth` strip. `unavailable` means the query FAILED: its empty list is
 * not a measurement of zero.
 */
export type SourceReadState = 'ok' | 'empty' | 'truncated' | 'unavailable'

export interface SourceRead {
  /** Table name (stable key). */
  key: string
  label: string
  state: SourceReadState
  rows: number
  /** The read cap; `truncated` means the cap was hit and older rows exist. */
  limit: number | null
  detail: string
}
