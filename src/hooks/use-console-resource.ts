import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * One Owner-Admin console tab's server state: its (filtered, paged) payload,
 * its query, and the rules every tab follows —
 *   - loads the first time the tab asks for it (ensureLoaded), not on page load;
 *   - a query change refetches from page 1, debounced;
 *   - only the newest request may write (a slow old response is dropped);
 *   - an SSE frame refetches ONLY when the model version moved.
 */
export interface ConsoleResource<TData, TQuery> {
  data: TData | null
  query: TQuery
  setQuery: (patch: Partial<TQuery>) => void
  resetQuery: () => void
  loading: boolean
  error: string | null
  ensureLoaded: () => void
  refresh: (page?: number) => Promise<void>
  onStreamVersion: (version: string) => void
  isActive: () => boolean
}

type VersionedPayload = { version: string; generatedAt: string; pagination?: { page: number } }

export function useConsoleResource<TData extends VersionedPayload, TQuery extends Record<string, string>>(options: {
  path: string
  defaults: TQuery
  fetcher: <T>(path: string) => Promise<T>
  limit?: number
  debounceMs?: number
}): ConsoleResource<TData, TQuery> {
  const [data, setData] = useState<TData | null>(null)
  const [query, setQueryState] = useState<TQuery>(options.defaults)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const fetcherRef = useRef(options.fetcher)
  fetcherRef.current = options.fetcher
  const queryRef = useRef(query)
  queryRef.current = query
  const pageRef = useRef(1)
  const seqRef = useRef(0)
  const versionRef = useRef<string | null>(null)
  const activeRef = useRef(false)
  const lastQueryKey = useRef<string | null>(null)

  const refresh = useCallback(async (page?: number) => {
    activeRef.current = true
    const requestId = ++seqRef.current
    const targetPage = page ?? pageRef.current
    setLoading(true)
    try {
      const params = new URLSearchParams({ ...queryRef.current, page: String(targetPage), ...(options.limit ? { limit: String(options.limit) } : {}) })
      const payload = await fetcherRef.current<TData>(`${options.path}?${params}`)
      if (requestId !== seqRef.current) return
      setData(payload)
      versionRef.current = payload.version
      pageRef.current = payload.pagination?.page ?? targetPage
      setError(null)
    } catch (err) {
      if (requestId === seqRef.current) setError(err instanceof Error && err.message ? err.message : 'Request failed')
    } finally {
      if (requestId === seqRef.current) setLoading(false)
    }
  }, [options.limit, options.path])

  const ensureLoaded = useCallback(() => {
    if (activeRef.current) return
    void refresh(1)
  }, [refresh])

  // Refetch from page 1 when the query VALUE changes (StrictMode-safe).
  useEffect(() => {
    const key = JSON.stringify(query)
    if (lastQueryKey.current === null || lastQueryKey.current === key) {
      lastQueryKey.current = key
      return undefined
    }
    lastQueryKey.current = key
    if (!activeRef.current) return undefined
    const handle = window.setTimeout(() => void refresh(1), options.debounceMs ?? 250)
    return () => window.clearTimeout(handle)
  }, [options.debounceMs, query, refresh])

  const onStreamVersion = useCallback((version: string) => {
    if (!activeRef.current || versionRef.current === null || versionRef.current === version) return
    versionRef.current = version
    void refresh()
  }, [refresh])

  const setQuery = useCallback((patch: Partial<TQuery>) => {
    setQueryState((current) => ({ ...current, ...patch }))
  }, [])

  const resetQuery = useCallback(() => {
    setQueryState(options.defaults)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const isActive = useCallback(() => activeRef.current, [])

  return { data, query, setQuery, resetQuery, loading, error, ensureLoaded, refresh, onStreamVersion, isActive }
}
