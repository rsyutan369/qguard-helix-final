'use client'
import { useCallback, useEffect, useRef, useState } from 'react'
import { useAuth } from '@/contexts/auth-context'
import type { ClusterDetail, EstateOverview, GraphLevel } from '@/lib/estate'
import type { WorkflowGraph } from '@/components/trust-workflow/graph-model'

/**
 * Estate Remediation Intelligence — data hooks.
 *
 * Every hook reads a projection of ONE server-side model (30 s single-flight
 * cache per tenant), so the fix plan, the maps and the campaigns can never show
 * numbers computed at different moments. A failed refresh keeps the last good
 * data and surfaces the error instead of blanking the page.
 */

export type LoadState = 'loading' | 'ready' | 'error'

const BASE = '/api/v1/estate-intelligence'

async function getJson<T>(path: string, token: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(path, { headers: { Authorization: `Bearer ${token}` }, signal })
  const json = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(json?.error?.message || `Request failed (${res.status})`)
  return json.data as T
}

function useEndpoint<T>(path: string | null) {
  const { session } = useAuth()
  const token = session?.access_token
  const [data, setData] = useState<T | null>(null)
  const [state, setState] = useState<LoadState>('loading')
  const [error, setError] = useState<string | null>(null)
  const controller = useRef<AbortController | null>(null)

  const load = useCallback(async (suffix = '') => {
    if (!token || !path) return
    controller.current?.abort()
    const next = new AbortController()
    controller.current = next
    setState((current) => (current === 'ready' ? 'ready' : 'loading'))
    try {
      const joiner = path.includes('?') ? '&' : '?'
      const result = await getJson<T>(`${path}${suffix ? `${joiner}${suffix}` : ''}`, token, next.signal)
      setData(result)
      setError(null)
      setState('ready')
    } catch (err) {
      if ((err as Error).name === 'AbortError') return
      setError((err as Error).message)
      setState('error')
    }
  }, [token, path])

  useEffect(() => {
    if (!path) { setData(null); return }
    void load()
    return () => controller.current?.abort()
  }, [load, path])

  return { data, state, error, refresh: (force = false) => load(force ? 'refresh=1' : '') }
}

export function useEstateOverview() {
  return useEndpoint<EstateOverview>(BASE)
}

export function useEstateFix(id: string | null, options: { offset: number; limit: number; status: string; q: string }) {
  const query = new URLSearchParams({ offset: String(options.offset), limit: String(options.limit), status: options.status, q: options.q })
  return useEndpoint<ClusterDetail>(id ? `${BASE}/fixes/${encodeURIComponent(id)}?${query}` : null)
}

export function useEstateGraph(level: GraphLevel, focus: string | null) {
  const path = level === 'root-cause'
    ? `${BASE}/graph?level=root-cause`
    : focus ? `${BASE}/graph?level=${level}&focus=${encodeURIComponent(focus)}` : null
  return useEndpoint<{ generatedAt: string; level: GraphLevel; focus: string | null; graph: WorkflowGraph }>(path)
}

export interface AssetHit { id: string; name: string; owner: string | null; environment: string; openFixes: number }

export function useEstateSearch() {
  const { session } = useAuth()
  const token = session?.access_token
  return useCallback(async (q: string) => {
    if (!token || q.trim().length < 2) return [] as AssetHit[]
    return getJson<AssetHit[]>(`${BASE}/search?q=${encodeURIComponent(q.trim())}`, token)
  }, [token])
}

/** Queues a campaign wave through the existing, tenant-verified Migration Planner queue. */
export function useQueueWave() {
  const { session } = useAuth()
  const token = session?.access_token
  return useCallback(async (assetIds: string[]) => {
    if (!token) throw new Error('Not signed in')
    const res = await fetch('/api/v1/migration-planner/queue', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ assetIds }),
    })
    const json = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(json?.error?.message || `Queue request failed (${res.status})`)
    return json
  }, [token])
}
