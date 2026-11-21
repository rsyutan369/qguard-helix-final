'use client'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useAuth } from '@/contexts/auth-context'
import type { ClusterDetail, EstateGraphSnapshot, EstateOverview, GraphLevel, MapAsset, MapDimension, MapGroupDetail } from '@/lib/estate'
import { useLiveModel } from './use-live-resource'

/**
 * Estate Remediation Intelligence — data hooks.
 *
 * Each endpoint reads a tenant-scoped projection of the same cached model.
 * A failed refresh can retain the last good result within the same request scope.
 */

export type LoadState = 'loading' | 'ready' | 'error'

const BASE = '/api/v1/estate-intelligence'
const ESTATE_TABLES = ['assets', 'crypto_inventory', 'certificates', 'asset_relationships', 'migration_jobs', 'migration_validation_logs', 'migration_plans']

async function getJson<T>(path: string, token: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(path, { headers: { Authorization: `Bearer ${token}` }, signal, cache: 'no-store' })
  const json = await res.json().catch(() => ({}))
  if (!res.ok || !json.data) throw new Error(json?.error?.message || `Request failed (${res.status})`)
  return json.data as T
}

function useEndpoint<T>(path: string | null, revision?: string) {
  const { session, user } = useAuth()
  const token = user && session?.user.id === user.id ? session.access_token : null
  const scope = useMemo(() => ({}), [path, user?.id, Boolean(token)])
  const [snapshot, setSnapshot] = useState<{ scope: object; data: T | null; error: string | null; refreshing: boolean } | null>(null)
  const controller = useRef<{ scope: object; request: AbortController } | null>(null)

  const refresh = useCallback(async (force = false) => {
    if (!token || !path) return
    if (controller.current?.scope === scope) return
    controller.current?.request.abort()
    const next = new AbortController()
    controller.current = { scope, request: next }
    setSnapshot((current) => ({ scope, data: current?.scope === scope ? current.data : null, error: null, refreshing: true }))
    try {
      const joiner = path.includes('?') ? '&' : '?'
      const signal = AbortSignal.any([next.signal, AbortSignal.timeout(30_000)])
      const result = await getJson<T>(force && path === BASE ? `${path}${joiner}refresh=1` : path, token, signal)
      if (!next.signal.aborted) setSnapshot({ scope, data: result, error: null, refreshing: false })
    } catch (err) {
      if (!next.signal.aborted) setSnapshot((current) => ({ scope, data: current?.scope === scope ? current.data : null, error: (err as Error).message, refreshing: false }))
    } finally {
      if (controller.current?.request === next) controller.current = null
    }
  }, [scope, token, path])

  useEffect(() => {
    void refresh()
    return () => {
      if (controller.current?.scope !== scope) return
      controller.current.request.abort()
      controller.current = null
    }
  }, [refresh, scope, revision])

  const current = snapshot?.scope === scope ? snapshot : null
  const state: LoadState = current?.error ? 'error' : current?.data ? 'ready' : 'loading'
  return { data: current?.data ?? null, state, error: current?.error ?? null, refreshing: current?.refreshing ?? false, refresh }
}

export function useEstateOverview() {
  return useLiveModel<EstateOverview>({
    url: BASE,
    streamUrl: `${BASE}/stream`,
    event: 'estate-intelligence',
    channelPrefix: 'estate-intelligence',
    realtimeTables: ESTATE_TABLES,
    validate: (raw) => typeof raw.generatedAt === 'string' && typeof raw.revision === 'string' &&
      typeof raw.hasData === 'boolean' && Array.isArray(raw.coverage) && Array.isArray(raw.clusters) &&
      Boolean(raw.summary && raw.maps && raw.burndown && raw.sankey && raw.heatmap && raw.ownership),
  })
}

export function useEstateFix(id: string | null, options: { offset: number; limit: number; status: string; q: string }, revision: string) {
  const query = new URLSearchParams({ offset: String(options.offset), limit: String(options.limit), status: options.status, q: options.q })
  return useEndpoint<ClusterDetail>(id ? `${BASE}/fixes/${encodeURIComponent(id)}?${query}` : null, revision)
}

export function useEstateGraph(level: GraphLevel | null, focus: string | null, revision?: string) {
  const path = level === 'root-cause'
    ? `${BASE}/graph?level=root-cause`
    : level && focus ? `${BASE}/graph?level=${level}&focus=${encodeURIComponent(focus)}` : null
  return useEndpoint<EstateGraphSnapshot>(path, revision)
}

export function useEstateMapAssets(dimension: MapDimension, group: string, offset: number, revision: string) {
  const query = new URLSearchParams({ dimension, group, offset: String(offset) })
  return useEndpoint<MapGroupDetail>(`${BASE}/map/assets?${query}`, revision)
}

export function useEstateSearch() {
  const { session, user } = useAuth()
  const token = user && session?.user.id === user.id ? session.access_token : null
  return useCallback(async (q: string, signal?: AbortSignal) => {
    if (!token || q.trim().length < 2) return []
    return getJson<MapAsset[]>(`${BASE}/search?q=${encodeURIComponent(q.trim())}`, token, signal)
  }, [token])
}

/** Queues a campaign wave through the existing, tenant-verified Migration Planner queue. */
export function useQueueWave() {
  const { session, user } = useAuth()
  const token = user && session?.user.id === user.id ? session.access_token : null
  return useCallback(async (assetIds: string[]) => {
    if (!token) throw new Error('Not signed in')
    const res = await fetch('/api/v1/migration-planner/queue', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ assetIds }),
    })
    const json = await res.json().catch(() => ({}))
    if (!res.ok || !Array.isArray(json?.data?.entries)) throw new Error(json?.error?.message || `Queue request failed (${res.status})`)
    const confirmed = new Set(json.data.entries.map((entry: { assetId: string }) => entry.assetId))
    return assetIds.filter((id) => confirmed.has(id)).length
  }, [token])
}
