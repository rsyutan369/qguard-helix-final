'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { useAuth } from '@/contexts/auth-context'
import type {
  BlastRadiusResult,
  DependencyChainStep,
  EvidenceRequestRecord,
  ExperimentRecord,
  ExperimentTarget,
  ExternalTrustIntelligence,
  Readiness,
  VendorRecord,
} from '@/lib/ecosystem/external-trust-intelligence'

/**
 * External Trust & Ecosystem — page-scoped data hooks.
 *
 * All four pages read projections of ONE server-side computation (15s
 * single-flight cache), so the vendor register, the dependency map, the trust
 * chains and the lab can never show numbers derived at different moments.
 *
 * Load state is explicit: a failed refresh keeps the previous snapshot and
 * surfaces the error, rather than blanking the page into zeros.
 */

export type TrustLoadState = 'loading' | 'success' | 'error'

interface Envelope {
  generatedAt: string
  hasData: boolean
  evidence: ExternalTrustIntelligence['evidence']
}

export type VendorPayload = Envelope & {
  records: VendorRecord[]
  total: number
  totalUnfiltered: number
  summary: ExternalTrustIntelligence['vendors']['summary']
  distribution: ExternalTrustIntelligence['vendors']['distribution']
  evidenceRequests: EvidenceRequestRecord[]
  persistenceAvailable: boolean
  filters: { owners: string[]; categories: string[] }
}

export type EcosystemPayload = Envelope & ExternalTrustIntelligence['ecosystem'] & {
  focus: string | null
  blastRadius: BlastRadiusResult | null
  dependencyChain: DependencyChainStep[]
}

export type TrustPayload = Envelope & ExternalTrustIntelligence['trust']

export type LabPayload = Envelope & ExternalTrustIntelligence['lab']

interface UseExternalTrustResult<T> {
  data: T | null
  state: TrustLoadState
  error: string | null
  live: boolean
  lastGoodAt: string | null
  refresh: (force?: boolean) => Promise<void>
}

function useTrustEndpoint<T>(path: string, query = '', stream = true): UseExternalTrustResult<T> {
  const { session, user } = useAuth()
  const token = session?.access_token

  const [data, setData] = useState<T | null>(null)
  const [state, setState] = useState<TrustLoadState>('loading')
  const [error, setError] = useState<string | null>(null)
  const [live, setLive] = useState(false)
  const [lastGoodAt, setLastGoodAt] = useState<string | null>(null)
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false }
  }, [])

  const refresh = useCallback(async (force = false) => {
    if (!token) return
    setState((current) => (current === 'success' ? current : 'loading'))
    try {
      const separator = query ? (query.startsWith('?') ? '&' : '?') : '?'
      const suffix = `${query}${force ? `${separator}refresh=1` : ''}`
      const response = await fetch(`/api/v1/external-trust${path}${suffix}`, {
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      })
      const payload = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`)
      if (!mounted.current) return
      setData(payload.data as T)
      setLastGoodAt((payload.data as Envelope)?.generatedAt ?? null)
      setState('success')
      setError(null)
    } catch (err) {
      if (!mounted.current) return
      // The previous snapshot is retained deliberately — an error must never
      // render as "no dependencies" or "no findings".
      setError(err instanceof Error ? err.message : 'External trust data unavailable')
      setState('error')
    }
  }, [token, path, query])

  useEffect(() => {
    if (!token || !user) return
    void refresh()
  }, [token, user, refresh])

  useEffect(() => {
    if (!token || !stream) return
    let retry: ReturnType<typeof setTimeout> | undefined
    let disposed = false

    const connect = () => {
      if (disposed) return
      const source = new EventSource(`/api/v1/external-trust/stream?token=${encodeURIComponent(token)}`)
      source.onopen = () => { if (!disposed) setLive(true) }
      source.onerror = () => {
        setLive(false)
        source.close()
        if (!disposed) retry = setTimeout(connect, 15_000)
      }
      // The stream carries the full snapshot; each page re-reads its own
      // projection so server-side filtering and focus stay authoritative.
      source.addEventListener('external-trust-update', () => { void refresh() })
      source.addEventListener('external-trust-error', (event) => {
        try {
          const parsed = JSON.parse((event as MessageEvent).data) as { message?: string }
          if (mounted.current) setError(parsed.message || 'External trust stream error')
        } catch { /* ignore malformed frame */ }
      })
      return source
    }

    const source = connect()
    return () => {
      disposed = true
      if (retry) clearTimeout(retry)
      source?.close()
      setLive(false)
    }
  }, [token, stream, refresh])

  return { data, state, error, live, lastGoodAt, refresh }
}

export function useVendorReadiness(query = '') {
  return useTrustEndpoint<VendorPayload>('/vendors', query)
}

export function useEcosystemMap(focus: string | null) {
  return useTrustEndpoint<EcosystemPayload>('/ecosystem', focus ? `?focus=${encodeURIComponent(focus)}` : '')
}

export function useTrustChains() {
  return useTrustEndpoint<TrustPayload>('/trust')
}

export function useHybridLab() {
  return useTrustEndpoint<LabPayload>('/lab')
}

/* ------------------------------------------------------------------ */
/* Write actions                                                       */
/* ------------------------------------------------------------------ */

async function post<T>(path: string, token: string | undefined, body: unknown, method: 'POST' | 'PATCH' = 'POST'): Promise<T> {
  if (!token) throw new Error('Not authenticated')
  const response = await fetch(`/api/v1/external-trust${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  })
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) {
    const issues = payload?.error?.issues as Array<{ message: string }> | undefined
    throw new Error(issues?.length ? issues.map((issue) => issue.message).join(' ') : payload?.error?.message || `HTTP ${response.status}`)
  }
  return payload.data as T
}

export function useExternalTrustActions() {
  const { session } = useAuth()
  const token = session?.access_token

  const requestEvidence = useCallback(
    (vendorId: string, body: { requestType: string; dueAt?: string; owner?: string; notes?: string }) =>
      post<unknown>(`/vendors/${encodeURIComponent(vendorId)}/evidence-requests`, token, body),
    [token],
  )

  const updateEvidenceRequest = useCallback(
    (id: string, body: Record<string, unknown>) =>
      post<unknown>(`/evidence-requests/${encodeURIComponent(id)}`, token, body, 'PATCH'),
    [token],
  )

  // The API maps the stored row through `toExperimentRecord`, so a freshly-run
  // experiment is the same ExperimentRecord the history list holds.
  const runExperiment = useCallback(
    (body: { targetId: string; executionMode: string; configuration?: Record<string, string> }) =>
      post<{ experiment: ExperimentRecord; persisted: boolean; persistenceNote?: string }>(
        '/lab/experiments', token, body,
      ),
    [token],
  )

  const generateEvidence = useCallback(
    (experimentId: string) =>
      post<{ evidenceId: string; disclaimer: string }>(`/lab/experiments/${encodeURIComponent(experimentId)}/evidence`, token, {}),
    [token],
  )

  const loadRecommendation = useCallback(
    async (targetId: string) => {
      if (!token) throw new Error('Not authenticated')
      const response = await fetch(`/api/v1/external-trust/lab/targets/${encodeURIComponent(targetId)}/recommendation`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      const payload = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`)
      return payload.data as { target: ExperimentTarget; observed: { algorithms: string[]; protocols: string[] }; recommended: Record<string, string> }
    },
    [token],
  )

  return { requestEvidence, updateEvidenceRequest, runExperiment, generateEvidence, loadRecommendation }
}

export type { Readiness }
