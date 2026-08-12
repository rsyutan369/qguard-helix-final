import { useCallback, useEffect, useRef, useState } from 'react'
import { useAuth } from '@/contexts/auth-context'
import type { CryptoAgilityIntelligence } from '@/lib/crypto-agility/agility-intelligence'

/**
 * useCryptoAgility — live Crypto Agility Command Center™ state.
 *
 * One JSON fetch on mount, then a Server-Sent Events subscription for updates.
 * The server caches the computation per tenant (15s TTL) and pushes on a 20s
 * cadence, so many open dashboards collapse onto one computation.
 *
 * Load states are explicit so the UI can distinguish "loading", "no evidence"
 * and "request failed" — a failure must never render as zeros.
 */

export type AgilityLoadState = 'loading' | 'success' | 'error'

export interface UseCryptoAgilityResult {
  data: CryptoAgilityIntelligence | null
  state: AgilityLoadState
  error: string | null
  live: boolean
  /** Last snapshot kept across a failed refresh, so "View Last Successful Assessment" is real. */
  lastGoodAt: string | null
  refresh: (force?: boolean) => Promise<void>
}

export function useCryptoAgility(streamEnabled = true): UseCryptoAgilityResult {
  const { session, user } = useAuth()
  const token = session?.access_token

  const [data, setData] = useState<CryptoAgilityIntelligence | null>(null)
  const [state, setState] = useState<AgilityLoadState>('loading')
  const [error, setError] = useState<string | null>(null)
  const [live, setLive] = useState(false)
  const [lastGoodAt, setLastGoodAt] = useState<string | null>(null)
  const sourceRef = useRef<EventSource | null>(null)
  const mountedRef = useRef(true)

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
    }
  }, [])

  const refresh = useCallback(
    async (force = false) => {
      if (!token) return
      setState((current) => (current === 'success' ? current : 'loading'))
      try {
        const response = await fetch(`/api/v1/crypto-agility${force ? '?refresh=1' : ''}`, {
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        })
        const payload = await response.json().catch(() => ({}))
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`)
        if (!mountedRef.current) return
        setData(payload.data as CryptoAgilityIntelligence)
        setLastGoodAt((payload.data as CryptoAgilityIntelligence)?.generatedAt ?? null)
        setState('success')
        setError(null)
      } catch (err) {
        if (!mountedRef.current) return
        // The previous snapshot is deliberately retained — an error must not
        // silently blank the page into zeros.
        setError(err instanceof Error ? err.message : 'Crypto agility data unavailable')
        setState('error')
      }
    },
    [token],
  )

  useEffect(() => {
    if (!token || !user) return
    void refresh()
  }, [token, user, refresh])

  useEffect(() => {
    if (!token || !streamEnabled) return
    let retry: ReturnType<typeof setTimeout> | undefined
    let disposed = false

    const connect = () => {
      if (disposed) return
      const source = new EventSource(`/api/v1/crypto-agility/stream?token=${encodeURIComponent(token)}`)
      sourceRef.current = source

      source.onopen = () => {
        if (!disposed) setLive(true)
      }
      source.onerror = () => {
        setLive(false)
        source.close()
        if (!disposed) retry = setTimeout(connect, 15_000)
      }
      source.addEventListener('agility-update', (event) => {
        try {
          const parsed = JSON.parse((event as MessageEvent).data) as CryptoAgilityIntelligence
          if (!mountedRef.current) return
          setData(parsed)
          setLastGoodAt(parsed.generatedAt)
          setState('success')
          setError(null)
        } catch {
          /* malformed frame — keep the previous snapshot */
        }
      })
      source.addEventListener('agility-error', (event) => {
        try {
          const parsed = JSON.parse((event as MessageEvent).data) as { message?: string }
          if (mountedRef.current) setError(parsed.message || 'Crypto agility stream error')
        } catch {
          /* ignore */
        }
      })
    }

    connect()
    return () => {
      disposed = true
      if (retry) clearTimeout(retry)
      sourceRef.current?.close()
      sourceRef.current = null
      setLive(false)
    }
  }, [token, streamEnabled])

  return { data, state, error, live, lastGoodAt, refresh }
}

export default useCryptoAgility
