'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { useAuth } from '@/contexts/auth-context'
import { openAuthenticatedEventStream } from '@/lib/authenticated-event-stream'
import { applyEvents, emptyGraph, liveFrameLength, type LiveGraphState } from '@/lib/live-scan/graph-reducer'
import type { LiveEvent, RunListItem, RunMeta } from '@/lib/live-scan/types'

/**
 * Real Time Scanning — run lifecycle + live stream.
 *
 * Snapshot then stream, with no gap: the snapshot returns the full event log
 * and its head sequence, and the stream is opened `after=<head>`. Reconnects
 * resume from the last APPLIED sequence, and the reducer ignores any sequence
 * it has already applied, so overlap is harmless and a gap is impossible.
 *
 * Evidence-only frames travel with the next visible discovery. Each new card
 * gets its own render even when multiple observations arrive in one SSE chunk.
 */

export type StreamHealth = 'idle' | 'connecting' | 'live' | 'reconnecting' | 'ended' | 'error'

export interface StartScanInput {
  name: string
  targets: string[]
  concurrency: number
  targetTimeoutSec: number
  expiringWithinDays: number
}

export interface ScanLimits {
  maxTargets: number
  concurrency: { min: number; max: number; default: number }
  targetTimeoutSec: { min: number; max: number; default: number }
  expiringWithinDays: { min: number; max: number; default: number }
}

const BASE = '/api/v1/scanner/live'
const FLUSH_MS = 75

async function readError(response: Response): Promise<string> {
  try {
    const body = await response.json()
    return body?.error?.message || `Request failed (${response.status})`
  } catch {
    return `Request failed (${response.status})`
  }
}

export function useLiveScan(initialRunId: string | null) {
  const { session } = useAuth()
  const token = session?.access_token ?? null

  const [runId, setRunId] = useState<string | null>(initialRunId)
  const [graph, setGraph] = useState<LiveGraphState>(() => emptyGraph())
  const [events, setEvents] = useState<LiveEvent[]>([])
  const [health, setHealth] = useState<StreamHealth>('idle')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [runs, setRuns] = useState<RunListItem[]>([])
  const [limits, setLimits] = useState<ScanLimits | null>(null)
  const [lastHeartbeat, setLastHeartbeat] = useState<string | null>(null)

  const graphRef = useRef(graph)
  const bufferRef = useRef<LiveEvent[]>([])
  const flushTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const request = useCallback(async (path: string, init?: RequestInit) => {
    if (!token) throw new Error('Sign in to use Real Time Scanning.')
    const response = await fetch(`${BASE}${path}`, {
      ...init,
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
      cache: 'no-store',
    })
    if (!response.ok) throw new Error(await readError(response))
    return response.json()
  }, [token])

  const flush = useCallback(function drain() {
    flushTimer.current = null
    const pending = bufferRef.current
    const known = graphRef.current
    const batch = pending.splice(0, liveFrameLength(known, pending))
    if (!batch.length) return
    const next = applyEvents(known, batch)
    graphRef.current = next
    setGraph(next)
    // The run is over once its terminal event is applied, even before the
    // server closes the stream (it does so only after persisting the record).
    if (batch.some((event) => event.type === 'scan.completed' || event.type === 'scan.failed' || event.type === 'scan.cancelled')) {
      setHealth('ended')
    }
    setEvents((current) => {
      const known = new Set(current.map((event) => event.seq))
      const fresh = batch.filter((event) => !known.has(event.seq))
      return fresh.length ? [...current, ...fresh].sort((a, b) => a.seq - b.seq) : current
    })
    if (pending.length) flushTimer.current = setTimeout(drain, FLUSH_MS)
  }, [])

  const enqueue = useCallback((event: LiveEvent) => {
    bufferRef.current.push(event)
    if (!flushTimer.current) flushTimer.current = setTimeout(flush, FLUSH_MS)
  }, [flush])

  const refreshRuns = useCallback(async () => {
    try {
      const body = await request('/runs')
      setRuns(body.runs ?? [])
      setLimits(body.limits ?? null)
    } catch (err) {
      setError((err as Error).message)
    }
  }, [request])

  /* ---------------------------- snapshot + stream ---------------------------- */

  useEffect(() => {
    if (!token || !runId) return
    let cancelled = false
    let close: (() => void) | null = null
    let retry: ReturnType<typeof setTimeout> | null = null
    let attempt = 0

    const connect = (after = graphRef.current.lastSeq) => {
      if (cancelled) return
      setHealth(attempt ? 'reconnecting' : 'connecting')
      close = openAuthenticatedEventStream(`${BASE}/runs/${encodeURIComponent(runId)}/stream?after=${after}`, token, {
        onOpen: () => { attempt = 0; setHealth('live') },
        onEvent: (name, data) => {
          if (name === 'live') {
            try { enqueue(JSON.parse(data) as LiveEvent) } catch { /* malformed frame */ }
          } else if (name === 'heartbeat') {
            setLastHeartbeat(new Date().toISOString())
          } else if (name === 'end') {
            ended = true
            if (!bufferRef.current.length) setHealth('ended')
          }
        },
        onError: () => {
          if (cancelled) return
          if (ended) return
          attempt += 1
          setHealth('reconnecting')
          retry = setTimeout(() => connect(), Math.min(15_000, 1_000 * 2 ** Math.min(attempt - 1, 4)))
        },
      })
    }
    let ended = false

    ;(async () => {
      setLoading(true)
      setError(null)
      try {
        const body = await request(`/runs/${encodeURIComponent(runId)}`)
        if (cancelled) return
        const snapshot = body.events as LiveEvent[]
        const fresh = applyEvents(emptyGraph(), snapshot)
        const workerAlive = (body.run as RunMeta & { workerAlive?: boolean }).workerAlive
        if (workerAlive && graphRef.current.lastSeq === 0) {
          for (const event of snapshot) enqueue(event)
        } else {
          graphRef.current = fresh
          setGraph(fresh)
          setEvents(snapshot)
        }
        if (workerAlive) connect(fresh.lastSeq)
        else setHealth('ended')
      } catch (err) {
        if (!cancelled) { setError((err as Error).message); setHealth('error') }
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()

    return () => {
      cancelled = true
      close?.()
      if (retry) clearTimeout(retry)
      if (flushTimer.current) { clearTimeout(flushTimer.current); flushTimer.current = null }
      bufferRef.current = []
    }
  }, [token, runId, request, enqueue])

  useEffect(() => { if (token) void refreshRuns() }, [token, refreshRuns])
  // When a run ends, refresh history so it appears with its stored session.
  useEffect(() => { if (health === 'ended') void refreshRuns() }, [health, refreshRuns])

  /* ---------------------------- commands ---------------------------- */

  const openRun = useCallback((id: string | null) => {
    setGraph(emptyGraph())
    graphRef.current = emptyGraph()
    setEvents([])
    setHealth('idle')
    setRunId(id)
  }, [])

  const start = useCallback(async (input: StartScanInput) => {
    const body = await request('/runs', { method: 'POST', body: JSON.stringify({ ...input, authorized: true }) })
    openRun(body.run.id as string)
    void refreshRuns()
    return body.run as RunMeta
  }, [request, openRun, refreshRuns])

  const control = useCallback(async (action: 'pause' | 'resume' | 'cancel') => {
    if (!runId) return
    try {
      await request(`/runs/${encodeURIComponent(runId)}/${action}`, { method: 'POST', body: '{}' })
    } catch (err) {
      setError((err as Error).message)
    }
  }, [request, runId])

  const rescan = useCallback(async (target: string): Promise<'queued' | 'finished'> => {
    if (!runId) return 'finished'
    const response = await fetch(`${BASE}/runs/${encodeURIComponent(runId)}/rescan`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ target }),
    })
    if (response.status === 409) return 'finished'
    if (!response.ok) throw new Error(await readError(response))
    return 'queued'
  }, [runId, token])

  const download = useCallback(async (format: 'json' | 'csv') => {
    if (!runId || !token) return
    const response = await fetch(`${BASE}/runs/${encodeURIComponent(runId)}/export?format=${format}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    if (!response.ok) { setError(await readError(response)); return }
    const blob = await response.blob()
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `live-scan-${format === 'csv' ? 'findings' : 'graph'}-${runId.slice(0, 8)}.${format}`
    anchor.click()
    URL.revokeObjectURL(url)
  }, [runId, token])

  return {
    token, runId, graph, events, health, error, setError, loading, runs, limits, lastHeartbeat,
    openRun, start, control, rescan, download, refreshRuns,
  }
}
