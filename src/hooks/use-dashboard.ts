import { useState, useEffect, useCallback, useRef } from 'react'
import { useAuth } from '@/contexts/auth-context'
import { supabase } from '@/lib/supabase'

export interface DashboardSummary {
  /** Canonical 0–100, LOWER-better — same scale/direction as the executive KPI. */
  quantumRiskScore: number
  riskBand: string
  /** Canonical 0–100, HIGHER-better posture composite. */
  quantumReadinessScore: number
  readinessBand: string
  /** False = nothing measured yet; render "No baseline", never the 0. */
  hasBaseline: boolean
  riskTrend: number
  vulnerableAssetsCount: number
  /** Distinct subjects with a risk signal in the last 7 days (⊆ vulnerableAssetsCount). */
  newVulnerableAssets: number
  /** Raw signal count for the same window — what drives `riskTrend`. */
  newFindings: number
  totalCbomItems: number
  activeMigrations: number
  failedMigrations: number
  completedMigrations: number
  migrationCompletionRate: number
  criticalExposures: number
  highExposures: number
  unresolvedVulns: number
  expiringCerts: number
  totalAssets: number
  lastScanAt: string | null
  monitoringStatus: string
}

export interface SecurityEvent {
  id: string
  timestamp: string
  /** Faithful to the recorded severity — HIGH is its own tier, never folded into critical. */
  severity: 'critical' | 'high' | 'warning' | 'info' | 'success'
  eventType: string
  message: string
  assetId: string | null
  resourceName: string | null
  resourceType: string | null
  metadata: Record<string, unknown>
  isRead: boolean
}

/**
 * The exposure-map node/edge shapes are declared ONCE, in the API-contract lib.
 * They used to be re-declared here, and the two copies had already drifted
 * (`color` existed on one side only). Re-exported so existing importers of
 * `@/hooks/use-dashboard` keep working.
 */
export type { ExposureNode, ExposureNodeEvidence, ExposureEdge } from '@/lib/dashboard-service'
import type { ExposureNode, ExposureEdge } from '@/lib/dashboard-service'
import type { EstateWorkflowGraph } from '@/lib/dashboard/estate-workflow'

export interface ExposureMap {
  nodes: ExposureNode[]
  edges: ExposureEdge[]
}

export type EstateWorkflow = EstateWorkflowGraph

export interface ActivityItem {
  id: string
  type: string
  title: string
  description: string
  status: string
  timestamp: string
}

export interface Recommendation {
  id: string
  /** 1 critical · 2 high · 3 medium · 4 low. */
  priority: number
  category: string
  title: string
  description: string
  assetId: string | null
  action: string
  estimatedEffort: string
  /** Open findings (or grouped signals) this action closes. */
  findingCount?: number
  /** Where the action was derived from: 'findings', 'certificates', 'scanner_alerts', … */
  source?: string
}

export interface HealthStatus {
  status: string
  timestamp: string
  services: {
    supabase: string
    scanner: string
    migration: string
    realtime: string
  }
  version: string
}

// ---- Executive Command Center snapshot (/api/v1/dashboard/executive) ----

export interface ExecutiveKpi {
  id: string
  label: string
  value: number
  unit: string
  format: 'score' | 'count' | 'percent' | 'currency'
  direction: 'lower-better' | 'higher-better'
  target: number
  targetLabel: string
  deltaPercent: number
  trend: 'up' | 'down' | 'flat'
  /**
   * 'history' when `trend`/`sparkline` are this metric's OWN stored history;
   * 'none' when no history exists — the card then says so instead of "stable".
   */
  trendBasis?: 'history' | 'none'
  level?: string
  sparkline: number[]
  /** Real composition of the value (e.g. findings by severity), shown when there is no history. */
  breakdown?: Array<{ label: string; value: number; tone: 'critical' | 'warning' | 'good' | 'neutral' | 'info' }>
  lastUpdated: string
  route: string
  hint: string
  modeled?: boolean
  unmeasured?: boolean
}

export interface ExecutiveNarrativeFact {
  id: string
  label: string
  value: string | number
  tone: 'critical' | 'warning' | 'good' | 'neutral'
  /** 'relative-time' = `value` is an ISO timestamp to render as an age. */
  format?: 'relative-time'
  /** A planning estimate, not a measurement. */
  modeled?: boolean
  hint?: string
}

export interface PipelineStage {
  key: string
  label: string
  completion: number
  remaining: number
}

export interface ComplianceFramework {
  id: string
  name: string
  progress: number
  evidenceCount: number
  attestedEvidenceCount: number
  /** Failing + partially met requirements, as MEASURED by the governance model. */
  gaps: number
  requirementsTotal: number
  requirementsMeasured: number
  /** Measured requirements / total requirements. */
  coverage: number
  modeled: boolean
}

export interface AssetCategory {
  key: string
  label: string
  count: number
  atRisk: number
}

export interface ExecutiveSnapshot {
  generatedAt: string
  hasData: boolean
  lastAssessmentAt: string | null
  narrative: {
    posture: string
    readinessScore: number
    riskScore: number
    riskLevel: string
    hasData: boolean
    facts: ExecutiveNarrativeFact[]
    priority: { title: string; detail: string; severity: string; route: string }
    /** Which evidence sources the assessment holds — replaces the old "AI confidence" constant. */
    evidenceCoverage: { pct: number; present: number; total: number; missing: string[] }
    summary: string
  }
  kpis: ExecutiveKpi[]
  pipeline: {
    stages: PipelineStage[]
    overallCompletion: number
    remainingAssets: number
    estimatedFinishWeeks: number
    bottleneck: string
    certificationReadiness: number
  }
  compliance: { overall: number; measured: boolean; frameworks: ComplianceFramework[] }
  businessImpact: {
    modeled: boolean
    financialExposure: number
    revenueProtected: number
    missionCriticalAssets: number
    taggedCriticalAssets: number
    applicationsAtRisk: number
    applications: number
    operationalImpact: number
    estimatedDowntimeHours: number
    /** null — no stored history of the modelled exposure exists. */
    riskTrendDelta: number | null
    /** Upper-bound ROI; null when exposure or cost is not modelled. */
    projectedRoiPct: number | null
    migrationCostUsd: number
    assumptions: string
    criticalityTagged?: boolean
  }
  assetInventory: { total: number; categories: AssetCategory[] }
  threatIntel: {
    hndl: number
    legacyCrypto: number
    downgrade: number
    shadowCrypto: number
    kev: number
    cves: number
    epssMax: number
    shorAtRisk: number
    groverWeakened: number
    quantumVulnerable: number
    feeds: Array<{ id: string; title: string; severity: string; source: string; at: string }>
    hasThreatFeed: boolean
  }
  runtime: {
    events24h: number
    totalEvents: number
    queueDepth: number
    activeWorkers: number
    totalWorkers: number
    freshHeartbeats: number
    activeScans: number
    scanThroughput: number
    /** True only when runtime events exist — absence is not a clean bill of health. */
    measured: boolean
    /** True when at least one collector is enrolled, however quiet. */
    agentsEnrolled: boolean
    process: { cpuMs: number; heapUsedMb: number; rssMb: number; aggregationLatencyMs: number }
  }
  exposureGraph: {
    nodes: Array<{ id: string; label: string; type: string; environment: string; riskScore: number; posture: string; internetFacing: boolean }>
    edges: Array<{ source: string; target: string; type: string }>
  }
  riskTrend: Array<{ label: string; readiness: number; risk: number }>
  topRiskAssets: Array<{ asset: string; assetType: string; environment: string; owner: string; riskScore: number; status: string }>
  scores: Record<string, number | string>
  inventory: Record<string, number>
  recommendedActions: Array<{ id: string; title: string; detail: string; severity: string; route: string }>
}

export type LoadingState = 'loading' | 'success' | 'error' | 'offline'

export function useDashboard() {
  const { session, user } = useAuth()
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [executive, setExecutive] = useState<ExecutiveSnapshot | null>(null)
  const [events, setEvents] = useState<SecurityEvent[]>([])
  /** PQC-ready confirmations in the event window — counted, not streamed as threats. */
  const [eventsOmitted, setEventsOmitted] = useState(0)
  const [estateWorkflow, setEstateWorkflow] = useState<EstateWorkflow | null>(null)
  const estateWorkflowTextRef = useRef<string | null>(null)
  const [workflowState, setWorkflowState] = useState<LoadingState>('loading')
  const [recommendations, setRecommendations] = useState<Recommendation[]>([])
  /** Every action derived, before the endpoint's bound — so the panel can disclose it. */
  const [recommendationsTotal, setRecommendationsTotal] = useState(0)
  const [health, setHealth] = useState<HealthStatus | null>(null)
  const [summaryState, setSummaryState] = useState<LoadingState>('loading')
  const [executiveState, setExecutiveState] = useState<LoadingState>('loading')
  const [eventsState, setEventsState] = useState<LoadingState>('loading')
  const [recommendationsState, setRecommendationsState] = useState<LoadingState>('loading')
  const [lastSyncAt, setLastSyncAt] = useState<string | null>(null)
  /*
   * LIVE means a channel is open NOW. This used to be a boolean set true on the
   * first SUBSCRIBED/onopen and never set false again, so "Live" and "SSE up"
   * survived every later disconnect. Each channel now registers and
   * deregisters itself; the indicator is true only while at least one is open.
   */
  const liveChannelsRef = useRef<Set<string>>(new Set())
  const [sseConnected, setSseConnected] = useState(false)
  const markChannel = useCallback((id: string, open: boolean) => {
    const channels = liveChannelsRef.current
    if (open) channels.add(id)
    else channels.delete(id)
    setSseConnected(channels.size > 0)
  }, [])
  const eventSourcesRef = useRef<EventSource[]>([])
  const sseReconnectTimersRef = useRef<ReturnType<typeof setTimeout>[]>([])
  // Coalesced, single-flight refresh control. Automatic triggers (30s poll,
  // Supabase realtime, SSE signals) all funnel through a throttle so bursts
  // collapse to at most one full refresh per MIN_AUTO_REFRESH_MS, and a refresh
  // never overlaps itself — this removes the reload storm that kept flipping the
  // dashboard back into its loading state.
  const refreshInFlightRef = useRef(false)
  const refreshPendingRef = useRef(false)
  const lastRefreshAtRef = useRef(0)
  const throttleTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const token = session?.access_token

  const apiHeaders = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  }

  const fetchSummary = useCallback(async () => {
    if (!token) return
    setSummaryState(current => current === 'success' || current === 'offline' ? current : 'loading')
    try {
      const res = await fetch('/api/v1/dashboard/summary', { headers: apiHeaders })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const json = await res.json()
      setSummary(json.data)
      setSummaryState('success')
      setLastSyncAt(new Date().toISOString())
    } catch (err) {
      console.error('Failed to fetch dashboard summary:', err)
      setSummaryState(prev => prev === 'success' || prev === 'offline' ? 'offline' : 'error')
    }
  }, [token])

  const fetchExecutive = useCallback(async () => {
    if (!token) return
    setExecutiveState(current => current === 'success' || current === 'offline' ? current : 'loading')
    try {
      const res = await fetch('/api/v1/dashboard/executive', { headers: apiHeaders })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const json = await res.json()
      setExecutive(json.data)
      setExecutiveState('success')
    } catch (err) {
      console.error('Failed to fetch executive snapshot:', err)
      setExecutiveState(prev => prev === 'success' || prev === 'offline' ? 'offline' : 'error')
    }
  }, [token])

  const fetchEvents = useCallback(async () => {
    if (!token) return
    setEventsState(current => current === 'success' || current === 'offline' ? current : 'loading')
    try {
      const res = await fetch('/api/v1/dashboard/events?limit=50', { headers: apiHeaders })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const json = await res.json()
      setEvents(json.data?.events || [])
      setEventsOmitted(Number(json.data?.pqcConfirmationsOmitted) || 0)
      setEventsState('success')
    } catch (err) {
      console.error('Failed to fetch security events:', err)
      setEventsState(prev => prev === 'success' || prev === 'offline' ? 'offline' : 'error')
    }
  }, [token])

  /**
   * The Estate Exposure Workflow graph.
   *
   * Built SERVER-side from the canonical finding set and CBOM the KPI cards
   * count, so the workflow and the numbers above it cannot disagree.
   */
  const fetchEstateWorkflow = useCallback(async () => {
    if (!token) return
    setWorkflowState(current => current === 'success' || current === 'offline' ? current : 'loading')
    try {
      const res = await fetch('/api/v1/dashboard/estate-workflow', { headers: apiHeaders })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const text = await res.text()
      // Keep the SAME object when nothing changed. Realtime events refetch this
      // every few seconds while a migration runs; a fresh-but-identical object
      // made the workflow canvas discard its layout, re-run the physics and
      // snap the view back each time — the map never settled and Fit was
      // overwritten within seconds. The payload is deterministic (certificate
      // days-left is its only clock-derived value), so equal text = equal graph.
      if (text !== estateWorkflowTextRef.current) {
        estateWorkflowTextRef.current = text
        setEstateWorkflow(JSON.parse(text).data || null)
      }
      setWorkflowState('success')
    } catch (err) {
      console.error('Failed to fetch estate workflow:', err)
      setWorkflowState(prev => prev === 'success' || prev === 'offline' ? 'offline' : 'error')
    }
  }, [token])

  const fetchRecommendations = useCallback(async () => {
    if (!token) return
    setRecommendationsState(current => current === 'success' || current === 'offline' ? current : 'loading')
    try {
      const res = await fetch('/api/v1/dashboard/recommendations', { headers: apiHeaders })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const json = await res.json()
      const list: Recommendation[] = json.data?.recommendations || []
      setRecommendations(list)
      setRecommendationsTotal(Number(json.data?.total) || list.length)
      setRecommendationsState('success')
    } catch (err) {
      console.error('Failed to fetch recommendations:', err)
      setRecommendationsState(prev => prev === 'success' || prev === 'offline' ? 'offline' : 'error')
    }
  }, [token])

  const fetchHealth = useCallback(async () => {
    if (!token) return
    try {
      const res = await fetch('/api/v1/dashboard/health', { headers: apiHeaders })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const json = await res.json()
      setHealth(json.data)
    } catch (err) {
      console.error('Failed to fetch health:', err)
      setHealth(null)
    }
  }, [token])

  // Single-flight core: runs one full refresh at a time. If triggers arrive
  // while a refresh is in flight, exactly one trailing refresh is queued (so a
  // burst of realtime events never fans out into overlapping heavy refetches).
  const runRefresh = useCallback(async () => {
    if (refreshInFlightRef.current) {
      refreshPendingRef.current = true
      return
    }
    refreshInFlightRef.current = true
    lastRefreshAtRef.current = Date.now()
    try {
      // Only what /dashboard renders. The exposure map and activity feed were
      // fetched on every refresh and never drawn — two extra estate reads per
      // 30s tick for nothing.
      await Promise.all([
        fetchSummary(), fetchExecutive(), fetchEvents(),
        fetchEstateWorkflow(), fetchRecommendations(), fetchHealth(),
      ])
    } finally {
      refreshInFlightRef.current = false
      if (refreshPendingRef.current) {
        refreshPendingRef.current = false
        void runRefresh()
      }
    }
  }, [fetchSummary, fetchExecutive, fetchEvents, fetchEstateWorkflow, fetchRecommendations, fetchHealth])

  // User-initiated (header refresh button / error reconnect): refresh now.
  const refreshAll = useCallback(() => { void runRefresh() }, [runRefresh])

  // Automatic triggers: coalesce + throttle to at most one refresh every 5s.
  const queueRefreshAll = useCallback(() => {
    if (throttleTimerRef.current) return
    const wait = Math.max(0, 5000 - (Date.now() - lastRefreshAtRef.current))
    throttleTimerRef.current = setTimeout(() => {
      throttleTimerRef.current = null
      void runRefresh()
    }, wait)
  }, [runRefresh])

  // Initial data load
  useEffect(() => {
    if (!token || !user) return
    refreshAll()
  }, [token, user, refreshAll])

  // Auto-refresh every 30 seconds (through the single-flight throttle).
  useEffect(() => {
    if (!token) return
    const interval = setInterval(() => { queueRefreshAll() }, 30000)
    return () => clearInterval(interval)
  }, [token, queueRefreshAll])

  // Supabase Realtime subscriptions for live updates
  useEffect(() => {
    if (!user) return

    const channels: ReturnType<typeof supabase.channel>[] = []

    const tables = [
      'assets',
      'asset_relationships',
      'crypto_inventory',
      'crypto_exposures',
      'vulnerabilities',
      'pqc_scan_sessions',
      'pqc_scan_results',
      'scanner_evidence',
      'scanner_alerts',
      'scanner_agents',
      'scanner_agent_policies',
      'runtime_crypto_events',
      'certificates',
      'generated_keys',
      'migration_jobs',
      'migration_events',
      'security_events',
      'user_security_events',
      'auth_events',
      'audit_logs',
      'vault_files',
      'vault_audit_logs',
      'compliance_evidence',
      'connector_accounts',
      'agent_heartbeats',
      'qrng_events',
    ]

    for (const tableName of tables) {
      const channel = supabase
        .channel(`dashboard-${tableName}`)
        .on(
          'postgres_changes',
          { event: '*', schema: 'public', table: tableName, filter: `user_id=eq.${user.id}` },
          queueRefreshAll,
        )
        .subscribe((status) => {
          // The realtime websocket is the dashboard's true "live" channel. Open
          // on SUBSCRIBED; closed on any terminal status.
          if (status === 'SUBSCRIBED') markChannel(`realtime:${tableName}`, true)
          else if (status === 'CLOSED' || status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') markChannel(`realtime:${tableName}`, false)
        })
      channels.push(channel)
    }

    return () => {
      for (const channel of channels) {
        supabase.removeChannel(channel)
      }
      for (const tableName of tables) markChannel(`realtime:${tableName}`, false)
    }
  }, [user, queueRefreshAll, markChannel])

  // SSE for change-driven signals. The dashboard-/metrics- streams were REMOVED:
  // they emitted an unconditional "*-update" every 8s (a hidden fast poll) that
  // forced a full 7-endpoint refetch, and — together with the other persistent
  // EventSources — saturated the browser's per-origin HTTP/1.1 connection limit
  // (~6), starving the real data fetches and keeping the page stuck loading.
  // Periodic freshness now comes from the 30s poll; change-driven freshness from
  // the Supabase realtime websocket above. Each remaining stream reconnects on
  // its OWN exponential backoff, so a stream the tenant isn't entitled to backs
  // off alone instead of tearing down the healthy streams every 10s.
  useEffect(() => {
    if (!token) return
    const tokenParam = encodeURIComponent(token)
    const specs: Array<{ url: string; events: string[] }> = [
      { url: `/api/v1/scanner/intelligence/stream?token=${tokenParam}`, events: ['scanner-intelligence'] },
      { url: `/api/v1/agent-scanner/stream?token=${tokenParam}`, events: ['agent-scanner-sync'] },
      { url: `/api/v1/vault/share/events?token=${tokenParam}`, events: ['failed_attempt', 'link_destroyed'] },
    ]

    let cancelled = false
    eventSourcesRef.current = []
    sseReconnectTimersRef.current = []

    const connect = (spec: { url: string; events: string[] }, attempt: number) => {
      if (cancelled) return
      const es = new EventSource(spec.url)
      eventSourcesRef.current.push(es)
      es.onopen = () => markChannel(`sse:${spec.url}`, true)
      for (const ev of spec.events) es.addEventListener(ev, queueRefreshAll)
      es.onerror = () => {
        markChannel(`sse:${spec.url}`, false)
        es.close()
        eventSourcesRef.current = eventSourcesRef.current.filter((s) => s !== es)
        if (cancelled) return
        const delay = Math.min(60000, 5000 * 2 ** Math.min(attempt, 4))
        const timer = setTimeout(() => connect(spec, attempt + 1), delay)
        sseReconnectTimersRef.current.push(timer)
      }
    }

    for (const spec of specs) connect(spec, 0)

    return () => {
      cancelled = true
      for (const stream of eventSourcesRef.current) stream.close()
      eventSourcesRef.current = []
      for (const timer of sseReconnectTimersRef.current) clearTimeout(timer)
      sseReconnectTimersRef.current = []
      for (const spec of specs) markChannel(`sse:${spec.url}`, false)
    }
  }, [token, queueRefreshAll, markChannel])

  useEffect(() => () => {
    if (throttleTimerRef.current) clearTimeout(throttleTimerRef.current)
    for (const timer of sseReconnectTimersRef.current) clearTimeout(timer)
    for (const stream of eventSourcesRef.current) stream.close()
  }, [])

  return {
    summary,
    executive,
    events,
    eventsOmitted,
    estateWorkflow,
    workflowState,
    recommendations,
    recommendationsTotal,
    health,
    summaryState,
    executiveState,
    eventsState,
    recommendationsState,
    lastSyncAt,
    sseConnected,
    refreshAll,
    fetchSummary,
    fetchExecutive,
    fetchEvents,
  }
}
