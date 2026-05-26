import { useState, useEffect, useCallback, useRef } from 'react'
import { useAuth } from '@/contexts/auth-context'
import { supabase } from '@/lib/supabase'

export interface DashboardSummary {
  quantumRiskScore: number
  riskBand: string
  riskTrend: number
  vulnerableAssetsCount: number
  newVulnerableAssets: number
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
  severity: 'critical' | 'warning' | 'info' | 'success'
  eventType: string
  message: string
  assetId: string | null
  resourceName: string | null
  resourceType: string | null
  metadata: Record<string, unknown>
  isRead: boolean
}

export interface ExposureNode {
  id: string
  name: string
  type: string
  environment: string
  criticality: string
  status: string
  riskScore: number
  color: string
}

export interface ExposureEdge {
  source: string
  target: string
  type: string
}

export interface ExposureMap {
  nodes: ExposureNode[]
  edges: ExposureEdge[]
}

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
  priority: number
  category: string
  title: string
  description: string
  assetId: string | null
  action: string
  estimatedEffort: string
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

export type LoadingState = 'loading' | 'success' | 'error' | 'offline'

export function useDashboard() {
  const { session, user } = useAuth()
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [exposureMap, setExposureMap] = useState<ExposureMap>({ nodes: [], edges: [] })
  const [activities, setActivities] = useState<ActivityItem[]>([])
  const [recommendations, setRecommendations] = useState<Recommendation[]>([])
  const [health, setHealth] = useState<HealthStatus | null>(null)
  const [summaryState, setSummaryState] = useState<LoadingState>('loading')
  const [eventsState, setEventsState] = useState<LoadingState>('loading')
  const [mapState, setMapState] = useState<LoadingState>('loading')
  const [activityState, setActivityState] = useState<LoadingState>('loading')
  const [recommendationsState, setRecommendationsState] = useState<LoadingState>('loading')
  const [lastSyncAt, setLastSyncAt] = useState<string | null>(null)
  const [sseConnected, setSseConnected] = useState(false)
  const eventSourcesRef = useRef<EventSource[]>([])
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const token = session?.access_token

  const apiHeaders = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  }

  const fetchSummary = useCallback(async () => {
    if (!token) return
    setSummaryState('loading')
    try {
      const res = await fetch('/api/v1/dashboard/summary', { headers: apiHeaders })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const json = await res.json()
      setSummary(json.data)
      setSummaryState('success')
      setLastSyncAt(new Date().toISOString())
    } catch (err) {
      console.error('Failed to fetch dashboard summary:', err)
      setSummaryState(prev => prev === 'success' ? 'offline' : 'error')
    }
  }, [token])

  const fetchEvents = useCallback(async () => {
    if (!token) return
    setEventsState('loading')
    try {
      const res = await fetch('/api/v1/dashboard/events?limit=50', { headers: apiHeaders })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const json = await res.json()
      setEvents(json.data?.events || [])
      setEventsState('success')
    } catch (err) {
      console.error('Failed to fetch security events:', err)
      setEventsState(prev => prev === 'success' ? 'offline' : 'error')
    }
  }, [token])

  const fetchExposureMap = useCallback(async () => {
    if (!token) return
    setMapState('loading')
    try {
      const res = await fetch('/api/v1/dashboard/exposure-map', { headers: apiHeaders })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const json = await res.json()
      setExposureMap(json.data || { nodes: [], edges: [] })
      setMapState('success')
    } catch (err) {
      console.error('Failed to fetch exposure map:', err)
      setMapState(prev => prev === 'success' ? 'offline' : 'error')
    }
  }, [token])

  const fetchActivity = useCallback(async () => {
    if (!token) return
    setActivityState('loading')
    try {
      const res = await fetch('/api/v1/dashboard/activity?limit=20', { headers: apiHeaders })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const json = await res.json()
      setActivities(json.data?.activities || [])
      setActivityState('success')
    } catch (err) {
      console.error('Failed to fetch activity:', err)
      setActivityState(prev => prev === 'success' ? 'offline' : 'error')
    }
  }, [token])

  const fetchRecommendations = useCallback(async () => {
    if (!token) return
    setRecommendationsState('loading')
    try {
      const res = await fetch('/api/v1/dashboard/recommendations', { headers: apiHeaders })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const json = await res.json()
      setRecommendations(json.data?.recommendations || [])
      setRecommendationsState('success')
    } catch (err) {
      console.error('Failed to fetch recommendations:', err)
      setRecommendationsState(prev => prev === 'success' ? 'offline' : 'error')
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

  const refreshAll = useCallback(() => {
    fetchSummary()
    fetchEvents()
    fetchExposureMap()
    fetchActivity()
    fetchRecommendations()
    fetchHealth()
  }, [fetchSummary, fetchEvents, fetchExposureMap, fetchActivity, fetchRecommendations, fetchHealth])

  const queueRefreshAll = useCallback(() => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current)
    refreshTimerRef.current = setTimeout(() => {
      refreshTimerRef.current = null
      refreshAll()
    }, 250)
  }, [refreshAll])

  // Initial data load
  useEffect(() => {
    if (!token || !user) return
    refreshAll()
  }, [token, user, refreshAll])

  // Auto-refresh every 30 seconds
  useEffect(() => {
    if (!token) return
    const interval = setInterval(() => {
      fetchSummary()
      fetchHealth()
      fetchEvents()
    }, 30000)
    return () => clearInterval(interval)
  }, [token, fetchSummary, fetchHealth, fetchEvents])

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
        .subscribe()
      channels.push(channel)
    }

    return () => {
      for (const channel of channels) {
        supabase.removeChannel(channel)
      }
    }
  }, [user, queueRefreshAll])

  // SSE connection for real-time metric pushes (fallback for complex updates)
  useEffect(() => {
    if (!token) return

    const closeStreams = () => {
      for (const stream of eventSourcesRef.current) stream.close()
      eventSourcesRef.current = []
      setSseConnected(false)
    }

    const connectSSE = () => {
      closeStreams()
      const metricsStream = new EventSource(`/api/v1/metrics/stream?token=${encodeURIComponent(token)}`)
      const scannerStream = new EventSource(`/api/v1/scanner/intelligence/stream?token=${encodeURIComponent(token)}`)
      const vaultStream = new EventSource(`/api/v1/vault/share/events?token=${encodeURIComponent(token)}`)
      eventSourcesRef.current = [metricsStream, scannerStream, vaultStream]

      const markOpen = () => setSseConnected(true)
      const reconnect = () => {
        setSseConnected(false)
        closeStreams()
        if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current)
        reconnectTimerRef.current = setTimeout(connectSSE, 10000)
      }

      metricsStream.onopen = markOpen
      scannerStream.onopen = markOpen
      vaultStream.onopen = markOpen
      metricsStream.onerror = reconnect
      scannerStream.onerror = reconnect
      vaultStream.onerror = reconnect

      metricsStream.addEventListener('metrics-update', queueRefreshAll)
      metricsStream.addEventListener('runtime-crypto-update', queueRefreshAll)
      metricsStream.addEventListener('scan-complete', queueRefreshAll)
      scannerStream.addEventListener('scanner-intelligence', queueRefreshAll)
      scannerStream.addEventListener('scanner-error', queueRefreshAll)
      vaultStream.addEventListener('failed_attempt', queueRefreshAll)
      vaultStream.addEventListener('link_destroyed', queueRefreshAll)
    }

    connectSSE()
    return () => {
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current)
      closeStreams()
    }
  }, [token, queueRefreshAll])

  useEffect(() => () => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current)
    if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current)
    for (const stream of eventSourcesRef.current) stream.close()
  }, [])

  return {
    summary,
    events,
    exposureMap,
    activities,
    recommendations,
    health,
    summaryState,
    eventsState,
    mapState,
    activityState,
    recommendationsState,
    lastSyncAt,
    sseConnected,
    refreshAll,
    fetchSummary,
    fetchEvents,
  }
}
