const AGENT_ONLINE_WINDOW_MS = 15 * 60 * 1000
const HEARTBEAT_FRESH_WINDOW_MS = 5 * 60 * 1000

type SourceRows = {
  assets?: any[]
  scannerAgents?: any[]
  connectorAccounts?: any[]
  agentHeartbeats?: any[]
  scanSessions?: any[]
  runtimeEvents?: any[]
  scannerEvidence?: any[]
  scannerAlerts?: any[]
  scanResults?: any[]
  cryptoInventory?: any[]
  cryptoExposures?: any[]
  securityEvents?: any[]
  generatedKeys?: any[]
  certificates?: any[]
  qrngEvents?: any[]
  vaultAuditLogs?: any[]
  vulnerabilities?: any[]
  auditLogs?: any[]
  authEvents?: any[]
  userSecurityEvents?: any[]
  userSessions?: any[]
  userDevices?: any[]
  complianceEvidence?: any[]
  migrationJobs?: any[]
}

function rows(value: any[] | undefined) {
  return Array.isArray(value) ? value : []
}

function recordOf(value: unknown): Record<string, unknown> {
  if (typeof value === 'string' && value.trim()) {
    try {
      const parsed = JSON.parse(value)
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {}
    } catch {
      return {}
    }
  }
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

function textValue(value: unknown, fallback = '') {
  return typeof value === 'string' && value.trim() ? value.trim() : fallback
}

function dateMs(value: unknown) {
  const ms = new Date(String(value || '')).getTime()
  return Number.isFinite(ms) ? ms : 0
}

function latestDate(...values: unknown[]) {
  const valid = values.map(dateMs).filter(Boolean).sort((a, b) => b - a)
  return valid.length ? new Date(valid[0]).toISOString() : null
}

function isFresh(value: unknown, windowMs: number) {
  const ms = dateMs(value)
  return ms > 0 && Date.now() - ms <= windowMs
}

function assetIsActive(asset: any) {
  const metadata = recordOf(asset?.metadata)
  const status = textValue(asset?.status, textValue(metadata.status, 'active')).toLowerCase()
  return !/(archived|deleted|decommissioned|disabled|inactive|retired)/i.test(status)
}

function agentIsOnline(agent: any) {
  const status = textValue(agent?.status, '').toLowerCase()
  return /active|connected|healthy|online|ready|running/.test(status) || isFresh(agent?.last_seen_at || agent?.updated_at, AGENT_ONLINE_WINDOW_MS)
}

function scanStatus(row: any) {
  return textValue(row?.status, 'pending').toLowerCase()
}

function scanTimestamp(row: any) {
  return row?.completed_at || row?.started_at || row?.updated_at || row?.created_at
}

export function buildTenantTelemetrySync(input: SourceRows) {
  const assetRows = rows(input.assets)
  const agentRows = rows(input.scannerAgents)
  const heartbeatRows = rows(input.agentHeartbeats)
  const scanRows = rows(input.scanSessions)
  const scanResultRows = rows(input.scanResults)
  const activeAssets = assetRows.filter(assetIsActive).length
  const onlineAgents = agentRows.filter(agentIsOnline).length
  const freshHeartbeats = heartbeatRows.filter((row) => isFresh(row?.observed_at || row?.created_at, HEARTBEAT_FRESH_WINDOW_MS)).length
  const runningScans = scanRows.filter((row) => /^(analyzing|in_progress|pending|processing|queued|running|scheduled)$/.test(scanStatus(row))).length
  const completedScans = scanRows.filter((row) => /^(complete|completed|success|succeeded)$/.test(scanStatus(row))).length
  const failedScans = scanRows.filter((row) => /^(cancelled|error|failed|timeout)$/.test(scanStatus(row))).length

  return {
    activeAssets,
    inactiveAssets: Math.max(0, assetRows.length - activeAssets),
    onlineAgents,
    offlineAgents: Math.max(0, agentRows.length - onlineAgents),
    freshHeartbeats,
    scanSessions: scanRows.length,
    runningScans,
    completedScans,
    failedScans,
    latestScanAt: latestDate(
      ...scanRows.map(scanTimestamp),
      ...scanResultRows.map((row) => row?.created_at),
    ),
    latestAgentHeartbeatAt: latestDate(
      ...heartbeatRows.map((row) => row?.observed_at || row?.created_at),
      ...agentRows.map((row) => row?.last_seen_at || row?.updated_at),
    ),
    latestDiscoveryAt: latestDate(
      ...rows(input.runtimeEvents).map((row) => row?.observed_at || row?.created_at),
      ...rows(input.scannerEvidence).map((row) => row?.observed_at || row?.processed_at || row?.created_at),
      ...rows(input.scannerAlerts).map((row) => row?.updated_at || row?.created_at),
      ...scanResultRows.map((row) => row?.created_at),
      ...rows(input.cryptoInventory).map((row) => row?.discovered_at || row?.created_at),
      ...rows(input.cryptoExposures).map((row) => row?.updated_at || row?.created_at),
      ...rows(input.securityEvents).map((row) => row?.created_at),
      ...rows(input.generatedKeys).map((row) => row?.updated_at || row?.created_at),
      ...rows(input.certificates).map((row) => row?.updated_at || row?.created_at),
      ...rows(input.qrngEvents).map((row) => row?.created_at),
      ...rows(input.vaultAuditLogs).map((row) => row?.created_at),
      ...rows(input.vulnerabilities).map((row) => row?.updated_at || row?.created_at),
      ...rows(input.auditLogs).map((row) => row?.created_at),
      ...rows(input.authEvents).map((row) => row?.created_at),
      ...rows(input.userSecurityEvents).map((row) => row?.created_at),
      ...rows(input.userSessions).map((row) => row?.updated_at || row?.created_at),
      ...rows(input.userDevices).map((row) => row?.last_active || row?.updated_at || row?.created_at),
      ...rows(input.complianceEvidence).map((row) => row?.updated_at || row?.created_at),
      ...rows(input.migrationJobs).map((row) => row?.updated_at || row?.completed_at || row?.created_at),
    ),
  }
}
