/** Health counts derived from recorded operational state and heartbeats. */
export function countTelemetrySources(input: {
  scannerAgents: Record<string, unknown>[]
  connectorAccounts: Record<string, unknown>[]
  scanSessions: Record<string, unknown>[]
}, now: number) {
  const status = (value: unknown) => String(value ?? '').trim().toLowerCase()
  const agentsOnline = input.scannerAgents.filter((agent) => {
    const seen = Date.parse(String(agent.last_seen_at ?? ''))
    return Number.isFinite(seen) && seen <= now && now - seen < 10 * 60_000 &&
      !['offline', 'inactive', 'disabled', 'disconnected', 'revoked'].includes(status(agent.status))
  }).length
  return {
    agentsOnline,
    connectorsActive: input.connectorAccounts.filter((row) => ['active', 'connected', 'ok', 'healthy', 'synced'].includes(status(row.status))).length,
    runningScans: input.scanSessions.filter((row) => ['running', 'in_progress', 'scanning', 'analyzing'].includes(status(row.status))).length,
  }
}
