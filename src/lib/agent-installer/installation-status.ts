export interface InstallationActivity {
  at: string
  status: string
  phase: string | null
  message: string | null
}

/** Installation events are evidence of setup, never evidence of a heartbeat. */
export function installationAttention(
  activity: InstallationActivity[],
  connected: boolean,
  now = Date.now(),
): { kind: 'failed' | 'delayed'; message: string } | null {
  if (connected) return null
  const ordered = [...activity].sort((a, b) => Date.parse(b.at) - Date.parse(a.at))
  const started = ordered.find((entry) => entry.phase === 'installation_started' || entry.status === 'install:installation_started')
  const start = started ? Date.parse(started.at) : -Infinity
  const failed = ordered.find((entry) => Date.parse(entry.at) >= start && (entry.phase === 'failed' || entry.status === 'install:failed'))
  if (failed) return { kind: 'failed', message: failed.message || 'Installation reported a failure. Review the agent log on the target host.' }
  const service = ordered.find((entry) => Date.parse(entry.at) >= start && (entry.phase === 'service_started' || entry.status === 'install:service_started'))
  if (service && now - Date.parse(service.at) >= 120_000) {
    return { kind: 'delayed', message: 'The startup task was reported started, but no current connection is verified after two minutes. Review the agent log and task status on the target host. A running task alone does not confirm this agent connected.' }
  }
  return null
}
