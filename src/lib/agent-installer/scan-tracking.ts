import type { AgentCommand } from './agent-release'

export const scanWorkflowPath = (agentId: string, commandId: string) =>
  `/dashboard/live-migration?${new URLSearchParams({ agentId, commandId })}#agent-workflow`

export interface ScanTrackingFrame {
  status: string
  telemetry: Record<string, unknown>
  observed_at: string
}

const number = (value: unknown): number | null => value === null || value === undefined || value === '' || !Number.isFinite(Number(value)) ? null : Number(value)
const time = (value: unknown) => Date.parse(String(value || '')) || 0

/** A command receipt stays terminal even when the agent starts a scheduled run. */
export function trackRequestedScan(command: AgentCommand, frames: ScanTrackingFrame[], now = Date.now()) {
  const ordered = [...frames].sort((a, b) => time(a.observed_at) - time(b.observed_at))
  const runningAck = ordered.find((row) => row.telemetry.commandId === command.id && row.status === `command:${command.type}:running`)
  const startedAt = command.startedAt || runningAck?.observed_at || null
  const end = command.completedAt ? time(command.completedAt) : Infinity
  const ownFrames = startedAt ? ordered.filter((row) => time(row.observed_at) >= time(startedAt) && time(row.observed_at) <= end) : []
  const terminal = ownFrames.find((row) => row.telemetry.phase === 'completed' || row.telemetry.phase === 'failed' || (row.status === 'scan_progress' && ['scan_complete', 'scan_failed'].includes(String(row.telemetry.stage))))
  const progressFrames = ownFrames.filter((row) => row.status === 'scan_progress' && (!terminal || time(row.observed_at) <= time(terminal.observed_at)))
  const last = progressFrames.at(-1)
  const result = command.result || terminal?.telemetry || {}
  const status = command.status === 'completed' || command.status === 'failed' ? command.status
    : terminal ? terminal.telemetry.phase === 'failed' || terminal.telemetry.stage === 'scan_failed' ? 'failed' : 'completed' : command.status
  const settled = status === 'completed' || status === 'failed'
  const stale = command.status === 'running' && now - time(last?.observed_at || startedAt || command.deliveredAt || command.queuedAt) > 10 * 60_000
  const state = status === 'failed' ? 'failed'
    : status === 'completed' ? result.degraded === true ? 'completed_with_errors' : 'completed'
      : stale ? 'stalled' : command.status === 'running' ? 'running' : 'queued'
  return {
    commandId: command.id,
    state,
    queuedAt: command.queuedAt,
    startedAt,
    completedAt: command.completedAt || terminal?.observed_at || null,
    updatedAt: command.completedAt || terminal?.observed_at || last?.observed_at || startedAt || command.deliveredAt || command.queuedAt,
    stage: settled ? status === 'failed' ? 'scan_failed' : 'scan_complete' : last?.telemetry.stage ? String(last.telemetry.stage) : null,
    message: status === 'failed' ? command.error || String(result.error || 'The agent reported that this scan failed.')
      : status === 'completed' ? result.degraded === true ? 'Scan finished with publishing errors. Review the agent details.' : 'Requested scan completed.'
        : stale ? 'No scan progress received for over 10 minutes. Check the agent connection.'
          : command.status === 'running' ? String(last?.telemetry.message || 'Agent acknowledged the scan; waiting for progress.')
            : 'Queued — waiting for the agent to pick up this request.',
    progress: status === 'completed' ? 100 : (state === 'running' || state === 'stalled') && number(last?.telemetry.progress) !== null ? Math.max(0, Math.min(100, number(last?.telemetry.progress)!)) : null,
    evidenceCount: number(result.evidenceCount),
    runtimeEventCount: number(result.runtimeEventCount),
    acceptedCount: number(result.acceptedCount ?? result.acceptedByControlPlane ?? result.accepted),
    rejectedByPolicy: number(result.rejectedByPolicy),
  }
}

export type TrackedScan = ReturnType<typeof trackRequestedScan>
