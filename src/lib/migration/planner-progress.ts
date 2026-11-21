import { isPassingValidation } from './job-safety'

export function migrationJobInProgress(status: unknown) {
  return !['completed', 'failed', 'cancelled', 'canceled', 'rolled_back'].includes(String(status).trim().toLowerCase())
}

export const HANDOFF_REVIEW_FIELDS = [
  {
    key: 'compatibilityEvidence',
    label: 'Compatibility evidence',
    hint: 'Reference the sandbox run or representative test for each asset, including the outcome.',
    placeholder: 'e.g. Payments API — Sandbox run LAB-42 passed client and proxy TLS tests.',
  },
  {
    key: 'changeWindow',
    label: 'Approved change window',
    hint: 'Record the window, time zone, and change ticket or owner approval.',
    placeholder: 'e.g. Sat 22:00–23:00 PHT (UTC+8) · Approved under CHG-1042.',
  },
  {
    key: 'rollbackReference',
    label: 'Rollback procedure',
    hint: 'Reference the backup or snapshot, recovery steps, and who owns rollback.',
    placeholder: 'e.g. Platform Ops restores snapshot SNAP-42 and reruns the health check.',
  },
] as const

export type HandoffReview = Record<(typeof HANDOFF_REVIEW_FIELDS)[number]['key'], string>

export function parseHandoffReview(value: unknown): HandoffReview | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null
  const review = value as Record<string, unknown>
  const fields = HANDOFF_REVIEW_FIELDS.map(({ key }) => [key, typeof review[key] === 'string' ? review[key].trim() : ''] as const)
  if (fields.some(([, detail]) => !detail || detail.length > 500)) return null
  return Object.fromEntries(fields) as HandoffReview
}

export function plannerStageAccess({ queued, proposed, approved, verified }: {
  queued: boolean; proposed: boolean; approved: boolean; verified: boolean;
}) {
  const planning = queued || proposed
  return { findings: true, planning, execution: planning && approved, analytics: planning && approved && verified }
}

export function isVerifiedMigrationJob(job: {
  status: string; validationEvidenceStatus?: string; validationCount: number; executionBacked: boolean; isSandbox?: boolean;
}) {
  return !job.isSandbox && job.status === 'completed' && job.executionBacked && job.validationCount > 0 && isPassingValidation(job.validationEvidenceStatus)
}

export function isHeldMigrationWave(job: { metadata?: Record<string, unknown> }) {
  const execution = job.metadata?.execution as Record<string, unknown> | undefined
  return execution?.sequenceState === 'waiting_for_prior_phase' ||
    (execution?.gateRequired === true && execution.agentDispatchStatus === 'waiting_for_orchestration')
}

export function isAwaitingMigrationWave(job: { rawStatus: string; metadata?: Record<string, unknown> }) {
  return job.rawStatus === 'pending' && isHeldMigrationWave(job)
}
