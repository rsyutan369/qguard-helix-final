import { resolveWriteAuthority } from '@/lib/agent-installer/agent-scope'
import { jobPlanId } from '@/lib/migration/job-safety'
import type { OperationalAgent } from '@/lib/migration/operational-workflow'

/**
 * Shared, tolerant reads for the two facts that decide whether an operational
 * migration job can move: the approval recorded on its plan, and the agent
 * fleet that could execute it.
 *
 * The sandbox snapshot owned private copies of both. The orchestration
 * snapshot needs exactly the same reads (and must reach the same verdicts the
 * agent claim path enforces), so they live here once.
 *
 * Both are deliberately tolerant: a failed read must not abort the caller's
 * snapshot, and it must never be mistaken for a NEGATIVE answer — "plan never
 * read" is not "not approved", and an unreadable fleet is not "no agents".
 */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Client = any

export function isMissingTable(error: unknown): boolean {
  const e = error as { code?: unknown; message?: unknown } | null
  const text = `${e?.code || ''} ${e?.message || ''}`.toLowerCase()
  return text.includes('42p01') || text.includes('pgrst205') || text.includes('does not exist') || text.includes('could not find the table')
}

export interface PlanApprovals {
  plans: Map<string, { status: unknown; metadata: { approval: unknown }; name: string | null }>
  /** Plan ids that were actually queried — "read, no approval" vs "never read". */
  queried: Set<string>
}

/**
 * Approval records for the plans the given jobs declare. Projects only what
 * `planApproval` reads (a plan's metadata blob is large and this runs on every
 * snapshot), plus the plan's display name when one was recorded.
 */
export async function loadPlanApprovals(client: Client, userId: string, jobs: Array<{ metadata?: unknown }>, logPrefix = '[fleet]'): Promise<PlanApprovals> {
  const planIds = Array.from(new Set(jobs.map((job) => jobPlanId(job)).filter(Boolean))).slice(0, 200)
  const empty: PlanApprovals = { plans: new Map(), queried: new Set() }
  if (planIds.length === 0) return empty
  try {
    const { data, error } = await client
      .from('migration_plans')
      .select('id, status, approval:metadata->approval, plan_name:metadata->>name, plan_title:metadata->>planName')
      .eq('user_id', userId)
      .in('id', planIds)
    if (error) {
      if (!isMissingTable(error)) console.warn(`${logPrefix} plan approval read failed:`, error.message)
      return empty
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rows = ((data as any[]) || [])
    return {
      plans: new Map(rows.map((row) => [
        String(row.id),
        { status: row.status, metadata: { approval: row.approval }, name: (row.plan_name || row.plan_title || null) as string | null },
      ])),
      queried: new Set(planIds),
    }
  } catch (error) {
    console.warn(`${logPrefix} plan approval read threw:`, (error as Error)?.message || error)
    return empty
  }
}

/** The tenant's enrolled agents, or null when they could not be read (never "none"). */
export async function loadAgentFleet(client: Client, userId: string, logPrefix = '[fleet]'): Promise<OperationalAgent[] | null> {
  try {
    const { data, error } = await client
      .from('scanner_agents')
      .select('id, name, hostname, status, last_seen_at, revoked_at, capabilities, role:metadata->>role, remediation_authorized:metadata->remediationAuthorized, migration_authorized:metadata->migrationAuthorized')
      .eq('user_id', userId)
      .limit(500)
    if (error) {
      // No agent table provisioned means no agent can exist — a measured "none".
      if (isMissingTable(error)) return []
      console.warn(`${logPrefix} agent fleet read failed:`, error.message)
      return null
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return ((data as any[]) || []).map((row) => ({
      id: String(row.id),
      name: row.name || row.hostname || null,
      role: row.role || null,
      lastSeenAt: row.last_seen_at || null,
      revoked: Boolean(row.revoked_at) || String(row.status || '').toLowerCase() === 'revoked',
      writeAuthority: resolveWriteAuthority(row.role, row.capabilities, {
        remediationAuthorized: row.remediation_authorized,
        migrationAuthorized: row.migration_authorized,
      }),
    }))
  } catch (error) {
    console.warn(`${logPrefix} agent fleet read threw:`, (error as Error)?.message || error)
    return null
  }
}
