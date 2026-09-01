/**
 * Agent role and scan-module entitlement (Agent_Installer_Refactor §15, §37, §41).
 *
 * Two rules from the specification meet here, and they are the same rule seen
 * from two sides:
 *
 *   §41  "The agent must not be able to claim role=administrator and thereby
 *         gain privileges. The backend must maintain the authoritative role."
 *   §15  Least privilege: role -> capabilities -> policies -> allowed operations.
 *
 * Before this module the enrolment route took its role straight out of
 * caller-supplied `metadata.role`, which meant a tenant could mint a `patcher`
 * — an agent that WRITES to their hosts — by editing one JSON field. The role
 * is now resolved server-side against the tenant's plan, and the requested
 * scan-module list is clamped to what that plan permits.
 *
 * The tier line is drawn at `mutatesTargets`:
 *
 *   collector, scanner   read-only     BASIC
 *   patcher, operator    writes hosts  PRO
 *
 * That is a rule an administrator can hold in their head, and it means a Basic
 * tenant can never hold an agent capable of modifying one of their endpoints.
 *
 * Policy itself lives in `src/lib/subscription-access.ts` so the browser reads
 * the same matrix; this module is only the enforcement point.
 */

import type { NextFunction, Request, Response } from 'express'
import { getServerUser, getToken } from '@/lib/supabase-server'
import { resolveEntitlement, type Entitlement } from './subscription-guard'
import {
  AGENT_ROLE_MIN_TIER,
  agentRoleDenialMessage,
  agentRolesForTier,
  agentScanTypesForTier,
  filterAgentScanTypes,
  resolveAgentRoleAccess,
  TIER_LABEL,
  type AccessTier,
  type AgentRoleId,
} from '@/lib/subscription-access'

export interface AgentEntitlementRequest extends Request {
  user?: { id: string; email?: string | null }
  token?: string
  /** Resolved once per request and reused by every check below. */
  agentEntitlement?: Entitlement
}

/** Every known role id, so an unknown string is refused rather than defaulted. */
const KNOWN_ROLES = Object.keys(AGENT_ROLE_MIN_TIER) as AgentRoleId[]

export function isAgentRoleId(value: unknown): value is AgentRoleId {
  return typeof value === 'string' && (KNOWN_ROLES as string[]).includes(value)
}

/**
 * The caller's authoritative plan.
 *
 * Throws on an infrastructure failure so the caller can decide the direction to
 * fail. Agent role checks fail CLOSED (see `requireAgentRole`) because granting
 * a write-capable agent on a transient billing error has no visible symptom and
 * lasts until someone notices.
 */
export async function entitlementFor(req: AgentEntitlementRequest): Promise<Entitlement> {
  if (req.agentEntitlement) return req.agentEntitlement
  const token = req.token ?? getToken(req)
  if (!token) throw new Error('agent-entitlement: no token')
  const user = req.user ?? (await getServerUser(token))
  if (!user) throw new Error('agent-entitlement: no user')
  const entitlement = await resolveEntitlement(user.id, user.email, token)
  req.agentEntitlement = entitlement
  return entitlement
}

export interface RoleDecision {
  ok: boolean
  role: AgentRoleId
  status: number
  code: string
  message: string
  detail: Record<string, unknown>
}

/**
 * Decide whether this caller may hold an agent in `requestedRole`.
 *
 * `roleLabel` is passed in rather than imported so this module stays free of a
 * dependency on the agent-release catalogue, which pulls in installer
 * templates. `tools/agent-access-check.ts` asserts the two role lists match.
 */
export async function decideAgentRole(
  req: AgentEntitlementRequest,
  requestedRole: unknown,
  roleLabel: (role: AgentRoleId) => string,
): Promise<RoleDecision> {
  /* An unrecognised role is refused, never silently defaulted to `collector`.
     Defaulting would mean a typo produces a working agent with a role the
     operator did not ask for, which is the kind of surprise that ends with
     someone assuming a host is being scanned when it is not. */
  if (requestedRole !== undefined && requestedRole !== null && requestedRole !== '' && !isAgentRoleId(requestedRole)) {
    return {
      ok: false,
      role: 'collector',
      status: 400,
      code: 'AGENT_ROLE_UNKNOWN',
      message: `Unknown agent role. Supported roles: ${KNOWN_ROLES.join(', ')}.`,
      detail: { requested: String(requestedRole), supported: KNOWN_ROLES },
    }
  }

  const role: AgentRoleId = isAgentRoleId(requestedRole) ? requestedRole : 'collector'

  let entitlement: Entitlement
  try {
    entitlement = await entitlementFor(req)
  } catch {
    /* §62 fail-closed. A write-capable agent granted because billing was
       briefly unreadable would keep that capability until a human noticed. */
    return {
      ok: false,
      role,
      status: 503,
      code: 'ENTITLEMENT_UNAVAILABLE',
      message: 'Your subscription could not be verified right now, so the agent was not enrolled. Please retry in a moment.',
      detail: { role },
    }
  }

  const access = resolveAgentRoleAccess(role, entitlement.tier, entitlement.isActive, true)
  if (access.allowed) {
    return { ok: true, role, status: 200, code: 'OK', message: '', detail: {} }
  }

  return {
    ok: false,
    role,
    status: 403,
    code: 'SUBSCRIPTION_REQUIRED',
    message: agentRoleDenialMessage(access, roleLabel(role)),
    detail: {
      role,
      requiredTier: access.requiredTier,
      currentTier: entitlement.tier,
      status: entitlement.status,
      includedIn: access.includedIn,
      availableRoles: agentRolesForTier(entitlement.tier),
      reason: access.reason,
    },
  }
}

export interface ScanTypeDecision {
  allowed: string[]
  /** Requested modules this plan does not include. Recorded, never dropped silently. */
  denied: string[]
  tier: AccessTier
}

/**
 * Clamp a requested scan-module list to the tenant's plan.
 *
 * Returns the removals as well as the survivors. The caller records the
 * removals on the agent policy so the Agent Center can show them as "not
 * included in your plan" rather than the agent simply never reporting on those
 * dimensions — an absent dimension reads as a clean one, which is the exact
 * failure the scanner work spent this whole project eliminating.
 */
export async function decideScanTypes(
  req: AgentEntitlementRequest,
  requested: readonly string[] | null | undefined,
): Promise<ScanTypeDecision> {
  let tier: AccessTier = 'none'
  try {
    const entitlement = await entitlementFor(req)
    tier = entitlement.isActive ? entitlement.tier : 'none'
  } catch {
    tier = 'none'
  }

  /* No requested list means "the role's default", which the caller resolves;
     clamping an empty request would hand back an empty policy. */
  if (!requested || requested.length === 0) {
    return { allowed: agentScanTypesForTier(tier), denied: [], tier }
  }
  const { allowed, denied } = filterAgentScanTypes(tier, requested)
  return { allowed, denied, tier }
}

/**
 * Middleware: refuse the request unless the caller's plan includes `role`.
 *
 * Used on the routes that ACT on a write-capable agent (remediation dispatch,
 * migration claim), so a tenant who downgrades from Pro to Basic immediately
 * stops being able to drive the patcher agents they already have — the agent
 * rows survive, but they can no longer be commanded.
 */
export function requireAgentRoleTier(role: AgentRoleId) {
  return async (req: AgentEntitlementRequest, res: Response, next: NextFunction) => {
    const decision = await decideAgentRole(req, role, (id) => TIER_LABEL[AGENT_ROLE_MIN_TIER[id]])
    if (decision.ok) return next()
    return res.status(decision.status).json({
      error: { code: decision.code, message: decision.message, detail: decision.detail },
    })
  }
}

/* ────────────────────────── tenant tier on the agent-authenticated path ──── */

/**
 * The tier of the tenant that owns an agent.
 *
 * The agent-facing routes authenticate the AGENT, not a user, so there is no
 * user token to scope a read with — `resolveEntitlement` cannot be used. This
 * reads the owning tenant's newest billing row through the service client
 * instead, keyed on the `user_id` already proven by `requireAgentAuth`.
 *
 * Cached briefly because the remediation-job poll runs on every agent tick and
 * a billing read per tick per agent is a real cost. The window is short enough
 * that a downgrade takes effect within a minute, which is the right trade for a
 * capability check that is re-evaluated continuously anyway.
 */
const tierCache = new Map<string, { tier: AccessTier; isActive: boolean; at: number }>()
const TIER_TTL_MS = 60_000

export async function tenantTierForAgent(
  client: { from: (table: string) => any } | null,
  userId: string,
): Promise<{ tier: AccessTier; isActive: boolean; resolved: boolean }> {
  const cached = tierCache.get(userId)
  if (cached && Date.now() - cached.at < TIER_TTL_MS) {
    return { tier: cached.tier, isActive: cached.isActive, resolved: true }
  }
  if (!client) return { tier: 'none', isActive: false, resolved: false }

  try {
    const { data, error } = await client
      .from('billing_subscriptions')
      .select('plan,status')
      .eq('user_id', userId)
      .order('updated_at', { ascending: false })
      .limit(1)
      .maybeSingle()
    if (error) throw error

    const { normalizeTier, isAccessGrantingStatus } = await import('@/lib/subscription-access')
    const tier = normalizeTier(data?.plan)
    const isActive = isAccessGrantingStatus(data?.status)
    tierCache.set(userId, { tier, isActive, at: Date.now() })
    return { tier, isActive, resolved: true }
  } catch {
    /* `resolved: false` is NOT the same as "no plan". The caller must be able
       to tell a genuine Basic tenant from a billing read that failed, because
       the two deserve different handling: refuse the write job either way, but
       say which happened. */
    return { tier: 'none', isActive: false, resolved: false }
  }
}

/** Drop a tenant's cached tier — call after a plan change. */
export function invalidateTenantTier(userId: string): void {
  tierCache.delete(userId)
}

/**
 * May this agent execute WRITE operations right now?
 *
 * Checks two independent things, both of which must hold:
 *   1. the agent's server-resolved role is one that writes (patcher/operator)
 *   2. the owning tenant currently holds a plan that includes that role
 *
 * (2) is what makes a downgrade take effect on agents that already exist. The
 * agent rows survive — deleting a tenant's fleet on a billing blip would be far
 * worse — but they stop being handed work.
 */
export async function agentMayWrite(
  client: { from: (table: string) => any } | null,
  agent: { user_id: string; metadata?: Record<string, unknown> | null },
  operation: 'remediation' | 'migration',
): Promise<{ allowed: boolean; reason: string }> {
  const role = agent.metadata?.role
  const requiredRole: AgentRoleId = operation === 'migration' ? 'operator' : 'patcher'

  if (!isAgentRoleId(role)) {
    return { allowed: false, reason: 'agent_role_unresolved' }
  }
  if (operation === 'migration' && role !== 'operator') {
    return { allowed: false, reason: 'agent_role_not_migration_operator' }
  }
  if (operation === 'remediation' && role !== 'patcher' && role !== 'operator') {
    return { allowed: false, reason: 'agent_role_read_only' }
  }

  const { tier, isActive, resolved } = await tenantTierForAgent(client, agent.user_id)
  if (!resolved) return { allowed: false, reason: 'entitlement_unavailable' }

  const access = resolveAgentRoleAccess(requiredRole, tier, isActive, true)
  if (!access.allowed) {
    return {
      allowed: false,
      reason: access.reason === 'inactive-subscription' ? 'subscription_inactive' : 'plan_does_not_include_role',
    }
  }
  return { allowed: true, reason: '' }
}
