import type { NextFunction, Request, Response } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { isOwnerEmail } from '@/lib/admin-access'
import {
  TIER_RANK,
  TIER_LABEL,
  normalizeTier,
  isAccessGrantingStatus,
  tierMeets,
  type AccessTier,
  type PlanTier,
} from '@/lib/subscription-access'

// Server-side subscription enforcement — the authoritative gate. Mounted once at
// /api/v1, it maps each request path to the plan tier that module requires and
// blocks callers whose active subscription is below it. This is defense in depth
// behind the frontend route guards: even a hand-crafted API request is checked.
//
// Enforcement mode (env SUBSCRIPTION_ENFORCEMENT):
//   'enforce' (default) — deny with 403.
//   'shadow'            — allow but log the would-be denial (safe rollout).
//   'off'               — disabled.
const ENFORCEMENT = (process.env.SUBSCRIPTION_ENFORCEMENT || 'enforce').toLowerCase()

// API path prefix -> minimum plan tier. Matched by longest (most specific)
// prefix. Paths NOT listed here (billing, paypal, profile, auth, admin, the
// dashboard overview) are ungated so users can subscribe and manage their plan.
//
// DELIBERATELY ABSENT: `/api/v1/exposure`.
//
// That router serves all three assessment modes at one prefix — Web is
// anonymous by design (it is the product's front door), Local needs BASIC and
// Dev needs PRO. A prefix rule cannot express three different answers for one
// prefix, and adding `/api/v1/exposure` here would either lock the free Web
// assessment out or, worse, be set to the lowest common tier and hand Dev away.
//
// So that router gates itself per route, keyed on the MODE, in
// `src/api-server/exposure.ts` (`requireMode`). Both read the same matrix in
// `src/lib/subscription-access.ts`, and `tools/exposure-access-check.ts`
// asserts that every executing route still carries its guard. If you came here
// to "fix" the missing entry: it is not missing.
const API_MIN_TIER: Array<{ prefix: string; tier: PlanTier }> = [
  // BASIC — Quantum Readiness & Assessment Engine + entry migration tools
  { prefix: '/api/v1/quantum-readiness', tier: 'basic' },
  { prefix: '/api/v1/exposure-graph', tier: 'basic' }, // Quantum Exposure Graph™ dependency & migration intelligence (QR suite)
  { prefix: '/api/v1/reports', tier: 'basic' },
  { prefix: '/api/v1/migration-planner', tier: 'basic' },
  { prefix: '/api/v1/cost-assumptions', tier: 'basic' },
  { prefix: '/api/v1/sandbox', tier: 'basic' },
  { prefix: '/api/v1/harvest-now', tier: 'basic' },
  { prefix: '/api/v1/quantum-certification', tier: 'basic' }, // Quantum Trust Certification Engine (BASIC/PRO/ELITE)
  { prefix: '/api/v1/quantum-remediation', tier: 'basic' }, // Intelligent Quantum Remediation Engine (pairs with certification)
  { prefix: '/api/v1/migration-workflow', tier: 'basic' }, // Cross-module workflow rail (state-driven lifecycle)
  { prefix: '/api/v1/migration-intelligence', tier: 'basic' }, // Shared Responsibility Quantum Migration Intelligence Engine™ (ownership model)
  { prefix: '/api/v1/copilot', tier: 'basic' }, // Sophia AI Security Copilot™ — available to every paying tenant; tools self-gate by RBAC + the caller's own module entitlements
  // BASIC scans its own assets (feeds QR Engine / Migration Planner / Sandbox).
  { prefix: '/api/v1/scanner', tier: 'basic' },

  // Agent Collector Scanners (scanner "Agents" tab) and the Agent Center
  // (/downloads) are BASIC, not Pro.
  //
  // A Basic tenant may deploy and operate the two READ-ONLY agent roles —
  // Collector and Scanner — because those are what feed the Quantum Readiness
  // engine that Basic already pays for. What Basic may NOT hold is an agent
  // that writes to a host: Patcher and Migration Operator are PRO.
  //
  // That distinction is per-ROLE, not per-path, so it cannot be expressed here
  // (every role is enrolled through the same endpoint). It is enforced in
  // `src/api-server/agent-entitlement.ts`, which resolves the role server-side
  // against the tenant's plan and clamps the scan-module list to match. Setting
  // this prefix to `pro` would lock Basic out of the collector entirely; setting
  // it to `basic` WITHOUT that module would hand Basic a patcher. Both are
  // needed together.
  { prefix: '/api/v1/agent-scanner', tier: 'basic' },
  { prefix: '/api/v1/agent-installer', tier: 'basic' },

  // PRO — Discovery (remaining) / Operations / Ecosystem / Intelligence / PQAuth / Observability / Trust Center
  { prefix: '/api/v1/migration', tier: 'pro' }, // timeline / phases / live-migration (NOT migration-planner: longer prefix wins)
  { prefix: '/api/v1/migration-snapshots', tier: 'pro' }, // Snapshot Management for safe rollback (live-migration)
  { prefix: '/api/v1/migration-orchestrator', tier: 'pro' }, // Massive-scale orchestration engine (live-migration)
  { prefix: '/api/v1/dashboard/pqauth', tier: 'pro' },
  { prefix: '/api/v1/dashboard/telemetry-correlation', tier: 'pro' },
  { prefix: '/api/v1/dashboard/quantum-risk-scoring', tier: 'pro' },
  // Intelligence suite — the frontend routes /dashboard/drift, /dashboard/vulnerabilities
  // and /dashboard/runtime-crypto-intel are all Pro. Without these entries the APIs
  // behind them matched no prefix and were served ungated, so a hand-crafted request
  // reached Pro data from a Starter account.
  { prefix: '/api/v1/dashboard/drift', tier: 'pro' },
  { prefix: '/api/v1/dashboard/vulnerabilities', tier: 'pro' },
  { prefix: '/api/v1/runtime-crypto-intel', tier: 'pro' },
  { prefix: '/api/v1/dashboard/tls-telemetry', tier: 'pro' },
  { prefix: '/api/v1/dashboard/tls-orchestrator', tier: 'pro' },
  { prefix: '/api/v1/dashboard/pki-visibility', tier: 'pro' },
  { prefix: '/api/v1/dashboard/protocol-analytics', tier: 'pro' },
  { prefix: '/api/v1/dashboard/encryption-monitoring', tier: 'pro' },
  { prefix: '/api/v1/dashboard/ecosystem-supply-chain', tier: 'pro' },
  { prefix: '/api/v1/dashboard/trust-state-discovery', tier: 'pro' },
  // Trust Dashboard: its frontend route is Pro in subscription-access.ts. The
  // API had no entry at all until the Trust Fabric refactor gave the page a
  // backend, so gate it to the same tier as the UI it serves.
  { prefix: '/api/v1/dashboard/trust-dashboard', tier: 'pro' },
  { prefix: '/api/v1/dashboard/zero-trust', tier: 'pro' },
  // Crypto Agility Command Center™ — the frontend route /dashboard/crypto-agility
  // is Pro; both its API surfaces are gated here so a hand-crafted request is
  // held to the same tier as the UI.
  { prefix: '/api/v1/crypto-agility', tier: 'pro' },
  { prefix: '/api/v1/dashboard/crypto-agility', tier: 'pro' },
  // External Trust & Ecosystem suite — the four frontend routes are Pro, so the
  // API that backs them is held to the same tier.
  { prefix: '/api/v1/external-trust', tier: 'pro' },
  { prefix: '/api/v1/dashboard/ecosystem-supply-chain', tier: 'pro' },

  // ELITE — Governance / Telemetry / QKMS
  // The Compliance Command Center's frontend route (/dashboard/compliance) is
  // Elite in subscription-access.ts, but its API matched no prefix here and was
  // served UNGATED — a hand-crafted request reached Elite compliance data from
  // any signed-in account. Held to the same tier as the UI it serves.
  { prefix: '/api/v1/dashboard/compliance', tier: 'elite' },
  { prefix: '/api/v1/dashboard/quantum-governance', tier: 'elite' },
  { prefix: '/api/v1/dashboard/audit-vault', tier: 'elite' },
  { prefix: '/api/v1/dashboard/regulatory-mapping', tier: 'elite' },
  { prefix: '/api/v1/dashboard/runtime-telemetry', tier: 'elite' },
  { prefix: '/api/v1/dashboard/certificate-telemetry', tier: 'elite' },
  { prefix: '/api/v1/dashboard/multi-cloud-telemetry', tier: 'elite' },
  { prefix: '/api/v1/dashboard/qkms', tier: 'elite' },
  { prefix: '/api/qkms', tier: 'elite' }, // legacy alias mount
]

function requiredTierForPath(path: string): PlanTier | null {
  let best: { prefix: string; tier: PlanTier } | null = null
  for (const entry of API_MIN_TIER) {
    if (path === entry.prefix || path.startsWith(entry.prefix + '/')) {
      if (!best || entry.prefix.length > best.prefix.length) best = entry
    }
  }
  return best ? best.tier : null
}

export interface Entitlement {
  tier: AccessTier
  status: string | null
  isActive: boolean
  isOwner: boolean
}

/**
 * Authoritative server-side entitlement for the caller. Reads the caller's own
 * newest billing_subscriptions row via their token (RLS-scoped, same as
 * billing.ts) and falls back to profiles.tier only for the free/none case — a
 * paid tier requires a real active subscription row. Owner emails always
 * resolve to Elite. THROWS on infra failure (no client / query error) so the
 * gateway can fail OPEN rather than lock out a real subscriber.
 */
export async function resolveEntitlement(userId: string, email: string | null | undefined, token: string): Promise<Entitlement> {
  if (isOwnerEmail(email)) {
    return { tier: 'elite', status: 'active', isActive: true, isOwner: true }
  }
  const client = createAuthClient(token)
  if (!client) throw new Error('subscription: no supabase auth client')

  const { data: sub, error: subError } = await client
    .from('billing_subscriptions')
    .select('plan,status,updated_at')
    .eq('user_id', userId)
    .order('updated_at', { ascending: false })
    .limit(1)
    .maybeSingle()
  if (subError) throw subError
  if (sub) {
    return {
      tier: normalizeTier(sub.plan),
      status: sub.status ?? null,
      isActive: isAccessGrantingStatus(sub.status),
      isOwner: false,
    }
  }
  const { data: profile } = await client.from('profiles').select('tier').eq('id', userId).maybeSingle()
  const tier = normalizeTier(profile?.tier)
  return { tier, status: tier === 'none' ? null : 'incomplete', isActive: false, isOwner: false }
}

function deny(res: Response, required: PlanTier, ent: Entitlement) {
  return res.status(403).json({
    error: {
      code: 'SUBSCRIPTION_REQUIRED',
      message: `This module requires the ${TIER_LABEL[required]} plan or higher.`,
      requiredTier: required,
      currentTier: ent.tier,
      status: ent.status,
    },
  })
}

/**
 * Central gateway middleware — mount once at /api/v1 BEFORE the module routers.
 * Ungated paths pass straight through; unauthenticated requests to gated paths
 * pass through too so the router's own requireAuth returns 401.
 */
export async function subscriptionGateway(req: Request, res: Response, next: NextFunction) {
  if (ENFORCEMENT === 'off') return next()

  const path = (req.originalUrl || req.url || '').split('?')[0]
  const required = requiredTierForPath(path)
  if (!required) return next() // ungated module (billing, paypal, profile, overview, ...)

  const token = getToken(req)
  if (!token) return next() // let the router's auth layer answer with 401

  try {
    const user = await getServerUser(token)
    if (!user) return next() // invalid token → router returns 401

    const ent = await resolveEntitlement(user.id, user.email, token)
    if (ent.isActive && tierMeets(ent.tier, required)) {
      ;(req as Request & { entitlement?: Entitlement }).entitlement = ent
      return next()
    }

    if (ENFORCEMENT === 'shadow') {
      console.warn(`[subscription] SHADOW allow: ${user.id} tier=${ent.tier} (${ent.status}) needs ${required} for ${path}`)
      return next()
    }
    console.warn(`[subscription] DENY: ${user.id} tier=${ent.tier} (${ent.status}) needs ${required} for ${path}`)
    return deny(res, required, ent)
  } catch (err) {
    // Infra error resolving entitlement — fail OPEN (log) rather than brick the
    // platform; the frontend gate still applies and this can't be attacker-forced.
    console.error('[subscription] gateway error (allowing through):', err)
    return next()
  }
}

export { TIER_RANK }
