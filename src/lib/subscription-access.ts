// Centralized subscription access control (RBAC by plan tier).
//
// Single source of truth for "which plan can reach which module", imported by
// BOTH the frontend route guards / sidebar filter AND the backend API
// middleware — so frontend gating is never the only enforcement. Keep this file
// dependency-free (no browser or Node APIs) so it runs in either environment.
//
// Tier ladder (each higher tier inherits everything below it):
//   none  <  starter  <  basic  <  pro  <  elite
//
// Plan -> access (per Qguard_Wiki/Subscriptions_Access):
//   STARTER : QGuard Messaging only (Starter Dashboard: profile + subscription +
//             downloads). No enterprise dashboard modules.
//   BASIC   : + Overview, Quantum Readiness & Assessment Engine, Migration
//             Planner, Migration Sandbox.
//   PRO     : + Discovery, Operations, Ecosystem & Supply Chain, Intelligence,
//             PQAuth, Observability, Trust Center.
//   ELITE   : everything (QKMS, Governance, Telemetry, Quantum Tools, and any
//             future / unmapped module).

export type PlanTier = 'starter' | 'basic' | 'pro' | 'elite';
export type AccessTier = 'none' | PlanTier;

export const TIER_RANK: Record<AccessTier, number> = {
  none: 0,
  starter: 1,
  basic: 2,
  pro: 3,
  elite: 4,
};

export const TIER_LABEL: Record<PlanTier, string> = {
  starter: 'Starter',
  basic: 'Basic',
  pro: 'Pro',
  elite: 'Elite',
};

export const TIER_ORDER: PlanTier[] = ['starter', 'basic', 'pro', 'elite'];

// Subscription statuses that actually grant access. Everything else
// (past_due, cancelled, expired, suspended, incomplete) is locked out.
// `pending_renewal` still has an active period, so it keeps access; grace-period
// handling for `past_due` is intentionally strict here and can be relaxed by
// adding it to this set if a grace policy is desired.
export const ACCESS_STATUSES = new Set(['active', 'trial', 'pending_renewal']);

export function isAccessGrantingStatus(status: string | null | undefined): boolean {
  return !!status && ACCESS_STATUSES.has(String(status).toLowerCase());
}

/** Normalize any plan representation (profiles.tier, billing plan, 'free', null) to an AccessTier. */
export function normalizeTier(value: string | null | undefined): AccessTier {
  const v = String(value ?? '').trim().toLowerCase();
  if (v === 'starter' || v === 'basic' || v === 'pro' || v === 'elite') return v;
  return 'none';
}

export interface EntitlementRecord {
  tier: AccessTier;
  status: string | null;
  isActive: boolean;
  isOwner: boolean;
  /** Where the entitlement came from: the owner bypass, a billing row, or nothing. */
  source: 'owner' | 'subscription' | 'none';
}

/**
 * THE entitlement rule, as pure data -> data. The API gateway
 * (subscription-guard `resolveEntitlement`) and the Owner Admin Users console
 * both call it, so "what plan does this user actually have" has one answer:
 * owner -> Elite; a billing_subscriptions row -> its plan, granting access only
 * while its status is access-granting; otherwise nothing. `profiles.tier` alone
 * never grants access (it is a mirror, not an entitlement).
 */
export function entitlementFromRecords(input: {
  isOwner: boolean;
  subscription: { plan?: string | null; status?: string | null } | null | undefined;
  profileTier?: string | null;
}): EntitlementRecord {
  if (input.isOwner) {
    return { tier: 'elite', status: 'active', isActive: true, isOwner: true, source: 'owner' };
  }
  if (input.subscription) {
    const status = input.subscription.status ?? null;
    return {
      tier: normalizeTier(input.subscription.plan),
      status,
      isActive: isAccessGrantingStatus(status),
      isOwner: false,
      source: 'subscription',
    };
  }
  const tier = normalizeTier(input.profileTier);
  return { tier, status: tier === 'none' ? null : 'incomplete', isActive: false, isOwner: false, source: 'none' };
}

/** True when `tier` sits at or above `required` on the ladder. */
export function tierMeets(tier: AccessTier, required: AccessTier): boolean {
  return TIER_RANK[tier] >= TIER_RANK[required];
}

// Path prefix -> minimum tier required. Matched by longest (most specific)
// prefix, with segment-boundary matching so `/dashboard/quantum-readiness`
// never matches `/dashboard/quantum-risk-scoring`. Anything under /dashboard
// that is NOT listed falls through to ELITE (fail-closed: a new module never
// leaks to a lower tier by accident).
const MODULE_MIN_TIER: Array<{ prefix: string; tier: PlanTier }> = [
  // Everyone with any active plan manages their account + subscription here.
  { prefix: '/dashboard/settings', tier: 'starter' },

  // BASIC — Quantum Readiness & Assessment Engine + entry migration tools + overview.
  { prefix: '/dashboard', tier: 'basic' }, // exact overview (see resolveRequiredTier)
  { prefix: '/dashboard/quantum-readiness', tier: 'basic' },
  { prefix: '/dashboard/migration-intelligence', tier: 'basic' }, // Shared Responsibility Quantum Migration Intelligence Engine™
  { prefix: '/dashboard/migration-planner', tier: 'basic' },
  { prefix: '/dashboard/migration-sandbox', tier: 'basic' },
  { prefix: '/dashboard/harvest-now', tier: 'basic' }, // HNDL assessment (QR engine)
  { prefix: '/dashboard/quantum-certification', tier: 'basic' }, // Quantum Trust Certification (BASIC/PRO/ELITE)
  // Sophia AI Security Copilot™ — available to every paying tenant (the copilot
  // itself self-limits answers to the tools the caller's role + plan permit).
  { prefix: '/dashboard/sophia', tier: 'basic' },
  // BASIC also scans its own assets and reviews the inventory that feeds the
  // QR Assessment Engine / Migration Planner / Sandbox. CBOM Explorer is part of
  // this loop — it visualizes the same scanner CBOM inventory (/api/v1/scanner/*,
  // already a BASIC API), so it belongs to the BASIC discovery experience.
  { prefix: '/dashboard/scanner', tier: 'basic' },
  { prefix: '/dashboard/assets', tier: 'basic' },
  { prefix: '/dashboard/assets_map', tier: 'basic' },
  { prefix: '/dashboard/cbom', tier: 'basic' },

  // PRO — Discovery (remaining)
  { prefix: '/dashboard/shadow-crypto', tier: 'pro' },
  // PRO — Operations
  { prefix: '/dashboard/migration-timeline', tier: 'pro' },
  { prefix: '/dashboard/pqc-orchestration', tier: 'pro' },
  { prefix: '/dashboard/crypto-agility', tier: 'pro' },
  { prefix: '/dashboard/live-migration', tier: 'pro' },
  // PRO — Ecosystem & Supply Chain
  { prefix: '/dashboard/vendor-pqc-readiness', tier: 'pro' },
  { prefix: '/dashboard/ecosystem-dependency-map', tier: 'pro' },
  { prefix: '/dashboard/trust-chain-analyzer', tier: 'pro' },
  { prefix: '/dashboard/hybrid-crypto-lab', tier: 'pro' },
  // PRO — Intelligence
  { prefix: '/dashboard/runtime-crypto-intel', tier: 'pro' },
  { prefix: '/dashboard/telemetry-correlation', tier: 'pro' },
  { prefix: '/dashboard/drift', tier: 'pro' },
  { prefix: '/dashboard/quantum-risk-scoring', tier: 'pro' },
  // PRO — PQAuth
  { prefix: '/dashboard/pqauth', tier: 'pro' },
  // PRO — Observability
  { prefix: '/dashboard/tls-telemetry', tier: 'pro' },
  { prefix: '/dashboard/pki-visibility', tier: 'pro' },
  { prefix: '/dashboard/protocol-analytics', tier: 'pro' },
  { prefix: '/dashboard/encryption-monitoring', tier: 'pro' },
  { prefix: '/dashboard/tls-orchestrator', tier: 'pro' },
  // PRO — Trust Center
  { prefix: '/dashboard/trust-dashboard', tier: 'pro' },
  { prefix: '/dashboard/trust-state-discovery', tier: 'pro' },

  // ELITE — QKMS
  { prefix: '/dashboard/qkms', tier: 'elite' },
  // ELITE — Governance
  { prefix: '/dashboard/compliance', tier: 'elite' },
  { prefix: '/dashboard/quantum-governance', tier: 'elite' },
  { prefix: '/dashboard/audit-vault', tier: 'elite' },
  { prefix: '/dashboard/regulatory-mapping', tier: 'elite' },
  // ELITE — Telemetry
  { prefix: '/dashboard/runtime-telemetry', tier: 'elite' },
  { prefix: '/dashboard/certificate-telemetry', tier: 'elite' },
  { prefix: '/dashboard/multi-cloud-telemetry', tier: 'elite' },
  // ELITE — Quantum Tools
  { prefix: '/dashboard/vault', tier: 'elite' },
  { prefix: '/dashboard/qrng', tier: 'elite' },
  { prefix: '/dashboard/keys', tier: 'elite' },
  { prefix: '/dashboard/otp', tier: 'elite' },
  { prefix: '/dashboard/pki', tier: 'elite' },
  { prefix: '/dashboard/tokenize', tier: 'elite' },
  { prefix: '/dashboard/comm', tier: 'elite' },
  { prefix: '/dashboard/cloud', tier: 'elite' },
];

function matchesPrefix(path: string, prefix: string): boolean {
  return path === prefix || path.startsWith(prefix + '/');
}

/**
 * Minimum tier required to view a dashboard path. Unmapped `/dashboard/*` paths
 * fall through to ELITE (fail-closed). `/dashboard` exactly (the Overview) is
 * BASIC — Starter users get the dedicated Starter Dashboard instead.
 */
export function resolveRequiredTier(pathname: string): PlanTier {
  const path = (pathname || '').replace(/\/+$/, '') || '/dashboard';
  if (path === '/dashboard') return 'basic';

  let best: { prefix: string; tier: PlanTier } | null = null;
  for (const entry of MODULE_MIN_TIER) {
    if (entry.prefix === '/dashboard') continue; // handled as the exact-overview case above
    if (matchesPrefix(path, entry.prefix)) {
      if (!best || entry.prefix.length > best.prefix.length) best = entry;
    }
  }
  return best ? best.tier : 'elite';
}

/** Can a user on `tier` open `pathname`? */
export function canAccessPath(tier: AccessTier, pathname: string): boolean {
  return tierMeets(tier, resolveRequiredTier(pathname));
}

/** The lowest plan that unlocks `pathname` (for "Upgrade to X" messaging). */
export function requiredPlanFor(pathname: string): PlanTier {
  return resolveRequiredTier(pathname);
}

/* ══════════════════════ exposure assessment modes (Web / Local / Dev) ══════ */

/**
 * The three scanning modes on /public-scan and /dashboard/scanner.
 *
 * These are NOT dashboard paths, so they cannot be expressed in MODULE_MIN_TIER:
 * all three live at the same URL and are selected by a tab. The entitlement is
 * a property of the MODE, not of the route, so it needs its own matrix — and
 * that matrix has to be readable from both sides, because the panels decide
 * what to render from it and the API decides what to execute from it.
 */
export type ExposureScanMode = 'web' | 'local' | 'dev';

/**
 * Mode -> minimum tier.
 *
 *   web    anonymous. The public assessment is the product's front door and
 *          stays free; requiring an account here would remove the thing that
 *          brings people to the platform at all.
 *   local  BASIC. Reads the user's own filesystem and codebase and can persist
 *          the result into their governed inventory — that is a tenant feature.
 *   dev    PRO. Executes server-side against repositories, registries, clusters
 *          and cloud accounts, and holds connector credentials. It costs real
 *          compute per scan and reaches infrastructure, so it sits a tier above.
 *
 * STARTER is deliberately absent: a Starter plan is QGuard Messaging only, so
 * it gets exactly what an anonymous visitor gets here — the Web assessment.
 */
export const EXPOSURE_MODE_MIN_TIER: Record<ExposureScanMode, AccessTier> = {
  web: 'none',
  local: 'basic',
  dev: 'pro',
};

/** The plans that include a mode, for "included in Basic, Pro and Elite" copy. */
export function plansIncluding(mode: ExposureScanMode): PlanTier[] {
  const required = EXPOSURE_MODE_MIN_TIER[mode];
  return TIER_ORDER.filter((plan) => tierMeets(plan, required));
}

export interface ExposureModeAccess {
  mode: ExposureScanMode;
  /** True when this caller may actually execute a scan in this mode. */
  allowed: boolean;
  requiredTier: AccessTier;
  /** Plans that include the mode. Empty for `web`, which needs no plan. */
  includedIn: PlanTier[];
  /** Why access was refused. `null` when allowed. */
  reason: 'unauthenticated' | 'inactive-subscription' | 'tier-too-low' | null;
}

/**
 * Resolve a caller's access to one mode.
 *
 * Shared by the UI and the API so the two can never disagree about who may
 * scan. The three refusal reasons are kept distinct because they need three
 * different next steps: sign in, fix billing, or upgrade — and collapsing them
 * into one "upgrade" message sends a paying customer with an expired card to
 * the wrong page.
 */
export function resolveExposureModeAccess(
  mode: ExposureScanMode,
  tier: AccessTier,
  isActive: boolean,
  authenticated: boolean,
): ExposureModeAccess {
  const requiredTier = EXPOSURE_MODE_MIN_TIER[mode];
  const includedIn = requiredTier === 'none' ? [] : plansIncluding(mode);

  if (requiredTier === 'none') {
    return { mode, allowed: true, requiredTier, includedIn, reason: null };
  }
  if (!authenticated) {
    return { mode, allowed: false, requiredTier, includedIn, reason: 'unauthenticated' };
  }
  if (!tierMeets(tier, requiredTier)) {
    return { mode, allowed: false, requiredTier, includedIn, reason: 'tier-too-low' };
  }
  /* Tier is high enough but the subscription is not in an access-granting
     state (past_due, cancelled, expired). Checked AFTER the tier test so the
     message names the real blocker rather than telling a lapsed Elite customer
     to upgrade. */
  if (!isActive) {
    return { mode, allowed: false, requiredTier, includedIn, reason: 'inactive-subscription' };
  }
  return { mode, allowed: true, requiredTier, includedIn, reason: null };
}

/** One-line explanation of a refusal, for the gate panel and the API error. */
export function exposureModeDenialMessage(access: ExposureModeAccess): string {
  const label = access.requiredTier === 'none' ? '' : TIER_LABEL[access.requiredTier as PlanTier];
  const modeLabel = access.mode === 'local' ? 'Local' : access.mode === 'dev' ? 'Dev' : 'Web';
  switch (access.reason) {
    case 'unauthenticated':
      return `${modeLabel} assessment requires an account on the ${label} plan or higher. The Web assessment is available without one.`;
    case 'tier-too-low':
      return `${modeLabel} assessment requires the ${label} plan or higher.`;
    case 'inactive-subscription':
      return `Your subscription is not currently active, so ${modeLabel} assessment is unavailable. Reactivate it to restore access.`;
    default:
      return '';
  }
}

/* ═════════════════════════════════════ agent roles and scan engines by tier ═ */

/**
 * The four agent roles, matching `AGENT_ROLES` in lib/agent-installer/agent-release.
 *
 * Kept as a string union here rather than imported, so this module stays
 * dependency-free and can be read by the API gateway, the installer templates
 * and the browser alike. `tools/agent-access-check.ts` asserts the two lists
 * cannot drift apart.
 */
export type AgentRoleId = 'collector' | 'scanner' | 'patcher' | 'operator';

/**
 * Role -> minimum tier.
 *
 *   collector  BASIC. Read-only inventory and evidence collection. This is the
 *              agent that feeds the Quantum Readiness engine, so it belongs
 *              wherever the QR engine belongs.
 *   scanner    BASIC. Read-only classification of what the collector found.
 *              Same blast radius as the collector: it writes nothing.
 *   patcher    PRO. WRITES to the host — configuration remediation, certificate
 *              replacement, TLS changes. A role that can change a production
 *              endpoint is not an entry-tier feature.
 *   operator   PRO. Executes migration cutovers. Highest blast radius of all.
 *
 * The line is drawn at `mutatesTargets`, deliberately: the two read-only roles
 * are Basic and the two writing roles are Pro. That is a rule an administrator
 * can hold in their head, and it means a Basic tenant can never hold an agent
 * that modifies one of their endpoints.
 */
export const AGENT_ROLE_MIN_TIER: Record<AgentRoleId, PlanTier> = {
  collector: 'basic',
  scanner: 'basic',
  patcher: 'pro',
  operator: 'pro',
};

/** Roles a tier may enroll, deploy and download an installer for. */
export function agentRolesForTier(tier: AccessTier): AgentRoleId[] {
  return (Object.keys(AGENT_ROLE_MIN_TIER) as AgentRoleId[]).filter((role) =>
    tierMeets(tier, AGENT_ROLE_MIN_TIER[role]),
  );
}

/** The plans that include an agent role, for "included in Pro and Elite" copy. */
export function plansIncludingAgentRole(role: AgentRoleId): PlanTier[] {
  return TIER_ORDER.filter((plan) => tierMeets(plan, AGENT_ROLE_MIN_TIER[role]));
}

export interface AgentRoleAccess {
  role: AgentRoleId;
  allowed: boolean;
  requiredTier: PlanTier;
  includedIn: PlanTier[];
  reason: 'unauthenticated' | 'inactive-subscription' | 'tier-too-low' | null;
}

/**
 * Resolve a caller's access to one agent role.
 *
 * Mirrors `resolveExposureModeAccess` exactly, including the order of the
 * checks: tier before status, so a lapsed Pro customer is told their
 * subscription needs reactivating rather than being told to buy Pro again.
 */
export function resolveAgentRoleAccess(
  role: AgentRoleId,
  tier: AccessTier,
  isActive: boolean,
  authenticated: boolean,
): AgentRoleAccess {
  const requiredTier = AGENT_ROLE_MIN_TIER[role];
  const includedIn = plansIncludingAgentRole(role);

  if (!authenticated) {
    return { role, allowed: false, requiredTier, includedIn, reason: 'unauthenticated' };
  }
  if (!tierMeets(tier, requiredTier)) {
    return { role, allowed: false, requiredTier, includedIn, reason: 'tier-too-low' };
  }
  if (!isActive) {
    return { role, allowed: false, requiredTier, includedIn, reason: 'inactive-subscription' };
  }
  return { role, allowed: true, requiredTier, includedIn, reason: null };
}

/** One-line explanation of an agent-role refusal. */
export function agentRoleDenialMessage(access: AgentRoleAccess, roleLabel: string): string {
  const label = TIER_LABEL[access.requiredTier];
  switch (access.reason) {
    case 'unauthenticated':
      return `The ${roleLabel} agent requires an account on the ${label} plan or higher.`;
    case 'tier-too-low':
      return `The ${roleLabel} agent requires the ${label} plan or higher. It can change host configuration, so it is not available on entry plans.`;
    case 'inactive-subscription':
      return `Your subscription is not currently active, so the ${roleLabel} agent is unavailable. Reactivate it to restore access.`;
    default:
      return '';
  }
}

/* ── agent scan modules ───────────────────────────────────────────────────── */

/**
 * Scan modules a tier's agents may execute.
 *
 * A role says what an agent is ALLOWED to do; a tier says how much of the
 * estate it may look at. The two are separate because a Basic tenant running a
 * collector should get a genuinely useful inventory of their own hosts — just
 * not the cloud-plane and service-mesh reach a Pro tenant is paying for.
 *
 * Anything not listed is refused for BASIC, so a module added later cannot leak
 * to a lower tier by being forgotten (the same fail-closed rule MODULE_MIN_TIER
 * uses).
 */
export const BASIC_AGENT_SCAN_TYPES: readonly string[] = [
  /* The host itself: everything a Basic tenant needs for a real CBOM of the
     machines they installed the agent on. */
  'tls',
  'certificates',
  'pki',
  'ssh',
  'packages',
  'configs',
  'libraries',
  'filesystem',
  'application',
  'runtime',
  'web_application',
  'public_tls',
];

/**
 * Additional modules PRO and ELITE agents may run.
 *
 * These reach BEYOND the host the agent is installed on — cloud control planes,
 * orchestration layers, managed key stores — which is the reach Pro buys.
 */
export const PRO_AGENT_SCAN_TYPES: readonly string[] = [
  'vpn',
  'kubernetes',
  'service_mesh',
  'api_gateway',
  'load_balancer',
  'hsm',
  'cloud',
  'cloud_kms',
  'cloud_hsm',
  'cloud_database',
  'cloud_storage',
  'cloud_load_balancer',
  'api',
  'cdn',
  'container',
  'database',
  'messaging',
  'identity',
  'email',
  'native',
  'ebpf',
  'etw',
];

/** The scan modules a tier's agents may run. */
export function agentScanTypesForTier(tier: AccessTier): string[] {
  if (!tierMeets(tier, 'basic')) return [];
  const types = [...BASIC_AGENT_SCAN_TYPES];
  if (tierMeets(tier, 'pro')) types.push(...PRO_AGENT_SCAN_TYPES);
  return types;
}

/**
 * Narrow a requested scan-type list to what the tier actually permits.
 *
 * Returns BOTH the permitted list and what was removed, because silently
 * dropping modules is how a scan comes back clean on a dimension nobody looked
 * at. The caller records the removals as Not Assessed with the reason.
 */
export function filterAgentScanTypes(
  tier: AccessTier,
  requested: readonly string[],
): { allowed: string[]; denied: string[] } {
  const permitted = new Set(agentScanTypesForTier(tier));
  const allowed: string[] = [];
  const denied: string[] = [];
  for (const type of requested) {
    if (permitted.has(type)) allowed.push(type);
    else denied.push(type);
  }
  return { allowed, denied };
}
