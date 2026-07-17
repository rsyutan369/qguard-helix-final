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
  { prefix: '/dashboard/migration-planner', tier: 'basic' },
  { prefix: '/dashboard/migration-sandbox', tier: 'basic' },
  { prefix: '/dashboard/harvest-now', tier: 'basic' }, // HNDL assessment (QR engine)
  { prefix: '/dashboard/quantum-certification', tier: 'basic' }, // Quantum Trust Certification (BASIC/PRO/ELITE)
  // BASIC also scans its own assets and reviews the inventory that feeds the
  // QR Assessment Engine / Migration Planner / Sandbox.
  { prefix: '/dashboard/scanner', tier: 'basic' },
  { prefix: '/dashboard/assets', tier: 'basic' },
  { prefix: '/dashboard/assets_map', tier: 'basic' },

  // PRO — Discovery (remaining)
  { prefix: '/dashboard/cbom', tier: 'pro' },
  { prefix: '/dashboard/shadow-crypto', tier: 'pro' },
  { prefix: '/dashboard/crypto-exposure', tier: 'pro' },
  // PRO — Operations
  { prefix: '/dashboard/migration-timeline', tier: 'pro' },
  { prefix: '/dashboard/migration-phases', tier: 'pro' },
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
  { prefix: '/dashboard/behavioral-analytics', tier: 'pro' },
  { prefix: '/dashboard/telemetry-correlation', tier: 'pro' },
  { prefix: '/dashboard/drift', tier: 'pro' },
  { prefix: '/dashboard/quantum-risk-scoring', tier: 'pro' },
  { prefix: '/dashboard/vulnerabilities', tier: 'pro' },
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
  { prefix: '/dashboard/identity-trust', tier: 'pro' },
  { prefix: '/dashboard/device-trust', tier: 'pro' },
  { prefix: '/dashboard/continuous-trust', tier: 'pro' },
  { prefix: '/dashboard/trust-analytics', tier: 'pro' },

  // ELITE — QKMS
  { prefix: '/dashboard/qkms', tier: 'elite' },
  // ELITE — Governance
  { prefix: '/dashboard/compliance', tier: 'elite' },
  { prefix: '/dashboard/quantum-governance', tier: 'elite' },
  { prefix: '/dashboard/crypto-policies', tier: 'elite' },
  { prefix: '/dashboard/audit-vault', tier: 'elite' },
  { prefix: '/dashboard/regulatory-mapping', tier: 'elite' },
  { prefix: '/dashboard/standards-mapping', tier: 'elite' },
  // ELITE — Telemetry
  { prefix: '/dashboard/runtime-telemetry', tier: 'elite' },
  { prefix: '/dashboard/certificate-telemetry', tier: 'elite' },
  { prefix: '/dashboard/key-analytics', tier: 'elite' },
  { prefix: '/dashboard/api-encryption', tier: 'elite' },
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
