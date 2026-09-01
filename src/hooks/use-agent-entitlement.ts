'use client';

/**
 * Which agent roles and scan modules this tenant's plan includes.
 *
 * Same two-reading shape as `use-exposure-access`, for the same reason: the
 * local matrix resolves instantly so a Pro customer never sees a locked
 * Patcher card flash on mount, and the server's answer wins once it lands so a
 * stale client read can never offer a role the API will refuse.
 *
 * The server reading comes from `/api/v1/agent-installer/releases`, which
 * already had to be called to render the download centre — so the authoritative
 * entitlement costs no extra round trip.
 *
 * Enforcement is in `src/api-server/agent-entitlement.ts`. This is the UX layer.
 */

import React from 'react';
import { useAuth } from '@/contexts/auth-context';
import { useSubscription } from '@/hooks/use-subscription';
import { supabase } from '@/lib/supabase';
import {
  AGENT_ROLE_MIN_TIER,
  agentRoleDenialMessage,
  agentRolesForTier,
  agentScanTypesForTier,
  plansIncludingAgentRole,
  resolveAgentRoleAccess,
  TIER_LABEL,
  type AccessTier,
  type AgentRoleId,
  type PlanTier,
} from '@/lib/subscription-access';

export interface AgentRoleEntitlement {
  role: AgentRoleId;
  allowed: boolean;
  requiredTier: PlanTier;
  includedIn: PlanTier[];
  /** Empty when allowed. */
  message: string;
}

export interface UseAgentEntitlementResult {
  loading: boolean;
  /** True once the server's answer has been applied. */
  verified: boolean;
  /** True when the server could not read billing — say so, do not guess. */
  degraded: boolean;
  tier: AccessTier;
  /** Roles this plan may enroll, deploy and download an installer for. */
  roles: AgentRoleId[];
  /** Per-role decision, including the refused ones so the UI can explain them. */
  byRole: Record<AgentRoleId, AgentRoleEntitlement>;
  /** Scan modules this plan's agents may execute. */
  scanTypes: string[];
  /** True when the plan includes at least one host-modifying role. */
  canWrite: boolean;
}

const ALL_ROLES = Object.keys(AGENT_ROLE_MIN_TIER) as AgentRoleId[];

const ROLE_LABEL: Record<AgentRoleId, string> = {
  collector: 'Collector',
  scanner: 'Scanner',
  patcher: 'Patcher',
  operator: 'Migration Operator',
};

interface ServerEntitlement {
  tier: AccessTier;
  degraded: boolean;
  roles: AgentRoleId[];
  scanTypes: string[];
}

/** Shared across hook instances — one fetch per page, not one per card. */
let inflight: Promise<ServerEntitlement | null> | null = null;
let cached: { value: ServerEntitlement | null; at: number; key: string } | null = null;
const TTL_MS = 30_000;

async function loadEntitlement(key: string): Promise<ServerEntitlement | null> {
  if (cached && cached.key === key && Date.now() - cached.at < TTL_MS) return cached.value;
  if (inflight) return inflight;

  inflight = (async () => {
    try {
      const { data } = await supabase.auth.getSession();
      const token = data.session?.access_token;
      if (!token) return null;
      const response = await fetch('/api/v1/agent-installer/releases', {
        headers: { authorization: `Bearer ${token}` },
      });
      if (!response.ok) return null;
      const body = await response.json();
      const entitlement = body?.data?.entitlement;
      if (!entitlement) return null;
      const value: ServerEntitlement = {
        tier: entitlement.tier ?? 'none',
        degraded: Boolean(entitlement.degraded),
        roles: Array.isArray(entitlement.roles) ? entitlement.roles : [],
        scanTypes: Array.isArray(entitlement.scanTypes) ? entitlement.scanTypes : [],
      };
      cached = { value, at: Date.now(), key };
      return value;
    } catch {
      /* Network failure. Fall back to the local reading rather than locking a
         paying customer out because one request did not land. */
      return null;
    } finally {
      inflight = null;
    }
  })();

  return inflight;
}

/** Invalidate the shared cache — call after a plan change. */
export function refreshAgentEntitlement(): void {
  cached = null;
}

export function useAgentEntitlement(): UseAgentEntitlementResult {
  const { user } = useAuth();
  const subscription = useSubscription();
  const [server, setServer] = React.useState<ServerEntitlement | null>(null);
  const [serverLoading, setServerLoading] = React.useState(true);

  const userId = user?.id ?? null;

  React.useEffect(() => {
    let cancelled = false;
    setServerLoading(true);
    void loadEntitlement(userId ?? 'anonymous').then((value) => {
      if (cancelled) return;
      setServer(value);
      setServerLoading(false);
    });
    return () => {
      cancelled = true;
    };
  }, [userId, subscription.tier, subscription.status]);

  return React.useMemo(() => {
    /* The server's tier wins when present. It already accounts for the owner
       override and for a subscription whose status stopped granting access. */
    const tier: AccessTier = server ? server.tier : subscription.isActive ? subscription.tier : 'none';
    const authenticated = Boolean(userId);

    const byRole = Object.fromEntries(
      ALL_ROLES.map((role) => {
        const access = resolveAgentRoleAccess(role, tier, tier !== 'none', authenticated);
        /* When the server sent a role list, trust it over the recomputation —
           it is the list the API will actually honour. */
        const allowed = server ? server.roles.includes(role) : access.allowed;
        return [
          role,
          {
            role,
            allowed,
            requiredTier: AGENT_ROLE_MIN_TIER[role],
            includedIn: plansIncludingAgentRole(role),
            message: allowed ? '' : agentRoleDenialMessage(access, ROLE_LABEL[role]),
          } satisfies AgentRoleEntitlement,
        ];
      }),
    ) as Record<AgentRoleId, AgentRoleEntitlement>;

    const roles = server ? server.roles : agentRolesForTier(tier);

    return {
      loading: subscription.loading || serverLoading,
      verified: Boolean(server),
      degraded: Boolean(server?.degraded),
      tier,
      roles,
      byRole,
      scanTypes: server ? server.scanTypes : agentScanTypesForTier(tier),
      canWrite: roles.includes('patcher') || roles.includes('operator'),
    };
  }, [server, serverLoading, subscription.tier, subscription.isActive, subscription.loading, userId]);
}

/** Display label for a role id, shared by the console and the download centre. */
export function agentRoleLabel(role: AgentRoleId): string {
  return ROLE_LABEL[role];
}

/** "Included in Pro and Elite" — the plan ribbon copy. */
export function agentRolePlanCopy(role: AgentRoleId): string {
  const plans = plansIncludingAgentRole(role).map((plan) => TIER_LABEL[plan]);
  if (plans.length === 0) return '';
  if (plans.length === 1) return `Included in ${plans[0]}`;
  return `Included in ${plans.slice(0, -1).join(', ')} and ${plans[plans.length - 1]}`;
}
