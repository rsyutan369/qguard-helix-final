# Agent Roles, Entitlement and Least Privilege

How QGuard Helix decides what an agent may do, and which plan may hold one.

Spec: `Qguard_Wiki/Agent_Installer_Refactor_Enhancements` §11–§15, §37, §40–§41.

---

## The four roles

The role catalogue lives in `src/lib/agent-installer/agent-release.ts`
(`AGENT_ROLES`). Each entry declares its modules, scan types, capabilities and —
the field everything else keys on — `mutatesTargets`.

| Role | `mutatesTargets` | Authority |
|---|---|---|
| **Collector** | no | Reads cryptographic evidence from allowed paths and targets. Never writes to the host. |
| **Scanner** | no | Classifies discovered algorithms against FIPS 203/204/205. Never writes to the host. |
| **Patcher** | **yes** | Applies approved changes to allow-listed paths only, always with a snapshot, post-change validation and automatic rollback on failure. |
| **Migration Operator** | **yes** | Claims migration jobs that pass tenant, asset, capability, policy, approval and allowed-path checks. Rollback configuration is mandatory. |

---

## Which plan may hold which role

```
                 Collector  Scanner  Patcher  Operator
  anonymous          –         –        –         –
  Starter            –         –        –         –
  Basic              ✓         ✓        –         –
  Pro                ✓         ✓        ✓         ✓
  Elite              ✓         ✓        ✓         ✓
  any tier, lapsed   –         –        –         –
```

**The line is `mutatesTargets`.** The two read-only roles are Basic; the two
that write to a host are Pro. That is deliberate and worth stating plainly: a
Basic tenant can never hold an agent capable of modifying one of their
endpoints.

Basic gets the read-only roles because those are what feed the Quantum Readiness
engine Basic already pays for. Withholding them would leave that engine with
nothing to read on a plan that is sold on it.

A **lapsed** subscription loses every role, including the read-only ones. An
agent is a running process on a customer host, not a report — leaving one
enrolled and collecting after billing stops is not a grace period, it is an
unauthorised deployment.

Policy: `AGENT_ROLE_MIN_TIER` in `src/lib/subscription-access.ts`.

---

## Scan modules by plan

A role says what an agent is *allowed to do*; a plan says *how much of the
estate* it may look at.

**Basic — the host itself** (12 modules): `tls`, `certificates`, `pki`, `ssh`,
`packages`, `configs`, `libraries`, `filesystem`, `application`, `runtime`,
`web_application`, `public_tls`.

**Pro and Elite — everything above, plus reach beyond the host** (22 more):
`vpn`, `kubernetes`, `service_mesh`, `api_gateway`, `load_balancer`, `hsm`,
`cloud`, `cloud_kms`, `cloud_hsm`, `cloud_database`, `cloud_storage`,
`cloud_load_balancer`, `api`, `cdn`, `container`, `database`, `messaging`,
`identity`, `email`, `native`, `ebpf`, `etw`.

Requested modules a plan does not include are **recorded, not dropped**. They
land on the agent's `metadata.scanTypesDeniedByPlan` and surface in the Agent
Center as "not included in your plan". A silently dropped module leaves a
dimension nobody looked at, and an unexamined dimension reads as a clean one.

---

## Enforcement points

The role is resolved **server-side** at four independent points. §41: *"The
agent must not be able to claim `role=administrator` and thereby gain
privileges. The backend must maintain the authoritative role."*

1. **Enrolment** — `POST /api/v1/agent-scanner/agents/enroll`
   `decideAgentRole()` checks the requested role against the tenant's plan
   before any row is written. The resolved role is written **after** the
   caller's metadata spread so it overrides anything they supplied, and
   capabilities are derived from the role definition rather than the request
   body. An unknown role string is refused, never defaulted.

2. **Package generation** — `POST /api/v1/agent-installer/package`
   Re-checked against the plan held *now*. An agent row enrolled under Pro
   survives a downgrade to Basic — deleting a fleet on a billing change would be
   worse — but a downgraded tenant cannot keep minting fresh installers for a
   write-capable role.

3. **Job dispatch** — `GET /api/v1/agent-scanner/agent/remediation/jobs`
   `agentMayWrite()` re-checks on **every poll**, so a downgrade, a lapsed card
   or a revocation stops work reaching agents that already exist. The queue
   returns empty with the reason stated rather than silently.

4. **Gateway floor** — `src/api-server/subscription-guard.ts`
   `/api/v1/agent-scanner` and `/api/v1/agent-installer` are gated at **Basic**.
   The per-role split cannot be expressed as a path prefix (every role enrols
   through the same endpoint), which is why the module in (1)–(3) is required
   *together with* this floor. Setting the prefix to `pro` locks Basic out of
   the collector; setting it to `basic` without the module hands Basic a
   patcher.

All four fail **closed** on a billing read error (`ENTITLEMENT_UNAVAILABLE`,
503). This differs from the central subscription gateway, which fails *open* —
and the difference is deliberate. Locking a subscriber out of an entire
dashboard over a transient Supabase blip is worse than a brief over-grant. Here
the blast radius is a write-capable agent on a production host, and an
over-grant has no visible symptom until someone notices.

---

## The UX layer

`src/hooks/use-agent-entitlement.ts` reads the same matrix for the browser, with
the server's answer (from `/api/v1/agent-installer/releases`) winning once it
lands. Roles are shown **in full** with the unentitled ones marked and
unselectable, never hidden — a Basic tenant should leave knowing that Patcher
and Migration Operator exist and what they do, because that is the argument for
Pro. A wizard that is silently shorter reads as a missing feature.

---

## Verification

```bash
npx tsx tools/agent-access-check.ts
```

110 checks: the full plan × role matrix, the `mutatesTargets` invariant asserted
against the role catalogue itself, module clamping and denial reporting, the
control-plane environment policy, and source-level assertions that each of the
four enforcement points is still wired.
