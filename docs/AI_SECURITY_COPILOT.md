# Sophia — QGuard Helix AI Security Copilot™

Sophia is the central AI intelligence layer of QGuard Helix. She is available on
**every dashboard page** (a floating dock) and as a **full console** at
`/dashboard/sophia`, and gives customers natural-language access to every
module: assets, scans, CBOM, exposure graph, quantum readiness, HNDL,
migrations, snapshots/rollback, remediation, certificates/PKI, telemetry and
collectors, compliance and certification, and executive reporting.

Sophia operates as an AI Cybersecurity Consultant, Quantum Migration Advisor,
PKI Expert, Risk Analyst, Compliance Advisor and Infrastructure Architect —
**always answering from the authenticated tenant's live data**, never from
static pretrained knowledge, and never fabricating metrics.

Implements: `Qguard_Wiki/AI_Security_CoPilot` + `Qguard_Wiki/AI_CoPilot_Multi-Tenant_Isolation`.

---

## Architecture

```
User ─▶ Auth (requireAuth) ─▶ Tenant + RBAC context ─▶ Rate limit ─▶
Prompt sanitizer ─▶ Intent detection ─▶ Objective inference ─▶ Question
expansion ─▶ Cross-module investigation (parallel typed tools) ─▶ Evidence
correlation (TenantIntelligence) ─▶ Dependency / risk reasoning ─▶ Deep
synthesis (mode composers) ─▶ Proactive findings ─▶ Structured answer ─▶ SSE
```

## Deep reasoning (consultant mode)

Sophia answers like a CISO / PQC consultant, not a chatbot. She infers the
user's **actual objective** — not the literal question — and, for consultative
questions, runs a **full cross-module investigation** before answering:

| Question | Inferred objective | Answer |
|----------|-------------------|--------|
| "How do I migrate my assets?" | guidance | dependency-safe migration **strategy** (roots-first order, per-step rationale + what breaks if reversed, rollback, effort) |
| "What should I migrate first?" | prioritization | ranked order with **WHY** (risk × exposure × blast radius × internet-facing) |
| "Am I quantum ready?" | executive | readiness verdict, drivers, business risk, roadmap |
| "Why can't I certify?" | gap_analysis | unmet criteria, **root cause**, fastest path to close |
| "Why is this high risk?" | explain | risk drivers, Shor/Grover, blast radius, impact |
| "Show my certificates" | status | focused lookup (direct mode — no over-investigation) |

Investigate-mode answers carry a rich structure (all evidence-derived, never
fabricated): **objective · key findings · risk outlook (before → after) ·
evidence · root cause · business impact · technical analysis · dependency-safe
migration strategy · dependencies · what-could-break · rollback strategy ·
recommendations · proactive findings · next actions · reasoning trace ·
standards · confidence**. When a tenant has no data, Sophia says exactly what is
missing and what to scan/configure — she never invents a strategy or metric.

**Cross-module search:** each consultative question runs ~20 read-only tools
spanning assets, CBOM, scanner, readiness, risk, exposure graph, blast radius,
trust chains, Harvest-Now, migration status/jobs/snapshots, certificates,
remediation, certification, compliance, telemetry and collectors — cheap because
they reuse the platform's 15s per-tenant single-flight builder caches — then
correlates everything into one `TenantIntelligence` view (`copilot-engine.ts`).

**Proactive intelligence:** while investigating, Sophia surfaces unprompted
issues that affect the answer — expired/expiring certificates, offline
collectors, failed migration jobs, a migration in progress with no snapshot,
critical remediation blockers.

| Layer | File |
|-------|------|
| Contract (isomorphic types) | `src/types/copilot.ts` |
| Knowledge base | `src/api-server/copilot-knowledge.ts` |
| Tool layer (57 MCP-style tools) | `src/api-server/copilot-tools.ts` |
| Reasoning engine (8 agents + coordinator) | `src/api-server/copilot-engine.ts` |
| AI Gateway (`/api/v1/copilot`) | `src/api-server/copilot.ts` |
| Schema | `supabase/sophia-copilot-schema.sql` |
| Hook | `src/hooks/use-copilot.ts` |
| Answer renderer | `src/components/copilot/SophiaMessage.tsx` |
| Floating dock (all pages) | `src/components/copilot/SophiaCopilot.tsx` |
| Full console | `src/app/dashboard/sophia/page.tsx` |
| Offline verification | `tools/copilot-check.ts` |

---

## Multi-tenant isolation (non-negotiable)

Every request derives a `ToolContext` from the **caller's own** RLS auth client
(`createAuthClient(token)`) and `user_id`. Tools reach data two ways, both
tenant-pinned:

1. **Shared cached builders** — `buildSnapshot`, `buildScannerIntelligence`,
   `buildExposureIntelligence`, the remediation/certification engines,
   `buildHndlIntelligence`, `buildWorkflowState`, `buildSnapshotDashboard` —
   all already scope by `userId`.
2. **`tenantRows()` / `tenantCount()`** — the ONLY direct table path, which
   **always** applies `.eq('user_id', ctx.userId)` on top of RLS
   (defense-in-depth). `tools/copilot-check.ts` proves this: it runs every tool
   against a recording mock client and asserts **zero unscoped queries**.

Sophia can never read, cache, reference or expose another tenant's data — by
construction, not by convention.

## RBAC — role capability matrix

Roles resolve from `profiles.role` (owner email → `owner`; single-account
tenants default to `infrastructure_admin` of their own tenant). Capabilities:

| Role | read | operate | audit | executive |
|------|:----:|:-------:|:-----:|:---------:|
| Owner | yes | yes | yes | yes |
| Infrastructure Admin | yes | yes | yes | yes |
| Security Analyst | yes | no | no | no |
| Executive | yes | no | no | yes |
| Auditor | yes | no | yes | yes |

`runTool` denies out-of-scope tools at runtime (status `denied`, audited). E.g.
an analyst cannot `approveRemediation`; an executive cannot `operate`; only
auditors/operators can read audit logs.

## Human-in-the-loop actions

Operate-class tools (`approveRemediation`, `rejectRemediation`, `createSnapshot`,
`restoreSnapshot`, `rollbackMigration`, `rollbackAsset`, `simulateMigration`,
`generateExecutiveReport`) **never mutate production state autonomously**. They
run RBAC + a real preflight, write an audit entry, and return a deep link into
the owning module where the existing validation/rollback safeguards execute the
change. Mutation authority stays with the module.

## Prompt-injection protection

`sanitizePrompt()` strips control/zero-width/bidi unicode and blocks
instruction-override, system-prompt probing, cross-tenant access, secret
exfiltration, raw SQL and role-hijack attempts **before any data access**.
Blocked prompts get a safe answer that discloses nothing.

---

## The 57 tools (MCP-style)

Assets (`getAssets`, `getAssetById`, `searchAssets`, `getAssetRelationships`) ·
Scanner (`getLatestScans`, `getFindings`, `getCryptoInventory`) ·
CBOM (`getCBOM`, `getLibraries`, `getAlgorithms`) ·
Exposure (`getExposureGraph`, `getBlastRadius`, `getTrustChains`, `getDependencies`) ·
Migration (`getMigrationJobs`, `getMigrationStatus`, `getMigrationTimeline`, `simulateMigration`) ·
Remediation (`getPendingRemediation`, `approveRemediation`, `rejectRemediation`, `getRemediationHistory`) ·
Certificates/PKI (`getCertificates`, `getCertificateChains`, `getQuantumCertificates`, `getCertificateAuthorities`, `getTrustStores`, `getKeyInventory`) ·
Harvest Now (`getHarvestNowExposure`) ·
Reports (`getReports`, `generateExecutiveReport`) ·
Telemetry/Collectors (`getLiveTelemetry`, `getHeartbeat`, `getAgentHealth`, `getCollectors`, `getCollectorsStatus`, `getPatchers`, `getRunningWorkflows`) ·
Connectors (`getCloudConnectors`, `getConnectorStatus`) ·
Compliance (`getComplianceStatus`, `getNISTScore`, `getCNSACompliance`) ·
Readiness/Risk (`getQuantumReadiness`, `getReadinessHistory`, `getRiskAnalysis`, `getRiskScore`) ·
Certification (`getCertificationStatus`, `getCertificationEligibility`) ·
Snapshots/Rollback (`getSnapshots`, `createSnapshot`, `restoreSnapshot`, `rollbackMigration`, `rollbackAsset`) ·
Logs (`searchLogs`, `getAuditTrail`) ·
Recommendations (`generateRecommendations`).

## Specialist agents

`asset_intelligence`, `migration_advisor`, `pki_expert`, `risk_analyst`,
`compliance_advisor`, `executive_advisor`, `telemetry_agent`,
`threat_intelligence` — routed and merged by the `coordinator`.

## Answer format (every response)

`summary · evidence · reasoning · recommendations (standards-tagged) · risk ·
next actions · related pages · confidence · tool runs · follow-ups`. Confidence
is deterministic (tool coverage × data freshness), and empty tenants get honest
setup guidance instead of fabricated numbers.

Standards catalog: NIST CSF 2.0, SP 800-53/57/131A/208, SP 1800-38, FIPS
203/204/205, CNSA 2.0, ISO/IEC 27001+19790, PCI DSS, CIS v8, OWASP ASVS, ETSI
QSC, IETF hybrid TLS.

---

## API — `/api/v1/copilot` (Basic tier +)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/context` | Tenant + role + capabilities + persistence mode |
| GET | `/suggestions?page=` | Page-aware suggested questions |
| GET | `/insights` | Proactive, severity-ranked, deep-linked insights |
| GET | `/health` | Engine component status |
| GET | `/conversations` | List (pinned first) |
| POST | `/conversations` | Create |
| GET | `/conversations/search?q=` | Search titles + message content |
| GET | `/conversations/:id` | Conversation + messages |
| PATCH | `/conversations/:id` | Pin / rename |
| DELETE | `/conversations/:id` | Delete |
| GET | `/conversations/:id/export` | JSON export |
| POST | `/chat` (`?stream=1`) | Ask Sophia — JSON or SSE stream |

**Chat SSE events:** `stage` (thinking/intent/planning/reading/reasoning/
generating/done), `tool` (per tool run), `answer` (full structured answer),
`meta` (conversationId), `error`.

Security: `requireAuth`, per-tenant token-bucket rate limiting (8/20s burst,
40/5min), audit logging to `audit_logs`, subscription gateway (Basic tier).

## Persistence

Conversations persist to `copilot_conversations` + `copilot_messages` (RLS
`auth.uid() = user_id`). **Apply `supabase/sophia-copilot-schema.sql`** to make
history durable across sessions/devices; until then the gateway uses a bounded
in-memory store and the copilot works out of the box (`persistence: "memory"`
in `/context`).

## Frontend

- **Floating dock** (`SophiaCopilot`) is mounted in `DashboardLayout` → present
  on every dashboard page. Streams stages + tool chips, renders structured
  answers, page-aware suggestions, voice in/out (Web Speech, when supported).
- **Full console** (`/dashboard/sophia`) — conversation history (new / search /
  pin / export / delete) · streaming chat · right rail with tenant/RBAC context,
  proactive insights and suggestions.
- Nav: "Sophia AI Security Copilot™" under Core Modules.

---

## Verification

```
npx tsx tools/copilot-check.ts   # 14 sections, all pass
npx tsc --noEmit                 # clean
npx vite build                   # green
```

`copilot-check.ts` asserts: intent detection + follow-ups, planner, 57-tool
registry completeness vs spec, **strict tenant scoping** (every direct query
`user_id`-pinned), RBAC denial matrix, role normalization, prompt sanitizer,
confidence bounds, evidence composition, empty-tenant honesty, conversation
memory, insight ranking, rate limiter, suggestions.

Live smoke (dev server): `/copilot/health`, `/context`, `/suggestions`, `/chat`
all return **401** without a token (auth-first); unknown paths return 404
(router confirmed mounted).

## Rollback

Additive. Remove the mounts (`index.ts` router, `DashboardLayout` widget,
`App.tsx` route, nav item) + the new files. `copilot_*` tables are standalone.
