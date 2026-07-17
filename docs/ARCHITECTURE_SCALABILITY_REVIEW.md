# QGuard Helix — Architecture & Scalability Review

Per `Qguard_Wiki/Architechture_Review_Scalability-Validation` (2026-07-17).
Reviewed as a complete ecosystem: frontend modules, Express API services,
Supabase data layer, scanner/agent pipeline, evidence engines (QR snapshot,
Q-REMEDY, certification, workflow), SSE/realtime telemetry.

**Verdict: the platform architecture handles small → large-enterprise tenants
correctly today** — headline numbers stay truthful at any estate size, every
engine is payload-bounded, and tenant isolation is enforced at the database.
Two scalability defects found in this review were fixed immediately (shared
computation cache; composite index pack). Genuine roadmap items for
100k+-asset/many-tenant SaaS operation are listed honestly at the end.

---

## 1. Scale tiers — how the architecture behaves

The platform uses a deliberate **bounded-detail / exact-headline** design:

- Detail queries are row-capped (assets 1500–2000, CBOM 2500, findings 2000,
  runtime events 4000 …) so memory and compute are bounded regardless of
  estate size.
- Headline numbers come from exact `HEAD count` queries, never from capped
  page lengths — a 100,000-asset tenant reports 100,000 assets while the UI
  pages the highest-risk detail rows.
- Engine outputs are capped and aggregated: Q-REMEDY greedy runs over the top
  600 candidates and ships ≤400 ranked actions with the tail simulated in
  aggregate; ladder shows 8 steps + aggregate rung; asset lifecycle states cap
  at 200 (highest risk first); findings dedupe per asset+domain with instance
  counts.

| Tier | Behavior |
| --- | --- |
| 1–10 assets | Full detail everywhere; empty states honest; identical math. |
| 10–500 | All rows inside caps — exact and detail views coincide. |
| 1,000–100,000+ | Exact counts drive every score; detail views rank by risk/priority; effort model plans parallel workstreams (up to 64 lanes) so timelines stay bounded; payloads stay constant-size. |

## 2. Multi-tenant isolation

- Every table is tenant-scoped by `user_id` with Supabase **RLS as the
  enforcement point**; API queries run on the caller's JWT client, so a query
  that "forgets" a filter still cannot cross tenants.
- Service role is used only where designed: the public certificate
  verification portal (rate-limited, non-sensitive projection), the ML-DSA
  issuer key table (RLS no-policy), and owner-only admin/revenue modules.
- Subscription gateway enforces plan tiers server-side per API prefix
  (fail-closed for unlisted dashboard paths).
- **Limitation (roadmap):** tenant == one account. Organizations with
  departments/business units/multiple seats per tenant need an org model
  (org_id + membership + role claims in RLS). The single-key scoping makes
  this a mechanical migration (`user_id` → `tenant_id`) when prioritized.

## 3. Asset-type & environment coverage (not just qguardhelix.com)

Nothing in the engines is hardcoded to any asset. The pipeline is
evidence-driven end to end:

- **Discovery** — scanner modules (TLS protocol, certificates, cipher suites,
  key exchange, signature algorithms, hashing, SSH) + secrets/pattern catalog
  + `qguard-agent` collectors (runtime/native collectors, remediation jobs)
  + cloud `connector_accounts`. Whatever they write into
  `assets`/`crypto_inventory`/`pqc_scan_results`/`runtime_crypto_events`
  flows through every module.
- **Classification** — findings are typed generically by `classifyDomain`
  (TLS, SSH, VPN/IPsec, PKI/certificates, key management/HSM/KMS,
  applications/libraries/SDKs/dependencies, cloud services, data-at-rest,
  identity/JWT/OAuth, third-party/vendor) and mapped to NIST playbooks —
  RSA/ECC/ECDSA/SHA-1/3DES/legacy-TLS detection is pattern-based across all
  of them. API keys/tokens/secrets land via the scanner's secret patterns and
  the key-management/identity domains.
- Verified in this session with mixed synthetic estates (web server + database
  + SaaS vendor + expired certs + evidence gaps) and the live tenant.
- **Honest boundary:** coverage equals what agents/scanners/connectors observe.
  Deep Kubernetes/serverless/IoT discovery depends on deploying the agent or
  connector into those environments — the data model and engines already
  accept those asset types.

## 4. Real-time CBOM / Assets and cross-module consistency

- CBOM and Assets render from live scanner intelligence (fetch + SSE) and
  Supabase realtime (publications verified per module); certificates renewals,
  key rotations, new scans and migration completions all mutate the same
  authoritative tables, so every consumer updates within its cadence
  (8–30s SSE + postgres_changes push).
- **Fixed in this review (the guide's "shared authoritative model"
  recommendation):** scanner intelligence and the QR snapshot are now
  **per-tenant, single-flight, 15s-TTL shared computations**
  (`scanner.ts` / `quantum-readiness.ts`). Previously each open dashboard and
  each SSE tick recomputed them independently — O(open dashboards × ticks)
  heavy work and the possibility of two pages computing slightly different
  states. Now all modules (Assets, CBOM, QR pages, Risk, Harvest Now,
  Remediation, Certification, Planner, Workflow rail) derive from the SAME
  computation inside a window — consistent by construction. The cache is
  bypassed while a tenant has an active scan so live scan progress stays
  real-time, and failures are never cached.
- Measured effect (real tenant): QR snapshot 9.2s → **0.5s**, remediation
  5.2s → **1.5s**, certification → 2.1s, planner → 0.7s, scanner
  intelligence → 0.7s within a warm window; each tenant now costs one heavy
  computation per 15s regardless of how many dashboards/streams are open.

## 5. Remediation engine at scale

Bounded by design (see §1): grouping per asset+domain, 8-factor prioritization
over exact counts, marginal-gain simulation over the capped candidate set with
aggregate-tail projection, automation flags per playbook, progress from real
migration jobs, and certification forecasting from the same criteria the
certification engine enforces. Complexity is O(assets) for synthesis and
O(cap²)≤O(600²) for the greedy — independent of estate size.

## 6. Database performance

- 124 tenant indexes already existed across module schemas.
- **Added `supabase/scale-indexes.sql`** (idempotent, guarded per table):
  composite `(user_id, <order-col> DESC)` indexes matching the platform's
  hot query shape, plus partial-filter composites for the exact-count paths
  (`crypto_inventory(user_id, is_vulnerable)`, `certificates(user_id,
  not_after)`, `migration_jobs/plans(user_id, status)` …). **Run once in the
  Supabase SQL Editor.**

## 7. Honest roadmap (not yet horizontal-scale SaaS)

These do not affect correctness at any tenant size today, but matter for
many-thousand-concurrent-tenant SaaS operation:

1. **Single-node state** — active scan jobs, the new computation caches and
   SSE connections live in process memory. Multi-instance deployment needs
   externalized state (Redis/queue) or sticky sessions. The cache API was
   written so a Redis backend can replace the Maps without caller changes.
2. **Job queue for scans/agents** — scan orchestration is in-process;
   a durable queue (e.g. pg-boss on the existing Postgres) would give retry,
   backpressure and worker autoscaling.
3. **Org-level tenancy** (see §2).
4. **Event-driven cache invalidation** — TTL windows are below all consumer
   cadences today; a `postgres_changes`-driven invalidation would cut the
   staleness bound from 15s to near-zero.

## 8. Standards alignment

FIPS 203/204/205 terminology enforced by tests (ML-KEM never presented as a
signature algorithm); CNSA 2.0 / CISA / NCSC-aligned playbooks; certification
policy floors prevent tenant self-certification; ML-DSA-65-signed,
publicly verifiable certificates; header-auth SSE (no tokens in URLs);
rate-limited public portal; Zero-Trust posture (client never owns privileged
logic; server-side tier gating; RLS everywhere).
