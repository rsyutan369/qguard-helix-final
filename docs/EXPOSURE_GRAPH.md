# Quantum Exposure Graph™ — Enterprise Cryptographic Dependency & Migration Intelligence

Spec: `Qguard_Wiki/Crypto_Exposure_Graph_Enhancement`
Page: `/dashboard/quantum-readiness/exposure-graph`
API: `/api/v1/exposure-graph` (Basic tier — part of the Quantum Readiness suite)

The exposure graph was redesigned from a static 40-node posture visualization
into a full Enterprise Cryptographic Dependency Graph, Trust Relationship Map,
Migration Impact Analysis Engine and Migration Dependency Intelligence platform.

## Architecture

```
Supabase evidence tables ──► buildSnapshot (QR engine, 15s single-flight)
        │                            │
        ▼                            ▼
src/api-server/exposure-graph.ts — assembleExposureIntelligence()  [pure]
        │   per-tenant 15s single-flight cache
        ├── GET  /api/v1/exposure-graph          (JSON)
        └── GET  /api/v1/exposure-graph/stream   (SSE, 30s, header-auth only)
                     │
                     ▼
src/hooks/use-exposure-graph.ts  (fetch + ReadableStream SSE + Supabase realtime)
                     │
                     ▼
src/app/dashboard/quantum-readiness/exposure-graph/
  page.tsx           — composition, KPI band, toolbar, fullscreen
  _graph.tsx         — zoom/pan SVG canvas, layouts, animations
  _panels.tsx        — node/edge rail, Impact + Blast Radius panels
  _intelligence.tsx  — waves/clusters/blockers, third-party, prioritisation, advisor
  _common.ts         — posture/trust-class/category visual constants

src/lib/exposure-graph-intel.ts — ISOMORPHIC pure intelligence shared by the
backend assembler, the frontend (instant client-side Impact/Blast computation on
selection) and tools/exposure-graph-check.ts. One implementation, three consumers.
src/types/exposure-graph.ts — the shared contract.
```

## Evidence sources (tenant-scoped, no fabrication)

`assets`, `asset_relationships`, `crypto_inventory` (CBOM), `certificates`,
`runtime_crypto_events`, `pqc_scan_results`, `crypto_exposures`,
`connector_accounts`, `migration_jobs` — plus the QR snapshot for score floors
so the graph can never contradict the other Quantum Readiness pages.

External entities are materialised **only from observed evidence**:

- **External CAs** — certificate `issuer` DNs that do not match a tenant asset
  (issuers that DO match become edges to the internal PKI asset instead).
- **Third-party services** — runtime-event hosts that do not resolve to tenant
  assets (hosts that do resolve become internal `communicates-with` edges).
- **Cloud providers** — connector accounts, graphed only when at least one
  asset links to the provider via type/region/metadata; otherwise they appear
  in the third-party table without a fabricated graph edge.

Empty tenant ⇒ `hasData:false`, zeroed summary, empty sections, setup guidance.

## Node model — five-state posture

`vulnerable` 🔴 · `hybrid` 🟡 · `pqc` 🟢 · `migrating` 🔵 (active migration_jobs)
· `unknown` ⚪ (no crypto evidence). Nodes carry category (24 enterprise
categories), migration tier (12-tier ladder CA→KMS→IdP→PKI→VPN→LB→API→DB→K8s→
Web→Endpoints→Vendors), observed algorithms/protocols/certificates, degrees,
blast radius, composite priority with explainable drivers.

## Intelligence sections

- **Migration Impact Analysis™** (client-side, instant, same code as the check
  tool): current state → NIST target mapping (RSA→ML-DSA-65 / ECDH→X25519+
  ML-KEM-768 hybrid / SHA-1→SHA3-256 / 3DES→AES-256-GCM) → what-will-break per
  real neighbor category → required remediation → bounded risk/downtime/
  compatibility/confidence estimates (labelled planning estimates).
- **Blast Radius Analysis™** — BFS (undirected, depth-capped 6) with
  direct/indirect/trust-chain membership, environments, per-tier breakdown.
- **Migration Dependency Intelligence™** — waves by tier ladder, must-migrate-
  together clusters (union-find over trust-chain-class edges between pending
  nodes), blockers (vulnerable vendors / trust anchors / KMS).
- **AI Migration Advisor™** — rule-based, evidence-gated recommendations
  (trust-anchor-first, IdP-before-certs, vendor delay, hybrid TLS for internet
  endpoints, pinning audit, coordinated windows, visibility gap) + estimates
  mirroring the QR snapshot.
- **Third-Party Dependency Analysis** — vendor, category, connected assets,
  observed crypto, TLS version, readiness, risk, migration compatibility.
- **Risk Prioritization** — top 20 by composite score with drivers.

## Graph UX

Zoom (wheel, buttons), pan (drag), fit, full-screen (Esc exits), search with
match dropdown + centering, posture/layer/third-party filters, five group-by
layouts (Quantum Readiness / Migration Layer columns / Environment / Asset
Type / Region), animated trust flows on selection, SMIL blast pulse, rotating
dashes for migrating nodes, diamond = trust anchors, rounded square = KMS/HSM,
dashed = external, orange dot = internet-facing, curved edges with arrowheads,
hover tooltip, memoized content so pan/zoom only re-renders the transform.

## Security

Header-only bearer auth on both routes (no token-in-URL), tenant isolation via
`user_id` scoping + RLS, subscription gateway entry `basic` tier, SSE via
fetch+ReadableStream.

## Verification

- `npx tsx tools/exposure-graph-check.ts` — 64 offline checks over the pure
  assembler and intel functions (graph derivation, five-state posture, waves/
  clusters/blockers, blast BFS, impact mapping, third-party derivation,
  empty-state honesty). All pass.
- `npx tsc --noEmit` and `npm run build` clean.
- Live E2E: 401 unauthenticated, 200 owner with real tenant evidence, SSE
  emits `exposure-intelligence` frames; headless-Chrome render check confirmed
  KPI band, canvas, node selection, Impact tab and the honest empty state with
  zero console errors.
