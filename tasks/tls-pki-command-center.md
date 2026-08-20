# TLS & PKI Intelligence Command Center — Refactor Plan

Guideline: `Qguard_Wiki/Observability_Refactor`
Pages: /dashboard/tls-telemetry, /pki-visibility, /protocol-analytics, /tls-orchestrator

## Findings from the audit (what was wrong)

1. `/api/v1/dashboard/tls-orchestrator` was mounted on the SAME router as
   tls-telemetry — the orchestrator had no backend of its own.
2. `tls-telemetry.ts` synthesised "connections" from certificate rows, scan
   results and security events (`connections: 1` per row) and then reported them
   as `totalConnections` / `successfulHandshakes` — handshake counts that were
   never observed.
3. `protocol-analytics` was a `mode="protocol"` alias of the generic
   CryptoOperationsDashboard — no protocol-specific model at all.
4. `tls-orchestrator/page.tsx` fabricated middlebox TYPES (`index % 3 === 0 ?
   'Load Balancer' : ...`), derived `classicalPercent` as
   `100 - hybrid - downgrade`, and hardcoded an "Admin / CISO" identity card.
5. Cipher-suite handling used substring matching (`isWeakTls`) instead of the
   canonical `analyzeCryptoObservation()` decomposer — the exact defect class
   documented in `src/lib/crypto/suite-anatomy.ts`.
6. No shared model: each page had its own classification, so the same asset
   could read differently on each.
7. SSE carried only a "refresh" ping with the token in the query string.
8. No hooks — fetch logic was copy-pasted inside each page component.

## Target architecture

    assets / crypto_inventory / certificates / runtime_crypto_events /
    scanner_evidence / pqc_scan_results / crypto_exposures / migration_jobs
        |
        v
    buildSnapshot()  (quantum-readiness — canonical tenant scores)
    buildPortfolio() (migration-planner — canonical per-asset posture)
        |
        v
    src/lib/tls-pki/*            pure, isomorphic ONE model
      - classify.ts   canonical TLS/PKI classification on suite-anatomy
      - intelligence.ts  buildTlsPkiIntelligence(inputs)
        |
        v
    src/api-server/tls-pki.ts    single 15s single-flight cache, 4 view
                                 projections + SSE + server-side paging
        |
        v
    src/hooks/use-tls-pki.ts     header-auth SSE + realtime nudge + backoff
        |
        v
    4 pages sharing _components/tls-pki primitives

## Steps

- [x] Audit existing endpoints, hooks, SSE, data model
- [x] `src/lib/tls-pki/types.ts` — canonical types
- [x] `src/lib/tls-pki/classify.ts` — endpoint/cert/protocol classification
- [x] `src/lib/tls-pki/intelligence.ts` — the pure engine
- [x] `src/api-server/tls-pki.ts` — loader + cache + 4 routers + real actions
- [x] Mount in `index.ts`, retire `tls-telemetry.ts` / `pki-visibility.ts`
- [x] `src/hooks/use-tls-pki.ts`
- [x] `_components/tls-pki/` shared UI primitives
- [x] Rewrite the 4 pages
- [x] Typecheck + build + browser verification against live tenant data

## Accuracy defects the live-data verification caught (all fixed)

Measured on the real tenant (2 assets, 68 components), the first working build
still published several false statements. Each was fixed at the source:

1. **11 "TLS endpoints" on a 2-asset estate.** `runtime_crypto_events` and
   `scanner_evidence` carry library, config-reference and process observations
   as well as transport ones. A `crypto_library` row naming RSA-2048 on host
   `e2e-fixture` minted a phantom TLS endpoint with a quantum-vulnerable
   verdict, and sat in the denominator of every percentage. Fixed with
   positive-evidence gates (`isTransportEvent` / `isTransportEvidence`).
   Endpoints: 11 → 4, measured: 3.
2. **"Legacy TLS: 0 — no deprecated protocol observed"** printed directly above
   an anomaly panel reporting a TLS 1.0/1.1 endpoint. Two causes: `TLSv1` (no
   minor number) was unparseable, and the tile read the version CEILING instead
   of the floor. Both fixed; legacy now 1, and the same rule is used by the
   posture tile, the protocol page and the orchestrator.
3. **Orchestrator skipped the critical action.** Same ceiling-vs-floor bug: an
   endpoint preferring TLS 1.2 while still answering TLS 1.0 was offered only
   "Enable TLS 1.3". Now emits "Disable deprecated TLS versions" (critical).
4. **5 certificates on a 3-certificate estate.** One leaf appeared as
   `CN=www.cloudflare.com`, `www.cloudflare.com` and
   `https://www.cloudflare.com/`; one CA appeared under both its RFC 4514 DN and
   its comma-joined value list. Fixed with `commonNameOf()` normalisation plus a
   conservative second merge pass for records carrying no serial/fingerprint.
5. **`RSA-2048-2048`, `ECDSA P-256 (Certificate)-256`.** Key size appended to an
   algorithm string that already stated it. One shared `algorithmLabel` on the
   model now serves every surface.
6. **Findings list read "Rsa / Rsa / Rsa / Rsa".** Four distinct findings looked
   like one repeated row: `titleCase` destroyed the acronym and the title never
   named the measured value. Fixed with an acronym-aware `labelCase` and a title
   that carries the suite.
7. **Cipher suites filed under "key agreement".** The category was guessed from
   the whole narrative (which mentions "forward secrecy"); it now asks the
   canonical decomposer what the algorithm actually is.
8. **Cold-start 500 on the first request after every server start.** Caused by
   the route layer importing a helper from the engine. The PKI rollups moved
   into the engine, leaving a single-direction module graph.

## Verified end-to-end

* All four view endpoints return byte-identical shared figures (posture,
  totals, telemetry) — cross-page synchronisation holds by construction.
* Queueing an endpoint from the Orchestrator writes the Migration Planner's own
  queue (`migration_plans`), and the planner reads it back: one shared queue,
  no second writer. Test write reverted afterwards.
* Typecheck clean for all new modules; `vite build` succeeds.

## Non-negotiables

* Canonical unit is the ENDPOINT (asset + host + port). One identity everywhere.
* Every displayed number traces to a row; where evidence is absent the surface
  says so ("Not observed" / "Awaiting telemetry"), never zero-as-good-news.
* Handshake counts only where an observation actually carries one.
* Orchestrator actions call real backends (migration-planner queue/plans) or are
  navigational and labelled as such. No fake progress.
