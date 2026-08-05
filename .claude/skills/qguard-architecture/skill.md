---
name: qguard-architecture
description: QGuard Helix platform architecture — where code actually lives, the runtime API topology, module communication, persistence as shared truth, multi-tenancy and scalability posture. Use when starting work in an unfamiliar area, adding a service or module, deciding where new code belongs, or when a change must stay consistent across dashboards, reports and downstream engines.
priority: critical
owner: qguard-helix
version: 1.0
---

# Platform Architecture

## The runtime topology — read this first

**`/api/v1` is served by the Express app in `src/api-server/`, mounted by Vite.**

Next-style `route.ts` files under `src/app/api/**` are **dead code** — they are
excluded in `tsconfig` and reference paths that do not exist. Editing them
produces no effect and is a recurring source of wasted time.

Consequences:

- Backend route changes require a `npm run dev` restart to register.
- Verify a route is mounted with `curl` — a `401` proves both the router and its
  auth middleware are live.

```
Browser (React/Vite)
   │  fetch + EventSource
   ▼
Express api-server  (src/api-server/*.ts, one router per domain)
   │  service-role or user-scoped Supabase client
   ▼
Supabase (Postgres + RLS + realtime)
```

## Persistence is the integration point

Modules do not call each other. They **share rows**.

The scanner writes `assets`, `crypto_inventory`, `pqc_scan_results`,
`crypto_exposures`, `certificates`, `pqc_scan_sessions`, `security_events`,
`audit_logs`, `vulnerabilities`. CBOM, Assets, Crypto Exposure, Quantum
Readiness, Migration Planner and Reports **recompute from those same rows**.

This is why cross-module consistency holds: the score is recomputed, the rows are
the shared truth. It is also why you must **never write a derived metric into a
table another module treats as raw input** — that turns a derivation into a
duplicate.

## Layering rule

```
lib/          pure domain logic — no Express, no Supabase, no React
api-server/   HTTP, auth, persistence, orchestration
app/          React surfaces; derivations in _intel.ts-style pure modules
```

`src/api-server/scanner-module-ledger.ts` is deliberately pure and
dependency-free so the **frontend can import it**. That is how backend finding
ownership and UI surface grouping are guaranteed not to drift. Prefer sharing a
pure module over reimplementing a rule on both sides.

## Shared snapshot caches — reuse, never hand-roll

Aggregations that several surfaces need are computed once behind a ~15 s
single-flight cache:

- `buildSnapshot()` — estate-wide posture
- `buildScannerIntelligence()` — scanner estate view (CBOM, Assets, Exposure, QR)

Six dashboards consume `src/lib/scanner/use-scanner-intelligence.ts`. **Do not
write a new aggregation query for a number one of these already produces** — that
is how two "authoritative" totals appear.

Design posture: **bounded detail, exact headline.** Headline counts are exact;
detail lists are capped and say so.

## Multi-tenancy

- Every query is tenant-scoped; `user_id` is pinned server-side, never taken
  from the client.
- RLS is the backstop, not the mechanism. Client-side authorization is never
  trusted.
- Owner-only surfaces bypass RLS deliberately via service-role SSE, because RLS
  makes client realtime useless for cross-tenant views. Where that happens it is
  explicit and audited.
- Realtime requires tables to be in the `supabase_realtime` publication —
  a missing publication is a silent failure mode.

## Streaming

SSE is the platform's realtime transport (`text/event-stream`). Contracts live in
`qguard-scanner-orchestration` and `qguard-backend-engineering`. The invariant
that matters architecturally: **only the outermost orchestrator may declare a run
terminal**; nested engines' lifecycle frames are namespaced before forwarding.

## Agent / connector model

Cloud, Kubernetes, container and VM discovery run through the tenant-owned
collector and connector model in `src/api-server/agent-scanner.ts`, with an
explicit credential boundary: **QGuard never holds global credentials**;
customers authorise least-privilege access in their own environment.

When asked to "add cloud scanning", the architectural answer is usually *wire the
crypto catalog into the existing collector ingestion path*, not build a new
provider SDK integration.

## Adding a module — checklist

- [ ] Pure logic in `lib/`, HTTP in `api-server/`, derivations beside the surface.
- [ ] Reuse `buildSnapshot` / `buildScannerIntelligence` rather than new queries.
- [ ] Persist to the shared tables; do not invent a parallel store.
- [ ] Tenant-scope every read and write.
- [ ] If backend and frontend need the same rule, share a pure module.
- [ ] Restart the dev server after adding routes; verify with `curl`.
