---
name: qguard-backend-engineering
description: Backend implementation standards for QGuard Helix — Express /api/v1 routers, Supabase access, Server-Sent Events, background work, error handling, retries, graceful degradation and audit logging. Use when adding or changing an API route, streaming endpoint, persistence path, scheduler or connector.
priority: critical
owner: qguard-helix
version: 1.0
---

# Backend Engineering

Runtime topology and the dead-`route.ts` trap: see `qguard-architecture`.

## Router conventions

One router per domain in `src/api-server/`, mounted under `/api/v1/<domain>`.

```ts
const router = Router()
router.use(requireAuth)     // resolves the user, pins req.user — never trust the client
```

- Errors are typed: `res.status(4xx).json({ error: { code, message } })`.
- `code` is a stable machine string; `message` is operator-readable.
- Tenant-scope every query with the resolved `user.id`.

Auth uses **local ES256 verification with a cache** (`getServerUser`), not a
per-request GoTrue round-trip — that was the cause of slow pages and burst 401s.
Pass `{ full: true }` only when `created_at` / `last_sign_in_at` are needed.

## Server-Sent Events

```ts
res.setHeader('Content-Type', 'text/event-stream')
res.setHeader('Cache-Control', 'no-cache, no-transform')
res.setHeader('Connection', 'keep-alive')
res.setHeader('X-Accel-Buffering', 'no')   // required behind proxies
res.flushHeaders?.()
```

Rules learned the hard way:

- **Only the outermost orchestrator declares a run terminal.** Namespace a nested
  engine's own lifecycle frames before forwarding (`target-scan-complete`).
- Intermediate frames must not carry `status: 'completed'`.
- Reserve the top of the progress range for finalization; clamp nested progress.
- Handle `req.on('close')` — mark the job cancelled so work stops.
- Always `res.end()` in `finally`, and delete the job from the active map.
- Emit a machine-readable summary with terminal frames (`moduleLedger`) so the
  client never has to infer state from absence.

## Persistence

- Writes go to the shared cryptographic tables; other modules recompute from
  them. Never write a derived metric into a raw-input table.
- Provide a **memory fallback** (`PersistenceMode`) so a missing table degrades
  rather than failing the run.
- Cascading deletes must be explicit and tenant-scoped, with orphan cleanup that
  preserves rows still referenced by other scans.
- Write an audit tombstone for destructive operations.

## Graceful degradation — the contract

An expected failure is a **result**, not an exception.

```ts
// Not found / private / rate limited / unreachable / empty
return {
  accessible: false,
  notice: 'GitHub denied access to "owner/repo" (HTTP 403) — the API rate limit may be exhausted.',
  recommendation: 'Configure GITHUB_TOKEN on the scanner to raise the limit and read private repositories.',
  patterns: [],
}
```

Every degraded path carries **why** and **what to do next**. A caller must be
able to distinguish *nothing found* from *could not look* — collapsing those two
is how a scan reports a clean bill for something it never read.

## Retries and timeouts

`withRetry(fn, name, retries, timeout)` wraps each module: bounded retries,
per-module timeout, and an overall scan timeout racing the whole run.

- Give slow modules their own budget (TLS needs ~45 s for handshake + probes).
- Report a retry as evidence — a target that only responds on attempt 3 is a
  finding about stability.
- An error accompanied by evidence is a **Completed measurement with a caveat**,
  not a failure.

## Background work and schedulers

- Never let an unhandled rejection reach the process — it kills the server. Wrap
  scheduled work in try/catch and log with context.
- Long-running work belongs in a job with lease/backoff/dead-letter semantics
  (see the migration orchestrator), not in a request handler.
- Heartbeats: 30–60 s.

## Environment and secrets

- Read tokens from `process.env` **server-side only**; guard with
  `typeof process === 'undefined'` so shared modules stay bundler-safe.
- Never log a token; never return one to the client.
- Missing optional credentials must degrade with guidance, never throw.
- Vite dev only exposes whitelisted env vars to the client — a `VITE_`-prefixed
  value is **inlined at build time**, so editing `.env` requires a rebuild.

## Review checklist

- [ ] `requireAuth` applied; `user.id` pinned server-side.
- [ ] Typed error envelope with a stable `code`.
- [ ] SSE headers complete; `close` handled; `res.end()` in `finally`.
- [ ] Terminal frames carry the authoritative summary.
- [ ] Expected failures return a `notice` + `recommendation`, never throw.
- [ ] Timeouts and bounded retries on every outbound call.
- [ ] Dev server restarted and route verified with `curl`.
