---
name: qguard-performance
description: Performance and scalability patterns for QGuard Helix — shared single-flight snapshot caches, bounded work budgets, streaming under load, query and render cost. Use when a page is slow, a scan is long-running, an aggregation is expensive, or a change must hold up across thousands of assets.
priority: high
owner: qguard-helix
version: 1.0
---

# Performance & Scalability

## Design posture: bounded detail, exact headline

Headline counts are **exact** — they are what the platform is judged on.
Detail lists are **capped**, and the cap is disclosed ("60 of 825 candidate files
were analysed"). Silence about truncation implies full coverage and is a
correctness bug, not just a performance one.

## Shared single-flight caches — reuse, never hand-roll

Estate aggregations are computed once behind a ~15 s single-flight cache:

- `buildSnapshot()` — estate-wide posture
- `buildScannerIntelligence()` — scanner estate view

Six dashboards consume `use-scanner-intelligence.ts`. **Do not add a new
aggregation query for a number one of these already produces.** Hand-rolled
duplicates cost queries *and* create a second "authoritative" total.

Supporting indexes live in `scale-indexes.sql`.

## Bounded budgets

Every outward-facing engine declares explicit limits:

| Budget | Value |
|---|---|
| Files per repository scan | 60 |
| Bytes per file | 500 KB |
| Matches per scan | 400 |
| Tree entries | 4 000 |
| Per-module timeout | 15 s (TLS 45 s) |
| Whole-scan timeout | 120 s |
| Inter-request delay | ~120–200 ms |

Prioritise **within** the budget rather than raising it: dependency manifests
rank above source files, because one manifest describes an entire dependency
graph while one source file describes one call site. A representative sample
beats a truncated arbitrary one.

## Line-level cost in matching

- Skip lines longer than ~4 000 chars — minified bundles are one enormous line
  and yield noise, not signal.
- Deduplicate per `(file, pattern)` within a small window so a loop that hashes
  twenty times contributes one finding.
- Never use `/g` on shared regex objects: `lastIndex` leaks between files.

## Streaming under load

- Reserve the top of the progress range for finalization; clamp nested progress.
- Pace event bursts to the UI rather than rendering 200 at once; drain
  immediately under `prefers-reduced-motion`.
- Throttle realtime-triggered reloads (~500 ms) — un-throttled storms are a
  known cause of "stuck loading".
- Budget `EventSource` connections per page; five saturate the browser's
  per-origin HTTP/1.1 limit and the page appears hung.
- Never `await` unrelated I/O inside a stream reader loop.

## Query cost

- Tenant-scope first; let the index do the filtering.
- Batch inserts instead of per-item round-trips (per-device serial inserts were a
  measured cause of slow sends).
- Avoid N+1 across module boundaries — read the shared snapshot instead.
- Auth: local ES256 verification with a cache, not a per-request GoTrue call.

## Render cost

- `useMemo` on real inputs; do not recompute an assessment per animation frame.
- Bail out of layout effects when geometry has not moved (0.5 px tolerance).
- Derive expensive panels only when open (the node inspector costs nothing while
  closed).
- Keep animation off the critical path of correctness — a visualization must
  never be the source of a number.

## Long-running work

Anything that can exceed a request belongs in a job with lease, backoff,
back-pressure and dead-letter semantics (the migration orchestrator is the
reference implementation), not in a handler.

## Checklist

- [ ] Reused an existing snapshot instead of a new aggregation.
- [ ] Explicit budget, with truncation disclosed to the user.
- [ ] Prioritisation makes the sample representative.
- [ ] Timeouts and bounded retries on every outbound call.
- [ ] No unrelated `await` inside a stream loop; realtime throttled.
- [ ] Memoised derivations; no per-frame recomputation.
