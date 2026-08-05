---
name: qguard-frontend-engineering
description: Frontend implementation standards for QGuard Helix — React and TypeScript structure, consuming SSE streams, derivation modules, hooks, state scope, realtime throttling, and render performance. Use when building or changing a dashboard surface, wiring a stream to the UI, adding a hook, or fixing stalled/flickering/inconsistent UI state.
priority: critical
owner: qguard-helix
version: 1.0
---

# Frontend Engineering

Stack: React + TypeScript + Vite + Tailwind + ShadCN + Framer Motion.
Routing is `react-router-dom`. Data comes from `/api/v1` over fetch and SSE.

## Surface composition

A dashboard surface is split so derivations stay pure and testable:

```
ScannerDashboard.tsx   state, handlers, SSE reader
_types.ts              shared vocabulary mirroring the SSE payloads
_intel.ts              PURE derivations: evidence → assessment model
_hero.tsx              visualization
_sections.tsx          result panels — each takes `assessment`, not raw state
```

**Panels receive the derived model, never raw state.** One derivation
(`buildAssessment`) feeds every panel, which is what makes cross-panel agreement
structural rather than aspirational. See `qguard-data-integrity`.

Because `_intel.ts` is pure, `tools/scanner-dashboard-check.ts` drives it with
fixtures — no browser, no server.

## Consuming an SSE stream

```ts
const reader = response.body.getReader()
let buffer = ''
while (true) {
  const { value, done } = await reader.read()
  if (done) break
  buffer += decoder.decode(value, { stream: true })
  const chunks = buffer.split('\n\n')
  buffer = chunks.pop() || ''            // keep the partial frame
  for (const chunk of chunks) { /* … */ }
}
```

Rules:

- **Never `await` unrelated I/O inside the loop.** `await fetchHistory()` stalls
  consumption of frames the backend has already written. Use `void fetchHistory()`.
- **Require positive proof of a terminal frame** — do not treat any
  `scan-complete` as the end:

```ts
const isTerminal = event.type === 'scan-complete'
  && event.status === 'completed'
  && Boolean(event.scanSessionId)
```

- Apply the authoritative array when it arrives (`event.moduleStates`) rather
  than accumulating your own view of it.
- Preserve `AbortController` for cancel, and reset all derived state at run start.

## Live vs reconciled state

Two distinct inputs, deliberately:

| Prop | Meaning |
|---|---|
| `findings` / `modules` | the LIVE stream — empty between runs, drives animation |
| `evidenceFindings` / `evidenceModules` | reconciled (live, else the persisted scan) — drives panels |

Feeding reconciled state into a visualization replays it as if a scan were
running; feeding live state into panels empties them after a reload. Keep them
separate and name them clearly.

## Realtime discipline

- Throttle realtime-triggered reloads (~500 ms). Un-throttled
  supersede-before-complete storms are a known cause of "stuck loading".
- Handlers must be idempotent — the same event will arrive twice.
- Budget `EventSource` connections per page; browsers cap per-origin HTTP/1.1
  connections and five streams will saturate it.
- A table must be in the `supabase_realtime` publication or subscriptions
  silently never fire.

## Hooks and effects

- Key effects on **stable identity** (`conversation.id`), not on the object —
  keying on the object re-runs on every re-render.
- Reading latest state without re-subscribing: keep it in a ref
  (`latestModules.current = modules`).
- Guard "settle once" transitions with a ref, and re-check preconditions inside
  the effect rather than trusting the dependency array.
- Withhold verdicts the evidence does not support: if a run is not gradeable,
  do not settle a grade onto the visualization.

## TypeScript

- Types mirror the SSE payloads in `_types.ts` — one vocabulary, not per-file
  re-declarations.
- New optional fields on persisted shapes must be optional (`reason?: string | null`)
  so history written before the field still parses.
- React 19: `key` is not part of props — a component typed with `key?:` fails
  `tsc`. Pass `key` on the element, never through a props type.
- Duplicate-React `key` gotcha: rendering a list of atoms from a second React
  instance needs a Fragment wrapper.

## Render performance

- Derive with `useMemo` keyed on real inputs; avoid recomputing an assessment on
  every frame of a live scan.
- Bail out of geometry/layout effects when nothing moved (compare within 0.5 px).
- Cap animated collections; pace bursts rather than rendering 200 events at once.
- Respect `prefers-reduced-motion` — drain queues immediately.
- Mobile: root grids need `grid-cols-[minmax(0,1fr)]` and the main scroll
  container `overflow-x-hidden`, or a wide table poisons the implicit track and
  the whole page pans sideways.

## Review checklist

- [ ] Panels take the derived model, not raw state.
- [ ] Derivations are pure and covered by a check tool.
- [ ] No `await` on unrelated I/O inside a stream reader.
- [ ] Terminal frames identified positively, not by type alone.
- [ ] Live and reconciled state are separate props.
- [ ] Realtime handlers throttled and idempotent.
- [ ] Unmeasured values render as Unknown, never 0.
