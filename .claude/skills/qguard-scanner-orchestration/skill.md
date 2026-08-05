---
name: qguard-scanner-orchestration
description: The scanner module execution contract for QGuard Helix — module ledger, terminal-state guarantee, web-to-catalog routing, finding ownership, SSE frame discipline and the Discovery Workflow rail. Use when changing /dashboard/scanner, /api/v1/scanner, the web-scanner orchestrator, adding a scanner module, or when modules report Skipped/Queued/wrong counts.
priority: critical
owner: qguard-helix
version: 1.0
---

# Scanner Orchestration & the Module Ledger

## Where the code is

| Concern | File |
|---|---|
| HTTP + SSE route, persistence, Scanner_2 pass | `src/api-server/scanner.ts` |
| **Module ledger** (catalog, routing, ownership, applicability) | `src/api-server/scanner-module-ledger.ts` — *pure, no Express/Supabase* |
| Live web scan (TLS, cert, cipher, headers, code) | `src/lib/scanner/web-scanner/scan-orchestrator.ts` |
| Repository scanning, all platforms | `src/lib/scanner/web-scanner/repo-scanner.ts` |
| Dashboard state + SSE reader | `src/app/dashboard/scanner_dashboard/ScannerDashboard.tsx` |
| Derivations for every result panel | `…/scanner_dashboard/_intel.ts` |

The ledger is dependency-free **on purpose**: the frontend imports it so backend
ownership rules and UI grouping cannot drift apart.

## The ledger contract — four invariants

1. **No module is ever left unresolved.** Before every terminal frame
   (`scan-complete`, `scan-failed`, `scan-cancelled`), `closeModuleLedger()` runs.
   When the client is told the run ended, every module carries
   `Completed | No findings | Failed | Skipped`.
2. **`Skipped` always carries a reason** and `notApplicable: true`. It means
   "does not apply to these targets" — never "we lost track of it".
3. **An applicable module that never reported is `Failed`**, with the cause.
   Downgrading an execution gap to a skip hides a real defect.
4. **Ownership is total and unique.** Every finding has exactly one owning
   module, and per-module counts sum to the assessment total.

```ts
const closeModuleLedger = (abortReason: string | null) => {
  const applicability = moduleApplicability(normalized)
  for (const module of moduleStates) {
    if (module.status !== 'Queued' && module.status !== 'Running') continue
    const reason = applicability[module.id]
    if (reason && module.status === 'Queued') {
      updateModule(module.id, { status: 'Skipped', reason, notApplicable: true, error: null })
      continue
    }
    const failure = abortReason
      ? `Scan ended before this module reported: ${abortReason}`
      : 'Module did not report a terminal state before the run finished'
    updateModule(module.id, { status: 'Failed', error: failure, reason: failure })
  }
}
```

Close the ledger **before** persistence, so the states written to history are the
states the client receives.

## Adding a scanner module — the checklist

- [ ] Add `{ id, name }` to `SCANNER_MODULE_CATALOG`.
- [ ] Give it a **real producer** — an orchestrator block emitting
      `module-start`/`module-complete`, or an API-layer lifecycle call.
- [ ] Add an EXACT entry to `WEB_MODULE_TO_CATALOG` (substring matching is
      fallback only — it is how "Detection Rules Engine" once published the hash
      scanner's state).
- [ ] Route its findings in `moduleIdForFinding`, most-specific-first.
- [ ] Assign it to exactly one surface in `SCANNER_NODE_MODULES`.
- [ ] Add an applicability reason in `moduleApplicability` if it can legitimately
      not apply.
- [ ] `tools/scanner-module-ledger-check.ts` asserts every catalog module has a
      producer and that surfaces partition the catalog exactly.

## Signalling "not applicable" from the orchestrator

Do not put the reason in a free-text error and sniff for it later. Use the marker:

```ts
export const NOT_APPLICABLE_PREFIX = 'not-applicable:'
moduleComplete('cipher-suite-analyzer', 'Cipher Suite Enumeration', target, 54, count,
  tlsResult ? null : notApplicable('cipher suite enumeration requires a completed TLS handshake'))
```

`classifyModuleOutcome()` turns it into `{ status, error, reason, notApplicable }`.
Note the deliberate rule: **an error alongside evidence is a Completed
measurement with a caveat**, not a failure.

## SSE frame discipline

**Only the outermost orchestrator may declare a run terminal.** A nested engine's
own lifecycle frames must be namespaced before forwarding:

```ts
const forwardedType =
  event.type === 'scan-complete' ? 'target-scan-complete'
: event.type === 'scan-start'    ? 'target-scan-start'
: event.type === 'error'         ? 'target-scan-error'
: event.type
```

Client-side, require positive proof of the authoritative frame:

```ts
const isTerminalComplete =
  event.type === 'scan-complete' && event.status === 'completed' && Boolean(event.scanSessionId)
```

Other frame rules learned the hard way:

- Reserve the top of the progress range (98–100) for finalization; clamp
  per-target progress to 97 so a nested frame cannot paint a full bar mid-run.
- Intermediate frames must not carry `status: 'completed'` — use `'analyzing'`.
- **Never `await` unrelated I/O inside the stream reader** (`void fetchHistory()`).
- The QVE timeline is **append-only** — an entry can never be updated, so a
  `status: 'running'` line keeps its spinner forever. Log settled observations
  only (`details.timeline = false` for Running transitions).

## Multi-target runs

Module states are per **run**, not per target. Therefore:

- **A measurement is never downgraded to not-applicable.** In a mixed queue
  (domain + repo), the repository pass would otherwise mark TLS modules
  inapplicable and erase evidence the earlier target produced.

```ts
const alreadyMeasured = state.status === 'Completed' || state.status === 'No findings'
if (alreadyMeasured && patch.status === 'Skipped') return
```

- Per-module counts come from a run-scoped ledger, not from recomputing over
  `results` (which is only appended when a target finishes — that is why live
  cards used to reset to "1 finding").

## The Discovery Workflow rail

Stage states are disjoint and each means exactly one thing:

| State | Meaning |
|---|---|
| `complete` | every owned module resolved, at least one measured |
| `partial` | measured, but a module never reported — a real gap |
| `na` | every owned module legitimately did not apply |
| `failed` | an owned module errored |
| `running` / `waiting` | not reached yet |

Coverage is `measured / applicable` **everywhere** (rail, Discovery Coverage,
Module Execution Flow) — not-applicable modules leave the denominator, or a web
scan permanently reads ~70% covered.

## Verification

```bash
npx tsx tools/scanner-module-ledger-check.ts      # routing, producers, closure, partition
npx tsx tools/discovery-workflow-probe.ts www.cloudflare.com domain   # LIVE end-to-end
npx tsx tools/scanner-dashboard-check.ts          # assessment derivations
```

The probe runs a real scan, replays the API ledger and prints the rail — a
healthy run shows all six surfaces COMPLETE with counts tallying exactly.
