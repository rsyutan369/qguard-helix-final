---
name: qguard-testing-validation
description: How QGuard Helix proves work is correct — the offline check-tool pattern, positive and negative controls, live probes, and what counts as evidence of completion. Use before claiming any task is done, when adding a verification tool, or when deciding what evidence a change requires.
priority: critical
owner: qguard-helix
version: 1.0
---

# Testing & Validation

**Implementation is not completion. Verification is completion.**

A claim of "done" must be accompanied by a command that was run and output that
was quoted. "It should work" is not evidence.

## The check-tool pattern

QGuard Helix verifies logic with standalone `tools/*-check.ts` scripts run via
`npx tsx`. They need no server, no Supabase and no network, so they run in
seconds and can be re-run by anyone.

```
tools/scanner-module-ledger-check.ts   ledger routing, producers, closure, partition
tools/scanner-dashboard-check.ts       assessment derivations, single-scope contract
tools/crypto-detection-check.ts        catalog structure, 8-language controls, false positives
tools/repo-provider-check.ts           platform parsing, misclassification guards
tools/public-scan-check.ts             public engine invariants
tools/hndl-check.ts                    harvest-now-decrypt-later sections
tools/discovery-workflow-probe.ts      LIVE end-to-end scan + rail rendering
```

Shape:

```ts
let failures = 0
function assert(condition: boolean, label: string) {
  if (condition) console.log(`  ok   ${label}`)
  else { failures += 1; console.log(`  FAIL ${label}`) }
}
// …sections…
process.exitCode = failures > 0 ? 1 : 0
```

**Do not call `process.exit()`** when the script opened a server or socket —
forcing exit races libuv's teardown on Windows and turns a passing run into exit
127. Set `process.exitCode` and let the loop drain.

## Positive and negative controls

Zero findings is ambiguous: *correctly found nothing* or *silently broken*. A
positive control removes the ambiguity by feeding the engine content that MUST
trigger.

```ts
// POSITIVE — planted content that must be detected
const source = `const h = createHash('md5')\nconst kp = generateKeyPairSync('rsa', {})`
assert(algosIn(source).includes('md5'), 'detects MD5')

// NEGATIVE — content that must NOT trigger
assert(detect('let seed = 42; regenerate(seed);').length === 0,
  'the word "seed" does not trigger the SEED cipher pattern')
```

Every expansion of a matching catalog needs both. A detector with no
false-positive test will eventually cry wolf, and a detector with no positive
control can silently die.

## Test the invariant, not the implementation

Assertions written by reading the code tend to encode the code's bugs. Prefer
invariants that would hold for *any* correct implementation:

- per-item counts sum to the displayed total
- surfaces partition the catalog exactly once
- every catalog module has a producer
- `Skipped` always carries a reason
- an unmeasured dimension is never scored

These caught real bugs that reading the code did not: `"asymmetric"` matching a
`symmetric` rule, `"Web Crypto (hash)"` misattributed, `.env` never selected.

## Live probes

Offline checks prove logic; a live probe proves the pipeline. `discovery-workflow-probe.ts`
runs a real scan, replays the API ledger and prints the Discovery Workflow exactly
as the dashboard renders it.

```bash
npx tsx tools/discovery-workflow-probe.ts www.cloudflare.com domain
```

Live probes must handle an unreachable network gracefully and **say which
assertions they skipped** — a probe that silently drops assertions when offline
reports false confidence.

## Evidence ladder

Pick the weakest rung that actually proves the claim:

| Claim | Required evidence |
|---|---|
| Logic is correct | offline check tool passes |
| Types are sound | `npx tsc --noEmit -p tsconfig.json`, filtered to touched files |
| It builds | `npm run build` |
| The engine really works | live probe against a real target |
| The route is mounted | `curl` returns 401 (proves router + auth) |
| The UI renders it | screenshot, or an explicit statement that the UI was not driven |

Never claim a rung you did not run. If the UI could not be driven — permissions,
auth, no browser — say so plainly instead of implying it was checked.

## Interpreting a full-repo typecheck

The repository has **15 pre-existing type errors** in `admin/page.tsx`,
`harvest-now`, `settings`, `tls-orchestrator`, `vault` and a few components.
They are unrelated to scanner work. Filter to what you touched:

```bash
npx tsc --noEmit -p tsconfig.json 2>&1 | grep -Ei "scanner|repo-|crypto-patterns|web-scanner"
```

Report the total separately so the number is not mistaken for regressions you
introduced.

## Completion checklist

- [ ] Relevant `tools/*-check.ts` pass — output quoted.
- [ ] `tsc` shows no errors in files you touched.
- [ ] `npm run build` succeeds.
- [ ] A live probe ran, or its absence is explained.
- [ ] New behaviour has a test that would FAIL without the change.
- [ ] Anything that could not be verified is stated explicitly.
