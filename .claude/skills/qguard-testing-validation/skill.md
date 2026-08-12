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
tools/scanner-hero-cards-check.ts      hero card label/colour consistency (exhaustive
                                       sweep of the node state space) + measured-hybrid
                                       PQ honesty, with classical/unprobed negative controls
tools/crypto-detection-check.ts        catalog structure, 8-language controls, false positives
tools/repo-provider-check.ts           platform parsing, misclassification guards
tools/public-scan-check.ts             LIVE public engine invariants (139) — scores,
                                       grading model, seven-state statuses, PLUS the
                                       unreachable-endpoint contract: an unanswered
                                       port must fast-fail (<20s, was 66.7s), mark
                                       stages `unavailable` not `failed`, and publish
                                       null for every score/risk/readiness. Also pins
                                       reachability classification — loopback must be
                                       `blocked`, which is how the SSRF hole from
                                       `net.connect` skipping `lookup` on IP literals
                                       was caught. `PROBE_UNREACHABLE_HOST` overrides
                                       the filtered target (default smtp.gmail.com)
tools/hndl-check.ts                    harvest-now-decrypt-later sections
tools/discovery-workflow-probe.ts      LIVE end-to-end scan + rail rendering
tools/dashboard-summary-check.ts       LIVE /dashboard/summary scale + direction:
                                       risk 0-100 lower-better vs readiness
                                       higher-better, bands derived from the
                                       shared tables, agreement with the
                                       executive KPI, subject-vs-finding counts,
                                       + an unmeasured-estate negative control
tools/scanner-finding-identity-check.ts  finding de-duplication identity (the four
                                       storage views of one observation collapse,
                                       distinct observations do NOT), narrative
                                       preservation, CBOM component partition,
                                       at-risk subset scope, chart denominator,
                                       algorithm-vs-posture classification, the
                                       sandbox graded-observation count, and risk
                                       score DIRECTION + non-saturation
tools/sandbox-twin-check.ts            twin/graph/predictions/benchmark/Sophia/
                                       approval gate + null-not-zero rollback
                                       figures and covered/detail agreement
tools/sandbox-latency-probe.ts         LIVE sandbox: cross-engine reconciliation,
                                       cold-vs-warm build cost, and the cache
                                       contract (single-flight via a shared
                                       `generatedAt`, TTL expiry, and with
                                       PROBE_MUTATE=1 the invalidate-on-write
                                       path, which cleans up after itself)
```

### The cross-population sanity probe

Two classes of defect are invisible in the source and obvious in the payload.
Run these against the live API before believing any headline count:

```js
// 1. Is a "findings" total actually distinct observations?
//    distinctBy(semantic key) << total means the dedupe key is wrong.
const g = new Map(); findings.forEach(f => {
  const k = [f.algorithm, hostOf(f.location)].join('|'); g.set(k, (g.get(k)||0)+1)
});
console.log(findings.length, '→', g.size)   // 255 → 66 was issue #20

// 2. Do per-row counts sum to the headline?
assets.reduce((s,a) => s + a.vulnerableCount, 0) === summary.vulnerableComponents

// 3. Do two INDEPENDENTLY derived counts of the same universe agree?
//    scanner severityCounts vs quantum-readiness riskDistribution vs the
//    workflow rail's "N critical · M findings" — all three read the same list.
```

An independently-derived count agreeing is the strongest evidence a grouping is
correct. Issue #20's fix was confirmed when the de-duplicated finding count
(66, of which 62 non-safe) matched `quantumVulnerableComponents: 62` produced by
an unrelated grouping of `crypto_inventory`.

### Verifying an authenticated endpoint without a password

`dashboard-summary-check.ts` needs a REAL user session — the service-role key
bypasses RLS and would read rows the app cannot, proving nothing. Mint one from
the service role instead of storing test passwords:

```ts
const { data: link } = await admin.auth.admin.generateLink({ type: 'magiclink', email })
const { data } = await anonClient.auth.verifyOtp({
  token_hash: (link as any).properties.hashed_token, type: 'magiclink',
})
const token = data.session!.access_token   // now call the API as that user
```

`generateLink` does NOT send mail, so it is safe to run repeatedly. The same
session can be injected into a browser via
`localStorage.setItem('sb-<project-ref>-auth-token', JSON.stringify(session))`
when a render site has to be checked. Clear it afterwards.

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
