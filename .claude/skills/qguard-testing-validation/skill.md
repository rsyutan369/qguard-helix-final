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
tools/sandbox-details-check.tsx        Details dialog: resolves operational AND
                                       sandbox rows (old lookup as negative
                                       control), every operational stage incl.
                                       unreadable-≠-no, role table vs
                                       agentMayWrite source, 409 guard on engine
                                       actions, and renderToStaticMarkup of both
                                       dialog kinds (wrap Link users in MemoryRouter)
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

### Agent authority + rollback (needs the dev server)

`rollback-live-check.ts` drives the whole audited lifecycle against real rows:
enrol collector/patcher/operator → claim → snapshot gate → executed event →
restore → agent acknowledgement → audit. It creates and deletes everything it
touches, including on failure.

```bash
npx tsx tools/rollback-check.ts          # 83 offline invariants, no server
npx tsx tools/rollback-live-check.ts     # 82 live assertions, needs :3000
npx tsx tools/platform-reset.ts          # dry run; --apply clears all operational data, keeps accounts/billing
npx tsx tools/rollback-legacy-reconcile.ts   # dry run; --apply to correct legacy rows
```

Two things it catches that reading the code did not:

- **an agent with no heartbeat is not an executor.** The first live run returned
  `awaiting-executor` for a correctly-enrolled operator, because the check never
  made the agent check in. That is the gate working; the check was wrong.
- **agent-authenticated routes need `x-qguard-agent-id` as well as the bearer
  token** (`requireAgentAuth`). A bearer-only call returns 401 and looks like a
  bad token.

### Revenue Intelligence + billing integrity (needs the dev server for --live)

```bash
npx tsx tools/revenue-intelligence-check.ts                  # 25 offline: model fixture, negative controls, webhook rules, CSV injection
npx tsx tools/revenue-intelligence-check.ts --live           # +13: owner gate + audit rows, exports, SSE, RLS exploit probes, Admin MRR == Revenue MRR
npx tsx tools/revenue-intelligence-check.ts --live --mutate  # +5: Admin -> DB -> User UI -> Revenue on a QA row (restored), provider guard
npx tsx tools/revenue-intelligence-render-check.ts           # 40 static renders: 6 pages x loading/error/stale/empty/QA/populated
npx tsx tools/billing-edge-check.ts                          # Edge Function pure logic
```

What these caught that reading the code did not:

- **`fetch().text()` strips a UTF-8 BOM.** The export check failed "missing BOM"
  on a correct export. Assert the first three BYTES (`arrayBuffer()`).
- **A 33-day-old subscription gives a real 0% churn.** A negative control that
  expected `null` was wrong; the fixture had to be younger than the 30-day window.
- **Page components import the browser Supabase client** (via the dashboard
  primitives), which reads `import.meta.env` and crashes under plain tsx. The
  render check loads its cases through `vite.createServer().ssrLoadModule()` —
  the dev server's own transform — instead of patching `src/lib/supabase.ts`.
- **Deno Edge Functions can be type-checked without Deno:** a throwaway
  tsconfig with `paths: { "jsr:@supabase/supabase-js@2": ["node_modules/@supabase/supabase-js"] }`
  and a `declare const Deno` shim. Prove it with a negative control (inject a
  type error into a copy — it must fail).

### Owner Admin > Users (needs the dev server for --live)

```bash
npx tsx tools/admin-users-check.ts                    # 20 offline: directory model fixture (status drift, NULL role filter, entitlement, unmeasured = null, CSV injection)
npx tsx tools/admin-users-check.ts --live             # +10: API vs an independent read of auth (RPC) + billing; Overview/Security tabs == Users tab
npx tsx tools/admin-users-check.ts --live --mutate    # +18: every action on a DISPOSABLE account it creates and deletes
npx tsx tools/admin-users-sse-probe.ts                # stream: idle ticks keep one version, a write pushes a new one (~0.4s)
```

What these caught that reading the code did not:

- **An admin plan grant on a user with no billing row failed** on
  `billing_subscriptions.subscription_id NOT NULL` — the old "Approve Pro"
  button never worked for such users. Only the `--mutate` run exercises it.
- **Sign-out must be proven with the OLD token.** The check calls
  `/api/v1/profile` with the pre-revocation access token (expects 401) and
  `refreshSession` with the old refresh token (expects an error). Sleep ~1.1s
  before minting the next token: `iat` is whole seconds.
- **Supabase's built-in mailer rate-limits** reset emails (429); the check
  accepts "sent" or a clear provider error, never a silent success.
- A heavy `npm run build` on this machine (~1.5 GB free RAM) starves the dev
  server for minutes: a failing live probe right after a build is not a code
  regression — re-measure `curl -w %{time_total}` on a 401 first.

### Owner Admin > Roles, Tenants, Plans & Billing, Security, Governance, History

```bash
npx tsx tools/admin-console-check.ts                    # 25 offline: the six pure models (true permission counts, no invented domain/region, MRR rule, measured controls, policy verification, SHA3 tamper detection, history categories/past tense)
npx tsx tools/admin-console-check.ts --live             # +10: API vs an independent read of Supabase; Admin MRR == Revenue MRR; no fabricated threat/compliance text
npx tsx tools/admin-console-check.ts --live --mutate    # +12: every action on DISPOSABLE role/tenant/user/policy/evidence it creates and removes
npx tsx tools/admin-console-sse-probe.ts                # every console frame: delivered, version stable while idle, new version <1s after a write
```

What these caught that reading the code did not:

- **Creating a tenant without a storage quota 500'd** (NOT NULL column, the API
  wrote NULL). The form had promised "Empty = unlimited". Only `--mutate` hit it.
- **Edits audited unchanged fields** — the no-op PATCH assertion
  (`NO_CHANGES`, `changes` keys) caught it.
- **The revenue check leaked 3 live sessions per run** — found by querying
  `auth.sessions` for `user_agent = 'node'` after the probes. After any live
  check, that count for the run window must be 0.
- **Mobile blowout on Security only** — measure `main.scrollWidth` vs
  `clientWidth` per tab at 375px (document width alone stays 375 because `main`
  clips), then list elements whose right edge exceeds the viewport outside an
  `overflow-x: auto` ancestor.

### Assets & CBOM register + Report Studio (/dashboard/assets)

```bash
npx tsx tools/asset-register-check.ts                    # 54 offline: findings never components, CBOM-key grouping, PQC-ready only when all safe, unassessed band, evidence-time freshness, NIST-role PQC targets, subset totals, divergence reporting
npx tsx tools/asset-report-check.ts                      # 96 offline: scope honesty, reconciliation, consolidation totals, validation gates, KEM-on-signature sweep, SHA3 seal + tamper control, 3 templates x 7 formats rendered + structurally checked, 600-asset build bound
npx tsx tools/assets-live-check.ts http://localhost:3001 # 57 live on 3 tenants: API contract, register == CBOM == QR, no finding as component, evidence-based last-scanned, change-only SSE, reports reconcile
```

What these caught that reading the code did not:

- **`null ?? fallback` is not "no value".** A fixture meaning "never scanned"
  passed `lastScanned: null` and `??` turned it into a timestamp — which exposed
  the real defect: an asset with no evidence got its RECORD time as "last
  scanned". Use `'key' in o ? o.key : default` in fixtures.
- **"No exception" is not "renders correctly".** All 21 template x format
  renders succeeded before anyone looked; rasterising the PDF showed a 25-column
  register wrapping one character per line. With no poppler on this machine,
  render pages via pdf.js in headless Chrome (scratch `pdfshot.mjs`) and drive the
  page over CDP with Node 24's built-in `WebSocket` (`.report-smoke/page-shot.mjs`:
  magic-link session into localStorage, tall viewport because the dashboard
  scrolls inside its own container, `Browser.setDownloadBehavior` to capture real
  browser exports).
- **Per-click generation** gave each format of "one" report its own id and digest;
  grep the report id across every downloaded file.

### Database security changes (live project)

```bash
npx tsx tools/security-definer-check.ts   # anon / member / outsider probes through the Data API
```

- **`verifyOtp` signs in the client it runs on.** Minting sessions on the shared
  "anon" client silently turned every later anon probe into an authenticated
  call; a revoked-for-anon function looked still callable. Use a throwaway
  client per sign-in.
- **Dry-run RLS / function changes on the real schema** with
  `BEGIN; snapshot; <migration>; snapshot; DO $$ ... RAISE EXCEPTION '<report>' $$`
  — the exception rolls everything back and carries the report out. Snapshot
  per (user x table) row counts by `SET LOCAL ROLE authenticated` +
  `set_config('request.jwt.claims', ...)`, and record `insufficient_privilege`
  as a value (-1) instead of letting it abort the run.
- **pg_cron / scheduled SQL**: test the function in the same rollback pattern
  with a throwaway row whose period already ended AND one that has not.

Two traps worth remembering for any check of this shape:

- assert the **call site**, not just the helper. The headline defect here was a
  correct `agentMayWrite(..., 'migration')` with no caller, which every unit test
  of the helper would have passed.
- assert that a dashboard builder performs **no writes** by regexing its own
  function body for `.update(` / `.insert(`. `buildSnapshotDashboard` was
  rewriting migration jobs on a GET.

### Sophia AI Copilot (/dashboard/sophia)

```bash
npx tsx tools/sophia-question-audit.ts                     # 1,440 checks: EVERY suggested question + follow-ups + per-asset + empty tenant + analyst role + change tracking; expected values from the REAL buildRemediationPlan / buildAssetRegister
SOPHIA_AUDIT_PRINT=1 npx tsx tools/sophia-question-audit.ts # same, printing each answer for prose review
npx tsx tools/copilot-check.ts                             # security: tenant scoping, RBAC, injection, rate limit
npx tsx tools/sophia-check.ts                              # algorithm-question accuracy (RSA/ECDSA/ML-KEM joins, 42703 vs 42P01)
npx tsc --noEmit -p tsconfig.sophia.json                   # ~1 min scoped typecheck (full repo tsc takes >9 min)
```

What these caught that reading the code did not:

- **Mocks that share the code's bug.** The builder mocks used the same wrong
  field names as the tools (`criteria`, `label`, `banner.level`), so a certification
  answer that could never name a blocker passed. Shape mocks from the real type.
- **Asking the product's own suggestions.** The suites asserted hand-picked
  questions; none asked the eleven questions the page offers. The audit now fails
  if any offered suggestion is not covered.
- **Reading the prose.** `SOPHIA_AUDIT_PRINT=1` exposed a dossier listing the
  SAFE AES-256-GCM after "are quantum-vulnerable" — every assertion passed.

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

The repository has **~26 pre-existing type errors** in `admin/page.tsx`,
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
