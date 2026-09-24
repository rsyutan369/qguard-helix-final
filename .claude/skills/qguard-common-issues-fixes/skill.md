---
name: qguard-common-issues-fixes
description: Registry of QGuard Helix problems that have already been diagnosed and fixed, indexed by the SYMPTOM a user reports. Use whenever a bug is reported, a dashboard shows wrong or inconsistent data, a scanner module misbehaves, SSE or realtime updates fail, scores disagree between panels, or a scan produces zero/implausible results. Each entry gives Problem, Root Cause, Solution and a Prevention Checklist.
priority: critical
owner: qguard-helix
version: 1.0
---

# Common Issues & Proven Fixes

Indexed by **what the user sees**, because that is what gets reported. Read the
symptom column first.

> Rule: never fix a symptom you have not reproduced or traced. If your fix would
> make the symptom disappear without explaining it, you are hiding it. See
> `qguard-debugging-rca`.

---

## 1. Discovery Workflow surfaces read "SKIPPED" on a scan that clearly measured them

**Symptom.** `/dashboard/scanner` shows "Transport & Ciphers · SKIPPED" and
"Certificates & Keys · SKIPPED" while the same cards show 10+ real findings. On a
re-run, almost every surface reads SKIPPED.

**Root causes — there were four, and all four were real:**

1. **Catalogued modules with no producer.** `key-exchange-scanner` and
   `signature-algorithm-scanner` were in the module catalog but nothing ever
   emitted a state for them. They sat at `Queued` for the whole run, and the rail
   painted anything unresolved-after-the-run as grey.
2. **Loose substring routing.** `mapWebModule` matched on substrings, so
   "Detection Rules Engine" published the *hash algorithm scanner's* state and
   masked the fact the real hash module never ran.
3. **A leaked per-target terminal frame.** `executeWebScan` emits its own
   `scan-complete` per target; the API forwarded it verbatim. The client treated
   it as the end of the job, flipped to "SCAN COMPLETE", marked every
   not-yet-reported module skipped, and graded a partial estate.
4. **TLS 1.3 key exchange read `unknown`.** TLS 1.3 suite names carry no
   key-exchange token and Node's `getEphemeralKeyInfo()` returns `{}` on some
   builds, so the key-exchange module reported "not applicable" on every modern
   endpoint.

**Solution.**

- `src/api-server/scanner-module-ledger.ts` — pure, dependency-free module
  holding the catalog, exact-id web→catalog routing, finding ownership, outcome
  classification, and target applicability.
- `closeModuleLedger()` runs before EVERY terminal frame. No module may be
  `Queued`/`Running` when the client is told the run ended.
- `Skipped` always carries `reason` + `notApplicable`. An applicable module that
  never reported is **Failed**, not Skipped.
- Per-target lifecycle frames are namespaced (`target-scan-complete`), and the
  client only accepts a terminal frame carrying `scanSessionId`.
- RFC 8446 permits only ephemeral (EC)DHE, so TLS 1.3 resolves to
  `ECDHE (TLS 1.3 key_share)` — a protocol guarantee, not a guess.

**Prevention checklist**

- [ ] Every catalogued module has a named producer, verified by a test.
- [ ] Routing tables match on EXACT ids; substrings are fallback only.
- [ ] A nested engine's lifecycle events are namespaced before forwarding.
- [ ] Only the outermost orchestrator may declare a run terminal.
- [ ] "Not applicable" always carries an operator-readable reason.
- [ ] Run `tools/scanner-module-ledger-check.ts` and `tools/discovery-workflow-probe.ts`.

---

## 2. Two panels show different numbers for the same thing

**Symptom.** "Grade A · 96%" beside "106 critical findings". Estate Footprint
disagrees with the Executive Summary. Hero counters disagree with the table.

**Root cause.** Per-field fallbacks: `summary?.critical ?? estate.criticalFindings`.
Each field independently chose scan-scope or estate-scope, so one panel described
a run and the next described the whole tenant. Both numbers were true; the
combination was nonsense.

**Solution.** Choose the scope ONCE and make every field follow it:

```ts
const scope: 'scan' | 'estate' = summary ? 'scan' : 'estate'
const scoped = {
  totalFindings: scope === 'scan' ? summary!.totalFindings : estate.totalFindings,
  critical:      scope === 'scan' ? summary!.critical      : estate.criticalFindings,
  // …every headline field, from the same branch
}
```

Also gate the grade: a run with unreported modules is **not gradeable**.

**Prevention checklist**

- [ ] No `a ?? b` fallback where `a` and `b` come from different populations.
- [ ] Every panel names the scope it is describing in its own copy.
- [ ] A test asserts scan-scope and estate-scope switch together, all-or-nothing.
- [ ] See `qguard-data-integrity`.

---

## 3. Repository scan returns zero findings on code that obviously uses MD5/RSA

**Symptom.** "Code & Dependencies · 0 findings" for a repository that plainly
contains `createHash('md5')` and `generateKeyPairSync('rsa')`.

**Root cause.** Two independent failures:

1. **Case sensitivity.** `/\bRSA\b/` and `/\bMD5\b/` were case-SENSITIVE, but
   real code passes lowercase strings to factories.
2. **Name-only matching.** The catalog matched algorithm NAMES; it had no rules
   for the API-call IDIOMS that dominate real source.

Compounding it: dependency manifests were invisible — `.txt` (requirements.txt)
and `.mod`/`.sum` were missing from the scannable extensions, and extension-less
files (Gemfile, Dockerfile, Pipfile) were filtered out before any pattern ran.
`.env` was skipped too, because `lastIndexOf('.') === 0` for a dotfile.

**Solution.** See `qguard-crypto-detection`. Catalog 65 → 125 patterns:
case-insensitive on distinctive tokens, API idioms across 8 languages, PQC rules,
MAC/KDF/hash families, 7 dependency ecosystems, and a basename-aware
`isScannablePath()` with a `SCANNABLE_FILENAMES` set.

**Prevention checklist**

- [ ] Every new pattern has a positive control in `tools/crypto-detection-check.ts`.
- [ ] Every catalog change bumps `EXPECTED_WEB_CRYPTO_PATTERNS` in `runtime-health.ts`.
- [ ] Zero findings is treated as a hypothesis to disprove, never as "clean".
- [ ] False-positive controls exist for any newly case-insensitive token.

---

## 4. A dashboard shows a plausible number that was never measured

**Symptom.** A perfect score for a dimension the scan could not reach.

**Root cause.** `risk-scoring.ts` invented values for unmeasured dimensions —
`50` for a missing certificate, and `0` risk (a *perfect* posture) for
application crypto when no repo was scanned.

**Solution.** Each dimension returns `number | null`. Unmeasured dimensions are
excluded and their **weight redistributed**; consumers receive
`breakdownApplicable` + `measuredWeight` so a measurement is distinguishable from
a filler zero.

**Prevention checklist**

- [ ] "Not measured" and "measured as good" never share a representation.
- [ ] Unmeasured dimensions leave the denominator; they are not scored 0 or 100.
- [ ] Empty-state tests assert Unknown, never a numeric default.

---

## 5. SSE stream stalls, or the UI freezes mid-scan

**Symptom.** Progress stops; frames arrive late in a burst; the page appears hung.

**Root causes.**

- `await fetchHistory()` **inside** the stream reader loop — a REST round-trip
  stalls consumption of frames the backend has already written.
- Un-throttled realtime reload storms (supersede-before-complete).
- Five simultaneous `EventSource` connections saturating the browser's per-origin
  HTTP/1.1 limit.

**Solution.** Never await unrelated I/O inside a reader loop (`void fn()`).
Throttle realtime-triggered reloads (~500 ms). Single-flight shared snapshots.
Budget EventSource connections per page.

**Prevention checklist**

- [ ] The stream reader body contains no `await` on unrelated network calls.
- [ ] Realtime handlers are throttled and idempotent.
- [ ] Count concurrent EventSource connections per page.

---

## 6. A regex silently never matches, and the source looks correct

**Symptom.** A pattern that is obviously right matches nothing.

**Root cause.** A shell heredoc (`python - <<'PY'` … `.replace()`) wrote a
**literal 0x08 backspace byte** instead of the two characters `\b`. `grep`, `sed`
and file readers all render 0x08 as nothing, so the source *looked* correct.

**Solution.**

```bash
python -c "import io;d=io.open('file.ts','rb').read();print(d.count(b'\x08'))"
```

Repair by replacing `b'\x08'` with `b'\x5cb'`. Same trap applies to `\f \v \a`.

**Prevention checklist**

- [ ] Use the Edit tool — not shell heredocs — for anything containing regex escapes.
- [ ] After a scripted edit touching escapes, scan for control bytes.
- [ ] A pattern that "should" match gets a unit test, not a read-through.

---

## 7. Module counts do not add up to the total

**Symptom.** Per-module finding counts sum to less/more than the headline total.

**Root cause.** Finding ownership was ambiguous: `moduleIdForFinding` routed
`"Certificate Signature"` to the hash scanner (the algorithm name contains
"sha"), so the signature module always showed zero. Ordering bugs of the same
family: `includes('symmetric')` also matches `"asymmetric"`; `includes('hash')`
claimed `"Web Crypto (hash)"` before the code-origin rule could.

**Solution.** Ownership is total and unique, and **order matters** — most
specific first. Code-origin categories are claimed before algorithm-class tests.
A run-scoped ledger (`moduleFindingLedger`) is the single place a per-module
count comes from.

**Prevention checklist**

- [ ] A test asserts per-module counts sum to the total.
- [ ] Every category maps to exactly one owning module.
- [ ] Substring rules are checked against their own superstrings.

---

## 8. Scan works locally but reads nothing in the deployed environment

**Symptom.** Repository scans return only a "Repository Access Notice".

**Root cause.** Unauthenticated GitHub API = 60 requests/hour/IP, exhausted.
Not a code defect — the graceful degradation was working as designed.

**Solution.** Set per-provider tokens on the api-server: `GITHUB_TOKEN`,
`GITLAB_TOKEN`, `BITBUCKET_TOKEN`, `AZURE_DEVOPS_TOKEN`, `GITEA_TOKEN`.
Verify with `curl -s https://api.github.com/rate_limit`.

**Prevention checklist**

- [ ] Rate-limit and auth state are surfaced in the finding, not swallowed.
- [ ] Degraded results carry an actionable `recommendation`.
- [ ] "Zero findings" distinguishes *nothing found* from *could not look*.

---

## 9. An ordinary website gets scanned as source code

**Symptom.** `https://example.com/blog/post` classified as a repository.

**Root cause.** The repository parser falls back to a Gitea-compatible shape for
ANY unknown host with two path segments — which describes most website URLs.

**Solution.** `RepoRef.confidence: 'certain' | 'heuristic'`. Auto-classification
(`repositoryProvider()`) trusts only `certain`; explicit user submission stays
permissive.

**Prevention checklist**

- [ ] Permissive parsers are never wired directly to auto-classification.
- [ ] Negative tests exist for the *absence* of a classification.

---

## 10. Backend route changes appear to have no effect

**Symptom.** A new endpoint 404s; a changed handler runs the old code.

**Root cause.** The runtime `/api/v1` is the Express app in `src/api-server/`,
mounted by Vite. Route registration happens at server start. Next-style
`route.ts` files under `src/app/api/**` are **dead code** (tsconfig-excluded).

**Solution.** Restart `npm run dev` after adding or changing a route. Edit the
Express router, not the Next route file.

**Prevention checklist**

- [ ] Confirm which file actually serves the path before editing.
- [ ] Verify with `curl` (401 proves the router mounted and auth is enforced).

---

## 11. A card's label says "Secure" while its colour says critical

**Symptom.** A hero node card on `/dashboard/scanner` reads **Secure** in red.
Quantum Posture reads **Critical** on an endpoint with live hybrid PQ.

**Root cause.** Two independent aggregations of one surface, rendered together.
`QveNode.verdict` was whatever module reported LAST (`moduleEvent()` in
`_qve-bridge.ts` wrote `details.verdict` per module, and a surface is fed by up
to eight), while the accent came from `beamColor(node)` — driven by
`node.severity`, the worst severity of ANY event routed there. A transport
surface that had already collected four static-RSA suites read "Secure" because
its last module happened to be clean.

**Solution.** `resolveNodeVerdict(node)` in `src/app/public-scan/_qve/types.ts`
is the ONE classifier; `beamColor` delegates to it, and the card label, badge
icon, border, meter and both node inspectors read the same result. The bridge no
longer emits a per-module verdict; the surface-specific phrase survives as muted
context under the state, never as the coloured headline.

**Prevention checklist**

- [ ] A displayed status word and the colour it is painted in come from ONE
      function of ONE input — never two derivations of the same evidence.
- [ ] A free-text phrase from a derivation is never rendered in a semantic
      colour; only a resolved state is.
- [ ] `tools/scanner-hero-cards-check.ts` sweeps the whole node state space
      (924 combinations) for label/colour contradictions. Extend it, don't
      spot-check.

---

## 12. A hybrid post-quantum endpoint is scored as classical-only

**Symptom.** Cloudflare (live `X25519MLKEM768`) reports HIGH "ECDHE (TLS 1.3
key_share)", HIGH "HNDL Risk", TLS-003 and HNDL-001 — and Quantum Posture
Critical.

**Root cause.** `tls.getEphemeralKeyInfo()` returns an EMPTY object for a TLS
1.3 handshake, so `tlsResult.keyExchange` degrades to the literal string
`"ECDHE (TLS 1.3 key_share)"` on *every* modern endpoint regardless of the group
negotiated, and `negotiatedCurve` is null. Every consumer that substring-tested
that label — `getKeyExchangeThreat`, `calculateHndlTimeline`, TLS-003, HNDL-001,
HNDL-003 — therefore concluded "classical ECDHE" even though the edge phase had
already proven the hybrid group by offering each named group in isolation.

**Solution.** Read `edgeIntelligence.pqKeyAgreement` (measured), not the socket
label. `measuredKemApplied(ctx)` in `detection-rules.ts` is the shared predicate;
`calculateHndlTimeline` takes a `kemApplied` argument; the orchestrator emits
`[SAFE] X25519MLKEM768` and suppresses the transport HNDL finding when the KEM
is applied. Certificate/signature exposure is untouched — a hybrid key agreement
does nothing for a classical certificate.

**Prevention checklist**

- [ ] Never infer a negotiated TLS 1.3 group from a Node socket property.
      Node exposes none; only the named-group probe knows.
- [ ] A PQC assertion reads measured evidence, never a finding title or a
      key-exchange label (recommendation strings contain "ML-KEM" too).
- [ ] Every suppression has a NEGATIVE control proving it still fires on a
      classical endpoint AND on an unprobed one.
- [ ] Verify against a known-hybrid host: `node -e` with
      `tls.connect({groups:'X25519MLKEM768'})` is the ground truth.

---

## 13. Every dashboard page reloads when the browser tab regains focus

**Symptom.** Switch browser tab or window, come back, and the page you were on
re-mounts from scratch — an in-progress scan's results vanish.

**Root cause.** A three-step chain. supabase-js re-emits `onAuthStateChange` on
`visibilitychange` with a NEWLY CONSTRUCTED session object even when nothing
changed → `auth-context` assigned it straight into `setSession`/`setUser`, giving
every consumer a new `user` identity → `useSubscription`'s `load` callback (keyed
on the user OBJECT) changed identity, and its effect unconditionally set
`loading: true` → `DashboardLayout:280` renders `<DashboardShell/>` instead of
`<Outlet/>` while `subscription.loading`, unmounting the entire page.

**Solution.** `isSameSession`/`isSameUser` value-comparison in `auth-context.tsx`
plus a memoized context value; `useSubscription` keys on `user?.id` and tracks
`resolvedFor` so `loading` means "never resolved for this user", not "a refresh
is in flight".

**Prevention checklist**

- [ ] Never derive a hook dependency from a Supabase `user`/`session` OBJECT.
      Use `user?.id` / `access_token` — primitives.
- [ ] A background refresh never sets a `loading` flag that gates a route's
      children. Distinguish "first resolution" from "revalidating".
- [ ] Any provider whose value gates rendering is memoized.

---

## 14. A hybrid post-quantum endpoint's surface cards all read "Critical" under a "Fair" headline

**Symptom.** `/dashboard/scanner` on a live `X25519MLKEM768` endpoint: composite
**71 · C+ · Fair**, but Transport & Ciphers **Critical 39**, Certificates & Keys
**Critical 25**, Quantum Posture **Critical 32** — while the Quantum Posture card
itself reads "PQ key agreement: Applied", "Quantum vulnerability: Hybrid-protected"
and "Measured PQ readiness: 81%". The Transport card reads "Post-quantum key
agreement: Applied" two rows above "8 accepted · 8 quantum-vulnerable".

**Root causes — four, each independently sufficient:**

1. **The measured key agreement never reached the scoring model.**
   `calculateRiskScore(...)` was called WITHOUT `edgeIntelligence`, so
   `buildPublishedCategories` fell back to `tlsResult.keyExchange` — the literal
   `"ECDHE (TLS 1.3 key_share)"` Node reports for every TLS 1.3 handshake. That
   scored the hybrid endpoint as classical three times over: `keyExchange()` gave
   70 instead of 100, `postQuantumReadinessFromSignals({hybridObserved:false})`
   forfeited the 55-point allowance, and `cryptographicAlgorithms()` counted the
   hybrid group as quantum-vulnerable. This is issue #12's root cause recurring in
   a module the original fix did not reach.
2. **The hero cards ran a SECOND scoring model.** `scoreNodes(findings)` was a
   residual-severity mean (SAFE 1.0 → CRITICAL 0) over the finding list, while the
   gauge ran the published weighted categories. One scan, two models, two verdicts.
   Worse, it was computed independently in THREE places (`buildAssessment`,
   `_qve-bridge` settle, `buildNodeEvidence`).
3. **One certificate produced five HIGH findings for two facts.**
   `certInfo.detectedOids` contains `ecPublicKey`, `secp256r1 (P-256)` and
   `ecdsa-with-SHA256` — all restatements of the key and signature already reported
   by the dedicated findings. `(5×0.15 + 0.75)/6 = 0.25` → exactly the 25 on screen.
4. **The cipher-suite database is static.** TLS 1.3 rows are hardcoded
   `quantumVulnerable: true, MEDIUM` because a TLS 1.3 suite name carries no
   key-exchange token; `analyzeCipherSuites` took no group argument.

Plus a standards error the audit surfaced: `ecPublicKey`, `secp256r1` and
`rsaEncryption` recommended **ML-KEM** — a KEM — as the replacement for a
*certificate* key.

**Solution.**

- `measuredKeyAgreement(edge)` / `measuredKemApplied(edge)` in
  `edge-intelligence-model.ts` — ONE reading of the named-group probe, consumed by
  `detection-rules`, `published-scoring` and `cipher-suite-analyzer`.
- `edgeIntelligence` threaded through `calculateRiskScore` →
  `buildPublishedCategories`. OCSP/CT/DNS-CAA became genuinely measurable and are
  now scored rather than permanently `applicable: false`.
- `SCANNER_NODE_CATEGORIES` + `scoreNodesFromCategories()` in the dashboard's
  `_intel.ts`: surface scores are a PROJECTION of the same decomposition the gauge
  uses. Computed once in `buildAssessment` and passed to the bridge and inspector.
  `identity` maps to `[]` — the published model has no SSH/JWT category, so that
  card is honestly unscored rather than given an averaged stand-in.
- `leafRestatedOids(cert)` in `certificate-parser.ts` (backed by new
  `publicKeyOid` / `publicKeyCurveOid` fields) suppresses restatements at source.
- `OidClassification.role` + `pqcReplacementFor(oid, usage)`: FIPS 203 for key
  establishment, FIPS 204 for authentication, resolved by the role the call site
  OBSERVED.

Live result on the same endpoint: composite 71 → **77 (B-)**, Transport
39 → **74**, Certificates 25 → **73**, Posture 32 → **76**; certificate findings
6 → 3. Static-RSA suites stayed **CRITICAL** and Forward Secrecy stayed capped at
70 — the genuine exposure is now what drives the transport score.

**Prevention checklist**

- [ ] A surface/card score is a PROJECTION of the headline model, never a second
      aggregation of the same evidence. If re-aggregating the cards by their own
      weights does not reproduce the composite, they are two models.
- [ ] Derive a value ONCE and pass it down. Three call sites computing "the same"
      number is three chances to drift.
- [ ] Never read a PQ verdict from a socket property or a finding title —
      `measuredKeyAgreement()` is the only reading (issues #11, #12, and this one).
- [ ] A posture score is never a mean over an evidence list: adding a probe that
      emits more rows must not lower the posture of the surface it probed.
- [ ] Every suppression gets a NEGATIVE control. Hybrid must NOT soften static-RSA
      or TLS 1.2 suites — ML-KEM lives only in the TLS 1.3 key_share.
- [ ] ML-KEM is key establishment ONLY. Any recommendation pairing it with
      "certificate"/"signature" is a defect.
- [ ] A metric that cannot vary carries no information. If a card must read
      Critical for every host on the internet, the model is wrong, not the host.
- [ ] Run `tools/scanner-scoring-check.ts` (37 assertions, positive + negative)
      and `tools/scanner-dashboard-check.ts`.

---

## 15. Dashboards render empty and the server logs "canceling statement due to statement timeout"

**Problem**

Many pages show zeros or empty states, and the API server logs bursts of:

```
Dashboard telemetry pqc_scan_sessions query skipped: canceling statement due to statement timeout
Quantum readiness pqc_scan_results query skipped: canceling statement due to statement timeout
Dashboard telemetry crypto_inventory query skipped: canceling statement due to statement timeout
```

The obvious reading — "the tables have grown too big, we need indexes" — is wrong
and sends you to `scale-indexes.sql` for nothing. `pqc_scan_sessions` held **32
rows** when this fired.

**Root Cause**

Row **size**, not row **count**. The scanner writes its entire payload into
`pqc_scan_sessions.metadata`: the buffered SSE event log, the full `results`
array, `enterpriseScanner2`, `moduleStates`. Measured: **419KB average per row,
853KB worst, 13.9MB across 32 sessions.**

Eighteen call sites across twelve routers selected that column — `dashboard.ts`
alone had nine — and most never read it. Every one of them transferred 13.9MB
per request. Measured against the real database:

| concurrent requests | with `metadata` | without |
|---|---|---|
| 1 | 2 600–4 900 ms | 165 ms |
| 4 | 19 959 ms | 306 ms |
| 8 | 106 213 ms | 254 ms |
| 12 | 112 206 ms | 252 ms |

Against the `authenticated` role's statement timeout the queries are cancelled,
`safeRows` swallows the error and returns `[]`, and the page renders empty. The
saturation also starves unrelated queries, which is why `crypto_inventory` and
`pqc_scan_results` time out as collateral damage — chasing *those* tables is a
dead end.

Inside the event log, the weight was duplication: `finding` 2685KB, `result`
1659KB, `module` 613KB, `moduleStates` 520KB, `metrics` 414KB, `modules` +
`moduleCatalog` 524KB — all already stored once elsewhere in the same record,
or in `pqc_scan_results`.

**Solution**

- Read side: dropped `metadata` from the fourteen call sites that never read it;
  narrowed the three HNDL sites to `results:metadata->results` and
  `trust-center-dashboard.ts` to `mt:metadata->>target` (PostgREST JSON-path
  projection). Twelve-way fan-out went **112 206 ms → 1 092 ms**.
- Write side: `src/lib/scanner/session-payload.ts` — `persistableTelemetry()`
  strips duplicated keys from each stored event, reduces `module` to
  `{id,name,status}` (history renders `event.module?.name`), and caps the log at
  1000 events with an explicit `telemetry-truncated` marker. Applied at all
  three persistence points in `scanner.ts`. Live SSE is untouched.
- Existing rows: `tools/compact-scan-session-telemetry.ts` (dry run by default,
  `--apply` to write) — 13.11MB → 6.67MB.

**Prevention Checklist**

- [ ] A statement timeout on a small table means row SIZE or contention. Check
      payload bytes before touching indexes: `count=exact` was 345ms on this
      table while the same query WITH `metadata` took 4 956ms.
- [ ] Never `select('*')` or select a JSONB blob in a polled/aggregating route.
      Name the columns; if you need one key, project it (`alias:col->key`).
- [ ] Before adding a JSONB column to a select list, grep whether the handler
      actually reads it. Fourteen of eighteen call sites here did not.
- [ ] Never store in a row something the same row already stores, or that a
      relational table owns. Findings belong to `pqc_scan_results`.
- [ ] Anything append-only that is persisted needs a ceiling, and trimming must
      announce itself — a truncated log must never look complete.
- [ ] `safeRows`-style helpers hide this class of failure. An empty dashboard
      plus a `query skipped` warning is a FAILED query, not "no data".
- [ ] Run `tools/scan-session-payload-check.ts` (18 assertions, positive +
      negative) and `tools/migration-assets-check.ts`.

---

## 16. A whole table's worth of evidence silently disappears from a dashboard

**Problem**

`/dashboard/migration-planner` showed no validation evidence at all, with:

```
[migration-planner] migration_validation_logs query skipped: column migration_validation_logs.asset_id does not exist
```

**Root Cause**

`migration-planner.ts` asked for `id, asset_id, migration_job_id, status,
created_at`. `migration_validation_logs` has neither `asset_id` nor
`migration_job_id` — its only FK is `migration_id → migration_jobs(id)`, which
is exactly what `agent-scanner.ts` writes. PostgREST rejects the **whole**
query on one unknown column (42703), so a single wrong column name cost every
row in the table, not just that field.

**Solution**

Query `id, migration_id, status, created_at`; `asset-intelligence.ts` now groups
by `migration_id || migration_job_id || job_id` so agent-written and legacy rows
both resolve. Pinned by two fixture rows in `tools/migration-assets-check.ts`.

**Prevention Checklist**

- [ ] PostgREST is all-or-nothing on the select list. One bad column = zero rows,
      reported as a warning, not an error — it looks like "no data".
- [ ] Check the column against `supabase/dashboard-schema.sql` AND against the
      writer. Reader and writer disagreeing on a FK name is the recurring shape.
- [ ] Confirm the fix by running the select against the database, not by reading
      the schema file — the deployed table is the authority.

---

## 17. Users log in fine but every plan is gone — "no subscription" after rotating Supabase credentials

**Problem**

After pointing `.env` at a different Supabase project (or restoring one), existing
users authenticate normally but the dashboard shows the `<UpgradeRequired
variant="no-subscription">` screen, and Starter accounts land on `StarterDashboard`
regardless of the plan they used to have. Nothing in the gating code changed.

**Root Cause**

Entitlement is **data, not code**. `use-subscription.ts` and
`api-server/subscription-guard.ts` both read a `billing_subscriptions` row keyed by
`user_id`, and user IDs are per-project. A new project starts with an empty
`billing_subscriptions` table, so every lookup falls through to the
`profiles.tier` branch — which deliberately refuses to trust a paid tier without a
subscription row (`status: 'incomplete'`, `isActive: false`). The gate is working
exactly as designed; the rows are simply absent.

Two follow-on traps in a fresh project:

- Only users who re-registered exist in `auth.users`. `tools/seed-test-subscriptions.ts`
  reports `SKIP … not registered yet` for the rest and cannot create them.
- `zachmatthew369@gmail.com` (owner) **cannot** be recreated through `/register` —
  `api-server/auth.ts` returns `EMAIL_NOT_ALLOWED` for `isOwnerEmail` as
  anti-squatting. Provision it from the Supabase dashboard or via service-role
  `auth.admin.createUser`.

**Solution**

Re-seed, do not re-code: `npx tsx tools/seed-test-subscriptions.ts` (idempotent,
service-role, upserts on the `user_id` unique index and sets `profiles.tier`).
Confirm the base schema migrations reached the new project first — the base
`plan` CHECK is `('Starter','Pro','Elite')` and **`Basic` only exists after
`supabase/paypal-subscription-migration.sql`**, so a Basic seed fails with a check
violation on a half-migrated project. Probe for `paypal_webhook_events` to tell
whether that migration ran.

**Prevention Checklist**

- [ ] Treat any Supabase URL/key change as a data migration, not a config edit.
      Auth users, `billing_subscriptions`, and `profiles.tier` are all per-project.
- [ ] Verify through the *frontend's* path, not the service-role client — the
      service key bypasses RLS and will read rows the app cannot. Mint a real user
      session without a password: `admin.auth.admin.generateLink({type:'magiclink',
      email})` → `anonClient.auth.verifyOtp({token_hash: link.properties.hashed_token,
      type:'magiclink'})`, then run the exact `use-subscription.ts` select. This is
      the only check that proves RLS policies made it into the new project.
- [ ] Check the `plan` CHECK constraint before seeding a tier the base schema
      never had.
- [ ] `billing_subscriptions` must be in the `supabase_realtime` publication or
      plan changes will not go live without a reload (`billing-subscription-schema.sql`
      adds it conditionally — it only runs if that file was applied).

---

## 18. A score reads "23/100" beside a band that says "Critical"

**Problem**

`/dashboard/summary` reported `quantumRiskScore: 232` with `riskBand: 'Critical'`,
while `/dashboard/executive`'s `quantum-risk` KPI reported `75/100 (High)` for the
same estate at the same moment. The posture panel rendered **"Quantum Risk Score
23 /100"** directly above **"Risk Band: Critical"** — a reassuring number under an
alarming label.

**Root Cause**

Three compounding faults on one value:

1. The composite in `buildDashboardSummaryFallback` was
   `readiness*0.45 + coverage*0.2 + (100-pressure)*0.35` — a **higher-better
   posture** measure — but was published as `quantumRiskScore`, a risk name.
   The name inverted the meaning.
2. It was scaled `*10` onto a private **0–1000** range with its own band ladder
   (`>=850 Quantum Ready … else Critical`), colliding with the platform's
   canonical 0–100 `RISK_BANDS` and with the executive KPI's 0–100 lower-better
   scale.
3. The frontend "converted" it by **guessing**:
   `riskTo100 = score > 100 ? score / 10 : score`. So 232 became 23, and a
   higher-better number was rendered on a lower-better meter.

Each layer looked locally reasonable, which is why it survived: the API had a
self-consistent band table, and the frontend had a plausible-looking normaliser.

A second defect in the same payload: `newVulnerableAssets` returned
`currentFindings`, a raw signal count, so one asset with 98 recent findings
reported "98 new vulnerable assets" beside "1 vulnerable asset".

**Solution**

Publish both measures under their real names on the canonical scales, banded by
the shared tables in `asset-intelligence.ts`:
`quantumRiskScore` (0–100 lower-better, `riskBandFor`), `quantumReadinessScore`
(0–100 higher-better, `levelFromReadiness`), plus `hasBaseline` so an unmeasured
estate renders `--` instead of a 0 that reads as perfect on a lower-better scale.
Delete the frontend's scale guess and read the field directly. Give every risk
signal the `subject` it was observed on — keyed exactly like `vulnerableSubjects`
— so `newVulnerableAssets` counts distinct subjects and is a strict subset of
`vulnerableAssetsCount`; the old signal count moved to `newFindings`.
Summary risk and the executive KPI now both read **74 (High)**.
Pinned by `tools/dashboard-summary-check.ts`.

**Prevention Checklist**

- [ ] A field name states a DIRECTION. `*Risk*` must be lower-better and
      `*Readiness*` higher-better. A composite built from `(100 - pressure)` is a
      readiness measure however it is named.
- [ ] Never normalise a scale by inspecting the value
      (`x > 100 ? x / 10 : x`). If a consumer cannot tell 0–100 from 0–1000
      without guessing, the producer is publishing the wrong contract.
- [ ] Bands come from `RISK_BANDS` / `levelFromReadiness` in
      `src/lib/migration/asset-intelligence.ts`. A local band ladder is a
      duplicate rule that WILL drift (rule 5).
- [ ] A field ending in `Assets` counts distinct subjects; one ending in
      `Findings` counts signals. Assert `newX <= totalX` — the subset relation is
      what catches a count/subject mix-up.
- [ ] Compare the payload against the OTHER endpoint describing the same
      population before believing it. Two numbers for one estate that disagree in
      SCALE or DIRECTION are a defect even when each is internally consistent.
- [ ] Check the render site is reachable before claiming a visual fix —
      `TelemetryFeatures.tsx` turned out to have zero importers.

---

---

## 19. A page goes BLACK and BLANK the moment a write action succeeds

**Problem**

`/dashboard/hybrid-crypto-lab` → build an experiment → **Run Experiment** → the
entire application disappears, leaving a bare dark background. No error, no
message. The POST succeeded (201) and the row was written — only the render
died. The user's URL ends in `#`, because the "Create Experiment" call to action
in the empty state was `href: '#'` and went nowhere.

**Root Cause**

Two shapes for one concept. `hybrid_crypto_experiments` rows are projected into
the camelCase domain record `ExperimentRecord` by a mapper inside
`buildExternalTrustIntelligence` — but **only on the read path**. The write path
returned the raw snake_case row straight from `.insert(...).select('*')` (and,
in the not-provisioned branch, the raw `record` object it had just built).

So a freshly-run experiment had `execution_mode` / `duration_ms` /
`payload.target`, while the UI read `executionMode` / `durationMs` /
`target`. Two fields rendered the string `undefined`; the third,
`result.target.label` at `HybridCryptoLab.tsx:444`, threw
`TypeError: Cannot read properties of undefined (reading 'label')` **during
render**. There is no error boundary above the dashboard routes, so React
unmounted the whole tree — the "black blank screen" is the page background with
nothing left on it.

Two things kept it invisible:

- `setResult(payload.experiment as never)` — the cast erased the exact type
  error that would have named this bug at compile time.
- The UI read `result.result?.checks` / `.findings` / `.basis`, which happen to
  work on the raw row (it has a `result` JSONB column). Half the view was
  written against the row and half against the record, so neither shape was
  obviously wrong.

**Solution**

- `toExperimentRecord(row, now?)` exported from
  `src/lib/ecosystem/external-trust-intelligence.ts` is now the ONE row→record
  projection. `buildExternalTrustIntelligence` calls it; both branches of
  `POST /lab/experiments` call it. Verified live: the read path and the write
  path return byte-identical key sets.
- The UI reads the record (`result.checks`, `result.findings`, `result.basis`,
  `result.durationMs`, `result.executionMode`) and the `as never` cast is gone,
  so the contract is now enforced by `tsc`.
- The extracted mapper also stopped fabricating: the old fallback hardcoded
  `port: 443`, `environment: 'unknown'`, `vendorId: null`, `assetId: null` for a
  row with no `payload`. It now reads the real `target_port` / `environment` /
  `vendor_id` / `asset_id` columns.
- `PageErrorBoundary` in `_components/external-trust/_shared.tsx` wraps all four
  suite pages: a render fault now shows a stated error with a retry, and is
  bounded to the page instead of blanking the application.
- `EmptyState`'s `cta` takes `href` **or** `onClick` (a union that makes
  `href: '#'` unrepresentable). "Create Experiment" now opens the builder at
  step 1; a filter matching nothing gets its own empty state instead of a bare
  table header.

**Prevention Checklist**

- [ ] A write endpoint returns the SAME projected shape its read endpoint
      returns. Never return a raw `.select('*')` row to a UI that consumes a
      mapped domain type — assert the two key sets are equal in a check tool.
- [ ] Row→domain mapping lives in ONE exported function. An inline `.map()`
      inside an aggregate builder is invisible to the write path that needs it.
- [ ] `as never` / `as unknown as T` on an API response is a defect waiting to
      happen; it silences precisely the mismatch you need reported. If a cast
      seems necessary, the contract is wrong.
- [ ] A component must read one shape. Reading `x.result.checks` (row) beside
      `x.target.label` (record) in the same view means nobody knows which
      contract applies.
- [ ] Any route whose render can throw needs a boundary above it, or one bad
      field takes down the entire application and reports nothing.
- [ ] `href="#"` is never a call to action. In-page actions are `<button>`.
- [ ] Reproduce a "blank screen" by RUNNING the action against the live API and
      printing the response keys — the shape mismatch is invisible in the source
      when a cast hides it. `tools/external-trust-check.ts` §12 pins it offline.

---

## 20. Finding counts are ~4× too high, and one finding is listed twice in a row

**Problem**

`/dashboard/cbom` → Vulnerabilities showed `TLS_RSA_WITH_AES_256_CBC_SHA ·
www.cloudflare.com · Critical` **twice consecutively**, "FINDINGS 255" and
"CRITICAL SIGNALS 47" for a two-asset tenant holding 66 cryptographic
components. The Assets page repeated the inflation ("255 signals", CRITICAL 47),
the QR Engine's `riskDistribution` mirrored it, and the workflow rail read
"47 critical · 251 findings".

**Root Cause**

The scanner persists every detection to `pqc_scan_results`, `crypto_exposures`
and `crypto_inventory`, AND keeps it in the scan session's own findings array.
Those are four STORAGE VIEWS of one observation. `mergeScannerFindings` keyed on

```ts
[finding.source, finding.algorithm, finding.location, finding.category, finding.evidence]
```

— and `source` is precisely the field guaranteed to differ between them. So the
dedupe key contained the very dimension that distinguishes duplicates. `category`
was no better: the same cipher suite is filed as `"rsa"` (crypto_exposures),
`"Cipher Suite"` (pqc_scan_results) and `"algorithm"` (crypto_inventory).
`location` differs too — the session copy writes `"Cipher Suite — https://host/"`
and rule-derived findings write their rule id (`"Detection Rule TLS-008"`) with
no target in it at all.

Measured on the live tenant: **255 findings for 66 real observations**, `maxObs`
5. Because `quantum-readiness.ts` copies `intel.severityCounts` into
`riskDistribution`, the inflation propagated to the QR risk score and every
consumer of it.

**Solution**

`src/lib/scanner/finding-identity.ts` — pure and dependency-free (same
discipline as `scanner-module-ledger.ts`) so the rule is testable offline and
shared rather than reimplemented. Identity is a property of the OBSERVATION:

```ts
findingIdentityKey = [algorithm, findingSubject(f), detectionMethod].join('|')
```

`normalizeFindingSubject()` reduces all four location shapes to a bare host and
returns `''` for anything that is not one, so `computeScannerIntelligence` must
stamp `scanTarget` on both history findings (`entry.target`) and asset findings
(`asset.url || asset.domain || asset.name`) for rule-derived rows to resolve. A
`detectionMethod` that is really a table name is neutralised via
`FINDING_STORAGE_SOURCES`. Strongest severity wins; `richerText()` keeps the
most specific description/evidence/recommendation from ANY merged copy, because
the highest-severity copy is usually the terse `crypto_exposures` row while the
session copy holds the analyst explanation. The merged record carries
`observations` and `sources`.

Live result: **255 → 66 findings**, critical 47 → 13, and the deduped finding
count now equals the CBOM component count with `62` non-safe — matching
`quantumVulnerableComponents: 62` derived by a completely independent grouping.
That agreement is the evidence the merge is right rather than over-collapsed.

**Prevention Checklist**

- [ ] A dedupe key must never contain the field that distinguishes the copies —
      `source`, `category` and raw `location` all identify the WRITER, not the
      observation. Key on what was found, where, and how it was measured.
- [ ] Before trusting a finding total, group the list by a semantic key and
      compare. `distinctBy(algorithm, host) << total` is the signature.
- [ ] Cross-check the finding count against an independently-derived count of
      the same universe (here: grouped `crypto_inventory` components). Two
      unrelated groupings agreeing is strong evidence; disagreeing is the bug.
- [ ] A merge that loses text is a merge that loses evidence. Take max severity
      but richest narrative.
- [ ] `severityCounts` is copied wholesale into `quantum-readiness.ts`
      (`riskDistribution`) and from there into `migration-workflow.ts`. Any
      change to the finding list moves the QR risk score — verify all three.
- [ ] Run `tools/scanner-finding-identity-check.ts` (39 assertions, positive +
      negative), plus `tools/scanner-dashboard-check.ts` and
      `tools/dashboard-summary-check.ts`.

---

## 21. A 66-component estate reports "At Risk 100" and "At Risk 100%"

**Problem**

`/dashboard/cbom` Overview: "CRYPTO COMPONENTS 66" beside "AT RISK 100", and a
readiness legend reading **PQC Ready 6.1% · In Progress 0% · Not PQC Ready
93.9% · At Risk 100%** — four rows that look like a partition and sum to 200%.
Three more panels on the page repeated the number.

**Root Cause**

```ts
const atRisk = entries.filter((e) => e.isVulnerable && riskRank(e.riskSeverity) >= 2).length
             + Number(data.summary.criticalFindings || 0)   // 53 + 47 = 100
```

A COMPONENT count added to a FINDING count. Both operands were correct; the
addition was a category error, and `percent()` then clamped the result to 100%
so it looked like a plausible catastrophe instead of an overflow.

Three neighbouring scope faults on the same page:

- `totalComponents = stats.totalComponents || entries.length` (and the same for
  `pqcReady` / `vulnerableComponents`) — a per-field `||` between two different
  populations, i.e. a scope decision in disguise (rule 2).
- `notPqcReady = total - pqcReady - inProgress` where `inProgress` came from the
  raw rows and `total` from the grouped stats, so the three did not partition.
- The Algorithm Distribution donut summed only its **top 6** slices and labelled
  that "Total": 12 stood in for 66, and every percentage used the wrong
  denominator (2 of 66 rendered as 16.7%).

**Solution**

One scope decision (`hasComponentStats`) that every component field follows;
`pqcReady + inProgress + notPqcReady === totalComponents` by construction;
`atRiskComponents` is component-scope and rendered as an explicit SUBSET of Not
PQC Ready, with `criticalFindings` shown separately under its own name. The
donut's denominator is the whole measured population with an explicit
`Other (N more)` slice.

**Prevention Checklist**

- [ ] Never `+` two counts unless they count the same kind of thing. If one is
      named `*Components` and the other `*Findings`, the sum is meaningless.
- [ ] Any count rendered as a percentage of a universe must be assertable as
      `≤ universe`. `percent()` clamping to 100 HIDES this class of bug.
- [ ] Legend rows that read as a partition must sum to 100%. A subset row is
      labelled as one and separated by a rule.
- [ ] A chart's denominator is the population, never the visible top-N. Show the
      remainder as its own slice.
- [ ] See rule 2 in `qguard-data-integrity`; pinned by
      `tools/scanner-finding-identity-check.ts` §5–6.

---

## 22. An asset scoring 23/100 in green is filtered and badged CRITICAL

**Problem**

`/dashboard/assets`: the risk filter chips read `CRITICAL 2 · HIGH 0 · MEDIUM 0
· LOW 0` while the table showed those same two assets at **23/100** (emerald)
and **55/100** (amber), and the expanded panel badged the 23/100 asset
"CRITICAL".

**Root Cause**

Two aggregations of one concept rendered together — the same shape as issues #11
and #14. `assetRiskLevel()` took the MAX over the score band, the backend's
`riskLevel`, and the exposure level of **every component**; one critical
component among 23 therefore made the whole asset critical, while the number
next to it was the backend's composite `riskScore`.

Alongside it, three presentation faults:

- The header badge read "Reconciled with Quantum Readiness Engine" on a page
  that never called the QR API.
- The PQC-ready component share was labelled **"Quantum Readiness"** — the name
  the QR composite carries everywhere else, with a different value (6% vs 21).
- "255 signals" sat above severity bars summing to 251: `totalFindings` counts
  SAFE findings, the bars do not.

**Solution**

`assetRiskLevel()` is now a PROJECTION of the risk score
(`normalizeRiskLevel(asset.riskLevel) || riskLevelFromScore(asset.riskScore)`).
The worst component severity is still real and still shown — as its own labelled
chip (`worstComponentSeverity`), never as the asset's band. `useQuantumReadiness`
is actually consumed, so the badge states match / diverged / awaiting / no
evidence from a real comparison, and the two readiness figures appear under
their own names ("Quantum Readiness (QR Engine)" vs "PQC Component Coverage").
The severity panel quotes `gradedFindings` (critical+high+medium+low), which is
what the bars add up to.

Also: `vulnerableComponents()` stopped re-merging `cryptoInventory` on a
narrower key than the backend grouped by — the per-row counts now sum to the
headline exactly (19 + 43 = 62) instead of relying on a coincidence.

**Prevention Checklist**

- [ ] A band shown next to a score is a function OF that score. Worst-of-children
      is a different measure and needs a different label and its own slot.
- [ ] A badge that claims cross-module agreement must read the other module. If
      the page cannot call it, delete the claim.
- [ ] Two figures that share a name across pages must share a value. If they are
      genuinely different measures, rename one.
- [ ] A total quoted above a breakdown must equal the breakdown's sum, or the
      difference must be stated (here: SAFE findings).
- [ ] When the backend already publishes a count, read it — do not recompute it
      client-side on a different key.

---

## 23. A page reports "Risk Score 0/100" while the QR Engine reports 75/High

**Problem**

`/dashboard/migration-sandbox` Overview rendered **"Readiness Scores: 6/100 PQC
Ready · 0/100 Risk Score · 39/100 Compliance"**, the Validation tab rendered the
same value as **"Security 0/100"**, and Sophia's AI Insights showed **"Risk
Score 0%"** — for a tenant the Quantum Readiness Engine scored **75/100 High**.
The same page also reported **22 critical / 50 high exposures** where CBOM,
Assets, the QR Engine and the workflow rail all said **13 / 30**.

**Root Cause**

Three faults, each independently sufficient:

1. **A posture score published under a risk name.**
   `riskScore = 100 - (critical*15 + high*8 + expiringCerts*5 + openVulns*3 + …)`
   is HIGHER-is-better. It was rendered beside PQC-readiness and compliance
   (both higher-better) *and* named like the platform's canonical
   lower-better `quantumRiskScore`. This is issue #18 recurring in another module.
2. **It could not vary.** Seven critical exposures alone exhaust the 100 points,
   so the metric reads 0 for every real estate. A metric that cannot vary
   carries no information.
3. **Severity counts were summed across three storage views.**
   `criticalExposures = crypto_exposures.critical + pqc_scan_results.critical +
   scanner_alerts.critical`, and `openVulns = vulnerabilities + scanner_alerts`
   counted the alerts a *second* time on the same page. See issue #20 — these
   tables hold the same observations.

Plus: `pqcReadiness` fell back to `completedJobs / totalJobs` when there was no
inventory — a migration-job completion rate published as cryptographic
readiness, so a tenant with one finished job and no CBOM would read
"PQC Readiness 100%".

**Solution**

- `riskScoreFromLoad(load, halfLife)` in `src/lib/migration/asset-intelligence.ts`
  (beside `RISK_BANDS`, so check tools need not import the Express router):
  `100 * (1 - e^(-load/60))` — strictly increasing, asymptotic, never pegs.
  Verified: a 13-critical/30-high estate scores 73, a 50/100 estate 99.
- `sandbox.ts` prefers the QR Engine's `scores.quantumRisk` via the exported
  `buildSnapshot`, publishing `quantumRiskScore` (0–100, lower-better),
  `quantumRiskLevel` from `riskBandFor`, and `quantumRiskSource` so a reader can
  tell which computation answered. NOT `scannerIntel.summary.riskScore` — that
  is the scanner's per-asset risk MEAN (39 here), a different measurement that
  merely shares the scale.
- Severity counts come from `buildScannerIntelligence().severityCounts`, with
  `dedupeGradedObservations()` in `src/lib/scanner/finding-identity.ts` as a
  same-unit fallback. `scanner_alerts` no longer double-count into `openVulns`.
- `ScoreGauge` takes `number | null` plus `lowerBetter`; null renders "—".

**Prevention Checklist**

- [ ] A field named `*Risk*` is lower-better; `*Readiness*`/`*Score*` in a
      confidence row is higher-better. `100 - penalties` is a POSTURE measure
      however it is named (issue #18).
- [ ] Before shipping a scored metric, evaluate it at a realistic estate AND at
      10× that. If both give the same number, the model is wrong.
- [ ] Never sum severity counts across `crypto_exposures` + `pqc_scan_results` +
      `scanner_alerts` — they are storage views of one observation set (#20).
- [ ] Check no table feeds two different counters on the same page.
- [ ] A fallback must measure the SAME THING. Job completion rate is not
      readiness; the scanner's asset-risk mean is not the QR quantum risk.
- [ ] Run `tools/scanner-finding-identity-check.ts` §7–8 and
      `tools/sandbox-twin-check.ts`.

---

## 24. An unrehearsed rollback reports "0%" and a perfect "RPO 0m"

**Problem**

`/dashboard/migration-sandbox` → Rollback, with zero simulations ever run:
**ROLLBACK SUCCESS 0%**, **RPO 0m**, **SNAPSHOT COVERAGE 0%** — and the
restoration checklist showed "Policy restoration ✗" beside the text *"Crypto-policy
state is recorded in each snapshot entry."*, and "Trust chain restoration ✓"
beside *"Trust chain evidence limited — PKI restore partially verified."*

**Root Cause**

`buildRollbackAnalysis` returned `successProbabilityPct: 0` and
`rpoMinutes: 0` when `sandboxSims.length === 0`, while setting
`available: sandboxSims.length > 0 || assets > 0` — so the UI treated an
unmeasured analysis as available and rendered its placeholder zeros as
measurements. **0% confidence is indistinguishable from a rehearsal that failed
every time, and RPO 0m is the BEST possible recovery point objective** — the
unmeasured state rendered as the ideal one.

The checklist `detail` strings were written for the covered case only and
emitted unconditionally, so three of six rows asserted the opposite of their own
`covered` flag.

A fourth, related fault: `predictFailures` scored `certificate_failure` from
`expiring + nonPqc` over `certs.length`. Every pre-migration tenant has 100%
classical certificates, so the ratio is always 1.0 and the prediction read
**88% for everyone** — and it was the single blocker holding the approval gate.
Its `affectedAssets` came from the `expiring` subset only, so a count of 2
rendered with an empty asset list.

**Solution**

`assessed` flag; `successProbabilityPct` / `snapshotCoveragePct` / `rpoMinutes` /
`rtoMinutes` / `downtimePredictionMin` are `number | null`, and every render site
prints "Not assessed". The approval gate still FAILS without a rehearsal — but
as an unmet gate, not as a 0% measurement. Each checklist `detail` is now a
ternary on its own `covered` value. `certificate_failure` is driven by expiring
certificates (a real replacement hazard); classical certificates became
`certificate_replacement_scope`, explicitly labelled *"expected pre-migration
state, not a detected fault"*, at a bounded 36%. Overall failure probability
47% → 17%.

**Prevention Checklist**

- [ ] For any metric where 0 is the IDEAL value (RPO, downtime, error count,
      risk), unmeasured must be `null` — never 0. This is the inverse of the
      usual trap and is easy to miss.
- [ ] An `available`/`ready` flag must be gated on the thing actually being
      measured, not on some other evidence existing.
- [ ] A `detail`/`reason` string must be a function of the flag it sits beside.
      Unconditional copy next to a conditional flag WILL contradict it.
- [ ] A probability whose denominator is "all of X" reads ~100% whenever the
      condition is universal. Ask: what does this predict for a tenant that has
      not started? If the answer is "the same as everyone", it is not a prediction.
- [ ] An affected-asset list must be built from the same rows as its count.
- [ ] `tools/sandbox-twin-check.ts` pins all of this (null rollback figures,
      the covered/detail agreement sweep, auto-rollback readiness).

---

## 25. One dashboard rebuilds a 1.5s payload once per client per SSE tick

**Problem**

`/api/v1/sandbox/snapshot` had no cache while `/stream` rebuilt it every 8s PER
CONNECTED CLIENT. Measured on a two-asset tenant: five concurrent callers took
**2365ms of wall clock** because each ran its own full build — a 14-table tenant
load plus the entire twin assembly. Cost scales with
(open dashboards × SSE ticks × estate size).

`buildScannerIntelligence` and the QR `buildSnapshot` had both had the
short-TTL single-flight treatment for exactly this reason; the sandbox was the
one hot path that never got it.

**Root Cause**

Not an oversight so much as a hazard: `buildSandboxPayload` calls
`advanceSandboxJobs` — a MUTATION — at the top, so it looks uncacheable.

It is cacheable, because simulation progress is derived from elapsed time
(`(elapsed / duration) * 100`), not incremented per call. Running the engine
less often changes WHEN a row is written, never how fast a simulation
completes. It also already carried a 2.5s per-tenant throttle, and the
background scheduler is a 15s floor.

**Solution**

`getSandboxSnapshot()` — per-tenant, 5s TTL, single-flight (concurrent callers
await the same in-flight promise). Read routes (`/snapshot`, `/stream`,
`/export`) go through it; the four mutating routes go through
`buildSandboxPayloadOrNull`, which **invalidates first** so an operator action
never returns a pre-mutation payload. `advanceSandboxJobs` now returns
`advancedUsers`, and the scheduler drops exactly those tenants' snapshots so
live progress is never hidden behind the TTL.

Measured after: warm hit **3ms**, five concurrent callers share **one**
computation (`distinctGeneratedAt === 1`).

Second, subtler fix in the same change: the snapshot had begun awaiting the QR
assessment outright. QR costs ~1s cold and blocking on it put an entire
assessment in the sandbox's first-paint path. It is now bounded
(`QR_SNAPSHOT_DEADLINE_MS`), and — importantly — a missed deadline is
distinguished from "QR has no evidence": the former yields `null`
(renders "—"), the latter falls back to the locally derived score. Collapsing
the two would have published a divergent risk number for a few seconds and then
jumped, which is the exact divergence issue #23 fixed.

**Prevention Checklist**

- [ ] A mutation inside a build function does NOT make it uncacheable. Ask
      whether the mutation is time-derived/idempotent — if so, cache it and
      document why. If not, split read from write.
- [ ] Any route an SSE stream polls needs single-flight, or its cost multiplies
      by connected clients.
- [ ] Every mutating route must invalidate before rebuilding, or operator
      actions look like no-ops. Grep: each `router.post` in the file must reach
      the invalidating helper.
- [ ] A background engine that writes behind the cache must invalidate the
      tenants it touched, or its changes sit invisible for the TTL.
- [ ] Never `await` another module's cold snapshot on a first-paint path without
      a deadline — and make "timed out" a DIFFERENT state from "no data".
- [ ] Prove sharing with a deterministic marker (`generatedAt`), not wall clock.
      Timing a shared build also times whatever dependency caches happened to be
      cold, so it is a noisy proxy for the thing you actually mean.
- [ ] `tools/sandbox-latency-probe.ts` asserts all of this;
      `PROBE_MUTATE=1` additionally exercises the invalidate-on-write path and
      cleans up after itself.

---

## 26. A scan takes 60+ seconds and ends in four red FAILED stages

**Problem**

`/public-scan` against an endpoint whose port 443 does not answer:

```
DNS Resolution          COMPLETE     1 address(es), CAA unknown
TLS Handshake           FAILED       TLS connection timeout after 15000ms
Certificate Collection  FAILED       Certificate probe timed out
Security Header Analysis FAILED      origin unreachable
Quantum Assessment      FAILED       PQ readiness 0% · quantum risk Low
Executive Report        COMPLETE     Assessment ready in 61.3s
```

Reproduced exactly with `smtp.gmail.com:443` (resolves publicly, silently drops
TCP/443) — measured **66.7s**. Four red crosses read as "this endpoint failed
four security controls"; the truth is that nothing answered, so nothing was
measured. The one stage marked FAILED even quoted a computed readiness and a
reassuring risk level.

**Root Cause**

Six independent faults, and the first is the one that produced the other five:

1. **No reachability preflight.** Every engine discovered the dead port on its
   own and paid its own timeout: `analyzeTlsResilient` retried the primary
   handshake 3× at 15s (its `isTransientHandshakeError` matches `/timeout/i`, and
   the deadline was checked *after* each attempt, so every attempt started with
   the full ceiling however little budget remained), then the certificate engine
   spent 16s and the HTTP engine 8s more. `connectTlsAny` additionally multiplied
   the primary timeout by the resolved address count.
2. **`computeQuantumRisk` returned `'Low'` for an empty factor list.**
   `factors.length ? Math.max(...) : 0` → score 0 → level `Low`. An endpoint that
   refused every connection was published at the LOWEST quantum risk on the scale.
3. **`emptyBundle` published `quantumRisk: 'Critical'`, score 100** for the same
   no-evidence condition — two contradictory fabrications for one state.
4. **The rail detail was unconditional.** `onEngine('cryptographic-intelligence',
   ok, \`PQ readiness ${…}% · quantum risk ${…}\`)` printed computed values even
   when `ok` was false, and `ok` was `algorithms.length > 0` — so "no catalogue"
   rendered as a failed module quoting a score.
5. **`0` published for unmeasured scores.** `encryptionScore` / `classicalScore` /
   `postQuantumReadiness` were `number`, so the grade was correctly withheld
   (`N/A · Insufficient evidence`) while its own inputs rendered as `0` with the
   gauge pointing at 0 and its legend reading *Critical*.
6. **Copy asserting facts about an unprobed target**: `quantumVulnerability:
   'Vulnerable'` ("No hybrid key agreement offered" — we never asked); a
   `Sustain hybrid deployment` migration target from the `if (!migrationTargets
   .length)` fallback; and a harvest-now timeline built around the literal string
   `"unknown"` ("Sessions harvested today become readable once unknown is
   broken").

**Solution**

- `engines/reachability-engine.ts` — one SSRF-contained TCP connect classifying
  `open | refused | filtered | unreachable | blocked | unresolved`. `filtered`
  (silence) is the only falsifiable verdict and is confirmed with a second probe;
  everything else answered and is definitive on one sample. It also supplies the
  real `tcpConnectMs` the Handshake panel used to report as "not measured".
- `runScanEngines` runs it FIRST and, when the port does not answer, returns
  `unreachableBundle(...)`: TLS/certificate/HTTP become `unmeasuredResult(...)`
  (new `EngineResult.unmeasured` flag) all quoting one shared reason. DNS still
  runs — it distinguishes "wrong DNS" from "dead service".
- `PublicScanStageState` gained `'unavailable'`, rendered amber "NOT MEASURED"
  with a dash, never a red cross. `cachedStages` replays the same states.
- `notAssessedCrypto(reason)` is the single representation of "not assessed":
  `quantumRisk`, `quantumRiskScore` and `postQuantumReadiness` are `null` and
  `assessed: false` carries the reason. `computePostQuantumReadiness` returns
  `measured`.
- Executive scores are `number | null`; `CountUp` / `Meter` / `Gauge` / `scoreColor`
  render "—", a dashed track, a scale with no pointer, and slate.
- `analyzeTls(host, port, { handshakeTimeoutMs, deadline })`; the resilient wrapper
  checks the budget BEFORE each attempt and sizes it from what is left.
- **Bonus root cause found while verifying**: `vite.config.ts`'s `isApiSourceFile`
  only matched `src/api-server/`, so the cached `apiApp` kept serving engine code
  imported at boot — editing anything under `src/lib/` changed nothing at runtime.
  Now matches `src/lib/` and `src/services/` too.

Result: **66.7s → 8.4s**, four `unavailable` stages, every score withheld.
`expired.badssl.com` still grades **F/Critical** with 3 CRITICAL findings
(negative control), `cloudflare.com` still **C+ / PQ 81% / hybrid detected**.

**Prevention Checklist**

- [ ] Establish a shared prerequisite ONCE. If N engines each independently
      discover the same failure, the scan pays N timeouts and produces N
      differently-worded excuses for one fact.
- [ ] A retry policy must check its budget BEFORE the attempt and size the
      attempt from what remains. Checking afterwards overruns by one full timeout.
- [ ] Never retry a deterministic negative. A timeout on a filtered port is the
      most reproducible result there is.
- [ ] `factors.length ? … : 0` on a risk scale means "no evidence" scores as
      "best case". Return `null` and make consumers branch.
- [ ] Grep for a second representation of the same empty state before adding one —
      `emptyBundle` said Critical while `computeQuantumRisk` said Low.
- [ ] A stage detail string must be a function of the stage's own outcome. An
      unconditional template beside a conditional state WILL contradict it (#24).
- [ ] Withholding a grade but publishing its inputs is not a partial fix. If the
      composite is `null`, so are the numbers it was computed from.
- [ ] `failed` and `unavailable` are different claims. A module that never ran has
      accused the target of nothing.
- [ ] Any copy naming an algorithm must be gated on having OBSERVED one. Search
      the rendered strings for the literal word "unknown" appearing mid-sentence.
- [ ] `net.connect`/`tls.connect` SKIP a custom `lookup` when the host is an IP
      literal — `checkHostSyntax` is required as well, or loopback and cloud
      metadata are reachable. `tools/public-scan-check.ts` asserts this; it caught
      exactly this hole in the new engine.
- [ ] Verify against BOTH a filtered port and a reachable-but-broken host. The
      second is what proves the fast-fail did not silence real findings.
- [ ] `npx tsx tools/public-scan-check.ts <host>` — 139 invariants, including the
      full unreachable-endpoint contract (override the filtered target with
      `PROBE_UNREACHABLE_HOST`).

---

## 27. A rollback "completes" and the asset was never touched

**Problem**

The Snapshots panel on `/dashboard/live-migration` showed restored snapshots and
`rolled_back` migration jobs, with an audit line reading *"Restored
<asset> from MSNAP-…"* and `restoration_status: 'completed'`. Nothing had run on
the asset. A tenant with zero agents could produce these records simply by
opening the page.

**Root Cause**

Four separate holes, all with the same shape — a database write standing in for
an operation:

1. `autoRollbackFailedJobs()` (migration-snapshots.ts) flipped every FAILED job
   to `rolled_back` and its snapshot to `restored`, with no executor at all. It
   was called from `buildSnapshotDashboard()`, i.e. from **GET /** and from the
   20-second SSE tick, so opening a dashboard mutated tenant state.
2. `POST /:snapshotId/restore` wrote `status: executor ? 'restored' : 'restorable'`.
   `executor` meant *an active agent row exists for this tenant* — not that
   anything was dispatched, and nothing was. The audit said "dispatched…
   awaiting confirmation" while the row said restored.
3. The agent's own config backup (`targetPath`/`backupPath`/`beforeHash`,
   produced by `applyLocalConfigRemediation`) was posted in the event
   `metadata.snapshot` and **discarded** — `executorEvents` keeps only
   type/status/progress. The platform could not roll anything back even in
   principle while still offering a Restore button.
4. `rollback_requested` (written by `/migration/jobs/:id/action` and
   `/plans/:id/action`) had no consumer anywhere. The job parked forever.

**Solution**

- Rollback is a real command. `AgentCommandType` gained `'rollback'`; the agent
  runtime implements it in `drainCommands` (`executeRollbackCommand`): refuses
  unless write-capable, re-verifies the backup against the recorded digest,
  copies the current file aside first (`.qguard-prerollback-*`), restores,
  re-hashes, and acks `completed` **only if verified**.
- `settleAgentRollback()` is now the only writer of `status: 'restored'`, and it
  keys on the executor's `verified` flag. Unverified → `restore_failed`, which
  stays restorable so it can be retried.
- `resolveRollbackExecutor()` dispatches only to the agent that *made* the change
  (the backup lives on that host), and only when it is connected, write-capable,
  entitled, and running ≥ `AGENT_ROLLBACK_MIN_VERSION`.
- `recordSnapshotExecution()` persists the agent's backup descriptor (and the
  cloud adapters' `rollbackPlan`) onto the snapshot, so restore has a real target.
- `executeCloudConnectorRollback()` replays the recorded provider rollback plan
  for AWS ELB/S3/RDS, Azure App Gateway/Storage, GCS/GCP HTTPS LB.
- `buildSnapshotDashboard` is read-only. Snapshot creation moved to
  `ensureSnapshotForJob()`, a **gate** in the agent claim path.
- Four honest dispositions, never collapsed: `dispatched`, `restored`, `failed`,
  `awaiting-executor`.

Verified live: `npx tsx tools/rollback-live-check.ts` — 59 assertions against the
running server and the real database.

**Prevention Checklist**

- [ ] A status that asserts something about the CUSTOMER'S asset may only be
      written by the code path that received an executor's confirmation. Grep for
      every write of that literal and count them; two is auditable, six is not.
- [ ] "An executor EXISTS" is not "an executor RAN". `agents.length ? 'restored'
      : 'restorable'` is this bug in one line.
- [ ] A GET handler and an SSE tick must not write. Put `.update(`/`.insert(` in
      a regression check over the dashboard-builder body (`tools/rollback-check.ts`
      section 2 does exactly this).
- [ ] A guard that is created lazily by a dashboard is not a guard. If the rule is
      "never change an asset without a snapshot", the snapshot belongs in the
      dispatch path, not in a panel nobody may open.
- [ ] Before offering a destructive control, ask what would physically perform it.
      If the answer is "nothing", render the reason instead of the button —
      `restoreExecutable` + `restoreBlockedReason`.
- [ ] A backup is only a restore source while it still hashes to the digest
      recorded when it was taken. Verify before writing it back, never after.
- [ ] Make the rollback itself reversible (copy the current file aside first).
- [ ] A new agent command needs a MINIMUM RUNTIME VERSION check. An older agent
      answers "Unsupported command type", which settles as a failed restore and
      hides the real fix (upgrade the host).
- [ ] Records written by the broken path are still in the customer's database.
      Correct them with an appended audit row (`tools/rollback-legacy-reconcile.ts`),
      never by deleting history.

---

## 28. A Patcher agent executes a Live Migration cutover

**Problem**

The platform publishes four agent types and tells the customer that Migration
Operator "executes approved Live Migration cutovers" while Patcher applies
"remediation on allowed configuration paths". A Patcher claimed and executed
cutovers. A **Collector** — a read-only agent — could drive a migration job to
`completed` with a single POST.

**Root Cause**

`agentMayWrite(client, agent, 'migration')` in `agent-entitlement.ts` was written
for exactly this and had **no call site**. The only caller
(`GET /agent/remediation/jobs`) asked for `'remediation'`, which patcher *and*
operator both satisfy. `requireAgentRoleTier` was likewise exported and unused.

Separately, `POST /agent/remediation/jobs/:id/event` — the endpoint that moves a
job to `completed` — had **no capability check at all**. The claim path checked
the role; the path that declares the work finished did not.

**Solution**

- `jobExecutionClass(job)` in `agent-scanner.ts` classifies a job as `migration`
  (owned by a migration plan, or a cutover job type) or `remediation` (HNDL /
  config patch). One classifier, used by both the claim path and the event path.
- The job poll resolves BOTH capabilities once and applies them per job.
- The event endpoint re-checks the matching capability and returns 403.
- Refusals are returned as `refusedByRole` and written to the job as
  `metadata.dispatchBlock`, so Live Migration renders *why* rather than leaving
  the job at "Awaiting Agent" forever.

**Prevention Checklist**

- [ ] An exported enforcement helper with no call site is a defect, not dead code.
      `grep -c` the helper name; 1 means it is only defined.
- [ ] Enforce at EVERY state transition that matters, not just the first. Claiming
      work and declaring it finished are two different authorisations.
- [ ] If the UI states an authority boundary ("executes only…"), there must be a
      test that a wrongly-typed actor is refused. `tools/rollback-live-check.ts`
      section 2 enrols a real patcher and asserts it cannot take a cutover.
- [ ] A refusal must be reported, never silently filtered. An empty job list can
      mean "no work", "not your role" or "no snapshot" — three different operator
      actions.
- [ ] `agentsOnline` counted `status='active'`, a column that stays active until
      revocation. Liveness is a HEARTBEAT fact; use `HEARTBEAT_ONLINE_WINDOW_MS`.

---

## 29. Harvest Now jobs "queue" forever — or run with nobody's approval

**Problem**

Audit §2 requires explicit approval before any change to a customer asset. The
dispatch gate blocked only `rejected` and `pending_approval` plans, so every
other state dispatched unapproved: the planner's own `awaiting_agent` default,
plans whose `status` was `approved` because they had been EXPORTED to PDF or
pushed to the sandbox, and every Harvest Now remediation job — which has no plan
at all and reached the fleet via a plain Resume. The first attempt at a positive
gate ("no plan → block") fixed the approval hole and silently stranded every
Harvest Now job, because nothing could approve a planless job.

Two neighbours of the same defect:

- The agent claim path had **no sandbox exclusion**. A queued `[DRY RUN]` job
  whose target algorithm matched the PQC regex could be claimed by a real Patcher.
  `sandbox.ts` and `migration.ts` each had a private simulation predicate, and
  they had drifted (only one honoured `metadata.dryRun`).
- `POST /agent/remediation/jobs/:id/event` accepted any job with NO assigned
  agent, so a write-capable agent could post `completed` for work that was never
  claimed — bypassing both the approval gate and the snapshot gate, which live in
  the claim path.

**Root Cause**

Approval was modelled as the absence of a rejection, on one unit (the plan),
while work arrives in two shapes (planned migrations, per-finding remediation).
`planStatusForAction()` returned `'approved'` for `export`/`sandbox`, and
`loadMigrationPlan()` defaulted a missing row's status to `'approved'`.
`planApproval()` also read only one of the two shapes a plan travels in
(`metadata` on the raw row, `migrationMetadata` on the mapped payload), so the
positive control failed while every negative control passed.

**Solution**

`src/lib/migration/job-safety.ts` — one isomorphic module read by the dispatch
routes, the agent poll + event endpoint, the sandbox engine and the UI:

- `isSimulationJob()` — the UNION of every writer's markers; sandbox.ts and
  migration.ts delegate to it; the claim path filters on it first.
- `jobApproval(job, plan)` — planned job → the plan's recorded decision; planless
  job → the job's own `metadata.approval`; a job record cannot override a
  rejected plan; a planned job whose plan cannot be read is NOT approved.
- `approvalRecord()` — attributed (`decidedBy`, `decidedAt`, `reason`, `via`).
- New `approve` action on `/migration/jobs/:id/action` (bulk only with an
  explicit selection); Resume/Retry refuse unapproved work with the reason;
  Live Migration shows **Approve & queue** behind a confirmation, and hides
  Resume until approved.
- Event endpoint: `if (assignedAgentId !== agent.id)` — the claim is the only door.

Proven by `tools/agent-governance-check.mjs` (10 — now includes a never-approved
plan AND a bare `status:'approved'` as negative controls) and
`tools/rollback-live-check.ts` §2a/§2b.

**Prevention Checklist**

- [ ] An authorisation gate asks the POSITIVE question ("who approved this?"),
      never the negative one ("was it rejected?"). A negative gate admits every
      state nobody thought to list.
- [ ] A `status` string is not an approval. Approval is a record with a name.
- [ ] Before adding a precondition, enumerate EVERY producer of the thing being
      gated (`grep` for inserts, including multi-line `.from(t)\n.insert(`). A
      gate that one producer can never satisfy is an outage, not a control.
- [ ] Include a negative control that is the SYSTEM'S OWN DEFAULT state, not just
      the obviously-bad states. `awaiting_agent` was the one that mattered.
- [ ] A predicate over a record that travels in two shapes must read both — and
      the positive control is what catches it when it doesn't.
- [ ] Gates that live in a "claim" step are bypassed by any endpoint that acts
      on unclaimed work. Every state-changing endpoint re-checks the claim.
- [ ] One predicate per concept. Two copies of "is this a simulation?" had
      already drifted; the third call site had none.

---

## 30. "Key Rotations: 3" when no key was ever rotated

**Problem**

Live Migration reported certificate replacements, key rotations and TLS
handshakes before any change had happened, a 100% migration success rate with
nothing completed or failed, "Critical Systems Protected" equal to
`completed − failed`, and the same readiness number as three separate tiles
(Quantum Readiness, Audit Readiness, Compliance). Failed validations were counted
as Verified.

**Root Cause**

- Counters regexed free text over every telemetry row:
  `countTelemetry(/key|rotation|kem|envelope/)`. The claim row for an ML-KEM job
  contains "kem", so CLAIMING a job counted as a key rotation, and one row could
  count toward several operations.
- `/pass|success|valid/` matches "invalid" and "validation_failed".
- `completed + failed > 0 ? rate : 100` — success from no data.

**Solution**

`buildLiveTelemetry()` (exported, pure) counts operations **per job, once**,
classified by the recorded `job_type` via `OPERATION_CLASS_BY_JOB_TYPE`, and only
when the job completed with a passing validation. `isPassingValidation()` uses
exact tokens. UI tiles state what they count; the report reads the same fields
with matching labels.

**Prevention Checklist**

- [ ] Count OUTCOMES from structured fields, never mentions in free text.
      `tools/rollback-check.ts` §10 asserts a claim row is not a rotation.
- [ ] A status regex containing `valid` also matches `invalid`. Use exact tokens.
- [ ] A ratio with a zero denominator is "—", not 100%.
- [ ] If two tiles show the same variable, they must show the same LABEL.
- [ ] Classify an operation once, at the job, by its type — the substring trap
      from #22/`dhe`/`ecdh` recurs in every counter built on regex.

---

## 31. Agents report ECDSA as "RSA-1024 CRITICAL" and hybrid ML-KEM as classical X25519

**Problem**

On the agent evidence path: an ECDSA P-256 certificate issued by a CA named
"...TLS RSA SHA256...CA" was stored as RSA-1024 critical; an Ed25519 certificate
whose subject contained "rsa" ("Mersault Ltd") likewise; the hybrid groups
X25519MLKEM768 / mlkem768x25519-sha256 were stored as classical X25519; every
AES-256-GCM component was stored `is_quantum_safe: false` WITH a quantum exposure
row; and a config line merely naming an OQS provider wrote a quantum-SAFE row.
The agent's own labels were lossy too (`ecdh-sha2-nistp256` -> "ECDSA-P256", a key
exchange filed as a signature; RSA-3072 -> "RSA-2048"; RC4 -> "3DES").

**Root Cause**

- `normalizeEvidenceAlgorithm` (scanner_2/modules) substring-matched `rsa`,
  `x25519`, `tls` over `JSON.stringify(rawEvidence)` - issuer and subject names
  decided the key algorithm, and `P-256`'s "256" was parsed as an RSA modulus.
- `isPqcReadyEvidence` matched "pqc"/"hybrid" anywhere in the JSON (including the
  agent's own rule LABEL).
- `is_quantum_safe: finding.threatLevel === 'safe'` - no severity profile is ever
  `safe`, so it was always false.
- `evidenceMatch` found the FIRST evidence on the host, not the one that produced
  the finding.
- `classifyAgentEvidence` asked the knowledge base first; its alias scan matched
  the part it knew (`rsa-sha2-512` -> SHA-2, `TLS_ECDHE_RSA_...` -> AES).
- The canonical classifier itself missed sntrup761x25519, SecP384r1MLKEM1024,
  hybrid signatures, JOSE algorithms and hyphenated `TLS-1.3`.
- `scanEvidenceWithModules` had NO test.

**Solution**

One classifier: `analyzeCryptoObservation` decides quantum posture everywhere;
`classicalProfileFor()` maps its decomposition to a severity profile from
structured fields only; the inventory keeps the precise observed name; exposures
only for `vulnerable`; dependencies never become algorithm findings. Proven by
`tools/agent-evidence-classification-check.ts` (67) with a negative control
(restoring the old module fails exactly on the traps above).

**Prevention Checklist**

- [ ] Never classify from `JSON.stringify(record)`. Read the structured field.
- [ ] A predicate over a severity LEVEL must be checked against the levels that
      exist. `=== 'safe'` against a table with no `safe` entry is always false.
- [ ] Match a finding to its source by id, never by a shared attribute.
- [ ] Composite names (suites, SSH methods, hybrid groups) go to the decomposer,
      not a substring lookup.
- [ ] Every production path that writes a verdict needs a test whose fixtures are
      the traps - issuer names, subjects, curve sizes, hybrid groups.

---

## 32. The agent collects everything and uploads nothing ("control plane accepted 0")

**Problem**

`QGuard agent scan complete. Collected 31 evidence record(s) ... control plane
accepted 0; 2 publish error(s): Do not know how to serialize a BigInt`.

**Root Cause**

The TLS handshake scanner put `cert.publicKey.asymmetricKeyDetails` into
`rawEvidence`. For an RSA certificate Node reports `publicExponent` as a BigInt
(65537n); `JSON.stringify` throws; the WHOLE batch fails. Every agent scanning an
endpoint with an RSA certificate - the commonest kind - uploaded nothing. The
lifecycle e2e passed because its TLS target presents an ECDSA certificate.

**Solution**

`jsonSafe()` at the source, and a BigInt replacer in `publishBatch` as defence in
depth. Caught by `tools/agent-collector-offline-check.ts`, which runs the SHIPPED
bundle against a real lab (RSA/ECDSA/ML-DSA certs, keys, JWKS, SAML, live hybrid
and classical TLS servers) with a local recording control plane - no database.

**Prevention Checklist**

- [ ] Never put a Node crypto object's details into a payload without a JSON-safe
      copy: `asymmetricKeyDetails` carries BigInt.
- [ ] Test the uploader with an RSA certificate specifically.
- [ ] "accepted 0" after collecting N is a failure, not a quiet scan. Read the
      agent's own summary line in every live test.
- [ ] An assertion like "every certificate has X" passes on ZERO certificates.
      Require the collection to be non-empty.

---

## 33. A Patcher never patches a real Harvest Now job

**Problem**

Approved Harvest Now remediation jobs always ended "manual change required".
Separately, the Collector never read certificates or keys from disk, never
collected identity signing material, and never measured the TLS key-exchange
group - the one HNDL-deciding fact about a TLS endpoint.

**Root Cause**

- `buildHndlRemediationCandidates` dropped the finding's `evidenceRecord`, so the
  queued job never named the file to change.
- Both `adapterForJob` (agent) and `remediationAdapter` (server) classified by
  substring before checking for a file: `/etc/app/tls.conf` matched "tls" and
  routed to the NETWORK adapter, which is manual only.
- `scanAllowedPath` handled manifests, configs and SSH public keys only; the
  `certificates`/`pki` scan types had no filesystem implementation.

**Solution**

The candidate carries `location` (filePath/target/host/port/sourceAgentId) into
job metadata; a job naming a local file is `local_configuration` first. New agent
collectors: `scanTlsKeyExchange` (single-group handshakes; untestable is not
rejected), `scanCryptoMaterialFile` (PEM/DER/bundles plus key METADATA and
public-key fingerprint, never material), `scanIdentityFile` (JWKS, SAML metadata).
The server claim scope fails closed and resolves `..` with a path boundary.

**Prevention Checklist**

- [ ] Follow a capability end-to-end from the button the customer presses to the
      host being changed. A capability no product flow can reach is not a feature.
- [ ] Classify by the most specific structured fact first (a file path), then by
      words.
- [ ] A declared scan type with no collector behind it must fail a check.

---

## 34. New Supabase project: test accounts "lose" their plans and every table says `42501 permission denied`

**Problem**

After moving `.env` to a Supabase project created after 2026-05-30 and applying
every `supabase/*.sql` + messaging migration, users sign in but land on
`<UpgradeRequired variant="no-subscription">`, dashboards are empty, and
`tools/seed-test-subscriptions.ts` cannot write — even with the service-role key.
Separately, QA accounts that WERE seeded kept falling out of QGuard Messaging
about a month after each seed.

**Root Cause**

- Supabase no longer grants `anon` / `authenticated` / `service_role` on tables
  created in `public` (changelog discussion #45329). The tables exist, but
  PostgREST answers `42501 permission denied for table X` before RLS runs — for
  all 152 tables and all three roles, including the service key. A non-existent
  table answers `PGRST205` instead, which is how to tell the two apart.
- `use-subscription.ts` ignores the query error, so the gate renders "no
  subscription" instead of an error; `subscriptionGateway` catches the throw and
  fails OPEN, so the API let every signed-in account through to Elite routes.
- The seed set a 30-day `current_period_end`. The web gate reads `status` only,
  but `qguard_has_messaging_access()` (migration 030) and
  `qguard-messaging/src/lib/subscription.ts` lock 72h after period end.

**Solution**

Run `supabase/data-api-grants.sql` in the SQL Editor (idempotent). It grants
`service_role` on everything, and `anon`/`authenticated` only on tables whose
LIVE `pg_class.relrowsecurity` is on (and `security_invoker` views). 8 tables in
`supabase/schema.sql` never enable RLS in the migrations, yet on
`xsbdlahuecadzfajlvis` all 8 had RLS on — the migration text is not the database,
which is why the script reads the catalog instead of a list. Then
`npx tsx tools/seed-test-subscriptions.ts`
(now 365-day periods, and it stops with a grants hint on 42501). The owner
`zachmatthew369@gmail.com` must be created in Supabase > Authentication > Users —
`/register` refuses owner emails.

**Prevention Checklist**

- [ ] On any project swap, probe one table with the service key BEFORE seeding:
      `42501` = grants missing, `PGRST205` = migration missing.
- [ ] Re-run `supabase/data-api-grants.sql` after applying any new migration —
      default privileges only cover `service_role` for new tables.
- [ ] Never "fix" 42501 with a blanket `grant all ... to anon`: a table without
      RLS becomes readable and writable by anyone holding the public anon key.
- [ ] A seeded or comp subscription needs a `current_period_end` far enough out
      for the messaging paywall, not just an `active` status.
- [ ] Check live RLS without SQL access and without writing: anon `POST
      /rest/v1/<table>` with body `{}`. "violates row-level security" = RLS on;
      `23502` not-null = RLS off (anon reached the row). RLS WITH CHECK runs
      before NOT NULL; calibrate on `billing_subscriptions` first.
- [ ] Grants do not cover functions: SECURITY DEFINER RPCs keep EXECUTE for
      PUBLIC. `get_dashboard_summary`, `get_exposure_map`,
      `get_profile_security_snapshot` (+ 2 more) take any user id and answered
      200 to anon — a cross-tenant read independent of table grants.

---

## 35. Anyone with the anon key reads another tenant's profile; Crypto Agility shows no policy exceptions

**Problem**

Two defects that surface once a project's tables are reachable (entry #34):

- `POST /rest/v1/rpc/get_profile_security_snapshot {"p_user_id": "<any id>"}`
  with only the PUBLIC anon key returns that user's profile, preferences and
  security settings. Same for `get_dashboard_summary`, `get_exposure_map`,
  `get_recent_security_events`, `calculate_quantum_risk_score`. User ids are
  not secret: public avatar URLs are `avatars/<user_id>/...`.
- Crypto Agility always reports zero policy exceptions, whatever the tenant has
  recorded.

Also seen while provisioning: `qkms-command-center-schema.sql` fails with
`42P01 relation "public.qkms_keys" does not exist` if it runs before
`qkms-lifecycle-schema.sql`, which creates that table.

**Root Cause**

- The five functions (`dashboard-schema.sql`, `profile-security-schema.sql`) are
  SECURITY DEFINER, take the user id as an ARGUMENT and never compare it with
  `auth.uid()`. Definer rights bypass RLS inside them, and Postgres grants
  EXECUTE on every new function to PUBLIC. Table grants (#34) do not touch
  functions. No application code calls them.
- `schema.sql` creates `quantum_governance_*` without RLS or policies. On the
  new project RLS came up enabled anyway, with no policy. `crypto-agility.ts`
  reads `quantum_governance_exceptions` through `createAuthClient(token)` (the
  user's JWT), so RLS returns zero rows and `safeRows` passes on an empty list
  ("absent tenants degrade to no exceptions"). The old project had RLS off, so
  it worked there and was cross-tenant readable too.
- The `.from('table')` grep that audits table usage misses helpers taking the
  table name as an argument: `safeRows(client, 'quantum_governance_exceptions', …)`.

**Solution**

`supabase/rpc-and-rls-hardening.sql` (idempotent, independent of the order with
`data-api-grants.sql`):
- Revokes EXECUTE on the five functions from PUBLIC/anon/authenticated and
  grants it to service_role.
- Enables RLS on all 8 `schema.sql` tables.
- Adds `<table>_user_isolation` (`FOR ALL TO authenticated`, `user_id = (select
  auth.uid())`) on the four `quantum_governance_*` tables. `migrations`,
  `migration_logs`, `risk_scores` and `telemetry` stay service-role only.

Proven on PGlite (Postgres 17) with the full bundle, Supabase stubs (roles,
`auth.uid()/email()/jwt()`, `storage.objects/foldername`, `supabase_realtime`)
and both script orders:
- **Positive control:** anon reads another user's snapshot before the fix.
- **Negative control:** with RLS on and no policy, the owner reads 0 of their own
  exceptions.
- **After the fix:**
  - The five RPCs are denied to anon and to other tenants.
  - `vault_folder_path_array`, `get_or_create_vault_profile`,
    `verify_share_link_access` (anon) and `qguard_is_owner` still work.
  - The exact Crypto Agility query returns the owner's row, and nothing to others.

Working SQL order for a fresh project:
1. `schema.sql`
2. `dashboard-schema.sql`
3. `profile-security-schema.sql`
4. `billing-subscription-schema.sql`
5. `admin-dashboard-schema.sql`
6. `paypal-subscription-migration.sql`
7. `play-billing-migration.sql`
8. `quantum-vault-production-schema.sql`
9. `vault-complete-migration.sql`
10. `vault-files-migration.sql`
11. `vault-profile-rls-recursion-fix.sql`
12. `vault-security-hardening.sql`
13. `generated-keys-schema.sql`
14. `governance-schema.sql`
15. `migration-cost-assumptions-schema.sql`
16. `migration-snapshots-schema.sql`
17. `external-trust-schema.sql`
18. `pqauth-identity-schema.sql`
19. `qkms-lifecycle-schema.sql`
20. `qkms-command-center-schema.sql`
21. `quantum-certification-schema.sql`
22. `sophia-copilot-schema.sql`
23. `quantum-readiness-realtime.sql`
24. `scale-indexes.sql`
25. `data-api-grants.sql`
26. `rpc-and-rls-hardening.sql`

(`vault-schema.sql` is superseded by the production vault schema.)

**Prevention Checklist**

- [ ] A SECURITY DEFINER function that takes a user/tenant id must either check
      it against `auth.uid()` or be REVOKEd from PUBLIC. Audit with:
      `select oid::regprocedure, has_function_privilege('anon', oid, 'EXECUTE')
      from pg_proc where pronamespace = 'public'::regnamespace and prosecdef`.
- [ ] Probe an RPC leak without reading real data: call it as anon with a random
      UUID. 200 = executable, 42501 = closed.
- [ ] RLS without a policy is not "secure by default" for code that reads with
      the user's token — it is an always-empty list. Grep the user-token client
      (`createAuthClient`) callers for every table they read, including helper
      arguments, and give each an owner policy.
- [ ] Audit table usage with `rg "['\"\`]<table>['\"\`]"`, not only `.from(`.
- [ ] Dry-run a migration bundle on PGlite with Supabase stubs before applying it
      to a real project. The whole bundle applies in ~7s and catches file-order
      dependencies (`qkms_keys`) and policy defects with behavioural checks.

---

## 35. QGuard Messaging desktop: "Couldn't reach the secure sign-in service" on a machine that is online

**Problem**

The installed desktop app (or `dist` served by Tauri) refuses every sign-in with
`AUTH_UNREACHABLE_MESSAGE` from `qguard-messaging/src/lib/auth-context.tsx`,
while the web platform signs in fine. Seen 2026-08-12 and 2026-09-17.

**Root Cause**

Vite inlines `VITE_SUPABASE_URL` / `VITE_SUPABASE_ANON_KEY` into the bundle at
build time, and Tauri embeds that bundle in the exe. After a Supabase project
switch, an installer built earlier still calls the old project. When that project
has been deleted its hostname is NXDOMAIN, `fetch` throws "Failed to fetch",
`isTransientAuthError` matches, and three retries end in the "check your
connection" text — which points away from the real cause. (A restricted but live
project returns an HTTP error instead.)

**Solution**

Compare `grep -rhoE '[a-z]{20}\.supabase\.co' qguard-messaging/dist/assets | sort -u`
with `VITE_SUPABASE_URL` in `qguard-messaging/.env.local`, and resolve the baked
host (`nslookup <ref>.supabase.co 1.1.1.1`). Then rebuild with
`qguard-messaging/tools/release.ps1 -Version <x.y.z>`; it re-inlines the env, signs
the updater artifacts, and re-syncs `sizeMb` + `sha256` in
`src/app/qguard-messaging/_shared.tsx`. Reinstall from `public/downloads`.
Android: `qguard-messaging/docs/BUILD_NATIVE.md` path B (CLI build → copy `.so`
into `jniLibs` → `gradlew assembleArm64Release bundleArm64Release -x
rustBuildArm64Release`), then `node tools/verify-android-release.mjs
--forbid-asset <old entry js>`. The CLI's failed symlink DELETES the old `.so`
from `jniLibs`, so the copy step is mandatory, not optional.

**Prevention Checklist**

- [ ] Every Supabase project switch is also a desktop AND Android rebuild — the
      apps carry the project address inside the binary.
- [ ] The Tauri CSP (`https://*.supabase.co`) is not the cause; don't edit it.
- [ ] Don't grep the exe for the ref: embedded assets are brotli-compressed.
      Check `dist/assets` and that dist, exe and `.sig` share one build time.

---

## 36. "Details" does nothing on an Operational Migration Queue row

**Problem**

`/dashboard/migration-sandbox` → Overview → Operational Migration Queue → a row
such as *PQC Migration: expired.badssl.com · Migration Workflow · queued ·
"Awaiting sandbox executor capacity."* → **Details** opens nothing. Details on a
sandbox simulation row works.

**Root Cause**

The page kept a COPY of the clicked row in `selectedSimulation` plus an effect
that re-found it on every snapshot — in `data.simulations`, and closed the dialog
when it was missing. `simulations` is only the sandbox subset of `workflows`, so
every operational job was "missing": the dialog mounted and was set back to null
on the same commit. Nothing errored and nothing was logged.

Opening the dialog then exposed that it had only ever been built for simulations:

- the queue copy "Awaiting sandbox executor capacity." came from
  `phaseForProgress()` for EVERY queued job — the job was actually approved and
  waiting for a Migration Operator agent, and the tenant had none enrolled;
- the header read **low** risk (`quantumRisk("Classical crypto")` matches only
  literal "rsa" / "ecdsa" / "dh ") for an asset with 9 critical exposure rows;
- **Restore** / **Restore Snapshot** called the sandbox engine, which wrote
  `rolled_back` + "rollback posture validated" onto the REAL job with nothing run
  (entry #27's defect, reachable again through the sandbox);
- "Recent Events" was `.slice(-5)` of a newest-first list — the five OLDEST;
- snapshot cards read `riskState.riskScore`, written from `summary.riskScore`,
  a field the summary no longer carries — every capture recorded 0.

**Solution**

- The page stores `selectedJobId` and derives the record with
  `findJobRecord(id, data.workflows, data.simulations)` (`_shared.tsx`).
- `src/lib/migration/operational-workflow.ts` (pure, isomorphic):
  `describeOperationalWorkflow()` reads the shared `jobApproval` verdict, the
  recorded `dispatchBlock`, and the agent fleet by role
  (`AGENT_ROLES_FOR_EXECUTION`, mirrored from `agentMayWrite`) into a stage,
  headline, next action, four gates and deep links. `dispatchBlockFor()` is now
  the one refusal rule — Live Migration uses it too.
- `sandbox.ts` loads plan approvals (`approval:metadata->approval` projection)
  and `scanner_agents` (`role:metadata->>role`) only when operational jobs exist,
  tolerantly: an unread plan is `approval-unreadable`, an unread fleet is
  `unknown` — never "not approved" / "no agents".
- `SimulationDetails.tsx` renders the operational panel (Execution Readiness
  gates, next action, Live Migration / Agent Center links) and never offers
  engine controls on an operational job. `/jobs/:id/action` returns
  **409 OPERATIONAL_JOB** for pause/resume/retry/stop/restore_snapshot on one,
  and `/bulk-action` filters them out.
- Row risk uses `evidenceRiskLevel()` — the same function the Simulation
  Builder ranks targets by.

**Prevention Checklist**

- [ ] A dialog/drawer holds an ID, not a copy of the row, and resolves it from
      EVERY list it can be opened from. An effect that "refreshes" a copy from a
      narrower list silently closes it.
- [ ] Before reusing a detail view for a second kind of record, list which of
      its controls act on that kind. A button that was unreachable becomes a
      live write the moment the view opens.
- [ ] `.slice(-n)` means "latest" only on an oldest-first list. Check the
      query's `order()` before naming it "recent".
- [ ] After renaming a summary field, grep for readers of the OLD name —
      `summary.riskScore` kept being read (as 0) for months.
- [ ] Unreadable ≠ no. Approval and fleet reads that fail must surface as
      unknown, with the rest of the snapshot still served.
- [ ] Run `npx tsx tools/sandbox-details-check.tsx` (98 checks: selection,
      every operational stage with negative controls, role-table drift against
      `agentMayWrite`, the 409 guard, and static renders of both dialog kinds).

---

## 37. Revenue Intelligence shows $39 MRR with no payments — and any user can make themselves Elite

**Problem**

`/dashboard/revenue-intelligence` reported **MRR $39.00, ARR $468, Health 75**
and a forecast of **$468 ARR** for a database with **zero invoices** — the
only subscriptions were three `provider: 'manual_test'` QA seeds. Separately, a
signed-in user could `PATCH /rest/v1/billing_subscriptions` their own row to
`plan: 'Elite', status: 'active'` (probe answered `ALLOWED rows=1`), and opening
Settings > Billing on an account with no subscription created an ACTIVE one.

**Root Cause**

Eleven defects, in four groups:

1. **Entitlement writable by its subject.** `billing_subscriptions` carried
   `*_insert_own` / `*_update_own` policies; `profiles_update_own` let a user
   change `tier`; and `billing.ts ensureSubscription()` INSERTED an `active` row
   whose plan came from that user-writable `profiles.tier`. Three routes to free
   Elite, each also fabricating MRR.
2. **Revenue from rows no provider ever charged.** MRR summed every
   access-granting row × catalog price — QA seeds, comps, admin grants.
3. **Silent under-measurement.** `.limit(5000)` returns at most PostgREST's
   `max_rows` (1000); Play invoices used `upsert(onConflict: provider_invoice_id)`
   on a PARTIAL unique index (42P10 — the same trap the PayPal webhook hit) inside
   `bestEffort`, so no Play payment was ever recorded; failed PayPal payments
   never became invoices (success rate could not fall below 100%); user audit
   inserts ran on the user's token against a table with no insert policy; admin
   status writes (`approved`, `inactive`, `canceled`) violated the CHECK
   constraint, so Approve/Deactivate/Cancel failed on every click.
4. **Models that could not be right.** Windows in server-local time vs a UTC
   timeline; USD and EUR summed together; partial refunds counted as full and
   dated at the payment; health score filling unmeasured inputs with 0/100;
   forecast regressing over the partial current month and compounding a
   partial-month growth ratio; Admin's MRR computed by a second formula
   (latest-invoice fallback, different active rule) — two MRRs.

**Solution**

- `src/lib/billing/revenue-model.ts` — ONE pure model (classification
  provider/manual/complimentary, MRR rule, refund-at-refund-time, UTC calendar,
  per-currency, null-not-zero, weight redistribution, completed-month forecast
  with measured/derived/assumption inputs, backtest, and ten reconciliation
  invariants computed on every build). `revenue.ts`, `admin.ts` and the UI all
  read it; the frontend imports its types.
- `supabase/billing-integrity-hardening.sql` (applied): drops the two policies,
  adds `trg_profiles_protect_managed_columns`, the webhook claim ledger columns,
  `billing_notifications` to realtime, and paged-read indexes.
- `billing.ts`: no insert on read; service-client writes pinned to `user.id`;
  PayPal cancel fails closed; provider-billed auto-renew toggles refused.
- Webhooks (`supabase/functions/billing` + Express twin via shared `logic.ts`):
  claim-before-side-effects idempotency, failed-payment invoices, cumulative
  refunds, one audit vocabulary (`BILLING_AUDIT`), no overwrite of recorded sales.
- `admin.ts`: DB status vocabulary, provider-managed guard (409), customer
  billing trail + notification on every admin change, shared MRR.

**Prevention Checklist**

- [ ] An entitlement table has NO user write policy. Probe it: a user-token
      `update().select()` must return `[]`, an insert must error.
- [ ] A GET handler never creates an access-granting row.
- [ ] MRR counts only rows a payment provider bills; test/comp/manual rows are
      counted and disclosed separately.
- [ ] Never `.limit(N > 1000)` against PostgREST; page with `.range()` and report
      a ceiling hit.
- [ ] Never `upsert(onConflict)` on a partial unique index — select-then-insert.
- [ ] An audit write must be checked for `{ error }`; try/catch alone never fires.
- [ ] Every status an app writes must be in the column's CHECK constraint —
      compare against `pg_get_constraintdef`, not the migration file.
- [ ] Two screens showing "MRR" must call one function; assert equality live.
- [ ] Run `tools/revenue-intelligence-check.ts --live` and
      `tools/revenue-intelligence-render-check.ts`.

---

## 38. Advisor: "28 SECURITY DEFINER functions executable by anon" — and revoking them would break messaging

**Problem**

The Supabase security advisor listed 28 `SECURITY DEFINER` functions callable
by `anon`, 45 by `authenticated`, and 19 with a mutable `search_path`. Three
were real holes: `ensure_messaging_defaults(p_user_id)` let anyone (even anon)
reset another user's messaging modules; `log_qguard_profile_security_event` let
anon plant events in any user's security log; `qguard_has_messaging_access(uid)`
told any user whether someone else is a paying messaging customer. The
predicates behind messaging RLS were also membership/contact oracles.

**Root Cause**

Postgres grants EXECUTE to PUBLIC on every new function, definer rights bypass
RLS inside the function, and the functions trusted a user-id ARGUMENT instead of
`auth.uid()`. The obvious fix — `REVOKE ... FROM anon, authenticated` — is wrong
for the predicates: RLS policies (`TO public`, including `storage.objects`) call
them AS THE QUERYING ROLE, so revoking turns an empty result into
`permission denied` (already true before the fix: anon querying
`messaging_devices` errored because anon lacked EXECUTE on
`shares_messaging_conversation`).

**Solution** (`supabase/security-definer-hardening.sql`)

- Predicates stay executable but **guard inside**:
  `COALESCE(auth.role(),'') NOT IN ('anon','authenticated') OR <caller is a party>`.
  Inside a SECURITY DEFINER body `current_user` is the OWNER — use `auth.role()`
  / `auth.uid()` (JWT claims), never `current_user`, to know who called.
- "Caller is a party" had to be derived from EVERY call site:
  `messaging_envelopes_sender_insert` checks the RECIPIENT's membership, so
  `is_messaging_conversation_member` also answers when the caller is a member of
  that conversation; `can_view_messaging_profile` and
  `claim_messaging_one_time_prekey` call `is_messaging_contact` with the caller in
  either position.
- Trigger / event-trigger functions: REVOKE freely — Postgres does not check
  EXECUTE when a trigger fires (verified live as `authenticated`).
- Check column defaults before revoking: `vault_shared_links.token` defaults to
  `generate_secure_token(32)`, which runs as the inserting user.
- `search_path = public, extensions` (pgcrypto lives in `extensions`).
- Proven by a rolled-back dry run on the live schema that snapshots row counts
  per (user x table) before/after (70 cells, 0 changes), then
  `tools/security-definer-check.ts` (7 live Data API probes).

**Prevention Checklist**

- [ ] Before revoking EXECUTE, list callers in THREE places: `pg_policies`
      (incl. `storage`), column defaults, and other function bodies — plus app
      `rpc()` calls.
- [ ] A definer function taking a user id must compare it to `auth.uid()` (or be
      service-role only). Probe with anon + a random UUID.
- [ ] A guard on an RLS helper must accept every argument shape its policies
      pass — read each policy expression; one policy checked the recipient.
- [ ] Prove RLS changes with a before/after visibility snapshot inside
      `BEGIN ... RAISE EXCEPTION` (auto-rollback), not by reading policies.
- [ ] In check tools, never call `verifyOtp` on the client you use as "anon" —
      it signs that client in (see `qguard-testing-validation`).

---

## 39. Admin > Users: every user shows "0 active / 0 idle / 0 devices", MFA and roles look wrong, and "Force logout" does nothing

**Problem**

`/dashboard/admin` → Users showed 0 sessions and "IP: unknown" for every account
while Supabase Auth held 41 live sessions; the MFA column/KPI counted the
`mfa_required` policy flag (0 users ever enrolled); the owner rendered as role
"USER", plan "FREE / none"; the "User" role filter returned 0 rows although every
row displayed "User"; "Showing 1–N of <all users>" ignored filters. Actions:
Force logout revoked rows in an empty table; Suspend left live sessions and
unexpired tokens working; "Approve Pro subscription" failed for any user with no
billing row; Reset password rendered a clickable account-takeover link (and
stored it in the audit log); Delete removed the profile before the auth user and
deleted PayPal-billed subscription rows without cancelling at PayPal; PATCH's
owner guard checked the REQUEST BODY's email. Every SSE tick (10s) triggered ~11
client refetches, and typing in the search box reloaded all seven panels.

**Root Cause**

1. `public.user_sessions` / `user_devices` are written only when a user opens
   Settings (`profile.ts touchDeviceAndSession`). They are not a session store.
   The real store is `auth.sessions` (+ `auth.refresh_tokens`, `auth.mfa_factors`),
   which PostgREST does not expose — so the console never read it.
2. `profiles.role` is NULL for self-registered users (the protect trigger sets it);
   `.eq('role','user')` never matches NULL. Role/plan were displayed from
   different fields than the filters queried.
3. `billing_subscriptions.subscription_id` is NOT NULL; every other writer mints
   one (`paypal_…`, `gp_…`, `test-sub-…`) — the admin upsert did not.
4. Access tokens are verified locally (ES256), so deleting sessions stops refresh
   but an issued token keeps working until `exp`.
5. `refreshAll` depended on every filter-bound refresher, and each SSE frame
   handler called a refetch regardless of change.

**Solution**

- `supabase/admin-user-directory.sql` (applied): `admin_user_auth_directory()`,
  `admin_user_auth_sessions(uuid)`, `admin_revoke_user_sessions(uuid)` — SECURITY
  DEFINER, `search_path=''`, EXECUTE revoked from public/anon/authenticated,
  granted to service_role only.
- `src/lib/admin/user-directory.ts` — ONE pure model (status = profile × auth ban
  × email confirmation with drift reasons; plan = `entitlementFromRecords`, the
  gateway's rule, now shared in `subscription-access.ts`; billing class via
  `classifySubscription`; sessions/MFA null when unmeasured; 7 integrity checks;
  change `version`). API, KPIs, filters, CSV export, Overview "Total Users" and
  Security-tab MFA coverage all read it (5s single-flight cache).
- `supabase-server.ts revokeUserTokensIssuedBefore()` — getServerUser rejects a
  user's tokens with `iat` < an admin revocation; hydrated from
  `admin_session_revocations`.
- Actions rewritten in `admin.ts` (ban → profile with rollback → end sessions;
  owner protection by the TARGET's email; delete = typed-email confirmation,
  409 on an active provider subscription, auth-first cascade; recovery link never
  audited; reset email or one-time link → new `/reset-password` page).
- Hook: filter changes refresh only their list (value-compared, StrictMode-safe),
  stale responses dropped by sequence number; SSE `admin-users` frame carries
  KPIs + version and the table refetches only on a version change; a write pushes
  a frame to every open console at once (~0.4s); one shared 8s stream bundle.

**Prevention Checklist**

- [ ] Before displaying "sessions", "last login IP" or "MFA", name the store.
      `user_sessions` is Settings telemetry; Supabase Auth is the truth.
- [ ] A filter must query the SAME derived field the row displays (NULL role →
      "User" must be filterable as "User").
- [ ] A "sign out"/"suspend" control must defeat (a) refresh tokens AND (b)
      already-issued access tokens when verification is local.
- [ ] An owner/self guard reads the target record, never the request body.
- [ ] Never render a recovery/magic link as `<a href>` in an admin console, and
      strip it before any audit write.
- [ ] Deleting an account with an active provider subscription must fail closed.
- [ ] Every writer of a NOT NULL column without a default mints it — grep the
      other writers (`subscription_id:`) before adding an upsert path.
- [ ] SSE frames carry a change version; clients refetch on change only.
- [ ] Run `npx tsx tools/admin-users-check.ts --live --mutate` and
      `tools/admin-users-sse-probe.ts` after touching `/api/v1/admin/users*`.

---

## 40. Admin > Roles / Tenants / Billing / Security / Governance / History show invented figures and dead buttons

**Problem**

The six non-Users tabs of `/dashboard/admin` were largely fabricated or unwired:
role permission counts of 64/128/256 and holder counts not tied to any user;
every tenant shown with domain `<slug>.qguard.app` and region `us-east-1`;
"Upcoming invoices" listing complimentary QA seeds; Security showing
"Brute Force Login … SSH, RDP, VPN" threat narratives, "0/5 GB" sensors and
"SOC 2 Type II / PCI DSS / ISO 27001" compliance tiles with no evidence behind
them; Governance "Compliant" badges for policies nothing checked; History
reconstructed from the CURRENT state of records ("Subscription active", "Role
active") and every unknown audit action — including Revenue Intelligence page
views — categorised as "security". Upgrade/Downgrade buttons wrote plan changes
around the one subscription writer; tenant quotas were never enforced.

Found while verifying the rebuild: creating a tenant without a storage quota
500'd (`organizations.quota_storage_gb` / `quota_users` / `plan` are NOT NULL with
defaults 5/5/'free' — the API wrote explicit NULL, and the form promised "Empty =
unlimited"); edit forms PATCHed every field so the audit trail claimed every field
changed; the Security grids blew out to 722px on a 375px phone; and
`tools/revenue-intelligence-check.ts` leaked 3 live Supabase sessions per run,
inflating the very "session sprawl" control the Security tab measures.

**Root Cause**

1. No models: each panel computed (or hard-coded) its own figures in the route or
   the component, so nothing could be reconciled and nothing was traceable.
2. History read domain tables, not the audit trail, so it showed state, not
   actions. `admin_audit_events` is the only record of who did what.
3. Roles have no per-request enforcement in this platform — their only real
   effect is the Sophia copilot capability mapping (`normalizeRole` /
   `ROLE_CAPABILITIES` in `src/api-server/copilot-knowledge.ts`), and
   `normalizeRole` falls back to `infrastructure_admin` (read+operate+audit+
   executive) for any account WITHOUT a role. The console never said so.
4. Unset optional inputs were written as NULL into NOT NULL columns.

**Solution**

- Pure isomorphic models in `src/lib/admin/`: `role-catalog.ts`,
  `tenant-directory.ts`, `billing-console.ts` (revenue-model rules, same MRR as
  Revenue Intelligence), `security-posture.ts` (8 measured controls, each naming
  the accounts/findings it is about; findings name their asset via
  `assets.name`), `governance.ts` (policy verification states met / not_met /
  enforced_by_platform / attested — never "Compliant"; evidence packages are
  SHA3-256 over `canonicalJson(snapshot)`, re-verified on read),
  `admin-history.ts` (audit rows only; view actions hidden by default;
  `revenue.*` categorised; final verb rendered past tense). Shared helpers in
  `model-utils.ts` (`canonicalJson`, `modelVersion`, `toCsv`, `paginate`).
- `src/api-server/admin.ts`: one 5s `cachedConsoleModel` per tab shared by route,
  SSE frame and export; `invalidateAdminModels()` after every write pushes new
  frames (<1s); `sameStoredValue()` drops no-op PATCH fields before auditing;
  tenant create omits unset quotas (schema defaults), edit refuses clearing one
  (`QUOTA_REQUIRED`); `assertTenantCapacity` enforces the user quota; plan
  changes go only through Manage plan (`applyAdminSubscription`).
- Frontend: `src/app/dashboard/admin/_{roles,tenants,billing,security,governance,history}/`
  on `_shared/console.tsx` + `src/hooks/use-console-resource.ts` (lazy load,
  debounced value-compared queries, stale-response guard, refetch on SSE version
  change only). Grids use `grid-cols-[minmax(0,1fr)]`; tables scroll in their own
  `overflow-x-auto`.

**Prevention Checklist**

- [ ] A console tab reads ONE model from `src/lib/admin/*`; its route, SSE frame
      and export all call the same cached loader.
- [ ] "History" = the audit trail. Never synthesise history from current state.
- [ ] Before labelling a role, say what it actually changes (today: Sophia
      capabilities only). Do not display permission counts that nothing enforces
      as if they were enforced.
- [ ] No compliance framework status without evidence; unverifiable policies are
      "Attested", not "Compliant".
- [ ] Unset optional inputs are OMITTED from inserts (let schema defaults apply);
      check `information_schema.columns.is_nullable` before promising "blank =
      unlimited" in a form.
- [ ] PATCH routes compare against the stored row and audit only real changes.
- [ ] Test tools that mint sessions (`verifyOtp`) must `signOut({scope:'local'})`
      every client they create — leaked sessions pollute live security metrics.
- [ ] A check that writes rows directly (as a webhook would) must allow for the
      5s admin model cache — it bypasses `invalidateAdminModels()`.
- [ ] Run `tools/admin-console-check.ts --live --mutate` and
      `tools/admin-console-sse-probe.ts` after touching `/api/v1/admin/*`.

---

## Adding an entry

Use exactly this shape — Problem, Root Cause, Solution, Prevention Checklist.
An entry with no Prevention Checklist has not been learned from. Name real files,
real functions and real commands; a generalised lesson is not retrievable when
the symptom recurs.
