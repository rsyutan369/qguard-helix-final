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

## Adding an entry

Use exactly this shape — Problem, Root Cause, Solution, Prevention Checklist.
An entry with no Prevention Checklist has not been learned from. Name real files,
real functions and real commands; a generalised lesson is not retrievable when
the symptom recurs.
