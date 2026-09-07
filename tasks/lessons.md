# Lessons — Q-Shrink Vault Engine

## L1 — Web Streams: read before you write, settle both sides on error
**Failure pattern:** `CompressionStream`/`DecompressionStream` via `new Response(stream.readable).arrayBuffer()` produced intermittently truncated output (`Z_BUF_ERROR: unexpected end of file`), and a *deliberately* corrupt decompress (tamper test) crashed the **next** test with an uncaught `TypeError` from Node's webstreams adapter.
**Root cause:** (a) writing without an active reader / without awaiting risks truncated collection and backpressure deadlock; (b) when a transform errors, `new Response(readable)` can leave a dangling, unhandled stream `error` event that surfaces on a later tick.
**Prevention rule:** pump transform streams manually — get both reader and writer, run read+write concurrently, and on error `cancel()` the reader, `abort()` the writer, and `Promise.allSettled` both halves before rethrowing a clean error. Never use `new Response(readable)` for data that may be corrupt. (`src/lib/vault/q-shrink/codec.ts`)

## L2 — Test assertions must match the algorithm's real behavior
**Failure pattern:** a cross-file dedup assertion failed because the "shared" content was repetitive *text* whose 69-byte period doesn't align to 8 KB chunk boundaries — it compresses ~99% but doesn't dedup.
**Prevention rule:** to exercise block-level dedup, share a large **random** blob (stable, alignable content-defined boundaries). Compression and deduplication are different wins; test them with inputs that isolate each.

## L3 — Compress before encrypt; never inflate
**Rule:** high-entropy ciphertext is incompressible, so optimization must precede encryption. Entropy-gate + a post-compression guard + a container-vs-original guard guarantee the sealed object is never larger than the input (`applied:false` seals raw bytes). Each file compresses in isolation (no CRIME/BREACH shared-context oracle).

## L4 — A self-describing magic must be unforgeable by the payload it describes
**Failure pattern:** restore detected containers purely by the `QSHRN1` magic, while the no-inflation path sealed *raw* bytes with `applied:false`. A real user file whose plaintext happened to begin with the 7 magic bytes (`51 53 48 52 4E 31 01`) was therefore mis-detected as a container on download and `restorePackage` tried to `JSON.parse` random bytes → threw → **permanent data loss for a correctly-sealed file**. Attacker-craftable (just upload a file starting with those bytes; a re-uploaded vault container literally does).
**Root cause:** the two halves of the contract disagreed — optimize could emit a passthrough that collides with the very sentinel restore treats as authoritative. The `applied` flag that was *supposed* to disambiguate lived in mutable, unauthenticated server metadata, so restore (correctly, for zero-knowledge) ignored it — leaving magic-only detection with a false-positive hole.
**Prevention rule:** when a format is detected by an in-band sentinel, the *producer* must guarantee no non-format payload can start with that sentinel. Here: `optimizeFile` now wraps any raw input that begins with the magic instead of passing it through (`!beneficial && !isQShrinkPackage(data)` gates passthrough), so the magic is truly authoritative and the decision stays inside the GCM-authenticated bytes — never trusting mutable metadata. Regression covered in `roundtrip-test.ts` → `[magic-collision safety]`.

## L6 — A CSP is only "done" once a browser confirms it (and it surfaces hidden deps)
**Failure pattern (caught by testing):** the strict CSP built and the meta injected cleanly, but loading it under `vite preview` + Playwright showed 37 console errors — the policy was blocking third-party placeholder avatars (`randomuser.me`, `loremfaces.net`) hard-coded in `Landing.tsx`. A build-pass alone would have shipped either broken images or a quietly-weakened policy.
**Root cause:** static checks (tsc/build) can't see runtime resource loads; CSP enforcement only happens in a browser. The external images were also fake placeholder faces (against the project's "no fabricated data" rule) leaking visitor IPs.
**Prevention rule:** verify a CSP by serving the build and reading the browser console for violations (`Refused to…`) AND confirming the app still renders (root has children, inline-script hash matches → theme applies). Keep the policy strict and fix the *app* (here: local data-URI `initialsAvatar`) rather than loosening `img-src`/`script-src` to accommodate it. Inline scripts must be allow-listed by SHA-256 hash, never `'unsafe-inline'`; compute the hash at build over the exact emitted script text.

## L7 — API and DB schema drifted apart; the generic 500 hid it
**Failure pattern:** "Failed to create shared link" on every share. The share API (`/api/v1/vault/share` insert + `/public` select + GET/DELETE filters) referenced columns `owner_id, encrypted_payload, iv, integrity_hash, password_salt, destroyed_reason` that **do not exist** in the deployed `vault_shared_links` table — which actually has `user_id` (NOT NULL, RLS `user_id = auth.uid()`), `encryption_metadata` (JSONB), `password_hash`. So the INSERT referenced unknown columns AND omitted NOT-NULL `user_id` → Postgres error → the route swallowed it as a generic `DB_ERROR` 500.
**Root cause:** the route was written against a planned/phantom schema that was never migrated; nothing in the repo SQL or RLS ever defined those columns (uploads/keys work because they correctly use `user_id`). The generic error message hid the real Postgres detail.
**Prevention rule:** persist a feature's data using the columns that actually exist — store variable share crypto (`payload, iv, integrityHash, recipientWrap, passwordSalt, passwordKdf, sharingMode`) in the existing `encryption_metadata` JSONB, not invented columns; keep write and read paths reading the SAME shape. Never swallow a DB error into a generic message — surface `code/message/details/hint` (guarded to dev) so schema/RLS drift is visible immediately. Adjacent bugs found in the same pass: client sent `expiresAt` but the route read `expiresIn`; `passwordSalt/recipientWrap/passwordKdf` arrived nested under `encryptionMetadata` and were never stored or returned (so recipient-bound/password reads were also broken).

## L5 — "Encrypt the filename" is a cross-cutting cutover, not a column swap
**Failure pattern (avoided):** the obvious way to stop leaking `original_filename` is to make it a placeholder and decrypt on display. But that one column is read by **public shared-link routes** (a share recipient has *no vault keys*, so a sealed name is undecryptable for them) and by **server-side analytics dashboards** (which by design can't hold user keys). A blind flip would have shown random IDs to share recipients and placeholders in dashboards — a regression worse than the metadata leak, and untestable without an authenticated session.
**Root cause:** filename is both a confidentiality concern (owner) and a functional field (sharing/telemetry); encrypting it for the owner removes it from every party that legitimately can't decrypt.
**Prevention rule:** before "just encrypt field X", grep every reader. If any reader can't possess the key (anonymous share, server telemetry), the change needs a *separate name-delivery path* for them and authenticated E2E testing — ship the additive capture (`envelope_meta.sealedMeta`) first, defer the destructive cutover. The HNDL-critical hardening was the **passphrase KDF (PBKDF2→Argon2id) + strength enforcement**, not the metadata — fix the root-of-trust first.

## 2026-08-26 — Video calling failed in both directions on 1.3.0

**Failure pattern.** A fix that is correct in isolation can be completely inert
because of an upstream defect, and it will look like the fix did not work. The
1.3.0 ring fan-out ("ring every device") was correct code fanning out to a
one-element list, because `deliveryDeviceBucket` keyed on `user_id:device_label`
and every platform registered the identical hardcoded label `"Windows Desktop"`.

**Root causes (4, independent).**
1. Identical hardcoded device labels collapsed every account to ONE addressable
   device — for messages as well as calls.
2. `App.tsx` returned the Android PIN screen in an early return ABOVE
   `CallProvider`, so backgrounding the phone unmounted the call-signal
   subscription entirely.
3. The shipped public TURN relay could not allocate, AND an unallocatable TURN
   entry stops ICE gathering from ever completing — a broken relay was strictly
   worse than no relay.
4. One fixed 45s wall clock covered both ringing and connecting, so a
   slow-but-advancing connection was killed at the moment it was about to work.

**Prevention rules.**
- A discriminator that is *hardcoded identical everywhere* is not a
  discriminator. When deduplicating "the same device", key on something that
  actually diverges per device (here: `last_seen_at` recency), not on a label
  the code itself writes.
- Anything that must survive a lock/gate must be mounted ABOVE that gate. Check
  what an early `return` unmounts before adding one.
- Never ship a third-party dependency in the media path without a runtime health
  check. And verify a TURN server by driving REAL Chromium ICE over CDP — a
  hand-rolled STUN probe returns errors that may be your own bug.
- A timeout should measure the thing it is protecting against. Elapsed time is
  not progress; if the operation can legitimately take longer, gate on progress
  and keep a separate absolute ceiling.
- A failure state that unmounts its own UI discards its error message. Check
  that a `failed` reason has somewhere to render.
- `messaging_call_signals` is a complete call timeline — read it before theorising
  about call bugs.

## 2026-08-26 (2) — "100% · Fully protected" above "2 of 4 layers fully active"

**Failure pattern.** Two models measuring the same thing on one screen, and the
WRONG one was the pessimistic-looking one. The headline (`buildSecurityPosture`)
was right; the phone's reactor (`buildCryptoStack`) was mis-measuring. The user
reasonably read the low number as a security gap. It was not: their cryptography
was fully active.

**Root cause.** `buildCryptoStack` diverged from the canonical posture engine in
three ways, and `security-score.ts` already documented the trap in its own code
("stale device identities left behind by reinstalls ... make a perfectly healthy
device read as awaiting prekey material forever"):
1. Divided Identity/Handshake by EVERY non-revoked device row. A reinstall mints
   a new identity and strands the old row forever with no signed prekey — the
   live account had 2 live devices and 3 stranded rows, so Handshake read 2/5.
2. Counted build-provenance gates (code signing, obfuscation, control-flow
   flattening) in the Runtime layer. `security-score.ts` deliberately excludes
   them; they describe how the binary was produced, not whether the running
   cryptography works.
3. Measured Session against an aspirational target (24) instead of the readiness
   threshold the rest of the platform uses (16).

Separately, on Android the runtime genuinely could not measure itself:
`current_binary_measurement()` used `std::env::current_exe()`, which on Android
is the zygote (`/system/bin/app_process64`) — not our code, and unreadable in
the app sandbox. Two integrity checks reported "unavailable" for that reason
alone. Fixed by measuring the app's own loaded `.so`, located via
`/proc/self/maps`.

**Prevention rules.**
- Before adding a second measurement of something already measured, find the
  existing engine and reuse its vocabulary. If a module's header comment warns
  about a trap, the new module is probably about to fall into it.
- A ratio is only as honest as its denominator. State the population in the UI
  ("across N enrolled devices") — an unqualified "2 of 4" hides the bug.
- Narrowing a denominator is legitimate ONLY when the excluded rows are
  reclassified and surfaced with their own action, never silently dropped. Test
  both directions: that stranded rows stop deflating the layer, AND that a real
  gap on a live device still fails it.
- Two numbers on one screen that can contradict each other WILL. Make the
  stronger claim structurally conditional on the weaker evidence (`scoreVerdict`
  now takes the layers) so the contradiction cannot be written again.
- `#[cfg(target_os = "android")]` code is NOT compiled by a host `cargo check`.
  Verify with `cargo check --lib --target aarch64-linux-android`, and put the
  NDK's `toolchains/llvm/prebuilt/windows-x86_64/bin` on PATH first or cc-rs
  fails with "failed to find tool clang.exe".

## Exposure Assessment Engine — Web/Local/Dev (2026-08-31)

**Failure pattern: a server-only module reached the browser through a registry.**
`registry.ts` statically imported the cloud connector engines so `engineById`
could resolve them. Every browser surface that reads the registry — the engine
selector, the profile list, the health panel — therefore pulled `node:crypto`
into the client bundle, and `/public-scan` failed to render at all.
*Prevention:* when a module is the lookup table for BOTH describable and
executable things, split them. Descriptors are data and may be imported
anywhere; implementations are registered by a side-effect import that only the
server performs. `dev/connectors.ts` is that boundary.

**Failure pattern: a path-matching wildcard that silently matched nothing.**
The Kubernetes rules used `*capabilities.add[]` where `*` meant ONE path
segment, but a container securityContext sits six segments deep. Four whole rule
families — dangerous capabilities, hostPath mounts, image provenance, inline
secret env vars — matched nothing and the scan reported a clean workload.
*Prevention:* a security rule that finds nothing is indistinguishable from a
passing control, so every matcher needs a fixture that proves it FIRES. The
check harness now asserts each rule family produces its finding.

**Failure pattern: redaction keyed off the wrong field.**
The snippet redactor looked for secret-shaped IDENTIFIERS, so
`DATABASE_URL=postgres://app:realpassword@host` passed straight through — the
credential is in the URL userinfo and the identifier says "URL". Likewise a
Kubernetes inline secret's key is literally `value`.
*Prevention:* redact by SHAPE (URL userinfo, PEM body, provider token formats)
as well as by identifier, and let a rule that knows its matched value is a
credential say so explicitly (`redactValue`). The harness asserts no fixture
credential appears anywhere in the serialised assessment.

**Environment trap: `python - <<'PY'` heredocs collapse backslashes here.**
Patch scripts written this way corrupted `\n` into a literal newline inside a
regex and `\uE000` into the raw code point, twice. Git-Bash-on-Windows is not
passing the quoted heredoc through literally.
*Prevention:* use the Edit/Write tools for any content containing backslashes;
if a script is unavoidable, build backslashes with `chr(92)` and verify by
re-reading the file from disk, not by asserting on the in-memory string.

## Scanner accuracy refactor (Agents_Scanner_Engines_Enhancements)

**Failure pattern: the reporting gate asked about the wrong subject.**
A `bcrypt` call with `rounds=8` produced no finding, because the gate asked
whether the ALGORITHM was weak — and bcrypt is fine. The weakness was the
PARAMETER. Same shape as the AES/ECB miss, where the cipher is strong and the
MODE is broken.
*Prevention:* when a rule is about a parameter or a mode, the publish decision
must key on the rule family, not on the algorithm's own verdict. Both cases now
have a corpus fixture.

**Failure pattern: a call-shape guard that prose also satisfies.**
`logger.info('RSA key generation failed')` was reported as an RSA finding. The
first fix required the match to sit inside a call's arguments — which a log line
also does. What actually separates them is that prose has WORDS: the second fix
counts words in the enclosing quoted region (>=3 = prose, <2 = an API argument).
*Prevention:* when suppressing string-literal matches, discriminate on the shape
of the STRING, not on the shape of the call around it.

**Failure pattern: `\b` before a version number.**
`/\bTLSv?1\b/` matched the "TLSv1" inside "TLSv1.2", because "." is a word
boundary — so a hardened `ssl_protocols TLSv1.2 TLSv1.3` was published as
offering TLS 1.0. Third time this repository has been bitten by a word-boundary
assumption (see also `dhparam1024.pem` and the SHA-1 regex).
*Prevention:* version-number regexes end with `(?![\d.])`, never `\b`.

**Failure pattern: absent classification silently skips the finding.**
`Math.random()` in a token generator produced nothing, because the classifier
returned no algorithm and the loop began `if (!classification.algorithm)
continue`. The weakness was real and modelled nowhere.
*Prevention:* a detector that can fire without naming a registry algorithm needs
a registry entry for the weakness itself (`weak-prng`), or the guard silently
eats it. The negative-corpus run cannot catch this — only the positive corpus can.

**Duplicated grammar is a drift risk even when duplication is the right call.**
`suite-anatomy.ts` and `tls-intelligence.ts` both parse cipher suites, and
consolidating them would have touched eight unrelated consumers.
*Prevention:* when two implementations of the same grammar are kept
deliberately, add a test that asserts they AGREE on the fields both produce
(`checkDecomposerAgreement`). Documentation alone does not stop drift.

**Panel tiles must reconcile with the number above them.**
The detection summary showed `Confirmed 0 / Potential 0` beside a scan with 1
finding, because findings whose engine records no determination state were
counted nowhere. A reader comparing the two is left to guess which is wrong.
*Prevention:* when a panel decomposes a total, the parts must sum to it — add
the residual bucket (here §90's "Not established") and say in the copy that they
sum.


## Web / Local / Dev subscription gate

**A prefix-based gateway cannot gate three modes served at one prefix.**
`/api/v1/exposure` serves Web (anonymous), Local (Basic) and Dev (Pro). Adding
it to `API_MIN_TIER` would either lock the free Web assessment out or, set to
the lowest common tier, hand Dev away. The omission looks like a bug and is not.
*Prevention:* the router gates itself per route on the MODE, and
`subscription-guard.ts` now carries a comment saying so by name — the trap here
is a future maintainer "fixing" the missing entry.

**Fail-open and fail-closed are per-blast-radius decisions, not per-codebase.**
The central gateway fails OPEN on a billing read error, correctly: locking a
subscriber out of a whole dashboard over a transient Supabase blip is worse than
a brief over-grant. The exposure mode gate fails CLOSED, also correctly: the
blast radius is one scan, and silently granting a paid feature has no symptom.
*Prevention:* when copying an existing guard's error handling, re-derive the
direction from what is actually at risk rather than inheriting it.

**A gate that hides the feature cannot sell it.**
The first instinct is to render "Upgrade required" over an empty panel. That
makes the case for nothing: a visitor leaves without learning what a Local
assessment does. The gate now shows every capability, the privacy assurance and
the plans — everything except the button that runs it.

**Client-side entitlement must never be the only reading, and must not flash.**
Two failure modes pull in opposite directions: a stale client read that says
"allowed" produces a 403 on submit, and a slow server read shows "upgrade" to a
paying customer for a beat. Fixed by reading BOTH — local matrix for first
paint, server answer wins once it lands — with a skeleton over the resolving
window so neither is visible.

**Three refusals need three next steps.** Collapsing unauthenticated,
tier-too-low and inactive-subscription into one "upgrade" message sends a
lapsed Elite customer to the pricing page to buy what they already own. The
check tool asserts the lapsed message does not contain the word "upgrade".


## Agent tier gating and detection honesty

**A dependency proves a LIBRARY, never an ALGORITHM — and never a key size.**
The agent's package classifier mapped `openssl` → RSA-2048, `libsodium` →
RSA-2048, `bcrypt` → SHA-256, `crypto-js` → AES-128. Three were factually wrong
(libsodium ships no RSA; bcrypt is Blowfish-derived) and all four invented a key
size that appears in no manifest — then fed the CBOM, the vulnerable-component
count and the migration plan as measurements.
*Prevention:* manifest evidence names the library at LOW confidence and lists
what it makes AVAILABLE. An algorithm is named only when the package name itself
states one. `tools/agent-access-check.ts` greps the classifier for key-size
literals so the fabrication cannot come back.

**Library match must beat algorithm-substring match.**
After the rewrite, `ssh2` classified as the SSH *protocol* because `findAlgorithm`
ran first and matched a substring. An exact catalogue hit is a more specific
signal than an algorithm name appearing inside a package name.
*Prevention:* library catalogue first, algorithm second.

**Removing a fabrication can be a coverage regression.** Deleting the invented
mappings left `crypto-js`, `jsonwebtoken` and `node-forge` classified as nothing
at all — they are real crypto libraries. Honest-but-silent is still wrong.
*Prevention:* when replacing a fabricating classifier, check the inputs it used
to handle still produce SOME correct answer; 17 libraries were added.

**A caller-supplied field spread into a DB row is a privilege escalation.**
`metadata` was spread verbatim into the agent row and `metadata.role` decided
the agent's capabilities — so any tenant could mint a `patcher` (an agent that
writes to their hosts) by editing one JSON field.
*Prevention:* server-resolved fields are written AFTER the caller's spread so
they overwrite it, and the check tool asserts the ordering by grepping for
`role: resolvedRole` following the spread.

**Entitlement must be re-checked where the work is handed out, not only where
the resource is created.** An agent enrolled under Pro keeps its row after a
downgrade — correctly, since deleting a fleet on a billing change is worse. What
must stop is the WORK, so `agentMayWrite` runs on every job poll.

**A prefix-based gateway cannot express a per-role split.** Second instance of
this shape in one project (the first was Web/Local/Dev at `/api/v1/exposure`).
Setting `/api/v1/agent-*` to `pro` locks Basic out of the collector; setting it
to `basic` alone hands Basic a patcher. Both the floor and the per-role module
are required, and the gateway now says so in a comment naming the file.


## Scanner panel contradictions (test.openquantumsafe.org)

**Two engines observing one endpoint, three panels each doing their own
fallback arithmetic over the pair.** One page published Forward Secrecy as
"Not offered" (red), "Not observed" AND 100 simultaneously, beside a
Post-Quantum panel claiming "No TLS handshake completed" — printed directly
under a negotiated TLS 1.3 suite, a 5-certificate chain and an 85-day validity.
*Root cause:* the socket analyser succeeded and the edge named-group prober
timed out. Each panel resolved the pair differently.
*Prevention:* one `reconcileTransport()` in
`lib/scanner/web-scanner/transport-truth.ts`; every panel and the published
scorer read it. The check tool counts `displayForwardSecrecy(` call sites so a
fourth private chain fails the build.

**A boolean cannot express "not measured", and defaults to the worst answer.**
`EdgeTransport.forwardSecrecy: boolean` read `false` when the probe never ran —
publishing the strongest possible negative claim from zero evidence. Its
siblings in the same interface (`alpnProbed`, `chainTrusted: boolean | null`)
already had the tri-state; this one field missed it.
*Prevention:* every reading in the reconciler is `Measured<T>` with
`value: T | null`. `false` is returned ONLY when something was measured and
found absent, and the invariant test asserts exactly that across five
observation states.

**An engine must scope its failure message to its own probe.** "No TLS
handshake completed" was the edge prober describing ITS failure, but the
platform had completed a handshake through another engine. Naming what actually
failed — "named key-agreement groups could not be probed" — is both accurate
and more useful.

**TLS 1.3 makes forward secrecy a protocol fact, not a measurement.** The
protocol has no non-ephemeral key exchange, so a completed 1.3 handshake is
forward secret by construction — no probe needed. Waiting on one produced "Not
offered" on an endpoint that cannot possibly lack it.

**A "not scored" footnote beside a number is worse than either alone.** The
Encryption Score card rendered `14 / Limited` directly above its own note
saying post-quantum readiness was not scored. A non-nullable
`postQuantumReadiness: number` forced a finding-share fallback whenever the
weighted model excluded the dimension.
*Prevention:* nullable end-to-end with a reason, and the fallback only fires
when there is no edge evidence at all.

**"Unknown" beside "HIGH" is a contradiction, not caution.** Quantum
Vulnerability read Unknown while the same panel listed the ECDSA P-256 leaf as a
HIGH risk factor with an ML-DSA-65 migration target at 80% confidence. The
verdict gated on the edge probe alone; the risk factors came from a parsed
certificate. A parsed certificate IS quantum-relevant evidence.
*Prevention:* `hasTransportEvidence` now accepts either source, and the
reconciler scopes the claim — "the handshake that was negotiated used X, which
Shor breaks; whether this endpoint would ALSO accept a post-quantum group was
not measured."


## Local/Dev panel reconciliation and engine liveness

**Two correct numbers with no unit stated read as one wrong number.**
Quantum Exposure counted CBOM COMPONENTS ("Vulnerable 7"); the Findings filter
counted FINDINGS ("8 vulnerable"); Scanned Assets summed findings per asset.
All four were right. None said what it counted, so clicking the filter after
reading the summary looked like the product contradicting itself.
*Prevention:* `lib/scanner/exposure/exposure-truth.ts` publishes BOTH unit
counts from one place, every panel prints its unit, and a `unitNote` explains
the difference — rendered only when the two actually differ.

**Readiness must be a share of components, never of findings.** Computing it
over findings makes an estate look worse the more thoroughly it is scanned,
since one weak component can raise several findings.

**A raw NUL byte in a source file makes git treat it as binary.**
`orchestrator.ts` used `' '` as the `**` glob sentinel, written as an actual
0x00 byte. `file` reported "data", and every change to the file that decides
WHICH ENGINES RUN showed as "Binary files differ" with no reviewable diff.
Behaviour was fine; reviewability was not.
*Prevention:* U+E000 (private use) as the sentinel, written as the escape
``. The liveness tool asserts the file contains no NUL bytes. Third
appearance of heredoc-written source corrupting a file in this project.

**De-duplicate a display list by the thing it names, not by the row.**
The coverage ledger keys `notAssessed` on `dimension|reason`, so two engines
that could not read the SAME dimension for slightly different reasons both
survived — and the panel said "2 dimensions could not be read (Dependency
vulnerability advisories, Dependency vulnerability advisories)". One dimension
is one gap however many engines noticed it.

**`WORD + 's'` is not pluralisation when WORD is upper-case.** Produced
"COMPONENTs" in a panel whose whole job is to look precise.

**Engines need a liveness test, not just an accuracy test.** An engine whose
rule family silently matches nothing produces a clean-looking report, and this
project has shipped that twice (four Kubernetes families broken by `*` vs `**`,
weak-DH broken by a leading `` before a digit).
*Prevention:* `tools/exposure-engine-liveness-check.ts` plants one file per
engine and asserts each engine reported something from ITS file — plus that
every engine reached a terminal state and that silence is explained.


## /public-scan panel consistency

**The page was already right, and the audit is what established that.**
Unlike the dashboard Web tab — where three panels each computed forward
secrecy from their own fallback chain — `/public-scan` evaluates the control
set exactly once in `assess.ts` and every panel is a projection of that array.
The check tool proves the property holds rather than assuming it, across four
observation states.

**"Not observed" and "Not measured" are different answers and were conflated.**
`CryptoIntelligence.forwardSecrecy` was a three-state union, so an endpoint that
never completed a handshake reported "Not observed" — a measured absence, and
the strongest negative available — while the Forward Secrecy CONTROL on the same
report correctly said "Unknown". One fact, two vocabularies, two answers.
*Prevention:* a fourth state, `Not measured`, and a check asserting
`control "Unknown"` ⇔ `panel "Not measured"` in every state. Colour follows:
measured-absent is rose, never-measured is slate — painting both amber said the
same thing about a real gap and about a silent endpoint.

**A flag-carrying contract only works if every consumer reads the flag.**
`ScoreComponent.score` is coerced to 0 for an unmeasured dimension with the
truth in `applicable`; `computePostQuantumReadiness` always returns a number
with the truth in `measured`. Both are legitimate — the scoring model needs a
number — but a panel that renders `score` directly publishes 0, which on a
higher-is-better scale is the worst possible MEASURED result. The panels do
check; the check tool now asserts they still do.

**Testing the wrong contract produces four confident false positives.**
My first pass asserted `component.score === null` for unmeasured dimensions and
reported four defects that did not exist — the contract is `applicable === false`.
*Prevention:* when a check tool reports a defect, read the type's own contract
before believing it. The failure output was persuasive and wrong.

## Light theme: /dashboard/scanner stayed black (2026-09-04)

**An opacity modifier makes a different class name, and the whole page fell
through the theme layer because of it.**
The light-theme compatibility layer neutralises hardcoded dark fills with exact
utility selectors — `.bg-\[\#080d1a\]`. Every panel on /dashboard/scanner and
the Crypto Exposure tabs comes from one shared atom whose fill is
`bg-[#080d1a]/80`, and Tailwind emits that as its own utility. The exact
selector cannot match it, so the entire page stayed dark while the shell around
it went white — and the text ramp inverted on top of it, so headings rendered
near-black on a near-black ground. Two thirds of the dark fills across the
dashboards carry a modifier, so this was never scanner-specific.
*Prevention:* the layer matches `[class*="bg-[#hex]"]`, which covers the plain
fill, every `/alpha` variant and any variant prefix in one selector, and
`dashboard-contrast-check.ts` now asserts that modifier-form fills are covered.

**The guard tool was green on a page that was visibly broken, because it
asserted the wrong thing.**
It checked that the hex was *listed* in the layer, not that the class *as the
markup writes it* is matched. A check that restates the fix instead of the
property is worth nothing.
*Prevention:* assert the observable property — coverage of the class as used.

**A check tool that walks only the route tree cannot see a shared atom.**
It walked `src/app/dashboard`, but this page is drawn almost entirely by
`components/quantum-scan/ui.tsx` and `components/exposure/*`. The dark fills
those introduce were invisible to it.
*Prevention:* the walk now includes every directory whose components render
inside `.qg-dashboard-main`, not just the route files.

**An escape hatch only half the sheet honours is not an escape hatch.**
There are two light layers — an older `.dashboard-theme-scope` one and the
newer `.qg-dashboard-main` one — and only the newer carried
`:not(.qg-force-dark)`. So the deliberately dark QVE stage still had its
`text-white` heading inverted to near-black by the older layer.
*Prevention:* both layers carry the guard on every utility remap, and the check
tool asserts it.

**Not every dark surface is a bug.** The Quantum Visualization Engine grades its
node-card verdict colours for contrast against a FIXED dark `HERO_SURFACE`.
Re-surfacing it would not have lightened the visualisation, it would have broken
the colour model the verdicts are read from. It is marked `qg-force-dark` and
stays dark in both themes — deliberately, not by omission.

## Light theme: the QVE hero, and the WebGL rebuild that froze the tab (2026-09-04)

**A stylesheet cannot reach a value.** The light-theme compatibility layer
re-surfaces the engine's DOM chrome, but an SVG `fill`, an inline gradient, a
canvas `fillStyle` and a Three.js material are VALUES, not styles. Those needed
a value source — `_qve/theme.ts`, a palette resolved from the active theme and
defaulting to dark so /public-scan is untouched by construction.

**The contrast helper had the surface baked in as a constant.**
`readableOnDark` raised a published grade colour until it cleared 4.5:1 against
a fixed `HERO_SURFACE`. On white the correction has to run the other way, so
the surface became a PARAMETER and the walk reads its luminance to decide which
direction is legible. One function still, so nothing drifts.
*Prevention:* `tools/qve-theme-check.ts` asserts every verdict on both grounds.

**Testing the float and rendering the rounded value are different things.**
The walk measured the un-rounded HSL result, then `toHex` rounded each channel
— which cost up to a hundredth of a ratio point and returned #0b815a at 4.49:1
from a function whose entire contract is "this clears 4.5:1". The check tool
caught it on the first run. *Prevention:* measure the candidate that will
actually be painted, never its pre-rounding neighbour.

**Putting a theme in a WebGL boot effect's dependencies froze the tab.**
`PacketEngine` re-initialised its PixiJS Application when the palette changed —
and its teardown destroys the canvas element (`destroy(true, …)`), so the
rebuild ran `Application.init({ canvas })` against a dead node. The tab stopped
responding to script and to navigation; only a fresh tab recovered it. The
screenshot timeouts looked like a busy compositor and were a blocked main
thread.
*Root cause, not symptom:* the texture never needed rebuilding — sprites are
`tint`ed per beam, so the glow canvas is a white ALPHA ramp and theme-neutral.
Only the blend mode changes ('add' on navy, 'normal' on white, because additive
blending has no headroom on a white page), and that is applied to the live
display list. `ParticleField` had the same latent shape and got the same
treatment, which its own header comment had already warned about.
*Prevention:* a theme value never belongs in the dependency array of an effect
that owns a GPU context. Put it in a ref and apply it to the live scene.

**A dark object on a light ground is not a bug.** The globe body stays deep
navy in both themes — it is a physical object in the scene, and inverting it
would erase it. What had to change is everything drawn as EMITTED light: the
additive hex field, bloom, god rays and the white packet head, all damped by a
single `glow` factor, because light cannot be added to white.

## /dashboard: Estate Exposure Workflow, and the KPI it exposed (2026-09-04)

**A renderer can be shared when a MODEL cannot.** The scanner's Exposure
Workflow renders one `ExposureAssessment` — a scan, its phases, the engine
processes those phases spawned. None of that exists at tenant level. The
tempting shortcut was to synthesise an assessment from tenant rows and reuse
`buildWorkflowGraph` unchanged; it would have invented phases and processes that
never executed. The estate got its own projection into the same `WorkflowGraph`
shape instead, and the renderer took a pre-built graph as an alternative source
— four touch points, Local and Dev behaviour untouched.

**Two projections of one tenant must read one row loader.** `/exposure-map` and
`/estate-workflow` sit on the same page. Letting each issue its own query set is
exactly how two panels come to report a different number of assets, so the query
set was extracted to `loadEstateRows` and the check tool asserts NEITHER route
body contains a `safeRows(` of its own.

**Verifying the guard is not the same as verifying the file.** The first pass of
the check tool asserted `safeRows(client, 'asset_relationships')` appeared once
in the whole FILE — and failed, because two unrelated endpoints legitimately
read that table. The property that actually matters is scoped to the two route
bodies. A check that overreaches fails on correct code and teaches nothing.

**The workflow was accurate and the panel above it was not.** With Supabase
returning 402 the tenant has no rows, and the new workflow correctly reports an
empty estate — while the KPI tiles on the same page report "Critical Assets 14"
and "Open Findings 27" against an executive snapshot whose own `hasData` flag is
`false`. The 14 comes from `snap.inventory.quantumVulnerableAssets` in the
canonical Quantum Readiness snapshot. Not introduced here and not in scope, but
it is the same defect class the estate projection was built to avoid, and it is
on the same screen — so it is reported rather than quietly left.

**Stale HMR keeps looking like a real bug.** `ReferenceError: Server is not
defined` pointed at an icon map whose import was demonstrably present, and tsc
was clean. A fresh tab showed nothing. Second time this session: when the
browser contradicts the file AND the typechecker, reload before debugging.

## /dashboard accuracy audit — four real defects (2026-09-04)

Asked "is everything on this page accurate?", the answer was no. Four distinct
defects, three of them pre-existing:

**1. A component count wearing an asset label.** `buildSnapshot` did:

    if (assetsAssessed === 0) { quantumVulnerableAssets = vulnerable }

— substituting CBOM component counts into the ASSET fields whenever the tenant
held no assets. A tenant with ZERO assets published "28 quantum-vulnerable
assets", a number equal to its 28 vulnerable components, and it propagated to
the executive KPI, Business Impact, Threat Intelligence, the migration pipeline,
governance, HNDL and the copilot. Deleted. Zero assets is the correct answer to
"how many assets", and `hasData` already separates it from "measured and clean".
The executive KPI is now UNIT-AWARE instead: with no inventory it reports
"Quantum-Vulnerable Components" under its own label and routes to the CBOM page.

**2. The numbers were real; the read paths disagreed.** The deeper cause of the
whole inconsistency was not fabrication. With the database unreachable the
scanner keeps completed results in an in-memory store, so everything derived
from `buildScannerIntelligence` kept reporting real scan output while anything
reading the database directly showed an empty estate — the migration workflow
said "2 assets · Discovery complete" beside an exposure map drawing nothing.
`loadEstateRows` now falls back to the same store AND returns a `persistence`
flag that reaches the UI as a banner. A degraded read is fine; an undisclosed
one is not.

**3. Finding titles published as cryptography.** "Weak RSA Key Size" is a
scanner finding title that lives in the same `algorithm` column as "RSA-2048",
and it was becoming an algorithm node — an entity that is not a primitive, which
an operator could click. The platform already owned the predicate
(`isCryptographicPrimitive`, written by crypto-agility for this exact reason).
Reusing it took algorithms from 37 to 17, and the 40 rejections are COUNTED and
displayed so a lower total reads as a rejection, not as missing data.

**4. A third number for one table.** The projection counted all 59
`crypto_inventory` rows as CBOM components where the canonical snapshot counted
35, because that table stores findings alongside cryptography. Reusing the
shared `isCryptographicComponent` predicate aligned it exactly.

*The pattern in all four:* the platform already had the correct predicate, the
correct unit and the correct disclosure. Every defect was a place that re-derived
instead of reusing. Before writing a classifier, grep for one.

## /dashboard audit, part 2 — the split closed, two more defects (2026-09-04)

**One store, or the page cannot be consistent.** `buildSnapshot` read assets
from the database only, while the component numbers on the SAME snapshot
arrived through `buildScannerIntelligence`, which is memory-aware. That is how
one snapshot came to report 35 cryptographic components and 0 assets in the same
breath, and why Quantum Readiness said "nothing to assess" beside a migration
workflow reading "2 assets · Discovery complete". The raw reads now fall back to
the same store, and the snapshot carries `persistence` so every surface built on
it can disclose a degraded read. Result: assets, findings and components agree
across the executive KPIs, the migration workflow and the estate workflow.

**A green shield over four open actions.** AI Recommendations built its list
from its OWN direct table reads, got nothing, and rendered an emerald shield
reading "Your posture is stable" — while the canonical engine held four
recommended actions, one CRITICAL. Two fixes, because there were two bugs: the
endpoint now falls back to `snap.recommendedActions` before publishing "nothing
to do", and the empty state no longer makes a claim about posture or paints
itself as a pass.

**One message for two different answers.** The Threat Timeline said "No events
match" whether a filter had excluded everything or the tenant had no events at
all — the second reads as "we looked and it's clean". Now distinguished, and the
no-events case states that it is not an assessment.

**Audited and left alone, with reasons:** Compliance is a disclosed model over
the canonical governance control engine (`modeled: true`, MODELLED badge,
evidence count shown) — a model, not a fabrication. Shared Responsibility counts
59 findings where the registers count 52 because it projects the scanner
INTELLIGENCE finding set, deduped by finding identity; a real definitional
difference, not a double-count, and unifying finding definitions across engines
is a platform-level decision, not a drive-by edit.

*The recurring shape, again:* every defect was a surface deriving its own answer
instead of reading the canonical one. The fix each time was a fallback to the
engine that already knew.

## Estate workflow: asset focus, and a word-boundary false negative (2026-09-04)

**Focus must stop at the focus kind, or it does nothing.** An estate graph is
hub-and-spoke: two assets with fifty findings each are unreadable together. The
naive scope — "keep everything reachable from the focused asset" — pulls the
whole estate straight back in, because RSA-2048 sits on both assets and the
traversal crosses it. `focusScope` therefore stops at any OTHER node of the
focus kind. A shared algorithm still appears under both assets, which is
correct: it is genuinely on both.

**Focus is a VIEW, never a recount.** The reconciliation totals keep describing
the whole estate while the canvas shows a subset, so the footer states that a
focus is active. A filtered graph that silently looks like the whole tenant is
the same defect class as a fabricated one.

**The `\b` trap, for the third time in this codebase.** Reusing the platform's
`isCryptographicPrimitive` to keep scanner finding titles out of algorithm nodes
also rejected `SHA256withRSA` — the most common way an X.509 certificate records
its algorithm. Every token in that pattern is `\b`-anchored, and there is no
word boundary inside "withRSA": `h` and `R` are both word characters, so
`\bRSA\b` cannot see it and `SHA256` fails its trailing boundary for the same
reason. Fixed at source with an unanchored `WITH(RSA|DSA|ECDSA|ED25519)`
alternative, which also corrects crypto-agility's primitive counts.
*Prevention:* when a token can appear CONCATENATED, `\b` is the wrong anchor —
and the only way this surfaced was a check-tool assertion that asserted a shared
algorithm must exist. Write the assertion that would notice.

**A failing assertion is not automatically a failing feature.** The first run
failed on "a shared algorithm appears under both assets" — and the bug was in my
FIXTURE (RSA-2048 was only on one asset), which then exposed the real predicate
bug when corrected to the genuinely shared one. Read what the assertion actually
claims before changing the code it points at.

## Exposure Workflow canvas: it was not too small, it was unbounded (2026-09-04)

Reported as "widen the graph canvas, it overlaps when I drag it down". Two
causes, and the obvious one was the lesser:

**1. Unbounded panning.** React Flow pans without limit unless given
`translateExtent`. One downward drag carried the entire graph out of the frame,
leaving an empty canvas with no way back except Fit — which reads as the map
BREAKING rather than as the map having been moved. The extent is now the
layout's own seeded extent plus a margin larger than any viewport: always
somewhere to pan to, never anywhere to lose the graph in. Derived from the
SEEDED extent rather than live body positions, because the force simulation
moves every tick and a bound that moved with it would feel like the drag was
fighting back.

**2. A magic 560px.** The force layout for ~90 entities spreads over roughly
1900 x 1370 units, so a flat 560px viewport showed a keyhole of it. Height now
scales with the VIEWPORT and with the graph's own size — a two-node lens does
not reserve a screen of emptiness, a dense one gets room.

**A hidden control is not a simplification.** The focus picker rendered only
above one candidate, so on a single-asset estate it vanished entirely and an
operator who had just asked for that filter would hunt for it. It now always
renders and SAYS why it cannot help yet ("One asset in this estate — nothing to
filter between yet"), which is the difference between a considered empty state
and a missing feature.
