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
