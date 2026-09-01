# Qguard Helix — Crypto Discovery & Quantum Exposure Scanner™ enhancement

Spec: `Qguard_Wiki/Agents_Scanner_Engines_Enhancements` (§1-96).
`Scanners/` contains 10 SPECIFICATION documents, not code — reviewed, no engines
to inventory there. The real engines live in `src/lib/scanner/`.

## §3 Architecture map — what already exists

| Concern | Module | Lines | Verdict |
| --- | --- | --- | --- |
| Cipher-suite decomposition | `lib/crypto/suite-anatomy.ts` | 383 | Good. 4-state quantum only. |
| Algorithm vocabulary | `exposure/algorithms.ts` | 700 | Good. No curves/params/standards. |
| Pattern catalogue | `web-scanner/crypto-patterns.ts` | 1470 | 125 LEXICAL rules only. |
| Rule engine (legacy) | `scanner_2/rules/detection-rules.ts` | 1278 | Own shape, not §44. |
| Fingerprints | `scanner_2/fingerprints/index.ts` | 1119 | Reused. |
| OID database | `web-scanner/oid-database.ts` | 614 | Reused, extended. |
| Cert parser / TLS / cipher | `web-scanner/*` | 1756 | Reused. |
| Web engines | `public-scan/engines/*` | 8 | Reused. |
| Exposure engines | `exposure/content/*` | 18 | Built last turn. |

**Duplication found:** algorithm facts are defined in FOUR places
(suite-anatomy, exposure/algorithms, crypto-patterns, oid-database).
§7 forbids exactly this. One knowledge base becomes the source of truth and the
others delegate to it.

## Plan

- [x] A. **Crypto Knowledge Base™** `lib/crypto/knowledge-base/`
      50 algorithms (§7 16-field model) · 14 curves (§8,§10) · 27 libraries (§25) ·
      ~40 api call-shapes (§29) · 23 standards (§41-43,§75,§76) · quantum 7-state (§36-§39)
- [x] B. **Rule Engine** `knowledge-base/rules.ts` — 24 QGH-* ids, `RULE_SET_VERSION` 3.0.0 (§44,§86)
- [x] C. **Ground Truth Engine** (§45-§49) — evidence quality axis, 8 detection layers
- [x] D. **Detector upgrades** — API-semantic source layer (§27-29), RSA (§9),
      ECC (§10), DH (§11), KDF params (§16), randomness (§17), SSH (§31)
- [x] E. **Certificate Intelligence** (§22-24) — pubkey vs sig separated into two findings
- [x] F. **TLS Intelligence** (§18-21) — full suite decomposition, per-component classification
- [x] G. Wired into exposure engines, the scanner dashboard's transport
      disclosure (§19 exposure-locus row), and the agent heartbeat
      (knowledge-base + rule-set version, agent 1.5.2); `/exposure/engines`
      now publishes per-engine versions and `/exposure/capabilities` the
      knowledge-base summary (§85)
- [x] H. **UI** — `components/exposure/ScannerIntelligence.tsx`:
      Scanned Assets (§64, includes not-assessed and failed engines as rows) ·
      How This Was Detected (determination tiles reconcile to the finding count) ·
      Evidence Matrix (§47 per-layer corroboration) ·
      Standards Cited (§76 obligation + applicability) ·
      Platform Reconciliation (counts + destination module) ·
      Scanner Engines (live health, versions, knowledge-base disclosure).
      Mounted on both the Local and Dev panels via `ScannerIntelligenceSection`.
- [x] I. **Test corpus** (§65-68) — `tools/scanner-accuracy-check.ts`,
      143 checks, precision 100% / recall 100% **on this corpus only**
- [x] J. Typecheck clean (no new errors), agent bundle builds dependency-free,
      all four check tools pass, Local + Dev verified in the browser (§91,§92)

### Decisions worth recording

**Two cipher-suite decomposers, deliberately.** `lib/crypto/suite-anatomy.ts`
stays the pure, dependency-free reader that eight dashboards and the offline
check tools already consume; `lib/crypto/tls-intelligence.ts` is the
knowledge-base-backed one that classifies each component on both axes. Giving
suite-anatomy a knowledge-base dependency would have rippled through all eight
consumers for no accuracy gain. The risk of the two drifting is covered by
`checkDecomposerAgreement()` in the accuracy tool, which asserts they agree on
forward secrecy, bulk cipher and static-RSA key transport across seven suites.

### Open item for the user

**Dev connector credentials are process-scoped.** Cloud and cluster connections
live in an in-process store for the API server's lifetime; persisting them needs
an encryption-at-rest design and a migration. The UI states this. Awaiting a
decision on whether to build it.


## Web / Local / Dev subscription gate

**Policy** (`src/lib/subscription-access.ts`, one matrix both sides read):

| Caller | Web | Local | Dev |
|---|---|---|---|
| anonymous | yes | no | no |
| Starter | yes | no | no |
| Basic | yes | yes | no |
| Pro | yes | yes | yes |
| Elite | yes | yes | yes |
| any tier, lapsed subscription | yes | no | no |

Web stays free and anonymous — it is the front door. Local needs BASIC (it reads
the tenant's own code and can persist into their governed inventory). Dev needs
PRO (it executes server-side and holds connector credentials).

- [x] `EXPOSURE_MODE_MIN_TIER` + `resolveExposureModeAccess()` +
      `exposureModeDenialMessage()` — isomorphic, imported by BOTH the panels
      and the API so the two cannot disagree about who may scan.
- [x] **Server enforcement** — `requireMode(mode)` in `src/api-server/exposure.ts`
      on all 15 executing/reading/persisting routes. Verified live: every one
      returns 401 to an anonymous caller while `/capabilities` and `/engines`
      still return 200.
- [x] Fails **CLOSED** on a billing read error (`ENTITLEMENT_UNAVAILABLE`, 503).
      The central gateway fails open because bricking a dashboard on a transient
      Supabase error is worse; here the blast radius is one scan.
- [x] `GET /exposure/entitlement` — the authoritative per-mode answer, valid for
      anonymous callers too, so the page can SHOW the paid modes without
      offering them.
- [x] **UI** — `ModeAccessGate` renders the mode in full (every capability, the
      privacy/read-only assurance, the plans that include it) with the execution
      controls removed. `ModeAccessSkeleton` covers the resolving window so a
      paying customer never sees "upgrade" flash. Three refusal reasons get
      three CTAs: sign in / reactivate / upgrade.
- [x] Tabs carry a padlock but stay **clickable** — the panel behind them is the
      argument for the plan.
- [x] Gate lives in the PANELS, not the pages, so /public-scan and
      /dashboard/scanner cannot drift apart.
- [x] `tools/exposure-access-check.ts` — 59 checks: the full plan×mode matrix,
      every guarded route, the anonymous exemptions, and a sweep that fails if
      any exposure route is left unclassified.


## Agent tier gating + Agent_Installer_Refactor (§2, §3, §15, §41, §61, §62)

**Role policy** (`AGENT_ROLE_MIN_TIER`) — the line is `mutatesTargets`:

| Plan | Collector | Scanner | Patcher | Migration Operator |
|---|---|---|---|---|
| Basic | yes | yes | — | — |
| Pro / Elite | yes | yes | yes | yes |
| lapsed | — | — | — | — |

**Scan modules:** Basic = 12 host modules; Pro/Elite add 22 that reach beyond
the host (cloud planes, k8s, service mesh, HSM). Denied modules are RECORDED on
`metadata.scanTypesDeniedByPlan`, never silently dropped.

- [x] `/api/v1/agent-scanner` + `/api/v1/agent-installer` retiered PRO → BASIC,
      with the per-role split enforced in `api-server/agent-entitlement.ts`
      (a prefix cannot express it — every role enrols through one endpoint)
- [x] **§41** role is server-resolved at enrolment and written AFTER the caller's
      metadata spread; capabilities derived from the role definition; unknown
      role refused rather than defaulted to collector
- [x] Re-checked at package time (a downgrade cannot mint new write installers)
      and on every remediation-job poll (`agentMayWrite`)
- [x] All four points fail CLOSED on a billing read error
- [x] **§2/§3/§61/§62** `agent-environment.ts` — dev/staging/production, HTTPS
      required off-dev, loopback + RFC1918 + ULA refused in production, parsed
      hostname matching (not substring). Enforced at installer generation, at
      API-server config and at agent boot (exit 78). Verified live: the exact
      §2 combination is refused, both valid combinations pass.
- [x] **UI** — `use-agent-entitlement` hook, role picker shows all four with the
      unentitled marked and unselectable, downloads-page plan ribbon,
      `/downloads` and `?tab=agents` retiered to Basic
- [x] **Detection accuracy** — the package classifier's fabrications removed
      (see lessons); 17 application libraries added to the knowledge base
- [x] `tools/agent-access-check.ts` — 110 checks
- [x] `AGENT_ROLES.md`, `AGENT_SECURITY.md`

### Deferred from the spec, with reasons

The guideline is a multi-phase re-architecture (§1–§71). Delivered above:
§2, §3, §11–§15, §37 (partial), §40–§41, §61, §62, §69 (sweep). Not delivered,
each needing infrastructure this change cannot create:

- **§4 mutual TLS / §6 device-bound certificate identity** — needs a CA and an
  issuance/rotation service.
- **§5 one-time enrolment tokens** — the installer still embeds a rotatable
  agent token. Needs an `agent_enrollments` table + migration.
- **§9/§10 code signing + signed release manifest** — needs a signing key in a
  managed secret store and a release pipeline. SHA-256 verification already works.
- **§16–§19 command signing, nonce, replay protection** — typed commands and the
  queue exist; cryptographic signing needs the §4 key material.
- **§20–§26 full approval/pre-check/snapshot/rollback lifecycle** — substantially
  present in the existing remediation pipeline; the four-eyes and emergency
  workflows (§38, §39) are not.
- **§32 Windows Service** — still a Scheduled Task.
- **§46** the 16 proposed tables — existing tables reused, as with the exposure
  persistence decision.

These are real gaps, not oversights. Each is a separate piece of work with its
own migration and key-management design.


## Scanner panel reconciliation

- [x] `lib/scanner/web-scanner/transport-truth.ts` — one `reconcileTransport()`
      returning tri-state `Measured<T>` readings; `false` only ever means
      measured-and-absent
- [x] Three independent forward-secrecy computations replaced with the shared
      reading (Observed Attack Surface, Cryptographic Intelligence,
      Cryptographic Findings) + the published scorer
- [x] TLS 1.3 ⇒ forward secret by construction (protocol fact, not a probe)
- [x] Post-Quantum Readiness nullable end-to-end; renders "Not scored" with the
      reason instead of a fallback number
- [x] Quantum Vulnerability licensed by certificate evidence as well as the
      group probe; scoped reason instead of "Unknown"
- [x] "No TLS handshake completed" replaced at source with what actually failed
- [x] `tools/scanner-panel-consistency-check.ts` — 95 checks: the reported
      state reproduced exactly, all five observation states, the cross-panel
      invariant, and structural assertions that panels read the reconciler
- [x] Verified live against test.openquantumsafe.org: TLS 1.3 / PQ Pass /
      Forward Secrecy Enabled / Quantum Vulnerability Hybrid-protected /
      Readiness 78 "Hybrid ready" — no panel contradicts another


## Local / Dev panel reconciliation + engine liveness

- [x] `lib/scanner/exposure/exposure-truth.ts` — one count model publishing
      BOTH units (components and findings) with the unit named, nullable
      readiness computed over components, severity, and partial-scan disclosure
- [x] Quantum Exposure states "Counting cryptographic components"; the Findings
      table says "findings"; Scanned Assets names its column "Quantum (findings)"
- [x] `unitNote` explains the difference, rendered only when they differ
- [x] `completenessNote` warns when a total came from a partial scan
- [x] `notAssessed` de-duplicated by dimension (was listing one gap twice)
- [x] **orchestrator.ts NUL bytes removed** — git treated the engine-selection
      file as binary; now text, diffable, behaviour verified identical
- [x] `tools/exposure-engine-liveness-check.ts` — 44 checks. Runs the REAL
      orchestrator over a fixture tree with one file per engine:
      13/13 engines ran, all reached terminal states, each detected its own
      planted material. 31 findings, 11 components, readiness 36%.


## /public-scan panel consistency

- [x] Audited all 14 panels. Architecture already correct: `assess.ts` builds
      the control set once and every panel projects it — verified, not assumed
- [x] **Fixed:** `Not observed` vs `Not measured` conflation in
      `CryptoIntelligence.forwardSecrecy` (a never-answered endpoint was
      reported as lacking forward secrecy while the control said "Unknown");
      fourth state added, colour split rose/slate
- [x] `tools/public-scan-consistency-check.ts` — 103 checks over four
      observation states (TLS 1.3 hybrid / TLS 1.3 classical / TLS 1.2 static
      RSA / no handshake): panels project one control array, the intelligence
      panel restates controls faithfully, TLS 1.3 needs no probe, the composite
      equals its weighted parts, nothing unprobed is scored as a failure, and
      panels check `applicable` / `measured` before publishing a number
- [x] Verified live against cloudflare.com: TLS 1.3 + legacy → Forward Secrecy
      Partial (static RSA accepted) → Key Exchange Hybrid PQ → PQ Agreement Pass
      → Quantum Vulnerability Hybrid-protected. Every panel agrees, and OCSP
      Stapling reads "Not applicable" rather than 0.
