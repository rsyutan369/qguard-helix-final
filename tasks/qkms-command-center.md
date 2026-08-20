# QKMS Command Center — Refactor & Integration Plan

Brief: `Qguard_Wiki/QKMS_Enhancement_Refactor`
Pages: `/dashboard/qkms/{overview,inventory,lifecycle,governance,rotation,readiness,risk-analysis}`

---

## 1. Audit findings (what is actually broken today)

Read of `src/api-server/qkms-dashboard.ts` (1603 lines) and
`src/app/dashboard/_components/QkmsDashboard.tsx` (2077 lines).

| # | Defect | Evidence | Brief section violated |
|---|--------|----------|------------------------|
| D1 | **Two rival risk models.** Backend publishes `riskScore = 100 - trustScore + …`; the frontend recomputes a 7-factor weighted score in `keyRiskFactors()`. Inventory shows one number, Risk Analysis another **for the same key**. | `qkms-dashboard.ts:560` vs `QkmsDashboard.tsx:1403` | 3, 16, 17 |
| D2 | **ML-DSA / SLH-DSA keys are classified WEAK.** `isWeakAlgorithm()` substring-matches `dsa`, which hits `ML-DSA-65` and `SLH-DSA`. Every PQC signature key is then also `rotationRequired`, counted in `weakAlgorithms`, and blocks the migration gate. | `qkms-dashboard.ts:172` | 2, 14, 16 |
| D3 | **Classification runs over a JSON blob**, not over the algorithm. `sourceText` concatenates name + backend + purpose + environment + `JSON.stringify(metadata)`, so any key whose metadata mentions `aes-cbc` or `rc4` is deprecated. | `qkms-dashboard.ts:520` | 2, 19 |
| D4 | **Unit-mixing counts.** `weakAlgorithms = (weak keys) + (matching finding rows)`; `findings = keyTextRows.length + keyPostureFindings`. Overview reports a number that no table can reconcile. | `qkms-dashboard.ts:747` | 2, 17 |
| D5 | **`policyViolations` is a regex over arbitrary JSON** of exposures/alerts/security-events/vulns, not an evaluation of keys against policies. Not drillable, not a governance violation. | `qkms-dashboard.ts:748` | 12, 17 |
| D6 | **Certificates marked weak when `is_expiring_soon`.** Expiry is not algorithm weakness. | `qkms-dashboard.ts:~735` | 2, 16 |
| D7 | **SSE is an 8-second poller** that rebuilds 26 tenant queries per client per tick; the page opens **4** EventSource connections and passes the bearer token in the query string. No change detection, no backoff, no de-dup. | `qkms-dashboard.ts:1560`, `QkmsDashboard.tsx:466` | 6, 25 |
| D8 | **No caching / no single-flight.** Every request re-runs 26 queries; N open pages = N× cost and pages can disagree inside one tick. | `buildQkmsSnapshot` | 25 |
| D9 | **No server-side filter/sort/pagination.** Whole inventory (capped at 260, silently truncated) ships to the browser and is filtered client-side. | `qkms-dashboard.ts:1140` | 9, 25 |
| D10 | **Migration gate has 3 states** (`allow/warn/block`), not the 6 the brief specifies, and carries no *why / evidence / blocker / action*. | `qkms-dashboard.ts:1035` | 15 |
| D11 | **Fake functionality.** `POST /export` returns a file body but the client throws it away and shows a toast; PDF returns `queued` and nothing is produced. The 9-step rotation "workflow" and `Start Dry Run` call `/precheck`, which ignores `keyId`. | `QkmsDashboard.tsx:1207`, `1770` | 13, 24 |
| D12 | **Lifecycle state derived twice** — backend `rotationStatus`, frontend `lifecycleState()` — so Lifecycle and Rotation can label the same key differently. | `QkmsDashboard.tsx:1335` | 3, 17 |
| D13 | **No key version identity**, no evidence identity (`scanId`/`telemetryId`/`findingId`), no drill-down from any metric. | — | 3, 8, 10, 19 |
| D14 | **Absence reads as good news.** A key with no rotation policy, no last-rotated date and no expiry is rendered `Healthy`. | `rotationStatusFor()` | 2, 26 |
| D15 | `qkms_rotation_jobs.key_id` is `UUID`, but canonical key ids are prefixed strings. Jobs are matched to keys by string-stripping, so a job can attach to the wrong key or to none. | schema + `cleanKeyId()` | 3 |

---

## 2. Target architecture

```
scanner / agents / runtime telemetry / certificates / generated keys / qkms_* tables
      │
      ▼  (26 tenant-scoped queries, bounded, single-flight, 15s TTL)
src/api-server/qkms-dashboard.ts        ← queries + cache + routes + SSE + governed actions
      │
      ▼  pure, isomorphic, no I/O
src/lib/qkms/                           ← THE single source of truth
   types.ts          canonical model + vocabularies
   classify.ts       key classification on top of lib/crypto/suite-anatomy
   lifecycle.ts      one lifecycle + rotation state machine
   governance.ts     policy evaluation → violations, custody, entropy
   risk.ts           ONE explainable weighted risk model
   readiness.ts      PQC readiness + 6-state migration gate
   intelligence.ts   buildQkmsIntelligence(inputs) → QkmsIntelligence
      │
      ▼  projectView(model, mode)     ← seven projections of ONE model
src/hooks/use-qkms.ts                   ← one hook, header-auth SSE, backoff, realtime nudge
      │
      ▼
src/app/dashboard/_components/qkms/*.tsx  ← seven page bodies on the shared design system
```

Rule: **the seven pages are projections, never re-derivations.** No page recomputes a
score, a state or a count the model already publishes.

---

## 3. Work breakdown

### Backend / model
- [x] B1 `src/lib/qkms/types.ts` — canonical model, identity rules, vocabularies.
- [x] B2 `src/lib/qkms/classify.ts` — classification via `analyzeCryptoObservation` (fixes D2, D3, D6); `namesKeyMaterial()` replaces the loose `isKeyText`.
- [x] B3 `src/lib/qkms/lifecycle.ts` — one lifecycle + rotation state machine, honest `unknown` (fixes D12, D14).
- [x] B4 `src/lib/qkms/governance.ts` — policy → violation evaluation, custody classification, entropy posture (fixes D5).
- [x] B5 `src/lib/qkms/risk.ts` — one weighted, explainable model consuming violations (fixes D1).
- [x] B6 `src/lib/qkms/readiness.ts` — readiness by family + 6-state gate with why/evidence/blockers/actions (fixes D10).
- [x] B7 `src/lib/qkms/intelligence.ts` — assembler: identity, dedupe, cross-links, counts by unit (fixes D4, D13).
- [x] B8 Rewrite `src/api-server/qkms-dashboard.ts`: 15s single-flight cache, `projectView`, server-side filter/sort/paginate, change-detected SSE, header auth (fixes D7, D8, D9).
- [x] B9 Governed write actions with real state machine + audit: rotation work orders (request/approve/execute/validate/complete/fail), revoke, assign owner, decommission, policy CRUD. Capability flags so no control is offered that the backend cannot honour (fixes D11).
- [x] B10 `supabase/qkms-command-center-schema.sql` — additive, idempotent: `key_ref TEXT` on jobs/audit (fixes D15), `qkms_key_versions`, version + state columns, validation columns.

### Frontend
- [x] F1 `src/hooks/use-qkms.ts` — one hook + named wrappers + detail + actions.
- [x] F2 `src/app/dashboard/_components/qkms/shell.tsx` — shared shell, nav, states, key vocabulary badges (on `observability/primitives`).
- [x] F3 Overview — executive + operational, every KPI drills down.
- [x] F4 Inventory — server-side search/filter/sort/paginate + full key inspection drawer.
- [x] F5 Lifecycle — state machine funnel, age/expiry buckets, attention lists.
- [x] F6 Governance — policies, violations, custody, entropy, audit.
- [x] F7 Rotation — health, queue, work-order state machine, validation, evidence.
- [x] F8 Readiness — family readiness, migration gate with explanation.
- [x] F9 Risk Analysis — distribution, factor decomposition, explainable drawer, remediation queue.
- [x] F10 Real exports through `services/reporting` (PDF/XLSX/DOCX/HTML/CSV/JSON) with a reconciliation table (fixes D11).
- [x] F11 Page wrappers re-pointed; delete `QkmsDashboard.tsx`.

### Verification
- [x] V1 `npx tsc --noEmit` clean.
- [x] V2 Cross-page tally check tool: same key ⇒ same id, risk, lifecycle, rotation, posture on all seven projections.
- [x] V3 Build succeeds.

---

## 4. Invariants the implementation must hold

1. One key = one `keyId` across all seven projections.
2. `riskScore` is computed once, in `lib/qkms/risk.ts`, and is never recomputed in the UI.
3. `lifecycleState` / `rotationState` are computed once, in `lib/qkms/lifecycle.ts`.
4. A count never sums two different units. Keys are counted in keys; violations in violations; findings in findings.
5. Absence of evidence is `unknown`, never `healthy` and never `0`.
6. Every published finding carries `evidence[]` with table + record id + observed-at.
7. No control is rendered unless the corresponding capability flag is true.
8. Tenant scope is enforced in every query and every write; ids from the client are re-resolved against the tenant model before use.

---

## 5. Defects the check tools found DURING the rebuild

The two check suites (`tools/qkms-check.ts` offline, plus a live cross-page run
against the tenant API) caught eight further defects that code review had not.
Five were in the new engine; three were only visible against real tenant data.

| # | Defect | Found by | Fix |
|---|--------|----------|-----|
| D16 | A bare `DSA` / `DH` / `ElGamal` resolved to "unknown posture" instead of quantum-vulnerable — the shared decomposer declines them, and the first fix for it was placed after an early return, so it never ran. | offline check | `classicalFallthrough()` in `classify.ts`, gated on the decomposer having already declined the string, with anchored patterns (a `` boundary sits inside `ML-DSA`). |
| D17 | A scan row's `created_at` is when the SCANNER saw the key, not when the key was created. Mapping it to `createdAt` gave every freshly-discovered key an age and a lifecycle of "active". | offline check | Discovery rows take `createdAt` only from a creation date the scanner actually captured. |
| D18 | `never-rotated` fired on keys days old that had simply not reached their first rotation, burying genuinely neglected keys. | offline check | Scoped to `ageDays >= NEVER_ROTATED_AFTER_DAYS` (180); younger keys read `healthy` with a reason that states no rotation has occurred yet. |
| D19 | **`ECDSA P-256` published as DEPRECATED** — `rsaInadequate()` compared a 256-bit EC key size against an RSA modulus threshold. On the live estate this marked six certificate keys "broken against classical attack" and BLOCKED the migration gate with a false reason. | live data | `rsaInadequate()` gated on the family actually being RSA. 256 bits of ECC ≈ 3072 of RSA; the scales are not comparable. |
| D20 | **`crypto_inventory` is the CBOM, not a key registry.** Treating its rows as keys turned 72 scan observations into a 15-key inventory containing "Detection Rule CERT-002", "TLS Handshake — https://…" and five separate "keys" for one certificate. | live data | `namesKeyMaterial()` now requires a key-bearing `item_type` or a fingerprint. Estate corrected 15 → 3 real certificate keys. |
| D21 | Unrecognised backend strings were echoed back as storage backends, filling the custody chart with finding titles. | live data | `classifyCustody()` keeps a declared string only when it looks like a storage location; otherwise custody is honestly `Unknown`. |
| D22 | Certificate-derived identity used the subject label, so two different certificates on one host could collapse into one key (or fail to merge) on incidental label differences. | review of live data | Certificate keys anchor on the certificate SERIAL (`key:crt:`), so they are exactly as distinct as the certificates they come from. |
| D23 | Hybrid-adoption readiness reported "no asymmetric keys were discovered" on an estate of three certificate keys, contradicting the signature band directly above it. | browser | The `certificate` key class is asymmetric and now counts toward hybrid adoption. |
| D24 | `relativeTime()` renders every FUTURE timestamp as "just now", so a rotation due in eleven months read as urgent. | browser | QKMS-local `whenRelative()` handles both directions; the shared primitive is untouched for the four suites that only render observations. |

## 6. Verification results

| Gate | Result |
|------|--------|
| `npx tsc --noEmit` | No QKMS errors. Files with errors match the pre-existing baseline exactly. |
| `npm run build` | Succeeds. |
| `tools/qkms-check.ts` (100 offline invariants, 15 groups) | ALL PASSED |
| Live cross-page check (7 projections + drill-downs, real tenant) | ALL PASSED |
| Browser walkthrough, all seven pages | Render correctly, no console errors |

Live estate at time of verification: **3 keys · 6 violations · gate BLOCKED · average risk 60**,
every page reporting byte-identical metrics, gate state and nav badges.

The live check proves the cross-page contract directly: seven concurrent
projections share one `generatedAt`, no key disagrees on any of ten fields
across the pages that show it, and `/keys`, `/violations` and `/rotation-jobs`
totals reconcile exactly with the headline metrics.
