# Intelligent Quantum Remediation Engine™ (Q-REMEDY)

Transforms the Quantum Readiness module from a reporting dashboard into an
intelligent remediation platform: instead of "Not Quantum Ready", the platform
shows **"Here's exactly how to become Quantum Ready"** — per-asset remediation
actions, a live Certification Readiness Score™, and the projected score after
each recommendation, all the way to Quantum Trust Certification™ eligibility.

Spec: `Qguard_Wiki/Intelligent_Quantum_Remediation&Certification_Engine`.

---

## Where it lives

| Piece | Path |
| --- | --- |
| Dashboard page | `/dashboard/quantum-readiness/remediation` (`src/app/dashboard/quantum-readiness/remediation/page.tsx`) |
| API | `GET /api/v1/quantum-remediation` + `GET /api/v1/quantum-remediation/stream` (SSE) |
| Engine + router | `src/api-server/quantum-remediation.ts` |
| Contract types | `src/types/quantum-remediation.ts` |
| Frontend hook | `src/hooks/use-quantum-remediation.ts` (fetch + header-auth SSE + evidence realtime) |
| Offline checks | `npx tsx tools/remediation-check.ts` (no server needed) |
| Live checks | `npx tsx tools/remediation-live-check.ts` (running server + Basic+ account) |

Navigation: QR subnav (`QR_PAGES` in `_shared.tsx`), sidebar (Quantum Readiness
Assessment Engine section), QR hub module card, and a CTA banner on the
Certification page whenever the tenant is not yet eligible.

Access tier: **Basic+** (frontend `/dashboard/quantum-readiness` prefix rule;
backend `API_MIN_TIER` entry in `subscription-guard.ts`).

## Reuse map (no duplicated services)

The engine composes existing platform sources — it owns no new tables:

- `buildSnapshot` (quantum-readiness.ts) — scores, inventory, severity distribution.
- `buildScannerIntelligence` (scanner.ts) — per-asset vulnerability payloads.
- `gatherEvidence` / `evaluateEligibility` / `loadPolicy` (quantum-certification.ts,
  now exported) — the SAME 10 required criteria the certification engine enforces.
- `buildReportModel` confidence / residual risk / validation (via gatherEvidence).
- `assets`, `asset_relationships` (blast radius), `certificates` (expired),
  `migration_jobs` (in-progress status + recently-fixed) — read-only.

## The Q-REMEDY algorithm

1. **Normalize** — every discovered asset's measured vulnerabilities (scanner
   findings, CBOM components, expired certificates) grouped per asset per domain.
2. **Classify** — remediation domain (TLS / SSH / VPN / PKI / key-management /
   application / cloud / data-at-rest / identity / vendor / evidence-coverage)
   → a NIST-aligned playbook: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205
   (SLH-DSA), CNSA 2.0, RFC 8784 (PQ PSK for IKEv2), TLS 1.3, CISA/NCSC
   migration guidance. Each playbook carries steps, current→target state,
   effort/downtime model, rollback, breaking-change warnings, automation flag,
   and a deep link into the executing module (Migration Planner, CBOM, PKI
   Visibility, QKMS, Harvest Now, Vendor Readiness, Sandbox…).
3. **Prioritize** — composite 0–100 score, weights documented in the payload:
   severity 20%, certification impact 16%, business criticality 14%, internet
   exposure 12%, HNDL relevance 12%, data sensitivity 10%, blast radius 8%,
   compliance hits 8% → Critical/High/Medium/Low queues + quick wins
   (gain-per-effort leverage).
4. **Score** — Certification Readiness Score™ = Σ (criterion progress × 10%)
   over the 10 required certification criteria. Threshold criteria progress
   linearly toward their limits; zero-tolerance criteria (critical findings,
   vulnerable components, disallowed algorithms, expired certs) progress
   relative to the measured baseline; report validation is binary.
   **100% ⇔ certification eligible** — the score can never disagree with the
   certification engine because both read the same criteria.
5. **Simulate** — marginal-gain greedy ordering: each remaining action is
   re-simulated against the evolving measures (`applyImpact` re-blends the QR
   score model with the action's measured deltas; unattributed residuals are
   held at baseline) and the best gain-per-effort is picked next. Output is the
   Readiness Projection Ladder™: `Current → After #1 → … → Certification
   Eligible` (or an honestly-labelled "Projected Maximum" when remaining
   criteria need new evidence to close).

### Evidence honesty

- No fabricated findings: every action originates from real scanner/CBOM/
  certificate/graph evidence; an empty estate produces zero actions and a
  scanner CTA.
- Action status is **derived**, never asserted: a finding present in the latest
  scan = open; a running `migration_jobs` row on the asset = in progress; the
  live score only moves when a rescan verifies the change.
- Projections are labelled simulations and the full methodology (formula,
  factor weights, simulation model) ships in every payload and renders on-page.
- "Recently fixed" comes exclusively from completed `migration_jobs` rows.

## Page sections

Hero (score ring + eligibility + estimated certification date + queue chips) ·
Readiness Projection Ladder™ · Certification Requirements (unmet cards with
description, business impact, technical impact, solution, related assets, ETA,
score increase, deep link) · Asset-Level Remediation Queue (priority tabs +
expandable per-action detail: why-not-ready evidence, steps, current→target,
standards, downtime, rollback, breaking changes, blast radius incl. dependents
/ dependencies / third parties, priority factor breakdown, sandbox link) ·
Critical Blockers · Remediation Progress (completion %, recently fixed,
upcoming) · Assets by Risk (+ vendor / replacement flags) · Readiness Trend ·
AI Quantum Advisor™ (the spec's 9 questions answered deterministically from
the plan) · Methodology & Evidence Honesty.

## Certification workflow (end-to-end)

Scan → Discover → CBOM → QR Assessment → **Q-REMEDY roadmap** → execute via
Migration Planner/Sandbox → rescan → score recomputes automatically (SSE +
realtime) → all 10 criteria pass → Certification page unlocks issuance →
ML-DSA-65-signed Quantum Trust Certificate™ → continuous monitoring keeps
validating (drift auto-suspends — see `docs/QUANTUM_TRUST_CERTIFICATION.md`).

## Verification (2026-07-16)

- `npx tsx tools/remediation-check.ts` — 46/46 offline checks pass (domain
  classification, FIPS terminology guard, score bounds/monotonicity, impact
  floors, ladder monotonicity, queue partition, honesty invariants).
- `npx tsx tools/remediation-live-check.ts` — live against the real tenant:
  401 unauth, 200 authed, 44.9% live score, monotone ladder 44.9→97.2%,
  9 advisor answers, SSE frame received. Subscription gateway verified
  (Starter → 403, Basic → 200).
- `tsc --noEmit` clean; `vite build` clean.

Note: plan assembly is heavy (~5s on the reference tenant — snapshot + scanner
intelligence + report model + greedy simulation); the SSE stream re-emits every
30s. Restart the dev server after pulling these changes so Vite mounts the new
Express route.
