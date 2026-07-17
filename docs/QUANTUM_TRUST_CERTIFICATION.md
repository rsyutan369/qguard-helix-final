# Quantum Trust Certification Engine™

Enterprise Post-Quantum Readiness certification for QGuard Helix. Issues signed,
publicly verifiable digital certificates **only** when an organization's measured
cryptographic posture meets every published eligibility criterion — certification
is *computed from evidence, never asserted*, and continuously re-validated.

Module route: `/dashboard/quantum-certification` (under the Quantum Readiness
Assessment Engine™). Access tiers: **Basic, Pro, Elite**. Public verification
portal: `/verify-certificate` (no authentication).

---

## 1. Architecture

```
Quantum Readiness snapshot ──► Eligibility Rules Engine ──► Certificate Generator
 (buildSnapshot, real evidence)   (configurable policy +      (canonical payload →
        │                          platform floors)            SHA3-256 hash →
        ▼                              │                        ML-DSA-65 signature →
 Enterprise report model               ▼                        QR verification URL)
 (buildReportModel: confidence,   Trust Score /1000 +                │
  residual risk, validation)      Bronze→Diamond level               ▼
        │                              │                    certificates + signatures
        └──────────────┬───────────────┘                    + assets + algorithms
                       ▼                                            │
              Continuous Monitoring ◄───────────────────────────────┘
        (every dashboard load / SSE tick re-validates the active
         certificate; drift → auto-suspend + notify)
                       │
                       ▼
          Public Verification Portal (service role, rate-limited)
          recomputes SHA3-256 + verifies ML-DSA-65 signature live
```

**Reuse, no duplication.** The engine consumes existing platform capabilities:

| Capability | Source |
|---|---|
| Cryptographic evidence & scoring | `buildSnapshot` (`src/api-server/quantum-readiness.ts`) |
| Confidence, residual risk, self-validation, business risks | `buildReportModel` (`src/services/reporting/ReportEvidence.ts`) |
| QR matrix rendering | `qrMatrix` (`src/services/reporting/ReportQr.ts`) |
| Digital signatures | `ml_dsa65` (`@noble/post-quantum`, the same primitive the Quantum Vault uses) |
| Integrity hash | `sha3_256` (`@noble/hashes`) |
| Auth / RBAC / tenant isolation | Supabase JWT + RLS + `subscription-guard` |
| PDF generation | `pdf-lib` |

### Files

| Layer | Path |
|---|---|
| Database schema | `supabase/quantum-certification-schema.sql` |
| Shared types | `src/types/quantum-certification.ts` |
| Engine + API + public verify | `src/api-server/quantum-certification.ts` |
| React hook | `src/hooks/use-quantum-certification.ts` |
| Certificate artwork (SVG) | `src/components/certification/QuantumTrustCertificate.tsx` |
| Export (SVG/PNG/PDF/JSON/audit) | `src/services/certification/certificate-export.ts` |
| Dashboard page | `src/app/dashboard/quantum-certification/page.tsx` |
| Public portal page | `src/pages/VerifyCertificate.tsx` |
| Offline verification | `tools/certification-check.ts` |

---

## 2. Database

Run once in the Supabase SQL Editor (after `billing-subscription-schema.sql`):

```
supabase/quantum-certification-schema.sql
```

> **Naming:** the issued-certificate table is **`quantum_trust_certificates`**,
> NOT `certificates`. The platform already ships a `certificates` table that is
> the X.509 / TLS certificate **inventory** (columns `not_before`/`not_after`/…).
> The engine reads that inventory read-only for the "expired certificates"
> criterion (`INVENTORY_CERT_TABLE`) and writes issued certificates to its own
> `quantum_trust_certificates` table (`CERT_TABLE`) — the two never collide.

Tables (all tenant-scoped by `user_id`, owner-only RLS):

- `quantum_trust_certificates` — issued certificates (status, level, trust score,
  canonical `payload`, `certificate_hash`, verification URL, issue/expiry).
- `certificate_assets` — validated assets covered by each certificate.
- `certificate_algorithms` — verified cryptographic stack at issuance.
- `certificate_signatures` — ML-DSA-65 signature, issuer public key, chain.
- `certificate_history` — lifecycle events (issued/renewed/revoked/…).
- `certificate_downloads` — export audit trail.
- `certificate_validation` — every eligibility / re-validation run.
- `certificate_policies` — per-tenant configurable thresholds (bounded by floors).
- `certificate_audit` — append-only action log.
- `certificate_verification_logs` — public portal lookups (service-role only).
- `certificate_notifications` — expiry / suspension / renewal notices.

Two platform tables have **RLS enabled with no policies** — only the service role
can read them: `certificate_signing_keys` (the issuer seed) and
`certificate_verification_logs`.

Realtime is enabled for `certificates`, `certificate_history`,
`certificate_notifications` so the dashboard updates live.

---

## 3. API

Tenant endpoints (require auth + Basic tier), mounted at
`/api/v1/quantum-certification`:

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Certification dashboard (eligibility, certificate, history, advisor). |
| GET | `/stream` | SSE dashboard stream (header-authenticated; re-validates every 20s). |
| POST | `/issue` | Issue a certificate (`{ organization, organizationLogo? }`). 422 if not eligible. |
| POST | `/:id/renew` | Re-issue from current evidence, superseding the old certificate. |
| POST | `/:id/suspend` | Suspend (`{ reason }`). |
| POST | `/:id/revoke` | Revoke (`{ reason }`). |
| POST | `/:id/reinstate` | Reinstate a suspended cert — only if evidence passes again. |
| POST | `/:id/download-event` | Record an export (`{ format }`). |
| GET | `/:id/package` | Machine-readable certificate + audit package (JSON). |

Public endpoints (no auth, rate-limited 30/min/IP), mounted at
`/api/v1/certificate-verification`:

| Method | Path | Purpose |
|---|---|---|
| GET | `/:certificateId` | Verify a certificate — live SHA3-256 + ML-DSA-65 check. |
| GET | `/lookup?company=` | Search certificates by organization name. |

Realtime events (via Supabase realtime + SSE): `CertificateIssued`,
`CertificateRenewed`, `CertificateRevoked`, `CertificateSuspended`,
`CertificateExpired`, `CertificateValidated`, `CertificateDownloaded`
(represented as `certificate_history.event` rows the dashboard subscribes to).

---

## 4. Certification Workflow

```
Discovery Scan → Quantum Readiness Assessment → HNDL Assessment →
Cryptographic Inventory → CBOM → Migration Recommendations →
Customer Implements Changes → Re-scan → Validation Engine →
Policy Validation → Eligibility Engine → Certificate Generator →
Digital Signature → QR Code → Public Verification → Continuous Monitoring →
Renewal Engine
```

### Eligibility criteria (default policy)

Required (all must pass): Overall Readiness ≥ 90, Critical Quantum
Vulnerabilities = 0, HNDL Exposure ≤ 25, Residual Risk ≤ 25 (Low), Assessment
Confidence ≥ 95, PQC Adoption ≥ 85, **no** disallowed algorithms (RSA, ECC,
ECDSA, SHA-1, 3DES, TLS 1.0/1.1, …), Vulnerable Components = 0, Expired
Certificates = 0, Report Self-Validation = PASS. Advisory: Crypto Agility active.

Policies are per-tenant configurable via `certificate_policies.rules`, but the
engine enforces **platform floors** (`POLICY_FLOORS`): a tenant can *tighten* a
threshold, never loosen it below the published minimum. This prevents
self-certification by policy edit.

### Certification levels (weighted Quantum Trust Score™, 0–1000)

| Level | Meaning | Gate |
|---|---|---|
| Bronze | Initial Readiness | eligible |
| Silver | Hybrid PQC Implemented | ≥ 700 + hybrid evidence |
| Gold | Enterprise Quantum Secure | ≥ 800 + hybrid |
| Platinum | Advanced Quantum Trust | ≥ 900 + hybrid |
| Diamond | Continuous Quantum Trust Certified | ≥ 950 + hybrid + ≥ 3 assessments |

Score weighting: readiness 30%, PQC adoption 20%, inverse quantum risk 15%,
inverse HNDL 15%, evidence confidence 10%, validation + crypto agility 10%.

---

## 5. Certificate Lifecycle & Renewal

- **Issue** — only when eligible. Builds the canonical payload, hashes it
  (SHA3-256), signs it (ML-DSA-65), persists certificate + signature + assets +
  algorithms, writes history + audit, returns the certificate.
- **Continuous monitoring** — on every dashboard load / SSE tick the active
  certificate is re-validated against live evidence. New quantum vulnerabilities
  (drift) → **auto-suspend + notify + require reassessment**. Lazy expiry marks
  past-due certificates `expired`.
- **Renewal** — re-runs eligibility from current evidence and issues a new
  certificate, marking the previous one `superseded`. Auto-renewal is offered
  when the estate still passes; otherwise renewal is refused with remediation.
- **Suspend / Revoke / Reinstate** — owner actions; reinstatement requires the
  estate to currently pass all criteria (no silent un-suspend).
- **Expiration notifications** — a one-time "expiring soon" notice within 30 days.

---

## 6. Security Model

- **Evidence-gated issuance** — a certificate is impossible to obtain without
  measured, passing evidence. No manual override path grants certification.
- **Cryptographic integrity** — canonical (sorted-key) JSON → SHA3-256 hash →
  ML-DSA-65 (FIPS 204) signature. The public portal recomputes the hash and
  verifies the signature *live* on every lookup, so tampering with any stored
  field is structurally detectable (not a status flag).
- **Signing key isolation** — the issuer seed lives in `certificate_signing_keys`
  (RLS, no policies → service role only). It is never exposed to clients.
- **Tenant isolation** — RLS on every tenant table; the engine writes with the
  caller's JWT client so RLS is the enforcement point.
- **RBAC / tiering** — `subscription-guard` gates the tenant API at Basic; the
  frontend gates the route via `subscription-access`.
- **Transport auth** — the SSE stream is header-authenticated (token never in the
  URL). No query-string token fallback on JSON/SSE endpoints.
- **Public portal hardening** — no auth by design, but rate-limited (30/min/IP),
  service-role reads of non-sensitive fields only, parameterized `ilike` search,
  and every lookup logged. Logos are bounded data-URLs (no external fetch/SSRF).
- **OWASP** — input validation (org/logo/format), output encoding (SVG/JSON),
  no SQL injection (Supabase parameterized queries), audit logging on every
  action, signed/verifiable downloads.

---

## 7. Downloads & Report Integration

Exports (from the dashboard, recorded in `certificate_downloads`): **Enterprise
PDF**, **PNG**, **SVG**, **JSON** (machine-readable), **Audit Package** (JSON
including the canonical payload, lifecycle and validation history + verification
instructions). All derive losslessly from the self-contained certificate SVG.

The enterprise report already carries a certification block — the **Executive
Certification Summary** (`buildCertificationSummary`) — with certification status,
the published criteria (eligibility), milestones and the attestation, so every
assessment report reflects certification state without duplicating the engine.

---

## 8. Guides

### Customer Guide
1. Run a PQC discovery scan and complete the Quantum Readiness Assessment.
2. Remediate findings using the AI Migration Advisor™ and Harvest Now guidance.
3. Re-scan. Open **Quantum Trust Certification™** and review the eligibility
   checklist — each unmet criterion shows exactly what to fix.
4. When all required criteria pass, enter your organization name (and optional
   logo) and **Issue Quantum Trust Certificate**.
5. Download the PDF/PNG/SVG, or share the verification URL / QR code. Anyone can
   verify it at `/verify-certificate`.

### Administrator Guide
- Apply `supabase/quantum-certification-schema.sql` once. The issuer ML-DSA-65
  keypair is generated and persisted automatically on first use.
- Set `CERT_VERIFICATION_ORIGIN` (e.g. `https://verify.qguardhelix.com`) so QR
  codes and verification URLs point to production.
- Tenant policies live in `certificate_policies.rules`; platform floors are
  enforced in code (`POLICY_FLOORS`).

### Developer Guide
- Offline verification: `npx tsx tools/certification-check.ts` (eligibility
  gating, trust-score/level engine, SHA3-256 determinism, ML-DSA-65
  sign/verify + tamper detection — no server required).
- The engine's pure functions (`evaluateEligibility`, `computeTrustScore`,
  `levelForScore`, `hashCanonical`, `testSignPayload`/`testVerifyPayload`) are
  exported for testing.
- Env: `CERT_VERIFICATION_ORIGIN` / `VITE_CERT_VERIFICATION_ORIGIN`.

---

## 9. Verification status

- `tsc --noEmit`: clean.
- `vite build`: clean.
- `tools/certification-check.ts`: all checks pass.
- Live (dev server): Starter → 403; Basic → 200 dashboard; issuance refused for a
  non-remediated tenant (evidence-gated); public verify returns graceful
  `found:false` for unknown IDs; SSE stream connected.
- **Pending:** the user must run `supabase/quantum-certification-schema.sql` in
  the Supabase SQL Editor to enable issuance, signing and public verification of
  real certificates. Until then the dashboard shows a setup banner and computes
  eligibility live from assessment evidence.
```
