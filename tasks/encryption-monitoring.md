# Encryption Monitoring — Refactor, Wire, Synchronize & Enhance

Guideline: `Qguard_Wiki/Observability_Refactor` (same contract as the TLS/PKI suite)
Page: `/dashboard/encryption-monitoring`

## Audit — what the page published on the live tenant

The tenant has **2 assets**, Quantum Readiness **33/100**, PQC adoption **33%**,
**0** generated keys, **0** vault files, **0** QRNG events. The page reported:

| Published | Reality |
|---|---|
| `totalEvents: 564` | ~586 rows summed across `crypto_inventory` + `crypto_exposures` + `pqc_scan_results` + `scanner_alerts` + runtime + evidence + security events. These are STORAGE VIEWS of the same observations — the exact triple-count `scanner/finding-identity.ts` documents. |
| `assetsCovered: 23`, `encryptedAssets: 23` | The tenant has 2 assets. |
| `pqcReady: 396` (`70%`) | The QR Engine says 33%. The page contradicted the platform's own canonical score. |
| `legacyProtocols: 524` | More "legacy protocols" than there are events. |
| `keyRotations: 338` | With `totalKeys: 0`. Rotations of keys that do not exist. |
| `downgradeDetections: 260` | TLS Telemetry measures 0 downgrades from the same evidence. |
| `healthScore: 87` | On an estate the QR Engine scores 33 with 348 "high-risk findings". |

Root cause: `crypto-operations-dashboard.ts` classified rows with
`isEncryptionText()` — a substring test matching
`encrypt|cipher|key|pki|certificate|tls|ssl|aes|rsa|ecdsa|...`, i.e. nearly
every cryptographic row in the tenant. The page was therefore a relabelled copy
of the TLS/PKI pages, computed a second time, with a second set of numbers.

## The real scope of this page

Encryption Monitoring is **data protection**, not transport. The TLS suite owns
protocol / suite / key-agreement / certificate. This page owns what protects
DATA:

* symmetric ciphers (AES, ChaCha20, 3DES, RC4)
* hashes and MACs (SHA-2/3, SHA-1, MD5, HMAC)
* KDFs and password hashing (PBKDF2, Argon2, scrypt, bcrypt)
* key material — `generated_keys`: entropy source, quality, rotation, expiry
* vault / data-at-rest protection — `vault_files`
* at-rest and KMS/HSM policy evidence from agents
  (`cloud-storage-encryption-policy`, `database-crypto-policy`, `cloud-kms-policy`, …)
* application-layer and shadow crypto (`crypto-library`, `package-manifest`,
  `jwt-algorithm`, `config-reference`)
* crypto operations actually observed at runtime (encrypt / decrypt / sign /
  verify / key usage)

## The quantum story here is GROVER, not Shor

This is the single most important correctness rule on this page. Symmetric and
hash primitives are NOT broken by a quantum computer the way RSA/ECC are:

| Primitive | Classical | Post-quantum (Grover/BHT) | Verdict |
|---|---|---|---|
| AES-256 / ChaCha20-Poly1305 | 256-bit | ~128-bit | Safe — CNSA 2.0 approved |
| AES-192 | 192-bit | ~96-bit | Below CNSA 2.0 |
| AES-128 | 128-bit | ~64-bit | Weakened, not broken |
| 3DES / DES / RC4 | already broken | — | Critical, independent of quantum |
| SHA-384 / SHA-512 / SHA3 | — | adequate | Safe — CNSA 2.0 |
| SHA-256 | 128-bit collision | ~128-bit preimage | Adequate; CNSA 2.0 prefers SHA-384+ |
| SHA-1 / MD5 | collision-broken | — | Critical, independent of quantum |

Rendering `AES-256-GCM` as quantum-vulnerable is a documented past defect of
this platform (Harvest Now published it as Critical). This page must never do
it, and must explain WHY the verdict differs from the TLS pages.

## Steps

- [x] `src/lib/encryption/types.ts` — canonical data-protection model
- [x] `src/lib/encryption/strength.ts` — the Grover strength model
- [x] `src/lib/encryption/intelligence.ts` — pure engine on `suite-anatomy`
- [x] `src/api-server/encryption-monitoring.ts` — cache + routes + SSE + paging
- [x] `src/hooks/use-encryption-monitoring.ts`
- [x] Rewrite the page on the shared observability primitives
- [x] Rename `_components/tls-pki` → `_components/observability`, add 5th nav tab
- [x] Retire `crypto-operations-dashboard.ts` + `CryptoOperationsDashboard.tsx`
- [x] Typecheck + build + live-tenant verification

## Result on the same tenant

| Before | After |
|---|---|
| 564 "events" | 9 distinct measurements |
| 23 assets covered (of 2) | 1 of 2 assets, 50% — plus 8 unattributed observations reported separately |
| 70% PQC-ready (QR Engine: 33%) | Quantum readiness 33%, reproduced verbatim |
| 338 key rotations, 0 keys | Key material: "Not measured — no key store connected" |
| 260 downgrade detections | (transport concern — owned by the TLS pages) |
| healthScore 87 | CNSA 2.0: 100% of the 1 primitive whose parameters were recorded |

## Accuracy defects the live-data verification caught (all fixed)

1. **Coverage above 100%.** `assetsWithEvidence` keyed on `assetId || assetName`,
   counting hosts, process names and file paths as assets — 8 "assets" on a
   2-asset estate, hidden by the clamp. Now counts tenant asset ids only, with
   unattributed observations reported as their own figure.
2. **Protocol versions in the algorithm inventory.** The application-evidence
   branch filed anything a library declared, so `TLS-1.2` appeared as an
   application "algorithm" with no strength verdict that could attach to it.
   Protocol names are now declined — they belong to Protocol Analytics.
3. **Six identical "RSA-2048 — Broken" findings.** Findings keyed on the
   observation label, so one library produced a row per location. Unattributed
   observations now collapse onto one finding whose `instances` counts them.
4. **RSA-2048 labelled "Broken".** RSA is sound classically and broken only by
   Shor on a CRQC. Collapsing it into `broken` overstated today's risk AND
   contradicted the transport pages, which correctly say "Quantum Vulnerable".
   Added a distinct `quantum-vulnerable` verdict at severity `high`, matching
   how the TLS suite ranks the same primitive.
5. **A fabricated security figure.** `classicalBits` for RSA was computed as
   `log2(bits) * 12`, printing "132-bit classical" for RSA-2048. That is not a
   real relationship; replaced with the published NIST SP 800-57 Table 2
   equivalences (RSA-2048 = 112).
6. **AES-256-GCM rendered as a finding.** The scanner writes a result row for
   every observation it grades, including SAFE ones. Safe-graded, low-severity
   scanner rows are now excluded from the findings list — they are already in
   the algorithm inventory, and listing them invites exactly the misreading this
   page exists to prevent.

## Non-negotiables

* One observation counted ONCE. `crypto_inventory` is the primary observation
  store; `crypto_exposures` / `pqc_scan_results` / `scanner_alerts` are findings
  merged on `findingIdentityKey`, never summed.
* Estate scores are reproduced from `buildSnapshot`, never recomputed.
* Key material, vault and at-rest figures show empty states when the tenant has
  none — never a derived number standing in for a missing source.
* Grover, not Shor. AES-256 is safe and the page says why.
