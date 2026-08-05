---
name: qguard-pqc-detection
description: Post-quantum cryptography detection and classification in QGuard Helix — ML-KEM, ML-DSA, SLH-DSA, hybrid TLS and hybrid certificates, and the classical/hybrid/post-quantum verdict model. Use when working on PQC detection, quantum readiness scoring, HNDL exposure, algorithm classification, or migration recommendations.
priority: critical
owner: qguard-helix
version: 1.0
---

# Post-Quantum Detection & Classification

Terminology is normative — see `_shared/pqc-standards.md`. Never describe ML-KEM
as a signature algorithm.

| Purpose | Standard | Algorithm |
|---|---|---|
| Key establishment | FIPS 203 | **ML-KEM** (Kyber) |
| Digital signature | FIPS 204 | **ML-DSA** (Dilithium) |
| Digital signature | FIPS 205 | **SLH-DSA** (SPHINCS+) |
| Symmetric | — | AES-256-GCM |
| Hashing | — | SHA3-256 / SHA3-512 |

Approved hybrids: `X25519 + ML-KEM`, `Ed25519 + ML-DSA`.

## The three-way verdict

Every asset must be classifiable as exactly one of:

| Verdict | Meaning |
|---|---|
| **Classical only** | no PQC observed anywhere in the path |
| **Hybrid** | classical + PQC together (the recommended migration posture) |
| **Post-quantum** | PQC without a classical fallback |

Plus a mandatory fourth state: **Not observed** — the scan could not reach the
evidence. Never collapse "no PQC found" into "classical only" when the surface
was never measured. See `qguard-data-integrity`.

## Where PQC is detected

**1. Source code and dependencies** — `crypto-patterns.ts` ids 100–105:
ML-KEM/Kyber, ML-DSA/Dilithium, SLH-DSA/SPHINCS+, Falcon/BIKE/HQC/McEliece,
liboqs/pqcrypto/PQClean, hybrid group names.

**2. Client-side bundles** — `web-crypto-scanner.ts` has its **own** array with
ML-KEM, PQC signatures, PQC libraries and hybrid groups.

**3. Transport** — hybrid named-group probing in the public-scan TLS engine.

### These are the only rules that can raise a SAFE asymmetric verdict

Before they existed, a repository that had **already migrated to ML-KEM** scored
identically to one that had done nothing: the catalog could only find classical
algorithms, so "no PQC detected" was a foregone conclusion. A detector that can
only find failures produces a posture that can only look bad.

## Hybrid group names need their own rule

```ts
// `X25519MLKEM768` has NO word boundary before "MLKEM",
// so /\bML-?KEM\b/ cannot see it.
regex: /X25519MLKEM768|X25519Kyber768|SecP256r1MLKEM768|P256Kyber768/gi
```

Attribute these to `Hybrid ML-KEM`, not to a generic "library" bucket — a hybrid
group is a key-agreement fact, not a dependency fact.

## TLS probing invariants

- **Probe named groups sequentially.** Parallel probing false-negatives.
- **TLS 1.3 always uses ephemeral (EC)DHE** (RFC 8446). Suite names carry no
  key-exchange token and Node's `getEphemeralKeyInfo()` returns `{}` on some
  builds, so derive `ECDHE (TLS 1.3 key_share)` from the protocol — a guarantee,
  not a guess. Leave the *group* null when genuinely unknown.
- A budget-exhausted group probe is **inconclusive**, not "unsupported". Report
  which groups were left unmeasured.

## Readiness scoring — one model

`postQuantumReadinessFromSignals` in `grading-model` is the platform definition:
hybrid key agreement 55, PQ signature 30, TLS 1.3 12, short-lived certificates 8,
CT 3, enforced HSTS 3.

Do **not** substitute `pqcReady / totalFindings` — that is a share of findings, a
different measurement of a different population. Using it is why one surface
reported 0 % where another reported 8 % for the same host.

Scanner_2's asset-level readiness is reported **separately and labelled with its
source**, never averaged into the platform figure.

## HNDL exposure

Harvest-Now-Decrypt-Later is derived from the key agreement **and** the
certificate key, so it is produced by — and counted against — the key exchange
analyzer. Urgency comes from estimated years-to-CRQC against data shelf life.

Grover halves symmetric margins: AES-128 is `MEDIUM`, AES-256 and ChaCha20 are
`SAFE`. Shor breaks RSA/DH/ECC outright: those are `CRITICAL` regardless of key
size — a larger RSA key is not a mitigation.

## Migration recommendations

Every recommendation must carry: the classical algorithm observed, the
recommended PQC replacement, the NIST standard, migration complexity, concrete
steps, and the count of affected observations. A recommendation with no observed
finding behind it must say so rather than implying exposure.

## Checklist

- [ ] Correct FIPS mapping; ML-KEM never called a signature algorithm.
- [ ] Classical / hybrid / post-quantum / **not observed** all distinguishable.
- [ ] PQC rules exist in **both** catalogs (source and client-side).
- [ ] Hybrid group names have their own rule.
- [ ] Readiness uses the published category model, not a finding share.
- [ ] Named-group probing is sequential.
- [ ] `tools/crypto-detection-check.ts` PQC controls pass.
