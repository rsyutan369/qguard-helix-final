---
name: qguard-crypto-detection
description: How QGuard Helix detects cryptography in source code, dependencies and client-side bundles — the 125-pattern catalog, pattern authoring rules, file selection, and the false-positive discipline. Use when adding or changing detection rules, when a scan misses an algorithm it should find, when a scan reports zero findings, or when extending coverage to a new language or package ecosystem.
priority: critical
owner: qguard-helix
version: 1.0
---

# Cryptographic Detection Catalogue

## Where the code is

| Concern | File |
|---|---|
| Source/dependency patterns (125) | `src/lib/scanner/web-scanner/crypto-patterns.ts` |
| Client-side bundle patterns (separate array) | `src/lib/scanner/web-scanner/web-crypto-scanner.ts` |
| Matching, file selection, budgets | `src/lib/scanner/web-scanner/repo-scanner.ts` |
| Expected counts / health | `src/lib/scanner/web-scanner/runtime-health.ts` |
| Regression suite | `tools/crypto-detection-check.ts` |

`web-crypto-scanner.ts` has its **own** `WEB_CRYPTO_PATTERNS` array. It is not
the same catalog — a rule added to one is not present in the other.

## The two rule shapes — you need both

This is the single most important lesson in this skill.

```ts
// SHAPE 1 — algorithm NAME. Necessary, but not how most code is written.
{ regex: /\bRSA\b/i, algorithm: 'RSA', threatLevel: 'CRITICAL' }

// SHAPE 2 — API-CALL IDIOM. How real code actually looks.
{ regex: /createHash\(\s*['"`](md5|md4|md2)['"`]/i, algorithm: 'MD5' }
{ regex: /generateKeyPair(Sync)?\(\s*['"`](rsa|rsa-pss)['"`]/i, algorithm: 'RSA' }
{ regex: /hashlib\.(md5|md4|sha1)\s*\(/i, algorithm: 'MD5/SHA-1' }
```

Matching only shape 1 — and case-sensitively — is why a repository that plainly
used MD5 and RSA once reported **zero findings**. Real code passes lowercase
strings to factories.

## Case sensitivity — deliberate, not uniform

Add `/i` for distinctive tokens: RSA, MD5, ECDSA, RC4, SHA-1, secp256*, Blowfish,
Twofish, Camellia.

**Do NOT** make these case-insensitive:

| Token | Why |
|---|---|
| `SEED` | matches "random seed", "setSeed" — extremely common |
| `IDEA` | matches the English word |
| `DES` | matches "des" in prose and identifiers |
| `DSA` | `dsa` is a common identifier (`const dsa = ml_dsa44`) in ML-DSA code — issue #55 |

**Post-quantum names END in classical tokens.** `ML-DSA`, `SLH-DSA`, `FN-DSA` end in
`DSA`, and `-` is a word boundary, so `\bDSA\b` matches all three. Any rule on a token a
PQC name ends with needs a prefix lookbehind (`(?<!(?:ML|SLH|FN)[-_ ]?)\bDSA\b`) and a
negative control. Identifier rules (`Keypair::generate`) need a leading `\b`, or
`LocalKemKeypair::generate` matches.

**Compound labels** (`algorithm: 'DSA/ElGamal'`) are resolved to the alternative the
MATCHED TEXT names by `lexicalAlgorithmFor` in `exposure/content/source-crypto.ts`.
Never let one reach the classifier as text: `findAlgorithm` takes the longest alias in
the string, so `DSA/ElGamal` always meant ElGamal.

For those, keep the case-sensitive name rule and add explicit cipher-string
idioms (`'des-ede3-cbc'`, `createCipheriv('des'`) to get the real coverage.

## Ordering traps that have bitten

```ts
// `includes('symmetric')` ALSO matches "asymmetric".
if (category === 'symmetric encryption') return 'cipher-suite-scanner'   // exact

// Code-origin categories BEFORE algorithm-class tests, or "Web Crypto (hash)"
// is attributed to the certificate hash analyzer.
if (category.includes('source code') || category.includes('web crypto')) return 'dependency-crypto-scanner'
if (category.includes('hash')) return 'hash-algorithm-scanner'

// `hash(` is a substring of `createHash(` — anchor the PHP rule.
regex: /\bhash\(\s*['"](md5|sha1)['"]/i
```

## Catalogue coverage (125 patterns)

| Family | Covered |
|---|---|
| Asymmetric | RSA, DSA, DH, ECDH, ECDSA, Ed25519/448, X25519/448, ElGamal, SM2 |
| Symmetric | AES-128/192/256, ChaCha20, 3DES, DES, RC2, RC4, Blowfish, Twofish, IDEA, Camellia, SEED, SM4, Salsa20 |
| Hash | MD2/4/5, SHA-1, SHA-2, SHA-3, BLAKE2, BLAKE3, RIPEMD, Whirlpool, SM3 |
| MAC | HMAC (+ HMAC-over-broken-hash), CMAC, GMAC, Poly1305 |
| KDF | PBKDF2, HKDF, Argon2, bcrypt, scrypt, obsolete PBKDF1/crypt |
| **Post-Quantum** | ML-KEM, ML-DSA, SLH-DSA, Falcon, BIKE, HQC, McEliece, liboqs/PQClean, hybrid groups |
| Dependencies | npm/yarn/pnpm, PyPI, Go modules, Cargo, Maven/Gradle, NuGet, Composer, RubyGems |
| Code smells | ECB mode, `Math.random()` for key material, disabled TLS verification, committed private keys |
| Protocol config | SSLv2/3, TLS 1.0/1.1, weak SSH KEX and host keys |

**PQC rules are the only ones that can raise a SAFE *asymmetric* verdict.**
Without them a repository that had already migrated to ML-KEM scored identically
to one that had done nothing. Symmetric SAFE rules (AES-256, ChaCha20, SHA-2/3)
matter for the same reason — a catalog that can only find failures produces a
posture that can only look bad.

## File selection

```ts
export function isScannablePath(path: string): boolean {
  const basename = path.split('/').pop()?.toLowerCase() ?? ''
  if (SCANNABLE_FILENAMES.has(basename)) return true          // go.mod, Gemfile, Dockerfile
  if (basename.startsWith('.') && SCANNABLE_EXTENSIONS.has(basename)) return true  // .env
  const dot = basename.lastIndexOf('.')
  if (dot <= 0) return false
  return SCANNABLE_EXTENSIONS.has(basename.slice(dot))
}
```

Two bugs are encoded here:

- Extension-only filtering skipped `go.mod`, `Gemfile`, `Dockerfile`, `Pipfile` —
  the files that hold the dependency graph.
- Dotfiles have `lastIndexOf('.') === 0`, so `.env` — the likeliest place to find
  committed key material — was skipped entirely.

**Manifests rank above source files** in the bounded budget: one manifest
describes an entire dependency graph, one source file describes one call site.

## Deduplication

Per `(file, pattern)` within a 5-line window. Several *distinct* rules firing on
one line is correct and expected (a name rule and an idiom rule describe the same
usage from different angles). What must not happen is the **same** rule firing
once per line.

## Authoring checklist

- [ ] Unique `id`; `label`, `algorithm`, `category`, `description` all present.
- [ ] **No `/g` flag** — `lastIndex` leaks between files with a shared regex object.
- [ ] Positive control added to `tools/crypto-detection-check.ts`.
- [ ] False-positive control added if the token is short or a real English word.
- [ ] Checked against its own superstrings (`symmetric` ⊂ `asymmetric`).
- [ ] `EXPECTED_WEB_CRYPTO_PATTERNS` in `runtime-health.ts` bumped, or health
      reports `degraded`.
- [ ] If the rule targets client-side code, added to the **other** array too.

```bash
npx tsx tools/crypto-detection-check.ts
```

Positive controls span 8 languages, PQC, manifests and file selection; the
false-positive controls assert that prose, `"seed"` and `"idea"` never trigger.

## Interpreting zero findings

Zero findings is a **hypothesis to disprove**, never a clean bill. Distinguish:

- *Nothing found* — the scanner read files and matched nothing.
- *Could not look* — rate limited, private, unreachable, unsupported type.

The second must surface as a degraded result with a `recommendation`, and must
never be scored as a passing posture.
