/**
 * Crypto classification accuracy — the contract.
 *
 * Guards the three rules a Dev/Local scan of this repository broke, each of
 * which put a wrong number in front of the customer:
 *
 *  1. HYBRID needs two ASYMMETRIC halves, NAMED AS ONE THING.
 *     `detectHybridPartner` used to answer "is there a PQC token anywhere in
 *     the ±4-line window, and a classical token anywhere in it". Any file that
 *     merely lists algorithm names — a catalogue, a config enum, a switch over
 *     supported suites — made every primitive near it hybrid. A real scan
 *     published 33 RSA and 46 ECDSA components as hybrid, i.e. as quantum-
 *     PROTECTED, and MD5, DES, RC4, SHA-1 and AES as "completed migration
 *     work, not an exposure".
 *
 *  2. READINESS is ONE formula.
 *     The reconciler counted `resistant` (every symmetric cipher and hash) on
 *     both sides of the ratio while `summariseCbom` excluded it, so the same
 *     scan published 48% on the Quantum Exposure panel and 31% on the CBOM
 *     panel.
 *
 *  3. A KEY SIZE must be written against the algorithm that owns it.
 *     `parseKeySize` took the first plausible digit run anywhere in the
 *     string, so `sha256WithRSAEncryption` published `RSA-256 for digital
 *     signature` as a CRITICAL finding. RSA-256 is not a key size that exists.
 *
 *   npx tsx tools/crypto-classification-check.ts
 */

import { classify, detectHybridPartner, findAlgorithm, parseKeySize } from '@/lib/crypto/knowledge-base';
import { postQuantumReadiness } from '@/lib/scanner/exposure/exposure-truth';
import { hybridRoles } from '@/lib/crypto/hybrid-construction';

let failures = 0;
let checks = 0;

function ok(condition: boolean, label: string, detail = '') {
  checks += 1;
  if (condition) {
    console.log(`  \x1b[32mok  \x1b[0m ${label}`);
  } else {
    failures += 1;
    console.log(`  \x1b[31mFAIL\x1b[0m ${label}${detail ? ` \x1b[2m(${detail})\x1b[0m` : ''}`);
  }
}

function section(title: string) {
  console.log(`\n\x1b[36m── ${title} ${'─'.repeat(Math.max(0, 62 - title.length))}\x1b[0m`);
}

/** The quantum status the pipeline would publish for one observation. */
function statusOf(algorithm: string, context: string): string {
  const partner = detectHybridPartner(context, algorithm);
  return classify({ algorithm, context, hybridPartner: partner }).quantumStatus;
}

/* ─────────────────────────────────── real hybrids must stay recognised ──── */

section('A real hybrid construction is still recognised');

/* `algorithm` is what the detector observed; `context` is the window it sat in.
   The fused GROUP NAME (`X25519MLKEM768`) is not itself an algorithm the
   knowledge base resolves — the halves are — so the observed algorithm is
   always one half, which is what the source engines actually pass. */
const REAL_HYBRIDS: Array<[string, string]> = [
  ['x25519', 'const group = "X25519MLKEM768";'],
  ['ML-KEM', 'const group = "X25519MLKEM768";'],
  ['x25519', 'kex_algorithms = x25519_kyber768'],
  ['ECDH', 'suite: p256_mlkem768'],
  ['ML-KEM', 'suite: p256_mlkem768'],
  ['x25519', 'sntrup761x25519-sha512@openssh.com'],
  ['Ed25519', 'signature: Ed25519+ML-DSA'],
  ['ECDSA', 'composite = ecdsa_p256_mldsa44'],
  ['ML-DSA', 'composite = ecdsa_p256_mldsa44'],
];

for (const [algorithm, context] of REAL_HYBRIDS) {
  const partner = detectHybridPartner(context, algorithm);
  ok(partner !== null, `${algorithm} in "${context.slice(0, 42)}" pairs with a partner`, `partner=${partner}`);
  if (partner !== null) {
    ok(
      statusOf(algorithm, context) === 'HYBRID',
      `  …and is classified HYBRID`,
      statusOf(algorithm, context),
    );
  }
}

/* ──────────────────────────── co-occurrence must NOT create a hybrid ────── */

section('Naming two algorithms nearby is not a hybrid deployment');

/* The shape of a real algorithm catalogue, a config enum, or a migration note —
   the thing that made a whole repository read as quantum-protected. */
const CATALOGUE = `
  const SUPPORTED = ['RSA', 'ECDSA', 'Ed25519', 'ML-KEM', 'ML-DSA', 'SLH-DSA'];
  // TODO: migrate RSA signing to ML-DSA before 2030
`;

for (const algorithm of ['RSA', 'ECDSA', 'Ed25519']) {
  ok(
    detectHybridPartner(CATALOGUE, algorithm) === null,
    `${algorithm} listed beside PQC names finds no partner`,
    String(detectHybridPartner(CATALOGUE, algorithm)),
  );
  ok(
    statusOf(algorithm, CATALOGUE) === 'QUANTUM_VULNERABLE',
    `  …and stays QUANTUM_VULNERABLE, not quantum-protected`,
    statusOf(algorithm, CATALOGUE),
  );
}

for (const algorithm of ['ML-KEM', 'ML-DSA', 'SLH-DSA']) {
  ok(
    statusOf(algorithm, CATALOGUE) === 'PQC_STANDARDIZED',
    `${algorithm} listed beside classical names stays PQC_STANDARDIZED`,
    statusOf(algorithm, CATALOGUE),
  );
}

ok(
  detectHybridPartner('function rsa_to_mlkem_migration() {}', 'RSA') === null,
  'a migration function name is not a hybrid construction',
);

/* ───────────────────── a hash or a cipher is never half of a hybrid ─────── */

section('Only asymmetric primitives can be half of a hybrid');

const NEAR_PQC = 'const kem = MLKEM768(); const digest = md5(x); const c = AES(k); sha1(y); des(z); rc4(w);';

for (const algorithm of ['MD5', 'SHA-1', 'AES', 'DES', 'RC4', '3DES', 'HMAC']) {
  const status = statusOf(algorithm, NEAR_PQC);
  ok(status !== 'HYBRID', `${algorithm} beside ML-KEM is NOT published as HYBRID`, status);
}

ok(
  hybridRoles({ asymmetric: false, shorBroken: false }, { asymmetric: true, shorBroken: false }) === null,
  'hybridRoles rejects a non-asymmetric half',
);
ok(
  hybridRoles({ asymmetric: true, shorBroken: true }, { asymmetric: true, shorBroken: false }) !== null,
  'hybridRoles accepts classical-asymmetric + post-quantum-asymmetric',
);
ok(
  hybridRoles({ asymmetric: true, shorBroken: true }, { asymmetric: true, shorBroken: true }) === null,
  'hybridRoles rejects two classical halves',
);
ok(
  hybridRoles({ asymmetric: true, shorBroken: false }, { asymmetric: true, shorBroken: false }) === null,
  'hybridRoles rejects two post-quantum halves',
);

/* ──────────────────────── a key size must be written against its owner ──── */

section('A key size is only read when the observation states it');

const RSA = findAlgorithm('RSA');
const AES = findAlgorithm('AES');
const ECDSA = findAlgorithm('ECDSA');

ok(parseKeySize('RSA-2048', RSA) === 2048, 'RSA-2048 reads 2048');
ok(parseKeySize('rsa2048', RSA) === 2048, 'rsa2048 reads 2048');
ok(parseKeySize('2048-bit RSA key', RSA) === 2048, '"2048-bit RSA key" reads 2048');
ok(parseKeySize('AES-256', AES) === 256, 'AES-256 reads 256');
ok(parseKeySize('4096', RSA) === 4096, 'a bare number is the size');

/* The defect: a digest length read as the modulus. */
ok(
  parseKeySize('sha256WithRSAEncryption', RSA) === null,
  'sha256WithRSAEncryption does NOT read as RSA-256',
  String(parseKeySize('sha256WithRSAEncryption', RSA)),
);
ok(
  parseKeySize('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', RSA) === null,
  'a cipher suite does NOT give RSA the bulk cipher key length',
  String(parseKeySize('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', RSA)),
);
ok(parseKeySize('copyright 2024', RSA) === null, 'a year is not a key size');
ok(
  parseKeySize('RSA-256', RSA) === null,
  'RSA-256 is rejected outright — no such key size exists',
  String(parseKeySize('RSA-256', RSA)),
);
ok(
  parseKeySize('ECDSA-256', ECDSA) === 256,
  'ECDSA-256 is accepted — 256 IS a curve size',
  String(parseKeySize('ECDSA-256', ECDSA)),
);

/* An observation that states nothing must report nothing, not a guess. */
ok(
  parseKeySize('createSign("RSA-SHA256")', RSA) === null,
  'a signing call naming its digest states no key size',
  String(parseKeySize('createSign("RSA-SHA256")', RSA)),
);

/* ───────────────────────────────── readiness is one formula ─────────────── */

section('Post-quantum readiness is one formula, over one population');

ok(postQuantumReadiness({ vulnerable: 0, hybrid: 0, pqc: 0 }) === null,
  'nothing quantum-relevant ⇒ readiness withheld, never 0 or 100');

ok(postQuantumReadiness({ vulnerable: 10, hybrid: 0, pqc: 0 }) === 0,
  'all vulnerable ⇒ 0%');

ok(postQuantumReadiness({ vulnerable: 0, hybrid: 0, pqc: 10 }) === 100,
  'all post-quantum ⇒ 100%');

ok(postQuantumReadiness({ vulnerable: 0, hybrid: 10, pqc: 0 }) === 60,
  'all hybrid ⇒ 60%: real progress, but a classical half still has to be retired');

/* The defect itself: symmetric and hash volume must not move the number. */
const withoutSymmetric = postQuantumReadiness({ vulnerable: 100, hybrid: 0, pqc: 0 });
ok(withoutSymmetric === 0,
  'an estate of RSA reads 0% ready',
  String(withoutSymmetric));
ok(
  postQuantumReadiness({ vulnerable: 100, hybrid: 0, pqc: 0 }) === withoutSymmetric,
  'adding 1000 AES/SHA-256 components cannot raise readiness (they are not in the ratio)',
);

console.log('');
console.log('═'.repeat(70));
if (failures === 0) {
  console.log(`\x1b[32m✓ ${checks} crypto-classification checks passed\x1b[0m`);
  process.exit(0);
}
console.log(`\x1b[31m✗ ${failures} of ${checks} checks failed\x1b[0m`);
process.exit(1);
