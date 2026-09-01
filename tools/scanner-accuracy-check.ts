/**
 * Scanner accuracy corpus and precision/recall harness (§65, §66, §67, §68).
 *
 *   npx tsx tools/scanner-accuracy-check.ts
 *
 * §67: "Only publish metrics that are actually measured from a defined test
 *       corpus." This file IS that corpus. The precision and recall numbers it
 *       prints are computed from these fixtures and nothing else — they are not
 *       claims about arbitrary real-world code, and the report says so.
 *
 * §66 calls the negative corpus "extremely important", and it is the half that
 * decides whether a scanner is usable. A detector that finds every RSA key and
 * also flags the word "RSA" in a README produces a report nobody reads. Every
 * negative case below is a real pattern that a naive crypto scanner reports and
 * that this one must not.
 *
 * All key material is fake. Offline; no network calls.
 */

import { emptyWorkspace } from '../src/lib/scanner/exposure/engine-contract';
import { toWorkspaceFile } from '../src/lib/scanner/exposure/content/file-discovery';
import { runExposureScan } from '../src/lib/scanner/exposure/orchestrator';
import { resolveProfile } from '../src/lib/scanner/exposure/profiles';
import type { ExposureAssessment, ExposureFinding } from '../src/lib/scanner/exposure/types';
import {
  classify,
  findAlgorithm,
  findCurve,
  knowledgeBaseSummary,
  establishGroundTruth,
} from '../src/lib/crypto/knowledge-base';
import {
  assessProtocol,
  cipherListPermits,
  classifyGroup,
  decomposeSuite,
  assessSshAlgorithm,
} from '../src/lib/crypto/tls-intelligence';
import { assessCertificate, parseCertificate } from '../src/lib/crypto/certificate-intelligence';
import { analyzeCryptoObservation } from '../src/lib/crypto/suite-anatomy';

/* ═══════════════════════════════════════════════════════════════ harness ═══ */

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(label: string, condition: boolean, detail?: string): void {
  if (condition) {
    passed += 1;
    return;
  }
  failed += 1;
  failures.push(`${label}${detail ? ` — ${detail}` : ''}`);
}

function section(title: string): void {
  console.log(`\n\x1b[36m── ${title} ${'─'.repeat(Math.max(0, 60 - title.length))}\x1b[0m`);
}

/* ═════════════════════════════════════════════════ positive corpus (§65) ═══ */

/**
 * Each entry states what the scanner MUST find. `algorithm` is the canonical
 * name expected; `role` is the cryptographic role that must be established.
 */
interface PositiveCase {
  file: string;
  content: string;
  expect: Array<{ algorithm: string; role?: string; quantum?: string; minSeverity?: string }>;
}

const POSITIVE_CORPUS: PositiveCase[] = [
  {
    file: 'src/sign.ts',
    content: `
import crypto from 'node:crypto';
export function signPayload(payload: string, key: string) {
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(payload);
  return signer.sign(key, 'base64');
}
`,
    expect: [{ algorithm: 'RSA', role: 'signature', quantum: 'vulnerable' }],
  },
  {
    file: 'src/hash.py',
    content: `
import hashlib
def legacy_digest(value):
    return hashlib.md5(value.encode()).hexdigest()
def modern_digest(value):
    return hashlib.sha256(value.encode()).hexdigest()
`,
    expect: [{ algorithm: 'MD5', role: 'hashing' }],
  },
  {
    file: 'src/Crypto.java',
    content: `
public class Crypto {
  public void weak() throws Exception {
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    Signature signature = Signature.getInstance("SHA1withRSA");
  }
}
`,
    expect: [
      { algorithm: 'AES', role: 'encryption' },
      { algorithm: 'RSA' },
    ],
  },
  {
    file: 'src/keys.go',
    content: `
package main
import ("crypto/ecdsa"; "crypto/elliptic"; "crypto/rand")
func generate() {
  key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  _ = key
}
`,
    expect: [{ algorithm: 'ECDSA', quantum: 'vulnerable' }],
  },
  {
    file: 'nginx.conf',
    content: `
server {
  ssl_protocols TLSv1 TLSv1.2 TLSv1.3;
  ssl_ciphers HIGH:!aNULL:!MD5:!RC4;
  ssl_ecdh_curve X25519MLKEM768:X25519;
}
`,
    expect: [
      { algorithm: 'TLS' },
      { algorithm: 'ML-KEM', quantum: 'hybrid' },
    ],
  },
  {
    file: 'src/weak-random.ts',
    content: `
export function makeSessionToken() {
  const token = Math.random().toString(36).slice(2);
  return token;
}
`,
    expect: [{ algorithm: 'random' }],
  },
  {
    file: 'src/kdf.ts',
    content: `
import bcrypt from 'bcrypt';
export const hashPassword = (password: string) => bcrypt.hash(password, { rounds: 8 });
`,
    expect: [{ algorithm: 'bcrypt', role: 'password-derivation' }],
  },
  {
    file: 'src/pqc.ts',
    content: `
import { ml_kem768 } from '@noble/post-quantum/ml-kem';
export function encapsulate(publicKey: Uint8Array) {
  return ml_kem768.encapsulate(publicKey);
}
`,
    expect: [{ algorithm: 'ML-KEM', quantum: 'pqc' }],
  },
];

/* ═════════════════════════════════════════════════ negative corpus (§66) ═══ */

/**
 * Every entry here MUST produce no finding above `info`.
 *
 * §66 lists the categories; each is represented by a case a naive scanner
 * genuinely gets wrong.
 */
interface NegativeCase {
  file: string;
  content: string;
  why: string;
}

const NEGATIVE_CORPUS: NegativeCase[] = [
  {
    file: 'README.md',
    content: '# Security\n\nWe use RSA and AES-256 to protect data. MD5 was removed in v2.\nSee the design doc for our ECDSA key rotation policy.\n',
    why: 'documentation mentioning algorithm names',
  },
  {
    file: 'src/notes.ts',
    content: `
// TODO: migrate off RSA — it is quantum vulnerable.
/* Historical: this module used MD5 before 2019. */
// We must never use DES or RC4 here.
export const NOTE = 'unused';
`,
    why: 'comments describing intent and history',
  },
  {
    file: 'src/vars.ts',
    content: `
const RSA = 'not-an-algorithm';
let aes = computeAverageEarningsShare();
const described = (value: string) => value.trim();
const dhcpLease = 3600;
const openSslVersion = '3.0.11';
export { RSA, aes, described, dhcpLease, openSslVersion };
`,
    why: 'identifiers that collide with algorithm names (RSA, aes, described→DES, dhcp→DH, OpenSSL→SSL)',
  },
  {
    file: 'src/logging.ts',
    content: `
logger.info('Falling back from ECDHE to RSA key exchange');
logger.warn('Deprecated: SHA-1 signatures are no longer accepted');
throw new Error('AES-128 keys are not supported by this endpoint');
`,
    why: 'log messages and error strings',
  },
  {
    file: 'src/animation.ts',
    content: `
export function jitter() {
  return Math.random() * 40;
}
export function shuffleDisplayOrder(items: string[]) {
  return items.sort(() => Math.random() - 0.5);
}
`,
    why: 'non-cryptographic random with no security context',
  },
  {
    file: 'src/etag.ts',
    content: `
import crypto from 'node:crypto';
export function cacheKey(body: string) {
  return crypto.createHash('md5').update(body).digest('hex');
}
`,
    why: 'MD5 as a cache key — a non-security hash use',
  },
  {
    file: 'hardened.conf',
    content: `
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:!aNULL:!MD5:!RC4:!3DES:!EXPORT;
ssl_prefer_server_ciphers on;
`,
    why: 'an OpenSSL cipher list that EXCLUDES the weak suites with !',
  },
  {
    file: '.env.example',
    content: `
DATABASE_URL=postgres://user:changeme@localhost:5432/app
API_KEY=your-api-key-here
JWT_SECRET=\${VAULT_JWT_SECRET}
AWS_SECRET_ACCESS_KEY=
`,
    why: 'placeholder credentials in a template file',
  },
  {
    file: 'src/disabled.ts',
    content: `
const config = {
  allowMD5: false,
  disableSHA1: true,
  enableRC4: false,
  legacyCiphersEnabled: false,
};
export default config;
`,
    why: 'controls that DISABLE weak algorithms',
  },
];

/* ═════════════════════════════════════════════════════ unit-level checks ═══ */

function checkKnowledgeBase(): void {
  section('Crypto Knowledge Base (§7)');

  const summary = knowledgeBaseSummary();
  check('Algorithm registry is populated', summary.algorithms.total >= 35, String(summary.algorithms.total));
  check('Curve registry is populated', summary.curves.total >= 12, String(summary.curves.total));
  check('Library catalogue is populated', summary.libraries.total >= 20, String(summary.libraries.total));
  check('API rules cover 10+ languages', summary.apiRules.languages.length >= 10, summary.apiRules.languages.join(','));
  check('QGH rule set is populated', summary.scannerRules.total >= 18, String(summary.scannerRules.total));
  check('Standards layer cites 4+ authorities', summary.standards.authorities.length >= 4, summary.standards.authorities.join(','));

  section('Classical and quantum are INDEPENDENT axes (§9, §36-§38)');

  const rsa2048 = classify({ algorithm: 'RSA', keySize: 2048, declaredRole: 'digital-signature' });
  check('RSA-2048 is classically ACCEPTABLE, not broken', rsa2048.classicalSecurity === 'ACCEPTABLE', rsa2048.classicalSecurity);
  check('RSA-2048 is quantum vulnerable', rsa2048.quantumStatus === 'QUANTUM_VULNERABLE');
  check('RSA rationale never says "currently broken"', !/currently.{0,20}broken/i.test(rsa2048.quantumRationale), rsa2048.quantumRationale);
  check('RSA-2048 rationale states it is not breakable today', /not breakable today|migration candidate/i.test(rsa2048.quantumRationale));

  const rsa1024 = classify({ algorithm: 'RSA', keySize: 1024, declaredRole: 'digital-signature' });
  check('RSA-1024 IS classically broken', rsa1024.classicalSecurity === 'BROKEN', rsa1024.classicalSecurity);

  const sha1 = classify({ algorithm: 'SHA-1', declaredRole: 'certificate-signature' });
  check('SHA-1 is classically BROKEN', sha1.classicalSecurity === 'BROKEN');
  check('SHA-1 is quantum RESISTANT (it is not a Shor target)', sha1.quantumStatus === 'QUANTUM_RESISTANT', sha1.quantumStatus);
  check('SHA-1 is excluded from the quantum-relevant population', sha1.quantumRelevant === false);

  const aes256 = classify({ algorithm: 'AES-256-GCM', declaredRole: 'storage-encryption' });
  check('AES-256 is quantum RESISTANT (§95)', aes256.quantumStatus === 'QUANTUM_RESISTANT', aes256.quantumStatus);
  check('AES-256 is not a migration candidate', aes256.quantumRelevant === false);
  check('AES-256 effective quantum strength is published', aes256.effectiveQuantumStrength === 128, String(aes256.effectiveQuantumStrength));

  const aes128 = classify({ algorithm: 'AES-128', declaredRole: 'encryption' });
  check('AES-128 effective quantum strength is 64 bits', aes128.effectiveQuantumStrength === 64, String(aes128.effectiveQuantumStrength));
  check('AES-128 is still not classified vulnerable', aes128.quantumStatus === 'QUANTUM_RESISTANT');

  const mlkem = classify({ algorithm: 'kyber768', declaredRole: 'key-establishment' });
  check('Kyber normalises to ML-KEM (§39)', mlkem.canonicalName === 'ML-KEM', mlkem.canonicalName);
  check('ML-KEM is PQC_STANDARDIZED', mlkem.quantumStatus === 'PQC_STANDARDIZED');
  check('ML-KEM cites FIPS 203', mlkem.standards.some((entry) => entry.standardId === 'FIPS-203'));

  section('Role-appropriate migration targets (§80)');

  const rsaKex = classify({ algorithm: 'RSA', declaredRole: 'key-transport' });
  check('RSA key transport → ML-KEM', /ML-KEM/.test(rsaKex.migrationTarget ?? ''), rsaKex.migrationTarget);
  check('RSA key transport is NOT told to use ML-DSA', !/ML-DSA/.test(rsaKex.migrationTarget ?? ''));

  const rsaSig = classify({ algorithm: 'RSA', declaredRole: 'digital-signature' });
  check('RSA signature → ML-DSA', /ML-DSA/.test(rsaSig.migrationTarget ?? ''), rsaSig.migrationTarget);

  const ecdh = classify({ algorithm: 'ECDH', declaredRole: 'key-establishment' });
  check('ECDH → ML-KEM, never ML-DSA', /ML-KEM/.test(ecdh.migrationTarget ?? '') && !/ML-DSA/.test(ecdh.migrationTarget ?? ''), ecdh.migrationTarget);

  const rsaUnknownRole = classify({ algorithm: 'RSA' });
  check('RSA with no role gets NO migration target (§80)', rsaUnknownRole.migrationTarget === undefined, rsaUnknownRole.migrationTarget);
  check('RSA with no role records the gap', rsaUnknownRole.undetermined.includes('cryptographic role'));

  section('Named-curve intelligence (§8, §10)');

  const p224 = findCurve('secp224r1');
  const p256 = findCurve('prime256v1');
  check('P-224 resolves', p224?.curveId === 'p-224');
  check('P-256 resolves from prime256v1', p256?.curveId === 'p-256');
  check('P-224 is weaker than P-256', (p224?.classicalStrength ?? 0) < (p256?.classicalStrength ?? 0));
  check('P-224 is LEGACY, P-256 is STRONG', p224?.classicalSecurity === 'LEGACY' && p256?.classicalSecurity === 'STRONG');

  const x25519 = findCurve('x25519');
  const ed25519 = findCurve('ed25519');
  check('X25519 does key agreement only', x25519?.roles.includes('key-establishment') === true && x25519?.roles.includes('digital-signature') === false);
  check('Ed25519 signs only', ed25519?.roles.includes('digital-signature') === true && ed25519?.roles.includes('key-establishment') === false);
  check('secp256k1 is flagged as non-NIST', /not a NIST curve/i.test(findCurve('secp256k1')?.note ?? ''));

  section('Alias collisions the scanner has previously shipped');

  check('"OpenSSL" does not resolve to SSL', findAlgorithm('OpenSSL')?.algorithmId !== 'ssl-legacy', String(findAlgorithm('OpenSSL')?.canonicalName));
  check('"described" does not resolve to DES', findAlgorithm('described') === null);
  check('"dhcpLease" does not resolve to DH', findAlgorithm('dhcpLease') === null);
  check('"ecdh" resolves to ECDH not Diffie-Hellman', findAlgorithm('ecdh')?.algorithmId === 'ecdh');
  check('"Dilithium" resolves to ML-DSA', findAlgorithm('Dilithium')?.canonicalName === 'ML-DSA');
  check('"SPHINCS+" resolves to SLH-DSA', findAlgorithm('SPHINCS+')?.canonicalName === 'SLH-DSA');
}

function checkTlsIntelligence(): void {
  section('TLS Intelligence — suite decomposition (§19, §20)');

  const tls12 = decomposeSuite('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384');
  check('TLS 1.2 suite decomposes', tls12 !== null);
  check('Key exchange is ECDHE', tls12?.keyExchange?.observed === 'ECDHE', tls12?.keyExchange?.observed);
  check('Authentication is RSA', tls12?.authentication?.observed === 'RSA', tls12?.authentication?.observed);
  check('Bulk cipher is AES-256-GCM', tls12?.bulk?.observed === 'AES-256-GCM', tls12?.bulk?.observed);
  check('MAC is SHA-384', tls12?.mac?.observed === 'SHA-384', tls12?.mac?.observed);
  check('Forward secrecy is true for ECDHE', tls12?.forwardSecrecy === true);
  check('§19: the exposure is named as the key exchange and auth, not the suite',
    tls12?.quantumExposureFrom.includes('key-exchange') === true && tls12?.quantumExposureFrom.includes('authentication') === true,
    tls12?.quantumExposureFrom.join(','));
  check('§19: the bulk cipher is NOT part of the quantum exposure',
    tls12?.quantumExposureFrom.includes('bulk' as never) === false);
  check('The summary names the resistant components', /AES-256-GCM/.test(tls12?.quantumSummary ?? ''), tls12?.quantumSummary);
  check('ECDHE summary warns about harvest-now', /harvest-now|recorded handshake/i.test(tls12?.quantumSummary ?? ''));

  const staticRsa = decomposeSuite('TLS_RSA_WITH_AES_128_CBC_SHA');
  check('Static RSA key transport has no forward secrecy', staticRsa?.forwardSecrecy === false);
  check('Static RSA is flagged classically', staticRsa?.classicallyBroken === true, staticRsa?.classicalSummary);
  check('Static RSA is NOT read as a TLS 1.3 suite', staticRsa?.grammar === 'tls12', staticRsa?.grammar);

  const tls13 = decomposeSuite('TLS_AES_256_GCM_SHA384');
  check('TLS 1.3 suite uses the 1.3 grammar', tls13?.grammar === 'tls13', tls13?.grammar);
  check('TLS 1.3 suite names no key exchange', tls13?.keyExchange === null);
  check('TLS 1.3 has forward secrecy by construction', tls13?.forwardSecrecy === true);
  check('TLS 1.3 with no group says the exposure is undetermined', /supported_groups|does not carry/i.test(tls13?.quantumSummary ?? ''));

  const tls13Hybrid = decomposeSuite('TLS_AES_256_GCM_SHA384', 'X25519MLKEM768');
  check('TLS 1.3 + hybrid group reports no quantum exposure',
    tls13Hybrid?.quantumExposureFrom.length === 0 && /no known quantum exposure/i.test(tls13Hybrid?.quantumSummary ?? ''),
    tls13Hybrid?.quantumSummary);

  const rc4 = decomposeSuite('TLS_RSA_WITH_RC4_128_SHA');
  check('RC4 suite is classically broken', rc4?.classicallyBroken === true);

  section('TLS Intelligence — named groups (§21)');

  const hybrid = classifyGroup('X25519MLKEM768');
  check('X25519MLKEM768 is recognised as hybrid', hybrid.hybrid === true);
  check('Hybrid group classifies as HYBRID, not vulnerable', hybrid.classification.quantumStatus === 'HYBRID', hybrid.classification.quantumStatus);

  const plainX25519 = classifyGroup('x25519');
  check('Plain X25519 is quantum vulnerable', plainX25519.classification.quantumStatus === 'QUANTUM_VULNERABLE');
  check('Plain X25519 is not marked hybrid', plainX25519.hybrid === false);

  const ffdhe = classifyGroup('ffdhe2048');
  check('ffdhe2048 resolves to Diffie-Hellman at 2048 bits', ffdhe.classification.canonicalName === 'Diffie-Hellman' && ffdhe.classification.keySize === 2048);

  section('TLS Intelligence — OpenSSL cipher lists');

  const hardened = 'HIGH:!aNULL:!MD5:!RC4:!3DES';
  check('An excluded token is NOT permitted', !cipherListPermits(hardened, 'RC4'));
  check('An excluded aNULL is NOT permitted', !cipherListPermits(hardened, 'aNULL'));
  check('A permitted token IS permitted', cipherListPermits('HIGH:RC4-SHA', 'RC4'));

  section('TLS Intelligence — protocols (§18)');

  check('TLS 1.0 is deprecated and not PQC-capable', assessProtocol('TLSv1.0').deprecated && !assessProtocol('TLSv1.0').pqcCapable);
  check('TLS 1.2 is current but not PQC-capable', !assessProtocol('TLSv1.2').deprecated && !assessProtocol('TLSv1.2').pqcCapable);
  check('TLS 1.3 is PQC-capable', assessProtocol('TLSv1.3').pqcCapable);
  check('SSLv3 is critical', assessProtocol('SSLv3').severity === 'critical');

  section('SSH algorithms (§31)');

  const sntrup = assessSshAlgorithm('sntrup761x25519-sha512@openssh.com', 'kex');
  check('OpenSSH hybrid KEX is recognised as hybrid', sntrup.classification.quantumStatus === 'HYBRID', sntrup.classification.quantumStatus);
  check('OpenSSH hybrid KEX is not flagged weak', sntrup.weak === false);

  const weakKex = assessSshAlgorithm('diffie-hellman-group1-sha1', 'kex');
  check('SHA-1 SSH KEX is flagged weak', weakKex.weak === true);

  const ed = assessSshAlgorithm('ssh-ed25519', 'hostkey');
  check('Ed25519 host key is quantum vulnerable', ed.classification.quantumStatus === 'QUANTUM_VULNERABLE');
  check('Ed25519 host key is not flagged classically weak', ed.weak === false);
}

function checkCertificateIntelligence(): void {
  section('Certificate Intelligence — §23 field separation');

  /* A minimal but structurally valid certificate: RSA-2048 SPKI, signed with
     sha256WithRSAEncryption. Built by hand so the parser is tested against
     exactly the structure it claims to read. */
  const der = buildFixtureCertificate();
  const certificate = parseCertificate(der);

  check('Fixture certificate parses', certificate.parsed, certificate.undetermined.join('; '));
  check('Public key algorithm is read', certificate.publicKey.algorithm === 'RSA', String(certificate.publicKey.algorithm));
  check('Public key size is read', certificate.publicKey.keySize === 2048, String(certificate.publicKey.keySize));
  check('Signature algorithm is read', certificate.signature.algorithm === 'RSA', String(certificate.signature.algorithm));
  check('Signature HASH is read separately', certificate.signature.hash === 'SHA-256', String(certificate.signature.hash));

  const assessment = assessCertificate(certificate);
  check('§23: public key and signature produce SEPARATE classifications',
    assessment.publicKeyClassification !== null && assessment.signatureClassification !== null);
  check('§23: the public key classification is role-tagged as a certificate key',
    assessment.publicKeyClassification?.role === 'certificate-public-key');
  check('§23: the signature classification is role-tagged as a certificate signature',
    assessment.signatureClassification?.role === 'certificate-signature');

  /* The same certificate with a SHA-1 signature must change ONLY the signature
     verdict, leaving the subject key verdict untouched. */
  const sha1Der = buildFixtureCertificate('1.2.840.113549.1.1.5');
  const sha1Cert = parseCertificate(sha1Der);
  const sha1Assessment = assessCertificate(sha1Cert);
  check('SHA-1 signature is detected', sha1Cert.signature.hash === 'SHA-1', String(sha1Cert.signature.hash));
  check('SHA-1 raises QGH-CERT-001', sha1Assessment.findings.some((entry) => entry.ruleId === 'QGH-CERT-001'));
  check('SHA-1 signature does NOT change the subject key verdict',
    sha1Assessment.publicKeyClassification?.canonicalName === assessment.publicKeyClassification?.canonicalName);
  check('The SHA-1 finding says remediation is the CA\'s',
    sha1Assessment.findings.some((entry) => /BY THE CA|re-issuance/i.test(entry.detail)));
}

function checkGroundTruth(): void {
  section('Ground Truth Engine (§45, §47, §48)');

  const now = new Date().toISOString();
  const lexicalOnly = establishGroundTruth([
    { engineId: 'source-crypto', evidenceType: 'STATIC_ANALYSIS', quality: 'WEAK', layer: 'lexical', summary: 'x', observedAt: now },
  ]);
  check('A single lexical match is never high confidence', lexicalOnly.confidenceBand !== 'high', lexicalOnly.confidenceBand);
  check('A single lexical match is POTENTIAL, not CONFIRMED', lexicalOnly.determination !== 'CONFIRMED');

  const repeated = establishGroundTruth([
    { engineId: 'source-crypto', evidenceType: 'STATIC_ANALYSIS', quality: 'WEAK', layer: 'lexical', summary: 'x', observedAt: now },
    { engineId: 'source-crypto', evidenceType: 'STATIC_ANALYSIS', quality: 'WEAK', layer: 'lexical', summary: 'y', observedAt: now },
    { engineId: 'source-crypto', evidenceType: 'STATIC_ANALYSIS', quality: 'WEAK', layer: 'lexical', summary: 'z', observedAt: now },
  ]);
  check('Repetition of ONE layer does not raise confidence', repeated.confidence === lexicalOnly.confidence,
    `${lexicalOnly.confidence} vs ${repeated.confidence}`);

  const multiLayer = establishGroundTruth([
    { engineId: 'source-crypto', evidenceType: 'STATIC_ANALYSIS', quality: 'DIRECT', layer: 'api', summary: 'x', observedAt: now },
    { engineId: 'source-crypto', evidenceType: 'STATIC_ANALYSIS', quality: 'WEAK', layer: 'lexical', summary: 'y', observedAt: now },
  ]);
  check('Independent layers DO raise confidence', multiLayer.confidence > lexicalOnly.confidence);
  check('DIRECT + corroboration reaches CONFIRMED', multiLayer.determination === 'CONFIRMED', multiLayer.determination);

  const withCaveats = establishGroundTruth([
    { engineId: 'source-crypto', evidenceType: 'STATIC_ANALYSIS', quality: 'DIRECT', layer: 'api', summary: 'x', observedAt: now, caveats: ['in a comment', 'test path'] },
  ]);
  check('Caveats reduce confidence', withCaveats.confidence < multiLayer.confidence);
  check('Caveats are published, not hidden', withCaveats.caveats.length === 2);
  check('The rationale explains the confidence', withCaveats.rationale.length > 40);

  const crossEngine = establishGroundTruth([
    { engineId: 'source-crypto', evidenceType: 'STATIC_ANALYSIS', quality: 'DIRECT', layer: 'api', summary: 'x', observedAt: now },
    { engineId: 'certificate-material', evidenceType: 'CERTIFICATE_OBSERVATION', quality: 'DIRECT', layer: 'ast', summary: 'y', observedAt: now },
  ]);
  check('§48: cross-engine agreement is recorded', crossEngine.corroboratingEngines.length === 2);
  check('§48: cross-engine agreement raises confidence', crossEngine.confidence > multiLayer.confidence);
}


/* ══════════════════════════════════════════ decomposer agreement (§7) ═══ */

/**
 * The platform has TWO cipher-suite readers and they must never disagree.
 *
 *   suite-anatomy.ts      pure, dependency-free, consumed by eight dashboards
 *                         and the offline check tools. Answers "what kind of
 *                         observation is this string, and which primitive
 *                         carries the quantum risk".
 *   tls-intelligence.ts   knowledge-base backed. Answers the same question AND
 *                         classifies every component on both the classical and
 *                         the quantum axis, which suite-anatomy deliberately
 *                         does not do because it takes no dependencies.
 *
 * Keeping both is a considered trade: rewriting suite-anatomy's eight consumers
 * to take a knowledge-base dependency is a far larger change than the accuracy
 * work asked for. What is NOT acceptable is the two drifting apart, because a
 * dashboard reading one and a scanner reading the other would then publish
 * different key exchanges for the same suite. This test is the seam: any change
 * to either grammar that moves them apart fails here.
 */
function checkDecomposerAgreement(): void {
  section('Decomposer agreement — suite-anatomy vs tls-intelligence (§7)');

  const suites = [
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
    'TLS_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
  ];

  for (const suite of suites) {
    const modern = decomposeSuite(suite);
    const legacy = analyzeCryptoObservation({ algorithm: suite });

    const parsed = Boolean(modern) && legacy.kind === 'cipher-suite';
    check(`${suite} — both decomposers parse it`, parsed);
    if (!parsed) continue;

    /* Forward secrecy is the field a disagreement would be most visible in:
       one panel saying "forward secret" beside another saying "not" is exactly
       the contradiction the single-source rule exists to prevent. */
    check(
      `${suite} — forward secrecy agrees`,
      modern!.forwardSecrecy === legacy.forwardSecrecy,
      `tls-intelligence=${String(modern!.forwardSecrecy)} suite-anatomy=${String(legacy.forwardSecrecy)}`,
    );

    /* The bulk cipher is the other field both name explicitly. Labels differ in
       punctuation between the modules (AES_256_GCM vs AES-256-GCM), so compare
       on the normalised token rather than the display string. */
    const normalise = (value: string | null | undefined) => (value ?? '').toUpperCase().replace(/[-_]/g, '');
    check(
      `${suite} — bulk cipher agrees`,
      normalise(modern!.bulk?.observed) === normalise(legacy.bulk),
      `tls-intelligence=${modern!.bulk?.observed ?? 'null'} suite-anatomy=${legacy.bulk ?? 'null'}`,
    );

    /* Static RSA key transport is the single most consequential reading either
       module makes, because it decides whether recorded traffic is retroactively
       decryptable. Both must reach it. */
    if (suite.startsWith('TLS_RSA_WITH')) {
      check(
        `${suite} — both read static RSA key transport`,
        modern!.keyExchange?.observed?.toUpperCase() === 'RSA' && legacy.keyExchange?.toUpperCase() === 'RSA',
        `tls-intelligence=${modern!.keyExchange?.observed ?? 'null'} suite-anatomy=${legacy.keyExchange ?? 'null'}`,
      );
    }
  }
}

/* ═══════════════════════════════════════════════════ corpus execution ══════ */

async function runCorpus(files: Array<{ path: string; content: string }>): Promise<ExposureAssessment> {
  const workspace = emptyWorkspace();
  workspace.files = files.map((entry) => toWorkspaceFile(entry.path, entry.content));
  const { engines } = resolveProfile('local', 'deep');
  return runExposureScan({
    scanId: 'accuracy-corpus',
    mode: 'local',
    target: { kind: 'local', label: 'corpus', rootName: 'corpus', fileCount: files.length, viaAgent: false },
    profileId: 'deep',
    engineIds: engines,
    workspace,
    localOnly: true,
    budgetMs: 120_000,
    concurrency: 2,
  });
}

function matchesExpectation(
  findings: ExposureFinding[],
  file: string,
  expectation: PositiveCase['expect'][number],
): boolean {
  return findings.some((finding) => {
    if (!finding.evidence.some((entry) => entry.file === file)) return false;
    const algorithmMatches =
      finding.canonicalAlgorithm === expectation.algorithm ||
      finding.algorithm === expectation.algorithm ||
      finding.title.includes(expectation.algorithm) ||
      (expectation.algorithm === 'random' && /PRNG/i.test(finding.title));
    if (!algorithmMatches) return false;
    if (expectation.quantum && finding.quantumStatus !== expectation.quantum) return false;
    if (expectation.role && finding.role !== expectation.role) return false;
    return true;
  });
}

/* ══════════════════════════════════════════════════════════════════ main ═══ */

async function main(): Promise<void> {
  console.log('\x1b[1mQGuard Helix Scanner — accuracy corpus (§65-§68)\x1b[0m');
  console.log('Offline. All credentials and keys in fixtures are fake.\n');

  checkKnowledgeBase();
  checkTlsIntelligence();
  checkCertificateIntelligence();
  checkGroundTruth();
  checkDecomposerAgreement();

  /* ── positive corpus: recall ──────────────────────────────────────────── */
  section('Positive corpus — recall (§65)');
  const positiveAssessment = await runCorpus(POSITIVE_CORPUS.map((entry) => ({ path: entry.file, content: entry.content })));

  let expectedTotal = 0;
  let found = 0;
  for (const testCase of POSITIVE_CORPUS) {
    for (const expectation of testCase.expect) {
      expectedTotal += 1;
      const hit = matchesExpectation(positiveAssessment.findings, testCase.file, expectation);
      if (hit) found += 1;
      check(
        `${testCase.file} → ${expectation.algorithm}${expectation.role ? ` (${expectation.role})` : ''}`,
        hit,
        hit ? undefined : 'not detected',
      );
    }
  }

  /* ── negative corpus: precision ───────────────────────────────────────── */
  section('Negative corpus — false positives (§66)');
  const negativeAssessment = await runCorpus(NEGATIVE_CORPUS.map((entry) => ({ path: entry.file, content: entry.content })));

  let falsePositives = 0;
  for (const testCase of NEGATIVE_CORPUS) {
    const offending = negativeAssessment.findings.filter(
      (finding) =>
        finding.evidence.some((entry) => entry.file === testCase.file) &&
        finding.severity !== 'info' &&
        finding.severity !== 'low',
    );
    falsePositives += offending.length;
    check(
      `${testCase.file} (${testCase.why})`,
      offending.length === 0,
      offending.length ? offending.map((entry) => `${entry.severity}: ${entry.title}`).join(' | ') : undefined,
    );
  }

  /* ── measured metrics (§67) ───────────────────────────────────────────── */
  section('Measured detection metrics (§67)');

  const truePositives = found;
  const falseNegatives = expectedTotal - found;
  const precision = truePositives + falsePositives > 0 ? truePositives / (truePositives + falsePositives) : 1;
  const recall = expectedTotal > 0 ? truePositives / expectedTotal : 1;

  console.log(`  Corpus: ${POSITIVE_CORPUS.length} positive files, ${NEGATIVE_CORPUS.length} negative files`);
  console.log(`  True positives : ${truePositives}`);
  console.log(`  False negatives: ${falseNegatives}`);
  console.log(`  False positives: ${falsePositives}  (findings above LOW on the negative corpus)`);
  console.log(`  Precision      : ${(precision * 100).toFixed(1)}%`);
  console.log(`  Recall         : ${(recall * 100).toFixed(1)}%`);
  console.log('\n  \x1b[2mThese figures are measured from THIS corpus only. They are not a claim');
  console.log('  about arbitrary real-world code, and must not be published as one.\x1b[0m');

  check('Precision is at least 90% on the defined corpus', precision >= 0.9, `${(precision * 100).toFixed(1)}%`);
  check('Recall is at least 85% on the defined corpus', recall >= 0.85, `${(recall * 100).toFixed(1)}%`);

  /* ── summary ──────────────────────────────────────────────────────────── */
  console.log(`\n\x1b[1m${'═'.repeat(66)}\x1b[0m`);
  if (failed === 0) {
    console.log(`\x1b[32m✓ ${passed} checks passed\x1b[0m`);
    process.exit(0);
  }
  console.log(`\x1b[31m✗ ${failed} of ${passed + failed} checks FAILED\x1b[0m\n`);
  for (const failure of failures) console.log(`  \x1b[31m✗\x1b[0m ${failure}`);
  process.exit(1);
}

/* ─────────────────────────────────────────────────── certificate fixture ──── */

/**
 * Build a structurally valid X.509 DER with an RSA-2048 SPKI.
 *
 * Hand-built so the parser is exercised against exactly the structure it claims
 * to read, with no dependency on a key being generated at check time.
 */
function buildFixtureCertificate(signatureOid = '1.2.840.113549.1.1.11'): Uint8Array {
  const encodeLength = (length: number): number[] => {
    if (length < 0x80) return [length];
    if (length < 0x100) return [0x81, length];
    return [0x82, (length >> 8) & 0xff, length & 0xff];
  };
  const tlv = (tag: number, content: number[]): number[] => [tag, ...encodeLength(content.length), ...content];

  const encodeOid = (oid: string): number[] => {
    const parts = oid.split('.').map(Number);
    const body: number[] = [parts[0] * 40 + parts[1]];
    for (const part of parts.slice(2)) {
      if (part < 128) {
        body.push(part);
        continue;
      }
      const chunks: number[] = [];
      let value = part;
      while (value > 0) {
        chunks.unshift(value & 0x7f);
        value >>= 7;
      }
      for (let index = 0; index < chunks.length - 1; index += 1) chunks[index] |= 0x80;
      body.push(...chunks);
    }
    return tlv(0x06, body);
  };

  /* RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER } */
  const modulus = tlv(0x02, [0x00, ...new Array(256).fill(0xab)]);
  const exponent = tlv(0x02, [0x01, 0x00, 0x01]);
  const rsaKey = tlv(0x30, [...modulus, ...exponent]);
  const bitString = tlv(0x03, [0x00, ...rsaKey]);

  const algorithmId = tlv(0x30, [...encodeOid('1.2.840.113549.1.1.1'), ...tlv(0x05, [])]);
  const spki = tlv(0x30, [...algorithmId, ...bitString]);

  const version = tlv(0xa0, tlv(0x02, [0x02]));
  const serial = tlv(0x02, [0x01, 0x23, 0x45]);
  const sigAlgInner = tlv(0x30, [...encodeOid(signatureOid), ...tlv(0x05, [])]);

  const name = (common: string): number[] =>
    tlv(0x30, tlv(0x31, tlv(0x30, [...encodeOid('2.5.4.3'), ...tlv(0x13, [...common].map((c) => c.charCodeAt(0)))])));

  const issuer = name('QGuard Test CA');
  const subject = name('fixture.example.com');
  const validity = tlv(0x30, [
    ...tlv(0x17, [...'240101000000Z'].map((c) => c.charCodeAt(0))),
    ...tlv(0x17, [...'340101000000Z'].map((c) => c.charCodeAt(0))),
  ]);

  const tbs = tlv(0x30, [...version, ...serial, ...sigAlgInner, ...issuer, ...validity, ...subject, ...spki]);
  const sigAlgOuter = tlv(0x30, [...encodeOid(signatureOid), ...tlv(0x05, [])]);
  const signature = tlv(0x03, [0x00, 0xde, 0xad, 0xbe, 0xef]);

  return Uint8Array.from(tlv(0x30, [...tbs, ...sigAlgOuter, ...signature]));
}

main().catch((error) => {
  console.error('\x1b[31mThe accuracy harness itself failed:\x1b[0m', error);
  process.exit(1);
});
