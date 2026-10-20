/**
 * Exposure detection accuracy check — the defects a real post-quantum codebase
 * exposed, pinned with positive AND negative controls.
 *
 * Every other exposure check ran the pipeline over this repository's own
 * TypeScript, and passed while a scan of QGuard Messaging's Rust crypto (a
 * codebase built on ML-KEM-1024, ML-DSA-65/87, X25519, AES-256-GCM, HKDF and
 * SHA3) published:
 *
 *   • 20 "ElGamal" components — the DSA inside every ML-DSA-87 mention
 *   • every `LocalKemKeypair::generate()` (ML-KEM) as an Ed25519 signature
 *   • `use x25519_dalek` as Ed25519 (a compound "ECC/EdDSA" label resolved to
 *     its longest alias rather than to what the line said)
 *   • "Resistant 0" and no AES/HKDF/SHA3 component at all, because the CBOM
 *     was built from findings and strong primitives raise no finding
 *   • "Config files 8" for 4 files (discovery and the engine both counted them)
 *   • a Coverage panel calling never-measured dimensions "read, none found"
 *   • a "10 highest-priority" action list that was not the 10 most severe
 *   • report registers that promised evidence and actions they did not carry
 *
 *   npx tsx tools/exposure-detection-accuracy-check.ts
 */

import fs from 'node:fs';
import path from 'node:path';
import { CRYPTO_PATTERNS } from '../src/lib/scanner/web-scanner/crypto-patterns';
import { lexicalAlgorithmFor } from '../src/lib/scanner/exposure/content/source-crypto';
import { detectByApi, languageOfPath, prepareDocument } from '../src/lib/scanner/exposure/content/crypto-semantics';
import { runExposureScan } from '../src/lib/scanner/exposure/orchestrator';
import { emptyWorkspace } from '../src/lib/scanner/exposure/engine-contract';
import { toWorkspaceFile } from '../src/lib/scanner/exposure/content/file-discovery';
import { resolveProfile } from '../src/lib/scanner/exposure/profiles';
import { buildCbom, classicalReplacementFor, componentPqcTarget } from '../src/lib/scanner/exposure/cbom';
import { coverageReadings, policyExclusions } from '../src/lib/scanner/exposure/panel-model';
import { RECOMMENDATION_LIMIT, rankRecommendations } from '../src/lib/scanner/exposure/recommendations';
import { computeScores } from '../src/lib/scanner/exposure/risk';
import { emptyCoverage, type CorrelatedExposure, type EngineRun, type ExposureAssessment, type ExposureFinding } from '../src/lib/scanner/exposure/types';
import { buildExposureReport } from '../src/services/reporting/ExposureReport';
import { brandingSchema } from '../src/services/reporting/schemas/ReportSchema';

let passed = 0;
const failures: string[] = [];
function check(ok: boolean, label: string, detail = '') {
  if (ok) {
    passed += 1;
    console.log(`  \x1b[32mok  \x1b[0m ${label}`);
  } else {
    failures.push(`${label}${detail ? ` — ${detail}` : ''}`);
    console.log(`  \x1b[31mFAIL\x1b[0m ${label}${detail ? ` \x1b[2m(${detail})\x1b[0m` : ''}`);
  }
}
const section = (title: string) => console.log(`\n\x1b[36m── ${title} ${'─'.repeat(Math.max(0, 62 - title.length))}\x1b[0m`);

/* ═══════════════════════════════════════════ 1. the DSA catalogue rule ═══ */
section('1. Pattern 65 never reads ML-DSA / SLH-DSA / FN-DSA as DSA');
const dsa = CRYPTO_PATTERNS.find((pattern) => pattern.id === 65)!;
for (const line of [
  'dual-signed Ed25519 + ML-DSA-87', 'SLH-DSA (FIPS 205)', 'FN-DSA-512', 'ml_dsa::MlDsa65', '"pq_signature":"ML-DSA-65"',
  /* identifiers, not algorithm names — noble-post-quantum's own variables */
  'const dsa = (kind === "pk" ? DSA_BY_PK : DSA_BY_SK).get(key.length);', 'for (const [dsa, OMEGA, K] of cases) {',
]) {
  check(!dsa.regex.test(line), `negative: "${line}" is not DSA`);
}
for (const line of ['KeyPairGenerator.getInstance("DSA")', 'new DSACryptoServiceProvider()', 'ElGamal encryption', 'from Crypto.PublicKey import DSA', 'DSA-1024', '-----BEGIN DSA PRIVATE KEY-----']) {
  check(dsa.regex.test(line), `positive: "${line}" still matches`);
}

/* ═════════════════════════════════════ 2. compound catalogue labels ══════ */
section('2. A compound label resolves to what the line actually names');
const resolveOn = (id: number, line: string) => {
  const pattern = CRYPTO_PATTERNS.find((entry) => entry.id === id)!;
  return pattern.regex.test(line) ? lexicalAlgorithmFor(pattern.algorithm, pattern.regex, line) : null;
};
check(resolveOn(65, 'KeyPairGenerator.getInstance("DSA")') === 'DSA', 'DSA/ElGamal + "DSA" → DSA (was ElGamal)', String(resolveOn(65, 'KeyPairGenerator.getInstance("DSA")')));
check(resolveOn(65, 'ElGamal encryption') === 'ElGamal', 'DSA/ElGamal + "ElGamal" → ElGamal');
check(resolveOn(65, 'new DSACryptoServiceProvider()') === 'DSA', 'DSA/ElGamal + "DSACryptoServiceProvider" → DSA');
const eccLabel = CRYPTO_PATTERNS.find((pattern) => pattern.algorithm === 'ECC/EdDSA');
if (eccLabel) {
  const resolved = lexicalAlgorithmFor(eccLabel.algorithm, eccLabel.regex, 'use x25519_dalek::{EphemeralSecret, StaticSecret};');
  check(resolved === 'X25519', 'ECC/EdDSA + "use x25519_dalek" → X25519 (was Ed25519)', resolved);
}
check(lexicalAlgorithmFor('RSA', /RSA/, 'RSA') === 'RSA', 'a single-algorithm label is returned unchanged');
check(lexicalAlgorithmFor('PGP/GPG', /gpg/i, 'gpg --sign') === 'PGP/GPG', 'a label naming no known algorithm is left as written');

/* ═════════════════════════════════════════ 3. the Rust Ed25519 API rule ═══ */
section('3. Rust API rules need a word boundary');
const apiAlgorithms = (source: string) =>
  detectByApi(prepareDocument('src/k.rs', source, languageOfPath('src/k.rs'))).map((entry) => entry.classification.canonicalName);
check(!apiAlgorithms('let kem = LocalKemKeypair::generate();').includes('Ed25519'), 'negative: LocalKemKeypair::generate() is not Ed25519');
check(!apiAlgorithms('let s = VaultSigningKeypair::generate();').includes('Ed25519'), 'negative: VaultSigningKeypair::generate() is not Ed25519');
check(apiAlgorithms('let key = SigningKey::generate(&mut OsRng);').includes('Ed25519'), 'positive: SigningKey::generate() is Ed25519');
check(apiAlgorithms('let vk = ed25519_dalek::VerifyingKey::from_bytes(&b);').includes('Ed25519'), 'positive: ed25519_dalek:: is Ed25519');

/* ═══════════════════════════════════════════ 4. a real scan, end to end ═══ */
section('4. Strong primitives reach the CBOM; coverage is not double-counted');
const corpus = [
  toWorkspaceFile('src/crypto.rs', [
    'use aes_gcm::{Aes256Gcm, KeyInit};',
    'use hkdf::Hkdf;',
    'use sha3::Sha3_256;',
    'use x25519_dalek::{EphemeralSecret, PublicKey};',
    'pub fn seal(key: &[u8]) { let cipher = Aes256Gcm::new(key.into()); }',
    'pub fn derive(ikm: &[u8]) { let hk = Hkdf::<Sha3_256>::new(None, ikm); }',
    '/// dual-signed Ed25519 + ML-DSA-87 (FIPS 204)',
    'pub fn kem() { let kp = LocalKemKeypair::generate(); }',
  ].join('\n')),
  toWorkspaceFile('config/app.json', '{"tls": {"minVersion": "TLSv1.2"}}'),
  toWorkspaceFile('config/service.yaml', 'server:\n  port: 8443\n  tls: true\n'),
];
const { engines } = resolveProfile('local', 'deep');
const workspace = emptyWorkspace();
workspace.files = corpus;
const assessment = await runExposureScan({
  scanId: 'accuracy-check',
  mode: 'local',
  target: { kind: 'local', label: 'fixture', rootName: 'fixture', fileCount: corpus.length, viaAgent: false },
  profileId: 'deep',
  engineIds: engines,
  workspace,
  localOnly: true,
});

const algorithms = new Set(assessment.cbom.map((component) => component.canonicalAlgorithm));
check(!algorithms.has('ElGamal'), 'no ElGamal component from an ML-DSA-87 comment', [...algorithms].join(', '));
check(algorithms.has('X25519'), 'X25519 is inventoried as X25519', [...algorithms].join(', '));
check(algorithms.has('AES'), 'AES-256-GCM reaches the CBOM although it raises no finding');
check(assessment.cbom.some((component) => component.quantumStatus === 'resistant'), 'the resistant bucket is populated by real components');
check(
  !assessment.findings.some((finding) => finding.category === 'Cryptographic Inventory'),
  'inventory observations are never counted as findings',
);
check((assessment.inventory?.length ?? 0) > 0, `the assessment carries its inventory observations (${assessment.inventory?.length ?? 0})`);
check(
  buildCbom([...assessment.findings, ...(assessment.inventory ?? [])]).length === assessment.cbom.length,
  'the sync re-derivation (findings + inventory) rebuilds exactly the CBOM on screen',
);
check(
  buildCbom(assessment.findings).length < assessment.cbom.length,
  'negative control: findings alone rebuild a SMALLER CBOM — the gap the inventory closes',
);
const configFiles = corpus.filter((file) => file.classification === 'config').length;
check(
  assessment.task.coverage.configFiles === configFiles,
  `config files are counted once (${assessment.task.coverage.configFiles} reported, ${configFiles} in the corpus)`,
);
check(
  policyExclusions(assessment.task.coverage).every((entry) => !/^Binary files/i.test(entry)),
  'the binary-files statement is not presented as an exclusion rule',
);
check(
  !assessment.findings.some((finding) => /-255 on Ed25519/.test(finding.title)),
  'titles do not restate a size or curve the algorithm name already carries',
);

/* ═══════════════════════════════════════════ 5. coverage readings ═══════ */
section('5. A zero is a measurement only when its engine reported');
const run = (engineId: string, state: EngineRun['state']): EngineRun => ({
  engineId, label: engineId, state, progress: 100, startedAt: null, completedAt: null, findingCount: 0,
});
const readingFor = (key: string, runs: EngineRun[]) =>
  coverageReadings(emptyCoverage(), runs).find((reading) => reading.key === key)!.state;
check(readingFor('cloudResources', [run('file-discovery', 'completed')]) === 'not-selected', 'no cloud engine in the run → "outside this profile"');
check(readingFor('containers', [run('container-security', 'failed')]) === 'not-reported', 'a failed engine → "not measured", never a zero');
check(readingFor('containers', [run('container-security', 'not-applicable')]) === 'measured-zero', 'nothing in scope to read → a measured zero');
check(readingFor('configFiles', [run('configuration-security', 'completed')]) === 'measured-zero', 'a completed engine that counted none → a measured zero');
check(
  coverageReadings({ ...emptyCoverage(), secrets: 3 }, []).find((reading) => reading.key === 'secrets')!.state === 'measured',
  'a positive count is always a measurement',
);

/* ═════════════════════════════════════ 5b. quantum risk vs readiness ═════ */
section('5b. Quantum risk and readiness share one population');
{
  const evidence = [{ summary: 'fixture', observedAt: '2026-10-14T00:00:00.000Z' }];
  /* A library that is overwhelmingly post-quantum: 51 PQC components in four
     algorithm families, 7 classical components in seven. Weighed by exposure,
     the seven classical algorithms outnumbered the four PQC families and the
     estate read "Quantum risk 74 — high" beside "Readiness 88%". */
  const component = (id: string, algorithm: string, status: 'pqc' | 'vulnerable', usage: 'signature' | 'key-exchange') => ({
    id, algorithm, canonicalAlgorithm: algorithm, usage, confidence: 'high', detection: 'observed', quantumStatus: status, layer: 'source', evidence,
  }) as const;
  const components = [
    ...Array.from({ length: 51 }, (_, index) => component(`p${index}`, ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'FN-DSA (Falcon)'][index % 4], 'pqc', index % 4 === 0 ? 'key-exchange' : 'signature')),
    ...['ECDSA', 'Ed25519', 'DSA', 'X25519', 'RSA', 'ECDH', 'SM2'].map((name, index) => component(`v${index}`, name, 'vulnerable', 'signature')),
  ].map((entry) => ({ ...entry, evidence: [...entry.evidence] }));
  const exposureOf = (name: string, status: 'pqc' | 'vulnerable'): CorrelatedExposure => ({
    key: name, title: name, severity: status === 'pqc' ? 'info' : 'medium', confidence: 'high', quantumStatus: status, canonicalAlgorithm: name,
    role: 'signature', layers: ['source'], findingIds: [name], evidence,
  });
  const byExposure = [
    ...['ML-KEM', 'ML-DSA', 'SLH-DSA', 'FN-DSA (Falcon)'].map((name) => exposureOf(name, 'pqc')),
    ...['ECDSA', 'Ed25519', 'DSA', 'X25519', 'RSA', 'ECDH', 'SM2'].map((name) => exposureOf(name, 'vulnerable')),
  ];
  const base = { findings: [] as ExposureFinding[], exposures: byExposure, coverage: emptyCoverage(), runs: [] as EngineRun[] };
  const scored = computeScores({ ...base, components: components as never });
  const legacy = computeScores(base);
  check((scored.quantumRisk ?? 100) < 35, `component-weighted quantum risk agrees with ~88% readiness (${scored.quantumRisk})`);
  check(/quantum-relevant components/.test(scored.basis[1]), 'the basis names its unit: components');
  check((legacy.quantumRisk ?? 0) >= 60, `negative control: the exposure-weighted figure that read "high" (${legacy.quantumRisk})`);
}

/* ═══════════════════════════════════════════ 6. recommendation ranking ═══ */
section('6. The action list is ranked once, most severe first');
const evidence = [{ summary: 'fixture', observedAt: '2026-10-14T00:00:00.000Z' }];
const finding = (id: string, severity: ExposureFinding['severity'], candidate: boolean, recommendation: string): ExposureFinding => ({
  id, scanId: 's', engineId: 'source-crypto', mode: 'local', layer: 'source', category: 'Cryptographic Usage', title: id,
  description: id, severity, confidence: 'high', detection: 'observed', quantumStatus: candidate ? 'vulnerable' : 'unknown',
  recommendation, evidence, firstSeen: evidence[0].observedAt, lastSeen: evidence[0].observedAt,
  migration: candidate ? { candidate: true, complexity: 'medium' } : { candidate: false },
});
const findings: ExposureFinding[] = [finding('urgent-high', 'high', false, 'Rotate the committed key')];
const exposures: CorrelatedExposure[] = [];
for (let index = 0; index < 12; index += 1) {
  const item = finding(`crit-${index}`, 'critical', true, `Migrate component ${index}`);
  findings.push(item);
  exposures.push({
    key: item.id, title: item.title, severity: 'critical', confidence: 'high', quantumStatus: 'vulnerable',
    layers: ['source'], findingIds: [item.id], evidence, recommendation: item.recommendation, migration: item.migration,
  });
}
const ranked = rankRecommendations({ findings, exposures });
check(ranked.length === 13, `every distinct action is ranked (${ranked.length})`);
check(
  ranked.slice(0, RECOMMENDATION_LIMIT).every((entry) => entry.severity === 'critical'),
  'the first ten are the ten most severe — a HIGH urgent action no longer sits above CRITICAL ones',
);
check(ranked[ranked.length - 1].title === 'Rotate the committed key', 'the urgent HIGH action is still listed, at its severity');
const tieFindings = [finding('urgent-crit', 'critical', false, 'Revoke the leaked token'), ...findings.slice(1, 3)];
const tie = rankRecommendations({ findings: tieFindings, exposures: exposures.slice(0, 2) });
check(tie[0].title === 'Revoke the leaked token', 'within one severity, urgent present-tense work comes first');

/* ═══════════════════════════════════════════ 7. the exported report ═════ */
section('7. The report registers carry what the document promises');
const repoAssessment = JSON.parse(JSON.stringify(assessment)) as ExposureAssessment;
const report = buildExposureReport({
  assessment: repoAssessment,
  template: 'remediation',
  depth: 'summary',
  branding: brandingSchema.parse({}),
  generatedBy: 'accuracy-check',
  generatedAt: '2026-10-14T00:00:00.000Z',
});
const table = (title: string) => report.tables.find((entry) => entry.title === title);
const evidenceRows = assessment.exposures.reduce((sum, exposure) => sum + exposure.evidence.length, 0);
check((table('Exposure Evidence')?.rows.length ?? 0) === evidenceRows, `the Exposure Evidence register holds every evidence record (${evidenceRows})`);
const actions = rankRecommendations({ findings: assessment.findings, exposures: assessment.exposures });
check(
  (table('Engine Recommendations')?.rows.length ?? 0) === (actions.length || 0),
  `the action register is the complete ranked list (${actions.length}), not the panel's ten`,
);
check(
  assessment.intelligence.recommendations.every((entry, index) => actions[index]?.title === entry.title),
  "the panel's actions are the register's leading rows, in order",
);
check(report.reconciliation.every((row) => row.matches), 'every reconciliation row in the document matches', report.reconciliation.filter((row) => !row.matches).map((row) => row.metric).join('; '));
const cbomRegister = table('Cryptographic Bill of Materials')!;
const targetAt = cbomRegister.columns.indexOf('Post-quantum target');
const idAt = cbomRegister.columns.indexOf('Component ID');
const withTarget = assessment.cbom.filter((component) => component.migrationTarget);
check(
  withTarget.every((component) => cbomRegister.rows.find((row) => row[idAt] === component.id)?.[targetAt] === component.migrationTarget),
  `the CBOM register prints the engine's recorded target verbatim (${withTarget.length} components)`,
);
const ledger = table('Coverage Ledger')!;
check(ledger.columns.includes('Reading'), 'the coverage ledger states what each count means');
check(
  ledger.rows.some((row) => String(row[2]).startsWith('Outside this profile')) === coverageReadings(assessment.task.coverage, assessment.task.runs).some((reading) => reading.state === 'not-selected'),
  'the ledger and the panel classify the same zeros the same way',
);
const md5 = { id: 'md5', algorithm: 'MD5', canonicalAlgorithm: 'MD5', usage: 'hashing', confidence: 'high', detection: 'observed', quantumStatus: 'resistant', layer: 'source', evidence } as const;
check(classicalReplacementFor({ ...md5, evidence: [...evidence] }) === 'SHA-256 or SHA3-256', 'a classically broken hash names its classical replacement');
check(componentPqcTarget({ ...md5, evidence: [...evidence] }) === undefined, 'and no post-quantum target, because it needs none');

/* ═══════════════════════════════════════════ 8. Dev CBOM export path ════ */
section('8. Dev CBOM exports never navigate to an authenticated route');
const devPanel = fs.readFileSync(path.join(import.meta.dirname, '..', 'src', 'components', 'exposure', 'DevAssessmentPanel.tsx'), 'utf8');
check(!/\/api\/v1\/exposure\/scans\/[^\n]*\/cbom/.test(devPanel), 'no Dev export links to /exposure/scans/:id/cbom (a navigation carries no bearer token → 401)');
check(/exportCbomFile\(/.test(devPanel), 'Dev exports the CBOM through the shared client-side exporter');

/* ════════════════════════════════════════════════════════════════════ */
console.log(`\n${failures.length === 0 ? '\x1b[32m✓' : '\x1b[31m✗'} ${passed} passed, ${failures.length} failed\x1b[0m`);
if (failures.length) {
  for (const failure of failures) console.log(`  - ${failure}`);
  process.exit(1);
}
