/**
 * Scanner_2 accuracy — offline verification of the enterprise pass.
 *
 * WHAT THIS TOOL EXISTS TO PREVENT
 * --------------------------------
 * A scan of `www.google.com` — hybrid X25519MLKEM768 key agreement measured at
 * 100% confidence, an ECDSA P-256 leaf, an RSA-2048 issuer — published this on
 * the Quantum Posture card:
 *
 *   Asset readiness · Scanner_2   19% · Critical Risk
 *   Risk aggregate · Scanner_2    749 · moderate-risk
 *   Severity split · Scanner_2    8C · 3H · 1M · 4L
 *   Harvest-now exposure          8 asset(s) · key agreement protected
 *
 * Four rows, four defects:
 *
 *  1. Six of the eight harvest-now records claimed **RSA-1024** — an algorithm
 *     that appears nowhere on that endpoint. The bit-size regex made its
 *     algorithm prefix optional and took the first 3-4 digit run in the string,
 *     so `AES_128` and `SHA256` were read as the RSA modulus.
 *  2. "8 asset(s)" was eight OBSERVATIONS on one asset, and "19% · Critical
 *     Risk" was a readiness percentage wearing a risk label, computed over
 *     findings while the detail line called them "inventoried asset(s)".
 *  3. "749 · moderate-risk" was 65% constant: five of the seven risk categories
 *     were never scanned and each was scored a passing 850 at full weight.
 *  4. The finding risk scale was mixed. The API adapter emitted 0-100, the
 *     detection rules 0-1000, and the merge compared them with `>` — so a rule
 *     hit always won and the enriched set carried both scales at once.
 *
 * Run: npx tsx tools/scanner2-accuracy-check.ts
 */
import { normalizeToScanner2Algorithm } from '../src/lib/scanner/scanner_2/algorithm-normalizer';
import { calculateQuantumRiskScore } from '../src/lib/scanner/scanner_2/engine/risk-scoring';
import { calculateQuantumReadiness } from '../src/lib/scanner/scanner_2/pqc-migration-engine';
import { analyzeHNDLRisks } from '../src/lib/scanner/scanner_2/hndl-analyzer';
import { buildQuantumRiskAssessment } from '../src/lib/scanner/scanner_2/correlation-engine';
import type { ScanFinding } from '../src/types/scanner.types';

let passed = 0;
const failures: string[] = [];

function check(label: string, condition: boolean, detail?: string): void {
  if (condition) {
    passed += 1;
    console.log(`  ok   ${label}`);
    return;
  }
  failures.push(`${label}${detail ? ` — ${detail}` : ''}`);
  console.log(`  FAIL ${label}${detail ? ` — ${detail}` : ''}`);
}

function section(title: string): void {
  console.log(`\n\x1b[36m── ${title} ${'─'.repeat(Math.max(0, 58 - title.length))}\x1b[0m`);
}

/* ═════════════════════════════════════════ 1. algorithm normalization ═════ */

function checkAlgorithmNormalization(): void {
  section('Algorithm normalization never invents a key size');

  /* Every one of these was published as RSA-1024, the most alarming classical
     key size in the model, on endpoints carrying no 1024-bit key at all. */
  const noPhantom: Array<[string, string]> = [
    ['TLS_RSA_WITH_AES_128_GCM_SHA256', 'RSA-2048'],
    ['TLS_RSA_WITH_AES_256_GCM_SHA384', 'RSA-2048'],
    ['TLS_RSA_WITH_AES_128_CBC_SHA', 'RSA-2048'],
    ['TLS_RSA_WITH_AES_256_CBC_SHA', 'RSA-2048'],
    ['sha256WithRSAEncryption', 'RSA-2048'],
    ['sha1WithRSAEncryption', 'RSA-2048'],
  ];
  for (const [input, expected] of noPhantom) {
    const got = normalizeToScanner2Algorithm(input);
    check(`"${input}" → ${expected}`, got === expected, String(got));
  }

  /* A suite is four decisions wearing one name, and the KEY EXCHANGE is the one
     Shor breaks retroactively. `TLS_ECDHE_RSA_...` is forward secret; filing it
     as an RSA key transport misstated both the mechanism and the remedy. */
  section('Cipher suites are classified by their key exchange');
  const byKeyExchange: Array<[string, string]> = [
    ['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'ECC-P256'],
    ['TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'ECC-P256'],
    ['TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'ECC-P256'],
    ['TLS_DHE_RSA_WITH_AES_128_CBC_SHA', 'DH-2048'],
    ['TLS_AES_256_GCM_SHA384', 'AES-256'],
    ['TLS_AES_128_GCM_SHA256', 'AES-128'],
  ];
  for (const [input, expected] of byKeyExchange) {
    const got = normalizeToScanner2Algorithm(input);
    check(`"${input}" → ${expected}`, got === expected, String(got));
  }

  section('A stated key size is still read');
  for (const [input, expected] of [
    ['RSA-1024', 'RSA-1024'],
    ['1024 bit RSA', 'RSA-1024'],
    ['RSA-2048', 'RSA-2048'],
    ['rsaEncryption 2048', 'RSA-2048'],
    ['RSA-4096', 'RSA-4096'],
    ['Diffie-Hellman 1024', 'DH-1024'],
  ] as const) {
    const got = normalizeToScanner2Algorithm(input);
    check(`"${input}" → ${expected}`, got === expected, String(got));
  }

  /* A hybrid group is not a classical algorithm. `X25519MLKEM768` contains
     "x25519", so the measured proof that the endpoint is PROTECTED was filed as
     a Shor-breakable key agreement and counted as an asset requiring migration —
     lowering readiness because the endpoint had deployed post-quantum crypto. */
  section('Post-quantum primitives leave the classical model');
  for (const input of ['X25519MLKEM768', 'ML-KEM-768 (FIPS 203)', 'ML-DSA-65', 'SecP256r1MLKEM768', 'X25519Kyber768']) {
    const got = normalizeToScanner2Algorithm(input);
    check(`"${input}" is not classified as a classical algorithm`, got === null, String(got));
  }
}

/* ═══════════════════════════════════════════════ 2. one risk scale ════════ */

function finding(overrides: Partial<ScanFinding> & { moduleId: string; riskScore: number }): ScanFinding {
  return {
    id: `f-${Math.random().toString(36).slice(2)}`,
    scanId: 'scan-1',
    target: { id: 't1', name: 'www.example.com', type: 'cloud-infrastructure', metadata: {} },
    detectedAlgorithm: 'RSA-2048',
    algorithmCategory: 'public-key',
    threatLevel: 'high',
    quantumThreat: 'shor',
    isHNDLRisk: true,
    description: 'observed',
    recommendation: 'migrate',
    quantumBreakTime: 'hours',
    classicalBreakTime: 'years',
    severity: 'high',
    pqcReplacement: 'ML-KEM-768',
    evidence: {} as ScanFinding['evidence'],
    remediation: {} as ScanFinding['remediation'],
    timestamp: new Date().toISOString(),
    ...overrides,
  } as ScanFinding;
}

function checkRiskScale(): void {
  section('The risk aggregate scores only what was measured');

  /* A web scan reaches `networks` (tls-/cert-/dns- module prefixes) and
     `applications` (everything else). Devices, cloud, blockchain, telecom and
     infrastructure — 0.65 of the model's weight — are never observed. */
  const webScan = [
    finding({ moduleId: 'tls-cipher-suite-scanner', riskScore: 950, severity: 'critical', threatLevel: 'critical' }),
    finding({ moduleId: 'tls-cipher-suite-scanner', riskScore: 950, severity: 'critical', threatLevel: 'critical' }),
    finding({ moduleId: 'cert-authority-trust-scanner', riskScore: 820 }),
    finding({ moduleId: 'app-crypto-library-scanner', riskScore: 550, severity: 'moderate', threatLevel: 'medium' }),
  ];
  const risk = calculateQuantumRiskScore(webScan);

  check(
    'unobserved categories are reported, not scored',
    risk.measuredCategories.length === 2 &&
      risk.measuredCategories.includes('networks') &&
      risk.measuredCategories.includes('applications'),
    risk.measuredCategories.join(', '),
  );
  check(
    'the measured weight is published so the number can be read for what it is',
    Math.abs(risk.measuredWeight - 0.35) < 0.001,
    String(risk.measuredWeight),
  );
  /* The load-bearing assertion. With the old constant the five unscanned
     categories contributed 0.65 × 850 = 552 all by themselves, so this set
     could not score below 552 however bad the evidence was. */
  check(
    'a critical web surface cannot be lifted into "moderate-risk" by categories nobody scanned',
    risk.overall < 700,
    `overall=${risk.overall} level=${risk.level}`,
  );
  const expected = Math.round(((1000 - 906.67) * 0.2 + (1000 - 550) * 0.15) / 0.35);
  check(
    'the aggregate is the weighted mean over measured categories only',
    Math.abs(risk.overall - expected) <= 2,
    `overall=${risk.overall} expected≈${expected}`,
  );

  section('Nothing measured means nothing claimed');
  const empty = calculateQuantumRiskScore([]);
  check('an empty run measures no category', empty.measuredCategories.length === 0);
  check('an empty run reports zero measured weight', empty.measuredWeight === 0, String(empty.measuredWeight));

  section('Findings arrive on one scale');
  /* `1000 - avgRisk` is only meaningful if every riskScore is on the 0-1000
     scale. When the adapter emitted 0-100 and the rules 0-1000, an unmatched
     finding scored ~950 ("safe") and a matched one ~50 ("catastrophic") from
     identical evidence. */
  const mixed = calculateQuantumRiskScore([
    finding({ moduleId: 'tls-x', riskScore: 950, severity: 'critical', threatLevel: 'critical' }),
  ]);
  check(
    'a critical finding on the 0-1000 scale drives its category low',
    mixed.breakdown.networks <= 100,
    String(mixed.breakdown.networks),
  );

  section('Attack classification reads the same scale it is given');
  /* Thresholds were 80/60/40 — the 0-100 ladder applied to a 0-1000 average, so
     this returned CRITICAL for effectively every finding set it ever saw. */
  const safeAssessment = buildQuantumRiskAssessment([
    finding({ moduleId: 'tls-x', riskScore: 120, severity: 'low', threatLevel: 'low' }),
    finding({ moduleId: 'tls-y', riskScore: 150, severity: 'low', threatLevel: 'low' }),
  ]);
  check(
    'a low-risk finding set is not classified CRITICAL',
    safeAssessment.classification === 'LOW',
    safeAssessment.classification,
  );
  const gravelyExposed = buildQuantumRiskAssessment([
    finding({ moduleId: 'tls-x', riskScore: 950, severity: 'critical', threatLevel: 'critical' }),
    finding({ moduleId: 'tls-y', riskScore: 920, severity: 'critical', threatLevel: 'critical' }),
  ]);
  check(
    'a genuinely critical finding set still classifies CRITICAL',
    gravelyExposed.classification === 'CRITICAL',
    gravelyExposed.classification,
  );
}

/* ═════════════════════════════════════ 3. readiness counts its population ═ */

function checkReadinessPopulation(): void {
  section('Readiness names the population it counts');

  const oneAssetManyObservations = [
    { detectedAlgorithm: 'RSA-2048', threatLevel: 'critical', riskScore: 950, target: { name: 'www.example.com' } },
    { detectedAlgorithm: 'RSA-2048', threatLevel: 'critical', riskScore: 950, target: { name: 'www.example.com' } },
    { detectedAlgorithm: 'ECC-P256', threatLevel: 'high', riskScore: 820, target: { name: 'www.example.com' } },
    { detectedAlgorithm: 'AES-256', threatLevel: 'safe', riskScore: 50, target: { name: 'www.example.com' } },
  ];
  const readiness = calculateQuantumReadiness(oneAssetManyObservations);

  /* The row read "3 of 16 inventoried asset(s)" on a tenant with ONE asset,
     because `totalAssets` held the finding count. */
  check(
    'a single-asset scan reports ONE asset, however many observations it made',
    readiness.totalAssets === 1,
    `totalAssets=${readiness.totalAssets}`,
  );
  check(
    'the observation counts are reported separately and are not asset counts',
    readiness.totalFindings === 4 && readiness.quantumSafeFindings === 1,
    `${readiness.quantumSafeFindings}/${readiness.totalFindings}`,
  );
  check(
    'an asset with an observation requiring migration is not counted quantum-safe',
    readiness.quantumSafeAssets === 0,
    String(readiness.quantumSafeAssets),
  );

  /* Three readiness labels and two RISK labels on one scale is how "19% ·
     Critical Risk" came to sit two rows above "749 · moderate-risk". */
  section('Readiness bands are readiness labels, never risk levels');
  for (const scoreCase of [0, 10, 25, 45, 65, 85, 100]) {
    const findings = Array.from({ length: 100 }, (_, index) => ({
      detectedAlgorithm: index < scoreCase ? 'AES-256' : 'RSA-2048',
      threatLevel: 'high',
      riskScore: 820,
      target: { name: 'www.example.com' },
    }));
    const band = calculateQuantumReadiness(findings);
    check(
      `readiness ${band.score}% is labelled "${band.label}", not a risk level`,
      !/risk/i.test(band.label),
      band.label,
    );
  }

  section('An empty run is not "fully quantum-ready"');
  const nothing = calculateQuantumReadiness([]);
  check('nothing scored → not assessed', nothing.notAssessed === true && nothing.label === 'Not assessed', nothing.label);
  check('nothing scored → no 100% claimed', nothing.score === 0, String(nothing.score));
}

/* ══════════════════════════════════════════ 4. harvest-now is per finding ═ */

function checkHndlPopulation(): void {
  section('Harvest-now records are observations, not assets');

  const findings = [
    finding({ moduleId: 'tls-a', riskScore: 950, detectedAlgorithm: 'RSA-2048' }),
    finding({ moduleId: 'tls-b', riskScore: 950, detectedAlgorithm: 'RSA-2048' }),
    finding({ moduleId: 'tls-c', riskScore: 820, detectedAlgorithm: 'ECC-P256' }),
  ];
  const hndl = analyzeHNDLRisks(findings);
  check('one record per observation', hndl.length === 3, String(hndl.length));
  const assets = new Set(hndl.map((item) => item.targetName));
  check(
    'every record carries its target, so the asset population is recoverable',
    assets.size === 1 && assets.has('www.example.com'),
    Array.from(assets).join(', '),
  );
  check(
    'no phantom RSA-1024 reaches the harvest-now list',
    hndl.every((item) => item.algorithm !== 'RSA-1024'),
    hndl.map((item) => item.algorithm).join(', '),
  );
}

/* ═══════════════════════════════════════════════════════════════ run ══════ */

checkAlgorithmNormalization();
checkRiskScale();
checkReadinessPopulation();
checkHndlPopulation();

console.log('\n══════════════════════════════════════════════════════════════════');
if (failures.length > 0) {
  console.log(`\x1b[31m✗ ${failures.length} check(s) FAILED\x1b[0m`);
  for (const failure of failures) console.log(`   • ${failure}`);
  process.exit(1);
}
console.log(`\x1b[32m✓ ${passed} Scanner_2 accuracy checks passed\x1b[0m`);
