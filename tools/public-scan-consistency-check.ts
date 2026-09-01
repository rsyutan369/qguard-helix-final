/**
 * /public-scan panel consistency — offline verification.
 *
 * The Web tab on the DASHBOARD had three panels each computing forward secrecy
 * from its own fallback chain, so one page published "Not offered", "Not
 * observed" and 100 simultaneously. That was fixed by a shared reconciler.
 *
 * `/public-scan` is built differently and better: `assess.ts` evaluates the
 * control set exactly once and every panel is a projection of that array. This
 * tool proves that property actually holds — and checks the places where a
 * projection can still drift from its source:
 *
 *   1. The Cryptographic Intelligence panel restates several control verdicts
 *      in its own vocabulary. Those restatements must agree with the controls.
 *   2. The Encryption Score is a weighted sum. It must equal its own parts.
 *   3. Unmeasured dimensions must not be scored as failures anywhere.
 *   4. `Not measured` and `Not observed` must stay distinct — one means the
 *      handshake was read and carried no ephemeral key, the other means no
 *      handshake was read at all.
 *
 * Run: npx tsx tools/public-scan-consistency-check.ts
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildControlStates, resolveForwardSecrecy } from '../src/lib/scanner/public-scan/controls';
import {
  buildExecutiveSummary,
  buildIntelligence,
  computePostQuantumReadiness,
  toAttackSurface,
  toFindings,
} from '../src/lib/scanner/public-scan/engine';
import { buildScoreCategories, SCORE_CATEGORY_DEFS } from '../src/lib/scanner/public-scan/grading-model';
import type { PublicScanEvidence } from '../src/lib/scanner/public-scan/types';

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
  console.log(`\n\x1b[36m── ${title} ${'─'.repeat(Math.max(0, 56 - title.length))}\x1b[0m`);
}

/* ══════════════════════════════════════════════════════════════ fixtures ═══ */

/**
 * Evidence in the four states that matter.
 *
 * Fields the assessor does not read are elided with a cast — the point is the
 * OBSERVATION STATE, not a faithful copy of every engine's output.
 */
function evidenceFor(state: 'tls13-hybrid' | 'tls13-classical' | 'tls12-static-rsa' | 'no-handshake'): PublicScanEvidence {
  const noHandshake = state === 'no-handshake';
  const tls13 = state === 'tls13-hybrid' || state === 'tls13-classical';

  const tls = noHandshake
    ? null
    : {
        tlsVersion: tls13 ? 'TLSv1.3' : 'TLSv1.2',
        cipherSuite: tls13 ? 'TLS_AES_256_GCM_SHA384' : 'TLS_RSA_WITH_AES_256_GCM_SHA384',
        keyExchange: tls13 ? 'ECDHE (TLS 1.3 key_share)' : 'RSA',
        signatureAlgorithm: 'ecdsa-with-SHA384',
        supportedProtocols: tls13 ? ['TLSv1.3'] : ['TLSv1.2'],
        protocolSupport: [],
        negotiatedCurve: null,
        serverName: 'fixture.example',
        peerCertificate: null,
        cipherSuites: [],
        ephemeralKeyType: null,
        ephemeralKeySize: null,
      };

  const cipherSuites =
    state === 'tls12-static-rsa'
      ? ([{ name: 'TLS_RSA_WITH_AES_256_GCM_SHA384', standardName: 'TLS_RSA_WITH_AES_256_GCM_SHA384', category: 'rsa-kex' }] as never)
      : ([] as never);

  return {
    tls,
    certificate: null,
    certificateExtras: null,
    cipherSuites,
    keyAgreement: {
      probed: state === 'tls13-hybrid' || state === 'tls13-classical',
      hybridGroups: state === 'tls13-hybrid' ? ['X25519MLKEM768'] : [],
      pureKemGroups: [],
      classicalGroups: state === 'tls13-classical' ? ['X25519'] : [],
      primaryGroup: state === 'tls13-hybrid' ? 'X25519MLKEM768' : state === 'tls13-classical' ? 'X25519' : null,
      forwardSecrecy: !noHandshake && state !== 'tls12-static-rsa',
      forwardSecrecyBasis: noHandshake ? '' : 'ephemeral key agreement measured',
    } as never,
    /* Filled out enough for every control to run. The states below vary the
       TRANSPORT observation only; DNS and HTTP are held constant and unprobed
       so a difference between two rows can only come from the transport. */
    dns: {
      addresses: [],
      addressCount: 0,
      caaPresent: false,
      caaQueryable: false,
      caaRecords: [],
      dnssecQueryable: false,
      dnssecSigned: false,
      dnssecValidated: false,
      dkimSelectorsFound: [],
      dmarc: null,
      spf: null,
      mailExchangers: [],
      resolvedVia: null,
      error: 'not probed in this fixture',
    } as never,
    http: {
      reachable: false,
      headers: [],
      fingerprint: { signals: [] },
      error: 'not probed in this fixture',
    } as never,
    timing: {} as never,
    port: 443,
    alpn: null,
    /* The engine bundle. Only the fields the control set reads are populated,
       and the TLS branch is what varies between states. */
    engines: {
      host: 'fixture.example',
      tls: {
        ok: !noHandshake,
        data: {
          handshake: !noHandshake,
          alpn: null,
          alpnOffered: [],
          http2: false,
        },
      },
      certificate: { data: { hostnameMatches: null, sanCount: 0 } },
      dns: {
        data: {
          dnssecQueryable: false,
          dnssecSigned: false,
          dnssecValidated: false,
          dkimSelectorsFound: [],
          dmarc: null,
          spf: null,
          mailExchangers: [],
        },
      },
      http: { data: { reachable: false, fingerprint: { signals: [] } } },
      crypto: {
        data: {
          algorithms: [],
          assessed: !noHandshake,
          notAssessedReason: noHandshake ? 'No TLS handshake was completed for this target.' : null,
          quantumRisk: noHandshake ? null : 'High',
          riskFactors: [],
          migrationTargets: [],
        },
      },
    } as never,
  } as PublicScanEvidence;
}

const STATES = ['tls13-hybrid', 'tls13-classical', 'tls12-static-rsa', 'no-handshake'] as const;

/* ══════════════════════════ 1. panels project the SAME control array ═══════ */

function checkProjection(): void {
  section('Every panel is a projection of one control array');

  for (const state of STATES) {
    const evidence = evidenceFor(state);
    const controls = buildControlStates(evidence);
    const findings = toFindings(controls);
    const surface = toAttackSurface(controls);

    /* A finding or a surface row that names a control the array does not
       contain is a panel inventing its own row. */
    const controlKeys = new Set(controls.map((entry) => entry.key));
    check(
      `${state}: every attack-surface row comes from a control`,
      surface.every((row) => controlKeys.has(row.key)),
      surface.filter((row) => !controlKeys.has(row.key)).map((row) => row.key).join(', '),
    );
    check(
      `${state}: findings never outnumber the controls that produced them`,
      findings.length <= controls.length,
      `${findings.length} findings from ${controls.length} controls`,
    );
  }
}

/* ══════════════════════ 2. the intelligence panel agrees with the controls ══ */

function checkIntelligenceAgreesWithControls(): void {
  section('Cryptographic Intelligence restates the controls faithfully');

  for (const state of STATES) {
    const evidence = evidenceFor(state);
    const controls = buildControlStates(evidence);
    const intelligence = buildIntelligence(evidence, 80);
    const fsControl = controls.find((entry) => entry.key === 'forward-secrecy');

    check(`${state}: a forward-secrecy control exists`, Boolean(fsControl));
    if (!fsControl) continue;

    /* The panel and the control must not disagree about whether the fact was
       measured at all. This is the pairing that used to break: the control
       correctly said "Unknown" for an endpoint that never answered, while the
       panel said "Not observed" — a measured absence. */
    const controlUnknown = fsControl.status === 'Unknown';
    const panelUnmeasured = intelligence.forwardSecrecy === 'Not measured';
    check(
      `${state}: control "Unknown" ⟺ panel "Not measured"`,
      controlUnknown === panelUnmeasured,
      `control=${fsControl.status} panel=${intelligence.forwardSecrecy}`,
    );

    /* And when it WAS measured, the two must reach the same verdict. */
    if (!controlUnknown) {
      const controlHealthy = fsControl.status === 'Healthy';
      const panelEnabled = intelligence.forwardSecrecy === 'Enabled';
      check(
        `${state}: control Healthy ⟺ panel Enabled`,
        controlHealthy === panelEnabled,
        `control=${fsControl.status} panel=${intelligence.forwardSecrecy}`,
      );
      const controlWarning = fsControl.status === 'Warning';
      const panelPartial = intelligence.forwardSecrecy === 'Partial';
      check(
        `${state}: control Warning ⟺ panel Partial`,
        controlWarning === panelPartial,
        `control=${fsControl.status} panel=${intelligence.forwardSecrecy}`,
      );
    }
  }

  section('Not measured and Not observed stay distinct');

  const silent = buildIntelligence(evidenceFor('no-handshake'), 80);
  check(
    'no handshake → "Not measured"',
    silent.forwardSecrecy === 'Not measured',
    `got "${silent.forwardSecrecy}" — an endpoint that never answered must not be reported as lacking forward secrecy`,
  );

  const staticRsa = buildIntelligence(evidenceFor('tls12-static-rsa'), 80);
  check(
    'TLS 1.2 static-RSA → a measured verdict, not "Not measured"',
    staticRsa.forwardSecrecy !== 'Not measured',
    `got "${staticRsa.forwardSecrecy}" — this handshake WAS read`,
  );

  const hybrid = buildIntelligence(evidenceFor('tls13-hybrid'), 80);
  check('TLS 1.3 hybrid → Enabled', hybrid.forwardSecrecy === 'Enabled', hybrid.forwardSecrecy);
}

/* ══════════════════════════ 3. TLS 1.3 is forward secret by construction ═══ */

function checkTls13(): void {
  section('TLS 1.3 resolves forward secrecy without a probe');

  for (const state of ['tls13-hybrid', 'tls13-classical'] as const) {
    const fs = resolveForwardSecrecy(evidenceFor(state));
    check(`${state}: enabled`, fs.enabled, fs.basis);
    check(
      `${state}: the basis cites the protocol, not a probe`,
      /TLS 1\.3/.test(fs.basis),
      fs.basis,
    );
    check(`${state}: not caveated — no static RSA accepted`, !fs.caveated);
  }

  const capped = resolveForwardSecrecy(evidenceFor('tls12-static-rsa'));
  check(
    'static-RSA acceptance is reported, not hidden',
    !capped.enabled || capped.caveated,
    `enabled=${capped.enabled} caveated=${capped.caveated}`,
  );

  const silent = resolveForwardSecrecy(evidenceFor('no-handshake'));
  check('no handshake → not enabled', !silent.enabled);
  check('and a reason is given', silent.basis.trim().length > 0, silent.basis);
}

/* ══════════════════════════════ 4. the score equals its own parts ══════════ */

function checkScoreArithmetic(): void {
  section('The Encryption Score equals its published decomposition');

  for (const state of STATES) {
    const evidence = evidenceFor(state);
    const controls = buildControlStates(evidence);
    const pq = computePostQuantumReadiness(evidence);
    const components = buildScoreCategories(evidence, controls, pq.score);
    const executive = buildExecutiveSummary(evidence, components, toFindings(controls));

    /* `ScoreComponent.score` is coerced to 0 for an unmeasured dimension, with
       the truth carried in `applicable`. That is a deliberate contract — the
       scoring model needs a number — so the reconciliation must filter on
       `applicable`, exactly as the panel does. A consumer that reads `score`
       without checking `applicable` publishes 0 for something nobody measured. */
    const measured = components.filter((entry) => entry.applicable);
    const totalWeight = measured.reduce((sum, entry) => sum + entry.weight, 0);
    const expected = totalWeight > 0
      ? Math.round(measured.reduce((sum, entry) => sum + entry.score * entry.weight, 0) / totalWeight)
      : null;

    check(
      `${state}: composite (${executive.encryptionScore}) matches the weighted parts (${expected})`,
      executive.encryptionScore === null || expected === null || Math.abs(executive.encryptionScore - expected) <= 1,
      `${measured.length} applicable of ${components.length}, total weight ${totalWeight}`,
    );

    check(
      `${state}: every component weight comes from the published model`,
      components.every((entry) => SCORE_CATEGORY_DEFS.some((model) => model.key === entry.key && model.weight === entry.weight)),
      'a weight that is not in SCORE_CATEGORY_DEFS cannot be reconciled by a reader',
    );

    check(
      `${state}: inapplicable components carry a reason`,
      components.every((entry) => entry.applicable || (entry.observed ?? '').trim().length > 0),
      components.filter((entry) => !entry.applicable && !(entry.observed ?? '').trim()).map((entry) => entry.key).join(', '),
    );
  }
}

/* ═══════════════════ 5. nothing unmeasured is scored as a failure ══════════ */

function checkNoFabricatedFailures(): void {
  section('An unprobed dimension is never scored as a failure');

  const evidence = evidenceFor('no-handshake');
  const controls = buildControlStates(evidence);
  const components = buildScoreCategories(evidence, controls, computePostQuantumReadiness(evidence).score);

  /* The transport dimensions cannot be known without a handshake. Each must be
     null (excluded, weight redistributed) or Unknown — never 0, which is the
     worst MEASURED score and reads as "we looked and it is absent". */
  for (const key of ['forward-secrecy', 'key-exchange', 'cipher-suites', 'tls-configuration', 'post-quantum-readiness']) {
    const component = components.find((entry) => entry.key === key);
    if (!component) continue;
    check(
      `no handshake: "${key}" is marked inapplicable`,
      !component.applicable,
      `applicable=${component.applicable} score=${component.score} — a dimension nobody could read must be excluded, not scored`,
    );
  }

  for (const control of controls) {
    if (control.status !== 'Unknown') continue;
    check(
      `Unknown control "${control.key}" states why`,
      Boolean(control.evidence && control.evidence.trim().length > 0),
      'an unexplained Unknown is indistinguishable from a bug',
    );
    check(
      `Unknown control "${control.key}" is not rated above LOW`,
      control.severity === 'LOW' || control.severity === 'SAFE',
      `severity=${control.severity} — an unmeasured control must not drive a high-severity finding`,
    );
  }

  section('Post-quantum readiness: measured or null, never a consolation number');

  for (const state of STATES) {
    const pq = computePostQuantumReadiness(evidenceFor(state));
    check(
      `${state}: readiness is null or 0-100`,
      pq.score === null || (pq.score >= 0 && pq.score <= 100),
      String(pq.score),
    );
    /* `score` is always a number here by contract; `measured` is what says
       whether any consumer may publish it. 55 of its 100 points come from
       hybrid key agreement, so an unprobed endpoint scores 0 by construction —
       and 0% is a verdict this scan did not earn. */
    if (state === 'no-handshake') {
      check(
        'no handshake → readiness is NOT measured',
        !pq.measured,
        `measured=${pq.measured} score=${pq.score} — no named group could be offered`,
      );
      check('and a reason is recorded', pq.reasons.length > 0, 'an unpublished number needs an explanation');
    }
    if (state === 'tls13-hybrid') {
      check('hybrid → readiness IS measured', pq.measured, 'a measured hybrid group must license a number');
    }
  }
}


/* ═══════════════ 6. panels honour the applicable / measured flags ══════════ */

/**
 * The structural half.
 *
 * `ScoreComponent.score` is 0 for an unmeasured dimension and `applicable`
 * carries the truth; `computePostQuantumReadiness` returns a number always and
 * `measured` carries the truth. Both contracts work only if every consumer
 * checks the flag. A panel that renders `score` directly publishes 0 for a
 * dimension nobody read — which on a higher-is-better scale is the worst
 * possible MEASURED result.
 */
function checkPanelsHonourFlags(): void {
  section('Panels check the flag before publishing the number');

  const sections = readFileSync(join(process.cwd(), 'src', 'app', 'public-scan', '_sections.tsx'), 'utf8');

  check(
    'the score decomposition gates the meter on `applicable`',
    /component\.applicable \? component\.score : 0/.test(sections),
    'rendering `score` unguarded shows 0 for an unmeasured dimension',
  );
  check(
    'and gates the printed number too',
    /component\.applicable \? component\.score : '—'/.test(sections),
  );
  check(
    'an inapplicable component is labelled, not just blanked',
    /Not observable/.test(sections),
    'a bare em-dash is indistinguishable from a rendering bug',
  );

  const engine = readFileSync(join(process.cwd(), 'src', 'lib', 'scanner', 'public-scan', 'engine.ts'), 'utf8');
  check(
    'readiness is published only when `measured`',
    /\.measured/.test(engine),
    'the raw score is 0 by construction for an unprobed endpoint',
  );
  check(
    'the intelligence panel distinguishes Not measured from Not observed',
    /'Not measured'/.test(engine) && /'Not observed'/.test(engine),
  );

  const types = readFileSync(join(process.cwd(), 'src', 'lib', 'scanner', 'public-scan', 'types.ts'), 'utf8');
  check(
    'the forwardSecrecy union carries all four states',
    /'Enabled' \| 'Partial' \| 'Not observed' \| 'Not measured'/.test(types),
  );
  check(
    'classicalScore and encryptionScore are nullable',
    /classicalScore: number \| null/.test(types) && /encryptionScore: number \| null/.test(types),
    'publishing 0 for an endpoint that never answered says its encryption was examined and found critical',
  );
}

/* ══════════════════════════════════════════════════════════════════ main ═══ */

function main(): void {
  console.log('\x1b[1mQGuard Helix — /public-scan panel consistency\x1b[0m');
  console.log('Offline. Drives the real assessor across four observation states.\n');

  checkProjection();
  checkIntelligenceAgreesWithControls();
  checkTls13();
  checkScoreArithmetic();
  checkNoFabricatedFailures();
  checkPanelsHonourFlags();

  console.log(`\n\x1b[1m${'═'.repeat(66)}\x1b[0m`);
  if (failed === 0) {
    console.log(`\x1b[32m✓ ${passed} checks passed\x1b[0m`);
    return;
  }
  console.log(`\x1b[31m✗ ${failed} of ${passed + failed} checks failed\x1b[0m\n`);
  for (const failure of failures) console.log(`  \x1b[31m•\x1b[0m ${failure}`);
  process.exitCode = 1;
}

main();
