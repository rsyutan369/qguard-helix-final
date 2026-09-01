/**
 * Scanner dashboard panel consistency — offline verification.
 *
 * Reproduces the exact observation state from the reported defect and asserts
 * that every panel reaches the SAME conclusion from it.
 *
 * The reported scan of `test.openquantumsafe.org` published, on one page:
 *
 *   Observed Attack Surface     TLS Version: TLSv1.3
 *   Observed Attack Surface     Forward Secrecy: Not offered        (red)
 *   Cryptographic Intelligence  Forward Secrecy: Not observed
 *   Score decomposition         Forward Secrecy: 100
 *   Post-Quantum Key Agreement  "No TLS handshake completed"
 *
 * Three answers for forward secrecy, and a claim that no handshake completed
 * printed beside the protocol, cipher suite, 5-certificate chain and 85-day
 * validity that only a completed handshake can produce.
 *
 * Run: npx tsx tools/scanner-panel-consistency-check.ts
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  displayForwardSecrecy,
  reconcileTransport,
  transportReconciliationNote,
  type TransportTruth,
} from '../src/lib/scanner/web-scanner/transport-truth';
import type { TlsAnalysisResult } from '../src/lib/scanner/web-scanner/types';
import type { EdgeIntelligence } from '../src/lib/scanner/web-scanner/edge-intelligence';

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

/** The socket analyser SUCCEEDED: TLS 1.3, AES-256-GCM, 5-cert chain. */
function socketSucceeded(overrides: Partial<TlsAnalysisResult> = {}): TlsAnalysisResult {
  return {
    tlsVersion: 'TLSv1.3',
    cipherSuite: 'TLS_AES_256_GCM_SHA384',
    /* Node returns `{}` from getEphemeralKeyInfo() on TLS 1.3, so the analyser
       degrades to this literal on EVERY modern endpoint. */
    keyExchange: 'ECDHE (TLS 1.3 key_share)',
    signatureAlgorithm: 'ecdsa-with-SHA384',
    supportedProtocols: ['TLSv1.3'],
    protocolSupport: [],
    negotiatedCurve: null,
    serverName: 'test.openquantumsafe.org',
    peerCertificate: null,
    cipherSuites: [],
    ephemeralKeyType: null,
    ephemeralKeySize: null,
    ...overrides,
  } as TlsAnalysisResult;
}

function socketFailed(): TlsAnalysisResult | null {
  return null;
}

/** The edge named-group prober TIMED OUT — no handshake of its own. */
function edgeTimedOut(): EdgeIntelligence {
  return {
    transport: {
      negotiatedProtocol: null,
      supportedProtocols: [],
      legacyProtocols: [],
      negotiatedCipher: null,
      keyExchange: '',
      /* The bug in one field: a plain boolean, so a probe that never ran
         reports `false`, which renders as "this endpoint has no forward
         secrecy" — the strongest possible claim from no evidence. */
      forwardSecrecy: false,
      forwardSecrecyBasis: '',
      staticRsaAccepted: false,
      alpn: null,
      alpnOffered: [],
      http2: false,
      alpnProbed: false,
      sessionTickets: null,
      sessionReuse: null,
      handshakeMs: null,
      error: 'TLS connection timeout to test.openquantumsafe.org:443',
    },
    pqKeyAgreement: { probed: false, hybridGroups: [], pureKemGroups: [], primaryGroup: null } as never,
  } as unknown as EdgeIntelligence;
}

/** The edge prober SUCCEEDED and measured a hybrid group. */
function edgeMeasuredHybrid(): EdgeIntelligence {
  return {
    transport: {
      negotiatedProtocol: 'TLSv1.3',
      supportedProtocols: ['TLSv1.3'],
      legacyProtocols: [],
      negotiatedCipher: 'TLS_AES_256_GCM_SHA384',
      keyExchange: 'X25519MLKEM768',
      forwardSecrecy: true,
      forwardSecrecyBasis: 'ephemeral key agreement measured',
      staticRsaAccepted: false,
      alpn: 'h2',
      alpnOffered: ['h2'],
      http2: true,
      alpnProbed: true,
      sessionTickets: null,
      sessionReuse: null,
      handshakeMs: 120,
      error: null,
    },
    pqKeyAgreement: {
      probed: true,
      hybridGroups: ['X25519MLKEM768'],
      pureKemGroups: [],
      primaryGroup: 'X25519MLKEM768',
    } as never,
  } as unknown as EdgeIntelligence;
}

/** The edge prober SUCCEEDED and found only classical groups. */
function edgeMeasuredClassical(): EdgeIntelligence {
  const base = edgeMeasuredHybrid();
  return {
    ...base,
    transport: { ...base.transport, keyExchange: 'X25519' },
    pqKeyAgreement: { probed: true, hybridGroups: [], pureKemGroups: [], primaryGroup: 'X25519' } as never,
  } as unknown as EdgeIntelligence;
}

/* ═══════════════════════════════ 1. the reported defect, exactly ═══════════ */

function checkReportedDefect(): void {
  section('The reported scan: socket OK, edge probe timed out');

  const truth = reconcileTransport(socketSucceeded(), edgeTimedOut(), null);

  check(
    'a handshake IS reported as completed',
    truth.handshakeCompleted,
    'the socket analyser negotiated TLS 1.3; claiming otherwise contradicts the protocol, suite and chain on the same page',
  );
  check('the source is named as the socket', truth.handshakeSources.includes('socket'));
  check('no handshake-failure text is emitted', truth.handshakeFailure === '', truth.handshakeFailure);

  check('protocol is measured as TLSv1.3', truth.protocol.value === 'TLSv1.3' && truth.protocol.measured);
  check('cipher suite is measured', truth.cipherSuite.value === 'TLS_AES_256_GCM_SHA384' && truth.cipherSuite.measured);

  section('Forward secrecy: ONE answer, not three');

  check(
    'forward secrecy is measured TRUE',
    truth.forwardSecrecy.measured && truth.forwardSecrecy.value === true,
    `got measured=${truth.forwardSecrecy.measured} value=${truth.forwardSecrecy.value} — TLS 1.3 has no non-ephemeral key exchange`,
  );
  check(
    'and the basis names the reason rather than a probe',
    /TLS 1\.3/.test(truth.forwardSecrecy.basis) && /construction/i.test(truth.forwardSecrecy.basis),
    truth.forwardSecrecy.basis,
  );
  check(
    'the display string is "Enabled", never "Not offered"',
    displayForwardSecrecy(truth) === 'Enabled',
    displayForwardSecrecy(truth),
  );

  section('Post-quantum: not measured, and says so accurately');

  check('state is not-measured', truth.postQuantum.state === 'not-measured', truth.postQuantum.state);
  check(
    'the reason does NOT claim the handshake failed',
    !/No TLS handshake completed/i.test(truth.postQuantum.reason),
    `"${truth.postQuantum.reason}" — a handshake DID complete; only the group probe did not`,
  );
  check(
    'the reason names what actually failed',
    /named key-agreement groups were not probed/i.test(truth.postQuantum.reason),
    truth.postQuantum.reason,
  );
  check(
    'and preserves the not-measured / not-supported distinction',
    /not measured/i.test(truth.postQuantum.reason) && /not "not supported"/i.test(truth.postQuantum.reason),
    truth.postQuantum.reason,
  );

  section('Quantum vulnerability: a verdict the evidence supports');

  /* The original page said "Unknown" while ALSO publishing a HIGH quantum risk
     factor for the ECDSA P-256 leaf and an ML-DSA-65 migration target at 80%
     confidence. Either the exposure is unknown or it is high; it cannot be both. */
  check(
    'a verdict IS reached from the observed key exchange',
    truth.quantumVulnerability.measured,
    'the negotiated ECDHE key exchange was observed, so the session negotiated IS quantum vulnerable',
  );
  check(
    'the verdict is vulnerable',
    truth.quantumVulnerability.value === 'vulnerable',
    String(truth.quantumVulnerability.value),
  );
  check(
    'and it scopes itself to what was measured',
    /was not measured/i.test(truth.quantumVulnerability.basis),
    `"${truth.quantumVulnerability.basis}" — must not imply the endpoint cannot do PQ`,
  );

  section('The disagreement is disclosed, not hidden');

  const note = transportReconciliationNote(truth);
  check('a reconciliation note is produced', Boolean(note));
  check(
    'it states which facts are measured and which are not',
    Boolean(note && /measured/i.test(note) && /not/i.test(note)),
    note ?? '(none)',
  );
}

/* ═══════════════════════════════ 2. the states that must still work ════════ */

function checkMeasuredStates(): void {
  section('Edge measured a HYBRID group');

  const hybrid = reconcileTransport(socketSucceeded(), edgeMeasuredHybrid(), null);
  check('handshake completed', hybrid.handshakeCompleted);
  check('post-quantum state is hybrid', hybrid.postQuantum.state === 'hybrid', hybrid.postQuantum.state);
  check('label reads Applied', hybrid.postQuantum.label === 'Applied', hybrid.postQuantum.label);
  check('group is named', hybrid.postQuantum.group === 'X25519MLKEM768', String(hybrid.postQuantum.group));
  check(
    'quantum vulnerability is hybrid, not vulnerable',
    hybrid.quantumVulnerability.value === 'hybrid',
    String(hybrid.quantumVulnerability.value),
  );
  check('forward secrecy enabled', displayForwardSecrecy(hybrid) === 'Enabled');
  check('no reconciliation note — nothing disagreed', transportReconciliationNote(hybrid) === null);

  section('Edge measured CLASSICAL groups only');

  const classical = reconcileTransport(socketSucceeded(), edgeMeasuredClassical(), null);
  check('post-quantum state is classical', classical.postQuantum.state === 'classical', classical.postQuantum.state);
  check(
    'quantum vulnerability is vulnerable',
    classical.quantumVulnerability.value === 'vulnerable',
    String(classical.quantumVulnerability.value),
  );
  check(
    'and the reason cites the probe, not the negotiated suite',
    /every named group/i.test(classical.quantumVulnerability.basis),
    classical.quantumVulnerability.basis,
  );

  section('BOTH engines failed — nothing is claimed');

  const nothing = reconcileTransport(socketFailed(), edgeTimedOut(), null);
  check('handshake not completed', !nothing.handshakeCompleted);
  check('a failure reason is given', nothing.handshakeFailure.length > 0, nothing.handshakeFailure);
  check('protocol is NOT measured', !nothing.protocol.measured);
  check('cipher suite is NOT measured', !nothing.cipherSuite.measured);
  check(
    'forward secrecy is NOT measured — never false',
    !nothing.forwardSecrecy.measured && nothing.forwardSecrecy.value === null,
    `value=${nothing.forwardSecrecy.value} — a timed-out probe must not publish "no forward secrecy"`,
  );
  check('display reads "Not measured"', displayForwardSecrecy(nothing) === 'Not measured', displayForwardSecrecy(nothing));
  check(
    'quantum vulnerability is NOT measured',
    !nothing.quantumVulnerability.measured,
    'with no handshake there is nothing quantum-relevant to judge',
  );
  check(
    'post-quantum reason cites the handshake failure',
    /No TLS handshake completed/i.test(nothing.postQuantum.reason),
    nothing.postQuantum.reason,
  );
}

/* ═══════════════════════════ 3. TLS 1.2 must not inherit the 1.3 shortcut ══ */

function checkTls12(): void {
  section('TLS 1.2 is judged on its actual key exchange');

  const ephemeral12 = reconcileTransport(
    socketSucceeded({ tlsVersion: 'TLSv1.2', keyExchange: 'ECDHE', cipherSuite: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384' }),
    edgeTimedOut(),
    null,
  );
  check(
    'ECDHE on 1.2 is forward secret',
    ephemeral12.forwardSecrecy.value === true && ephemeral12.forwardSecrecy.measured,
    ephemeral12.forwardSecrecy.basis,
  );
  check(
    'and the basis does NOT cite the TLS 1.3 construction argument',
    !/TLS 1\.3/.test(ephemeral12.forwardSecrecy.basis),
    ephemeral12.forwardSecrecy.basis,
  );

  const staticRsa12 = reconcileTransport(
    socketSucceeded({
      tlsVersion: 'TLSv1.2',
      keyExchange: 'RSA',
      cipherSuite: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
      cipherSuites: [{ name: 'TLS_RSA_WITH_AES_256_GCM_SHA384', category: 'rsa-kex' }] as never,
    }),
    edgeTimedOut(),
    null,
  );
  check(
    'static-RSA key transport is NOT forward secret',
    staticRsa12.forwardSecrecy.value === false && staticRsa12.forwardSecrecy.measured,
    `value=${staticRsa12.forwardSecrecy.value} — this is a measured negative, which is legitimate`,
  );
  check('display reads "Not offered"', displayForwardSecrecy(staticRsa12) === 'Not offered', displayForwardSecrecy(staticRsa12));
  check(
    'static RSA acceptance is measured true',
    staticRsa12.staticRsaAccepted.value === true,
    String(staticRsa12.staticRsaAccepted.value),
  );

  section('Partial: ephemeral negotiated but static RSA also accepted');

  const partial = reconcileTransport(
    socketSucceeded({
      tlsVersion: 'TLSv1.2',
      keyExchange: 'ECDHE',
      cipherSuites: [
        { name: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', category: 'ecdhe-rsa' },
        { name: 'TLS_RSA_WITH_AES_256_GCM_SHA384', category: 'rsa-kex' },
      ] as never,
    }),
    edgeTimedOut(),
    null,
  );
  check('forward secrecy is true but capped', partial.forwardSecrecy.value === true);
  check('display reads "Partial"', displayForwardSecrecy(partial) === 'Partial', displayForwardSecrecy(partial));
}

/* ══════════════════════════════ 4. the cross-panel invariant ═══════════════ */

/**
 * The rule the whole module exists to enforce, stated as one assertion.
 *
 * Whatever the observation state, no panel may claim a handshake did not
 * complete while another publishes facts only a handshake produces, and no
 * panel may publish a negative verdict for something that was never measured.
 */
function checkInvariant(): void {
  section('Cross-panel invariant across every observation state');

  const states: Array<{ label: string; truth: TransportTruth }> = [
    { label: 'socket OK, edge timeout', truth: reconcileTransport(socketSucceeded(), edgeTimedOut(), null) },
    { label: 'both OK, hybrid', truth: reconcileTransport(socketSucceeded(), edgeMeasuredHybrid(), null) },
    { label: 'both OK, classical', truth: reconcileTransport(socketSucceeded(), edgeMeasuredClassical(), null) },
    { label: 'both failed', truth: reconcileTransport(socketFailed(), edgeTimedOut(), null) },
    { label: 'edge only', truth: reconcileTransport(null, edgeMeasuredHybrid(), null) },
  ];

  for (const { label, truth } of states) {
    /* (a) A measured protocol implies a completed handshake. */
    check(
      `${label}: protocol measured ⟹ handshake completed`,
      !truth.protocol.measured || truth.handshakeCompleted,
      'a protocol cannot be negotiated without a handshake',
    );

    /* (b) No handshake ⟹ nothing about the session is measured. */
    check(
      `${label}: no handshake ⟹ nothing measured`,
      truth.handshakeCompleted ||
        (!truth.protocol.measured && !truth.cipherSuite.measured && !truth.forwardSecrecy.measured),
      'facts were published for a session that never happened',
    );

    /* (c) A negative verdict is only ever a MEASURED one. */
    check(
      `${label}: forward secrecy false ⟹ measured`,
      truth.forwardSecrecy.value !== false || truth.forwardSecrecy.measured,
      'a fabricated negative — the exact defect being fixed',
    );

    /* (d) The handshake-failure text and a completed handshake are exclusive. */
    check(
      `${label}: failure text ⟺ no handshake`,
      (truth.handshakeFailure === '') === truth.handshakeCompleted,
      `handshakeCompleted=${truth.handshakeCompleted} failure="${truth.handshakeFailure}"`,
    );

    /* (e) Every unmeasured reading carries a reason. A blank "Not measured"
           teaches the reader nothing and looks like a rendering bug. */
    for (const [field, reading] of [
      ['protocol', truth.protocol],
      ['cipherSuite', truth.cipherSuite],
      ['keyExchange', truth.keyExchange],
      ['forwardSecrecy', truth.forwardSecrecy],
    ] as const) {
      check(
        `${label}: ${field} unmeasured ⟹ has a reason`,
        reading.measured || reading.basis.trim().length > 0,
        'an unexplained "Not measured" is indistinguishable from a bug',
      );
    }
  }
}


/* ══════════════════════ 5. no panel re-derives what the truth already says ══ */

/**
 * The structural half of the guarantee.
 *
 * The invariant above proves the RECONCILER is self-consistent. This proves the
 * PANELS actually read it — because a second engine, however correct, fixes
 * nothing if a panel keeps its own private fallback chain. Three of them did,
 * which is why one page showed three answers for forward secrecy.
 */
function checkPanelsReadTheTruth(): void {
  section('Panels read the reconciler, not their own arithmetic');

  const intel = readFileSync(join(process.cwd(), 'src', 'app', 'dashboard', 'scanner_dashboard', '_intel.ts'), 'utf8');
  const scoring = readFileSync(join(process.cwd(), 'src', 'lib', 'scanner', 'web-scanner', 'published-scoring.ts'), 'utf8');
  const sections = readFileSync(join(process.cwd(), 'src', 'app', 'dashboard', 'scanner_dashboard', '_sections.tsx'), 'utf8');

  check(
    'the dashboard imports the reconciler',
    /from '@\/lib\/scanner\/web-scanner\/transport-truth'/.test(intel),
  );
  check(
    'the published scorer imports it too',
    /from '\.\/transport-truth'/.test(scoring),
    'the scorer produced the 100 that contradicted two panels',
  );

  /* All three forward-secrecy sites must go through `displayForwardSecrecy` or
     the reconciled reading. Counting them is what catches a fourth site being
     added later with its own chain. */
  const fsCalls = (intel.match(/displayForwardSecrecy\(/g) ?? []).length;
  check(
    `all forward-secrecy renderings use the shared display helper (found ${fsCalls})`,
    fsCalls >= 3,
    'there were three independent computations; each must now call the helper',
  );

  check(
    'no panel reads the raw edge boolean for forward secrecy any more',
    !/edge\?\.transport\.forwardSecrecy\s*$|:\s*edge\.transport\.forwardSecrecy/m.test(intel),
    'edge.transport.forwardSecrecy is `false` when the probe never ran',
  );
  check(
    'no panel reads edge.quantum.forwardSecrecy directly',
    !/edge\?\.quantum\.forwardSecrecy/.test(intel),
    'that string is "Not observed" whenever the edge probe failed',
  );

  section('Post-quantum readiness: a number XOR a "not scored" reason');

  check(
    'the executive reading is nullable',
    /postQuantumReadiness: number \| null/.test(intel),
    'a non-nullable number forced a fallback that produced 14 for an unscored dimension',
  );
  check(
    'a reason accompanies the null',
    /postQuantumReadinessReason/.test(intel) && /postQuantumReadinessReason/.test(sections),
  );
  check(
    'the panel renders "Not scored" rather than a number',
    /postQuantumReadiness === null \? 'Not scored'/.test(sections),
  );
  check(
    'and the finding-share fallback no longer fires when edge evidence exists',
    /summary\.totalFindings > 0 && !results\[0\]\?\.metadata\?\.edgeIntelligence/.test(intel),
    'that fallback is what manufactured a confident 14',
  );

  section('The misleading handshake message is gone at its source');

  const edgeIntel = readFileSync(join(process.cwd(), 'src', 'lib', 'scanner', 'web-scanner', 'edge-intelligence.ts'), 'utf8');
  const edgeModel = readFileSync(join(process.cwd(), 'src', 'lib', 'scanner', 'web-scanner', 'edge-intelligence-model.ts'), 'utf8');

  /* Strip comments before asserting: the fix's own explanation quotes the old
     wording, and a grep that cannot tell a comment from an emitted string would
     fail on the very change it is verifying. */
  const edgeIntelCode = edgeIntel
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '');
  check(
    'the PQ panel no longer EMITS "No TLS handshake completed"',
    !/No TLS handshake completed/.test(edgeIntelCode),
    'it appeared beneath a negotiated TLS 1.3 suite and a 5-certificate chain',
  );
  check(
    'it names the named-group probe instead',
    /Named key-agreement groups could not be probed/.test(edgeIntel),
  );
  check(
    'the quantum verdict no longer claims it either',
    !/No TLS handshake completed for this target/.test(edgeModel),
  );
  check(
    'certificate evidence licenses a quantum verdict',
    /hasCertificateEvidence/.test(edgeIntel),
    '"Unknown" beside a HIGH certificate risk factor is a contradiction',
  );
}

/* ══════════════════════════════════════════════════════════════════ main ═══ */

function main(): void {
  console.log('\x1b[1mQGuard Helix — scanner panel consistency\x1b[0m');
  console.log('Offline. Reproduces the reported observation state and asserts every panel agrees.\n');

  checkReportedDefect();
  checkMeasuredStates();
  checkTls12();
  checkInvariant();
  checkPanelsReadTheTruth();

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
