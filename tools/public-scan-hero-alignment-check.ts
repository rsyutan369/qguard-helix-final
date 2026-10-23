/**
 * /public-scan — cross-panel alignment, verified on REAL edge evidence.
 *
 *   npx tsx tools/public-scan-hero-alignment-check.ts [host ...]
 *   PUBLIC_SCAN_REPORTS_DIR=<dir of saved report JSON> npx tsx tools/public-scan-hero-alignment-check.ts
 *
 * The page renders one assessment through a dozen projections — Executive
 * Summary, Encryption Score, Cryptographic Intelligence, Findings, Timeline,
 * Recommendations, Sophia, the scan rail and the six hero cards. Each existing
 * check proved its own panel; none compared panels, and the audit of
 * 2026-10-23 found them disagreeing on real scans of cloudflare.com,
 * google.com and two badssl.com endpoints:
 *
 *   • Executive "Post-Quantum Readiness 8%" beside a decomposition row "not
 *     scored" — two implementations of one model.
 *   • "Adopt hybrid key exchange · +26" (and Sophia quoting it) where the graded
 *     score moves single digits — gains measured on a private 60/40 composite.
 *   • Hero TLS card "Fair · TLS 1.3 enabled" beside "TLS Version · HIGH ·
 *     legacy TLSv1" — the card's legacy regex never matched Node's "TLSv1".
 *   • Hero headers "6/9" beside "5 of 8"; Quantum card "Good" beside a
 *     CRITICAL Quantum Risk row; "Critical" pills counted as HIGH.
 *   • `TLS_ECDHE_RSA_WITH_…` scored as static-RSA key transport.
 *
 * Every assertion below is a cross-panel invariant. Each report is also
 * re-derived into the edge cases real scans rarely hit on demand (unsettled
 * hybrid probe, standalone ML-KEM, no TLS 1.3, unanswered DNS) by mutating its
 * real evidence, so the rules are exercised on complete, realistic bundles.
 */

import 'dotenv/config';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { assessPublicTarget, quantumStageDetail } from '../src/lib/scanner/public-scan/assess';
import {
  buildControlStates,
  buildExecutiveSummary,
  buildIntelligence,
  buildRecommendations,
  buildSophia,
  buildTimeline,
  computeClassicalScore,
  computePostQuantumReadiness,
  sortFindings,
  toFindings,
} from '../src/lib/scanner/public-scan/engine';
import { keyAgreementPhrase } from '../src/lib/scanner/public-scan/engines';
import { classifySuite } from '../src/lib/scanner/published-categories';
import { buildScoreCategories } from '../src/lib/scanner/public-scan/score-categories';
import type { PublicScanEvidence, PublicScanReport, PublicScanStage } from '../src/lib/scanner/public-scan/types';
import type { PublicScanObservation } from '../src/hooks/use-public-scan';
import {
  CONTROL_NODE,
  nodeScoreScopesFromReport,
  nodeScoresFromReport,
  observationEvent,
  stageTransitionEvents,
  reportEvidenceEvents,
} from '../src/app/public-scan/_qve/event-derivation';
import { initialQveState, qveReducer } from '../src/app/public-scan/_qve/scan-event-store';
import { resolveNodeVerdict } from '../src/app/public-scan/_qve/types';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(label: string, condition: boolean, detail = ''): void {
  if (condition) {
    passed += 1;
    return;
  }
  failed += 1;
  failures.push(`${label}${detail ? ` — ${detail}` : ''}`);
}

/* ═══════════════════════════════════════════════════════ pure predicates ═══ */

function predicates(): void {
  check('ECDHE-RSA is NOT static-RSA key transport', !classifySuite('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'ecdhe-rsa').staticRsa);
  check('DHE-RSA is NOT static-RSA key transport', !classifySuite('TLS_DHE_RSA_WITH_AES_256_GCM_SHA384', 'dhe-rsa').staticRsa);
  check('TLS_RSA_WITH is static-RSA key transport', classifySuite('TLS_RSA_WITH_AES_128_GCM_SHA256').staticRsa);
  check('the probe category decides OpenSSL-named suites', classifySuite('AES256-SHA', 'rsa-kex').staticRsa);
  check(
    'an unsettled hybrid probe is phrased as unsettled, not "classical only"',
    keyAgreementPhrase({ hybridGroups: [], hybridSettled: false, supportedProtocols: ['TLSv1.2', 'TLSv1.3'] }) ===
      'hybrid probe not settled',
  );
  check(
    'an endpoint without TLS 1.3 is phrased as a measured negative',
    keyAgreementPhrase({ hybridGroups: [], hybridSettled: false, supportedProtocols: ['TLSv1.2'] }).includes('no TLS 1.3'),
  );
}

/* ══════════════════════════════════════════════════════ report rebuild ═══ */

/** The composition assess.ts performs after the network phase, on given evidence. */
function rebuild(base: PublicScanReport, evidence: PublicScanEvidence): PublicScanReport {
  const controls = buildControlStates(evidence);
  const scoreComponents = buildScoreCategories(evidence, controls);
  const findings = sortFindings(toFindings(controls));
  const executive = buildExecutiveSummary(evidence, scoreComponents, findings);
  const recommendations = buildRecommendations(evidence, controls, scoreComponents);
  return {
    ...base,
    evidence,
    executive,
    scoreComponents,
    findings,
    intelligence: buildIntelligence(evidence, executive.confidence),
    timeline: buildTimeline(evidence),
    recommendations,
    sophia: buildSophia(evidence, executive, findings, recommendations),
  };
}

/** Real evidence, re-derived into the cases a live scan rarely produces on demand. */
function variants(report: PublicScanReport): Array<[string, PublicScanReport]> {
  const e = report.evidence;
  const out: Array<[string, PublicScanReport]> = [['as scanned', report]];
  if (!e.tls) return out;

  const tlsData = e.engines.tls.data;
  const unsettled: PublicScanEvidence = {
    ...e,
    tls: { ...e.tls, supportedProtocols: Array.from(new Set([...e.tls.supportedProtocols, 'TLSv1.3'])) },
    keyAgreement: { ...e.keyAgreement, probed: true, hybridSettled: false, hybridGroups: [], pureKemGroups: [], primaryGroup: null },
    engines: { ...e.engines, tls: { ...e.engines.tls, data: { ...tlsData, hybridGroups: [], pureKemGroups: [], hybridGroupsSettled: [] } } },
  };
  out.push(['hybrid probe unsettled', rebuild(report, unsettled)]);

  const pureKem: PublicScanEvidence = {
    ...unsettled,
    keyAgreement: { ...unsettled.keyAgreement, hybridSettled: true, pureKemGroups: ['MLKEM768'], primaryGroup: 'MLKEM768' },
    engines: { ...unsettled.engines, tls: { ...unsettled.engines.tls, data: { ...unsettled.engines.tls.data, pureKemGroups: ['MLKEM768'] } } },
  };
  out.push(['standalone ML-KEM', rebuild(report, pureKem)]);

  const noTls13: PublicScanEvidence = {
    ...e,
    tls: { ...e.tls, tlsVersion: 'TLSv1.2', supportedProtocols: e.tls.supportedProtocols.filter((p) => p !== 'TLSv1.3').concat(e.tls.supportedProtocols.includes('TLSv1.2') ? [] : ['TLSv1.2']) },
    keyAgreement: { ...e.keyAgreement, probed: true, hybridSettled: false, hybridGroups: [], pureKemGroups: [], primaryGroup: e.keyAgreement.classicalGroups[0] ?? null },
    engines: { ...e.engines, tls: { ...e.engines.tls, data: { ...tlsData, hybridGroups: [], pureKemGroups: [], hybridGroupsSettled: [], hybridProbed: false } } },
  };
  out.push(['no TLS 1.3', rebuild(report, noTls13)]);

  const dns = e.engines.dns.data;
  const dnsUnanswered: PublicScanEvidence = {
    ...e,
    engines: {
      ...e.engines,
      dns: {
        ...e.engines.dns,
        data: { ...dns, spf: null, dmarc: null, spfQueryable: false, dmarcQueryable: false, mailExchangers: dns.mailExchangers.length ? dns.mailExchangers : [{ priority: 10, exchange: 'mx.example' }] },
      },
    },
  };
  out.push(['SPF/DMARC lookups unanswered', rebuild(report, dnsUnanswered)]);
  return out;
}

/* ════════════════════════════════════════════════════ cross-panel rules ═══ */

const VERDICT_RANK: Record<string, number> = { critical: 3, 'at-risk': 2, review: 1, secure: 0 };
const SEVERITY_RANK: Record<string, number> = { CRITICAL: 3, HIGH: 2, MEDIUM: 1 };
const UNMEASURED = new Set(['Unknown', 'Not Observable', 'Not Applicable']);

/** The stream a LIVE assessment emitted — stage frames and observations in server order. */
type StreamFrame = { stage: PublicScanStage } | { observation: PublicScanObservation };
const LIVE_STREAM = new WeakMap<PublicScanReport, StreamFrame[]>();

function heroState(report: PublicScanReport) {
  let state = initialQveState();
  state = qveReducer(state, {
    type: 'ingest',
    event: { id: 'start', type: 'SCAN_STARTED', timestamp: Date.now(), category: 'scan', status: 'running', progress: 0, severity: 'info' },
  });
  /* The real page ingests the scan's live observations BEFORE the report's
     evidence, and a card keeps its first lines and its running maximum. A
     replay of the report alone cannot see a live observation settling a card
     the report then cannot correct — which is how an OCSP card read "Secure"
     on a Not Applicable row. */
  const previous = new Map<string, PublicScanStage['state']>();
  for (const frame of LIVE_STREAM.get(report) ?? []) {
    const events =
      'stage' in frame
        ? stageTransitionEvents(frame.stage, previous.get(frame.stage.key), 50, report.target.displayUrl)
        : [observationEvent(frame.observation, 50, report.target.displayUrl)];
    if ('stage' in frame) previous.set(frame.stage.key, frame.stage.state);
    for (const event of events) state = qveReducer(state, { type: 'ingest', event });
  }
  for (const event of reportEvidenceEvents(report)) state = qveReducer(state, { type: 'ingest', event });
  return qveReducer(state, {
    type: 'settle',
    grade: report.executive.gradeable ? report.executive.grade : null,
    gradeColor: report.executive.gradeColor,
    score: report.executive.encryptionScore,
    postQuantumScore: report.executive.postQuantumReadiness,
    nodeScores: nodeScoresFromReport(report),
    nodeScoreScopes: nodeScoreScopesFromReport(report),
  });
}

function assertReport(name: string, report: PublicScanReport): void {
  const tag = (label: string) => `[${name}] ${label}`;
  const e = report.executive;
  const pq = computePostQuantumReadiness(report.evidence);
  const pqRow = report.scoreComponents.find((component) => component.key === 'post-quantum-readiness')!;

  /* ── One post-quantum readiness ─────────────────────────────────────── */
  check(
    tag('Executive PQ readiness IS the decomposition row'),
    e.postQuantumReadiness === (pqRow.applicable ? pqRow.score : null),
    `card ${e.postQuantumReadiness} · row ${pqRow.applicable ? pqRow.score : 'n/a'}`,
  );
  check(
    tag('the key-agreement case agrees with the accepted groups'),
    e.postQuantumKeyAgreement === 'not-measured'
      ? e.postQuantumReadiness === null
      : e.postQuantumKeyAgreement === 'hybrid'
        ? report.evidence.keyAgreement.hybridGroups.length > 0
        : e.postQuantumKeyAgreement === 'pure-kem'
          ? (report.evidence.keyAgreement.pureKemGroups ?? []).length > 0
          : report.evidence.keyAgreement.hybridGroups.length === 0,
    e.postQuantumKeyAgreement,
  );
  check(
    tag('Cryptographic Intelligence exposure agrees with the readiness state'),
    report.intelligence.quantumVulnerability === 'Unknown' ? !pq.measured : pq.measured,
    report.intelligence.quantumVulnerability,
  );
  check(
    tag('standalone ML-KEM is never "Vulnerable"'),
    !pq.pureKemObserved || report.intelligence.quantumVulnerability !== 'Vulnerable',
  );
  check(
    tag('the rail quotes the report, not a private figure'),
    quantumStageDetail(e).includes(e.postQuantumReadiness === null ? 'not scored' : `${e.postQuantumReadiness}%`),
  );
  if (report.evidence.tls && !pq.measured) {
    check(
      tag('an unsettled probe is never narrated as "no handshake"'),
      !report.sophia.narrative.includes('No TLS handshake completed') &&
        !report.timeline[0].description.startsWith('No handshake completed'),
    );
  }
  check(
    tag('Sophia never prints a null readiness or an undefined value'),
    !/null%|undefined/.test(report.sophia.narrative),
    report.sophia.narrative.match(/.{0,60}(null%|undefined).{0,30}/)?.[0],
  );
  const algorithmsRow = report.scoreComponents.find((component) => component.key === 'cryptographic-algorithms');
  if (algorithmsRow?.applicable) {
    const stated = Number(algorithmsRow.observed.match(/^(\d+)/)?.[1] ?? -1);
    check(
      tag('the score row counts the algorithms the panel lists'),
      stated === report.intelligence.observedAlgorithms.length,
      `row ${stated} · panel ${report.intelligence.observedAlgorithms.length}`,
    );
  }

  /* ── One status vocabulary ──────────────────────────────────────────── */
  for (const finding of report.findings) {
    if (finding.status === 'Critical' || finding.severity === 'CRITICAL') {
      check(tag(`"${finding.control}" pill and census agree`), finding.status === 'Critical' && finding.severity === 'CRITICAL', `${finding.status}/${finding.severity}`);
    }
  }
  const risk = report.findings.find((finding) => finding.id === 'quantum-risk');
  const factors = report.evidence.engines.crypto.data.riskFactors;
  if (risk && factors.length) {
    const rank: Record<string, number> = { Critical: 3, High: 2, Medium: 1, Low: 0 };
    const top = Math.max(...factors.map((factor) => rank[factor.impact]));
    const named = factors.find((factor) => risk.finding.endsWith(`— ${factor.factor}`));
    check(tag('Quantum Risk names the factor that set its level'), Boolean(named) && rank[named!.impact] === top, risk.finding);
  }
  if (report.evidence.engines.dns.data.spfQueryable === false && !report.evidence.engines.dns.data.spf) {
    const email = report.findings.find((finding) => finding.id === 'email-authentication');
    check(tag('an unanswered SPF lookup is Unknown, not "Neither SPF nor DMARC"'), email?.status === 'Unknown', email?.finding);
  }

  /* ── Recommendations speak about the graded score ───────────────────── */
  const encryption = e.encryptionScore;
  for (const recommendation of report.recommendations) {
    if (recommendation.scoreGain === null) continue;
    check(tag(`"${recommendation.title}" has a graded score to add to`), encryption !== null);
    check(
      tag(`"${recommendation.title}" gain fits under the ceiling`),
      encryption !== null && recommendation.scoreGain >= 0 && encryption + recommendation.scoreGain <= 100,
      `${encryption} + ${recommendation.scoreGain}`,
    );
  }
  const DRIVER: Record<string, string> = {
    'disable-legacy-tls': 'tls-version',
    'enable-caa': 'dns-caa',
    'enable-hsts': 'hsts',
    'harden-http-headers': 'http-security',
    'enable-ocsp-stapling': 'ocsp-stapling',
    'hybrid-kex': 'pq-key-agreement',
  };
  const PRIORITY: Record<string, string> = { CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', SAFE: 'Low' };
  for (const recommendation of report.recommendations) {
    const driver = report.findings.find((finding) => finding.id === DRIVER[recommendation.id]);
    if (!driver) continue;
    check(
      tag(`"${recommendation.title}" carries its finding's urgency`),
      recommendation.priority === PRIORITY[driver.severity],
      `${recommendation.priority} vs ${driver.control} ${driver.severity}`,
    );
  }
  check(
    tag('static RSA is one recommendation, not two'),
    report.recommendations.filter((r) => r.id === 'strengthen-cipher-suites' || r.id === 'forward-secrecy').length <= 1,
  );
  if (report.evidence.tls && !pq.measured) {
    check(tag('no hybrid recommendation on an unsettled probe'), !report.recommendations.some((r) => r.id === 'hybrid-kex'));
  }
  const gains = report.recommendations.map((r) => r.scoreGain ?? 0);
  const best = Math.max(0, ...gains);
  if (best > 0) {
    check(tag('Sophia\'s "highest-value change" has the highest modelled gain'), report.sophia.narrative.includes(`+${best} points`));
  }
  // A CAA gain is independent of every other category, so it can be recomputed exactly.
  const caa = report.recommendations.find((r) => r.id === 'enable-caa');
  if (caa && caa.scoreGain !== null) {
    const improved = report.scoreComponents.map((c) => (c.key === 'dns-caa' ? { ...c, score: 100, applicable: true } : c));
    check(
      tag('a modelled gain reproduces from the published model'),
      caa.scoreGain === computeClassicalScore(improved) - computeClassicalScore(report.scoreComponents),
      `${caa.scoreGain}`,
    );
  }

  /* ── The hero says what the findings say ────────────────────────────── */
  for (const finding of report.findings) {
    check(tag(`"${finding.control}" has an owning hero card`), finding.id in CONTROL_NODE);
  }
  const hero = heroState(report);
  for (const node of Object.values(hero.nodes)) {
    const owned = report.findings.filter((finding) => CONTROL_NODE[finding.id] === node.key && !UNMEASURED.has(finding.status));
    const worst = Math.max(0, ...owned.map((finding) => SEVERITY_RANK[finding.severity] ?? 0));
    const verdict = resolveNodeVerdict(node);
    if (verdict.key === 'unmeasured' || verdict.key === 'failed') continue;
    check(
      tag(`${node.title} card is never calmer than its worst finding`),
      (VERDICT_RANK[verdict.key] ?? 0) >= worst,
      `${verdict.label} vs ${owned.map((f) => `${f.control}:${f.severity}`).join(', ')}`,
    );
  }
  /* The other direction: a card none of whose rows measured anything, and that
     carries no score, has not earned "Secure". The OCSP card read "Secure" on a
     Not Applicable row because a CT observation routed to it was a pass. */
  for (const node of Object.values(hero.nodes)) {
    const rows = report.findings.filter((finding) => CONTROL_NODE[finding.id] === node.key);
    if (rows.some((finding) => !UNMEASURED.has(finding.status)) || node.score !== null || node.state === 'idle') continue;
    const verdict = resolveNodeVerdict(node);
    check(tag(`${node.title} with nothing measured never reads Secure`), verdict.key !== 'secure', verdict.label);
  }
  const headersRow = report.findings.find((finding) => finding.id === 'http-security');
  if (headersRow && report.evidence.http.reachable) {
    const [hardened, total] = (headersRow.finding.match(/(\d+) of (\d+)/) ?? []).slice(1);
    check(
      tag('headers card counts the Findings row population'),
      hero.nodes.headers.lines.some((line) => line.startsWith(`${hardened}/${total} `)),
      `${hero.nodes.headers.lines.join(' | ')} vs ${headersRow.finding}`,
    );
  }
  const tlsRow = report.findings.find((finding) => finding.id === 'tls-version');
  if (tlsRow && report.evidence.tls) {
    const legacy = report.evidence.tls.supportedProtocols.some((p) => p === 'TLSv1' || p === 'TLSv1.1');
    check(
      tag('TLS card flags legacy protocols exactly when the row does'),
      hero.nodes.tls.lines.some((line) => /legacy/i.test(line)) === legacy && (tlsRow.status === 'High' || tlsRow.status === 'Critical') === legacy,
      hero.nodes.tls.lines.join(' | '),
    );
  }
  const caaRow = report.findings.find((finding) => finding.id === 'dns-caa');
  if (caaRow) {
    const line = hero.nodes.dns.lines.find((l) => /CAA/.test(l)) ?? '';
    check(
      tag('DNS card reads CAA the way the row does'),
      // The stage line ('CAA present / absent / unknown') and the evidence line
      // ('CAA record found / No CAA policy / not determined') are both accepted.
      caaRow.status === 'Unknown'
        ? /not determined|CAA unknown/.test(line)
        : caaRow.status === 'Healthy'
          ? /found|CAA present/.test(line)
          : /No CAA|CAA absent/.test(line),
      `${line} vs ${caaRow.status}`,
    );
  }
  for (const node of Object.values(hero.nodes)) {
    if (node.score !== null) check(tag(`${node.title} names what its number grades`), Boolean(node.scoreScope));
  }
  check(tag('the core readout is the encryption score'), hero.score === e.encryptionScore);
}

/* ══════════════════════════════════════════════════════════════ main ═══ */

async function loadReports(): Promise<Array<[string, PublicScanReport]>> {
  const dir = process.env.PUBLIC_SCAN_REPORTS_DIR;
  if (dir) {
    return readdirSync(dir)
      .filter((file) => file.endsWith('.json'))
      .map((file) => {
        const stored = JSON.parse(readFileSync(join(dir, file), 'utf8')) as PublicScanReport;
        // Re-derive with the CURRENT code: a saved report records evidence, not verdicts.
        // PUBLIC_SCAN_NO_REBUILD=1 judges the verdicts AS SAVED — the negative control
        // that proves these rules fail on reports produced before the fixes.
        const report = process.env.PUBLIC_SCAN_NO_REBUILD ? stored : rebuild(stored, stored.evidence);
        return [stored.target.host, report] as [string, PublicScanReport];
      });
  }
  const hosts = process.argv.slice(2).length ? process.argv.slice(2) : ['cloudflare.com', 'expired.badssl.com'];
  const reports: Array<[string, PublicScanReport]> = [];
  for (const host of hosts) {
    const started = Date.now();
    const stream: StreamFrame[] = [];
    const report = await assessPublicTarget({
      input: host,
      host,
      port: 443,
      onStage: (stage) => stream.push({ stage }),
      onObservation: (observation) =>
        stream.push({ observation: { ...observation, at: observation.at ?? Date.now() } as PublicScanObservation }),
    });
    LIVE_STREAM.set(report, stream);
    console.log(`  assessed ${host} in ${((Date.now() - started) / 1000).toFixed(1)}s · grade ${report.executive.grade}`);
    reports.push([host, report]);
  }
  return reports;
}

async function main(): Promise<void> {
  console.log('\n/public-scan cross-panel alignment\n');
  predicates();
  const reports = await loadReports();
  for (const [host, report] of reports) {
    const cases = process.env.PUBLIC_SCAN_NO_REBUILD ? ([['as saved', report]] as Array<[string, PublicScanReport]>) : variants(report);
    for (const [variant, derived] of cases) assertReport(`${host} · ${variant}`, derived);
  }
  if (failures.length) {
    console.log(`\n${failures.length} failure(s):`);
    for (const failure of failures) console.log(`  FAIL ${failure}`);
  }
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

void main().catch((error) => {
  console.error(error);
  process.exit(1);
});
