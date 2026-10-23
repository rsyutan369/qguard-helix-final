/**
 * Quantum Visualization Engine™ — event derivation (pure).
 *
 * Translates what the scanner actually reported into the engine's
 * {@link ScanEvent} vocabulary. Two sources, both real:
 *
 *  1. SSE `stage` frames  → lifecycle events (`*_STARTED` / `*_COMPLETED`).
 *     Emitted the moment the backend says a module started or finished, with
 *     the backend's own `detail` string carried through verbatim.
 *
 *  2. The completed report → one evidence event per observation the scan made
 *     (protocols probed, cipher suites enumerated, forward secrecy, chain
 *     trust, OCSP, CT, CAA, DNSSEC, named PQ key groups, findings).
 *
 * Nothing in here invents a value. Where the scanner could not observe
 * something the derived event says so (`status: 'info'`, "not observable")
 * rather than defaulting to a pass or a fail — that distinction is the whole
 * point of the scanner's seven-state model and the visualization must not
 * flatten it.
 */

import type {
  PublicScanReport,
  PublicScanStage,
  PublicScanStageKey,
} from '@/lib/scanner/public-scan/types';
import type { PublicScanObservation } from '@/hooks/use-public-scan';
import type {
  QveNodeKey,
  QvePublicNodeKey,
  ScanEvent,
  ScanEventSeverity,
  ScanEventStatus,
  ScanEventType,
} from './types';

/* ------------------------------------------------------------- node scoring - */

/**
 * Which of the report's twelve published grading categories belong to each
 * node. This is a projection of the SAME model that produces the headline
 * grade — not a second scoring scheme — so a node can never disagree with the
 * report it came from.
 *
 * `certificate-transparency` sits under Certificates rather than OCSP even
 * though the OCSP card surfaces an SCT count: CT is a property of the issued
 * certificate, and scoring it twice would double-count it.
 */
export const NODE_SCORE_CATEGORIES: Record<QvePublicNodeKey, readonly string[]> = {
  dns: ['dns-caa'],
  tls: ['tls-configuration', 'cipher-suites', 'forward-secrecy'],
  certificate: ['certificates', 'certificate-transparency'],
  headers: ['http-security-headers', 'hsts'],
  ocsp: ['ocsp-stapling'],
  quantum: ['key-exchange', 'cryptographic-algorithms', 'post-quantum-readiness'],
};

/**
 * Per-node 0-100 scores, weighted by each category's published weight.
 *
 * Inapplicable categories are excluded entirely rather than scored as zero —
 * the grading model already redistributes their weight, and a node whose only
 * category was unobservable returns no score at all so the UI can keep showing
 * "not measured" instead of painting it red.
 */
export function nodeScoresFromReport(report: PublicScanReport): Partial<Record<QveNodeKey, number>> {
  const byKey = new Map(report.scoreComponents.map((component) => [component.key, component]));
  const scores: Partial<Record<QveNodeKey, number>> = {};

  for (const [node, categories] of Object.entries(NODE_SCORE_CATEGORIES) as Array<
    [QvePublicNodeKey, readonly string[]]
  >) {
    let weighted = 0;
    let weight = 0;
    for (const category of categories) {
      const component = byKey.get(category);
      if (!component || !component.applicable) continue;
      weighted += component.score * component.weight;
      weight += component.weight;
    }
    if (weight > 0) scores[node] = Math.round(weighted / weight);
  }

  return scores;
}

/**
 * What each node's number is a score OF, for the card face — the applicable
 * published categories it projects, by label.
 *
 * Without it a single-category surface reads as a verdict on the whole surface:
 * "DNS & CAA · Critical · 0" on a domain whose only scored control is a missing
 * CAA record. The Dashboard Scanner already names its scopes; the public hero
 * now does too, from the same category table its scores come from.
 */
export function nodeScoreScopesFromReport(report: PublicScanReport): Partial<Record<QveNodeKey, string>> {
  const byKey = new Map(report.scoreComponents.map((component) => [component.key, component]));
  const scopes: Partial<Record<QveNodeKey, string>> = {};
  for (const [node, categories] of Object.entries(NODE_SCORE_CATEGORIES) as Array<
    [QvePublicNodeKey, readonly string[]]
  >) {
    const measured = categories
      .map((key) => byKey.get(key))
      .filter((component) => component?.applicable)
      .map((component) => component!.label);
    if (measured.length) scopes[node] = measured.join(' + ');
  }
  return scopes;
}

/**
 * The surface that owns each Public Findings row.
 *
 * Every assessed control belongs to exactly one card, so a card can be held to
 * the rows it summarises. Findings used to be routed to the run as a whole
 * ('scan'), which left each card's verdict to the derivation's own heuristics:
 * google.com's TLS card read "Fair · TLS 1.3 enabled" while the Findings table
 * listed TLS Version as HIGH for still accepting TLS 1.0, and cloudflare.com's
 * Quantum Readiness card read "Good" beside a CRITICAL Quantum Risk row.
 *
 * Grouping mirrors {@link NODE_SCORE_CATEGORIES}: Certificate Transparency is a
 * property of the issued certificate, so its row sits with Certificates.
 * `tools/public-scan-hero-alignment-check.ts` fails when a finding has no owner.
 */
export const CONTROL_NODE: Record<string, QvePublicNodeKey> = {
  'dns-caa': 'dns',
  dnssec: 'dns',
  'email-authentication': 'dns',
  'tls-version': 'tls',
  'cipher-suite': 'tls',
  'forward-secrecy': 'tls',
  alpn: 'tls',
  'certificate-algorithm': 'certificate',
  'certificate-issuer': 'certificate',
  'certificate-lifetime': 'certificate',
  'certificate-transparency': 'certificate',
  'hostname-coverage': 'certificate',
  hsts: 'headers',
  'http-security': 'headers',
  'ocsp-stapling': 'ocsp',
  'pq-key-agreement': 'quantum',
  'quantum-risk': 'quantum',
};

/* ------------------------------------------------------------------ helpers - */

let sequence = 0;
/** Monotonic ids — two events observed in the same millisecond stay distinct. */
function nextId(prefix: string): string {
  sequence += 1;
  return `${prefix}-${sequence}`;
}

interface EventDraft {
  type: ScanEventType;
  category: QveNodeKey | 'scan';
  status: ScanEventStatus;
  severity?: ScanEventSeverity;
  /** Full statement of the observation — timeline and inspector. */
  finding?: string;
  /**
   * Short form for the node card, which is ~200px wide. `null` marks a
   * timeline-only observation that must not take a card line. Omitted falls
   * back to `finding`.
   */
  nodeLine?: string | null;
  timelineLabel?: string;
  timelineDetail?: string;
  verdict?: string;
  nodeProgress?: number;
  postQuantum?: boolean;
  timeline?: boolean;
  /**
   * Why the surface is unmeasured, when it is. See
   * {@link QveNode.unmeasuredReason} — typed so the card's label never comes
   * from a free-text engine phrase.
   */
  unmeasuredReason?: 'not-applicable' | 'not-measured';
  details?: Record<string, unknown>;
}

function make(draft: EventDraft, progress: number, asset: string | null, timestamp: number): ScanEvent {
  const {
    type,
    category,
    status,
    severity = 'info',
    finding,
    nodeLine,
    timelineLabel,
    timelineDetail,
    verdict,
    nodeProgress,
    postQuantum,
    timeline,
    unmeasuredReason,
    details,
  } = draft;
  return {
    id: nextId(type),
    type,
    timestamp,
    category,
    status,
    progress,
    severity,
    finding,
    asset: asset ?? undefined,
    details: {
      ...details,
      ...(nodeLine !== undefined ? { nodeLine } : {}),
      ...(timelineLabel !== undefined ? { timelineLabel } : {}),
      ...(timelineDetail !== undefined ? { timelineDetail } : {}),
      ...(verdict !== undefined ? { verdict } : {}),
      ...(nodeProgress !== undefined ? { nodeProgress } : {}),
      ...(postQuantum !== undefined ? { postQuantum } : {}),
      ...(timeline !== undefined ? { timeline } : {}),
      ...(unmeasuredReason !== undefined ? { unmeasuredReason } : {}),
    },
  };
}

/** ThreatLevel → engine severity. */
function severityFromThreat(level: string): ScanEventSeverity {
  switch (level) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    default:
      return 'none';
  }
}

/**
 * Scanner ControlStatus → engine event status.
 *
 * `High` is a failure tier (a CRITICAL-looking control reconciled to HIGH
 * severity). It had no case here, so every HIGH row fell through to the neutral
 * `info` of an unmeasured control.
 */
function statusFromControl(status: string): ScanEventStatus {
  switch (status) {
    case 'Healthy':
      return 'pass';
    case 'Warning':
      return 'warning';
    case 'Critical':
    case 'High':
    case 'Not Supported':
      return 'critical';
    default:
      // Unknown / Not Observable / Not Applicable — deliberately neutral.
      return 'info';
  }
}

/** Statuses that carry no verdict. Their LOW severity is a placeholder, not a finding. */
const UNMEASURED_STATUSES = new Set(['Unknown', 'Not Observable', 'Not Applicable']);

/** The severity a finding contributes to its surface — none when nothing was measured. */
function findingSeverity(finding: { status: string; severity: string }): ScanEventSeverity {
  return UNMEASURED_STATUSES.has(finding.status) ? 'info' : severityFromThreat(finding.severity);
}

/** Display form of a Node protocol name ("TLSv1" is TLS 1.0, not "TLS 1"). */
function protocolLabel(protocol: string): string {
  if (protocol === 'TLSv1') return 'TLS 1.0';
  return protocol.replace(/^TLSv/, 'TLS ');
}

const STAGE_NODE: Record<PublicScanStageKey, QveNodeKey | null> = {
  dns: 'dns',
  tls: 'tls',
  certificate: 'certificate',
  headers: 'headers',
  quantum: 'quantum',
  report: null,
};

const STAGE_STARTED: Partial<Record<PublicScanStageKey, ScanEventType>> = {
  dns: 'DNS_STARTED',
  tls: 'TLS_STARTED',
};

/* -------------------------------------------------------- lifecycle events - */

export function scanStartedEvent(asset: string): ScanEvent {
  return make(
    {
      type: 'SCAN_STARTED',
      category: 'scan',
      status: 'running',
      severity: 'info',
      finding: `Assessment started for ${asset}`,
      timelineLabel: 'Assessment started',
      timelineDetail: asset,
    },
    0,
    asset,
    Date.now(),
  );
}

/**
 * The run ended without a report: the server refused to start it, reported a
 * failure, or the stream was lost. Without this the engine never left
 * `scanning` — stage-level ERRORs are the only other source of one — so the
 * hero kept saying "Scanning · Collecting edge evidence" under a status bar
 * that said the assessment had not started.
 */
export function scanEndedEvent(asset: string, message: string, refused: boolean): ScanEvent {
  return make(
    {
      type: 'ERROR',
      category: 'scan',
      status: 'failed',
      severity: 'info',
      finding: message,
      timelineLabel: refused ? 'Assessment not started' : 'Assessment could not complete',
      timelineDetail: message,
    },
    0,
    asset,
    Date.now(),
  );
}

/**
 * One event per real stage transition. `previous` is the state we last saw for
 * that stage, so a repeated frame produces nothing.
 */
export function stageTransitionEvents(
  stage: PublicScanStage,
  previousState: PublicScanStage['state'] | undefined,
  progress: number,
  asset: string | null,
): ScanEvent[] {
  if (previousState === stage.state) return [];
  const node = STAGE_NODE[stage.key];
  const now = Date.now();

  if (stage.state === 'running') {
    const type = STAGE_STARTED[stage.key] ?? 'SCAN_STARTED';
    if (!node) return [];
    return [
      make(
        {
          type: type === 'SCAN_STARTED' ? 'PQ_DISCOVERY' : type,
          category: node,
          status: 'running',
          severity: 'info',
          finding: stage.description,
          verdict: 'Scanning',
          nodeProgress: 35,
          timelineLabel: stage.label,
          timelineDetail: stage.description,
        },
        progress,
        asset,
        now,
      ),
    ];
  }

  if (stage.state === 'complete' || stage.state === 'failed' || stage.state === 'unavailable') {
    /* `unavailable` is settled but NOT failed: the module never ran, so the
       surface has no verdict rather than a bad one. It resolves the node to
       `unmeasured` (grey) instead of `failed` (red) — the hero used to light four
       surfaces critical-red for an endpoint that simply had not answered. */
    const unmeasured = stage.state === 'unavailable';
    const failed = stage.state === 'failed';
    if (unmeasured) {
      if (!node) return [];
      return [
        make(
          {
            type: 'WARNING',
            category: node,
            status: 'info',
            severity: 'info',
            finding: stage.detail || `${stage.label} could not be measured`,
            verdict: 'Not measured',
            unmeasuredReason: 'not-measured',
            nodeProgress: 100,
            timelineLabel: stage.label,
            timelineDetail: stage.detail,
          },
          progress,
          asset,
          now,
        ),
      ];
    }
    const type: ScanEventType =
      stage.key === 'dns' ? 'DNS_COMPLETED' : failed ? 'ERROR' : stage.key === 'report' ? 'SCAN_COMPLETED' : 'HEADERS';
    if (!node) {
      // The `report` stage is run-level, not a node.
      return stage.key === 'report' && !failed
        ? []
        : [
            make(
              {
                type: 'WARNING',
                category: 'scan',
                status: 'warning',
                severity: 'medium',
                finding: stage.detail || `${stage.label} did not complete`,
                timelineLabel: stage.label,
                timelineDetail: stage.detail,
              },
              progress,
              asset,
              now,
            ),
          ];
    }
    return [
      make(
        {
          type: failed ? 'ERROR' : type,
          category: node,
          status: failed ? 'failed' : 'info',
          severity: failed ? 'high' : 'info',
          finding: stage.detail || stage.description,
          // A completed module does NOT get a placeholder verdict. It used to
          // stamp "Analyzing", which raced the module's own live observations:
          // whichever landed second won, so a card that had already reported
          // "Resolved" could fall back to "Analyzing" and sit there. Silence
          // here means "keep whatever the evidence said" — and a failure is the
          // one case where the lifecycle event IS the verdict.
          verdict: failed ? 'Unreachable' : undefined,
          nodeProgress: failed ? 100 : 75,
          timelineLabel: stage.label,
          timelineDetail: stage.detail,
        },
        progress,
        asset,
        now,
      ),
    ];
  }

  return [];
}

/* ------------------------------------------------------- live observations - */

/** Observation status → the engine's event status. */
const OBSERVATION_STATUS: Record<string, ScanEventStatus> = {
  pass: 'pass',
  warning: 'warning',
  critical: 'critical',
  info: 'info',
};

/**
 * A live measurement, as an engine event.
 *
 * These arrive DURING the scan, each stamped with the moment the scanner made
 * the measurement, so they are dispatched straight through rather than queued:
 * the pacing is the scan's own, which is the entire point. The completed
 * report still emits its full evidence set afterwards — the store de-duplicates
 * card lines, and the report remains the authoritative account of the run.
 */
export function observationEvent(
  observation: PublicScanObservation,
  progress: number,
  asset: string | null,
): ScanEvent {
  const status = OBSERVATION_STATUS[observation.status] ?? 'info';
  // A probe announcement ("Offering X in isolation") is deliberately given no
  // card line: it is work in progress, not a result, and must not displace
  // evidence a card has already earned.
  const provisional = observation.status === 'info' && /^(Offering|Probing) /.test(observation.detail);

  return make(
    {
      type: 'FINDING',
      category: observation.surface,
      status,
      severity: observation.severity,
      finding: observation.detail,
      nodeLine: provisional ? null : observation.detail,
      timelineLabel: observation.label,
      timelineDetail: observation.detail,
      verdict: observation.verdict,
      postQuantum: observation.postQuantum,
    },
    progress,
    asset,
    observation.at,
  );
}

/* ---------------------------------------------------------- evidence events - */

function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

/**
 * Every observation the completed report contains, as events. Ordered so the
 * timeline reads in the sequence the scan actually performed the work: DNS →
 * TLS → certificate → headers → revocation → post-quantum → findings.
 *
 * ONE VERDICT PER CONTROL. Each evidence event takes its status and severity
 * from the Public Findings row it restates, never from a heuristic of its own.
 * The heuristics had drifted from the rows: a headers ratio over a different
 * denominator ("6/9" beside "5 of 8"), a legacy-protocol regex that did not
 * match Node's "TLSv1" (so TLS 1.0 was never flagged), a CAA verdict that
 * ignored an unfinished RFC 8659 climb, and a forward-secrecy test that missed
 * TLS 1.3's guarantee. Reading the row makes the card and the table one fact.
 */
export function reportEvidenceEvents(report: PublicScanReport): ScanEvent[] {
  const asset = report.target.displayUrl;
  const now = Date.now();
  const events: ScanEvent[] = [];
  const push = (draft: EventDraft, progress = 100) => {
    events.push(make(draft, progress, asset, now));
  };

  const { evidence, executive } = report;
  const engines = evidence.engines;
  const dns = engines.dns.data;
  const tls = evidence.tls;
  const certificate = evidence.certificateExtras;
  const http = evidence.http;
  const keyAgreement = evidence.keyAgreement;

  const findingById = new Map(report.findings.map((finding) => [finding.id, finding]));
  /** Status + severity of the Public Findings row with this id, when it exists. */
  const tone = (id: string, fallback: { status: ScanEventStatus; severity: ScanEventSeverity }) => {
    const finding = findingById.get(id);
    return finding ? { status: statusFromControl(finding.status), severity: findingSeverity(finding) } : fallback;
  };

  /* The port never accepted a TCP connection, so the TLS / certificate / HTTP
     branches below have nothing to report. They are emitted as `info` +
     "Not measured" instead of `failed` + "TLS negotiation failed": the module did
     not fail, it was never able to run, and an ERROR event both paints the
     surface card critical-red and pushes the run's peak severity to high on the
     strength of an endpoint being switched off. */
  const unreachable = report.unreachable;
  const unreachableReason = report.reachability?.summary ?? 'the endpoint did not answer on this port';

  /* ── DNS & CAA ─────────────────────────────────────────────────────────── */

  const dnsReachable = dns.addressCount > 0;
  push({
    type: 'DNS_COMPLETED',
    category: 'dns',
    // Inventory, like the `internet-facing` row: resolving says nothing about
    // DNS security, so it must not settle the card as a pass on its own.
    status: dnsReachable ? 'info' : 'critical',
    severity: dnsReachable ? 'none' : 'high',
    verdict: dnsReachable ? 'Resolved' : 'Unresolved',
    finding: dnsReachable
      ? `${pluralize(dns.addressCount, 'address', 'addresses')} resolved · ${dns.resolvedVia}`
      : 'No public address records',
    nodeLine: dnsReachable ? `${pluralize(dns.addressCount, 'address', 'addresses')} resolved` : 'No address records',
    nodeProgress: 100,
    timelineLabel: 'DNS discovery',
    timelineDetail: dns.resolvedVia,
    details: { addresses: dns.addressCount, ipv4: dns.ipv4.length, ipv6: dns.ipv6.length },
  });

  /* Answered only when a resolver replied AND the climb reached the registrable
     domain — the `dns-caa` row's own rule. A leaf name with no RRset of its own
     inherits its apex's policy, so a half-finished climb proves nothing. */
  const caaAnswered = dns.caaQueryable && dns.caaClimbComplete;
  push({
    type: 'CAA',
    category: 'dns',
    ...tone('dns-caa', { status: 'info', severity: 'info' }),
    ...(!caaAnswered ? { unmeasuredReason: 'not-measured' as const } : {}),
    verdict: !caaAnswered ? 'Undetermined' : dns.caaPresent ? 'Secure' : 'Open issuance',
    finding: !caaAnswered
      ? dns.caaQueryable
        ? 'CAA undetermined — the climb to the registrable domain did not complete'
        : 'CAA not observable from this resolver'
      : dns.caaPresent
        ? `CAA record found · ${pluralize(dns.caaRecords.length, 'issuer')}`
        : 'No CAA issuance policy',
    nodeLine: !caaAnswered ? 'CAA not determined' : dns.caaPresent ? 'CAA record found' : 'No CAA policy',
    timelineLabel: 'CAA issuance policy',
    timelineDetail: dns.caaAtName ?? dns.caaSource ?? undefined,
  });

  push({
    type: 'DNSSEC',
    category: 'dns',
    ...tone('dnssec', { status: 'info', severity: 'info' }),
    finding: !dns.dnssecQueryable
      ? 'DNSSEC not observable'
      : dns.dnssecSigned
        ? `Zone signed${dns.dnssecValidated ? ', resolver-validated' : ''}`
        : 'Zone not DNSSEC-signed',
    // Timeline only: the DNS card's two lines belong to resolution and CAA.
    nodeLine: null,
    timelineLabel: 'DNSSEC validation',
  });

  /* ── TLS & protocols ───────────────────────────────────────────────────── */

  if (tls) {
    // Node names TLS 1.0 "TLSv1" — the `tls-version` row's exact predicate.
    const legacy = tls.supportedProtocols.filter((protocol) => protocol === 'TLSv1' || protocol === 'TLSv1.1');
    const hasTls13 = tls.supportedProtocols.includes('TLSv1.3');
    const legacyLabel = legacy.map(protocolLabel).join(', ');
    push({
      type: 'TLS_PROTOCOLS',
      category: 'tls',
      ...tone('tls-version', { status: 'info', severity: 'info' }),
      verdict: legacy.length ? 'Legacy exposed' : hasTls13 ? 'Secure' : 'Dated',
      finding: legacy.length
        ? `Legacy protocols accepted: ${legacyLabel}`
        : `${tls.supportedProtocols.map(protocolLabel).join(' / ')} accepted`,
      nodeLine: legacy.length
        ? `Legacy ${legacyLabel} accepted`
        : hasTls13
          ? 'TLS 1.3 enabled'
          : `${protocolLabel(tls.tlsVersion)} — no TLS 1.3`,
      nodeProgress: 100,
      timelineLabel: 'Protocol enumeration',
      timelineDetail: `${pluralize(tls.protocolSupport.length, 'version')} probed`,
      details: { protocols: tls.supportedProtocols },
    });

    const staticRsa = evidence.cipherSuites.some((suite) => suite.category === 'rsa-kex');
    push({
      type: 'TLS_CIPHERS',
      category: 'tls',
      ...tone('cipher-suite', { status: 'info', severity: 'info' }),
      finding: `${tls.cipherSuite || 'Negotiated suite'} · ${pluralize(evidence.cipherSuites.length, 'suite')} enumerated${
        staticRsa ? ' · static-RSA key transport accepted' : ''
      }`,
      nodeLine: staticRsa
        ? 'Static-RSA suites accepted'
        : evidence.cipherSuites.length
          ? `${pluralize(evidence.cipherSuites.length, 'suite')} confirmed`
          : 'Negotiated suite only',
      timelineLabel: 'Cipher analysis',
      timelineDetail: tls.cipherSuite || undefined,
      details: { suites: evidence.cipherSuites.length },
    });

    const forwardSecrecy = findingById.get('forward-secrecy');
    const secrecyHolds = forwardSecrecy?.status === 'Healthy';
    push({
      type: 'TLS_PFS',
      category: 'tls',
      ...tone('forward-secrecy', { status: 'info', severity: 'info' }),
      finding: forwardSecrecy ? `Forward secrecy: ${forwardSecrecy.finding}` : 'Forward secrecy not assessed',
      // Timeline only when secrecy holds; a gap earns a card line.
      nodeLine: secrecyHolds || !forwardSecrecy
        ? null
        : forwardSecrecy.status === 'Warning'
          ? 'Forward secrecy partial'
          : 'No forward secrecy',
      timelineLabel: 'Forward secrecy',
      timelineDetail: keyAgreement.forwardSecrecyBasis,
    });
  } else {
    push({
      type: unreachable ? 'WARNING' : 'ERROR',
      category: 'tls',
      status: unreachable ? 'info' : 'failed',
      severity: unreachable ? 'info' : 'high',
      verdict: unreachable ? 'Not measured' : 'No handshake',
      ...(unreachable ? { unmeasuredReason: 'not-measured' as const } : {}),
      finding: unreachable ? unreachableReason : (report.degradedReason ?? 'TLS handshake could not be completed'),
      nodeProgress: 100,
      timelineLabel: unreachable ? 'TLS not measured' : 'TLS negotiation failed',
    });
  }

  /* ── Certificate chain ─────────────────────────────────────────────────── */

  if (certificate) {
    push({
      type: 'TLS_CERTIFICATE',
      category: 'certificate',
      ...tone('certificate-issuer', {
        status: certificate.chainTrusted ? 'pass' : 'critical',
        severity: certificate.chainTrusted ? 'none' : 'high',
      }),
      verdict: certificate.chainTrusted ? 'Valid chain' : 'Untrusted chain',
      finding: certificate.chainTrusted
        ? `Valid chain · ${pluralize(certificate.chainDepth, 'certificate')}`
        : (certificate.trustError ?? 'Chain does not verify against the trust store'),
      nodeLine: certificate.chainTrusted ? 'Valid chain' : 'Chain not verified',
      nodeProgress: 100,
      timelineLabel: 'Certificate chain',
      timelineDetail: `${pluralize(certificate.sanCount, 'SAN')} · ${certificate.daysRemaining}d remaining`,
      details: { chainDepth: certificate.chainDepth, sanCount: certificate.sanCount },
    });

    push({
      type: 'CT',
      category: 'certificate',
      ...tone('certificate-transparency', { status: 'info', severity: 'info' }),
      finding: certificate.signedCertificateTimestamps
        ? `${pluralize(certificate.sctCount, 'SCT')} in Certificate Transparency`
        : 'No embedded Certificate Transparency SCTs',
      // The card's second line is the chain size; CT itself is in the timeline.
      nodeLine: pluralize(certificate.chainDepth, 'certificate'),
      timelineLabel: 'CT log verification',
    });

    /* ── OCSP & revocation ───────────────────────────────────────────────── */

    push({
      type: 'OCSP',
      category: 'ocsp',
      ...tone('ocsp-stapling', { status: 'info', severity: 'info' }),
      verdict: certificate.ocspStapled ? 'Secure' : certificate.ocspUri ? 'Not stapled' : 'No responder',
      ...(!certificate.ocspUri && !certificate.ocspStapled ? { unmeasuredReason: 'not-applicable' as const } : {}),
      finding: certificate.ocspStapled
        ? 'Stapling enabled'
        : certificate.ocspUri
          ? certificate.ocspResponderState === 'unreachable'
            ? 'Responder published but not answering, and no response stapled'
            : 'Responder published, response not stapled'
          : 'No OCSP responder in the certificate',
      nodeLine: certificate.ocspStapled
        ? 'Stapling enabled'
        : certificate.ocspUri
          ? 'Response not stapled'
          : 'No OCSP responder',
      nodeProgress: 100,
      timelineLabel: 'OCSP stapling',
      timelineDetail: certificate.ocspUri ?? undefined,
    });

    push({
      type: 'CT',
      category: 'ocsp',
      status: 'info',
      severity: 'info',
      finding: certificate.mustStaple
        ? 'must-staple asserted'
        : `${pluralize(certificate.sctCount, 'SCT')} · chain depth ${certificate.chainDepth}`,
      nodeLine: certificate.signedCertificateTimestamps
        ? `${pluralize(certificate.sctCount, 'SCT')} logged`
        : 'No CT SCTs',
      timeline: false,
    });
  } else {
    push({
      type: unreachable ? 'WARNING' : 'ERROR',
      category: 'certificate',
      status: unreachable ? 'info' : 'failed',
      severity: unreachable ? 'info' : 'high',
      verdict: unreachable ? 'Not measured' : 'Unavailable',
      ...(unreachable ? { unmeasuredReason: 'not-measured' as const } : {}),
      finding: unreachable
        ? `Chain not collected — ${unreachableReason}`
        : 'Certificate chain could not be collected',
      nodeProgress: 100,
      timelineLabel: unreachable ? 'Certificate not measured' : 'Certificate collection failed',
    });
    push({
      type: 'OCSP',
      category: 'ocsp',
      status: 'info',
      severity: 'info',
      verdict: 'Not observable',
      unmeasuredReason: 'not-measured',
      finding: 'Revocation state requires a served chain',
      nodeProgress: 100,
      timeline: false,
    });
  }

  /* ── HTTP headers ──────────────────────────────────────────────────────── */

  if (http.reachable) {
    /* The `http-security` row's population: HSTS is graded on its own card line
       and in its own category, and a header superseded by an equivalent control
       is exempt. Counting every header printed "6/9" on the card while the
       Findings table, the score decomposition and the live rail said "5 of 8". */
    const transport = http.headers.filter(
      (header) => header.name !== 'strict-transport-security' && header.applicable !== false,
    );
    const hardened = transport.filter((header) => header.secure).length;
    const ratio = transport.length ? hardened / transport.length : 0;
    push({
      type: 'HEADERS',
      category: 'headers',
      ...tone('http-security', { status: 'info', severity: 'info' }),
      verdict: ratio >= 0.8 ? 'Good' : ratio >= 0.5 ? 'Fair' : 'Weak',
      finding: `${hardened} of ${transport.length} transport headers hardened`,
      nodeLine: `${hardened}/${transport.length} headers hardened`,
      nodeProgress: 100,
      timelineLabel: 'HTTP headers',
      timelineDetail: `HTTP ${http.statusCode ?? '—'}${http.server ? ` · ${http.server}` : ''}`,
      details: { secure: hardened, total: transport.length },
    });

    push({
      type: 'HEADERS',
      category: 'headers',
      status: 'info',
      severity: 'info',
      finding: `HTTP ${http.statusCode}${http.server ? ` · ${http.server}` : ''}`,
      nodeLine: http.server ? `Served by ${http.server}` : `HTTP ${http.statusCode}`,
      timeline: false,
    });
  } else {
    push({
      type: unreachable ? 'WARNING' : 'ERROR',
      category: 'headers',
      status: unreachable ? 'info' : 'failed',
      severity: unreachable ? 'info' : 'medium',
      verdict: unreachable ? 'Not measured' : 'Unreachable',
      ...(unreachable ? { unmeasuredReason: 'not-measured' as const } : {}),
      finding: unreachable
        ? `Headers not collected — ${unreachableReason}`
        : (http.error ?? 'Origin did not answer over HTTPS'),
      nodeProgress: 100,
      timelineLabel: unreachable ? 'HTTP headers not measured' : 'HTTP probe failed',
    });
  }

  /* ── Post-quantum readiness ────────────────────────────────────────────── */

  const hybrid = keyAgreement.hybridGroups;
  const pureKem = keyAgreement.pureKemGroups ?? [];

  push({
    type: 'PQ_DISCOVERY',
    category: 'quantum',
    status: 'info',
    severity: 'info',
    finding: keyAgreement.probed
      ? `${pluralize(hybrid.length + pureKem.length + keyAgreement.classicalGroups.length, 'named group')} accepted when offered individually`
      : 'Named key-agreement groups could not be probed',
    nodeLine: null,
    timelineLabel: 'Quantum discovery',
    timelineDetail: keyAgreement.probed ? 'One group offered per handshake' : undefined,
  });

  for (const group of hybrid) {
    push({
      type: 'PQC_GROUP',
      category: 'quantum',
      status: 'pass',
      severity: 'none',
      postQuantum: true,
      verdict: 'Hybrid PQ',
      finding: `${group} accepted`,
      nodeLine: null,
      nodeProgress: 100,
      timelineLabel: `Hybrid group ${group}`,
    });
  }
  for (const group of pureKem) {
    push({
      type: 'PQC_GROUP',
      category: 'quantum',
      status: 'warning',
      severity: 'none',
      postQuantum: true,
      verdict: 'PQ only',
      finding: `${group} accepted — standalone ML-KEM, no classical hedge`,
      nodeLine: null,
      nodeProgress: 100,
      timelineLabel: `Standalone ML-KEM group ${group}`,
    });
  }

  /* The key-agreement case is read from the report, which reads it from the
     published model — never re-derived from the readiness percentage, and never
     "no TLS handshake completed" for a run whose handshake completed but whose
     hybrid probe did not settle. */
  const pqState = executive.postQuantumKeyAgreement;
  const pqKex = pqState === 'hybrid' || pqState === 'pure-kem';
  const pqRow = findingById.get('pq-key-agreement');
  const tls13Absent = Boolean(tls?.supportedProtocols.length) && !tls?.supportedProtocols.includes('TLSv1.3');
  push({
    type: 'PQ_KEM',
    category: 'quantum',
    ...tone('pq-key-agreement', { status: 'info', severity: 'info' }),
    ...(pqState === 'not-measured' && !tls ? { unmeasuredReason: 'not-measured' as const } : {}),
    postQuantum: pqKex,
    verdict:
      pqState === 'not-measured'
        ? 'Not measured'
        : pqState === 'hybrid'
          ? 'Hybrid ready'
          : pqState === 'pure-kem'
            ? 'PQ only'
            : tls13Absent
              ? 'No TLS 1.3'
              : 'Classical only',
    finding: executive.postQuantumDetail,
    nodeLine:
      pqState === 'not-measured'
        ? tls
          ? 'Hybrid probe not settled'
          : 'Not measured'
        : pqState === 'hybrid'
          ? `${keyAgreement.primaryGroup ?? hybrid[0]} active`
          : pqState === 'pure-kem'
            ? `${pureKem[0]} · no hybrid`
            : tls13Absent
              ? 'No TLS 1.3 — hybrid unavailable'
              : (pqRow?.status === 'Unknown' ? 'Hybrid not settled' : 'Hybrid not detected'),
    nodeProgress: 100,
    timelineLabel: 'ML-KEM key establishment',
    timelineDetail:
      executive.postQuantumReadiness === null
        ? 'PQ readiness not scored'
        : `PQ readiness ${executive.postQuantumReadiness}%`,
    details: { readiness: executive.postQuantumReadiness ?? undefined },
  });

  const signature = report.evidence.certificate?.signatureAlgorithm ?? null;
  const pqSignature = executive.postQuantumSignatureObserved;
  push({
    type: 'PQ_SIGNATURE',
    category: 'quantum',
    status: !signature ? 'info' : pqSignature ? 'pass' : 'info',
    severity: 'info',
    postQuantum: pqSignature,
    finding: !signature
      ? 'Signature algorithm not observable'
      : pqSignature
        ? `Certificate signed with ${signature} — post-quantum signature (FIPS 204/205)`
        : `Certificate signed with ${signature} — ML-DSA migration target`,
    nodeLine: !signature ? 'Signatures not observable' : pqSignature ? 'Post-quantum signature' : 'Classical signatures',
    timelineLabel: 'Signature algorithm',
    // The signature itself — this entry used to carry the key-agreement reason,
    // so the log read "Signature algorithm · Hybrid … key agreement accepted".
    timelineDetail: signature ? `${signature} · ${pqSignature ? 'post-quantum (FIPS 204/205)' : 'classical — ML-DSA migration target'}` : undefined,
  });

  /* ── Findings, each on the surface it describes ────────────────────────── */

  /* Every row of the Public Findings table reaches its own card, so a card's
     verdict can never read calmer than the most severe row the table lists for
     that surface. The row adds no card line (`nodeLine: null`) — it is the
     verdict's input, not new evidence — and only the alert-level rows earn a
     timeline entry, as before. */
  for (const finding of report.findings) {
    const severity = findingSeverity(finding);
    // A healthy or unmeasured row changes no verdict; replaying it would only
    // add packet bursts and audio cues for nothing.
    if (severity === 'none' || severity === 'info') continue;
    const alert = finding.severity === 'CRITICAL' || finding.severity === 'HIGH';
    push({
      type: 'FINDING',
      category: CONTROL_NODE[finding.id] ?? 'scan',
      status: statusFromControl(finding.status),
      severity,
      finding: finding.finding,
      nodeLine: null,
      timeline: alert,
      timelineLabel: finding.control,
      timelineDetail: finding.finding,
    });
  }

  /* ── Run complete ──────────────────────────────────────────────────────── */

  push({
    type: 'SCAN_COMPLETED',
    category: 'scan',
    status: report.degraded ? 'warning' : 'pass',
    severity: report.degraded ? 'medium' : 'none',
    finding: report.degraded
      ? `Assessment complete with limited evidence — grade ${executive.grade}`
      : `Assessment complete — grade ${executive.grade}`,
    timelineLabel: 'Assessment complete',
    timelineDetail: `Grade ${executive.grade} · ${
      executive.encryptionScore === null ? 'score withheld' : `score ${executive.encryptionScore}/100`
    } · ${(report.durationMs / 1000).toFixed(1)}s`,
    details: {
      grade: executive.grade,
      score: executive.encryptionScore ?? undefined,
      postQuantum: pqKex,
    },
  });

  return events;
}
