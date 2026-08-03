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
export const NODE_SCORE_CATEGORIES: Record<QveNodeKey, readonly string[]> = {
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
    [QveNodeKey, readonly string[]]
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

/** Scanner ControlStatus → engine event status. */
function statusFromControl(status: string): ScanEventStatus {
  switch (status) {
    case 'Healthy':
      return 'pass';
    case 'Warning':
      return 'warning';
    case 'Critical':
    case 'Not Supported':
      return 'critical';
    default:
      // Unknown / Not Observable / Not Applicable — deliberately neutral.
      return 'info';
  }
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

  if (stage.state === 'complete' || stage.state === 'failed') {
    const failed = stage.state === 'failed';
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
  const provisional = observation.status === 'info' && /^Offering /.test(observation.detail);

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
 */
export function reportEvidenceEvents(report: PublicScanReport): ScanEvent[] {
  const asset = report.target.displayUrl;
  const now = Date.now();
  const events: ScanEvent[] = [];
  const push = (draft: EventDraft, progress = 100) => {
    events.push(make(draft, progress, asset, now));
  };

  const { evidence, executive, intelligence } = report;
  const engines = evidence.engines;
  const dns = engines.dns.data;
  const tls = evidence.tls;
  const certificate = evidence.certificateExtras;
  const http = evidence.http;
  const keyAgreement = evidence.keyAgreement;

  /* ── DNS & CAA ─────────────────────────────────────────────────────────── */

  const dnsReachable = dns.addressCount > 0;
  push({
    type: 'DNS_COMPLETED',
    category: 'dns',
    status: dnsReachable ? 'pass' : 'critical',
    severity: dnsReachable ? 'none' : 'high',
    verdict: dnsReachable ? 'Resolved' : 'Unresolved',
    finding: dnsReachable
      ? `${pluralize(dns.addressCount, 'address')} resolved · ${dns.resolvedVia}`
      : 'No public address records',
    nodeLine: dnsReachable ? `${pluralize(dns.addressCount, 'address')} resolved` : 'No address records',
    nodeProgress: 100,
    timelineLabel: 'DNS discovery',
    timelineDetail: dns.resolvedVia,
    details: { addresses: dns.addressCount, ipv4: dns.ipv4.length, ipv6: dns.ipv6.length },
  });

  push({
    type: 'CAA',
    category: 'dns',
    status: !dns.caaQueryable ? 'info' : dns.caaPresent ? 'pass' : 'warning',
    severity: !dns.caaQueryable ? 'info' : dns.caaPresent ? 'none' : 'low',
    verdict: !dns.caaQueryable ? 'Partial' : dns.caaPresent ? 'Secure' : 'Open issuance',
    finding: !dns.caaQueryable
      ? 'CAA not observable from this resolver'
      : dns.caaPresent
        ? `CAA record found · ${pluralize(dns.caaRecords.length, 'issuer')}`
        : 'No CAA issuance policy',
    nodeLine: !dns.caaQueryable ? 'CAA not observable' : dns.caaPresent ? 'CAA record found' : 'No CAA policy',
    timelineLabel: 'CAA issuance policy',
    timelineDetail: dns.caaAtName ?? dns.caaSource ?? undefined,
  });

  push({
    type: 'DNSSEC',
    category: 'dns',
    status: !dns.dnssecQueryable ? 'info' : dns.dnssecSigned ? 'pass' : 'warning',
    severity: !dns.dnssecQueryable ? 'info' : dns.dnssecSigned ? 'none' : 'low',
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
    const legacy = tls.supportedProtocols.filter((protocol) => /1\.0|1\.1|SSL/i.test(protocol));
    const hasTls13 = tls.supportedProtocols.some((protocol) => /1\.3/.test(protocol));
    push({
      type: 'TLS_PROTOCOLS',
      category: 'tls',
      status: legacy.length ? 'warning' : hasTls13 ? 'pass' : 'warning',
      severity: legacy.length ? 'medium' : 'none',
      verdict: legacy.length ? 'Legacy exposed' : hasTls13 ? 'Secure' : 'Dated',
      finding: legacy.length
        ? `Legacy protocols offered: ${legacy.join(', ')}`
        : `${tls.supportedProtocols.join(' / ')} accepted`,
      nodeLine: legacy.length
        ? `Legacy ${legacy.join(', ')} offered`
        : hasTls13
          ? 'TLS 1.3 enabled'
          : `${tls.tlsVersion} negotiated`,
      nodeProgress: 100,
      timelineLabel: 'Protocol enumeration',
      timelineDetail: `${pluralize(tls.protocolSupport.length, 'version')} probed`,
      details: { protocols: tls.supportedProtocols },
    });

    push({
      type: 'TLS_CIPHERS',
      category: 'tls',
      status: 'pass',
      severity: 'none',
      finding: `${tls.cipherSuite || 'Negotiated suite'} · ${pluralize(evidence.cipherSuites.length, 'suite')} enumerated`,
      nodeLine: evidence.cipherSuites.length
        ? `${pluralize(evidence.cipherSuites.length, 'suite')} confirmed`
        : 'Negotiated suite only',
      timelineLabel: 'Cipher analysis',
      timelineDetail: tls.cipherSuite || undefined,
      details: { suites: evidence.cipherSuites.length },
    });

    push({
      type: 'TLS_PFS',
      category: 'tls',
      status: keyAgreement.forwardSecrecy ? 'pass' : 'warning',
      severity: keyAgreement.forwardSecrecy ? 'none' : 'medium',
      finding: keyAgreement.forwardSecrecy
        ? `Forward secrecy via ${keyAgreement.primaryGroup ?? (tls.keyExchange || 'ephemeral key agreement')}`
        : 'Forward secrecy not established',
      // Timeline only when secrecy holds; a failure earns a card line.
      nodeLine: keyAgreement.forwardSecrecy ? null : 'No forward secrecy',
      timelineLabel: 'Forward secrecy',
      timelineDetail: keyAgreement.forwardSecrecyBasis,
    });
  } else {
    push({
      type: 'ERROR',
      category: 'tls',
      status: 'failed',
      severity: 'high',
      verdict: 'No handshake',
      finding: report.degradedReason ?? 'TLS handshake could not be completed',
      nodeProgress: 100,
      timelineLabel: 'TLS negotiation failed',
    });
  }

  /* ── Certificate chain ─────────────────────────────────────────────────── */

  if (certificate) {
    push({
      type: 'TLS_CERTIFICATE',
      category: 'certificate',
      status: certificate.chainTrusted ? 'pass' : 'critical',
      severity: certificate.chainTrusted ? 'none' : 'high',
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
      status: certificate.signedCertificateTimestamps ? 'pass' : 'warning',
      severity: certificate.signedCertificateTimestamps ? 'none' : 'low',
      finding: certificate.signedCertificateTimestamps
        ? `${pluralize(certificate.sctCount, 'SCT')} in Certificate Transparency`
        : 'No embedded Certificate Transparency SCTs',
      nodeLine: pluralize(certificate.chainDepth, 'certificate'),
      timelineLabel: 'CT log verification',
    });

    /* ── OCSP & revocation ───────────────────────────────────────────────── */

    push({
      type: 'OCSP',
      category: 'ocsp',
      status: certificate.ocspStapled ? 'pass' : certificate.ocspUri ? 'warning' : 'info',
      severity: certificate.ocspStapled ? 'none' : certificate.ocspUri ? 'low' : 'info',
      verdict: certificate.ocspStapled ? 'Secure' : certificate.ocspUri ? 'Not stapled' : 'No responder',
      finding: certificate.ocspStapled
        ? 'Stapling enabled'
        : certificate.ocspUri
          ? 'Responder published, response not stapled'
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
      status: certificate.mustStaple ? 'pass' : 'info',
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
      type: 'ERROR',
      category: 'certificate',
      status: 'failed',
      severity: 'high',
      verdict: 'Unavailable',
      finding: 'Certificate chain could not be collected',
      nodeProgress: 100,
      timelineLabel: 'Certificate collection failed',
    });
    push({
      type: 'OCSP',
      category: 'ocsp',
      status: 'info',
      severity: 'info',
      verdict: 'Not observable',
      finding: 'Revocation state requires a served chain',
      nodeProgress: 100,
      timeline: false,
    });
  }

  /* ── HTTP headers ──────────────────────────────────────────────────────── */

  if (http.reachable) {
    const total = http.headers.length;
    const secure = http.headers.filter((header) => header.secure).length;
    const ratio = total ? secure / total : 0;
    push({
      type: 'HEADERS',
      category: 'headers',
      status: ratio >= 0.8 ? 'pass' : ratio >= 0.5 ? 'warning' : 'critical',
      severity: ratio >= 0.8 ? 'none' : ratio >= 0.5 ? 'low' : 'medium',
      verdict: ratio >= 0.8 ? 'Good' : ratio >= 0.5 ? 'Fair' : 'Weak',
      finding: `${secure}/${total} security headers detected`,
      nodeLine: `${secure}/${total} headers hardened`,
      nodeProgress: 100,
      timelineLabel: 'HTTP headers',
      timelineDetail: `HTTP ${http.statusCode ?? '—'}${http.server ? ` · ${http.server}` : ''}`,
      details: { secure, total },
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
      type: 'ERROR',
      category: 'headers',
      status: 'failed',
      severity: 'medium',
      verdict: 'Unreachable',
      finding: http.error ?? 'Origin did not answer over HTTPS',
      nodeProgress: 100,
      timelineLabel: 'HTTP probe failed',
    });
  }

  /* ── Post-quantum readiness ────────────────────────────────────────────── */

  const hybrid = keyAgreement.hybridGroups;
  const pqReady = hybrid.length > 0;

  push({
    type: 'PQ_DISCOVERY',
    category: 'quantum',
    status: keyAgreement.probed ? 'info' : 'info',
    severity: 'info',
    finding: keyAgreement.probed
      ? `${pluralize(hybrid.length + keyAgreement.classicalGroups.length, 'named group')} probed individually`
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

  push({
    type: 'PQ_KEM',
    category: 'quantum',
    status: pqReady ? 'pass' : 'warning',
    severity: pqReady ? 'none' : 'medium',
    postQuantum: pqReady,
    verdict: pqReady ? 'Hybrid ready' : executive.postQuantumReadiness >= 40 ? 'Fair' : 'Classical only',
    finding: pqReady
      ? `ML-KEM key establishment active (${keyAgreement.primaryGroup ?? hybrid[0]})`
      : 'Hybrid not detected · classical key establishment only',
    nodeLine: pqReady ? `${keyAgreement.primaryGroup ?? hybrid[0]} active` : 'Hybrid not detected',
    nodeProgress: 100,
    timelineLabel: 'ML-KEM key establishment',
    timelineDetail: `PQ readiness ${executive.postQuantumReadiness}%`,
    details: { readiness: executive.postQuantumReadiness },
  });

  const signature = report.evidence.certificate?.signatureAlgorithm ?? null;
  push({
    type: 'PQ_SIGNATURE',
    category: 'quantum',
    status: 'info',
    severity: 'info',
    finding: signature
      ? `Certificate signed with ${signature} — ML-DSA migration target`
      : 'Signature algorithm not observable',
    nodeLine: signature ? 'Classical signatures' : 'Signatures not observable',
    timelineLabel: 'Signature algorithm',
    timelineDetail: intelligence.quantumVulnerabilityReason,
  });

  /* ── Findings that matter ──────────────────────────────────────────────── */

  for (const finding of report.findings) {
    if (finding.severity !== 'CRITICAL' && finding.severity !== 'HIGH') continue;
    push({
      type: 'FINDING',
      category: 'scan',
      status: statusFromControl(finding.status),
      severity: severityFromThreat(finding.severity),
      finding: finding.finding,
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
    timelineDetail: `Grade ${executive.grade} · score ${executive.encryptionScore}/100 · ${(report.durationMs / 1000).toFixed(1)}s`,
    details: {
      grade: executive.grade,
      score: executive.encryptionScore,
      postQuantum: pqReady,
    },
  });

  return events;
}
