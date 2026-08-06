/**
 * Quantum Visualization Engine™ (QVE) — type contract.
 *
 * The QVE is the visualization subsystem behind the /public-scan hero. It is
 * deliberately isolated from the scanning logic: it consumes a stream of
 * `ScanEvent`s and knows nothing about how they were produced, so the same
 * engine can be mounted on the Quantum Readiness dashboard, Migration Sandbox
 * or a future SOC view without dragging the public scanner along with it.
 *
 * HONESTY CONTRACT — the reason this file exists rather than an animation
 * timeline: every visual state in the engine is a pure function of the events
 * it has received. There is no timer that "advances the scan". Progress, node
 * status, beam colour, score ring and grade are all derived from real
 * `/api/v1/public-scan/stream` frames and from the completed report's own
 * evidence. When no events have arrived the engine renders an explicit idle
 * state instead of inventing one.
 */

/* ------------------------------------------------------------------ events - */

/**
 * Event vocabulary. Lifecycle events (`*_STARTED` / `*_COMPLETED`) are emitted
 * from real SSE `stage` frames; the fine-grained evidence events (TLS_CIPHERS,
 * PQ_KEM, CT, …) are emitted from the completed report's evidence bundle, one
 * per observation that was actually made.
 */
export type ScanEventType =
  | 'SCAN_STARTED'
  | 'DNS_STARTED'
  | 'DNS_COMPLETED'
  | 'TLS_STARTED'
  | 'TLS_PROTOCOLS'
  | 'TLS_CIPHERS'
  | 'TLS_PFS'
  | 'TLS_CERTIFICATE'
  | 'OCSP'
  | 'HEADERS'
  | 'CAA'
  | 'DNSSEC'
  | 'CT'
  | 'PQ_DISCOVERY'
  | 'PQC_GROUP'
  | 'PQ_KEM'
  | 'PQ_SIGNATURE'
  | 'FINDING'
  | 'WARNING'
  | 'ERROR'
  | 'SCAN_COMPLETED';

/** Verdict carried by an event. Mirrors the scanner's seven-state model. */
export type ScanEventStatus = 'running' | 'pass' | 'warning' | 'critical' | 'info' | 'failed';

/** Severity ramp — drives beam colour, sparks and the alert pulse. */
export type ScanEventSeverity = 'none' | 'info' | 'low' | 'medium' | 'high' | 'critical';

/**
 * A single observation from the scan pipeline.
 *
 * `category` is a {@link QveNodeKey} for anything that belongs to a node, or
 * `'scan'` for lifecycle events that belong to the run as a whole.
 */
export interface ScanEvent {
  /** Stable identity so React lists and the packet engine can key on it. */
  id: string;
  type: ScanEventType;
  timestamp: number;
  category: QveNodeKey | 'scan';
  status: ScanEventStatus;
  /** 0-100 overall scan progress at the moment this event was observed. */
  progress: number;
  severity: ScanEventSeverity;
  /** Human-readable statement of what was observed. */
  finding?: string;
  /** The asset the observation is about (host:port). */
  asset?: string;
  details?: Record<string, unknown>;
}

/* ------------------------------------------------------------------- nodes - */

/**
 * Identity of a category node rendered around the core.
 *
 * Deliberately an open string rather than a closed union: the node ring is
 * supplied by whoever mounts the engine (see `QveProvider`'s `blueprints`
 * prop), because the categories a scan reports are a property of that scan, not
 * of the visualization. /public-scan mounts the six public-edge surfaces
 * (`QVE_NODE_BLUEPRINTS` — DNS/CAA, TLS, certificates, headers, OCSP, quantum);
 * the authenticated Dashboard Scanner mounts its own estate-discovery ring. A
 * closed union would have forced one surface's vocabulary onto the other.
 */
export type QveNodeKey = string;

/** The six public-edge node keys, for modules that speak specifically to them. */
export type QvePublicNodeKey = 'dns' | 'tls' | 'certificate' | 'headers' | 'ocsp' | 'quantum';

/**
 * `unmeasured` is a SETTLED state, not a transitional one: the modules behind
 * the surface reported and explicitly declined to measure it — an SSH probe
 * against a target with no SSH endpoint, a repository scanner with no
 * repository. It exists because such a module's event carries `status: 'info'`,
 * which previously fell through to `scanning` and left the card spinning for
 * the rest of the session on a scan that had demonstrably finished.
 */
export type QveNodeState = 'idle' | 'scanning' | 'unmeasured' | 'pass' | 'warning' | 'critical' | 'failed';

export interface QveNode {
  key: QveNodeKey;
  /** Uppercase title, e.g. "DNS & CAA". */
  title: string;
  state: QveNodeState;
  /** Verdict word under the title, e.g. "Secure", "Good", "Fair". */
  verdict: string;
  /** Up to two evidence lines under the verdict. */
  lines: string[];
  /** 0-100 completion for this node's own progress arc. */
  progress: number;
  severity: ScanEventSeverity;
  /** Timestamp of the most recent event routed to this node. */
  updatedAt: number;
  /** Set when the node carries post-quantum evidence — drives violet energy. */
  postQuantum: boolean;
  /**
   * True once at least one real observation has been routed here. Until then the
   * card is showing its idle legend, which must be replaced wholesale rather
   * than merged with — otherwise "Origin not queried" survives next to the
   * headers the scanner just read.
   */
  hasEvidence: boolean;
  /**
   * This node's own 0-100 score, as a weight-respecting aggregate of the
   * published grading model's categories that belong to it (see
   * `NODE_SCORE_CATEGORIES`). Null until the report lands — a node has no score
   * while it is still being measured, and inventing one would be the exact kind
   * of fabricated posture number the platform forbids.
   */
  score: number | null;
  /** Grade band derived from {@link score}. Null while unscored. */
  band: QveGradeBand | null;
}

/* ------------------------------------------------------------- engine state - */

export type QveRunState = 'idle' | 'scanning' | 'complete' | 'error';

export interface QveTimelineEntry {
  id: string;
  /** Elapsed time from SCAN_STARTED, formatted mm:ss. */
  clock: string;
  label: string;
  status: ScanEventStatus;
  severity: ScanEventSeverity;
  detail?: string;
}

export interface QveState {
  run: QveRunState;
  /** Epoch ms of SCAN_STARTED; null while idle. */
  startedAt: number | null;
  /** 0-100, from real stage completion only. */
  progress: number;
  /** Grade letter once the report lands, else null. */
  grade: string | null;
  gradeColor: string | null;
  /** Composite encryption score 0-100 driving the score ring. */
  score: number;
  /** Post-quantum readiness 0-100. */
  postQuantumScore: number;
  /** True once hybrid ML-KEM / ML-DSA evidence has been observed. */
  quantumDetected: boolean;
  /** Highest severity seen in this run — drives the core's alert state. */
  peakSeverity: ScanEventSeverity;
  nodes: Record<QveNodeKey, QveNode>;
  events: ScanEvent[];
  timeline: QveTimelineEntry[];
  /** Monotonic counter incremented on every ingested event; cheap render key. */
  tick: number;
  asset: string | null;
  errorMessage: string | null;
}

/* ------------------------------------------------------------------ colours - */

/**
 * Beam / packet palette. Blue → green → amber → red by verdict, violet for
 * post-quantum energy, exactly as specified by the engine guidelines.
 *
 * `idle` is deliberately NOT slate-800. A conduit at `#334155` over the hero's
 * `#040810` backdrop is below the threshold at which a 1px stroke is visible at
 * all, which made the two nodes that settle last — OCSP and Quantum Readiness —
 * look disconnected from the core for most of the run. The topology must read
 * before a scan starts, so the dormant conduit is a dimmed steel that survives
 * the backdrop.
 */
export const QVE_COLOR = {
  scanning: '#38bdf8',
  pass: '#34d399',
  warning: '#fbbf24',
  /**
   * HIGH severity. Distinct from `critical` on purpose: "at risk" and
   * "critical" are different verdicts and must not share a colour, or the card
   * cannot tell an operator which surface to open first. Matches the HIGH tone
   * the findings lists already use.
   */
  high: '#fb923c',
  critical: '#f43f5e',
  quantum: '#a78bfa',
  idle: '#64748b',
  cyan: '#22d3ee',
} as const;

/* ------------------------------------------------------------- grade bands - */

/**
 * Verdict bands. These are the colour of a *measured posture*, not decoration,
 * so they follow the published grading vocabulary:
 *
 *   elite / excellent   green   — hardened, nothing outstanding
 *   good / fair         cyan    — acceptable, with work to do
 *   weak                amber   — degraded controls
 *   critical            red     — critical or high-severity exposure
 *
 * Green and cyan are each shared by two bands on purpose: the band name is the
 * precise statement and the colour is the at-a-glance one, and four colours is
 * the most a viewer can reliably separate in peripheral vision on a beam.
 */
export type QveGradeBand = 'elite' | 'excellent' | 'good' | 'fair' | 'weak' | 'critical';

export const QVE_BAND_COLOR: Record<QveGradeBand, string> = {
  elite: '#34d399',
  excellent: '#34d399',
  good: '#22d3ee',
  fair: '#22d3ee',
  weak: '#fbbf24',
  critical: '#f43f5e',
};

export const QVE_BAND_LABEL: Record<QveGradeBand, string> = {
  elite: 'Elite',
  excellent: 'Excellent',
  good: 'Good',
  fair: 'Fair',
  weak: 'Weak',
  critical: 'Critical',
};

/**
 * Score → band. Thresholds are aligned to the scanner's own
 * `SCORE_GRADE_TABLE`: 90+ is A-and-above, 80+ is B+/A-, 70+ is B-/B, 60+ is
 * C-/C+, below 50 is D/F. Keeping the cuts on the same boundaries is what stops
 * a beam from reading green next to a card that says C.
 */
export function bandForScore(score: number): QveGradeBand {
  if (score >= 95) return 'elite';
  if (score >= 85) return 'excellent';
  if (score >= 75) return 'good';
  if (score >= 60) return 'fair';
  if (score >= 50) return 'weak';
  return 'critical';
}

/* ------------------------------------------------------------ node verdict - */

/**
 * The canonical security state of a node. ONE value, from which the label, the
 * accent colour, the badge icon, the border and the meter are all derived.
 */
export type QveVerdictKey =
  | 'idle'
  | 'scanning'
  | 'unmeasured'
  | 'failed'
  | 'critical'
  | 'at-risk'
  | 'review'
  | 'secure';

export interface QveResolvedVerdict {
  key: QveVerdictKey;
  /** The word rendered in {@link color}. Never contradicts it. */
  label: string;
  color: string;
  /** True when the state warrants alert chrome (shake, spark, red/orange). */
  alert: boolean;
  /** Why this state was assigned — shown as the card's tooltip. */
  basis: string;
}

/**
 * Resolve a node's ONE security state.
 *
 * This exists because the card used to carry two independent aggregations of
 * the same surface and render them side by side. `node.verdict` was whatever
 * the LAST module routed to the node happened to say, while the accent colour
 * came from `node.severity`, the worst severity of ANY event ever routed there.
 * A transport surface whose final module reported clean while four static-RSA
 * cipher suites had already landed rendered the word "Secure" in critical red.
 *
 * The ladder, in order:
 *
 *  1. Lifecycle first — idle, scanning and failed are states of the RUN, and no
 *     amount of evidence changes what they mean.
 *
 *  2. A settled node with no evidence is `unmeasured`, not a pass. "Nothing was
 *     measured here" and "everything measured here was clean" are different
 *     answers and must never share a colour.
 *
 *  3. Peak observed severity sets the class. CRITICAL → Critical, HIGH → At
 *     Risk, MEDIUM → Review. The worst thing actually observed about a surface
 *     is the thing an operator has to see first, and unlike an average it
 *     cannot be diluted by counting one fact several ways.
 *
 *  4. Below MEDIUM the measured BAND decides, so a clean-but-dated surface
 *     reads Good/Fair rather than a flat green. The band's colour and its label
 *     come from the same table, so they cannot disagree either.
 *
 *  5. Otherwise: Secure.
 *
 * The band can refine a non-alert verdict but can never manufacture an alert
 * one: the score is a mean over findings, and a mean over a surface that
 * restates one certificate five ways is not evidence of five problems.
 */
export function resolveNodeVerdict(node: QveNode): QveResolvedVerdict {
  if (node.state === 'idle') {
    return { key: 'idle', label: node.verdict || 'Standby', color: QVE_COLOR.idle, alert: false, basis: 'No evidence collected for this surface yet.' };
  }
  if (node.state === 'scanning') {
    return { key: 'scanning', label: 'Scanning', color: QVE_COLOR.scanning, alert: false, basis: 'This surface is being measured now.' };
  }
  if (node.state === 'failed') {
    return { key: 'failed', label: 'Failed', color: QVE_COLOR.critical, alert: true, basis: 'A module behind this surface did not complete, so the surface is unassessed.' };
  }
  /* A module that declined to measure this surface reported a reason, and the
     reason is the point — "not applicable" is a measured answer, but it is not
     a pass and must never be painted like one. */
  if (node.state === 'unmeasured') {
    return {
      key: 'unmeasured',
      label: 'Not applicable',
      color: QVE_COLOR.idle,
      alert: false,
      basis:
        node.lines[0] ??
        'The modules behind this surface reported that it does not apply to the submitted targets. This is not a pass.',
    };
  }
  if (!node.hasEvidence) {
    return {
      key: 'unmeasured',
      label: 'Not measured',
      color: QVE_COLOR.idle,
      alert: false,
      basis: 'The modules behind this surface reported, but the target exposed nothing here to measure. This is not a pass.',
    };
  }

  const scored = node.score !== null ? ` Measured posture ${node.score}/100.` : '';

  if (node.severity === 'critical') {
    return { key: 'critical', label: 'Critical', color: QVE_COLOR.critical, alert: true, basis: `At least one CRITICAL finding was observed on this surface.${scored}` };
  }
  if (node.severity === 'high') {
    return { key: 'at-risk', label: 'At Risk', color: QVE_COLOR.high, alert: true, basis: `The most severe finding on this surface is HIGH.${scored}` };
  }
  if (node.severity === 'medium' || node.state === 'warning') {
    return { key: 'review', label: 'Review', color: QVE_COLOR.warning, alert: false, basis: `The most severe finding on this surface is MEDIUM.${scored}` };
  }
  if (node.band) {
    /* The band refines a calm verdict; it cannot manufacture an alarming one.
       Nothing above LOW was observed here, so the surface must not be labelled
       Critical on the strength of an average — the score is a mean over
       findings, and a mean over a surface that restates one certificate five
       ways is not evidence of five problems. A degraded aggregate with no
       severe finding is a Review, and says so. */
    const alarmingBand = node.band === 'critical' || node.band === 'weak';
    if (alarmingBand) {
      return {
        key: 'review',
        label: 'Review',
        color: QVE_COLOR.warning,
        alert: false,
        basis: `No finding above LOW was observed, but the aggregate posture is ${QVE_BAND_LABEL[node.band].toLowerCase()}.${scored}`,
      };
    }
    return {
      key: 'secure',
      label: QVE_BAND_LABEL[node.band],
      color: QVE_BAND_COLOR[node.band],
      alert: false,
      basis: `No finding above LOW was observed on this surface.${scored}`,
    };
  }
  return { key: 'secure', label: 'Secure', color: QVE_COLOR.pass, alert: false, basis: `No finding above LOW was observed on this surface.${scored}` };
}

/**
 * The colour a node's beam, ring and chrome carry.
 *
 * Delegates to {@link resolveNodeVerdict} rather than running its own ladder:
 * the colour and the word beside it are the same function of the same input, so
 * "Secure" can never be painted red.
 */
export function beamColor(node: QveNode): string {
  return resolveNodeVerdict(node).color;
}

/** Quantum-wave colour ramp, keyed off the published grade letter. */
export function gradeWaveColors(grade: string | null): [string, string] {
  switch (grade) {
    case 'A+':
      return [QVE_COLOR.quantum, QVE_COLOR.cyan];
    case 'A':
    case 'A-':
      return ['#38bdf8', '#22d3ee'];
    case 'B+':
    case 'B':
    case 'B-':
      return ['#34d399', '#22d3ee'];
    case 'C+':
    case 'C':
    case 'C-':
      return ['#fbbf24', '#a3e635'];
    case 'D':
      return ['#fb923c', '#fbbf24'];
    case 'F':
      return ['#f43f5e', '#fb7185'];
    default:
      return ['#38bdf8', '#a78bfa'];
  }
}

const SEVERITY_RANK: Record<ScanEventSeverity, number> = {
  none: 0,
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};

export function maxSeverity(a: ScanEventSeverity, b: ScanEventSeverity): ScanEventSeverity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

export function isAlertSeverity(severity: ScanEventSeverity): boolean {
  return SEVERITY_RANK[severity] >= SEVERITY_RANK.high;
}
