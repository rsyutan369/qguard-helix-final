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
 * The six category nodes rendered around the core. They mirror the reference
 * hero exactly: CAA/DNSSEC/CT evidence surfaces inside the DNS and certificate
 * nodes rather than as separate cards, which keeps the ring readable at the
 * width the hero actually has.
 */
export type QveNodeKey = 'dns' | 'tls' | 'certificate' | 'headers' | 'ocsp' | 'quantum';

export type QveNodeState = 'idle' | 'scanning' | 'pass' | 'warning' | 'critical' | 'failed';

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

/**
 * The colour a node's beam, ring and chrome carry.
 *
 * Order matters, and it is an escalation ladder:
 *
 *  1. A HIGH or CRITICAL severity observation wins outright. A node that scores
 *     88 but is serving an untrusted chain is red, not green — the worst thing
 *     observed about a surface is the thing an operator has to see first.
 *
 *  2. Otherwise the MEASURED BAND decides, once the node has been scored. This
 *     deliberately outranks the node's lifecycle state. The lifecycle status is
 *     a coarse per-observation heuristic (an HTTP surface with under half its
 *     headers hardened is flagged `critical` while it is being read); the band
 *     is a weighted aggregate of the published grading model. Letting the
 *     heuristic win painted a surface scoring 62 — a Fair C — in the same red
 *     as one scoring 12, which is precisely the kind of colour that stops
 *     meaning anything.
 *
 *  3. Before a score exists, the lifecycle state is all there is.
 */
export function beamColor(node: QveNode): string {
  if (isAlertSeverity(node.severity)) return QVE_COLOR.critical;
  if (node.band && node.hasEvidence) return QVE_BAND_COLOR[node.band];
  if (node.state === 'critical' || node.state === 'failed') return QVE_COLOR.critical;
  if (node.state === 'warning') return QVE_COLOR.warning;
  if (node.state === 'pass') return QVE_COLOR.pass;
  if (node.state === 'scanning') return QVE_COLOR.scanning;
  return QVE_COLOR.idle;
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
