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
 */
export const QVE_COLOR = {
  scanning: '#38bdf8',
  pass: '#34d399',
  warning: '#fbbf24',
  critical: '#f43f5e',
  quantum: '#a78bfa',
  idle: '#334155',
  cyan: '#22d3ee',
} as const;

export function beamColor(node: QveNode): string {
  if (node.state === 'critical' || node.state === 'failed') return QVE_COLOR.critical;
  if (node.state === 'warning') return QVE_COLOR.warning;
  if (node.state === 'pass') return node.postQuantum ? QVE_COLOR.quantum : QVE_COLOR.pass;
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
