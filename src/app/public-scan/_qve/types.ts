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
import {
  RATING_TIERS,
  RISK_COLOR,
  RISK_ORDER,
  SCORE_GRADE_TABLE,
  arcBandColorFor,
  scoreToGrade,
} from '@/lib/scanner/public-scan/grading-model';
import type { RiskBand } from '@/lib/scanner/public-scan/types';

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
 * Verdict bands — the six ratings of the published Security Grade Reference
 * ("How the Grading Works"), nothing more.
 *
 * This used to be a hand-maintained table with its own thresholds (95/85/75/
 * 60/50) and its own four-colour palette, sitting alongside the published
 * `SCORE_GRADE_TABLE` (98/94/90/85/80/75/70/65/60/50) and its eleven grade
 * colours. Two tables describing one thing drift, and they had: a surface
 * measured at 8/100 — grade F, Critical, dark red in the published model —
 * rendered as an amber "Review" card with an amber beam.
 *
 * Everything below is now DERIVED from the grading model. There is no second
 * threshold list and no second palette to keep in step.
 */
export type QveGradeBand = 'elite' | 'excellent' | 'good' | 'fair' | 'weak' | 'critical';

/**
 * Band colour for the legend, taken from each rating's best grade.
 *
 * For anything that HAS a score, prefer {@link bandColorForScore}: a rating can
 * span grades of different colours (Fair covers B- blue, C+ yellow and C
 * orange), so only the score resolves the exact published colour.
 */
export const QVE_BAND_COLOR: Record<QveGradeBand, string> = RATING_TIERS.reduce(
  (map, tier) => {
    map[tier.rating.toLowerCase() as QveGradeBand] = tier.color;
    return map;
  },
  {} as Record<QveGradeBand, string>,
);

export const QVE_BAND_LABEL: Record<QveGradeBand, string> = RATING_TIERS.reduce(
  (map, tier) => {
    map[tier.rating.toLowerCase() as QveGradeBand] = tier.rating;
    return map;
  },
  {} as Record<QveGradeBand, string>,
);

/** Score → band, straight off the published score-to-grade table. */
export function bandForScore(score: number): QveGradeBand {
  return scoreToGrade(score).rating.toLowerCase() as QveGradeBand;
}

/**
 * The exact published colour for a score — `scoreToGrade(score).color`.
 * The card, its beam and the gauge segment under the same number therefore
 * cannot be different colours.
 */
export function bandColorForScore(score: number): string {
  return readableOnDark(arcBandColorFor(score));
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

/* ─────────────────────────────────────────────── legibility on the dark hero ─ */

/**
 * Raise a published grade colour to a legible luminance on the hero's dark card
 * surface, WITHOUT changing what it means.
 *
 * The Security Grade Reference is printed on a light table, where grade F's
 * `#991b1b` reads as a strong dark red. On the hero's `#070d1b` card the same
 * hex measures 2.33:1 against its background — under the 4.5:1 floor for the
 * 11.5px bold verdict label, i.e. the most important word on the card is the
 * hardest one to read.
 *
 * Only LIGHTNESS moves. Hue and saturation are untouched, so grade F stays the
 * same red and nothing about the semantic mapping changes; this is a rendering
 * transform for one surface, not a second palette. Every consumer goes through
 * this one function, so there is nothing to keep in step.
 */
const HERO_SURFACE: RGB = [7, 13, 27]; // #070d1b — the CategoryNode card fill
const MIN_LABEL_CONTRAST = 4.5;

type RGB = [number, number, number];

const toLinear = (channel: number): number => {
  const value = channel / 255;
  return value <= 0.03928 ? value / 12.92 : Math.pow((value + 0.055) / 1.055, 2.4);
};

const luminance = ([r, g, b]: RGB): number => 0.2126 * toLinear(r) + 0.7152 * toLinear(g) + 0.0722 * toLinear(b);

export function contrastRatio(a: RGB, b: RGB): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

export function hexToRgb(hex: string): RGB {
  const value = hex.replace('#', '');
  const full = value.length === 3 ? value.split('').map((c) => c + c).join('') : value;
  return [parseInt(full.slice(0, 2), 16), parseInt(full.slice(2, 4), 16), parseInt(full.slice(4, 6), 16)];
}

const toHex = ([r, g, b]: RGB): string =>
  `#${[r, g, b].map((c) => Math.round(Math.max(0, Math.min(255, c))).toString(16).padStart(2, '0')).join('')}`;

function rgbToHsl([r, g, b]: RGB): [number, number, number] {
  const [rn, gn, bn] = [r / 255, g / 255, b / 255];
  const max = Math.max(rn, gn, bn);
  const min = Math.min(rn, gn, bn);
  const lightness = (max + min) / 2;
  if (max === min) return [0, 0, lightness];
  const delta = max - min;
  const saturation = lightness > 0.5 ? delta / (2 - max - min) : delta / (max + min);
  const hue =
    max === rn ? ((gn - bn) / delta + (gn < bn ? 6 : 0)) : max === gn ? (bn - rn) / delta + 2 : (rn - gn) / delta + 4;
  return [hue / 6, saturation, lightness];
}

function hslToRgb(h: number, s: number, l: number): RGB {
  if (s === 0) return [l * 255, l * 255, l * 255];
  const q = l < 0.5 ? l * (1 + s) : l + s - l * s;
  const p = 2 * l - q;
  const channel = (t: number) => {
    let value = t;
    if (value < 0) value += 1;
    if (value > 1) value -= 1;
    if (value < 1 / 6) return p + (q - p) * 6 * value;
    if (value < 1 / 2) return q;
    if (value < 2 / 3) return p + (q - p) * (2 / 3 - value) * 6;
    return p;
  };
  return [channel(h + 1 / 3) * 255, channel(h) * 255, channel(h - 1 / 3) * 255];
}

const readableCache = new Map<string, string>();

export function readableOnDark(hex: string): string {
  const cached = readableCache.get(hex);
  if (cached) return cached;
  const [hue, saturation, startLightness] = rgbToHsl(hexToRgb(hex));
  let lightness = startLightness;
  let result = hex;
  for (let step = 0; step < 48; step += 1) {
    const rgb = hslToRgb(hue, saturation, lightness);
    if (contrastRatio(rgb, HERO_SURFACE) >= MIN_LABEL_CONTRAST) {
      result = step === 0 ? hex : toHex(rgb);
      break;
    }
    if (lightness >= 0.9) {
      result = toHex(rgb);
      break;
    }
    lightness = Math.min(0.9, lightness + 0.015);
  }
  readableCache.set(hex, result);
  return result;
}

/** Published rating → the verdict key that picks the card's badge icon. */
const VERDICT_KEY_BY_RATING: Record<string, QveVerdictKey> = {
  Elite: 'secure',
  Excellent: 'secure',
  Good: 'secure',
  Fair: 'review',
  Weak: 'at-risk',
  Critical: 'critical',
};

/** Severity ranking on the published risk scale, so the two can be compared. */
const riskRank = (band: RiskBand): number => RISK_ORDER.indexOf(band);

/**
 * Risk implied by the worst finding severity observed on a surface.
 *
 * Mapped onto the published `RiskBand` vocabulary rather than a private one, so
 * "worst finding" and "measured posture" are expressed on a single scale and can
 * actually be compared instead of one silently overriding the other.
 */
function riskFromSeverity(severity: ScanEventSeverity, state: QveNodeState): RiskBand | null {
  if (severity === 'critical') return 'Critical';
  if (severity === 'high') return 'High';
  if (severity === 'medium' || state === 'warning') return 'Elevated';
  return null;
}

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

  const grade = node.score !== null ? scoreToGrade(node.score) : null;
  const scored = grade
    ? ` Measured posture ${node.score}/100 — grade ${grade.grade}, ${grade.rating.toLowerCase()} (${grade.riskLevel.toLowerCase()} risk).`
    : '';

  const severityRisk = riskFromSeverity(node.severity, node.state);
  const scoreRisk = grade?.riskLevel ?? null;

  /* WHICHEVER IS WORSE DECIDES — and it can only ever escalate.
     Two facts are known about a settled surface: the worst thing observed on it,
     and what the published model makes of its measured posture. A card that
     reads calmer than EITHER is misleading, so neither is allowed to soften the
     other. The previous ladder let severity short-circuit the score entirely and
     then, worse, capped a `weak`/`critical` band at an amber "Review" — which is
     how a surface scoring 8/100 (grade F, Critical) came to be painted amber. */
  const severityDecides =
    severityRisk !== null && (scoreRisk === null || riskRank(severityRisk) > riskRank(scoreRisk));

  if (severityDecides && severityRisk) {
    const bySeverity: Record<string, { key: QveVerdictKey; label: string; alert: boolean; worst: string }> = {
      Critical: { key: 'critical', label: 'Critical', alert: true, worst: 'CRITICAL' },
      High: { key: 'at-risk', label: 'At Risk', alert: true, worst: 'HIGH' },
      Elevated: { key: 'review', label: 'Review', alert: false, worst: 'MEDIUM' },
    };
    const entry = bySeverity[severityRisk] ?? bySeverity.Elevated;
    return {
      key: entry.key,
      label: entry.label,
      color: readableOnDark(RISK_COLOR[severityRisk]),
      alert: entry.alert,
      basis: `The most severe finding on this surface is ${entry.worst}, which outranks its measured posture.${scored}`,
    };
  }

  if (grade) {
    /* Score decides. The label is the published RATING for that score and the
       colour is that grade's own colour, so the word, the number beside it, the
       beam and the gauge segment are all one lookup and cannot disagree. */
    return {
      key: VERDICT_KEY_BY_RATING[grade.rating] ?? 'review',
      label: grade.rating,
      color: readableOnDark(grade.color),
      alert: grade.rating === 'Critical' || grade.rating === 'Weak',
      basis: severityRisk
        ? `Graded on measured posture; the worst finding here (${severityRisk.toLowerCase()} risk) does not outrank it.${scored}`
        : `No finding above LOW was observed on this surface.${scored}`,
    };
  }

  /* Unscored but settled — severity is all there is to go on. */
  if (severityRisk) {
    const label = severityRisk === 'Critical' ? 'Critical' : severityRisk === 'High' ? 'At Risk' : 'Review';
    const key: QveVerdictKey = severityRisk === 'Critical' ? 'critical' : severityRisk === 'High' ? 'at-risk' : 'review';
    return {
      key,
      label,
      color: readableOnDark(RISK_COLOR[severityRisk]),
      alert: severityRisk !== 'Elevated',
      basis: 'Graded from observed findings; this surface has no scored category in the published model.',
    };
  }
  return { key: 'secure', label: 'Secure', color: QVE_COLOR.pass, alert: false, basis: 'No finding above LOW was observed on this surface.' };
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

/**
 * Quantum-wave colour ramp for a published grade letter.
 *
 * The primary stop is the grade's OWN colour from `SCORE_GRADE_TABLE` rather
 * than a hand-picked one, so the wave around the core cannot read green while
 * the grade beside it reads F. Only the secondary stop is chosen for contrast —
 * A+ keeps its violet quantum companion, everything else pairs with cyan.
 */
export function gradeWaveColors(grade: string | null): [string, string] {
  if (!grade) return ['#38bdf8', QVE_COLOR.quantum];
  const row = SCORE_GRADE_TABLE.find((entry) => entry.grade === grade);
  if (!row) return ['#38bdf8', QVE_COLOR.quantum];
  return [row.color, grade === 'A+' ? QVE_COLOR.quantum : QVE_COLOR.cyan];
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
