/**
 * Dashboard Scanner — assessment intelligence.
 *
 * Pure, side-effect-free derivations that turn the scanner's REAL output —
 * `/api/v1/scanner/stream` summary + per-target results + the Scanner_2
 * enterprise pass + module execution states + the tenant-wide Scanner
 * Intelligence snapshot — into the enterprise assessment model the page
 * renders.
 *
 * HONESTY CONTRACT (identical to /public-scan's):
 *   • Every number traces to a measurement the scanner actually made.
 *   • Anything not measured is reported as Unknown / Not observed, never as 0
 *     and never as a failure.
 *   • The composite score is the backend's own `summary.qScore`, and the
 *     decomposition below is the backend's own published `riskBreakdown` with
 *     its published weights — so the gauge, the grade letter and the category
 *     bars are three views of ONE number and cannot drift apart.
 *   • Grades come from the platform-wide `grading-model`, the same table
 *     /public-scan grades against, so a domain assessed on both surfaces is
 *     graded on one scale.
 */

import {
  RISK_COLOR,
  RISK_ORDER,
  SCORE_CATEGORY_DEFS,
  scoreToGrade,
} from '@/lib/scanner/public-scan/grading-model';
/* The scanner's own finding-ownership rule, imported rather than reimplemented.
   `scanner-module-ledger` is a pure, dependency-free module (no Express, no
   Supabase) exported for exactly this: the backend credits a finding to a
   module, and this page routes the same finding to the surface that module
   belongs to, so the two can never disagree. */
import { moduleIdForFinding } from '@/api-server/scanner-module-ledger';
/* The recommendation join runs through the SAME normalizer that produced the
   recommendation — see `buildRecommendations`. */
import { normalizeToScanner2Algorithm } from '@/lib/scanner/scanner_2/algorithm-normalizer';
/* The platform's shared component rule — the same one CBOM, the Quantum
   Readiness engine and the estate workflow filter through, so this panel's
   component count reconciles with theirs for the same scan. */
import { isCryptographicComponent } from '@/lib/scanner/finding-identity';
import { algorithmFamily } from '@/lib/governance/subjects';
/* The edge attribution line is DERIVED, not re-derived. `edge-intelligence-model`
   is the isomorphic half of the edge engine (pure functions, no sockets), so the
   dashboard and the scanner phrase "behind Cloudflare" from one implementation
   instead of two that can drift. */
import { describeEdgeInfrastructure, headerTally } from '@/lib/scanner/web-scanner/edge-intelligence-model';
import { buildAlgorithmCensus, type AlgorithmCensus } from '@/lib/scanner/web-scanner/algorithm-census';
import { decomposeSuite } from '@/lib/crypto/tls-intelligence';
import { analyzeCryptoObservation } from '@/lib/crypto/suite-anatomy';
import {
  displayForwardSecrecy,
  reconcileTransport,
  staticRsaSuites,
  transportReconciliationNote,
} from '@/lib/scanner/web-scanner/transport-truth';
import type { RiskBand } from '@/lib/scanner/public-scan/types';
import type {
  DefensiveFinding,
  EdgeIntelligence,
  EnterpriseScanner2,
  ModuleState,
  PqcRecommendation,
  PublishedScoreCategory,
  ScanResultRecord,
  ScanRiskApplicability,
  ScanRiskBreakdown,
  ScanStatus,
  ScanSummary,
  ThreatLevel,
} from './_types';

const clamp = (value: number) => Math.max(0, Math.min(100, Math.round(value)));

/**
 * The six sub-surfaces an {@link EdgeIntelligence} record always carries when
 * the collector wrote it completely.
 */
const EDGE_SURFACES = ['pqKeyAgreement', 'transport', 'certificate', 'dns', 'http', 'quantum'] as const;

/**
 * Read a persisted public-edge measurement, or nothing.
 *
 * `metadata.edgeIntelligence` is JSONB written by the edge collector and read
 * back, possibly years later, by this page. Roughly thirty call sites read
 * `edge.transport.*`, `edge.certificate.*`, `edge.http.*` and so on, and a
 * record that is missing one of those sub-surfaces — truncated, partially
 * written, or produced by a build that predates the surface — took the whole
 * dashboard down with `Cannot read properties of undefined`.
 *
 * Rather than scatter thirty guards, the record is validated once here. An
 * incomplete record is not a partial measurement that can be salvaged: the
 * panels would have to caption every row with which surface was missing. It is
 * treated as ABSENT, which every panel already renders honestly as "not
 * probed" — the platform's standing rule that absence is reported as absence
 * and never as a measurement.
 */
function readEdgeIntelligence(
  metadata: { edgeIntelligence?: EdgeIntelligence | null } | null | undefined,
): EdgeIntelligence | null {
  const edge = metadata?.edgeIntelligence;
  if (!edge || typeof edge !== 'object') return null;
  const record = edge as unknown as Record<string, unknown>;
  for (const surface of EDGE_SURFACES) {
    if (!record[surface] || typeof record[surface] !== 'object') return null;
  }
  return edge;
}

/* ==================================================================== nodes = */

/**
 * The six discovery surfaces the Dashboard Scanner visualises, and the scanner
 * modules that feed each one. This is a routing table over the REAL module
 * catalog in `src/api-server/scanner.ts` — every id below is a module the
 * backend actually runs, so a node can never light up for work that did not
 * happen.
 */
export const SCANNER_NODE_MODULES: Record<string, readonly string[]> = {
  discovery: [
    'target-validation',
    'dns-security-scanner',
    'edge-infrastructure-scanner',
    'asset-inventory-synchronizer',
    'scanner2-module-registry',
  ],
  transport: ['tls-protocol-scanner', 'cipher-suite-scanner', 'key-exchange-scanner', 'pq-key-agreement-scanner'],
  certificates: [
    'certificate-scanner',
    'signature-algorithm-scanner',
    'hash-algorithm-scanner',
    'revocation-transparency-scanner',
  ],
  identity: ['ssh-host-key-scanner', 'jwt-signing-scanner'],
  code: ['dependency-crypto-scanner', 'http-security-scanner', 'cbom-generator', 'scanner2-fingerprint-matcher', 'scanner2-detection-rules'],
  posture: [
    'crypto-detection-rules',
    'scanner2-hndl-analyzer',
    'scanner2-correlation-engine',
    'scanner2-pqc-migration-engine',
    'scanner2-risk-qscore-engine',
    'risk-scoring-engine',
    'crypto-exposure-graph-builder',
    'audit-history-logger',
  ],
};

/** Structurally identical to the engine's `NodeBlueprint`, declared here so the
 * derivations stay free of a dependency on the visualization package. */
export interface ScannerNodeBlueprint {
  key: string;
  title: string;
  idleVerdict: string;
  idleLines: string[];
}

export const SCANNER_NODE_BLUEPRINTS: readonly ScannerNodeBlueprint[] = [
  {
    key: 'discovery',
    title: 'Asset Discovery',
    idleVerdict: 'Standby',
    idleLines: ['No targets authorized', 'Inventory not synchronized'],
  },
  {
    key: 'transport',
    title: 'Transport & Ciphers',
    idleVerdict: 'Standby',
    idleLines: ['Protocols unprobed', 'Cipher suites unread'],
  },
  {
    key: 'certificates',
    title: 'Certificates & Keys',
    idleVerdict: 'Standby',
    idleLines: ['Chains not collected', 'Key algorithms unknown'],
  },
  {
    key: 'identity',
    title: 'Identity & Tokens',
    idleVerdict: 'Standby',
    idleLines: ['SSH host keys unread', 'Token algorithms unknown'],
  },
  {
    key: 'code',
    title: 'Code & Dependencies',
    idleVerdict: 'Standby',
    idleLines: ['Repositories not scanned', 'CBOM not generated'],
  },
  {
    key: 'posture',
    title: 'Quantum Posture',
    idleVerdict: 'Standby',
    idleLines: ['HNDL exposure unscored', 'Risk model not run'],
  },
];

/** Left column / right column split around the core, matching the public hero. */
export const SCANNER_LEFT_NODES: readonly string[] = ['discovery', 'transport', 'certificates'];
export const SCANNER_RIGHT_NODES: readonly string[] = ['identity', 'code', 'posture'];

/** Module id → node key, inverted from the routing table above. */
export const MODULE_NODE = ((): Record<string, string> => {
  const map: Record<string, string> = {};
  for (const [node, modules] of Object.entries(SCANNER_NODE_MODULES)) {
    for (const moduleId of modules) map[moduleId] = node;
  }
  return map;
})();

/**
 * Finding → node key, derived from the module that OWNS the finding.
 *
 * This used to be a second, independently-maintained category table, and it
 * drifted from the backend's ownership rules exactly the way two copies of a
 * rule always do: `Web Crypto (hash)` was attributed to the certificate surface
 * (because the string contains "hash") while the scanner credited it to the
 * dependency scanner on the Code surface, so a node card's finding list and its
 * module's finding count disagreed for the same observation.
 *
 * Routing now goes through the scanner's own ledger — `moduleIdForFinding` —
 * and then through `MODULE_NODE`. One rule, one answer, on both sides of the
 * wire. `scanner-module-ledger` is a dependency-free pure module for precisely
 * this reason: it is shared, not duplicated.
 */
export function nodeForFindingCategory(category: string, detectionMethod = '', algorithm = ''): string {
  return MODULE_NODE[moduleIdForFinding({ category, detectionMethod, algorithm })] ?? 'posture';
}

/* =================================================================== model == */

export interface ScoreComponent {
  key: string;
  label: string;
  /** Published weight from the scanner's own risk model. */
  weight: number;
  /** Posture 0-100 (higher is better). Null when the dimension was not measured. */
  score: number | null;
  /** What the number was computed from — shown verbatim, never a caption. */
  observed: string;
  /**
   * WHAT THIS CATEGORY MEASURES, from the published model.
   *
   * The reported contradiction — "TLS Configuration: TLSv1.3, 100" sitting
   * beside "Post-Quantum Key Agreement: Not offered" and "Quantum
   * Vulnerability: Vulnerable" — is not a disagreement between two numbers.
   * Both readings are correct: that category scores the protocol VERSION, and
   * TLS 1.3 is a prerequisite for hybrid key agreement rather than evidence of
   * it. The page simply never said so, leaving a full green bar labelled "TLS
   * Configuration" to be read as "TLS is fine". The scope now travels with the
   * row, so a reader can see which categories carry the post-quantum verdict
   * and which do not.
   */
  description: string;
  /** True when this category's score moves with post-quantum deployment. */
  postQuantumRelevant: boolean;
}

export interface SurfaceItem {
  key: string;
  label: string;
  value: string;
  status: 'pass' | 'fail' | 'partial' | 'info' | 'unknown';
  detail: string;
  /**
   * The observations behind the verdict, shown verbatim when the row is opened.
   *
   * A one-word verdict is only trustworthy if the operator can see what
   * produced it. "Applied" for post-quantum key agreement means nothing without
   * the negotiated protocol, the group, both halves of the hybrid construction
   * and how many handshakes confirmed it — so those travel WITH the verdict
   * rather than living in a separate report the reader has to go and find.
   */
  evidence?: Array<{ label: string; value: string }>;
}

export interface TimelinePhase {
  key: string;
  title: string;
  horizon: string;
  description: string;
  state: 'past' | 'now' | 'active' | 'target';
}

export interface RecommendationCard {
  id: string;
  title: string;
  priority: 'Critical' | 'High' | 'Medium' | 'Low';
  businessImpact: string;
  effort: string;
  standard: string;
  affected: number;
  steps: string[];
  rationale: string;
}

export interface FootprintMetric {
  key: string;
  label: string;
  value: number;
  countedFrom: string;
}

export interface CoverageItem {
  key: string;
  label: string;
  status: 'pass' | 'partial' | 'fail' | 'unknown';
  detail: string;
}

export interface ScannerAssessment {
  /** False until at least one real measurement exists for this tenant. */
  hasEvidence: boolean;
  /** True while the numbers describe a run still in flight. */
  live: boolean;
  provenance: string;
  target: { label: string; count: number; completedAt: string | null };
  executive: {
    grade: string;
    gradeLabel: string;
    gradeColor: string;
    gradeable: boolean;
    gradeDetail: string;
    encryptionScore: number;
    classicalScore: number;
    /**
     * null = NOT SCORED.
     *
     * The panel used to render `14 / Limited` directly above its own footnote
     * saying "post-quantum readiness was not scored: no TLS handshake
     * completed". The 14 came from a finding-share fallback that runs when the
     * weighted model excluded the dimension — so the page published a number
     * and a denial of that number at the same time.
     */
    postQuantumReadiness: number | null;
    /** Why it was not scored. Rendered in place of the number. */
    postQuantumReadinessReason: string | null;
    evidenceCoverage: number;
    businessRisk: RiskBand;
    businessRiskDetail: string;
    migrationComplexity: string;
    migrationComplexityDetail: string;
    confidence: number;
    confidenceDetail: string;
  };
  scoreComponents: ScoreComponent[];
  /**
   * The weighted mean of the measured `scoreComponents`, i.e. what the published
   * risk model alone says the posture is. Null until a decomposition exists.
   *
   * This is normally identical to `executive.encryptionScore`, because the
   * backend's summary risk score IS the mean of the same per-target weighted
   * scores (weighted mean and arithmetic mean commute). It diverges when the
   * summary was rebuilt from stored findings by severity count rather than from
   * the weighted model — so the two are reported separately and reconciled in
   * the UI instead of one silently overwriting the other.
   */
  decompositionScore: number | null;
  /** True when the decomposition and the composite agree within rounding. */
  decompositionAgrees: boolean;
  /**
   * The published model split into its classical and post-quantum halves, with
   * the share of MEASURED weight each half carries. The Encryption Score panel
   * renders both flanks from this, so the two numbers beside the gauge
   * reproduce the gauge.
   */
  postureSplit: ReturnType<typeof postureSlices>;
  /** Short "projected from" caption per node surface, keyed like `nodeScores`. */
  nodeScoreScopes: Record<string, string>;
  attackSurface: SurfaceItem[];
  intelligence: {
    /** The rows the panel renders — the census, capped for display. */
    observedAlgorithms: Array<{ name: string; role: string; quantumVulnerable: boolean; count: number }>;
    /**
     * The FULL census behind those rows, so the panel can state the total it is
     * truncating and print the same sentence the score decomposition prints.
     * One census: the score row and this panel can no longer disagree about how
     * many algorithms were observed or how many of them are post-quantum.
     */
    algorithmCensus: AlgorithmCensus;
    keyExchange: string;
    forwardSecrecy: string;
    quantumVulnerability: string;
    /** Why that verdict, in the engine's own words. Never a generic caption. */
    quantumVulnerabilityReason: string;
    /**
     * Measured post-quantum readiness for the scanned endpoint, and the
     * evidence behind it. Null when no public-edge measurement is attached.
     */
    postQuantumReadiness: { score: number; reasons: string[] } | null;
    /** Set only when readiness is withheld — the same reason the model states. */
    postQuantumReadinessReason: string | null;
    /** The Quantum Risk Engine's per-primitive explanation of the verdict. */
    quantumRiskFactors: Array<{ factor: string; observed: string; impact: string; explanation: string }>;
    migrationTargets: Array<{ name: string; standard: string; replaces: string }>;
    confidence: number;
    scanner2Readiness: { score: number; label: string } | null;
  };
  timeline: TimelinePhase[];
  recommendations: RecommendationCard[];
  footprint: {
    metrics: FootprintMetric[];
    exposureLevel: string;
    basis: string;
    /**
     * The component population, derived ONCE.
     *
     * Every panel that wants to say something about "components" reads these
     * rather than recomputing. Sophia's narrative used to assert
     * "78% of discovered components are already quantum-safe" from
     * `executive.postQuantumReadiness`, which is the published READINESS
     * CATEGORY — a posture score over controls, not a share of an inventory —
     * while the Estate Footprint beside it counted 14 of 18 components
     * quantum-vulnerable.
     */
    components: { total: number; vulnerable: number; policyFindings: number };
  };
  coverage: CoverageItem[];
  scope: { analyzed: string[]; notAnalyzed: string[]; statement: string };
  nodeScores: Record<string, number>;
  hndl: { immediate: number; soon: number; planned: number; window: { earliest: number; latest: number } | null };
}

/* ================================================================= helpers == */

const THREAT_RANK: Record<ThreatLevel, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, SAFE: 0 };

/** Escalate to the more severe of two risk bands. */
function worstRisk(a: RiskBand, b: RiskBand): RiskBand {
  return RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b) ? a : b;
}

function riskBandForScore(posture: number): RiskBand {
  if (posture >= 90) return 'Very Low';
  if (posture >= 80) return 'Low';
  if (posture >= 65) return 'Moderate';
  if (posture >= 50) return 'Elevated';
  if (posture >= 35) return 'High';
  return 'Critical';
}

function average(values: number[]): number | null {
  if (values.length === 0) return null;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

/**
 * Count + noun, with an explicit plural when the default "+s" is wrong.
 *
 * Exported so panels phrase a count the same way the derivations do. The
 * default caught out `pluralize(6, 'algorithm family')` → "6 algorithm familys",
 * which shipped on the Executive Summary.
 */
export function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

export function riskColorFor(band: RiskBand): string {
  return RISK_COLOR[band];
}

/* ============================================================ node scoring == */

/**
 * Which of THIS scanner's published grading categories belong to each of THIS
 * dashboard's six discovery surfaces.
 *
 * WHY THIS REPLACED A SEVERITY MEAN
 * ---------------------------------
 * A node's headline number used to be `scoreNodes(findings)`: the mean of a
 * residual-security ladder (SAFE 1.0 → CRITICAL 0) over every finding routed to
 * the surface. It produced two defects that reinforced each other.
 *
 * 1. It was a SECOND SCORING MODEL. The gauge, the grade letter and the category
 *    bars all come from the published weighted categories; the cards came from a
 *    mean over finding counts. One scan therefore published "C+ · Fair · 71"
 *    beside four surfaces reading "Critical" — two true statements from two
 *    different models, presented as one assessment.
 *
 * 2. A mean over findings counts SYNONYMS. One certificate that restated its key
 *    three ways and its signature twice contributed five HIGH observations, and
 *    the mean read that as five problems. The duplication is fixed at source in
 *    `scan-orchestrator`, but a mean over an evidence list is structurally the
 *    wrong shape for a posture score regardless: adding a probe that emits more
 *    rows must not lower the posture of the surface it probed.
 *
 * The projection below is a VIEW of the same weighted model the headline uses,
 * so a card can never disagree with the gauge above it. Note this is the
 * Dashboard Scanner's own mapping over its own six surfaces — /public-scan has a
 * separate ring, a separate engine and its own `NODE_SCORE_CATEGORIES`. The two
 * surfaces share only the published grading STANDARD, never a pipeline.
 *
 * INVARIANT: every published category appears exactly once, so no measurement is
 * double-counted across surfaces and none is silently dropped.
 * `tools/scanner-scoring-check.ts` asserts it.
 */
export const SCANNER_NODE_CATEGORIES: Record<string, readonly string[]> = {
  discovery: ['dns-caa'],
  transport: ['tls-configuration', 'cipher-suites', 'forward-secrecy'],
  certificates: ['certificates', 'certificate-transparency', 'ocsp-stapling'],
  /* The Code & Dependencies card is where this dashboard renders the
     application-layer controls it measures (response headers, HSTS). Application
     cryptography itself — repository and Web Crypto patterns — has no category of
     its own in the published model; it is folded into `cryptographic-algorithms`
     and therefore scored on the Quantum Posture surface. */
  code: ['http-security-headers', 'hsts'],
  /* `key-exchange` sits here, not on Transport, and that placement is load-
     bearing. It is the category that carries the hybrid ML-KEM reading, and a
     Quantum Posture card scored without it is structurally incapable of
     reflecting a hybrid deployment: test.openquantumsafe.org — the reference
     post-quantum endpoint, serving X25519MLKEM768 across every handshake —
     published "Quantum Posture · At Risk 67" while Transport & Ciphers banked
     the 100 that its key agreement had earned.

     It also puts this ring in agreement with /public-scan's `quantum` node,
     which has always grouped it this way. Key agreement is a transport property
     AND a quantum one; of the two readings, only one of them lets the card say
     something true about post-quantum posture. */
  posture: ['key-exchange', 'cryptographic-algorithms', 'post-quantum-readiness'],
  /**
   * Deliberately empty. The published model has NO category for SSH host keys or
   * token signing algorithms, so this surface has no measured posture to report
   * and shows none. Its verdict comes from the severity of what it observed,
   * which `resolveNodeVerdict` handles as a first-class unscored case.
   *
   * Inventing a number here — by averaging its findings, as the old model did —
   * would publish a posture the platform never measured, which is the one thing
   * the honesty contract forbids outright.
   */
  identity: [],
};

/**
 * Per-node posture 0-100, projected from the published category scores.
 *
 * Weighted by each category's published weight, and inapplicable categories are
 * excluded entirely rather than scored zero — the grading model already
 * redistributes their weight. A surface whose every category was unmeasurable
 * returns NO score, so the card keeps showing "not measured" instead of being
 * painted red for evidence nobody collected.
 */
export function scoreNodesFromCategories(components: ScoreComponent[]): Record<string, number> {
  const byKey = new Map(components.map((component) => [component.key, component]));
  const scores: Record<string, number> = {};

  for (const [node, categories] of Object.entries(SCANNER_NODE_CATEGORIES)) {
    let weighted = 0;
    let weight = 0;
    for (const key of categories) {
      const component = byKey.get(key);
      if (!component || component.score === null) continue;
      weighted += component.score * component.weight;
      weight += component.weight;
    }
    if (weight > 0) scores[node] = clamp(weighted / weight);
  }

  return scores;
}

/**
 * The SHORT form of the same provenance, for the card face.
 *
 * The inspector's full sentence is only reachable after a click, and the
 * contradiction a reader hits first is on the card: Asset Discovery rendering
 * `0 · Critical` in red while every row inside it — 1 target, 1 asset
 * synchronized, 5 of 5 modules reported — is healthy. Nothing on that card said
 * its posture number is a projection of one published category (DNS CAA), so
 * the number read as a verdict on discovery itself.
 *
 * Naming the categories on the face is what makes the number checkable without
 * making it wrong.
 */
export function nodeScoreScopes(components: ScoreComponent[]): Record<string, string> {
  const byKey = new Map(components.map((component) => [component.key, component]));
  const scopes: Record<string, string> = {};
  for (const [node, categories] of Object.entries(SCANNER_NODE_CATEGORIES)) {
    const measured = categories
      .map((key) => byKey.get(key))
      .filter((component): component is ScoreComponent => Boolean(component) && component!.score !== null);
    if (measured.length > 0) scopes[node] = measured.map((component) => component.label).join(' + ');
  }
  return scopes;
}

/**
 * What a node's score was computed from, for the inspector's provenance line.
 * A number an operator cannot trace is a number they cannot defend in an audit.
 */
export function nodeScoreBasis(nodeKey: string, components: ScoreComponent[]): string {
  const categories = SCANNER_NODE_CATEGORIES[nodeKey] ?? [];
  if (categories.length === 0) {
    return 'The published grading model has no category for this surface, so no posture score is claimed. The verdict below is graded from the severity of what was observed here.';
  }
  const byKey = new Map(components.map((component) => [component.key, component]));
  const measured = categories
    .map((key) => byKey.get(key))
    .filter((component): component is ScoreComponent => Boolean(component) && component!.score !== null);
  if (measured.length === 0) {
    return 'None of this surface’s grading categories could be measured on the submitted targets, so no posture score is claimed.';
  }
  return `Weighted mean of ${measured
    .map((component) => `${component.label} ${component.score}/100 (weight ${component.weight})`)
    .join(' · ')} — the same categories, weights and grade table that produced the composite score above.`;
}

/**
 * Post-quantum signature and KEM primitives, by name.
 *
 * Declared once so the certificate panel, the observed-algorithm list and any
 * future consumer classify a chain the same way. Both call sites previously
 * hardcoded "recoverable by Shor", which would have mislabelled the very
 * migration target this dashboard recommends.
 */
export const PQ_ALGORITHM_PATTERN = /ml-?kem|ml-?dsa|slh-?dsa|dilithium|kyber|sphincs|falcon|xmss|lms\b/i;

/** The two quantum categories of the published model. */
/**
 * The two quantum categories of the published model.
 *
 * Exported because the Encryption Score panel splits the model into classical
 * and post-quantum weight, and it was doing so with `key !== 'pqcReadiness'` —
 * a key that does not exist in the decomposition. That filter matched nothing,
 * so the panel printed "100% of the weighted model" under Classical Encryption
 * and "0% of the weighted model" under a Post-Quantum Readiness score of 78.
 */
export const PQ_CATEGORY_KEYS = new Set(['cryptographic-algorithms', 'post-quantum-readiness']);

/**
 * The caption under a post-quantum number, and what that number IS.
 *
 * TWO NUMBERS, TWO LADDERS — this type exists so they cannot be the same one.
 */
export interface PostQuantumCaption {
  /** The phrase printed under the figure. */
  headline: string;
  /** What the figure measures. Printed, not implied. */
  scope: string;
}

/**
 * The Executive Summary's Post-Quantum Readiness tile.
 *
 * This is the published `post-quantum-readiness` CATEGORY: hybrid key
 * agreement, post-quantum signatures, a TLS 1.3 floor, certificate lifetime and
 * CT participation. It describes the endpoint's readiness CONTROLS.
 *
 * ITS LADDER IS DISJOINT FROM {@link postQuantumPostureCaption}'S BY
 * CONSTRUCTION. Both tiles used to run `score >= 60 ? 'Controls largely in
 * place' : 'Migration outstanding'`, so a www.cloudflare.com scan published
 * "81% · Controls largely in place" in the Executive Summary and "51 ·
 * Migration outstanding" in the Encryption Score — one page asserting both
 * halves of a contradiction about the same subject, in the same words, from two
 * correct measurements. `tools/scanner-result-alignment-check.ts` sweeps every
 * (readiness, posture) pair and fails on any shared phrase.
 */
export function postQuantumReadinessCaption(score: number | null): PostQuantumCaption {
  const scope = 'Published Post-Quantum Readiness category — the endpoint\'s readiness controls, not a share of its inventory.';
  if (score === null) return { headline: 'Not scored', scope };
  if (score >= 85) return { headline: 'Readiness controls in place', scope };
  if (score >= 60) return { headline: 'Readiness controls mostly in place', scope };
  if (score >= 35) return { headline: 'Readiness controls partly in place', scope };
  return { headline: 'Readiness controls not yet in place', scope };
}

/**
 * The Encryption Score panel's Post-Quantum Posture flank.
 *
 * This is the post-quantum WEIGHT SLICE of the composite — Cryptographic
 * Algorithms plus Post-Quantum Readiness — and it is the only number that,
 * weighted against the classical flank, reproduces the gauge between them. It
 * runs lower than the readiness category whenever the inventory still holds
 * classical primitives, because the algorithm census is most of its weight.
 */
export function postQuantumPostureCaption(score: number | null): PostQuantumCaption {
  const scope = 'Post-quantum weight slice of the composite — it is what, weighted against the classical flank, reproduces the gauge.';
  if (score === null) return { headline: 'Posture not scored', scope };
  if (score >= 85) return { headline: 'Inventory largely migrated', scope };
  if (score >= 60) return { headline: 'Migration well advanced', scope };
  if (score >= 35) return { headline: 'Migration in progress', scope };
  return { headline: 'Migration outstanding', scope };
}

/**
 * Every category whose score MOVES when post-quantum cryptography is deployed.
 *
 * Wider than `PQ_CATEGORY_KEYS`, which is the classical/quantum weight SPLIT.
 * Key Exchange belongs here too — a hybrid group scores it 100 and a classical
 * one 70 — and saying so is what reconciles "TLS Configuration 100" with
 * "Quantum Vulnerability: Vulnerable" for a reader: the protocol version is a
 * prerequisite for hybrid key agreement, not evidence of it, and the three rows
 * below are where the post-quantum verdict is actually decided.
 */
export const PQ_SENSITIVE_CATEGORY_KEYS = new Set([
  'key-exchange',
  'cryptographic-algorithms',
  'post-quantum-readiness',
]);

/** What each published category measures, by key. */
const CATEGORY_DESCRIPTION = new Map(SCORE_CATEGORY_DEFS.map((def) => [def.key, def.description]));

/**
 * The published model split into its classical and post-quantum halves.
 *
 * ONE computation, because the Encryption Score panel shows all three numbers
 * at once — classical on the left, post-quantum on the right, the composite in
 * the gauge between them — and a reader is entitled to check that the flanks
 * produce the middle.
 *
 * Two things were wrong before. The weight captions were taken over EVERY
 * category including the unmeasured ones, while the scores beside them are
 * weighted means over the measured ones only, so the percentages described a
 * different aggregation than the numbers they captioned. And the right-hand
 * number was the Post-Quantum Readiness CATEGORY (weight 3) captioned "8% of
 * the weighted model" — the 8% slice is that category plus Cryptographic
 * Algorithms, and on the audited scan it scored 27, not 73. The two flanks
 * therefore could not reproduce the gauge no matter how carefully a reader
 * added them up.
 *
 * Shares are taken over MEASURED weight, so they sum to 100 and mean
 * "this much of what was actually aggregated".
 */
export interface PostureSlice {
  /** Weighted mean over this half's measured categories. Null when none were. */
  score: number | null;
  /** Share of the MEASURED weight this half carries, 0-100. */
  weightShare: number;
  /** The categories that contributed, for the provenance line. */
  categories: string[];
}

export function postureSlices(components: ScoreComponent[]): {
  classical: PostureSlice;
  postQuantum: PostureSlice;
  /** Weighted mean over everything measured — must equal the decomposition. */
  composite: number | null;
} {
  const measured = components.filter((component) => component.score !== null);
  const totalWeight = measured.reduce((sum, component) => sum + component.weight, 0);

  const slice = (keep: (component: ScoreComponent) => boolean): PostureSlice => {
    const rows = measured.filter(keep);
    const weight = rows.reduce((sum, component) => sum + component.weight, 0);
    return {
      score:
        weight > 0
          ? clamp(rows.reduce((sum, component) => sum + (component.score as number) * component.weight, 0) / weight)
          : null,
      weightShare: totalWeight > 0 ? Math.round((weight / totalWeight) * 100) : 0,
      categories: rows.map((component) => component.label),
    };
  };

  const classical = slice((component) => !PQ_CATEGORY_KEYS.has(component.key));
  const postQuantum = slice((component) => PQ_CATEGORY_KEYS.has(component.key));
  return {
    classical,
    postQuantum,
    composite:
      totalWeight > 0
        ? clamp(
            measured.reduce((sum, component) => sum + (component.score as number) * component.weight, 0) / totalWeight,
          )
        : null,
  };
}

/**
 * Merge each target's published category scores into one estate decomposition.
 *
 * A category is averaged over the targets that MEASURED it, and reported null
 * when no target did — the UI still lists it, greyed, with the reason. Older
 * scans that predate published scoring fall back to the engineering breakdown so
 * reviewing history keeps working.
 */
function mergePublishedCategories(
  results: ScanResultRecord[],
  fallbackBreakdown: Partial<Record<keyof ScanRiskBreakdown, number>> | null,
): ScoreComponent[] {
  const rows = results
    .map((result) => result.metadata?.scoreCategories)
    .filter((value): value is PublishedScoreCategory[] => Array.isArray(value) && value.length > 0);

  if (rows.length === 0) {
    // Pre-published-scoring scan: show the engineering decomposition instead of
    // an empty panel, labelled so it is not mistaken for the published model.
    return RISK_WEIGHTS.map((definition) => {
      const risk = fallbackBreakdown?.[definition.key];
      return {
        key: definition.key,
        label: definition.label,
        weight: definition.weight,
        score: risk === undefined ? null : clamp(100 - risk),
        observed: risk !== undefined
          ? `${definition.description} (engineering model — rescan for the published categories)`
          : 'Not decomposed — run a scan to collect the per-target model',
        description: definition.description,
        postQuantumRelevant: PQ_SENSITIVE_CATEGORY_KEYS.has(definition.key),
      };
    });
  }

  const order: PublishedScoreCategory[] = rows[0];
  return order.map((template) => {
    const measured = rows
      .map((row) => row.find((category) => category.key === template.key))
      .filter((category): category is PublishedScoreCategory => Boolean(category?.applicable));
    const mean = average(measured.map((category) => category.score));
    const observedValues = Array.from(new Set(measured.map((category) => category.observed))).filter(Boolean);
    return {
      key: template.key,
      label: template.label,
      weight: template.weight,
      score: mean === null ? null : clamp(mean),
      observed: observedValues.length
        ? observedValues.slice(0, 2).join(' · ')
        : template.observed || 'not observed',
      /* Read from the published defs by key rather than from the persisted row.
         Scans written before the description existed still get it, and a stored
         row can never carry a stale description of what the category measures. */
      description: CATEGORY_DESCRIPTION.get(template.key) ?? '',
      postQuantumRelevant: PQ_SENSITIVE_CATEGORY_KEYS.has(template.key),
    };
  });
}

/* ========================================================= node evidence ==== */

export interface EvidenceRow {
  label: string;
  value: string;
  /** Explicit colour when the value itself is the verdict. */
  tone?: string;
  /** Longer provenance, shown as the row's tooltip. */
  detail?: string;
}

export interface NodeEvidence {
  /** Ordered evidence rows for the node's detail panel. */
  rows: EvidenceRow[];
  /** The scanner modules that produced this node, with their real end state. */
  modules: Array<{ id: string; name: string; status: string; findings: number; durationMs: number | null }>;
  /** Findings routed to this node, most severe first. */
  findings: DefensiveFinding[];
  /** Node posture 0-100, or null when nothing was measured here. */
  score: number | null;
  /** The categories and weights behind {@link score}, stated so it can be audited. */
  scoreBasis: string;
  /** Why the panel is empty, when it is. */
  emptyReason: string | null;
}

const TONE_PASS = '#34d399';
const TONE_WARN = '#fbbf24';
const TONE_FAIL = '#f43f5e';
const TONE_PQ = '#a78bfa';
const TONE_MUTED = '#94a3b8';

function certificateName(source: Record<string, string> | undefined): string | null {
  if (!source) return null;
  return source.CN || source.commonName || source.O || source.organizationName || null;
}

function daysUntil(iso: string | undefined): number | null {
  if (!iso) return null;
  const at = Date.parse(iso);
  if (!Number.isFinite(at)) return null;
  return Math.round((at - Date.now()) / 86400000);
}

/**
 * Real, per-node evidence for the hero's detail panel.
 *
 * Every row is read from something the scanner returned for THIS tenant's scan:
 * the per-target TLS analysis, the parsed certificate chain, the repository and
 * Web Crypto passes, the security-header probe, the Scanner_2 enterprise pass,
 * and the module execution states. A surface the scan did not reach returns an
 * `emptyReason` naming why, rather than empty rows or invented values.
 */
export function buildNodeEvidence(
  nodeKey: string,
  input: {
    results: ScanResultRecord[];
    findings: DefensiveFinding[];
    modules: ModuleState[];
    scanner2: EnterpriseScanner2 | null;
    targets: string[];
    linked: { cbom: number; assets: number; exposures: number };
    /**
     * The assessment's published category decomposition.
     *
     * Passed in rather than recomputed here: this panel, the hero card and the
     * Encryption Score table are three views of ONE decomposition, and the way
     * they used to drift was each deriving its own from the same raw findings.
     */
    scoreComponents: ScoreComponent[];
  },
): NodeEvidence {
  const primary = input.results[0] ?? null;
  const tls = primary?.metadata?.tlsAnalysis ?? null;
  const certificate = primary?.certificateInfo ?? null;
  const api = primary?.metadata?.apiSecurityResult ?? null;
  const repo = primary?.metadata?.repoScanResult ?? null;
  const webCrypto = primary?.metadata?.webCryptoResult ?? null;
  const scanner2 = input.scanner2;
  /* The public-edge measurement. This is where the answers the raw socket
     cannot give live: Node's `getEphemeralKeyInfo()` is empty for a TLS 1.3
     handshake, so `tls.negotiatedCurve` is null and `tls.keyExchange` degrades
     to "ECDHE (TLS 1.3 key_share)" on every modern endpoint. The edge engine
     resolved the real group by offering each named group in isolation, and the
     panels below read THAT rather than printing "Not observed" over evidence
     the scanner holds. */
  const edge = readEdgeIntelligence(primary?.metadata);
  const pq = edge?.pqKeyAgreement ?? null;
  const edgeTransport = edge?.transport ?? null;
  const edgeCert = edge?.certificate ?? null;

  const moduleIds = SCANNER_NODE_MODULES[nodeKey] ?? [];
  const modules = input.modules
    .filter((module) => moduleIds.includes(module.id))
    .map((module) => ({
      id: module.id,
      name: module.name,
      status: module.status,
      findings: module.findingsCount,
      durationMs: module.durationMs,
    }));

  const nodeFindings = input.findings
    .filter((finding) => nodeForFindingCategory(finding.category, finding.detectionMethod, finding.algorithm) === nodeKey)
    .sort((a, b) => THREAT_RANK[b.threatLevel] - THREAT_RANK[a.threatLevel]);

  const score = scoreNodesFromCategories(input.scoreComponents)[nodeKey] ?? null;
  const scoreBasis = nodeScoreBasis(nodeKey, input.scoreComponents);
  const rows: EvidenceRow[] = [];

  switch (nodeKey) {
    case 'discovery': {
      rows.push(
        {
          label: 'Authorized targets',
          value: input.targets.length ? String(input.targets.length) : (primary ? '1' : '—'),
          detail: input.targets.join(', ') || primary?.target || 'No target queued',
        },
        {
          label: 'Target',
          value: primary?.target ?? input.targets[0] ?? 'Not submitted',
          detail: 'The normalized asset the scanner connected to',
        },
        {
          label: 'Target type',
          value: primary?.targetType ?? primary?.metadata?.targetType ?? 'Unknown',
          detail: 'Classification the asset validator assigned',
        },
        {
          label: 'Assets synchronized',
          value: input.linked.assets ? String(input.linked.assets) : '—',
          detail: 'Asset inventory rows written for this tenant',
          tone: input.linked.assets > 0 ? TONE_PASS : undefined,
        },
        {
          label: 'Exposure nodes',
          value: input.linked.exposures ? String(input.linked.exposures) : '—',
          detail: 'Nodes added to the crypto exposure graph',
        },
        {
          label: 'Scan duration',
          value: primary?.durationMs ? `${(primary.durationMs / 1000).toFixed(1)} s` : '—',
          detail: 'Wall-clock time the orchestrator reported for this target',
        },
      );
      break;
    }

    case 'transport': {
      if (!tls && !edgeTransport) break;
      // Protocol acceptance is answered by whichever engine probed it. The edge
      // engine probes every version individually; the socket only ever knows
      // the one it negotiated.
      const supported = (edgeTransport?.supportedProtocols?.length
        ? edgeTransport.supportedProtocols
        : tls?.supportedProtocols) ?? [];
      const legacy = edgeTransport?.legacyProtocols?.length
        ? edgeTransport.legacyProtocols
        : supported.filter((protocol) => /1\.0|1\.1|SSLv/i.test(protocol));
      const negotiated = tls?.tlsVersion || edgeTransport?.negotiatedProtocol || '';
      const suites = tls?.cipherSuites ?? [];
      /* ONE predicate for the whole page — see `isStaticRsaSuite`. This line
         tested only `keyExchange === 'RSA'`, so a `TLS_RSA_WITH_…` suite whose
         key exchange the analyser left blank was counted by the Observed Attack
         Surface and not here: "Static RSA accepted" on one panel, "No" on the
         other, for one handshake. */
      const staticRsa = staticRsaSuites(suites);
      const hybridApplied = Boolean(pq?.probed && pq.state === 'pass' && pq.hybridGroups.length > 0);
      const pureKem = Boolean(pq?.probed && !hybridApplied && pq.pureKemGroups.length > 0);
      /* THE measured named group, or null. TLS 1.3 suites do not name their key
         exchange, so every 1.3 suite this endpoint accepts is reached through
         the same measured group — passing it to each of them is what lets one
         model answer for every row below. */
      const measuredGroup = hybridApplied || pureKem
        ? (pq?.primaryGroup ?? pq?.pureKemGroups?.[0] ?? null)
        : (tls?.negotiatedCurve ?? null);
      /* Decompose the NEGOTIATED suite, passing the measured named group so a
         TLS 1.3 suite is read against the group that was actually used rather
         than against the classical default its name implies. */
      /* ONE reconciled transport reading for every row below. */
      const transport = reconcileTransport(tls, edge, undefined);
      const negotiatedSuiteName = tls?.cipherSuite || edgeTransport?.negotiatedCipher || '';
      const suiteAnatomy = negotiatedSuiteName ? decomposeSuite(negotiatedSuiteName, measuredGroup) : null;

      /* Quantum exposure per ACCEPTED suite, from the one decomposer.
         A suite whose name cannot be parsed is left out of the exposed count
         rather than assumed either way — an unparsed suite gets no invented
         attribution, here or in the locus row. */
      const suiteExposure = suites.map((suite) => {
        const name = suite.standardName ?? suite.name ?? '';
        const anatomy = decomposeSuite(name, measuredGroup);
        return { name, exposed: anatomy ? anatomy.quantumExposureFrom.length > 0 : Boolean(suite.quantumVulnerable) };
      });
      const exposedSuites = suiteExposure.filter((entry) => entry.exposed).length;
      const negotiatedKey = negotiatedSuiteName.trim().toUpperCase();
      const otherExposedSuites = suiteExposure.filter(
        (entry) => entry.exposed && entry.name.trim().toUpperCase() !== negotiatedKey,
      ).length;

      rows.push(
        {
          label: 'Negotiated protocol',
          value: negotiated || 'Not observed',
          tone: /1\.3/.test(negotiated) ? TONE_PASS : /1\.2/.test(negotiated) ? TONE_WARN : TONE_FAIL,
          detail: 'Protocol version selected during the observed handshake',
        },
        {
          label: 'Protocols accepted',
          value: supported.length ? supported.join(' / ') : 'Not probed',
          tone: legacy.length > 0 ? TONE_FAIL : supported.length ? TONE_PASS : TONE_MUTED,
          detail: legacy.length
            ? `${legacy.join(', ')} still accepted — deprecated by RFC 8996`
            : supported.length
              ? 'Each version was probed individually — anything absent was refused'
              : 'No per-version probe completed for this target',
        },
        /* Key agreement is the MEASURED group, not the socket's label. This row
           is the one that used to read "ECDHE (TLS 1.3 key_share)" on an
           endpoint running X25519MLKEM768. */
        {
          label: 'Key agreement',
          value: hybridApplied
            ? `${pq?.primaryGroup} (hybrid)`
            : pureKem
              ? `${pq?.pureKemGroups?.join(', ')} (no classical hedge)`
              : tls?.keyExchange || edgeTransport?.keyExchange || 'Not observed',
          tone: hybridApplied || pureKem ? TONE_PQ : TONE_WARN,
          detail: hybridApplied
            ? `${pq?.classicalComponent} + ${pq?.postQuantumComponent}, accepted when offered in isolation under a TLS 1.3 floor across ${pq?.handshakes} handshake(s) · confidence ${pq?.confidence}%`
            : pq?.hybridProbed
              ? `Every hybrid ML-KEM group was offered in isolation and refused across ${pq.handshakes} handshake(s)`
              : 'Key-agreement mechanism used by the negotiated connection',
        },
        {
          label: 'Post-quantum key agreement',
          value: pq?.probed ? pq.value : 'Not probed',
          tone: hybridApplied ? TONE_PQ : pureKem ? TONE_WARN : pq?.probed ? TONE_FAIL : TONE_MUTED,
          detail: pq?.detail ?? 'Named-group probing requires a completed TLS handshake',
        },
        /* Reconciled, not re-derived. This row, the Cryptographic Intelligence
           panel and the score decomposition each used to compute forward
           secrecy from a different fallback chain, and on a TLS 1.3 endpoint
           whose named-group probe timed out they published "Not offered",
           "Not observed" and 100 simultaneously. All three now read the same
           `transport-truth` reconciliation. */
        {
          label: 'Forward secrecy',
          value: displayForwardSecrecy(transport),
          tone: !transport.forwardSecrecy.measured
            ? TONE_MUTED
            : transport.forwardSecrecy.value
              ? (transport.staticRsaAccepted.value === true ? TONE_WARN : TONE_PASS)
              : TONE_FAIL,
          detail: transport.forwardSecrecy.basis,
        },
        {
          label: 'Cipher suite',
          value: tls?.cipherSuite || edgeTransport?.negotiatedCipher || 'Not observed',
          tone: /GCM|CHACHA20|CCM/i.test(tls?.cipherSuite ?? '') ? TONE_PASS : TONE_WARN,
          detail: 'Suite selected on the negotiated connection',
        },
        /* Which PART of the suite carries the quantum exposure.
           A suite is four independent decisions wearing one name, and
           "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 - vulnerable" is true but
           useless: it does not say what to change. The decomposer classifies
           each component through the knowledge base and names the one Shor
           breaks, so the row answers "replace the ECDHE key agreement", not
           "your TLS is broken". Omitted entirely when the suite name is not
           recognisable - an unparsed suite gets no invented attribution. */
        ...(suiteAnatomy
          ? [
              {
                /* THE LABEL CARRIES THE SCOPE.
                   This row decomposes the NEGOTIATED suite only, and on a
                   hybrid TLS 1.3 endpoint it correctly finds no exposure — then
                   printed "None identified in the suite" in the pass colour
                   directly above "8 accepted · 8 quantum-vulnerable". Both
                   statements were true of different populations and the page
                   read as self-contradictory. The scope is now in the label,
                   and the tone is capped when other accepted suites carry
                   exposure the negotiated one does not. */
                label: 'Quantum exposure locus · negotiated suite',
                value: suiteAnatomy.quantumExposureFrom.length
                  ? suiteAnatomy.quantumExposureFrom
                      .map((part) => (part === 'key-exchange' ? 'Key agreement' : part === 'authentication' ? 'Server authentication' : part === 'bulk' ? 'Bulk cipher' : 'MAC'))
                      .join(' + ')
                  : otherExposedSuites > 0
                    ? 'None in this suite — other accepted suites are exposed'
                    : 'None identified in the suite',
                tone: suiteAnatomy.quantumExposureFrom.length
                  ? TONE_WARN
                  : otherExposedSuites > 0
                    ? TONE_WARN
                    : TONE_PASS,
                detail: otherExposedSuites > 0 && !suiteAnatomy.quantumExposureFrom.length
                  ? `${suiteAnatomy.quantumSummary} This describes the suite that was negotiated. ${pluralize(otherExposedSuites, 'other accepted suite')} carr${otherExposedSuites === 1 ? 'ies' : 'y'} quantum-vulnerable key agreement, and a session steered onto one of those is not covered by it.`
                  : suiteAnatomy.quantumSummary,
              },
            ]
          : []),
        {
          label: 'Suites enumerated',
          /* ONE model decides which suites are exposed.
             This count used to read the per-suite `quantumVulnerable` flag,
             which is set from the suite NAME alone — so it counted the
             negotiated TLS 1.3 suite as vulnerable while the row above,
             decomposing that same suite against the measured X25519MLKEM768
             group, reported no exposure at all. Both rows now run
             `decomposeSuite` with the measured group, so the negotiated suite
             cannot be exposed in one row and protected in the other. */
          value: suites.length ? `${suites.length} accepted · ${exposedSuites} quantum-vulnerable` : '—',
          tone: exposedSuites > 0 ? TONE_WARN : suites.length ? TONE_PASS : undefined,
          detail: suites.length
            ? `Each suite was offered alone and accepted by the endpoint: ${suites.map((suite) => suite.standardName ?? suite.name).join(', ')}.` +
              (suites.length - exposedSuites > 0
                ? ` ${pluralize(suites.length - exposedSuites, 'suite')} carr${suites.length - exposedSuites === 1 ? 'ies' : 'y'} no quantum-vulnerable key agreement${hybridApplied ? ` under the measured ${pq?.primaryGroup} group` : ''}.`
                : '')
            : 'Full offered-suite enumeration from the cipher scanner',
        },
        /* Static-RSA acceptance is the single most consequential thing on this
           surface and was previously buried in the suite list: a suite with RSA
           key exchange has NO forward secrecy, so recorded traffic is
           retroactively decryptable the moment the server key is broken —
           which the hybrid group does nothing to prevent. */
        {
          label: 'Static RSA accepted',
          value: staticRsa.length
            ? `Yes · ${staticRsa.length} suite(s)`
            : edgeTransport
              ? edgeTransport.staticRsaAccepted
                ? 'Yes'
                : 'No'
              : suites.length
                ? 'No'
                : 'Not probed',
          tone:
            staticRsa.length || edgeTransport?.staticRsaAccepted
              ? TONE_FAIL
              : suites.length || edgeTransport
                ? TONE_PASS
                : TONE_MUTED,
          detail: staticRsa.length
            ? `${staticRsa.map((suite) => suite.standardName ?? suite.name).join(', ')} — no forward secrecy: sessions using these suites are retroactively decryptable and are NOT covered by any hybrid key agreement`
            : 'RSA key exchange offers no forward secrecy and must be disabled',
        },
        {
          label: 'ALPN',
          value: edgeTransport?.alpnProbed ? (edgeTransport.alpn ?? 'None negotiated') : 'Not probed',
          tone: edgeTransport?.alpn ? TONE_PASS : TONE_MUTED,
          detail: edgeTransport?.alpnOffered?.length
            ? `Offered: ${edgeTransport.alpnOffered.join(', ')}`
            : 'Application protocols negotiated in the handshake',
        },
      );
      break;
    }

    case 'certificates': {
      if (!certificate && !edgeCert?.probed) break;
      const remaining = certificate ? daysUntil(certificate.validTo) : (edgeCert?.daysRemaining ?? null);
      const chain = certificate?.chain ?? [];
      const isPqSignature = /ml-dsa|dilithium|slh-dsa|sphincs|falcon/i.test(
        `${certificate?.signatureAlgorithm ?? ''} ${certificate?.publicKeyAlgorithm ?? ''}`,
      );

      if (certificate) {
        rows.push(
          {
            label: 'Public key',
            value: `${certificate.publicKeyAlgorithm}${certificate.publicKeySize ? ` ${certificate.publicKeySize}` : ''}`,
            tone: isPqSignature
              ? TONE_PQ
              : /rsa/i.test(certificate.publicKeyAlgorithm) && certificate.publicKeySize < 2048
                ? TONE_FAIL
                : TONE_WARN,
            detail: isPqSignature
              ? 'Post-quantum certificate key'
              : 'Leaf certificate key — classically sound but recoverable by Shor, until replaced by ML-DSA (FIPS 204)',
          },
          {
            label: 'Signature algorithm',
            value: certificate.signatureAlgorithm || 'Unknown',
            tone: /sha-?1|md5/i.test(certificate.signatureAlgorithm || '')
              ? TONE_FAIL
              : isPqSignature
                ? TONE_PQ
                : TONE_WARN,
            detail: 'Algorithm the issuing CA signed this certificate with',
          },
          {
            label: 'Issuer',
            value: certificateName(certificate.issuer) ?? 'Unknown',
            detail: 'Certificate authority that issued the leaf',
          },
          {
            label: 'Subject',
            value: certificateName(certificate.subject) ?? 'Unknown',
            detail: 'Distinguished name the certificate was issued to',
          },
        );
      }

      rows.push({
        label: 'Validity',
        value: remaining === null
          ? 'Unknown'
          : certificate?.isExpired || remaining < 0
            ? 'Expired'
            : `${remaining} day${remaining === 1 ? '' : 's'} remaining`,
        tone: certificate?.isExpired || (remaining ?? 0) < 0 ? TONE_FAIL : (remaining ?? 0) < 30 ? TONE_WARN : TONE_PASS,
        detail: certificate ? `Valid ${certificate.validFrom} → ${certificate.validTo}` : 'Remaining lifetime of the served leaf',
      });

      /* Chain TRUST is a measurement the parsed certificate cannot make — it
         needs a validated handshake against a trust store, which is what the
         edge engine performs. "3 certificates returned" and "3 certificates
         that chain to a trusted root" are different statements. */
      rows.push({
        label: 'Chain',
        value: edgeCert?.probed
          ? `${edgeCert.chainDepth} certificate(s) · ${edgeCert.chainTrusted === null ? 'trust unknown' : edgeCert.chainTrusted ? 'trusted' : 'UNTRUSTED'}`
          : chain.length
            ? `${chain.length} certificate(s)`
            : 'Not collected',
        tone:
          edgeCert?.probed && edgeCert.chainTrusted === false
            ? TONE_FAIL
            : chain.some((entry) => entry.isExpired)
              ? TONE_FAIL
              : edgeCert?.chainTrusted || chain.length
                ? TONE_PASS
                : TONE_MUTED,
        detail:
          edgeCert?.trustError ||
          chain.map((entry) => entry.subject).join(' → ') ||
          'Chain presented by the endpoint and validated against the public trust store',
      });

      if (edgeCert?.probed) {
        rows.push(
          {
            label: 'Hostname match',
            value: edgeCert.hostnameMatches === null ? 'Unknown' : edgeCert.hostnameMatches ? 'Yes' : 'NO',
            tone: edgeCert.hostnameMatches === false ? TONE_FAIL : edgeCert.hostnameMatches ? TONE_PASS : TONE_MUTED,
            detail: edgeCert.subjectAltNames.length
              ? `${edgeCert.sanCount} SAN(s): ${edgeCert.subjectAltNames.slice(0, 4).join(', ')}${edgeCert.sanCount > 4 ? ' …' : ''}`
              : 'No subject alternative names were parsed',
          },
          {
            label: 'OCSP stapling',
            value: edgeCert.ocspStapled ? 'Stapled' : edgeCert.mustStaple ? 'MUST-STAPLE VIOLATED' : 'Not stapled',
            tone: edgeCert.ocspStapled ? TONE_PASS : edgeCert.mustStaple ? TONE_FAIL : TONE_WARN,
            detail: edgeCert.ocspResponderDetail ?? `Responder state: ${edgeCert.ocspResponderState}`,
          },
          {
            label: 'Certificate Transparency',
            value: edgeCert.sctPresent ? `${edgeCert.sctCount} SCT(s)` : 'No SCTs found',
            tone: edgeCert.sctPresent ? TONE_PASS : TONE_WARN,
            detail: edgeCert.sctPresent
              ? 'Misissuance for this name would be publicly auditable'
              : 'No Signed Certificate Timestamps in the certificate, handshake or stapled OCSP response',
          },
        );
      }

      if (certificate) {
        rows.push({
          label: 'Self-signed',
          value: certificate.isSelfSigned ? 'Yes' : 'No',
          tone: certificate.isSelfSigned ? TONE_FAIL : TONE_PASS,
          detail: 'A self-signed leaf is not anchored to a public trust store',
        });
      }
      break;
    }

    case 'identity': {
      /* ROUTED BY THE SHARED RULE, NOT BY A SECOND ONE.
         This panel used to select its rows with `/jwt|token/i` over the
         category while the module ledger routed findings with
         `moduleIdForFinding`. The two rules disagreed, and the panel rendered
         its "no identity surface was submitted, so the identity modules had
         nothing to read" empty state directly above its own module row reading
         "JWT signing algorithm scanner · 2 findings". Selecting from
         `nodeFindings` — which is `nodeForFindingCategory`, derived from the
         ledger — makes that disagreement structurally impossible. */
      const sshFindings = nodeFindings.filter(
        (finding) => moduleIdForFinding({
          category: finding.category,
          detectionMethod: finding.detectionMethod,
          algorithm: finding.algorithm,
        }) === 'ssh-host-key-scanner',
      );
      const jwtFindings = nodeFindings.filter((finding) => !sshFindings.includes(finding));
      if (sshFindings.length === 0 && jwtFindings.length === 0) break;
      const hostKeys = Array.from(
        new Set(sshFindings.filter((finding) => /host key/i.test(finding.category)).map((finding) => finding.algorithm)),
      );
      const sshKex = Array.from(
        new Set(sshFindings.filter((finding) => /exchange/i.test(finding.category)).map((finding) => finding.algorithm)),
      );
      rows.push(
        {
          label: 'SSH host keys',
          value: hostKeys.length ? hostKeys.join(', ') : 'Not observed',
          tone: hostKeys.some((key) => /rsa|dss/i.test(key)) ? TONE_WARN : hostKeys.length ? TONE_PASS : TONE_MUTED,
          detail: 'Host key algorithms advertised in the SSH banner',
        },
        {
          label: 'SSH key exchange',
          value: sshKex.length ? sshKex.slice(0, 3).join(', ') : 'Not observed',
          detail: 'Key-exchange algorithms offered by the SSH server',
        },
        {
          label: 'Token algorithms',
          value: jwtFindings.length
            ? Array.from(new Set(jwtFindings.map((finding) => finding.algorithm))).slice(0, 3).join(', ')
            : 'Not observed',
          tone: jwtFindings.some((finding) => finding.threatLevel !== 'SAFE') ? TONE_WARN : TONE_MUTED,
          detail: 'Signing algorithms detected on JWT-issuing endpoints',
        },
        {
          label: 'Identity observations',
          value: String(sshFindings.length + jwtFindings.length),
          detail: 'Findings routed to the identity surface',
        },
      );
      break;
    }

    case 'code': {
      const headers = api?.securityHeaders ?? [];
      const repoPatterns = repo?.patterns ?? [];
      const webPatterns = webCrypto?.patterns ?? [];
      /* ONE header model for the whole page.
         ------------------------------------------------------------------
         This row counted `api.securityHeaders` — every header the probe asked
         for, HSTS included, with no notion of applicability — while the
         Observed Attack Surface row counts the EDGE model, which excludes HSTS
         (it has its own row) and drops headers that are not applicable or are
         superseded by a stronger one. The same scan therefore published
         "2/10 hardened" here and "1/8 hardened" there.

         The edge model is the better measurement and it is the one the
         published `http-security-headers` category is scored from, so this row
         reads it too. The probe's own list stays as the fallback for records
         written before the edge engine ran. */
      const edgeHttp = edge?.http;
      /* ONE tally, shared with the Observed Attack Surface row and with the
         published `http-security-headers` category. The fallback used to count
         `headers.length` — every probed header, HSTS included — while the
         surface row counted the non-HSTS set, so the same scan read
         "1/3 hardened" here and "0/2 hardened" there. */
      const tally = headerTally(edgeHttp, headers);
      const useEdge = tally.source === 'edge';
      const hardened = tally.hardened ?? 0;
      const applicable = tally.applicable ?? 0;
      if (headers.length === 0 && !edgeHttp?.reachable && !repo && !webCrypto) break;
      if (applicable > 0) {
        rows.push({
          label: 'Security headers',
          value: tally.label,
          tone: hardened === applicable ? TONE_PASS : hardened > applicable / 2 ? TONE_WARN : TONE_FAIL,
          detail: useEdge
            ? (edgeHttp!.headers ?? [])
                .filter((header) => header.name !== 'strict-transport-security' && header.status !== 'Not Applicable' && header.status !== 'Healthy')
                .map((header) => `${header.name}: ${header.present ? header.weakness || 'present, weak' : 'absent'}`)
                .join(' · ') ||
              'Every applicable transport-security header is hardened. Counted over the applicable set — HSTS is reported on its own row.'
            : headers
                .filter((header) => !header.secure)
                .map((header) => `${header.name}: ${header.present ? 'present, weak' : 'absent'}`)
                .join(' · ') || 'Every probed header is hardened',
        });
      }
      if (repo) {
        rows.push(
          {
            label: 'Repository',
            value: repo.accessible === false ? (repo.notice ?? 'Not accessible') : (repo.repoName ?? 'Scanned'),
            tone: repo.accessible === false ? TONE_MUTED : TONE_PASS,
            detail: repo.repoUrl ?? 'Repository supplied with this scan',
          },
          {
            label: 'Files scanned',
            value: repo.filesScanned !== undefined ? `${repo.filesScanned}/${repo.totalFiles ?? repo.filesScanned}` : '—',
            detail: `Branch ${repo.defaultBranch ?? 'default'} · visibility ${repo.visibility ?? 'unknown'}`,
          },
          {
            label: 'Crypto patterns',
            value: repoPatterns.length ? String(repoPatterns.length) : 'None matched',
            tone: repoPatterns.some((pattern) => pattern.threatLevel === 'CRITICAL' || pattern.threatLevel === 'HIGH')
              ? TONE_FAIL
              : repoPatterns.length
                ? TONE_WARN
                : TONE_PASS,
            detail: 'Cryptographic API and key-material patterns matched in source',
          },
        );
      }
      if (webCrypto) {
        rows.push({
          label: 'Web Crypto usage',
          value: webPatterns.length ? `${webPatterns.length} in ${webCrypto.scriptsAnalyzed ?? 0} script(s)` : 'None detected',
          tone: webPatterns.some((pattern) => pattern.threatLevel !== 'SAFE') ? TONE_WARN : TONE_PASS,
          detail: `${webCrypto.pagesScanned ?? 0} page(s) analyzed`,
        });
      }
      if (api?.endpointsProbed) {
        rows.push({
          label: 'API endpoints probed',
          value: String(api.endpointsProbed),
          detail: `Against ${api.hostname ?? primary?.target ?? 'the submitted host'}`,
        });
      }
      /* WHAT THIS SURFACE'S SCORE IS ACTUALLY ABOUT.
         The published model has no category for application cryptography, so
         this surface is scored on HTTP Security Headers and HSTS — which is
         defensible, but the card is titled "Code & Dependencies" and reads as a
         verdict on source code. When the dependency scanner did not run (a bare
         domain exposes no repository and no page bundle), a reader is entitled
         to know that the number in front of them was not measured from any
         code at all. */
      const dependencyModule = input.modules.find((module) => module.id === 'dependency-crypto-scanner');
      if (!repo && !webCrypto) {
        rows.push({
          label: 'Application cryptography',
          value: 'Not read',
          tone: TONE_MUTED,
          detail:
            `${dependencyModule?.reason ?? 'No repository or page bundle was read on this run'}. ` +
            'Submit a repository URL or an https:// page to read source and bundle cryptography. ' +
            'The posture score on this card is measured from the response-header controls above, not from code.',
        });
      }
      break;
    }

    case 'posture': {
      const readiness = scanner2?.quantumReadiness ?? null;
      const risk = scanner2?.quantumRiskScore ?? null;
      const attack = scanner2?.attackAssessment ?? null;
      const hndl = scanner2?.hndlRisks ?? [];
      const quantum = edge?.quantum ?? null;
      /* The PUBLISHED category, not the edge engine's raw number.
         The row below calls itself "the published Post-Quantum Readiness
         category for this target", and on a run whose hybrid probe never
         settled that category is excluded — while the edge engine still
         carries the figure it computed from a `hybridObserved: false` it had
         no evidence for. Reading the raw number put "6%" inside a card whose
         own score decomposition said the dimension was not measured. */
      const publishedReadiness = input.scoreComponents.find(
        (component) => component.key === 'post-quantum-readiness',
      );
      const endpointReadiness =
        publishedReadiness && publishedReadiness.score !== null
          ? publishedReadiness.score
          : publishedReadiness
            ? null
            : (quantum?.postQuantumReadiness ?? null);
      const hybridApplied = Boolean(pq?.probed && pq.state === 'pass' && pq.hybridGroups.length > 0);
      if (!readiness && !risk && !attack && hndl.length === 0 && !quantum && !pq?.probed) break;

      /* The SAME reconciliation the Transport panel and the Cryptographic
         Intelligence panel read. Deriving a second quantum verdict here is how
         "Hybrid-protected" came to sit above "Static RSA accepted: Yes". */
      const transport = reconcileTransport(tls, edge, undefined);
      const verdict = transport.quantumVulnerability;
      const postureVerdict = verdict.measured
        ? verdict.value === 'hybrid'
          ? { label: 'Hybrid-protected', tone: TONE_PQ, basis: verdict.basis }
          : verdict.value === 'hybrid-partial'
            ? { label: 'Hybrid — partial coverage', tone: TONE_WARN, basis: verdict.basis }
            : verdict.value === 'resistant'
              ? { label: 'Quantum-resistant', tone: TONE_PQ, basis: verdict.basis }
              : { label: 'Vulnerable', tone: TONE_FAIL, basis: verdict.basis }
        : { label: 'Not measured', tone: TONE_MUTED, basis: verdict.basis };

      /* How much of the assessment's evidence Scanner_2 could actually score.
         Its model only accepts algorithms it can map onto the classical
         catalogue, so its severity split is a subset of the assessment's — and
         a subset presented without its denominator reads as a disagreement. */
      const scanner2Mapped = scanner2?.observedFindings?.length ?? null;
      const scanner2Coverage = scanner2Mapped !== null && input.findings.length > 0
        ? { mapped: scanner2Mapped, total: input.findings.length, unmapped: Math.max(0, input.findings.length - scanner2Mapped) }
        : null;

      /* The measured post-quantum posture leads, because it is the one thing on
         this surface that was DIRECTLY observed rather than modelled. An
         endpoint running hybrid ML-KEM key agreement is not "Critical" on the
         strength of a modelled break window, and a panel that opened with the
         model said exactly that. */
      if (pq?.probed) {
        rows.push({
          label: 'PQ key agreement',
          value: pq.value,
          tone: hybridApplied ? TONE_PQ : pq.pureKemGroups.length ? TONE_WARN : TONE_FAIL,
          detail: pq.detail,
        });
        if (hybridApplied) {
          rows.push({
            label: 'Hybrid construction',
            value: `${pq.classicalComponent} + ${pq.postQuantumComponent}`,
            tone: TONE_PQ,
            detail: `${pq.primaryGroup} accepted in isolation across ${pq.handshakes} handshake(s) · confidence ${pq.confidence}%. Session secrets on this channel are not recoverable by Shor.`,
          });
        }
      }
      if (quantum) {
        rows.push(
          {
            label: 'Signature posture',
            value: quantum.pqSignatureObserved ? 'Post-quantum signature observed' : 'Classical signatures',
            tone: quantum.pqSignatureObserved ? TONE_PQ : TONE_WARN,
            detail: quantum.pqSignatureObserved
              ? 'A post-quantum signature was parsed from the served certificate chain'
              : 'Certificate authentication remains classical — ML-DSA (FIPS 204) is the migration target. Signature exposure is forgery-at-break, not harvest-now.',
          },
          /* NAME THE POPULATION.
             This card can carry three different "readiness" numbers — this
             endpoint's measured posture, Scanner_2's estate-wide asset share,
             and Scanner_2's risk aggregate — and they legitimately differ
             because they count different things. Labelling all three
             "readiness" is what made the panel read as self-contradictory, so
             every row below states its source and its population in the label
             itself, not only in a tooltip. */
          /* `Math.round(null)` is 0, and 0 here reads as "measured, and as bad as
             it gets" on a higher-is-better scale. A target whose port never
             answered reports "Not measured" and stays tonally neutral. */
          {
            label: 'PQ readiness · this endpoint',
            value: endpointReadiness === null ? 'Not measured' : `${Math.round(endpointReadiness)}%`,
            tone:
              endpointReadiness === null
                ? TONE_MUTED
                : endpointReadiness >= 60
                  ? TONE_PASS
                  : endpointReadiness >= 35
                    ? TONE_WARN
                    : TONE_FAIL,
            detail:
              endpointReadiness === null
                ? publishedReadiness?.observed ??
                  'The published Post-Quantum Readiness category was not measured on this run.'
                : `${quantum.readinessReasons.slice(0, 3).join(' · ') || 'Measured from the observed edge surface'}` +
                  ' — the published Post-Quantum Readiness category for this target, and the same number the surface score above is partly derived from.',
          },
          /* ONE lookup decides the word AND the colour.
             This row used to take its value from `quantum.vulnerability` and its
             tone from `quantum.quantumRisk` — two fields of the same object that
             legitimately disagree, because one describes the key agreement and
             the other aggregates every risk factor. The result was the literal
             string "Hybrid-protected" rendered in the failure colour. It now
             reads the reconciled transport verdict, the same one the
             Cryptographic Intelligence panel prints, so the two cannot diverge
             and a partially-covered hybrid endpoint is amber in both. */
          {
            label: 'Quantum vulnerability',
            value: postureVerdict.label,
            tone: postureVerdict.tone,
            detail: postureVerdict.basis,
          },
        );
      }
      if (readiness) {
        /* NAME THE POPULATION, AND COUNT IT HONESTLY.
           This row printed `readiness.totalAssets`, which the migration engine
           filled with `findings.length` — so a single-asset scan reported
           "3 of 16 inventoried asset(s)". The engine now returns both counts
           separately; the row leads with the observation count it actually
           grades and states the asset count beside it. */
        /* Records written before the engine separated the two populations
           carry only the old `totalAssets` (which held the finding count), so
           the observation counts are optional and the row degrades to the
           percentage rather than restating a number it can no longer name. */
        const safeObservations = readiness.quantumSafeFindings;
        const totalObservations = readiness.totalFindings;
        const readinessDetail = readiness.notAssessed
          ? 'No cryptographic observation could be mapped to the migration model, so no readiness share is claimed.'
          : totalObservations !== undefined && safeObservations !== undefined
            ? `${safeObservations} of ${totalObservations} cryptographic observation(s) on ` +
              `${pluralize(readiness.totalAssets, 'scanned asset')} need no migration. This is a share of OBSERVATIONS, not of the ` +
              "asset inventory, and not this endpoint's measured posture — it does not contribute to the surface score above."
            : 'Share of the cryptographic observations Scanner_2 could map onto its migration model that need no migration. ' +
              "This is a share of OBSERVATIONS, not of the asset inventory, and not this endpoint's measured posture.";
        rows.push({
          label: 'Migration readiness · Scanner_2',
          value: readiness.notAssessed ? 'Not assessed' : `${Math.round(readiness.score)}% · ${readiness.label}`,
          tone: readiness.notAssessed ? TONE_MUTED : readiness.score >= 60 ? TONE_PASS : TONE_WARN,
          detail: readinessDetail,
        });
      }
      if (risk) {
        /* Scanner_2's model has seven categories; a web scan reaches two of
           them. The other five are UNMEASURED — they used to be scored 850 and
           carried their full weight, so 65% of this number described nothing at
           all and always described it favourably. The weight is now
           redistributed over what was measured, and the row states the coverage
           so the number can be read for what it is. */
        /* `measuredWeight` is absent on records written before the aggregate
           stopped scoring unobserved categories, so its absence means "coverage
           unknown" and must not be read as zero coverage. */
        const measuredPct = risk.measuredWeight === undefined ? null : Math.round(risk.measuredWeight * 100);
        const measuredNames = (risk.measuredCategories ?? []).join(', ');
        rows.push(
          {
            label: 'Risk aggregate · Scanner_2',
            value: measuredPct === 0 ? 'Not assessed' : `${Math.round(risk.overall)} · ${risk.level}`,
            tone:
              measuredPct === 0
                ? TONE_MUTED
                : risk.level === 'quantum-safe'
                  ? TONE_PASS
                  : risk.level === 'critical-risk'
                    ? TONE_FAIL
                    : TONE_WARN,
            detail: measuredPct === 0
              ? 'No Scanner_2 category was observed on the submitted targets, so no aggregate is claimed.'
              : `Finding-weighted index on Scanner_2's own 0-1000 scale — not a 0-100 posture, and not an input to the surface ` +
                `score above.` +
                (measuredPct === null
                  ? ' Recorded before this run reported its category coverage.'
                  : ` Computed over the ${measuredNames || 'observed'} categor${(risk.measuredCategories?.length ?? 0) === 1 ? 'y' : 'ies'} ` +
                    `only (${measuredPct}% of the model's weight); the categories this scan did not reach are excluded rather than assumed safe.`),
          },
          {
            label: 'Severity split · Scanner_2',
            value: `${risk.criticalCount}C · ${risk.highCount}H · ${risk.moderateCount}M · ${risk.lowCount}L`,
            /* Scanner_2 scores only the observations whose algorithm it can map
               onto its classical model, so this split is a SUBSET of the
               assessment's own finding counts. Printing it beside them without
               saying so is what made the two look like a disagreement. */
            detail: scanner2Coverage
              ? `${risk.totalFindings} of ${scanner2Coverage.total} recorded observation(s) carry an algorithm Scanner_2 models, and only those are scored here. ` +
                `The remaining ${scanner2Coverage.unmapped} are counted in this assessment's own severity totals.`
              : `${risk.totalFindings} enriched finding(s) scored`,
          },
        );
      }
      if (hndl.length > 0) {
        const immediate = hndl.filter((item) => item.urgencyLevel === 'immediate').length;
        const exposedAssets = new Set(hndl.map((item) => item.targetName).filter(Boolean)).size || 1;
        const algorithms = Array.from(new Set(hndl.map((item) => item.algorithm))).slice(0, 4).join(', ');
        /* COUNT WHAT THE WORD SAYS.
           `hndlRisks` holds one record per OBSERVATION, and every record from a
           single-target scan carries the same `targetName` — so "8 asset(s)"
           was eight observations on one asset. And "key agreement protected"
           was asserted from `hybridApplied` alone, on an endpoint that also
           accepted four static-RSA suites: those sessions are harvestable
           whatever the hybrid group does. Coverage now decides the claim. */
        const covered = hybridApplied && transport.hybridCoverage.value === true;
        const partiallyCovered = hybridApplied && transport.hybridCoverage.value === false;
        rows.push({
          label: 'Harvest-now exposure',
          value: covered
            ? `${pluralize(hndl.length, 'observation')} · key agreement protected`
            : partiallyCovered
              ? `${pluralize(hndl.length, 'observation')} · hybrid does not cover every path`
              : `${pluralize(hndl.length, 'observation')} · ${immediate} immediate`,
          tone: covered ? TONE_WARN : immediate > 0 ? TONE_FAIL : TONE_WARN,
          detail:
            `Across ${pluralize(exposedAssets, 'scanned asset')}: ${algorithms}. ` +
            (covered
              ? 'Transport key agreement is hybrid post-quantum on every path measured, so recorded sessions are NOT decryptable by a future CRQC. The remaining exposure is signature and stored-data, not traffic.'
              : partiallyCovered
                ? transport.hybridCoverage.basis
                : 'Recorded traffic protected by these algorithms is decryptable once a cryptographically relevant quantum computer exists.'),
        });
      }
      if (attack) {
        rows.push(
          {
            label: 'Break window',
            value: `${attack.estimatedBreakWindow.earliest}–${attack.estimatedBreakWindow.latest}`,
            tone: TONE_PQ,
            detail: 'Modelled from the algorithms actually observed, not a fixed date',
          },
          {
            label: 'Attack correlations',
            value: `${attack.attackCorrelations.length} chain(s) · ${attack.classification}`,
            tone: attack.classification === 'CRITICAL' ? TONE_FAIL : TONE_WARN,
            detail: 'Multi-step exposure chains built from correlated findings',
          },
        );
      }
      /* ONE source of migration targets, and it is the one that measured this
         endpoint.
         ------------------------------------------------------------------
         Two things were wrong here. The list was deduplicated on
         `classicalAlgorithm`, so two suites mapping to the same target printed
         it twice — the row read "TLS 1.3 with ML-KEM Hybrid, TLS 1.3 with
         ML-KEM Hybrid". And it read Scanner_2's catalogue while the
         Cryptographic Intelligence panel read the edge engine's, so the same
         ECDSA P-256 leaf was told to migrate to ML-DSA-65 on one panel and
         ML-DSA-44 on the other. The edge engine wins when it measured the
         endpoint, exactly as `buildAssessment` already decides for the
         intelligence panel, so the two panels cannot name different targets for
         the same key. */
      const edgeTargets = edge?.quantum?.migrationTargets ?? [];
      const migration = edgeTargets.length
        ? Array.from(new Map(edgeTargets.map((target) => [target.name, {
            recommendedPQC: target.name,
            classicalAlgorithm: target.replaces,
            nistStandard: target.standard,
          }] as const)).values())
        : Array.from(
            new Map(
              (scanner2?.migrationRecommendations ?? []).map((item) => [item.recommendedPQC, {
                recommendedPQC: item.recommendedPQC,
                classicalAlgorithm: item.classicalAlgorithm,
                nistStandard: item.nistStandard,
              }] as const),
            ).values(),
          );
      if (migration.length > 0) {
        rows.push({
          label: 'Migration targets',
          value: migration.slice(0, 2).map((item) => item.recommendedPQC).join(', '),
          tone: TONE_PQ,
          detail: `${migration
            .map((item) => `${item.classicalAlgorithm} → ${item.recommendedPQC} (${item.nistStandard})`)
            .join(' · ')}. ${
            edgeTargets.length
              ? 'Named from the primitives this scan actually observed on the endpoint' +
                (hybridApplied ? `, which is why ${pq?.primaryGroup} does not appear — it is already deployed here.` : '.')
              : 'From the Scanner_2 migration catalogue; no public-edge measurement is attached to this scan.'
          }`,
        });
      }
      break;
    }

    default:
      break;
  }

  // Why the panel is empty, stated precisely. "Not measured" and "measured as
  // clean" must never look the same.
  let emptyReason: string | null = null;
  if (rows.length === 0) {
    const ran = modules.some((module) => module.status !== 'Queued');
    if (!primary && input.findings.length === 0) {
      emptyReason = 'No scan evidence yet. Queue an authorized target and run a scan — this panel only ever shows what the scanner actually observed.';
    } else if (nodeKey === 'identity') {
      emptyReason = 'No SSH endpoint or token-issuing surface was submitted with this scan, so the identity modules had nothing to read.';
    } else if (nodeKey === 'code') {
      emptyReason = 'No repository URL was submitted and the origin returned no security-header surface, so the code and dependency modules had nothing to read.';
    } else if (nodeKey === 'posture') {
      emptyReason = 'The Scanner_2 enterprise pass has not produced a posture model for this scan yet.';
    } else if (!ran) {
      emptyReason = 'The modules behind this surface have not reported for this run.';
    } else {
      emptyReason = 'These modules ran but the target exposed nothing for this surface to measure.';
    }
  }

  return { rows, modules, findings: nodeFindings.slice(0, 6), score, scoreBasis, emptyReason };
}

/* ============================================================== evidence ==== */

/**
 * Merge the per-target risk decompositions into one estate view.
 *
 * A dimension is averaged across the targets that MEASURED it, and reported as
 * null when no target did. Averaging in a filler zero from a target that never
 * looked at (say) application code would reintroduce, one level up, exactly the
 * inflation the engine's weight redistribution removes.
 */
function mergeRiskBreakdown(results: ScanResultRecord[]): Partial<Record<keyof ScanRiskBreakdown, number>> | null {
  const rows = results
    .map((result) => ({
      breakdown: result.metadata?.riskBreakdown,
      applicable: result.metadata?.riskBreakdownApplicable,
    }))
    .filter((row): row is { breakdown: ScanRiskBreakdown; applicable: ScanRiskApplicability | null | undefined } =>
      Boolean(row.breakdown),
    );
  if (rows.length === 0) return null;

  const keys: Array<keyof ScanRiskBreakdown> = [
    'certificateRisk',
    'tlsConfigRisk',
    'cipherSuiteRisk',
    'appCryptoRisk',
    'pqcReadiness',
  ];

  const merged: Partial<Record<keyof ScanRiskBreakdown, number>> = {};
  for (const key of keys) {
    const measured = rows
      // Results persisted before applicability was tracked carry no map; those
      // are treated as measured so historical scans keep rendering.
      .filter((row) => row.applicable == null || row.applicable[key])
      .map((row) => row.breakdown[key]);
    const mean = average(measured);
    if (mean !== null) merged[key] = mean;
  }
  return merged;
}

/**
 * The scanner's published risk weights (lib/scanner/web-scanner/risk-scoring).
 * Expressed as percentages so the panel can state them, and so the weighted
 * mean of the posture column reproduces `summary.qScore` exactly.
 */
const RISK_WEIGHTS: Array<{
  key: keyof ScanRiskBreakdown;
  label: string;
  weight: number;
  /** True for the single dedicated post-quantum category. */
  postQuantum: boolean;
  description: string;
}> = [
  { key: 'certificateRisk', label: 'Certificate Posture', weight: 25, postQuantum: false, description: 'public-key algorithm, key size, validity and chain of every certificate collected' },
  { key: 'tlsConfigRisk', label: 'TLS Configuration', weight: 25, postQuantum: false, description: 'negotiated protocol versions and handshake configuration' },
  { key: 'cipherSuiteRisk', label: 'Cipher Suites', weight: 20, postQuantum: false, description: 'offered cipher suites, AEAD usage and forward secrecy' },
  { key: 'appCryptoRisk', label: 'Application Cryptography', weight: 15, postQuantum: false, description: 'repository patterns, Web Crypto usage and API security surface' },
  { key: 'pqcReadiness', label: 'Post-Quantum Readiness', weight: 15, postQuantum: true, description: 'PQC-readiness detection rules across transport and certificates' },
];

/* ============================================================== assessment == */

export interface AssessmentInput {
  status: ScanStatus;
  summary: ScanSummary | null;
  findings: DefensiveFinding[];
  modules: ModuleState[];
  results: ScanResultRecord[];
  scanner2: EnterpriseScanner2 | null;
  targets: string[];
  completedAt: string | null;
  /** Tenant-wide totals from Scanner Intelligence — the platform's headline. */
  estate: {
    totalAssets: number;
    totalFindings: number;
    criticalFindings: number;
    /**
     * High-severity findings across the estate.
     *
     * This used to be absent from the contract, and estate scope substituted a
     * literal `0`. The Executive Summary reads it to decide between "N
     * high-severity findings outstanding" and "No critical or high-severity
     * cryptographic findings were recorded" — so a tenant with open high
     * findings and no criticals was told, in writing, that it had neither.
     * Absence is not good news; the count is carried.
     */
    highFindings: number;
    vulnerableAssets: number;
    /**
     * Quantum-vulnerable COMPONENTS across the estate — the same population the
     * CBOM page counts. Estate scope previously used `totalFindings` as the
     * vulnerable count, which classed every SAFE and INFO finding as vulnerable
     * and meant a fully PQC estate could still be labelled "Vulnerable".
     */
    vulnerableComponents: number;
    pqcReadiness: number;
    riskScore: number;
  };
  linked: { cbom: number; assets: number; exposures: number };
  provenance: string;
}

export function buildAssessment(input: AssessmentInput): ScannerAssessment {
  const { summary, findings, modules, results, scanner2 } = input;

  const executedModules = modules.filter((module) => module.status !== 'Queued');
  const completedModules = modules.filter((module) => module.status === 'Completed' || module.status === 'No findings');
  const skippedModules = modules.filter((module) => module.status === 'Skipped');
  const failedModules = modules.filter((module) => module.status === 'Failed');
  const unreportedModules = modules.filter((module) => module.status === 'Queued');

  const hasEvidence = Boolean(summary) || findings.length > 0 || input.estate.totalFindings > 0;
  const live = input.status === 'queued' || input.status === 'running' || input.status === 'analyzing';

  /* ── ONE evidence scope ──────────────────────────────────────────────────
     Every executive number below is read from a single scope, never mixed.
     Blending them is how the page could show a scan-scoped grade of A beside an
     estate-scoped count of 106 critical findings: two true numbers describing
     two different populations, presented as if they described one.

     `scan`   — a run (live or the one being reviewed) produced a summary.
     `estate` — no scan is in view, so the tenant-wide Scanner Intelligence
                snapshot answers every question instead. */
  const scope: 'scan' | 'estate' = summary ? 'scan' : 'estate';
  /* COUNTS ARE COUNTS. A summary field that is absent or non-numeric is read as
     zero rather than allowed to travel as `undefined`, which the panels printed
     verbatim ("Estate Footprint · assets: undefined") and which poisoned every
     arithmetic that touched it. The canonical summary shape is enforced at the
     API boundary (reconcileStoredSummary); this keeps a malformed one from
     rendering as text. */
  const count = (value: unknown): number => {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  };
  const scoped = {
    totalFindings: count(scope === 'scan' ? summary!.totalFindings : input.estate.totalFindings),
    critical: count(scope === 'scan' ? summary!.critical : input.estate.criticalFindings),
    high: count(scope === 'scan' ? summary!.high : input.estate.highFindings),
    vulnerable: count(scope === 'scan' ? summary!.vulnerable : input.estate.vulnerableComponents),
    assets: count(scope === 'scan' ? summary!.targetsScanned : input.estate.totalAssets),
  };

  /* ── Composite score ─────────────────────────────────────────────────────
     `qScore` is the backend's posture score (100 − exposure). It is what the
     History tab, the Assets page and the CBOM view already display, so using
     it here is what keeps the scanner's headline in lock-step with the rest of
     the platform rather than introducing a second opinion. */
  /* A SCORE IS A NUMBER OR IT IS ABSENT — it is never NaN.
     `clamp()` is Math.round-based, so `clamp(undefined)` returns NaN silently
     (strictNullChecks is off project-wide). A stored summary that carried no
     `qScore` therefore published NaN as the tenant's encryption score, which
     `scoreToGrade` floored to "F · Critical" and the timeline printed as
     "NaN/100". The source of those summaries is fixed at the API boundary; this
     is the second line of defence, and it degrades to "not scored" rather than
     to a zero that reads as a measurement. */
  const finite = (value: unknown): number | null => {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  };
  const summaryScore = summary ? finite(summary.qScore) : null;
  const estateScore = finite(input.estate.riskScore);
  const encryptionScoreValue = summary
    ? (summaryScore !== null ? clamp(summaryScore) : null)
    : (estateScore !== null ? clamp(100 - estateScore) : null);
  const encryptionScore = encryptionScoreValue ?? 0;
  const breakdown = mergeRiskBreakdown(results);

  /* The published twelve-category decomposition, merged across targets. This is
     the same model, the same weights and the same grade table /public-scan uses,
     which is what lets a host assessed on either surface be compared directly. */
  const scoreComponents = mergePublishedCategories(results, breakdown);

  /* Classical = every category except the two quantum ones, matching
     CLASSICAL_CATEGORY_KEYS in the published model. Both halves and their
     weight shares come from ONE function, so the Encryption Score panel cannot
     caption a number with a weight that was not used to compute it. */
  const postureSplit = postureSlices(scoreComponents);
  const classicalScore = postureSplit.classical.score ?? encryptionScore;

  // What the published weighted model alone says, kept beside the headline so a
  // divergence is visible rather than hidden.
  const measuredComponents = scoreComponents.filter((component) => component.score !== null);
  const decompositionWeight = measuredComponents.reduce((sum, component) => sum + component.weight, 0);
  const decompositionScore = decompositionWeight > 0
    ? clamp(
        measuredComponents.reduce((sum, component) => sum + (component.score as number) * component.weight, 0) /
          decompositionWeight,
      )
    : null;
  const decompositionAgrees =
    decompositionScore === null || Math.abs(decompositionScore - encryptionScore) <= 1;

  /* ── Post-quantum readiness ──────────────────────────────────────────────
     The headline PQ number is the platform's own readiness figure (share of
     discovered components that are already quantum-safe). Scanner_2's
     asset-level readiness is reported separately, labelled with its source,
     rather than averaged into it — two different measurements of two different
     populations must not be silently blended. */
  /* The published model's Post-Quantum Readiness category IS the platform's
     definition — hybrid key agreement 55, PQ signature 30, TLS 1.3 12,
     short-lived certificates 8, CT 3, enforced HSTS 3. Using the share of
     findings rated SAFE instead was a different measurement of a different
     population, and it is why this surface reported 0% where /public-scan
     reported 8% for the same host. The finding-share is kept only as a fallback
     for estates with no transport evidence at all. */
  const publishedPq = scoreComponents.find((component) => component.key === 'post-quantum-readiness');
  const pqWasScored = publishedPq?.score !== null && publishedPq?.score !== undefined;
  /* When the published model measured it, that is the number. When it did NOT,
     the honest answer is null — not a finding-share fallback that produces a
     confident-looking 14 for an endpoint whose named groups were never probed.
     The fallback survives only for estates with findings but no transport
     evidence at all, where a share of the inventory IS the best available
     reading and is labelled as such. */
  const postQuantumReadiness = pqWasScored
    ? publishedPq!.score
    : summary && summary.totalFindings > 0 && !results[0]?.metadata?.edgeIntelligence
      ? clamp((summary.pqcReady / summary.totalFindings) * 100)
      : null;
  const postQuantumReadinessReason = postQuantumReadiness !== null
    ? null
    /* `observed` carries the not-measured reason for every score component
       (see ScoreComponent above), so the panel states the same cause the score
       decomposition does rather than inventing a second explanation. */
    : publishedPq?.observed
      || 'Post-quantum readiness was not scored: named key-agreement groups were not probed, so no post-quantum group could be offered to this endpoint.';

  const scanner2Readiness = scanner2?.quantumReadiness
    ? { score: clamp(scanner2.quantumReadiness.score), label: scanner2.quantumReadiness.label }
    : null;

  /* ── Evidence coverage & confidence ────────────────────────────────────
     Coverage is measured against the modules that COULD apply. A module the
     scanner correctly reported as not applicable — an SSH host-key probe on a
     URL target — is not a coverage gap and must not depress the number, or
     every web scan would permanently read ~70% covered. */
  const applicableModules = modules.length - skippedModules.length;
  const evidenceCoverage = applicableModules > 0
    ? clamp((completedModules.length / applicableModules) * 100)
    : modules.length > 0
      // Every catalogued module was inapplicable: there is no coverage to claim.
      ? 0
      : hasEvidence
        ? 100
        : 0;

  const measuredConfidence = average(
    results
      .map((result) => result.metadata?.scanConfidence?.confidence)
      .filter((value): value is number => typeof value === 'number'),
  );
  const confidence = measuredConfidence !== null ? clamp(measuredConfidence) : evidenceCoverage;
  const confidenceFactors = Array.from(
    new Set(results.flatMap((result) => result.metadata?.scanConfidence?.factors ?? [])),
  );
  const confidenceDetail = confidenceFactors.length
    ? confidenceFactors.slice(0, 3).join(' · ')
    : `${completedModules.length} of ${applicableModules || modules.length || executedModules.length} applicable scanner modules reported evidence.`;

  /* ── Grade ───────────────────────────────────────────────────────────────
     A grade is withheld until the scan actually completed with a summary: a
     letter computed from a partial run is a claim the evidence does not
     support. */
  /* A grade is a claim about a whole estate, so it is withheld until the run is
     settled AND the module ledger is closed. `unreportedModules` is non-empty
     only when a run was cut short: grading there produced the "Grade A · 96%"
     on a scan that had run six of twenty-three modules. */
  const runSettled = !live && unreportedModules.length === 0;
  /* `encryptionScoreValue !== null`: a grade is a statement about a score, so an
     absent score cannot be graded — it must not fall through to an "F". */
  const gradeable =
    hasEvidence
    && runSettled
    && encryptionScoreValue !== null
    && (Boolean(summary) || input.estate.totalFindings > 0);
  const gradeRow = scoreToGrade(encryptionScore);
  const grade = gradeable ? gradeRow.grade : '—';
  const gradeLabel = gradeable
    ? gradeRow.rating
    : live
      ? 'Assessment running'
      : unreportedModules.length > 0
        ? 'Incomplete run'
        : 'Awaiting scan';
  const gradeColor = gradeable ? gradeRow.color : '#94a3b8';
  const gradeDetail = gradeable
    ? evidenceCoverage >= 100
      ? gradeRow.meaning
      : `${gradeRow.meaning} Graded on ${evidenceCoverage}% module coverage${
          skippedModules.length ? `; ${pluralize(skippedModules.length, 'module')} did not apply to these targets` : ''
        }.`
    : live
      ? 'A grade is withheld until every module has reported.'
      : unreportedModules.length > 0
        ? `${pluralize(unreportedModules.length, 'module')} never reported, so this run cannot be graded. Re-run the scan.`
        : 'Run an authorized scan to grade this estate.';

  /* ── Business risk ──────────────────────────────────────────────────────
     Score-derived, then floored by the presence of critical findings: an estate
     with an open critical exposure is not "Low risk" no matter what the mean
     says. */
  const criticalCount = scoped.critical;
  const highCount = scoped.high;
  const scopeNoun = scope === 'scan' ? 'this assessment' : 'the tenant estate';
  let businessRisk: RiskBand = gradeable ? riskBandForScore(encryptionScore) : 'Not assessable';
  if (gradeable && criticalCount > 0) businessRisk = worstRisk(businessRisk, 'High');
  if (gradeable && criticalCount >= 5) businessRisk = worstRisk(businessRisk, 'Critical');
  const businessRiskDetail = gradeable
    ? criticalCount > 0
      ? `${pluralize(criticalCount, 'critical finding')} open across ${scopeNoun}.`
      : highCount > 0
        ? `No critical findings; ${pluralize(highCount, 'high-severity finding')} outstanding across ${scopeNoun}.`
        : `No critical or high-severity cryptographic findings were recorded across ${scopeNoun}.`
    : 'Risk cannot be stated before a completed scan.';

  /* ── Component population ─────────────────────────────────────────────
     A cryptographic COMPONENT is an algorithm, key, certificate, suite or
     protocol version in the inventory. A detection-rule observation — "No
     Certificate Pinning", "Regulatory Compliance Gap" — is a finding about the
     estate, not an inventory entry.

     `isCryptographicComponent` is the platform's shared rule: CBOM, the Quantum
     Readiness engine and the estate workflow all filter through it, and this
     panel not doing so is why its "Crypto Components" tile could not be
     reconciled against the CBOM page for the same scan. */
  const componentFindings = findings.filter((finding) =>
    isCryptographicComponent({ name: finding.category, algorithm: finding.algorithm }, algorithmFamily),
  );
  const vulnerableComponents = componentFindings.filter(
    (finding) =>
      finding.status === 'Quantum-vulnerable' ||
      finding.status === 'Legacy/deprecated' ||
      finding.status === 'Misconfigured',
  ).length;
  const policyFindings = findings.filter((finding) => !componentFindings.includes(finding));

  /* ── Migration complexity ─────────────────────────────────────────────── */
  const recommendations = scanner2?.migrationRecommendations ?? [];
  /* Only entries that actually ask for work. The catalogue contains
     "No Migration Needed" confirmations (AES-256 → AES-256), and counting them
     made this line claim more families "require migration" than do — the same
     entries the Executive Recommendations panel now drops. */
  const migrationsRequired = recommendations.filter(
    (recommendation) =>
      !/no migration needed/i.test(recommendation.migrationType ?? '') &&
      recommendation.classicalAlgorithm !== recommendation.recommendedPQC,
  );
  const complexityRank: Record<PqcRecommendation['migrationComplexity'], number> = {
    LOW: 1,
    MEDIUM: 2,
    HIGH: 3,
    CRITICAL: 4,
  };
  const worstComplexity = migrationsRequired.reduce<PqcRecommendation['migrationComplexity'] | null>(
    (worst, recommendation) =>
      !worst || complexityRank[recommendation.migrationComplexity] > complexityRank[worst]
        ? recommendation.migrationComplexity
        : worst,
    null,
  );
  const migrationComplexity = worstComplexity
    ? worstComplexity.charAt(0) + worstComplexity.slice(1).toLowerCase()
    : 'Unknown';
  // `pluralize` appends "s" unless told otherwise — this line read "6 algorithm familys".
  const migrationComplexityDetail = worstComplexity
    ? `${pluralize(migrationsRequired.length, 'algorithm family', 'algorithm families')} ${
        migrationsRequired.length === 1 ? 'requires' : 'require'
      } migration; the hardest is rated ${worstComplexity}.`
    : 'No migration recommendations have been generated for this estate yet.';

  /* ── Attack surface ─────────────────────────────────────────────────────
     Only what was actually read off the wire. A control the scan did not reach
     renders `unknown`, never `fail`. */
  const attackSurface = buildAttackSurface(input, findings);

  /* ── Cryptographic intelligence ───────────────────────────────────────── */
  const edge = readEdgeIntelligence(results[0]?.metadata);
  const algorithmCensus = buildObservedAlgorithms(results, findings, edge);
  /* The panel shows the first rows; the census total travels with them so the
     panel can declare what it is not showing rather than silently truncating. */
  const observedAlgorithms = algorithmCensus.entries.slice(0, 8).map((entry) => ({
    name: entry.name,
    role: entry.role,
    quantumVulnerable: entry.quantumVulnerable,
    count: entry.count,
  }));

  // The negotiated key agreement is a direct measurement when the edge engine
  // reached the target. It is preferred over the raw handshake because Node
  // never reports the TLS 1.3 group — only the named-group probe knows it — so
  // this is the difference between "ECDHE (TLS 1.3 key_share)" and the actual
  // group. Findings are the last resort, for targets with no transport at all
  // (a repository URL), never a substitute for a measurement.
  const negotiatedTls = results[0]?.metadata?.tlsAnalysis ?? null;
  const keyExchangeFindings = findings.filter((finding) =>
    /key exchange|key agreement|kex|ecdhe|dhe|x25519|ml-kem|kyber/i.test(`${finding.category} ${finding.algorithm}`),
  );
  const keyExchange = edge?.transport?.keyExchange && edge.transport.keyExchange !== 'unknown'
    ? edge.transport.keyExchange
    : negotiatedTls?.keyExchange
      ? negotiatedTls.negotiatedCurve
        ? `${negotiatedTls.keyExchange} (${negotiatedTls.negotiatedCurve})`
        : negotiatedTls.keyExchange
      : keyExchangeFindings.length
        ? Array.from(new Set(keyExchangeFindings.map((finding) => finding.algorithm))).slice(0, 3).join(', ')
        : 'Not observed';

  /* ONE reconciled transport reading, shared with the Observed Attack Surface
     rows and the score decomposition. This panel used to read
     `edge.quantum.forwardSecrecy`, which is a string the edge engine sets to
     "Not observed" whenever ITS probe failed — even when the socket handshake
     had measured a TLS 1.3 session that is forward secret by construction. */
  const transport = reconcileTransport(negotiatedTls, edge, undefined);
  const forwardSecrecy = transport.forwardSecrecy.measured
    ? displayForwardSecrecy(transport)
    : keyExchangeFindings.length
      ? keyExchangeFindings.some((finding) => /ecdhe|dhe|x25519/i.test(finding.algorithm))
        ? 'Enabled'
        : 'Not offered'
      : 'Not measured';
  const forwardSecrecyBasis = transport.forwardSecrecy.basis;

  /* Quantum vulnerability — from transport evidence, never from finding titles.
     ------------------------------------------------------------------------
     This previously read: "does ANY finding's algorithm string match
     /ml-kem|ml-dsa|kyber|dilithium|slh-dsa/? then Hybrid-protected". Every
     recommendation this scanner produces contains one of those strings —
     "Migrate to ML-KEM-768", "Enable X25519Kyber768 hybrid key exchange" — so
     the estate was declared hybrid-protected precisely BECAUSE the scan had
     recommended hybrid protection. expired.badssl.com, which is TLS 1.2-only
     with an expired chain and static RSA accepted, reported "Hybrid-protected"
     for exactly that reason.

     The verdict is now the edge engine's, computed from the named-group probe
     and the parsed certificate chain — the same classification /public-scan
     publishes, so one host cannot be graded differently on the two surfaces. */
  /* The reconciled reading wins over the edge engine's own verdict.
     ------------------------------------------------------------------------
     The edge engine reports "Unknown" whenever ITS named-group probe failed.
     But when the socket handshake completed, the key exchange that was
     ACTUALLY negotiated was observed — and if it is classical, the session
     that happened IS quantum vulnerable. Publishing "Unknown" beside a HIGH
     quantum risk factor for the same certificate (which the page did) is a
     contradiction: either the exposure is unknown or it is high.

     The reconciler scopes the claim precisely — "the handshake that was
     negotiated used X, which Shor breaks; whether this endpoint would ALSO
     accept a post-quantum group was not measured" — which is both honest and
     more useful than "Unknown". */
  const transportVerdict = transport.quantumVulnerability;
  const quantumVulnerability = transportVerdict.measured
    ? transportVerdict.value === 'hybrid'
      ? 'Hybrid-protected'
      /* A hybrid endpoint that ALSO accepts static RSA or a pre-1.3 protocol is
         not harvest-now safe, and calling it "Hybrid-protected" beside its own
         "Static RSA accepted: Yes" row is the contradiction operators reported.
         The verdict names the gap instead of hiding it in the tooltip. */
      : transportVerdict.value === 'hybrid-partial'
        ? 'Hybrid — partial coverage'
        : transportVerdict.value === 'resistant'
          ? 'Quantum-resistant'
          : 'Vulnerable'
    : edge
      ? edge.quantum.vulnerability
      : !hasEvidence
        ? 'Unknown'
        : scoped.vulnerable > 0
          ? 'Vulnerable'
          : 'Not observed';
  const quantumVulnerabilityReason = transportVerdict.measured
    ? transportVerdict.basis
    : edge
      ? edge.quantum.vulnerabilityReason
      : !hasEvidence
        ? 'No cryptographic evidence has been recorded for this view yet.'
        : 'Derived from persisted finding severities; no public-edge measurement is attached to this scan.';

  /* Migration targets: the edge engine's, when it measured the endpoint, because
     those name the primitive actually observed. The Scanner_2 migration engine
     supplies the estate-wide list otherwise. */
  const rawMigrationTargets = edge?.quantum?.migrationTargets?.length
    ? edge.quantum.migrationTargets.map((target) => ({
        name: target.name,
        standard: target.standard,
        replaces: target.replaces,
      }))
    : recommendations.map((recommendation) => ({
        name: recommendation.recommendedPQC,
        standard: recommendation.nistStandard,
        replaces: recommendation.classicalAlgorithm,
      }));
  /* De-duplicated on the PAIR, not the name.
     One post-quantum algorithm legitimately replaces several classical ones —
     ML-KEM-768 stands in for RSA-2048, RSA-1024 and ECC-P256 alike — so those
     are distinct, useful rows and are kept. What must not survive is the same
     (target, replaces) pair arriving twice from two engines, which is a
     duplicate of one fact. */
  const seenTargets = new Set<string>();
  const migrationTargets = rawMigrationTargets
    .filter((target) => {
      const identity = `${target.name}::${target.replaces}`;
      if (seenTargets.has(identity)) return false;
      seenTargets.add(identity);
      return true;
    })
    .slice(0, 5);

  /* ── Timeline & HNDL ─────────────────────────────────────────────────── */
  const hndlRisks = scanner2?.hndlRisks ?? [];
  const hndl = {
    immediate: hndlRisks.filter((risk) => risk.urgencyLevel === 'immediate').length,
    soon: hndlRisks.filter((risk) => risk.urgencyLevel === 'soon').length,
    planned: hndlRisks.filter((risk) => risk.urgencyLevel === 'planned').length,
    window: scanner2?.attackAssessment?.estimatedBreakWindow ?? null,
  };

  /* Everything the assessment did NOT measure, with the scanner's own reason. */
  const notAnalyzedLines = [
    ...skippedModules.map(
      (module) => `${module.name} — ${module.reason || 'not applicable to the submitted target types'}`,
    ),
    ...failedModules.map((module) => `${module.name} — FAILED: ${module.error || module.reason || 'no error reported'}`),
    ...unreportedModules.map((module) => `${module.name} — never reported; this run's coverage is incomplete`),
  ];

  /* ── Assembly ────────────────────────────────────────────────────────── */
  return {
    hasEvidence,
    live,
    provenance: input.provenance,
    target: {
      label: input.targets.length ? input.targets.join(', ') : `${input.estate.totalAssets} discovered assets`,
      count: scoped.assets,
      completedAt: input.completedAt,
    },
    executive: {
      grade,
      gradeLabel,
      gradeColor,
      gradeable,
      gradeDetail,
      encryptionScore,
      classicalScore,
      postQuantumReadiness,
      postQuantumReadinessReason,
      evidenceCoverage,
      businessRisk,
      businessRiskDetail,
      migrationComplexity,
      migrationComplexityDetail,
      confidence,
      confidenceDetail,
    },
    scoreComponents,
    decompositionScore,
    decompositionAgrees,
    postureSplit,
    attackSurface,
    intelligence: {
      observedAlgorithms,
      algorithmCensus,
      keyExchange,
      forwardSecrecy,
      quantumVulnerability,
      quantumVulnerabilityReason,
      /* ONE READINESS NUMBER PER PAGE.
         This read `edge.quantum.postQuantumReadiness` directly while the
         Encryption Score panel read the published category, and on a run whose
         hybrid probe never settled the two disagreed in the worst possible
         way: the category was correctly withheld as "not measured" while this
         panel published "Endpoint PQ Readiness 6%" — a confident number built
         on a hybrid signal that carries 55 of its 100 points and was never
         observed. It now reads the same category, so the panel is silent
         exactly when the model is. */
      postQuantumReadiness:
        edge && postQuantumReadiness !== null
          ? { score: postQuantumReadiness, reasons: edge.quantum.readinessReasons }
          : null,
      /* Why it is silent, in the score decomposition's own words. */
      postQuantumReadinessReason: postQuantumReadiness === null ? postQuantumReadinessReason : null,
      quantumRiskFactors: edge?.quantum?.riskFactors ?? [],
      migrationTargets,
      confidence,
      scanner2Readiness,
    },
    /* `encryptionScoreValue`, not `encryptionScore`: the timeline must say
       "Not scored" rather than print the 0 the display value falls back to. */
    timeline: buildTimeline(hndl, encryptionScoreValue, postQuantumReadiness, postQuantumReadinessReason),
    recommendations: buildRecommendations(
      recommendations,
      findings,
      [
        /* Measured, not assumed: only primitives the named-group probe actually
           accepted on this endpoint. */
        ...(edge?.pqKeyAgreement?.probed ? edge.pqKeyAgreement.kemParameterSets : []),
        ...(edge?.pqKeyAgreement?.probed ? edge.pqKeyAgreement.hybridGroups : []),
      ],
      edge?.quantum?.migrationTargets ?? [],
    ),
    footprint: {
      metrics: [
        {
          key: 'assets',
          label: 'Assets Scanned',
          value: scoped.assets,
          countedFrom: scope === 'scan'
            ? 'authorized targets the scanner completed a pass over in this assessment'
            : 'assets in the tenant inventory, from the Scanner Intelligence snapshot',
        },
        /* COMPONENTS ARE CRYPTOGRAPHY, NOT EVERY FINDING.
           This tile printed the raw finding total under the label "Crypto
           Components". The scan's findings include detection-RULE observations
           — "No Certificate Pinning", "Regulatory Compliance Gap", "Wide Crypto
           Attack Surface" — which are statements about the estate, not entries
           in a cryptographic inventory. Counting them here made this panel
           disagree with the CBOM page and the Quantum Readiness engine, which
           both filter the same rows through `isCryptographicComponent`. It now
           reads the same rule, and the policy findings are reported on their own
           line instead of being silently folded into the component count. */
        /* SCOPE IS PICKED ONCE, AND THIS TILE FOLLOWS IT.
           In estate scope every other tile switches to the Scanner Intelligence
           snapshot, but this one kept counting the findings still held in view
           while its caption claimed tenant provenance — a scan-scoped number
           labelled as an estate-scoped one, which is exactly the mix Rule 2
           forbids. The snapshot carries TOTALS, not rows, so there is nothing
           to classify against `isCryptographicComponent`: the honest estate
           answer is the observation total, reported as the observation total
           it is. */
        {
          key: 'components',
          label: scope === 'scan' ? 'Crypto Components' : 'Crypto Observations',
          value: scope === 'scan' ? componentFindings.length : input.estate.totalFindings,
          /* "DISTINCT" WAS THE WRONG WORD and it made this tile irreconcilable
             with the Cryptographic Intelligence census beside it. These are
             inventory ROWS — every accepted cipher suite is its own row, as is
             each certificate key and signature — so a www.cloudflare.com scan
             counts 16 of them and calls 12 quantum-vulnerable, while the
             algorithm census on the same page reports 12 observed ALGORITHMS of
             which 6 are asymmetric and 2 post-quantum. Both are right; one
             counts occurrences and the other counts primitives, and nothing on
             either panel said so. The unit is now named here. */
          countedFrom: scope === 'scan'
            ? `cryptographic inventory entries recorded by this assessment — one per observed occurrence (each accepted cipher suite, certificate key and signature is its own entry), counted with the same rule CBOM and Quantum Readiness use. The Cryptographic Intelligence census counts distinct ALGORITHMS instead, so its totals are smaller by design.${policyFindings.length ? ` ${pluralize(policyFindings.length, 'further finding')} in this scan ${policyFindings.length === 1 ? 'is a policy or configuration observation' : 'are policy or configuration observations'}, not inventory.` : ''}`
            : 'cryptographic observations recorded for this tenant, from the Scanner Intelligence snapshot — a total, not a classified component inventory; open CBOM for the component view',
        },
        {
          key: 'cbom',
          label: 'CBOM Records',
          value: input.linked.cbom,
          countedFrom: 'rows written to the cryptographic bill of materials by the scan in view',
        },
        {
          key: 'exposures',
          label: 'Exposure Nodes',
          value: input.linked.exposures,
          countedFrom: 'nodes added to the crypto exposure graph by the scan in view',
        },
      ],
      /* Same population as the tile above it. `scoped.vulnerable` counts every
         finding whose status is vulnerable/legacy/misconfigured, rule findings
         included, so this line claimed 27 "quantum-vulnerable components" on a
         scan holding far fewer actual components. */
      exposureLevel: gradeable
        ? `${businessRisk} — ${pluralize(vulnerableComponents, 'quantum-vulnerable component')}`
        : 'Not assessed',
      basis: `Counted from the scanner's own persisted records for this tenant, scoped to ${scopeNoun}: ${pluralize(completedModules.length, 'module')} measured, ${pluralize(skippedModules.length, 'module')} not applicable, ${pluralize(input.linked.assets, 'asset record')} synchronized. Nothing here is estimated.`,
      components: {
        total: componentFindings.length,
        vulnerable: vulnerableComponents,
        policyFindings: policyFindings.length,
      },
    },
    coverage: buildCoverage(modules, failedModules, skippedModules, unreportedModules),
    scope: {
      analyzed: completedModules.length
        ? completedModules.map((module) => module.name)
        : ['No module has reported evidence yet'],
      // Verbatim reasons from the scanner's module ledger — never a guess about
      // why a module did not run.
      notAnalyzed: notAnalyzedLines.length
        ? notAnalyzedLines
        : ['Every catalogued module was applicable to the submitted targets and reported evidence'],
      statement:
        'The Dashboard Scanner performs authorized, defensive cryptographic inventory only: no exploitation, credential collection, stealth behaviour or unauthorized reconnaissance. Results persist per tenant and populate CBOM, Assets, Crypto Exposure, Quantum Readiness and Migration Planner.',
    },
    /* Projected from the SAME decomposition the gauge and the category bars
       read, so a surface card can never contradict the composite above it. */
    nodeScores: scoreNodesFromCategories(scoreComponents),
    nodeScoreScopes: nodeScoreScopes(scoreComponents),
    hndl,
  };
}

/**
 * Algorithms the scan actually observed.
 *
 * Delegates to the platform's shared census. This function used to keep its own
 * list, with its own vulnerability rule, while the backend's
 * `cryptographic-algorithms` category kept a second one — so a single scan
 * published "4 algorithms observed · 1 quantum-safe" in the score decomposition
 * directly above a panel listing three algorithms, none of them quantum-safe.
 *
 * The rules that made this list correct are preserved inside the census and now
 * apply to both readers: detection-rule TITLES are not algorithms; the socket's
 * "ECDHE (TLS 1.3 key_share)" placeholder names no group so it is not an
 * observation of one; the named-group probe is authoritative for key agreement;
 * and ordering is by algorithm CLASS so the symmetric and protocol material is
 * not pushed past the display cap by a wall of Shor-breakable entries.
 */
function buildObservedAlgorithms(
  results: ScanResultRecord[],
  findings: DefensiveFinding[],
  edge: EdgeIntelligence | null,
): AlgorithmCensus {
  return buildAlgorithmCensus({
    observations: results.map((result) => {
      const measured = result.metadata?.edgeIntelligence?.pqKeyAgreement;
      return {
        tls: result.metadata?.tlsAnalysis ?? null,
        certificate: result.certificateInfo ?? null,
        keyAgreement: measured?.probed
          ? {
              probed: true,
              kemApplied: measured.hybridGroups.length > 0 || measured.pureKemGroups.length > 0,
              hybrid: measured.hybridGroups.length > 0,
              group:
                measured.primaryGroup ?? measured.hybridGroups[0] ?? measured.pureKemGroups[0] ?? null,
              classicalComponent: measured.classicalComponent ?? null,
              postQuantumComponent: measured.postQuantumComponent ?? null,
              kemParameterSets: measured.kemParameterSets ?? [],
            }
          : null,
      };
    }),
    fallbackFindings: findings.map((finding) => ({
      algorithm: finding.algorithm,
      category: finding.category,
    })),
  });
}

/* =========================================================== sub-builders == */

/**
 * The observed attack surface.
 *
 * Mirrors /public-scan's control list one row for one row, so the same host can
 * be read side by side on either surface — and since both now consume the SAME
 * engine bundle, the two cannot disagree about one host.
 *
 * HOW THE "NOT PROBED" ROWS WERE FIXED
 * ------------------------------------
 * Eight controls used to render a flat "Not probed": OCSP stapling, Certificate
 * Transparency, CAA, DNSSEC, ALPN and edge attribution, plus HSTS and the
 * header tally reading "Not observed". That was honest at the time — the
 * authenticated orchestrator genuinely did not perform those probes — but
 * "honest about a gap" is not the same as "measured", and the gap had no reason
 * to exist: /public-scan had run every one of those probes for months.
 *
 * The orchestrator now runs that engine bundle per target and persists the
 * result as `metadata.edgeIntelligence`. Each row below reads its own measured
 * field, so a verdict is a verdict and an absence is stated as one.
 *
 * The contract that made those rows safe still holds and is now enforced per
 * control rather than per surface: a control whose evidence is genuinely
 * missing renders `unknown` with the engine's own reason attached. "We looked
 * and it is absent" and "we could not look" must never render the same.
 */
function buildAttackSurface(input: AssessmentInput, findings: DefensiveFinding[]): SurfaceItem[] {
  const primary = input.results[0];
  const tls = primary?.metadata?.tlsAnalysis ?? null;
  const certificate = primary?.certificateInfo ?? null;
  const api = primary?.metadata?.apiSecurityResult ?? null;
  const edge = readEdgeIntelligence(primary?.metadata);
  const scanner2 = input.scanner2;
  const items: SurfaceItem[] = [];

  /**
   * A control whose evidence never arrived.
   *
   * Reserved for two cases only: a scan persisted before the edge engine
   * existed, and an edge phase that could not complete. Both are genuine
   * "not measured", and the reason says which.
   */
  const unmeasured = (key: string, label: string, why: string): SurfaceItem => ({
    key,
    label,
    value: 'Not measured',
    status: 'unknown',
    detail: edge
      ? why
      : `${why} No public-edge evidence is attached to this scan — either the target has no public edge, or this record predates the edge intelligence engine. Re-run the scan to measure it.`,
  });

  /* ── Reachability ──────────────────────────────────────────────────────── */
  const reachable = Boolean(tls) || Boolean(api?.endpointsProbed);
  items.push({
    key: 'internet-facing',
    label: 'Internet Facing',
    value: !primary ? 'Not observed' : reachable ? 'Yes' : 'No',
    status: !primary ? 'unknown' : reachable ? 'info' : 'pass',
    detail: reachable
      ? 'The scanner completed a network connection to this target from the public Internet.'
      : 'No network service answered on the submitted target.',
  });

  const targetUrl = primary?.target ?? input.targets[0] ?? '';
  const portMatch = targetUrl.match(/:(\d+)/);
  const isHttps = /^https/i.test(targetUrl) || Boolean(tls);
  items.push({
    key: 'tls-service',
    label: 'TLS Service',
    value: !primary ? 'Not observed' : isHttps ? `HTTPS (${portMatch ? portMatch[1] : '443'})` : 'None',
    status: !primary ? 'unknown' : isHttps ? 'pass' : 'fail',
    detail: 'Transport service the scanner negotiated against.',
  });

  /* ── Certificate ───────────────────────────────────────────────────────── */
  const certChain = certificate?.chain ?? [];
  items.push({
    key: 'certificate-chain',
    label: 'Certificate Chain',
    value: certificate ? `${certChain.length || 1} cert${(certChain.length || 1) === 1 ? '' : 's'}` : 'Not observed',
    status: !certificate ? 'unknown' : certChain.length > 1 ? 'pass' : 'partial',
    detail: certChain.length
      ? certChain.map((entry) => entry.subject).join(' -> ')
      : 'Only the leaf certificate was returned; no intermediates were served.',
  });

  /* Names covered.
     This used to print the CN alone with a caveat that SANs "are not extracted
     by the authenticated certificate parser". They are now — the edge
     certificate engine parses the subjectAltName extension — so the row states
     the real coverage instead of apologising for a single name. */
  const commonName = certificate?.subject?.CN ?? certificate?.subject?.commonName ?? null;
  const sans = edge?.certificate?.subjectAltNames ?? [];
  const sanCount = edge?.certificate?.sanCount ?? 0;
  items.push({
    key: 'names-covered',
    label: 'Names Covered',
    value: sanCount
      ? sanCount === 1
        ? sans[0] ?? commonName ?? '1 name'
        : `${pluralize(sanCount, 'name')}`
      : commonName ?? 'Not observed',
    status: sanCount || commonName ? 'info' : 'unknown',
    detail: sanCount
      ? `Subject alternative names on the leaf certificate${edge?.certificate?.isWildcard ? ' (wildcard coverage present)' : ''}.`
      : commonName
        ? 'Common name on the leaf certificate; no subjectAltName extension was parsed from the served chain.'
        : 'No certificate subject was parsed.',
    evidence: sanCount
      ? [
          { label: 'Common name', value: commonName ?? 'not set' },
          {
            label: `Subject alternative names (${sanCount})`,
            value: sans.length < sanCount ? `${sans.join(', ')} … +${sanCount - sans.length} more` : sans.join(', '),
          },
          { label: 'Wildcard', value: edge?.certificate?.isWildcard ? 'yes' : 'no' },
          {
            label: 'Hostname match',
            value:
              edge?.certificate?.hostnameMatches === null || edge?.certificate?.hostnameMatches === undefined
                ? 'not evaluated'
                : edge.certificate.hostnameMatches
                  ? 'the scanned name is covered'
                  : 'the scanned name is NOT covered by this certificate',
          },
        ]
      : undefined,
  });

  /* ── Transport ─────────────────────────────────────────────────────────── */
  const protocols = tls?.supportedProtocols ?? [];
  const legacyProtocols = protocols.filter((protocol) => /TLSv1(\.0)?$|TLSv1\.1|SSLv/i.test(protocol));
  const tlsVersion = primary?.tlsVersion ?? tls?.tlsVersion ?? null;
  items.push({
    key: 'tls-version',
    label: 'TLS Version',
    value: !tlsVersion
      ? 'Not observed'
      : legacyProtocols.length
        ? `${tlsVersion} + legacy`
        : protocols.length
          ? protocols.join(', ')
          : tlsVersion,
    status: !tlsVersion ? 'unknown' : legacyProtocols.length ? 'fail' : /1\.3/.test(tlsVersion) ? 'pass' : 'partial',
    detail: legacyProtocols.length
      ? `${legacyProtocols.join(', ')} still accepted - deprecated by RFC 8996.`
      : 'Protocol versions the endpoint accepted, probed individually.',
  });

  /* Static-RSA key transport, counted ONCE for the whole page.
     ------------------------------------------------------------------------
     This filter was `/(^|_)RSA_WITH/i`, and `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
     contains `_RSA_WITH`. So the two forward-secret ECDHE_RSA suites were
     counted as static RSA and this row published "6 static-RSA key-transport
     suite(s)" while the Transport & Ciphers panel — which matches on the
     suite's parsed KEY EXCHANGE — published "Yes · 4 suite(s)" for the same
     handshake. RSA in `ECDHE_RSA` is the server's AUTHENTICATION, not the key
     exchange; those sessions are forward secret and are not retroactively
     decryptable.

     The test is now anchored to the static-RSA grammar (`TLS_RSA_WITH_…`) and
     to the parsed key exchange, which is what every other consumer of this fact
     already uses — see `transport-truth.reconcileTransport`. */
  const staticRsa = staticRsaSuites(tls?.cipherSuites ?? []);
  items.push({
    key: 'cipher',
    label: 'Cipher Suite',
    value: !tls
      ? 'Not observed'
      : staticRsa.length
        ? 'Static RSA accepted'
        : tls.cipherSuite || 'Not observed',
    status: !tls ? 'unknown' : staticRsa.length ? 'fail' : /GCM|CHACHA20|CCM/i.test(tls.cipherSuite) ? 'pass' : 'partial',
    detail: staticRsa.length
      ? `Negotiated ${tls?.cipherSuite}, but ${pluralize(staticRsa.length, 'static-RSA key-transport suite')} ${staticRsa.length === 1 ? 'is' : 'are'} also accepted.`
      : 'Cipher suite selected during the observed handshake.',
  });

  /* Chain trust.
     The edge certificate engine performs a real trust-store validation and
     returns the OpenSSL reason on failure, which is strictly better evidence
     than inferring "fail" from the expiry flag alone. Local flags remain the
     fallback so this row still renders on records predating that engine. */
  const chainExpired = certChain.some((entry) => entry.isExpired);
  const chainTrusted = edge?.certificate?.chainTrusted ?? null;
  const localTrustFail = Boolean(certificate?.isSelfSigned || chainExpired || certificate?.isExpired);
  items.push({
    key: 'chain-trust',
    label: 'Chain Trust',
    value: !certificate && chainTrusted === null
      ? 'Not observed'
      : chainTrusted === true
        ? 'Pass'
        : chainTrusted === false
          ? 'Fail'
          : certificate?.isSelfSigned
            ? 'Self-signed'
            : localTrustFail
              ? 'Fail'
              : 'Pass',
    status: !certificate && chainTrusted === null
      ? 'unknown'
      : chainTrusted === false || localTrustFail
        ? 'fail'
        : 'pass',
    detail: edge?.certificate?.trustError
      ? `Chain validation failed against the public trust store: ${edge.certificate.trustError}`
      : chainTrusted === true
        ? 'Chain validated against the public trust store.'
        : certificate?.isExpired
          ? 'The leaf certificate has expired, so the chain does not validate.'
          : certificate?.isSelfSigned
            ? 'The leaf is self-signed and not anchored to a public trust store.'
            : 'Chain validated against the trust store.',
    evidence: edge?.certificate?.probed
      ? [
          { label: 'Trust-store verdict', value: chainTrusted === null ? 'not evaluated' : chainTrusted ? 'trusted' : 'NOT trusted' },
          { label: 'Reason', value: edge.certificate.trustError ?? 'no validation error reported' },
          { label: 'Chain depth', value: `${edge.certificate.chainDepth} certificate(s) served` },
        ]
      : undefined,
  });

  /* Key exchange.
     The named-group probe is the only way to learn the TLS 1.3 group — Node
     never exposes it, which is why this row used to read "ECDHE (TLS 1.3
     key_share)" with no group at all on every modern endpoint. */
  const kexLabel = edge?.transport?.keyExchange && edge.transport.keyExchange !== 'unknown'
    ? edge.transport.keyExchange
    : tls?.keyExchange
      ? tls.negotiatedCurve
        ? `${tls.keyExchange} (${tls.negotiatedCurve})`
        : tls.keyExchange
      : null;
  items.push({
    key: 'key-exchange',
    label: 'Key Exchange',
    value: kexLabel ?? 'Not observed',
    status: !kexLabel
      ? 'unknown'
      : /ml-kem|kyber/i.test(kexLabel)
        ? 'pass'
        : /ecdhe|dhe|x25519/i.test(kexLabel)
          ? 'partial'
          : 'fail',
    detail: edge?.transport?.keyExchange
      ? 'Key agreement for the session, with the named group confirmed by offering each group in isolation.'
      : 'Key-agreement mechanism negotiated for the session.',
  });

  /* Post-quantum key agreement — a MEASUREMENT, not an inference.
     The old row tested whether the strings "ml-kem" or "kyber" appeared in the
     negotiated suite name, the curve name, or ANY finding title. The first two
     can never contain them (TLS 1.3 suite names carry no key-exchange token and
     Node returns no group), and the third matched the scanner's own
     recommendations — so the row printed a hedging "Observed" that was
     simultaneously unable to confirm a real hybrid endpoint like Cloudflare and
     able to claim one for an endpoint with no post-quantum support at all.
     It now reports the named-group probe's verdict, with its evidence. */
  if (edge?.pqKeyAgreement) {
    const pq = edge.pqKeyAgreement;
    items.push({
      key: 'pq-key-agreement',
      label: 'Post-Quantum Key Agreement',
      value: pq.value,
      status: pq.state,
      detail: pq.detail,
      evidence: pq.evidence,
    });
  } else {
    items.push(
      unmeasured(
        'pq-key-agreement',
        'Post-Quantum Key Agreement',
        'Hybrid ML-KEM support is established by offering each named group in isolation under a TLS 1.3 floor.',
      ),
    );
  }

  /* ── HTTP ──────────────────────────────────────────────────────────────────
     Both header rows previously read the api-security scanner's output, which
     collects headers with Node's `fetch()` — and `fetch()` refuses to connect
     over an expired, self-signed or untrusted chain. On exactly the targets
     whose headers matter most (expired.badssl.com being the canonical case)
     that returned an empty set, and the rows rendered "Not observed" for
     headers the origin had plainly sent. The edge engine reads the same
     response over a permissive agent, so it is the primary source here and the
     api scanner is the fallback. */
  const headers = api?.securityHeaders ?? [];
  const edgeHsts = edge?.http?.hsts ?? null;
  const hstsHeader = headers.find((header) => header.name.toLowerCase() === 'strict-transport-security');

  if (edgeHsts && edge?.http?.reachable) {
    const enforced = edgeHsts.status === 'Healthy';
    items.push({
      key: 'hsts',
      label: 'HSTS',
      value: !edgeHsts.present ? 'Missing' : enforced ? 'Enforced' : 'Weak',
      status: !edgeHsts.present ? 'fail' : enforced ? 'pass' : 'partial',
      detail: !edgeHsts.present
        ? 'The origin returned no Strict-Transport-Security header, so a first visit over plain HTTP is strippable.'
        : `Strict-Transport-Security: ${edgeHsts.raw}`,
      evidence: [
        { label: 'Header', value: edgeHsts.raw ?? 'absent' },
        {
          label: 'max-age',
          value: edgeHsts.maxAge === null
            ? 'not set'
            : `${edgeHsts.maxAge}s (${Math.round(edgeHsts.maxAge / 86400)} days)${edgeHsts.maxAge < 31_536_000 ? ' — below the one-year recommendation' : ''}`,
        },
        { label: 'includeSubDomains', value: edgeHsts.includeSubDomains ? 'set' : 'not set' },
        { label: 'preload', value: edgeHsts.preload ? 'set' : 'not set' },
        {
          label: 'Preload eligible',
          value: edgeHsts.preloadEligible
            ? 'yes — meets the hstspreload.org submission requirements'
            : edgeHsts.preloadBlockers.length
              ? `no — ${edgeHsts.preloadBlockers.join('; ')}`
              : 'no',
        },
      ],
    });
  } else if (headers.length) {
    items.push({
      key: 'hsts',
      label: 'HSTS',
      value: !hstsHeader?.present ? 'Missing' : hstsHeader.secure ? 'Enforced' : 'Weak',
      status: !hstsHeader?.present ? 'fail' : hstsHeader.secure ? 'pass' : 'partial',
      detail: hstsHeader?.value ?? 'No Strict-Transport-Security header was returned by the origin.',
    });
  } else {
    items.push(
      unmeasured(
        'hsts',
        'HSTS',
        edge && !edge.http.reachable
          ? `The origin did not answer over HTTPS (${edge.http.error ?? 'no response'}), so no header could be read. This is not the same as an absent header.`
          : 'HSTS is read from the origin\'s HTTPS response headers.',
      ),
    );
  }

  const edgeTransportHeaders = (edge?.http?.headers ?? []).filter(
    (header) => header.name !== 'strict-transport-security' && header.status !== 'Not Applicable',
  );
  const nonHstsHeaders = headers.filter((header) => header.name.toLowerCase() !== 'strict-transport-security');

  const headerReading = headerTally(edge?.http, headers);
  if (headerReading.source === 'edge') {
    const hardened = headerReading.hardened ?? 0;
    const applicable = headerReading.applicable ?? 0;
    const weak = edgeTransportHeaders.filter((header) => header.status !== 'Healthy');
    items.push({
      key: 'headers',
      label: 'HTTP Security Headers',
      value: headerReading.label,
      status: hardened === applicable ? 'pass' : hardened === 0 ? 'fail' : 'partial',
      detail: weak.length
        ? weak
            .map((header) => `${header.name}: ${header.present ? header.weakness || 'present, weak' : 'absent'}`)
            .join(' · ')
        : 'Every applicable transport-security header is hardened.',
      evidence: edgeTransportHeaders.map((header) => ({
        label: header.name,
        value: header.supersededBy
          ? `not required — superseded by ${header.supersededBy}`
          : header.present
            ? `${header.status}${header.weakness ? ` — ${header.weakness}` : ''}${header.value ? ` · ${header.value}` : ''}`
            : 'absent',
      })),
    });
  } else if (headerReading.source === 'api-probe') {
    const hardened = headerReading.hardened ?? 0;
    items.push({
      key: 'headers',
      label: 'HTTP Security Headers',
      value: headerReading.label,
      status: hardened === nonHstsHeaders.length ? 'pass' : hardened === 0 ? 'fail' : 'partial',
      detail: nonHstsHeaders
        .filter((header) => !header.secure)
        .map((header) => `${header.name}: ${header.present ? 'present, weak' : 'absent'}`)
        .join(' · ') || 'Every probed transport-security header is hardened.',
    });
  } else {
    items.push(
      unmeasured(
        'headers',
        'HTTP Security Headers',
        edge && !edge.http.reachable
          ? `The origin did not answer over HTTPS (${edge.http.error ?? 'no response'}), so no response headers were collected.`
          : 'Transport-security headers are read from the origin\'s HTTPS response.',
      ),
    );
  }

  /* ── Public-edge controls ──────────────────────────────────────────────────
     Every row below used to be a flat "Not probed". They are now measured by
     the same engines /public-scan uses, and each states its own evidence. */

  /* OCSP stapling. `not-advertised` and `unreachable` are different failures
     and are never flattened: one is a certificate that never promised
     revocation checking, the other is one that promised it and cannot deliver. */
  if (edge?.certificate?.probed) {
    const cert = edge.certificate;
    items.push({
      key: 'ocsp-stapling',
      label: 'OCSP Stapling',
      value: cert.ocspStapled ? 'Enabled' : cert.mustStaple ? 'Must-staple violated' : 'Not stapled',
      status: cert.ocspStapled ? 'pass' : cert.mustStaple ? 'fail' : 'partial',
      detail: cert.ocspStapled
        ? 'A stapled OCSP response was delivered in the handshake, so clients learn revocation status without contacting the CA.'
        : cert.mustStaple
          ? 'The certificate carries the must-staple extension but no response was stapled — conforming clients are required to hard-fail this connection.'
          : `No OCSP response was stapled. Revocation checking falls back to a client-side fetch, which leaks browsing metadata and is soft-failed by most clients (responder: ${cert.ocspResponderState}).`,
      evidence: [
        { label: 'Stapled in handshake', value: cert.ocspStapled ? 'yes' : 'no' },
        { label: 'Responder state', value: `${cert.ocspResponderState}${cert.ocspResponderDetail ? ` — ${cert.ocspResponderDetail}` : ''}` },
        { label: 'Responder URI', value: cert.ocspUri ?? 'none advertised in the certificate' },
        { label: 'Must-staple', value: cert.mustStaple ? 'required by the certificate' : 'not required' },
        { label: 'CRL distribution points', value: cert.crlDistributionPoints.join(', ') || 'none published' },
      ],
    });
  } else {
    items.push(
      unmeasured('ocsp-stapling', 'OCSP Stapling', 'Revocation stapling is read from the TLS handshake extension.'),
    );
  }

  /* Certificate Transparency. */
  if (edge?.certificate?.probed) {
    const cert = edge.certificate;
    items.push({
      key: 'certificate-transparency',
      label: 'Certificate Transparency',
      value: cert.sctPresent ? `${pluralize(cert.sctCount, 'SCT')}` : 'No SCTs',
      status: cert.sctPresent ? (cert.sctCount >= 2 ? 'pass' : 'partial') : 'fail',
      detail: cert.sctPresent
        ? `${cert.sctCount} Signed Certificate Timestamp(s) present, so issuance for this name is publicly auditable.${cert.sctCount < 2 ? ' Chrome requires at least two SCTs from independent logs for publicly-trusted certificates.' : ''}`
        : 'No Signed Certificate Timestamps were found in the certificate, the handshake or a stapled OCSP response — misissuance for this name would not be publicly auditable.',
      evidence: [
        { label: 'SCTs present', value: cert.sctPresent ? 'yes' : 'no' },
        { label: 'SCT count', value: String(cert.sctCount) },
        {
          label: 'Sources checked',
          value: 'certificate extension (1.3.6.1.4.1.11129.2.4.2), TLS handshake extension, stapled OCSP response',
        },
      ],
    });
  } else {
    items.push(
      unmeasured(
        'certificate-transparency',
        'Certificate Transparency',
        'SCTs are read from the certificate extension, the TLS handshake or a stapled OCSP response.',
      ),
    );
  }

  /* DNS CAA. `caaQueryable` is what separates "no policy published" from "no
     resolver answered" — the distinction UDP/53 blocking used to destroy, which
     is why the DNS engine falls back to DNS-over-HTTPS before reporting either. */
  if (edge?.dns?.caaQueryable) {
    const dns = edge.dns;
    items.push({
      key: 'dns-caa',
      label: 'DNS Security (CAA)',
      value: dns.caaPresent ? `Present (${dns.caaRecords.length})` : 'Missing',
      status: dns.caaPresent ? 'pass' : 'partial',
      detail: dns.caaPresent
        ? `A CAA issuance policy restricts which CAs may issue for ${dns.caaAtName}.`
        : `No CAA record is published for ${dns.caaAtName || edge.host}, so any public CA may issue a certificate for this name. This is a measured absence — the resolver returned an authoritative answer.`,
      evidence: [
        { label: 'Records', value: dns.caaRecords.join(' | ') || 'none published' },
        { label: 'Checked at', value: dns.caaAtName ?? edge.host },
        { label: 'Resolver', value: dns.caaSource ?? 'unknown' },
      ],
    });
  } else {
    items.push(
      unmeasured(
        'dns-caa',
        'DNS Security (CAA)',
        'CAA issuance policy is read over DNS; no resolver returned an authoritative answer for this name over UDP/53 or DNS-over-HTTPS.',
      ),
    );
  }

  /* DNSSEC. Zone signing and resolver validation are separate facts: DNSKEY
     presence proves the zone is signed, the AD bit proves a validating resolver
     actually verified the chain. */
  if (edge?.dns?.dnssecQueryable) {
    const dns = edge.dns;
    items.push({
      key: 'dnssec',
      label: 'DNSSEC',
      value: dns.dnssecSigned ? (dns.dnssecValidated ? 'Signed & validated' : 'Signed') : 'Unsigned',
      status: dns.dnssecSigned ? (dns.dnssecValidated ? 'pass' : 'partial') : 'partial',
      detail: dns.dnssecSigned
        ? dns.dnssecValidated
          ? 'The zone publishes DNSKEY records and a validating resolver verified the chain of trust (AD bit set).'
          : 'The zone publishes DNSKEY records, but the resolver did not return the AD bit, so the chain of trust to the parent was not confirmed.'
        : 'No DNSKEY record was returned for the zone, so DNS answers for this name are not origin-authenticated and can be spoofed on the resolution path.',
      evidence: [
        { label: 'Zone signed (DNSKEY)', value: dns.dnssecSigned ? 'yes' : 'no' },
        { label: 'Resolver-validated (AD bit)', value: dns.dnssecValidated ? 'yes' : 'no' },
        { label: 'Transport', value: dns.transports.join(', ') || dns.resolvedVia },
      ],
    });
  } else {
    items.push(
      unmeasured('dnssec', 'DNSSEC', 'Zone signing is established by querying DNSKEY over DNS-over-HTTPS.'),
    );
  }

  /* ALPN. A completed handshake that negotiates no protocol is a MEASURED
     absence (the server declined our offer) and must not read the same as a
     handshake that never happened. */
  if (edge?.transport?.alpnProbed) {
    const transport = edge.transport;
    items.push({
      key: 'alpn',
      label: 'ALPN',
      value: transport.alpn ? (transport.alpn === 'h2' ? 'h2 (HTTP/2)' : transport.alpn) : 'Not negotiated',
      status: transport.alpn ? 'pass' : 'partial',
      detail: transport.alpn
        ? `The endpoint selected ${transport.alpn} from the offered protocol list during the TLS handshake.`
        : 'The endpoint completed the handshake without selecting an application protocol from the offered list, so the connection falls back to HTTP/1.1 by convention.',
      evidence: [
        { label: 'Negotiated', value: transport.alpn ?? 'none selected' },
        { label: 'Offered', value: transport.alpnOffered.join(', ') },
        { label: 'HTTP/2', value: transport.http2 ? 'supported' : 'not negotiated' },
        { label: 'HTTP version observed on the origin', value: edge.http.httpVersion ?? 'not observed' },
      ],
    });
  } else {
    items.push(
      unmeasured('alpn', 'ALPN', 'The negotiated application protocol is read from the TLS handshake ALPN extension.'),
    );
  }

  /* ── Estate-only controls the public surface cannot see ────────────────── */
  const keyAlgorithm = certificate?.publicKeyAlgorithm || null;
  const keySize = certificate?.publicKeySize ?? null;
  const keyLabel = keyAlgorithm
    ? keySize && !keyAlgorithm.includes(String(keySize))
      ? `${keyAlgorithm} ${keySize}-bit`
      : keyAlgorithm
    : null;
  items.push({
    key: 'cert-key',
    label: 'Certificate Key',
    value: keyLabel ?? 'Not observed',
    status: keyAlgorithm ? (/rsa/i.test(keyAlgorithm) && (keySize ?? 0) < 2048 ? 'fail' : 'partial') : 'unknown',
    detail: 'Public-key algorithm of the leaf certificate - quantum-vulnerable until replaced by ML-DSA.',
  });

  const certDaysRemaining = certificate?.validTo
    ? Math.round((Date.parse(certificate.validTo) - Date.now()) / 86400000)
    : null;
  items.push({
    key: 'cert-validity',
    label: 'Certificate Validity',
    value: !certificate
      ? 'Not observed'
      : certificate.isExpired
        ? 'Expired'
        : certDaysRemaining !== null
          ? `${certDaysRemaining} day${certDaysRemaining === 1 ? '' : 's'} left`
          : 'Unknown',
    status: !certificate ? 'unknown' : certificate.isExpired ? 'fail' : (certDaysRemaining ?? 999) < 30 ? 'partial' : 'pass',
    detail: certificate ? `Valid ${certificate.validFrom} to ${certificate.validTo}` : 'No certificate chain was collected.',
  });

  /* Forward secrecy.
     TLS 1.3 removes every static key-transport suite from the protocol, so a
     completed 1.3 handshake IS proof of forward secrecy regardless of what Node
     reports for the ephemeral key (it returns `{}` for 1.3). The edge engine
     encodes that reasoning and returns the basis it used, so the row can state
     WHY rather than asserting a flag. */
  /* Reconciled, not re-derived — the third of the three sites that each had
     its own fallback chain. `edge.transport.forwardSecrecy` is a plain boolean
     that reads `false` when the probe never ran, which is how a timed-out
     probe published "Not offered" on a TLS 1.3 endpoint. */
  const surfaceTransport = reconcileTransport(tls, edge, undefined);
  const edgeStaticRsa = surfaceTransport.staticRsaAccepted.value === true;
  const pfsDisplay = displayForwardSecrecy(surfaceTransport);
  items.push({
    key: 'pfs',
    label: 'Forward Secrecy',
    value: pfsDisplay,
    status: !surfaceTransport.forwardSecrecy.measured
      ? 'unknown'
      : !surfaceTransport.forwardSecrecy.value
        ? 'fail'
        : edgeStaticRsa
          ? 'partial'
          : 'pass',
    detail: edgeStaticRsa
      ? `${surfaceTransport.forwardSecrecy.basis} However, static-RSA key-transport suite(s) are also accepted; sessions negotiated on those have no forward secrecy at all.`
      : surfaceTransport.forwardSecrecy.basis,
    evidence: edge?.transport
      ? [
          { label: 'Basis', value: surfaceTransport.forwardSecrecy.basis },
          { label: 'Static RSA key transport accepted', value: edgeStaticRsa ? 'yes' : 'no' },
          { label: 'Session tickets', value: edge.transport.sessionTickets === null ? 'not observed' : edge.transport.sessionTickets ? 'issued' : 'not issued' },
          { label: 'Session resumption honoured', value: edge.transport.sessionReuse === null ? 'not tested' : edge.transport.sessionReuse ? 'yes' : 'no' },
        ]
      : undefined,
  });

  const sshFindings = findings.filter((finding) => /ssh/i.test(finding.category));
  items.push({
    key: 'ssh',
    label: 'SSH Host Keys',
    value: sshFindings.length ? pluralize(sshFindings.length, 'observation') : 'Not applicable',
    status: sshFindings.length
      ? sshFindings.some((finding) => finding.threatLevel === 'CRITICAL' || finding.threatLevel === 'HIGH')
        ? 'fail'
        : 'partial'
      : 'unknown',
    detail: sshFindings.length
      ? 'Host key and key-exchange metadata collected from the SSH banner.'
      : 'No SSH endpoint was submitted with this scan.',
  });

  const repoFindings = findings.filter((finding) => /repository|library|app-crypto|webcrypto/i.test(finding.category));
  const repoScanned = Boolean(primary?.metadata?.repoScanResult || primary?.metadata?.webCryptoResult);
  items.push({
    key: 'code',
    label: 'Source & Dependencies',
    value: repoScanned ? pluralize(repoFindings.length, 'pattern') : 'Not scanned',
    status: !repoScanned ? 'unknown' : repoFindings.some((finding) => finding.threatLevel !== 'SAFE') ? 'partial' : 'pass',
    detail: repoScanned
      ? 'Cryptographic patterns matched inside the submitted repository and page scripts.'
      : 'No repository URL was submitted with this scan.',
  });

  /* ── Aggregate verdicts ────────────────────────────────────────────────── */
  const quantumRisk = scanner2?.attackAssessment?.classification ?? null;
  items.push({
    key: 'quantum-risk',
    label: 'Quantum Risk',
    value: quantumRisk
      ? quantumRisk.charAt(0) + quantumRisk.slice(1).toLowerCase()
      : scanner2?.quantumRiskScore?.level ?? 'Not observed',
    status: !quantumRisk
      ? 'unknown'
      : quantumRisk === 'CRITICAL' || quantumRisk === 'HIGH'
        ? 'fail'
        : quantumRisk === 'MEDIUM'
          ? 'partial'
          : 'pass',
    detail: scanner2?.attackAssessment
      ? `Scanner_2 quantum risk assessment across ${pluralize(scanner2.attackAssessment.attackCorrelations.length, 'correlated exposure chain')}.`
      : 'The Scanner_2 enterprise pass has not scored this estate yet.',
  });

  /* Edge attribution.
     A host behind no CDN is a REAL answer ("Origin-served") and must not render
     the same as a host whose headers were never read — which is exactly what
     the old flat "Not probed" did to both. */
  if (edge) {
    const infrastructure = describeEdgeInfrastructure(edge);
    items.push({
      key: 'edge-infrastructure',
      label: 'Edge Infrastructure',
      value: infrastructure.value,
      status: infrastructure.state,
      detail: infrastructure.detail,
      evidence: infrastructure.evidence.length ? infrastructure.evidence : undefined,
    });
  } else {
    items.push(
      unmeasured(
        'edge-infrastructure',
        'Edge Infrastructure',
        'CDN, WAF, cloud and reverse-proxy attribution is read from response-header signatures.',
      ),
    );
  }

  return items;
}

/**
 * @param encryptionScore     0-100, or null when no posture score exists.
 * @param postQuantumReadiness 0-100, or **null when the published model
 *        WITHHELD it** (the hybrid named-group probe never settled).
 *
 * Both parameters were typed `number` while the caller passes `number | null`.
 * `strictNullChecks` is off in this project, so the null travelled silently and
 * the panel rendered `"NaN/100"` and `"NaN% ready"`, captioned "Most of the
 * controls it scores are not yet deployed" — a confident failure verdict
 * manufactured from a measurement the model had deliberately declined to make.
 * A withheld number is rendered as withheld, with the reason.
 */
function buildTimeline(
  hndl: ScannerAssessment['hndl'],
  encryptionScore: number | null,
  postQuantumReadiness: number | null,
  postQuantumReadinessReason: string | null,
): TimelinePhase[] {
  const scored = (value: number | null | undefined): value is number =>
    typeof value === 'number' && Number.isFinite(value);
  const window = hndl.window;
  const harvesting = hndl.immediate + hndl.soon + hndl.planned;

  return [
    {
      key: 'today',
      title: 'Today — measured posture',
      horizon: scored(encryptionScore) ? `${encryptionScore}/100` : 'Not scored',
      description: scored(encryptionScore)
        ? `Current cryptographic posture across the scanned estate, from the scanner's own weighted risk model.`
        : 'No posture score has been recorded for this view yet. Run an authorized scan to measure it.',
      state: 'now',
    },
    {
      key: 'harvest',
      title: 'Harvest Now, Decrypt Later',
      horizon: harvesting > 0 ? `${harvesting} exposed` : 'None recorded',
      description:
        harvesting > 0
          ? `${hndl.immediate} immediate, ${hndl.soon} near-term and ${hndl.planned} planned HNDL exposures identified by the Scanner_2 analyzer.`
          : 'No harvest-now exposure was identified in the recorded findings.',
      state: harvesting > 0 ? 'active' : 'past',
    },
    {
      key: 'break',
      title: 'Modelled cryptographically-relevant quantum window',
      horizon: window ? `${window.earliest}–${window.latest}` : 'Not modelled',
      description: window
        ? 'Break window estimated by the Scanner_2 quantum risk assessment from the algorithms actually observed.'
        : 'A break window is only modelled once quantum-vulnerable algorithms have been observed.',
      state: window ? 'active' : 'past',
    },
    {
      key: 'migration',
      title: 'Post-quantum migration',
      horizon: scored(postQuantumReadiness) ? `${postQuantumReadiness}% ready` : 'Not measured',
      /* SAY WHAT THE NUMBER MEASURES.
         `postQuantumReadiness` is the published Post-Quantum Readiness CATEGORY
         — a posture score built from hybrid key agreement, PQ signatures, a
         TLS 1.3 floor, certificate lifetime and CT. It is NOT a share of
         components. The old copy read "A majority of discovered components are
         already quantum-safe" at 78%, on a scan whose own Estate Footprint
         panel two cards below reported 27 of 31 components quantum-vulnerable.
         Both numbers were right; the sentence attached to one described the
         other. */
      description: !scored(postQuantumReadiness)
        /* The model's own words for its silence — never a fabricated verdict. */
        ? postQuantumReadinessReason
          ?? 'Post-quantum readiness was not scored for this view, so no migration position can be stated yet.'
        : postQuantumReadiness >= 60
          ? `Measured post-quantum readiness for the scanned endpoint is ${postQuantumReadiness}/100 — the published readiness category, not a share of components. The controls it scores are largely in place; close the remainder through the Migration Planner.`
          : `Measured post-quantum readiness for the scanned endpoint is ${postQuantumReadiness}/100 — the published readiness category, not a share of components. Most of the controls it scores are not yet deployed; plan the migration in the Migration Planner.`,
      state: 'target',
    },
  ];
}

/**
 * Executive recommendations, joined to the evidence that produced them.
 *
 * ── The two defects this rewrite removes ────────────────────────────────────
 *
 * 1. THE JOIN NEVER MATCHED. `affected` was
 *      `finding.algorithm.toLowerCase().includes(recommendation.classicalAlgorithm)`
 *    — a raw substring test — while the recommendation itself was produced from
 *    `normalizeToScanner2Algorithm(finding.algorithm)`. No finding's algorithm
 *    string literally contains "rsa-2048"; the observations are
 *    `TLS_RSA_WITH_AES_128_GCM_SHA256` and `sha256WithRSAEncryption`. So five of
 *    six cards reported `affected: 0` and printed
 *      "RSA-2048 was matched by the migration engine but no finding in the
 *       current view uses it"
 *    which contradicts the card's own existence: the engine derived it FROM
 *    those findings. One rule now decides both, so the count cannot be zero for
 *    a recommendation the evidence generated.
 *
 * 2. NO-OP CARDS. The catalogue contains entries whose `migrationType` is
 *    "No Migration Needed" and whose step list is "No action required". One
 *    rendered as "Replace AES-256 with AES-256 (quantum-resilient)" in a panel
 *    headed Executive Recommendations. Those are confirmations, not
 *    recommendations, and they no longer occupy a card.
 */
/**
 * Which job a post-quantum primitive does.
 *
 * A KEM establishes a key and a signature scheme authenticates; neither can do
 * the other's work, and the platform's own PQC standard says so in as many
 * words. The migration catalogue is keyed on the CLASSICAL algorithm, and
 * "RSA-2048" names two entirely different migrations depending on whether it is
 * transporting a key or signing a certificate. When the edge engine's measured
 * target (ML-DSA-65, replacing the leaf SIGNATURE) was allowed to override the
 * catalogue's recommendation (ML-KEM-768, replacing RSA KEY TRANSPORT), the
 * card kept the catalogue's rationale and alternatives — and published
 * "Replace RSA-2048 with ML-DSA-65 · alternatives: FrodoKEM, BIKE, HQC", three
 * KEMs offered as substitutes for a signature scheme, above the step "Disable
 * RSA key exchange on servers".
 *
 * Named explicitly rather than inferred, because the shared decomposer
 * classifies the round-3 competition names (Falcon, BIKE, HQC, NTRU, Classic
 * McEliece, XMSS) as unclassifiable policy strings, and a silent `null` would
 * let exactly the mismatch above through.
 */
type PqcRole = 'key-establishment' | 'signature';

const PQC_PRIMITIVE_ROLE: Array<[RegExp, PqcRole]> = [
  /* Word-anchored where the token is a short common substring. Unanchored,
     "lms" matches inside ordinary words and "bike"/"hqc" inside product names —
     the same missing-word-boundary trap that has produced false classifications
     in this codebase before. */
  [/ml-?kem|kyber|frodokem|mceliece|\bntru\b|\bbike\b|\bhqc\b|\bsike\b/i, 'key-establishment'],
  [/ml-?dsa|dilithium|slh-?dsa|sphincs|falcon|\bxmss\b|\blms\b|picnic|rainbow/i, 'signature'],
];

export function pqcRole(name: string | null | undefined): PqcRole | null {
  const value = String(name ?? '');
  if (!value.trim()) return null;
  for (const [pattern, role] of PQC_PRIMITIVE_ROLE) if (pattern.test(value)) return role;
  const kind = analyzeCryptoObservation({ algorithm: value }).kind;
  if (kind === 'signature') return 'signature';
  if (kind === 'key-exchange') return 'key-establishment';
  return null;
}

function buildRecommendations(
  recommendations: PqcRecommendation[],
  findings: DefensiveFinding[],
  /** Primitives the scan MEASURED as already deployed on the endpoint. */
  alreadyDeployed: string[] = [],
  /**
   * The edge engine's migration targets, when it measured this endpoint.
   *
   * These name the parameter set chosen for the primitive that was ACTUALLY
   * observed, and they are what the Cryptographic Intelligence and Quantum
   * Posture panels already publish. Without this, the same ECDSA P-256 leaf was
   * told to migrate to ML-DSA-65 on two panels and ML-DSA-44 on this one.
   */
  edgeTargets: Array<{ name: string; standard: string; replaces: string }> = [],
): RecommendationCard[] {
  const actionable = recommendations.filter(
    (recommendation) =>
      !/no migration needed/i.test(recommendation.migrationType ?? '') &&
      recommendation.classicalAlgorithm !== recommendation.recommendedPQC,
  );
  if (actionable.length === 0) {
    // No fabricated advice: when the migration engine has produced nothing, the
    // panel says so rather than printing generic filler.
    return [];
  }

  const priorityFor: Record<PqcRecommendation['migrationComplexity'], RecommendationCard['priority']> = {
    CRITICAL: 'Critical',
    HIGH: 'High',
    MEDIUM: 'Medium',
    LOW: 'Low',
  };

  const deployed = alreadyDeployed
    .filter(Boolean)
    .map((value) => value.toLowerCase().replace(/[^a-z0-9]/g, ''));

  /* Edge target keyed by the classical primitive it replaces, through the same
     normalizer the rest of this join uses. */
  const measuredTargetFor = new Map<string, { name: string; standard: string }>();
  for (const target of edgeTargets) {
    const classical = normalizeToScanner2Algorithm(target.replaces);
    if (classical) measuredTargetFor.set(classical, { name: target.name, standard: target.standard });
  }

  return actionable
    .map((recommendation) => {
      /* The SAME normalizer that produced this recommendation decides which
         observations it covers. */
      const affected = findings.filter(
        (finding) => normalizeToScanner2Algorithm(finding.algorithm) === recommendation.classicalAlgorithm,
      );
      const worst = affected.reduce<ThreatLevel>(
        (level, finding) => (THREAT_RANK[finding.threatLevel] > THREAT_RANK[level] ? finding.threatLevel : level),
        'SAFE',
      );
      /* When the scan measured the recommended primitive as live on this
         endpoint, the outstanding work is DISABLING the classical path, not
         deploying the primitive. Telling an operator to "deploy hybrid
         X25519 + ML-KEM-768" on an endpoint confirmed at 100% confidence to be
         running X25519MLKEM768 is advice the same page disproves. */
      /* The measured target wins over the catalogue's default parameter set —
         but ONLY when the two do the same job.

         The catalogue is keyed on the classical algorithm, and "RSA-2048" is
         two different migrations: RSA key transport is replaced by a KEM, an
         RSA certificate signature by a signature scheme. The edge engine's
         measured target names the SIGNATURE replacement (ML-DSA-65), and
         letting it override a key-exchange catalogue entry kept that entry's
         rationale, alternatives and steps — publishing "Replace RSA-2048 with
         ML-DSA-65 · alternatives: FrodoKEM, BIKE, HQC" above "Disable RSA key
         exchange on servers". A KEM cannot sign, and the platform's own PQC
         standard forbids saying otherwise. A cross-role target is left to the
         PQ Migration Targets panel, which states the role it replaces. */
      const measuredTarget = measuredTargetFor.get(recommendation.classicalAlgorithm);
      const catalogueRole = pqcRole(recommendation.recommendedPQC);
      const measured =
        measuredTarget && (catalogueRole === null || pqcRole(measuredTarget.name) === catalogueRole)
          ? measuredTarget
          : undefined;
      const recommendedPQC = measured?.name ?? recommendation.recommendedPQC;
      const standard = measured?.standard ?? recommendation.nistStandard;
      /* Alternatives must do the recommended primitive's job too. Filtered
         rather than trusted, so a catalogue edit can never reintroduce the
         cross-role list on a card. */
      const alternatives = recommendation.alternativePQC.filter((alternative) => {
        const role = pqcRole(alternative);
        return catalogueRole === null || role === null || role === catalogueRole;
      });
      const target = recommendedPQC.toLowerCase().replace(/[^a-z0-9]/g, '');
      const isDeployed = deployed.some((primitive) => target.includes(primitive) || primitive.includes(target));
      const observedNames = Array.from(new Set(affected.map((finding) => finding.algorithm))).slice(0, 3);
      /* A step that says "deploy X" under a title that says X is already
         deployed is the card arguing with itself. Those steps are dropped and
         the remaining ones — which are the disable/rotate work that IS
         outstanding — are kept in order. */
      const steps = isDeployed
        ? recommendation.migrationSteps.filter((step) => !/^\s*(deploy|enable|configure|generate|upgrade)\b/i.test(step))
        : recommendation.migrationSteps;
      return {
        id: recommendation.classicalAlgorithm,
        title: isDeployed
          ? `Retire ${recommendation.classicalAlgorithm} — ${recommendedPQC} is already deployed`
          : `Replace ${recommendation.classicalAlgorithm} with ${recommendedPQC}`,
        priority: priorityFor[recommendation.migrationComplexity],
        businessImpact:
          affected.length > 0
            ? `${pluralize(affected.length, 'observation')} in this assessment ${
                affected.length === 1 ? 'resolves' : 'resolve'
              } to ${recommendation.classicalAlgorithm}` +
              `${observedNames.length ? ` (${observedNames.join(', ')})` : ''}; the most severe is rated ${worst}.` +
              (isDeployed
                ? ` ${recommendedPQC} was measured as live on this endpoint, so the outstanding work is disabling the classical path, not deploying the replacement.`
                : '')
            : `${recommendation.classicalAlgorithm} is in the migration catalogue, but no observation in this assessment resolves to it.`,
        effort: recommendation.estimatedEffort,
        standard,
        affected: affected.length,
        steps: steps.length ? steps : recommendation.migrationSteps,
        rationale: `${recommendation.migrationType} · alternatives: ${alternatives.slice(0, 3).join(', ') || 'none published'}`,
      };
    })
    .sort((a, b) => {
      const order: Record<RecommendationCard['priority'], number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
      return order[a.priority] - order[b.priority] || b.affected - a.affected;
    });
}

/**
 * Discovery Coverage — measured against what COULD be measured.
 *
 * Coverage is stated per surface as `measured / applicable`, with modules the
 * scanner declared inapplicable excluded from the denominator and named with
 * their reason. This is the same arithmetic the Discovery Workflow rail uses,
 * so the two panels can never disagree about the same surface.
 */
function buildCoverage(
  modules: ModuleState[],
  failed: ModuleState[],
  skipped: ModuleState[],
  unreported: ModuleState[],
): CoverageItem[] {
  if (modules.length === 0) {
    return [
      {
        key: 'catalog',
        label: 'Scanner module catalog',
        status: 'unknown',
        detail: 'The module catalog is published when a scan stream opens.',
      },
    ];
  }

  return Object.entries(SCANNER_NODE_MODULES).map(([node, moduleIds]) => {
    const owned = modules.filter((module) => moduleIds.includes(module.id));
    const done = owned.filter((module) => module.status === 'Completed' || module.status === 'No findings');
    const broken = owned.filter((module) => module.status === 'Failed');
    const notApplicable = owned.filter((module) => module.status === 'Skipped');
    const pending = owned.filter((module) => module.status === 'Queued');
    const applicable = owned.length - notApplicable.length;
    const blueprint = SCANNER_NODE_BLUEPRINTS.find((entry) => entry.key === node);
    const status: CoverageItem['status'] = owned.length === 0
      ? 'unknown'
      : broken.length > 0
        ? 'fail'
        : applicable === 0
          ? 'unknown'
          : done.length === applicable
            ? 'pass'
            : 'partial';
    /* Modules in one surface usually share a reason ("no TLS endpoint was in
       scope"), so it is stated once rather than repeated per module. */
    const naReasons = Array.from(
      new Set(notApplicable.map((module) => module.reason || `${module.name} did not apply`)),
    );
    const notes = [
      broken.length ? `${broken.length} failed` : null,
      notApplicable.length ? `${notApplicable.length} not applicable (${naReasons.join('; ')})` : null,
      pending.length ? `${pending.length} never reported` : null,
    ].filter(Boolean);
    return {
      key: node,
      label: blueprint?.title ?? node,
      status,
      detail: owned.length === 0
        ? 'No module in this surface was published for this run.'
        : applicable === 0
          ? `No module in this surface applied to the submitted targets — ${naReasons.join('; ')}`
          : `${done.length}/${applicable} applicable modules reported${notes.length ? ` — ${notes.join(', ')}` : ''}.`,
    };
  }).concat(
    failed.length > 0
      ? [{
          key: 'errors',
          label: 'Module errors',
          status: 'fail' as const,
          detail: failed.map((module) => `${module.name}: ${module.error ?? module.reason ?? 'failed'}`).join(' · '),
        }]
      : [],
  ).concat(
    unreported.length > 0
      ? [{
          key: 'unreported',
          label: 'Unreported modules',
          status: 'partial' as const,
          detail: `${unreported.map((module) => module.name).join(', ')} produced no terminal state. Re-run the scan for full coverage.`,
        }]
      : [],
  );
}
