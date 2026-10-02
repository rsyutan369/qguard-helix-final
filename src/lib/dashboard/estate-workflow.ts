/**
 * QGuard Helix Estate Exposure Workflow™ — the tenant-level projection.
 *
 * The scanner's Exposure Workflow renders ONE {@link ExposureAssessment}: a
 * scan, the lifecycle phases it walked, the engine processes each phase
 * spawned, and the cryptography those processes read. That lineage does not
 * exist at tenant level — there is no single run, no phase tree and no engine
 * registry spanning an estate.
 *
 * The estate has its OWN lineage, and every link in it is a row:
 *
 *   scan session ──assessed──▶ asset ──hosts──▶ CBOM component ──implements──▶ algorithm
 *                               │  │                                              ▲
 *                               │  └──hosts──▶ certificate ──implements────────────┘
 *                               │
 *                               ├◀─observed-at── finding ──concerns──▶ algorithm
 *                               │                   └──remediated by──▶ remediation
 *                               └──connects──▶ asset          (asset_relationships)
 *
 * So the RENDERER is reused unchanged and only the PROJECTION is new.
 * Synthesising a fake assessment out of tenant rows would have invented phases
 * and engine processes that never ran.
 *
 * ACCURACY CONTRACT — every rule here is enforced by tools/estate-workflow-check.ts
 * ------------------------------------------------------------------------------
 * 1. ONE FINDING SET, ONE CBOM. Findings and components arrive ALREADY
 *    canonical — the merged finding set and the grouped CBOM entries of
 *    `buildScannerIntelligence`, the same objects the Open Findings KPI, the
 *    Cryptographic Inventory KPI, the CBOM page and the Findings tables count.
 *    This module never reads the raw registers, so it cannot publish a third
 *    number for them. (It used to: it projected `vulnerabilities` AND
 *    `crypto_exposures` — the derived bucket register beside the primary one —
 *    and one node per raw inventory row, publishing 31 findings and 101
 *    components beside KPIs that read 20 and 12.)
 * 2. RISK IS NOT RECOMPUTED. Per-asset risk arrives from the shared
 *    `deriveAssetPostureModel` — the same call /dashboard/assets, Quantum
 *    Readiness and the Migration Planner make. This module owns no scoring.
 * 3. ABSENCE IS NOT SAFETY (§43). An asset with no evidence carries severity
 *    `null`, rendered "None", never `info` and never a passing colour.
 * 4. SEVERITY BELONGS TO ITS OWN EVIDENCE. An algorithm's severity is the worst
 *    finding that concerns THAT algorithm; a remediation's is the worst finding
 *    it closes. Neither inherits the severity of the asset it sits on — that is
 *    how ML-KEM and "No action required" both used to read HIGH.
 * 5. TOPOLOGY IS OBSERVED, NEVER INFERRED. Asset-to-asset edges are real
 *    `asset_relationships` rows; session-to-asset edges are real
 *    `pqc_scan_results.scan_session_id` links.
 * 6. QUANTUM VERDICTS COME FROM THE CRYPTO KNOWLEDGE BASE, the platform's single
 *    source of cryptographic truth — never from a private regex.
 * 7. BOUNDED, AND HONEST ABOUT IT. Capped per kind by severity rank, with what
 *    was dropped reported in `truncation` for the caller to render.
 *
 * ISOMORPHIC: no DOM, no Node built-ins — the api-server builds it, the browser
 * renders it, and a report could embed it without a second implementation.
 */

import type {
  DetectionMethod,
  ExposureFinding,
  ExposureLayer,
  FindingSeverity,
  QuantumStatus,
} from '../scanner/exposure/types';
import { SEVERITY_ORDER } from '../scanner/exposure/types';
import { GENERIC_FINDING_TEXT } from '../scanner/finding-identity';
import { isCryptographicPrimitive } from '../crypto-agility/agility-intelligence';
import { findAlgorithm } from '../crypto/knowledge-base/algorithms';
import type {
  WorkflowEdge,
  WorkflowGraph,
  WorkflowGrouping,
  WorkflowLensDefinition,
  WorkflowNode,
  WorkflowNodeKind,
} from '../scanner/exposure/workflow-graph';
import { NODE_KIND_LABEL } from '../scanner/exposure/workflow-graph';

/* ─────────────────────────────────────────────────────────────── input rows ── */

export interface EstateRow {
  [key: string]: unknown;
}

/**
 * One CANONICAL finding — an entry of `buildScannerIntelligence().findings`,
 * the merged set every other surface counts. The caller resolves `assetId`.
 */
export interface EstateFindingInput {
  id: string;
  /** Estate asset the finding was observed on; '' when it cannot be linked. */
  assetId: string;
  /** What was found. The scanner records the subject here ("ECDHE (TLS 1.3 key_share)", "Missing CSP"). */
  title: string;
  category: string;
  /** Raw threat level: CRITICAL | HIGH | MEDIUM | LOW | SAFE. */
  threatLevel: string;
  status: string;
  description: string;
  recommendation: string;
  evidence: string;
  location: string;
  detectedAt: string | null;
  /** Storage rows merged into this one observation. */
  observations: number;
  sources: string[];
  ownership: string | null;
  keySize: number | null;
}

/** One CANONICAL CBOM component — an entry of `buildScannerIntelligence().cbom.entries`. */
export interface EstateComponentInput {
  id: string;
  assetId: string;
  name: string;
  type: string;
  algorithm: string;
  isVulnerable: boolean;
  isQuantumSafe: boolean;
  /** The exposure level the scanner recorded for it. */
  riskSeverity: string;
  /** Raw inventory rows grouped into this component. */
  instances: number;
  detectionMethod: string;
  lastSeen: string | null;
  replacement: string | null;
}

export interface EstateWorkflowInput {
  assets: EstateRow[];
  relationships: EstateRow[];
  /** Canonical findings (open AND the PQC-ready confirmations — SAFE is filtered here). */
  findings: EstateFindingInput[];
  /** Canonical CBOM components. */
  components: EstateComponentInput[];
  certificates: EstateRow[];
  /**
   * pqc_scan_results rows, read ONLY for `scan_session_id` × `asset_id` — the
   * recorded link between a scan session and the assets it assessed. They are
   * never projected as findings (they are storage copies of the findings above).
   */
  scanLinks: EstateRow[];
  /** pqc_scan_sessions — the parent processes. */
  sessions: EstateRow[];
  runtimeEvents: EstateRow[];
  /** Canonical per-asset risk, keyed by asset id, from the SHARED posture model (rule 2). */
  assetRisk: Map<string, number>;
  /** Canonical per-asset posture from the same shared model. */
  assetPosture: Map<string, 'pqc' | 'hybrid' | 'vulnerable'>;
  /**
   * Which store answered. 'memory' means the database was unreachable and the
   * scanner's in-process results were read instead — real scan output, but a
   * DEGRADED read the UI must disclose.
   */
  persistence?: 'database' | 'memory';
}

/* ────────────────────────────────────────────────────────────────── helpers ── */

function str(value: unknown): string {
  return value === null || value === undefined ? '' : String(value);
}

function lower(value: unknown): string {
  return str(value).trim().toLowerCase();
}

/**
 * Map any severity vocabulary the platform uses onto the one scale.
 *
 * `null` for an unrecognised or absent value — and for SAFE, which is a verdict
 * of "no exposure", not a severity. Defaulting an unknown to `info` would be
 * the fabrication rule 3 forbids.
 */
export function severityOf(value: unknown): FindingSeverity | null {
  const raw = lower(value);
  if (!raw) return null;
  if (raw === 'critical' || raw === 'severe') return 'critical';
  if (raw === 'high') return 'high';
  if (raw === 'medium' || raw === 'moderate') return 'medium';
  if (raw === 'low' || raw === 'minor') return 'low';
  if (raw === 'info' || raw === 'informational') return 'info';
  return null;
}

function worseSeverity(a: FindingSeverity | null, b: FindingSeverity | null): FindingSeverity | null {
  if (a === null) return b;
  if (b === null) return a;
  return SEVERITY_ORDER[a] <= SEVERITY_ORDER[b] ? a : b;
}

const SEVERITY_RANK_FOR_CAP: Record<FindingSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const SEVERITY_GROUP_LABEL: Record<FindingSeverity | 'none', string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
  none: 'No finding attached',
};

/** Nodes with no severity sort last, so a cap keeps the worst evidence. */
function capRank(node: WorkflowNode): number {
  return node.severity === null ? 9 : SEVERITY_RANK_FOR_CAP[node.severity];
}

/**
 * Canonicalise a recorded algorithm label so one primitive is one node.
 *
 * A trailing parenthetical is the WRITER's context, not part of the primitive:
 * the certificate table records "ECDSA P-256" while the CBOM records the same
 * key as "ECDSA P-256 (Certificate)". Keyed verbatim they drew as two nodes.
 */
function algorithmKey(raw: string): string {
  return raw.trim().replace(/\s*\([^)]*\)\s*$/, '').toUpperCase().replace(/\s+/g, ' ');
}

/** Normalise free text for grouping identical recorded actions. */
function textKey(raw: string): string {
  return raw.trim().toLowerCase().replace(/\s+/g, ' ').replace(/[.;:,]+$/, '');
}

function pushFact(facts: Array<{ label: string; value: string }>, label: string, value: string | number | null | undefined) {
  if (value === null || value === undefined || value === '') return;
  facts.push({ label, value: String(value) });
}

function day(value: unknown): string {
  return str(value).slice(0, 10);
}

/* ───────────────────────────────────────────────────────── quantum verdicts ── */

const HYBRID_RE = /\bhybrid\b|x25519[-_ ]?mlkem|secp256r1[-_ ]?mlkem|p-?256[-_ ]?ml-?kem|mlkem\d{3,4}x25519|\+\s*ml-?kem|\+\s*kyber/i;
const PQC_TOKEN_RE = /ml-?kem|ml-?dsa|slh-?dsa|kyber|dilithium|sphincs|falcon/i;

/**
 * Quantum verdict for a recorded algorithm label, from the Crypto Knowledge
 * Base (rule 6).
 *
 * Unrecognised → `unknown`, never `resistant`. A protocol version →
 * `not-applicable`: a protocol's quantum exposure is set by the group and
 * signature it negotiates, which are projected as their own nodes.
 */
export function quantumVerdictFor(label: string): QuantumStatus {
  const text = label.trim();
  if (!text) return 'unknown';
  if (HYBRID_RE.test(text) && PQC_TOKEN_RE.test(text)) return 'hybrid';
  /* "SHA256withRSA": the hash is only the digest half of a signature whose
     public-key half is the quantum-relevant one. */
  const signedWith = /with[-_ ]?(rsa|dsa|ecdsa|ed25519|ed448)\b/i.exec(text);
  const definition = findAlgorithm(signedWith ? signedWith[1] : text);
  if (!definition) return PQC_TOKEN_RE.test(text) ? 'pqc' : 'unknown';
  if (definition.quantumStatus === 'PQC_STANDARDIZED') return 'pqc';
  if (definition.shorBroken) return 'vulnerable';
  if (definition.primitiveType === 'protocol') return 'not-applicable';
  if (definition.quantumStatus === 'QUANTUM_RESISTANT' || definition.groverAffected) return 'resistant';
  return 'unknown';
}

const QUANTUM_VERDICT_LABEL: Record<QuantumStatus, string> = {
  vulnerable: 'Quantum-vulnerable (Shor)',
  resistant: 'Quantum-resistant',
  hybrid: 'Hybrid post-quantum',
  pqc: 'Post-quantum',
  unknown: 'Not recognised — no verdict published',
  'not-applicable': 'Protocol — set by the negotiated group and signature',
};

/* ─────────────────────────────────────────────────────── finding projection ── */

const NO_ACTION_RE = /^no (action|change|remediation) (is )?(required|needed)/i;

/** A recommendation worth drawing as a node: recorded, specific, and an action. */
function isActionableRecommendation(text: string): boolean {
  const key = textKey(text);
  if (!key) return false;
  if (GENERIC_FINDING_TEXT.has(key) || GENERIC_FINDING_TEXT.has(`${key}.`)) return false;
  return !NO_ACTION_RE.test(key);
}

/**
 * One recommended action, grouped from the canonical findings that recorded it.
 *
 * This is the ONE derivation of "what should I do next" on /dashboard: the
 * Exposure Workflow's Remediation lens and the AI Recommendations panel both
 * read it, so the two can never recommend different work for one estate, list
 * the same action four times, or promote "no action required" to an action.
 */
export interface RecommendedAction {
  key: string;
  text: string;
  /** Worst severity among the findings it closes. */
  severity: FindingSeverity;
  findingIds: string[];
  /** What each closed finding was about ("ECDHE (TLS 1.3 key_share)", "Missing CSP"). */
  subjects: string[];
  assetIds: string[];
  categories: string[];
}

export function groupRecommendedActions(findings: EstateFindingInput[]): {
  actions: RecommendedAction[];
  /** Open findings whose recorded recommendation was a placeholder or "no action required". */
  nonAction: number;
} {
  const groups = new Map<string, RecommendedAction>();
  let nonAction = 0;
  for (const finding of findings) {
    const severity = severityOf(finding.threatLevel);
    if (!severity) continue;
    const text = finding.recommendation.trim();
    if (!isActionableRecommendation(text)) {
      if (text) nonAction += 1;
      continue;
    }
    const key = textKey(text);
    const entry = groups.get(key) ?? { key, text, severity, findingIds: [], subjects: [], assetIds: [], categories: [] };
    entry.severity = worseSeverity(entry.severity, severity) ?? severity;
    entry.findingIds.push(finding.id);
    if (finding.title && !entry.subjects.includes(finding.title)) entry.subjects.push(finding.title);
    if (finding.assetId && !entry.assetIds.includes(finding.assetId)) entry.assetIds.push(finding.assetId);
    if (finding.category && !entry.categories.includes(finding.category)) entry.categories.push(finding.category);
    groups.set(key, entry);
  }
  const actions = [...groups.values()].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.findingIds.length - a.findingIds.length || a.text.localeCompare(b.text),
  );
  return { actions, nonAction };
}

/** Where on the estate a finding was observed — drives the finding sheet's layer label. */
function layerForFinding(finding: EstateFindingInput): ExposureLayer {
  const text = `${finding.category} ${finding.location}`.toLowerCase();
  if (/web crypto|source|inline|\.js\b|repository|code/.test(text)) return 'source';
  if (/header|csp|x-frame|hsts|api security|information disclosure|config/.test(`${text} ${finding.title.toLowerCase()}`)) {
    return 'configuration';
  }
  return 'edge';
}

/**
 * The canonical finding as the platform's finding sheet reads it, so the
 * inspector's "Attached findings" opens the SAME evidence sheet the scanner
 * uses — never a second, divergent rendering of one finding.
 */
function toExposureFinding(finding: EstateFindingInput, severity: FindingSeverity, assetName: string): ExposureFinding {
  const quantum = quantumVerdictFor(finding.title);
  const seen = finding.detectedAt ?? '';
  const recommendation = isActionableRecommendation(finding.recommendation) ? finding.recommendation : undefined;
  return {
    id: finding.id,
    scanId: 'estate',
    engineId: 'estate',
    mode: finding.sources.some((source) => /agent/i.test(source)) ? 'local' : 'web',
    layer: layerForFinding(finding),
    category: finding.category || 'Finding',
    title: finding.title || 'Finding',
    description: finding.description || finding.evidence || 'Recorded by the scanner.',
    severity,
    confidence: 'high',
    detection: 'observed',
    algorithm: isCryptographicPrimitive(finding.title) ? finding.title : undefined,
    canonicalAlgorithm: isCryptographicPrimitive(finding.title) ? findAlgorithm(finding.title)?.canonicalName ?? finding.title : undefined,
    keySize: finding.keySize,
    quantumStatus: quantum === 'unknown' && !isCryptographicPrimitive(finding.title) ? 'not-applicable' : quantum,
    recommendation,
    evidence: [
      {
        summary: finding.evidence || finding.description || 'Recorded by the scanner.',
        scope: assetName || undefined,
        reference: finding.location || undefined,
        attributes: {
          Status: finding.status || '—',
          'Merged observations': finding.observations,
          Sources: finding.sources.join(', ') || '—',
          ...(finding.ownership ? { Ownership: finding.ownership } : {}),
        },
        observedAt: seen,
      },
    ],
    firstSeen: seen,
    lastSeen: seen,
    assetRef: finding.assetId || undefined,
  };
}

/* ──────────────────────────────────────────────────────────────────── caps ── */

/**
 * A force layout stops being readable — and stops being interactive on a
 * laptop — well before a thousand bodies, so the projection is bounded by
 * severity rank and states what it dropped.
 */
const CAPS: Partial<Record<WorkflowNodeKind, number>> = {
  asset: 140,
  finding: 180,
  component: 120,
  certificate: 80,
  algorithm: 60,
  remediation: 40,
};

/* ───────────────────────────────────────────────────────────────── the lenses ─ */

/**
 * The estate lenses.
 *
 * Every lens is a projection of the SAME graph — nothing is recomputed per tab
 * — so a node's severity, size and relationships cannot disagree between them.
 * Each default grouping is one the estate graph actually populates.
 */
export const ESTATE_LENSES: WorkflowLensDefinition[] = [
  {
    id: 'flow',
    label: 'Estate Flow',
    description:
      'The whole estate as one chain: the scan sessions that ran, the assets they assessed, and the findings and cryptography those assets carry.',
    kinds: ['scan', 'asset', 'finding', 'algorithm'],
    groupBy: 'kind',
  },
  {
    id: 'process',
    label: 'Dependency Tree',
    description:
      'Parent and child only. Scan sessions linked to the assets their results were recorded against, and real asset-to-asset relationships from the inventory — nothing infers a topology from a name.',
    kinds: ['scan', 'asset'],
    groupBy: 'environment',
  },
  {
    id: 'algorithms',
    label: 'Cryptography',
    description:
      'Cryptography as the centre of gravity: every algorithm on record, the CBOM components that implement it and the findings that concern it. Each algorithm carries the severity of its OWN findings; switch colour to Type for the quantum verdict.',
    kinds: ['algorithm', 'component', 'finding'],
    groupBy: 'severity',
  },
  {
    id: 'cbom',
    label: 'CBOM Graph',
    description:
      'The Cryptographic Bill of Materials as a graph — the same components the CBOM page and the Cryptographic Inventory KPI count, the assets that host them and the algorithms they implement.',
    kinds: ['component', 'algorithm', 'asset'],
    groupBy: 'kind',
  },
  {
    id: 'supply',
    label: 'Certificates & PKI',
    description:
      'Certificate estate: every certificate held, the asset presenting it and the signature algorithm behind it. Severity here is measured validity — expired, inside 30 or 90 days.',
    kinds: ['certificate', 'asset', 'algorithm'],
    groupBy: 'kind',
  },
  {
    id: 'correlation',
    label: 'Exposure',
    description:
      'Where the risk actually sits. The open findings grouped by severity with the asset each was observed at and the algorithm it concerns, so the worst evidence and its owner are read together.',
    kinds: ['finding', 'asset', 'algorithm'],
    groupBy: 'severity',
  },
  {
    id: 'remediation',
    label: 'Remediation',
    description:
      'The forward path: each recommended action the scanner recorded, the open findings it closes and the assets those sit on. Sized by how many findings each action clears.',
    kinds: ['remediation', 'finding', 'asset'],
    groupBy: 'severity',
  },
];

/** Groupings the estate graph populates — offered in place of the scanner's phase/layer. */
export const ESTATE_GROUPINGS: WorkflowGrouping[] = ['none', 'severity', 'kind', 'environment', 'criticality'];

/* ──────────────────────────────────────────────────────────────── the builder ─ */

export interface EstateWorkflowGraph extends WorkflowGraph {
  /** The canonical open findings, in the shape the finding sheet renders. */
  findingCorpus: ExposureFinding[];
  /** Estate-level totals the caller prints beside the canvas. */
  estate: {
    assets: number;
    assessedAssets: number;
    unassessedAssets: number;
    relationships: number;
    sessions: number;
    lastScanAt: string | null;
    persistence: 'database' | 'memory';
    /** Canonical OPEN findings — equals the Open Findings KPI. */
    openFindings: number;
    /** PQC-ready confirmations (SAFE) — counted, not drawn as findings. */
    pqcConfirmations: number;
    /** Canonical CBOM components — equals the Cryptographic Inventory KPI. */
    components: number;
    /** Raw inventory rows those components group. */
    componentInstances: number;
    /** Findings that could not be linked to an asset in the inventory. */
    unlinkedFindings: number;
    certificates: number;
    /**
     * Recorded algorithm values that are not cryptographic primitives (finding
     * titles such as "ECDSA Certificate Detected") and so produced no algorithm
     * node — surfaced so a lower count reads as a REJECTION, not missing data.
     */
    rejectedAlgorithmLabels: number;
    /** Recommendations excluded because they were placeholders or "no action required". */
    nonActionRecommendations: number;
  };
}

export function buildEstateWorkflowGraph(input: EstateWorkflowInput): EstateWorkflowGraph {
  const nodes: WorkflowNode[] = [];
  const edges: WorkflowEdge[] = [];
  const seenEdges = new Set<string>();

  const addEdge = (
    source: string,
    target: string,
    kind: WorkflowEdge['kind'],
    severity: FindingSeverity | null,
    detection: DetectionMethod,
  ) => {
    const id = `${source}->${target}:${kind}`;
    if (seenEdges.has(id)) return;
    seenEdges.add(id);
    edges.push({ id, source, target, kind, severity, detection });
  };

  const assetById = new Map<string, EstateRow>();
  for (const asset of input.assets) {
    const id = str(asset.id);
    if (id) assetById.set(id, asset);
  }
  const assetName = (id: string) => str(assetById.get(id)?.name) || '';
  /** Grouping memberships a node inherits from the asset it belongs to. */
  const assetGroups = (id: string): Partial<Record<WorkflowGrouping, string>> => {
    const asset = assetById.get(id);
    if (!asset) return {};
    return {
      environment: `env:${str(asset.environment) || 'unspecified'}`,
      criticality: `crit:${str(asset.criticality) || 'unspecified'}`,
    };
  };

  /* ── 1. Findings — canonical, open only ─────────────────────────────────
     SAFE entries are PQC-ready confirmations ("ML-KEM detected"): real
     evidence, but not exposure. They are counted and stated, and the CBOM
     components already carry them — drawing them as findings would inflate
     every finding total on a page whose KPI says otherwise. */

  const findingsByAsset = new Map<string, string[]>();
  const severityByAsset = new Map<string, FindingSeverity | null>();
  const findingsByAlgorithm = new Map<string, Array<{ id: string; severity: FindingSeverity }>>();
  const findingCorpus: ExposureFinding[] = [];
  const openFindings: Array<{ input: EstateFindingInput; severity: FindingSeverity }> = [];
  let pqcConfirmations = 0;
  let unlinkedFindings = 0;

  for (const finding of input.findings) {
    const severity = severityOf(finding.threatLevel);
    if (!severity) {
      pqcConfirmations += lower(finding.threatLevel) === 'safe' ? 1 : 0;
      continue;
    }
    openFindings.push({ input: finding, severity });
  }

  for (const { input: finding, severity } of openFindings) {
    const nodeId = `finding:${finding.id}`;
    const assetId = assetById.has(finding.assetId) ? finding.assetId : '';
    if (!assetId) unlinkedFindings += 1;
    const facts: Array<{ label: string; value: string }> = [];
    pushFact(facts, 'Severity', severity.toUpperCase());
    pushFact(facts, 'Category', finding.category);
    pushFact(facts, 'Status', finding.status);
    pushFact(facts, 'Asset', assetId ? assetName(assetId) : 'Not linked to an inventoried asset');
    pushFact(facts, 'Location', finding.location);
    pushFact(facts, 'Merged observations', finding.observations);
    pushFact(facts, 'Recorded in', finding.sources.join(', '));
    pushFact(facts, 'Ownership', finding.ownership);
    pushFact(facts, 'Detected', day(finding.detectedAt));
    nodes.push({
      id: nodeId,
      kind: 'finding',
      label: finding.title || `Finding ${finding.id.slice(0, 8)}`,
      sublabel: finding.description || finding.category,
      severity,
      confidence: 'high',
      detection: 'observed',
      quantumStatus: null,
      findingIds: [finding.id],
      weight: 1,
      groups: {
        severity: `sev:${severity}`,
        kind: 'kind:finding',
        ...(assetId ? assetGroups(assetId) : {}),
      },
      facts,
      findingRef: finding.id,
    });
    findingCorpus.push(toExposureFinding(finding, severity, assetId ? assetName(assetId) : ''));

    if (assetId) {
      const list = findingsByAsset.get(assetId) ?? [];
      list.push(finding.id);
      findingsByAsset.set(assetId, list);
      severityByAsset.set(assetId, worseSeverity(severityByAsset.get(assetId) ?? null, severity));
      addEdge(nodeId, `asset:${assetId}`, 'observed-at', severity, 'observed');
    }

    /* A finding CONCERNS an algorithm when the scanner recorded that algorithm
       as its subject. Keyed exactly, so a finding about a header never
       attaches to the cryptography next to it. */
    if (isCryptographicPrimitive(finding.title)) {
      const key = algorithmKey(finding.title);
      const list = findingsByAlgorithm.get(key) ?? [];
      list.push({ id: finding.id, severity });
      findingsByAlgorithm.set(key, list);
    }
  }

  /* ── 2. Algorithms — one node per recorded primitive ────────────────── */

  interface AlgorithmAcc {
    id: string;
    key: string;
    label: string;
    quantum: QuantumStatus;
    assets: Set<string>;
    sources: Set<string>;
    occurrences: number;
  }
  const algorithms = new Map<string, AlgorithmAcc>();
  let rejectedAlgorithmLabels = 0;

  const noteAlgorithm = (raw: unknown, assetId: string, source: string, weight = 1) => {
    const label = str(raw).trim();
    if (!label) return null;
    /* The algorithm column carries scanner FINDING TITLES alongside primitives
       ("ECDSA Certificate Detected" beside "ECDSA P-256"). The platform's own
       predicate decides — it is reused, not re-derived. */
    if (!isCryptographicPrimitive(label)) {
      rejectedAlgorithmLabels += 1;
      return null;
    }
    const key = algorithmKey(label);
    let entry = algorithms.get(key);
    if (!entry) {
      entry = {
        id: `algorithm:${key}`,
        key,
        label,
        quantum: quantumVerdictFor(label),
        assets: new Set<string>(),
        sources: new Set<string>(),
        occurrences: 0,
      };
      algorithms.set(key, entry);
    }
    entry.occurrences += Math.max(1, weight);
    entry.sources.add(source);
    if (assetId) entry.assets.add(assetId);
    return entry;
  };

  /* ── 3. CBOM components — canonical, one node per component ─────────── */

  const componentsByAsset = new Map<string, number>();
  let componentInstances = 0;
  for (const component of input.components) {
    const nodeId = `component:${component.id}`;
    const assetId = assetById.has(component.assetId) ? component.assetId : '';
    const instances = Math.max(1, component.instances || 1);
    componentInstances += instances;
    if (assetId) componentsByAsset.set(assetId, (componentsByAsset.get(assetId) ?? 0) + 1);
    const algorithm = noteAlgorithm(component.algorithm, assetId, 'CBOM', instances);

    /* A component is not a finding. It carries the exposure level the scanner
       recorded for it, and `null` when none was recorded or it is PQC-ready. */
    const recorded = severityOf(component.riskSeverity);
    const severity = component.isVulnerable && !component.isQuantumSafe ? recorded ?? 'medium' : null;
    const tenantVerdict: QuantumStatus = component.isQuantumSafe
      ? (() => {
          const kb = quantumVerdictFor(component.algorithm);
          return kb === 'pqc' || kb === 'hybrid' ? kb : 'resistant';
        })()
      : component.isVulnerable
        ? 'vulnerable'
        : algorithm?.quantum ?? 'unknown';
    const kbVerdict = quantumVerdictFor(component.algorithm);

    const facts: Array<{ label: string; value: string }> = [];
    pushFact(facts, 'Component', component.name);
    pushFact(facts, 'Type', component.type);
    pushFact(facts, 'Algorithm', component.algorithm);
    pushFact(facts, 'Instances', instances);
    pushFact(facts, 'Recorded verdict', component.isQuantumSafe ? 'PQC-ready' : component.isVulnerable ? 'Quantum-vulnerable' : 'Unclassified');
    /* Rule 7 of data integrity: where two verdicts should agree but do not,
       report both rather than letting one overwrite the other. */
    if (
      component.isVulnerable &&
      !component.isQuantumSafe &&
      (kbVerdict === 'resistant' || kbVerdict === 'not-applicable')
    ) {
      pushFact(
        facts,
        'Knowledge-base verdict',
        kbVerdict === 'resistant'
          ? 'Quantum-resistant primitive — the recorded exposure is the key exchange negotiated with it, not the cipher'
          : QUANTUM_VERDICT_LABEL[kbVerdict],
      );
    }
    pushFact(facts, 'Exposure level', component.riskSeverity);
    pushFact(facts, 'Detection', component.detectionMethod);
    pushFact(facts, 'Replacement', component.replacement);
    pushFact(facts, 'Asset', assetId ? assetName(assetId) : 'Not linked to an inventoried asset');
    pushFact(facts, 'Last seen', day(component.lastSeen));

    nodes.push({
      id: nodeId,
      kind: 'component',
      label: component.algorithm || component.name || `Component ${component.id.slice(0, 8)}`,
      sublabel: `${component.name}${instances > 1 ? ` · ${instances} instances` : ''}`,
      severity,
      confidence: 'high',
      detection: 'observed',
      quantumStatus: tenantVerdict,
      findingIds: [],
      weight: instances,
      groups: {
        severity: `sev:${severity ?? 'none'}`,
        kind: 'kind:component',
        ...(assetId ? assetGroups(assetId) : {}),
      },
      facts,
    });
    if (algorithm) addEdge(nodeId, algorithm.id, 'implements', severity, 'observed');
    if (assetId) addEdge(`asset:${assetId}`, nodeId, 'hosts', severity, 'observed');
  }

  /* ── 4. Certificates ──────────────────────────────────────────────────
     Expiry is a MEASURED fact, so it drives severity: expired is critical,
     inside 30 days high, inside 90 medium. A certificate with no `not_after`
     is unclassified, not healthy. */

  const certsByAsset = new Map<string, number>();
  const now = Date.now();
  for (const row of input.certificates) {
    const id = `certificate:${str(row.id)}`;
    const assetId = assetById.has(str(row.asset_id)) ? str(row.asset_id) : '';
    if (assetId) certsByAsset.set(assetId, (certsByAsset.get(assetId) ?? 0) + 1);
    const algorithmLabel = str(row.algorithm);
    const algorithm = noteAlgorithm(algorithmLabel, assetId, 'Certificate');
    const notAfter = str(row.not_after);
    const expiresAt = notAfter ? Date.parse(notAfter) : Number.NaN;
    const daysLeft = Number.isFinite(expiresAt) ? Math.floor((expiresAt - now) / 86400000) : null;
    const severity: FindingSeverity | null =
      daysLeft === null ? null : daysLeft < 0 ? 'critical' : daysLeft <= 30 ? 'high' : daysLeft <= 90 ? 'medium' : null;
    const quantum = row.is_quantum_safe === true ? 'pqc' : quantumVerdictFor(algorithmLabel);
    const facts: Array<{ label: string; value: string }> = [];
    pushFact(facts, 'Subject', str(row.subject));
    pushFact(facts, 'Issuer', str(row.issuer));
    pushFact(facts, 'Key algorithm', algorithmLabel);
    pushFact(facts, 'Key size', row.key_size ? `${str(row.key_size)} bits` : null);
    pushFact(facts, 'Status', str(row.status));
    pushFact(facts, 'Valid from', day(row.not_before));
    pushFact(facts, 'Expires', notAfter ? day(notAfter) : 'Not recorded');
    pushFact(
      facts,
      'Validity',
      daysLeft === null ? 'Expiry not recorded' : daysLeft < 0 ? `Expired ${Math.abs(daysLeft)}d ago` : `${daysLeft}d remaining`,
    );
    pushFact(facts, 'Quantum verdict', QUANTUM_VERDICT_LABEL[quantum]);
    pushFact(facts, 'Asset', assetId ? assetName(assetId) : 'Not linked to an inventoried asset');
    nodes.push({
      id,
      kind: 'certificate',
      label: str(row.subject) || str(row.name) || algorithmLabel || `Certificate ${str(row.id).slice(0, 8)}`,
      sublabel: notAfter ? `${algorithmLabel || 'Certificate'} · expires ${day(notAfter)}` : 'Expiry not recorded',
      severity,
      confidence: 'high',
      detection: 'observed',
      quantumStatus: quantum,
      findingIds: [],
      weight: 1,
      groups: {
        severity: `sev:${severity ?? 'none'}`,
        kind: 'kind:certificate',
        ...(assetId ? assetGroups(assetId) : {}),
      },
      facts,
    });
    if (algorithm) addEdge(id, algorithm.id, 'implements', severity, 'observed');
    if (assetId) addEdge(`asset:${assetId}`, id, 'hosts', severity, 'observed');
  }

  /* A finding whose subject is a primitive that no component or certificate
     recorded still names that primitive — it becomes a node too. */
  for (const { input: finding } of openFindings) {
    if (!isCryptographicPrimitive(finding.title)) continue;
    const key = algorithmKey(finding.title);
    if (algorithms.has(key)) {
      const entry = algorithms.get(key)!;
      if (finding.assetId && assetById.has(finding.assetId)) entry.assets.add(finding.assetId);
      entry.sources.add('Finding');
      continue;
    }
    noteAlgorithm(finding.title, assetById.has(finding.assetId) ? finding.assetId : '', 'Finding');
  }

  /* ── 5. Algorithm nodes — severity from their OWN findings (rule 4) ───── */

  for (const entry of algorithms.values()) {
    const concerning = findingsByAlgorithm.get(entry.key) ?? [];
    let severity: FindingSeverity | null = null;
    for (const finding of concerning) severity = worseSeverity(severity, finding.severity);
    const facts: Array<{ label: string; value: string }> = [];
    pushFact(facts, 'Quantum verdict', QUANTUM_VERDICT_LABEL[entry.quantum]);
    const definition = findAlgorithm(entry.label);
    pushFact(facts, 'Knowledge base', definition ? `${definition.canonicalName} · ${definition.primitiveType.replace(/-/g, ' ')}` : 'Not in the knowledge base');
    pushFact(facts, 'Open findings about it', concerning.length);
    pushFact(facts, 'Recorded instances', entry.occurrences);
    pushFact(facts, 'Assets carrying it', entry.assets.size);
    pushFact(facts, 'Evidence sources', [...entry.sources].join(', '));
    nodes.push({
      id: entry.id,
      kind: 'algorithm',
      label: entry.label,
      sublabel: `${QUANTUM_VERDICT_LABEL[entry.quantum]} · ${entry.assets.size} asset${entry.assets.size === 1 ? '' : 's'}`,
      severity,
      confidence: 'high',
      /* Inferred: an algorithm node is a CONCLUSION drawn from the rows that
         named it, not an artefact that was itself read (§63). */
      detection: 'inferred',
      quantumStatus: entry.quantum,
      findingIds: concerning.map((finding) => finding.id),
      weight: Math.max(1, entry.occurrences),
      groups: { severity: `sev:${severity ?? 'none'}`, kind: 'kind:algorithm' },
      facts,
    });
    for (const finding of concerning) addEdge(`finding:${finding.id}`, entry.id, 'subject', finding.severity, 'observed');
    for (const assetId of entry.assets) addEdge(`asset:${assetId}`, entry.id, 'subject', null, 'inferred');
  }

  /* ── 6. Assets ──────────────────────────────────────────────────────────
     Risk and posture come from the SHARED model (rule 2); evidence decides
     whether the asset was ASSESSED at all (rule 3). */

  const runtimeByAsset = new Map<string, number>();
  for (const row of input.runtimeEvents) {
    const assetId = str(row.asset_id);
    if (assetId) runtimeByAsset.set(assetId, (runtimeByAsset.get(assetId) ?? 0) + 1);
  }
  const sessionsByAsset = new Map<string, Set<string>>();
  for (const row of input.scanLinks) {
    const assetId = str(row.asset_id);
    const sessionId = str(row.scan_session_id);
    if (!assetId || !sessionId) continue;
    const set = sessionsByAsset.get(assetId) ?? new Set<string>();
    set.add(sessionId);
    sessionsByAsset.set(assetId, set);
  }

  const assetNodes: WorkflowNode[] = [];
  let assessedAssets = 0;
  for (const row of input.assets) {
    const id = str(row.id);
    if (!id) continue;
    const nodeId = `asset:${id}`;
    const findingIds = findingsByAsset.get(id) ?? [];
    const components = componentsByAsset.get(id) ?? 0;
    const runtime = runtimeByAsset.get(id) ?? 0;
    const certs = certsByAsset.get(id) ?? 0;
    const sessions = sessionsByAsset.get(id)?.size ?? 0;
    const assessed = findingIds.length + components + runtime + certs + sessions > 0;
    if (assessed) assessedAssets += 1;

    const environment = str(row.environment) || 'unspecified';
    const criticality = str(row.criticality) || 'unspecified';
    const risk = input.assetRisk.get(id);
    const posture = input.assetPosture.get(id) ?? null;
    const severity = assessed ? severityByAsset.get(id) ?? null : null;

    const facts: Array<{ label: string; value: string }> = [];
    pushFact(facts, 'Type', str(row.type));
    pushFact(facts, 'Environment', environment);
    pushFact(facts, 'Business criticality', criticality);
    pushFact(facts, 'Lifecycle status', str(row.status));
    /* The score is only printed when the asset was actually assessed. A 0 on an
       unmeasured asset would read as "no risk". */
    pushFact(facts, 'Risk score', assessed && risk !== undefined ? `${Math.round(risk)}/100` : 'Not assessed');
    pushFact(
      facts,
      'Quantum posture',
      assessed && posture ? (posture === 'pqc' ? 'PQC-ready' : posture === 'hybrid' ? 'Hybrid / in progress' : 'Quantum-vulnerable') : 'Not assessed',
    );
    pushFact(facts, 'Open findings', findingIds.length);
    pushFact(facts, 'Worst finding', severity ? severity.toUpperCase() : assessed ? 'None open' : 'Not assessed');
    pushFact(facts, 'CBOM components', components);
    pushFact(facts, 'Certificates', certs);
    pushFact(facts, 'Scan sessions', sessions);
    pushFact(facts, 'Runtime events', runtime);

    const node: WorkflowNode = {
      id: nodeId,
      kind: 'asset',
      label: str(row.name) || `Asset ${id.slice(0, 8)}`,
      sublabel: `${str(row.type) || 'asset'} · ${environment}`,
      severity,
      confidence: assessed ? 'high' : null,
      detection: assessed ? 'observed' : 'unknown',
      quantumStatus: assessed && posture ? (posture === 'pqc' ? 'pqc' : posture === 'hybrid' ? 'hybrid' : 'vulnerable') : null,
      findingIds,
      weight: Math.max(1, findingIds.length + components + certs),
      groups: {
        severity: `sev:${severity ?? 'none'}`,
        kind: 'kind:asset',
        environment: `env:${environment}`,
        criticality: `crit:${criticality}`,
      },
      facts,
      state: assessed ? undefined : 'Not assessed',
    };
    assetNodes.push(node);
    nodes.push(node);
  }

  /* ── 7. Asset relationships — the real topology (rule 5) ─────────────── */

  let relationshipsProjected = 0;
  for (const row of input.relationships) {
    const source = str(row.source_asset_id);
    const target = str(row.target_asset_id);
    if (!assetById.has(source) || !assetById.has(target)) continue;
    relationshipsProjected += 1;
    addEdge(
      `asset:${source}`,
      `asset:${target}`,
      'connects',
      worseSeverity(severityByAsset.get(source) ?? null, severityByAsset.get(target) ?? null),
      'observed',
    );
  }

  /* ── 8. Scan sessions — the parent processes ───────────────────────────
     A session links to the assets whose recorded scan results carry its id.
     Only when NO such link exists anywhere (a store that does not record it)
     is the most recent completed session drawn as the root, and that edge is
     marked INFERRED so it can be switched off. */

  let lastScanAt: string | null = null;
  const sortedSessions = [...input.sessions].sort(
    (a, b) => Date.parse(str(b.created_at) || '0') - Date.parse(str(a.created_at) || '0'),
  );
  const sessionNodeIds = new Set<string>();
  for (const row of sortedSessions.slice(0, 12)) {
    const sessionId = str(row.id);
    const id = `scan:${sessionId}`;
    sessionNodeIds.add(sessionId);
    const completed = str(row.completed_at);
    const started = str(row.started_at) || str(row.created_at);
    if (completed && (!lastScanAt || completed > lastScanAt)) lastScanAt = completed;
    const durationMs = completed && started ? Date.parse(completed) - Date.parse(started) : Number.NaN;
    const target = str(row.target_scope);
    const facts: Array<{ label: string; value: string }> = [];
    pushFact(facts, 'Target', target);
    pushFact(facts, 'Status', str(row.status));
    /* `findings_count` counts every row the run persisted — PQC-ready
       confirmations and duplicate storage copies included — so it is an
       observation count, NOT the open-finding total. Labelled as what it is. */
    pushFact(facts, 'Observations recorded', str(row.findings_count));
    pushFact(facts, 'Started', started ? started.slice(0, 19).replace('T', ' ') : null);
    pushFact(facts, 'Completed', completed ? completed.slice(0, 19).replace('T', ' ') : 'Not completed');
    pushFact(facts, 'Duration', Number.isFinite(durationMs) && durationMs >= 0 ? `${Math.round(durationMs / 1000)}s` : null);
    nodes.push({
      id,
      kind: 'scan',
      label: target ? `Scan · ${target.replace(/^https?:\/\//, '').replace(/\/$/, '')}` : `Scan ${sessionId.slice(0, 8)}`,
      sublabel: `${str(row.status) || 'unknown'} · ${completed ? day(completed) : 'in progress'}`,
      severity: null,
      confidence: null,
      detection: 'observed',
      quantumStatus: null,
      findingIds: [],
      weight: Math.max(1, Number(row.findings_count) || 1),
      groups: { severity: 'sev:none', kind: 'kind:scan' },
      facts,
      state: str(row.status) || undefined,
    });
  }

  let recordedSessionLinks = 0;
  for (const [assetId, sessions] of sessionsByAsset) {
    if (!assetById.has(assetId)) continue;
    for (const sessionId of sessions) {
      if (!sessionNodeIds.has(sessionId)) continue;
      recordedSessionLinks += 1;
      addEdge(`scan:${sessionId}`, `asset:${assetId}`, 'assessed', severityByAsset.get(assetId) ?? null, 'observed');
    }
  }
  if (recordedSessionLinks === 0 && sortedSessions.length > 0) {
    const root = `scan:${str(sortedSessions[0].id)}`;
    for (const asset of assetNodes) {
      if (asset.detection !== 'observed') continue;
      addEdge(root, asset.id, 'assessed', asset.severity, 'inferred');
    }
  }

  /* ── 9. Remediation — the actions recorded on the findings ─────────────
     Grouped by recorded text. A remediation closes exactly the findings that
     recommend it, and carries the worst of THEIR severities (rule 4).
     Placeholders and "no action required" are not actions and are counted,
     not drawn. */

  const findingSeverityById = new Map(openFindings.map(({ input: finding, severity }) => [finding.id, severity]));
  const { actions, nonAction: nonActionRecommendations } = groupRecommendedActions(openFindings.map(({ input: finding }) => finding));
  actions.forEach((action, index) => {
    const id = `remediation:${index + 1}`;
    const assets = action.assetIds.filter((assetId) => assetById.has(assetId));
    const facts: Array<{ label: string; value: string }> = [];
    pushFact(facts, 'Recommended action', action.text);
    pushFact(facts, 'Open findings it closes', action.findingIds.length);
    pushFact(facts, 'Addresses', action.subjects.join(', '));
    pushFact(facts, 'Worst severity addressed', action.severity.toUpperCase());
    pushFact(facts, 'Assets affected', assets.map(assetName).filter(Boolean).join(', ') || 'Not linked to an inventoried asset');
    pushFact(facts, 'Source', 'Recorded by the scanner on each finding');
    nodes.push({
      id,
      kind: 'remediation',
      label: action.text.length > 64 ? `${action.text.slice(0, 61)}…` : action.text,
      sublabel: `Closes ${action.findingIds.length} open finding${action.findingIds.length === 1 ? '' : 's'}`,
      severity: action.severity,
      confidence: null,
      /* Inferred: each action is on record, but grouping identical actions
         across findings is this module's conclusion (§63). */
      detection: 'inferred',
      quantumStatus: null,
      findingIds: action.findingIds,
      weight: Math.max(1, action.findingIds.length),
      groups: { severity: `sev:${action.severity}`, kind: 'kind:remediation' },
      facts,
    });
    for (const findingId of action.findingIds) {
      addEdge(`finding:${findingId}`, id, 'remediates', findingSeverityById.get(findingId) ?? null, 'observed');
    }
  });

  /* ── 10. Bound it, and say what was dropped ───────────────────────────── */

  const dropped: Array<{ kind: WorkflowNodeKind; dropped: number; total: number }> = [];
  const keptIds = new Set<string>();
  const byKind = new Map<WorkflowNodeKind, WorkflowNode[]>();
  for (const node of nodes) {
    const list = byKind.get(node.kind) ?? [];
    list.push(node);
    byKind.set(node.kind, list);
  }
  const kept: WorkflowNode[] = [];
  for (const [kind, list] of byKind) {
    const cap = CAPS[kind];
    if (cap === undefined || list.length <= cap) {
      for (const node of list) {
        kept.push(node);
        keptIds.add(node.id);
      }
      continue;
    }
    /* Keep the worst evidence, then the heaviest — a cap must never silently
       drop the critical rows and leave a calm-looking picture behind. */
    const ordered = [...list].sort((a, b) => capRank(a) - capRank(b) || b.weight - a.weight);
    for (const node of ordered.slice(0, cap)) {
      kept.push(node);
      keptIds.add(node.id);
    }
    dropped.push({ kind, dropped: list.length - cap, total: list.length });
  }

  const keptEdges = edges.filter((edge) => keptIds.has(edge.source) && keptIds.has(edge.target));
  const keptFindingIds = new Set(kept.filter((node) => node.kind === 'finding').flatMap((node) => node.findingIds));

  /* ── 11. Clusters — one per populated group, for every grouping offered ── */

  const clusters: WorkflowGraph['clusters'] = [];
  const clusterSeverity = new Map<string, { grouping: WorkflowGrouping; severity: FindingSeverity | null }>();
  for (const node of kept) {
    for (const grouping of ['severity', 'kind', 'environment', 'criticality'] as WorkflowGrouping[]) {
      const groupId = node.groups[grouping];
      if (!groupId) continue;
      const current = clusterSeverity.get(groupId);
      clusterSeverity.set(groupId, {
        grouping,
        severity: worseSeverity(current?.severity ?? null, node.severity),
      });
    }
  }
  for (const [groupId, { grouping, severity }] of clusterSeverity) {
    const value = groupId.slice(groupId.indexOf(':') + 1);
    const label =
      grouping === 'severity'
        ? SEVERITY_GROUP_LABEL[(value as FindingSeverity | 'none')] ?? value
        : grouping === 'kind'
          ? NODE_KIND_LABEL[value as WorkflowNodeKind] ?? value
          : value;
    clusters.push({ id: groupId, label, grouping, severity: grouping === 'severity' && value === 'none' ? null : severity });
  }

  const counts = {} as Record<WorkflowNodeKind, number>;
  for (const kind of Object.keys(NODE_KIND_LABEL) as WorkflowNodeKind[]) counts[kind] = 0;
  for (const node of kept) counts[node.kind] += 1;

  return {
    nodes: kept,
    edges: keptEdges,
    clusters,
    counts,
    /* The reconciliation contract, against the CANONICAL totals — the same
       numbers the Open Findings and Cryptographic Inventory KPIs print. */
    reconciliation: {
      findingsInAssessment: openFindings.length,
      findingsProjected: counts.finding,
      componentsInAssessment: input.components.length,
      componentsProjected: counts.component,
      exposuresInAssessment: 0,
      exposuresProjected: 0,
    },
    truncation: { truncated: dropped.length > 0, dropped },
    findingCorpus: findingCorpus.filter((finding) => keptFindingIds.has(finding.id)),
    estate: {
      assets: input.assets.length,
      assessedAssets,
      unassessedAssets: Math.max(0, input.assets.length - assessedAssets),
      relationships: relationshipsProjected,
      sessions: input.sessions.length,
      lastScanAt,
      persistence: input.persistence ?? 'database',
      openFindings: openFindings.length,
      pqcConfirmations,
      components: input.components.length,
      componentInstances,
      unlinkedFindings,
      certificates: input.certificates.length,
      rejectedAlgorithmLabels,
      nonActionRecommendations,
    },
  };
}
