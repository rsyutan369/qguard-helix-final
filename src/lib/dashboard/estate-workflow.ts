/**
 * QGuard Helix Estate Exposure Workflow™ — the tenant-level projection.
 *
 * The scanner's Exposure Workflow renders ONE {@link ExposureAssessment}: a
 * scan, the lifecycle phases it walked, the engine processes each phase
 * spawned, and the cryptography those processes read. That lineage does not
 * exist at tenant level — there is no single run, no phase tree and no engine
 * registry spanning an estate.
 *
 * The estate has its OWN process lineage, and it is just as real because every
 * link is a row:
 *
 *   scan session ──assessed──▶ asset ──hosts──▶ component ──implements──▶ algorithm
 *                               │  │              ▲
 *                               │  └──hosts──▶ certificate
 *                               │
 *                               ├◀─observed-at── finding ──remediated by──▶ remediation
 *                               └──connects──▶ asset          (asset_relationships)
 *
 * So the RENDERER is reused unchanged and only the PROJECTION is new.
 * Synthesising a fake assessment out of tenant rows would have invented phases
 * and engine processes that never ran, which is the precise fabrication the
 * platform's data-integrity rules exist to prevent.
 *
 * ACCURACY CONTRACT — every rule here is enforced by tools/estate-workflow-check.ts
 * ------------------------------------------------------------------------------
 * 1. DERIVED ROWS ENRICH, THEY NEVER ADD. Every node is a projection of a row
 *    the tenant already holds. The graph cannot contain an asset, finding,
 *    component or certificate that Assets, CBOM and Findings do not also
 *    contain, and `reconciliation` states projected-vs-source so a reader can
 *    check the picture against the panels around it.
 * 2. RISK IS NOT RECOMPUTED. Per-asset risk arrives from the shared
 *    `deriveAssetPostureModel` — the same call /dashboard/assets, Quantum
 *    Readiness and the Migration Planner make — so an asset reads the same
 *    number on every page. This module owns no scoring of its own.
 * 3. ABSENCE IS NOT SAFETY (§43). An asset with no evidence carries severity
 *    `null`, rendered "None", never `info` and never a passing colour. "We did
 *    not measure it" and "it is clean" are different answers.
 * 4. SEVERITY IS NOT CONFIDENCE (§37). Both travel on the node, separately.
 * 5. TOPOLOGY IS OBSERVED, NEVER INFERRED. Asset-to-asset edges are the real
 *    `asset_relationships` rows. Nothing here guesses a parent from a name.
 * 6. BOUNDED, AND HONEST ABOUT IT. Capped per kind by severity rank, with what
 *    was dropped reported in `truncation` for the caller to render.
 *
 * ISOMORPHIC: no DOM, no Node built-ins — the api-server builds it, the browser
 * renders it, and a report could embed it without a second implementation.
 */

import type {
  DetectionMethod,
  FindingConfidence,
  FindingSeverity,
  QuantumStatus,
} from '../scanner/exposure/types';
import { SEVERITY_ORDER } from '../scanner/exposure/types';
import { isCryptographicComponent } from '../scanner/finding-identity';
import { algorithmFamily } from '../governance/subjects';
import { isCryptographicPrimitive } from '../crypto-agility/agility-intelligence';
import type {
  WorkflowEdge,
  WorkflowGraph,
  WorkflowGrouping,
  WorkflowLensDefinition,
  WorkflowNode,
  WorkflowNodeKind,
} from '../scanner/exposure/workflow-graph';

/* ─────────────────────────────────────────────────────────────── input rows ── */

/**
 * The tenant rows this projection reads.
 *
 * Deliberately the SAME query set `/api/v1/dashboard/exposure-map` already
 * issues, plus scan sessions. Reading a different set would let the workflow
 * and the panels beside it disagree about the same estate, which is the one
 * failure mode this whole module exists to avoid.
 */
export interface EstateRow {
  [key: string]: unknown;
}

export interface EstateWorkflowInput {
  assets: EstateRow[];
  relationships: EstateRow[];
  /** crypto_inventory — the CBOM. */
  inventory: EstateRow[];
  /** crypto_exposures. */
  exposures: EstateRow[];
  vulnerabilities: EstateRow[];
  certificates: EstateRow[];
  /** pqc_scan_results — per-asset algorithm observations. */
  scanResults: EstateRow[];
  /** pqc_scan_sessions — the parent processes. */
  sessions: EstateRow[];
  runtimeEvents: EstateRow[];
  /**
   * Canonical per-asset risk, keyed by asset id, from the SHARED posture model.
   * Passed IN rather than computed here: rule 2.
   */
  assetRisk: Map<string, number>;
  /** Canonical per-asset posture from the same shared model. */
  assetPosture: Map<string, 'pqc' | 'hybrid' | 'vulnerable'>;
  /**
   * Which store answered. 'memory' means the database was unreachable and the
   * scanner's in-process results were read instead — real scan output, but a
   * DEGRADED read, and the UI must say so rather than present it as the
   * tenant's durable estate.
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
 * Map any severity vocabulary the platform's tables use onto the one scale.
 *
 * `null` is returned for an unrecognised or absent value rather than a default
 * of `info`: an unreadable severity is an unknown severity, and defaulting it
 * to the mildest band would be the same fabrication rule 3 forbids.
 */
function severityOf(value: unknown): FindingSeverity | null {
  const raw = lower(value);
  if (!raw) return null;
  if (raw === 'critical' || raw === 'severe') return 'critical';
  if (raw === 'high') return 'high';
  if (raw === 'medium' || raw === 'moderate') return 'medium';
  if (raw === 'low' || raw === 'minor') return 'low';
  if (raw === 'info' || raw === 'informational' || raw === 'none') return 'info';
  return null;
}

function worseSeverity(a: FindingSeverity | null, b: FindingSeverity | null): FindingSeverity | null {
  if (a === null) return b;
  if (b === null) return a;
  return SEVERITY_ORDER[a] <= SEVERITY_ORDER[b] ? a : b;
}

const SEVERITY_RANK_FOR_CAP: Record<FindingSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** Nodes with no severity sort last, so a cap keeps the worst evidence. */
function capRank(node: WorkflowNode): number {
  return node.severity === null ? 9 : SEVERITY_RANK_FOR_CAP[node.severity];
}

/**
 * Quantum verdict for an algorithm string.
 *
 * Intentionally conservative: anything not recognised is `unknown`, never
 * `resistant`. Guessing an unrecognised token safe is how an estate acquires a
 * quantum-ready asset it never earned.
 */
function quantumOfAlgorithm(raw: string): QuantumStatus {
  const value = raw.trim().toLowerCase();
  if (!value) return 'unknown';
  if (/ml-kem|ml-dsa|slh-dsa|kyber|dilithium|sphincs|falcon|frodo|bike|hqc|classic-mceliece/.test(value)) return 'pqc';
  if (/hybrid|x25519(\+|-)|p256(\+|-)|\+ml-kem|\+kyber/.test(value)) return 'hybrid';
  if (/rsa|dsa|ecdsa|ecdh|diffie|dh\b|elgamal|secp|prime256|curve25519|ed25519|x25519/.test(value)) return 'vulnerable';
  if (/aes-?256|chacha20|sha3|sha-?384|sha-?512|hmac/.test(value)) return 'resistant';
  if (/aes-?128|sha-?256/.test(value)) return 'resistant';
  if (/md5|sha-?1|des|rc4|3des|blowfish/.test(value)) return 'vulnerable';
  return 'unknown';
}

/** Canonicalise an algorithm token so one algorithm is one node. */
function algorithmKey(raw: string): string {
  return raw.trim().toUpperCase().replace(/\s+/g, ' ');
}

function pushFact(facts: Array<{ label: string; value: string }>, label: string, value: string | number | null | undefined) {
  if (value === null || value === undefined || value === '') return;
  facts.push({ label, value: String(value) });
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
  algorithm: 50,
  remediation: 30,
};

/* ───────────────────────────────────────────────────────────────── the lenses ─ */

/**
 * The estate lenses.
 *
 * Every lens is a projection of the SAME graph — nothing is recomputed per tab
 * — so a node's severity, size and relationships cannot disagree between them.
 * They are named for what an operator on /dashboard is actually asking.
 */
export const ESTATE_LENSES: WorkflowLensDefinition[] = [
  {
    id: 'flow',
    label: 'Estate Flow',
    description:
      'The whole estate as one chain: the scan sessions that ran, the assets they assessed, and the findings and cryptography those assets carry.',
    kinds: ['scan', 'asset', 'finding', 'algorithm'],
    groupBy: 'environment',
  },
  {
    id: 'process',
    label: 'Dependency Tree',
    description:
      'Parent and child only. Real asset-to-asset relationships as recorded in the inventory — nothing here infers a topology from a name.',
    kinds: ['scan', 'asset'],
    groupBy: 'environment',
  },
  {
    id: 'algorithms',
    label: 'Cryptography',
    description:
      'Cryptography as the centre of gravity: every algorithm observed on the estate and the assets and findings that carry it. Switch colour to Type for the quantum verdict.',
    kinds: ['algorithm', 'asset', 'finding', 'component'],
    groupBy: 'severity',
  },
  {
    id: 'cbom',
    label: 'CBOM Graph',
    description:
      'The Cryptographic Bill of Materials as a graph — inventory components, the assets that host them and the algorithms they implement.',
    kinds: ['component', 'algorithm', 'asset'],
    groupBy: 'environment',
  },
  {
    id: 'supply',
    label: 'Certificates & PKI',
    description:
      'Certificate estate: every certificate held, the asset presenting it and the signature algorithm behind it.',
    kinds: ['certificate', 'asset', 'algorithm'],
    groupBy: 'severity',
  },
  {
    id: 'correlation',
    label: 'Exposure',
    description:
      'Where the risk actually sits. Findings grouped by severity with the asset each was observed at, so the worst evidence and its owner are read together.',
    kinds: ['finding', 'asset', 'algorithm'],
    groupBy: 'severity',
  },
  {
    id: 'remediation',
    label: 'Remediation',
    description:
      'The forward path: the recommended actions on record, the assets they apply to and the findings they close.',
    kinds: ['remediation', 'finding', 'asset'],
    groupBy: 'criticality',
  },
];

/* ──────────────────────────────────────────────────────────────── the builder ─ */

export interface EstateWorkflowGraph extends WorkflowGraph {
  /** Estate-level totals the caller prints beside the canvas. */
  estate: {
    assets: number;
    assessedAssets: number;
    unassessedAssets: number;
    relationships: number;
    sessions: number;
    lastScanAt: string | null;
    /** Which store answered. Rendered as a disclosure when not 'database'. */
    persistence: 'database' | 'memory';
    /**
     * Recorded algorithm values that were scanner finding titles rather than
     * cryptographic primitives, and so produced no algorithm node. Surfaced so
     * a lower algorithm count reads as a REJECTION, not as missing data.
     */
    rejectedAlgorithmLabels: number;
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

  /* ── 1. Evidence indexes ────────────────────────────────────────────────
     Built once, keyed by asset id, so every later pass reads the same tallies
     the exposure map and the asset dossiers read. */

  const assetIds = new Set<string>();
  for (const asset of input.assets) {
    const id = str(asset.id);
    if (id) assetIds.add(id);
  }

  const findingsByAsset = new Map<string, string[]>();
  const severityByAsset = new Map<string, FindingSeverity | null>();
  const attachFinding = (assetId: string, nodeId: string, severity: FindingSeverity | null) => {
    if (!assetId) return;
    const list = findingsByAsset.get(assetId) ?? [];
    list.push(nodeId);
    findingsByAsset.set(assetId, list);
    severityByAsset.set(assetId, worseSeverity(severityByAsset.get(assetId) ?? null, severity));
  };

  /* ── 2. Findings ────────────────────────────────────────────────────────
     Two tables carry findings at tenant level and they are DIFFERENT things:
     `vulnerabilities` is the remediation backlog, `crypto_exposures` is the
     cryptographic exposure register. Both are projected, each labelled with its
     origin, so the graph's finding count reconciles against both panels and a
     reader can tell which register a node came from. Resolved vulnerabilities
     are excluded — the same filter the exposure map applies — because a closed
     item is not current exposure. */

  const RESOLVED = new Set(['resolved', 'closed', 'false_positive', 'accepted', 'mitigated']);
  let vulnerabilitiesConsidered = 0;

  for (const row of input.vulnerabilities) {
    if (RESOLVED.has(lower(row.status))) continue;
    vulnerabilitiesConsidered += 1;
    const id = `finding:vuln:${str(row.id)}`;
    const assetId = str(row.asset_id);
    const severity = severityOf(row.severity);
    const facts: Array<{ label: string; value: string }> = [];
    pushFact(facts, 'Register', 'Vulnerability backlog');
    pushFact(facts, 'Severity', severity ? severity.toUpperCase() : 'Unclassified');
    pushFact(facts, 'Status', str(row.status) || 'open');
    pushFact(facts, 'Recorded', str(row.created_at).slice(0, 10));
    nodes.push({
      id,
      kind: 'finding',
      label: str(row.title) || str(row.name) || `Vulnerability ${str(row.id).slice(0, 8)}`,
      sublabel: assetId ? 'Observed on an estate asset' : 'Not linked to an asset',
      severity,
      confidence: 'high',
      detection: 'observed',
      quantumStatus: null,
      findingIds: [id],
      weight: 1,
      groups: {},
      facts,
      findingRef: str(row.id),
    });
    attachFinding(assetId, id, severity);
  }

  for (const row of input.exposures) {
    const id = `finding:exposure:${str(row.id)}`;
    const assetId = str(row.asset_id);
    const severity = severityOf(row.severity);
    const facts: Array<{ label: string; value: string }> = [];
    pushFact(facts, 'Register', 'Cryptographic exposure');
    pushFact(facts, 'Exposure type', str(row.exposure_type));
    pushFact(facts, 'Severity', severity ? severity.toUpperCase() : 'Unclassified');
    pushFact(facts, 'Recorded', str(row.created_at).slice(0, 10));
    nodes.push({
      id,
      kind: 'finding',
      label: str(row.exposure_type) || `Exposure ${str(row.id).slice(0, 8)}`,
      sublabel: 'Cryptographic exposure register',
      severity,
      confidence: 'high',
      detection: 'observed',
      quantumStatus: null,
      findingIds: [id],
      weight: 1,
      groups: {},
      facts,
      findingRef: str(row.id),
    });
    attachFinding(assetId, id, severity);
  }

  /* ── 3. Algorithms ──────────────────────────────────────────────────────
     One node per distinct algorithm, assembled from every table that records
     one: the inventory, the scan results and the certificate estate. The
     quantum verdict is classified from the token itself and is `unknown` when
     unrecognised — never `resistant`. */

  interface AlgorithmAcc {
    id: string;
    label: string;
    quantum: QuantumStatus;
    assets: Set<string>;
    sources: Set<string>;
    occurrences: number;
  }
  const algorithms = new Map<string, AlgorithmAcc>();

  /* Rejected labels, so the reader is told WHY the algorithm count is lower
     than the number of recorded values. Silence here would look like data loss. */
  let rejectedAlgorithmLabels = 0;

  const noteAlgorithm = (raw: unknown, assetId: string, source: string) => {
    const label = str(raw).trim();
    if (!label) return null;
    /* The `algorithm` column carries scanner FINDING TITLES alongside real
       primitives — "Weak RSA Key Size" sits in the same field as "RSA-2048".
       Projecting a title as an algorithm node publishes an entity that is not a
       cryptographic primitive, and an operator who clicks it gets a sentence
       where an algorithm should be. The platform already owns this predicate
       (crypto-agility uses it for exactly this reason), so it is reused rather
       than re-derived. */
    if (!isCryptographicPrimitive(label)) {
      rejectedAlgorithmLabels += 1;
      return null;
    }
    const key = algorithmKey(label);
    let entry = algorithms.get(key);
    if (!entry) {
      entry = {
        id: `algorithm:${key}`,
        label,
        quantum: quantumOfAlgorithm(label),
        assets: new Set<string>(),
        sources: new Set<string>(),
        occurrences: 0,
      };
      algorithms.set(key, entry);
    }
    entry.occurrences += 1;
    entry.sources.add(source);
    if (assetId) entry.assets.add(assetId);
    return entry;
  };

  /* ── 4. CBOM components ─────────────────────────────────────────────────
     One node per crypto_inventory row. `is_vulnerable` is the tenant's own
     verdict and is reported as such — this module does not re-derive it. */

  /*
   * The crypto_inventory table stores scanner FINDINGS alongside real
   * cryptography — rows whose algorithm reads "No Certificate Pinning".
   * Counting those as CBOM
   * components inflates the component total AND both sides of the
   * quantum-vulnerable ratio, which is why the canonical snapshot filters them
   * with this shared predicate. The workflow reads the SAME predicate, so its
   * component count matches the CBOM page and Quantum Readiness rather than
   * publishing a third number for one table.
   */
  const cryptoInventoryRows = input.inventory.filter((row) => isCryptographicComponent(row, algorithmFamily));

  const componentNodes: WorkflowNode[] = [];
  for (const row of cryptoInventoryRows) {
    const id = `component:${str(row.id)}`;
    const assetId = str(row.asset_id);
    const algorithmLabel = str(row.algorithm);
    const algorithm = noteAlgorithm(algorithmLabel, assetId, 'CBOM inventory');
    const vulnerable = row.is_vulnerable === true;
    const quantumSafe = row.is_quantum_safe === true;
    /* A component is not a finding. It carries the severity of the exposure
       level the tenant recorded for it, and `null` when none was recorded —
       an inventory row with no exposure level is unclassified, not clean. */
    const severity = vulnerable ? (severityOf(row.exposure_level) ?? 'high') : severityOf(row.exposure_level);
    const facts: Array<{ label: string; value: string }> = [];
    pushFact(facts, 'Algorithm', algorithmLabel);
    pushFact(facts, 'Protocol', str(row.protocol));
    pushFact(facts, 'Exposure level', str(row.exposure_level));
    pushFact(facts, 'Tenant verdict', vulnerable ? 'Quantum-vulnerable' : quantumSafe ? 'Quantum-safe' : 'Unclassified');
    pushFact(facts, 'Discovered', str(row.discovered_at).slice(0, 10));
    const node: WorkflowNode = {
      id,
      kind: 'component',
      label: algorithmLabel || str(row.name) || `Component ${str(row.id).slice(0, 8)}`,
      sublabel: str(row.protocol) || 'Cryptographic inventory record',
      severity,
      confidence: 'high',
      detection: 'observed',
      quantumStatus: quantumSafe ? 'resistant' : vulnerable ? 'vulnerable' : algorithm?.quantum ?? 'unknown',
      findingIds: [],
      weight: 1,
      groups: {},
      facts,
    };
    componentNodes.push(node);
    nodes.push(node);
    if (algorithm) addEdge(id, algorithm.id, 'implements', severity, 'observed');
  }

  /* ── 5. Certificates ────────────────────────────────────────────────────
     Expiry is a MEASURED fact, so it drives severity: an expired certificate
     is critical and one inside 30 days is high. A certificate with no
     `not_after` is unclassified, not healthy. */

  const certificateNodes: WorkflowNode[] = [];
  const now = Date.now();
  for (const row of input.certificates) {
    const id = `certificate:${str(row.id)}`;
    const assetId = str(row.asset_id);
    const algorithmLabel = str(row.algorithm);
    const algorithm = noteAlgorithm(algorithmLabel, assetId, 'Certificate estate');
    const notAfter = str(row.not_after);
    const expiresAt = notAfter ? Date.parse(notAfter) : Number.NaN;
    const daysLeft = Number.isFinite(expiresAt) ? Math.round((expiresAt - now) / 86400000) : null;
    const severity: FindingSeverity | null =
      daysLeft === null ? null : daysLeft < 0 ? 'critical' : daysLeft <= 30 ? 'high' : daysLeft <= 90 ? 'medium' : null;
    const facts: Array<{ label: string; value: string }> = [];
    pushFact(facts, 'Signature algorithm', algorithmLabel);
    pushFact(facts, 'Status', str(row.status));
    pushFact(facts, 'Expires', notAfter ? notAfter.slice(0, 10) : 'Not recorded');
    pushFact(
      facts,
      'Validity',
      daysLeft === null ? 'Expiry not recorded' : daysLeft < 0 ? `Expired ${Math.abs(daysLeft)}d ago` : `${daysLeft}d remaining`,
    );
    pushFact(facts, 'Quantum-safe', row.is_quantum_safe === true ? 'Yes (tenant verdict)' : 'Not asserted');
    const node: WorkflowNode = {
      id,
      kind: 'certificate',
      label: str(row.common_name) || str(row.subject) || algorithmLabel || `Certificate ${str(row.id).slice(0, 8)}`,
      sublabel: notAfter ? `Expires ${notAfter.slice(0, 10)}` : 'Expiry not recorded',
      severity,
      confidence: 'high',
      detection: 'observed',
      quantumStatus: row.is_quantum_safe === true ? 'resistant' : algorithm?.quantum ?? 'unknown',
      findingIds: [],
      weight: 1,
      groups: {},
      facts,
    };
    certificateNodes.push(node);
    nodes.push(node);
    if (algorithm) addEdge(id, algorithm.id, 'implements', severity, 'observed');
  }

  /* Scan results contribute algorithm observations and per-asset threat level. */
  for (const row of input.scanResults) {
    noteAlgorithm(row.algorithm, str(row.asset_id), 'PQC scan result');
  }

  /* ── 6. Algorithm nodes ─────────────────────────────────────────────── */

  const algorithmNodes: WorkflowNode[] = [];
  for (const entry of algorithms.values()) {
    /* An algorithm's severity is inherited from the assets carrying it, so a
       vulnerable algorithm on an unassessed estate does not manufacture a
       finding that no register holds. */
    let severity: FindingSeverity | null = null;
    const findingIds: string[] = [];
    for (const assetId of entry.assets) {
      severity = worseSeverity(severity, severityByAsset.get(assetId) ?? null);
      for (const findingId of findingsByAsset.get(assetId) ?? []) findingIds.push(findingId);
    }
    const facts: Array<{ label: string; value: string }> = [];
    pushFact(facts, 'Quantum verdict', entry.quantum);
    pushFact(facts, 'Observations', entry.occurrences);
    pushFact(facts, 'Assets carrying it', entry.assets.size);
    pushFact(facts, 'Evidence sources', [...entry.sources].join(', '));
    const node: WorkflowNode = {
      id: entry.id,
      kind: 'algorithm',
      label: entry.label,
      sublabel: `${entry.occurrences} observation${entry.occurrences === 1 ? '' : 's'} across ${entry.assets.size} asset${entry.assets.size === 1 ? '' : 's'}`,
      severity,
      confidence: 'high',
      /* Inferred: an algorithm node is a CONCLUSION drawn from the rows that
         named it, not an artefact that was itself read (§63). The UI can hide
         inferred nodes to show only what is literally on record. */
      detection: 'inferred',
      quantumStatus: entry.quantum,
      findingIds,
      weight: Math.max(1, entry.occurrences),
      groups: {},
      facts,
    };
    algorithmNodes.push(node);
    nodes.push(node);
  }

  /* ── 7. Assets ──────────────────────────────────────────────────────────
     The centre of the estate model. Risk and posture come from the SHARED
     model (rule 2); evidence tallies decide whether the asset was ASSESSED at
     all, and an unassessed asset carries severity `null` (rule 3). */

  const assetNodes: WorkflowNode[] = [];
  const componentsByAsset = new Map<string, number>();
  for (const row of cryptoInventoryRows) {
    const assetId = str(row.asset_id);
    if (assetId) componentsByAsset.set(assetId, (componentsByAsset.get(assetId) ?? 0) + 1);
  }
  const runtimeByAsset = new Map<string, number>();
  for (const row of input.runtimeEvents) {
    const assetId = str(row.asset_id);
    if (assetId) runtimeByAsset.set(assetId, (runtimeByAsset.get(assetId) ?? 0) + 1);
  }
  const resultsByAsset = new Map<string, number>();
  for (const row of input.scanResults) {
    const assetId = str(row.asset_id);
    if (assetId) resultsByAsset.set(assetId, (resultsByAsset.get(assetId) ?? 0) + 1);
  }
  const certsByAsset = new Map<string, number>();
  for (const row of input.certificates) {
    const assetId = str(row.asset_id);
    if (assetId) certsByAsset.set(assetId, (certsByAsset.get(assetId) ?? 0) + 1);
  }

  let assessedAssets = 0;
  for (const row of input.assets) {
    const id = str(row.id);
    if (!id) continue;
    const nodeId = `asset:${id}`;
    const findingIds = findingsByAsset.get(id) ?? [];
    const components = componentsByAsset.get(id) ?? 0;
    const runtime = runtimeByAsset.get(id) ?? 0;
    const results = resultsByAsset.get(id) ?? 0;
    const certs = certsByAsset.get(id) ?? 0;
    const assessed = findingIds.length + components + runtime + results + certs > 0;
    if (assessed) assessedAssets += 1;

    const environment = str(row.environment) || 'unspecified';
    const criticality = str(row.criticality) || 'unspecified';
    const risk = input.assetRisk.get(id);
    const posture = input.assetPosture.get(id) ?? null;

    const facts: Array<{ label: string; value: string }> = [];
    pushFact(facts, 'Type', str(row.type));
    pushFact(facts, 'Environment', environment);
    pushFact(facts, 'Criticality', criticality);
    pushFact(facts, 'Lifecycle status', str(row.status));
    /* The score is only printed when the asset was actually assessed. A 0 on an
       unmeasured asset would read as "no risk", which is the strongest possible
       claim about something nobody looked at. */
    pushFact(facts, 'Risk score', assessed && risk !== undefined ? `${Math.round(risk)}/100` : 'Not assessed');
    pushFact(facts, 'Quantum posture', assessed && posture ? posture : 'Not assessed');
    pushFact(facts, 'Open findings', findingIds.length);
    pushFact(facts, 'CBOM components', components);
    pushFact(facts, 'Certificates', certs);
    pushFact(facts, 'Scan observations', results);
    pushFact(facts, 'Runtime events', runtime);

    const node: WorkflowNode = {
      id: nodeId,
      kind: 'asset',
      label: str(row.name) || `Asset ${id.slice(0, 8)}`,
      sublabel: `${str(row.type) || 'asset'} · ${environment}`,
      severity: assessed ? severityByAsset.get(id) ?? null : null,
      confidence: assessed ? 'high' : null,
      detection: assessed ? 'observed' : 'unknown',
      quantumStatus: assessed && posture ? (posture === 'pqc' ? 'pqc' : posture === 'hybrid' ? 'hybrid' : 'vulnerable') : null,
      findingIds,
      weight: Math.max(1, findingIds.length + components + certs),
      groups: { environment: `env:${environment}`, criticality: `crit:${criticality}` },
      facts,
      state: assessed ? undefined : 'Not assessed',
    };
    assetNodes.push(node);
    nodes.push(node);

    for (const findingId of findingIds) {
      addEdge(findingId, nodeId, 'observed-at', severityByAsset.get(id) ?? null, 'observed');
    }
  }

  /* Asset → component / certificate ownership, and asset → algorithm reach. */
  for (const row of cryptoInventoryRows) {
    const assetId = str(row.asset_id);
    if (assetId && assetIds.has(assetId)) addEdge(`asset:${assetId}`, `component:${str(row.id)}`, 'hosts', null, 'observed');
  }
  for (const row of input.certificates) {
    const assetId = str(row.asset_id);
    if (assetId && assetIds.has(assetId)) addEdge(`asset:${assetId}`, `certificate:${str(row.id)}`, 'hosts', null, 'observed');
  }
  for (const entry of algorithms.values()) {
    for (const assetId of entry.assets) {
      if (!assetIds.has(assetId)) continue;
      addEdge(`asset:${assetId}`, entry.id, 'subject', severityByAsset.get(assetId) ?? null, 'inferred');
    }
  }

  /* ── 8. Asset relationships — the real topology (rule 5) ─────────────── */

  let relationshipsProjected = 0;
  for (const row of input.relationships) {
    const source = str(row.source_asset_id);
    const target = str(row.target_asset_id);
    if (!assetIds.has(source) || !assetIds.has(target)) continue;
    relationshipsProjected += 1;
    addEdge(
      `asset:${source}`,
      `asset:${target}`,
      'connects',
      worseSeverity(severityByAsset.get(source) ?? null, severityByAsset.get(target) ?? null),
      'observed',
    );
  }

  /* ── 9. Scan sessions — the parent processes ───────────────────────────
     A session is the tenant-level equivalent of the assessment node: the run
     that produced the evidence. Sessions are linked to the assets whose scan
     results carry their id where the schema records it; where it does not, the
     session still stands on its own with its recorded finding count, and no
     edge is invented to fill the gap. */

  const sessionNodes: WorkflowNode[] = [];
  let lastScanAt: string | null = null;
  const sortedSessions = [...input.sessions].sort(
    (a, b) => Date.parse(str(b.created_at) || '0') - Date.parse(str(a.created_at) || '0'),
  );
  for (const row of sortedSessions.slice(0, 12)) {
    const id = `scan:${str(row.id)}`;
    const completed = str(row.completed_at);
    const started = str(row.started_at) || str(row.created_at);
    if (completed && (!lastScanAt || completed > lastScanAt)) lastScanAt = completed;
    const facts: Array<{ label: string; value: string }> = [];
    pushFact(facts, 'Status', str(row.status));
    pushFact(facts, 'Findings recorded', str(row.findings_count));
    pushFact(facts, 'Started', started ? started.slice(0, 19).replace('T', ' ') : null);
    pushFact(facts, 'Completed', completed ? completed.slice(0, 19).replace('T', ' ') : 'Not completed');
    const node: WorkflowNode = {
      id,
      kind: 'scan',
      label: `Scan ${str(row.id).slice(0, 8)}`,
      sublabel: `${str(row.status) || 'unknown'} · ${completed ? completed.slice(0, 10) : 'in progress'}`,
      severity: null,
      confidence: null,
      detection: 'observed',
      quantumStatus: null,
      findingIds: [],
      weight: Math.max(1, Number(row.findings_count) || 1),
      groups: {},
      facts,
      state: str(row.status) || undefined,
    };
    sessionNodes.push(node);
    nodes.push(node);
  }

  /* The most recent completed session is the estate's assessment root, so the
     Flow lens reads as one chain rather than a scatter of disconnected assets. */
  const rootSession = sessionNodes[0] ?? null;
  if (rootSession) {
    for (const asset of assetNodes) {
      if (asset.detection !== 'observed') continue;
      addEdge(rootSession.id, asset.id, 'assessed', asset.severity, 'observed');
    }
  }

  /* ── 10. Remediation ──────────────────────────────────────────────────── */

  /* Remediation text is a RECORDED column on `pqc_scan_results`, not a
     recommendation this module composes. Scan results are read here for that
     text and for their algorithms only — they are deliberately NOT projected as
     findings, because the two finding registers above already hold the
     estate's current exposure and counting a scan result a third time would
     inflate every total on the page. */
  interface RemediationAcc {
    text: string;
    assets: Set<string>;
    occurrences: number;
    threat: FindingSeverity | null;
  }
  const remediations = new Map<string, RemediationAcc>();
  for (const row of input.scanResults) {
    const text = str(row.remediation).trim();
    if (!text) continue;
    const key = text.toLowerCase();
    let entry = remediations.get(key);
    if (!entry) {
      entry = { text, assets: new Set<string>(), occurrences: 0, threat: null };
      remediations.set(key, entry);
    }
    entry.occurrences += 1;
    entry.threat = worseSeverity(entry.threat, severityOf(row.threat_level));
    const assetId = str(row.asset_id);
    if (assetId) entry.assets.add(assetId);
  }

  const remediationNodes: WorkflowNode[] = [];
  let remediationIndex = 0;
  for (const entry of remediations.values()) {
    remediationIndex += 1;
    const id = `remediation:${remediationIndex}`;
    const findingIds: string[] = [];
    let severity: FindingSeverity | null = entry.threat;
    for (const assetId of entry.assets) {
      severity = worseSeverity(severity, severityByAsset.get(assetId) ?? null);
      for (const findingId of findingsByAsset.get(assetId) ?? []) findingIds.push(findingId);
    }
    const facts: Array<{ label: string; value: string }> = [];
    pushFact(facts, 'Recorded action', entry.text);
    pushFact(facts, 'Scan observations recommending it', entry.occurrences);
    pushFact(facts, 'Assets it applies to', entry.assets.size);
    pushFact(facts, 'Worst threat level behind it', entry.threat ? entry.threat.toUpperCase() : 'Unclassified');
    pushFact(facts, 'Open findings on those assets', findingIds.length);
    const node: WorkflowNode = {
      id,
      kind: 'remediation',
      label: entry.text.length > 64 ? `${entry.text.slice(0, 61)}…` : entry.text,
      sublabel: `Recorded on ${entry.occurrences} scan observation${entry.occurrences === 1 ? '' : 's'}`,
      severity,
      confidence: null,
      /* Inferred: the ACTION is on record, but grouping it across observations
         and attaching it to an asset's open findings is this module's
         conclusion, not a row (§63). */
      detection: 'inferred',
      quantumStatus: null,
      findingIds,
      weight: Math.max(1, entry.occurrences),
      groups: {},
      facts,
    };
    remediationNodes.push(node);
    nodes.push(node);
    for (const assetId of entry.assets) {
      if (assetIds.has(assetId)) addEdge(`asset:${assetId}`, id, 'remediates', severity, 'inferred');
    }
  }

  /* ── 11. Bound it, and say what was dropped ───────────────────────────── */

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

  /* ── 12. Clusters ─────────────────────────────────────────────────────── */

  const clusters: WorkflowGraph['clusters'] = [];
  const clusterSeen = new Map<string, FindingSeverity | null>();
  for (const node of kept) {
    for (const grouping of ['environment', 'criticality'] as WorkflowGrouping[]) {
      const groupId = node.groups[grouping];
      if (!groupId) continue;
      clusterSeen.set(groupId, worseSeverity(clusterSeen.get(groupId) ?? null, node.severity));
    }
  }
  for (const [groupId, severity] of clusterSeen) {
    const [prefix, ...rest] = groupId.split(':');
    clusters.push({
      id: groupId,
      label: rest.join(':') || groupId,
      grouping: prefix === 'env' ? 'environment' : 'criticality',
      severity,
    });
  }

  const counts = {} as Record<WorkflowNodeKind, number>;
  const KINDS: WorkflowNodeKind[] = [
    'scan', 'phase', 'engine', 'layer', 'asset', 'certificate',
    'finding', 'algorithm', 'component', 'dependency', 'secret', 'file', 'exposure', 'remediation',
  ];
  for (const kind of KINDS) counts[kind] = 0;
  for (const node of kept) counts[node.kind] += 1;

  return {
    nodes: kept,
    edges: keptEdges,
    clusters,
    counts,
    /* The reconciliation contract. Rendered by the caller so a reader can check
       the picture against the panels around it — see rule 1. */
    reconciliation: {
      findingsInAssessment: vulnerabilitiesConsidered + input.exposures.length,
      findingsProjected: counts.finding,
      componentsInAssessment: cryptoInventoryRows.length,
      componentsProjected: counts.component,
      exposuresInAssessment: input.exposures.length,
      exposuresProjected: input.exposures.length,
    },
    truncation: { truncated: dropped.length > 0, dropped },
    estate: {
      assets: input.assets.length,
      assessedAssets,
      unassessedAssets: Math.max(0, input.assets.length - assessedAssets),
      relationships: relationshipsProjected,
      sessions: input.sessions.length,
      lastScanAt,
      persistence: input.persistence ?? 'database',
      rejectedAlgorithmLabels,
    },
  };
}
