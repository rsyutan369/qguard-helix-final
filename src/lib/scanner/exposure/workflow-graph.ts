/**
 * QGuard Helix Exposure Workflow Graph™ — the process/exposure relationship model.
 *
 * Turns one {@link ExposureAssessment} into a typed node/edge graph that shows
 * HOW the assessment happened and WHAT it connected: the parent scan, its
 * lifecycle phases, the engine processes each phase spawned, the engine→engine
 * dependency chain, the findings those processes produced, and the code,
 * algorithms, components, dependencies, secrets, correlated exposures and
 * remediations those findings reach.
 *
 * DESIGN RULES — the same ones the rest of this subsystem is held to
 * ------------------------------------------------------------------
 * 1. DERIVED ROWS ENRICH, THEY NEVER ADD. Every node here is a projection of
 *    something the assessment already contains. The graph cannot introduce a
 *    finding, an algorithm or a component that the Findings table and the CBOM
 *    do not also contain, so `graph.reconciliation` can be asserted against the
 *    panels above it and must always agree.
 * 2. DETECTION METHOD SURVIVES THE PROJECTION (§63). A node carries the
 *    detection method of the evidence behind it. Algorithm, component and
 *    remediation nodes are `inferred` — they are conclusions drawn from what
 *    was read, not artefacts that were read — and the UI is able to hide them
 *    so an operator can see only what is literally present in the corpus.
 * 3. ABSENCE IS NOT SAFETY (§43). A node with no finding behind it has severity
 *    `null` ("None"), never `info` and never a passing colour. Nothing in this
 *    module converts "we did not measure it" into "it is fine".
 * 4. SEVERITY IS NOT CONFIDENCE (§37). Both travel on the node, separately.
 * 5. BOUNDED, AND HONEST ABOUT IT. A graph is unreadable and slow past a few
 *    hundred nodes, so the projection is capped — but it reports what it
 *    dropped in `truncation`, and the caller must render that.
 *
 * ISOMORPHIC: no DOM, no Node built-ins. Same model in the browser worker, the
 * api-server and the report engine.
 */

import type {
  CbomComponent,
  CorrelatedExposure,
  DetectionMethod,
  ExposureAssessment,
  ExposureFinding,
  ExposureLayer,
  FindingConfidence,
  FindingSeverity,
  QuantumStatus,
} from './types';
import { SEVERITY_ORDER, stableHash } from './types';
import { layerLabel } from './correlate';
import { describeAlgorithm } from './algorithms';
import { CAPABILITY_LABEL, type EngineCapability, type EngineDescriptor } from './engine-contract';

/* ──────────────────────────────────────────────────────────────── vocabulary ── */

/** The entity types the graph can contain. Rendered as the filter chips. */
export type WorkflowNodeKind =
  | 'scan'
  | 'phase'
  | 'engine'
  | 'layer'
  | 'finding'
  | 'algorithm'
  /* Estate-only kinds. A single assessment has no notion of an asset or a
     certificate — those exist at TENANT level, where the corpus is the estate
     rather than one authorised target. They live in the shared vocabulary so
     both projections speak one language and the renderer stays single-source. */
  | 'asset'
  | 'certificate'
  | 'component'
  | 'dependency'
  | 'secret'
  | 'file'
  | 'exposure'
  | 'remediation';

export const NODE_KIND_LABEL: Record<WorkflowNodeKind, string> = {
  scan: 'Assessment',
  phase: 'Phases',
  engine: 'Processes',
  layer: 'Layers',
  asset: 'Assets',
  certificate: 'Certificates',
  finding: 'Findings',
  algorithm: 'Algorithms',
  component: 'CBOM',
  dependency: 'Dependencies',
  secret: 'Secrets',
  file: 'Files',
  exposure: 'Exposures',
  remediation: 'Remediation',
};

/** Singular form, for the inspector heading. */
export const NODE_KIND_SINGULAR: Record<WorkflowNodeKind, string> = {
  scan: 'Assessment',
  phase: 'Lifecycle phase',
  engine: 'Scanner process',
  layer: 'Exposure layer',
  asset: 'Estate asset',
  certificate: 'Certificate',
  finding: 'Finding',
  algorithm: 'Algorithm',
  component: 'CBOM component',
  dependency: 'Dependency',
  secret: 'Secret material',
  file: 'Source artefact',
  exposure: 'Correlated exposure',
  remediation: 'Remediation',
};

/** How two entities are related. Drives edge styling and the inspector. */
export type WorkflowEdgeKind =
  | 'orchestrates'
  | 'spawns'
  | 'requires'
  | 'produces'
  | 'observed-at'
  | 'evidence'
  | 'subject'
  | 'implements'
  | 'supplies'
  | 'exposes'
  | 'correlates'
  | 'remediates'
  /* Estate-only relations. */
  | 'assessed'
  | 'connects'
  | 'hosts';

export const EDGE_KIND_LABEL: Record<WorkflowEdgeKind, string> = {
  orchestrates: 'orchestrates',
  spawns: 'spawns process',
  requires: 'requires output of',
  produces: 'produced',
  'observed-at': 'observed at',
  evidence: 'evidence in',
  subject: 'concerns algorithm',
  implements: 'implements',
  supplies: 'supplies',
  exposes: 'exposes',
  correlates: 'correlates',
  remediates: 'remediated by',
  assessed: 'assessed',
  connects: 'connects to',
  hosts: 'hosts',
};

/** The lens (tab) a viewer is looking through. Each selects node kinds. */
export type WorkflowLens =
  | 'flow'
  | 'process'
  | 'code'
  | 'algorithms'
  | 'cbom'
  | 'supply'
  | 'correlation'
  | 'remediation';

export interface WorkflowLensDefinition {
  id: WorkflowLens;
  label: string;
  /** One sentence shown under the tab strip. */
  description: string;
  /** Node kinds this lens admits. */
  kinds: WorkflowNodeKind[];
  /** How the canvas groups nodes into compound boxes by default. */
  groupBy: WorkflowGrouping;
}

export type WorkflowGrouping = 'none' | 'phase' | 'layer' | 'severity' | 'kind' | 'environment' | 'criticality';

export const GROUPING_LABEL: Record<WorkflowGrouping, string> = {
  none: 'None',
  phase: 'Phase',
  layer: 'Layer',
  severity: 'Risk',
  kind: 'Type',
  environment: 'Environment',
  criticality: 'Criticality',
};

/**
 * The eight lenses.
 *
 * Every lens is a projection of the SAME graph — nothing is recomputed per tab
 * — so a node's severity, size and relationships cannot disagree between them.
 */
export const WORKFLOW_LENSES: WorkflowLensDefinition[] = [
  {
    id: 'flow',
    label: 'Exposure Flow',
    description:
      'The whole assessment as one chain: the scan, the lifecycle phases it ran, the engine processes each phase spawned, and the findings and cryptography they reached.',
    kinds: ['scan', 'phase', 'engine', 'finding', 'algorithm', 'layer'],
    groupBy: 'phase',
  },
  {
    id: 'process',
    label: 'Process Tree',
    description:
      'Parent and child processes only. Phases spawn engines; an engine that requires another engine’s output is drawn behind it in dependency order.',
    kinds: ['scan', 'phase', 'engine'],
    groupBy: 'phase',
  },
  {
    id: 'code',
    label: 'Code & Layers',
    description:
      'Where the evidence physically sits: the files that were read, the findings observed in them and the layer each observation belongs to.',
    kinds: ['file', 'finding', 'layer', 'secret'],
    groupBy: 'layer',
  },
  {
    id: 'algorithms',
    label: 'Algorithms',
    description:
      'Cryptography as the centre of gravity: each algorithm and every finding that concerns it, coloured by quantum verdict where you switch colour to Type.',
    kinds: ['algorithm', 'finding', 'component', 'layer'],
    groupBy: 'severity',
  },
  {
    id: 'cbom',
    label: 'CBOM Graph',
    description:
      'The Cryptographic Bill of Materials as a graph — components, the algorithms they implement and the declared dependency edges between them.',
    kinds: ['component', 'algorithm', 'dependency', 'layer'],
    groupBy: 'layer',
  },
  {
    id: 'supply',
    label: 'Supply Chain',
    description:
      'Third-party origin of cryptography: packages that were declared, the components they supply and the findings that reference them.',
    kinds: ['dependency', 'component', 'algorithm', 'finding'],
    groupBy: 'kind',
  },
  {
    id: 'correlation',
    label: 'Correlation',
    description:
      'One exposure, many observations. Each correlated exposure with the individual findings that collapsed into it and the layers they were seen at.',
    kinds: ['exposure', 'finding', 'layer', 'algorithm'],
    groupBy: 'severity',
  },
  {
    id: 'remediation',
    label: 'Remediation',
    description:
      'The forward path: findings grouped under the recommended action that closes them, sized by how many findings each action clears.',
    kinds: ['remediation', 'finding', 'algorithm', 'exposure'],
    groupBy: 'severity',
  },
];

/* ──────────────────────────────────────────────────────────────── the phases ── */

export type WorkflowPhaseId = 'acquisition' | 'analysis' | 'synthesis' | 'correlation' | 'scoring';

interface PhaseDefinition {
  id: WorkflowPhaseId;
  label: string;
  detail: string;
}

/**
 * The lifecycle the orchestrator actually walks (see `orchestrator.ts`:
 * discovering → analyzing → correlating → scoring). Engines are attached to a
 * phase by their declared capability, so the tree is read out of the registry
 * rather than hand-listed here.
 */
const PHASES: PhaseDefinition[] = [
  { id: 'acquisition', label: 'Acquisition', detail: 'Enumerate and classify the authorised corpus.' },
  { id: 'analysis', label: 'Analysis', detail: 'Read the corpus with every applicable detection engine.' },
  { id: 'synthesis', label: 'Synthesis', detail: 'Compose the CBOM and derive the quantum verdicts.' },
  { id: 'correlation', label: 'Correlation', detail: 'Collapse repeated observations into single exposures.' },
  { id: 'scoring', label: 'Scoring', detail: 'Publish the risk, quantum, coverage and confidence readings.' },
];

const SYNTHESIS_CAPABILITIES: EngineCapability[] = ['cbom', 'quantum', 'supply-chain'];

function phaseForCapability(capability: EngineCapability): WorkflowPhaseId {
  if (capability === 'discovery') return 'acquisition';
  if (SYNTHESIS_CAPABILITIES.includes(capability)) return 'synthesis';
  return 'analysis';
}

/* ────────────────────────────────────────────────────────────────── the model ── */

export interface WorkflowNode {
  id: string;
  kind: WorkflowNodeKind;
  label: string;
  /** Second line in the inspector; never rendered on the canvas. */
  sublabel?: string;
  /**
   * Highest severity of the findings behind this node. `null` means NO finding
   * is attached — rendered "None", never as a pass.
   */
  severity: FindingSeverity | null;
  /** Lowest confidence among contributing evidence, or null when none applies. */
  confidence: FindingConfidence | null;
  /** How the platform knows this node exists. */
  detection: DetectionMethod;
  quantumStatus: QuantumStatus | null;
  /** Findings attached to this node. Drives size and the inspector list. */
  findingIds: string[];
  /** Count used for sizing; equals findingIds.length except on scan/phase rollups. */
  weight: number;
  /** Compound-node membership, one per grouping mode. */
  groups: Partial<Record<WorkflowGrouping, string>>;
  layer?: ExposureLayer;
  phase?: WorkflowPhaseId;
  /** Free-form facts for the inspector, in render order. */
  facts: Array<{ label: string; value: string }>;
  /** Present on finding nodes so the inspector can open the real detail sheet. */
  findingRef?: string;
  /** True when the engine reached a terminal state that produced nothing. */
  state?: string;
}

export interface WorkflowEdge {
  id: string;
  source: string;
  target: string;
  kind: WorkflowEdgeKind;
  /** Severity inherited from the more severe endpoint; drives edge colour. */
  severity: FindingSeverity | null;
  /** Inferred edges are dashed and hidden with the inferred toggle. */
  detection: DetectionMethod;
}

export interface WorkflowCluster {
  id: string;
  label: string;
  grouping: WorkflowGrouping;
  /** Accent used for the compound box border. */
  severity: FindingSeverity | null;
}

export interface WorkflowGraph {
  nodes: WorkflowNode[];
  edges: WorkflowEdge[];
  clusters: WorkflowCluster[];
  /** Node totals per entity type, before any UI filter. */
  counts: Record<WorkflowNodeKind, number>;
  /**
   * The reconciliation contract: what the graph projected vs. what the
   * assessment holds. The UI prints this so a reader can verify the picture
   * has not invented or silently dropped anything.
   */
  reconciliation: {
    findingsInAssessment: number;
    findingsProjected: number;
    componentsInAssessment: number;
    componentsProjected: number;
    exposuresInAssessment: number;
    exposuresProjected: number;
  };
  truncation: {
    truncated: boolean;
    /** Per-kind counts that were capped, highest severity retained. */
    dropped: Array<{ kind: WorkflowNodeKind; dropped: number; total: number }>;
  };
}

/* ─────────────────────────────────────────────────────────────────── limits ── */

/**
 * Per-kind caps. A force layout stops being readable — and stops being
 * interactive on a laptop — well before a thousand bodies, so the projection is
 * bounded by severity rank and the caller states what it dropped.
 */
const CAPS: Partial<Record<WorkflowNodeKind, number>> = {
  finding: 160,
  file: 70,
  algorithm: 40,
  component: 90,
  dependency: 60,
  secret: 40,
  exposure: 60,
  remediation: 30,
};

/* ────────────────────────────────────────────────────────────────── helpers ── */

function worseSeverity(a: FindingSeverity | null, b: FindingSeverity | null): FindingSeverity | null {
  if (a === null) return b;
  if (b === null) return a;
  return SEVERITY_ORDER[a] <= SEVERITY_ORDER[b] ? a : b;
}

const CONFIDENCE_RANK: Record<FindingConfidence, number> = { high: 3, medium: 2, low: 1, unknown: 0 };

function weakerConfidence(a: FindingConfidence | null, b: FindingConfidence | null): FindingConfidence | null {
  if (a === null) return b;
  if (b === null) return a;
  return CONFIDENCE_RANK[a] <= CONFIDENCE_RANK[b] ? a : b;
}

const QUANTUM_RANK: Record<QuantumStatus, number> = {
  vulnerable: 5,
  hybrid: 4,
  pqc: 3,
  resistant: 2,
  unknown: 1,
  'not-applicable': 0,
};

function dominantQuantum(a: QuantumStatus | null, b: QuantumStatus | null): QuantumStatus | null {
  if (a === null) return b;
  if (b === null) return a;
  return QUANTUM_RANK[a] >= QUANTUM_RANK[b] ? a : b;
}

/** Trim a path to something that fits a node label without losing identity. */
function shortenPath(path: string, max = 30): string {
  const clean = path.replace(/\\/g, '/');
  if (clean.length <= max) return clean;
  const parts = clean.split('/');
  const file = parts[parts.length - 1] ?? clean;
  if (file.length >= max) return `…${file.slice(-(max - 1))}`;
  const parent = parts[parts.length - 2];
  const candidate = parent ? `${parent}/${file}` : file;
  return candidate.length <= max ? `…/${candidate}` : `…/${file}`;
}

function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}

/* ───────────────────────────────────────────────────────────── the projection ── */

export interface BuildWorkflowGraphOptions {
  /**
   * Engine descriptors for the assessed mode. Supplies the `dependsOn` edges
   * that make the process tree a real dependency graph rather than a flat list.
   */
  descriptors?: EngineDescriptor[];
}

/**
 * Project an assessment onto the workflow graph.
 *
 * Pure and deterministic: the same assessment always yields the same node ids,
 * which is what lets a selection survive a re-render and a re-layout.
 */
export function buildWorkflowGraph(
  assessment: ExposureAssessment,
  options: BuildWorkflowGraphOptions = {},
): WorkflowGraph {
  const nodes = new Map<string, WorkflowNode>();
  const edges = new Map<string, WorkflowEdge>();
  const clusters = new Map<string, WorkflowCluster>();
  const dropped: WorkflowGraph['truncation']['dropped'] = [];

  const descriptorById = new Map((options.descriptors ?? []).map((entry) => [entry.id, entry]));

  const addNode = (node: WorkflowNode) => {
    const existing = nodes.get(node.id);
    if (!existing) {
      /* The node OWNS its arrays. Call sites pass `exposure.findingIds` and
         `recommendation.findingIds` straight from the assessment, and the merge
         below pushes into them — so without this copy a derived view would
         write back into the source of truth. It did: two recommendations that
         share a title merged, and the push landed in the array the assessment's
         own exposure row was pointing at, silently adding an observation to a
         correlated exposure that never had one. */
      nodes.set(node.id, { ...node, findingIds: [...node.findingIds], facts: [...node.facts] });
      return nodes.get(node.id)!;
    }
    /* Merge rather than replace: a node reached from two directions keeps the
       worst severity and the weakest confidence it has been shown. */
    existing.severity = worseSeverity(existing.severity, node.severity);
    existing.confidence = weakerConfidence(existing.confidence, node.confidence);
    existing.quantumStatus = dominantQuantum(existing.quantumStatus, node.quantumStatus);
    for (const id of node.findingIds) if (!existing.findingIds.includes(id)) existing.findingIds.push(id);
    existing.weight = Math.max(existing.weight, node.weight, existing.findingIds.length);
    existing.groups = { ...node.groups, ...existing.groups };
    for (const fact of node.facts) {
      if (!existing.facts.some((entry) => entry.label === fact.label)) existing.facts.push(fact);
    }
    return existing;
  };

  const addEdge = (
    source: string,
    target: string,
    kind: WorkflowEdgeKind,
    severity: FindingSeverity | null,
    detection: DetectionMethod,
  ) => {
    if (source === target) return;
    /* `correlates` is a symmetric relation. Stored directionally it becomes two
       edges drawn on top of each other, which doubles the stroke count and the
       degree the layout has to satisfy for no added meaning. */
    const [from, to] = kind === 'correlates' && source > target ? [target, source] : [source, target];
    const id = `${from}->${to}:${kind}`;
    const existing = edges.get(id);
    if (existing) {
      existing.severity = worseSeverity(existing.severity, severity);
      return;
    }
    edges.set(id, { id, source: from, target: to, kind, severity, detection });
  };

  /**
   * An id that is unique within the graph.
   *
   * Two source rows may legitimately share the text a node id is derived from —
   * the recommendation engine really does emit the same title twice for two
   * different populations. Collapsing them would make the graph show fewer
   * remediations than the panel above it, which is exactly the kind of quiet
   * disagreement `reconciliation` exists to make impossible.
   */
  const claimId = (base: string): string => {
    if (!nodes.has(base)) return base;
    let suffix = 2;
    while (nodes.has(`${base}~${suffix}`)) suffix += 1;
    return `${base}~${suffix}`;
  };

  const addCluster = (id: string, label: string, grouping: WorkflowGrouping, severity: FindingSeverity | null) => {
    const existing = clusters.get(id);
    if (existing) {
      existing.severity = worseSeverity(existing.severity, severity);
      return;
    }
    clusters.set(id, { id, label, grouping, severity });
  };

  /* ── findings, ranked and bounded ─────────────────────────────────────── */

  const allFindings = [...assessment.findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );
  const findingCap = CAPS.finding ?? allFindings.length;
  const findings = allFindings.slice(0, findingCap);
  if (allFindings.length > findings.length) {
    dropped.push({ kind: 'finding', dropped: allFindings.length - findings.length, total: allFindings.length });
  }
  const projectedFindingIds = new Set(findings.map((finding) => finding.id));

  const severityOfFindings = (list: ExposureFinding[]): FindingSeverity | null =>
    list.reduce<FindingSeverity | null>((worst, finding) => worseSeverity(worst, finding.severity), null);

  /* ── 1. the scan root ─────────────────────────────────────────────────── */

  const task = assessment.task;
  const scanId = `scan:${task.scanId}`;
  const overallSeverity = severityOfFindings(findings);
  const targetLabel =
    task.target.kind === 'local'
      ? task.target.rootName
      : task.target.kind === 'repository'
        ? `${task.target.owner}/${task.target.repo}`
        : task.target.kind === 'web'
          ? task.target.host
          : task.target.kind === 'container'
            ? task.target.image
            : task.target.kind === 'kubernetes'
              ? task.target.cluster
              : task.target.account;

  addNode({
    id: scanId,
    kind: 'scan',
    label: truncate(targetLabel, 26),
    sublabel: `${task.mode.toUpperCase()} assessment · ${task.profileId}`,
    severity: overallSeverity,
    confidence: null,
    detection: 'observed',
    quantumStatus: null,
    findingIds: findings.map((finding) => finding.id),
    weight: Math.max(findings.length, 6),
    groups: {},
    facts: [
      { label: 'Scan id', value: task.scanId },
      { label: 'Mode', value: task.mode.toUpperCase() },
      { label: 'Profile', value: task.profileId },
      { label: 'Status', value: task.status },
      { label: 'Engines selected', value: String(task.engines.length) },
      { label: 'Findings', value: String(assessment.findings.length) },
      { label: 'Files analysed', value: task.coverage.filesAnalyzed.toLocaleString() },
      { label: 'Local only', value: task.localOnly ? 'Yes — nothing left the device' : 'No' },
    ],
    state: task.status,
  });

  /* ── 2. phases (parent processes) ─────────────────────────────────────── */

  const runsByEngine = new Map(task.runs.map((run) => [run.engineId, run]));
  const findingsByEngine = new Map<string, ExposureFinding[]>();
  for (const finding of findings) {
    const list = findingsByEngine.get(finding.engineId);
    if (list) list.push(finding);
    else findingsByEngine.set(finding.engineId, [finding]);
  }

  /* Only phases that actually have work attached are drawn. Correlation and
     scoring are orchestrator-owned and appear when they produced something. */
  const enginePhase = new Map<string, WorkflowPhaseId>();
  for (const run of task.runs) {
    const descriptor = descriptorById.get(run.engineId);
    const capability = descriptor?.capability ?? 'crypto';
    enginePhase.set(run.engineId, phaseForCapability(capability));
  }

  const activePhases = new Set<WorkflowPhaseId>(enginePhase.size ? [...enginePhase.values()] : []);
  if (assessment.exposures.length > 0) activePhases.add('correlation');
  if (task.scores.securityRisk !== null || task.scores.quantumRisk !== null) activePhases.add('scoring');

  for (const phase of PHASES) {
    if (!activePhases.has(phase.id)) continue;
    const phaseEngines = task.runs.filter((run) => enginePhase.get(run.engineId) === phase.id);
    /* Correlation runs no engine of its own — its work is the exposures it
       produced. Attributing their contributing findings to the phase is what
       makes its severity band traceable: a phase that shows "High" can be
       clicked through to the observations that earned it, instead of asserting
       a colour with nothing behind it. */
    const phaseFindings =
      phase.id === 'correlation'
        ? assessment.exposures
            .flatMap((exposure) => exposure.findingIds)
            .filter((id, index, list) => list.indexOf(id) === index)
            .map((id) => findings.find((finding) => finding.id === id))
            .filter((finding): finding is ExposureFinding => Boolean(finding))
        : phaseEngines.flatMap((run) => findingsByEngine.get(run.engineId) ?? []);
    const phaseSeverity = severityOfFindings(phaseFindings);

    const id = `phase:${phase.id}`;
    addCluster(`group:phase:${phase.id}`, phase.label, 'phase', phaseSeverity);
    addNode({
      id,
      kind: 'phase',
      label: phase.label,
      sublabel: phase.detail,
      severity: phaseSeverity,
      confidence: null,
      detection: 'observed',
      quantumStatus: null,
      findingIds: phaseFindings.map((finding) => finding.id),
      weight: Math.max(phaseFindings.length, phaseEngines.length, 4),
      groups: { phase: `group:phase:${phase.id}`, kind: 'group:kind:phase' },
      phase: phase.id,
      facts: [
        { label: 'Stage', value: phase.detail },
        { label: 'Processes', value: String(phaseEngines.length) },
        ...(phase.id === 'correlation'
          ? [{ label: 'Exposures produced', value: String(assessment.exposures.length) }]
          : phase.id === 'scoring'
            ? [
                { label: 'Security risk', value: task.scores.securityRisk === null ? 'Not measured' : String(task.scores.securityRisk) },
                { label: 'Quantum risk', value: task.scores.quantumRisk === null ? 'Not measured' : String(task.scores.quantumRisk) },
                { label: 'Coverage', value: task.scores.coverage === null ? 'Not measured' : `${task.scores.coverage}%` },
              ]
            : [{ label: 'Findings from stage', value: String(phaseFindings.length) }]),
      ],
    });
    addEdge(scanId, id, 'orchestrates', phaseSeverity, 'observed');
  }

  /* Phases run in order; draw the hand-off so the workflow reads left to right. */
  const orderedActive = PHASES.filter((phase) => activePhases.has(phase.id));
  for (let index = 1; index < orderedActive.length; index += 1) {
    addEdge(
      `phase:${orderedActive[index - 1].id}`,
      `phase:${orderedActive[index].id}`,
      'requires',
      null,
      'observed',
    );
  }

  /* ── 3. engines (child processes) ─────────────────────────────────────── */

  for (const run of task.runs) {
    const descriptor = descriptorById.get(run.engineId);
    const phase = enginePhase.get(run.engineId) ?? 'analysis';
    const engineFindings = findingsByEngine.get(run.engineId) ?? [];
    const severity = severityOfFindings(engineFindings);
    const id = `engine:${run.engineId}`;

    addNode({
      id,
      kind: 'engine',
      label: truncate(run.label || descriptor?.label || run.engineId, 24),
      sublabel: descriptor?.description,
      severity,
      confidence: null,
      detection: 'observed',
      quantumStatus: null,
      findingIds: engineFindings.map((finding) => finding.id),
      weight: Math.max(engineFindings.length, 2),
      groups: { phase: `group:phase:${phase}`, kind: 'group:kind:engine' },
      phase,
      layer: descriptor?.layer,
      facts: [
        { label: 'Engine id', value: run.engineId },
        { label: 'State', value: run.state },
        { label: 'Capability', value: descriptor ? CAPABILITY_LABEL[descriptor.capability] : '—' },
        { label: 'Layer', value: descriptor ? layerLabel(descriptor.layer) : '—' },
        { label: 'Findings', value: String(run.findingCount) },
        ...(run.detail ? [{ label: 'Detail', value: run.detail }] : []),
        ...(descriptor?.dependsOn?.length
          ? [{ label: 'Requires', value: descriptor.dependsOn.join(', ') }]
          : []),
        ...(run.units ? [{ label: 'Work', value: `${run.units.done.toLocaleString()} / ${run.units.total.toLocaleString()} ${run.units.unit}` }] : []),
      ],
      state: run.state,
    });
    addEdge(`phase:${phase}`, id, 'spawns', severity, 'observed');
  }

  /* Engine → engine dependency edges: the real parent/child process chain, read
     out of the registry rather than assumed from ordering. */
  for (const run of task.runs) {
    const descriptor = descriptorById.get(run.engineId);
    for (const parent of descriptor?.dependsOn ?? []) {
      if (!runsByEngine.has(parent)) continue;
      addEdge(`engine:${run.engineId}`, `engine:${parent}`, 'requires', null, 'observed');
    }
  }

  /* ── 4. layers ────────────────────────────────────────────────────────── */

  const layersSeen = new Map<ExposureLayer, ExposureFinding[]>();
  for (const finding of findings) {
    const list = layersSeen.get(finding.layer);
    if (list) list.push(finding);
    else layersSeen.set(finding.layer, [finding]);
  }
  for (const [layer, list] of layersSeen) {
    const severity = severityOfFindings(list);
    addCluster(`group:layer:${layer}`, layerLabel(layer), 'layer', severity);
    addNode({
      id: `layer:${layer}`,
      kind: 'layer',
      label: layerLabel(layer),
      severity,
      confidence: null,
      detection: 'observed',
      quantumStatus: null,
      findingIds: list.map((finding) => finding.id),
      weight: Math.max(list.length, 3),
      groups: { layer: `group:layer:${layer}`, kind: 'group:kind:layer' },
      layer,
      facts: [
        { label: 'Layer', value: layerLabel(layer) },
        { label: 'Findings at layer', value: String(list.length) },
        {
          label: 'Components at layer',
          value: String(assessment.intelligence.byLayer.find((entry) => entry.layer === layer)?.components ?? 0),
        },
      ],
    });
  }

  /* ── 5. findings ──────────────────────────────────────────────────────── */

  const fileNodes = new Map<string, ExposureFinding[]>();

  /**
   * Which correlated exposures each finding belongs to.
   *
   * Engines set `relatedTo` to every sibling in a correlation group, so drawing
   * those links literally produces a near-complete CLIQUE: a 25-finding group
   * becomes 600 edges that all say the same thing the group already says. On a
   * real corpus that was 1,738 of 2,366 edges — three quarters of the canvas
   * spent restating one fact, at a cost the force layout cannot absorb.
   *
   * The correlated exposure node already carries that relationship as a STAR
   * (n edges, one hub), so a sibling link is drawn only when the two findings
   * do NOT already share an exposure — i.e. only when it says something the
   * hub does not.
   */
  const exposureKeysByFinding = new Map<string, Set<string>>();
  for (const exposure of assessment.exposures) {
    for (const memberId of exposure.findingIds) {
      const keys = exposureKeysByFinding.get(memberId);
      if (keys) keys.add(exposure.key);
      else exposureKeysByFinding.set(memberId, new Set([exposure.key]));
    }
  }

  for (const finding of findings) {
    const id = `finding:${finding.id}`;
    const evidence = finding.evidence[0];
    addCluster(`group:severity:${finding.severity}`, finding.severity, 'severity', finding.severity);

    addNode({
      id,
      kind: 'finding',
      label: truncate(finding.title, 34),
      sublabel: finding.description,
      severity: finding.severity,
      confidence: finding.confidence,
      detection: finding.detection,
      quantumStatus: finding.quantumStatus,
      findingIds: [finding.id],
      weight: 1,
      groups: {
        phase: `group:phase:${enginePhase.get(finding.engineId) ?? 'analysis'}`,
        layer: `group:layer:${finding.layer}`,
        severity: `group:severity:${finding.severity}`,
        kind: 'group:kind:finding',
      },
      layer: finding.layer,
      phase: enginePhase.get(finding.engineId),
      findingRef: finding.id,
      facts: [
        { label: 'Category', value: finding.subcategory ? `${finding.category} · ${finding.subcategory}` : finding.category },
        { label: 'Severity', value: finding.severity },
        { label: 'Confidence', value: finding.confidence },
        { label: 'Detection', value: finding.detection },
        { label: 'Layer', value: layerLabel(finding.layer) },
        ...(finding.canonicalAlgorithm || finding.algorithm
          ? [{ label: 'Algorithm', value: finding.canonicalAlgorithm ?? finding.algorithm! }]
          : []),
        ...(finding.role ? [{ label: 'Role', value: finding.role }] : []),
        ...(evidence?.file ? [{ label: 'Evidence', value: `${evidence.file}${evidence.line ? `:${evidence.line}` : ''}` }] : []),
        ...(finding.migration?.candidate ? [{ label: 'Migration', value: `${finding.migration.priority ?? 'P?'} → ${finding.migration.target ?? 'PQC target'}` }] : []),
      ],
    });

    addEdge(`engine:${finding.engineId}`, id, 'produces', finding.severity, 'observed');
    if (layersSeen.has(finding.layer)) {
      addEdge(id, `layer:${finding.layer}`, 'observed-at', finding.severity, 'observed');
    }

    /* File evidence: the artefact the observation physically sits in. */
    const file = evidence?.file;
    if (file) {
      const list = fileNodes.get(file);
      if (list) list.push(finding);
      else fileNodes.set(file, [finding]);
    }

    /* Explicit finding→finding relationships the engines declared, minus the
       ones the exposure hub already expresses (see the index above). */
    const ownKeys = exposureKeysByFinding.get(finding.id);
    for (const related of finding.relatedTo ?? []) {
      if (!projectedFindingIds.has(related)) continue;
      const relatedKeys = exposureKeysByFinding.get(related);
      if (ownKeys && relatedKeys && [...ownKeys].some((key) => relatedKeys.has(key))) continue;
      addEdge(id, `finding:${related}`, 'correlates', finding.severity, 'inferred');
    }
  }

  /* ── 6. files ─────────────────────────────────────────────────────────── */

  const rankedFiles = [...fileNodes.entries()].sort((a, b) => {
    const bySeverity = SEVERITY_ORDER[severityOfFindings(a[1]) ?? 'info'] - SEVERITY_ORDER[severityOfFindings(b[1]) ?? 'info'];
    return bySeverity !== 0 ? bySeverity : b[1].length - a[1].length;
  });
  const fileCap = CAPS.file ?? rankedFiles.length;
  if (rankedFiles.length > fileCap) {
    dropped.push({ kind: 'file', dropped: rankedFiles.length - fileCap, total: rankedFiles.length });
  }
  for (const [path, list] of rankedFiles.slice(0, fileCap)) {
    const severity = severityOfFindings(list);
    const id = `file:${stableHash(path)}`;
    addNode({
      id,
      kind: 'file',
      label: shortenPath(path),
      sublabel: path,
      severity,
      confidence: null,
      detection: 'observed',
      quantumStatus: null,
      findingIds: list.map((finding) => finding.id),
      weight: list.length,
      groups: {
        layer: `group:layer:${list[0].layer}`,
        severity: severity ? `group:severity:${severity}` : undefined,
        kind: 'group:kind:file',
      },
      layer: list[0].layer,
      facts: [
        { label: 'Path', value: path },
        { label: 'Findings in file', value: String(list.length) },
        { label: 'Read locally only', value: list[0].evidence[0]?.localOnly ? 'Yes' : 'Not stated' },
      ],
    });
    for (const finding of list) {
      addEdge(`finding:${finding.id}`, id, 'evidence', finding.severity, 'observed');
    }
  }

  /* ── 7. algorithms ────────────────────────────────────────────────────── */

  const algorithmFindings = new Map<string, ExposureFinding[]>();
  for (const finding of findings) {
    const name = finding.canonicalAlgorithm ?? finding.algorithm;
    if (!name) continue;
    const list = algorithmFindings.get(name);
    if (list) list.push(finding);
    else algorithmFindings.set(name, [finding]);
  }
  const rankedAlgorithms = [...algorithmFindings.entries()].sort((a, b) => {
    const bySeverity = SEVERITY_ORDER[severityOfFindings(a[1]) ?? 'info'] - SEVERITY_ORDER[severityOfFindings(b[1]) ?? 'info'];
    return bySeverity !== 0 ? bySeverity : b[1].length - a[1].length;
  });
  const algorithmCap = CAPS.algorithm ?? rankedAlgorithms.length;
  if (rankedAlgorithms.length > algorithmCap) {
    dropped.push({ kind: 'algorithm', dropped: rankedAlgorithms.length - algorithmCap, total: rankedAlgorithms.length });
  }
  const algorithmNodeIds = new Map<string, string>();
  for (const [name, list] of rankedAlgorithms.slice(0, algorithmCap)) {
    const severity = severityOfFindings(list);
    const quantum = list.reduce<QuantumStatus | null>((worst, finding) => dominantQuantum(worst, finding.quantumStatus), null);
    const canonical = describeAlgorithm(name);
    const id = `algorithm:${stableHash(name)}`;
    algorithmNodeIds.set(name, id);
    addNode({
      id,
      kind: 'algorithm',
      label: truncate(name, 22),
      sublabel: canonical?.standard,
      severity,
      confidence: list.reduce<FindingConfidence | null>((weakest, finding) => weakerConfidence(weakest, finding.confidence), null),
      /* An algorithm node is a CONCLUSION about the corpus, not an artefact
         that was read. It is inferred, and the inferred toggle can hide it. */
      detection: 'inferred',
      quantumStatus: quantum,
      findingIds: list.map((finding) => finding.id),
      weight: list.length,
      groups: {
        severity: severity ? `group:severity:${severity}` : undefined,
        kind: 'group:kind:algorithm',
        layer: `group:layer:${list[0].layer}`,
      },
      layer: list[0].layer,
      facts: [
        { label: 'Algorithm', value: name },
        ...(canonical?.standard ? [{ label: 'Standard', value: canonical.standard }] : []),
        ...(canonical?.family ? [{ label: 'Family', value: canonical.family }] : []),
        { label: 'Findings', value: String(list.length) },
        ...(canonical
          ? [
              { label: 'Shor-broken', value: canonical.shorBroken ? 'Yes' : 'No' },
              { label: 'Grover-affected', value: canonical.groverAffected ? 'Yes' : 'No' },
              ...(canonical.classicallyWeak ? [{ label: 'Classically weak', value: 'Yes' }] : []),
            ]
          : []),
      ],
    });
    for (const finding of list) {
      addEdge(`finding:${finding.id}`, id, 'subject', finding.severity, 'inferred');
    }
  }

  /* ── 8. CBOM components ───────────────────────────────────────────────── */

  const rankedComponents: CbomComponent[] = [...assessment.cbom].sort(
    (a, b) => QUANTUM_RANK[b.quantumStatus] - QUANTUM_RANK[a.quantumStatus],
  );
  const componentCap = CAPS.component ?? rankedComponents.length;
  if (rankedComponents.length > componentCap) {
    dropped.push({ kind: 'component', dropped: rankedComponents.length - componentCap, total: rankedComponents.length });
  }
  const projectedComponents = rankedComponents.slice(0, componentCap);
  const componentIds = new Set(projectedComponents.map((component) => component.id));

  for (const component of projectedComponents) {
    const id = `component:${component.id}`;
    const label = component.library ?? component.package ?? component.algorithm;
    addNode({
      id,
      kind: 'component',
      label: truncate(label, 22),
      sublabel: `${component.canonicalAlgorithm} · ${component.usage}`,
      /* A CBOM component is an inventory entry, not a defect. It carries no
         severity of its own — only the quantum verdict. */
      severity: null,
      confidence: component.confidence,
      detection: component.detection,
      quantumStatus: component.quantumStatus,
      findingIds: [],
      weight: 1 + (component.dependsOn?.length ?? 0),
      groups: { layer: `group:layer:${component.layer}`, kind: 'group:kind:component' },
      layer: component.layer,
      facts: [
        { label: 'Algorithm', value: component.canonicalAlgorithm },
        { label: 'Usage', value: component.usage },
        ...(component.library ? [{ label: 'Library', value: component.library }] : []),
        ...(component.package ? [{ label: 'Package', value: component.package }] : []),
        ...(component.version ? [{ label: 'Version', value: component.version }] : []),
        ...(component.keySize ? [{ label: 'Key size', value: `${component.keySize} bit` }] : []),
        ...(component.file ? [{ label: 'Location', value: `${component.file}${component.line ? `:${component.line}` : ''}` }] : []),
        { label: 'Detection', value: component.detection },
        { label: 'Layer', value: layerLabel(component.layer) },
      ],
    });

    const algorithmNode = algorithmNodeIds.get(component.canonicalAlgorithm);
    if (algorithmNode) addEdge(id, algorithmNode, 'implements', null, 'inferred');
    for (const parent of component.dependsOn ?? []) {
      if (!componentIds.has(parent)) continue;
      addEdge(id, `component:${parent}`, 'requires', null, 'inferred');
    }
  }

  /* ── 9. dependencies ──────────────────────────────────────────────────── */

  const cryptoDependencies = assessment.intelligence.dependencies.filter(
    (entry) => entry.cryptoRelevant || entry.quantumRelevant,
  );
  const dependencyCap = CAPS.dependency ?? cryptoDependencies.length;
  if (cryptoDependencies.length > dependencyCap) {
    dropped.push({ kind: 'dependency', dropped: cryptoDependencies.length - dependencyCap, total: cryptoDependencies.length });
  }
  for (const dependency of cryptoDependencies.slice(0, dependencyCap)) {
    const id = `dependency:${stableHash(`${dependency.ecosystem}|${dependency.name}`)}`;
    addNode({
      id,
      kind: 'dependency',
      label: truncate(dependency.name, 22),
      sublabel: `${dependency.ecosystem} · ${dependency.version}`,
      severity: null,
      confidence: null,
      detection: 'observed',
      quantumStatus: dependency.quantumRelevant ? 'unknown' : null,
      findingIds: [],
      weight: dependency.direct ? 3 : 2,
      groups: { layer: 'group:layer:dependency', kind: 'group:kind:dependency' },
      layer: 'dependency',
      facts: [
        { label: 'Package', value: dependency.name },
        { label: 'Version', value: dependency.version },
        { label: 'Ecosystem', value: dependency.ecosystem },
        { label: 'Resolution', value: dependency.direct ? 'Direct' : 'Transitive' },
        { label: 'Crypto relevant', value: dependency.cryptoRelevant ? 'Yes' : 'No' },
        { label: 'Quantum relevant', value: dependency.quantumRelevant ? 'Yes' : 'No' },
      ],
    });

    /* Link a package to the components it supplies, matched on the package or
       library name the CBOM recorded — never on a substring guess. */
    for (const component of projectedComponents) {
      if (component.package !== dependency.name && component.library !== dependency.name) continue;
      addEdge(id, `component:${component.id}`, 'supplies', null, 'inferred');
    }
    /* And to the findings that named it as their library. */
    for (const finding of findings) {
      if (finding.library !== dependency.name && finding.component !== dependency.name) continue;
      addEdge(id, `finding:${finding.id}`, 'supplies', finding.severity, 'inferred');
    }
  }

  /* ── 10. secrets ──────────────────────────────────────────────────────── */

  const secretCap = CAPS.secret ?? assessment.intelligence.secrets.length;
  const rankedSecrets = [...assessment.intelligence.secrets].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );
  if (rankedSecrets.length > secretCap) {
    dropped.push({ kind: 'secret', dropped: rankedSecrets.length - secretCap, total: rankedSecrets.length });
  }
  for (const secret of rankedSecrets.slice(0, secretCap)) {
    const id = `secret:${stableHash(`${secret.type}|${secret.location}`)}`;
    addNode({
      id,
      kind: 'secret',
      label: truncate(secret.type, 22),
      sublabel: secret.location,
      severity: secret.severity,
      confidence: secret.confidence,
      detection: 'observed',
      quantumStatus: null,
      findingIds: [],
      weight: 2,
      groups: {
        layer: 'group:layer:secret',
        severity: `group:severity:${secret.severity}`,
        kind: 'group:kind:secret',
      },
      layer: 'secret',
      facts: [
        { label: 'Type', value: secret.type },
        { label: 'Location', value: secret.location },
        { label: 'Severity', value: secret.severity },
        { label: 'Confidence', value: secret.confidence },
        /* The value is redacted at the source of truth; it is never carried. */
        { label: 'Value', value: secret.value },
        { label: 'Historical', value: secret.historical ? 'Found in Git history' : 'Present in working tree' },
      ],
    });
    /* Attach to the file it lives in when that file is on the canvas. */
    const path = secret.location.split(':')[0];
    const fileId = `file:${stableHash(path)}`;
    if (nodes.has(fileId)) addEdge(id, fileId, 'exposes', secret.severity, 'observed');
  }

  /* ── 11. correlated exposures ─────────────────────────────────────────── */

  const rankedExposures: CorrelatedExposure[] = [...assessment.exposures].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );
  const exposureCap = CAPS.exposure ?? rankedExposures.length;
  if (rankedExposures.length > exposureCap) {
    dropped.push({ kind: 'exposure', dropped: rankedExposures.length - exposureCap, total: rankedExposures.length });
  }
  const projectedExposures = rankedExposures.slice(0, exposureCap);
  for (const exposure of projectedExposures) {
    const id = claimId(`exposure:${stableHash(exposure.key)}`);
    addNode({
      id,
      kind: 'exposure',
      label: truncate(exposure.title, 30),
      sublabel: `${exposure.findingIds.length} observation${exposure.findingIds.length === 1 ? '' : 's'} across ${exposure.layers.length} layer${exposure.layers.length === 1 ? '' : 's'}`,
      severity: exposure.severity,
      confidence: exposure.confidence,
      detection: 'inferred',
      quantumStatus: exposure.quantumStatus,
      findingIds: exposure.findingIds,
      weight: Math.max(exposure.findingIds.length, 2),
      groups: { severity: `group:severity:${exposure.severity}`, kind: 'group:kind:exposure' },
      facts: [
        { label: 'Exposure', value: exposure.title },
        { label: 'Severity', value: exposure.severity },
        { label: 'Confidence', value: exposure.confidence },
        ...(exposure.canonicalAlgorithm ? [{ label: 'Algorithm', value: exposure.canonicalAlgorithm }] : []),
        ...(exposure.role ? [{ label: 'Role', value: exposure.role }] : []),
        { label: 'Contributing findings', value: String(exposure.findingIds.length) },
        { label: 'Layers', value: exposure.layers.map(layerLabel).join(' → ') },
        ...(exposure.path?.length ? [{ label: 'Cryptographic path', value: exposure.path.map((hop) => hop.label).join(' → ') }] : []),
      ],
    });
    for (const findingId of exposure.findingIds) {
      if (!projectedFindingIds.has(findingId)) continue;
      addEdge(id, `finding:${findingId}`, 'correlates', exposure.severity, 'inferred');
    }
    for (const layer of exposure.layers) {
      if (nodes.has(`layer:${layer}`)) addEdge(id, `layer:${layer}`, 'observed-at', exposure.severity, 'inferred');
    }
    if (exposure.canonicalAlgorithm) {
      const algorithmNode = algorithmNodeIds.get(exposure.canonicalAlgorithm);
      if (algorithmNode) addEdge(id, algorithmNode, 'subject', exposure.severity, 'inferred');
    }
    addEdge('phase:correlation', id, 'produces', exposure.severity, 'observed');
  }

  /* ── 12. remediation ──────────────────────────────────────────────────── */

  const remediationCap = CAPS.remediation ?? assessment.intelligence.recommendations.length;
  const rankedRemediations = [...assessment.intelligence.recommendations].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );
  if (rankedRemediations.length > remediationCap) {
    dropped.push({ kind: 'remediation', dropped: rankedRemediations.length - remediationCap, total: rankedRemediations.length });
  }
  for (const recommendation of rankedRemediations.slice(0, remediationCap)) {
    const id = claimId(`remediation:${stableHash(recommendation.title)}`);
    addNode({
      id,
      kind: 'remediation',
      label: truncate(recommendation.title, 30),
      sublabel: recommendation.detail,
      severity: recommendation.severity,
      confidence: null,
      detection: 'inferred',
      quantumStatus: null,
      findingIds: recommendation.findingIds,
      weight: Math.max(recommendation.findingIds.length, 2),
      groups: { severity: `group:severity:${recommendation.severity}`, kind: 'group:kind:remediation' },
      facts: [
        { label: 'Action', value: recommendation.title },
        { label: 'Detail', value: recommendation.detail },
        { label: 'Severity addressed', value: recommendation.severity },
        { label: 'Effort', value: recommendation.effort },
        { label: 'Findings closed', value: String(recommendation.findingIds.length) },
      ],
    });
    for (const findingId of recommendation.findingIds) {
      if (!projectedFindingIds.has(findingId)) continue;
      addEdge(`finding:${findingId}`, id, 'remediates', recommendation.severity, 'inferred');
    }
  }

  /* ── kind clusters, added last so their severity is fully aggregated ──── */

  for (const node of nodes.values()) {
    const kindGroup = node.groups.kind;
    if (!kindGroup) continue;
    addCluster(kindGroup, NODE_KIND_LABEL[node.kind], 'kind', node.severity);
  }

  /* ── counts + reconciliation ──────────────────────────────────────────── */

  const counts = Object.fromEntries(
    (Object.keys(NODE_KIND_LABEL) as WorkflowNodeKind[]).map((kind) => [kind, 0]),
  ) as Record<WorkflowNodeKind, number>;
  for (const node of nodes.values()) counts[node.kind] += 1;

  /* Drop edges whose endpoints were capped away, so the canvas never draws a
     line to a node that is not there. */
  const liveEdges = [...edges.values()].filter((edge) => nodes.has(edge.source) && nodes.has(edge.target));

  return {
    nodes: [...nodes.values()],
    edges: liveEdges,
    clusters: [...clusters.values()],
    counts,
    reconciliation: {
      findingsInAssessment: assessment.findings.length,
      findingsProjected: counts.finding,
      componentsInAssessment: assessment.cbom.length,
      componentsProjected: counts.component,
      exposuresInAssessment: assessment.exposures.length,
      exposuresProjected: counts.exposure,
    },
    truncation: { truncated: dropped.length > 0, dropped },
  };
}

/* ────────────────────────────────────────────────────────────── lens filter ── */

export interface LensProjection {
  nodes: WorkflowNode[];
  edges: WorkflowEdge[];
  clusters: WorkflowCluster[];
}

/**
 * Narrow a graph to one lens plus the operator's filters.
 *
 * Runs on the already-built graph — the model is computed once per assessment,
 * so switching tabs cannot change a node's severity, size or verdict.
 */
/**
 * The subgraph belonging to a set of FOCUSED entities.
 *
 * An estate graph is a hub-and-spoke: two assets with sixty findings each
 * produce a hairball in which neither asset's story can be read. Focusing one
 * asset has to keep everything attached to it — its findings, the components
 * and certificates it hosts, the algorithms those implement, the remediations
 * that close them and the scan that assessed it — while dropping the rest.
 *
 * The traversal is therefore breadth-first from the focused nodes, and it
 * STOPS at any other node of the focus kind. Without that rule an asset would
 * reach a shared algorithm (RSA-2048 is on both assets), cross it, and pull the
 * whole estate back in — the filter would appear to do nothing. Shared
 * algorithms still appear under BOTH assets, which is correct: they are
 * genuinely on both.
 *
 * Returns the ids to keep. Focus is a VIEW, never a recount: the graph's
 * reconciliation totals still describe the whole estate, and the caller states
 * that a focus is active.
 */
export function focusScope(
  graph: WorkflowGraph,
  focusIds: ReadonlySet<string>,
  focusKind: WorkflowNodeKind,
): Set<string> {
  const keep = new Set<string>(focusIds);
  if (focusIds.size === 0) return keep;

  const kindById = new Map(graph.nodes.map((node) => [node.id, node.kind]));
  const adjacency = new Map<string, string[]>();
  for (const edge of graph.edges) {
    if (!adjacency.has(edge.source)) adjacency.set(edge.source, []);
    if (!adjacency.has(edge.target)) adjacency.set(edge.target, []);
    adjacency.get(edge.source)!.push(edge.target);
    adjacency.get(edge.target)!.push(edge.source);
  }

  const frontier = [...focusIds];
  while (frontier.length > 0) {
    const id = frontier.pop()!;
    for (const neighbour of adjacency.get(id) ?? []) {
      // Never cross into another entity of the focus kind — that is the whole
      // point of focusing one of them.
      if (kindById.get(neighbour) === focusKind && !focusIds.has(neighbour)) continue;
      if (keep.has(neighbour)) continue;
      keep.add(neighbour);
      frontier.push(neighbour);
    }
  }
  return keep;
}

export function projectLens(
  graph: WorkflowGraph,
  options: {
    lens: WorkflowLensDefinition;
    /** Node kinds the operator has switched OFF. */
    hiddenKinds: ReadonlySet<WorkflowNodeKind>;
    /** When false, `inferred` and `potential` nodes are removed. */
    showInferred: boolean;
    grouping: WorkflowGrouping;
    /** Free-text match over label and sublabel. Empty means no filter. */
    query: string;
    /** Severity bands the operator has switched OFF. `none` covers severity null. */
    hiddenSeverities: ReadonlySet<FindingSeverity | 'none'>;
    /**
     * Entities the operator has focused on. Empty means the whole graph.
     * Applied BEFORE the lens so a focus keeps its subject's full story
     * whichever lens is open.
     */
    focusIds?: ReadonlySet<string>;
    /** The kind `focusIds` refers to. Traversal stops at other members of it. */
    focusKind?: WorkflowNodeKind;
  },
): LensProjection {
  const { lens, hiddenKinds, showInferred, grouping, query, hiddenSeverities, focusIds, focusKind } = options;
  const scope = focusIds && focusIds.size > 0 && focusKind ? focusScope(graph, focusIds, focusKind) : null;
  const admitted = new Set(lens.kinds);
  const needle = query.trim().toLowerCase();

  const nodes = graph.nodes.filter((node) => {
    if (scope && !scope.has(node.id)) return false;
    if (!admitted.has(node.kind)) return false;
    if (hiddenKinds.has(node.kind)) return false;
    if (!showInferred && (node.detection === 'inferred' || node.detection === 'potential')) return false;
    if (hiddenSeverities.has(node.severity ?? 'none')) return false;
    if (needle) {
      const haystack = `${node.label} ${node.sublabel ?? ''} ${node.facts.map((fact) => fact.value).join(' ')}`.toLowerCase();
      if (!haystack.includes(needle)) return false;
    }
    return true;
  });

  const live = new Set(nodes.map((node) => node.id));
  const edges = graph.edges.filter((edge) => {
    if (!live.has(edge.source) || !live.has(edge.target)) return false;
    if (!showInferred && edge.detection !== 'observed') return false;
    return true;
  });

  const usedGroups = new Set(
    nodes.map((node) => node.groups[grouping]).filter((value): value is string => Boolean(value)),
  );
  const clusters =
    grouping === 'none' ? [] : graph.clusters.filter((cluster) => cluster.grouping === grouping && usedGroups.has(cluster.id));

  return { nodes, edges, clusters };
}

/** Node ids one hop from `id`, in either direction. Used for hover highlight. */
export function neighboursOf(edges: readonly WorkflowEdge[], id: string): Set<string> {
  const result = new Set<string>([id]);
  for (const edge of edges) {
    if (edge.source === id) result.add(edge.target);
    else if (edge.target === id) result.add(edge.source);
  }
  return result;
}

/** Degree map, used to size nodes by how connected they are. */
export function degreeMap(edges: readonly WorkflowEdge[]): Map<string, number> {
  const degrees = new Map<string, number>();
  for (const edge of edges) {
    degrees.set(edge.source, (degrees.get(edge.source) ?? 0) + 1);
    degrees.set(edge.target, (degrees.get(edge.target) ?? 0) + 1);
  }
  return degrees;
}
