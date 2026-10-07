/**
 * QGuard Helix Exposure Assessment Engine™ — canonical domain model.
 *
 * ONE vocabulary shared by the three scan modes (WEB / LOCAL / DEV), by every
 * engine, by the orchestrator, by the API and by the UI. Engines never invent
 * their own result shape: they emit {@link ExposureFinding} and
 * {@link ExposureEvidence}, and everything downstream — correlation, scoring,
 * CBOM, persistence, Sophia — reads that one shape.
 *
 * DESIGN RULES (from the implementation specification)
 * ----------------------------------------------------
 * 1. SEVERITY IS NOT CONFIDENCE (§37). A finding may be Critical/Medium: the
 *    consequence if real, and how sure the scanner is that it is real. They are
 *    separate fields and are never collapsed into one number.
 * 2. DETECTION METHOD IS PUBLISHED (§63). `observed` / `inferred` / `potential`
 *    / `unknown`. An inference is never rendered as an observation.
 * 3. ABSENCE IS NOT SAFETY (§43 of spec 2). A dimension that could not be read
 *    is `not-assessed` with a reason — never a pass, never a zero.
 * 4. EVERY FINDING CARRIES EVIDENCE (§36). A finding with no evidence cannot be
 *    constructed: `evidence` is required.
 *
 * This module is ISOMORPHIC — it must import nothing that is Node-only or
 * DOM-only, because the same engines run in the browser (LOCAL mode, so source
 * never leaves the device) and on the server (DEV mode).
 */

/* ────────────────────────────────────────────────────────────────── modes ── */

/** The three top-level assessment modes. */
export type ScanMode = 'web' | 'local' | 'dev';

export const SCAN_MODES: readonly ScanMode[] = ['web', 'local', 'dev'];

export const SCAN_MODE_LABEL: Record<ScanMode, string> = {
  web: 'Web',
  local: 'Local',
  dev: 'Dev',
};

export const SCAN_MODE_DESCRIPTION: Record<ScanMode, string> = {
  web: 'Internet-facing exposure assessment.',
  local: 'Local device, filesystem and codebase assessment.',
  dev: 'Repository, container, Kubernetes and cloud-native assessment.',
};

/* ────────────────────────────────────────────────────────────── task state ── */

/** Lifecycle of a scan task (§29). */
export type ScanTaskStatus =
  | 'queued'
  | 'initializing'
  | 'discovering'
  | 'analyzing'
  | 'correlating'
  | 'scoring'
  | 'completed'
  | 'partial'
  | 'failed'
  | 'cancelled';

export const TERMINAL_TASK_STATUSES: readonly ScanTaskStatus[] = [
  'completed',
  'partial',
  'failed',
  'cancelled',
];

/** Per-engine execution state. Mirrors the module ledger discipline used by the
 *  web scanner: an engine ALWAYS reaches a terminal state. */
export type EngineRunState =
  | 'pending'
  | 'skipped'
  | 'running'
  | 'completed'
  | 'failed'
  | 'not-applicable'
  | 'not-assessed'
  | 'cancelled';

export const TERMINAL_ENGINE_STATES: readonly EngineRunState[] = [
  'skipped',
  'completed',
  'failed',
  'not-applicable',
  'not-assessed',
  'cancelled',
];

/* ─────────────────────────────────────────────────────────────── findings ── */

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingConfidence = 'high' | 'medium' | 'low' | 'unknown';

/**
 * How the scanner knows (§63).
 *
 * `observed`  — the scanner read the artefact itself (a matched line, a parsed
 *               certificate, an API response).
 * `inferred`  — derived from something else that was observed (a dependency
 *               implies a crypto library implies an algorithm).
 * `potential` — a pattern matched but the surrounding context does not prove
 *               the cryptography is actually used.
 * `unknown`   — provenance could not be established.
 */
export type DetectionMethod = 'observed' | 'inferred' | 'potential' | 'unknown';

/**
 * Quantum classification (§64).
 *
 * Deliberately NOT a boolean, and deliberately role-aware: AES-256 used for
 * data-at-rest is `resistant`, while RSA-2048 used for a signature is
 * `vulnerable`. `not-applicable` exists so a non-cryptographic finding (a
 * privileged container) is never scored as a quantum verdict.
 */
export type QuantumStatus =
  | 'vulnerable'
  | 'resistant'
  | 'hybrid'
  | 'pqc'
  | 'unknown'
  | 'not-applicable';

/** What the cryptography is being used FOR. Drives both the quantum verdict and
 *  the migration recommendation (§23). */
export type CryptoRole =
  | 'key-exchange'
  | 'signature'
  | 'encryption'
  | 'authentication'
  | 'integrity'
  | 'hashing'
  | 'password-derivation'
  | 'key-derivation'
  | 'tls'
  | 'certificate'
  | 'code-signing'
  | 'token-signing'
  | 'storage-encryption'
  | 'database-encryption'
  | 'key-management'
  | 'random'
  | 'unknown';

/** The layer a finding was observed at. Used by the correlation engine to build
 *  the cloud-native cryptographic path (Spec-2 §29). */
export type ExposureLayer =
  | 'edge'
  | 'source'
  | 'dependency'
  | 'configuration'
  | 'secret'
  | 'container'
  | 'registry'
  | 'kubernetes'
  | 'iac'
  | 'cicd'
  | 'cloud'
  | 'certificate'
  | 'identity'
  | 'runtime';

/** Where the observation was made. Sensitive values are NEVER placed here. */
export interface ExposureEvidence {
  /** Human sentence describing what was seen. Required — §36. */
  summary: string;
  /** Repository / device / cluster / account the observation belongs to. */
  scope?: string;
  /** Relative path within the scope. */
  file?: string;
  line?: number;
  /** Redacted excerpt. Never a secret value, never more than 240 chars. */
  snippet?: string;
  /** Git commit, image digest, resource ARN/ID, certificate serial… */
  reference?: string;
  branch?: string;
  /** Provider/platform the evidence came from (github, aws, kubernetes…). */
  provider?: string;
  /** The engine's own rule identifier. */
  ruleId?: string;
  /** Anything else structured the UI can render as key/value. */
  attributes?: Record<string, string | number | boolean | null>;
  /** True when the raw material stayed on the user's device (§43). */
  localOnly?: boolean;
  observedAt: string;
}

/** The canonical finding (§38). */
export interface ExposureFinding {
  /** Stable within a scan: `${engineId}:${hash-of-identity}`. */
  id: string;
  scanId: string;
  engineId: string;
  mode: ScanMode;
  layer: ExposureLayer;
  category: string;
  subcategory?: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  detection: DetectionMethod;
  /** Cryptographic subject, when the finding is about cryptography. */
  algorithm?: string;
  /** Canonical algorithm after alias normalisation (Kyber → ML-KEM). */
  canonicalAlgorithm?: string;
  keySize?: number | null;
  mode_?: string;
  protocol?: string;
  library?: string;
  component?: string;
  version?: string;
  role?: CryptoRole;
  quantumStatus: QuantumStatus;
  /** Why the quantum verdict is what it is. Rendered verbatim. */
  quantumRationale?: string;
  recommendation?: string;
  references?: string[];
  evidence: ExposureEvidence[];
  /** Set by the correlation engine when several findings are one exposure. */
  correlationKey?: string;
  firstSeen: string;
  lastSeen: string;
  /** Asset/component this belongs to, once the graph is built. */
  assetRef?: string;
  /** Relationships to other findings, for the exposure graph. */
  relatedTo?: string[];
  /** Migration hand-off payload (§53). */
  migration?: {
    candidate: boolean;
    target?: string;
    priority?: 'P1' | 'P2' | 'P3' | 'P4';
    complexity?: 'low' | 'medium' | 'high';
    blastRadius?: number;
  };
}

/** A correlated exposure: several findings that are the same underlying issue
 *  (§39). Rendered as ONE row with several evidence sources. */
export interface CorrelatedExposure {
  key: string;
  title: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  quantumStatus: QuantumStatus;
  canonicalAlgorithm?: string;
  role?: CryptoRole;
  /** The layers this exposure was seen at, in pipeline order. */
  layers: ExposureLayer[];
  /** Every contributing finding id. */
  findingIds: string[];
  /** Merged, de-duplicated evidence. */
  evidence: ExposureEvidence[];
  recommendation?: string;
  /** The cryptographic path when the evidence supports it (Spec-2 §29-30). */
  path?: Array<{ layer: ExposureLayer; label: string; detail?: string }>;
  migration?: ExposureFinding['migration'];
}

/* ───────────────────────────────────────────────────────────── cbom model ── */

/** One cryptographic component in the CBOM (§11). */
export interface CbomComponent {
  id: string;
  /** Package or library the cryptography comes from, when known. */
  package?: string;
  library?: string;
  version?: string;
  language?: string;
  file?: string;
  line?: number;
  function?: string;
  algorithm: string;
  canonicalAlgorithm: string;
  keySize?: number | null;
  cipherMode?: string;
  protocol?: string;
  usage: CryptoRole;
  provider?: string;
  confidence: FindingConfidence;
  detection: DetectionMethod;
  quantumStatus: QuantumStatus;
  layer: ExposureLayer;
  evidence: ExposureEvidence[];
  /** Ids of the components this one depends on (dependency → library → algo). */
  dependsOn?: string[];
}

/* ────────────────────────────────────────────────────────────── coverage ── */

/**
 * What was and was NOT assessed (§41, Spec-2 §42-43).
 *
 * `notAssessed` is the honesty valve: an engine that could not read a resource
 * records it here with a reason, and the UI renders "Not Assessed", never
 * "no vulnerability".
 */
export interface ScanCoverage {
  filesDiscovered: number;
  filesAnalyzed: number;
  filesSkipped: number;
  filesUnsupported: number;
  bytesAnalyzed: number;
  repositories: number;
  branches: number;
  commitsAnalyzed: number;
  dependencies: number;
  containers: number;
  images: number;
  kubernetesNamespaces: number;
  kubernetesWorkloads: number;
  cloudResources: number;
  iacFiles: number;
  cicdWorkflows: number;
  cryptoComponents: number;
  certificates: number;
  secrets: number;
  configFiles: number;
  /** Stated exclusions, so "100% coverage" is never implied (§41). */
  exclusions: string[];
  /** Dimensions that could not be read, each with its reason. */
  notAssessed: Array<{ dimension: string; reason: string; engineId?: string }>;
  /** True when a bounded budget truncated the work. */
  truncated: boolean;
  truncationNote?: string;
  /**
   * Engines whose own budget stopped them before they had read their remit.
   *
   * `truncated` alone is a flag with nobody attached to it, and coverage is
   * scored per ENGINE — so a truncating engine was still counted as having
   * covered its remit in full, and a run that stopped 400 files short
   * published "Coverage 100%" beside its own "totals are a floor" note.
   * Naming the engine lets `computeCoverage` stop crediting it.
   */
  truncatedBy: string[];
}

export function emptyCoverage(): ScanCoverage {
  return {
    filesDiscovered: 0,
    filesAnalyzed: 0,
    filesSkipped: 0,
    filesUnsupported: 0,
    bytesAnalyzed: 0,
    repositories: 0,
    branches: 0,
    commitsAnalyzed: 0,
    dependencies: 0,
    containers: 0,
    images: 0,
    kubernetesNamespaces: 0,
    kubernetesWorkloads: 0,
    cloudResources: 0,
    iacFiles: 0,
    cicdWorkflows: 0,
    cryptoComponents: 0,
    certificates: 0,
    secrets: 0,
    configFiles: 0,
    exclusions: [],
    notAssessed: [],
    truncated: false,
    truncatedBy: [],
  };
}

/** Merge coverage produced by parallel engines. */
export function mergeCoverage(base: ScanCoverage, patch: Partial<ScanCoverage>): ScanCoverage {
  const next: ScanCoverage = { ...base };
  for (const [key, value] of Object.entries(patch)) {
    if (value === undefined || value === null) continue;
    if (key === 'exclusions' || key === 'notAssessed' || key === 'truncatedBy') continue;
    if (key === 'truncated') {
      next.truncated = next.truncated || Boolean(value);
      continue;
    }
    if (key === 'truncationNote') {
      next.truncationNote = next.truncationNote ?? (value as string);
      continue;
    }
    if (typeof value === 'number') {
      (next as unknown as Record<string, number>)[key] =
        ((next as unknown as Record<string, number>)[key] ?? 0) + value;
    }
  }
  if (patch.exclusions?.length) {
    next.exclusions = Array.from(new Set([...next.exclusions, ...patch.exclusions]));
  }
  if (patch.truncatedBy?.length) {
    /* `next.truncatedBy` can be absent on a coverage object rehydrated from a
       record written before this field existed. */
    next.truncatedBy = Array.from(new Set([...(next.truncatedBy ?? []), ...patch.truncatedBy]));
  }
  if (patch.notAssessed?.length) {
    /* Keyed on DIMENSION alone. Keying on `dimension|reason` let one gap appear
       several times whenever two code paths worded it differently — which is
       how the panel came to read "Not assessed (3)" over two real dimensions,
       beside a completeness note that had deduplicated to 2.

       A dimension is one gap however many engines noticed it, so a second
       report of a dimension already present merges its reason instead of
       adding a row. The first engine to report it keeps attribution: it is the
       one whose absence the reader is being told about. */
    const byDimension = new Map(next.notAssessed.map((entry) => [entry.dimension, { ...entry }]));
    for (const entry of patch.notAssessed) {
      const existing = byDimension.get(entry.dimension);
      if (!existing) {
        byDimension.set(entry.dimension, { ...entry });
        continue;
      }
      if (!existing.reason.includes(entry.reason)) existing.reason = `${existing.reason} ${entry.reason}`.trim();
    }
    next.notAssessed = [...byDimension.values()];
  }
  return next;
}

/* ──────────────────────────────────────────────────────────────── scoring ── */

/** Five independent readings — deliberately NOT collapsed into one (§40). */
export interface ExposureScores {
  /** 0-100, higher is worse. null when nothing was measured. */
  securityRisk: number | null;
  quantumRisk: number | null;
  migrationRisk: number | null;
  /** 0-100 — how much of the estate in scope was actually read. */
  coverage: number | null;
  /** 0-100 — weighted confidence of the findings behind the scores. */
  confidence: number | null;
  /** Band labels published alongside the numbers. */
  securityBand: RiskBand | null;
  quantumBand: RiskBand | null;
  migrationBand: RiskBand | null;
  /** Why each score is what it is — rendered, never hidden. */
  basis: string[];
}

export type RiskBand = 'critical' | 'high' | 'moderate' | 'low' | 'minimal';

/* ────────────────────────────────────────────────────────────── task model ── */

/** What is being scanned. Discriminated by mode. */
export type ScanTarget =
  | { kind: 'web'; url: string; host: string; port: number }
  | {
      kind: 'local';
      label: string;
      /** Directory name / file count the user authorised. */
      rootName: string;
      fileCount: number;
      /** True when the QGuard Local Agent performed the collection. */
      viaAgent: boolean;
      agentId?: string;
    }
  | {
      kind: 'repository';
      url: string;
      provider: string;
      owner: string;
      repo: string;
      branch?: string;
      visibility: 'public' | 'private' | 'unknown';
    }
  | { kind: 'container'; image: string; registry?: string; digest?: string }
  | { kind: 'kubernetes'; cluster: string; namespaces: string[]; live: boolean }
  | { kind: 'cloud'; provider: 'aws' | 'azure' | 'gcp'; account: string; regions: string[] };

export interface ScanTask {
  scanId: string;
  tenantId: string | null;
  userId: string | null;
  mode: ScanMode;
  profileId: string;
  target: ScanTarget;
  /** Engine ids the planner selected. */
  engines: string[];
  status: ScanTaskStatus;
  createdAt: string;
  startedAt: string | null;
  completedAt: string | null;
  /** Per-engine ledger. Always present for every selected engine. */
  runs: EngineRun[];
  coverage: ScanCoverage;
  scores: ExposureScores;
  findingCount: number;
  /** Set when the scan reached `partial` or `failed`. */
  failureReason?: string;
  /** Exclusion rules in force (§42). */
  exclusions: ScanExclusions;
  /** True when raw material never left the device (§43). */
  localOnly: boolean;
}

export interface EngineRun {
  engineId: string;
  label: string;
  state: EngineRunState;
  /** 0-100. Derived from real completion counts, never from a timer (§34). */
  progress: number;
  startedAt: string | null;
  completedAt: string | null;
  findingCount: number;
  /** Reason for `failed`, `skipped`, `not-applicable`, `not-assessed`. */
  detail?: string;
  /** Sub-step the engine is on right now, for the live card. */
  step?: string;
  /** Real unit counts, so the bar can never run ahead of the work. */
  units?: { done: number; total: number; unit: string };
}

/** Exclusions (§42). */
export interface ScanExclusions {
  directories: string[];
  files: string[];
  patterns: string[];
  extensions: string[];
  dependencies: string[];
  secretRules: string[];
}

export function defaultExclusions(): ScanExclusions {
  return {
    directories: ['node_modules', 'dist', 'build', 'coverage', '.next', 'vendor', 'target', '__pycache__', '.venv'],
    files: [],
    patterns: [],
    extensions: [],
    dependencies: [],
    secretRules: [],
  };
}

/* ─────────────────────────────────────────────────────────────── events ─── */

/** The scan event model (§35). Every UI update traces to one of these. */
export type ScanEventName =
  | 'scan.created'
  | 'scan.started'
  | 'engine.started'
  | 'engine.progress'
  | 'finding.discovered'
  | 'evidence.collected'
  | 'engine.completed'
  | 'engine.failed'
  | 'correlation.completed'
  | 'scoring.completed'
  | 'scan.completed'
  | 'scan.cancelled'
  | 'scan.failed';

export interface ScanEvent {
  event: ScanEventName;
  scanId: string;
  timestamp: string;
  engineId?: string;
  engineLabel?: string;
  state?: EngineRunState;
  progress?: number;
  step?: string;
  units?: { done: number; total: number; unit: string };
  severity?: FindingSeverity;
  message?: string;
  finding?: ExposureFinding;
  /** Terminal frame payload. */
  result?: ExposureAssessment;
  detail?: string;
}

export type ScanEventSink = (event: ScanEvent) => void;

/* ─────────────────────────────────────────────────────────── assessment ─── */

/** Everything a completed (or partial) scan produced. */
export interface ExposureAssessment {
  task: ScanTask;
  findings: ExposureFinding[];
  exposures: CorrelatedExposure[];
  cbom: CbomComponent[];
  /** Mode-specific structured intelligence the panels render. */
  intelligence: ExposureIntelligence;
  /** Generated at composition time; stable for export. */
  generatedAt: string;
  /** Schema version so a stored report can be read back safely. */
  schemaVersion: 1;
}

/** Aggregated, presentation-ready intelligence derived from the findings. */
export interface ExposureIntelligence {
  quantum: {
    vulnerable: number;
    hybrid: number;
    pqc: number;
    resistant: number;
    unknown: number;
    notApplicable: number;
    /** null when no cryptographic component was observed at all. */
    readiness: number | null;
  };
  severity: Record<FindingSeverity, number>;
  byLayer: Array<{ layer: ExposureLayer; findings: number; critical: number; components: number }>;
  byEngine: Array<{ engineId: string; label: string; findings: number; state: EngineRunState }>;
  /**
   * The algorithms observed, largest group first.
   *
   * `quantumStatus` is the DOMINANT status in the group and `mix` carries the
   * full split, because an algorithm group is not homogeneous: ML-KEM appears
   * both standalone (`pqc`) and inside hybrid constructions (`hybrid`). A single
   * status per algorithm was published from whichever component happened to be
   * enumerated first, which is how 202 components rendered `hybrid` under a cell
   * reporting 23.
   */
  topAlgorithms: Array<{
    algorithm: string;
    count: number;
    quantumStatus: QuantumStatus;
    mix: Array<{ status: QuantumStatus; count: number }>;
    classicallyWeak: number;
  }>;
  /**
   * Distinct algorithm groups in the CBOM, before `topAlgorithms` is capped.
   *
   * The chip row shows the twelve largest groups. Saying so needs this total,
   * or a reader sums the chips and gets fewer components than the CBOM panel
   * beside it reports.
   */
  algorithmGroups: number;
  languages: Array<{ language: string; files: number }>;
  frameworks: string[];
  dependencies: Array<{
    name: string;
    version: string;
    ecosystem: string;
    direct: boolean;
    cryptoRelevant: boolean;
    quantumRelevant: boolean;
  }>;
  secrets: Array<{
    type: string;
    location: string;
    severity: FindingSeverity;
    confidence: FindingConfidence;
    /** ALWAYS the literal string '[REDACTED]'. */
    value: '[REDACTED]';
    historical: boolean;
  }>;
  /** Repository / cluster / cloud facts the panels show. */
  facts: Array<{ label: string; value: string; detail?: string }>;
  /** Recommended next actions, evidence-backed. */
  recommendations: Array<{
    title: string;
    detail: string;
    severity: FindingSeverity;
    effort: 'low' | 'medium' | 'high';
    findingIds: string[];
  }>;
  /**
   * How many distinct actions the scan actually produced, before the panel cap.
   *
   * `recommendations` is capped at ten so the panel stays readable. Rendering
   * that cap with no denominator tells a reader the estate needs ten things
   * done, when a real scan produced 27 — the reader then plans against a list
   * that silently dropped more work than it showed. The panel prints
   * "the 10 highest-priority of 27" because this number is published.
   */
  recommendationCandidates: number;
}

/* ───────────────────────────────────────────────────────────── utilities ─── */

export const SEVERITY_ORDER: Record<FindingSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const SEVERITY_WEIGHT: Record<FindingSeverity, number> = {
  critical: 100,
  high: 60,
  medium: 30,
  low: 10,
  info: 0,
};

export const CONFIDENCE_WEIGHT: Record<FindingConfidence, number> = {
  high: 1,
  medium: 0.7,
  low: 0.4,
  unknown: 0.25,
};

export function compareSeverity(a: FindingSeverity, b: FindingSeverity): number {
  return SEVERITY_ORDER[a] - SEVERITY_ORDER[b];
}

export function riskBand(score: number | null): RiskBand | null {
  if (score === null || Number.isNaN(score)) return null;
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 35) return 'moderate';
  if (score >= 15) return 'low';
  return 'minimal';
}

/**
 * FNV-1a, 32-bit. Deterministic, dependency-free and isomorphic — the same
 * finding gets the same id in the browser and on the server, which is what
 * makes local-then-sync deduplication work.
 */
export function stableHash(input: string): string {
  let hash = 0x811c9dc5;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}

/** A finding id that is stable across runs of the same scanner on the same
 *  artefact — so two scans can be compared (§55). */
export function findingId(engineId: string, identity: string): string {
  return `${engineId}-${stableHash(identity)}`;
}
