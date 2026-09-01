/**
 * QGuard Helix Exposure Assessment Engine™ — the engine contract (§32).
 *
 * Every scanner engine in every mode implements exactly this interface, which
 * is what lets one orchestrator run web, local and dev pipelines without
 * knowing anything about them.
 *
 * The contract's most important clause is the TERMINAL-STATE GUARANTEE: an
 * engine that starts always ends in a terminal state. It may end in `failed`,
 * `not-applicable` or `not-assessed` — but it may never leave the ledger
 * showing `running`, because a rail stuck on "Running" is how a scan silently
 * loses a module.
 *
 * Isomorphic: no Node, no DOM.
 */

import type {
  CryptoRole,
  DetectionMethod,
  EngineRunState,
  ExposureEvidence,
  ExposureFinding,
  ExposureLayer,
  FindingConfidence,
  FindingSeverity,
  QuantumStatus,
  ScanCoverage,
  ScanMode,
  ScanTarget,
} from './types';
import { emptyCoverage, findingId } from './types';

/* ────────────────────────────────────────────────────────────── descriptor ── */

/** Static metadata about an engine. Drives the registry, the selector and the
 *  health panel — none of which may claim an engine exists that does not. */
export interface EngineDescriptor {
  id: string;
  label: string;
  /** One sentence describing what it measures, shown in the engine selector. */
  description: string;
  mode: ScanMode;
  layer: ExposureLayer;
  /** Category tag used by scan profiles (crypto, secrets, dependencies…). */
  capability: EngineCapability;
  /** Engines that must have completed before this one may run. */
  dependsOn?: string[];
  /** Rough share of a full scan, used ONLY to order work — never for progress. */
  weight: number;
  /** True when the engine reads material that must not leave the device. */
  privacySensitive?: boolean;
  /** Minimum plan tier for the authenticated platform. Null = available to all. */
  minTier?: 'basic' | 'pro' | 'elite' | null;
}

export type EngineCapability =
  | 'discovery'
  | 'crypto'
  | 'cbom'
  | 'secrets'
  | 'dependencies'
  | 'configuration'
  | 'git-history'
  | 'container'
  | 'kubernetes'
  | 'iac'
  | 'cicd'
  | 'cloud'
  | 'registry'
  | 'supply-chain'
  | 'quantum'
  | 'transport'
  | 'certificates'
  | 'identity';

export const CAPABILITY_LABEL: Record<EngineCapability, string> = {
  discovery: 'Discovery',
  crypto: 'Cryptography',
  cbom: 'CBOM',
  secrets: 'Secrets',
  dependencies: 'Dependencies',
  configuration: 'Configuration',
  'git-history': 'Git History',
  container: 'Containers',
  kubernetes: 'Kubernetes',
  iac: 'Infrastructure as Code',
  cicd: 'CI/CD',
  cloud: 'Cloud',
  registry: 'Registries',
  'supply-chain': 'Supply Chain',
  quantum: 'Quantum Readiness',
  transport: 'Transport & Protocols',
  certificates: 'Certificates & PKI',
  identity: 'Identity & Tokens',
};

/* ───────────────────────────────────────────────────────────────── context ── */

/** Everything an engine is given. It reads; it never reaches outside this. */
export interface EngineContext {
  scanId: string;
  mode: ScanMode;
  target: ScanTarget;
  /** Shared, engine-populated workspace: file corpus, repo metadata, adapters. */
  workspace: ScanWorkspace;
  /** Wall-clock budget for THIS engine. Degrade at expiry; never hang. */
  budgetMs: number;
  /** Resolves true when the operator cancelled. Poll it in every loop. */
  isCancelled: () => boolean;
  /** Report a real sub-step. `units` must be counts of finished work. */
  report: (step: string, units?: { done: number; total: number; unit: string }) => void;
  /** Emit a finding the moment it is discovered, so the UI streams. */
  emit: (finding: ExposureFinding) => void;
  /** Record a dimension that could not be read (§43 of spec 2). */
  notAssessed: (dimension: string, reason: string) => void;
  /** Exclusion predicate, already compiled from the operator's rules. */
  isExcluded: (path: string) => boolean;
  /** Optional secret for provider access. Never logged, never echoed. */
  credential?: EngineCredential | null;
}

export interface EngineCredential {
  kind: 'git-token' | 'kubeconfig' | 'aws' | 'azure' | 'gcp' | 'registry';
  /** Opaque handle resolved server-side; raw material never reaches the client. */
  value: Record<string, string>;
}

/**
 * The shared workspace.
 *
 * The acquisition engines (local FS collector, repo collector) populate
 * `files`; every content engine then reads the SAME corpus. That is what makes
 * one file read serve twelve engines instead of twelve reads serving one each.
 */
export interface ScanWorkspace {
  /** Every file in scope, already filtered by the discovery engine. */
  files: WorkspaceFile[];
  /** Facts discovered about the target: languages, frameworks, facets. */
  facets: Set<TargetFacet>;
  /** Repository / cluster / account metadata, keyed by producer. */
  meta: Record<string, unknown>;
  /** Free-form notes engines leave for one another. */
  notes: string[];
}

export interface WorkspaceFile {
  /** Path relative to the scan root, forward slashes, no leading slash. */
  path: string;
  /** UTF-8 text. Binary files are discovered but never given content. */
  content: string | null;
  size: number;
  /** True when the file could not be decoded as text. */
  binary: boolean;
  /** Lower-cased extension including the dot, or ''. */
  ext: string;
  /** Lower-cased basename. */
  basename: string;
  /** Set by the file-discovery engine. */
  classification: FileClassification;
  /** Only for git-history findings: the commit the content came from. */
  commit?: string;
}

export type FileClassification =
  | 'source'
  | 'manifest'
  | 'lockfile'
  | 'config'
  | 'certificate'
  | 'key-material'
  | 'container'
  | 'kubernetes'
  | 'helm'
  | 'iac'
  | 'cicd'
  | 'documentation'
  | 'archive'
  | 'binary'
  | 'other';

export function emptyWorkspace(): ScanWorkspace {
  return { files: [], facets: new Set(), meta: {}, notes: [] };
}

/** Facts about the target that the Smart Scan Planner reads (Spec-2 §32). */
export type TargetFacet =
  | 'git-repository'
  | 'node'
  | 'python'
  | 'java'
  | 'dotnet'
  | 'go'
  | 'rust'
  | 'ruby'
  | 'php'
  | 'swift'
  | 'kotlin'
  | 'cpp'
  | 'dockerfile'
  | 'compose'
  | 'kubernetes'
  | 'helm'
  | 'kustomize'
  | 'terraform'
  | 'cloudformation'
  | 'bicep'
  | 'pulumi'
  | 'ansible'
  | 'github-actions'
  | 'gitlab-ci'
  | 'azure-pipelines'
  | 'jenkins'
  | 'circleci'
  | 'certificates'
  | 'key-material'
  | 'env-files'
  | 'service-mesh';

/* ────────────────────────────────────────────────────────────────── result ── */

export interface EngineResult {
  state: Extract<EngineRunState, 'completed' | 'failed' | 'not-applicable' | 'not-assessed' | 'skipped'>;
  findings: ExposureFinding[];
  coverage: Partial<ScanCoverage>;
  /** Reason, required for every non-`completed` state. */
  detail?: string;
  /** Structured output other engines or the intelligence builder consume. */
  output?: Record<string, unknown>;
}

/**
 * The answer to "does this engine have anything to do here?".
 *
 * `reason` is required whenever `applicable` is false — it becomes the ledger's
 * `not-applicable` detail, which is what stops a zero-finding engine from
 * reading as a pass.
 */
export interface EngineApplicability {
  applicable: boolean;
  reason?: string;
}

/** The engine itself (§32: initialize / validateTarget / execute / …). */
export interface ExposureEngine {
  descriptor: EngineDescriptor;
  /**
   * Cheap pre-flight. Return `false` with a reason when the engine has nothing
   * to do for this target — the orchestrator records `not-applicable`, which is
   * honest, instead of `completed` with zero findings, which reads as a pass.
   */
  appliesTo(context: EngineContext): EngineApplicability;
  execute(context: EngineContext): Promise<EngineResult>;
}

/* ─────────────────────────────────────────────────────── finding builders ── */

/** Arguments for {@link buildFinding}. Everything the canonical model needs and
 *  nothing it does not. */
export interface FindingInput {
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
  algorithm?: string;
  canonicalAlgorithm?: string;
  keySize?: number | null;
  cipherMode?: string;
  protocol?: string;
  library?: string;
  component?: string;
  version?: string;
  role?: CryptoRole;
  quantumStatus: QuantumStatus;
  quantumRationale?: string;
  recommendation?: string;
  references?: string[];
  evidence: ExposureEvidence[];
  /** Extra identity material so two different findings never collide. */
  identity: string;
  migration?: ExposureFinding['migration'];
}

/** Construct a canonical finding. The only sanctioned way to make one. */
export function buildFinding(input: FindingInput): ExposureFinding {
  const now = new Date().toISOString();
  return {
    id: findingId(input.engineId, input.identity),
    scanId: input.scanId,
    engineId: input.engineId,
    mode: input.mode,
    layer: input.layer,
    category: input.category,
    subcategory: input.subcategory,
    title: input.title,
    description: input.description,
    severity: input.severity,
    confidence: input.confidence,
    detection: input.detection,
    algorithm: input.algorithm,
    canonicalAlgorithm: input.canonicalAlgorithm,
    keySize: input.keySize ?? null,
    mode_: input.cipherMode,
    protocol: input.protocol,
    library: input.library,
    component: input.component,
    version: input.version,
    role: input.role,
    quantumStatus: input.quantumStatus,
    quantumRationale: input.quantumRationale,
    recommendation: input.recommendation,
    references: input.references,
    evidence: input.evidence,
    firstSeen: now,
    lastSeen: now,
    migration: input.migration,
  };
}

/** Evidence helper that enforces the redaction and length rules. */
export function buildEvidence(input: Omit<ExposureEvidence, 'observedAt'> & { observedAt?: string }): ExposureEvidence {
  return {
    ...input,
    snippet: input.snippet ? redactSnippet(input.snippet) : undefined,
    observedAt: input.observedAt ?? new Date().toISOString(),
  };
}

/**
 * Redact anything that looks like key material or a credential before it can
 * reach evidence, then truncate.
 *
 * Applied to EVERY snippet, not only to secret findings — a crypto finding on
 * the line `const key = "AKIA…"` would otherwise carry the credential into the
 * report, the export and the database.
 */
export function redactSnippet(raw: string): string {
  let text = raw;

  // PEM blocks: keep the header, drop the body entirely.
  text = text.replace(
    /-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?(-----END [A-Z0-9 ]+-----)?/g,
    (_match, label: string) => `-----BEGIN ${label}----- [REDACTED]`,
  );

  // Long base64/hex runs are key material far more often than they are code.
  text = text.replace(/\b[A-Za-z0-9+/]{40,}={0,2}\b/g, '[REDACTED]');
  text = text.replace(/\b(?:0x)?[0-9a-fA-F]{40,}\b/g, '[REDACTED]');

  // Provider-shaped credentials.
  text = text.replace(/\bAKIA[0-9A-Z]{16}\b/g, 'AKIA[REDACTED]');
  text = text.replace(/\bASIA[0-9A-Z]{16}\b/g, 'ASIA[REDACTED]');
  text = text.replace(/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, 'gh*_[REDACTED]');
  text = text.replace(/\bglpat-[A-Za-z0-9_-]{16,}\b/g, 'glpat-[REDACTED]');
  text = text.replace(/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, 'xox*-[REDACTED]');
  text = text.replace(/\bsk-[A-Za-z0-9]{20,}\b/g, 'sk-[REDACTED]');
  text = text.replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/g, '[REDACTED JWT]');

  /* Credentials in a URL's userinfo — `scheme://user:PASSWORD@host`.
     This needs its own rule because the assignment rule below keys off a
     secret-shaped IDENTIFIER, and the most common carrier of an inline
     credential is `DATABASE_URL`, which contains no trigger word at all. */
  text = text.replace(/([a-z][a-z0-9+.-]*:\/\/[^:\s'"@/]+:)([^@\s'"/]+)(@)/gi, '$1[REDACTED]$3');

  // Assignments to secret-shaped identifiers.
  text = text.replace(
    /((?:pass(?:word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential)\s*[:=]\s*)(["'`]?)([^\s"'`,;]{4,})\2/gi,
    (_match, prefix: string, quote: string) => `${prefix}${quote}[REDACTED]${quote}`,
  );

  return text.length > 240 ? `${text.slice(0, 237)}…` : text;
}

/* ─────────────────────────────────────────────────────────────── helpers ─── */

/** Standard `not-applicable` result, so every engine phrases it identically. */
export function notApplicable(reason: string): EngineResult {
  return { state: 'not-applicable', findings: [], coverage: {}, detail: reason };
}

/** Standard `not-assessed` result — the honest answer to "no permission". */
export function notAssessed(reason: string, dimension?: string): EngineResult {
  return {
    state: 'not-assessed',
    findings: [],
    coverage: dimension ? { notAssessed: [{ dimension, reason }] } : {},
    detail: reason,
  };
}

/** Standard success result. */
export function completed(findings: ExposureFinding[], coverage: Partial<ScanCoverage> = {}, output?: Record<string, unknown>): EngineResult {
  return { state: 'completed', findings, coverage, output };
}

/** Standard failure result. */
export function failed(reason: string, partialFindings: ExposureFinding[] = []): EngineResult {
  return { state: 'failed', findings: partialFindings, coverage: {}, detail: reason };
}

export { emptyCoverage };
