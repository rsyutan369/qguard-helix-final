/**
 * Exposure Assessment History — the record model.
 *
 * A Local or Dev assessment that has been recorded to the tenant's inventory
 * exists afterwards as NORMALISED ROWS, never as a stored blob: the session in
 * `pqc_scan_sessions`, its findings in `pqc_scan_results` and its cryptographic
 * components in `crypto_inventory`. That split is deliberate — a previous
 * incident on this platform put whole assessments in `pqc_scan_sessions.metadata`
 * and a 32-row table began timing out at 13.9 MB per query.
 *
 * This module turns those rows back into the SAME `ExposureAssessment` shape the
 * live panels render, so a scan reviewed a month later reads exactly as it did
 * the moment it finished, through the same components.
 *
 * THREE RULES GOVERN IT, and they are what make the History tab trustworthy:
 *
 *  1. **Re-derive, never re-invent.** Correlated exposures, the CBOM summary and
 *     the presentation intelligence are recomputed with the very functions a
 *     live run uses (`correlateFindings`, `summariseCbom`, `buildIntelligence`).
 *     A historical assessment therefore cannot disagree with a live one about
 *     the same evidence.
 *
 *  2. **Declare what the record does not hold.** Anything a row never carried is
 *     reported in `provenance.notRetained` and rendered as "not retained",
 *     never as an empty list. An empty dependency table that means "we did not
 *     store them" reads to an auditor as "this repository has no dependencies",
 *     which is the exact class of defect this platform keeps fixing.
 *
 *  3. **Never manufacture a verdict.** A row without a stored quantum status
 *     rehydrates as `unknown`, not as `resistant`. Absence is not good news.
 *
 * Pure and isomorphic — no Express, no Supabase, no Node built-ins — so the API
 * and the browser can both use it and cannot drift apart.
 */

import type {
  CbomComponent,
  CorrelatedExposure,
  CryptoRole,
  DetectionMethod,
  EngineRun,
  ExposureAssessment,
  ExposureEvidence,
  ExposureFinding,
  ExposureIntelligence,
  ExposureLayer,
  ExposureScores,
  FindingConfidence,
  FindingSeverity,
  QuantumStatus,
  ScanCoverage,
  ScanTarget,
  ScanTask,
  ScanTaskStatus,
} from './types';
import { emptyCoverage } from './types';
import { correlateFindings } from './correlate';
import { buildCbom, summariseCbom } from './cbom';
import { computeScores } from './risk';
import { buildIntelligence } from './orchestrator';
import { emptyWorkspace } from './engine-contract';

/* ────────────────────────────────────────────────────────── record identity ── */

/** The two exposure modes that produce a durable record. */
export type ExposureHistoryMode = 'local' | 'dev';

/**
 * The `metadata.scannerMode` marker written by `exposure-persistence`.
 *
 * This is the ONLY thing that separates an exposure assessment from a Web
 * scanner session in `pqc_scan_sessions`, so it is defined once, here, and both
 * the writer and the reader import it.
 */
export function scannerModeFor(mode: ExposureHistoryMode): string {
  return `exposure-${mode}`;
}

/** The `metadata.source` marker on every finding / component / exposure row. */
export function rowSourceFor(mode: ExposureHistoryMode): string {
  return `exposure-${mode}`;
}

/** Current shape of the record this module reads. Bumped when the writer adds fields. */
export const EXPOSURE_HISTORY_RECORD_VERSION = 2;

/* ─────────────────────────────────────────────────────────────── row shapes ── */

/** A `pqc_scan_sessions` row, as PostgREST returns it. */
export interface SessionRow {
  id: string;
  user_id?: string | null;
  status?: string | null;
  target_scope?: string | null;
  findings_count?: number | null;
  metadata?: Record<string, unknown> | null;
  started_at?: string | null;
  completed_at?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
}

/** A `pqc_scan_results` row. */
export interface FindingRow {
  id?: string;
  scan_session_id?: string | null;
  asset_id?: string | null;
  finding_type?: string | null;
  algorithm?: string | null;
  threat_level?: string | null;
  description?: string | null;
  remediation?: string | null;
  metadata?: Record<string, unknown> | null;
  created_at?: string | null;
}

/** A `crypto_inventory` row. */
export interface InventoryRow {
  id?: string;
  asset_id?: string | null;
  item_type?: string | null;
  name?: string | null;
  algorithm?: string | null;
  key_size?: number | null;
  protocol?: string | null;
  exposure_level?: string | null;
  is_vulnerable?: boolean | null;
  is_quantum_safe?: boolean | null;
  metadata?: Record<string, unknown> | null;
  discovered_at?: string | null;
}

/* ───────────────────────────────────────────────────────────── the entry ──── */

/** Severity split of the findings actually recorded for one assessment. */
export interface HistorySeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

/**
 * One row of the History list.
 *
 * Every number here is counted from the rows that were really written, so the
 * list and the detail view can never report different totals for one scan.
 */
export interface ExposureHistoryEntry {
  scanId: string;
  /**
   * The id the assessment engine gave the run, when the record kept it.
   *
   * Distinct from `scanId`, which is the id of the row the assessment was
   * written to. Both are needed: the row id addresses the record, the engine id
   * is what an in-flight run still in the API's job store calls itself.
   */
  sourceScanId: string | null;
  mode: ExposureHistoryMode;
  /** `recorded` = durable rows in the tenant's inventory. */
  origin: 'recorded' | 'session';
  target: string;
  targetKind: string;
  profileId: string;
  engines: string[];
  status: ScanTaskStatus;
  /** The raw session status, when it disagrees with the task status. */
  sessionStatus: string;
  startedAt: string;
  completedAt: string | null;
  recordedAt: string | null;
  durationMs: number | null;
  /** Findings genuinely present as rows for this session. */
  findingCount: number;
  severity: HistorySeverityCounts;
  componentCount: number;
  quantumVulnerableComponents: number;
  quantumReadiness: number | null;
  exposureCount: number;
  scores: ExposureScores | null;
  coverage: { analyzed: number; discovered: number; percent: number | null; notAssessed: number };
  engineRuns: Array<{ engineId: string; label: string; state: string; findingCount: number; detail?: string }>;
  localOnly: boolean;
  /** True when the writer capped the rows it persisted. */
  truncated: boolean;
  /** Set when the record predates a field this UI reads. */
  recordVersion: number;
  /** Present only for `origin: 'session'` rows — an unrecorded live/held scan. */
  live?: { progress: number; running: boolean; note: string };
}

/* ───────────────────────────────────────────────────────────── provenance ─── */

export interface HistoryProvenance {
  recordVersion: number;
  recordedAt: string | null;
  /** Fields read straight out of the record. */
  rehydrated: string[];
  /** Fields recomputed from the rehydrated evidence with the live code path. */
  derived: string[];
  /** Fields the record never held. Rendered as "not retained", never as zero. */
  notRetained: Array<{ field: string; reason: string }>;
  /** Fields the writer capped, with what survived. */
  truncated: Array<{ field: string; kept: number; note: string }>;
}

export interface RestoredAssessment {
  assessment: ExposureAssessment;
  provenance: HistoryProvenance;
}

/* ─────────────────────────────────────────────────────────────── coercion ─── */

const SEVERITIES: readonly FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
const CONFIDENCES: readonly FindingConfidence[] = ['high', 'medium', 'low', 'unknown'];
const DETECTIONS: readonly DetectionMethod[] = ['observed', 'inferred', 'potential', 'unknown'];
const QUANTUM_STATUSES: readonly QuantumStatus[] = [
  'vulnerable',
  'hybrid',
  'pqc',
  'resistant',
  'unknown',
  'not-applicable',
];
/**
 * The exposure layers, exactly as the platform defines them.
 *
 * There is no `unknown` member, deliberately: a layer is a claim about WHERE
 * something was observed, and inventing one would corrupt the by-layer
 * intelligence and the exposure path a reviewer reads. A row whose layer cannot
 * be recognised is therefore reported as unreadable rather than filed under a
 * layer it was never seen at.
 */
const LAYERS: readonly ExposureLayer[] = [
  'edge',
  'source',
  'dependency',
  'configuration',
  'secret',
  'container',
  'registry',
  'kubernetes',
  'iac',
  'cicd',
  'cloud',
  'certificate',
  'identity',
  'runtime',
];

function layerOf(value: unknown): ExposureLayer | null {
  return typeof value === 'string' && (LAYERS as readonly string[]).includes(value)
    ? (value as ExposureLayer)
    : null;
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim().length > 0 ? value : undefined;
}

function num(value: unknown): number | undefined {
  const parsed = typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : NaN;
  return Number.isFinite(parsed) ? parsed : undefined;
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
  return typeof value === 'string' && (allowed as readonly string[]).includes(value) ? (value as T) : fallback;
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function array(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

/**
 * Map a stored `threat_level` back to a severity.
 *
 * The column takes the finding's own severity verbatim on write, so this is
 * normally an identity. It is written defensively because the same column is
 * shared with the Web scanner, whose vocabulary is different.
 */
function severityFromRow(row: FindingRow, metadata: Record<string, unknown>): FindingSeverity {
  const fromMetadata = str(metadata.severity);
  if (fromMetadata && (SEVERITIES as readonly string[]).includes(fromMetadata)) return fromMetadata as FindingSeverity;
  const level = (row.threat_level ?? '').toLowerCase();
  if ((SEVERITIES as readonly string[]).includes(level)) return level as FindingSeverity;
  if (level === 'critical' || level === 'severe') return 'critical';
  if (level === 'high') return 'high';
  if (level === 'moderate' || level === 'medium') return 'medium';
  if (level === 'low') return 'low';
  return 'info';
}

function evidenceFrom(value: unknown, observedAt: string): ExposureEvidence[] {
  return array(value)
    .map((entry) => {
      const item = record(entry);
      const summary = str(item.summary);
      if (!summary) return null;
      const evidence: ExposureEvidence = {
        summary,
        scope: str(item.scope),
        file: str(item.file),
        line: num(item.line),
        snippet: str(item.snippet),
        reference: str(item.reference),
        branch: str(item.branch),
        provider: str(item.provider),
        ruleId: str(item.ruleId),
        attributes: item.attributes && typeof item.attributes === 'object'
          ? (item.attributes as ExposureEvidence['attributes'])
          : undefined,
        localOnly: typeof item.localOnly === 'boolean' ? item.localOnly : undefined,
        observedAt: str(item.observedAt) ?? observedAt,
      };
      return evidence;
    })
    .filter((entry): entry is ExposureEvidence => entry !== null);
}

/* ───────────────────────────────────────────────────────── row → finding ──── */

/**
 * Rebuild one `ExposureFinding` from its persisted row.
 *
 * Returns null when the row cannot support a finding the rest of the platform
 * would accept — the same contract `sanitiseFindings` enforces on write
 * (identity + at least one piece of evidence). A row that fails it is counted
 * as unreadable and disclosed, rather than rendered as a blank finding.
 */
export function restoreFinding(
  row: FindingRow,
  context: { scanId: string; mode: ExposureHistoryMode },
): ExposureFinding | null {
  const metadata = record(row.metadata);
  const id = str(metadata.findingId) ?? str(row.id);
  if (!id) return null;

  /* A finding with no recognisable layer cannot be placed in the evidence
     model, and guessing one would put it on a surface it was never seen at. */
  const layer = layerOf(metadata.layer);
  if (!layer) return null;

  const observedAt = str(row.created_at) ?? new Date(0).toISOString();
  const evidence = evidenceFrom(metadata.evidence, observedAt);

  /* The record keeps the finding's own location even when the evidence array
     was capped, so a finding whose evidence did not survive still says where it
     was seen instead of rendering with none. */
  const location = str(metadata.location);
  if (evidence.length === 0 && location) {
    evidence.push({
      summary: `Recorded at ${location}.`,
      file: location.includes('/') || location.includes('\\') ? location : undefined,
      reference: location.includes('/') || location.includes('\\') ? undefined : location,
      observedAt,
    });
  }
  if (evidence.length === 0) return null;

  const severity = severityFromRow(row, metadata);
  const migrationRaw = record(metadata.migration);
  const migration = typeof migrationRaw.candidate === 'boolean'
    ? {
      candidate: migrationRaw.candidate,
      target: str(migrationRaw.target),
      priority: str(migrationRaw.priority) as 'P1' | 'P2' | 'P3' | 'P4' | undefined,
      complexity: str(migrationRaw.complexity) as 'low' | 'medium' | 'high' | undefined,
      blastRadius: num(migrationRaw.blastRadius),
    }
    : undefined;

  return {
    id,
    scanId: context.scanId,
    engineId: str(metadata.engineId) ?? 'unknown',
    mode: context.mode,
    layer,
    category: str(row.finding_type) ?? 'finding',
    subcategory: str(metadata.subcategory),
    /* `title` has been retained since record version 2. Older records fall back
       to the description's first sentence — never to a manufactured headline. */
    title: str(metadata.title) ?? firstSentence(row.description) ?? str(row.finding_type) ?? 'Recorded finding',
    description: str(row.description) ?? '',
    severity,
    confidence: oneOf(metadata.confidence, CONFIDENCES, 'unknown'),
    detection: oneOf(metadata.detectionMethod, DETECTIONS, 'unknown'),
    algorithm: str(metadata.algorithmRaw) ?? str(row.algorithm),
    canonicalAlgorithm: str(row.algorithm),
    keySize: num(metadata.keySize) ?? null,
    protocol: str(metadata.protocol),
    library: str(metadata.library),
    component: str(metadata.component),
    version: str(metadata.version),
    role: str(metadata.role) as CryptoRole | undefined,
    quantumStatus: oneOf(metadata.quantumStatus, QUANTUM_STATUSES, 'unknown'),
    quantumRationale: str(metadata.quantumRationale),
    recommendation: str(row.remediation),
    references: array(metadata.references).filter((entry): entry is string => typeof entry === 'string'),
    evidence,
    correlationKey: str(metadata.correlationKey),
    firstSeen: str(metadata.firstSeen) ?? observedAt,
    lastSeen: str(metadata.lastSeen) ?? observedAt,
    assetRef: str(row.asset_id),
    migration,
  };
}

function firstSentence(value: string | null | undefined): string | undefined {
  const text = str(value);
  if (!text) return undefined;
  const stop = text.indexOf('. ');
  const sentence = stop > 12 ? text.slice(0, stop) : text;
  return sentence.length > 160 ? `${sentence.slice(0, 159)}…` : sentence;
}

/* ─────────────────────────────────────────────────────── row → component ──── */

/**
 * Rebuild one CBOM component from its `crypto_inventory` row.
 *
 * Only rows this assessment wrote are passed in — the caller filters on
 * `metadata.scanSessionId`, so a component discovered by a different scan can
 * never be attributed to this one.
 */
export function restoreComponent(row: InventoryRow): CbomComponent | null {
  const metadata = record(row.metadata);
  const id = str(metadata.componentId) ?? str(row.id);
  const canonical = str(row.algorithm);
  const layer = layerOf(metadata.layer);
  if (!id || !canonical || !layer) return null;

  const observedAt = str(row.discovered_at) ?? new Date(0).toISOString();
  const evidence = evidenceFrom(metadata.evidence, observedAt);

  return {
    id,
    package: str(metadata.package),
    library: str(metadata.library),
    version: str(metadata.version),
    language: str(metadata.language),
    file: str(metadata.file),
    line: num(metadata.line),
    algorithm: canonical,
    canonicalAlgorithm: canonical,
    keySize: row.key_size ?? null,
    protocol: str(row.protocol) ?? undefined,
    usage: (str(metadata.usage) as CryptoRole | undefined) ?? 'unknown',
    provider: str(metadata.provider),
    confidence: oneOf(metadata.confidence, CONFIDENCES, 'unknown'),
    detection: oneOf(metadata.detectionMethod, DETECTIONS, 'unknown'),
    /* The boolean columns are a projection of this status, not a substitute for
       it: `is_vulnerable = false` covers pqc, hybrid, resistant AND unknown. */
    quantumStatus: oneOf(metadata.quantumStatus, QUANTUM_STATUSES, 'unknown'),
    layer,
    evidence: evidence.length > 0
      ? evidence
      : [{ summary: `Recorded component ${canonical}.`, observedAt }],
    dependsOn: array(metadata.dependsOn).filter((entry): entry is string => typeof entry === 'string'),
    ...(str(metadata.migrationTarget) ? { migrationTarget: str(metadata.migrationTarget) } : {}),
  };
}

/* ─────────────────────────────────────────────────────────── the entry ────── */

/** Coerce the persisted session status back onto the task vocabulary. */
function taskStatusFrom(session: SessionRow, metadata: Record<string, unknown>): ScanTaskStatus {
  const stored = str(metadata.taskStatus);
  if (stored === 'completed' || stored === 'partial' || stored === 'failed' || stored === 'cancelled') return stored;
  const status = (session.status ?? '').toLowerCase();
  if (status === 'completed') return 'completed';
  if (status === 'cancelled') return 'cancelled';
  if (status === 'failed') return 'failed';
  return 'partial';
}

function scoresFrom(metadata: Record<string, unknown>): ExposureScores | null {
  const raw = record(metadata.scores);
  if (Object.keys(raw).length === 0) return null;
  return {
    securityRisk: num(raw.securityRisk) ?? null,
    quantumRisk: num(raw.quantumRisk) ?? null,
    migrationRisk: num(raw.migrationRisk) ?? null,
    coverage: num(raw.coverage) ?? null,
    confidence: num(raw.confidence) ?? null,
    securityBand: (str(raw.securityBand) as ExposureScores['securityBand']) ?? null,
    quantumBand: (str(raw.quantumBand) as ExposureScores['quantumBand']) ?? null,
    migrationBand: (str(raw.migrationBand) as ExposureScores['migrationBand']) ?? null,
    basis: array(raw.basis).filter((entry): entry is string => typeof entry === 'string'),
  };
}

function coverageFrom(metadata: Record<string, unknown>): ScanCoverage {
  const raw = record(metadata.coverage);
  if (Object.keys(raw).length === 0) return emptyCoverage();
  const base = emptyCoverage();
  for (const key of Object.keys(base) as Array<keyof ScanCoverage>) {
    const value = raw[key as string];
    if (typeof base[key] === 'number' && typeof value === 'number') {
      (base as unknown as Record<string, number>)[key as string] = value;
    }
  }
  base.exclusions = array(raw.exclusions).filter((entry): entry is string => typeof entry === 'string');
  base.notAssessed = array(raw.notAssessed)
    .map((entry) => record(entry))
    .filter((entry) => typeof entry.dimension === 'string' && typeof entry.reason === 'string')
    .map((entry) => ({
      dimension: entry.dimension as string,
      reason: entry.reason as string,
      engineId: str(entry.engineId),
    }));
  base.truncated = Boolean(raw.truncated);
  base.truncationNote = str(raw.truncationNote);
  base.truncatedBy = array(raw.truncatedBy).filter((entry): entry is string => typeof entry === 'string');
  return base;
}

function runsFrom(metadata: Record<string, unknown>): EngineRun[] {
  return array(metadata.runs)
    .map((entry) => record(entry))
    .filter((entry) => typeof entry.engineId === 'string')
    .map((entry) => ({
      engineId: entry.engineId as string,
      label: str(entry.label) ?? (entry.engineId as string),
      state: (str(entry.state) as EngineRun['state']) ?? 'completed',
      /* Progress is not retained: a finished run is 100% by definition, and a
         stored bar would be the only number here that is not a measurement. */
      progress: 100,
      startedAt: str(entry.startedAt) ?? null,
      completedAt: str(entry.completedAt) ?? null,
      findingCount: num(entry.findingCount) ?? 0,
      detail: str(entry.detail),
    }));
}

function targetFrom(metadata: Record<string, unknown>, fallbackLabel: string): ScanTarget {
  const stored = record(metadata.target);
  if (typeof stored.kind === 'string') return stored as unknown as ScanTarget;
  /* Record version 1 kept only the descriptive label. A local target is the
     honest reconstruction: it names what was scanned without inventing a
     provider, owner or branch the record never held. */
  return { kind: 'local', label: fallbackLabel, rootName: fallbackLabel, fileCount: 0, viaAgent: false };
}

/** Describe a target the way the History list labels it. */
export function targetKindOf(target: ScanTarget): string {
  return target.kind;
}

function severityCountsOf(findings: ExposureFinding[]): HistorySeverityCounts {
  const counts: HistorySeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

/**
 * Build one History list row.
 *
 * `findings` and `components` are the rows that really exist for this session,
 * so the list reports what is stored — not what the session header claims was
 * once written. Those two disagree whenever a batch insert partly failed, and
 * the stored count is the one that lies.
 */
export function buildHistoryEntry(input: {
  session: SessionRow;
  mode: ExposureHistoryMode;
  findings: ExposureFinding[];
  components: CbomComponent[];
  exposureCount: number;
}): ExposureHistoryEntry {
  const { session, mode, findings, components } = input;
  const metadata = record(session.metadata);
  const target = targetFrom(metadata, session.target_scope ?? 'assessment');
  const coverage = coverageFrom(metadata);
  const quantum = record(metadata.quantum);
  const persisted = record(metadata.persisted);
  const startedAt = session.started_at ?? session.created_at ?? new Date(0).toISOString();
  const completedAt = session.completed_at ?? null;
  const summary = summariseCbom(components);

  return {
    scanId: session.id,
    sourceScanId: str(metadata.sourceScanId) ?? null,
    mode,
    origin: 'recorded',
    target: session.target_scope ?? 'assessment',
    targetKind: targetKindOf(target),
    profileId: str(metadata.profileId) ?? 'standard',
    engines: array(metadata.engines).filter((entry): entry is string => typeof entry === 'string'),
    status: taskStatusFrom(session, metadata),
    sessionStatus: session.status ?? 'unknown',
    startedAt,
    completedAt,
    recordedAt: session.created_at ?? session.updated_at ?? null,
    durationMs: completedAt ? Date.parse(completedAt) - Date.parse(startedAt) : null,
    findingCount: findings.length,
    severity: severityCountsOf(findings),
    componentCount: components.length,
    /* From the components actually stored, recomputed by the shared summariser
       — not from the header's `quantum.vulnerable`, which describes the run and
       not the rows that survived it. */
    quantumVulnerableComponents: summary.vulnerable,
    quantumReadiness: components.length > 0 ? summary.readiness : (num(quantum.readiness) ?? null),
    exposureCount: input.exposureCount,
    scores: scoresFrom(metadata),
    coverage: {
      analyzed: coverage.filesAnalyzed,
      discovered: coverage.filesDiscovered,
      percent: coverage.filesDiscovered > 0
        ? Math.round((coverage.filesAnalyzed / coverage.filesDiscovered) * 1000) / 10
        : null,
      notAssessed: coverage.notAssessed.length,
    },
    engineRuns: runsFrom(metadata).map((run) => ({
      engineId: run.engineId,
      label: run.label,
      state: run.state,
      findingCount: run.findingCount,
      detail: run.detail,
    })),
    localOnly: Boolean(metadata.localOnly),
    truncated: Boolean(metadata.truncated) || Boolean(persisted.truncated),
    recordVersion: num(metadata.recordVersion) ?? 1,
  };
}

/* ──────────────────────────────────────────────────── full rehydration ────── */

/**
 * Rebuild the complete assessment for one recorded scan.
 *
 * Findings and components come out of the record; exposures, the CBOM summary
 * and the presentation intelligence are recomputed by the live code path, so a
 * historical detail view and a live results view derive identically.
 *
 * `scores` are read from the record rather than recomputed. They were computed
 * against the FULL finding set at scan time; the record may hold fewer rows if
 * the writer's row budget capped it, and silently re-scoring a truncated set
 * would publish a different — and better-looking — risk number for the same
 * scan. Where the record has no scores (a very old row), they are recomputed
 * from what survives and the substitution is disclosed.
 */
export function restoreAssessment(input: {
  session: SessionRow;
  mode: ExposureHistoryMode;
  findingRows: FindingRow[];
  inventoryRows: InventoryRow[];
}): RestoredAssessment {
  const { session, mode } = input;
  const metadata = record(session.metadata);
  const recordVersion = num(metadata.recordVersion) ?? 1;

  const notRetained: HistoryProvenance['notRetained'] = [];
  const truncated: HistoryProvenance['truncated'] = [];
  const derived: string[] = [];
  const rehydrated: string[] = [];

  /* ── findings ─────────────────────────────────────────────────────────── */
  const findings: ExposureFinding[] = [];
  let unreadableFindings = 0;
  for (const row of input.findingRows) {
    const finding = restoreFinding(row, { scanId: session.id, mode });
    if (finding) findings.push(finding);
    else unreadableFindings += 1;
  }
  findings.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.title.localeCompare(b.title));
  rehydrated.push(`${findings.length} finding${findings.length === 1 ? '' : 's'}`);
  if (unreadableFindings > 0) {
    notRetained.push({
      field: 'findings',
      reason: `${unreadableFindings} stored row${unreadableFindings === 1 ? '' : 's'} could not be read back as a finding — the row carries no identity, no evidence or no recognised exposure layer — and ${unreadableFindings === 1 ? 'is' : 'are'} excluded from every count on this page rather than being filed under a guess.`,
    });
  }

  /* ── components ───────────────────────────────────────────────────────── */
  const storedComponents: CbomComponent[] = [];
  for (const row of input.inventoryRows) {
    const component = restoreComponent(row);
    if (component) storedComponents.push(component);
  }

  /* A record written before components were persisted, or one whose inventory
     rows were deleted downstream, still has its findings — and the CBOM is a
     pure projection of those, so it is rebuilt rather than shown as empty. */
  const cbom = storedComponents.length > 0 ? storedComponents : buildCbom(findings);
  if (storedComponents.length > 0) {
    rehydrated.push(`${cbom.length} cryptographic component${cbom.length === 1 ? '' : 's'}`);
  } else if (cbom.length > 0) {
    derived.push('CBOM rebuilt from the recorded findings (no component rows are stored for this scan)');
  }

  /* ── derived layers ───────────────────────────────────────────────────── */
  const exposures: CorrelatedExposure[] = correlateFindings(findings);
  derived.push('correlated exposures', 'CBOM summary', 'quantum readiness');

  const coverage = coverageFrom(metadata);
  if (Object.keys(record(metadata.coverage)).length > 0) rehydrated.push('coverage and stated limitations');
  else notRetained.push({ field: 'coverage', reason: 'This record predates coverage retention, so what was and was not read cannot be stated.' });

  const runs = runsFrom(metadata);
  if (runs.length > 0) rehydrated.push('per-engine ledger');
  else notRetained.push({ field: 'engine ledger', reason: 'No per-engine ledger was retained with this record.' });

  let scores = scoresFrom(metadata);
  if (!scores) {
    scores = computeScores({ findings, exposures, components: cbom, coverage, runs });
    derived.push('scores recomputed from the recorded findings (the record holds none)');
  } else {
    rehydrated.push('risk, quantum, migration, coverage and confidence scores');
  }

  /* ── intelligence ─────────────────────────────────────────────────────── */
  const digest = record(metadata.intelligence);
  const intelligence = restoreIntelligence({ findings, exposures, cbom, runs, coverage, digest });

  const digestFields: Array<[string, keyof ExposureIntelligence, string]> = [
    ['languages', 'languages', 'the languages observed'],
    ['frameworks', 'frameworks', 'the frameworks detected'],
    ['dependencies', 'dependencies', 'the dependency inventory'],
    ['facts', 'facts', 'the target facts panel'],
  ];
  for (const [key, field, label] of digestFields) {
    if (array(digest[key]).length > 0) rehydrated.push(label);
    else {
      notRetained.push({
        field: field as string,
        reason: recordVersion >= 2
          ? `This assessment recorded no ${field}.`
          : `${label} is not held by this record — it was written before ${field} were retained. An empty panel here means "not retained", not "none found".`,
      });
    }
  }
  if (Boolean(digest.dependenciesTruncated)) {
    truncated.push({
      field: 'dependencies',
      kept: array(digest.dependencies).length,
      note: 'The dependency inventory exceeded the record budget; cryptographically relevant and direct dependencies were retained first.',
    });
  }

  const persisted = record(metadata.persisted);
  if (Boolean(metadata.truncated) || Boolean(persisted.truncated)) {
    truncated.push({
      field: 'findings and components',
      kept: findings.length + cbom.length,
      note: 'This assessment exceeded the row budget when it was recorded. The highest-severity findings and components were written; the remainder were not, and the scores shown are the ones computed at scan time over the complete set.',
    });
  }

  /* ── the task ─────────────────────────────────────────────────────────── */
  const startedAt = session.started_at ?? session.created_at ?? new Date(0).toISOString();
  const task: ScanTask = {
    scanId: session.id,
    tenantId: null,
    userId: session.user_id ?? null,
    mode,
    profileId: str(metadata.profileId) ?? 'standard',
    target: targetFrom(metadata, session.target_scope ?? 'assessment'),
    engines: array(metadata.engines).filter((entry): entry is string => typeof entry === 'string'),
    status: taskStatusFrom(session, metadata),
    createdAt: session.created_at ?? startedAt,
    startedAt,
    completedAt: session.completed_at ?? null,
    runs,
    coverage,
    scores,
    findingCount: findings.length,
    failureReason: str(metadata.failureReason),
    exclusions: {
      directories: array(record(metadata.exclusions).directories).filter((entry): entry is string => typeof entry === 'string'),
      files: array(record(metadata.exclusions).files).filter((entry): entry is string => typeof entry === 'string'),
      patterns: array(record(metadata.exclusions).patterns).filter((entry): entry is string => typeof entry === 'string'),
      extensions: array(record(metadata.exclusions).extensions).filter((entry): entry is string => typeof entry === 'string'),
      dependencies: array(record(metadata.exclusions).dependencies).filter((entry): entry is string => typeof entry === 'string'),
      secretRules: array(record(metadata.exclusions).secretRules).filter((entry): entry is string => typeof entry === 'string'),
    },
    localOnly: Boolean(metadata.localOnly),
  };

  const assessment: ExposureAssessment = {
    task,
    findings,
    exposures,
    cbom,
    intelligence,
    generatedAt: str(metadata.generatedAt) ?? session.completed_at ?? startedAt,
    schemaVersion: 1,
  };

  return {
    assessment,
    provenance: {
      recordVersion,
      recordedAt: session.created_at ?? null,
      rehydrated,
      derived,
      notRetained,
      truncated,
    },
  };
}

const SEVERITY_RANK: Record<FindingSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/**
 * Presentation intelligence for a restored assessment.
 *
 * Everything derivable from evidence is produced by `buildIntelligence` — the
 * same function a live scan calls — so the two can never disagree. The four
 * workspace-only fields (languages, frameworks, dependencies, facts) are
 * restored from the record's digest when it holds one, and otherwise stay empty
 * with the gap declared by the caller.
 */
function restoreIntelligence(input: {
  findings: ExposureFinding[];
  exposures: CorrelatedExposure[];
  cbom: CbomComponent[];
  runs: EngineRun[];
  coverage: ScanCoverage;
  digest: Record<string, unknown>;
}): ExposureIntelligence {
  const base = buildIntelligence({
    findings: input.findings,
    exposures: input.exposures,
    cbom: input.cbom,
    runs: input.runs,
    workspace: emptyWorkspace(),
    coverage: input.coverage,
  });

  const languages = array(input.digest.languages)
    .map((entry) => record(entry))
    .filter((entry) => typeof entry.language === 'string')
    .map((entry) => ({ language: entry.language as string, files: num(entry.files) ?? 0 }));

  const frameworks = array(input.digest.frameworks).filter((entry): entry is string => typeof entry === 'string');

  const dependencies = array(input.digest.dependencies)
    .map((entry) => record(entry))
    .filter((entry) => typeof entry.name === 'string')
    .map((entry) => ({
      name: entry.name as string,
      version: str(entry.version) ?? 'unknown',
      ecosystem: str(entry.ecosystem) ?? 'unknown',
      direct: Boolean(entry.direct),
      cryptoRelevant: Boolean(entry.cryptoRelevant),
      quantumRelevant: Boolean(entry.quantumRelevant),
    }));

  const storedFacts = array(input.digest.facts)
    .map((entry) => record(entry))
    .filter((entry) => typeof entry.label === 'string' && typeof entry.value === 'string')
    .map((entry) => ({ label: entry.label as string, value: entry.value as string, detail: str(entry.detail) }));

  return {
    ...base,
    languages,
    frameworks,
    dependencies,
    /* `buildIntelligence` always contributes the coverage facts; the record's
       target facts are prepended so a repository still names itself. */
    facts: storedFacts.length > 0 ? storedFacts : base.facts,
  };
}

/* ──────────────────────────────────────────────────── digest for the writer ── */

/** Caps for the record digest. The record is a row in a hot table, not a store. */
export const HISTORY_DIGEST_LIMITS = {
  languages: 25,
  frameworks: 40,
  facts: 24,
  dependencies: 200,
} as const;

export interface HistoryIntelligenceDigest {
  languages: ExposureIntelligence['languages'];
  frameworks: string[];
  dependencies: ExposureIntelligence['dependencies'];
  facts: ExposureIntelligence['facts'];
  dependenciesTruncated: boolean;
}

/**
 * The bounded slice of the intelligence that a record must keep.
 *
 * Only the four fields that cannot be recomputed from findings and components
 * are stored, each capped. Dependencies are ordered so that the ones a
 * cryptographic reviewer needs survive the cap first — a truncated list that
 * dropped every crypto library would be worse than none.
 */
export function buildIntelligenceDigest(
  /* Optional because a Local assessment is composed in the browser: a payload
     that omits the block must record an empty digest, not throw at the writer. */
  source: ExposureIntelligence | null | undefined,
): HistoryIntelligenceDigest {
  const intelligence = {
    languages: Array.isArray(source?.languages) ? source!.languages : [],
    frameworks: Array.isArray(source?.frameworks) ? source!.frameworks : [],
    dependencies: Array.isArray(source?.dependencies) ? source!.dependencies : [],
    facts: Array.isArray(source?.facts) ? source!.facts : [],
  };

  const ranked = [...intelligence.dependencies].sort((a, b) => {
    const rank = (entry: typeof a) => (entry.quantumRelevant ? 0 : entry.cryptoRelevant ? 1 : entry.direct ? 2 : 3);
    return rank(a) - rank(b) || a.name.localeCompare(b.name);
  });

  return {
    languages: intelligence.languages.slice(0, HISTORY_DIGEST_LIMITS.languages),
    frameworks: intelligence.frameworks.slice(0, HISTORY_DIGEST_LIMITS.frameworks),
    dependencies: ranked.slice(0, HISTORY_DIGEST_LIMITS.dependencies),
    facts: intelligence.facts.slice(0, HISTORY_DIGEST_LIMITS.facts),
    dependenciesTruncated: ranked.length > HISTORY_DIGEST_LIMITS.dependencies,
  };
}

/* ─────────────────────────────────────────────────────────── list summary ─── */

/** Portfolio-level totals for the History header. Counted, never estimated. */
export interface ExposureHistorySummary {
  assessments: number;
  recorded: number;
  session: number;
  findings: number;
  severity: HistorySeverityCounts;
  components: number;
  quantumVulnerableComponents: number;
  /** Readiness of the most recent assessment that measured any component. */
  latestReadiness: number | null;
  latestReadinessScanId: string | null;
  /** Distinct targets assessed. */
  targets: number;
  firstAt: string | null;
  lastAt: string | null;
}

export function summariseHistory(entries: ExposureHistoryEntry[]): ExposureHistorySummary {
  const severity: HistorySeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const targets = new Set<string>();
  let findings = 0;
  let components = 0;
  let quantumVulnerableComponents = 0;
  let recorded = 0;
  let session = 0;
  let firstAt: number | null = null;
  let lastAt: number | null = null;

  for (const entry of entries) {
    if (entry.origin === 'recorded') recorded += 1;
    else session += 1;
    findings += entry.findingCount;
    components += entry.componentCount;
    quantumVulnerableComponents += entry.quantumVulnerableComponents;
    targets.add(entry.target);
    for (const key of SEVERITIES) severity[key] += entry.severity[key];
    const at = Date.parse(entry.startedAt);
    if (Number.isFinite(at)) {
      firstAt = firstAt === null ? at : Math.min(firstAt, at);
      lastAt = lastAt === null ? at : Math.max(lastAt, at);
    }
  }

  const latest = [...entries]
    .filter((entry) => entry.quantumReadiness !== null && entry.componentCount > 0)
    .sort((a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt))[0];

  return {
    assessments: entries.length,
    recorded,
    session,
    findings,
    severity,
    components,
    quantumVulnerableComponents,
    latestReadiness: latest?.quantumReadiness ?? null,
    latestReadinessScanId: latest?.scanId ?? null,
    targets: targets.size,
    firstAt: firstAt === null ? null : new Date(firstAt).toISOString(),
    lastAt: lastAt === null ? null : new Date(lastAt).toISOString(),
  };
}

/**
 * A change fingerprint for the History stream.
 *
 * The SSE loop pushes only when this changes, so an idle dashboard costs one
 * comparison per tick instead of a re-render per tick.
 */
export function historyFingerprint(entries: ExposureHistoryEntry[]): string {
  return entries
    .map((entry) =>
      [
        entry.scanId,
        entry.origin,
        entry.status,
        entry.findingCount,
        entry.componentCount,
        entry.live?.progress ?? '',
      ].join(':'),
    )
    .join('|');
}
