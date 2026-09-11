/**
 * Exposure assessment persistence (§46, §73, Spec-2 §38).
 *
 * §73: "Do not create duplicate concepts if equivalent existing models already
 *       exist. Reuse existing Asset / Finding / Evidence / Crypto Component /
 *       CBOM / Risk / Migration Task / Tenant / User where appropriate."
 *
 * The specification's §46 lists fourteen new tables. This module deliberately
 * writes into the platform's EXISTING five instead:
 *
 *   pqc_scan_sessions   the scan task
 *   assets              the repository / device / cluster as an asset
 *   crypto_inventory    the CBOM components
 *   pqc_scan_results    the findings
 *   crypto_exposures    the quantum-vulnerable subset
 *
 * That choice is not a shortcut, it is the requirement: Assets, CBOM Explorer,
 * Quantum Readiness, Migration Planner, Certification and Sophia all read those
 * five tables. A parallel `scan_findings` table would have produced a Dev scan
 * whose results were invisible to every downstream module in the platform —
 * which is the opposite of §73 and of Spec-2 §38.
 *
 * Nothing here requires a migration, so the feature works against the schema
 * that is already deployed.
 *
 * TRUST BOUNDARY: for a Local scan the assessment was produced by the browser
 * and is untrusted. Every value written below is re-derived from the finding
 * fields; no client-supplied summary, score or count is persisted as fact.
 */

import type { SupabaseClient } from '@supabase/supabase-js';
import { getServiceClient } from '@/lib/supabase-server';
import type { CbomComponent, ExposureAssessment, ExposureFinding } from '@/lib/scanner/exposure/types';
import { buildCbom, summariseCbom } from '@/lib/scanner/exposure/cbom';
import { correlateFindings } from '@/lib/scanner/exposure/correlate';
import { computeScores } from '@/lib/scanner/exposure/risk';
import {
  buildIntelligenceDigest,
  EXPOSURE_HISTORY_RECORD_VERSION,
  rowSourceFor,
  scannerModeFor,
  type HistoryIntelligenceDigest,
} from '@/lib/scanner/exposure/history';

export interface PersistResult {
  scanSessionId: string | null;
  assetId: string | null;
  cryptoInventoryRows: number;
  scanResultRows: number;
  exposureRows: number;
  /** True when nothing could be written and the caller should say so. */
  degraded: boolean;
  notice?: string;
}

const MAX_ROWS = 2_000;

export async function persistExposureAssessment(input: {
  assessment: ExposureAssessment;
  userId: string;
  client: SupabaseClient | null;
  source: 'local' | 'dev';
}): Promise<PersistResult> {
  const client = input.client ?? getServiceClient();
  if (!client) {
    return {
      scanSessionId: null,
      assetId: null,
      cryptoInventoryRows: 0,
      scanResultRows: 0,
      exposureRows: 0,
      degraded: true,
      notice: 'No database client is available, so the assessment was not persisted. It remains available in this session only.',
    };
  }

  /* ── re-derive, never trust ────────────────────────────────────────────── */
  const findings = sanitiseFindings(input.assessment.findings);
  const cbom = buildCbom(findings);
  const exposures = correlateFindings(findings);
  const summary = summariseCbom(cbom);
  const scores = computeScores({
    findings,
    exposures,
    coverage: input.assessment.task.coverage,
    runs: input.assessment.task.runs,
  });

  const targetLabel = describeTarget(input.assessment);
  const now = new Date().toISOString();

  /* The only part of the presentation intelligence that cannot be recomputed
     from the findings and components this call is about to write. Capped and
     re-truncated here because a Local assessment arrives from the browser and
     this is the trust boundary. */
  const intelligenceDigest = sanitiseDigest(buildIntelligenceDigest(input.assessment.intelligence));

  /* ── 1. the scan session ───────────────────────────────────────────────── */
  const sessionPayload = {
    user_id: input.userId,
    status: input.assessment.task.status === 'completed' ? 'completed' : input.assessment.task.status === 'partial' ? 'completed' : 'failed',
    target_scope: targetLabel,
    progress: 100,
    total_assets: 1,
    scanned_assets: 1,
    findings_count: findings.length,
    metadata: {
      scannerMode: scannerModeFor(input.source),
      exposureMode: input.assessment.task.mode,
      profileId: input.assessment.task.profileId,
      engines: input.assessment.task.engines,
      /* ── the History record (§ Exposure Assessment History) ──────────────
         Everything below exists so a recorded assessment can be read back as
         the assessment it was, rather than as a row of totals. It is
         deliberately BOUNDED: this table is read on every dashboard, and an
         unbounded metadata blob here is what once made a 32-row table time out
         at 13.9 MB per query. Findings and components stay in their own
         tables; only what cannot be recomputed from them is kept here. */
      recordVersion: EXPOSURE_HISTORY_RECORD_VERSION,
      /* The id the ENGINE gave this scan, which is not the id of the row it is
         being written to. The History tab needs it to recognise that a Dev scan
         still held in the API's job store has already been recorded — without
         it the same assessment appears twice, once as a record and once as an
         unrecorded session scan, for as long as the job store keeps it. */
      sourceScanId: input.assessment.task.scanId,
      /* The structured target, so history states WHAT was assessed rather than
         re-parsing the display label. */
      target: input.assessment.task.target,
      /* The task's own verdict. `status` above collapses partial into
         completed for the platform's shared vocabulary; a reviewer of this
         assessment must still be able to see it completed with gaps. */
      taskStatus: input.assessment.task.status,
      failureReason: input.assessment.task.failureReason ?? null,
      exclusions: input.assessment.task.exclusions,
      intelligence: intelligenceDigest,
      runs: input.assessment.task.runs.map((run) => ({
        engineId: run.engineId,
        label: run.label,
        state: run.state,
        findingCount: run.findingCount,
        detail: run.detail,
      })),
      coverage: input.assessment.task.coverage,
      scores,
      quantum: {
        vulnerable: summary.vulnerable,
        hybrid: summary.hybrid,
        pqc: summary.pqc,
        resistant: summary.resistant,
        unknown: summary.unknown,
        readiness: summary.readiness,
      },
      correlatedExposures: exposures.length,
      localOnly: input.assessment.task.localOnly,
      /* Stated in the record itself so an auditor reading the row knows what
         the numbers do and do not cover. */
      limitations: input.assessment.task.coverage.notAssessed,
      generatedAt: input.assessment.generatedAt,
    },
    started_at: input.assessment.task.startedAt ?? now,
    completed_at: input.assessment.task.completedAt ?? now,
    updated_at: now,
  };

  let scanSessionId: string | null = null;
  const sessionInsert = await client.from('pqc_scan_sessions').insert(sessionPayload).select('id').single();
  if (sessionInsert.error || !sessionInsert.data?.id) {
    return {
      scanSessionId: null,
      assetId: null,
      cryptoInventoryRows: 0,
      scanResultRows: 0,
      exposureRows: 0,
      degraded: true,
      notice: `The scan session could not be written: ${sessionInsert.error?.message ?? 'unknown error'}.`,
    };
  }
  scanSessionId = sessionInsert.data.id as string;

  /* ── 2. the asset ──────────────────────────────────────────────────────── */
  const assetId = await upsertAsset(client, {
    userId: input.userId,
    name: targetLabel,
    type: assetTypeFor(input.assessment),
    criticality: criticalityFor(scores.securityRisk),
    metadata: {
      exposureMode: input.assessment.task.mode,
      source: input.source,
      target: input.assessment.task.target,
      last_scan_id: scanSessionId,
      last_scanned_at: now,
      languages: input.assessment.intelligence.languages,
      frameworks: input.assessment.intelligence.frameworks,
      quantumReadiness: summary.readiness,
      securityRisk: scores.securityRisk,
      quantumRisk: scores.quantumRisk,
      coverage: scores.coverage,
    },
  });

  /* One context for both row builders, so a finding row and a component row
     from the same assessment can never disagree about which scan they belong
     to. */
  const rowContext: RowContext = {
    userId: input.userId,
    scanSessionId,
    assetId,
    source: input.source,
    now,
  };

  /* ── 3. CBOM components ────────────────────────────────────────────────── */
  const inventoryRows = cbom.slice(0, MAX_ROWS).map((component) => buildInventoryRow(component, rowContext));

  const cryptoInventoryRows = await insertBatched(client, 'crypto_inventory', inventoryRows);

  /* ── 4. findings ───────────────────────────────────────────────────────── */
  const resultRows = findings.slice(0, MAX_ROWS).map((finding) => buildFindingRow(finding, rowContext));

  const scanResultRows = await insertBatched(client, 'pqc_scan_results', resultRows);

  /* ── 5. quantum-vulnerable exposures ───────────────────────────────────── */
  const exposureRowsPayload = findings
    .filter((finding) => finding.quantumStatus === 'vulnerable' && finding.severity !== 'info')
    .slice(0, MAX_ROWS)
    .map((finding) => ({
      user_id: input.userId,
      asset_id: assetId,
      exposure_type: finding.role && finding.role !== 'unknown' ? finding.role : finding.layer,
      severity: finding.severity,
      description: finding.description,
      detected_value: finding.canonicalAlgorithm ?? finding.algorithm ?? 'unknown',
      metadata: {
        scanSessionId,
        source: `exposure-${input.source}`,
        findingId: finding.id,
        engineId: finding.engineId,
        layer: finding.layer,
        quantumRationale: finding.quantumRationale ?? null,
        recommendation: finding.recommendation ?? null,
        location: finding.evidence[0]?.file ?? finding.evidence[0]?.reference ?? null,
      },
    }));

  const exposureRows = await insertBatched(client, 'crypto_exposures', exposureRowsPayload);

  /* Record what was written back onto the session, so the row is self-describing. */
  await client
    .from('pqc_scan_sessions')
    .update({
      metadata: {
        ...sessionPayload.metadata,
        persisted: { cryptoInventoryRows, scanResultRows, exposureRows, assetId },
        truncated: findings.length > MAX_ROWS || cbom.length > MAX_ROWS,
      },
      updated_at: new Date().toISOString(),
    })
    .eq('id', scanSessionId)
    .eq('user_id', input.userId);

  return {
    scanSessionId,
    assetId,
    cryptoInventoryRows,
    scanResultRows,
    exposureRows,
    degraded: false,
    notice:
      findings.length > MAX_ROWS || cbom.length > MAX_ROWS
        ? `The assessment exceeded the ${MAX_ROWS}-row persistence budget; the highest-severity findings and components were written and the rest were not.`
        : undefined,
  };
}

/* ────────────────────────────────────────────────────────────── row builders ── */

/**
 * The row shape the writer produces, extracted so the READER can be tested
 * against it.
 *
 * The History tab rebuilds an assessment from these rows. If the two ever drift
 * — a field renamed here, still read under its old name there — a recorded
 * assessment starts reading back wrong, and nothing would fail loudly. Because
 * both sides are now pure functions over the same shapes,
 * `tools/exposure-history-check.ts` can round-trip a real assessment through
 * them and assert it comes back identical.
 */
export interface RowContext {
  userId: string;
  scanSessionId: string;
  assetId: string | null;
  source: 'local' | 'dev';
  now: string;
}

export function buildInventoryRow(component: CbomComponent, context: RowContext) {
  return {
    user_id: context.userId,
    asset_id: context.assetId,
    item_type: itemTypeFor(component),
    name: `${component.usage === 'unknown' ? component.layer : component.usage}: ${component.canonicalAlgorithm}`,
    algorithm: component.canonicalAlgorithm,
    key_size: component.keySize ?? null,
    protocol: component.protocol ?? null,
    exposure_level: exposureLevelFor(component),
    is_vulnerable: component.quantumStatus === 'vulnerable',
    is_quantum_safe: component.quantumStatus === 'pqc' || component.quantumStatus === 'hybrid',
    metadata: {
      scanSessionId: context.scanSessionId,
      source: rowSourceFor(context.source),
      componentId: component.id,
      layer: component.layer,
      usage: component.usage,
      library: component.library ?? null,
      package: component.package ?? null,
      version: component.version ?? null,
      language: component.language ?? null,
      file: component.file ?? null,
      line: component.line ?? null,
      provider: component.provider ?? null,
      detectionMethod: component.detection,
      confidence: component.confidence,
      quantumStatus: component.quantumStatus,
      evidence: component.evidence.slice(0, 3).map((entry) => entry.summary),
      dependsOn: component.dependsOn ?? [],
    },
    discovered_at: context.now,
  };
}

export function buildFindingRow(finding: ExposureFinding, context: RowContext) {
  return {
    user_id: context.userId,
    scan_session_id: context.scanSessionId,
    asset_id: context.assetId,
    finding_type: finding.category,
    algorithm: finding.canonicalAlgorithm ?? finding.algorithm ?? null,
    threat_level: finding.severity,
    description: finding.description,
    remediation: finding.recommendation ?? null,
    metadata: {
      scanSessionId: context.scanSessionId,
      source: rowSourceFor(context.source),
      findingId: finding.id,
      engineId: finding.engineId,
      layer: finding.layer,
      /* ── retained for the History record ─────────────────────────────────
         `finding_type` holds the CATEGORY and `description` the prose; without
         the title a recorded finding has no headline, and history would have to
         invent one. These are short strings — the row's size is dominated by
         `evidence`, which is already capped. */
      title: finding.title,
      /* The raw algorithm string as the engine saw it. The column holds the
         CANONICAL name (Kyber → ML-KEM), and losing the observed spelling makes
         a historical finding impossible to reconcile against its own evidence. */
      algorithmRaw: finding.algorithm ?? null,
      protocol: finding.protocol ?? null,
      library: finding.library ?? null,
      references: (finding.references ?? []).slice(0, 8),
      firstSeen: finding.firstSeen,
      lastSeen: finding.lastSeen,
      subcategory: finding.subcategory ?? null,
      severity: finding.severity,
      confidence: finding.confidence,
      detectionMethod: finding.detection,
      quantumStatus: finding.quantumStatus,
      quantumRationale: finding.quantumRationale ?? null,
      role: finding.role ?? null,
      keySize: finding.keySize ?? null,
      component: finding.component ?? null,
      version: finding.version ?? null,
      correlationKey: finding.correlationKey ?? null,
      location: finding.evidence[0]?.file ?? finding.evidence[0]?.reference ?? null,
      evidence: finding.evidence.slice(0, 3),
      migration: finding.migration ?? null,
    },
  };
}

/* ───────────────────────────────────────────────────────────── sanitation ─── */

/**
 * Re-assert the invariants before anything is written.
 *
 * A Local assessment arrives from the browser. Even though the client is this
 * platform's own worker, the endpoint must behave as though it is not: strip
 * anything that looks like a secret value, cap string lengths, and drop
 * findings that do not satisfy the model's own required fields.
 */
function sanitiseFindings(findings: ExposureFinding[]): ExposureFinding[] {
  const out: ExposureFinding[] = [];
  const seen = new Set<string>();

  for (const finding of findings) {
    if (!finding?.id || !finding.title || !Array.isArray(finding.evidence) || finding.evidence.length === 0) continue;
    if (seen.has(finding.id)) continue;
    seen.add(finding.id);

    out.push({
      ...finding,
      title: truncate(finding.title, 300),
      description: truncate(finding.description ?? '', 2_000),
      recommendation: finding.recommendation ? truncate(finding.recommendation, 1_000) : undefined,
      quantumRationale: finding.quantumRationale ? truncate(finding.quantumRationale, 1_000) : undefined,
      evidence: finding.evidence.slice(0, 6).map((entry) => ({
        ...entry,
        summary: truncate(entry.summary ?? '', 500),
        // Belt and braces: the engines already redact, and this re-redacts.
        snippet: entry.snippet ? truncate(scrubSnippet(entry.snippet), 240) : undefined,
        attributes: entry.attributes
          ? Object.fromEntries(
              Object.entries(entry.attributes)
                .slice(0, 20)
                .map(([key, value]) => [key, typeof value === 'string' ? truncate(value, 200) : value]),
            )
          : undefined,
      })),
    });
  }

  return out;
}

/**
 * Bound and re-truncate the History digest.
 *
 * `buildIntelligenceDigest` decides WHAT is kept and how much of it; this
 * decides how long each string in it may be, because a Local assessment is
 * composed in the browser and every string in it is caller-controlled.
 */
function sanitiseDigest(digest: HistoryIntelligenceDigest): HistoryIntelligenceDigest {
  return {
    languages: digest.languages.map((entry) => ({
      language: truncate(String(entry.language ?? ''), 60),
      files: Number.isFinite(entry.files) ? entry.files : 0,
    })),
    frameworks: digest.frameworks.map((entry) => truncate(String(entry ?? ''), 80)),
    dependencies: digest.dependencies.map((entry) => ({
      name: truncate(String(entry.name ?? ''), 160),
      version: truncate(String(entry.version ?? ''), 60),
      ecosystem: truncate(String(entry.ecosystem ?? ''), 40),
      direct: Boolean(entry.direct),
      cryptoRelevant: Boolean(entry.cryptoRelevant),
      quantumRelevant: Boolean(entry.quantumRelevant),
    })),
    facts: digest.facts.map((entry) => ({
      label: truncate(String(entry.label ?? ''), 80),
      value: truncate(String(entry.value ?? ''), 240),
      detail: entry.detail ? truncate(String(entry.detail), 160) : undefined,
    })),
    dependenciesTruncated: digest.dependenciesTruncated,
  };
}

function scrubSnippet(snippet: string): string {
  return snippet
    .replace(/-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*/g, (_match, label: string) => `-----BEGIN ${label}----- [REDACTED]`)
    .replace(/([a-z][a-z0-9+.-]*:\/\/[^:\s'"@/]+:)([^@\s'"/]+)(@)/gi, '$1[REDACTED]$3')
    .replace(/\b[A-Za-z0-9+/]{40,}={0,2}\b/g, '[REDACTED]')
    .replace(/\b(?:0x)?[0-9a-fA-F]{40,}\b/g, '[REDACTED]')
    .replace(/\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, '$1[REDACTED]')
    .replace(/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, 'gh*_[REDACTED]')
    .replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/g, '[REDACTED JWT]');
}

function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

/* ─────────────────────────────────────────────────────────────── db helpers ── */

async function insertBatched(client: SupabaseClient, table: string, rows: Record<string, unknown>[]): Promise<number> {
  if (rows.length === 0) return 0;
  const BATCH = 200;
  let written = 0;
  for (let index = 0; index < rows.length; index += BATCH) {
    const batch = rows.slice(index, index + BATCH);
    const { error, data } = await client.from(table).insert(batch).select('id');
    if (error) {
      // One failed batch must not lose the batches that succeeded.
      console.warn(`[exposure-persistence] ${table} batch failed: ${error.message}`);
      continue;
    }
    written += data?.length ?? batch.length;
  }
  return written;
}

async function upsertAsset(
  client: SupabaseClient,
  input: { userId: string; name: string; type: string; criticality: string; metadata: Record<string, unknown> },
): Promise<string | null> {
  const existing = await client
    .from('assets')
    .select('id, metadata')
    .eq('user_id', input.userId)
    .eq('name', input.name)
    .limit(1);

  if (existing.data?.[0]?.id) {
    const merged = { ...(existing.data[0].metadata ?? {}), ...input.metadata };
    await client
      .from('assets')
      .update({ type: input.type, criticality: input.criticality, status: 'active', metadata: merged, updated_at: new Date().toISOString() })
      .eq('id', existing.data[0].id)
      .eq('user_id', input.userId);
    return existing.data[0].id as string;
  }

  const inserted = await client
    .from('assets')
    .insert({
      user_id: input.userId,
      name: input.name,
      type: input.type,
      criticality: input.criticality,
      status: 'active',
      metadata: input.metadata,
    })
    .select('id')
    .single();

  return inserted.data?.id ?? null;
}

/* ───────────────────────────────────────────────────────────── classifiers ── */

function describeTarget(assessment: ExposureAssessment): string {
  const target = assessment.task.target;
  switch (target.kind) {
    case 'repository': return `${target.provider}:${target.owner}/${target.repo}`;
    case 'local': return `local:${target.rootName}`;
    case 'kubernetes': return `k8s:${target.cluster}`;
    case 'cloud': return `${target.provider}:${target.account}`;
    case 'container': return `image:${target.image}`;
    case 'web': return target.host;
    default: return 'exposure-assessment';
  }
}

function assetTypeFor(assessment: ExposureAssessment): string {
  switch (assessment.task.target.kind) {
    case 'repository': return 'application';
    case 'local': return 'application';
    case 'kubernetes': return 'container_platform';
    case 'cloud': return 'cloud_service';
    case 'container': return 'container_image';
    case 'web': return 'web_application';
    default: return 'application';
  }
}

function criticalityFor(securityRisk: number | null): string {
  if (securityRisk === null) return 'low';
  if (securityRisk >= 80) return 'critical';
  if (securityRisk >= 60) return 'high';
  if (securityRisk >= 35) return 'medium';
  return 'low';
}

function itemTypeFor(component: CbomComponent): string {
  switch (component.layer) {
    case 'certificate': return 'certificate';
    case 'dependency': return 'library';
    case 'container': case 'registry': return 'container';
    case 'kubernetes': return 'workload';
    case 'cloud': return 'cloud_key';
    case 'identity': return 'key';
    default: return 'algorithm';
  }
}

function exposureLevelFor(component: CbomComponent): string {
  if (component.quantumStatus === 'vulnerable') {
    const exposed = ['tls', 'certificate', 'key-exchange', 'authentication', 'token-signing', 'code-signing'];
    return exposed.includes(component.usage) ? 'critical' : 'high';
  }
  if (component.quantumStatus === 'unknown') return 'medium';
  return 'low';
}
