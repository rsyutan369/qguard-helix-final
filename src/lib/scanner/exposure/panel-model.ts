/**
 * Panel model — the derivations behind the Local and Dev result panels.
 *
 * ── Why this module exists ──────────────────────────────────────────────────
 *
 * `reconcileExposure` already owns the headline counts, and no panel recomputes
 * them. But four panels carry numbers that are NOT headline counts — they are
 * derived populations, each with its own unit and its own cap:
 *
 *   Scanned Assets       one row per ASSET, with its findings and components
 *   Correlated Exposures how many exposures merged, and how many crossed layers
 *   Evidence Matrix      which findings can be corroborated at all
 *   Standards Cited      how many FINDINGS cite each publication
 *
 * Those derivations used to live inside the `.tsx` components. That is what let
 * every one of them drift, because a derivation inside a component cannot be
 * checked without re-implementing it — and a re-implementation is a second
 * source of truth that agrees on the day it is written and never again. Each of
 * the four defects below was invisible to a passing check suite for exactly
 * that reason:
 *
 *   • Scanned Assets keyed rows on `layer|name`, so ONE file became three
 *     assets (source, secret, certificate), each holding a fraction of its
 *     findings and only one of them holding its components. The inventory
 *     overstated how many assets were scanned and understated every split row.
 *
 *   • Correlated Exposures filtered on `findings > 1 OR layers > 1` and then
 *     labelled the result "N spanning multiple layers". A live Dev scan
 *     reported "30 spanning multiple layers" when the true number was ZERO —
 *     the panel overstated the one thing it exists to evidence.
 *
 *   • Evidence Matrix said "the 30 best-corroborated of 560 findings" when 16
 *     of those 560 carry no detection layer at all. Findings that CANNOT be
 *     corroborated were reported as merely lower-ranked.
 *
 *   • Standards Cited incremented once per matching REFERENCE under a column
 *     labelled "N findings", so a finding citing two clauses of one publication
 *     counted twice.
 *
 * Pure and dependency-free, like `exposure-truth`: the panels render it and
 * `tools/exposure-panel-accuracy-check.ts` asserts it, over the same numbers.
 */

import type { CorrelatedExposure, EngineRun, ExposureAssessment, ExposureFinding, ScanCoverage, ScanTarget } from './types';
import { layerLabel } from './correlate';

/**
 * The short name an assessment target is known by — on the report cover, in
 * every export filename and in the CBOM metadata.
 *
 * One rule, so a Dev CBOM, a Local CBOM and the report built from the same
 * assessment name the target identically.
 */
export function assessmentTargetLabel(target: ScanTarget): string {
  switch (target.kind) {
    case 'local':
      return target.label || target.rootName || 'Authorised folder';
    case 'repository':
      return `${target.owner}/${target.repo}`;
    case 'container':
      return target.image;
    case 'kubernetes':
      return target.cluster;
    case 'cloud':
      return `${target.provider.toUpperCase()} ${target.account}`;
    case 'web':
      return target.host;
    default:
      return 'Assessment target';
  }
}

/**
 * The exclusion RULES in force.
 *
 * Assessments recorded before binary files were counted separately carry the
 * sentence "Binary files are discovered and classified but not
 * content-analysed." in this list. It is a statement about `filesUnsupported`,
 * not a rule, so it is filtered here rather than tabled as "Excluded by
 * policy" beside the real binary-file count.
 */
export function policyExclusions(coverage: ScanCoverage): string[] {
  return coverage.exclusions.filter((entry) => !/^Binary files are discovered/i.test(entry));
}

/* ═════════════════════════════════════════════════ coverage dimensions ════ */

/**
 * The measurable dimensions of a scan, each with the engines that MEASURE it.
 *
 * A coverage figure of 0 is three different statements and the panels used to
 * make only one of them. "Kubernetes workloads 0" after the Kubernetes engine
 * read the corpus is a measurement; the same 0 when that engine was not in the
 * profile, or ran and failed, is not — yet all three printed as "Read, none
 * found … measurements of zero". The producer list is what tells them apart.
 *
 * ONE table, read by the Assessment Coverage panel, the Dev posture strip and
 * the report's Coverage Ledger, so they cannot classify the same zero
 * differently.
 */
export interface CoverageDimension {
  key: Exclude<keyof ScanCoverage, 'exclusions' | 'notAssessed' | 'truncated' | 'truncationNote' | 'truncatedBy'>;
  label: string;
  /** Engines whose completion makes a zero in this dimension a measurement. */
  producers: string[];
}

export const COVERAGE_DIMENSIONS: CoverageDimension[] = [
  { key: 'filesDiscovered', label: 'Files discovered', producers: ['file-discovery'] },
  { key: 'filesAnalyzed', label: 'Files analysed', producers: ['file-discovery'] },
  { key: 'filesUnsupported', label: 'Binary / unsupported', producers: ['file-discovery'] },
  { key: 'filesSkipped', label: 'Files skipped', producers: ['file-discovery'] },
  { key: 'dependencies', label: 'Dependencies', producers: ['dependency-analysis'] },
  { key: 'cryptoComponents', label: 'Crypto components', producers: ['source-crypto', 'certificate-material', 'dependency-analysis', 'cbom-generator'] },
  { key: 'certificates', label: 'Certificates', producers: ['certificate-material'] },
  { key: 'secrets', label: 'Secrets', producers: ['secret-discovery'] },
  { key: 'configFiles', label: 'Config files', producers: ['configuration-security'] },
  { key: 'containers', label: 'Containers', producers: ['container-security', 'registry-scan', 'k8s-live'] },
  { key: 'images', label: 'Images', producers: ['container-security', 'registry-scan'] },
  { key: 'kubernetesNamespaces', label: 'K8s namespaces', producers: ['kubernetes-security', 'k8s-live'] },
  { key: 'kubernetesWorkloads', label: 'K8s workloads', producers: ['kubernetes-security', 'k8s-live'] },
  { key: 'iacFiles', label: 'IaC files', producers: ['iac-security'] },
  { key: 'cicdWorkflows', label: 'CI/CD workflows', producers: ['cicd-security'] },
  { key: 'cloudResources', label: 'Cloud resources', producers: ['cloud-inventory', 'cloud-crypto'] },
  { key: 'branches', label: 'Branches', producers: ['git-history'] },
  { key: 'commitsAnalyzed', label: 'Commits analysed', producers: ['git-history'] },
];

/**
 * What a dimension's number means in THIS run.
 *
 *   measured        a positive count
 *   measured-zero   an engine that measures it completed (or found nothing in
 *                   scope to read) and counted none
 *   not-selected    no engine that measures it was part of the run
 *   not-reported    an engine that measures it was selected but failed, was
 *                   cancelled, skipped or could not assess — the zero is a gap
 */
export type CoverageReadingState = 'measured' | 'measured-zero' | 'not-selected' | 'not-reported';

export interface CoverageReading extends CoverageDimension {
  value: number;
  state: CoverageReadingState;
}

export function coverageReadings(coverage: ScanCoverage, runs: EngineRun[]): CoverageReading[] {
  const stateOf = new Map(runs.map((run) => [run.engineId, run.state]));
  return COVERAGE_DIMENSIONS.map((dimension) => {
    const value = Number(coverage[dimension.key] ?? 0) || 0;
    if (value > 0) return { ...dimension, value, state: 'measured' };
    const selected = dimension.producers.filter((id) => stateOf.has(id));
    if (selected.length === 0) return { ...dimension, value, state: 'not-selected' };
    const reported = selected.some((id) => stateOf.get(id) === 'completed' || stateOf.get(id) === 'not-applicable');
    return { ...dimension, value, state: reported ? 'measured-zero' : 'not-reported' };
  });
}

/* ═══════════════════════════════════════════════════════ scanned assets ═══ */

export interface AssetRow {
  id: string;
  name: string;
  /** Every layer the asset was observed through, joined for display. */
  kind: string;
  /** Live state, taken from the engine ledger rather than guessed. */
  state: 'scanned' | 'partial' | 'not-assessed';
  components: number;
  findings: number;
  critical: number;
  quantumVulnerable: number;
  /** Post-quantum only. Hybrid is counted separately — it is not the same claim. */
  pqc: number;
  hybrid: number;
  detail: string;
}

export interface AssetSummary {
  rows: AssetRow[];
  /** Rows the scan actually read and found something in. */
  scanned: number;
  /** Rows standing for an engine failure or an unread dimension. */
  gaps: number;
  /** Files the scan analysed, from the coverage ledger. */
  filesAnalyzed: number;
  /**
   * Files that were analysed and produced neither a finding nor a component.
   *
   * A row exists only where there was something to record, so the table has no
   * way to show a clean file — and the header's "N scanned" therefore counted
   * assets WITH EVIDENCE while reading as the size of the scanned estate. On a
   * 211-file corpus that published "128 scanned", understating the work by 83
   * files and quietly making every clean file invisible.
   */
  clean: number;
}

/**
 * The asset table plus the denominators its header needs.
 *
 * `rows` is `deriveAssets`; the rest is what stops the row count being read as
 * the size of the estate.
 */
export function summariseAssets(assessment: ExposureAssessment): AssetSummary {
  const rows = deriveAssets(assessment);
  const scanned = rows.filter((row) => row.state === 'scanned').length;
  const filesAnalyzed = assessment.task.coverage.filesAnalyzed;
  /* Only file-backed rows can be compared against the file ledger. A row named
     by scope or by layer (a cluster namespace, a cloud region) is not a file and
     must not be subtracted from one. */
  const fileRows = new Set(
    assessment.findings
      .map((finding) => finding.evidence[0]?.file)
      .concat(assessment.cbom.map((component) => component.file))
      .filter((file): file is string => typeof file === 'string' && file.length > 0),
  ).size;
  return {
    rows,
    scanned,
    gaps: rows.length - scanned,
    filesAnalyzed,
    clean: Math.max(0, filesAnalyzed - fileRows),
  };
}

/**
 * The name an asset is known by.
 *
 * Findings and components reach for the same identity through different fields,
 * so both fallbacks are spelled out here rather than once per call site — they
 * drifted apart when they were, and a file named by `reference` on one side and
 * `file` on the other became two assets.
 */
export function findingAssetName(finding: ExposureFinding): string {
  const evidence = finding.evidence[0];
  return evidence?.file ?? evidence?.reference ?? evidence?.scope ?? assessmentWide(finding.layer);
}

function componentAssetName(component: ExposureAssessment['cbom'][number]): string {
  return component.file ?? component.evidence[0]?.reference ?? assessmentWide(component.layer);
}

/**
 * The row for an observation that names no file, reference or scope — the
 * estate-wide quantum roll-ups, chiefly. It used to be the bare layer label,
 * so the inventory listed an asset called "Source code" that read as a file
 * the scan had opened.
 */
function assessmentWide(layer: ExposureFinding['layer']): string {
  return `Assessment-wide (${layerLabel(layer)})`;
}

/**
 * Derive the asset table.
 *
 * "Asset" here is the unit the estate is managed in — a file for source, a
 * manifest for a dependency, a workload for Kubernetes — because that is what a
 * reader can act on. Grouping by algorithm instead produces a table of
 * cryptography with no owner and no next step.
 *
 * An asset is identified by WHAT IT IS, never by the detection layer that
 * happened to observe it. The layer is an attribute of the observation and
 * belongs in the `kind` column, where all of them are listed.
 */
export function deriveAssets(assessment: ExposureAssessment): AssetRow[] {
  const byAsset = new Map<string, AssetRow>();
  const layersSeen = new Map<string, Set<string>>();

  const upsert = (id: string, name: string, kind: string): AssetRow => {
    const existing = byAsset.get(id);
    if (existing) return existing;
    const row: AssetRow = {
      id, name, kind,
      state: 'scanned',
      components: 0, findings: 0, critical: 0, quantumVulnerable: 0, pqc: 0, hybrid: 0,
      detail: '',
    };
    byAsset.set(id, row);
    return row;
  };

  const assetKey = (name: string) => `asset|${name}`;

  const noteLayer = (id: string, layer: ExposureFinding['layer']) => {
    let seen = layersSeen.get(id);
    if (!seen) {
      seen = new Set<string>();
      layersSeen.set(id, seen);
    }
    seen.add(layerLabel(layer));
  };

  for (const finding of assessment.findings) {
    const name = findingAssetName(finding);
    const id = assetKey(name);
    const row = upsert(id, name, layerLabel(finding.layer));
    noteLayer(id, finding.layer);
    row.findings += 1;
    if (finding.severity === 'critical') row.critical += 1;
    if (finding.quantumStatus === 'vulnerable') row.quantumVulnerable += 1;
    /* Hybrid is NOT post-quantum. It is a classical primitive still carrying a
       classical half, deployed alongside a PQC one — substantial migration
       progress, but the classical half has yet to be retired. Folding it into
       a column rendered as "pqc" told the reader that work was finished. */
    if (finding.quantumStatus === 'pqc') row.pqc += 1;
    if (finding.quantumStatus === 'hybrid') row.hybrid += 1;
  }

  for (const component of assessment.cbom) {
    const name = componentAssetName(component);
    const id = assetKey(name);
    const row = upsert(id, name, layerLabel(component.layer));
    noteLayer(id, component.layer);
    row.components += 1;
  }

  for (const [id, seen] of layersSeen) {
    const row = byAsset.get(id);
    if (row) row.kind = [...seen].sort().join(' · ');
  }

  /* Dimensions the scan could NOT read become rows in their own right (§64:
     never treat Not Scanned as Secure). Without this they vanish from the
     inventory, and an absent row reads as nothing to worry about. */
  for (const entry of assessment.task.coverage.notAssessed) {
    const row = upsert(`not-assessed|${entry.dimension}`, entry.dimension, 'Not assessed');
    row.state = 'not-assessed';
    row.detail = entry.reason;
  }

  /* Cancelled counts alongside failed. An engine stopped by the operator or by
     the time budget left the same hole as one that crashed, and the reconciler
     has always treated the two together — the table used to list only failures,
     so a cancelled engine's dimension vanished from the inventory entirely. */
  for (const run of assessment.task.runs) {
    if (run.state !== 'failed' && run.state !== 'cancelled') continue;
    const row = upsert(`${run.state}|${run.engineId}`, run.label,
      run.state === 'failed' ? 'Engine failure' : 'Engine cancelled');
    row.state = 'partial';
    row.detail = run.detail ?? 'The engine did not complete, so this dimension is incomplete rather than clean.';
  }

  const stateOrder: Record<AssetRow['state'], number> = { partial: 0, 'not-assessed': 1, scanned: 2 };
  return [...byAsset.values()].sort((a, b) => {
    if (a.state !== b.state) return stateOrder[a.state] - stateOrder[b.state];
    return b.critical - a.critical || b.quantumVulnerable - a.quantumVulnerable || b.findings - a.findings;
  });
}

/* ═══════════════════════════════════════════════ correlated exposures ═════ */

export interface CorrelationSummary {
  /** Exposures correlation actually merged — several findings, or several layers. */
  merged: CorrelatedExposure[];
  /** Of those, the ones that genuinely reach across layers. */
  crossLayer: number;
  /**
   * Exposures the panel does NOT render: one finding, one layer, nothing merged.
   *
   * They are still exposures. Every other surface counts them — the status bar
   * says "24 correlated exposures", the risk basis says "from 24 correlated
   * exposures" — so a panel that shows 7 without naming the other 17 reads as
   * the platform disagreeing with itself about how much was found.
   */
  singletons: number;
  /** The whole population, which is what every other panel reports. */
  total: number;
}

/**
 * Split the exposure population into what the panel shows and what it claims.
 *
 * These are two DIFFERENT claims and the header used to make the stronger one
 * for both: "merged several findings" is not "reached across layers", and a row
 * merging five findings inside one layer satisfies only the first.
 */
export function summariseCorrelation(exposures: CorrelatedExposure[]): CorrelationSummary {
  const merged = exposures.filter(
    (exposure) => exposure.findingIds.length > 1 || exposure.layers.length > 1,
  );
  return {
    merged,
    crossLayer: merged.filter((exposure) => exposure.layers.length > 1).length,
    singletons: exposures.length - merged.length,
    total: exposures.length,
  };
}

/* ═════════════════════════════════════════════════════ evidence matrix ════ */

export interface EvidencePopulation {
  /** Findings carrying at least one detection layer — all this table can plot. */
  corroborated: number;
  /** Findings with no detection layer at all: absent from the table, not ranked below it. */
  unbacked: number;
  total: number;
}

export function evidencePopulation(assessment: ExposureAssessment): EvidencePopulation {
  const corroborated = assessment.findings.filter((finding) =>
    finding.evidence.some((entry) => typeof entry.attributes?.detectionLayer === 'string'),
  ).length;
  return {
    corroborated,
    unbacked: assessment.findings.length - corroborated,
    total: assessment.findings.length,
  };
}

/* ══════════════════════════════════════════════════════ standards cited ═══ */

export interface StandardRow {
  publication: string;
  requirementType: string;
  applicability: string;
  /** DISTINCT findings citing this publication — the unit the column is labelled in. */
  findings: number;
}

/** `publication — TYPE, applies to: scope`, as written by citeStandard(). */
const CITATION = /^(.+?)\s+—\s+([A-Z_]+),\s+applies to:\s+([\s\S]+)$/;

export interface StandardsSummary {
  rows: StandardRow[];
  /** Findings citing at least one publication this panel could parse. */
  cited: number;
  /**
   * Findings citing none.
   *
   * They are absent from the table rather than ranked below it, and a
   * compliance reader counting the rows has no way to see them otherwise: the
   * per-row totals sum to far MORE than the finding count (one finding cites
   * several publications), so the arithmetic never reveals the gap.
   */
  uncited: number;
  total: number;
}

/**
 * Which standards the findings cite, and — the part §76 insists on — WHO each
 * one binds.
 *
 * Counts DISTINCT findings. Counting references instead silently converts the
 * column into a citation tally the moment one finding cites two clauses of the
 * same publication.
 */
export function summariseStandards(assessment: ExposureAssessment): StandardsSummary {
  const rows = deriveStandards(assessment);
  const cited = assessment.findings.filter((finding) =>
    (finding.references ?? []).some((reference) => CITATION.test(reference)),
  ).length;
  return {
    rows,
    cited,
    uncited: assessment.findings.length - cited,
    total: assessment.findings.length,
  };
}

export function deriveStandards(assessment: ExposureAssessment): StandardRow[] {
  const byPublication = new Map<string, StandardRow>();
  const citedBy = new Map<string, Set<string>>();

  for (const finding of assessment.findings) {
    for (const reference of finding.references ?? []) {
      const match = reference.match(CITATION);
      if (!match) continue;
      const publication = match[1];
      if (!byPublication.has(publication)) {
        byPublication.set(publication, {
          publication,
          requirementType: match[2],
          applicability: match[3],
          findings: 0,
        });
      }
      let seen = citedBy.get(publication);
      if (!seen) {
        seen = new Set<string>();
        citedBy.set(publication, seen);
      }
      seen.add(finding.id);
    }
  }

  for (const [publication, seen] of citedBy) {
    const row = byPublication.get(publication);
    if (row) row.findings = seen.size;
  }

  return [...byPublication.values()].sort((a, b) => b.findings - a.findings);
}

/* ═════════════════════════════════════════════════ algorithm chip row ═════ */

export interface AlgorithmChipCoverage {
  /** Groups rendered as chips. */
  shown: number;
  /** Distinct algorithm groups in the CBOM. */
  groups: number;
  /** Components the rendered chips account for. */
  components: number;
  /** Components in the CBOM. */
  total: number;
  /** True when the chips do not account for every component — the note must render. */
  truncated: boolean;
}

/**
 * What the "Algorithms observed" chip row does and does not account for.
 *
 * The row stops at the twelve largest groups. Rendered bare that is 487 of 515
 * components on a real scan, and a reader who sums the chips gets a total that
 * contradicts the CBOM cells directly above them.
 */
export function algorithmChipCoverage(assessment: ExposureAssessment): AlgorithmChipCoverage {
  const shown = assessment.intelligence.topAlgorithms;
  const groups = assessment.intelligence.algorithmGroups ?? shown.length;
  const components = shown.reduce((total, entry) => total + entry.count, 0);
  return {
    shown: shown.length,
    groups,
    components,
    total: assessment.cbom.length,
    truncated: groups > shown.length,
  };
}
