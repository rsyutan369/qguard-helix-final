/**
 * QGuard Helix Finding Correlation Engine™ (§39, Spec-2 §37, §29-30).
 *
 * §39: "RSA-2048 detected by Crypto Scanner, Dependency Scanner, TLS Scanner,
 *       Certificate Scanner. Do not display four unrelated findings if they
 *       represent the same underlying exposure."
 *
 * Correlation happens on the EXPOSURE IDENTITY — (canonical algorithm,
 * cryptographic role, subject) — never on the finding text and never on the
 * engine. Two things follow from that choice:
 *
 *  • The same RSA key seen in source, in a dependency, in a container and on a
 *    certificate collapses to ONE exposure with four evidence sources.
 *  • Two genuinely different RSA keys — one signing tokens, one terminating TLS
 *    — stay two exposures, because their roles differ. A correlation key that
 *    ignored role would merge them and under-count the estate.
 *
 * The second job is the CRYPTOGRAPHIC PATH (Spec-2 §29): when the evidence
 * supports it, order the layers into the chain the specification describes —
 * source → dependency → container → registry → Kubernetes → ingress →
 * certificate → cloud → edge. Only layers with actual evidence appear. A path
 * is a claim about reality, so an inferred hop is never drawn.
 */

import type {
  CorrelatedExposure,
  ExposureEvidence,
  ExposureFinding,
  ExposureLayer,
  FindingConfidence,
  FindingSeverity,
  QuantumStatus,
} from './types';
import { SEVERITY_ORDER, stableHash } from './types';
import { canonicalAlgorithmName } from './algorithms';

/** The pipeline order a cryptographic path is drawn in. */
const LAYER_ORDER: ExposureLayer[] = [
  'source',
  'dependency',
  'secret',
  'configuration',
  'container',
  'registry',
  'iac',
  'cicd',
  'kubernetes',
  'cloud',
  'certificate',
  'identity',
  'edge',
  'runtime',
];

const LAYER_LABEL: Record<ExposureLayer, string> = {
  source: 'Source code',
  dependency: 'Dependency',
  secret: 'Secret material',
  configuration: 'Configuration',
  container: 'Container',
  registry: 'Registry',
  iac: 'Infrastructure as code',
  cicd: 'CI/CD pipeline',
  kubernetes: 'Kubernetes',
  cloud: 'Cloud service',
  certificate: 'Certificate',
  identity: 'Identity',
  edge: 'Internet edge',
  runtime: 'Runtime',
};

const CONFIDENCE_RANK: Record<FindingConfidence, number> = { high: 3, medium: 2, low: 1, unknown: 0 };
const QUANTUM_RANK: Record<QuantumStatus, number> = {
  vulnerable: 5, hybrid: 4, pqc: 3, resistant: 2, unknown: 1, 'not-applicable': 0,
};

/**
 * The correlation key.
 *
 * Cryptographic findings correlate on (algorithm, role). Non-cryptographic
 * findings — a privileged container, a committed secret — correlate on
 * (category, subcategory, subject), because two privileged containers in two
 * files are two problems, not one.
 */
export function correlationKeyFor(finding: ExposureFinding): string {
  const algorithm = finding.canonicalAlgorithm ?? (finding.algorithm ? canonicalAlgorithmName(finding.algorithm) : null);

  if (algorithm && finding.quantumStatus !== 'not-applicable') {
    const keySize = finding.keySize ? `-${finding.keySize}` : '';
    return `crypto:${algorithm}${keySize}:${finding.role ?? 'unknown'}`;
  }

  const subject =
    finding.evidence[0]?.reference ??
    finding.evidence[0]?.file ??
    finding.component ??
    finding.title;
  return `issue:${finding.category}:${finding.subcategory ?? ''}:${subject}`;
}

/** Merge findings into correlated exposures. */
export function correlateFindings(findings: ExposureFinding[]): CorrelatedExposure[] {
  const groups = new Map<string, ExposureFinding[]>();

  for (const finding of findings) {
    const key = correlationKeyFor(finding);
    finding.correlationKey = key;
    const list = groups.get(key) ?? [];
    list.push(finding);
    groups.set(key, list);
  }

  const exposures: CorrelatedExposure[] = [];

  for (const [key, members] of groups) {
    const sorted = [...members].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
    const primary = sorted[0];

    /* Severity is the worst member's, because the exposure is as bad as its
       worst manifestation. Confidence is the BEST member's, because independent
       corroboration raises confidence — four engines seeing the same RSA key is
       stronger evidence than one, and taking the minimum would punish the
       estate for being thoroughly scanned. */
    const severity: FindingSeverity = primary.severity;
    const confidence = sorted.reduce<FindingConfidence>(
      (best, finding) => (CONFIDENCE_RANK[finding.confidence] > CONFIDENCE_RANK[best] ? finding.confidence : best),
      'unknown',
    );
    const quantumStatus = sorted.reduce<QuantumStatus>(
      (worst, finding) => (QUANTUM_RANK[finding.quantumStatus] > QUANTUM_RANK[worst] ? finding.quantumStatus : worst),
      'not-applicable',
    );

    const layers = uniqueLayersInOrder(sorted.map((finding) => finding.layer));
    const evidence = dedupeEvidence(sorted.flatMap((finding) => finding.evidence));

    /* Cross-layer relationships are recorded on the findings themselves so the
       exposure graph can draw them. */
    if (sorted.length > 1) {
      const ids = sorted.map((finding) => finding.id);
      for (const finding of sorted) {
        finding.relatedTo = ids.filter((id) => id !== finding.id);
      }
    }

    const migrationSource = sorted.find((finding) => finding.migration?.candidate);

    exposures.push({
      key,
      title: exposureTitle(primary, sorted.length, layers),
      severity,
      confidence,
      quantumStatus,
      canonicalAlgorithm: primary.canonicalAlgorithm,
      role: primary.role,
      layers,
      findingIds: sorted.map((finding) => finding.id),
      evidence,
      recommendation: sorted.find((finding) => finding.recommendation)?.recommendation,
      path: layers.length > 1 ? buildPath(sorted, layers) : undefined,
      migration: migrationSource?.migration,
    });
  }

  return exposures.sort((a, b) => {
    const severityDelta = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (severityDelta !== 0) return severityDelta;
    return b.evidence.length - a.evidence.length;
  });
}

function uniqueLayersInOrder(layers: ExposureLayer[]): ExposureLayer[] {
  const present = new Set(layers);
  return LAYER_ORDER.filter((layer) => present.has(layer));
}

function exposureTitle(primary: ExposureFinding, count: number, layers: ExposureLayer[]): string {
  if (primary.canonicalAlgorithm && primary.quantumStatus !== 'not-applicable') {
    const keySize = primary.keySize ? `-${primary.keySize}` : '';
    const role = primary.role && primary.role !== 'unknown' ? ` (${primary.role.replace(/-/g, ' ')})` : '';
    const suffix = count > 1 ? ` — ${count} occurrences across ${layers.length} layer${layers.length === 1 ? '' : 's'}` : '';
    return `${primary.canonicalAlgorithm}${keySize}${role}${suffix}`;
  }
  return count > 1 ? `${primary.title} (+${count - 1} more)` : primary.title;
}

function dedupeEvidence(evidence: ExposureEvidence[]): ExposureEvidence[] {
  const seen = new Set<string>();
  const out: ExposureEvidence[] = [];
  for (const item of evidence) {
    const key = stableHash(`${item.file ?? ''}|${item.line ?? ''}|${item.ruleId ?? ''}|${item.reference ?? ''}|${item.summary}`);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

/**
 * The cryptographic path.
 *
 * Each hop is a layer that actually produced evidence for THIS exposure, with
 * the most specific label that evidence carries. Nothing is interpolated: if
 * there is source evidence and Kubernetes evidence but no container evidence,
 * the path shows two hops, not three with a guess in the middle.
 */
function buildPath(findings: ExposureFinding[], layers: ExposureLayer[]): CorrelatedExposure['path'] {
  return layers.map((layer) => {
    const member = findings.find((finding) => finding.layer === layer);
    const evidence = member?.evidence[0];
    const detail = evidence?.reference ?? evidence?.file ?? member?.component ?? undefined;
    return { layer, label: LAYER_LABEL[layer], detail };
  });
}

/** Human label for a layer, for the UI. */
export function layerLabel(layer: ExposureLayer): string {
  return LAYER_LABEL[layer];
}
