/**
 * Cryptographic Ground Truth Engine™ (§45, §46, §47, §48, §49, §90).
 *
 * §49: "Was it actually observed? Where? How? By which engine? With what
 *       evidence? Can another scanner confirm it? What is the confidence?"
 *
 * This module answers those seven questions and nothing else. It does not
 * detect anything; it decides how much to believe what a detector reported.
 *
 * THE FOUR AXES §45 REQUIRES BE KEPT APART
 *
 *   SEVERITY          how bad it is IF real            — set by the rule
 *   CONFIDENCE        how sure we are that it is real  — computed here
 *   EVIDENCE QUALITY  how good the proof is            — computed here
 *   COVERAGE          how much we looked at            — set by the scan
 *
 * "Never equate High Severity with High Confidence." A committed private key is
 * Critical/High. A bare `RSA` in a comment is Critical-if-real/Very-low, and
 * conflating them is what makes a scanner unusable.
 *
 * §47's multi-layer model is the mechanism: the more INDEPENDENT layers agree,
 * the higher the confidence. Two lexical matches of the same string are not
 * two pieces of evidence — they are one, seen twice — so the model counts
 * DISTINCT layers, never observation count.
 */

import type {
  DetectionLayer,
  DeterminationState,
  EvidenceQuality,
  EvidenceType,
} from './types';
import { DETECTION_LAYER_WEIGHT, EVIDENCE_QUALITY_RANK } from './types';

/* ══════════════════════════════════════════════════════════ evidence item ══ */

/** One thing a detector actually saw. */
export interface GroundTruthEvidence {
  /** Which engine produced it. */
  engineId: string;
  /** How the detector knows. */
  evidenceType: EvidenceType;
  /** How good the proof is on its own. */
  quality: EvidenceQuality;
  /** Which of the eight §47 layers this came from. */
  layer: DetectionLayer;
  /** Human sentence. Required — a finding without one cannot be reviewed. */
  summary: string;
  /** Where. Redacted before it reaches here. */
  location?: { file?: string; line?: number; reference?: string; scope?: string };
  /** The rule that fired, with its version, for reproducibility (§86). */
  ruleId?: string;
  ruleVersion?: string;
  observedAt: string;
  /** Context that WEAKENS the evidence, recorded rather than discarded. */
  caveats?: string[];
}

/* ═══════════════════════════════════════════════════════════ the verdict ═══ */

export interface GroundTruthVerdict {
  /** §90's four permitted states. */
  determination: DeterminationState;
  /** 0-100. Published alongside the band, never instead of it. */
  confidence: number;
  confidenceBand: 'high' | 'medium' | 'low' | 'very-low';
  /** The best single piece of evidence backing this. */
  bestQuality: EvidenceQuality;
  /** Distinct §47 layers that agree. */
  layers: DetectionLayer[];
  /** Distinct engines that agree — the §48 cross-scanner signal. */
  corroboratingEngines: string[];
  /** Why the confidence is what it is. Rendered verbatim, never hidden. */
  rationale: string;
  /** Everything that reduced confidence, named. */
  caveats: string[];
}

/**
 * Compute ground truth from a set of evidence.
 *
 * The scoring is deliberately simple and auditable rather than tuned:
 *
 *   base        the best single evidence quality sets the ceiling
 *   corroboration each ADDITIONAL distinct layer adds its weight
 *   caveats     each recorded caveat subtracts
 *
 * A single WEAK lexical match can never reach "high" no matter how many times
 * the same string appears, because repetition adds no layers.
 */
export function establishGroundTruth(evidence: GroundTruthEvidence[]): GroundTruthVerdict {
  if (evidence.length === 0) {
    return {
      determination: 'UNKNOWN',
      confidence: 0,
      confidenceBand: 'very-low',
      bestQuality: 'WEAK',
      layers: [],
      corroboratingEngines: [],
      rationale: 'No evidence was supplied, so nothing is asserted.',
      caveats: ['No evidence.'],
    };
  }

  const layers = [...new Set(evidence.map((item) => item.layer))];
  const engines = [...new Set(evidence.map((item) => item.engineId))];
  const caveats = [...new Set(evidence.flatMap((item) => item.caveats ?? []))];

  const bestQuality = evidence.reduce<EvidenceQuality>(
    (best, item) => (EVIDENCE_QUALITY_RANK[item.quality] > EVIDENCE_QUALITY_RANK[best] ? item.quality : best),
    'WEAK',
  );

  /* ── base score from the strongest single proof ────────────────────────── */
  const base: Record<EvidenceQuality, number> = { DIRECT: 72, STRONG: 55, CIRCUMSTANTIAL: 34, WEAK: 18 };
  let score = base[bestQuality];

  /* ── corroboration: distinct layers beyond the first ───────────────────── */
  const sortedLayers = [...layers].sort((a, b) => DETECTION_LAYER_WEIGHT[b] - DETECTION_LAYER_WEIGHT[a]);
  for (const layer of sortedLayers.slice(1)) {
    score += DETECTION_LAYER_WEIGHT[layer] * 2;
  }

  /* ── cross-scanner agreement (§48) ─────────────────────────────────────── */
  if (engines.length > 1) score += Math.min(10, (engines.length - 1) * 5);

  /* ── caveats subtract ──────────────────────────────────────────────────── */
  score -= caveats.length * 9;

  score = Math.max(2, Math.min(99, Math.round(score)));

  const determination: DeterminationState =
    bestQuality === 'DIRECT' && score >= 70
      ? 'CONFIRMED'
      : score >= 40
        ? 'POTENTIAL'
        : bestQuality === 'WEAK'
          ? 'POTENTIAL'
          : 'UNKNOWN';

  const band: GroundTruthVerdict['confidenceBand'] =
    score >= 75 ? 'high' : score >= 50 ? 'medium' : score >= 30 ? 'low' : 'very-low';

  const parts: string[] = [];
  parts.push(
    `Strongest evidence is ${bestQuality.toLowerCase()} (${describeQuality(bestQuality)}), from ${describeLayer(sortedLayers[0])}.`,
  );
  if (layers.length > 1) {
    parts.push(`${layers.length} independent detection layers agree (${layers.map(describeLayer).join(', ')}).`);
  }
  if (engines.length > 1) {
    parts.push(`${engines.length} engines corroborate: ${engines.join(', ')}.`);
  }
  if (caveats.length > 0) {
    parts.push(`Confidence is reduced by: ${caveats.join('; ')}.`);
  }

  return {
    determination,
    confidence: score,
    confidenceBand: band,
    bestQuality,
    layers,
    corroboratingEngines: engines,
    rationale: parts.join(' '),
    caveats,
  };
}

function describeQuality(quality: EvidenceQuality): string {
  switch (quality) {
    case 'DIRECT': return 'the artefact itself was read';
    case 'STRONG': return 'an authoritative statement about the artefact';
    case 'CIRCUMSTANTIAL': return 'a fact that makes the conclusion likely but does not establish it';
    default: return 'a lexical match with no supporting context';
  }
}

function describeLayer(layer: DetectionLayer | undefined): string {
  if (!layer) return 'an unspecified layer';
  const labels: Record<DetectionLayer, string> = {
    lexical: 'a lexical match',
    ast: 'syntactic analysis',
    api: 'API semantics',
    configuration: 'a configuration directive',
    dependency: 'a dependency declaration',
    'data-flow': 'data-flow correlation',
    runtime: 'a runtime observation',
    'cross-scanner': 'cross-scanner correlation',
  };
  return labels[layer];
}

/* ══════════════════════════════════════════════════════ cross-correlation ══ */

/**
 * Merge evidence for what is provably the same cryptographic component (§48).
 *
 * `identityKey` must be the CRYPTOGRAPHIC identity — (algorithm, role,
 * subject) — never the finding text and never the engine. Two engines seeing
 * the same RSA key is corroboration; two different RSA keys with the same
 * algorithm name are two components, and merging them under-counts the estate.
 */
export function correlateEvidence(
  groups: Map<string, GroundTruthEvidence[]>,
): Map<string, GroundTruthVerdict> {
  const out = new Map<string, GroundTruthVerdict>();
  for (const [key, items] of groups) {
    const verdict = establishGroundTruth(items);
    /* A component confirmed by several engines gains the cross-scanner layer,
       which is exactly the §48 signal and is recorded rather than folded
       silently into the number. */
    if (verdict.corroboratingEngines.length > 1 && !verdict.layers.includes('cross-scanner')) {
      out.set(
        key,
        establishGroundTruth([
          ...items,
          {
            engineId: 'ground-truth',
            evidenceType: 'INFERENCE',
            quality: 'STRONG',
            layer: 'cross-scanner',
            summary: `Independently reported by ${verdict.corroboratingEngines.length} engines: ${verdict.corroboratingEngines.join(', ')}.`,
            observedAt: new Date().toISOString(),
          },
        ]),
      );
      continue;
    }
    out.set(key, verdict);
  }
  return out;
}

/* ═══════════════════════════════════════════════════════ caveat vocabulary ══ */

/**
 * The standard caveats, so every engine phrases the same doubt the same way
 * and the confidence penalty is consistent across the platform.
 */
export const CAVEATS = {
  inComment: 'the match is inside a comment, so it may describe intent rather than a call site',
  testPath: 'the file is on a test, fixture or example path',
  examplePath: 'the file is named as an example or template',
  negationContext: 'the surrounding line reads as a control that disables the algorithm rather than a use of it',
  noCallSite: 'the algorithm name appears without a call, assignment or configuration key',
  declaredNotUsed: 'the dependency declares the capability but no call site was observed (§26: available is not used)',
  templated: 'the manifest is an unrendered template, so the effective value may differ',
  truncated: 'the artefact was truncated by a scan budget',
  minified: 'the file appears to be minified or generated',
  unverifiedTransitive: 'the dependency is transitive and may not be reachable from application code',
} as const;

/* ════════════════════════════════════════════════════ engine versioning ═════ */

/**
 * §85, §86, §87: a finding must be traceable to the exact engine and rule
 * version that produced it, so a scan is reproducible and a rule change can be
 * correlated with a change in results.
 */
export interface EngineVersion {
  engineId: string;
  version: string;
  /** Bumped whenever the rule SET changes, independently of the engine code. */
  ruleSetVersion: string;
}

/**
 * The version register.
 *
 * These are hand-maintained and MUST be bumped when detection behaviour
 * changes — that is the whole point. A stale version silently breaks
 * reproducibility, so `tools/scanner-engine-check.ts` asserts every registered
 * engine appears here.
 */
export const ENGINE_VERSIONS: Record<string, EngineVersion> = {
  'file-discovery': { engineId: 'file-discovery', version: '2.0.0', ruleSetVersion: '2.0.0' },
  'source-crypto': { engineId: 'source-crypto', version: '3.0.0', ruleSetVersion: '3.0.0' },
  'secret-discovery': { engineId: 'secret-discovery', version: '2.1.0', ruleSetVersion: '2.1.0' },
  'dependency-analysis': { engineId: 'dependency-analysis', version: '2.1.0', ruleSetVersion: '2.1.0' },
  'configuration-security': { engineId: 'configuration-security', version: '2.1.0', ruleSetVersion: '2.1.0' },
  'certificate-material': { engineId: 'certificate-material', version: '3.0.0', ruleSetVersion: '3.0.0' },
  'container-security': { engineId: 'container-security', version: '2.0.0', ruleSetVersion: '2.0.0' },
  'kubernetes-security': { engineId: 'kubernetes-security', version: '2.1.0', ruleSetVersion: '2.1.0' },
  'iac-security': { engineId: 'iac-security', version: '2.0.0', ruleSetVersion: '2.0.0' },
  'cicd-security': { engineId: 'cicd-security', version: '2.0.0', ruleSetVersion: '2.0.0' },
  'git-history': { engineId: 'git-history', version: '2.0.0', ruleSetVersion: '2.0.0' },
  'cbom-generator': { engineId: 'cbom-generator', version: '3.0.0', ruleSetVersion: '3.0.0' },
  'quantum-assessment': { engineId: 'quantum-assessment', version: '3.0.0', ruleSetVersion: '3.0.0' },
  'supply-chain': { engineId: 'supply-chain', version: '2.0.0', ruleSetVersion: '2.0.0' },
  'k8s-live': { engineId: 'k8s-live', version: '2.0.0', ruleSetVersion: '2.0.0' },
  'registry-scan': { engineId: 'registry-scan', version: '2.0.0', ruleSetVersion: '2.0.0' },
  'cloud-inventory': { engineId: 'cloud-inventory', version: '2.0.0', ruleSetVersion: '2.0.0' },
  'cloud-crypto': { engineId: 'cloud-crypto', version: '2.0.0', ruleSetVersion: '2.0.0' },
};

/** The knowledge base's own version, stamped on every classification. */
export const KNOWLEDGE_BASE_VERSION = '1.0.0';

export function engineVersion(engineId: string): EngineVersion {
  return ENGINE_VERSIONS[engineId] ?? { engineId, version: 'unversioned', ruleSetVersion: 'unversioned' };
}

/**
 * The reproducibility stamp (§87).
 *
 * Recorded on every scan so a result can be re-derived, and so a difference
 * between two scans can be attributed to a rule change rather than to the
 * estate changing.
 */
export interface ReproducibilityStamp {
  knowledgeBaseVersion: string;
  engines: EngineVersion[];
  generatedAt: string;
}

export function reproducibilityStamp(engineIds: string[]): ReproducibilityStamp {
  return {
    knowledgeBaseVersion: KNOWLEDGE_BASE_VERSION,
    engines: engineIds.map(engineVersion),
    generatedAt: new Date().toISOString(),
  };
}
