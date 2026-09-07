/**
 * Cryptographic Usage Discovery Engine™ — v3, semantic (§6, §9, §27-§29, §46-§49).
 *
 * WHAT CHANGED IN v3, AND WHY
 *
 * v2 was a single lexical pass over the 125-pattern catalogue with contextual
 * demotion. It was accurate about what it saw but it could only ever see a
 * NAME, so it could not answer the question the whole platform depends on:
 * what is this algorithm being used FOR? Without the role, §80's rule against
 * blanket migration advice cannot be honoured — every RSA finding gets the same
 * recommendation whether it signs a token or wraps a key.
 *
 * v3 runs three layers over one prepared document and fuses them:
 *
 *   API (§29)        `crypto.createSign('RSA-SHA256')` → RSA, SIGNATURE, SHA-256,
 *                    DIRECT evidence. The role is proven, not inferred.
 *   AST-lite / flow  KDF work factors, and weak RNG correlated with a nearby
 *        (§28,§17)   cryptographic use — §17 requires that correlation before a
 *                    weak PRNG may be called a cryptographic finding at all.
 *   Lexical (§47)    the existing catalogue, now recorded as WEAK evidence that
 *                    corroborates rather than as a finding in its own right.
 *
 * The Ground Truth Engine then decides confidence from how many INDEPENDENT
 * layers agree, so the same RSA seen by the API layer and the lexical layer is
 * one high-confidence component, not two findings.
 */

import { CRYPTO_PATTERNS } from '@/lib/scanner/web-scanner/crypto-patterns';
import {
  CAVEATS,
  KNOWLEDGE_BASE_VERSION,
  RULE_SET_VERSION,
  citeStandard,
  establishGroundTruth,
  provenanceFor,
  type CryptoClassification,
  type CryptoRole as KbCryptoRole,
  type GroundTruthVerdict,
} from '@/lib/crypto/knowledge-base';
import type { CryptoRole as ExposureRole, DetectionMethod, FindingConfidence, FindingSeverity, QuantumStatus } from '../types';
import type { EngineContext, EngineResult, ExposureEngine, WorkspaceFile } from '../engine-contract';
import { buildEvidence, buildFinding, completed, reportStride } from '../engine-contract';
import {
  contextualiseLexical,
  detectByApi,
  detectByDataFlow,
  groupForGroundTruth,
  languageOfPath,
  prepareDocument,
  type CryptoObservation,
} from './crypto-semantics';

/* ─────────────────────────────────────────────────────────────── budgets ──── */

const MAX_LINE_LENGTH = 4_000;
const MAX_LEXICAL_MATCHES_PER_FILE = 60;
const MAX_COMPONENTS = 1_200;
/** Window inside which the same lexical rule in one file is one match. */
const DEDUP_WINDOW = 5;

const SCANNED_CLASSES = new Set([
  'source', 'manifest', 'lockfile', 'config', 'container',
  'kubernetes', 'helm', 'iac', 'cicd', 'certificate', 'key-material',
]);

/* ───────────────────────────────────────────────── model bridging ─────────── */

/**
 * The knowledge base's 7-state quantum model, projected onto the exposure
 * model's 6 states.
 *
 * `CLASSICAL_ONLY` has no exposure-model equivalent and collapses to `unknown`,
 * which is correct: it means the role was never established, and `unknown` is
 * exactly what the UI should show for that.
 */
function toExposureQuantum(status: CryptoClassification['quantumStatus']): QuantumStatus {
  switch (status) {
    case 'QUANTUM_VULNERABLE': return 'vulnerable';
    case 'PQC_STANDARDIZED': return 'pqc';
    case 'HYBRID': return 'hybrid';
    case 'QUANTUM_RESISTANT': return 'resistant';
    case 'NOT_APPLICABLE': return 'not-applicable';
    default: return 'unknown';
  }
}

/** The ground-truth band, projected onto the exposure confidence vocabulary. */
function toExposureConfidence(verdict: GroundTruthVerdict): FindingConfidence {
  switch (verdict.confidenceBand) {
    case 'high': return 'high';
    case 'medium': return 'medium';
    case 'low': return 'low';
    default: return 'unknown';
  }
}

/**
 * The detection method, from the strongest layer that contributed.
 *
 * §63: an inference must never be rendered as an observation. The mapping is
 * therefore from the LAYER, not from the confidence — a high-confidence
 * inference is still an inference.
 */
function toDetectionMethod(observations: CryptoObservation[]): DetectionMethod {
  if (observations.some((entry) => entry.layer === 'api' && entry.quality === 'DIRECT')) return 'observed';
  if (observations.some((entry) => entry.layer === 'ast' && entry.quality === 'DIRECT')) return 'observed';
  if (observations.some((entry) => entry.layer === 'configuration')) return 'observed';
  if (observations.some((entry) => entry.layer === 'data-flow')) return 'inferred';
  if (observations.some((entry) => entry.quality === 'CIRCUMSTANTIAL')) return 'inferred';
  return 'potential';
}

/**
 * Severity from the two INDEPENDENT verdicts plus the role (§9, §45).
 *
 * Classical and quantum are considered separately and the worse one wins,
 * because they are different problems: SHA-1 is urgent for classical reasons
 * and irrelevant for quantum ones, RSA-2048 is the reverse.
 */
function severityFor(classification: CryptoClassification, verdict: GroundTruthVerdict): FindingSeverity {
  const ladder: FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

  let classical: FindingSeverity = 'info';
  if (classification.classicalSecurity === 'BROKEN') classical = 'high';
  else if (classification.classicalSecurity === 'LEGACY') classical = 'medium';

  let quantum: FindingSeverity = 'info';
  if (classification.quantumStatus === 'QUANTUM_VULNERABLE') {
    quantum = classification.quantumRelevant ? 'high' : 'medium';
  }

  let severity = ladder[Math.min(ladder.indexOf(classical), ladder.indexOf(quantum))];

  /* Internet-facing and long-lived roles escalate; both are §77 factors that
     are knowable at classification time. */
  const exposedRoles: KbCryptoRole[] = ['transport-security', 'certificate-public-key', 'certificate-signature', 'key-establishment', 'token-signing', 'code-signing'];
  if (severity === 'high' && exposedRoles.includes(classification.role)) severity = 'critical';

  /* An undersized key is a present-tense problem, not a future one. */
  if (classification.keySize && classification.keySize <= 1024 && classification.classicalSecurity !== 'STRONG') {
    severity = 'critical';
  }

  /* Confidence caps severity. §45 keeps the axes separate, but publishing a
     Critical on evidence that is only a lexical match is how a scanner loses
     its reader — so a low-confidence finding is demoted rather than suppressed,
     and both numbers stay visible. */
  if (verdict.confidenceBand === 'very-low') return ladder[Math.min(ladder.length - 1, ladder.indexOf(severity) + 2)];
  if (verdict.confidenceBand === 'low') return ladder[Math.min(ladder.length - 1, ladder.indexOf(severity) + 1)];

  return severity;
}

/* ─────────────────────────────────────────────── lexical pass (catalogue) ─── */

interface LexicalMatch {
  line: number;
  algorithm: string;
  ruleId: string;
  label: string;
}

/** Run the existing 125-pattern catalogue, deduplicated per (file, rule). */
function lexicalMatches(file: WorkspaceFile): LexicalMatch[] {
  const content = file.content as string;
  const lines = content.split('\n');
  const matches: LexicalMatch[] = [];
  const seen = new Map<number, number>();

  for (let index = 0; index < lines.length && matches.length < MAX_LEXICAL_MATCHES_PER_FILE; index += 1) {
    const line = lines[index];
    if (!line || line.length > MAX_LINE_LENGTH) continue;

    for (const pattern of CRYPTO_PATTERNS) {
      if (!pattern.regex.test(line)) continue;
      const previous = seen.get(pattern.id);
      if (previous !== undefined && Math.abs(previous - index) < DEDUP_WINDOW) continue;
      seen.set(pattern.id, index);
      matches.push({
        line: index + 1,
        algorithm: pattern.algorithm,
        ruleId: `crypto-pattern-${pattern.id}`,
        label: pattern.label,
      });
      if (matches.length >= MAX_LEXICAL_MATCHES_PER_FILE) break;
    }
  }

  return matches;
}

/* ────────────────────────────────────────────────────────────── the engine ── */

export const sourceCryptoEngine: ExposureEngine = {
  descriptor: {
    id: 'source-crypto',
    label: 'Cryptographic Usage Discovery',
    description:
      'Three-layer cryptographic detection — API semantics, data-flow correlation and the 125-rule lexical catalogue — fused by the Ground Truth Engine so confidence reflects how many independent layers agree.',
    mode: 'local',
    layer: 'source',
    capability: 'crypto',
    dependsOn: ['file-discovery'],
    weight: 25,
    privacySensitive: true,
  },

  appliesTo(context) {
    const eligible = context.workspace.files.some(
      (file) => file.content && !context.isExcluded(file.path) && SCANNED_CLASSES.has(file.classification),
    );
    return eligible
      ? { applicable: true }
      : { applicable: false, reason: 'No readable source, configuration or manifest files were in scope.' };
  },

  async execute(context: EngineContext): Promise<EngineResult> {
    const files = context.workspace.files.filter(
      (file) => file.content && !context.isExcluded(file.path) && SCANNED_CLASSES.has(file.classification),
    );

    const findings: ReturnType<typeof buildFinding>[] = [];
    const componentKeys = new Set<string>();
    const layerTally: Record<string, number> = { api: 0, ast: 0, 'data-flow': 0, lexical: 0 };
    let processed = 0;
    let truncated = false;

    /* One update per ~2% of the work, whatever the corpus size. */
    const sourceStride = reportStride(files.length);
    for (const file of files) {
      if (context.isCancelled()) break;
      if (findings.length >= MAX_COMPONENTS) {
        truncated = true;
        break;
      }

      processed += 1;
      if (processed % sourceStride === 0 || processed === files.length) {
        context.report(`Analysing ${file.path}`, { done: processed, total: files.length, unit: 'files' });
      }

      const language = languageOfPath(file.path);
      const document = prepareDocument(file.path, file.content as string, language);

      /* ── the three layers ─────────────────────────────────────────────── */
      const observations: CryptoObservation[] = [
        ...detectByApi(document),
        ...detectByDataFlow(document),
        ...contextualiseLexical(document, lexicalMatches(file)),
      ];
      if (observations.length === 0) continue;

      for (const observation of observations) {
        layerTally[observation.layer] = (layerTally[observation.layer] ?? 0) + 1;
      }

      /* ── fuse into components ─────────────────────────────────────────── */
      const groups = groupForGroundTruth(document, observations);

      for (const [key, group] of groups) {
        if (findings.length >= MAX_COMPONENTS) {
          truncated = true;
          break;
        }

        const verdict = establishGroundTruth(group.evidence);

        /* The richest observation wins for the published classification: an API
           observation knows the role and the digest, a lexical one knows only
           the name. Ordering by layer weight rather than by array position is
           what stops a lexical match overwriting an API one. */
        const primary = [...group.observations].sort(
          (a, b) => layerRank(b.layer) - layerRank(a.layer) || qualityRank(b.quality) - qualityRank(a.quality),
        )[0];
        const classification = primary.classification;

        /* An algorithm the knowledge base does not recognise is not published
           as a cryptographic component. §89 prefers fewer accurate findings. */
        if (!classification.algorithm) continue;

        /* Nothing to say about a strong, resistant, correctly-sized primitive
           in a non-quantum-relevant role — recording it as a FINDING would be
           noise. It still reaches the CBOM through the component key below,
           which is the right home for an inventory entry. */
        componentKeys.add(`${classification.canonicalName}|${classification.role}`);
        /* A rule that fired because of a PARAMETER (a low KDF work factor) or a
           CONTEXT (a weak PRNG near key material) is a finding about the
           configuration, not about the algorithm — bcrypt is a perfectly good
           algorithm at cost 12 and a finding at cost 8. Gating those on the
           algorithm's own verdict silently dropped them. */
        const parameterFinding = primary.ruleId.startsWith('kdf-') || primary.ruleId.startsWith('rand-');
        const nonSecurityUse = group.observations.some((entry) => entry.attributes?.nonSecurityUse === true);

        const worthReporting =
          !nonSecurityUse &&
          (parameterFinding ||
            classification.classicalSecurity === 'BROKEN' ||
            classification.classicalSecurity === 'LEGACY' ||
            classification.quantumStatus === 'QUANTUM_VULNERABLE' ||
            classification.quantumStatus === 'HYBRID' ||
            classification.quantumStatus === 'PQC_STANDARDIZED' ||
            primary.layer === 'data-flow');
        if (!worthReporting) continue;

        const severity = severityFor(classification, verdict);
        const confidence = toExposureConfidence(verdict);
        const detection = toDetectionMethod(group.observations);
        const provenance = provenanceFor(mapToRuleId(primary, classification));

        const description = [
          describeObservation(primary, classification),
          classification.classicalRationale,
          classification.quantumRationale,
          verdict.rationale,
          classification.undetermined.length
            ? `Not established: ${classification.undetermined.join(', ')}.`
            : '',
        ]
          .filter(Boolean)
          .join(' ');

        const finding = buildFinding({
          scanId: context.scanId,
          engineId: 'source-crypto',
          mode: context.mode,
          layer: file.classification === 'manifest' || file.classification === 'lockfile' ? 'dependency' : 'source',
          category: 'Cryptographic Usage',
          subcategory: classification.algorithm.family,
          title: buildTitle(classification, primary),
          description,
          severity,
          confidence,
          detection,
          algorithm: classification.observedAs,
          canonicalAlgorithm: classification.canonicalName,
          keySize: classification.keySize,
          cipherMode: classification.cipherMode ?? undefined,
          protocol: classification.protocol ?? undefined,
          library: classification.library?.canonicalName,
          role: toExposureRole(classification.role),
          quantumStatus: toExposureQuantum(classification.quantumStatus),
          quantumRationale: classification.quantumRationale,
          recommendation: buildRecommendation(classification),
          references: classification.standards.map(citeStandard),
          evidence: group.observations.slice(0, 5).map((observation) =>
            buildEvidence({
              summary: `${observation.classification.canonicalName} via ${observation.ruleId} (${observation.layer} layer, ${observation.quality.toLowerCase()} evidence) at ${file.path}:${observation.line}`,
              file: file.path,
              line: observation.line,
              snippet: observation.snippet,
              ruleId: observation.ruleId,
              localOnly: context.mode === 'local',
              attributes: {
                detectionLayer: observation.layer,
                evidenceQuality: observation.quality,
                language,
                role: observation.classification.role,
                roleBasis: observation.classification.roleBasis,
                ...(observation.enclosingFunction ? { enclosingFunction: observation.enclosingFunction } : {}),
                ...(observation.caveats.length ? { caveats: observation.caveats.join('; ') } : {}),
                ...(observation.attributes ?? {}),
              },
            }),
          ),
          identity: `${key}|${primary.line}`,
          migration:
            classification.quantumStatus === 'QUANTUM_VULNERABLE' && classification.quantumRelevant
              ? {
                  candidate: true,
                  target: classification.migrationTarget,
                  priority: classification.migrationPriority ?? 'P3',
                  complexity: complexityFor(classification.role),
                }
              : { candidate: false },
        });

        /* Reproducibility (§85-§87): the exact engine, rule and knowledge-base
           version that produced this finding, so the result can be re-derived
           and a change in output attributed to a change in logic. */
        finding.evidence[0].attributes = {
          ...finding.evidence[0].attributes,
          engineVersion: '3.0.0',
          knowledgeBaseVersion: KNOWLEDGE_BASE_VERSION,
          ruleSetVersion: RULE_SET_VERSION,
          ...(provenance ? { qghRuleId: provenance.ruleId, qghRuleVersion: provenance.ruleVersion } : {}),
          groundTruth: verdict.determination,
          confidenceScore: verdict.confidence,
          detectionLayers: verdict.layers.join(','),
        };

        findings.push(finding);
        context.emit(finding);
      }
    }

    if (layerTally.api === 0 && layerTally.lexical > 0) {
      /* Worth saying: a corpus where NO call site matched but names appeared is
         either a language the API catalogue does not cover, or documentation. */
      context.notAssessed(
        'Cryptographic call sites',
        'No cryptographic API call was matched in this corpus, so every cryptographic observation rests on lexical evidence alone and is reported at correspondingly low confidence. This is expected for configuration-only or documentation-only scopes, and for languages outside the API catalogue.',
      );
    }

    return completed(
      findings,
      {
        cryptoComponents: componentKeys.size,
        truncated,
        truncationNote: truncated
          ? `Cryptographic analysis stopped at the engine budget of ${MAX_COMPONENTS} components; the estate may contain more.`
          : undefined,
      },
      {
        filesAnalyzed: processed,
        componentKeys: [...componentKeys],
        detectionLayers: layerTally,
        engineVersion: '3.0.0',
      },
    );
  },
};

/* ─────────────────────────────────────────────────────────────── helpers ──── */

function layerRank(layer: CryptoObservation['layer']): number {
  const ranks: Record<string, number> = { api: 5, 'data-flow': 4, ast: 4, configuration: 3, dependency: 2, lexical: 1 };
  return ranks[layer] ?? 0;
}

function qualityRank(quality: CryptoObservation['quality']): number {
  return { DIRECT: 4, STRONG: 3, CIRCUMSTANTIAL: 2, WEAK: 1 }[quality];
}

/** Map the exposure model's role vocabulary onto the knowledge base's. */
function toExposureRole(role: KbCryptoRole): ExposureRole {
  const table: Partial<Record<KbCryptoRole, ExposureRole>> = {
    'key-establishment': 'key-exchange',
    'key-transport': 'key-exchange',
    'digital-signature': 'signature',
    'certificate-public-key': 'certificate',
    'certificate-signature': 'certificate',
    'transport-security': 'tls',
    'authenticated-encryption': 'encryption',
    'random-generation': 'random',
  };
  return table[role] ?? (role as ExposureRole);
}

function buildTitle(classification: CryptoClassification, primary: CryptoObservation): string {
  const size = classification.keySize ? `-${classification.keySize}` : '';
  const curve = classification.curve ? ` on ${classification.curve.canonicalName}` : '';
  const role = classification.role !== 'unknown' ? ` for ${classification.role.replace(/-/g, ' ')}` : '';

  if (primary.layer === 'data-flow' && primary.observedAlgorithm === 'Non-cryptographic PRNG') {
    return `Non-cryptographic PRNG near ${String(primary.attributes?.securityContext ?? 'cryptographic material')}`;
  }
  if (primary.attributes?.parameter && primary.ruleId.startsWith('kdf-')) {
    return `${classification.canonicalName} work factor below the recommended floor (${primary.attributes.observed} ${primary.attributes.unit})`;
  }
  return `${classification.canonicalName}${size}${curve}${role}`;
}

function describeObservation(primary: CryptoObservation, classification: CryptoClassification): string {
  if (primary.layer === 'api') {
    return `Observed at a call site: ${primary.attributes?.api ?? primary.ruleId}${
      classification.library ? ` through ${classification.library.canonicalName}` : ''
    }. The cryptographic role is established by the call, not inferred from context.`;
  }
  if (primary.layer === 'data-flow') {
    const guidance = primary.attributes?.guidance;
    return typeof guidance === 'string'
      ? guidance
      : `Correlated by data flow: ${primary.attributes?.replacement ? `use ${primary.attributes.replacement} instead. ` : ''}This is an inference from nearby identifiers, not a proven data path.`;
  }
  if (primary.layer === 'ast') {
    const guidance = primary.attributes?.guidance;
    return typeof guidance === 'string' ? guidance : 'Read from a literal parameter at the call site.';
  }
  return `Matched by the lexical catalogue (${primary.attributes?.pattern ?? primary.ruleId}). A name alone does not establish use, so this is reported at reduced confidence unless another layer corroborates it.`;
}

function buildRecommendation(classification: CryptoClassification): string | undefined {
  const parts: string[] = [];
  if (classification.classicalSecurity === 'BROKEN') {
    parts.push(
      `${classification.canonicalName} is broken by classical cryptanalysis and should be replaced regardless of any post-quantum consideration.`,
    );
  }
  if (classification.migrationTarget) {
    parts.push(`Plan migration to ${classification.migrationTarget}.`);
  } else if (classification.quantumStatus === 'QUANTUM_VULNERABLE' && classification.role === 'unknown') {
    /* §80: no target without a role. Say why, so the gap is actionable. */
    parts.push(
      'Establish what this key is used for before selecting a migration target — the correct post-quantum replacement differs for key establishment and for signatures.',
    );
  }
  return parts.length ? parts.join(' ') : undefined;
}

function complexityFor(role: KbCryptoRole): 'low' | 'medium' | 'high' {
  if (role === 'transport-security' || role === 'certificate-public-key' || role === 'certificate-signature') return 'medium';
  if (role === 'code-signing' || role === 'key-management') return 'high';
  return 'high';
}

/** Map an observation to the QGH rule that governs it, for provenance. */
function mapToRuleId(primary: CryptoObservation, classification: CryptoClassification): string {
  if (primary.ruleId.startsWith('rand-')) return 'QGH-RAND-001';
  if (primary.ruleId.startsWith('kdf-')) return 'QGH-KDF-001';
  const family = classification.algorithm?.family ?? '';
  if (family === 'RSA') {
    return classification.keySize && classification.keySize <= 1024 ? 'QGH-CRYPTO-RSA-002' : 'QGH-CRYPTO-RSA-001';
  }
  if (family === 'ECC') {
    return classification.curve && classification.curve.classicalStrength < 128 ? 'QGH-CRYPTO-ECC-002' : 'QGH-CRYPTO-ECC-001';
  }
  if (family === 'DH') return 'QGH-CRYPTO-DH-001';
  if (family === 'SHA-1' || family === 'MD') return 'QGH-HASH-001';
  if (classification.algorithm?.quantumStatus === 'PQC_STANDARDIZED') return 'QGH-LIB-001';
  return 'QGH-CRYPTO-RSA-001';
}

export { CAVEATS };
