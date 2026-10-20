/**
 * Late-stage engines: CBOM, Quantum Assessment and Supply Chain.
 *
 * These three do not read files. They read the FINDINGS the content engines
 * already produced, which the orchestrator publishes on
 * `workspace.meta.findings` before the late stage runs. Modelling them as real
 * engines rather than as post-processing matters: they appear in the ledger,
 * they report progress, they can fail, and a scan whose quantum assessment did
 * not run is reported as PARTIAL rather than as complete-with-no-quantum-data.
 */

import type { ExposureFinding } from '../types';
import type { EngineContext, EngineResult, ExposureEngine } from '../engine-contract';
import { buildEvidence, buildFinding, completed, inventoryObservations, notApplicable } from '../engine-contract';
import { buildCbom, summariseCbom } from '../cbom';
import { classifyQuantum } from '../algorithms';

function accumulatedFindings(context: EngineContext): ExposureFinding[] {
  return (context.workspace.meta.findings as ExposureFinding[] | undefined) ?? [];
}

/**
 * Everything the CBOM is composed from: the findings AND the inventory
 * observations — cryptography that is present but raised nothing to act on.
 * The orchestrator's fallback builds from the same union, so the bill of
 * materials is identical whether or not this engine was selected.
 */
export function cbomSources(context: { workspace: EngineContext['workspace'] }): ExposureFinding[] {
  return [
    ...((context.workspace.meta.findings as ExposureFinding[] | undefined) ?? []),
    ...inventoryObservations(context.workspace),
  ];
}

/* ──────────────────────────────────────────────────────────── CBOM engine ── */

export const cbomEngine: ExposureEngine = {
  descriptor: {
    id: 'cbom-generator',
    label: 'CBOM Generation',
    description: 'Composes the Cryptographic Bill of Materials from every cryptographic component the other engines observed, with dependency edges between layers.',
    mode: 'local',
    layer: 'source',
    capability: 'cbom',
    dependsOn: ['source-crypto', 'dependency-analysis', 'certificate-material'],
    weight: 5,
  },

  appliesTo(context) {
    return cbomSources(context).length > 0
      ? { applicable: true }
      : { applicable: false, reason: 'No cryptographic observation was produced, so there is no cryptographic inventory to compose.' };
  },

  async execute(context: EngineContext): Promise<EngineResult> {
    const sources = cbomSources(context);
    context.report('Composing cryptographic inventory', { done: 0, total: sources.length, unit: 'observations' });

    const components = buildCbom(sources);
    const summary = summariseCbom(components);

    context.workspace.meta.cbom = components;
    context.workspace.meta.cbomSummary = summary;
    context.report('Cryptographic inventory composed', { done: sources.length, total: sources.length, unit: 'observations' });

    return completed([], { cryptoComponents: components.length }, { components: components.length, summary });
  },
};

/* ───────────────────────────────────────────────── quantum readiness engine ── */

export const quantumEngine: ExposureEngine = {
  descriptor: {
    id: 'quantum-assessment',
    label: 'Quantum Readiness Assessment',
    description: 'Classifies every cryptographic component as vulnerable, hybrid, post-quantum or resistant by algorithm AND role, and publishes the readiness ratio over the quantum-relevant population only.',
    mode: 'local',
    layer: 'source',
    capability: 'quantum',
    dependsOn: ['cbom-generator'],
    weight: 6,
  },

  appliesTo(context) {
    return cbomSources(context).length > 0
      ? { applicable: true }
      : { applicable: false, reason: 'No cryptographic evidence was collected, so no quantum verdict is published.' };
  },

  async execute(context: EngineContext): Promise<EngineResult> {
    const components = (context.workspace.meta.cbom as ReturnType<typeof buildCbom> | undefined) ?? [];
    if (components.length === 0) {
      return notApplicable('No cryptographic components were inventoried, so there is nothing to assess for quantum exposure.');
    }

    const summary = summariseCbom(components);
    context.report('Classifying quantum exposure', { done: components.length, total: components.length, unit: 'components' });

    const findings: ExposureFinding[] = [];

    /* One roll-up finding, and only when there is something to say. It exists
       so the estate-level verdict is itself evidence-backed and exportable —
       not so the finding count can be padded. */
    if (summary.vulnerable > 0) {
      /* Count the VULNERABLE members of each group, not the group total.
         Filtering on a single per-algorithm status dropped any group whose
         dominant status was something else — even when it carried vulnerable
         components — and printed the full group size for the ones it kept, so
         the "largest contributors" did not add up to the total they explained. */
      const worstAlgorithms = summary.byAlgorithm
        .map((entry) => ({
          algorithm: entry.algorithm,
          vulnerable: entry.mix.find((slice) => slice.status === 'vulnerable')?.count ?? 0,
        }))
        .filter((entry) => entry.vulnerable > 0)
        .sort((a, b) => b.vulnerable - a.vulnerable)
        .slice(0, 5)
        .map((entry) => `${entry.algorithm} (${entry.vulnerable})`);

      const finding = buildFinding({
        scanId: context.scanId,
        engineId: 'quantum-assessment',
        mode: context.mode,
        layer: 'source',
        category: 'Quantum Exposure',
        subcategory: 'Estate assessment',
        title: `${summary.vulnerable} quantum-vulnerable cryptographic component${summary.vulnerable === 1 ? '' : 's'} in scope`,
        description: [
          `Of ${summary.total} cryptographic components inventoried, ${summary.vulnerable} are broken by Shor's algorithm, ${summary.hybrid} are hybrid deployments and ${summary.pqc} are natively post-quantum.`,
          summary.readiness === null
            ? 'No post-quantum readiness percentage is published because no quantum-relevant component was observed.'
            : `Post-quantum readiness across the quantum-relevant population is ${summary.readiness}%.`,
          worstAlgorithms.length ? `The largest contributors are ${worstAlgorithms.join(', ')}.` : '',
          /* This used to assert "at adequate key sizes" unconditionally. On a
             corpus where all 230 resistant components were MD5, SHA-1, RC4 and
             DES, the platform published that sentence about primitives it had
             itself flagged as classically broken. Resistant is a verdict about
             Shor's algorithm; it is not a clean bill of health. */
          /* "at adequate key sizes" used to close this sentence unconditionally.
             The resistant bucket now carries the whole inventory — AES-128
             included — so the claim is limited to what the verdict means. */
          `${summary.resistant} symmetric, hash, MAC and key-derivation component${summary.resistant === 1 ? ' is' : 's are'} not broken by Shor's algorithm and ${summary.resistant === 1 ? 'is' : 'are'} excluded from the readiness ratio, because ${summary.resistant === 1 ? 'its' : 'their'} presence says nothing about the state of the asymmetric cryptography that actually needs migrating.`,
          summary.classicallyWeak > 0
            ? `${summary.classicallyWeak} of them ${summary.classicallyWeak === 1 ? 'is' : 'are'} nevertheless broken by classical cryptanalysis (MD5, SHA-1, RC4, DES and similar) and need${summary.classicallyWeak === 1 ? 's' : ''} replacing on ${summary.classicallyWeak === 1 ? 'its' : 'their'} own merits, independently of any quantum timeline.`
            : '',
        ].filter(Boolean).join(' '),
        severity: summary.vulnerable > 0 && summary.readiness !== null && summary.readiness < 25 ? 'high' : 'medium',
        confidence: 'high',
        detection: 'observed',
        quantumStatus: 'vulnerable',
        quantumRationale: 'Aggregated from the per-component verdicts, each of which states its own basis.',
        recommendation:
          'Work the migration in priority order: Internet-facing key agreement first, then long-lived signatures (certificates, code signing, tokens), then internal key exchange.',
        evidence: [
          buildEvidence({
            summary: `${summary.vulnerable} of ${summary.total} inventoried components classified quantum-vulnerable.`,
            ruleId: 'quantum-estate-rollup',
            localOnly: context.mode === 'local',
            attributes: {
              total: summary.total,
              vulnerable: summary.vulnerable,
              hybrid: summary.hybrid,
              pqc: summary.pqc,
              resistant: summary.resistant,
              readiness: summary.readiness ?? -1,
            },
          }),
        ],
        identity: `quantum-rollup|${context.scanId}`,
      });
      findings.push(finding);
      context.emit(finding);
    }

    if (summary.hybrid > 0 || summary.pqc > 0) {
      const finding = buildFinding({
        scanId: context.scanId,
        engineId: 'quantum-assessment',
        mode: context.mode,
        layer: 'source',
        category: 'Quantum Readiness',
        subcategory: 'Post-quantum adoption',
        title: `${summary.pqc + summary.hybrid} post-quantum or hybrid component${summary.pqc + summary.hybrid === 1 ? '' : 's'} already deployed`,
        description: `${summary.pqc} natively post-quantum and ${summary.hybrid} hybrid cryptographic component${summary.hybrid === 1 ? '' : 's'} were observed. This is migration work already completed, and it is recorded as evidence of readiness rather than as an exposure.`,
        severity: 'info',
        confidence: 'high',
        detection: 'observed',
        quantumStatus: summary.pqc > 0 ? 'pqc' : 'hybrid',
        quantumRationale: 'Standardised post-quantum primitives were observed in the estate.',
        evidence: [
          buildEvidence({
            summary: `${summary.pqc} PQC and ${summary.hybrid} hybrid components inventoried.`,
            ruleId: 'quantum-adoption-rollup',
            localOnly: context.mode === 'local',
          }),
        ],
        identity: `quantum-adoption|${context.scanId}`,
      });
      findings.push(finding);
      context.emit(finding);
    }

    return completed(findings, {}, { summary });
  },
};

/* ───────────────────────────────────────────────── supply chain engine ───── */

/**
 * Software Supply Chain Engine™ (Spec-2 §24).
 *
 * Looks for INCONSISTENCIES across layers, which is the one class of finding no
 * single-layer engine can produce: the crypto library the source depends on is
 * not the one the container installs; the image the pipeline builds is not the
 * image the Kubernetes manifest deploys; an artefact is published with no
 * signature step anywhere in the pipeline.
 */
export const supplyChainEngine: ExposureEngine = {
  descriptor: {
    id: 'supply-chain',
    label: 'Supply Chain Correlation',
    description: 'Correlates source, dependency, container, registry and deployment evidence to find mismatches between what is built and what is deployed.',
    mode: 'dev',
    layer: 'registry',
    capability: 'supply-chain',
    dependsOn: ['dependency-analysis', 'container-security', 'kubernetes-security'],
    weight: 6,
  },

  appliesTo(context) {
    const meta = context.workspace.meta;
    const hasContainers = Array.isArray(meta.images) && (meta.images as string[]).length > 0;
    const hasWorkloads = Array.isArray(meta.workloads) && (meta.workloads as string[]).length > 0;
    return hasContainers || hasWorkloads
      ? { applicable: true }
      : { applicable: false, reason: 'No container or deployment evidence was collected, so there is no supply chain to correlate.' };
  },

  async execute(context: EngineContext): Promise<EngineResult> {
    const findings: ExposureFinding[] = [];
    const meta = context.workspace.meta;
    const builtImages = new Set((meta.images as string[] | undefined) ?? []);
    const deployedImages = new Set(
      ((meta.deployedImages as string[] | undefined) ?? []).map((image) => image.trim()).filter(Boolean),
    );

    context.report('Correlating build and deployment evidence');

    /* ── build/deploy image mismatch ────────────────────────────────────── */
    if (builtImages.size > 0 && deployedImages.size > 0) {
      const repositoryOf = (image: string) => image.split('@')[0].split(':')[0].split('/').pop() ?? image;
      const builtRepos = new Set([...builtImages].map(repositoryOf));

      for (const deployed of deployedImages) {
        const repository = repositoryOf(deployed);
        if (builtRepos.has(repository)) continue;
        // Only report when the repository is plausibly first-party: an upstream
        // sidecar (nginx, redis, istio) is expected not to be built here.
        if (/^(nginx|redis|postgres|mysql|busybox|alpine|envoy|istio|fluent|prometheus|grafana|jaeger|vault|consul|traefik|curl|debian|ubuntu|node|python|golang|openjdk)/i.test(repository)) continue;

        const finding = buildFinding({
          scanId: context.scanId,
          engineId: 'supply-chain',
          mode: context.mode,
          layer: 'registry',
          category: 'Supply Chain',
          subcategory: 'Build/deploy mismatch',
          title: `Deployed image "${deployed}" is not built by this repository`,
          description:
            `A Kubernetes workload in scope deploys "${deployed}", and no Dockerfile in this repository builds an image with that name. Either the image comes from another repository — in which case its cryptographic inventory is outside this assessment — or the deployment references something that no longer exists. Both are gaps in the chain from source to production.`,
          severity: 'low',
          confidence: 'low',
          detection: 'inferred',
          quantumStatus: 'not-applicable',
          component: deployed,
          recommendation: 'Confirm which repository builds this image and include it in the assessment scope, so its cryptography appears in the CBOM.',
          evidence: [
            buildEvidence({
              summary: `Deployed image "${deployed}" has no matching Dockerfile in scope.`,
              reference: deployed,
              ruleId: 'supply-chain-image-mismatch',
              localOnly: context.mode === 'local',
              attributes: { deployed, builtImages: [...builtImages].slice(0, 10).join(', ') },
            }),
          ],
          identity: `supply-chain|image-mismatch|${deployed}`,
        });
        findings.push(finding);
        context.emit(finding);
      }
    }

    /* ── library version divergence (Spec-2 §24) ────────────────────────── */
    const allFindings = accumulatedFindings(context);
    const librariesByLayer = new Map<string, Map<string, Set<string>>>();
    for (const finding of allFindings) {
      if (!finding.library) continue;
      const byLibrary = librariesByLayer.get(finding.library) ?? new Map<string, Set<string>>();
      const versions = byLibrary.get(finding.layer) ?? new Set<string>();
      if (finding.version) versions.add(finding.version);
      byLibrary.set(finding.layer, versions);
      librariesByLayer.set(finding.library, byLibrary);
    }

    for (const [library, byLayer] of librariesByLayer) {
      if (byLayer.size < 2) continue;
      const allVersions = new Set<string>();
      for (const versions of byLayer.values()) for (const version of versions) allVersions.add(version);
      if (allVersions.size < 2) continue;

      const finding = buildFinding({
        scanId: context.scanId,
        engineId: 'supply-chain',
        mode: context.mode,
        layer: 'registry',
        category: 'Supply Chain',
        subcategory: 'Version divergence',
        title: `${library} appears at ${allVersions.size} different versions across layers`,
        description: `${library} is declared at ${[...allVersions].join(', ')} across ${[...byLayer.keys()].join(', ')}. When the cryptographic library the source is built against differs from the one the runtime loads, the algorithms actually available at runtime are not the ones the code was reviewed for.`,
        severity: 'medium',
        confidence: 'medium',
        detection: 'inferred',
        library,
        quantumStatus: 'unknown',
        quantumRationale: 'Post-quantum support differs sharply between library versions, so a version mismatch is also a readiness mismatch.',
        recommendation: `Pin ${library} to one version across build and runtime, and confirm which version provides the post-quantum primitives you intend to adopt.`,
        evidence: [
          buildEvidence({
            summary: `${library} at versions ${[...allVersions].join(', ')} across ${byLayer.size} layers.`,
            ruleId: 'supply-chain-version-divergence',
            localOnly: context.mode === 'local',
            attributes: { library, versions: [...allVersions].join(','), layers: [...byLayer.keys()].join(',') },
          }),
        ],
        identity: `supply-chain|version-divergence|${library}`,
      });
      findings.push(finding);
      context.emit(finding);
    }

    return completed(findings, {}, { builtImages: [...builtImages], deployedImages: [...deployedImages] });
  },
};
