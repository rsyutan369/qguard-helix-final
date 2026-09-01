/**
 * Scan Profiles and the Smart Scan Planner (§30, §31, Spec-2 §31, §32).
 *
 * §31 is the requirement that makes profiles more than cosmetic: "When a user
 * selects a scan task, only the required scanner engines should execute. It
 * should NOT automatically launch every scanner."
 *
 * So a profile is a set of ENGINE IDS, the planner intersects that set with
 * what the target actually contains, and the orchestrator runs the
 * intersection. A repository with no Kubernetes manifests never starts the
 * Kubernetes engine — it is recorded as `not-applicable` with the reason, which
 * is different from both "ran and found nothing" and "was skipped".
 *
 * Spec-2 §32 adds the second half: the planner PROPOSES, the user DISPOSES. The
 * recommendation is computed from the facets the discovery engine found, and is
 * always presented as a proposal the operator can change.
 */

import type { ScanMode } from './types';
import type { TargetFacet } from './engine-contract';
import { descriptorsForMode } from './registry';

/* ───────────────────────────────────────────────────────────────── profiles ── */

export interface ScanProfile {
  id: string;
  label: string;
  description: string;
  modes: ScanMode[];
  /** Engine ids. `custom` resolves to whatever the operator selected. */
  engines: string[];
  /** Ordering hint for the selector. */
  order: number;
  /** Shown as the profile's promise, so expectations match execution. */
  covers: string[];
  minTier?: 'basic' | 'pro' | 'elite' | null;
}

const CORE = ['file-discovery'];
const CRYPTO_SET = ['source-crypto', 'certificate-material', 'cbom-generator', 'quantum-assessment'];
const FULL_CONTENT = [
  'source-crypto',
  'secret-discovery',
  'dependency-analysis',
  'configuration-security',
  'certificate-material',
  'container-security',
  'kubernetes-security',
  'iac-security',
  'cicd-security',
  'cbom-generator',
  'quantum-assessment',
];

export const SCAN_PROFILES: ScanProfile[] = [
  {
    id: 'quick',
    label: 'Quick',
    description: 'A fast pass over cryptographic usage and credential material. Minutes, not a full inventory.',
    modes: ['local', 'dev'],
    engines: [...CORE, 'source-crypto', 'secret-discovery', 'quantum-assessment'],
    order: 1,
    covers: ['Cryptographic usage in source', 'Credential material', 'Quantum verdict'],
  },
  {
    id: 'standard',
    label: 'Standard',
    description: 'The balanced default: cryptography, secrets, dependencies, configuration and certificates, with a full CBOM.',
    modes: ['local', 'dev'],
    engines: [...CORE, 'source-crypto', 'secret-discovery', 'dependency-analysis', 'configuration-security', 'certificate-material', 'cbom-generator', 'quantum-assessment'],
    order: 2,
    covers: ['Everything in Quick', 'Dependency cryptography', 'Configuration weaknesses', 'Certificates and key material', 'CBOM'],
  },
  {
    id: 'deep',
    label: 'Deep',
    description: 'Every applicable engine, including containers, Kubernetes, infrastructure-as-code, CI/CD and repository history.',
    modes: ['local', 'dev'],
    engines: [...CORE, ...FULL_CONTENT, 'git-history', 'supply-chain'],
    order: 3,
    covers: ['Everything in Standard', 'Containers and Compose', 'Kubernetes, Helm and Kustomize', 'Terraform and IaC', 'CI/CD pipelines', 'Repository history', 'Supply-chain correlation'],
  },
  {
    id: 'cryptographic',
    label: 'Cryptographic',
    description: 'Cryptography only: usage, certificates, key material and the CBOM. No secret or configuration scanning.',
    modes: ['local', 'dev'],
    engines: [...CORE, ...CRYPTO_SET],
    order: 4,
    covers: ['Cryptographic usage', 'Certificates and key material', 'CBOM', 'Quantum classification'],
  },
  {
    id: 'quantum',
    label: 'Quantum',
    description: 'Post-quantum exposure across every layer that carries asymmetric cryptography.',
    modes: ['local', 'dev'],
    engines: [...CORE, 'source-crypto', 'dependency-analysis', 'certificate-material', 'configuration-security', 'kubernetes-security', 'cicd-security', 'cbom-generator', 'quantum-assessment'],
    order: 5,
    covers: ['Key exchange and signatures', 'TLS and PKI configuration', 'Certificate algorithms', 'Artefact signing', 'Quantum readiness ratio'],
  },
  {
    id: 'secrets',
    label: 'Secrets',
    description: 'Credential material only, current and — where readable — historical.',
    modes: ['local', 'dev'],
    engines: [...CORE, 'secret-discovery', 'git-history'],
    order: 6,
    covers: ['Provider credential shapes', 'High-entropy assignments', 'Committed key material', 'Historical exposure where readable'],
  },
  {
    id: 'supply-chain',
    label: 'Supply Chain',
    description: 'Dependencies, containers, registries, CI/CD and the correlation between what is built and what is deployed.',
    modes: ['local', 'dev'],
    engines: [...CORE, 'dependency-analysis', 'container-security', 'cicd-security', 'kubernetes-security', 'cbom-generator', 'supply-chain'],
    order: 7,
    covers: ['Dependency graph', 'Container build', 'Pipeline integrity', 'Artefact signing', 'Build/deploy mismatch'],
  },

  /* ── Dev-specific profiles (Spec-2 §31) ────────────────────────────────── */
  {
    id: 'container-deep',
    label: 'Container Deep',
    description: 'Dockerfiles, Compose, base images and the cryptographic libraries the image installs.',
    modes: ['dev', 'local'],
    engines: [...CORE, 'container-security', 'configuration-security', 'secret-discovery', 'cbom-generator', 'quantum-assessment'],
    order: 8,
    covers: ['Dockerfile analysis', 'Base image posture', 'Secrets in layers', 'Crypto packages'],
  },
  {
    id: 'kubernetes-deep',
    label: 'Kubernetes Deep',
    description: 'Manifests, Helm, Kustomize, RBAC, network policy, secret metadata and ingress TLS.',
    modes: ['dev', 'local'],
    engines: [...CORE, 'kubernetes-security', 'configuration-security', 'secret-discovery', 'certificate-material', 'cbom-generator', 'quantum-assessment'],
    order: 9,
    covers: ['Workload privilege', 'RBAC escalation paths', 'Network policy gaps', 'Ingress TLS and certificates'],
  },
  {
    id: 'cloud-deep',
    label: 'Cloud Deep',
    description: 'Connected cloud accounts: inventory, IAM, KMS, certificates, storage and network — read-only, metadata first.',
    modes: ['dev'],
    engines: [...CORE, 'cloud-inventory', 'cloud-crypto', 'kubernetes-security', 'cbom-generator', 'quantum-assessment'],
    order: 10,
    covers: ['Cloud resource inventory', 'Key management posture', 'Managed certificates', 'Transport policy'],
    minTier: 'pro',
  },
  {
    id: 'full-dev',
    label: 'Full Dev Environment',
    description: 'Every applicable engine across repository, containers, Kubernetes, IaC, CI/CD and any connected cloud or cluster.',
    modes: ['dev'],
    engines: [...CORE, ...FULL_CONTENT, 'git-history', 'supply-chain', 'cloud-inventory', 'cloud-crypto', 'k8s-live', 'registry-scan'],
    order: 11,
    covers: ['Every engine the target supports'],
    minTier: 'pro',
  },
  {
    id: 'custom',
    label: 'Custom',
    description: 'Choose exactly which engines run.',
    modes: ['local', 'dev'],
    engines: [],
    order: 12,
    covers: ['Operator-selected engines only'],
  },
];

export function profilesForMode(mode: ScanMode): ScanProfile[] {
  return SCAN_PROFILES.filter((profile) => profile.modes.includes(mode)).sort((a, b) => a.order - b.order);
}

export function profileById(id: string): ScanProfile | null {
  return SCAN_PROFILES.find((profile) => profile.id === id) ?? null;
}

/**
 * Resolve a profile to the engine ids that actually exist for the mode.
 *
 * A profile may name an engine that is not registered for a mode (the cloud
 * engines in Local, for instance). Those are dropped here rather than silently
 * failing at execution, and the caller is told what was dropped.
 */
export function resolveProfile(
  mode: ScanMode,
  profileId: string,
  customEngines: string[] = [],
): { engines: string[]; dropped: string[] } {
  const profile = profileById(profileId);
  const requested = profileId === 'custom' ? ['file-discovery', ...customEngines] : (profile?.engines ?? []);
  const available = new Set(descriptorsForMode(mode).map((descriptor) => descriptor.id));

  const engines: string[] = [];
  const dropped: string[] = [];
  for (const id of requested) {
    if (available.has(id)) {
      if (!engines.includes(id)) engines.push(id);
    } else if (!dropped.includes(id)) {
      dropped.push(id);
    }
  }
  return { engines, dropped };
}

/* ───────────────────────────────────────────────────── smart scan planner ── */

/** Which facet makes which engine relevant. */
const FACET_ENGINES: Partial<Record<TargetFacet, string[]>> = {
  'git-repository': ['git-history'],
  dockerfile: ['container-security'],
  compose: ['container-security'],
  kubernetes: ['kubernetes-security'],
  helm: ['kubernetes-security'],
  kustomize: ['kubernetes-security'],
  terraform: ['iac-security'],
  cloudformation: ['iac-security'],
  bicep: ['iac-security'],
  pulumi: ['iac-security'],
  ansible: ['iac-security'],
  'github-actions': ['cicd-security'],
  'gitlab-ci': ['cicd-security'],
  'azure-pipelines': ['cicd-security'],
  jenkins: ['cicd-security'],
  circleci: ['cicd-security'],
  certificates: ['certificate-material'],
  'key-material': ['certificate-material', 'secret-discovery'],
  'env-files': ['secret-discovery', 'configuration-security'],
  node: ['dependency-analysis', 'source-crypto'],
  python: ['dependency-analysis', 'source-crypto'],
  java: ['dependency-analysis', 'source-crypto'],
  dotnet: ['dependency-analysis', 'source-crypto'],
  go: ['dependency-analysis', 'source-crypto'],
  rust: ['dependency-analysis', 'source-crypto'],
  ruby: ['dependency-analysis', 'source-crypto'],
  php: ['dependency-analysis', 'source-crypto'],
  swift: ['dependency-analysis', 'source-crypto'],
  kotlin: ['dependency-analysis', 'source-crypto'],
  cpp: ['source-crypto'],
  'service-mesh': ['kubernetes-security'],
};

/** Human labels for the facets, for the recommendation panel. */
export const FACET_LABEL: Record<TargetFacet, string> = {
  'git-repository': 'Git repository',
  node: 'Node.js / TypeScript',
  python: 'Python',
  java: 'Java',
  dotnet: '.NET',
  go: 'Go',
  rust: 'Rust',
  ruby: 'Ruby',
  php: 'PHP',
  swift: 'Swift',
  kotlin: 'Kotlin',
  cpp: 'C / C++',
  dockerfile: 'Dockerfile',
  compose: 'Docker Compose',
  kubernetes: 'Kubernetes manifests',
  helm: 'Helm chart',
  kustomize: 'Kustomize',
  terraform: 'Terraform',
  cloudformation: 'CloudFormation',
  bicep: 'Azure Bicep',
  pulumi: 'Pulumi',
  ansible: 'Ansible',
  'github-actions': 'GitHub Actions',
  'gitlab-ci': 'GitLab CI',
  'azure-pipelines': 'Azure Pipelines',
  jenkins: 'Jenkins',
  circleci: 'CircleCI',
  certificates: 'Certificates',
  'key-material': 'Key material',
  'env-files': 'Environment files',
  'service-mesh': 'Service mesh',
};

export interface ScanPlan {
  /** Engines the planner recommends, with the reason each was chosen. */
  recommended: Array<{ engineId: string; label: string; reason: string }>;
  /** Engines available for this mode that the planner did NOT recommend. */
  optional: Array<{ engineId: string; label: string; reason: string }>;
  /** Detected facets, in the order they should be shown. */
  facets: TargetFacet[];
  /** The profile the planner suggests as a starting point. */
  suggestedProfile: string;
}

/**
 * Propose a scan from what the target actually contains.
 *
 * The recommendation always includes the universal engines (discovery,
 * cryptography, secrets, CBOM, quantum) because they apply to any corpus, and
 * adds the facet-specific ones on top. Anything not recommended is offered as
 * optional with the reason it was not selected, so the operator can see the
 * whole menu and the planner's reasoning at once.
 */
export function planScan(mode: ScanMode, facets: Set<TargetFacet>): ScanPlan {
  const descriptors = descriptorsForMode(mode);
  const labels = new Map(descriptors.map((descriptor) => [descriptor.id, descriptor.label]));

  const recommended = new Map<string, string>();
  const universal: Array<[string, string]> = [
    ['file-discovery', 'Always runs — it builds the corpus every other engine reads.'],
    ['source-crypto', 'Applies to any codebase.'],
    ['secret-discovery', 'Applies to any file corpus.'],
    ['cbom-generator', 'Composes the inventory from whatever the other engines find.'],
    ['quantum-assessment', 'Classifies whatever cryptography was inventoried.'],
  ];
  for (const [id, reason] of universal) {
    if (labels.has(id)) recommended.set(id, reason);
  }

  for (const facet of facets) {
    const engines = FACET_ENGINES[facet];
    if (!engines) continue;
    for (const id of engines) {
      if (!labels.has(id)) continue;
      const existing = recommended.get(id);
      const reason = `${FACET_LABEL[facet]} detected in the target.`;
      recommended.set(id, existing && !existing.startsWith('Always') && !existing.startsWith('Applies') && !existing.startsWith('Composes') && !existing.startsWith('Classifies')
        ? `${existing.replace(/\.$/, '')}; ${FACET_LABEL[facet]} also detected.`
        : reason);
    }
  }

  const optional = descriptors
    .filter((descriptor) => !recommended.has(descriptor.id))
    .map((descriptor) => ({
      engineId: descriptor.id,
      label: descriptor.label,
      reason: 'No evidence in the target requires this engine — it will report "not applicable" if run.',
    }));

  /* Suggest the narrowest profile whose engine set covers the recommendation. */
  const recommendedIds = new Set(recommended.keys());
  const suggested = profilesForMode(mode)
    .filter((profile) => profile.id !== 'custom')
    .sort((a, b) => a.engines.length - b.engines.length)
    .find((profile) => [...recommendedIds].every((id) => profile.engines.includes(id)));

  return {
    recommended: [...recommended.entries()].map(([engineId, reason]) => ({
      engineId,
      label: labels.get(engineId) ?? engineId,
      reason,
    })),
    optional,
    facets: [...facets],
    suggestedProfile: suggested?.id ?? 'deep',
  };
}
