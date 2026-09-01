/**
 * CI/CD Security Engine (§25, Spec-2 §26, §27).
 *
 * The build pipeline is where a repository's cryptography becomes an artefact
 * someone deploys, which makes it the single most valuable place to look for
 * two things:
 *
 *   SUPPLY-CHAIN INTEGRITY — is what gets built actually what gets deployed?
 *                            Unpinned third-party actions, unverified
 *                            downloads, unsigned artefacts, plaintext
 *                            registries.
 *   SIGNING CRYPTOGRAPHY   — what algorithm signs the artefacts, and is it a
 *                            post-quantum migration candidate? (Spec-2 §27
 *                            singles this out, correctly: artefact signatures
 *                            are long-lived assertions verified years later.)
 *
 * Detection is per-platform because the syntax differs, but the findings are
 * normalised so a GitHub Actions and a GitLab CI weakness of the same kind
 * correlate into one exposure.
 */

import type { CryptoRole, FindingSeverity } from '../types';
import type { EngineContext, EngineResult, ExposureEngine, WorkspaceFile } from '../engine-contract';
import { buildEvidence, buildFinding, completed } from '../engine-contract';
import { canonicalAlgorithmName, classifyQuantum } from '../algorithms';

/* ───────────────────────────────────────────────────────────────── platform ── */

export type CiPlatform = 'github-actions' | 'gitlab-ci' | 'azure-pipelines' | 'jenkins' | 'circleci' | 'tekton' | 'cloudbuild' | 'bitbucket' | 'unknown';

export function ciPlatformOf(path: string): CiPlatform {
  const lower = path.toLowerCase();
  if (lower.startsWith('.github/workflows/')) return 'github-actions';
  if (/(^|\/)\.gitlab-ci\.ya?ml$/.test(lower)) return 'gitlab-ci';
  if (/azure-pipelines/.test(lower)) return 'azure-pipelines';
  if (/jenkinsfile/.test(lower)) return 'jenkins';
  if (lower.startsWith('.circleci/')) return 'circleci';
  if (lower.startsWith('.tekton/')) return 'tekton';
  if (/cloudbuild\.ya?ml$/.test(lower)) return 'cloudbuild';
  if (/bitbucket-pipelines/.test(lower)) return 'bitbucket';
  return 'unknown';
}

const PLATFORM_LABEL: Record<CiPlatform, string> = {
  'github-actions': 'GitHub Actions',
  'gitlab-ci': 'GitLab CI',
  'azure-pipelines': 'Azure Pipelines',
  jenkins: 'Jenkins',
  circleci: 'CircleCI',
  tekton: 'Tekton',
  cloudbuild: 'Cloud Build',
  bitbucket: 'Bitbucket Pipelines',
  unknown: 'CI/CD',
};

/* ─────────────────────────────────────────────────────────────────── rules ── */

interface CiRule {
  id: string;
  platforms: CiPlatform[] | 'all';
  pattern: RegExp;
  title: string;
  description: string;
  severity: FindingSeverity;
  role: CryptoRole;
  algorithm?: string;
  recommendation: string;
  /** A positive signal — recorded as evidence of strength, not a weakness. */
  positive?: boolean;
  /** Suppress when this pattern is also present (the control is in place). */
  unless?: RegExp;
}

const CI_RULES: CiRule[] = [
  /* ── supply-chain integrity ─────────────────────────────────────────── */
  {
    id: 'ci-unpinned-action',
    platforms: ['github-actions'],
    pattern: /^\s*-?\s*uses:\s*(?!actions\/|github\/|\.\/)([\w.-]+\/[\w.-]+)@(?!v?[0-9a-f]{40})(\S+)/im,
    title: 'Third-party action referenced by a mutable tag',
    description:
      'A third-party GitHub Action is referenced by tag or branch rather than by a full commit SHA. Tags are mutable, so the code that runs with access to this workflow\'s secrets can be changed by the action\'s author — or by anyone who compromises their account — without any change to this repository.',
    severity: 'high',
    role: 'integrity',
    recommendation: 'Pin third-party actions to a full 40-character commit SHA and use Dependabot to raise the updates.',
  },
  {
    id: 'ci-pull-request-target',
    platforms: ['github-actions'],
    pattern: /^\s*pull_request_target\s*:/im,
    title: 'Workflow triggers on pull_request_target',
    description:
      'pull_request_target runs with the base repository\'s secrets and write token while checking out untrusted fork code. Combined with an explicit checkout of the PR head, this is the standard path to full repository compromise from an external pull request.',
    severity: 'high',
    role: 'unknown',
    recommendation: 'Use pull_request for untrusted code, or ensure pull_request_target never checks out or executes the PR head.',
  },
  {
    id: 'ci-broad-token-permission',
    platforms: ['github-actions'],
    pattern: /^\s*permissions\s*:\s*write-all\s*$/im,
    title: 'Workflow token granted write-all',
    description: 'The workflow grants GITHUB_TOKEN write-all, so every step — including third-party actions — can push code, publish packages and modify releases.',
    severity: 'high',
    role: 'unknown',
    recommendation: 'Set permissions to contents: read at the workflow level and elevate only the specific scopes a job needs.',
  },
  {
    id: 'ci-curl-pipe-shell',
    platforms: 'all',
    pattern: /(?:curl|wget)\s[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh/i,
    title: 'Pipeline pipes a downloaded script into a shell',
    description: 'A pipeline step downloads a script and executes it directly. Whatever the remote host serves at build time runs with the pipeline\'s credentials.',
    severity: 'high',
    role: 'integrity',
    recommendation: 'Download to a file, verify a pinned checksum or signature, then execute.',
  },
  {
    id: 'ci-insecure-download',
    platforms: 'all',
    pattern: /(?:curl|wget)\s[^\n]*(?:--insecure\b|-k\s|--no-check-certificate)/i,
    title: 'Pipeline downloads with TLS verification disabled',
    description: 'A build step fetches an artefact with certificate verification disabled, so the download is trivially tamperable by anyone on the network path.',
    severity: 'high',
    role: 'certificate',
    algorithm: 'TLS',
    recommendation: 'Remove the flag and install the required CA certificate into the runner image.',
  },
  {
    id: 'ci-plaintext-registry',
    platforms: 'all',
    pattern: /(?:--insecure-registry|registry\s*[:=]\s*["']?http:\/\/(?!localhost|127\.0\.0\.1))/i,
    title: 'Pipeline uses an insecure container registry',
    description: 'The pipeline is configured to talk to a container registry over plaintext HTTP or with the insecure-registry flag, so pushed and pulled images have no transport integrity.',
    severity: 'high',
    role: 'tls',
    algorithm: 'TLS',
    recommendation: 'Serve the registry over HTTPS with a certificate the runners trust.',
  },

  /* ── credentials ────────────────────────────────────────────────────── */
  {
    id: 'ci-hardcoded-secret',
    platforms: 'all',
    pattern: /^\s*(?:-\s*)?(?:[A-Za-z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|ACCESS_KEY|PRIVATE_KEY))\s*[:=]\s*(?!\$|\{\{|\$\{|<)["']?[A-Za-z0-9+/_=-]{12,}["']?\s*$/im,
    title: 'Credential value written directly into the pipeline definition',
    description:
      'A credential-shaped variable is assigned a literal value in the pipeline file rather than referenced from the platform\'s secret store. Pipeline files are readable by everyone with repository read access, and appear in every fork. The value has been redacted and is not stored.',
    severity: 'critical',
    role: 'unknown',
    recommendation: 'Move the value to the platform\'s encrypted secret store and reference it by name. Rotate the credential.',
  },
  {
    id: 'ci-secret-echoed',
    platforms: 'all',
    pattern: /echo\s+[^\n]*\$\{?\{?\s*(?:secrets|env)\.[A-Za-z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD)/i,
    title: 'Pipeline echoes a secret to the build log',
    description: 'A step echoes a secret-valued variable. Even where the platform masks known secret values, derived and concatenated values are frequently not masked, and build logs are retained far longer than the credential.',
    severity: 'high',
    role: 'unknown',
    recommendation: 'Remove the echo. Use the platform\'s masked-output mechanism if the value must be passed between steps.',
  },
  {
    id: 'ci-oidc-auth',
    platforms: ['github-actions', 'gitlab-ci'],
    pattern: /^\s*(?:id-token\s*:\s*write|role-to-assume\s*:|workload_identity_provider\s*:)/im,
    title: 'Pipeline authenticates with short-lived OIDC credentials',
    description: 'The pipeline uses OIDC federation to obtain short-lived cloud credentials instead of a long-lived stored key. This removes the standing credential the pipeline would otherwise have to protect.',
    severity: 'info',
    role: 'authentication',
    positive: true,
    recommendation: 'Confirm the trust policy restricts the subject claim to this repository and branch.',
  },

  /* ── artefact signing (Spec-2 §27) ──────────────────────────────────── */
  {
    id: 'ci-cosign-signing',
    platforms: 'all',
    pattern: /\bcosign\s+(sign|attest)\b/i,
    title: 'Container images are signed with Sigstore cosign',
    description:
      'The pipeline signs artefacts with cosign. Sigstore\'s default keyless flow issues short-lived ECDSA P-256 certificates from Fulcio, so the signature algorithm is ECDSA — quantum-vulnerable — but the certificate lifetime is measured in minutes, which materially limits harvest-now-decrypt-later relevance for the signing key itself. The transparency log entry, however, is a long-lived assertion.',
    severity: 'info',
    role: 'code-signing',
    algorithm: 'ECDSA',
    positive: true,
    recommendation: 'Track Sigstore for post-quantum signature support; the verification policy is where the migration will be configured.',
  },
  {
    id: 'ci-gpg-signing',
    platforms: 'all',
    pattern: /\b(?:gpg|gpg2)\s+(?:--detach-sig|--sign|--clearsign)\b/i,
    title: 'Artefacts are signed with GnuPG',
    description:
      'The pipeline signs artefacts with GnuPG. GPG signing keys are overwhelmingly RSA or Ed25519, both of which are broken by Shor\'s algorithm, and an artefact signature is verified for the entire supported life of the release — which is exactly the long-horizon assertion post-quantum migration must cover first.',
    severity: 'medium',
    role: 'code-signing',
    algorithm: 'RSA',
    recommendation: 'Plan a signing-key migration to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205), and support dual signatures during the transition so old verifiers keep working.',
  },
  {
    id: 'ci-jarsigner',
    platforms: 'all',
    pattern: /\bjarsigner\b|\bsigntool\b|\bcodesign\s+-/i,
    title: 'Platform code signing in the pipeline',
    description: 'The pipeline performs platform code signing. Code-signing certificates are long-lived assertions verified by operating systems years after issuance, which makes them a first-wave post-quantum migration target.',
    severity: 'medium',
    role: 'code-signing',
    algorithm: 'RSA',
    recommendation: 'Confirm the signing certificate\'s algorithm and plan for the platform vendor\'s post-quantum code-signing timeline.',
  },
  {
    id: 'ci-no-artifact-verification',
    platforms: 'all',
    pattern: /\b(?:docker|podman)\s+push\b/i,
    unless: /\bcosign\s+(sign|attest)\b|\bnotation\s+sign\b|COSIGN_|DOCKER_CONTENT_TRUST\s*[:=]\s*1/i,
    title: 'Container images are pushed without a signature step',
    description:
      'The pipeline pushes container images and contains no signing or attestation step. An unsigned image cannot be verified at admission, so a compromised registry or a mistaken tag cannot be distinguished from a legitimate release.',
    severity: 'medium',
    role: 'code-signing',
    recommendation: 'Add cosign signing and an attestation, then enforce signature verification with an admission policy.',
  },
  {
    id: 'ci-checksum-verification',
    platforms: 'all',
    pattern: /\b(?:sha256sum|shasum)\s+(?:-c|--check)\b|\bsha256\s*[:=]\s*[a-f0-9]{64}/i,
    title: 'Pipeline verifies a downloaded artefact against a checksum',
    description: 'A downloaded artefact is verified against a pinned SHA-256 digest, so a substituted download fails the build.',
    severity: 'info',
    role: 'integrity',
    algorithm: 'SHA-2',
    positive: true,
    recommendation: 'Keep the digest pinned when the version is bumped.',
  },
  {
    id: 'ci-md5-checksum',
    platforms: 'all',
    pattern: /\bmd5sum\s+(?:-c|--check)\b|\bmd5\s*[:=]\s*[a-f0-9]{32}\b/i,
    title: 'Pipeline verifies an artefact against an MD5 digest',
    description: 'The integrity check uses MD5, which is collision-broken. A prepared collision passes the check, so the verification provides no real integrity guarantee against a deliberate substitution.',
    severity: 'medium',
    role: 'integrity',
    algorithm: 'MD5',
    recommendation: 'Verify against SHA-256 instead.',
  },
];

/* ────────────────────────────────────────────────────────────── the engine ── */

export const cicdEngine: ExposureEngine = {
  descriptor: {
    id: 'cicd-security',
    label: 'CI/CD Security',
    description: 'Analyses build pipelines for supply-chain integrity, credential handling and artefact-signing cryptography across eight CI platforms.',
    mode: 'local',
    layer: 'cicd',
    capability: 'cicd',
    dependsOn: ['file-discovery'],
    weight: 10,
  },

  appliesTo(context) {
    return context.workspace.files.some((file) => file.content && file.classification === 'cicd')
      ? { applicable: true }
      : { applicable: false, reason: 'No CI/CD pipeline definitions were found in scope.' };
  },

  async execute(context: EngineContext): Promise<EngineResult> {
    const files = context.workspace.files.filter(
      (file) => file.content && !context.isExcluded(file.path) && file.classification === 'cicd',
    );

    const findings: ReturnType<typeof buildFinding>[] = [];
    const platforms = new Set<CiPlatform>();
    let processed = 0;

    for (const file of files) {
      if (context.isCancelled()) break;
      processed += 1;
      context.report(`Analysing ${file.path}`, { done: processed, total: files.length, unit: 'workflows' });

      const platform = ciPlatformOf(file.path);
      platforms.add(platform);
      const content = file.content as string;
      const lines = content.split('\n');

      for (const rule of CI_RULES) {
        if (rule.platforms !== 'all' && !rule.platforms.includes(platform)) continue;
        if (!rule.pattern.test(content)) continue;
        if (rule.unless && rule.unless.test(content)) continue;

        const singleLine = new RegExp(rule.pattern.source, rule.pattern.flags.replace('m', ''));
        const lineIndex = lines.findIndex((line) => !/^\s*#/.test(line) && singleLine.test(line));
        if (lineIndex === -1 && !rule.pattern.flags.includes('m')) continue;

        const quantum = rule.algorithm
          ? classifyQuantum({ algorithm: rule.algorithm, role: rule.role })
          : { status: 'not-applicable' as const, rationale: 'This is a pipeline control, not a cryptographic primitive.', quantumRelevant: false };

        findings.push(
          buildFinding({
            scanId: context.scanId,
            engineId: 'cicd-security',
            mode: context.mode,
            layer: 'cicd',
            category: rule.positive ? 'Pipeline Strength' : 'Pipeline Weakness',
            subcategory: PLATFORM_LABEL[platform],
            title: `${rule.title} — ${file.path}`,
            description: rule.description,
            severity: rule.severity,
            confidence: rule.id === 'ci-no-artifact-verification' ? 'medium' : 'high',
            detection: rule.id === 'ci-no-artifact-verification' ? 'inferred' : 'observed',
            algorithm: rule.algorithm,
            canonicalAlgorithm: rule.algorithm ? canonicalAlgorithmName(rule.algorithm) : undefined,
            role: rule.role,
            quantumStatus: quantum.status,
            quantumRationale: quantum.rationale,
            recommendation: rule.recommendation,
            evidence: [
              buildEvidence({
                summary: `${rule.title} in ${file.path}${lineIndex >= 0 ? `:${lineIndex + 1}` : ''}`,
                file: file.path,
                line: lineIndex >= 0 ? lineIndex + 1 : undefined,
                snippet: lineIndex >= 0 ? lines[lineIndex] : undefined,
                provider: platform,
                ruleId: rule.id,
                localOnly: context.mode === 'local',
                attributes: { platform: PLATFORM_LABEL[platform], positive: Boolean(rule.positive) },
              }),
            ],
            identity: `${file.path}|${rule.id}`,
            migration:
              rule.role === 'code-signing' && quantum.status === 'vulnerable'
                ? { candidate: true, target: quantum.migrationTarget, priority: 'P2', complexity: 'high' }
                : { candidate: false },
          }),
        );
      }
    }

    for (const finding of findings) context.emit(finding);

    return completed(
      findings,
      { cicdWorkflows: files.length },
      { platforms: [...platforms].map((platform) => PLATFORM_LABEL[platform]) },
    );
  },
};
