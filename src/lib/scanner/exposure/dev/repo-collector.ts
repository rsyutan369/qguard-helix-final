/**
 * Repository collector and Repository Intelligence Engine™ (§17, §19, §20, §21).
 *
 * Turns a repository reference on any of the five supported platforms into the
 * SAME workspace shape the local collector produces, so every content engine
 * runs unchanged against a hosted repository.
 *
 * §17: "Do not tightly couple repository logic to GitHub." The platform already
 * ships `repo-providers.ts` with GitHub, GitLab, Bitbucket, Azure DevOps and
 * Gitea adapters behind one interface; this module composes them rather than
 * duplicating them.
 *
 * §19 public repositories work with no credentials at all. §20 private
 * repositories require an explicitly supplied token and are never scanned
 * without one.
 *
 * The file BUDGET is the interesting design problem. A repository tree can hold
 * a hundred thousand entries and each file costs an HTTP round trip, so the
 * collector cannot read everything. It ranks by INFORMATION DENSITY — one
 * manifest describes an entire dependency graph, one Dockerfile describes an
 * entire image, one source file describes one call site — and then states in
 * coverage exactly what fraction it read, so the report never implies more.
 */

import {
  PROVIDER_LABEL,
  PROVIDER_TOKEN_ENV,
  createRepoAdapter,
  parseRepoReference,
  resolveProviderToken,
  type RepoAdapter,
  type RepoProvider,
  type RepoRef,
} from '@/lib/scanner/web-scanner/repo-providers';
import { isScannablePath } from '@/lib/scanner/web-scanner/crypto-patterns';
import { classifyFile, deriveFacets, detectFrameworks, languageHistogram, toWorkspaceFile } from '../content/file-discovery';
import type { ScanWorkspace, WorkspaceFile } from '../engine-contract';
import { emptyWorkspace } from '../engine-contract';

/* ─────────────────────────────────────────────────────────────── budgets ──── */

export interface RepoCollectorLimits {
  maxFiles: number;
  maxFileBytes: number;
  /** Delay between file reads, to stay inside provider rate limits. */
  requestDelayMs: number;
}

export const REPO_LIMITS: Record<'quick' | 'standard' | 'deep', RepoCollectorLimits> = {
  quick: { maxFiles: 60, maxFileBytes: 400_000, requestDelayMs: 90 },
  standard: { maxFiles: 200, maxFileBytes: 600_000, requestDelayMs: 70 },
  deep: { maxFiles: 600, maxFileBytes: 900_000, requestDelayMs: 45 },
};

const SKIP_DIRECTORIES = [
  'node_modules/', 'vendor/', 'dist/', 'build/', 'target/', '__pycache__/',
  '.next/', '.nuxt/', 'coverage/', '.venv/', 'site-packages/', 'third_party/',
  'testdata/', 'fixtures/', '.yarn/', 'bower_components/', 'Pods/',
];

/**
 * Files that are worth a round trip even though the generic scannable-path
 * filter would rank them low, because each one describes a whole subsystem.
 */
const HIGH_VALUE = [
  /(^|\/)dockerfile(\.|$)/i,
  /(^|\/)docker-compose\.ya?ml$/i,
  /(^|\/)compose\.ya?ml$/i,
  /^\.github\/workflows\//i,
  /(^|\/)\.gitlab-ci\.ya?ml$/i,
  /(^|\/)azure-pipelines[^/]*\.ya?ml$/i,
  /(^|\/)jenkinsfile$/i,
  /(^|\/)chart\.ya?ml$/i,
  /(^|\/)values\.ya?ml$/i,
  /(^|\/)kustomization\.ya?ml$/i,
  /\.tf$/i,
  /\.bicep$/i,
  /(^|\/)\.env(\.|$)/i,
  /(^|\/)(nginx|httpd|openssl)\.(conf|cnf)$/i,
  /(^|\/)ssh(d)?_config$/i,
];

const MANIFEST_NAMES = new Set([
  'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
  'requirements.txt', 'pyproject.toml', 'pipfile', 'poetry.lock',
  'go.mod', 'go.sum', 'cargo.toml', 'cargo.lock',
  'pom.xml', 'build.gradle', 'build.gradle.kts',
  'composer.json', 'composer.lock', 'gemfile', 'gemfile.lock',
  'package.swift', 'pubspec.yaml',
]);

/** Rank a path: lower is read first. */
export function rankRepoPath(path: string): number {
  const lower = path.toLowerCase();
  const basename = lower.split('/').pop() ?? '';
  if (MANIFEST_NAMES.has(basename)) return 0;
  if (HIGH_VALUE.some((pattern) => pattern.test(lower))) return 1;
  if (lower.endsWith('.pem') || lower.endsWith('.crt') || lower.endsWith('.key')) return 2;
  // Shallow source files describe the application; deeply nested ones are more
  // often generated, vendored or peripheral.
  const depth = lower.split('/').length;
  if (/\.(ts|tsx|js|jsx|py|go|rs|java|cs|rb|php|kt|swift|c|cpp|h)$/.test(lower)) return 3 + Math.min(3, Math.floor(depth / 3));
  return 8;
}

/* ─────────────────────────────────────────────────────────── collection ──── */

export interface RepoCollectionResult {
  workspace: ScanWorkspace;
  ref: RepoRef;
  /** null when the repository could not be resolved. */
  resolution: {
    ok: boolean;
    defaultBranch: string;
    branch: string;
    visibility: 'public' | 'private' | 'unknown';
    notice?: string;
    recommendation?: string;
  };
  stats: {
    treeEntries: number;
    candidates: number;
    read: number;
    failed: number;
    truncated: boolean;
  };
  limitations: Array<{ dimension: string; reason: string }>;
}

export interface RepoCollectOptions {
  branch?: string;
  token?: string | null;
  limits?: RepoCollectorLimits;
  isExcluded?: (path: string) => boolean;
  onProgress?: (progress: { done: number; total: number; current: string }) => void;
  isCancelled?: () => boolean;
}

/**
 * Validate a repository reference without reading it. Used by the Dev tab's
 * "Validate repository" step (§19).
 */
export async function validateRepository(
  url: string,
  token?: string | null,
): Promise<{
  ok: boolean;
  ref?: RepoRef;
  providerLabel?: string;
  defaultBranch?: string;
  visibility?: 'public' | 'private' | 'unknown';
  notice?: string;
  recommendation?: string;
  requiresToken?: boolean;
}> {
  const ref = parseRepoReference(url);
  if (!ref) {
    return {
      ok: false,
      notice: `"${url}" is not a repository reference this scanner recognises.`,
      recommendation: 'Supply a GitHub, GitLab, Bitbucket, Azure DevOps or self-hosted Git URL — for example https://gitlab.com/group/project.',
    };
  }

  const adapter = createRepoAdapter(ref, token ?? resolveProviderToken(ref.provider));
  const resolution = await adapter.resolve();

  return {
    ok: resolution.ok,
    ref,
    providerLabel: PROVIDER_LABEL[ref.provider],
    defaultBranch: resolution.defaultBranch,
    visibility: resolution.visibility,
    notice: resolution.notice,
    recommendation:
      resolution.recommendation ??
      (resolution.visibility === 'private' && !adapter.hasToken
        ? `This repository is private. Connect the provider or configure ${PROVIDER_TOKEN_ENV[ref.provider]} on the scanner to assess it.`
        : undefined),
    requiresToken: resolution.visibility === 'private' && !adapter.hasToken,
  };
}

/** Read a repository into a workspace. */
export async function collectRepository(url: string, options: RepoCollectOptions = {}): Promise<RepoCollectionResult> {
  const limits = options.limits ?? REPO_LIMITS.standard;
  const isExcluded = options.isExcluded ?? (() => false);
  const workspace = emptyWorkspace();
  const limitations: Array<{ dimension: string; reason: string }> = [];

  const ref = parseRepoReference(url);
  if (!ref) {
    throw new Error(`"${url}" is not a repository reference this scanner recognises.`);
  }

  const token = options.token ?? resolveProviderToken(ref.provider);
  const adapter: RepoAdapter = createRepoAdapter(ref, token);
  const label = PROVIDER_LABEL[ref.provider];

  const resolution = await adapter.resolve();
  if (!resolution.ok) {
    return {
      workspace,
      ref,
      resolution: {
        ok: false,
        defaultBranch: resolution.defaultBranch,
        branch: options.branch ?? resolution.defaultBranch,
        visibility: resolution.visibility,
        notice: resolution.notice ?? `${label} repository ${ref.owner}/${ref.repo} could not be resolved.`,
        recommendation: resolution.recommendation ?? `Verify the URL, or configure ${PROVIDER_TOKEN_ENV[ref.provider]} for private access.`,
      },
      stats: { treeEntries: 0, candidates: 0, read: 0, failed: 0, truncated: false },
      limitations: [
        {
          dimension: 'Repository access',
          reason: resolution.notice ?? `The repository could not be read, so nothing about it was assessed.`,
        },
      ],
    };
  }

  const branch = options.branch?.trim() || resolution.defaultBranch;
  const tree = await adapter.listTree(branch);

  if (tree.entries.length === 0) {
    return {
      workspace,
      ref,
      resolution: { ok: true, defaultBranch: resolution.defaultBranch, branch, visibility: resolution.visibility, notice: tree.notice },
      stats: { treeEntries: 0, candidates: 0, read: 0, failed: 0, truncated: false },
      limitations: [
        {
          dimension: 'Repository contents',
          reason: tree.notice ?? `Branch "${branch}" has no readable files, so no content was assessed.`,
        },
      ],
    };
  }

  /* ── select ─────────────────────────────────────────────────────────── */
  const candidates = tree.entries
    .filter((entry) => {
      const lower = entry.path.toLowerCase();
      if (SKIP_DIRECTORIES.some((directory) => lower.includes(directory))) return false;
      if (isExcluded(entry.path)) return false;
      if (entry.size && entry.size > limits.maxFileBytes) return false;
      // Anything high-value is read even when the generic filter would not.
      if (HIGH_VALUE.some((pattern) => pattern.test(lower))) return true;
      return isScannablePath(entry.path);
    })
    .sort((a, b) => rankRepoPath(a.path) - rankRepoPath(b.path));

  const selected = candidates.slice(0, limits.maxFiles);
  const truncated = candidates.length > selected.length || tree.truncated;

  /* ── read ───────────────────────────────────────────────────────────── */
  const files: WorkspaceFile[] = [];
  let failed = 0;

  for (let index = 0; index < selected.length; index += 1) {
    if (options.isCancelled?.()) break;
    const entry = selected[index];
    if (limits.requestDelayMs > 0 && index > 0) await delay(limits.requestDelayMs);

    let content: string | null = null;
    try {
      content = await adapter.readFile(entry.path, branch);
    } catch {
      content = null;
    }
    if (content === null) {
      failed += 1;
      continue;
    }
    files.push(toWorkspaceFile(entry.path, content, entry.size ?? content.length));

    /* Every tenth file was fine when nothing rendered this; now it drives the
       operator's progress bar, and ten files is roughly four seconds of network
       round-trips, so the bar moved in visible lurches. Report every file on a
       small repository and roughly two hundred times on a large one — one small
       SSE frame per several hundred milliseconds of real work. */
    const stride = Math.max(1, Math.ceil(selected.length / 200));
    if ((index + 1) % stride === 0 || index === selected.length - 1) {
      options.onProgress?.({ done: index + 1, total: selected.length, current: entry.path });
    }
  }

  /* Every tree entry that was NOT read is still catalogued, so file counts and
     the language histogram describe the repository rather than the sample. */
  const readPaths = new Set(files.map((file) => file.path));
  const catalogued: WorkspaceFile[] = tree.entries
    .filter((entry) => !readPaths.has(entry.path))
    .map((entry) => ({
      path: entry.path,
      content: null,
      size: entry.size ?? 0,
      binary: false,
      ext: extOf(entry.path),
      basename: (entry.path.split('/').pop() ?? '').toLowerCase(),
      classification: classifyFile(entry.path, null),
    }));

  workspace.files = [...files, ...catalogued];
  for (const facet of deriveFacets(workspace.files)) workspace.facets.add(facet);

  /* ── repository intelligence (§21) ──────────────────────────────────── */
  const languages = languageHistogram(workspace.files);
  const frameworks = detectFrameworks(files);
  workspace.meta.languages = languages;
  workspace.meta.frameworks = frameworks;
  workspace.meta.repository = {
    provider: ref.provider,
    providerLabel: label,
    owner: ref.owner,
    repo: ref.repo,
    fullName: `${ref.owner}/${ref.repo}`,
    webUrl: ref.webUrl,
    selfHosted: ref.selfHosted,
    branch,
    defaultBranch: resolution.defaultBranch,
    visibility: resolution.visibility,
    treeEntries: tree.entries.length,
    filesRead: files.length,
    buildSystems: detectBuildSystems(workspace.files),
  };

  if (truncated) {
    limitations.push({
      dimension: 'Repository file budget',
      reason: `The repository tree holds ${tree.entries.length} entries, of which ${candidates.length} were analysis candidates and ${files.length} were read within this profile's budget. Files are ranked by information density — dependency manifests, container and pipeline definitions first — so the sample is representative rather than arbitrary, but it is a sample. Run the Deep profile, or the Local scanner against a clone, for complete coverage.`,
    });
  }
  if (failed > 0) {
    limitations.push({
      dimension: 'Unreadable files',
      reason: `${failed} file${failed === 1 ? '' : 's'} could not be read from ${label} (rate limiting, size, or permission) and were skipped.`,
    });
  }
  if (tree.truncated) {
    limitations.push({
      dimension: 'Repository tree',
      reason: tree.notice ?? `${label} truncated the file tree response, so some paths were never offered to the scanner.`,
    });
  }
  limitations.push({
    dimension: 'Branch coverage',
    reason: `Only branch "${branch}" was analysed. Other branches, tags and unmerged pull requests were not read.`,
  });

  return {
    workspace,
    ref,
    resolution: { ok: true, defaultBranch: resolution.defaultBranch, branch, visibility: resolution.visibility, notice: tree.notice },
    stats: { treeEntries: tree.entries.length, candidates: candidates.length, read: files.length, failed, truncated },
    limitations,
  };
}

/* ────────────────────────────────────────────────────────────── helpers ──── */

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function extOf(path: string): string {
  const base = path.split('/').pop() ?? '';
  const dot = base.lastIndexOf('.');
  return dot <= 0 ? '' : base.slice(dot).toLowerCase();
}

function detectBuildSystems(files: WorkspaceFile[]): string[] {
  const systems = new Set<string>();
  for (const file of files) {
    switch (file.basename) {
      case 'package.json': systems.add('npm / Node.js'); break;
      case 'pom.xml': systems.add('Maven'); break;
      case 'build.gradle': case 'build.gradle.kts': systems.add('Gradle'); break;
      case 'cargo.toml': systems.add('Cargo'); break;
      case 'go.mod': systems.add('Go modules'); break;
      case 'pyproject.toml': systems.add('Python (PEP 517)'); break;
      case 'requirements.txt': systems.add('pip'); break;
      case 'composer.json': systems.add('Composer'); break;
      case 'gemfile': systems.add('Bundler'); break;
      case 'makefile': systems.add('Make'); break;
      case 'cmakelists.txt': systems.add('CMake'); break;
      case 'package.swift': systems.add('Swift Package Manager'); break;
      default:
        if (file.basename.endsWith('.csproj') || file.basename.endsWith('.sln')) systems.add('MSBuild');
        break;
    }
  }
  return [...systems].sort();
}

export { PROVIDER_LABEL, PROVIDER_TOKEN_ENV, parseRepoReference };
export type { RepoProvider, RepoRef };
