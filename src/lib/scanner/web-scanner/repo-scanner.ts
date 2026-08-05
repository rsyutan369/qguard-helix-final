/**
 * QGuard Scanner — Provider-Agnostic Repository Cryptography Scanner
 *
 * Runs the cryptographic pattern catalogue over a repository on ANY supported
 * source-code platform (GitHub, GitLab, Bitbucket, Azure DevOps, Gitea /
 * self-hosted), and over locally supplied files that were never pushed anywhere.
 *
 * The platform-specific parts live in `repo-providers.ts`; everything here —
 * file selection, budget, matching, deduplication — is shared, so a repository
 * is analysed identically wherever it is hosted.
 */

import type { GitCryptoMatch, GitRepoScanResult, ThreatLevel } from './types'
import { CRYPTO_PATTERNS, PRIORITY_EXTENSIONS, SCANNABLE_FILENAMES, isScannablePath } from './crypto-patterns'
import {
  PROVIDER_LABEL,
  PROVIDER_TOKEN_ENV,
  createRepoAdapter,
  parseRepoReference,
  type RepoAdapter,
  type RepoProvider,
} from './repo-providers'

const MAX_FILES_TO_SCAN = 60
const MAX_FILE_SIZE = 500_000
const REQUEST_DELAY = 120
const MAX_MATCHES = 400

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function getExtension(path: string): string {
  const basename = path.split('/').pop() ?? ''
  const dot = basename.lastIndexOf('.')
  return dot <= 0 ? '' : basename.slice(dot).toLowerCase()
}

const SKIP_DIRECTORIES = [
  'node_modules/', 'vendor/', '.git/', 'dist/', 'build/', 'target/',
  '__pycache__/', '.next/', '.nuxt/', 'coverage/', '.venv/', 'site-packages/',
  'third_party/', 'testdata/', 'fixtures/',
]

/**
 * Rank a path for the bounded file budget.
 *
 * Dependency manifests rank first: one manifest describes an entire dependency
 * graph, while one source file describes one call site. With a bounded budget
 * that ordering is what makes the result representative rather than arbitrary.
 */
export function rankPath(path: string): number {
  const basename = path.split('/').pop()?.toLowerCase() ?? ''
  if (SCANNABLE_FILENAMES.has(basename)) return 0
  return PRIORITY_EXTENSIONS.has(getExtension(path)) ? 1 : 2
}

/** Files worth reading, most informative first, within the budget. */
export function selectFiles(
  entries: Array<{ path: string; size?: number }>,
  budget = MAX_FILES_TO_SCAN,
): Array<{ path: string; size?: number }> {
  return entries
    .filter((entry) => {
      if (!isScannablePath(entry.path)) return false
      if (entry.size && entry.size > MAX_FILE_SIZE) return false
      const lower = entry.path.toLowerCase()
      if (SKIP_DIRECTORIES.some((dir) => lower.includes(dir))) return false
      return true
    })
    .sort((a, b) => rankPath(a.path) - rankPath(b.path))
    .slice(0, budget)
}

/**
 * Apply the catalogue to one file's contents.
 *
 * Deduplicates per (file, pattern) within a 5-line window so a loop that uses
 * MD5 twenty times contributes one finding, not twenty.
 */
export function matchFileContent(path: string, content: string): GitCryptoMatch[] {
  const matches: GitCryptoMatch[] = []
  const lines = content.split('\n')
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]
    if (!line || line.length > 4_000) continue // skip minified megabyte lines
    for (const pattern of CRYPTO_PATTERNS) {
      if (!line.match(pattern.regex)) continue
      const duplicate = matches.find(
        (existing) => existing.file === path && existing.pattern === pattern.label && Math.abs(existing.line - (index + 1)) < 5,
      )
      if (duplicate) continue
      matches.push({
        file: path,
        line: index + 1,
        pattern: pattern.label,
        category: pattern.category,
        algorithm: pattern.algorithm,
        snippet: lines.slice(Math.max(0, index - 1), Math.min(lines.length, index + 2)).join('\n').substring(0, 200),
        threatLevel: pattern.threatLevel as ThreatLevel,
        description: pattern.description,
      })
    }
  }
  return matches
}

/** A repository the scanner could not read — reported, never thrown. */
function degraded(
  repoUrl: string,
  repoName: string,
  notice: string,
  recommendation: string,
  visibility: GitRepoScanResult['visibility'] = 'unknown',
  defaultBranch?: string,
): GitRepoScanResult {
  return {
    repoUrl,
    repoName,
    filesScanned: 0,
    totalFiles: 0,
    patterns: [],
    accessible: false,
    notice,
    recommendation,
    visibility,
    defaultBranch,
  }
}

/**
 * Scan a repository on any supported platform.
 *
 * Public repositories work with no credentials on every platform. A token only
 * raises rate limits and unlocks private repositories, and its absence is
 * reported as guidance rather than as an error.
 */
export async function scanRepository(repoUrl: string, tokenOverride?: string | null): Promise<GitRepoScanResult> {
  const ref = parseRepoReference(repoUrl)
  if (!ref) {
    return degraded(
      repoUrl,
      repoUrl,
      `"${repoUrl}" is not a repository reference this scanner recognises.`,
      'Supply a GitHub, GitLab, Bitbucket, Azure DevOps or self-hosted Git URL (for example https://gitlab.com/group/project).',
    )
  }

  const repoName = `${ref.owner}/${ref.repo}`
  const adapter: RepoAdapter = createRepoAdapter(ref, tokenOverride)
  const label = PROVIDER_LABEL[ref.provider]

  const resolution = await adapter.resolve()
  if (!resolution.ok) {
    return degraded(
      ref.webUrl,
      repoName,
      resolution.notice || `${label} repository "${repoName}" could not be resolved.`,
      resolution.recommendation || `Configure ${PROVIDER_TOKEN_ENV[ref.provider]} on the scanner, or verify the URL.`,
      resolution.visibility,
    )
  }

  const tree = await adapter.listTree(resolution.defaultBranch)
  if (tree.entries.length === 0) {
    return degraded(
      ref.webUrl,
      repoName,
      tree.notice || `${label} repository "${repoName}" has no readable files on branch "${resolution.defaultBranch}".`,
      'The default branch may have no commits, or the repository may be empty.',
      resolution.visibility,
      resolution.defaultBranch,
    )
  }

  const selected = selectFiles(tree.entries)
  const patterns: GitCryptoMatch[] = []
  let filesScanned = 0

  for (const file of selected) {
    if (patterns.length >= MAX_MATCHES) break
    if (REQUEST_DELAY > 0) await delay(REQUEST_DELAY)
    const content = await adapter.readFile(file.path, resolution.defaultBranch)
    if (content === null) continue
    filesScanned += 1
    patterns.push(...matchFileContent(file.path, content))
  }

  return {
    repoUrl: ref.webUrl,
    repoName,
    filesScanned,
    totalFiles: tree.entries.length,
    patterns: patterns.slice(0, MAX_MATCHES),
    accessible: true,
    visibility: resolution.visibility,
    defaultBranch: resolution.defaultBranch,
    notice: tree.truncated
      ? `The file tree was truncated at the scanner's budget; ${filesScanned} of ${tree.entries.length} candidate files were analysed.`
      : undefined,
  }
}

/* ─────────────────────────────────────────────────────────── local sources */

export interface LocalFileInput {
  /** Path as it should appear in findings, e.g. "src/crypto.ts". */
  path: string
  /** UTF-8 decoded file contents. */
  content: string
}

export interface LocalScanResult extends GitRepoScanResult {
  /** Files present in the input that were not eligible for analysis. */
  skippedFiles: number
}

/**
 * Scan locally supplied source — an uploaded archive, a folder, or individual
 * files — with the SAME catalogue and the same selection rules used for hosted
 * repositories, so a pre-deployment codebase is assessed on identical terms.
 *
 * This is what makes cryptographic discovery possible before anything is
 * pushed or deployed.
 */
export function scanLocalSource(files: LocalFileInput[], sourceLabel = 'local upload'): LocalScanResult {
  const entries = files.map((file) => ({ path: file.path, size: file.content.length }))
  const selected = selectFiles(entries, Math.max(MAX_FILES_TO_SCAN, files.length))
  const selectedPaths = new Set(selected.map((entry) => entry.path));
  const byPath = new Map(files.map((file) => [file.path, file.content]))

  const patterns: GitCryptoMatch[] = []
  let filesScanned = 0
  for (const entry of selected) {
    const content = byPath.get(entry.path)
    if (content === undefined) continue
    filesScanned += 1
    patterns.push(...matchFileContent(entry.path, content))
    if (patterns.length >= MAX_MATCHES) break
  }

  return {
    repoUrl: sourceLabel,
    repoName: sourceLabel,
    filesScanned,
    totalFiles: files.length,
    skippedFiles: files.length - selectedPaths.size,
    patterns: patterns.slice(0, MAX_MATCHES),
    accessible: true,
    visibility: 'unknown',
    notice: files.length === 0
      ? 'No files were supplied for analysis.'
      : filesScanned === 0
        ? 'None of the supplied files were of a type this scanner analyses (source, manifests, configuration or key material).'
        : undefined,
  }
}

/**
 * Provider of a reference, for AUTO-CLASSIFYING a pasted target.
 *
 * Only a `certain` identification counts: a known platform host, an
 * unmistakable repository marker in the path, or a git remote. A self-hosted
 * host that merely looks plausible returns null, so an ordinary website with a
 * two-segment path (`https://example.com/blog/post`) is still scanned as a
 * website. `scanRepository` itself remains permissive — a user who explicitly
 * submits a self-hosted repo URL still gets it scanned.
 */
export function repositoryProvider(repoUrl: string): RepoProvider | null {
  const ref = parseRepoReference(repoUrl)
  if (!ref || ref.confidence !== 'certain') return null
  return ref.provider
}
