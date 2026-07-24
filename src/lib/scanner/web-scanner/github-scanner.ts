/**
 * QGuard Web Scanner — GitHub Repository Crypto Scanner
 * Scans GitHub repositories for quantum-vulnerable cryptographic patterns in
 * source, dependency manifests and config.
 *
 * Uses the GitHub REST API. Public repos work unauthenticated (60 req/hr). A
 * token (GITHUB_TOKEN / GH_TOKEN env, provided to the api-server) unlocks
 * PRIVATE repositories and raises the rate limit to 5000 req/hr. When a repo
 * cannot be read (private without a token, not found, rate-limited or empty)
 * the scan degrades gracefully with an actionable notice instead of failing
 * the whole module.
 */

import type { GitRepoScanResult, GitCryptoMatch, ThreatLevel } from './types'
import { CRYPTO_PATTERNS, SCANNABLE_EXTENSIONS, PRIORITY_EXTENSIONS } from './crypto-patterns'

const GITHUB_API = 'https://api.github.com'
const MAX_FILES_TO_SCAN = 50
const MAX_FILE_SIZE = 500_000 // 500KB max per file
const REQUEST_DELAY = 200 // ms between requests to avoid rate limiting
const FETCH_TIMEOUT = 8_000 // 8 seconds per request

interface GitHubTreeItem {
  path: string
  type: 'blob' | 'tree'
  size?: number
  sha: string
  url: string
}

interface GitHubTreeResponse {
  sha: string
  tree: GitHubTreeItem[]
  truncated: boolean
}

interface GitHubContentResponse {
  content: string
  encoding: string
  size: number
  name: string
  path: string
}

/**
 * Resolve an optional GitHub access token from the server environment. Present
 * only server-side (the scanner runs in the Express api-server); returns null
 * in the browser or when unset. Never logged or returned to the client.
 */
function resolveGitHubToken(): string | null {
  if (typeof process === 'undefined' || !process.env) return null
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || process.env.GITHUB_ACCESS_TOKEN
  return token && token.trim() ? token.trim() : null
}

/** Actionable hint that depends on whether a token is configured. */
function accessHint(hasToken: boolean): string {
  return hasToken
    ? 'Verify the repository URL is correct and that the configured GitHub token can access it.'
    : 'If this is a private repository, configure a GITHUB_TOKEN (or GH_TOKEN) environment variable on the scanner to enable private-repo scanning; otherwise verify the URL is correct and the repository is public.'
}

/**
 * Parse a GitHub repo reference into owner and repo name. Handles https/http
 * URLs, protocol-less "owner/repo", scp-style git@github.com:owner/repo.git,
 * ".git" suffixes, deep paths (/tree/main, /blob/...), and query/hash noise.
 */
function parseRepoUrl(repoUrl: string): { owner: string; repo: string } | null {
  const raw = (repoUrl || '').trim()
  if (!raw) return null

  // scp-like SSH remote: git@github.com:owner/repo(.git)
  const scp = raw.match(/^git@github\.com:([^/]+)\/(.+)$/i)
  if (scp) return { owner: scp[1], repo: cleanRepoName(scp[2]) }

  // strip fragment + query before matching
  const s = raw.split('#')[0].split('?')[0]
  const patterns = [
    /github\.com[/:]([^/]+)\/([^/\s]+)/i, // any github.com URL
    /^([^/\s]+)\/([^/\s]+)$/,             // bare owner/repo
  ]
  for (const pattern of patterns) {
    const match = s.match(pattern)
    if (match && match[1] && match[2]) {
      const owner = match[1].replace(/\/$/, '')
      const repo = cleanRepoName(match[2])
      if (owner && repo) return { owner, repo }
    }
  }
  return null
}

/** Strip .git, any trailing path (tree/main, blob/…) and trailing slashes. */
function cleanRepoName(value: string): string {
  return value
    .replace(/\.git$/i, '')
    .replace(/\/.*$/, '') // drop /tree/<branch>, /blob/<path>, etc.
    .replace(/\/$/, '')
    .trim()
}

/**
 * Make a rate-limited, optionally-authenticated fetch to the GitHub API.
 */
async function githubFetch(url: string, token: string | null): Promise<Response> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT)

  try {
    const headers: Record<string, string> = {
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'QGuard-Scanner/2.5',
      'X-GitHub-Api-Version': '2022-11-28',
    }
    if (token) headers['Authorization'] = `Bearer ${token}`
    return await fetch(url, { headers, signal: controller.signal })
  } finally {
    clearTimeout(timeout)
  }
}

/**
 * Delay between API calls to respect rate limits
 */
function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

/**
 * Get the file extension from a path
 */
function getExtension(path: string): string {
  const dotIndex = path.lastIndexOf('.')
  if (dotIndex === -1) return ''
  return path.substring(dotIndex).toLowerCase()
}

/**
 * Scan a GitHub repository for quantum-vulnerable cryptographic patterns
 */
export async function scanGitHubRepo(repoUrl: string): Promise<GitRepoScanResult> {
  const parsed = parseRepoUrl(repoUrl)
  if (!parsed) {
    // Not a hard failure: report it as an inaccessible target with guidance.
    return {
      repoUrl,
      repoName: repoUrl,
      filesScanned: 0,
      totalFiles: 0,
      patterns: [],
      accessible: false,
      visibility: 'unknown',
      notice: `Could not parse a GitHub owner/repository from "${repoUrl}".`,
      recommendation: 'Use a URL like https://github.com/<owner>/<repository>.',
    }
  }

  const { owner, repo } = parsed
  const repoName = `${owner}/${repo}`
  const token = resolveGitHubToken()
  const hasToken = !!token
  const patterns: GitCryptoMatch[] = []

  // Graceful degraded result helper — the module completes with a notice
  // instead of throwing (which would mark the whole scan module FAILED).
  const degraded = (notice: string, recommendation: string, visibility: 'public' | 'private' | 'unknown' = 'unknown', defaultBranch?: string): GitRepoScanResult => ({
    repoUrl: `https://github.com/${repoName}`,
    repoName,
    filesScanned: 0,
    totalFiles: 0,
    patterns: [],
    accessible: false,
    visibility,
    defaultBranch,
    notice,
    recommendation,
  })

  // Step 0: Preflight the repository to confirm access + resolve the real
  // default branch (the git/trees/HEAD ref is unreliable). This also cleanly
  // distinguishes private-without-token / not-found / rate-limited / empty.
  let defaultBranch = 'HEAD'
  let visibility: 'public' | 'private' | 'unknown' = 'unknown'
  try {
    const metaRes = await githubFetch(`${GITHUB_API}/repos/${owner}/${repo}`, token)
    if (metaRes.status === 404) {
      return degraded(
        `Repository "${repoName}" was not found or is private and not accessible with the current credentials.`,
        accessHint(hasToken),
      )
    }
    if (metaRes.status === 401) {
      return degraded('GitHub authentication failed — the configured token was rejected.', 'Check that the GITHUB_TOKEN value is valid and has repo read scope.')
    }
    if (metaRes.status === 403) {
      const remaining = metaRes.headers.get('x-ratelimit-remaining')
      if (remaining === '0') {
        return degraded(
          'GitHub API rate limit reached.',
          hasToken ? 'Wait for the rate-limit window to reset, then re-run the scan.' : 'Configure a GITHUB_TOKEN to raise the limit from 60 to 5,000 requests/hour.',
        )
      }
      return degraded(`Access to repository "${repoName}" is forbidden.`, accessHint(hasToken))
    }
    if (!metaRes.ok) {
      return degraded(`GitHub API returned ${metaRes.status} ${metaRes.statusText} for "${repoName}".`, 'Verify the repository URL and try again.')
    }
    const info = await metaRes.json() as { default_branch?: string; private?: boolean; size?: number }
    defaultBranch = info.default_branch || 'HEAD'
    visibility = info.private ? 'private' : 'public'
    if (typeof info.size === 'number' && info.size === 0) {
      return degraded(`Repository "${repoName}" is empty — no files to scan.`, 'Push code to the repository, then re-run the scan.', visibility, defaultBranch)
    }
  } catch (err) {
    if ((err as Error).name === 'AbortError') {
      return degraded(`Preflight request to GitHub timed out for "${repoName}".`, 'GitHub may be slow or unreachable from the scanner; retry shortly.')
    }
    return degraded(`Could not reach GitHub to inspect "${repoName}": ${(err as Error).message}.`, 'Check the scanner\'s outbound network access to api.github.com, then retry.')
  }

  // Step 1: Get the file tree using the resolved default branch (fallback HEAD)
  let tree: GitHubTreeItem[] = []
  try {
    let treeRes = await githubFetch(
      `${GITHUB_API}/repos/${owner}/${repo}/git/trees/${encodeURIComponent(defaultBranch)}?recursive=1`,
      token,
    )
    if (!treeRes.ok && defaultBranch !== 'HEAD') {
      treeRes = await githubFetch(`${GITHUB_API}/repos/${owner}/${repo}/git/trees/HEAD?recursive=1`, token)
    }
    if (!treeRes.ok) {
      // Repo exists (preflight passed) but the tree couldn't be read.
      return degraded(
        `Could not read the file tree for "${repoName}" (${treeRes.status}).`,
        'The default branch may have no commits, or the repository is unusually large; scanning was skipped.',
        visibility,
        defaultBranch,
      )
    }
    const treeData: GitHubTreeResponse = await treeRes.json()
    tree = treeData.tree.filter(item => item.type === 'blob')
  } catch (err) {
    if ((err as Error).name === 'AbortError') {
      return degraded(`Reading the file tree for "${repoName}" timed out.`, 'GitHub may be slow; retry shortly.', visibility, defaultBranch)
    }
    return degraded(`Failed to read the file tree for "${repoName}": ${(err as Error).message}.`, 'Retry shortly; if it persists, verify the repository URL.', visibility, defaultBranch)
  }

  // Step 2: Filter to scannable files
  const scannableFiles = tree.filter(item => {
    const ext = getExtension(item.path)
    if (!SCANNABLE_EXTENSIONS.has(ext)) return false
    if (item.size && item.size > MAX_FILE_SIZE) return false
    // Skip common non-code directories
    const skipDirs = ['node_modules/', 'vendor/', '.git/', 'dist/', 'build/', '__pycache__/', '.next/']
    if (skipDirs.some(d => item.path.includes(d))) return false
    return true
  })

  // Step 3: Prioritize files and limit count
  const prioritized = scannableFiles.sort((a, b) => {
    const aIsPriority = PRIORITY_EXTENSIONS.has(getExtension(a.path)) ? 0 : 1
    const bIsPriority = PRIORITY_EXTENSIONS.has(getExtension(b.path)) ? 0 : 1
    return aIsPriority - bIsPriority
  })

  const filesToScan = prioritized.slice(0, MAX_FILES_TO_SCAN)

  // Step 4: Scan each file
  for (const file of filesToScan) {
    try {
      await delay(REQUEST_DELAY)

      const contentRes = await githubFetch(
        `${GITHUB_API}/repos/${owner}/${repo}/contents/${file.path}`,
        token,
      )

      if (!contentRes.ok) continue

      const contentData: GitHubContentResponse = await contentRes.json()

      if (contentData.encoding !== 'base64' || !contentData.content) continue

      // Decode base64 content
      const content = Buffer.from(contentData.content, 'base64').toString('utf-8')
      const lines = content.split('\n')

      // Apply regex patterns
      for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        const line = lines[lineNum]

        for (const pattern of CRYPTO_PATTERNS) {
          const match = line.match(pattern.regex)
          if (match) {
            // Avoid duplicate findings for the same pattern in the same file
            const existingDupe = patterns.find(
              p => p.file === file.path && p.pattern === pattern.label && Math.abs(p.line - (lineNum + 1)) < 5
            )
            if (existingDupe) continue

            // Extract a snippet around the match
            const snippetStart = Math.max(0, lineNum - 1)
            const snippetEnd = Math.min(lines.length, lineNum + 2)
            const snippet = lines.slice(snippetStart, snippetEnd).join('\n').substring(0, 200)

            patterns.push({
              file: file.path,
              line: lineNum + 1,
              pattern: pattern.label,
              category: pattern.category,
              algorithm: pattern.algorithm,
              snippet,
              threatLevel: pattern.threatLevel as ThreatLevel,
              description: pattern.description,
            })
          }
        }
      }
    } catch {
      // Skip files that fail to fetch
      continue
    }
  }

  return {
    repoUrl: `https://github.com/${repoName}`,
    repoName,
    filesScanned: filesToScan.length,
    totalFiles: scannableFiles.length,
    patterns,
    accessible: true,
    visibility,
    defaultBranch,
    notice: filesToScan.length === 0 ? `No scannable source or dependency files found in "${repoName}".` : undefined,
  }
}

/**
 * Quick check if a URL is a GitHub repository
 */
export function isGitHubUrl(url: string): boolean {
  return /github\.com\/[^/]+\/[^/]+/.test(url)
}
