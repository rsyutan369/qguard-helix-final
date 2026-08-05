/**
 * QGuard Scanner — Source Code Platform Adapters
 *
 * One uniform interface over the five source-code platforms the discovery
 * engine supports, so the cryptographic pattern catalogue runs identically
 * whichever platform a repository lives on:
 *
 *   • GitHub            (github.com and GitHub Enterprise Server)
 *   • GitLab            (gitlab.com and self-managed)
 *   • Bitbucket         (bitbucket.org Cloud)
 *   • Azure DevOps      (dev.azure.com / visualstudio.com)
 *   • Gitea / Forgejo   (self-hosted; GitHub-compatible API v1)
 *
 * DESIGN RULES
 * ------------
 * 1. PUBLIC REPOSITORIES MUST WORK UNAUTHENTICATED. Every adapter is usable
 *    with no credentials at all; a token only raises rate limits and unlocks
 *    private repositories. A missing token is never an error.
 * 2. NO ADAPTER EVER THROWS for an expected condition (not found, private,
 *    rate-limited, empty, network error). Each returns a typed, degraded
 *    result carrying the reason and the operator's next step, so one
 *    unreachable repository never fails the surrounding scan.
 * 3. Tokens are read from the server environment only, are never logged, and
 *    never leave the api-server.
 */

export type RepoProvider = 'github' | 'gitlab' | 'bitbucket' | 'azure-devops' | 'gitea'

export interface RepoRef {
  provider: RepoProvider
  /** API origin, e.g. https://api.github.com or https://gitlab.example.com */
  apiBase: string
  /** Namespace: user, org, group (may contain "/" on GitLab and Azure DevOps). */
  owner: string
  repo: string
  /** Canonical human-facing URL. */
  webUrl: string
  /** Azure DevOps only: the project that contains the repository. */
  project?: string
  /** True when the host is not the vendor's public SaaS instance. */
  selfHosted: boolean
  /**
   * How the platform was identified.
   *
   * `certain`   — a known platform host, or an unmistakable repository marker
   *               in the path (`/_git/`, `/-/tree/`, a `.git` suffix).
   * `heuristic` — a self-hosted host that merely *looks* like a Git server.
   *
   * Auto-classification of a pasted target only trusts `certain`; otherwise
   * `https://example.com/blog/post` would be scanned as a repository instead of
   * a website, because it also has two path segments.
   */
  confidence: 'certain' | 'heuristic'
}

export interface RepoTreeEntry {
  path: string
  size?: number
}

export interface RepoResolution {
  ok: boolean
  defaultBranch: string
  visibility: 'public' | 'private' | 'unknown'
  /** Why the repository could not be resolved, when ok === false. */
  notice?: string
  recommendation?: string
}

/** A platform adapter. Every method degrades rather than throwing. */
export interface RepoAdapter {
  ref: RepoRef
  hasToken: boolean
  resolve(): Promise<RepoResolution>
  listTree(branch: string): Promise<{ entries: RepoTreeEntry[]; truncated: boolean; notice?: string }>
  readFile(path: string, branch: string): Promise<string | null>
}

const FETCH_TIMEOUT = 8_000
const MAX_TREE_ENTRIES = 4_000

/* ------------------------------------------------------------------ tokens -- */

/**
 * Per-provider token resolution. Server-side only — returns null in a browser
 * bundle, which is what keeps public scanning working without credentials.
 */
export function resolveProviderToken(provider: RepoProvider): string | null {
  if (typeof process === 'undefined' || !process.env) return null
  const env = process.env
  const pick = (...names: string[]) => {
    for (const name of names) {
      const value = env[name]
      if (value && value.trim()) return value.trim()
    }
    return null
  }
  switch (provider) {
    case 'github':
      return pick('GITHUB_TOKEN', 'GH_TOKEN', 'GITHUB_ACCESS_TOKEN')
    case 'gitlab':
      return pick('GITLAB_TOKEN', 'GITLAB_ACCESS_TOKEN', 'CI_JOB_TOKEN')
    case 'bitbucket':
      return pick('BITBUCKET_TOKEN', 'BITBUCKET_ACCESS_TOKEN', 'BITBUCKET_APP_PASSWORD')
    case 'azure-devops':
      return pick('AZURE_DEVOPS_TOKEN', 'AZURE_DEVOPS_PAT', 'SYSTEM_ACCESSTOKEN')
    case 'gitea':
      return pick('GITEA_TOKEN', 'FORGEJO_TOKEN')
    default:
      return null
  }
}

/** The env var an operator should set, named in user-facing guidance. */
export const PROVIDER_TOKEN_ENV: Record<RepoProvider, string> = {
  github: 'GITHUB_TOKEN',
  gitlab: 'GITLAB_TOKEN',
  bitbucket: 'BITBUCKET_TOKEN',
  'azure-devops': 'AZURE_DEVOPS_TOKEN',
  gitea: 'GITEA_TOKEN',
}

export const PROVIDER_LABEL: Record<RepoProvider, string> = {
  github: 'GitHub',
  gitlab: 'GitLab',
  bitbucket: 'Bitbucket',
  'azure-devops': 'Azure DevOps',
  gitea: 'Gitea/Forgejo',
}

/* ------------------------------------------------------------------ parsing -- */

function stripGit(value: string): string {
  return value.replace(/\.git$/i, '').replace(/\/+$/, '').trim()
}

/**
 * Parse any repository reference into a provider-qualified `RepoRef`.
 *
 * Accepts https URLs, scp-style SSH remotes (`git@host:owner/repo.git`), deep
 * URLs (`/tree/main/...`, `/-/blob/...`, `/src/main/...`), query/fragment noise,
 * and the bare `owner/repo` shorthand (assumed GitHub, matching git's own
 * convention).
 */
export function parseRepoReference(input: string): RepoRef | null {
  const raw = (input || '').trim()
  if (!raw) return null

  // scp-style SSH remote: git@host:path/to/repo.git
  const scp = raw.match(/^(?:ssh:\/\/)?git@([^:/]+)[:/](.+)$/i)
  if (scp) {
    const ref = fromHostAndPath(scp[1], stripGit(scp[2]), `https://${scp[1]}/${stripGit(scp[2])}`)
    // A `git@host:path` remote IS a repository by construction.
    return ref ? { ...ref, confidence: 'certain' } : null
  }

  const withoutNoise = raw.split('#')[0].split('?')[0]

  if (/^https?:\/\//i.test(withoutNoise)) {
    let url: URL
    try {
      url = new URL(withoutNoise)
    } catch {
      return null
    }
    return fromHostAndPath(url.host, stripGit(url.pathname.replace(/^\/+/, '')), withoutNoise)
  }

  // host-qualified without scheme: github.com/owner/repo
  if (/^[a-z0-9.-]+\.[a-z]{2,}\//i.test(withoutNoise)) {
    const slash = withoutNoise.indexOf('/')
    return fromHostAndPath(withoutNoise.slice(0, slash), stripGit(withoutNoise.slice(slash + 1)), `https://${withoutNoise}`)
  }

  // bare owner/repo — git's own shorthand for GitHub
  const bare = withoutNoise.match(/^([\w.-]+)\/([\w.-]+)$/)
  if (bare) {
    return {
      provider: 'github',
      apiBase: 'https://api.github.com',
      owner: bare[1],
      repo: stripGit(bare[2]),
      webUrl: `https://github.com/${bare[1]}/${stripGit(bare[2])}`,
      selfHosted: false,
      confidence: 'certain',
    }
  }
  return null
}

function fromHostAndPath(host: string, path: string, webUrl: string): RepoRef | null {
  const cleanHost = host.toLowerCase().replace(/:\d+$/, (m) => m) // keep explicit ports
  const segments = path.split('/').filter(Boolean)
  if (segments.length < 2) return null

  // ── Azure DevOps ────────────────────────────────────────────────────────
  // dev.azure.com/{org}/{project}/_git/{repo}  |  {org}.visualstudio.com/{project}/_git/{repo}
  if (cleanHost === 'dev.azure.com' || cleanHost.endsWith('.visualstudio.com')) {
    const gitIndex = segments.indexOf('_git')
    if (gitIndex > 0 && segments[gitIndex + 1]) {
      const isVsts = cleanHost.endsWith('.visualstudio.com')
      const org = isVsts ? cleanHost.split('.')[0] : segments[0]
      const project = isVsts ? segments[gitIndex - 1] : segments.slice(1, gitIndex).join('/')
      const repo = stripGit(segments[gitIndex + 1])
      return {
        provider: 'azure-devops',
        apiBase: `https://dev.azure.com/${org}`,
        owner: org,
        project: project || repo,
        repo,
        webUrl,
        selfHosted: false,
        confidence: 'certain',
      }
    }
    return null
  }

  // ── Bitbucket Cloud ─────────────────────────────────────────────────────
  if (cleanHost === 'bitbucket.org' || cleanHost === 'www.bitbucket.org') {
    return {
      provider: 'bitbucket',
      apiBase: 'https://api.bitbucket.org/2.0',
      owner: segments[0],
      repo: stripGit(segments[1]),
      webUrl,
      selfHosted: false,
      confidence: 'certain',
    }
  }

  // ── GitHub (SaaS + Enterprise Server) ───────────────────────────────────
  if (cleanHost === 'github.com' || cleanHost === 'www.github.com') {
    return {
      provider: 'github',
      apiBase: 'https://api.github.com',
      owner: segments[0],
      repo: stripGit(segments[1]),
      webUrl,
      selfHosted: false,
      confidence: 'certain',
    }
  }
  if (cleanHost.includes('github')) {
    // GitHub Enterprise Server: https://github.acme.com/owner/repo → /api/v3
    return {
      provider: 'github',
      apiBase: `https://${cleanHost}/api/v3`,
      owner: segments[0],
      repo: stripGit(segments[1]),
      webUrl,
      selfHosted: true,
      confidence: 'certain',
    }
  }

  // ── GitLab (SaaS + self-managed) ────────────────────────────────────────
  // GitLab groups nest arbitrarily: /group/subgroup/project. "/-/" separates
  // the project path from the in-repo route (/-/blob/main/src/x.ts).
  const isGitLab = cleanHost === 'gitlab.com' || cleanHost.includes('gitlab')
  if (isGitLab) {
    const dashIndex = segments.indexOf('-')
    const projectSegments = dashIndex > 0 ? segments.slice(0, dashIndex) : segments
    if (projectSegments.length < 2) return null
    const repo = stripGit(projectSegments[projectSegments.length - 1])
    const owner = projectSegments.slice(0, -1).join('/')
    return {
      provider: 'gitlab',
      apiBase: cleanHost === 'gitlab.com' ? 'https://gitlab.com/api/v4' : `https://${cleanHost}/api/v4`,
      owner,
      repo,
      webUrl,
      selfHosted: cleanHost !== 'gitlab.com',
      confidence: cleanHost === 'gitlab.com' || cleanHost.startsWith('gitlab.') ? 'certain' : 'heuristic',
    }
  }

  // ── Gitea / Forgejo / unknown self-hosted ───────────────────────────────
  // Treated as the GitHub-compatible API v1 shape, which Gitea, Forgejo and
  // Codeberg all implement. Unreachable hosts degrade with a notice.
  /* Anything else is TREATED as a Gitea-compatible self-hosted server, but only
     claimed with confidence when the host name or the path says "git". Without
     this gate every two-segment website path (`/blog/post`) would be classified
     as a repository. */
  // Public Gitea/Forgejo/sourcehut instances whose names carry no "git" token.
  const KNOWN_SELF_HOSTED_PLATFORMS = ['codeberg.org', 'gitea.com', 'notabug.org', 'sr.ht', 'git.sr.ht']
  const hostLooksLikeGit =
    KNOWN_SELF_HOSTED_PLATFORMS.includes(cleanHost) ||
    /\b(git|gitea|forgejo|gogs|scm|stash|code|source|repo)\b/.test(cleanHost)
  const pathLooksLikeGit = /(^|\/)_git\/|\/-\/(tree|blob)\/|\.git$/i.test(path) || /\.git$/i.test(webUrl)
  return {
    provider: 'gitea',
    apiBase: `https://${cleanHost}/api/v1`,
    owner: segments[0],
    repo: stripGit(segments[1]),
    webUrl,
    selfHosted: true,
    confidence: hostLooksLikeGit || pathLooksLikeGit ? 'certain' : 'heuristic',
  }
}

/* ------------------------------------------------------------------- fetch -- */

async function safeFetch(url: string, headers: Record<string, string>): Promise<Response | null> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT)
  try {
    return await fetch(url, { headers: { 'User-Agent': 'QGuard-Scanner/2.6', ...headers }, signal: controller.signal })
  } catch {
    // Network error, DNS failure, timeout — an expected condition for a
    // self-hosted host that is not reachable from the scanner runtime.
    return null
  } finally {
    clearTimeout(timeout)
  }
}

function base64Decode(value: string): string {
  const clean = value.replace(/\s/g, '')
  if (typeof Buffer !== 'undefined') return Buffer.from(clean, 'base64').toString('utf-8')
  return atob(clean)
}

/** Shared "why did this fail" mapping, in operator language. */
function httpNotice(status: number, provider: RepoProvider, hasToken: boolean, repoName: string): RepoResolution {
  const envName = PROVIDER_TOKEN_ENV[provider]
  const label = PROVIDER_LABEL[provider]
  if (status === 404) {
    return {
      ok: false,
      defaultBranch: '',
      visibility: hasToken ? 'unknown' : 'private',
      notice: `"${repoName}" was not found on ${label}${hasToken ? '' : ', or it is private'}.`,
      recommendation: hasToken
        ? `Verify the repository path and that the configured ${envName} can access it.`
        : `Verify the repository path, or configure ${envName} on the scanner to read private repositories.`,
    }
  }
  if (status === 401 || status === 403) {
    return {
      ok: false,
      defaultBranch: '',
      visibility: 'unknown',
      notice: `${label} denied access to "${repoName}" (HTTP ${status}) — the API rate limit may be exhausted, or the repository is private.`,
      recommendation: `Configure ${envName} on the scanner to raise the rate limit and read private repositories.`,
    }
  }
  return {
    ok: false,
    defaultBranch: '',
    visibility: 'unknown',
    notice: `${label} returned HTTP ${status} for "${repoName}".`,
    recommendation: 'Retry shortly; if it persists, verify the repository URL and the platform status.',
  }
}

function unreachable(ref: RepoRef): RepoResolution {
  return {
    ok: false,
    defaultBranch: '',
    visibility: 'unknown',
    notice: `${PROVIDER_LABEL[ref.provider]} host "${new URL(ref.apiBase).host}" could not be reached from the scanner runtime.`,
    recommendation: ref.selfHosted
      ? 'Self-hosted platforms are often private to your network — deploy a tenant collector agent on an authorized network path.'
      : 'Check outbound network access from the scanner runtime and retry.',
  }
}

/* ------------------------------------------------------------- GitHub/Gitea */

/** GitHub REST v3 and the Gitea/Forgejo v1 API are shape-compatible. */
function githubStyleAdapter(ref: RepoRef, token: string | null): RepoAdapter {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (token) {
    headers.Authorization = ref.provider === 'gitea' ? `token ${token}` : `Bearer ${token}`
  }
  const repoBase = `${ref.apiBase}/repos/${encodeURIComponent(ref.owner)}/${encodeURIComponent(ref.repo)}`

  return {
    ref,
    hasToken: Boolean(token),
    async resolve() {
      const res = await safeFetch(repoBase, headers)
      if (!res) return unreachable(ref)
      if (!res.ok) return httpNotice(res.status, ref.provider, Boolean(token), `${ref.owner}/${ref.repo}`)
      const data: any = await res.json().catch(() => null)
      if (!data) return httpNotice(502, ref.provider, Boolean(token), `${ref.owner}/${ref.repo}`)
      return {
        ok: true,
        defaultBranch: data.default_branch || 'main',
        visibility: data.private ? 'private' : 'public',
      }
    },
    async listTree(branch) {
      const url = `${repoBase}/git/trees/${encodeURIComponent(branch)}?recursive=${ref.provider === 'gitea' ? 'true' : '1'}`
      const res = await safeFetch(url, headers)
      if (!res || !res.ok) {
        return { entries: [], truncated: false, notice: `Could not read the file tree (HTTP ${res?.status ?? 'network error'}).` }
      }
      const data: any = await res.json().catch(() => null)
      const tree = Array.isArray(data?.tree) ? data.tree : []
      return {
        entries: tree
          .filter((item: any) => item.type === 'blob')
          .slice(0, MAX_TREE_ENTRIES)
          .map((item: any) => ({ path: String(item.path), size: Number(item.size) || undefined })),
        truncated: Boolean(data?.truncated),
      }
    },
    async readFile(path, branch) {
      const url = `${repoBase}/contents/${path.split('/').map(encodeURIComponent).join('/')}?ref=${encodeURIComponent(branch)}`
      const res = await safeFetch(url, headers)
      if (!res || !res.ok) return null
      const data: any = await res.json().catch(() => null)
      if (!data || data.encoding !== 'base64' || !data.content) return null
      try {
        return base64Decode(data.content)
      } catch {
        return null
      }
    },
  }
}

/* ------------------------------------------------------------------ GitLab */

function gitlabAdapter(ref: RepoRef, token: string | null): RepoAdapter {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (token) headers['PRIVATE-TOKEN'] = token
  // GitLab identifies a project by its URL-encoded full path, subgroups included.
  const projectId = encodeURIComponent(`${ref.owner}/${ref.repo}`)
  const projectBase = `${ref.apiBase}/projects/${projectId}`

  return {
    ref,
    hasToken: Boolean(token),
    async resolve() {
      const res = await safeFetch(projectBase, headers)
      if (!res) return unreachable(ref)
      if (!res.ok) return httpNotice(res.status, 'gitlab', Boolean(token), `${ref.owner}/${ref.repo}`)
      const data: any = await res.json().catch(() => null)
      if (!data) return httpNotice(502, 'gitlab', Boolean(token), `${ref.owner}/${ref.repo}`)
      return {
        ok: true,
        defaultBranch: data.default_branch || 'main',
        visibility: data.visibility === 'public' ? 'public' : 'private',
      }
    },
    async listTree(branch) {
      // GitLab paginates the recursive tree; walk pages up to the entry budget.
      const entries: RepoTreeEntry[] = []
      let page = 1
      let truncated = false
      while (entries.length < MAX_TREE_ENTRIES && page <= 20) {
        const url = `${projectBase}/repository/tree?recursive=true&per_page=100&page=${page}&ref=${encodeURIComponent(branch)}`
        const res = await safeFetch(url, headers)
        if (!res || !res.ok) {
          if (page === 1) return { entries: [], truncated: false, notice: `Could not read the file tree (HTTP ${res?.status ?? 'network error'}).` }
          break
        }
        const data: any = await res.json().catch(() => null)
        if (!Array.isArray(data) || data.length === 0) break
        for (const item of data) {
          if (item.type === 'blob') entries.push({ path: String(item.path) })
        }
        if (data.length < 100) break
        page += 1
        if (page > 20) truncated = true
      }
      return { entries: entries.slice(0, MAX_TREE_ENTRIES), truncated }
    },
    async readFile(path, branch) {
      const url = `${projectBase}/repository/files/${encodeURIComponent(path)}/raw?ref=${encodeURIComponent(branch)}`
      const res = await safeFetch(url, headers)
      if (!res || !res.ok) return null
      return res.text().catch(() => null)
    },
  }
}

/* --------------------------------------------------------------- Bitbucket */

function bitbucketAdapter(ref: RepoRef, token: string | null): RepoAdapter {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (token) {
    // A raw token is a Bearer access token; "user:app_password" is Basic auth.
    headers.Authorization = token.includes(':')
      ? `Basic ${typeof Buffer !== 'undefined' ? Buffer.from(token).toString('base64') : btoa(token)}`
      : `Bearer ${token}`
  }
  const repoBase = `${ref.apiBase}/repositories/${encodeURIComponent(ref.owner)}/${encodeURIComponent(ref.repo)}`

  return {
    ref,
    hasToken: Boolean(token),
    async resolve() {
      const res = await safeFetch(repoBase, headers)
      if (!res) return unreachable(ref)
      if (!res.ok) return httpNotice(res.status, 'bitbucket', Boolean(token), `${ref.owner}/${ref.repo}`)
      const data: any = await res.json().catch(() => null)
      if (!data) return httpNotice(502, 'bitbucket', Boolean(token), `${ref.owner}/${ref.repo}`)
      return {
        ok: true,
        defaultBranch: data.mainbranch?.name || 'main',
        visibility: data.is_private ? 'private' : 'public',
      }
    },
    async listTree(branch) {
      /* Bitbucket has no recursive tree endpoint. `?max_depth` on /src returns a
         flattened listing, which is the closest equivalent; it paginates. */
      const entries: RepoTreeEntry[] = []
      let url: string | null =
        `${repoBase}/src/${encodeURIComponent(branch)}/?max_depth=8&pagelen=100&fields=values.path,values.type,values.size,next`
      let pages = 0
      while (url && entries.length < MAX_TREE_ENTRIES && pages < 20) {
        const res: Response | null = await safeFetch(url, headers)
        if (!res || !res.ok) {
          if (pages === 0) return { entries: [], truncated: false, notice: `Could not read the file tree (HTTP ${res?.status ?? 'network error'}).` }
          break
        }
        const data: any = await res.json().catch(() => null)
        if (!data || !Array.isArray(data.values)) break
        for (const item of data.values) {
          if (item.type === 'commit_file') entries.push({ path: String(item.path), size: Number(item.size) || undefined })
        }
        url = typeof data.next === 'string' ? data.next : null
        pages += 1
      }
      return { entries: entries.slice(0, MAX_TREE_ENTRIES), truncated: pages >= 20 }
    },
    async readFile(path, branch) {
      const url = `${repoBase}/src/${encodeURIComponent(branch)}/${path.split('/').map(encodeURIComponent).join('/')}`
      const res = await safeFetch(url, headers)
      if (!res || !res.ok) return null
      return res.text().catch(() => null)
    },
  }
}

/* ------------------------------------------------------------ Azure DevOps */

function azureDevOpsAdapter(ref: RepoRef, token: string | null): RepoAdapter {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (token) {
    // Azure DevOps PATs authenticate as Basic with an empty username.
    const basic = typeof Buffer !== 'undefined' ? Buffer.from(`:${token}`).toString('base64') : btoa(`:${token}`)
    headers.Authorization = `Basic ${basic}`
  }
  const project = encodeURIComponent(ref.project || ref.repo)
  const repoBase = `${ref.apiBase}/${project}/_apis/git/repositories/${encodeURIComponent(ref.repo)}`
  const API = 'api-version=7.0'

  return {
    ref,
    hasToken: Boolean(token),
    async resolve() {
      const res = await safeFetch(`${repoBase}?${API}`, headers)
      if (!res) return unreachable(ref)
      if (!res.ok) return httpNotice(res.status, 'azure-devops', Boolean(token), `${ref.owner}/${ref.repo}`)
      const data: any = await res.json().catch(() => null)
      if (!data) return httpNotice(502, 'azure-devops', Boolean(token), `${ref.owner}/${ref.repo}`)
      const branch = String(data.defaultBranch || 'refs/heads/main').replace(/^refs\/heads\//, '')
      return {
        ok: true,
        defaultBranch: branch,
        // Azure DevOps projects are private by default and the API does not
        // expose visibility on this endpoint; reaching it at all is the signal.
        visibility: data.project?.visibility === 'public' ? 'public' : 'private',
      }
    },
    async listTree(branch) {
      const url = `${repoBase}/items?recursionLevel=Full&versionDescriptor.version=${encodeURIComponent(branch)}&versionDescriptor.versionType=branch&${API}`
      const res = await safeFetch(url, headers)
      if (!res || !res.ok) {
        return { entries: [], truncated: false, notice: `Could not read the file tree (HTTP ${res?.status ?? 'network error'}).` }
      }
      const data: any = await res.json().catch(() => null)
      const values = Array.isArray(data?.value) ? data.value : []
      return {
        entries: values
          .filter((item: any) => item.gitObjectType === 'blob' || item.isFolder === false)
          .slice(0, MAX_TREE_ENTRIES)
          .map((item: any) => ({ path: String(item.path || '').replace(/^\//, '') })),
        truncated: false,
      }
    },
    async readFile(path, branch) {
      const url =
        `${repoBase}/items?path=${encodeURIComponent('/' + path.replace(/^\//, ''))}` +
        `&versionDescriptor.version=${encodeURIComponent(branch)}&versionDescriptor.versionType=branch` +
        `&includeContent=true&$format=text&${API}`
      const res = await safeFetch(url, headers)
      if (!res || !res.ok) return null
      return res.text().catch(() => null)
    },
  }
}

/* ---------------------------------------------------------------- factory -- */

/** Build the adapter for a parsed reference, wiring its provider token. */
export function createRepoAdapter(ref: RepoRef, tokenOverride?: string | null): RepoAdapter {
  const token = tokenOverride !== undefined ? tokenOverride : resolveProviderToken(ref.provider)
  switch (ref.provider) {
    case 'gitlab':
      return gitlabAdapter(ref, token)
    case 'bitbucket':
      return bitbucketAdapter(ref, token)
    case 'azure-devops':
      return azureDevOpsAdapter(ref, token)
    case 'github':
    case 'gitea':
    default:
      return githubStyleAdapter(ref, token)
  }
}

/** True when the input looks like a repository on any supported platform. */
export function isRepositoryReference(input: string): boolean {
  const ref = parseRepoReference(input)
  if (!ref) return false
  // A bare domain ("example.com/path") should not be mistaken for a repo unless
  // the host is a known platform or the path has the owner/repo shape.
  return Boolean(ref.owner && ref.repo)
}
