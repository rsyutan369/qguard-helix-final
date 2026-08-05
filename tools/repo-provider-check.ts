/**
 * Source-code platform adapters — regression suite.
 *
 * Proves the discovery engine recognises repositories on every supported
 * platform, that public repositories need no credentials, that an ordinary
 * website is never mistaken for a repository, and that unreachable or private
 * repositories degrade with an actionable reason instead of throwing.
 *
 *   npx tsx tools/repo-provider-check.ts
 */
import {
  PROVIDER_LABEL,
  PROVIDER_TOKEN_ENV,
  createRepoAdapter,
  parseRepoReference,
  resolveProviderToken,
  type RepoProvider,
} from '../src/lib/scanner/web-scanner/repo-providers'
import {
  matchFileContent,
  rankPath,
  repositoryProvider,
  scanLocalSource,
  selectFiles,
} from '../src/lib/scanner/web-scanner/repo-scanner'

let failures = 0
function assert(condition: boolean, label: string) {
  if (condition) console.log(`  ok   ${label}`)
  else {
    failures += 1
    console.log(`  FAIL ${label}`)
  }
}

/* ------------------------------------------------------------------ parsing */

const PARSE_CASES: Array<{ input: string; provider: RepoProvider; owner: string; repo: string; project?: string }> = [
  { input: 'https://github.com/anthropics/claude-code', provider: 'github', owner: 'anthropics', repo: 'claude-code' },
  { input: 'https://github.com/anthropics/claude-code.git', provider: 'github', owner: 'anthropics', repo: 'claude-code' },
  { input: 'https://github.com/anthropics/claude-code/tree/main/src', provider: 'github', owner: 'anthropics', repo: 'claude-code' },
  { input: 'git@github.com:anthropics/claude-code.git', provider: 'github', owner: 'anthropics', repo: 'claude-code' },
  { input: 'anthropics/claude-code', provider: 'github', owner: 'anthropics', repo: 'claude-code' },
  { input: 'https://github.acme.com/platform/api', provider: 'github', owner: 'platform', repo: 'api' },

  { input: 'https://gitlab.com/gitlab-org/gitlab', provider: 'gitlab', owner: 'gitlab-org', repo: 'gitlab' },
  { input: 'https://gitlab.com/group/subgroup/project', provider: 'gitlab', owner: 'group/subgroup', repo: 'project' },
  { input: 'https://gitlab.com/gitlab-org/gitlab/-/blob/master/README.md', provider: 'gitlab', owner: 'gitlab-org', repo: 'gitlab' },
  { input: 'https://gitlab.internal.acme.com/infra/tls-config', provider: 'gitlab', owner: 'infra', repo: 'tls-config' },

  { input: 'https://bitbucket.org/atlassian/pipelines', provider: 'bitbucket', owner: 'atlassian', repo: 'pipelines' },
  { input: 'https://bitbucket.org/atlassian/pipelines/src/master/', provider: 'bitbucket', owner: 'atlassian', repo: 'pipelines' },

  { input: 'https://dev.azure.com/contoso/Payments/_git/crypto-lib', provider: 'azure-devops', owner: 'contoso', repo: 'crypto-lib', project: 'Payments' },
  { input: 'https://contoso.visualstudio.com/Payments/_git/crypto-lib', provider: 'azure-devops', owner: 'contoso', repo: 'crypto-lib', project: 'Payments' },

  { input: 'https://codeberg.org/forgejo/forgejo', provider: 'gitea', owner: 'forgejo', repo: 'forgejo' },
  { input: 'https://git.acme.io/platform/pki', provider: 'gitea', owner: 'platform', repo: 'pki' },
]

function verifyParsing() {
  console.log('\n=== Repository reference parsing ===')
  for (const testCase of PARSE_CASES) {
    const ref = parseRepoReference(testCase.input)
    const ok =
      ref !== null &&
      ref.provider === testCase.provider &&
      ref.owner === testCase.owner &&
      ref.repo === testCase.repo &&
      (testCase.project === undefined || ref.project === testCase.project)
    assert(
      ok,
      `${testCase.input} → ${PROVIDER_LABEL[testCase.provider]} ${testCase.owner}/${testCase.repo}` +
        (ok ? '' : ` (got ${ref ? `${ref.provider} ${ref.owner}/${ref.repo}` : 'null'})`),
    )
  }
}

/* ------------------------------------------------- website misclassification */

function verifyWebsitesAreNotRepositories() {
  console.log('\n=== A website is never auto-classified as a repository ===')
  /* The permissive parser falls back to a Gitea-compatible shape for unknown
     hosts. Auto-classification must NOT trust that, or every two-segment URL
     would be scanned as source code instead of as a web endpoint. */
  for (const url of [
    'https://www.cloudflare.com/products/zero-trust',
    'https://example.com/blog/post',
    'https://shop.acme.com/cart/checkout',
    'https://docs.python.org/3/library',
    'https://news.ycombinator.com/item/123',
  ]) {
    assert(repositoryProvider(url) === null, `not a repository: ${url}`)
  }

  console.log('\n=== ...but every real platform IS auto-classified ===')
  for (const testCase of PARSE_CASES) {
    assert(repositoryProvider(testCase.input) === testCase.provider, `repository: ${testCase.input}`)
  }

  // A self-hosted host that names itself git IS trusted.
  assert(repositoryProvider('https://git.acme.io/platform/pki') === 'gitea', 'self-hosted "git.*" host is trusted')
  // ...one that does not, is not.
  assert(repositoryProvider('https://portal.acme.io/platform/pki') === null, 'ambiguous self-hosted host is not auto-classified')
}

/* --------------------------------------------------------- adapter contract */

function verifyAdapterContract() {
  console.log('\n=== Adapter contract ===')
  const providers: RepoProvider[] = ['github', 'gitlab', 'bitbucket', 'azure-devops', 'gitea']
  for (const provider of providers) {
    const sample = PARSE_CASES.find((testCase) => testCase.provider === provider)!
    const ref = parseRepoReference(sample.input)!
    const adapter = createRepoAdapter(ref, null) // explicitly unauthenticated
    assert(adapter.hasToken === false, `${PROVIDER_LABEL[provider]}: builds without credentials`)
    assert(typeof adapter.resolve === 'function' && typeof adapter.listTree === 'function' && typeof adapter.readFile === 'function',
      `${PROVIDER_LABEL[provider]}: implements the full adapter interface`)
    assert(Boolean(PROVIDER_TOKEN_ENV[provider]), `${PROVIDER_LABEL[provider]}: names its token env var (${PROVIDER_TOKEN_ENV[provider]})`)
    // Token resolution must never throw, with or without env configured.
    let threw = false
    try {
      resolveProviderToken(provider)
    } catch {
      threw = true
    }
    assert(!threw, `${PROVIDER_LABEL[provider]}: token resolution never throws`)
  }
}

/* ---------------------------------------------------- graceful degradation */

async function verifyGracefulDegradation() {
  console.log('\n=== Unreachable / invalid repositories degrade, never throw ===')
  const { scanRepository } = await import('../src/lib/scanner/web-scanner/repo-scanner')

  const bogus = await scanRepository('https://git.this-host-does-not-exist-qguard.invalid/a/b')
  assert(bogus.accessible === false, 'unreachable self-hosted host → accessible:false')
  assert(Boolean(bogus.notice), `carries a notice (${bogus.notice})`)
  assert(Boolean(bogus.recommendation), 'carries an actionable recommendation')
  assert(bogus.patterns.length === 0, 'produces no invented findings')

  const nonsense = await scanRepository('not a url at all')
  assert(nonsense.accessible === false, 'unparseable reference → accessible:false')
  assert((nonsense.recommendation || '').toLowerCase().includes('gitlab'), 'guidance names the supported platforms')
}

/* -------------------------------------------------------- local file source */

function verifyLocalScanning() {
  console.log('\n=== Local source (pre-deployment) scanning ===')
  const result = scanLocalSource(
    [
      { path: 'src/crypto.ts', content: `const h = createHash('md5')\nconst kp = generateKeyPairSync('rsa', {})` },
      { path: 'requirements.txt', content: 'pycryptodome==3.19.0' },
      { path: 'go.mod', content: 'require golang.org/x/crypto v0.17.0' },
      { path: 'README.md', content: 'Just documentation about RSA' },
      { path: 'assets/logo.png', content: 'binary-ish' },
    ],
    'uploaded.zip',
  )
  assert(result.accessible === true, 'local upload is accessible')
  assert(result.filesScanned === 3, `only analysable files are read (${result.filesScanned}/5)`)
  assert(result.skippedFiles === 2, `non-code files are reported as skipped (${result.skippedFiles})`)
  const algorithms = result.patterns.map((p) => p.algorithm.toLowerCase()).join(' | ')
  assert(algorithms.includes('md5'), 'detects MD5 in uploaded source')
  assert(algorithms.includes('rsa'), 'detects RSA in uploaded source')
  assert(algorithms.includes('python crypto library'), 'detects a Python dependency manifest')
  assert(algorithms.includes('go crypto module'), 'detects a Go module dependency')
  assert(
    !result.patterns.some((p) => p.file === 'README.md'),
    'documentation is excluded — prose about RSA is not a cryptographic asset',
  )

  const empty = scanLocalSource([], 'empty.zip')
  assert(empty.patterns.length === 0 && Boolean(empty.notice), 'an empty upload explains itself rather than reporting a clean bill')
}

/* --------------------------------------------------------- file prioritising */

function verifyFileSelection() {
  console.log('\n=== File budget prioritises the dependency graph ===')
  assert(rankPath('package.json') < rankPath('src/index.ts'), 'manifests outrank source files')
  // `.yaml` is itself a priority extension (TLS and cluster config live there),
  // so the contrast is against a genuinely incidental type.
  assert(rankPath('src/index.ts') < rankPath('templates/page.xml'), 'priority source outranks incidental file types')

  const selected = selectFiles(
    [
      { path: 'node_modules/lib/index.js' },
      { path: 'dist/bundle.js' },
      { path: 'src/a.ts' },
      { path: 'package.json' },
      { path: 'vendor/x.go' },
      { path: 'huge.ts', size: 900_000 },
    ],
    10,
  )
  const paths = selected.map((entry) => entry.path)
  assert(paths[0] === 'package.json', `manifest is read first (${paths[0]})`)
  assert(!paths.some((p) => p.includes('node_modules') || p.includes('dist/') || p.includes('vendor/')), 'build and vendor output is excluded')
  assert(!paths.includes('huge.ts'), 'oversized files are excluded')
}

function verifyMatching() {
  console.log('\n=== Per-file matching ===')
  const matches = matchFileContent('src/x.ts', `const a = createHash('md5')\nconst b = createHash('md5')\nconst c = createHash('md5')`)
  /* Several DISTINCT rules legitimately fire on one line — the algorithm-name
     rule and the API-idiom rule both describe the same MD5 usage from different
     angles. What must not happen is the SAME rule firing once per line, which
     would triple-count a loop that hashes in three places. */
  const labels = matches.map((m) => m.pattern)
  assert(new Set(labels).size === labels.length, `no rule fires more than once per file window (${labels.join(', ')})`)
  assert(matches.every((m) => m.line === 1), 'repeated adjacent usage collapses onto the first occurrence')
  assert(matches[0].file === 'src/x.ts', 'the finding carries file and line evidence')
  assert(
    !labels.some((label) => label.startsWith('PHP')),
    `a Node createHash call is not attributed to the PHP rule (${labels.join(', ')})`,
  )
}

/* ------------------------------------------------------------------ driver */

async function main() {
  verifyParsing()
  verifyWebsitesAreNotRepositories()
  verifyAdapterContract()
  verifyLocalScanning()
  verifyFileSelection()
  verifyMatching()
  await verifyGracefulDegradation()

  console.log('')
  if (failures > 0) {
    console.error(`${failures} repository provider check(s) FAILED.`)
    process.exitCode = 1
    return
  }
  console.log('All repository provider checks passed.')
  process.exitCode = 0
}

main()
