---
name: qguard-source-discovery
description: Multi-platform source code discovery for QGuard Helix — GitHub, GitLab, Bitbucket, Azure DevOps, Gitea/self-hosted, plus local file and archive scanning. Use when adding a source platform, debugging repository scans, handling authentication and rate limits, or when a website is misclassified as a repository.
priority: high
owner: qguard-helix
version: 1.0
---

# Source Code Platform Discovery

## Where the code is

| Concern | File |
|---|---|
| Platform adapters, URL parsing, tokens | `src/lib/scanner/web-scanner/repo-providers.ts` |
| Provider-agnostic scan, local sources | `src/lib/scanner/web-scanner/repo-scanner.ts` |
| Compatibility shim (21 lines) | `src/lib/scanner/web-scanner/github-scanner.ts` |
| Tests | `tools/repo-provider-check.ts` |

The catalog id in the module ledger stays `github-scanner` — it is the stable
routing key. Only the *display name* reflects the detected platform.

## Three design rules

1. **Public repositories must work with no credentials, on every platform.** A
   token only raises rate limits and unlocks private repos. A missing token is
   never an error.
2. **No adapter ever throws for an expected condition** — not found, private,
   rate limited, empty, network failure. Each returns a typed degraded result
   with a reason and an operator next step, so one unreachable repository never
   fails the surrounding scan.
3. **Tokens are server-side only**, never logged, never returned to the client.

## Platform quirks that cost time

| Platform | Quirk |
|---|---|
| **GitHub** | Enterprise Server lives at `https://host/api/v3`, not `/api/v1`. Unauthenticated = 60 req/hr/IP. |
| **GitLab** | Project id is the **URL-encoded full path** including nested subgroups (`group%2Fsub%2Fproject`). `/-/` separates project path from in-repo route. Recursive tree is **paginated**. Auth header is `PRIVATE-TOKEN`, not Bearer. |
| **Bitbucket** | **No recursive tree endpoint.** Closest equivalent is `/src/{branch}?max_depth=N`, paginated via `next`. A raw token is Bearer; `user:app_password` is Basic. |
| **Azure DevOps** | URLs use `/_git/`. PAT authenticates as **Basic with an EMPTY username** (`:PAT`). `defaultBranch` comes back as `refs/heads/main` — strip the prefix. |
| **Gitea/Forgejo** | GitHub-compatible API v1, but auth header is `token <t>`, not `Bearer`. |

Token env vars: `GITHUB_TOKEN`, `GITLAB_TOKEN`, `BITBUCKET_TOKEN`,
`AZURE_DEVOPS_TOKEN`, `GITEA_TOKEN`.

## The confidence gate — load-bearing

The parser falls back to a Gitea-compatible shape for **any** unknown host with
two path segments. That describes most website URLs.

```ts
confidence: 'certain' | 'heuristic'
```

- `certain` — a known platform host, an unmistakable path marker (`/_git/`,
  `/-/tree/`, `.git`), or a `git@host:path` remote.
- `heuristic` — a self-hosted host that merely looks plausible.

`repositoryProvider()` — used to **auto-classify a pasted target** — trusts only
`certain`. `scanRepository()` stays permissive, so a user who explicitly submits
a self-hosted URL still gets it scanned.

Without this gate, `https://example.com/blog/post` is scanned as source code.

Known public instances need an explicit allow-list, because their names contain
no "git" token: `codeberg.org`, `gitea.com`, `sr.ht`, `notabug.org`.

## Adding a platform

- [ ] Add to the `RepoProvider` union, `PROVIDER_LABEL`, `PROVIDER_TOKEN_ENV`.
- [ ] Add host detection in `fromHostAndPath` with the correct `confidence`.
- [ ] Implement `resolve()` / `listTree()` / `readFile()`; every path degrades.
- [ ] Wire into `createRepoAdapter`.
- [ ] Add parse cases AND a negative case to `tools/repo-provider-check.ts`.
- [ ] Verify live against a real public repository if one is reachable; say
      explicitly in your report if it was not testable.

## Local and pre-deployment sources

`scanLocalSource(files, label)` applies the **same** catalog and selection rules
to files that were never pushed anywhere, so a pre-deployment codebase is
assessed on identical terms.

```ts
const result = scanLocalSource(
  [{ path: 'src/crypto.ts', content: '…' }, { path: 'go.mod', content: '…' }],
  'uploaded.zip',
)
```

Reports `filesScanned`, `skippedFiles` and a `notice` explaining an empty result
("none of the supplied files were of a type this scanner analyses") rather than
implying a clean bill.

**Status:** engine and tests exist; there is **no upload endpoint or UI yet**.
`pizzip` is already a dependency and is the intended archive reader.

## Budgets

`MAX_FILES_TO_SCAN = 60`, `MAX_FILE_SIZE = 500 KB`, `MAX_MATCHES = 400`,
`MAX_TREE_ENTRIES = 4000`. Excluded directories: `node_modules/`, `vendor/`,
`dist/`, `build/`, `target/`, `__pycache__/`, `.next/`, `coverage/`, `.venv/`.

When the tree is truncated, say so in `notice` — "60 of 825 candidate files were
analysed" is honest; silence implies full coverage.

## Verified live (unauthenticated)

| Repository | Result |
|---|---|
| `gitlab.com/gitlab-org/gitlab-runner` | 60/1412 files → 16 findings |
| `bitbucket.org/atlassian/atlassian-jwt-js` | 11/14 files → 18 findings |
| `codeberg.org/forgejo/forgejo` | 60/825 files → 16 findings |
| `github.com/openssl/openssl` | 58/4000 files → 91 findings (incl. PQC) |

Azure DevOps, GitHub Enterprise and self-managed GitLab adapters are implemented
and unit-tested but were **not verified against a live instance** — no server was
available. Say so rather than implying coverage.
