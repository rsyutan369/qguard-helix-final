/**
 * QGuard Web Scanner — GitHub Repository Crypto Scanner (compatibility shim)
 *
 * The implementation now lives in `repo-scanner.ts`, which runs the SAME
 * cryptographic catalogue across GitHub, GitLab, Bitbucket, Azure DevOps and
 * self-hosted Gitea/Forgejo. This module is kept so existing callers and the
 * `github-scanner` module id in the scanner ledger keep working.
 */
import type { GitRepoScanResult } from './types'
import { scanRepository } from './repo-scanner'
import { parseRepoReference } from './repo-providers'

/** Scan a GitHub repository. Delegates to the provider-agnostic scanner. */
export async function scanGitHubRepo(repoUrl: string): Promise<GitRepoScanResult> {
  return scanRepository(repoUrl)
}

/** True when the reference points at github.com or GitHub Enterprise Server. */
export function isGitHubUrl(url: string): boolean {
  return parseRepoReference(url)?.provider === 'github'
}
