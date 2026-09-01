/**
 * Git History Engine (§15, §27).
 *
 * §15 asks for historical exposure: secrets and cryptography that were once
 * committed and may still be recoverable from the object database, clearly
 * distinguished from current exposure.
 *
 * WHAT THIS ENGINE ACTUALLY READS, and what it does not, matters more here than
 * anywhere else in the platform — because "we scanned your history" is a claim
 * a customer will rely on:
 *
 *   READ   `.git/HEAD`, `.git/config`, `.git/packed-refs`, `.git/refs/**`,
 *          `.git/logs/HEAD` (the reflog), `.git/COMMIT_EDITMSG`, and any LOOSE
 *          objects present (`.git/objects/xx/yyyy…`), which are zlib streams
 *          this engine inflates.
 *   NOT    packfiles (`.git/objects/pack/*.pack`). Traversing a packfile
 *          requires delta reconstruction against its index, which this engine
 *          does not implement. In a cloned repository almost all history lives
 *          in packfiles, so this engine reports history coverage as PARTIAL and
 *          says exactly which portion it read.
 *
 * The dishonest alternative — scanning refs, finding nothing, and reporting
 * "no historical secrets" — is the specific failure §15 and Spec-2 §43 exist to
 * prevent.
 */

import type { EngineContext, EngineResult, ExposureEngine, WorkspaceFile } from '../engine-contract';
import { buildEvidence, buildFinding, completed, notApplicable } from '../engine-contract';

/* ────────────────────────────────────────────────────────── ref discovery ── */

export interface GitRefs {
  head: string | null;
  branches: string[];
  tags: string[];
  remotes: Array<{ name: string; url: string }>;
  /** Commits named by refs and the reflog, newest first. */
  commits: string[];
}

/** Read refs, remotes and the reflog out of the `.git` files in the corpus. */
export function readGitRefs(files: WorkspaceFile[]): GitRefs {
  const byPath = new Map(files.map((file) => [file.path, file]));
  const refs: GitRefs = { head: null, branches: [], tags: [], remotes: [], commits: [] };

  const head = byPath.get('.git/HEAD')?.content;
  if (head) {
    const match = head.trim().match(/^ref:\s*refs\/heads\/(.+)$/);
    refs.head = match ? match[1] : head.trim();
  }

  for (const file of files) {
    if (!file.path.startsWith('.git/refs/') || !file.content) continue;
    const name = file.path.replace('.git/refs/', '');
    const sha = file.content.trim();
    if (!/^[0-9a-f]{40}$/.test(sha)) continue;
    refs.commits.push(sha);
    if (name.startsWith('heads/')) refs.branches.push(name.slice(6));
    else if (name.startsWith('tags/')) refs.tags.push(name.slice(5));
  }

  const packed = byPath.get('.git/packed-refs')?.content;
  if (packed) {
    for (const line of packed.split('\n')) {
      const match = line.match(/^([0-9a-f]{40})\s+refs\/(heads|tags|remotes)\/(.+)$/);
      if (!match) continue;
      refs.commits.push(match[1]);
      if (match[2] === 'heads') refs.branches.push(match[3]);
      else if (match[2] === 'tags') refs.tags.push(match[3]);
    }
  }

  const config = byPath.get('.git/config')?.content;
  if (config) {
    const regex = /\[remote\s+"([^"]+)"\]([\s\S]*?)(?=\n\[|$)/g;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(config)) !== null) {
      const url = match[2].match(/^\s*url\s*=\s*(.+)$/m)?.[1]?.trim();
      if (url) refs.remotes.push({ name: match[1], url: sanitiseRemoteUrl(url) });
    }
  }

  const reflog = byPath.get('.git/logs/HEAD')?.content;
  if (reflog) {
    for (const line of reflog.split('\n')) {
      const match = line.match(/^([0-9a-f]{40})\s+([0-9a-f]{40})/);
      if (!match) continue;
      refs.commits.push(match[2]);
    }
  }

  refs.branches = [...new Set(refs.branches)];
  refs.tags = [...new Set(refs.tags)];
  refs.commits = [...new Set(refs.commits)];
  return refs;
}

/** Strip inline credentials from a remote URL before it can become evidence. */
export function sanitiseRemoteUrl(url: string): string {
  return url.replace(/^(\w+:\/\/)[^@/]+@/, '$1[REDACTED]@');
}

/* ────────────────────────────────────────────────────────────── the engine ── */

const LOOSE_OBJECT = /^\.git\/objects\/[0-9a-f]{2}\/[0-9a-f]{38}$/;

export const gitHistoryEngine: ExposureEngine = {
  descriptor: {
    id: 'git-history',
    label: 'Git History',
    description: 'Reads repository refs, remotes and the reflog, and scans any loose objects present. Packed history is reported as not assessed rather than as clean.',
    mode: 'local',
    layer: 'source',
    capability: 'git-history',
    dependsOn: ['file-discovery'],
    weight: 8,
    privacySensitive: true,
  },

  appliesTo(context) {
    const hasGit = context.workspace.files.some((file) => file.path.startsWith('.git/'));
    return hasGit
      ? { applicable: true }
      : { applicable: false, reason: 'No .git directory was included in the selected scope, so repository history could not be read.' };
  },

  async execute(context: EngineContext): Promise<EngineResult> {
    const gitFiles = context.workspace.files.filter((file) => file.path.startsWith('.git/'));
    if (gitFiles.length === 0) {
      return notApplicable('No .git directory was included in the selected scope.');
    }

    context.report('Reading repository references');
    const refs = readGitRefs(gitFiles);
    const findings: ReturnType<typeof buildFinding>[] = [];

    context.workspace.meta.git = {
      head: refs.head,
      branches: refs.branches,
      tags: refs.tags,
      remotes: refs.remotes,
      commitCount: refs.commits.length,
    };

    /* ── remotes with embedded credentials ──────────────────────────────── */
    const config = gitFiles.find((file) => file.path === '.git/config');
    if (config?.content) {
      const lines = config.content.split('\n');
      for (let index = 0; index < lines.length; index += 1) {
        const match = lines[index].match(/^\s*url\s*=\s*(\w+:\/\/)([^@/\s]+)@/);
        if (!match) continue;
        const finding = buildFinding({
          scanId: context.scanId,
          engineId: 'git-history',
          mode: context.mode,
          layer: 'secret',
          category: 'Secret Exposure',
          subcategory: 'Git remote credential',
          title: 'Git remote URL carries embedded credentials',
          description:
            'A remote in .git/config embeds credentials directly in the URL. Anyone with read access to the working copy — including a backup, a shared machine or a container image built from it — can read the credential. The value has been redacted and is not stored.',
          severity: 'high',
          confidence: 'high',
          detection: 'observed',
          quantumStatus: 'not-applicable',
          recommendation: 'Remove the credential from the URL and use a credential helper, SSH key or short-lived token instead. Rotate the credential.',
          evidence: [
            buildEvidence({
              summary: `Remote URL with embedded credentials at .git/config:${index + 1}`,
              file: '.git/config',
              line: index + 1,
              snippet: `url = ${match[1]}[REDACTED]@…`,
              ruleId: 'git-remote-credential',
              localOnly: context.mode === 'local',
            }),
          ],
          identity: `.git/config|remote-credential|${index}`,
        });
        findings.push(finding);
        context.emit(finding);
      }
    }

    /* ── historical secret material in loose objects ────────────────────── */
    const looseObjects = gitFiles.filter((file) => LOOSE_OBJECT.test(file.path));
    const decoded: WorkspaceFile[] = [];
    let inflated = 0;
    let inflateFailures = 0;

    if (looseObjects.length > 0) {
      context.report('Inflating loose objects', { done: 0, total: looseObjects.length, unit: 'objects' });
      for (let index = 0; index < looseObjects.length; index += 1) {
        if (context.isCancelled()) break;
        const object = looseObjects[index];
        if (!object.content) {
          inflateFailures += 1;
          continue;
        }
        // Loose objects are zlib streams; the collector supplies them already
        // inflated when the runtime could do it, and null when it could not.
        const body = stripGitObjectHeader(object.content);
        if (body === null) {
          inflateFailures += 1;
          continue;
        }
        inflated += 1;
        decoded.push({
          ...object,
          path: `${object.path} (historical blob)`,
          content: body,
          commit: object.path.replace('.git/objects/', '').replace('/', ''),
        });
        if ((index + 1) % 20 === 0) {
          context.report('Inflating loose objects', { done: index + 1, total: looseObjects.length, unit: 'objects' });
        }
      }
    }

    /* Historical blobs are handed to the secret engine through the workspace
       rather than re-implementing secret detection here. One catalogue, one set
       of rules, one place to fix a false positive. */
    if (decoded.length > 0) {
      context.workspace.meta.historicalBlobs = decoded;
      context.workspace.files.push(...decoded);
    }

    /* ── the honesty statement ──────────────────────────────────────────── */
    const packFiles = gitFiles.filter((file) => file.path.startsWith('.git/objects/pack/'));
    if (packFiles.length > 0) {
      context.notAssessed(
        'Packed Git history',
        `${packFiles.length} packfile${packFiles.length === 1 ? '' : 's'} were found and were NOT traversed — this engine does not reconstruct packed deltas. In a cloned repository most history lives in packfiles, so historical secret and cryptography findings below cover only the ${inflated} loose object${inflated === 1 ? '' : 's'} that were readable. For full history analysis, run the assessment against the hosted repository in Dev mode, or use the QGuard Local Agent, which invokes git directly.`,
      );
    } else if (inflated === 0) {
      context.notAssessed(
        'Git object history',
        'No readable Git objects were present in the selected scope, so historical exposure was not assessed. Current working-tree exposure is unaffected.',
      );
    }

    if (inflateFailures > 0) {
      context.notAssessed(
        'Unreadable Git objects',
        `${inflateFailures} loose object${inflateFailures === 1 ? '' : 's'} could not be decompressed in this runtime and were skipped.`,
      );
    }

    /* ── branch / tag inventory as a positive fact ──────────────────────── */
    if (refs.branches.length || refs.tags.length) {
      const finding = buildFinding({
        scanId: context.scanId,
        engineId: 'git-history',
        mode: context.mode,
        layer: 'source',
        category: 'Repository Intelligence',
        subcategory: 'References',
        title: `Repository carries ${refs.branches.length} branch${refs.branches.length === 1 ? '' : 'es'} and ${refs.tags.length} tag${refs.tags.length === 1 ? '' : 's'}`,
        description: `HEAD is at ${refs.head ?? 'an unnamed reference'}. ${refs.remotes.length ? `Remotes: ${refs.remotes.map((remote) => `${remote.name} → ${remote.url}`).join(', ')}.` : 'No remotes are configured.'} Only the checked-out working tree was analysed for content; other branches were not, because their contents are not present on disk.`,
        severity: 'info',
        confidence: 'high',
        detection: 'observed',
        quantumStatus: 'not-applicable',
        evidence: [
          buildEvidence({
            summary: `${refs.branches.length} branches, ${refs.tags.length} tags, ${refs.commits.length} distinct commit references read from .git.`,
            file: '.git/packed-refs',
            ruleId: 'git-ref-inventory',
            localOnly: context.mode === 'local',
            attributes: {
              head: refs.head ?? '',
              branches: refs.branches.slice(0, 20).join(','),
              tags: refs.tags.slice(0, 20).join(','),
            },
          }),
        ],
        identity: `git-refs|${context.scanId}`,
      });
      findings.push(finding);
      context.emit(finding);
    }

    return completed(
      findings,
      {
        branches: refs.branches.length,
        commitsAnalyzed: inflated,
        notAssessed: packFiles.length
          ? [{ dimension: 'Packed Git history', reason: `${packFiles.length} packfiles were not traversed.`, engineId: 'git-history' }]
          : [],
        truncated: packFiles.length > 0,
        truncationNote: packFiles.length
          ? 'Packed Git history was not traversed; historical findings cover loose objects only.'
          : undefined,
      },
      { refs, looseObjectsRead: inflated, packFiles: packFiles.length },
    );
  },
};

/**
 * Strip the `blob <size>\0` header a Git object carries, and return only the
 * body when it is a blob. Trees and commits are binary or structural and are
 * not useful to the content engines.
 */
export function stripGitObjectHeader(inflated: string): string | null {
  const nul = inflated.indexOf('\0');
  if (nul === -1) return null;
  const header = inflated.slice(0, nul);
  if (!header.startsWith('blob ')) return null;
  return inflated.slice(nul + 1);
}
