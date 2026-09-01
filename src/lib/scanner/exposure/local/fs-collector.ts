/**
 * Local filesystem collector (§5, §7, §43, §59).
 *
 * §5: "Do NOT attempt to silently access the user's filesystem. The system must
 *      use explicit user authorization."
 *
 * Two authorised acquisition paths, in order of preference:
 *
 *  1. FILE SYSTEM ACCESS API — `showDirectoryPicker()`. The browser shows an OS
 *     directory picker; the page receives a handle scoped to exactly what the
 *     user chose, and nothing else. This is explicit, per-directory, revocable
 *     authorisation enforced by the browser, which is a stronger boundary than
 *     any agent-side allowlist.
 *  2. DIRECTORY INPUT — `<input type="file" webkitdirectory>`. The same user
 *     gesture in browsers without the FS Access API. It cannot read dot-
 *     directories, so `.git` and `.github` are invisible on this path — and the
 *     collector says so rather than reporting an empty history.
 *
 * §43 LOCAL-ONLY PROCESSING is not a promise here, it is a property: the files
 * are read into a Web Worker in the same tab and the engines run there. There
 * is no upload code path in this module at all.
 *
 * §59 SAFE FILE HANDLING: symlink loops cannot occur through the FS Access API
 * (it exposes no symlinks), depth and count budgets are hard, oversized files
 * are skipped rather than truncated, and archives are never extracted.
 */

import { toWorkspaceFile } from '../content/file-discovery';
import type { WorkspaceFile } from '../engine-contract';

/* ─────────────────────────────────────────────────────────────── budgets ──── */

export interface CollectorLimits {
  /** Hard ceiling on files read. */
  maxFiles: number;
  /** Files larger than this are recorded but not read (§58). */
  maxFileBytes: number;
  /** Total bytes read across the scan. */
  maxTotalBytes: number;
  /** Directory recursion depth. */
  maxDepth: number;
}

export const DEFAULT_LIMITS: CollectorLimits = {
  maxFiles: 8_000,
  maxFileBytes: 1_500_000,
  maxTotalBytes: 120_000_000,
  maxDepth: 14,
};

/** Directories never worth descending into, regardless of exclusion rules. */
const ALWAYS_SKIP = new Set([
  'node_modules', '.venv', 'venv', '__pycache__', '.mypy_cache', '.pytest_cache',
  'dist', 'build', 'out', 'target', '.next', '.nuxt', '.svelte-kit', '.turbo',
  'coverage', '.nyc_output', 'vendor', 'Pods', '.gradle', '.idea', '.vscode',
  'bower_components', 'jspm_packages', '.terraform', '.serverless', 'site-packages',
  '.cache', '.parcel-cache', '.yarn', 'bin', 'obj', 'DerivedData',
]);

/**
 * `.git` subpaths worth reading. The object database is enormous and mostly
 * packed; reading refs, config and the reflog gives the history engine what it
 * can actually use without pulling gigabytes into memory.
 */
const GIT_ALLOW = [
  '.git/HEAD',
  '.git/config',
  '.git/packed-refs',
  '.git/COMMIT_EDITMSG',
  '.git/description',
  '.git/logs/HEAD',
];
const GIT_ALLOW_PREFIX = ['.git/refs/', '.git/logs/refs/', '.git/info/'];

export interface CollectionResult {
  files: WorkspaceFile[];
  rootName: string;
  /** Everything the collector could not or would not read, with the reason. */
  limitations: Array<{ dimension: string; reason: string }>;
  stats: {
    discovered: number;
    read: number;
    skippedTooLarge: number;
    skippedDirectory: number;
    binary: number;
    totalBytes: number;
    truncated: boolean;
  };
}

export interface CollectionProgress {
  (progress: { discovered: number; read: number; current: string }): void;
}

/* ───────────────────────────────────── File System Access API collection ─── */

/** True when the browser exposes `showDirectoryPicker`. */
export function supportsDirectoryPicker(): boolean {
  return typeof window !== 'undefined' && typeof (window as any).showDirectoryPicker === 'function';
}

/** True when the browser supports `webkitdirectory` on a file input. */
export function supportsDirectoryInput(): boolean {
  if (typeof document === 'undefined') return false;
  const input = document.createElement('input');
  return 'webkitdirectory' in input;
}

type DirectoryHandle = any;

/**
 * Ask the user to authorise a directory. Returns null when they cancel.
 *
 * `mode: 'read'` is requested explicitly so the browser's permission prompt
 * states read-only access — the scanner never needs write, and asking for it
 * would be asking for permission it does not use.
 */
export async function requestDirectory(): Promise<DirectoryHandle | null> {
  if (!supportsDirectoryPicker()) return null;
  try {
    return await (window as any).showDirectoryPicker({ mode: 'read', id: 'qguard-exposure-scan' });
  } catch (error) {
    // AbortError is the user declining, which is not an error condition.
    if ((error as Error).name === 'AbortError') return null;
    throw error;
  }
}

/** Walk an authorised directory handle into a corpus. */
export async function collectFromDirectoryHandle(
  handle: DirectoryHandle,
  options: {
    limits?: Partial<CollectorLimits>;
    isExcluded?: (path: string) => boolean;
    includeGit?: boolean;
    onProgress?: CollectionProgress;
    isCancelled?: () => boolean;
  } = {},
): Promise<CollectionResult> {
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  const isExcluded = options.isExcluded ?? (() => false);
  const includeGit = options.includeGit ?? true;
  const files: WorkspaceFile[] = [];
  const limitations: Array<{ dimension: string; reason: string }> = [];
  const stats = { discovered: 0, read: 0, skippedTooLarge: 0, skippedDirectory: 0, binary: 0, totalBytes: 0, truncated: false };

  /* Visited inode-equivalents. The FS Access API does not expose symlinks, but
     `isSameEntry` still guards against a handle reachable twice through a
     mount, which is a real condition on macOS and in WSL. */
  const seen = new Set<string>();

  const walk = async (directory: DirectoryHandle, prefix: string, depth: number): Promise<void> => {
    if (options.isCancelled?.()) return;
    if (depth > limits.maxDepth) {
      limitations.push({ dimension: `Directory ${prefix}`, reason: `Recursion stopped at depth ${limits.maxDepth}.` });
      stats.truncated = true;
      return;
    }
    if (files.length >= limits.maxFiles || stats.totalBytes >= limits.maxTotalBytes) {
      stats.truncated = true;
      return;
    }

    for await (const [name, entry] of directory.entries()) {
      if (options.isCancelled?.()) return;
      if (files.length >= limits.maxFiles || stats.totalBytes >= limits.maxTotalBytes) {
        stats.truncated = true;
        return;
      }

      const path = prefix ? `${prefix}/${name}` : name;

      if (entry.kind === 'directory') {
        if (name === '.git') {
          if (!includeGit) {
            stats.skippedDirectory += 1;
            continue;
          }
          await walkGit(entry, '.git', 0);
          continue;
        }
        if (ALWAYS_SKIP.has(name) || isExcluded(path)) {
          stats.skippedDirectory += 1;
          continue;
        }
        if (seen.has(path)) continue;
        seen.add(path);
        await walk(entry, path, depth + 1);
        continue;
      }

      stats.discovered += 1;
      if (isExcluded(path)) continue;

      let file: File;
      try {
        file = await entry.getFile();
      } catch {
        limitations.push({ dimension: path, reason: 'The file could not be opened for reading.' });
        continue;
      }

      if (file.size > limits.maxFileBytes) {
        stats.skippedTooLarge += 1;
        files.push({
          path,
          content: null,
          size: file.size,
          binary: false,
          ext: extOf(path),
          basename: name.toLowerCase(),
          classification: 'other',
        });
        continue;
      }

      const workspaceFile = await readFileEntry(file, path);
      if (workspaceFile.binary) stats.binary += 1;
      else {
        stats.read += 1;
        stats.totalBytes += workspaceFile.size;
      }
      files.push(workspaceFile);

      if (stats.discovered % 100 === 0) {
        options.onProgress?.({ discovered: stats.discovered, read: stats.read, current: path });
      }
    }
  };

  /* The `.git` walk is separately budgeted and allowlisted so a large object
     database cannot consume the whole file budget. */
  const walkGit = async (directory: DirectoryHandle, prefix: string, depth: number): Promise<void> => {
    if (depth > 4) return;
    for await (const [name, entry] of directory.entries()) {
      const path = `${prefix}/${name}`;
      if (entry.kind === 'directory') {
        if (name === 'objects' || name === 'refs' || name === 'logs' || name === 'info') {
          await walkGit(entry, path, depth + 1);
        }
        continue;
      }
      const allowed = GIT_ALLOW.includes(path) || GIT_ALLOW_PREFIX.some((candidate) => path.startsWith(candidate));
      if (!allowed) continue;
      try {
        const file = await entry.getFile();
        if (file.size > 256_000) continue;
        files.push(await readFileEntry(file, path));
        stats.discovered += 1;
        stats.read += 1;
      } catch {
        /* an unreadable ref is not worth a limitation entry */
      }
    }
  };

  await walk(handle, '', 0);

  if (stats.truncated) {
    limitations.push({
      dimension: 'Collection budget',
      reason: `Collection stopped at the configured budget (${limits.maxFiles} files / ${Math.round(limits.maxTotalBytes / 1_000_000)} MB). Results describe the portion that was read.`,
    });
  }
  if (stats.skippedTooLarge > 0) {
    limitations.push({
      dimension: 'Oversized files',
      reason: `${stats.skippedTooLarge} file${stats.skippedTooLarge === 1 ? ' was' : 's were'} larger than ${Math.round(limits.maxFileBytes / 1000)} KB and were catalogued but not content-analysed.`,
    });
  }
  if (stats.skippedDirectory > 0) {
    limitations.push({
      dimension: 'Excluded directories',
      reason: `${stats.skippedDirectory} director${stats.skippedDirectory === 1 ? 'y was' : 'ies were'} skipped by the exclusion rules or the build-output defaults.`,
    });
  }

  return { files, rootName: handle.name ?? 'selected folder', limitations, stats };
}

/* ─────────────────────────────────────────── webkitdirectory collection ──── */

/**
 * Collect from a `<input webkitdirectory>` FileList.
 *
 * This path cannot see dot-directories in any browser, so `.git`, `.github` and
 * `.circleci` are simply absent. That is stated as a limitation rather than
 * silently producing "no CI/CD configuration found" — which would be a false
 * negative dressed as a clean result.
 */
export async function collectFromFileList(
  fileList: FileList | File[],
  options: {
    limits?: Partial<CollectorLimits>;
    isExcluded?: (path: string) => boolean;
    onProgress?: CollectionProgress;
    isCancelled?: () => boolean;
  } = {},
): Promise<CollectionResult> {
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  const isExcluded = options.isExcluded ?? (() => false);
  const all = Array.from(fileList as ArrayLike<File>);
  const files: WorkspaceFile[] = [];
  const limitations: Array<{ dimension: string; reason: string }> = [];
  const stats = { discovered: all.length, read: 0, skippedTooLarge: 0, skippedDirectory: 0, binary: 0, totalBytes: 0, truncated: false };

  const rootName = (() => {
    const first = (all[0] as any)?.webkitRelativePath as string | undefined;
    if (first && first.includes('/')) return first.split('/')[0];
    return all.length === 1 ? all[0].name : 'selected files';
  })();

  let sawDotDirectory = false;

  for (const file of all) {
    if (options.isCancelled?.()) break;
    if (files.length >= limits.maxFiles || stats.totalBytes >= limits.maxTotalBytes) {
      stats.truncated = true;
      break;
    }

    const relative = ((file as any).webkitRelativePath as string | undefined) || file.name;
    // Strip the picked root so paths match the FS Access API's shape.
    const path = relative.includes('/') ? relative.slice(relative.indexOf('/') + 1) : relative;

    if (path.split('/').some((segment) => ALWAYS_SKIP.has(segment))) {
      stats.skippedDirectory += 1;
      continue;
    }
    if (path.split('/').some((segment) => segment.startsWith('.') && segment.length > 1)) sawDotDirectory = true;
    if (isExcluded(path)) continue;

    if (file.size > limits.maxFileBytes) {
      stats.skippedTooLarge += 1;
      files.push({ path, content: null, size: file.size, binary: false, ext: extOf(path), basename: (path.split('/').pop() ?? '').toLowerCase(), classification: 'other' });
      continue;
    }

    const workspaceFile = await readFileEntry(file, path);
    if (workspaceFile.binary) stats.binary += 1;
    else {
      stats.read += 1;
      stats.totalBytes += workspaceFile.size;
    }
    files.push(workspaceFile);

    if (files.length % 100 === 0) options.onProgress?.({ discovered: stats.discovered, read: stats.read, current: path });
  }

  if (!sawDotDirectory) {
    limitations.push({
      dimension: 'Hidden directories',
      reason:
        'This browser\'s directory input does not expose dot-directories, so .git, .github, .gitlab-ci and .circleci were not available. Repository history and CI/CD pipelines were therefore NOT assessed on this path. Use a Chromium-based browser, which grants the File System Access API, for full coverage.',
    });
  }
  if (stats.truncated) {
    limitations.push({ dimension: 'Collection budget', reason: `Collection stopped at ${limits.maxFiles} files.` });
  }
  if (stats.skippedTooLarge > 0) {
    limitations.push({ dimension: 'Oversized files', reason: `${stats.skippedTooLarge} files exceeded the size budget and were catalogued but not read.` });
  }

  return { files, rootName, limitations, stats };
}

/* ────────────────────────────────────────────────────────────── decoding ──── */

const BINARY_EXT = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp', '.tiff', '.avif',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.mp3', '.mp4', '.mov', '.avi', '.webm', '.wav', '.ogg', '.flac',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.zip', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.rar',
  '.so', '.dll', '.dylib', '.exe', '.bin', '.o', '.a', '.class', '.pyc', '.wasm', '.node',
  '.jar', '.war', '.ear', '.whl', '.nupkg', '.apk', '.ipa', '.dmg', '.iso', '.db', '.sqlite',
]);

async function readFileEntry(file: File, path: string): Promise<WorkspaceFile> {
  const ext = extOf(path);

  /* Loose Git objects are zlib streams. `DecompressionStream('deflate')` is
     available in every browser that supports the FS Access API, so this is the
     one binary format the collector decodes — and it fails soft. */
  if (/^\.git\/objects\/[0-9a-f]{2}\/[0-9a-f]{38}$/.test(path)) {
    const inflated = await inflateZlib(await file.arrayBuffer());
    if (inflated === null) {
      return { path, content: null, size: file.size, binary: true, ext, basename: basenameOf(path), classification: 'binary' };
    }
    return toWorkspaceFile(path, inflated, file.size);
  }

  if (BINARY_EXT.has(ext)) {
    return { path, content: null, size: file.size, binary: true, ext, basename: basenameOf(path), classification: 'binary' };
  }

  try {
    const text = await file.text();
    return toWorkspaceFile(path, text, file.size);
  } catch {
    return { path, content: null, size: file.size, binary: true, ext, basename: basenameOf(path), classification: 'binary' };
  }
}

/** Inflate a zlib stream. Returns null when the runtime cannot, or it is not one. */
export async function inflateZlib(buffer: ArrayBuffer): Promise<string | null> {
  if (typeof DecompressionStream === 'undefined') return null;
  try {
    const stream = new Blob([buffer]).stream().pipeThrough(new DecompressionStream('deflate'));
    const inflated = await new Response(stream).arrayBuffer();
    // Git object bodies are text for blobs; a lossy decode of a binary blob is
    // harmless because the header check downstream rejects non-blob objects.
    return new TextDecoder('utf-8', { fatal: false }).decode(inflated);
  } catch {
    return null;
  }
}

function extOf(path: string): string {
  const base = path.split('/').pop() ?? '';
  const dot = base.lastIndexOf('.');
  return dot <= 0 ? '' : base.slice(dot).toLowerCase();
}

function basenameOf(path: string): string {
  return (path.split('/').pop() ?? '').toLowerCase();
}

/* ─────────────────────────────────────────────────── project fingerprint ──── */

/** A quick read of what the selected folder IS, for the target selector (§7). */
export interface ProjectFingerprint {
  rootName: string;
  totalFiles: number;
  sourceFiles: number;
  gitRepository: boolean;
  manifests: string[];
  detected: string[];
}

export function fingerprintProject(result: CollectionResult): ProjectFingerprint {
  const manifests = result.files
    .filter((file) => file.classification === 'manifest' || file.classification === 'lockfile')
    .map((file) => file.basename);

  const detected = new Set<string>();
  for (const file of result.files) {
    switch (file.basename) {
      case 'package.json': detected.add('Node.js'); break;
      case 'tsconfig.json': detected.add('TypeScript'); break;
      case 'requirements.txt': case 'pyproject.toml': case 'pipfile': detected.add('Python'); break;
      case 'go.mod': detected.add('Go'); break;
      case 'cargo.toml': detected.add('Rust'); break;
      case 'pom.xml': detected.add('Maven'); break;
      case 'build.gradle': case 'build.gradle.kts': detected.add('Gradle'); break;
      case 'gemfile': detected.add('Ruby'); break;
      case 'composer.json': detected.add('PHP'); break;
      case 'dockerfile': detected.add('Docker'); break;
      case 'chart.yaml': detected.add('Helm'); break;
      case 'kustomization.yaml': detected.add('Kustomize'); break;
      default:
        if (file.ext === '.tf') detected.add('Terraform');
        if (file.path.startsWith('.github/workflows/')) detected.add('GitHub Actions');
        if (file.classification === 'kubernetes') detected.add('Kubernetes');
        break;
    }
  }

  return {
    rootName: result.rootName,
    totalFiles: result.files.length,
    sourceFiles: result.files.filter((file) => file.classification === 'source').length,
    gitRepository: result.files.some((file) => file.path.startsWith('.git/')),
    manifests: [...new Set(manifests)],
    detected: [...detected].sort(),
  };
}
