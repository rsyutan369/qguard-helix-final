/**
 * File Discovery Engine (§8).
 *
 * The first engine in every LOCAL and DEV pipeline. It does not produce
 * findings about cryptography; it produces the CORPUS every other content
 * engine reads, plus the FACETS the Smart Scan Planner uses to decide which
 * engines are even relevant (Spec-2 §32).
 *
 * Classification is by name and shape, never by guesswork: `Dockerfile` is a
 * container file, `k8s/deployment.yaml` is only Kubernetes if its content
 * carries `apiVersion:` + `kind:`, and a `.yaml` that carries neither is just
 * configuration. Getting this wrong is how a Helm values file ends up scored
 * as a Kubernetes workload with no securityContext.
 */

import type { EngineContext, EngineResult, ExposureEngine, FileClassification, TargetFacet, WorkspaceFile } from '../engine-contract';
import { completed } from '../engine-contract';

/* ─────────────────────────────────────────────────────────── classification ── */

const MANIFEST_NAMES = new Set([
  'package.json', 'composer.json', 'pom.xml', 'build.gradle', 'build.gradle.kts', 'settings.gradle',
  'go.mod', 'cargo.toml', 'pyproject.toml', 'setup.py', 'setup.cfg', 'requirements.txt',
  'requirements-dev.txt', 'pipfile', 'gemfile', 'podfile', 'package.swift', 'pubspec.yaml',
  'mix.exs', 'rebar.config', 'project.clj', 'deps.edn', 'paket.dependencies', 'packages.config',
  'directory.packages.props', 'conanfile.txt', 'vcpkg.json', 'bower.json', 'deno.json',
]);

const LOCKFILE_NAMES = new Set([
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'npm-shrinkwrap.json', 'bun.lockb',
  'poetry.lock', 'pipfile.lock', 'cargo.lock', 'go.sum', 'composer.lock', 'gemfile.lock',
  'podfile.lock', 'package-lock.yaml', 'packages.lock.json', 'pubspec.lock', 'mix.lock',
  'gradle.lockfile',
]);

const CONTAINER_NAMES = new Set(['dockerfile', 'containerfile', 'docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml', '.dockerignore']);

const CICD_PATH_MARKERS: Array<{ marker: RegExp; facet: TargetFacet }> = [
  { marker: /^\.github\/workflows\//, facet: 'github-actions' },
  { marker: /(^|\/)\.gitlab-ci\.ya?ml$/, facet: 'gitlab-ci' },
  { marker: /(^|\/)azure-pipelines[^/]*\.ya?ml$/, facet: 'azure-pipelines' },
  { marker: /(^|\/)jenkinsfile$/i, facet: 'jenkins' },
  { marker: /^\.circleci\//, facet: 'circleci' },
  { marker: /^\.buildkite\//, facet: 'github-actions' },
  { marker: /(^|\/)(bitbucket-pipelines)\.ya?ml$/, facet: 'gitlab-ci' },
  { marker: /^\.tekton\//, facet: 'github-actions' },
  { marker: /(^|\/)cloudbuild\.ya?ml$/, facet: 'github-actions' },
];

const IAC_EXTENSIONS = new Set(['.tf', '.tfvars', '.hcl', '.bicep']);

const CERT_EXTENSIONS = new Set(['.pem', '.crt', '.cer', '.der', '.p7b', '.p7c', '.csr']);
const KEY_EXTENSIONS = new Set(['.key', '.p12', '.pfx', '.jks', '.keystore', '.p8', '.pk8', '.asc', '.gpg', '.ppk']);

const CONFIG_EXTENSIONS = new Set([
  '.yaml', '.yml', '.json', '.toml', '.ini', '.cfg', '.conf', '.properties', '.xml', '.env', '.plist',
]);

const SOURCE_EXTENSIONS = new Set([
  '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts',
  '.py', '.pyi', '.rb', '.php', '.go', '.rs', '.java', '.kt', '.kts', '.scala', '.groovy', '.clj',
  '.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hh', '.m', '.mm', '.swift',
  '.cs', '.fs', '.vb', '.sql', '.sh', '.bash', '.zsh', '.ps1', '.psm1', '.bat', '.cmd',
  '.pl', '.pm', '.lua', '.r', '.jl', '.dart', '.ex', '.exs', '.erl', '.hrl', '.nim', '.zig', '.v',
]);

const DOC_EXTENSIONS = new Set(['.md', '.mdx', '.rst', '.txt', '.adoc']);

const ARCHIVE_EXTENSIONS = new Set(['.zip', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.rar', '.jar', '.war', '.ear', '.whl', '.nupkg']);

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.svg', '.bmp', '.tiff',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.mp3', '.mp4', '.mov', '.avi', '.webm', '.wav', '.ogg',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.so', '.dll', '.dylib', '.exe', '.bin', '.o', '.a', '.class', '.pyc', '.wasm', '.node',
]);

/** Languages by extension, for the language breakdown. */
const LANGUAGE_BY_EXT: Record<string, string> = {
  '.js': 'JavaScript', '.jsx': 'JavaScript', '.mjs': 'JavaScript', '.cjs': 'JavaScript',
  '.ts': 'TypeScript', '.tsx': 'TypeScript', '.mts': 'TypeScript', '.cts': 'TypeScript',
  '.py': 'Python', '.pyi': 'Python',
  '.rb': 'Ruby', '.php': 'PHP', '.go': 'Go', '.rs': 'Rust',
  '.java': 'Java', '.kt': 'Kotlin', '.kts': 'Kotlin', '.scala': 'Scala', '.groovy': 'Groovy', '.clj': 'Clojure',
  '.c': 'C', '.h': 'C', '.cc': 'C++', '.cpp': 'C++', '.cxx': 'C++', '.hpp': 'C++', '.hh': 'C++',
  '.m': 'Objective-C', '.mm': 'Objective-C', '.swift': 'Swift',
  '.cs': 'C#', '.fs': 'F#', '.vb': 'Visual Basic',
  '.sh': 'Shell', '.bash': 'Shell', '.zsh': 'Shell', '.ps1': 'PowerShell', '.psm1': 'PowerShell',
  '.sql': 'SQL', '.pl': 'Perl', '.pm': 'Perl', '.lua': 'Lua', '.r': 'R', '.jl': 'Julia',
  '.dart': 'Dart', '.ex': 'Elixir', '.exs': 'Elixir', '.erl': 'Erlang', '.nim': 'Nim', '.zig': 'Zig',
};

const FACET_BY_LANGUAGE: Partial<Record<string, TargetFacet>> = {
  JavaScript: 'node', TypeScript: 'node', Python: 'python', Java: 'java', Kotlin: 'kotlin',
  Go: 'go', Rust: 'rust', Ruby: 'ruby', PHP: 'php', 'C#': 'dotnet', Swift: 'swift',
  'C++': 'cpp', C: 'cpp',
};

export function extensionOf(path: string): string {
  const basename = path.split('/').pop() ?? '';
  const dot = basename.lastIndexOf('.');
  if (dot <= 0) return '';
  return basename.slice(dot).toLowerCase();
}

export function basenameOf(path: string): string {
  return (path.split('/').pop() ?? '').toLowerCase();
}

export function languageOf(path: string): string | null {
  return LANGUAGE_BY_EXT[extensionOf(path)] ?? null;
}

/**
 * Classify one file.
 *
 * `content` is optional so classification also works during a tree listing,
 * before any file has been read — but the Kubernetes / Helm / IaC decisions
 * that genuinely need content are only made when it is present, and default to
 * `config` otherwise. A guess dressed as a classification is worse than the
 * honest fallback.
 */
export function classifyFile(path: string, content: string | null): FileClassification {
  const lower = path.toLowerCase();
  const basename = basenameOf(path);
  const ext = extensionOf(path);

  if (BINARY_EXTENSIONS.has(ext)) return 'binary';
  if (ARCHIVE_EXTENSIONS.has(ext)) return 'archive';
  if (CERT_EXTENSIONS.has(ext)) return 'certificate';
  if (KEY_EXTENSIONS.has(ext)) return 'key-material';
  if (/^id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/.test(basename)) return 'key-material';

  if (LOCKFILE_NAMES.has(basename)) return 'lockfile';
  if (MANIFEST_NAMES.has(basename)) return 'manifest';
  if (basename.endsWith('.csproj') || basename.endsWith('.fsproj') || basename.endsWith('.vbproj')) return 'manifest';
  if (basename.endsWith('.gemspec') || basename.endsWith('.podspec')) return 'manifest';

  if (CONTAINER_NAMES.has(basename) || basename.startsWith('dockerfile.') || ext === '.dockerfile') return 'container';

  for (const marker of CICD_PATH_MARKERS) {
    if (marker.marker.test(lower)) return 'cicd';
  }

  if (IAC_EXTENSIONS.has(ext)) return 'iac';
  if (basename === 'kustomization.yaml' || basename === 'kustomization.yml') return 'kubernetes';
  if (basename === 'chart.yaml' || basename === 'chart.yml') return 'helm';
  if (/(^|\/)templates\/.+\.ya?ml$/.test(lower) && lower.includes('chart')) return 'helm';
  if (basename === 'values.yaml' || basename === 'values.yml') return 'helm';

  if ((ext === '.yaml' || ext === '.yml') && content) {
    if (/^\s*apiVersion\s*:/m.test(content) && /^\s*kind\s*:/m.test(content)) {
      // Helm templates carry Go templating; they are Helm, not rendered K8s.
      return /\{\{[-\s]*[.\w]/.test(content) ? 'helm' : 'kubernetes';
    }
    if (/^\s*(AWSTemplateFormatVersion|Transform)\s*:/m.test(content)) return 'iac';
    if (/^\s*-?\s*hosts\s*:/m.test(content) && /\btasks\s*:/m.test(content)) return 'iac';
  }
  if (ext === '.json' && content && /"AWSTemplateFormatVersion"|"Resources"\s*:\s*\{/.test(content)) return 'iac';

  if (SOURCE_EXTENSIONS.has(ext)) return 'source';
  if (basename === 'makefile' || basename === 'cmakelists.txt' || ext === '.cmake') return 'source';
  if (CONFIG_EXTENSIONS.has(ext) || basename.startsWith('.env')) return 'config';
  if (['nginx.conf', 'httpd.conf', 'openssl.cnf', 'sshd_config', 'ssh_config', 'krb5.conf', 'my.cnf', 'redis.conf', 'postgresql.conf'].includes(basename)) return 'config';
  if (DOC_EXTENSIONS.has(ext)) return 'documentation';

  return 'other';
}

/** Cheap binary sniff for text we already hold. */
export function looksBinary(content: string): boolean {
  if (!content) return false;
  const sample = content.slice(0, 4096);
  let control = 0;
  for (let index = 0; index < sample.length; index += 1) {
    const code = sample.charCodeAt(index);
    if (code === 0) return true;
    if (code < 9 || (code > 13 && code < 32)) control += 1;
  }
  return control / Math.max(1, sample.length) > 0.02;
}

/** Build a WorkspaceFile from a path + optional content. */
export function toWorkspaceFile(path: string, content: string | null, size?: number): WorkspaceFile {
  const normalized = path.replace(/\\/g, '/').replace(/^\.?\//, '');
  const binary = content === null ? BINARY_EXTENSIONS.has(extensionOf(normalized)) : looksBinary(content);
  return {
    path: normalized,
    content: binary ? null : content,
    size: size ?? content?.length ?? 0,
    binary,
    ext: extensionOf(normalized),
    basename: basenameOf(normalized),
    classification: classifyFile(normalized, binary ? null : content),
  };
}

/* ────────────────────────────────────────────────────────────────── facets ── */

/** Derive planner facets from the corpus. Content-aware where it matters. */
export function deriveFacets(files: WorkspaceFile[]): Set<TargetFacet> {
  const facets = new Set<TargetFacet>();

  for (const file of files) {
    const language = LANGUAGE_BY_EXT[file.ext];
    if (language) {
      const facet = FACET_BY_LANGUAGE[language];
      if (facet) facets.add(facet);
    }

    switch (file.classification) {
      case 'container':
        facets.add(file.basename.startsWith('docker-compose') || file.basename.startsWith('compose') ? 'compose' : 'dockerfile');
        break;
      case 'kubernetes':
        facets.add(file.basename.startsWith('kustomization') ? 'kustomize' : 'kubernetes');
        break;
      case 'helm':
        facets.add('helm');
        break;
      case 'certificate':
        facets.add('certificates');
        break;
      case 'key-material':
        facets.add('key-material');
        break;
      case 'iac':
        if (file.ext === '.tf' || file.ext === '.tfvars' || file.ext === '.hcl') facets.add('terraform');
        else if (file.ext === '.bicep') facets.add('bicep');
        else if (file.content && /AWSTemplateFormatVersion|"Resources"/.test(file.content)) facets.add('cloudformation');
        else facets.add('ansible');
        break;
      default:
        break;
    }

    if (file.basename.startsWith('.env')) facets.add('env-files');
    if (file.path.startsWith('.git/')) facets.add('git-repository');

    for (const marker of CICD_PATH_MARKERS) {
      if (marker.marker.test(file.path.toLowerCase())) facets.add(marker.facet);
    }

    if (file.content) {
      if (/pulumi\.(yaml|ts|py|go)/i.test(file.basename)) facets.add('pulumi');
      if (/istio\.io|linkerd\.io|consul\.hashicorp\.com|appmesh/i.test(file.content)) facets.add('service-mesh');
    }
  }

  return facets;
}

/** Language histogram for the intelligence panel. */
export function languageHistogram(files: WorkspaceFile[]): Array<{ language: string; files: number }> {
  const counts = new Map<string, number>();
  for (const file of files) {
    const language = LANGUAGE_BY_EXT[file.ext];
    if (!language) continue;
    counts.set(language, (counts.get(language) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([language, count]) => ({ language, files: count }))
    .sort((a, b) => b.files - a.files);
}

/** Framework detection from manifests. Evidence-based only. */
export function detectFrameworks(files: WorkspaceFile[]): string[] {
  const frameworks = new Set<string>();
  const check = (content: string, table: Record<string, string>) => {
    for (const [needle, label] of Object.entries(table)) {
      if (content.includes(needle)) frameworks.add(label);
    }
  };

  for (const file of files) {
    if (!file.content) continue;
    if (file.basename === 'package.json') {
      check(file.content, {
        '"react"': 'React', '"next"': 'Next.js', '"vue"': 'Vue', '"nuxt"': 'Nuxt',
        '"@angular/core"': 'Angular', '"svelte"': 'Svelte', '"express"': 'Express',
        '"fastify"': 'Fastify', '"@nestjs/core"': 'NestJS', '"koa"': 'Koa', '"hono"': 'Hono',
        '"electron"': 'Electron', '"react-native"': 'React Native', '"vite"': 'Vite',
      });
    }
    if (file.basename === 'requirements.txt' || file.basename === 'pyproject.toml' || file.basename === 'pipfile') {
      check(file.content.toLowerCase(), {
        django: 'Django', flask: 'Flask', fastapi: 'FastAPI', tornado: 'Tornado', pyramid: 'Pyramid',
      });
    }
    if (file.basename === 'pom.xml' || file.basename.startsWith('build.gradle')) {
      check(file.content, {
        'spring-boot': 'Spring Boot', 'org.springframework': 'Spring', quarkus: 'Quarkus',
        'io.micronaut': 'Micronaut', 'jakarta.': 'Jakarta EE',
      });
    }
    if (file.basename === 'go.mod') {
      check(file.content, { 'gin-gonic': 'Gin', 'labstack/echo': 'Echo', 'gofiber': 'Fiber', 'go-chi': 'Chi' });
    }
    if (file.basename === 'cargo.toml') {
      check(file.content, { 'actix-web': 'Actix Web', axum: 'Axum', rocket: 'Rocket', tauri: 'Tauri' });
    }
    if (file.basename === 'gemfile') check(file.content, { rails: 'Ruby on Rails', sinatra: 'Sinatra' });
    if (file.basename === 'composer.json') check(file.content, { 'laravel/': 'Laravel', 'symfony/': 'Symfony' });
  }

  return [...frameworks].sort();
}

/* ─────────────────────────────────────────────────────────────── the engine ── */

export const fileDiscoveryEngine: ExposureEngine = {
  descriptor: {
    id: 'file-discovery',
    label: 'File Discovery',
    description: 'Classifies every file in scope, builds the shared corpus and derives the target facets that decide which engines are relevant.',
    mode: 'local',
    layer: 'source',
    capability: 'discovery',
    weight: 8,
    privacySensitive: true,
  },

  appliesTo(context) {
    return context.workspace.files.length > 0
      ? { applicable: true }
      : { applicable: false, reason: 'No files were supplied for analysis.' };
  },

  async execute(context: EngineContext): Promise<EngineResult> {
    const files = context.workspace.files;
    let analyzed = 0;
    let skipped = 0;
    let unsupported = 0;
    let bytes = 0;

    const byClassification = new Map<FileClassification, number>();

    for (const file of files) {
      if (context.isCancelled()) break;
      if (context.isExcluded(file.path)) {
        skipped += 1;
        continue;
      }
      if (file.binary) {
        unsupported += 1;
        byClassification.set('binary', (byClassification.get('binary') ?? 0) + 1);
        continue;
      }
      analyzed += 1;
      bytes += file.size;
      byClassification.set(file.classification, (byClassification.get(file.classification) ?? 0) + 1);
    }

    // Facets are the planner's input, so they are refreshed here from the
    // definitive corpus rather than trusted from the collector.
    const facets = deriveFacets(files.filter((file) => !context.isExcluded(file.path)));
    for (const facet of facets) context.workspace.facets.add(facet);

    const languages = languageHistogram(files);
    const frameworks = detectFrameworks(files);
    context.workspace.meta.languages = languages;
    context.workspace.meta.frameworks = frameworks;
    context.workspace.meta.fileClassification = Object.fromEntries(byClassification);

    context.report('Corpus classified', { done: files.length, total: files.length, unit: 'files' });

    /* Configuration files, certificates, IaC files and CI/CD workflows are NOT
       published here. Each is owned by the engine that actually reads them
       (configuration-security, certificate-material, iac-security,
       cicd-security), and `mergeCoverage` SUMS numeric fields — so publishing
       them from discovery as well counted every one of them twice: a corpus with
       4 configuration files reported "Config files 8" on the panel and in every
       exported report. The classification histogram is still on
       `workspace.meta.fileClassification` for anything that needs it. */
    return completed(
      [],
      {
        filesDiscovered: files.length,
        filesAnalyzed: analyzed,
        filesSkipped: skipped,
        filesUnsupported: unsupported,
        bytesAnalyzed: bytes,
      },
      { languages, frameworks, facets: [...facets], classification: Object.fromEntries(byClassification) },
    );
  },
};
