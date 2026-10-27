#!/usr/bin/env node
/**
 * Trim the website edition (dist-public/) to what the public site needs,
 * before it is published to static hosting (`npm run build:public`).
 *
 * Vite copies ALL of public/ into the output. For the website that would
 * publish working files nobody links to — internal screenshots (To_Fix/,
 * To_Audit/), the entitlement-gated messaging installer, and videos larger
 * than Cloudflare Pages accepts (25 MiB per file). So a file copied from
 * public/ is kept only if the built HTML, JS or CSS mentions its FILE NAME;
 * the hashed bundle under assets/ and the host config files are always kept.
 *
 * File names, not full paths: pages build paths from a folder constant
 * (`${MEDIA}/pqauth.webp`), so the full path never appears in the bundle. No
 * page builds a file NAME from a variable (`${x}.webp`) — checked when this was
 * written; tools/deploy/public-site-check.ts re-checks it on every build.
 * NEVER_PUBLISH is removed even when something mentions it.
 */
import { existsSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..')
const out = path.join(root, 'dist-public')
const publicDir = path.join(root, 'public')

/** Host configuration read by Cloudflare Pages, never referenced by the app. */
const ALWAYS_KEEP = new Set(['_headers', '_redirects', 'robots.txt', 'favicon.ico'])

/** Internal working files and gated artefacts: never on the public site. */
const NEVER_PUBLISH =[/^To_Fix\//, /^To_Audit\//, /^downloads\/QGuard-Messaging-Setup\.exe$/, /\.(exe|msi|apk|aab)$/i]

if (!existsSync(path.join(out, 'index.html'))) {
  console.error('[prune-public-site] dist-public/index.html not found: run `vite build --mode public` first.')
  process.exit(1)
}

function walk(dir, base = dir) {
  const files = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) files.push(...walk(full, base))
    else files.push(path.relative(base, full).split(path.sep).join('/'))
  }
  return files
}

/** Every built text file the browser loads: the page, scripts and styles. */
const builtText = walk(out)
  .filter((file) => file === 'index.html' || (file.startsWith('assets/') && /\.(js|mjs|css|html)$/.test(file)))
  .map((file) => readFileSync(path.join(out, file), 'utf8'))
  .join('\n')

const referenced = (relative) => {
  const name = relative.split('/').pop()
  return builtText.includes(name) || builtText.includes(encodeURIComponent(name))
}

let removed = 0
let removedBytes = 0
for (const relative of walk(publicDir)) {
  if (ALWAYS_KEEP.has(relative)) continue
  const target = path.join(out, relative)
  if (!existsSync(target)) continue
  if (!NEVER_PUBLISH.some((pattern) => pattern.test(relative)) && referenced(relative)) continue
  removedBytes += statSync(target).size
  rmSync(target)
  removed += 1
}

/* Folders left empty by the removals. */
function dropEmptyDirs(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue
    const full = path.join(dir, entry.name)
    dropEmptyDirs(full)
    if (readdirSync(full).length === 0) rmSync(full, { recursive: true })
  }
}
dropEmptyDirs(out)

const kept = walk(out)
const keptBytes = kept.reduce((sum, file) => sum + statSync(path.join(out, file)).size, 0)
console.log(
  `[prune-public-site] removed ${removed} unreferenced file(s) from public/ (${(removedBytes / 1048576).toFixed(1)} MiB); ` +
    `dist-public now holds ${kept.length} files (${(keptBytes / 1048576).toFixed(1)} MiB)`,
)
