/**
 * Client bundle boundary check.
 *
 * THE DEFECT THIS PREVENTS
 * ------------------------
 * Client modules must be safe to evaluate in the browser, including modules
 * loaded only when their route is opened. A server-only dependency can break
 * the route that imports it, or prevent the app from mounting if the dependency
 * is reached during startup.
 *
 * That is exactly what happened when the scanner dashboard imported a helper
 * from `@/api-server/scanner`. That module opens with `import { Router } from
 * 'express'`. Vite replaces Node built-ins with empty stubs in a browser
 * bundle, so Express's `util.inherits(...)` call resolved to `undefined` and
 * threw. The whole site went black with no error in the page, because nothing
 * had rendered yet to show one.
 *
 * WHAT THIS CHECKS
 * ----------------
 * Walk the module graph the browser actually loads, starting at the real entry
 * (`src/main.tsx`), following first-party imports only, and fail if any module
 * the browser must evaluate imports:
 *
 *   • a Node built-in (`fs`, `path`, `node:net`, …), or
 *   • a server-only package (`express`, …).
 *
 * Type-only imports are ignored: `import type { Request } from 'express'` is
 * erased before the bundler sees it and costs the browser nothing.
 *
 * Each failure is reported with the full import chain from the entry, so the
 * offending edge is obvious rather than something to bisect by hand.
 *
 * Run:  npx tsx tools/client-bundle-boundary-check.ts
 */

import fs from 'node:fs'
import path from 'node:path'
import { builtinModules } from 'node:module'

const ROOT = path.resolve(import.meta.dirname, '..')
const SRC = path.join(ROOT, 'src')
const ENTRY = path.join(SRC, 'main.tsx')

/** Packages that only ever run on the server. Importing one ships Node-only code. */
const SERVER_ONLY_PACKAGES = new Set(['express', 'bullmq', 'ioredis', 'pg', 'nodemailer'])

const NODE_BUILTINS = new Set(builtinModules)

const EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs']

/** Repo-relative POSIX path, so reported chains read the same on every platform. */
const rel = (file: string) => path.relative(ROOT, file).split(path.sep).join('/')

/** Resolve a first-party specifier to a file on disk, or null if it is a package. */
function resolveFirstParty(spec: string, fromFile: string): string | null {
  let base: string
  if (spec.startsWith('@/')) base = path.join(SRC, spec.slice(2))
  else if (spec.startsWith('./') || spec.startsWith('../')) base = path.resolve(path.dirname(fromFile), spec)
  else return null

  for (const ext of ['', ...EXTENSIONS]) {
    const candidate = base + ext
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate
  }
  for (const ext of EXTENSIONS) {
    const candidate = path.join(base, 'index' + ext)
    if (fs.existsSync(candidate)) return candidate
  }
  return null
}

interface Edge {
  spec: string
  typeOnly: boolean
}

/**
 * Extract every import/export specifier from a module, marking the ones that
 * are type-only. Deliberately regex-based rather than a full parse: the check
 * must run with no build step, and over-collecting a specifier is harmless
 * because a first-party path either exists on disk or is skipped.
 */
function readEdges(file: string): Edge[] {
  const source = fs.readFileSync(file, 'utf8')
  const edges: Edge[] = []

  // import ... from 'x'  |  export ... from 'x'  |  import 'x'
  const statement = /(?:^|\n)\s*(import|export)(\s+type)?\b([^;'"]*?)\bfrom\s*['"]([^'"]+)['"]|(?:^|\n)\s*import\s*['"]([^'"]+)['"]/g
  let m: RegExpExecArray | null
  while ((m = statement.exec(source)) !== null) {
    const spec = m[4] ?? m[5]
    if (!spec) continue
    const declaredTypeOnly = Boolean(m[2])
    // `import { type A, type B } from 'x'` — every named binding is a type.
    const clause = m[3] ?? ''
    const named = clause.match(/\{([\s\S]*?)\}/)
    const allNamedAreTypes =
      named !== null &&
      named[1].split(',').filter((s) => s.trim().length > 0).every((s) => /^\s*type\s+/.test(s))
    edges.push({ spec, typeOnly: declaredTypeOnly || allNamedAreTypes })
  }

  // dynamic import('x') — always a value import
  const dynamic = /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g
  while ((m = dynamic.exec(source)) !== null) edges.push({ spec: m[1], typeOnly: false })

  return edges
}

interface Violation {
  chain: string[]
  spec: string
  kind: 'node-builtin' | 'server-package'
}

const violations: Violation[] = []
const visited = new Set<string>()

function walk(file: string, chain: string[]): void {
  if (visited.has(file)) return
  visited.add(file)

  const nextChain = [...chain, rel(file)]

  for (const { spec, typeOnly } of readEdges(file)) {
    if (typeOnly) continue

    const bare = spec.replace(/^node:/, '').split('/')[0]
    if (spec.startsWith('node:') || NODE_BUILTINS.has(bare)) {
      violations.push({ chain: nextChain, spec, kind: 'node-builtin' })
      continue
    }
    if (SERVER_ONLY_PACKAGES.has(bare)) {
      violations.push({ chain: nextChain, spec, kind: 'server-package' })
      continue
    }

    const resolved = resolveFirstParty(spec, file)
    if (resolved) walk(resolved, nextChain)
  }
}

if (!fs.existsSync(ENTRY)) {
  console.error(`FAIL  client entry not found: ${ENTRY}`)
  process.exit(1)
}

walk(ENTRY, [])

console.log(`Client bundle boundary check`)
console.log(`  entry    : ${rel(ENTRY)}`)
console.log(`  modules  : ${visited.size} first-party modules reachable from the browser entry`)
console.log('')

if (violations.length === 0) {
  console.log('PASS  no Node built-in or server-only package is reachable from the client entry.')
  process.exit(0)
}

console.log(`FAIL  ${violations.length} server-only import(s) reachable from the browser entry.`)
console.log('')
console.log('The browser can evaluate these imports during startup or when opening a route.')
console.log('')

for (const v of violations) {
  const label = v.kind === 'node-builtin' ? 'Node built-in' : 'server-only package'
  console.log(`  ${label}: '${v.spec}'`)
  console.log(`  imported by ${v.chain[v.chain.length - 1]}`)
  console.log(`  chain from entry:`)
  for (const [i, step] of v.chain.entries()) console.log(`${'    '}${'  '.repeat(i > 6 ? 6 : i)}${i === 0 ? '' : '-> '}${step}`)
  console.log('')
}

console.log('Fix: move the shared logic into an isomorphic module under src/lib/ and import')
console.log('it from BOTH sides, rather than importing server code into the client.')
process.exit(1)
