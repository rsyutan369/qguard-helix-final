/**
 * Render verification for the Intelligence & Operations dashboards
 * (Migration Timeline, PQC Orchestration, Crypto Agility, Runtime Crypto
 * Intelligence, Telemetry Correlation, Drift Detection, Quantum Risk Scoring).
 *
 *   node tools/intel-ops-render/run.mjs            # every case file
 *   node tools/intel-ops-render/run.mjs drift      # cases/drift.tsx only
 *
 * Each `cases/<page>.tsx` builds its payloads with the REAL pure derivation
 * (no hand-written model objects) and calls `renderCases` from harness.tsx.
 * esbuild bundles it with ONLY the edges stubbed — auth, the Supabase client,
 * the subscription hook, and the data hooks (which hand the page the case's
 * payload). Every case is server-rendered; a crash, a console.error, a missing
 * expected label or a forbidden string fails the run.
 *
 * Case files are owned per page so they can be edited independently.
 */
import { build } from 'esbuild'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const root = path.resolve(here, '../..')
const only = process.argv[2]
const casesDir = path.join(here, 'cases')
const files = existsSync(casesDir)
  ? readdirSync(casesDir).filter((f) => /\.tsx?$/.test(f) && (!only || f.replace(/\.tsx?$/, '') === only))
  : []
if (!files.length) {
  console.log(only ? `No case file named ${only}` : 'No case files found in tools/intel-ops-render/cases')
  process.exitCode = 1
} else {
  // Bundles must sit inside the repo so external packages resolve from node_modules.
  const bundleDir = path.join(root, 'node_modules', '.cache', 'intel-ops-render')
  mkdirSync(bundleDir, { recursive: true })

  const STUBS = [
    [/(^|\/)contexts\/auth-context$/, 'stubs/auth-context.tsx'],
    [/(^|\/)lib\/supabase$/, 'stubs/supabase.ts'],
    [/(^|\/)hooks\/use-live-resource$/, 'stubs/use-live-resource.ts'],
    [/(^|\/)hooks\/use-subscription$/, 'stubs/use-subscription.ts'],
    [/(^|\/)hooks\/use-migration-workflow$/, 'stubs/use-migration-workflow.ts'],
    [/(^|\/)lib\/scanner\/use-scanner-intelligence$/, 'stubs/use-scanner-intelligence.ts'],
  ]

  let failed = 0
  for (const file of files) {
    const name = file.replace(/\.tsx?$/, '')
    const outfile = path.join(bundleDir, `${name}.mjs`)
    await build({
      entryPoints: [path.join(casesDir, file)],
      bundle: true,
      platform: 'node',
      format: 'esm',
      outfile,
      jsx: 'automatic',
      tsconfig: path.join(root, 'tsconfig.json'),
      loader: { '.css': 'empty', '.svg': 'dataurl', '.png': 'dataurl' },
      packages: 'external',
      define: { 'import.meta.env.DEV': 'false', 'import.meta.env.PROD': 'true', 'import.meta.env.MODE': '"production"' },
      logLevel: 'warning',
      banner: { js: "import { createRequire as __cr } from 'module'; const require = __cr(import.meta.url);" },
      plugins: [{
        name: 'intel-ops-render-stubs',
        setup(b) {
          b.onResolve({ filter: /auth-context|lib\/supabase|use-live-resource|use-subscription|use-migration-workflow|use-scanner-intelligence/ }, (args) => {
            // A stub may re-export the real module it stands in for.
            if (args.importer && path.resolve(args.importer).startsWith(path.join(here, 'stubs'))) return undefined
            const normalized = args.path.split(path.sep).join('/')
            const hit = STUBS.find(([re]) => re.test(normalized))
            return hit ? { path: path.join(here, hit[1]) } : undefined
          })
        },
      }],
    })
    console.log(`\n=== ${name}`)
    // One process per page: cases set globals, and a crash must not hide the next page.
    const result = spawnSync(process.execPath, [outfile], { cwd: root, stdio: 'inherit' })
    if (result.status !== 0) failed += 1
  }
  console.log(`\n${files.length} page case file(s) — ${failed} failed`)
  process.exitCode = failed ? 1 : 0
}
