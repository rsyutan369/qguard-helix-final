/**
 * Render smoke for the nine Quantum Readiness family pages.
 *
 *   node tools/qr-pages-render/run.mjs [workDir]
 *
 * 1. fixtures.ts builds every page's payload with the REAL server assemblers.
 * 2. esbuild bundles each page with ONLY auth, realtime, subscription and the
 *    live-data hook stubbed (the stub hands the page its fixture payload).
 * 3. Every page is server-rendered populated, empty and loading; a render
 *    crash, a console.error, a missing expected label or a forbidden string
 *    (a removed defect) fails the run.
 */
import { build } from 'esbuild'
import { execFileSync } from 'node:child_process'
import { mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const root = path.resolve(here, '../..')
const work = process.argv[2] || path.join(tmpdir(), 'qr-pages-render')
mkdirSync(work, { recursive: true })
const fixtures = path.join(work, 'fixtures.json')
// The bundle must sit inside the repo so its external packages resolve from
// node_modules; it is written to an ignored, throwaway directory.
const bundleDir = path.join(root, 'node_modules', '.cache', 'qr-pages-render')
mkdirSync(bundleDir, { recursive: true })
const bundle = path.join(bundleDir, 'entry.mjs')

execFileSync(process.execPath, [path.join(root, 'node_modules/tsx/dist/cli.mjs'), path.join(here, 'fixtures.ts'), fixtures], { cwd: root, stdio: 'inherit' })

const STUBS = [
  [/(^|\/)contexts\/auth-context$/, 'stubs/auth-context.tsx'],
  [/(^|\/)lib\/supabase$/, 'stubs/supabase.ts'],
  [/(^|\/)use-live-resource$/, 'stubs/use-live-resource.ts'],
  [/(^|\/)use-subscription$/, 'stubs/use-subscription.ts'],
]
await build({
  entryPoints: [path.join(here, 'entry.tsx')],
  bundle: true,
  platform: 'node',
  format: 'esm',
  outfile: bundle,
  jsx: 'automatic',
  tsconfig: path.join(root, 'tsconfig.json'),
  loader: { '.css': 'empty', '.svg': 'dataurl', '.png': 'dataurl' },
  packages: 'external',
  define: { 'import.meta.env.DEV': 'false', 'import.meta.env.PROD': 'true', 'import.meta.env.MODE': '"production"' },
  logLevel: 'warning',
  banner: { js: "import { createRequire as __cr } from 'module'; const require = __cr(import.meta.url);" },
  plugins: [{
    name: 'render-smoke-stubs',
    setup(b) {
      b.onResolve({ filter: /auth-context|lib\/supabase|use-live-resource|use-subscription/ }, (args) => {
        const normalized = args.path.split(path.sep).join('/')
        const hit = STUBS.find(([re]) => re.test(normalized))
        return hit ? { path: path.join(here, hit[1]) } : undefined
      })
    },
  }],
})
process.chdir(root)
process.argv[2] = fixtures
await import(pathToFileURL(bundle).href)
