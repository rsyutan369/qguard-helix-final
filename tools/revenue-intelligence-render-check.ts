/**
 * Static render check for the six Revenue Intelligence pages.
 *
 *   npx tsx tools/revenue-intelligence-render-check.ts
 *
 * The cases live in revenue-intelligence-render-cases.tsx. They import the real
 * page components, which (through the shared dashboard primitives) import the
 * browser Supabase client — and that reads `import.meta.env`, which only Vite
 * defines. So the cases are loaded through Vite's SSR module loader: exactly
 * the transform the dev server applies, with .env loaded the same way.
 */
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { createServer } from 'vite'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

const server = await createServer({
  root,
  configFile: false,
  logLevel: 'error',
  appType: 'custom',
  server: { middlewareMode: true, hmr: false, watch: null },
  resolve: { alias: { '@': path.join(root, 'src') } },
  esbuild: { jsx: 'automatic' },
  optimizeDeps: { noDiscovery: true, include: [] },
})

let exitCode = 1
try {
  const cases = await server.ssrLoadModule('/tools/revenue-intelligence-render-cases.tsx')
  exitCode = await cases.run()
} catch (error) {
  console.error(error)
} finally {
  await server.close()
}
process.exit(exitCode)
