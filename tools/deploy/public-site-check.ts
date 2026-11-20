/**
 * Website edition — publish gate for dist-public/ (`npm run build:public`).
 *
 *   npx tsx tools/deploy/public-site-check.ts
 *
 * The public website is the marketing pages plus the free Web assessment. It
 * must never carry the platform: no dashboard, no Local/Dev exposure engine,
 * no reporting exporters, no server code. This proves it from what the bundler
 * ACTUALLY included (.public-site/modules.json, written by vite.config.ts's
 * websiteEditionPlugin), not from reading imports, and then checks the output
 * folder against Cloudflare Pages' limits and against leaks:
 *
 *   • no platform module in the bundle (and the rule itself is self-tested)
 *   • no internal working files, installers, packages or source maps
 *   • no service-role key in any shipped file
 *   • every file under Cloudflare Pages' 25 MiB limit, fewer than 20,000 files
 *   • the SPA fallback works (no root 404.html) and the CSP is in the page
 *   • the API origin the scanner and demo form need is baked in (warning)
 */

import fs from 'node:fs'
import path from 'node:path'

const ROOT = path.resolve(import.meta.dirname, '..', '..')
const OUT = path.join(ROOT, 'dist-public')
const REPORT = path.join(ROOT, '.public-site', 'modules.json')
const MAX_FILE_BYTES = 25 * 1024 * 1024
const MAX_FILES = 20_000

let failed = 0
let warned = 0
const pass = (message: string) => console.log(`  PASS  ${message}`)
const fail = (message: string) => {
  failed += 1
  console.error(`  FAIL  ${message}`)
}
const warn = (message: string) => {
  warned += 1
  console.warn(`  WARN  ${message}`)
}

/**
 * First-party modules that belong to the platform, not the website. The
 * exceptions are what the Web assessment page renders a report with: its types,
 * the score-to-grade table, and the (unrendered) mode tabs component.
 */
const PLATFORM_MODULE_RULES: RegExp[] = [
  /^src\/App\.tsx$/,
  /^src\/main\.tsx$/,
  /^src\/app\/dashboard\//,
  /^src\/app\/(downloads|vault|api|admin)\//,
  /^src\/app\/authentication\/(?!AuthShell\.tsx$|auth-landing\.css$|(?:login|register|oauth-callback|confirm-email|reset-password)\/page\.tsx$)/,
  /^src\/api-server\//,
  /^src\/services\//,
  /^src\/lib\/scanner\/(?!public-scan\/(types|grading-model)\.ts$)/,
  /^src\/components\/exposure\/(?!ExposureModeTabs\.tsx$)/,
  /^src\/components\/(agent-installer|dashboard)\//,
  /^src\/lib\/(migration|quantum-readiness|exposure|qkms|pqauth|trust|ecosystem|copilot|agent|reporting|sophia|vault|tls-pki|shared-responsibility|admin)/,
]

const isPlatformModule = (file: string) => PLATFORM_MODULE_RULES.some((rule) => rule.test(file))

function walk(dir: string, base = dir): string[] {
  const files: string[] = []
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) files.push(...walk(full, base))
    else files.push(path.relative(base, full).split(path.sep).join('/'))
  }
  return files
}

console.log('\nRule self-test')
{
  const mustFlag = [
    'src/App.tsx',
    'src/app/dashboard/page.tsx',
    'src/app/authentication/device-link/page.tsx',
    'src/api-server/public-scan.ts',
    'src/services/reporting/ReportDocument.ts',
    'src/lib/scanner/exposure/content/secrets.ts',
    'src/lib/scanner/web-scanner/crypto-patterns.ts',
    'src/lib/scanner/public-scan/engines/tls-engine.ts',
    'src/components/exposure/LocalAssessmentPanel.tsx',
    'src/lib/agent-installer/agent-release.ts',
  ]
  const mustAllow = [
    'src/PublicApp.tsx',
    'src/pages/Landing.tsx',
    'src/app/public-scan/page.tsx',
    'src/app/authentication/login/page.tsx',
    'src/lib/scanner/public-scan/grading-model.ts',
    'src/lib/scanner/public-scan/types.ts',
    'src/components/exposure/ExposureModeTabs.tsx',
    'src/lib/demo-request.ts',
  ]
  const missed = mustFlag.filter((file) => !isPlatformModule(file))
  const wrong = mustAllow.filter(isPlatformModule)
  missed.length ? fail(`rules miss platform modules: ${missed.join(', ')}`) : pass(`rules flag all ${mustFlag.length} platform samples`)
  wrong.length ? fail(`rules flag website modules: ${wrong.join(', ')}`) : pass(`rules allow all ${mustAllow.length} website samples`)
}

console.log('\nBundle contents (from the bundler)')
if (!fs.existsSync(REPORT) || !fs.existsSync(path.join(OUT, 'index.html'))) {
  fail('no website build found: run `npm run build:public`')
} else if (fs.statSync(REPORT).mtimeMs + 60_000 < fs.statSync(path.join(OUT, 'index.html')).mtimeMs) {
  fail('.public-site/modules.json is older than dist-public/: rebuild with `npm run build:public`')
} else {
  const modules = JSON.parse(fs.readFileSync(REPORT, 'utf8')) as string[]
  const firstParty = modules.filter((file) => file.startsWith('src/'))
  const leaks = firstParty.filter(isPlatformModule)
  firstParty.includes('src/main-public.tsx')
    ? pass(`built from src/main-public.tsx (${firstParty.length} first-party modules)`)
    : fail('the build did not start at src/main-public.tsx — was it built with --mode public?')
  leaks.length
    ? fail(`${leaks.length} platform module(s) in the website bundle:\n        ${leaks.slice(0, 30).join('\n        ')}`)
    : pass('no platform module, engine, exporter or server file in the bundle')

  /* The prune step keeps public/ files by FILE NAME, which is sound only while
     no page builds a file name from a variable. */
  const builtNames: string[] = []
  for (const file of firstParty.filter((f) => /\.(tsx?|jsx?)$/.test(f))) {
    const text = fs.readFileSync(path.join(ROOT, file), 'utf8')
    for (const match of text.matchAll(/\$\{[^}]+\}\.(png|jpe?g|webp|gif|svg|mp4|webm|pdf)\b/g)) builtNames.push(`${file}: ${match[0]}`)
  }
  builtNames.length
    ? fail(`asset file names built at runtime (the prune step would drop them):\n        ${builtNames.join('\n        ')}`)
    : pass('no asset file name is built at runtime')
}

if (fs.existsSync(path.join(OUT, 'index.html'))) {
  console.log('\nPublished folder (dist-public/)')
  const files = walk(OUT)
  const sizes = files.map((file) => ({ file, bytes: fs.statSync(path.join(OUT, file)).size }))
  const total = sizes.reduce((sum, entry) => sum + entry.bytes, 0)

  files.length < MAX_FILES ? pass(`${files.length} files (${(total / 1048576).toFixed(1)} MiB)`) : fail(`${files.length} files: Cloudflare Pages allows ${MAX_FILES}`)
  const oversized = sizes.filter((entry) => entry.bytes > MAX_FILE_BYTES)
  oversized.length
    ? fail(`over 25 MiB (Cloudflare Pages rejects these): ${oversized.map((e) => `${e.file} ${(e.bytes / 1048576).toFixed(1)} MiB`).join(', ')}`)
    : pass(`largest file ${(Math.max(...sizes.map((e) => e.bytes)) / 1048576).toFixed(1)} MiB, under the 25 MiB limit`)

  const forbidden = files.filter((file) =>
    /^(To_Fix|To_Audit)\//.test(file) || /\.(exe|msi|apk|aab|map)$/i.test(file) || /(^|\/)\.env/.test(file),
  )
  forbidden.length
    ? fail(`internal, gated or source files would be published: ${forbidden.join(', ')}`)
    : pass('no internal screenshots, installers, packages, source maps or env files')

  fs.existsSync(path.join(OUT, '404.html'))
    ? fail('dist-public/404.html exists: Cloudflare Pages would stop serving index.html for app routes')
    : pass('no root 404.html, so Cloudflare Pages serves the app for every route')
  fs.existsSync(path.join(OUT, '_headers')) ? pass('_headers present (HSTS, frame and referrer policy)') : fail('_headers missing')

  const html = fs.readFileSync(path.join(OUT, 'index.html'), 'utf8')
  const csp = html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1] ?? ''
  csp ? pass('Content-Security-Policy meta present') : fail('Content-Security-Policy meta missing from index.html')
  html.includes('/src/main') ? fail('index.html still points at /src/ (an unbuilt entry)') : pass('index.html loads the built bundle')

  /* A JWT whose payload says service_role must never ship. */
  const shipped = files.filter((file) => /\.(js|mjs|css|html|json|txt)$/.test(file))
  const serviceKeys: string[] = []
  for (const file of shipped) {
    const text = fs.readFileSync(path.join(OUT, file), 'utf8')
    for (const token of text.matchAll(/eyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{10,}/g)) {
      try {
        const payload = JSON.parse(Buffer.from(token[1], 'base64url').toString('utf8')) as { role?: string }
        if (payload.role === 'service_role') serviceKeys.push(file)
      } catch {
        /* not a JWT */
      }
    }
  }
  serviceKeys.length ? fail(`service-role key found in: ${serviceKeys.join(', ')}`) : pass('no service-role key in any shipped file')

  const connect = (csp.match(/connect-src ([^;]+)/)?.[1] ?? '').split(/\s+/)
  const apiOrigins = connect.filter((token) => /^https?:\/\//.test(token) && !/supabase\.co$/.test(token))
  if (!apiOrigins.length) {
    warn('VITE_API_ORIGIN was not set at build time: the public scan and Request Demo will report "unavailable" until the public API is hosted and the site is rebuilt with it')
  } else if (apiOrigins.some((origin) => origin.startsWith('http://'))) {
    warn(`API origin is plain http (${apiOrigins.join(', ')}): fine for a local test, but browsers block it from an https site — rebuild with the https API address before publishing`)
  } else {
    pass(`API origin baked in for the scanner and demo form: ${apiOrigins.join(', ')}`)
  }
}

console.log(`\n${failed ? `FAILED — ${failed} problem(s)` : 'PASSED'}${warned ? `, ${warned} warning(s)` : ''}`)
process.exit(failed ? 1 : 0)
