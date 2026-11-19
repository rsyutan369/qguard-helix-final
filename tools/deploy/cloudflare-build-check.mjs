import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..')
const temporaryRoot = path.resolve(tmpdir())
const fixture = mkdtempSync(path.join(temporaryRoot, 'qguard-cloudflare-check-'))
// Resolve the dependency from this checkout while running the script against isolated files.
const source = readFileSync(path.join(root, 'tools/deploy/prune-static-output.mjs'), 'utf8')
  .replace("from 'vite'", 'from ' + JSON.stringify(import.meta.resolve('vite')))
const fileOrigin = 'https://api.example.invalid'
const overrideOrigin = 'https://preview-api.example.invalid'

function check(name, { files = {}, origin = fileOrigin, shellOrigin, expectedSuccess = true, extraAsset } = {}) {
  const caseRoot = path.join(fixture, name)
  mkdirSync(path.join(caseRoot, 'tools/deploy'), { recursive: true })
  mkdirSync(path.join(caseRoot, 'dist/downloads'), { recursive: true })
  writeFileSync(path.join(caseRoot, 'tools/deploy/prune-static-output.mjs'), source)
  writeFileSync(path.join(caseRoot, 'dist/index.html'), '<!doctype html><meta content="connect-src ' + origin + '">')
  writeFileSync(path.join(caseRoot, 'dist/_headers'), '/*\n  X-Content-Type-Options: nosniff\n')
  writeFileSync(path.join(caseRoot, 'dist/downloads/QGuard-Messaging-Setup.exe'), 'gated test artifact')
  for (const [name, contents] of Object.entries(files)) {
    writeFileSync(path.join(caseRoot, name), contents)
  }
  if (extraAsset) writeFileSync(path.join(caseRoot, 'dist', extraAsset), 'must not ship')

  const env = { ...process.env }
  delete env.VITE_API_ORIGIN
  if (shellOrigin !== undefined) env.VITE_API_ORIGIN = shellOrigin
  const result = spawnSync(process.execPath, [path.join(caseRoot, 'tools/deploy/prune-static-output.mjs'), '--cloudflare'], {
    cwd: caseRoot,
    env,
    encoding: 'utf8',
    windowsHide: true,
  })
  assert.equal(result.status === 0, expectedSuccess, name + '\n' + result.stdout + result.stderr)
  if (expectedSuccess) {
    // A successful environment check must still run the installer-removal guard.
    assert.equal(existsSync(path.join(caseRoot, 'dist/downloads/QGuard-Messaging-Setup.exe')), false, name + ': gated installer remained')
  }
  console.log('PASS ' + name)
}

try {
  check('production-file', { files: { '.env.production': 'VITE_API_ORIGIN=' + fileOrigin } })
  check('base-file', { files: { '.env': 'VITE_API_ORIGIN=' + fileOrigin } })
  check('production-overrides-base', {
    files: { '.env': 'VITE_API_ORIGIN=' + fileOrigin, '.env.production': 'VITE_API_ORIGIN=' + overrideOrigin },
    origin: overrideOrigin,
  })
  check('production-local-overrides-production', {
    files: { '.env.production': 'VITE_API_ORIGIN=' + fileOrigin, '.env.production.local': 'VITE_API_ORIGIN=' + overrideOrigin },
    origin: overrideOrigin,
  })
  check('shell-overrides-file', {
    files: { '.env.production': 'VITE_API_ORIGIN=' + fileOrigin },
    shellOrigin: overrideOrigin,
    origin: overrideOrigin,
  })
  check('missing-origin-rejected', { expectedSuccess: false })
  check('http-origin-rejected', { shellOrigin: 'http://api.example.invalid', origin: 'http://api.example.invalid', expectedSuccess: false })
  check('stale-html-rejected', { files: { '.env.production': 'VITE_API_ORIGIN=' + fileOrigin }, origin: overrideOrigin, expectedSuccess: false })
  check('private-env-file-rejected', { files: { '.env.production': 'VITE_API_ORIGIN=' + fileOrigin }, extraAsset: '.env', expectedSuccess: false })
} finally {
  // Limit cleanup to the dedicated temporary directory created by this check.
  assert.equal(path.dirname(fixture), temporaryRoot)
  assert.ok(path.basename(fixture).startsWith('qguard-cloudflare-check-'))
  rmSync(fixture, { recursive: true, force: true })
}
