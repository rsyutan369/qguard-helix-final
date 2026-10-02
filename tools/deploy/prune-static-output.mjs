#!/usr/bin/env node
/**
 * Remove entitlement-gated artefacts from the static build before it is
 * published to a CDN (Vercel `buildCommand`).
 *
 * Vite copies everything in public/ into dist/. The QGuard Messaging installer
 * lives in public/downloads/ because the API serves it from disk AFTER an
 * entitlement check (src/api-server/downloads.ts). On a static host that check
 * never runs, so the copy in dist/ would be downloadable by anyone. Deleting it
 * from the CDN output (plus the redirect in vercel.json) keeps the paywall
 * server-side only. The API container keeps its own copy.
 *
 * Local `npm run build` / `npm run dev` are unaffected — only the Vercel build
 * command runs this script.
 */
import { existsSync, rmSync, statSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..')
const dist = path.join(root, 'dist')

const GATED = ['downloads/QGuard-Messaging-Setup.exe']

if (!existsSync(path.join(dist, 'index.html'))) {
  console.error('[prune-static-output] dist/index.html not found: run the build first.')
  process.exit(1)
}

for (const relative of GATED) {
  const file = path.join(dist, relative)
  if (existsSync(file)) {
    const bytes = statSync(file).size
    rmSync(file)
    console.log(`[prune-static-output] removed gated artefact dist/${relative} (${bytes} bytes)`)
  } else {
    console.log(`[prune-static-output] dist/${relative} not present (nothing to remove)`)
  }
}
