#!/usr/bin/env node
/**
 * Remove entitlement-gated artefacts from the static build before it is
 * published to a CDN.
 *
 * Vite copies everything in public/ into dist/. The QGuard Messaging installer
 * lives in public/downloads/ because the API serves it from disk AFTER an
 * entitlement check (src/api-server/downloads.ts). On a static host that check
 * never runs, so the copy in dist/ would be downloadable by anyone. Removing it
 * from the CDN output keeps the paywall server-side. The API image keeps its copy.
 *
 * `npm run build:cloudflare` also checks Pages limits and the API origin.
 */
import { existsSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { loadEnv } from 'vite'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..')
const dist = path.join(root, 'dist')

const GATED = ['downloads/QGuard-Messaging-Setup.exe']
const cloudflare = process.argv.includes('--cloudflare')
const maxAssetBytes = 25 * 1024 * 1024

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

if (cloudflare) {
  // Match the production Vite build, including .env.production and shell overrides.
  const apiOrigin = loadEnv('production', root, 'VITE_API_ORIGIN').VITE_API_ORIGIN?.trim()
  const html = readFileSync(path.join(dist, 'index.html'), 'utf8')
  if (!apiOrigin || !/^https:\/\/[^/]+$/.test(apiOrigin) || !html.includes(apiOrigin)) {
    throw new Error('Set VITE_API_ORIGIN to the public HTTPS Droplet API origin in .env.production or the build environment, then rebuild. The built HTML must include the same origin.')
  }
  if (existsSync(path.join(dist, '404.html')) || !existsSync(path.join(dist, '_headers'))) {
    throw new Error('Cloudflare Pages requires the security headers and SPA fallback for dashboard and checkout routes.')
  }

  // This legacy download has no application references and exceeds the Pages asset limit.
  rmSync(path.join(dist, 'downloads', 'Qguard_Helix_Video.mp4'), { force: true })
  const files = readdirSync(dist, { recursive: true, withFileTypes: true }).filter((entry) => entry.isFile())
  if (files.length > 20_000) throw new Error('Cloudflare Pages Free supports at most 20,000 files.')
  const blocked = files.filter((entry) =>
    /(^\.env(?:\.|$)|\.(?:exe|msi|apk|aab|map)$)/i.test(entry.name) ||
    statSync(path.join(entry.parentPath, entry.name)).size > maxAssetBytes
  )
  if (blocked.length) throw new Error(`Files cannot be published to Cloudflare Pages: ${blocked.map((entry) => entry.name).join(', ')}`)

  for (const entry of files) {
    if (!/\.(?:js|mjs|css|html|json|txt)$/i.test(entry.name)) continue
    const contents = readFileSync(path.join(entry.parentPath, entry.name), 'utf8')
    const serviceRole = [...contents.matchAll(/eyJ[\w-]{10,}\.(eyJ[\w-]{10,})\.[\w-]{10,}/g)]
      .some(([, payload]) => {
        try { return JSON.parse(Buffer.from(payload, 'base64url').toString()).role === 'service_role' }
        catch { return false }
      })
    if (serviceRole || /\bsb_secret_[\w-]{20,}/.test(contents)) {
      throw new Error(`Supabase server key detected in ${entry.name}. Check the public build variables.`)
    }
  }
  console.log(`[cloudflare] Verified ${files.length} platform files in dist/`)
}
