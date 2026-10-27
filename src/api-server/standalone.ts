import 'dotenv/config'
import express from 'express'
import { existsSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createApiServer } from './index'
import { checkProductionConfig } from './runtime/config'
import { logEvent } from './runtime/observability'
import { jsonErrorHandler, listenWithGracefulDrain } from './runtime/serve'
import { primeTokenRevocations } from '@/lib/supabase-server'

/**
 * Standalone production entry (`npm start`, the container image).
 *
 * `npm run dev` never loads this file — the Vite dev server mounts
 * createApiServer() directly — so everything below (config preflight, graceful
 * drain, keep-alive tuning) only affects deployed processes.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const projectRoot = path.resolve(__dirname, '../..')
const distDir = path.join(projectRoot, 'dist')
const port = Number(process.env.PORT || process.env.API_PORT || 3000)
const isProduction = process.env.NODE_ENV === 'production'

// ---------------------------------------------------------------------------
// 1. Configuration preflight — fail safely and clearly, before listening.
// ---------------------------------------------------------------------------
if (isProduction) {
  const { errors, warnings } = checkProductionConfig()
  for (const warning of warnings) logEvent('warn', 'config_warning', { message: warning })
  if (errors.length) {
    for (const error of errors) logEvent('error', 'config_error', { message: error })
    logEvent('error', 'startup_aborted', { reason: 'invalid production configuration', errorCount: errors.length })
    process.exit(78) // EX_CONFIG
  }
}

const app = express()
const api = createApiServer()

app.use(api)

// The SPA is served by Vercel in the split deployment. Serving dist/ from this
// process is kept (default on, current behaviour) for single-host setups and
// can be switched off for API-only containers with SERVE_STATIC=false.
const serveStatic = process.env.SERVE_STATIC !== 'false' && existsSync(path.join(distDir, 'index.html'))
if (serveStatic) {
  app.use(express.static(distDir, { index: false, maxAge: '1h' }))

  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api/')) return next()
    res.sendFile(path.join(distDir, 'index.html'))
  })
}

app.use(jsonErrorHandler)

// ---------------------------------------------------------------------------
// 2. Listen with keep-alive tuning and the graceful drain (runtime/serve.ts).
// ---------------------------------------------------------------------------
listenWithGracefulDrain(app, {
  port,
  listening: { serveStatic },
  // Load admin token revocations before traffic arrives instead of on the
  // first authenticated request.
  onListening: () => void primeTokenRevocations(),
})
