import 'dotenv/config'
import express from 'express'
import { existsSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createApiServer } from './index'
import { checkProductionConfig } from './runtime/config'
import { beginDrain, buildInfo } from './runtime/lifecycle'
import { logEvent } from './runtime/observability'
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

function numberFromEnv(name: string, fallback: number): number {
  const value = Number(process.env[name])
  return Number.isFinite(value) && value >= 0 ? value : fallback
}

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

// Final error handler: JSON, no stack traces (Express's default handler prints
// them whenever NODE_ENV is not "production").
app.use((err: unknown, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const status = typeof (err as { status?: unknown })?.status === 'number' ? (err as { status: number }).status : 500
  const safeStatus = status >= 400 && status < 600 ? status : 500
  if (safeStatus >= 500) {
    logEvent('error', 'unhandled_error', {
      requestId: (req as express.Request & { requestId?: string }).requestId,
      message: err instanceof Error ? err.message : String(err),
    })
  }
  if (res.headersSent) return
  res.status(safeStatus).json({
    error: {
      code: safeStatus === 413 ? 'PAYLOAD_TOO_LARGE' : safeStatus === 400 ? 'BAD_REQUEST' : safeStatus >= 500 ? 'INTERNAL_ERROR' : 'REQUEST_ERROR',
      message: safeStatus >= 500 ? 'The request could not be completed.' : 'The request could not be processed.',
    },
  })
})

const server = app.listen(port, '0.0.0.0', () => {
  const info = buildInfo()
  logEvent('info', 'server_listening', { port, serveStatic, ...info })
  // Load admin token revocations before traffic arrives instead of on the
  // first authenticated request.
  void primeTokenRevocations()
})

// ---------------------------------------------------------------------------
// 2. Keep-alive tuning — must exceed the upstream (load balancer) idle timeout
//    or the proxy reuses sockets Node already closed, producing sporadic 502s.
// ---------------------------------------------------------------------------
server.keepAliveTimeout = numberFromEnv('HTTP_KEEP_ALIVE_TIMEOUT_MS', 65_000)
server.headersTimeout = server.keepAliveTimeout + 1_000

// ---------------------------------------------------------------------------
// 3. Graceful drain on SIGTERM/SIGINT (Kubernetes rolling updates, node drains).
//    readyz turns 503 immediately; after SHUTDOWN_DELAY_MS the listener closes;
//    open SSE streams and scans get SHUTDOWN_DRAIN_MS to finish before the
//    remaining sockets are closed. EventSource clients reconnect on their own.
//    terminationGracePeriodSeconds in the pod spec must exceed delay + drain.
// ---------------------------------------------------------------------------
let shuttingDown = false
function shutdown(signal: string) {
  if (shuttingDown) return
  shuttingDown = true
  const delayMs = numberFromEnv('SHUTDOWN_DELAY_MS', 5_000)
  const drainMs = numberFromEnv('SHUTDOWN_DRAIN_MS', 25_000)
  beginDrain()
  logEvent('info', 'shutdown_started', { signal, delayMs, drainMs })

  setTimeout(() => {
    server.close(() => {
      logEvent('info', 'shutdown_complete', { signal })
      process.exit(0)
    })
    server.closeIdleConnections()
    setTimeout(() => {
      logEvent('warn', 'shutdown_forced', { signal, reason: 'drain timeout reached; closing remaining connections' })
      server.closeAllConnections()
      setTimeout(() => process.exit(0), 1_000).unref()
    }, drainMs).unref()
  }, delayMs).unref()
}

process.on('SIGTERM', () => shutdown('SIGTERM'))
process.on('SIGINT', () => shutdown('SIGINT'))
