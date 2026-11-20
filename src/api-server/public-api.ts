/**
 * QGuard Helix — Public API (the website's backend).
 *
 * Serves the authenticated Web assessment and Request Demo form.
 * The scanner verifies accounts and stores daily usage in Supabase.
 *
 * It shares the HTTP baseline (HTTPS, security headers, CORS) with the full
 * platform API through runtime/http-baseline.ts. Entry:
 * src/api-server/public-standalone.ts (`npm run start:public-api`).
 *
 * The scanner needs raw TLS and DNS from Node 24 (OpenSSL 3.5 for the hybrid
 * ML-KEM groups), which is why this cannot run on Cloudflare Workers.
 */

import express, { Router } from 'express'
import demoRequestRoutes from './demo-request'
import publicScanRoutes from './public-scan'
import { corsPolicy, enforceHttps, securityHeaders } from './runtime/http-baseline'
import { buildInfo, isDraining, lifecycleSnapshot } from './runtime/lifecycle'
import { requestContext } from './runtime/observability'

/**
 * Probes for the hosting platform. Unlike the platform's readyz there is no
 * database to check: the process is ready unless it is draining.
 */
function publicHealthRoutes(): Router {
  const router = Router()
  router.get('/api/v1/healthz', (_req, res) => {
    res.setHeader('Cache-Control', 'no-store')
    res.json({ status: 'ok', ...lifecycleSnapshot() })
  })
  router.get('/api/v1/readyz', (_req, res) => {
    res.setHeader('Cache-Control', 'no-store')
    const { version, commit, environment } = buildInfo()
    const draining = isDraining()
    res.status(draining ? 503 : 200).json({
      status: draining ? 'draining' : 'ready',
      role: 'public',
      ...lifecycleSnapshot(),
      build: { version, commit, environment },
    })
  })
  return router
}

export function createPublicApiServer(): express.Express {
  const globalScope = globalThis as { __qguardRejectionGuardInstalled?: boolean }
  if (!globalScope.__qguardRejectionGuardInstalled) {
    globalScope.__qguardRejectionGuardInstalled = true
    process.on('unhandledRejection', (reason) => {
      const detail = reason instanceof Error ? (reason.stack || reason.message) : JSON.stringify(reason)
      console.error('[public-api] Unhandled promise rejection (server kept alive):', detail)
    })
  }

  const app = express()
  app.set('trust proxy', true)
  app.disable('x-powered-by')

  app.use(requestContext)
  // Ahead of the HTTPS redirect: platform health checks arrive over plain HTTP.
  app.use(publicHealthRoutes())
  app.use(enforceHttps)
  app.use(securityHeaders)
  app.use(corsPolicy)

  app.use('/api/v1/public-scan', publicScanRoutes)
  app.use(express.json({ limit: process.env.API_PUBLIC_JSON_LIMIT || '256kb' }))
  app.use('/api/v1/demo-request', demoRequestRoutes)

  app.use((_req, res) => {
    res.status(404).json({
      error: {
        code: 'NOT_FOUND',
        message: 'This API serves the public assessment and the demo request form only.',
      },
    })
  })

  return app
}
