import type { Express, NextFunction, Request, Response } from 'express'
import type { Server } from 'node:http'
import { beginDrain, buildInfo } from './lifecycle'
import { logEvent } from './observability'

/**
 * Process plumbing shared by the deployed API entries — the full platform
 * (src/api-server/standalone.ts) and the public API
 * (src/api-server/public-standalone.ts): the final JSON error handler, socket
 * keep-alive tuning and the graceful drain on SIGTERM/SIGINT.
 */

export function numberFromEnv(name: string, fallback: number): number {
  const value = Number(process.env[name])
  return Number.isFinite(value) && value >= 0 ? value : fallback
}

/**
 * Final error handler: JSON, no stack traces (Express's default handler prints
 * them whenever NODE_ENV is not "production").
 */
export function jsonErrorHandler(err: unknown, req: Request, res: Response, _next: NextFunction): void {
  const status = typeof (err as { status?: unknown })?.status === 'number' ? (err as { status: number }).status : 500
  const safeStatus = status >= 400 && status < 600 ? status : 500
  if (safeStatus >= 500) {
    logEvent('error', 'unhandled_error', {
      requestId: (req as Request & { requestId?: string }).requestId,
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
}

/**
 * Listen, then keep the process well-behaved behind a load balancer:
 *
 * Keep-alive tuning — must exceed the upstream (load balancer) idle timeout or
 * the proxy reuses sockets Node already closed, producing sporadic 502s.
 *
 * Graceful drain on SIGTERM/SIGINT (Kubernetes rolling updates, node drains,
 * a platform redeploy): readyz turns 503 immediately; after SHUTDOWN_DELAY_MS
 * the listener closes; open SSE streams and scans get SHUTDOWN_DRAIN_MS to
 * finish before the remaining sockets are closed. EventSource clients
 * reconnect on their own. A pod's terminationGracePeriodSeconds must exceed
 * delay + drain.
 */
export function listenWithGracefulDrain(
  app: Express,
  options: { port: number; listening?: Record<string, unknown>; onListening?: () => void },
): Server {
  // HOST=127.0.0.1 behind a local tunnel (cloudflared): nothing on the network
  // can reach the process except through the tunnel.
  const host = (process.env.HOST || '').trim() || '0.0.0.0'
  const server = app.listen(options.port, host, () => {
    logEvent('info', 'server_listening', { host, port: options.port, ...options.listening, ...buildInfo() })
    options.onListening?.()
  })

  server.keepAliveTimeout = numberFromEnv('HTTP_KEEP_ALIVE_TIMEOUT_MS', 65_000)
  server.headersTimeout = server.keepAliveTimeout + 1_000

  let shuttingDown = false
  const shutdown = (signal: string) => {
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
  return server
}
