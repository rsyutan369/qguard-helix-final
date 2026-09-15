/**
 * Entitlement-gated product downloads — /api/v1/downloads.
 *
 * The QGuard Messaging Windows installer used to sit in `public/downloads/`,
 * which meant the "Download for Windows" button on /qguard-messaging was a
 * PRESENTATION gate only: the button checked the session and the subscription,
 * then pointed an anchor at a static file that anyone could fetch with curl.
 * CLAUDE.md is explicit that the frontend must never own privileged logic and
 * that client-side authorization is never trusted, so the binary now leaves the
 * server through this router and nowhere else.
 *
 * Every request is checked twice, server-side:
 *   1. `getServerUser` verifies the Supabase JWT (local ES256 verification).
 *   2. `resolveEntitlement` reads the caller's own newest billing_subscriptions
 *      row — the SAME function the subscription gateway uses for module access,
 *      so the download gate and the module gate can never disagree.
 *
 * `resolveEntitlement` throws on infrastructure failure rather than returning a
 * negative answer, and this router deliberately does NOT copy the gateway's
 * fail-open behaviour: a database it cannot reach means a subscription it
 * cannot prove, and an unprovable subscription does not get the binary.
 */
import { Router, type NextFunction, type Request, type Response } from 'express'
import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { stat } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { resolveEntitlement, type Entitlement } from './subscription-guard'

const router = Router()

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const projectRoot = path.resolve(__dirname, '../..')

/** Filename the browser saves as, and the name shown on the download page. */
export const MESSAGING_INSTALLER_FILENAME = 'QGuard-Messaging-Setup.exe'

/**
 * Where the built installer can be. `dist/` is the production layout (Vite
 * copies `public/` into it at build time), `public/` is the dev-server layout.
 * Checked in that order so a deployed server never serves a stale working-copy
 * build that happens to be lying around next to it.
 */
const INSTALLER_CANDIDATES = [
  path.join(projectRoot, 'dist', 'downloads', MESSAGING_INSTALLER_FILENAME),
  path.join(projectRoot, 'public', 'downloads', MESSAGING_INSTALLER_FILENAME),
]

type AuthedRequest = Request & { user?: { id: string; email?: string | null }; token?: string; entitlement?: Entitlement }

function jsonError(res: Response, status: number, code: string, message: string, detail?: unknown) {
  return res.status(status).json({ error: { code, message, ...(detail === undefined ? {} : { detail }) } })
}

/* ------------------------------------------------------------------ */
/* Installer resolution + digest cache                                  */
/* ------------------------------------------------------------------ */

type InstallerFile = { file: string; bytes: number; mtimeMs: number }

async function resolveInstaller(): Promise<InstallerFile | null> {
  for (const file of INSTALLER_CANDIDATES) {
    try {
      const info = await stat(file)
      if (info.isFile()) return { file, bytes: info.size, mtimeMs: info.mtimeMs }
    } catch {
      /* Not at this location — try the next candidate. */
    }
  }
  return null
}

/**
 * SHA-256 of the exact bytes being served, published as a response header so a
 * caller can verify the download the same way the website's integrity panel
 * does. Hashing 6 MB on every request would be wasteful, so the digest is
 * cached against (path, size, mtime) — any republish changes the mtime and
 * invalidates it, which is the property that matters: the header can go stale
 * only if the file did not change.
 */
let digestCache: { key: string; sha256: string } | null = null

async function installerDigest(installer: InstallerFile): Promise<string> {
  const key = `${installer.file}:${installer.bytes}:${installer.mtimeMs}`
  if (digestCache && digestCache.key === key) return digestCache.sha256
  const sha256 = await new Promise<string>((resolve, reject) => {
    const hash = createHash('sha256')
    const stream = createReadStream(installer.file)
    stream.on('data', (chunk) => hash.update(chunk))
    stream.on('error', reject)
    stream.on('end', () => resolve(hash.digest('hex').toUpperCase()))
  })
  digestCache = { key, sha256 }
  return sha256
}

/* ------------------------------------------------------------------ */
/* Gate                                                                 */
/* ------------------------------------------------------------------ */

/**
 * Authenticated AND subscribed, proven server-side. Anything short of a
 * verified token plus an access-granting subscription row is refused with a
 * machine-readable code the download button turns into the right next step
 * (sign in, or choose a plan).
 */
async function requireSubscribedUser(req: AuthedRequest, res: Response, next: NextFunction) {
  const token = getToken(req)
  if (!token) {
    return jsonError(res, 401, 'UNAUTHORIZED', 'Sign in to download QGuard Messaging.')
  }

  const user = await getServerUser(token)
  if (!user) {
    return jsonError(res, 401, 'UNAUTHORIZED', 'Your session has expired — sign in again to download.')
  }

  let entitlement: Entitlement
  try {
    entitlement = await resolveEntitlement(user.id, user.email, token)
  } catch (error) {
    /* Fail CLOSED. The subscription gateway fails open so an infrastructure
       blip cannot brick the whole platform, but this route hands out a signed
       binary: an entitlement we could not read is an entitlement we cannot
       vouch for. */
    console.error('[downloads] entitlement lookup failed; refusing download:', error)
    return jsonError(res, 503, 'ENTITLEMENT_UNAVAILABLE', 'We could not confirm your subscription just now. Try again in a moment.')
  }

  if (!entitlement.isActive) {
    return jsonError(res, 403, 'SUBSCRIPTION_REQUIRED', 'An active subscription (Starter or above) is required to download QGuard Messaging.', {
      currentTier: entitlement.tier,
      status: entitlement.status,
      requiredTier: 'Starter',
    })
  }

  req.user = { id: user.id, email: user.email }
  req.token = token
  req.entitlement = entitlement
  return next()
}

/**
 * Best-effort audit trail. A failed log must never fail the download — the user
 * is entitled either way — so this swallows its own errors and never rejects.
 */
async function auditDownload(req: AuthedRequest, detail: Record<string, unknown>) {
  try {
    const client = createAuthClient(req.token || '')
    if (!client || !req.user) return
    await client.from('audit_logs').insert({
      user_id: req.user.id,
      action: 'messaging_installer_downloaded',
      entity_type: 'product_download',
      entity_id: MESSAGING_INSTALLER_FILENAME,
      details: {
        ...detail,
        tier: req.entitlement?.tier ?? null,
        status: req.entitlement?.status ?? null,
        userAgent: String(req.headers['user-agent'] || '').slice(0, 200),
        ip: req.ip || null,
      },
      created_at: new Date().toISOString(),
    })
  } catch {
    /* Audit is observability, not enforcement. */
  }
}

/* ------------------------------------------------------------------ */
/* Routes                                                               */
/* ------------------------------------------------------------------ */

/**
 * What the download page needs to render honestly before the user clicks:
 * whether this caller may download, and the size/digest of the exact file the
 * server would hand over. No binary, so it is cheap to call on page load.
 */
router.get('/messaging/windows/meta', requireSubscribedUser, async (req: AuthedRequest, res) => {
  const installer = await resolveInstaller()
  if (!installer) {
    return jsonError(res, 503, 'INSTALLER_UNAVAILABLE', 'No Windows build is published right now.')
  }
  const sha256 = await installerDigest(installer)
  res.setHeader('Cache-Control', 'no-store')
  return res.json({
    filename: MESSAGING_INSTALLER_FILENAME,
    sizeBytes: installer.bytes,
    sha256,
    entitled: true,
    tier: req.entitlement?.tier ?? null,
  })
})

/** The binary itself. Reached only by a verified, actively subscribed account. */
router.get('/messaging/windows', requireSubscribedUser, async (req: AuthedRequest, res) => {
  const installer = await resolveInstaller()
  if (!installer) {
    return jsonError(res, 503, 'INSTALLER_UNAVAILABLE', 'No Windows build is published right now.')
  }

  const sha256 = await installerDigest(installer)

  res.setHeader('Content-Type', 'application/octet-stream')
  res.setHeader('Content-Disposition', `attachment; filename="${MESSAGING_INSTALLER_FILENAME}"`)
  res.setHeader('Content-Length', String(installer.bytes))
  res.setHeader('X-QGuard-Installer-SHA256', sha256)
  /* Never let a shared cache or proxy hold a copy of an entitlement-gated
     binary where an unentitled request could be served from it. */
  res.setHeader('Cache-Control', 'no-store, private')
  res.setHeader('X-Content-Type-Options', 'nosniff')

  void auditDownload(req, { sizeBytes: installer.bytes, sha256 })

  const stream = createReadStream(installer.file)
  stream.on('error', (error) => {
    console.error('[downloads] installer stream failed:', error)
    if (!res.headersSent) jsonError(res, 500, 'STREAM_FAILED', 'The download could not be started.')
    else res.destroy()
  })
  stream.pipe(res)
})

/**
 * Blocks the legacy public path the installer used to be served from.
 *
 * Mounted at the APP root (not under /api/v1) and ahead of the static file
 * middleware, so `GET /downloads/QGuard-Messaging-Setup.exe` can no longer be
 * satisfied by express.static. Without this the router above is decoration:
 * the binary would still be one anonymous curl away.
 *
 * Scoped to the installer filename only — `public/downloads/` also holds
 * marketing images and `latest.json`, which are meant to stay public.
 */
export function blockPublicInstallerPath(req: Request, res: Response, next: NextFunction) {
  const pathname = (req.originalUrl || req.url || '').split('?')[0]
  if (pathname === `/downloads/${MESSAGING_INSTALLER_FILENAME}`) {
    return jsonError(
      res,
      403,
      'SUBSCRIPTION_REQUIRED',
      'The QGuard Messaging installer is available to signed-in subscribers. Download it from /qguard-messaging.',
      { downloadEndpoint: '/api/v1/downloads/messaging/windows' },
    )
  }
  return next()
}

export default router
