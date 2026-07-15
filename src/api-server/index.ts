import express from 'express'
import dashboardRoutes from './dashboard'
import behavioralAnalyticsRoutes from './behavioral-analytics'
import telemetryCorrelationRoutes from './telemetry-correlation'
import quantumRiskScoringRoutes from './quantum-risk-scoring'
import quantumReadinessRoutes from './quantum-readiness'
import reportsRoutes from './reports'
import migrationPlannerRoutes from './migration-planner'
import harvestNowRoutes from './harvest-now'
import tlsTelemetryRoutes from './tls-telemetry'
import pkiVisibilityRoutes from './pki-visibility'
import ecosystemSupplyChainRoutes from './ecosystem-supply-chain'
import trustStateDiscoveryRoutes from './trust-state-discovery'
import { protocolAnalyticsRoutes, encryptionMonitoringRoutes } from './crypto-operations-dashboard'
import { continuousTrustRoutes, identityTrustRoutes, deviceTrustRoutes, trustAnalyticsRoutes, zeroTrustRoutes } from './trust-center-dashboard'
import { quantumGovernanceRoutes, cryptoPoliciesRoutes, auditVaultRoutes, regulatoryMappingRoutes } from './governance-dashboard'
import { runtimeTelemetryRoutes, certificateTelemetryRoutes, keyAnalyticsRoutes, apiEncryptionRoutes, multiCloudTelemetryRoutes } from './observability-dashboard'
import qkmsRoutes from './qkms-dashboard'
import pqauthRoutes from './pqauth-dashboard'
import authRoutes from './auth'
import profileRoutes from './profile'
import billingRoutes from './billing'
import paypalRoutes from './paypal'
import playBillingRoutes from './play-billing'
import adminRoutes from './admin'
import scannerRoutes from './scanner'
import agentScannerRoutes, { startAgentScannerScheduler } from './agent-scanner'
import serviceRecordRoutes from './service-records'
import migrationRoutes from './migration'
import sandboxRoutes, { startSandboxScheduler } from './sandbox'
import { getServerUser, getServiceClient, getToken } from '@/lib/supabase-server'
import { subscriptionGateway } from './subscription-guard'
import { emitShareLinkEvent, subscribeOwnerEvents } from '@/lib/vault/share-events'

const shareIpAttempts = new Map<string, { count: number; windowStart: number }>()
const SHARE_RATE_LIMIT_WINDOW_MS = 60_000
const SHARE_RATE_LIMIT_MAX_REQUESTS = 10
const SHARE_MAX_PASSWORD_ATTEMPTS = 3
const DEFAULT_SHARE_EXPIRY_SECONDS = 15 * 60
const MAX_SHARE_EXPIRY_SECONDS = 7 * 24 * 60 * 60
const MAX_SHARE_DOWNLOADS = 25
const HSTS_HEADER = 'max-age=63072000; includeSubDomains; preload'
const API_CSP = [
  "default-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "object-src 'none'",
].join('; ')
const COOKIE_SAMESITE_VALUES = new Set(['Strict', 'Lax', 'None'])

function isShareIpRateLimited(ip: string): boolean {
  const now = Date.now()
  const entry = shareIpAttempts.get(ip)

  if (!entry || now - entry.windowStart > SHARE_RATE_LIMIT_WINDOW_MS) {
    shareIpAttempts.set(ip, { count: 1, windowStart: now })
    return false
  }

  entry.count += 1
  return entry.count > SHARE_RATE_LIMIT_MAX_REQUESTS
}

function readClientIp(req: express.Request): string {
  const forwarded = req.headers['x-forwarded-for']
  if (typeof forwarded === 'string' && forwarded.trim()) return forwarded.split(',')[0].trim()
  const realIp = req.headers['x-real-ip']
  if (typeof realIp === 'string' && realIp.trim()) return realIp.trim()
  return req.ip || req.socket.remoteAddress || 'unknown'
}

function byteaToText(value: unknown): string {
  if (!value) return ''
  const normalizeBytes = (bytes: Uint8Array | Buffer): string => {
    const buffer = Buffer.from(bytes)
    const text = buffer.toString('utf8').trim()
    return isBase64Payload(text) ? text : buffer.toString('base64')
  }

  if (typeof value === 'string') {
    if (value.startsWith('\\x')) {
      return normalizeBytes(Buffer.from(value.slice(2), 'hex'))
    }
    const trimmed = value.trim()
    if (isBase64Payload(trimmed)) return trimmed
    if (/^[0-9a-f]+$/i.test(trimmed) && trimmed.length % 2 === 0) {
      return Buffer.from(trimmed, 'hex').toString('base64')
    }
    return Buffer.from(trimmed, 'utf8').toString('base64')
  }
  if (value instanceof Uint8Array) {
    return normalizeBytes(value)
  }
  if (Array.isArray(value)) {
    return normalizeBytes(new Uint8Array(value))
  }
  if (typeof value === 'object' && value !== null) {
    const maybeBuffer = value as { type?: unknown; data?: unknown }
    if (maybeBuffer.type === 'Buffer' && Array.isArray(maybeBuffer.data)) {
      return normalizeBytes(new Uint8Array(maybeBuffer.data as number[]))
    }
  }
  return ''
}

function isBase64Payload(value: string): boolean {
  if (!value || value.length % 4 !== 0) return false
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return false
  try {
    Buffer.from(value, 'base64')
    return true
  } catch {
    return false
  }
}

function readShareMetadata(value: unknown): Record<string, unknown> {
  if (!value) return {}
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value)
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
        ? parsed as Record<string, unknown>
        : {}
    } catch {
      return {}
    }
  }
  return typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {}
}

function metadataText(metadata: Record<string, unknown>, key: string): string {
  const value = metadata[key]
  return typeof value === 'string' ? value : ''
}

function metadataObject(metadata: Record<string, unknown>, key: string): Record<string, unknown> | undefined {
  const value = metadata[key]
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined
}

function publicPasswordKdfMetadata(metadata: Record<string, unknown>): Record<string, unknown> | undefined {
  const passwordKdf = metadataObject(metadata, 'passwordKdf')
  if (!passwordKdf) return undefined
  return passwordKdf.algorithm === 'argon2id'
    ? { ...passwordKdf, algorithm: 'hardened-v2' }
    : passwordKdf
}

function isLocalRequest(req: express.Request): boolean {
  const host = (req.headers.host || '').split(':')[0].toLowerCase()
  return host === 'localhost' || host === '127.0.0.1' || host === '::1'
}

function isHttpsRequest(req: express.Request): boolean {
  const forwardedProto = req.headers['x-forwarded-proto']
  const proto = Array.isArray(forwardedProto) ? forwardedProto[0] : forwardedProto
  return req.secure || req.protocol === 'https' || String(proto || '').split(',')[0].trim() === 'https'
}

function shouldEnforceHttps(req: express.Request): boolean {
  const strictMode = process.env.NODE_ENV === 'production' ||
    process.env.FORCE_HTTPS === 'true' ||
    process.env.ENFORCE_HTTPS === 'true'

  return strictMode && !isLocalRequest(req) && !isHttpsRequest(req)
}

function shouldMarkCookieSecure(req: express.Request): boolean {
  return !isLocalRequest(req) && (
    process.env.NODE_ENV === 'production' ||
    process.env.FORCE_SECURE_COOKIES === 'true' ||
    isHttpsRequest(req)
  )
}

function configuredSameSite(): string {
  const rawValue = process.env.AUTH_COOKIE_SAMESITE || process.env.COOKIE_SAMESITE || 'Strict'
  const normalized = rawValue.slice(0, 1).toUpperCase() + rawValue.slice(1).toLowerCase()
  return COOKIE_SAMESITE_VALUES.has(normalized) ? normalized : 'Strict'
}

function hardenCookieHeader(cookie: string, req: express.Request): string {
  const parts = cookie.split(';').map((part) => part.trim()).filter(Boolean)
  if (!parts.length) return cookie

  const attrNames = new Set(
    parts.slice(1).map((part) => part.split('=')[0]?.trim().toLowerCase()).filter(Boolean)
  )
  const secureCookie = shouldMarkCookieSecure(req)
  const requestedSameSite = configuredSameSite()
  const sameSite = requestedSameSite === 'None' && !secureCookie ? 'Lax' : requestedSameSite

  if (!attrNames.has('httponly')) parts.push('HttpOnly')
  if (secureCookie && !attrNames.has('secure')) parts.push('Secure')
  if (!attrNames.has('samesite')) parts.push(`SameSite=${sameSite}`)
  if (!attrNames.has('path')) parts.push('Path=/')

  return parts.join('; ')
}

function hardenSetCookieHeader(
  value: number | string | readonly string[],
  req: express.Request,
): number | string | string[] {
  if (Array.isArray(value)) return value.map((cookie) => hardenCookieHeader(String(cookie), req))
  if (typeof value === 'string') return hardenCookieHeader(value, req)
  // Array.isArray() catches all arrays (incl. readonly) at runtime, so only `number` reaches here.
  return value as number
}

function installCookieHardening(req: express.Request, res: express.Response, next: express.NextFunction) {
  const originalSetHeader = res.setHeader.bind(res)
  res.setHeader = ((name: string, value: number | string | readonly string[]) => {
    if (name.toLowerCase() === 'set-cookie') {
      return originalSetHeader(name, hardenSetCookieHeader(value, req))
    }
    return originalSetHeader(name, value)
  }) as typeof res.setHeader

  next()
}

function normalizeShareExpiry(value: unknown): string {
  const now = Date.now()
  const fallback = new Date(now + DEFAULT_SHARE_EXPIRY_SECONDS * 1000).toISOString()
  if (typeof value !== 'string' || !value) return fallback

  const requested = new Date(value).getTime()
  if (!Number.isFinite(requested) || requested <= now) return fallback

  const maxExpiry = now + MAX_SHARE_EXPIRY_SECONDS * 1000
  return new Date(Math.min(requested, maxExpiry)).toISOString()
}

function normalizeShareDownloads(value: unknown): number {
  const requested = Number(value)
  if (!Number.isFinite(requested) || requested <= 0) return 1
  return Math.max(1, Math.min(MAX_SHARE_DOWNLOADS, Math.floor(requested)))
}

function allowedOrigin(req: express.Request): string | null {
  const origin = req.headers.origin
  if (!origin) return null

  const host = req.headers.host
  try {
    const originUrl = new URL(origin)
    if (host && originUrl.host === host) return origin

    const configured = [
      process.env.APP_ORIGIN,
      process.env.VITE_APP_ORIGIN,
      process.env.PUBLIC_APP_ORIGIN,
      process.env.ALLOWED_ORIGINS,
    ]
      .filter(Boolean)
      .flatMap((value) => String(value).split(','))
      .map((value) => value.trim())
      .filter(Boolean)

    if (configured.includes(origin)) return origin
  } catch {
    return null
  }

  return null
}

function setNoStoreShareHeaders(res: express.Response) {
  res.setHeader('Cache-Control', 'no-store, max-age=0')
  res.setHeader('Pragma', 'no-cache')
  res.setHeader('Expires', '0')
  res.setHeader('Referrer-Policy', 'no-referrer')
  res.setHeader('Content-Security-Policy', API_CSP)
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin')
}

/**
 * QGuard Helix — Express API Server
 * Mounted under /api/v1 in development via Vite configureServer.
 * In production, this can be run as a standalone server or mounted under an API gateway.
 */
export function createApiServer() {
  // Express 4 does not catch rejections from async route handlers; on Node's
  // default --unhandled-rejections=throw, one uncaught handler failure kills
  // the entire server process. Keep the server alive and log loudly instead —
  // individual requests still fail with their own error responses.
  const globalScope = globalThis as { __qguardRejectionGuardInstalled?: boolean }
  if (!globalScope.__qguardRejectionGuardInstalled) {
    globalScope.__qguardRejectionGuardInstalled = true
    process.on('unhandledRejection', (reason) => {
      const detail = reason instanceof Error ? (reason.stack || reason.message) : JSON.stringify(reason)
      console.error('[api] Unhandled promise rejection (server kept alive):', detail)
    })
  }

  const app = express()
  app.set('trust proxy', true)

  app.use(installCookieHardening)

  app.use((req, res, next) => {
    if (!shouldEnforceHttps(req)) {
      next()
      return
    }

    if (req.method === 'GET' || req.method === 'HEAD') {
      res.redirect(308, `https://${req.headers.host}${req.originalUrl}`)
      return
    }

    res.status(426).json({
      error: {
        code: 'HTTPS_REQUIRED',
        message: 'Secure share operations require HTTPS.',
      },
    })
  })

  app.use(express.json({
    limit: '80mb',
    verify: (req: express.Request & { rawBody?: Buffer }, _res, buf) => {
      req.rawBody = Buffer.from(buf)
    },
  }))

  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
    res.setHeader('X-Frame-Options', 'DENY')
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()')
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin')
    res.setHeader('X-DNS-Prefetch-Control', 'off')
    res.setHeader('Content-Security-Policy', API_CSP)
    if (process.env.NODE_ENV === 'production' || isHttpsRequest(req)) {
      res.setHeader('Strict-Transport-Security', HSTS_HEADER)
    }
    next()
  })

  // Same-origin CORS by default. Cross-origin API access can be enabled via
  // APP_ORIGIN / VITE_APP_ORIGIN / PUBLIC_APP_ORIGIN / ALLOWED_ORIGINS.
  app.use((req, res, next) => {
    const origin = req.headers.origin
    const originAllowed = allowedOrigin(req)
    if (originAllowed) {
      res.setHeader('Access-Control-Allow-Origin', originAllowed)
      res.setHeader('Vary', 'Origin')
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-QGuard-Device-Id, X-QGuard-Refresh-Token, X-QGuard-Agent-Id, X-QGuard-Agent-Token')
    if (req.method === 'OPTIONS') {
      if (origin && !originAllowed) {
        res.sendStatus(403)
        return
      }
      res.sendStatus(204)
      return
    }
    next()
  })

  // Health check
  app.get('/api/v1/health', (_req, res) => {
    res.json({
      data: {
        status: 'ok',
        version: '2.0.0',
        timestamp: new Date().toISOString(),
        services: {
          scanner: 'operational',
          pqcEngine: 'operational',
          qrng: 'operational',
          vault: 'operational',
          monitoring: 'operational',
        },
        pqcAlgorithms: ['ML-KEM (Kyber)', 'ML-DSA (Dilithium)', 'SPHINCS+', 'HYBRID'],
      },
    })
  })

  app.post('/api/v1/vault/share', async (req, res) => {
    setNoStoreShareHeaders(res)

    const token = getToken(req)
    const user = token ? await getServerUser(token) : null
    if (!user) {
      res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
      return
    }

    const db = getServiceClient()
    if (!db) {
      res.status(503).json({ error: { code: 'CONFIG_ERROR', message: 'Share service is unavailable' } })
      return
    }

    const body = req.body || {}
    const metadata = readShareMetadata(body.encryptionMetadata)
    const fileId = typeof body.fileId === 'string' ? body.fileId : ''
    const originalFilename = typeof body.originalFilename === 'string' ? body.originalFilename.trim() : ''
    const originalSize = Number(body.originalSize)
    const mimeType = typeof body.mimeType === 'string' && body.mimeType.trim()
      ? body.mimeType.trim()
      : 'application/octet-stream'
    const encryptedPayload = typeof body.encryptedPayload === 'string'
      ? body.encryptedPayload
      : metadataText(metadata, 'encryptedPayload')
    const iv = typeof body.iv === 'string' ? body.iv : metadataText(metadata, 'iv')
    const integrityHash = typeof body.integrityHash === 'string'
      ? body.integrityHash
      : metadataText(metadata, 'integrityHash')

    if (!fileId || !originalFilename || !Number.isFinite(originalSize) || originalSize <= 0 || !encryptedPayload || !iv || !integrityHash) {
      res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'Missing required share-link fields' } })
      return
    }

    if (encryptedPayload.length > 70_000_000) {
      res.status(413).json({ error: { code: 'PAYLOAD_TOO_LARGE', message: 'Encrypted payload exceeds the 50 MB secure-share limit' } })
      return
    }

    if (!isBase64Payload(encryptedPayload)) {
      res.status(400).json({ error: { code: 'INVALID_PAYLOAD', message: 'Encrypted payload must be base64 encoded' } })
      return
    }

    const { data: file, error: fileError } = await db
      .from('vault_files')
      .select('id, user_id')
      .eq('id', fileId)
      .eq('user_id', user.id)
      .maybeSingle()

    if (fileError) {
      console.error('[share/create] File ownership check failed:', fileError)
      res.status(500).json({ error: { code: 'FILE_CHECK_ERROR', message: 'Could not verify file ownership' } })
      return
    }

    if (!file) {
      res.status(404).json({ error: { code: 'FILE_NOT_FOUND', message: 'Vault file not found for this user' } })
      return
    }

    const maxDownloads = normalizeShareDownloads(body.maxDownloads)
    const expiresAt = normalizeShareExpiry(body.expiresAt)
    const isPasswordProtected = Boolean(body.isPasswordProtected)
    const passwordHash = typeof body.passwordHash === 'string' && body.passwordHash ? body.passwordHash : null
    const passwordHint = typeof body.passwordHint === 'string' && body.passwordHint ? body.passwordHint : undefined
    const passwordSalt = metadataText(metadata, 'passwordSalt')
    const permissions = Array.isArray(body.permissions) && body.permissions.length
      ? body.permissions.filter((permission: unknown) => typeof permission === 'string')
      : ['view', 'download']

    if (isPasswordProtected && (!passwordHash || !passwordSalt)) {
      res.status(400).json({ error: { code: 'PASSWORD_METADATA_REQUIRED', message: 'Password-protected shares require a client-side password hash and salt' } })
      return
    }

    const encryptionMetadata: Record<string, unknown> = {
      ...metadata,
      encryptedPayload,
      iv,
      integrityHash,
    }

    const insertPayload: Record<string, unknown> = {
      user_id: user.id,
      file_id: fileId,
      original_filename: originalFilename,
      original_size: originalSize,
      mime_type: mimeType,
      encryption_metadata: encryptionMetadata,
      is_password_protected: isPasswordProtected,
      password_hash: isPasswordProtected ? passwordHash : null,
      max_downloads: maxDownloads,
      expires_at: expiresAt,
      is_one_time: Boolean(body.isOneTime) || maxDownloads === 1,
      permissions,
    }

    if (passwordHint) {
      insertPayload.password_hint = passwordHint
    }

    const { data: link, error: insertError } = await db
      .from('vault_shared_links')
      .insert(insertPayload)
      .select('id, user_id, file_id, token, permissions, is_password_protected, max_downloads, download_count, is_one_time, is_revoked, is_destroyed, original_filename, original_size, mime_type, expires_at, last_accessed_at, created_at')
      .single()

    if (insertError || !link) {
      console.error('[share/create] Insert failed:', insertError)
      res.status(500).json({ error: { code: 'DB_ERROR', message: 'Failed to create shared link' } })
      return
    }

    await db.from('vault_audit_logs').insert({
      user_id: user.id,
      event_type: 'share_created',
      severity: 'info',
      result: 'success',
      resource_type: 'share_link',
      resource_id: link.id,
      description: `Created share link for: ${originalFilename}`,
      metadata: { fileId, originalSize, passwordProtected: isPasswordProtected, maxDownloads, expiresAt },
    })

    res.status(201).json({ data: link })
  })

  app.post('/api/v1/vault/share/public', async (req, res) => {
    setNoStoreShareHeaders(res)

    const { linkId, passwordHash } = req.body || {}

    if (!linkId || typeof linkId !== 'string') {
      res.status(400).json({ error: { code: 'MISSING_ID', message: 'Link ID required' } })
      return
    }

    const db = getServiceClient()
    if (!db) {
      res.status(503).json({ error: { code: 'CONFIG_ERROR', message: 'Share service is unavailable' } })
      return
    }

    const ip = readClientIp(req)
    const userAgent = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : null

    const { data: linkData, error: queryError } = await db
      .from('vault_shared_links')
      .select('id, user_id, encrypted_file_data, encryption_metadata, original_filename, original_size, mime_type, expires_at, max_downloads, download_count, is_revoked, is_password_protected, password_hash, failed_password_attempts, is_destroyed')
      .eq('id', linkId)
      .single()

    if (queryError || !linkData) {
      const detail = queryError ? `${queryError.code}: ${queryError.message}` : 'no row returned'
      console.error('[share/public] Query failed - linkId:', linkId, '| error:', detail)
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Shared link not found or has expired' } })
      return
    }

    const metadata = readShareMetadata(linkData.encryption_metadata)
    const remainingAttempts = Math.max(0, SHARE_MAX_PASSWORD_ATTEMPTS - (linkData.failed_password_attempts || 0))
    const passwordKdf = publicPasswordKdfMetadata(metadata)
    const recipientWrap = metadataObject(metadata, 'recipientWrap')

    if (linkData.is_destroyed) {
      res.status(410).json({
        error: {
          code: 'DESTROYED',
          message: 'This shared link has been permanently destroyed due to too many failed password attempts. The sender must share the file again.',
        },
      })
      return
    }

    if (linkData.is_revoked) {
      res.status(410).json({ error: { code: 'REVOKED', message: 'This shared link has been revoked' } })
      return
    }

    if (linkData.expires_at && new Date(linkData.expires_at) < new Date()) {
      res.status(410).json({ error: { code: 'EXPIRED', message: 'This shared link has expired' } })
      return
    }

    if (linkData.max_downloads !== null && linkData.download_count >= linkData.max_downloads) {
      res.status(410).json({ error: { code: 'LIMIT_REACHED', message: 'Download limit reached for this link' } })
      return
    }

    if (linkData.is_password_protected) {
      const passwordSalt = metadataText(metadata, 'passwordSalt')
      if (!passwordHash) {
        res.json({
          data: {
            requiresPassword: true,
            originalFilename: linkData.original_filename,
            originalSize: Number(linkData.original_size || 0),
            mimeType: linkData.mime_type || 'application/octet-stream',
            passwordSalt,
            passwordKdf,
            recipientWrap,
            remainingAttempts,
          },
        })
        return
      }

      if (isShareIpRateLimited(ip)) {
        res.status(429).json({ error: { code: 'RATE_LIMITED', message: 'Too many attempts. Please wait before trying again.' } })
        return
      }

      if (passwordHash !== linkData.password_hash) {
        const attemptsUsed = (linkData.failed_password_attempts || 0) + 1
        const nextRemaining = Math.max(0, SHARE_MAX_PASSWORD_ATTEMPTS - attemptsUsed)
        const shouldDestroy = attemptsUsed >= SHARE_MAX_PASSWORD_ATTEMPTS

        await db
          .from('vault_shared_links')
          .update({
            failed_password_attempts: attemptsUsed,
            is_destroyed: shouldDestroy,
            encrypted_file_data: shouldDestroy ? null : linkData.encrypted_file_data,
            encryption_metadata: shouldDestroy ? null : linkData.encryption_metadata,
            password_hash: shouldDestroy ? null : linkData.password_hash,
          })
          .eq('id', linkId)

        emitShareLinkEvent({
          type: shouldDestroy ? 'link_destroyed' : 'failed_attempt',
          linkId,
          ownerId: linkData.user_id,
          fileName: linkData.original_filename,
          attemptsUsed,
          remainingAttempts: nextRemaining,
          ip,
          timestamp: new Date().toISOString(),
        })

        if (shouldDestroy) {
          res.status(410).json({
            error: {
              code: 'DESTROYED',
              message: 'This shared link has been permanently destroyed due to too many failed password attempts. All encrypted data has been wiped. The sender must share the file again.',
              attemptsUsed,
              remainingAttempts: 0,
            },
          })
          return
        }

        res.status(403).json({
          error: {
            code: 'WRONG_PASSWORD',
            message: `Incorrect password. ${nextRemaining} attempt${nextRemaining === 1 ? '' : 's'} remaining before this link is permanently destroyed.`,
            attemptsUsed,
            remainingAttempts: nextRemaining,
          },
        })
        return
      }
    }

    const metadataPayload = metadataText(metadata, 'encryptedPayload')
    const encryptedPayload = metadataPayload && isBase64Payload(metadataPayload)
      ? metadataPayload
      : byteaToText(linkData.encrypted_file_data)
    const iv = metadataText(metadata, 'iv')
    const integrityHash = metadataText(metadata, 'integrityHash')

    if (!encryptedPayload || !iv || !integrityHash) {
      res.status(410).json({ error: { code: 'PAYLOAD_MISSING', message: 'Shared file payload is unavailable. The sender must create a new share link.' } })
      return
    }

    await db
      .from('vault_shared_links')
      .update({
        download_count: (linkData.download_count || 0) + 1,
        last_accessed_at: new Date().toISOString(),
      })
      .eq('id', linkId)

    res.json({
      data: {
        encryptedPayload,
        iv,
        integrityHash,
        originalFilename: linkData.original_filename,
        originalSize: Number(linkData.original_size || 0),
        mimeType: linkData.mime_type || 'application/octet-stream',
        isPasswordProtected: !!linkData.is_password_protected,
        passwordSalt: metadataText(metadata, 'passwordSalt'),
        passwordKdf,
        recipientWrap,
      },
    })
  })

  app.get('/api/v1/vault/share/events', async (req, res) => {
    const authHeader = req.headers.authorization
    const headerToken = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null
    const queryToken = typeof req.query.token === 'string' ? req.query.token : null
    const token = headerToken || queryToken
    const user = token ? await getServerUser(token) : null

    if (!user) {
      res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
      return
    }

    res.status(200)
    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache, no-transform')
    res.setHeader('Connection', 'keep-alive')
    res.setHeader('X-Accel-Buffering', 'no')
    res.flushHeaders?.()

    const send = (event: string, data: unknown) => {
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
    }

    send('connected', { userId: user.id, timestamp: new Date().toISOString() })

    const heartbeat = setInterval(() => {
      res.write(': heartbeat\n\n')
    }, 30_000)

    const unsubscribe = subscribeOwnerEvents(user.id, (event) => {
      const eventType = event.type === 'link_destroyed' ? 'link_destroyed' : 'failed_attempt'
      send(eventType, {
        ...event,
        fileName: event.fileName || event.filename || 'Shared file',
        ip: event.ip || event.ipAddress || 'unknown',
        attemptsUsed: event.attemptsUsed || 0,
        remainingAttempts: event.remainingAttempts || 0,
      })
    })

    req.on('close', () => {
      clearInterval(heartbeat)
      unsubscribe()
    })
  })

  // Server-side subscription enforcement — authoritative gate ahead of every
  // module router. Ungated paths (billing, paypal, profile, admin, overview)
  // pass straight through; gated modules require the caller's active plan tier.
  // Public (pre-auth) routes: registration must work without a token and is
  // not tier-gated, so it mounts before the subscription gateway.
  app.use('/api/v1/auth', authRoutes)

  app.use('/api', subscriptionGateway)

  // Dashboard API routes
  app.use('/api/v1/dashboard/behavioral-analytics', behavioralAnalyticsRoutes)
  app.use('/api/v1/dashboard/telemetry-correlation', telemetryCorrelationRoutes)
  app.use('/api/v1/dashboard/quantum-risk-scoring', quantumRiskScoringRoutes)
  app.use('/api/v1/quantum-readiness', quantumReadinessRoutes)
  app.use('/api/v1/reports', reportsRoutes)
  app.use('/api/v1/migration-planner', migrationPlannerRoutes)
  app.use('/api/v1/harvest-now', harvestNowRoutes)
  app.use('/api/v1/dashboard/tls-telemetry', tlsTelemetryRoutes)
  app.use('/api/v1/dashboard/tls-orchestrator', tlsTelemetryRoutes)
  app.use('/api/v1/dashboard/pki-visibility', pkiVisibilityRoutes)
  app.use('/api/v1/dashboard/ecosystem-supply-chain', ecosystemSupplyChainRoutes)
  app.use('/api/v1/dashboard/trust-state-discovery', trustStateDiscoveryRoutes)
  app.use('/api/v1/dashboard/protocol-analytics', protocolAnalyticsRoutes)
  app.use('/api/v1/dashboard/encryption-monitoring', encryptionMonitoringRoutes)
  app.use('/api/v1/dashboard/continuous-trust', continuousTrustRoutes)
  app.use('/api/v1/dashboard/identity-trust', identityTrustRoutes)
  app.use('/api/v1/dashboard/device-trust', deviceTrustRoutes)
  app.use('/api/v1/dashboard/trust-analytics', trustAnalyticsRoutes)
  app.use('/api/v1/dashboard/zero-trust', zeroTrustRoutes)
  app.use('/api/v1/dashboard/quantum-governance', quantumGovernanceRoutes)
  app.use('/api/v1/dashboard/crypto-policies', cryptoPoliciesRoutes)
  app.use('/api/v1/dashboard/audit-vault', auditVaultRoutes)
  app.use('/api/v1/dashboard/regulatory-mapping', regulatoryMappingRoutes)
  app.use('/api/v1/dashboard/runtime-telemetry', runtimeTelemetryRoutes)
  app.use('/api/v1/dashboard/certificate-telemetry', certificateTelemetryRoutes)
  app.use('/api/v1/dashboard/key-analytics', keyAnalyticsRoutes)
  app.use('/api/v1/dashboard/api-encryption', apiEncryptionRoutes)
  app.use('/api/v1/dashboard/multi-cloud-telemetry', multiCloudTelemetryRoutes)
  app.use('/api/v1/dashboard/pqauth', pqauthRoutes)
  app.use('/api/v1/dashboard/qkms', qkmsRoutes)
  app.use('/api/qkms', qkmsRoutes)
  app.use('/api/v1/dashboard', dashboardRoutes)
  app.use('/api/v1/migration', migrationRoutes)
  app.use('/api/v1/sandbox', sandboxRoutes)
  app.use('/api/v1/profile', profileRoutes)
  app.use('/api/v1/billing', billingRoutes)
  app.use('/api/v1/paypal', paypalRoutes)
  app.use('/api/v1/play-billing', playBillingRoutes)
  app.use('/api/v1/admin', adminRoutes)
  app.use('/api/v1/scanner', scannerRoutes)
  app.use('/api/v1/agent-scanner', agentScannerRoutes)
  app.use('/api/v1', serviceRecordRoutes)

  startAgentScannerScheduler()
  startSandboxScheduler()

  // API-only 404 handler. In standalone mode non-API routes fall through to Vite static files.
  app.use((req, res, next) => {
    if (!req.path.startsWith('/api/')) {
      next()
      return
    }
    res.status(404).json({ error: { code: 'NOT_FOUND', message: 'API endpoint not found' } })
  })

  return app
}

export default createApiServer
