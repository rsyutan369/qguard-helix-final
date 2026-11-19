import express from 'express'
import dashboardRoutes from './dashboard'
import telemetryCorrelationRoutes from './telemetry-correlation'
import quantumRiskScoringRoutes from './quantum-risk-intel'
import quantumReadinessRoutes from './quantum-readiness'
import exposureGraphRoutes from './exposure-graph'
import reportsRoutes from './reports'
import migrationPlannerRoutes from './migration-planner'
import costAssumptionsRoutes from './cost-assumptions'
import harvestNowRoutes from './harvest-now'
import quantumCertificationRoutes, { certificateVerificationRouter } from './quantum-certification'
import quantumRemediationRoutes from './quantum-remediation'
import migrationWorkflowRoutes from './migration-workflow'
import cryptoAgilityRoutes from './crypto-agility'
import runtimeCryptoIntelRoutes from './runtime-crypto-intel'
import driftDetectionRoutes from './drift-detection'
import externalTrustRoutes from './external-trust'
import estateIntelligenceRoutes from './estate-intelligence'
import migrationIntelligenceRoutes from './migration-intelligence'
import {
  tlsTelemetryRoutes,
  pkiVisibilityRoutes,
  protocolAnalyticsRoutes,
  tlsOrchestratorRoutes,
} from './tls-pki'
import ecosystemSupplyChainRoutes from './ecosystem-supply-chain'
import encryptionMonitoringRoutes from './encryption-monitoring'
import { zeroTrustRoutes } from './trust-center-dashboard'
// Enterprise Governance Command Layer — one model, four projections. Replaces
// the old governance-dashboard.ts (which returned the SAME payload for all
// three of its routes) and the compliance builder inside dashboard.ts.
import { complianceRoutes, quantumGovernanceRoutes, auditVaultRoutes, regulatoryMappingRoutes } from './governance'
// The Cryptographic Trust & Telemetry Command Center: four dashboards, one
// per-tenant model, so certificate/asset/cloud counts cannot disagree between
// them or with PKI Visibility, Quantum Readiness and Assets.
import {
  certificateTelemetryRoutes,
  multiCloudTelemetryRoutes,
  trustDashboardRoutes,
  trustStateDiscoveryRoutes,
} from './trust-fabric'
import runtimeTelemetryRoutes from './runtime-telemetry'
import qkmsRoutes from './qkms-dashboard'
import pqauthRoutes from './pqauth-dashboard'
import authRoutes from './auth'
import profileRoutes from './profile'
import billingRoutes from './billing'
import paypalRoutes from './paypal'
import playBillingRoutes from './play-billing'
import { googlePlayWebhookRoutes, subscriptionRoutes } from './subscriptions'
import revenueRoutes from './revenue'
import adminRoutes from './admin'
import streamTicketRoutes from './runtime/stream-tickets'
import scannerRoutes from './scanner'
import liveScanRoutes from './live-scan'
import publicScanRoutes from './public-scan'
import demoRequestRoutes from './demo-request'
import downloadRoutes, { blockPublicInstallerPath } from './downloads'
import exposureRoutes from './exposure'
import agentScannerRoutes, { startAgentScannerScheduler } from './agent-scanner'
import agentInstallerRoutes from './agent-installer'
import serviceRecordRoutes from './service-records'
import migrationRoutes from './migration'
import migrationSnapshotRoutes from './migration-snapshots'
import migrationOrchestratorRoutes from './migration-orchestrator'
import sandboxRoutes, { startSandboxScheduler } from './sandbox'
import copilotRoutes from './copilot'
import { getServerUser, getServiceClient, getToken } from '@/lib/supabase-server'
import { subscriptionGateway } from './subscription-guard'
import { emitShareLinkEvent, subscribeOwnerEvents } from '@/lib/vault/share-events'
import { healthProbeRoutes } from './runtime/health'
import { requestContext } from './runtime/observability'
import { readClientIp } from './runtime/client-ip'
import {
  API_CSP,
  corsPolicy,
  enforceHttps,
  isHttpsRequest,
  isLocalRequest,
  securityHeaders,
} from './runtime/http-baseline'

const shareIpAttempts = new Map<string, { count: number; windowStart: number }>()
const SHARE_RATE_LIMIT_WINDOW_MS = 60_000
const SHARE_RATE_LIMIT_MAX_REQUESTS = 10
const SHARE_MAX_PASSWORD_ATTEMPTS = 3
const SHARE_WRITE_RETRIES = 5
const DEFAULT_SHARE_EXPIRY_SECONDS = 15 * 60
const MAX_SHARE_EXPIRY_SECONDS = 7 * 24 * 60 * 60
const MAX_SHARE_DOWNLOADS = 25
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

  // Correlation id on every response (+ opt-in JSON access log, ACCESS_LOG=true).
  app.use(requestContext)

  /* Ahead of everything: the messaging installer must not be obtainable from
     the static public/downloads path it used to live at. Entitlement is proven
     at /api/v1/downloads/messaging/windows or not at all. */
  app.use(blockPublicInstallerPath)

  // Liveness/readiness probes. MUST stay ahead of the HTTPS enforcement below:
  // kubelet and load-balancer probes arrive over plain HTTP without
  // X-Forwarded-Proto and would otherwise be 308-redirected to https://<podIP>.
  app.use(healthProbeRoutes)

  app.use(installCookieHardening)

  app.use(enforceHttps)

  // The raw body is kept for webhook signature checks (billing.ts Stripe HMAC).
  // body-parser hands `verify` a buffer it never mutates or reuses, so keeping
  // the reference is equivalent to the previous copy at half the peak memory.
  const keepRawBody = (req: express.Request & { rawBody?: Buffer }, _res: unknown, buf: Buffer) => {
    req.rawBody = buf
  }

  // Unauthenticated endpoints only ever receive small JSON documents; parse
  // them with a tight limit so anonymous callers cannot make a pod buffer
  // 80 MB bodies. body-parser skips an already-parsed body, so the general
  // parser below leaves these requests alone.
  app.use(
    ['/api/v1/auth', '/api/v1/public-scan', '/api/v1/demo-request', '/api/v1/paypal/webhook', '/api/v1/play-billing/rtdn', '/api/v1/webhooks/google-play'],
    express.json({ limit: process.env.API_PUBLIC_JSON_LIMIT || '256kb', verify: keepRawBody }),
  )

  app.use(express.json({
    limit: process.env.API_JSON_LIMIT || '80mb',
    verify: keepRawBody,
  }))

  app.use(securityHeaders)

  // Same-origin CORS by default; see runtime/http-baseline.ts for the allow-list.
  app.use(corsPolicy)

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
    const loadShare = () => db
      .from('vault_shared_links')
      .select('id, user_id, encrypted_file_data, encryption_metadata, original_filename, original_size, mime_type, expires_at, max_downloads, download_count, is_revoked, is_password_protected, password_hash, failed_password_attempts, is_destroyed')
      .eq('id', linkId)
      .maybeSingle()

    const respondWithStorageError = () => {
      res.status(503).json({ error: { code: 'SHARE_UNAVAILABLE', message: 'Share service is temporarily unavailable. Please try again.' } })
    }
    let rateLimitChecked = false
    for (let attempt = 0; attempt < SHARE_WRITE_RETRIES; attempt++) {
      const { data: linkData, error: queryError } = await loadShare()
      if (queryError && queryError.code !== '22P02') {
        respondWithStorageError()
        return
      }
      if (!linkData) {
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

        if (!rateLimitChecked && isShareIpRateLimited(ip)) {
          res.status(429).json({ error: { code: 'RATE_LIMITED', message: 'Too many attempts. Please wait before trying again.' } })
          return
        }
        rateLimitChecked = true

        if (passwordHash !== linkData.password_hash) {
          const attemptsUsed = (linkData.failed_password_attempts || 0) + 1
          const nextRemaining = Math.max(0, SHARE_MAX_PASSWORD_ATTEMPTS - attemptsUsed)
          const shouldDestroy = attemptsUsed >= SHARE_MAX_PASSWORD_ATTEMPTS

          const { data: updated, error: updateError } = await db
            .from('vault_shared_links')
            .update({
              failed_password_attempts: attemptsUsed,
              ...(shouldDestroy && {
                is_destroyed: true,
                encrypted_file_data: null,
                encryption_metadata: null,
                password_hash: null,
              }),
            })
            .eq('id', linkId)
            .eq('is_revoked', false)
            .eq('is_destroyed', false)
            .eq('failed_password_attempts', linkData.failed_password_attempts)
            .eq('download_count', linkData.download_count)
            .or(`expires_at.is.null,expires_at.gt.${new Date().toISOString()}`)
            .select('id')
            .maybeSingle()
          if (updateError) {
            respondWithStorageError()
            return
          }
          if (!updated) continue

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

      const { data: updated, error: updateError } = await db
        .from('vault_shared_links')
        .update({
          download_count: (linkData.download_count || 0) + 1,
          last_accessed_at: new Date().toISOString(),
        })
        .eq('id', linkId)
        .eq('is_revoked', false)
        .eq('is_destroyed', false)
        .eq('download_count', linkData.download_count)
        .or(`expires_at.is.null,expires_at.gt.${new Date().toISOString()}`)
        .select('id')
        .maybeSingle()
      if (updateError) {
        respondWithStorageError()
        return
      }
      if (!updated) continue

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
      return
    }
    respondWithStorageError()
  })

  app.get('/api/v1/vault/share/events', async (req, res) => {
    const token = getToken(req)
    const user = token ? await getServerUser(token) : null

    if (!user) {
      res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
      return
    }

    res.status(200)
    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'private, no-store, no-transform')
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

  // Public Quantum Trust Certificate verification portal — no auth, no tier
  // gate (the certificate is meant to be verifiable by anyone). Mounted BEFORE
  // the subscription gateway so unauthenticated visitors can verify a cert.
  app.use('/api/v1/certificate-verification', certificateVerificationRouter)

  // Public Quantum Exposure Assessment™ — anonymous, edge-only scanner behind
  // /public-scan. No auth and no tier gate by design (that is the product), so
  // it mounts BEFORE the subscription gateway. It carries its own rate limiting,
  // concurrency cap, SSRF guard and result cache.
  app.use('/api/v1/public-scan', publicScanRoutes)

  // Entitlement-gated product downloads. Mounted BEFORE the subscription
  // gateway because it enforces a STRICTER rule than the gateway would: the
  // gateway fails open on an entitlement lookup error so a blip cannot brick
  // the platform, while handing out the signed installer must fail closed.
  app.use('/api/v1/downloads', downloadRoutes)

  // Request Demo submissions from the landing page, emailed to the sales inbox.
  // Anonymous by design (visitors have no account), so it mounts before the
  // gateway with its own validation, honeypot and rate limits.
  app.use('/api/v1/demo-request', demoRequestRoutes)

  // Exposure Assessment Engine™ — the Local and Dev counterparts to the public
  // edge scanner. Mounted BEFORE the subscription gateway because capability
  // disclosure, engine health, repository validation and PUBLIC repository
  // assessment are anonymous by design; every endpoint that touches tenant data
  // or a stored credential enforces its own authentication inside the router.
  app.use('/api/v1/exposure', exposureRoutes)

  app.use('/api', subscriptionGateway)

  // Dashboard API routes
  app.use('/api/v1/dashboard/telemetry-correlation', telemetryCorrelationRoutes)
  app.use('/api/v1/dashboard/quantum-risk-scoring', quantumRiskScoringRoutes)
  app.use('/api/v1/quantum-readiness', quantumReadinessRoutes)
  app.use('/api/v1/exposure-graph', exposureGraphRoutes)
  app.use('/api/v1/reports', reportsRoutes)
  app.use('/api/v1/migration-planner', migrationPlannerRoutes)
  app.use('/api/v1/cost-assumptions', costAssumptionsRoutes)
  app.use('/api/v1/harvest-now', harvestNowRoutes)
  app.use('/api/v1/quantum-certification', quantumCertificationRoutes)
  app.use('/api/v1/quantum-remediation', quantumRemediationRoutes)
  app.use('/api/v1/migration-workflow', migrationWorkflowRoutes)
  app.use('/api/v1/crypto-agility', cryptoAgilityRoutes)
  app.use('/api/v1/runtime-crypto-intel', runtimeCryptoIntelRoutes)
  app.use('/api/v1/dashboard/drift', driftDetectionRoutes)
  app.use('/api/v1/external-trust', externalTrustRoutes)
  app.use('/api/v1/estate-intelligence', estateIntelligenceRoutes)
  app.use('/api/v1/migration-intelligence', migrationIntelligenceRoutes)
  // TLS & PKI Intelligence Command Center - four projections of one model.
  app.use('/api/v1/dashboard/tls-telemetry', tlsTelemetryRoutes)
  app.use('/api/v1/dashboard/tls-orchestrator', tlsOrchestratorRoutes)
  app.use('/api/v1/dashboard/pki-visibility', pkiVisibilityRoutes)
  app.use('/api/v1/dashboard/ecosystem-supply-chain', ecosystemSupplyChainRoutes)
  app.use('/api/v1/dashboard/trust-dashboard', trustDashboardRoutes)
  app.use('/api/v1/dashboard/trust-state-discovery', trustStateDiscoveryRoutes)
  app.use('/api/v1/dashboard/protocol-analytics', protocolAnalyticsRoutes)
  app.use('/api/v1/dashboard/encryption-monitoring', encryptionMonitoringRoutes)
  app.use('/api/v1/dashboard/zero-trust', zeroTrustRoutes)
  // Governance layer is mounted BEFORE the generic /api/v1/dashboard router so
  // /dashboard/compliance resolves here rather than to the retired builder.
  app.use('/api/v1/dashboard/compliance', complianceRoutes)
  app.use('/api/v1/dashboard/quantum-governance', quantumGovernanceRoutes)
  app.use('/api/v1/dashboard/audit-vault', auditVaultRoutes)
  app.use('/api/v1/dashboard/regulatory-mapping', regulatoryMappingRoutes)
  app.use('/api/v1/dashboard/runtime-telemetry', runtimeTelemetryRoutes)
  app.use('/api/v1/dashboard/certificate-telemetry', certificateTelemetryRoutes)
  app.use('/api/v1/dashboard/multi-cloud-telemetry', multiCloudTelemetryRoutes)
  app.use('/api/v1/dashboard/pqauth', pqauthRoutes)
  app.use('/api/v1/dashboard/qkms', qkmsRoutes)
  app.use('/api/qkms', qkmsRoutes)
  app.use('/api/v1/dashboard', dashboardRoutes)
  app.use('/api/v1/migration-snapshots', migrationSnapshotRoutes)
  app.use('/api/v1/migration-orchestrator', migrationOrchestratorRoutes)
  app.use('/api/v1/migration', migrationRoutes)
  app.use('/api/v1/sandbox', sandboxRoutes)
  app.use('/api/v1/profile', profileRoutes)
  app.use('/api/v1/billing', billingRoutes)
  app.use('/api/v1/paypal', paypalRoutes)
  app.use('/api/v1/play-billing', playBillingRoutes)
  app.use('/api/v1/subscriptions', subscriptionRoutes)
  app.use('/api/v1/webhooks/google-play', googlePlayWebhookRoutes)
  app.use('/api/v1/revenue', revenueRoutes)
  app.use('/api/v1/admin', adminRoutes)
  app.use('/api/v1/stream-tickets', streamTicketRoutes)
  // Real Time Scanning — mounted before the scanner router so its paths are
  // not shadowed; same `/api/v1/scanner` BASIC gate in subscription-guard.
  app.use('/api/v1/scanner/live', liveScanRoutes)
  app.use('/api/v1/scanner', scannerRoutes)
  app.use('/api/v1/agent-installer', agentInstallerRoutes)
  app.use('/api/v1/agent-scanner', agentScannerRoutes)
  app.use('/api/v1/copilot', copilotRoutes)
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
