/**
 * Qguard Helix — Agent Installer & Deployment control plane.
 *
 * Mounted at /api/v1/agent-installer. Owns everything between "the tenant wants
 * an agent" and "the agent is streaming verified evidence":
 *
 *   releases        — what is published, its digest, which platforms it supports
 *   package         — generate a real, tenant-bound installer artifact
 *   runtime         — serve the signed single-file agent bundle to an enrolled agent
 *   installation    — per-phase installation state and history
 *   jobs/commands   — queue scan / upgrade / enable / disable work for an agent
 *   health          — heartbeat-derived health, telemetry and activity timeline
 *   findings/scans  — the evidence this agent actually produced
 *   events/stream   — `agent.*` SSE with Last-Event-ID recovery
 *
 * Reuse discipline (spec §37): agent identity, policy, enrollment, tokens,
 * heartbeats, evidence ingestion and remediation all remain owned by
 * agent-scanner.ts. Nothing here duplicates them — this router composes them.
 */

import { Router, type NextFunction, type Request, type Response } from 'express'
import { createHash, timingSafeEqual } from 'node:crypto'
import { readFile, stat } from 'node:fs/promises'
import path from 'node:path'
import type { SupabaseClient } from '@supabase/supabase-js'
import { createAuthClient, getServerUser, getServiceClient, getToken } from '@/lib/supabase-server'
import {
  AGENT_PLATFORMS,
  AGENT_ROLES,
  AGENT_RUNTIME_FILENAME,
  AGENT_VERSION,
  HEARTBEAT_GRACE_WINDOW_MS,
  HEARTBEAT_ONLINE_WINDOW_MS,
  INSTALL_PHASES,
  RELEASE_CHANNEL,
  agentPlatform,
  agentRole,
  type AgentCommandType,
  type AgentEventName,
  type AgentPlatform,
  type AgentRole,
  type ConnectionState,
} from '@/lib/agent-installer/agent-release'
import { commandHistory, commandQueue, enqueueAgentCommand } from './agent-command-queue'
import { trackRequestedScan } from '@/lib/agent-installer/scan-tracking'
import { generateInstaller, installQuickCommand } from '@/lib/agent-installer/installer-templates'
import { clampAgentScanTypes, resolveWriteAuthority } from '@/lib/agent-installer/agent-scope'
import {
  describeControlPlaneFailure,
  readAgentEnvironment,
  validateControlPlane,
} from '@/lib/agent-installer/agent-environment'
import { eventsSince, publishAgentEvent, subscribe } from './agent-event-bus'
import {
  decideAgentRole,
  decideScanTypes,
  entitlementFor,
  type AgentEntitlementRequest,
} from './agent-entitlement'
import {
  AGENT_ROLE_MIN_TIER,
  agentRolesForTier,
  agentScanTypesForTier,
  plansIncludingAgentRole,
  type AccessTier,
} from '@/lib/subscription-access'

const router = Router()

/* ------------------------------------------------------------------ */
/* Shared helpers                                                      */
/* ------------------------------------------------------------------ */

function jsonError(res: Response, status: number, code: string, message: string, detail?: unknown) {
  /* `detail` carries the structured half of a refusal — which role was asked
     for, which tier it needs, which roles this plan does include — so the UI
     can render an actionable gate instead of re-deriving policy from prose. */
  return res.status(status).json({ error: { code, message, ...(detail === undefined ? {} : { detail }) } })
}

function isMissingRuntimeTable(error: any) {
  const text = `${error?.code || ''} ${error?.message || ''}`.toLowerCase()
  return (
    text.includes('42p01') ||
    text.includes('pgrst205') ||
    text.includes('does not exist') ||
    text.includes('could not find the table')
  )
}

function hashToken(token: string) {
  return createHash('sha256').update(token).digest('hex')
}

function safeCompareHash(candidate: string, expected: string) {
  if (!expected) return false
  const a = Buffer.from(candidate)
  const b = Buffer.from(expected)
  return a.length === b.length && timingSafeEqual(a, b)
}

function cleanString(value: unknown, max = 255): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  if (!trimmed) return null
  return trimmed.slice(0, max)
}

interface AuthedRequest extends Request {
  user?: { id: string; email?: string | null }
  token?: string
  client?: SupabaseClient | null
}

interface AgentRequest extends Request {
  agent?: any
  client?: SupabaseClient | null
}

async function requireUserAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const token = getToken(req)
  if (!token) return jsonError(res, 401, 'UNAUTHORIZED', 'Authentication required')
  const user = await getServerUser(token)
  if (!user) return jsonError(res, 401, 'UNAUTHORIZED', 'Invalid or expired token')
  req.user = user as any
  req.token = token
  req.client = createAuthClient(token) || getServiceClient()
  next()
}

function agentCredentials(req: Request) {
  const agentId = typeof req.headers['x-qguard-agent-id'] === 'string' ? req.headers['x-qguard-agent-id'] : null
  const header = req.headers.authorization
  const bearer = header?.startsWith('Bearer ') ? header.slice(7) : null
  const explicit = typeof req.headers['x-qguard-agent-token'] === 'string' ? req.headers['x-qguard-agent-token'] : null
  return { agentId, token: explicit || bearer }
}

/**
 * Agent-credentialed access. Deliberately mirrors agent-scanner's contract so an
 * agent presents exactly one credential across the whole platform.
 */
async function requireAgentAuth(req: AgentRequest, res: Response, next: NextFunction) {
  const { agentId, token } = agentCredentials(req)
  if (!agentId || !token) return jsonError(res, 401, 'AGENT_UNAUTHORIZED', 'Agent id and token are required')

  const client = getServiceClient()
  if (!client) return jsonError(res, 503, 'DATABASE_UNAVAILABLE', 'Agent registry is unavailable')

  const { data: agent, error } = await client.from('scanner_agents').select('*').eq('id', agentId).limit(1).maybeSingle()
  if (error && !isMissingRuntimeTable(error)) {
    return jsonError(res, 500, 'AGENT_LOOKUP_FAILED', error.message)
  }
  if (!agent || agent.status === 'revoked' || agent.revoked_at) {
    return jsonError(res, 401, 'AGENT_REVOKED', 'Agent is not active')
  }
  if (!safeCompareHash(hashToken(token), agent.token_hash || '')) {
    return jsonError(res, 401, 'AGENT_UNAUTHORIZED', 'Invalid agent token')
  }

  req.agent = agent
  req.client = client
  next()
}

async function loadTenantAgent(client: SupabaseClient | null, userId: string, agentId: string) {
  if (!client) return null
  const { data, error } = await client
    .from('scanner_agents')
    .select('*')
    .eq('id', agentId)
    .eq('user_id', userId)
    .limit(1)
    .maybeSingle()
  if (error && !isMissingRuntimeTable(error)) throw new Error(error.message)
  return data || null
}

async function recordAudit(
  client: SupabaseClient | null,
  row: { userId: string; action: string; entityId: string | null; details: Record<string, unknown> },
) {
  if (!client) return
  const { error } = await client.from('audit_logs').insert({
    user_id: row.userId,
    action: row.action,
    entity_type: 'scanner_agent',
    entity_id: row.entityId,
    details: row.details,
  })
  if (error && !isMissingRuntimeTable(error)) {
    console.warn('[agent-installer] audit insert failed:', error.message)
  }
}

async function recordSecurityEvent(
  client: SupabaseClient | null,
  row: {
    userId: string
    eventType: string
    severity: string
    message: string
    resourceName: string | null
    metadata: Record<string, unknown>
  },
) {
  if (!client) return
  const { error } = await client.from('security_events').insert({
    user_id: row.userId,
    event_type: row.eventType,
    severity: row.severity,
    message: row.message,
    resource_name: row.resourceName,
    resource_type: 'scanner_agent',
    metadata: row.metadata,
  })
  if (error && !isMissingRuntimeTable(error)) {
    console.warn('[agent-installer] security event insert failed:', error.message)
  }
}

/**
 * Installation/lifecycle phases are written as `agent_heartbeats` rows. That table
 * already exists, is already tenant-scoped and already carries a jsonb telemetry
 * payload — so the activity timeline, install progress and health history all read
 * from ONE ordered source instead of a parallel table (spec §37).
 */
async function writeAgentEvent(
  client: SupabaseClient | null,
  agent: { id: string; user_id: string },
  status: string,
  telemetry: Record<string, unknown>,
  ip?: string | null,
) {
  if (!client) return
  const { error } = await client.from('agent_heartbeats').insert({
    user_id: agent.user_id,
    agent_id: agent.id,
    status,
    telemetry,
    ip_address: ip || null,
    observed_at: new Date().toISOString(),
  })
  if (error && !isMissingRuntimeTable(error)) {
    console.warn('[agent-installer] agent event insert failed:', error.message)
  }
}

/* ------------------------------------------------------------------ */
/* Release manifest (built by tools/build-agent-release.mjs)           */
/* ------------------------------------------------------------------ */

interface RuntimeRelease {
  version: string
  channel: string
  filename: string
  bytes: number
  sha256: string
  sha3_256: string
  builtAt: string
  requiresNode: string
  available: boolean
  reason?: string
}

const RUNTIME_DIR = path.resolve(process.cwd(), 'tools', 'qguard-agent', 'dist')
const RUNTIME_FILE = path.join(RUNTIME_DIR, AGENT_RUNTIME_FILENAME)
const MANIFEST_FILE = path.join(RUNTIME_DIR, 'manifest.json')

let releaseCache: { value: RuntimeRelease; loadedAt: number; mtimeMs: number } | null = null

/**
 * Reads the published manifest and re-verifies the digest against the bytes on
 * disk. A manifest that disagrees with the artifact is treated as unavailable —
 * an installer must never embed a checksum we cannot prove.
 */
async function loadRelease(): Promise<RuntimeRelease> {
  const unavailable = (reason: string): RuntimeRelease => ({
    version: AGENT_VERSION,
    channel: RELEASE_CHANNEL,
    filename: AGENT_RUNTIME_FILENAME,
    bytes: 0,
    sha256: '',
    sha3_256: '',
    builtAt: '',
    requiresNode: '>=18',
    available: false,
    reason,
  })

  let stats
  try {
    stats = await stat(RUNTIME_FILE)
  } catch {
    releaseCache = null
    return unavailable('Agent runtime has not been built. Run: npm run agent:release')
  }

  if (releaseCache && releaseCache.mtimeMs === stats.mtimeMs && Date.now() - releaseCache.loadedAt < 60_000) {
    return releaseCache.value
  }

  try {
    const [manifestRaw, bytes] = await Promise.all([readFile(MANIFEST_FILE, 'utf8'), readFile(RUNTIME_FILE)])
    const manifest = JSON.parse(manifestRaw)
    const actualSha256 = createHash('sha256').update(bytes).digest('hex')
    if (manifest?.runtime?.sha256 !== actualSha256) {
      return unavailable('Published manifest digest does not match the runtime on disk. Rebuild: npm run agent:release')
    }
    const value: RuntimeRelease = {
      version: String(manifest.version || AGENT_VERSION),
      channel: String(manifest.channel || RELEASE_CHANNEL),
      filename: String(manifest.runtime?.filename || AGENT_RUNTIME_FILENAME),
      bytes: Number(manifest.runtime?.bytes || bytes.length),
      sha256: actualSha256,
      sha3_256: String(manifest.runtime?.sha3_256 || createHash('sha3-256').update(bytes).digest('hex')),
      builtAt: String(manifest.builtAt || ''),
      requiresNode: String(manifest.runtime?.requiresNode || '>=18'),
      available: true,
    }
    releaseCache = { value, loadedAt: Date.now(), mtimeMs: stats.mtimeMs }
    return value
  } catch (error) {
    return unavailable(`Release manifest could not be read: ${(error as Error).message}`)
  }
}

/* ------------------------------------------------------------------ */
/* Connection + health derivation (spec §29 — never fabricate)         */
/* ------------------------------------------------------------------ */

export function connectionStateFor(agent: any): ConnectionState {
  if (agent?.revoked_at || agent?.status === 'revoked') return 'Offline'
  if (agent?.status === 'error') return 'Error'
  if (!agent?.last_seen_at) {
    // Never checked in. If it was created recently it is still installing.
    const createdAt = agent?.created_at ? Date.parse(agent.created_at) : 0
    if (createdAt && Date.now() - createdAt < HEARTBEAT_GRACE_WINDOW_MS) return 'Connecting'
    return 'Waiting'
  }
  const age = Date.now() - Date.parse(agent.last_seen_at)
  if (age <= HEARTBEAT_ONLINE_WINDOW_MS) return 'Connected'
  return 'Offline'
}

/* Queue helpers live in ./agent-command-queue so the snapshot rollback
   dispatcher shares one implementation of the bounded queue. */

/* ------------------------------------------------------------------ */
/* GET /releases — what is published (spec §25 GET /agent-releases)    */
/* ------------------------------------------------------------------ */

router.get('/releases', requireUserAuth, async (req: AuthedRequest, res) => {
  const release = await loadRelease()

  /*
   * The role catalogue is disclosed in full, with an `entitled` flag per role
   * rather than a filtered list (§48).
   *
   * A Basic tenant should SEE that Patcher and Migration Operator exist and
   * what they do — that is the argument for Pro. Hiding them would leave the
   * download centre silently shorter with no explanation, which teaches the
   * customer nothing and looks like a missing feature rather than a plan
   * boundary.
   */
  let tier: AccessTier = 'none'
  let entitlementDegraded = false
  try {
    const entitlement = await entitlementFor(req as AgentEntitlementRequest)
    tier = entitlement.isActive ? entitlement.tier : 'none'
  } catch {
    entitlementDegraded = true
  }
  const entitledRoles = agentRolesForTier(tier)
  const entitledScanTypes = agentScanTypesForTier(tier)

  res.json({
    data: {
      current: release,
      channel: RELEASE_CHANNEL,
      platforms: AGENT_PLATFORMS.map((platform) => ({
        id: platform.id,
        label: platform.label,
        filename: platform.filename,
        language: platform.language,
        architectures: platform.architectures,
        service: platform.service,
        privileges: platform.privileges,
        prerequisites: platform.prerequisites,
        quickCommand: installQuickCommand(platform.id),
      })),
      roles: AGENT_ROLES.map((role) => ({
        id: role.id,
        label: role.label,
        tagline: role.tagline,
        modules: role.modules,
        /* The modules this role would run FOR THIS TENANT, not the role's
           theoretical maximum — so a Basic tenant reading the catalogue sees
           the collector they will actually get. */
        scanTypes: role.scanTypes.filter((type) => entitledScanTypes.includes(type)),
        catalogueScanTypes: role.scanTypes,
        capabilities: role.capabilities,
        mutatesTargets: role.mutatesTargets,
        authority: role.authority,
        entitled: entitledRoles.includes(role.id),
        requiredTier: AGENT_ROLE_MIN_TIER[role.id],
        includedIn: plansIncludingAgentRole(role.id),
      })),
      entitlement: {
        tier,
        degraded: entitlementDegraded,
        roles: entitledRoles,
        scanTypes: entitledScanTypes,
      },
      installPhases: INSTALL_PHASES,
    },
  })
})

router.get('/releases/:platform', requireUserAuth, async (req: AuthedRequest, res) => {
  const platform = AGENT_PLATFORMS.find((item) => item.id === req.params.platform)
  if (!platform) return jsonError(res, 404, 'PLATFORM_NOT_FOUND', 'Unknown installation platform')
  const release = await loadRelease()
  res.json({ data: { platform, release, quickCommand: installQuickCommand(platform.id) } })
})

/* ------------------------------------------------------------------ */
/* POST /package — generate a real, tenant-bound installer             */
/* ------------------------------------------------------------------ */

/**
 * The control-plane URL an installer will bake in.
 *
 * Explicit configuration wins (§2: "Do not hard-code production URLs directly
 * into source code. Use environment configuration."). The request-derived
 * fallback exists so a developer running locally gets a working installer
 * without any setup — but it is only trusted in development, because deriving
 * a production endpoint from a `Host` header means an attacker who can reach
 * the server can choose where the agents they provision will phone home.
 */
function resolveApiUrl(req: Request): string {
  const configured = process.env.QGUARD_CONTROL_PLANE_URL || process.env.QGUARD_PUBLIC_API_URL || process.env.VITE_PUBLIC_APP_URL
  if (configured) return configured.replace(/\/+$/, '')
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim()
  const proto = forwardedProto || req.protocol || 'http'
  const host = String(req.headers['x-forwarded-host'] || req.headers.host || 'localhost:3000').split(',')[0].trim()
  return `${proto}://${host}`
}

const AGENT_ENVIRONMENT = readAgentEnvironment(process.env.QGUARD_ENVIRONMENT)

/**
 * Refuse to generate an installer that would ship an insecure control plane
 * (§3, §43, §62).
 *
 * This is the last point at which the platform controls what an agent will
 * talk to. Once a package is downloaded and run, a bad URL is on somebody's
 * production host.
 */
/* A plain interface, NOT a discriminated union: under this project's
   `strict: false` a union does not narrow on the `ok` literal, so
   `controlPlane.message` fails to type-check after the `if (!ok)` guard. Same
   trap the exposure engine contract hit. */
interface ControlPlaneGate {
  ok: boolean
  message?: string
  detail?: unknown
}

function assertControlPlane(apiUrl: string): ControlPlaneGate {
  const validation = validateControlPlane(apiUrl, AGENT_ENVIRONMENT)
  if (validation.ok) return { ok: true }
  return {
    ok: false,
    message: describeControlPlaneFailure(validation),
    detail: {
      environment: validation.environment,
      url: validation.url,
      errors: validation.errors,
      warnings: validation.warnings,
    },
  }
}

router.post('/package', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  const agentId = cleanString(req.body?.agentId, 120)
  const platformId = (cleanString(req.body?.platform, 40) || 'linux') as AgentPlatform
  const suppliedToken = cleanString(req.body?.token, 400)

  if (!agentId) return jsonError(res, 400, 'AGENT_REQUIRED', 'agentId is required')
  if (!AGENT_PLATFORMS.some((item) => item.id === platformId)) {
    return jsonError(res, 400, 'PLATFORM_UNSUPPORTED', 'Unknown installation platform')
  }

  const release = await loadRelease()
  if (!release.available) {
    return jsonError(res, 503, 'RELEASE_UNAVAILABLE', release.reason || 'No agent release is published')
  }

  let agent: any
  try {
    agent = await loadTenantAgent(client, user.id, agentId)
  } catch (error) {
    return jsonError(res, 500, 'AGENT_LOOKUP_FAILED', (error as Error).message)
  }
  if (!agent) return jsonError(res, 404, 'AGENT_NOT_FOUND', 'Agent not found for this tenant')
  if (agent.revoked_at || agent.status === 'revoked') {
    return jsonError(res, 409, 'AGENT_REVOKED', 'This agent is revoked. Create a new agent to deploy it.')
  }

  /*
   * Token handling (spec §6). Only the hash is stored, so the plaintext cannot be
   * recovered server-side. Either the caller still holds the one-time token from
   * enrollment — in which case we verify it and embed it, leaving prior installs
   * valid — or no valid token is available and the caller must rotate first. We
   * never silently mint a credential that invalidates deployed agents.
   */
  if (!suppliedToken) {
    return jsonError(
      res,
      409,
      'ENROLLMENT_TOKEN_REQUIRED',
      'The enrollment token is shown once and is not recoverable. Rotate the token to generate a new installer.',
    )
  }
  if (!safeCompareHash(hashToken(suppliedToken), agent.token_hash || '')) {
    return jsonError(
      res,
      409,
      'ENROLLMENT_TOKEN_STALE',
      'That enrollment token is no longer valid for this agent. Rotate the token and generate the installer again.',
    )
  }

  const role = (cleanString(agent.metadata?.role, 40) || 'collector') as AgentRole
  const roleDefinition = agentRole(role)
  const policy = agent.policy || {}
  /* The host-side write switches are baked from the agent's RECORDED write
     authority — never from the role alone. A Patcher the operator did not
     authorise ships with QGUARD_ENABLE_REMEDIATION=false. */
  const writeAuthority = resolveWriteAuthority(role, agent.capabilities, agent.metadata)

  /*
   * Re-check the plan at PACKAGE time, not only at enrolment.
   *
   * An agent row enrolled while the tenant held Pro survives a downgrade to
   * Basic — deleting their agents on a billing change would be worse. But a
   * downgraded tenant must not be able to keep minting fresh installers for a
   * write-capable role, so the gate is re-evaluated here against the plan they
   * hold NOW rather than the plan they held then (§15, §41).
   */
  const roleDecision = await decideAgentRole(req as AgentEntitlementRequest, role, (id) => agentRole(id).label)
  if (!roleDecision.ok) {
    return jsonError(res, roleDecision.status, roleDecision.code, roleDecision.message, roleDecision.detail)
  }

  /* And clamp the policy the installer will bake in, so a package generated
     today cannot carry modules the current plan no longer includes. */
  const requestedScanTypes = Array.isArray(policy.scanTypes) && policy.scanTypes.length
    ? policy.scanTypes.map(String)
    : roleDefinition.scanTypes
  const planClamp = await decideScanTypes(req as AgentEntitlementRequest, requestedScanTypes)
  const scanTypeDecision = { ...planClamp, allowed: clampAgentScanTypes(role, planClamp.allowed, null).allowed }

  const apiUrl = resolveApiUrl(req)
  const controlPlane = assertControlPlane(apiUrl)
  if (!controlPlane.ok) {
    return jsonError(res, 500, 'CONTROL_PLANE_INSECURE', controlPlane.message ?? 'Insecure control-plane configuration.', controlPlane.detail)
  }

  let installer
  try {
    installer = generateInstaller(platformId, {
      apiUrl,
      tenantId: user.id,
      agentId: agent.id,
      agentToken: suppliedToken,
      agentName: String(agent.name || 'Qguard Helix Agent'),
      role,
      environment: String(agent.metadata?.environment || 'production'),
      // The environment `apiUrl` was just validated against (assertControlPlane):
      // the agent re-applies the same rules at boot.
      controlPlaneEnvironment: AGENT_ENVIRONMENT,
      version: release.version,
      runtimeSha256: release.sha256,
      policy: {
        intervalSeconds: Number(policy.intervalSeconds || policy.interval_seconds || 60),
        allowedTargets: Array.isArray(policy.allowedTargets) ? policy.allowedTargets.map(String) : [],
        allowedPaths: Array.isArray(policy.allowedPaths) ? policy.allowedPaths.map(String) : [],
        scanTypes: scanTypeDecision.allowed,
        alertThreshold: String(policy.alertThreshold || 'moderate'),
      },
      remediationEnabled: writeAuthority.remediation,
      migrationEnabled: writeAuthority.migration,
      generatedAt: new Date().toISOString(),
      generatedBy: user.id,
    })
  } catch (error) {
    return jsonError(res, 400, 'PACKAGE_GENERATION_FAILED', (error as Error).message)
  }

  const installerSha256 = createHash('sha256').update(installer.content, 'utf8').digest('hex')
  const platform = agentPlatform(platformId)

  await writeAgentEvent(client, agent, 'install:package_generated', {
    phase: 'package_generated',
    platform: platformId,
    agentVersion: release.version,
    runtimeSha256: release.sha256,
    installerSha256,
  }, req.ip)

  await recordAudit(client, {
    userId: user.id,
    action: 'agent_installer_generated',
    entityId: agent.id,
    details: {
      platform: platformId,
      role,
      agentName: agent.name,
      agentVersion: release.version,
      runtimeSha256: release.sha256,
      installerSha256,
      // The token itself is never written to the audit trail.
      tokenEmbedded: true,
    },
  })

  publishAgentEvent(user.id, 'agent.installation_started', agent.id, {
    platform: platformId,
    version: release.version,
    agentName: agent.name,
  })

  res.json({
    data: {
      agentId: agent.id,
      agentName: agent.name,
      platform: platformId,
      role,
      filename: installer.filename,
      contentType: installer.contentType,
      language: installer.language,
      content: installer.content,
      installerSha256,
      runtime: {
        version: release.version,
        sha256: release.sha256,
        sha3_256: release.sha3_256,
        bytes: release.bytes,
        builtAt: release.builtAt,
        requiresNode: release.requiresNode,
      },
      instructions: {
        runCommand: installer.runCommand,
        privileges: installer.privileges,
        prerequisites: installer.prerequisites,
        service: installer.service,
        architectures: installer.architectures,
        quickCommand: installQuickCommand(platformId),
        label: platform.label,
      },
    },
  })
})

/* ------------------------------------------------------------------ */
/* GET /runtime — the signed agent bundle (agent-credentialed)         */
/* ------------------------------------------------------------------ */

router.get('/runtime', requireAgentAuth, async (req: AgentRequest, res) => {
  const agent = req.agent!
  const release = await loadRelease()
  if (!release.available) {
    return jsonError(res, 503, 'RELEASE_UNAVAILABLE', release.reason || 'No agent release is published')
  }

  let bytes: Buffer
  try {
    bytes = await readFile(RUNTIME_FILE)
  } catch (error) {
    return jsonError(res, 503, 'RUNTIME_UNAVAILABLE', (error as Error).message)
  }

  await writeAgentEvent(req.client || null, agent, 'install:runtime_downloaded', {
    phase: 'runtime_downloaded',
    version: release.version,
    sha256: release.sha256,
    bytes: bytes.length,
    userAgent: String(req.headers['user-agent'] || '').slice(0, 200),
  }, req.ip)

  publishAgentEvent(agent.user_id, 'agent.installation_started', agent.id, {
    phase: 'runtime_downloaded',
    version: release.version,
  })

  res.setHeader('Content-Type', 'application/javascript; charset=utf-8')
  res.setHeader('Content-Disposition', `attachment; filename="${AGENT_RUNTIME_FILENAME}"`)
  res.setHeader('Content-Length', String(bytes.length))
  res.setHeader('X-QGuard-Agent-Version', release.version)
  res.setHeader('X-QGuard-Runtime-SHA256', release.sha256)
  res.setHeader('X-QGuard-Runtime-SHA3-256', release.sha3_256)
  res.setHeader('Cache-Control', 'no-store')
  res.end(bytes)
})

/* ------------------------------------------------------------------ */
/* Agent-reported installation phases + self status                    */
/* ------------------------------------------------------------------ */

const VALID_PHASES = new Set<string>([...INSTALL_PHASES.map((phase) => phase.id), 'installation_started', 'failed'])

router.post('/installation-event', requireAgentAuth, async (req: AgentRequest, res) => {
  const agent = req.agent!
  const phase = cleanString(req.body?.phase, 60) || ''
  if (!VALID_PHASES.has(phase)) {
    return jsonError(res, 400, 'INVALID_PHASE', 'Unknown installation phase')
  }
  const detail = cleanString(req.body?.detail, 500)
  const platform = cleanString(req.body?.platform, 40)
  const version = cleanString(req.body?.version, 40)

  await writeAgentEvent(req.client || null, agent, `install:${phase}`, {
    phase,
    detail,
    platform,
    version,
    reportedBy: 'installer',
  }, req.ip)

  if (phase === 'failed') {
    await recordSecurityEvent(req.client || null, {
      userId: agent.user_id,
      eventType: 'scanner_agent_install_failed',
      severity: 'warning',
      message: `Agent installation failed: ${detail || 'no detail reported'}`,
      resourceName: agent.name || agent.id,
      metadata: { agentId: agent.id, phase, platform, detail },
    })
    publishAgentEvent(agent.user_id, 'agent.error', agent.id, { phase, detail, platform })
  } else {
    publishAgentEvent(agent.user_id, 'agent.installation_started', agent.id, { phase, detail, platform, version })
  }

  res.json({ data: { accepted: true, phase, observedAt: new Date().toISOString() } })
})

router.get('/self', requireAgentAuth, async (req: AgentRequest, res) => {
  const agent = req.agent!
  const release = await loadRelease()
  const state = connectionStateFor(agent)
  res.json({
    data: {
      agentId: agent.id,
      name: agent.name,
      connected: state === 'Connected',
      connectionState: state,
      status: agent.status,
      lastSeenAt: agent.last_seen_at || null,
      installedVersion: agent.version || null,
      latestVersion: release.available ? release.version : null,
      upgradeAvailable: Boolean(release.available && agent.version && agent.version !== release.version),
      policyEnabled: agent.policy?.enabled !== false,
    },
  })
})

/* ------------------------------------------------------------------ */
/* Command queue (spec §25 jobs / scan / upgrade / enable / disable)   */
/* ------------------------------------------------------------------ */

async function enqueueCommand(
  req: AuthedRequest,
  res: Response,
  type: AgentCommandType,
  payload: Record<string, unknown> = {},
) {
  const client = req.client || null
  const user = req.user!
  const agentId = req.params.id

  let agent: any
  try {
    agent = await loadTenantAgent(client, user.id, agentId)
  } catch (error) {
    return jsonError(res, 500, 'AGENT_LOOKUP_FAILED', (error as Error).message)
  }
  if (!agent) return jsonError(res, 404, 'AGENT_NOT_FOUND', 'Agent not found for this tenant')
  if (agent.revoked_at || agent.status === 'revoked') {
    return jsonError(res, 409, 'AGENT_REVOKED', 'Revoked agents cannot accept commands')
  }
  if ((type === 'scan' || type === 'rescan_validation') && agent.policy?.enabled === false) {
    return jsonError(res, 409, 'AGENT_DISABLED', 'Scanning is disabled by policy. Enable the collector before requesting a scan.')
  }

  const outcome = await enqueueAgentCommand(client, agent, type, { payload, requestedBy: user.id })
  if (!outcome.ok) return jsonError(res, outcome.status, outcome.code, outcome.message)
  if (outcome.deduplicated) {
    return res.json({ data: { command: outcome.command, deduplicated: true } })
  }
  const command = outcome.command!

  await writeAgentEvent(client, agent, `command:${type}`, { commandId: command.id, type, payload }, req.ip)
  await recordAudit(client, {
    userId: user.id,
    action: `agent_command_${type}`,
    entityId: agent.id,
    details: { commandId: command.id, type, payload, agentName: agent.name },
  })

  const eventName: AgentEventName =
    type === 'scan' || type === 'rescan_validation'
      ? 'agent.scan_started'
      : type === 'upgrade'
        ? 'agent.upgrade_started'
        : 'agent.heartbeat'
  publishAgentEvent(user.id, eventName, agent.id, { commandId: command.id, type, queued: true })

  const connection = connectionStateFor(agent)
  res.json({
    data: {
      command,
      // Honest delivery expectation: a queued command only runs when the agent polls.
      delivery:
        connection === 'Connected'
          ? 'Queued. The agent will pick this up on its next poll.'
          : 'Queued. The agent is not currently connected — this runs as soon as it checks in.',
      connectionState: connection,
    },
  })
}

router.post('/agents/:id/scan', requireUserAuth, (req: AuthedRequest, res) => enqueueCommand(req, res, 'scan', { requestedAt: new Date().toISOString() }))
router.post('/agents/:id/enable', requireUserAuth, (req: AuthedRequest, res) => enqueueCommand(req, res, 'enable'))
router.post('/agents/:id/disable', requireUserAuth, (req: AuthedRequest, res) => enqueueCommand(req, res, 'disable'))

router.post('/agents/:id/upgrade', requireUserAuth, async (req: AuthedRequest, res) => {
  const release = await loadRelease()
  if (!release.available) {
    return jsonError(res, 503, 'RELEASE_UNAVAILABLE', release.reason || 'No agent release is published')
  }
  return enqueueCommand(req, res, 'upgrade', { targetVersion: release.version, sha256: release.sha256 })
})

router.get('/agents/:id/jobs', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  let agent: any
  try {
    agent = await loadTenantAgent(client, user.id, req.params.id)
  } catch (error) {
    return jsonError(res, 500, 'AGENT_LOOKUP_FAILED', (error as Error).message)
  }
  if (!agent) return jsonError(res, 404, 'AGENT_NOT_FOUND', 'Agent not found for this tenant')
  res.json({ data: { queued: commandQueue(agent), history: commandHistory(agent) } })
})

/** Command-specific progress: a later scheduled scan cannot replace this result. */
router.get('/agents/:id/scan-status', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  if (!client) return jsonError(res, 503, 'DATABASE_UNAVAILABLE', 'Scan tracking is unavailable')
  try {
    const agent = await loadTenantAgent(client, user.id, req.params.id)
    if (!agent) return jsonError(res, 404, 'AGENT_NOT_FOUND', 'Agent not found for this tenant')
    const commandId = cleanString(req.query.commandId, 120)
    if (!commandId) return jsonError(res, 400, 'COMMAND_REQUIRED', 'commandId is required')
    const command = [...commandQueue(agent), ...commandHistory(agent)].find((item) => item.id === commandId && (item.type === 'scan' || item.type === 'rescan_validation'))
    if (!command) return jsonError(res, 404, 'SCAN_COMMAND_NOT_FOUND', 'This scan receipt is not available in this agent’s retained history.')
    let frames = client.from('agent_heartbeats').select('status, telemetry, observed_at')
      .eq('user_id', user.id).eq('agent_id', agent.id).gte('observed_at', command.startedAt || command.queuedAt)
      .order('observed_at', { ascending: false }).limit(1000)
    if (command.completedAt) frames = frames.lte('observed_at', command.completedAt)
    const { data, error } = await frames
    if (error) return jsonError(res, 503, 'SCAN_PROGRESS_UNAVAILABLE', 'Recorded scan progress could not be read. Retry shortly.')
    res.json({ data: {
      ...trackRequestedScan(command, data || []),
      agent: { id: agent.id, name: agent.name, hostname: agent.hostname, role: agent.metadata?.role || 'collector', platform: agent.platform },
      schedule: { enabled: agent.policy?.enabled !== false, intervalSeconds: Math.max(30, Math.min(60, Number(agent.policy?.intervalSeconds || 60))) },
    } })
  } catch (error) {
    return jsonError(res, 500, 'SCAN_TRACKING_FAILED', 'Unable to read the requested scan.')
  }
})

/* ------------------------------------------------------------------ */
/* Health, telemetry, activity, findings, scans                        */
/* ------------------------------------------------------------------ */

async function heartbeatRows(client: SupabaseClient | null, userId: string, agentId: string, limit: number) {
  if (!client) return []
  const { data, error } = await client
    .from('agent_heartbeats')
    .select('id, status, telemetry, observed_at, created_at')
    .eq('user_id', userId)
    .eq('agent_id', agentId)
    .order('observed_at', { ascending: false })
    .limit(limit)
  if (error) {
    if (isMissingRuntimeTable(error)) return []
    throw new Error(error.message)
  }
  return data || []
}

router.get('/agents/:id/health', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  let agent: any
  try {
    agent = await loadTenantAgent(client, user.id, req.params.id)
  } catch (error) {
    return jsonError(res, 500, 'AGENT_LOOKUP_FAILED', (error as Error).message)
  }
  if (!agent) return jsonError(res, 404, 'AGENT_NOT_FOUND', 'Agent not found for this tenant')

  let rows: any[] = []
  try {
    rows = await heartbeatRows(client, user.id, agent.id, 50)
  } catch (error) {
    return jsonError(res, 500, 'HEALTH_LOAD_FAILED', (error as Error).message)
  }

  const release = await loadRelease()
  const latestTelemetry = rows.find((row) => row.telemetry && row.telemetry.host)?.telemetry || null
  const connection = connectionStateFor(agent)

  res.json({
    data: {
      agentId: agent.id,
      connectionState: connection,
      lastSeenAt: agent.last_seen_at || null,
      installedVersion: agent.version || null,
      latestVersion: release.available ? release.version : null,
      upgradeAvailable: Boolean(release.available && agent.version && agent.version !== release.version),
      /*
       * Resource telemetry is reported by the agent. When the agent has never
       * checked in there is nothing to report — we return null rather than zeros,
       * because "0% memory used" and "no data" are not the same statement.
       */
      host: latestTelemetry?.host || null,
      memory: latestTelemetry?.memory || null,
      process: latestTelemetry?.process || null,
      counters: latestTelemetry?.counters || null,
      capabilities: latestTelemetry?.capabilities || agent.capabilities || null,
      /*
       * The knowledge-base and rule-set version this agent classifies against
       * (spec §51, §85). Null for an agent whose build predates the field —
       * which is itself the useful signal, because it means its findings were
       * produced by a rule set the platform can no longer name.
       */
      engine: latestTelemetry?.engine || null,
      telemetryAvailable: Boolean(latestTelemetry),
      heartbeats: rows.map((row) => ({
        id: row.id,
        status: row.status,
        observedAt: row.observed_at || row.created_at,
        phase: row.telemetry?.phase || null,
      })),
    },
  })
})

router.get('/agents/:id/activity', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  const limit = Math.max(1, Math.min(200, Number(req.query.limit) || 60))
  let agent: any
  try {
    agent = await loadTenantAgent(client, user.id, req.params.id)
  } catch (error) {
    return jsonError(res, 500, 'AGENT_LOOKUP_FAILED', (error as Error).message)
  }
  if (!agent) return jsonError(res, 404, 'AGENT_NOT_FOUND', 'Agent not found for this tenant')

  let rows: any[] = []
  try {
    rows = await heartbeatRows(client, user.id, agent.id, limit)
  } catch (error) {
    return jsonError(res, 500, 'ACTIVITY_LOAD_FAILED', (error as Error).message)
  }

  res.json({
    data: {
      activity: rows.map((row) => ({
        id: row.id,
        at: row.observed_at || row.created_at,
        status: row.status,
        phase: row.telemetry?.phase || null,
        stage: row.telemetry?.stage || null,
        progress: typeof row.telemetry?.progress === 'number' ? row.telemetry.progress : null,
        message: row.telemetry?.message || row.telemetry?.detail || null,
        evidenceCount: row.telemetry?.evidenceCount ?? null,
      })),
    },
  })
})

router.get('/agents/:id/findings', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  const limit = Math.max(1, Math.min(500, Number(req.query.limit) || 100))
  let agent: any
  try {
    agent = await loadTenantAgent(client, user.id, req.params.id)
  } catch (error) {
    return jsonError(res, 500, 'AGENT_LOOKUP_FAILED', (error as Error).message)
  }
  if (!agent) return jsonError(res, 404, 'AGENT_NOT_FOUND', 'Agent not found for this tenant')
  if (!client) return jsonError(res, 503, 'DATABASE_UNAVAILABLE', 'Evidence store is unavailable')

  const { data: evidence, error } = await client
    .from('scanner_evidence')
    .select(
      'id, evidence_type, asset_name, asset_type, target, host, port, protocol, observed_algorithm, key_size, certificate_fingerprint, file_path, package_name, package_version, confidence, raw_evidence, observed_at, created_at',
    )
    .eq('user_id', user.id)
    .eq('agent_id', agent.id)
    .order('observed_at', { ascending: false })
    .limit(limit)

  if (error && !isMissingRuntimeTable(error)) {
    return jsonError(res, 500, 'FINDINGS_LOAD_FAILED', error.message)
  }

  const { data: alerts } = await client
    .from('scanner_alerts')
    .select('id, severity, category, title, message, recommendation, status, created_at')
    .eq('user_id', user.id)
    .eq('agent_id', agent.id)
    .order('created_at', { ascending: false })
    .limit(limit)

  const rows = evidence || []
  res.json({
    data: {
      /*
       * `scanned` is the honest gate for the whole view: an agent that has produced
       * no evidence has NOT proven the host is clean, so the UI must render
       * "Not Yet Assessed" rather than "0 findings" (spec §29).
       */
      scanned: rows.length > 0,
      evidence: rows,
      alerts: alerts || [],
      collectorVersion: agent.version || null,
      agentId: agent.id,
    },
  })
})

router.get('/agents/:id/scans', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  let agent: any
  try {
    agent = await loadTenantAgent(client, user.id, req.params.id)
  } catch (error) {
    return jsonError(res, 500, 'AGENT_LOOKUP_FAILED', (error as Error).message)
  }
  if (!agent) return jsonError(res, 404, 'AGENT_NOT_FOUND', 'Agent not found for this tenant')

  let rows: any[] = []
  try {
    rows = await heartbeatRows(client, user.id, agent.id, 200)
  } catch (error) {
    return jsonError(res, 500, 'SCANS_LOAD_FAILED', (error as Error).message)
  }

  // A scan is bounded by its `starting` phase and one of the TERMINAL phases.
  //
  // `failed` is terminal too. Recognising only `completed` meant a scan that
  // died mid-flight never closed its session, so the Agent Center rendered a
  // long-dead scan as "Running" indefinitely — the visible half of the bug that
  // left agents stuck at "Calculating quantum exposure".
  //
  // Only the newest session may still be open: an older `starting` with no
  // terminal phase after it belongs to a run the agent never finished
  // reporting (process killed, host rebooted), and is closed as `interrupted`
  // rather than left claiming to be running.
  const scans: Array<Record<string, unknown>> = []
  let pendingStart: any = null

  const closeSession = (start: any, terminal: any, status: 'completed' | 'failed') => ({
    startedAt: start?.observed_at || null,
    completedAt: terminal.observed_at,
    durationMs:
      start?.observed_at && terminal.observed_at
        ? Date.parse(terminal.observed_at) - Date.parse(start.observed_at)
        : terminal.telemetry?.durationMs ?? null,
    evidenceCount: terminal.telemetry?.evidenceCount ?? null,
    runtimeEventCount: terminal.telemetry?.runtimeEventCount ?? null,
    remediationJobs: terminal.telemetry?.remediationJobs ?? null,
    acceptedCount: terminal.telemetry?.acceptedByControlPlane ?? null,
    rejectedByPolicy: terminal.telemetry?.rejectedByPolicy ?? null,
    outOfPolicy: terminal.telemetry?.outOfPolicy ?? null,
    degraded: Boolean(terminal.telemetry?.degraded),
    error: status === 'failed' ? (terminal.telemetry?.error ?? null) : null,
    status,
  })

  for (const row of [...rows].reverse()) {
    const phase = row.telemetry?.phase
    if (phase === 'starting') {
      // A new run started while the previous one was still open: the previous
      // run never reported a terminal phase and is recorded as interrupted.
      if (pendingStart) {
        scans.push({
          startedAt: pendingStart.observed_at,
          completedAt: null,
          durationMs: null,
          evidenceCount: null,
          degraded: false,
          error: 'The agent started a new scan before this one reported a result.',
          status: 'interrupted',
        })
      }
      pendingStart = row
    }
    if (phase === 'completed' || phase === 'failed') {
      scans.push(closeSession(pendingStart, row, phase === 'failed' ? 'failed' : 'completed'))
      pendingStart = null
    }
  }
  if (pendingStart) {
    scans.push({
      startedAt: pendingStart.observed_at,
      completedAt: null,
      durationMs: null,
      evidenceCount: null,
      degraded: false,
      error: null,
      status: 'running',
    })
  }

  res.json({ data: { scans: scans.reverse() } })
})

/* ------------------------------------------------------------------ */
/* Deployment summary (Downloads page header cards)                    */
/* ------------------------------------------------------------------ */

router.get('/summary', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  const release = await loadRelease()

  if (!client) return jsonError(res, 503, 'DATABASE_UNAVAILABLE', 'Agent registry is unavailable')

  const { data: agents, error } = await client
    .from('scanner_agents')
    .select('id, name, status, hostname, platform, version, capabilities, policy, last_seen_at, revoked_at, metadata, created_at, updated_at')
    .eq('user_id', user.id)
    .order('created_at', { ascending: false })

  if (error && !isMissingRuntimeTable(error)) {
    return jsonError(res, 500, 'AGENTS_LOAD_FAILED', error.message)
  }

  const rows = agents || []
  const decorated = rows.map((agent: any) => {
    const state = connectionStateFor(agent)
    const queue = commandQueue(agent)
    return {
      ...agent,
      token_hash: undefined,
      connectionState: state,
      role: agent.metadata?.role || 'collector',
      environment: agent.metadata?.environment || null,
      assignedAssetId: agent.metadata?.assetId || null,
      assignedAssetName: agent.metadata?.assetName || null,
      upgradeAvailable: Boolean(release.available && agent.version && agent.version !== release.version),
      pendingCommands: queue.filter((item) => item.status === 'queued' || item.status === 'delivered').length,
      currentTask: queue.find((item) => item.status === 'delivered' || item.status === 'running')?.type || null,
    }
  })

  const summary = {
    total: decorated.length,
    connected: decorated.filter((a) => a.connectionState === 'Connected').length,
    connecting: decorated.filter((a) => a.connectionState === 'Connecting').length,
    waiting: decorated.filter((a) => a.connectionState === 'Waiting').length,
    offline: decorated.filter((a) => a.connectionState === 'Offline').length,
    error: decorated.filter((a) => a.connectionState === 'Error').length,
    revoked: decorated.filter((a) => a.revoked_at || a.status === 'revoked').length,
    scanning: decorated.filter((a) => a.status === 'scanning').length,
    updatesAvailable: decorated.filter((a) => a.upgradeAvailable).length,
    activeJobs: decorated.reduce((total, a) => total + (a.pendingCommands || 0), 0),
  }

  res.json({ data: { agents: decorated, summary, release } })
})

/* ------------------------------------------------------------------ */
/* Tenant context — the assets an agent may be bound to (spec §6)      */
/* ------------------------------------------------------------------ */

/**
 * The asset picker source for the deployment wizard, plus how many agents each
 * asset already has. Strictly tenant-scoped: an agent can only ever be assigned
 * to an asset this caller owns, and the enrollment endpoint re-verifies the id
 * server-side rather than trusting whatever the client posts back.
 */
router.get('/assets', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  if (!client) return jsonError(res, 503, 'DATABASE_UNAVAILABLE', 'Asset inventory is unavailable')

  const search = cleanString(req.query.search, 120)
  let query = client
    .from('assets')
    // Binding kind and path are read as scalars so the picker never pulls whole metadata blobs.
    .select('id, name, type, environment, criticality, status, ip_address, service_owner, updated_at, binding_kind:metadata->>bindingKind, binding_path:metadata->>bindingPath')
    .eq('user_id', user.id)
    .order('name', { ascending: true })
    .limit(500)
  if (search) query = query.ilike('name', `%${search}%`)

  const { data: assets, error } = await query
  if (error && !isMissingRuntimeTable(error)) {
    return jsonError(res, 500, 'ASSETS_LOAD_FAILED', error.message)
  }

  const { data: agents } = await client
    .from('scanner_agents')
    .select('id, name, metadata, last_seen_at, revoked_at, status')
    .eq('user_id', user.id)

  const byAsset = new Map<string, Array<{ id: string; name: string; connectionState: ConnectionState }>>()
  for (const agent of agents || []) {
    const assetId = (agent as any).metadata?.assetId
    if (!assetId) continue
    const list = byAsset.get(assetId) || []
    list.push({ id: agent.id, name: agent.name, connectionState: connectionStateFor(agent) })
    byAsset.set(assetId, list)
  }

  res.json({
    data: {
      assets: (assets || []).map((asset: any) => ({
        ...asset,
        agents: byAsset.get(asset.id) || [],
      })),
      // Agents deliberately NOT bound to an asset — surfaced so the operator can
      // see coverage gaps rather than assume every agent is attributed.
      unassignedAgents: (agents || [])
        .filter((agent: any) => !agent.metadata?.assetId)
        .map((agent: any) => ({ id: agent.id, name: agent.name })),
      tenantId: user.id,
    },
  })
})

/* ------------------------------------------------------------------ */
/* SSE — agent.* events with Last-Event-ID recovery (spec §10, §28)    */
/* ------------------------------------------------------------------ */

router.get('/events/stream', async (req, res) => {
  const queryToken = typeof req.query.token === 'string' ? req.query.token : ''
  const token = getToken(req) || queryToken
  if (!token) return jsonError(res, 401, 'UNAUTHORIZED', 'Authentication required')

  const user = await getServerUser(token)
  if (!user) return jsonError(res, 401, 'UNAUTHORIZED', 'Invalid or expired token')

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  })

  // Resume point: the browser's Last-Event-ID header on reconnect, or an explicit
  // ?lastEventId for clients that cannot set headers on an EventSource.
  const lastEventHeader = req.headers['last-event-id']
  const headerValue = Array.isArray(lastEventHeader) ? lastEventHeader[0] : lastEventHeader
  let cursor = Number(headerValue || req.query.lastEventId || 0) || 0
  let closed = false

  const flush = () => {
    if (closed) return
    for (const event of eventsSince(user.id, cursor)) {
      res.write(`id: ${event.id}\n`)
      res.write(`event: ${event.name}\n`)
      res.write(`data: ${JSON.stringify({ agentId: event.agentId, at: event.at, ...event.payload })}\n\n`)
      cursor = event.id
    }
  }

  // Announce the real connection state before anything else, so the client never
  // has to assume it is connected (spec §28).
  res.write(`event: stream.ready\ndata: ${JSON.stringify({ at: new Date().toISOString(), replayFrom: cursor })}\n\n`)
  flush()

  const unsubscribe = subscribe(user.id, flush)
  const heartbeat = setInterval(() => {
    if (closed) return
    res.write(`event: stream.heartbeat\ndata: ${JSON.stringify({ at: new Date().toISOString() })}\n\n`)
  }, 25_000)

  req.on('close', () => {
    closed = true
    unsubscribe()
    clearInterval(heartbeat)
    res.end()
  })
})

export default router
