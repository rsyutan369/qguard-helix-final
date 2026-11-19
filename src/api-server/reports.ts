import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { randomUUID } from 'node:crypto'
import { z } from 'zod'
import { buildSnapshot } from './quantum-readiness'
import { buildScannerIntelligence } from './scanner'
import { buildAssetRegister, filterRows, type RegisterFilter } from '@/lib/assets/asset-register'
import { buildAssetReport, canonicalAssetReport } from '@/services/reporting/AssetReport'
import { sha3Hex } from '@/services/reporting/ReportIntegrity'
import type { InventoryReport } from '@/services/reporting/InventoryReport'
import { buildReadinessReportModel, listReportScopeAssets } from './readiness-report-model'
import { loadReportOperationalEvidence } from './report-operational-evidence'
import {
  getActiveReportOrganizationIds, ownsReportOrganization, readinessReportDigest,
  reportSnapshotClient, reportSnapshotDigest, saveReadinessReport, READINESS_REPORT_FAMILY,
} from './report-snapshot-store'
import {
  brandingSchema, evidenceAssessmentReportSchema, REPORT_FORMATS, REPORT_KINDS, type ReportProvenance,
} from '@/services/reporting/schemas/ReportSchema'

const router = Router()

type AuthedRequest = Request & { user?: { id: string; email?: string | null }; token?: string }

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = getToken(req)
  if (!token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  const user = await getServerUser(token)
  if (!user) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  ;(req as AuthedRequest).user = user
  ;(req as AuthedRequest).token = token
  next()
}

router.use((_req, res, next) => {
  res.setHeader('Cache-Control', 'private, no-store')
  next()
}, requireAuth)

const reportIdSchema = z.string().uuid()
const boundedBrand = (limit: number, fallback = '') => z.string().trim().max(limit).default(fallback)
const captureSchema = z.object({
  format: z.enum(REPORT_FORMATS).default('json'),
  kind: z.enum(REPORT_KINDS).default('executive'),
  preview: z.boolean().default(false),
  scopeAssets: z.array(reportIdSchema).min(1).max(2000).nullable().default(null),
  branding: brandingSchema.extend({
    companyName: boundedBrand(160, 'QGuard Helix'),
    companyLogo: z.string().max(524_320).regex(/^data:image\/(png|jpeg);base64,[A-Za-z0-9+/]+={0,2}$/).nullable().default(null),
    businessUnit: boundedBrand(160),
    reportOwner: boundedBrand(160),
    reviewer: boundedBrand(160),
    classification: boundedBrand(80, 'CONFIDENTIAL'),
    reportVersion: boundedBrand(32, '1.0'),
    customNotes: boundedBrand(3000),
  }).prefault({}),
}).strict()

const assetCaptureSchema = z.object({
  template: z.enum(['executive', 'technical', 'remediation']),
  scope: z.enum(['all', 'filtered', 'selection', 'single']),
  assetIds: z.array(z.string().min(1).max(256)).max(2000).default([]),
  filters: z.object({
    query: z.string().max(300).optional(),
    agentId: z.string().max(160).nullish(),
    sourceKind: z.string().max(40).nullish(),
    bands: z.array(z.string().max(40)).max(8).nullish(),
    statuses: z.array(z.string().max(40)).max(8).nullish(),
    freshness: z.array(z.string().max(40)).max(8).nullish(),
  }).strict().prefault({}),
  branding: captureSchema.shape.branding,
}).strict()

function assessmentReference(
  scanner: Awaited<ReturnType<typeof buildScannerIntelligence>>,
  assessment: Awaited<ReturnType<typeof buildSnapshot>> | null,
) {
  if (!assessment?.hasData) return null
  const { reportReadCoverage, reportEvidence, scores, inventory, riskDistribution, lastAssessmentAt } = assessment
  return reportSnapshotDigest({
    ...scanner.reportVersions, reportReadCoverage, reportEvidence, scores, inventory, riskDistribution, lastAssessmentAt,
  })
}

router.post('/asset-snapshots', async (req, res) => {
  const input = assetCaptureSchema.safeParse(req.body)
  if (!input.success) return res.status(400).json({ error: { message: 'Check the asset report template, branding and scope.' } })
  const { token, user } = req as AuthedRequest
  const { template, scope, assetIds, filters, branding } = input.data
  try {
    const store = reportSnapshotClient(token!)
    const [scanner, organizations] = await Promise.all([
      buildScannerIntelligence(token!, user!.id, { fresh: true }),
      getActiveReportOrganizationIds(store, user!.id).catch(() => []),
    ])
    if (scanner.mode !== 'database' || !scanner.reportVersions) {
      return res.status(503).json({ error: { message: 'Stored asset and CBOM evidence is unavailable.' } })
    }
    const assessment = scope === 'all' ? await buildSnapshot(token!, user!.id, scanner).catch(() => null) : null
    const compatible = assessment?.hasData && assessment.inventory.cryptoComponents > 0
      && assessment.inventory.cryptoComponents === scanner.summary.totalComponents
      && assessment.inventory.vulnerableComponents === scanner.summary.vulnerableComponents
      && ['assets', 'runtime_crypto_events', 'crypto_inventory'].every((source) =>
        assessment.reportReadCoverage?.some((row) => row.source === source && row.status === 'available'))
      && scanner.sourceCoverage?.every((row) => row.status === 'available')
    const register = buildAssetRegister({
      snapshot: scanner,
      qr: compatible ? {
        resolved: true, hasData: true, readiness: assessment.scores.quantumReadiness,
        readinessLevel: assessment.scores.quantumReadinessLevel, risk: assessment.scores.quantumRisk,
        components: assessment.inventory.cryptoComponents, vulnerableComponents: assessment.inventory.vulnerableComponents,
      } : undefined,
    })
    const ids = new Set(assetIds)
    const selection = scope === 'selection' || scope === 'single'
    const rows = selection ? register.rows.filter((row) => ids.has(row.id))
      : scope === 'filtered' ? filterRows(register.rows, filters as RegisterFilter) : register.rows
    if (!rows.length || (selection && rows.length !== ids.size) || (scope === 'single' && rows.length !== 1)) {
      return res.status(400).json({ error: { message: 'The selected scope is empty or assets have changed. Review the current register and capture again.' } })
    }
    const id = randomUUID()
    const organizationId = organizations.length === 1 ? organizations[0] : null
    const model = buildAssetReport({
      register, rows, template, branding, generatedBy: user!.email || 'QGuard Helix',
      generatedAt: scanner.generatedAt,
      scope: { type: selection ? 'selection' : scope as 'all' | 'filtered', description: scope === 'all' ? 'the full register' : `${rows.length} ${scope === 'filtered' ? 'filtered' : 'selected'} assets` },
      provenance: {
        reportId: id, workspaceOwnerId: user!.id, organizationId, snapshotAt: scanner.generatedAt,
        assetInventoryVersion: scanner.reportVersions.assetInventoryVersion, cbomVersion: scanner.reportVersions.cbomVersion,
        assessmentId: compatible ? assessmentReference(scanner, assessment) : null,
        dataCompleteness: [...(scanner.sourceCoverage || []), {
          source: 'Quantum readiness assessment', status: compatible ? 'available' : 'missing',
          detail: compatible ? 'The current workspace assessment and CBOM counts reconciled.'
            : 'No compatible workspace assessment could be linked to the scanner inventory.',
        }],
      },
    })
    if (model.document?.validation.status === 'fail') {
      return res.status(409).json({ error: { message: 'The captured inventory did not reconcile with the report rows.' } })
    }
    const summary = {
      id, name: model.meta.title, assetCount: rows.length,
      generatedAt: model.meta.generatedAt, hash: model.integrity?.hash,
      quality: model.meta.snapshot?.validationStatus === 'validated' ? 'Validated' : 'Incomplete',
    }
    const { error } = await store.from('report_snapshots').insert({
      id, user_id: user!.id, organization_id: organizationId, report_family: 'asset',
      model, summary,
    })
    if (error) throw error
    return res.status(201).json({ data: model, meta: summary })
  } catch (error) {
    console.error('Asset report capture failed:', error)
    return res.status(503).json({ error: { message: 'The asset snapshot could not be captured and saved.' } })
  }
})

router.get('/asset-snapshots', async (req, res) => {
  const { token, user } = req as AuthedRequest
  try {
    const store = reportSnapshotClient(token!)
    const [history, organizations] = await Promise.all([
      store.from('report_snapshots').select('organization_id, summary')
        .eq('user_id', user!.id).eq('report_family', 'asset')
        .order('created_at', { ascending: false }).order('id', { ascending: false }).limit(20),
      getActiveReportOrganizationIds(store, user!.id).catch(() => []),
    ])
    if (history.error) throw history.error
    return res.json({ data: (history.data || [])
      .filter((row) => ownsReportOrganization(row.organization_id, organizations)).map((row) => row.summary) })
  } catch (error) {
    console.error('Asset report history failed:', error)
    return res.status(503).json({ error: { message: 'Saved asset report history is unavailable.' } })
  }
})

router.get('/asset-snapshots/:reportId', async (req, res) => {
  const id = reportIdSchema.safeParse(req.params.reportId)
  const notFound = () => res.status(404).json({ error: { message: 'Saved asset report not found.' } })
  if (!id.success) return notFound()
  const { token, user } = req as AuthedRequest
  try {
    const store = reportSnapshotClient(token!)
    const { data, error } = await store.from('report_snapshots').select('organization_id, model, summary')
      .eq('id', id.data).eq('user_id', user!.id).eq('report_family', 'asset').maybeSingle()
    if (error) throw error
    if (!data || (data.organization_id && !ownsReportOrganization(data.organization_id, await getActiveReportOrganizationIds(store, user!.id)))) return notFound()
    const model = data.model as InventoryReport
    const scope = model.meta.snapshot
    if (scope?.reportId !== id.data || scope.workspaceOwnerId !== user!.id || scope.organizationId !== data.organization_id
      || data.summary.hash !== model.integrity?.hash || model.integrity?.hash !== sha3Hex(canonicalAssetReport(model))) {
      throw new Error('Saved asset report integrity check failed')
    }
    return res.json({ data: model })
  } catch (error) {
    console.error('Saved asset report read failed:', error)
    return res.status(503).json({ error: { message: 'The saved asset report could not be read and validated.' } })
  }
})

router.get('/assets', async (req, res) => {
  const { token, user } = req as AuthedRequest
  try {
    const scanner = await buildScannerIntelligence(token!, user!.id, { fresh: true })
    if (scanner.mode !== 'database') {
      return res.status(503).json({ error: { code: 'INVENTORY_UNAVAILABLE', message: 'The registered asset inventory could not be read.' } })
    }
    return res.json({ data: listReportScopeAssets(scanner) })
  } catch (error) {
    console.error('Report scope read failed:', error)
    return res.status(503).json({ error: { code: 'INVENTORY_UNAVAILABLE', message: 'The registered asset inventory could not be read.' } })
  }
})

router.post('/generate', async (req, res) => {
  const request = captureSchema.safeParse(req.body ?? {})
  if (!request.success) {
    return res.status(400).json({ error: { code: 'INVALID_REPORT_REQUEST', message: 'Check the report format, template, branding and selected asset IDs.' } })
  }
  const { user, token } = req as AuthedRequest
  const { format, kind, branding, preview, scopeAssets } = request.data
  const assetIds = scopeAssets ? [...new Set(scopeAssets)] : null
  const ownerId = user!.id
  try {
    const client = reportSnapshotClient(token!)
    const startedAt = new Date().toISOString()
    const scanner = await buildScannerIntelligence(token!, ownerId, { fresh: true })
    if (scanner.mode !== 'database' || !scanner.reportVersions) {
      return res.status(503).json({ error: { code: 'INVENTORY_UNAVAILABLE', message: 'Reports require readable stored asset and cryptographic inventory.' } })
    }
    if (assetIds) {
      const registeredIds = new Set(listReportScopeAssets(scanner).map((asset) => asset.key))
      if (assetIds.some((id) => !registeredIds.has(id))) {
        return res.status(400).json({ error: { code: 'INVALID_REPORT_SCOPE', message: 'One or more selected assets are unavailable. Refresh the asset list and select the current records.' } })
      }
    }
    const [assessmentRead, supplemental, organizationRead] = await Promise.all([
      buildSnapshot(token!, ownerId, scanner).catch((error) => {
        console.warn('Report assessment sources unavailable:', error)
        return null
      }),
      loadReportOperationalEvidence(token!, ownerId, assetIds),
      getActiveReportOrganizationIds(client, ownerId).catch(() => null),
    ])
    const confirmation = await buildScannerIntelligence(token!, ownerId, { fresh: true }).catch(() => null)
    const scannerVerified = confirmation?.mode === 'database'
      && confirmation.reportVersions?.assetInventoryVersion === scanner.reportVersions.assetInventoryVersion
      && confirmation.reportVersions?.cbomVersion === scanner.reportVersions.cbomVersion
      && confirmation.reportVersions?.findingsVersion === scanner.reportVersions.findingsVersion
    if (confirmation?.mode === 'database' && !scannerVerified) {
      return res.status(409).json({ error: { code: 'REPORT_SOURCES_CHANGED', message: 'Asset, CBOM or finding records changed during capture. Generate again for the latest evidence.' } })
    }
    const snapshotAt = new Date().toISOString()
    const organizationId = organizationRead?.length === 1 ? organizationRead[0] : null
    const provenance: ReportProvenance = {
      reportId: randomUUID(),
      workspaceOwnerId: ownerId,
      organizationId,
      snapshotAt,
      assetInventoryVersion: scanner.reportVersions.assetInventoryVersion,
      cbomVersion: scanner.reportVersions.cbomVersion,
      assessmentId: assetIds ? null : assessmentReference(scanner, assessmentRead),
      validationStatus: scannerVerified ? 'validated' : 'incomplete',
      dataCompleteness: [
        {
          source: 'Source consistency',
          status: scannerVerified ? 'available' : 'partial',
          detail: `${scannerVerified ? 'Asset, CBOM and scanner finding versions matched the confirmation read.' : 'The scanner confirmation read did not complete.'} Sources were read separately between ${startedAt} and ${snapshotAt} UTC.`,
        },
        {
          source: 'Organization membership',
          status: organizationId ? 'available' : 'missing',
          detail: organizationId
            ? 'One active organization membership was verified. Evidence is scoped to the signed-in account.'
            : 'A unique active membership could not be verified. Evidence is scoped to the signed-in account.',
        },
      ],
    }
    const model = evidenceAssessmentReportSchema.parse(buildReadinessReportModel({
      scanner, assessment: assessmentRead, assetIds, branding, kind,
      generatedBy: user!.email || 'QGuard Helix', provenance, supplemental,
    }))
    model.integrity = { algorithm: 'SHA3-256', hash: readinessReportDigest(model), signedAt: snapshotAt }
    if (!preview) await saveReadinessReport(client, ownerId, model, format)
    return res.status(preview ? 200 : 201).json({ data: model, meta: { format, saved: !preview } })
  } catch (error) {
    console.error('Report capture failed:', error)
    return res.status(503).json({ error: { code: 'REPORT_GENERATION_FAILED', message: 'The report could not be captured. Try again when evidence and report storage are available.' } })
  }
})

/* ------------------------------------------------------------------ */
/* Report & advisory audit trail                                       */
/* ------------------------------------------------------------------ */
/*
 * The Report Center's "Report History — versioning & audit trail" lived in one
 * browser's localStorage under a key shared by every account that signed in on
 * that browser, so it was neither an audit trail nor tenant-scoped. The AI
 * Executive Advisor's "Approve for Report" and its "Advisory Audit Trail" were
 * React state, gone on reload. Both now append to the tenant's `audit_logs`
 * (RLS: user_id = auth.uid()), the same table governance reads as evidence.
 * Bodies are validated and bounded — nothing the client sends is trusted raw.
 */
const REPORT_ENTITY = 'quantum_readiness_report'
const ADVISORY_ENTITY = 'executive_advisory'
const ADVISORY_ACTIONS = ['executive_advisory_generated', 'executive_advisory_approved'] as const

const boundedText = (value: unknown, max: number) => (typeof value === 'string' ? value.trim().slice(0, max) : '')
const score100 = (value: unknown) => {
  const n = Number(value)
  return Number.isFinite(n) ? Math.max(0, Math.min(100, Math.round(n))) : null
}
const isoOrNull = (value: unknown) => {
  const text = boundedText(value, 40)
  return text && Number.isFinite(Date.parse(text)) ? new Date(text).toISOString() : null
}

router.get('/history', async (req, res) => {
  const { user, token } = req as AuthedRequest
  const advisory = req.query.type === 'advisory'
  try {
    const client = createAuthClient(token!)
    if (!client) throw new Error('Database connection failed')
    const readLegacy = client.from('audit_logs')
      .select('id, action, details, created_at')
      .eq('user_id', user!.id)
      .eq('entity_type', advisory ? ADVISORY_ENTITY : REPORT_ENTITY)
      .order('created_at', { ascending: false })
      .limit(60)
    if (advisory) {
      const { data, error } = await readLegacy
      if (error) throw error
      return res.json({ data: (data || []).map((row) => ({
        ...(row.details || {}), id: row.id, action: row.action, createdAt: row.created_at,
      })) })
    }

    const store = reportSnapshotClient(token!)
    const [legacy, saved, activeOrganizations] = await Promise.all([
      readLegacy,
      store.from('report_snapshots').select('id, organization_id, summary, created_at')
        .eq('user_id', user!.id).eq('report_family', READINESS_REPORT_FAMILY)
        .order('created_at', { ascending: false }).order('id', { ascending: false }).limit(60),
      getActiveReportOrganizationIds(store, user!.id).catch(() => []),
    ])
    if (saved.error) throw saved.error
    const snapshots = (saved.data || [])
      .filter((row) => ownsReportOrganization(row.organization_id, activeOrganizations))
      .map((row) => ({ ...row.summary, id: row.id, action: 'report_generated', createdAt: row.created_at }))
    // Pre-migration rows are an activity log. Client-authored details must
    // never masquerade as a saved model or server-verified provenance.
    const prior = (legacy.data || []).map((row) => ({
      id: row.id, action: row.action, createdAt: row.created_at,
      title: boundedText(row.details?.title, 200),
      kind: boundedText(row.details?.kind, 40),
      format: boundedText(row.details?.format, 12),
      version: boundedText(row.details?.version, 32),
      generatedBy: boundedText(row.details?.generatedBy, 160),
    }))
    const data = [...snapshots, ...prior].sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, 60)
    return res.json({ data })
  } catch (error) {
    console.error('Report history read failed:', error)
    return res.status(503).json({ error: { code: 'HISTORY_READ_FAILED', message: 'Report history is unavailable.' } })
  }
})

router.get('/:reportId', async (req, res) => {
  const id = reportIdSchema.safeParse(req.params.reportId)
  const notFound = () => res.status(404).json({ error: { code: 'REPORT_NOT_FOUND', message: 'Saved report not found.' } })
  if (!id.success) return notFound()
  const { user, token } = req as AuthedRequest
  try {
    const client = reportSnapshotClient(token!)
    const { data, error } = await client.from('report_snapshots').select('organization_id, model')
      .eq('id', id.data).eq('user_id', user!.id).eq('report_family', READINESS_REPORT_FAMILY).maybeSingle()
    if (error) throw error
    if (!data) return notFound()
    if (data.organization_id !== null &&
      !ownsReportOrganization(data.organization_id, await getActiveReportOrganizationIds(client, user!.id))) return notFound()
    const model = evidenceAssessmentReportSchema.parse(data.model)
    if (model.meta.id !== id.data || model.provenance.reportId !== id.data
      || model.provenance.workspaceOwnerId !== user!.id || model.provenance.organizationId !== data.organization_id
      || model.integrity?.hash !== readinessReportDigest(model)) {
      throw new Error('Saved report integrity check failed')
    }
    return res.json({ data: model })
  } catch (error) {
    console.error('Saved report read failed:', error)
    return res.status(503).json({ error: { code: 'REPORT_READ_FAILED', message: 'The saved report could not be read and validated.' } })
  }
})

router.post('/advisories', async (req: Request, res: Response) => {
  try {
    const { user, token } = req as AuthedRequest
    const body = req.body || {}
    const action = `executive_advisory_${String(body.action || '')}`
    if (!ADVISORY_ACTIONS.includes(action as (typeof ADVISORY_ACTIONS)[number])) {
      return res.status(400).json({ error: { code: 'INVALID_ACTION', message: 'action must be generated or approved' } })
    }
    const advisoryId = boundedText(body.advisoryId, 80)
    if (!/^[A-Za-z0-9_-]{4,80}$/.test(advisoryId)) return res.status(400).json({ error: { code: 'INVALID_ID', message: 'advisoryId is required' } })
    const validation = body.validation === 'PASS' ? 'PASS' : 'FAIL'
    const details = {
      advisoryId,
      readiness: score100(body.readiness),
      risk: score100(body.risk),
      validation,
      assessmentAt: isoOrNull(body.assessmentAt),
      actor: user!.email || 'owner',
    }
    const client = createAuthClient(token!)
    if (!client) return res.status(500).json({ error: { code: 'DB_UNAVAILABLE', message: 'Database connection failed' } })
    const { data, error } = await client
      .from('audit_logs')
      .insert({ user_id: user!.id, action, entity_type: ADVISORY_ENTITY, details })
      .select('id, created_at')
      .single()
    if (error) return res.status(500).json({ error: { code: 'ADVISORY_WRITE_FAILED', message: error.message } })
    return res.status(201).json({ data: { id: data?.id, createdAt: data?.created_at, action, ...details } })
  } catch (error) {
    console.error('Advisory audit write failed:', error)
    return res.status(500).json({ error: { code: 'ADVISORY_WRITE_FAILED', message: 'Failed to record the advisory' } })
  }
})

export default router
