import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildSnapshot } from './quantum-readiness'
import { buildReportModel } from '@/services/reporting/ReportEvidence'
import { buildReportScope, scopeSnapshotToAssets } from '@/services/reporting/ReportScope'
import { brandingSchema, REPORT_FORMATS, REPORT_KINDS, type ReportKind } from '@/services/reporting/schemas/ReportSchema'

/**
 * Enterprise Reporting Engine™ — Phase 8 export API.
 *
 * `POST /api/v1/reports/generate` assembles the unified, tenant-scoped
 * EnterpriseAssessmentReport model from real Quantum Readiness assessment
 * evidence. The JSON model is the single source of truth; binary renderings
 * (PDF/DOCX/XLSX/PPTX/HTML, incl. embedded charts) are produced by the client
 * reporting engine, which requires a browser canvas for chart rasterisation.
 */

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

router.use(requireAuth)

router.post('/generate', async (req: Request, res: Response) => {
  try {
    const { user, token } = req as AuthedRequest
    const body = req.body || {}

    const format = String(body.format || 'json').toLowerCase()
    if (!REPORT_FORMATS.includes(format as never)) {
      return res.status(400).json({ error: { code: 'INVALID_FORMAT', message: `Unsupported format. Supported: ${REPORT_FORMATS.join(', ')}` } })
    }
    const kind: ReportKind = REPORT_KINDS.includes(body.kind) ? body.kind : 'executive'
    const branding = brandingSchema.parse(body.branding || {})

    // Optional asset scope — names/keys of assets the report should cover.
    const scopeAssets: string[] | null = Array.isArray(body.scopeAssets)
      ? body.scopeAssets.map((a: unknown) => String(a)).filter(Boolean)
      : null

    const snapshot = await buildSnapshot(token!, user!.id)
    const scope = buildReportScope(snapshot, scopeAssets?.length ? scopeAssets : null)
    const effectiveSnapshot = scope.type === 'custom' ? scopeSnapshotToAssets(snapshot, scopeAssets!) : snapshot
    const model = buildReportModel(effectiveSnapshot, branding, kind, user!.email || 'QGuard Helix', scope)

    return res.json({
      data: model,
      meta: {
        format,
        binaryRenderedClientSide: format !== 'json',
        note: format !== 'json'
          ? 'Binary formats (pdf, docx, xlsx, pptx, html) with embedded charts are rendered by the client reporting engine from this model.'
          : undefined,
      },
    })
  } catch (error) {
    console.error('Report generation error:', error)
    return res.status(500).json({ error: { code: 'REPORT_GENERATION_FAILED', message: error instanceof Error ? error.message : 'Failed to generate report model' } })
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

router.get('/history', async (req: Request, res: Response) => {
  try {
    const { user, token } = req as AuthedRequest
    const client = createAuthClient(token!)
    if (!client) return res.status(500).json({ error: { code: 'DB_UNAVAILABLE', message: 'Database connection failed' } })
    const type = req.query.type === 'advisory' ? ADVISORY_ENTITY : REPORT_ENTITY
    const { data, error } = await client
      .from('audit_logs')
      .select('id, action, details, created_at')
      .eq('user_id', user!.id)
      .eq('entity_type', type)
      .order('created_at', { ascending: false })
      .limit(60)
    if (error) return res.status(500).json({ error: { code: 'HISTORY_READ_FAILED', message: error.message } })
    return res.json({ data: (data || []).map((row) => ({ id: row.id, action: row.action, createdAt: row.created_at, ...(row.details || {}) })) })
  } catch (error) {
    console.error('Report history read failed:', error)
    return res.status(500).json({ error: { code: 'HISTORY_READ_FAILED', message: 'Failed to read report history' } })
  }
})

router.post('/history', async (req: Request, res: Response) => {
  try {
    const { user, token } = req as AuthedRequest
    const body = req.body || {}
    const kind = String(body.kind || '')
    const format = String(body.format || '').toLowerCase()
    if (!REPORT_KINDS.includes(kind as ReportKind)) return res.status(400).json({ error: { code: 'INVALID_KIND', message: 'Unknown report kind' } })
    if (!REPORT_FORMATS.includes(format as never)) return res.status(400).json({ error: { code: 'INVALID_FORMAT', message: 'Unknown report format' } })
    const integrityHash = boundedText(body.integrityHash, 128).toLowerCase()
    if (integrityHash && !/^[0-9a-f]{8,128}$/.test(integrityHash)) return res.status(400).json({ error: { code: 'INVALID_HASH', message: 'integrityHash must be hex' } })
    const details = {
      reportId: boundedText(body.reportId, 80),
      kind,
      format,
      title: boundedText(body.title, 200),
      version: boundedText(body.version, 20),
      scope: boundedText(body.scope, 120),
      integrityHash,
      generatedAt: isoOrNull(body.generatedAt) || new Date().toISOString(),
      generatedBy: user!.email || 'owner',
    }
    const client = createAuthClient(token!)
    if (!client) return res.status(500).json({ error: { code: 'DB_UNAVAILABLE', message: 'Database connection failed' } })
    const { data, error } = await client
      .from('audit_logs')
      .insert({ user_id: user!.id, action: 'report_generated', entity_type: REPORT_ENTITY, details })
      .select('id, created_at')
      .single()
    if (error) return res.status(500).json({ error: { code: 'HISTORY_WRITE_FAILED', message: error.message } })
    return res.status(201).json({ data: { id: data?.id, createdAt: data?.created_at, action: 'report_generated', ...details } })
  } catch (error) {
    console.error('Report history write failed:', error)
    return res.status(500).json({ error: { code: 'HISTORY_WRITE_FAILED', message: 'Failed to record report generation' } })
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
