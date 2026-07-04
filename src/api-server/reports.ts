import { Router, Request, Response, NextFunction } from 'express'
import { getServerUser, getToken } from '@/lib/supabase-server'
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

export default router
