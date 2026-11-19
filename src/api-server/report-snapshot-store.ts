import type { SupabaseClient } from '@supabase/supabase-js'
import { getWorkspaceServiceClient } from '@/lib/supabase-server'
import { sha3Hex } from '@/services/reporting/ReportIntegrity'
import type { EvidenceAssessmentReport, ReportFormat } from '@/services/reporting/schemas/ReportSchema'

export function reportSnapshotDigest(value: unknown): string {
  // JSONB may reorder object keys. Preserve array order and hash the same
  // canonical JSON before insertion and after retrieval.
  return sha3Hex(JSON.stringify(value, (_key, field: unknown) => {
    if (field === null || typeof field !== 'object' || Array.isArray(field)) return field
    return Object.fromEntries(Object.entries(field).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0))
  }))
}

export function readinessReportDigest(model: EvidenceAssessmentReport): string {
  const { integrity: _integrity, provenance, ...content } = model
  const { workspaceOwnerId: _workspaceOwnerId, ...exported } = provenance
  return reportSnapshotDigest({ ...content, provenance: exported })
}

export function reportSnapshotClient(token: string) {
  const client = getWorkspaceServiceClient(token)
  if (!client) throw new Error('Report storage is unavailable')
  return client
}

export async function getActiveReportOrganizationIds(client: SupabaseClient, userId: string): Promise<string[]> {
  const { data, error } = await client.from('organization_members')
    .select('organization_id, organizations!inner(status)')
    .eq('user_id', userId).eq('status', 'active').eq('organizations.status', 'active')
  if (error) throw error
  return [...new Set((data || []).map((row) => row.organization_id as string))]
}

export async function getReportOrganizationId(token: string, userId: string): Promise<string | null> {
  const organizations = await getActiveReportOrganizationIds(reportSnapshotClient(token), userId)
  return organizations.length === 1 ? organizations[0] : null
}

export const READINESS_REPORT_FAMILY = 'readiness'

export async function saveReadinessReport(client: SupabaseClient, userId: string, model: EvidenceAssessmentReport, format: ReportFormat) {
  if (model.provenance.workspaceOwnerId !== userId || model.provenance.reportId !== model.meta.id) {
    throw new Error('Report provenance does not match its storage scope')
  }
  const { error } = await client.from('report_snapshots').insert({
    id: model.meta.id,
    user_id: userId,
    organization_id: model.provenance.organizationId,
    report_family: READINESS_REPORT_FAMILY,
    summary: {
      reportId: model.meta.id,
      kind: model.meta.kind,
      title: model.meta.title,
      format,
      version: model.meta.version,
      scope: model.scope.type === 'custom' ? `${model.scope.selectedAssetCount} selected assets` : 'Full workspace',
      generatedAt: model.meta.generatedAt,
      generatedBy: model.meta.generatedBy,
      integrityHash: model.integrity?.hash,
      provenance: model.provenance,
    },
    model,
  })
  if (error) throw error
}

export function ownsReportOrganization(organizationId: string | null, activeOrganizations: string[]) {
  return organizationId === null || activeOrganizations.includes(organizationId)
}
