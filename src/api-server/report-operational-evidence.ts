import { createAuthClient } from '@/lib/supabase-server'
import { isSimulationJob, jobPlanId } from '@/lib/migration/job-safety'
import { indexJobValidations, orchestrationStatus, readJobVerification } from '@/lib/migration/orchestration-model'

type Cell = string | number
type ReportTable = { title: string; columns: string[]; rows: Cell[][] }
type Completeness = { source: string; status: 'available' | 'missing' | 'partial'; detail: string }
type OperationalEvidence = { tables: ReportTable[]; dataCompleteness: Completeness[] }
type Client = NonNullable<ReturnType<typeof createAuthClient>>
type Row = Record<string, unknown> & { id: string; job_type?: unknown; name?: unknown; metadata?: unknown }
type Read = { rows: Row[]; status: 'available' | 'missing' | 'partial' }

const PAGE_SIZE = 400
const MAX_JOBS = 2000
const MAX_VALIDATIONS = 4000
const MAX_GOVERNANCE_ROWS = 2000
const MAX_DETAIL_ROWS = 500
const EMPTY_READ: Read = { rows: [], status: 'available' }
const SOURCES = [
  'Migration jobs',
  'Migration plans',
  'Migration validation records',
  'Compliance evidence records',
  'Governance control assessments',
] as const

const value = (input: unknown): string => typeof input === 'string' && input.trim() ? input : 'Unavailable'
const record = (input: unknown): Record<string, unknown> =>
  input && typeof input === 'object' && !Array.isArray(input) ? input as Record<string, unknown> : {}

/**
 * Keyset pagination uses the immutable primary key so edits to updated_at do
 * not move records across page boundaries. A failed page invalidates the read,
 * and the extra row distinguishes a complete read from a capped one.
 */
async function readRows(client: Client, userId: string, table: string, columns: string, cap: number): Promise<Read> {
  const rows: Row[] = []
  try {
    let after: string | null = null
    while (rows.length <= cap) {
      const size = Math.min(PAGE_SIZE, cap + 1 - rows.length)
      let query = client.from(table).select(columns).eq('user_id', userId).order('id').limit(size)
      if (after) query = query.gt('id', after)
      const { data, error } = await query
      if (error || !Array.isArray(data)) return { rows: [], status: 'missing' }
      const page = data as unknown as Row[]
      rows.push(...page)
      if (page.length < size) break
      after = page[page.length - 1].id
    }
  } catch {
    return { rows: [], status: 'missing' }
  }
  return { rows: rows.slice(0, cap), status: rows.length > cap ? 'partial' : 'available' }
}

function completeness(source: string, read: Read, rows: Row[], extra = ''): Completeness {
  if (read.status === 'missing') return { source, status: 'missing', detail: 'The source could not be read.' }
  const partial = read.status === 'partial'
  const detailCapped = rows.length > MAX_DETAIL_ROWS
  const countDetail = rows.length
    ? `${partial ? 'At least ' : ''}${rows.length.toLocaleString('en-US')} matching records read.`
    : partial ? 'No matches in the bounded read. Additional records may exist.' : 'No matching records recorded.'
  const capDetail = partial ? ' The source exceeded the capture limit.' : ''
  const presentationDetail = detailCapped ? ` Showing the ${MAX_DETAIL_ROWS} most recent detail rows.` : ''
  return {
    source,
    status: partial || detailCapped ? 'partial' : 'available',
    detail: `${countDetail}${capDetail}${presentationDetail}${extra ? ` ${extra}` : ''}`,
  }
}

function recent(rows: Row[], column: string): Row[] {
  return [...rows]
    .sort((a, b) => (Date.parse(value(b[column])) || 0) - (Date.parse(value(a[column])) || 0) || b.id.localeCompare(a.id))
    .slice(0, MAX_DETAIL_ROWS)
}

export async function loadReportOperationalEvidence(
  token: string,
  userId: string,
  assetIds: string[] | null,
): Promise<OperationalEvidence> {
  const client = createAuthClient(token)
  if (!client || assetIds?.length === 0) {
    const detail = client ? 'No selected asset could be matched to a registered asset ID.' : 'The source connection is unavailable.'
    return { tables: [], dataCompleteness: SOURCES.map((source) => ({ source, status: 'missing', detail })) }
  }
  const scope = assetIds === null ? null : new Set(assetIds)
  const inScope = (row: Row) => !scope || (typeof row.asset_id === 'string' && scope.has(row.asset_id))
  const [jobRead, planRead, complianceRead, assessmentRead] = await Promise.all([
    readRows(client, userId, 'migration_jobs', 'id,asset_id,name,job_type,status,progress,metadata,updated_at', MAX_JOBS),
    readRows(client, userId, 'migration_plans', 'id,status,selected_asset_ids,metadata,approved_at,scheduled_at,updated_at', MAX_JOBS),
    readRows(client, userId, 'compliance_evidence', 'id,asset_id,framework,control_id,evidence_type,status,updated_at', MAX_GOVERNANCE_ROWS),
    scope ? EMPTY_READ : readRows(client, userId, 'governance_control_assessments',
      'id,control_id,attested_at,exception_approved_at,exception_expires_at,updated_at', MAX_GOVERNANCE_ROWS),
  ])
  const jobs = jobRead.rows.filter((row) => inScope(row) && !isSimulationJob(row))
  const planIds = new Set(jobs.map(jobPlanId).filter(Boolean))
  const plans = planRead.rows.filter((row) => row.id !== `asset-queue-${userId}` && !isSimulationJob(row) && (
    !scope || planIds.has(row.id)
    || (Array.isArray(row.selected_asset_ids) && row.selected_asset_ids.some((id) => scope.has(id)))
  ))
  const validationRead = jobs.length
    ? await readRows(client, userId, 'migration_validation_logs', 'id,migration_id,validation_type,status,created_at', MAX_VALIDATIONS)
    : EMPTY_READ
  const jobIds = new Set(jobs.map((job) => job.id))
  const validations = validationRead.rows.filter((row) => typeof row.migration_id === 'string' && jobIds.has(row.migration_id))
  const validationIndex = indexJobValidations(validations)
  const compliance = complianceRead.rows.filter(inScope)
  const assessments = assessmentRead.rows
  const tables: ReportTable[] = []

  if (jobRead.status === 'available') {
    const statuses = jobs.map((job) => orchestrationStatus(job.status))
    const completed = statuses.filter((status) => status === 'completed').length
    const failed = statuses.filter((status) => status === 'failed').length
    const cancelled = statuses.filter((status) => status === 'stopped').length
    const active = statuses.filter((status) => status === 'running' || status === 'validating').length
    const pending = statuses.filter((status) => status === 'queued' || status === 'paused').length
    const rollback = jobs.length - completed - failed - cancelled - active - pending
    const denominator = jobs.length - cancelled
    tables.push({
      title: 'Recorded migration and remediation activity',
      columns: ['Measure', 'Value', 'Basis'],
      rows: [
        ['Operational jobs', jobs.length, 'Persisted jobs in scope, excluding simulation and dry runs'],
        ['Pending or paused', pending, 'Queued, held, or paused jobs'],
        ['Running or validating', active, 'Executor and validation activity'],
        ['Completed by executor', completed, 'Completion recorded in migration_jobs'],
        ['Failed', failed, 'Failure recorded in migration_jobs'],
        ['Cancelled', cancelled, 'Excluded from the completion denominator'],
        ['Rollback', rollback, 'Rollback requested or recorded'],
        ['Completion rate', denominator ? `${Math.round(100 * completed / denominator)}%` : 'Unavailable', 'Executor completions divided by operational jobs excluding cancelled jobs'],
        ['Completed with a passing validation log',
          validationRead.status === 'available'
            ? jobs.filter((job, index) => statuses[index] === 'completed'
              && readJobVerification({ id: job.id }, validationIndex, 'ok', true).state === 'passed').length
            : 'Unavailable',
          'Completed jobs whose most recent migration_validation_logs record passes'],
      ],
    })
  }

  if (jobs.length) tables.push({
    title: 'Operational migration job records',
    columns: ['Job ID', 'Asset ID', 'Plan ID', 'Job type', 'Recorded status', 'Recorded progress', 'Latest recorded validation', 'Updated at (UTC)'],
    rows: recent(jobs, 'updated_at').map((job) => [
      job.id, value(job.asset_id), value(jobPlanId(job)), value(job.job_type), value(job.status),
      typeof job.progress === 'number' && job.progress >= 0 && job.progress <= 100 ? `${job.progress}%` : 'Unavailable',
      validationRead.status === 'available' ? value(validationIndex.get(job.id)?.latest.status) : 'Unavailable',
      value(job.updated_at),
    ]),
  })
  if (plans.length) tables.push({
    title: 'Recorded migration plans',
    columns: ['Plan ID', 'Plan name', 'Recorded status', 'Approved at (UTC)', 'Scheduled at (UTC)', 'Updated at (UTC)'],
    rows: recent(plans, 'updated_at').map((plan) => [
      plan.id, value(record(plan.metadata).name), value(plan.status), value(plan.approved_at), value(plan.scheduled_at), value(plan.updated_at),
    ]),
  })
  if (validations.length) tables.push({
    title: 'Migration validation evidence',
    columns: ['Validation ID', 'Job ID', 'Validation type', 'Recorded result', 'Recorded at (UTC)'],
    rows: recent(validations, 'created_at').map((row) => [
      row.id, value(row.migration_id), value(row.validation_type), value(row.status), value(row.created_at),
    ]),
  })
  if (compliance.length) tables.push({
    title: 'Recorded compliance evidence',
    columns: ['Evidence ID', 'Asset ID', 'Framework', 'Control', 'Evidence type', 'Recorded status', 'Updated at (UTC)'],
    rows: recent(compliance, 'updated_at').map((row) => [
      row.id, value(row.asset_id), value(row.framework), value(row.control_id), value(row.evidence_type), value(row.status), value(row.updated_at),
    ]),
  })
  if (assessments.length) tables.push({
    title: 'Recorded governance attestations and exceptions',
    columns: ['Assessment ID', 'Control', 'Attested at (UTC)', 'Exception approved at (UTC)', 'Exception expires at (UTC)', 'Updated at (UTC)'],
    rows: recent(assessments, 'updated_at').map((row) => [
      row.id, value(row.control_id), value(row.attested_at), value(row.exception_approved_at), value(row.exception_expires_at), value(row.updated_at),
    ]),
  })
  return {
    tables,
    dataCompleteness: [
      completeness(SOURCES[0], jobRead, jobs, 'Executions flagged as simulations are excluded.'),
      completeness(SOURCES[1], planRead, plans),
      jobRead.status !== 'available' && !jobs.length
        ? { source: SOURCES[2], status: 'missing', detail: 'Operational jobs could not be resolved for validation lookup.' }
        : completeness(SOURCES[2], jobRead.status === 'partial' && validationRead.status === 'available'
          ? { ...validationRead, status: 'partial' } : validationRead, validations, 'Restricted to in-scope operational jobs.'),
      completeness(SOURCES[3], complianceRead, compliance, 'Statuses are those recorded on individual evidence entries.'),
      scope ? { source: SOURCES[4], status: 'missing', detail: 'Governance control assessments are workspace-wide and carry no asset IDs.' }
        : completeness(SOURCES[4], assessmentRead, assessments),
    ],
  }
}
