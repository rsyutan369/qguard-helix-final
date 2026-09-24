import { useEffect, useMemo, useState } from 'react'
import { Ban, Clock3, Download, Eye, History, RefreshCw, Search, UserCog, Users, X } from 'lucide-react'
import type { AdminDashboard } from '@/hooks/use-admin-dashboard'
import { Chip, SelectField, formatCount, formatDateTime, timeAgo, useNow, type Tone } from '../_shared/primitives'
import { ConsoleHeader, EmptyState, ErrorBanner, Kpi, KpiGrid, Pager, ProvenanceNote } from '../_shared/console'

const RESULT_TONE: Record<string, Tone> = { completed: 'ok', recorded: 'neutral', warning: 'warn', blocked: 'bad', failed: 'bad' }
const CATEGORY_LABEL: Record<string, string> = {
  users: 'Users', roles: 'Roles', tenants: 'Tenants', billing: 'Billing', governance: 'Governance', security: 'Access denied', exports: 'Exports', views: 'Console views', other: 'Other', platform: 'Platform',
}

const SINCE_OPTIONS: Array<[string, string, number | null]> = [
  ['', 'Any time', null],
  ['24h', 'Last 24 hours', 24],
  ['7d', 'Last 7 days', 24 * 7],
  ['30d', 'Last 30 days', 24 * 30],
]

export function HistoryTab({ admin }: { admin: AdminDashboard }) {
  const resource = admin.history
  const { data, query } = resource
  const now = useNow()
  const [actorDraft, setActorDraft] = useState(query.actor)
  const [searchDraft, setSearchDraft] = useState(query.search)
  const [sinceKey, setSinceKey] = useState('')
  const { ensureLoaded } = resource
  useEffect(() => { ensureLoaded() }, [ensureLoaded])
  const stats = data?.stats
  const adminSource = query.source === 'admin'

  // Debounce free-text filters into the query (the resource refetches from page 1).
  useEffect(() => {
    const handle = window.setTimeout(() => {
      if (actorDraft !== query.actor || searchDraft !== query.search) resource.setQuery({ actor: actorDraft, search: searchDraft })
    }, 300)
    return () => window.clearTimeout(handle)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [actorDraft, searchDraft])

  const setSince = (key: string) => {
    setSinceKey(key)
    const hours = SINCE_OPTIONS.find(([value]) => value === key)?.[2] ?? null
    resource.setQuery({ since: hours ? new Date(Date.now() - hours * 3_600_000).toISOString() : '' })
  }

  const activeFilters = useMemo(() => [
    query.category !== 'all', Boolean(query.actor), Boolean(query.search), Boolean(query.since), query.includeViews === '1',
  ].filter(Boolean).length, [query])

  const reset = () => {
    setActorDraft('')
    setSearchDraft('')
    setSinceKey('')
    resource.setQuery({ category: 'all', actor: '', search: '', since: '', includeViews: '0' })
  }

  return (
    <div className="qgu space-y-5">
      <ConsoleHeader
        title="History"
        description="Every administrator action — who did it, to what, and the result — plus the platform's own event streams."
        admin={admin}
        updatedAt={data?.generatedAt}
        actions={(
          <>
            <button type="button" className="qgu-btn" onClick={() => void admin.exportHistory()} disabled={admin.mutating === 'export-history'}>
              <Download className="h-4 w-4" />
              Export CSV
            </button>
            <button type="button" className="qgu-btn" onClick={() => void resource.refresh()} disabled={resource.loading}>
              <RefreshCw className={`h-4 w-4 ${resource.loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </>
        )}
      />

      <KpiGrid loading={!stats} count={5}>
        {stats && (
          <>
            <Kpi icon={<UserCog className="h-4 w-4" />} label="Admin actions · 7d" value={formatCount(stats.last7d)} sub={stats.blocked7d ? `by ${stats.actors7d} account(s), incl. refused attempts` : `by ${stats.actors7d} account(s)`} onClick={reset} active={activeFilters === 0 && adminSource} />
            <Kpi icon={<Ban className="h-4 w-4" />} label="Blocked / failed · 7d" value={formatCount(stats.blocked7d)} sub="refused access or failed actions" subTone={stats.blocked7d ? 'warn' : undefined} onClick={() => resource.setQuery({ source: 'admin', category: 'security' })} active={query.category === 'security'} />
            <Kpi icon={<Eye className="h-4 w-4" />} label="Console views · 7d" value={formatCount(stats.views7d)} sub="recorded, hidden by default" onClick={() => resource.setQuery({ source: 'admin', category: 'views' })} active={query.category === 'views'} />
            <Kpi icon={<History className="h-4 w-4" />} label="Audit records" value={formatCount(stats.totalRecords)} sub={stats.oldestAt ? `since ${formatDateTime(stats.oldestAt)}` : 'none'} />
            <Kpi icon={<Clock3 className="h-4 w-4" />} label="Latest record" value={stats.latestAt ? timeAgo(stats.latestAt, now) : '—'} sub={stats.latestAt ? formatDateTime(stats.latestAt) : 'nothing recorded'} />
          </>
        )}
      </KpiGrid>

      <div className="qgu-panel space-y-3 p-4">
        <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-[200px_200px_minmax(0,1fr)_minmax(0,1fr)_180px]">
          <SelectField label="Source" value={query.source} onChange={(value) => resource.setQuery({ source: value, category: 'all' })}>
            <option value="admin">Administrator actions</option>
            <option value="security">Security events</option>
            <option value="billing">Billing events</option>
            <option value="migration">Migration events</option>
          </SelectField>
          <SelectField label="Category" value={query.category} onChange={(value) => resource.setQuery({ category: value })} className={adminSource ? '' : 'opacity-50'}>
            <option value="all">All categories{stats ? '' : ''}</option>
            {['users', 'roles', 'tenants', 'billing', 'governance', 'security', 'exports', 'views'].map((category) => (
              <option key={category} value={category} disabled={!adminSource}>{CATEGORY_LABEL[category]}{adminSource && stats?.byCategory[category] !== undefined ? ` (${stats.byCategory[category]} · 7d)` : ''}</option>
            ))}
          </SelectField>
          <div className="relative">
            <Users className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 qgu-muted" aria-hidden />
            <input className="qgu-field pl-9" aria-label="Filter by actor" placeholder={adminSource ? 'Actor email' : 'Actor (admin source only)'} disabled={!adminSource} value={actorDraft} onChange={(event) => setActorDraft(event.target.value)} />
          </div>
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 qgu-muted" aria-hidden />
            <input className="qgu-field pl-9" aria-label="Search history" placeholder={adminSource ? 'Action, target id or type' : 'Event type or message'} value={searchDraft} onChange={(event) => setSearchDraft(event.target.value)} />
          </div>
          <SelectField label="Time range" value={sinceKey} onChange={setSince}>
            {SINCE_OPTIONS.map(([value, label]) => <option key={value || 'any'} value={value}>{label}</option>)}
          </SelectField>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-xs qgu-soft">
          {adminSource && query.category === 'all' && (
            <label className="inline-flex items-center gap-2">
              <input type="checkbox" checked={query.includeViews === '1'} onChange={(event) => resource.setQuery({ includeViews: event.target.checked ? '1' : '0' })} />
              Include console views (page loads, stream connects, user inspections)
            </label>
          )}
          {activeFilters > 0 && (
            <button type="button" className="qgu-btn qgu-btn--ghost min-h-0 px-2 py-1 text-xs" onClick={reset}><X className="h-3.5 w-3.5" />Clear filters</button>
          )}
          {data && <span className="ml-auto">{formatCount(data.pagination.total)} matching record(s)</span>}
        </div>
      </div>

      <div className="qgu-panel overflow-hidden">
        {resource.error && <div className="m-4"><ErrorBanner message={`History could not be loaded: ${resource.error}`} onRetry={() => void resource.refresh()} /></div>}
        <div className="max-h-[70vh] overflow-auto">
          <table className="qgu-table min-w-[1060px]">
            <thead>
              <tr>
                <th scope="col">When</th>
                <th scope="col">Actor</th>
                <th scope="col">Action</th>
                <th scope="col">Target</th>
                <th scope="col">Result</th>
                <th scope="col">Detail</th>
              </tr>
            </thead>
            <tbody aria-busy={resource.loading}>
              {!data && !resource.error ? (
                Array.from({ length: 6 }, (_, index) => <tr key={index}><td colSpan={6}><div className="qgu-skeleton h-8" /></td></tr>)
              ) : data && data.entries.length === 0 ? (
                <tr><td colSpan={6}><EmptyState icon={<History className="h-6 w-6" />} title="No records match" body={activeFilters ? 'Widen or clear the filters.' : 'Records appear as soon as an administrator acts or the platform records an event.'} action={activeFilters ? <button type="button" className="qgu-btn" onClick={reset}>Clear filters</button> : undefined} /></td></tr>
              ) : data?.entries.map((entry) => (
                <tr key={entry.id}>
                  <td className="whitespace-nowrap text-xs">
                    <div className="font-mono font-bold qgu-strong">{formatDateTime(entry.at)}</div>
                    <div className="qgu-muted">{timeAgo(entry.at, now)}</div>
                  </td>
                  <td className="text-xs">
                    <div className="max-w-[220px] truncate font-bold qgu-strong">{entry.actor || <span className="qgu-muted">System</span>}</div>
                    <div className="font-mono qgu-muted">{entry.actorIp || 'IP not recorded'}</div>
                  </td>
                  <td>
                    <div className="text-sm font-bold qgu-strong">{entry.actionLabel}</div>
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Chip tone="neutral">{CATEGORY_LABEL[entry.category] || entry.category}</Chip>
                      <span className="font-mono text-[10px] qgu-muted">{entry.action}</span>
                    </div>
                  </td>
                  <td className="text-xs">
                    <div className="max-w-[260px] break-words qgu-strong">{entry.target || '—'}</div>
                    {(entry.targetType || entry.targetId) && <div className="max-w-[260px] break-all font-mono text-[10px] qgu-muted">{[entry.targetType, entry.targetId].filter(Boolean).join(' ')}</div>}
                  </td>
                  <td><Chip tone={RESULT_TONE[entry.result] || 'neutral'}>{entry.result.replace(/_/g, ' ')}</Chip></td>
                  <td className="max-w-[320px] text-xs qgu-soft">{entry.detail || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <Pager pagination={data?.pagination} noun="records" loading={resource.loading} onPage={(page) => void resource.refresh(page)} />
      </div>

      <ProvenanceNote>
        Administrator actions come from admin_audit_events (Admin console + Revenue Intelligence), written by the API as each action happens; platform sources read their own event tables. Nothing here is reconstructed from the current state of a record.
      </ProvenanceNote>
    </div>
  )
}
