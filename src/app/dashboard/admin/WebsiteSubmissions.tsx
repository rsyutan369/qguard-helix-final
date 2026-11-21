import { useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { useAuth } from '@/contexts/auth-context'

interface Submission {
  id: string
  created_at: string
  kind: 'demo' | 'pqc-checklist'
  source: string
  name: string
  email: string
  organization: string
  details: Record<string, string | boolean>
  email_status: string
}

interface Inbox {
  rows: Submission[]
  total: number
  pageSize: number
}

const STATUS_LABELS: Record<string, string> = {
  pending: 'Awaiting email status', accepted: 'Accepted by mail server', failed: 'Email failed',
  not_configured: 'Email unconfigured', not_applicable: '—',
}

export function WebsiteSubmissions() {
  const { user, session } = useAuth()
  const token = user && session?.user.id === user.id ? session.access_token : undefined
  const [kind, setKind] = useState('all')
  const [page, setPage] = useState(0)
  const [refresh, setRefresh] = useState(0)
  const [inbox, setInbox] = useState<Inbox | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    setInbox(null)
    setError('')
    if (!token) return
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout>
    const read = async () => {
      try {
        const response = await fetch(`/api/v1/admin/website-submissions?kind=${kind}&page=${page}`, {
          headers: { Authorization: `Bearer ${token}` }, signal: controller.signal,
        })
        const data = await response.json().catch(() => null)
        if (controller.signal.aborted) return
        if (!response.ok || !Array.isArray(data?.rows) || !Number.isInteger(data?.total)) {
          throw new Error(data?.error?.message || 'Could not load website submissions.')
        }
        setInbox(data)
        setError('')
      } catch (error) {
        if (!controller.signal.aborted) setError(error instanceof Error ? error.message : 'Could not load website submissions.')
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(read, 30_000)
      }
    }
    void read()
    return () => { controller.abort(); clearTimeout(timer) }
  }, [token, kind, page, refresh])

  return (
    <section className="q-card space-y-4 p-4 sm:p-6" aria-labelledby="website-submissions-title">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold" id="website-submissions-title">Website submissions</h2>
          <p className="mt-1 text-sm text-[var(--qg-text-secondary)]">Demo requests and checklist form submissions. Refreshes every 30 seconds.</p>
        </div>
        <div className="flex flex-wrap items-end gap-2">
          <label className="grid gap-1 text-sm font-medium">Submission type
            <select className="q-btn q-btn-ghost" value={kind} onChange={(event) => { setKind(event.target.value); setPage(0) }}>
              <option value="all">All submissions</option>
              <option value="demo">Demo requests</option>
              <option value="pqc-checklist">PQC checklist</option>
            </select>
          </label>
          <button className="q-btn q-btn-ghost" type="button" onClick={() => setRefresh((value) => value + 1)}>
            <RefreshCw size={14} aria-hidden="true" /> Refresh
          </button>
        </div>
      </div>
      {error && <p role="alert" className="text-sm">{error}</p>}
      {!error && !inbox && <p role="status" className="text-sm">Loading submissions…</p>}
      {inbox && (inbox.rows.length === 0 ? <p className="text-sm">No submissions on this page.</p> : (
        <div className="overflow-auto">
          <table className="w-full min-w-[720px] text-left text-sm">
            <thead><tr>{['Received', 'Type / source', 'Contact', 'Organization', 'Demo email', 'Details'].map((label) =>
              <th key={label} scope="col" className="p-3 font-semibold">{label}</th>)}</tr></thead>
            <tbody>{inbox.rows.map((row) => (
              <tr key={row.id} className="border-t border-[var(--qg-card-border)] align-top">
                <td className="p-3">{new Date(row.created_at).toLocaleString()}</td>
                <td className="p-3">{row.kind === 'demo' ? 'Demo request' : 'PQC checklist'}<div className="capitalize text-[var(--qg-text-secondary)]">{row.source}</div></td>
                <td className="p-3"><strong>{row.name}</strong><div className="break-all">{row.email}</div></td>
                <td className="p-3">{row.organization}</td>
                <td className="p-3">{STATUS_LABELS[row.email_status] ?? 'Unknown'}</td>
                <td className="p-3">
                  <details><summary className="cursor-pointer">View details</summary>
                    <dl className="mt-2 max-w-xs space-y-1">
                      {Object.entries(row.details).filter(([, value]) => value !== '').map(([field, value]) => (
                        <div key={field}><dt className="font-semibold capitalize">{field === 'communicationsConsent' ? 'Communications consent' : field === 'whitepaper' ? 'Readiness guide requested' : field}</dt>
                          <dd className="whitespace-pre-wrap break-words">{typeof value === 'boolean' ? (value ? 'Yes' : 'No') : value}</dd></div>
                      ))}
                    </dl>
                  </details>
                </td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      ))}
      {inbox && <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
        <span role="status">{inbox.total.toLocaleString()} submissions</span>
        <div className="flex gap-2">
          <button className="q-btn q-btn-ghost" type="button" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
          <button className="q-btn q-btn-ghost" type="button" disabled={(page + 1) * inbox.pageSize >= inbox.total} onClick={() => setPage(page + 1)}>Next</button>
        </div>
      </div>}
    </section>
  )
}
