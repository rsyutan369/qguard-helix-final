import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '@/contexts/auth-context'
import { ISSUANCE_UNAVAILABLE } from '@/lib/crypto/issuance-evidence'

type RecordRow = {
  id: string
  fingerprint?: string
  label?: string | null
  common_name?: string
  algorithm?: string
  key_algorithm?: string
  status?: string
  createdAt?: string
  created_at?: string
}

const LIMIT = 20

export function IssuanceRecords({ kind }: { kind: 'keys' | 'pki' }) {
  const { session } = useAuth()
  const token = session?.access_token
  const keys = kind === 'keys'
  const endpoint = `/api/v1/${kind}`
  const title = keys ? 'Encryption Keys' : 'Digital Certificates'
  const [page, setPage] = useState(0)
  const [refresh, setRefresh] = useState(0)
  const [status, setStatus] = useState('')
  const [result, setResult] = useState<{ owner: string; rows: RecordRow[]; total: number } | null>(null)
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)
  const tenantResult = result?.owner === session?.user.id ? result : null

  useEffect(() => {
    if (!token || !session?.user.id) return
    const owner = session.user.id
    const controller = new AbortController()
    const query = new URLSearchParams({ limit: String(LIMIT), offset: String(page * LIMIT) })
    if (keys && status) query.set('status', status)
    setError('')
    setPending(true)
    void fetch(`${endpoint}?${query}`, { headers: { Authorization: `Bearer ${token}` }, signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error('Could not load historical records.')
        const data = await response.json()
        if (!Array.isArray(data.data) || !Number.isFinite(data.meta?.total)) throw new Error('Historical records could not be read.')
        if (!controller.signal.aborted) setResult({ owner, rows: data.data, total: data.meta.total })
      })
      .catch((failure: Error) => { if (!controller.signal.aborted) { setResult(null); setError(failure.message) } })
      .finally(() => { if (!controller.signal.aborted) setPending(false) })
    return () => controller.abort()
  }, [endpoint, keys, page, refresh, session?.user.id, status, token])

  async function revokeRecord(record: RecordRow) {
    if (!token || pending) return
    setPending(true)
    setError('')
    try {
      const response = await fetch(endpoint, {
        method: 'PATCH', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'revoke', keyId: record.id }),
      })
      if (!response.ok) throw new Error('Could not mark the historical record revoked.')
      setRefresh((n) => n + 1)
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Could not update the historical record.')
      setPending(false)
    }
  }

  return (
    <main className="mx-auto max-w-6xl space-y-5 px-4 py-7 sm:px-8">
      <h1 className="text-2xl font-bold">{title}</h1>
      <div className="q-card space-y-2 p-5">
        <h2 className="font-semibold">{keys ? 'Key' : 'Certificate'} issuance unavailable</h2>
        <p className="text-sm leading-relaxed">{ISSUANCE_UNAVAILABLE.message}</p>
        <Link to="/docs" className="inline-block text-sm underline">Read the platform documentation</Link>
      </div>
      <section className="q-card space-y-4 p-5" aria-labelledby="issuance-history">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 id="issuance-history" className="font-semibold">Historical records</h2>
          <div className="flex gap-2">
            {keys && <select aria-label="Recorded status" value={status} onChange={(event) => { setPage(0); setStatus(event.target.value) }}>
              <option value="">All statuses</option>
              <option value="active">Active</option>
              <option value="revoked">Revoked</option>
              <option value="rotated">Rotated</option>
              <option value="expired">Expired</option>
            </select>}
            <button type="button" className="q-btn q-btn-ghost" disabled={!token || pending} onClick={() => setRefresh((n) => n + 1)}>Refresh</button>
          </div>
        </div>
        <p className="text-sm leading-relaxed">These records do not prove issuance, entropy validation or provider conformance. Confirm key and certificate state with your provider before relying on any record.</p>
        {error && <p role="alert" className="text-sm">{error}</p>}
        {!token ? <p className="text-sm">Sign in to view your records.</p>
          : pending && !tenantResult ? <p role="status" className="text-sm">Loading historical records…</p>
            : tenantResult?.rows.length ? (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[32rem] text-left text-sm">
                  <thead><tr><th scope="col">Record</th><th scope="col">Reported algorithm</th><th scope="col">Recorded status</th><th scope="col">Recorded date</th>{keys && <th scope="col">Record action</th>}</tr></thead>
                  <tbody className="divide-y divide-white/10">
                    {tenantResult.rows.map((record) => (
                      <tr key={record.id}>
                        <td className="max-w-[22rem] break-all py-2 pr-3">{record.common_name || record.label || record.fingerprint || record.id}</td>
                        <td className="pr-3">{record.algorithm || record.key_algorithm || 'Not recorded'}</td>
                        <td className="pr-3">{record.status || 'Not recorded'}</td>
                        <td className="pr-3">{record.createdAt || record.created_at ? new Date(record.createdAt || record.created_at!).toLocaleDateString() : 'Not recorded'}</td>
                        {keys && <td>{record.status === 'active' && <button className="q-btn q-btn-ghost" type="button" disabled={pending} onClick={() => void revokeRecord(record)}>Mark revoked</button>}</td>}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : tenantResult && !error ? <p className="text-sm">No historical records match this view.</p> : null}
        {tenantResult && tenantResult.total > LIMIT && (
          <div className="flex items-center gap-3 text-sm" aria-label="History pagination">
            <button className="q-btn q-btn-ghost" type="button" disabled={pending || page === 0} onClick={() => setPage((n) => n - 1)}>Previous</button>
            <span>Page {page + 1} of {Math.ceil(tenantResult.total / LIMIT)}</span>
            <button className="q-btn q-btn-ghost" type="button" disabled={pending || (page + 1) * LIMIT >= tenantResult.total} onClick={() => setPage((n) => n + 1)}>Next</button>
          </div>
        )}
      </section>
    </main>
  )
}
