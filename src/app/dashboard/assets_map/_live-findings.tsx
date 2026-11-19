import { useEffect, useId, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, ChevronDown, ExternalLink, RefreshCw, Trash2 } from 'lucide-react'
import { useAuth } from '@/contexts/auth-context'
import { EXPOSURE_LABEL, SEVERITY_LABEL, SEVERITY_RANK } from '@/lib/live-scan/policy'
import type { AssetAssessment, AssetFindingObservation } from '@/lib/live-scan/types'
import { panelClass } from '../_components/discovery/shell'

const PAGE_SIZE = 10
const REFRESH_MS = 15_000

const assessmentLabel = { scanning: 'Scan in progress', completed: 'Assessment completed', incomplete: 'Assessment incomplete' }
const actionClass = 'inline-flex min-h-9 items-center gap-1.5 rounded-md border border-[var(--qg-card-border)] px-2.5 text-xs font-semibold text-[var(--qg-dashboard-text-soft)] hover:border-[var(--qg-amber)]'

function removalKey(item: AssetAssessment, findingId?: string) {
  return JSON.stringify([item.runId, item.target, findingId])
}

function readRemovals(value: string | null): Set<string> {
  try {
    const entries: unknown = JSON.parse(value ?? '[]')
    return new Set(Array.isArray(entries) ? entries.filter((entry): entry is string => typeof entry === 'string') : [])
  } catch {
    return new Set()
  }
}

function saveRemovals(storageKey: string, entries: Set<string>) {
  try { localStorage.setItem(storageKey, JSON.stringify([...entries])) } catch { /* Still update the current panel. */ }
}

export function LiveAssetFindings({ refreshVersion }: { refreshVersion: number }) {
  const { session } = useAuth()
  if (!session?.user.id) return null
  return <FindingsPanel key={session.user.id} token={session.access_token} storageKey={`qguard:asset-findings:removed:${session.user.id}`} refreshVersion={refreshVersion} />
}

function FindingsPanel({ token, storageKey, refreshVersion }: { token: string; storageKey: string; refreshVersion: number }) {
  const contentId = useId()
  const [expanded, setExpanded] = useState(false)
  const [removed, setRemoved] = useState(() => {
    try { return readRemovals(localStorage.getItem(storageKey)) } catch { return new Set<string>() }
  })
  const [lastRemoval, setLastRemoval] = useState<{ key: string; label: string } | null>(null)
  const [result, setResult] = useState<{ token: string; observations: AssetFindingObservation[]; assessments: AssetAssessment[] } | null>(null)
  const [errorToken, setErrorToken] = useState<string | null>(null)
  const [refresh, setRefresh] = useState(0)
  const [target, setTarget] = useState('')
  const [page, setPage] = useState(0)

  useEffect(() => {
    const sync = (event: StorageEvent) => {
      if (event.key === storageKey || event.key === null) setRemoved(readRemovals(event.newValue))
    }
    window.addEventListener('storage', sync)
    return () => window.removeEventListener('storage', sync)
  }, [storageKey])

  function updateRemoval(key: string, hide: boolean) {
    let next = new Set(removed)
    try { next = readRemovals(localStorage.getItem(storageKey)) } catch { /* Keep the in-memory selection. */ }
    if (hide) next.add(key)
    else next.delete(key)
    setRemoved(next)
    saveRemovals(storageKey, next)
  }

  function remove(key: string, label: string) {
    updateRemoval(key, true)
    setLastRemoval({ key, label })
    setPage(0)
  }

  useEffect(() => {
    if (!token) return
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout>
    const load = async () => {
      try {
        const response = await fetch('/api/v1/scanner/live/asset-findings', {
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
          cache: 'no-store',
        })
        if (!response.ok) throw new Error('Could not load real-time scan findings')
        const body: { observations: AssetFindingObservation[]; assessments: AssetAssessment[] } = await response.json()
        if (controller.signal.aborted) return
        setResult({ token, ...body })
        setErrorToken(null)
      } catch {
        if (!controller.signal.aborted) setErrorToken(token)
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(load, REFRESH_MS)
      }
    }
    void load()
    return () => {
      controller.abort()
      clearTimeout(timer)
    }
  }, [token, refresh, refreshVersion])

  const findings = useMemo(() => result && result.token === token
    ? result.observations.filter((item) =>
      !removed.has(removalKey(item)) && !removed.has(removalKey(item, item.finding.id)) &&
      (item.finding.status === 'unknown' || (item.finding.status === 'open' && item.finding.severity !== 'info')))
      .sort((a, b) => Number(a.finding.status === 'unknown') - Number(b.finding.status === 'unknown')
        || SEVERITY_RANK[b.finding.severity] - SEVERITY_RANK[a.finding.severity] || b.observedAt.localeCompare(a.observedAt))
    : [], [result, token, removed])
  const assessments = result?.token === token ? result.assessments.filter((item) => !removed.has(removalKey(item))) : []
  const targets = assessments.map((assessment) => assessment.target).sort()
  const filtered = target && targets.includes(target) ? findings.filter((item) => item.target === target) : findings
  const pending = assessments.filter((item) => (!target || !targets.includes(target) || item.target === target) && item.assessment !== 'completed')
  const lastPage = Math.max(0, Math.ceil(filtered.length / PAGE_SIZE) - 1)
  const currentPage = Math.min(page, lastPage)
  const failed = Boolean(token && errorToken === token)
  const loaded = Boolean(token && result?.token === token)
  const selectedAssessment = assessments.find((item) => item.target === target)
  const hiddenCount = result?.token === token
    ? result.assessments.filter((item) => removed.has(removalKey(item))).length +
      result.observations.filter((item) => !removed.has(removalKey(item)) && removed.has(removalKey(item, item.finding.id))).length
    : 0

  return (
    <section className={panelClass} aria-labelledby="live-asset-findings">
      <h2 id="live-asset-findings">
        <button type="button" aria-expanded={expanded} aria-controls={contentId} onClick={() => setExpanded((value) => !value)}
          className="flex w-full flex-wrap items-center gap-2 rounded-xl px-4 py-3 text-left text-sm font-bold text-[var(--qg-dashboard-text)] hover:bg-[var(--qg-muted-panel)] focus-visible:outline focus-visible:outline-[var(--qg-amber)]">
          <AlertTriangle className="size-4 text-[var(--qg-amber)]" aria-hidden /> Real Time Scan Findings
          {loaded && <span className="text-xs font-normal text-[var(--qg-text-muted)]">{findings.length} {findings.length === 1 ? 'finding' : 'findings'} · {targets.length} {targets.length === 1 ? 'target' : 'targets'}</span>}
          <ChevronDown className={`ml-auto size-4 ${expanded ? 'rotate-180' : ''}`} aria-hidden />
        </button>
      </h2>
      <div id={contentId} hidden={!expanded} className="space-y-3 border-t border-[var(--qg-card-border)] p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-xs text-[var(--qg-text-muted)]">Latest assessment per target. Removing an item from this panel preserves its scan record.</p>
          <div className="flex flex-wrap items-center gap-3">
            {targets.length > 0 && (
              <label className="flex items-center gap-2 text-xs text-[var(--qg-dashboard-text-soft)]">
                Scanned target
                <select value={targets.includes(target) ? target : ''} onChange={(event) => { setTarget(event.target.value); setPage(0) }}
                  className="max-w-56 rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-2 py-2">
                  <option value="">All targets</option>
                  {targets.map((value) => <option key={value}>{value}</option>)}
                </select>
              </label>
            )}
            {selectedAssessment && <button type="button" className={actionClass}
              onClick={() => { remove(removalKey(selectedAssessment), selectedAssessment.target); setTarget('') }}>
              <Trash2 className="size-3.5" aria-hidden /> Remove assessment
            </button>}
            <button type="button" onClick={() => setRefresh((value) => value + 1)} aria-label="Refresh scanner findings"
              className="rounded-md border border-[var(--qg-card-border)] p-2 text-[var(--qg-dashboard-text-soft)] hover:border-[var(--qg-amber)]">
              <RefreshCw className="size-4" aria-hidden />
            </button>
          </div>
        </div>
        {hiddenCount > 0 && (
          <div className="flex flex-wrap items-center gap-2 rounded-md bg-[var(--qg-muted-panel)] px-3 py-2 text-xs text-[var(--qg-dashboard-text-soft)]">
            <span className="break-all" role="status">
              {lastRemoval && removed.has(lastRemoval.key) ? `Removed ${lastRemoval.label} from this panel.` : `${hiddenCount} hidden in this browser.`}
            </span>
            {lastRemoval && removed.has(lastRemoval.key) && <button type="button" className={actionClass}
              onClick={() => { updateRemoval(lastRemoval.key, false); setLastRemoval(null) }}>Undo</button>}
            <button type="button" className={actionClass} onClick={() => {
              const next = new Set<string>()
              saveRemovals(storageKey, next)
              setRemoved(next)
              setLastRemoval(null)
            }}>Restore all hidden items</button>
          </div>
        )}

        {failed && <p role="alert" className="text-xs text-[var(--qg-dashboard-text-soft)]">Scanner findings could not refresh.{loaded && ' Showing the last received records.'}</p>}
        {!loaded && !failed && <p role="status" className="text-xs text-[var(--qg-text-muted)]">Loading scanner findings…</p>}
        {loaded && !failed && !filtered.length && <p className="text-xs text-[var(--qg-text-muted)]">
          {assessments.length === 0 ? 'No assessments to display.' : 'No findings to display for this selection.'}
        </p>}
        {pending.length > 0 && (
          <details className="rounded-md border border-[var(--qg-card-border)] px-3 py-2 text-xs text-[var(--qg-dashboard-text-soft)]">
            <summary className="cursor-pointer font-semibold">{pending.length} target{pending.length === 1 ? '' : 's'} with an assessment in progress or incomplete</summary>
            <ul className="mt-2 max-h-48 space-y-1 overflow-auto">
              {pending.map((item) => <li key={item.target} className="flex flex-wrap items-center justify-between gap-2">
                <span><Link to={`/dashboard/scanner/real-time?run=${encodeURIComponent(item.runId)}`} className="break-all text-[var(--qg-amber)] hover:underline">{item.target}</Link>
                {' · '}{assessmentLabel[item.assessment]}</span>
                <button type="button" className={actionClass} aria-label={`Remove assessment for ${item.target}`}
                  onClick={() => remove(removalKey(item), item.target)}>Remove</button>
              </li>)}
            </ul>
          </details>
        )}
        <div className="divide-y divide-[var(--qg-card-border)]">
          {filtered.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE).map((item) => {
            const { finding } = item
            const scanLink = '/dashboard/scanner/real-time?' + new URLSearchParams({ run: item.runId, finding: finding.id })
            return (
              <div key={removalKey(item, finding.id)} className="flex flex-wrap items-start gap-x-3 gap-y-2 py-2">
                <details className="min-w-0 flex-[1_1_16rem]">
                  <summary className="cursor-pointer rounded-sm text-sm font-semibold text-[var(--qg-dashboard-text)] focus-visible:outline focus-visible:outline-[var(--qg-amber)]">
                    <span className="break-words">{finding.title}</span>
                    <span className="ml-2 inline-block rounded border border-[var(--qg-card-border)] px-1.5 py-0.5 text-[11px] text-[var(--qg-amber)]">
                      {finding.status === 'unknown' ? 'Assessment gap' : SEVERITY_LABEL[finding.severity]}
                    </span>
                    <span className="mt-1 block break-all text-xs font-normal text-[var(--qg-text-muted)]">{item.target} · {EXPOSURE_LABEL[finding.exposure]}</span>
                  </summary>
                  <div className="mt-3 space-y-3 rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] p-3 text-xs leading-relaxed text-[var(--qg-dashboard-text-soft)]">
                    <p>{finding.description}</p>
                    <div><h3 className="font-bold text-[var(--qg-dashboard-text)]">Recommended remediation</h3><p>{finding.remediation || 'No recommendation recorded.'}</p></div>
                    {finding.standards.length > 0 && <p>{finding.standards.join(' · ')}</p>}
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span>{assessmentLabel[item.assessment]} · Observed <time dateTime={item.observedAt}>{new Date(item.observedAt).toLocaleString()}</time></span>
                      <Link className="inline-flex items-center gap-1 font-bold text-[var(--qg-amber)] hover:underline" to={scanLink}>View scan evidence <ExternalLink className="size-3" aria-hidden /></Link>
                    </div>
                  </div>
                </details>
                <button type="button" className={actionClass} aria-label={`Remove finding: ${finding.title}`}
                  onClick={() => remove(removalKey(item, finding.id), finding.title)}>
                  <Trash2 className="size-3.5" aria-hidden /> Remove
                </button>
              </div>
            )
          })}
        </div>
        {lastPage > 0 && (
          <nav className="flex flex-wrap items-center gap-3 text-xs text-[var(--qg-dashboard-text-soft)]" aria-label="Scanner findings pages">
            <span>{currentPage * PAGE_SIZE + 1}–{Math.min((currentPage + 1) * PAGE_SIZE, filtered.length)} of {filtered.length}</span>
            <button type="button" className="px-2 py-1 disabled:opacity-40" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous</button>
            <button type="button" className="px-2 py-1 disabled:opacity-40" disabled={currentPage === lastPage} onClick={() => setPage(currentPage + 1)}>Next</button>
          </nav>
        )}
      </div>
    </section>
  )
}
