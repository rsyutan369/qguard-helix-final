import { useEffect, useId, useRef, useState } from 'react'
import { History, Trash2, X } from 'lucide-react'
import { useAuth } from '@/contexts/auth-context'
import type { LiveScanStatus, RunListItem } from '@/lib/live-scan/types'

type Props = {
  runs: RunListItem[]
  statusLabels: Record<LiveScanStatus, string>
  onOpen: (id: string) => void
  onClose: () => void
}

function readHidden(value: string | null): Set<string> {
  try {
    const ids: unknown = JSON.parse(value ?? '[]')
    return new Set(Array.isArray(ids) ? ids.filter((id): id is string => typeof id === 'string') : [])
  } catch {
    return new Set()
  }
}

export function ScanHistory(props: Props) {
  const { user } = useAuth()
  if (!user) return null
  return <HistoryDialog key={user.id} {...props} storageKey={`qguard:live-scan:removed:${user.id}`} />
}

function HistoryDialog({ runs, statusLabels, onOpen, onClose, storageKey }: Props & { storageKey: string }) {
  const dialogRef = useRef<HTMLDialogElement>(null)
  const titleId = useId()
  const descriptionId = useId()
  const [hidden, setHidden] = useState(() => {
    try { return readHidden(localStorage.getItem(storageKey)) } catch { return new Set<string>() }
  })
  const [lastRemoved, setLastRemoved] = useState<RunListItem | null>(null)

  useEffect(() => {
    const dialog = dialogRef.current
    dialog?.showModal()
    const sync = (event: StorageEvent) => {
      if (event.key === storageKey || event.key === null) setHidden(readHidden(event.newValue))
    }
    window.addEventListener('storage', sync)
    return () => {
      dialog?.close()
      window.removeEventListener('storage', sync)
    }
  }, [storageKey])

  const keyFor = (run: RunListItem) => run.sessionId ?? run.id
  const visible = runs.filter((run) => !hidden.has(keyFor(run)))
  const hiddenCount = runs.length - visible.length

  function save(next: Set<string>) {
    setHidden(next)
    try { localStorage.setItem(storageKey, JSON.stringify([...next])) } catch { /* Keep the current dialog usable. */ }
  }

  return (
    <dialog ref={dialogRef} className="rt-history" aria-labelledby={titleId} aria-describedby={descriptionId}
      onCancel={(event) => { event.preventDefault(); onClose() }}>
      <header className="rt-history-header">
        <div>
          <h2 id={titleId}><History size={17} aria-hidden /> Scan history</h2>
          <p id={descriptionId}>Removing a scan hides it from this list in this browser. Scan records and evidence are retained.</p>
        </div>
        <button type="button" className="rt-btn is-icon" autoFocus onClick={onClose} aria-label="Close scan history"><X size={16} aria-hidden /></button>
      </header>
      <div className="rt-history-content">
        {hiddenCount > 0 && (
          <div className="rt-history-feedback">
            <span role="status">
              {lastRemoved && hidden.has(keyFor(lastRemoved)) ? `Removed ${lastRemoved.name} from this list.` : `${hiddenCount} hidden`}
            </span>
            {lastRemoved && hidden.has(keyFor(lastRemoved)) && <button type="button" className="rt-btn" onClick={() => {
              const next = new Set(hidden)
              next.delete(keyFor(lastRemoved))
              save(next)
              setLastRemoved(null)
            }}>Undo</button>}
            <button type="button" className="rt-btn" onClick={() => { save(new Set()); setLastRemoved(null) }}>Restore all hidden scans</button>
          </div>
        )}
        {!visible.length && <p className="rt-muted">{runs.length ? 'No scans to display.' : 'No live scans yet.'}</p>}
        <ul className="rt-history-list">
          {visible.map((run) => (
            <li key={run.id} className="rt-history-row">
              <button type="button" className="rt-history-open" onClick={() => onOpen(run.id)}>
                <strong>{run.name}</strong>
                <span className="rt-chip">{statusLabels[run.status]}</span>
                <small>
                  {new Date(run.createdAt).toLocaleString()} · {run.targets.length} {run.targets.length === 1 ? 'target' : 'targets'}
                  {run.findings != null && ` · ${run.findings} open ${run.findings === 1 ? 'finding' : 'findings'}`}
                </small>
              </button>
              <button type="button" className="rt-btn is-danger" aria-label={`Remove ${run.name} from scan history`}
                onClick={() => {
                  save(new Set(hidden).add(keyFor(run)))
                  setLastRemoved(run)
                }}>
                <Trash2 size={14} aria-hidden /> Remove
              </button>
            </li>
          ))}
        </ul>
      </div>
    </dialog>
  )
}
