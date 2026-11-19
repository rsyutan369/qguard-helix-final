import { useEffect, useRef, useState } from 'react'
import { Archive, Loader2, RotateCcw, Trash2 } from 'lucide-react'

type Asset = { id: string; name: string }
export type LifecycleAction = 'archive' | 'remove' | 'restore'
export type LifecycleSelection = { action: LifecycleAction; assets: Asset[] }

const copy = {
  archive: { label: 'Archive', icon: Archive, description: 'Move these assets out of active inventory. You can restore them from Archived assets. Scan history is retained.' },
  restore: { label: 'Restore', icon: RotateCcw, description: 'Return this asset and its linked evidence to active inventory.' },
  remove: { label: 'Remove', icon: Trash2, description: 'Remove these assets from active inventory and the archive. This action cannot be undone here. Scan history is retained.' },
}

export function AssetLifecycleDialog({ selection, onClose, onConfirm }: {
  selection: LifecycleSelection
  onClose: () => void
  onConfirm: () => Promise<void>
}) {
  const dialogRef = useRef<HTMLDialogElement>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const { action, assets } = selection
  const { label, icon: Icon, description } = copy[action]
  const subject = assets.length === 1 ? '1 asset' : `${assets.length.toLocaleString()} assets`

  useEffect(() => {
    const dialog = dialogRef.current
    dialog?.showModal()
    return () => dialog?.close()
  }, [])

  async function submit() {
    setError('')
    setBusy(true)
    try {
      await onConfirm()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The inventory action could not be saved.')
      setBusy(false)
    }
  }

  return (
    <dialog ref={dialogRef} aria-labelledby="asset-lifecycle-title" aria-describedby="asset-lifecycle-description"
      onCancel={(event) => { event.preventDefault(); if (!busy) onClose() }}
      className="m-auto w-[calc(100%-2rem)] max-w-md rounded-xl border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] p-5 text-[var(--qg-dashboard-text)] shadow-2xl backdrop:bg-black/55">
      <div className="flex items-center gap-3">
        <Icon aria-hidden className={`size-5 ${action === 'remove' ? 'text-red-500' : 'text-[var(--qg-amber)]'}`} />
        <h2 id="asset-lifecycle-title" className="text-base font-bold">{label} {subject}?</h2>
      </div>
      <p id="asset-lifecycle-description" className="mt-3 text-sm leading-relaxed text-[var(--qg-dashboard-text-soft)]">{description}</p>
      <ul className="mt-3 max-h-32 space-y-1 overflow-auto rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] p-3 text-xs">
        {assets.slice(0, 8).map((asset) => <li className="break-words" key={asset.id}>{asset.name}</li>)}
        {assets.length > 8 && <li>And {(assets.length - 8).toLocaleString()} more</li>}
      </ul>
      {error && <p role="alert" className="mt-3 text-sm text-red-700 dark:text-red-300">{error}</p>}
      <div className="mt-5 flex flex-wrap justify-end gap-2">
        <button autoFocus disabled={busy} type="button" onClick={onClose} className="rounded-md border border-[var(--qg-card-border)] px-4 py-2 text-sm font-bold disabled:opacity-50">Cancel</button>
        <button disabled={busy} type="button" onClick={() => void submit()}
          className={`inline-flex items-center gap-2 rounded-md px-4 py-2 text-sm font-bold disabled:opacity-60 ${action === 'remove' ? 'bg-red-700 text-white' : 'bg-[var(--qg-amber)] text-[var(--qg-on-accent)]'}`}>
          {busy && <Loader2 className="size-4 animate-spin" aria-hidden />}
          {label} {subject}
        </button>
      </div>
    </dialog>
  )
}
