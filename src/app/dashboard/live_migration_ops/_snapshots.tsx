'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertTriangle,
  Archive,
  CheckCircle2,
  Database,
  Download,
  Fingerprint,
  GitCompare,
  History,
  Loader2,
  RotateCcw,
  Search,
  Server,
  ShieldCheck,
  Trash2,
  X,
  XCircle,
} from 'lucide-react'
import { useMigrationSnapshots } from '@/hooks/use-migration-snapshots'
import type { MigrationSnapshot } from '@/types/migration-snapshot'

const PANEL = 'rounded-2xl border border-white/10 bg-white/[0.035] backdrop-blur-xl text-white shadow-[0_18px_60px_rgba(0,0,0,0.35)]'
const INNER = 'rounded-xl border border-white/10 bg-white/[0.02]'
const EMERALD = '#34d399'
const CYAN = '#22d3ee'

function fmt(n: number) { return new Intl.NumberFormat('en-US').format(Math.round(n || 0)) }
function bytes(n: number) {
  if (!n) return '0 B'
  const u = ['B', 'KB', 'MB', 'GB']
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)))
  return `${(n / Math.pow(1024, i)).toFixed(i ? 1 : 0)} ${u[i]}`
}
function rel(value: string | null) {
  if (!value) return '—'
  const diff = Date.now() - Date.parse(value)
  if (!Number.isFinite(diff)) return '—'
  const m = Math.floor(diff / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  return h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`
}
function fullDate(value: string | null) {
  if (!value) return 'Never'
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? 'Unknown' : d.toLocaleString()
}

const STATUS_TONE: Record<string, string> = {
  restorable: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300',
  restored: 'border-cyan-400/30 bg-cyan-400/10 text-cyan-300',
  expired: 'border-amber-400/30 bg-amber-400/10 text-amber-200',
  deleted: 'border-white/10 bg-white/[0.04] text-white/40',
}

type StatusFilter = 'all' | 'restorable' | 'restored' | 'expired'

export function SnapshotManager({ open, onOpenChange, focusAssetName, enabled }: { open: boolean; onOpenChange: (v: boolean) => void; focusAssetName?: string | null; enabled: boolean }) {
  const snap = useMigrationSnapshots(enabled)
  const [tab, setTab] = useState<'snapshots' | 'audit'>('snapshots')
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState<StatusFilter>('all')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [compareMode, setCompareMode] = useState(false)
  const [compareIds, setCompareIds] = useState<string[]>([])
  const [confirmRestore, setConfirmRestore] = useState<string | null>(null)
  const [toast, setToast] = useState<{ tone: 'ok' | 'bad'; text: string } | null>(null)
  const closeRef = useRef<HTMLButtonElement>(null)

  const showToast = (tone: 'ok' | 'bad', text: string) => { setToast({ tone, text }); setTimeout(() => setToast(null), 3200) }

  useEffect(() => { if (open) closeRef.current?.focus() }, [open])
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onOpenChange(false) }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onOpenChange])
  // When opened from a job's Rollback, pre-filter to that asset's snapshots.
  useEffect(() => { if (open && focusAssetName) setQuery(focusAssetName) }, [open, focusAssetName])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return snap.data.snapshots.filter((s) => {
      if (status !== 'all' && s.status !== status) return false
      if (!q) return true
      return [s.snapshotId, s.assetName, s.assetType, s.environment, s.migrationJobId].some((v) => String(v || '').toLowerCase().includes(q))
    })
  }, [snap.data.snapshots, query, status])

  const selected = snap.data.snapshots.find((s) => s.id === selectedId || s.snapshotId === selectedId) || null
  const compareA = snap.data.snapshots.find((s) => s.snapshotId === compareIds[0]) || null
  const compareB = snap.data.snapshots.find((s) => s.snapshotId === compareIds[1]) || null

  const toggleCompare = (id: string) => {
    setCompareIds((cur) => cur.includes(id) ? cur.filter((x) => x !== id) : cur.length >= 2 ? [cur[1], id] : [...cur, id])
  }

  const downloadMetadata = (s: MigrationSnapshot) => {
    const blob = new Blob([JSON.stringify(s, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${s.snapshotId}-metadata.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const doRestore = async (id: string) => {
    const r = await snap.restoreSnapshot(id, 'Restore from Snapshot Management')
    setConfirmRestore(null)
    showToast(r.ok ? 'ok' : 'bad', r.ok ? `Restored ${id} — asset reverting to pre-migration state.` : r.message || 'Restore failed')
  }

  const s = snap.data.summary
  const dark = true // this surface sits on the dark live-migration page

  return (
    <>
      {/* Dashboard card (always visible where placed) */}
      <section className={`${PANEL} p-5`}>
        <div className="mb-3 flex items-center justify-between">
          <h3 className="inline-flex items-center gap-2 text-sm font-black uppercase tracking-wide text-white/80">
            <Archive className="h-4 w-4 text-cyan-300" /> Snapshot Management
          </h3>
          <div className="flex items-center gap-2">
            {snap.data.schemaReady ? (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-400/25 bg-emerald-400/10 px-2.5 py-0.5 text-[10px] font-black uppercase text-emerald-300">
                <ShieldCheck className="h-3 w-3" /> Auto-rollback {s.autoRollbackEnabled ? 'on' : 'off'}
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-400/25 bg-amber-400/10 px-2.5 py-0.5 text-[10px] font-black uppercase text-amber-200">
                <AlertTriangle className="h-3 w-3" /> Setup required
              </span>
            )}
            <button type="button" onClick={() => onOpenChange(true)} className="rounded-lg border border-cyan-400/40 bg-cyan-400/10 px-3 py-1.5 text-xs font-bold text-cyan-200 transition hover:bg-cyan-400/20">
              Manage
            </button>
          </div>
        </div>
        {!snap.data.schemaReady ? (
          <div className="rounded-xl border border-amber-400/25 bg-amber-400/[0.07] px-3 py-2.5 text-[12px] text-amber-100/90">
            Run <code className="rounded bg-black/40 px-1 py-0.5 font-mono text-[11px]">supabase/migration-snapshots-schema.sql</code> to enable pre-migration snapshots &amp; safe rollback.
          </div>
        ) : (
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {[
              { label: 'Total Snapshots', value: fmt(s.total), tone: CYAN },
              { label: 'Restorable', value: fmt(s.restorable), tone: EMERALD },
              { label: 'Auto Rollbacks', value: fmt(s.automaticRollbacks), tone: '#f59e0b' },
              { label: 'Manual Rollbacks', value: fmt(s.manualRollbacks), tone: '#a78bfa' },
              { label: 'Storage Used', value: bytes(s.storageBytes), tone: '#38bdf8' },
              { label: 'Integrity Verified', value: `${s.integrityVerified}/${s.total}`, tone: s.integrityFailed ? '#f87171' : EMERALD },
              { label: 'Latest Snapshot', value: rel(s.latestSnapshotAt), tone: '#22d3ee' },
              { label: 'Restored', value: fmt(s.restored), tone: '#94a3b8' },
            ].map((c) => (
              <div key={c.label} className={`${INNER} p-3`}>
                <div className="text-xl font-black tabular-nums" style={{ color: c.tone }}>{c.value}</div>
                <div className="mt-0.5 text-[10px] font-bold uppercase tracking-wide text-white/45">{c.label}</div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Management drawer */}
      {open ? (
        <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true" aria-label="Snapshot Management">
          {toast ? (
            <div className={`fixed bottom-6 right-6 z-[60] flex items-center gap-2 rounded-xl border px-4 py-2.5 text-sm font-semibold shadow-2xl backdrop-blur-xl ${toast.tone === 'ok' ? 'border-emerald-400/30 bg-emerald-500/15 text-emerald-100' : 'border-red-400/30 bg-red-500/15 text-red-100'}`}>
              {toast.tone === 'ok' ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />} {toast.text}
            </div>
          ) : null}
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => onOpenChange(false)} aria-hidden="true" />
          <div className="relative flex h-full w-full max-w-3xl flex-col overflow-hidden border-l border-white/10 bg-[#0b1120] text-white shadow-2xl">
            {/* Header */}
            <div className="flex items-start justify-between gap-3 border-b border-white/8 px-5 py-4">
              <div>
                <h3 className="flex items-center gap-2 text-lg font-black"><Archive className="h-5 w-5 text-cyan-300" /> Snapshot Management</h3>
                <p className="mt-0.5 text-[11px] text-white/45">Pre-migration backups of cryptographic &amp; configuration state — restore any asset to its exact prior state.</p>
              </div>
              <button ref={closeRef} type="button" onClick={() => onOpenChange(false)} className="rounded-lg border border-white/12 bg-white/[0.04] p-2 text-white/60 transition hover:text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-400" aria-label="Close"><X className="h-4 w-4" /></button>
            </div>

            {/* Tabs + controls */}
            <div className="flex flex-wrap items-center gap-2 border-b border-white/8 px-5 py-3">
              <div className="flex gap-1.5">
                <button type="button" onClick={() => setTab('snapshots')} className={`rounded-lg border px-3 py-1.5 text-xs font-bold transition ${tab === 'snapshots' ? 'border-cyan-400/40 bg-cyan-400/10 text-cyan-200' : 'border-white/8 bg-white/[0.02] text-white/55'}`}>Snapshots</button>
                <button type="button" onClick={() => setTab('audit')} className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-bold transition ${tab === 'audit' ? 'border-cyan-400/40 bg-cyan-400/10 text-cyan-200' : 'border-white/8 bg-white/[0.02] text-white/55'}`}><History className="h-3.5 w-3.5" /> Audit Log</button>
              </div>
              {tab === 'snapshots' ? (
                <>
                  <div className="relative ml-auto min-w-[180px] flex-1 sm:max-w-xs">
                    <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/35" />
                    <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search asset, id, environment…" className="w-full rounded-lg border border-white/12 bg-white/[0.03] py-1.5 pl-8 pr-3 text-xs text-white outline-none placeholder:text-white/25 focus:border-cyan-400/50" />
                  </div>
                  <select value={status} onChange={(e) => setStatus(e.target.value as StatusFilter)} className="rounded-lg border border-white/12 bg-white/[0.03] px-2.5 py-1.5 text-xs text-white outline-none focus:border-cyan-400/50">
                    <option value="all" className="bg-[#0b1120]">All</option>
                    <option value="restorable" className="bg-[#0b1120]">Restorable</option>
                    <option value="restored" className="bg-[#0b1120]">Restored</option>
                    <option value="expired" className="bg-[#0b1120]">Expired</option>
                  </select>
                  <button type="button" onClick={() => { setCompareMode((v) => !v); setCompareIds([]) }} className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-bold transition ${compareMode ? 'border-violet-400/40 bg-violet-400/10 text-violet-200' : 'border-white/12 bg-white/[0.04] text-white/60'}`}><GitCompare className="h-3.5 w-3.5" /> Compare</button>
                </>
              ) : null}
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto px-5 py-4">
              {!snap.data.schemaReady ? (
                <div className="rounded-xl border border-amber-400/25 bg-amber-400/[0.07] px-4 py-3 text-sm text-amber-100/90">
                  Snapshot tables are not provisioned yet. Run <code className="rounded bg-black/40 px-1 py-0.5 font-mono text-[12px]">supabase/migration-snapshots-schema.sql</code> in the Supabase SQL Editor.
                </div>
              ) : snap.state === 'loading' ? (
                <div className="flex items-center gap-2 text-sm text-white/50"><Loader2 className="h-4 w-4 animate-spin" /> Loading snapshots…</div>
              ) : tab === 'audit' ? (
                <AuditList audit={snap.data.audit} />
              ) : compareMode && compareA && compareB ? (
                <CompareView a={compareA} b={compareB} onExit={() => { setCompareMode(false); setCompareIds([]) }} />
              ) : (
                <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(280px,340px)]">
                  {/* List */}
                  <div className="space-y-2">
                    {compareMode ? <p className="text-[11px] text-white/45">Select two snapshots to compare ({compareIds.length}/2).</p> : null}
                    {filtered.length ? filtered.map((sn) => {
                      const active = selected?.snapshotId === sn.snapshotId
                      const checked = compareIds.includes(sn.snapshotId)
                      return (
                        <button key={sn.id} type="button" onClick={() => compareMode ? toggleCompare(sn.snapshotId) : setSelectedId(sn.snapshotId)} className={`w-full rounded-xl border p-3 text-left transition ${active || checked ? 'border-cyan-400/45 bg-cyan-400/[0.06]' : 'border-white/8 bg-white/[0.02] hover:border-white/20'}`}>
                          <div className="flex items-center justify-between gap-2">
                            <span className="flex min-w-0 items-center gap-2">
                              {compareMode ? <span className={`grid h-4 w-4 shrink-0 place-items-center rounded border ${checked ? 'border-cyan-400 bg-cyan-400/30' : 'border-white/25'}`}>{checked ? <CheckCircle2 className="h-3 w-3 text-cyan-200" /> : null}</span> : <Server className="h-3.5 w-3.5 shrink-0 text-white/40" />}
                              <span className="truncate text-sm font-bold text-white/85">{sn.assetName}</span>
                            </span>
                            <span className={`shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-bold ${STATUS_TONE[sn.status] || STATUS_TONE.deleted}`}>{sn.status}</span>
                          </div>
                          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[10px] text-white/40">
                            <span className="font-mono">{sn.snapshotId}</span>
                            <span>{sn.assetType} · {sn.environment}</span>
                            <span className="inline-flex items-center gap-1">{sn.integrityVerified ? <ShieldCheck className="h-3 w-3 text-emerald-300" /> : <AlertTriangle className="h-3 w-3 text-red-300" />} {sn.integrityAlgorithm}</span>
                            <span>{rel(sn.createdAt)}</span>
                          </div>
                        </button>
                      )
                    }) : (
                      <div className="rounded-xl border border-dashed border-white/12 bg-white/[0.015] px-4 py-10 text-center text-sm text-white/40">
                        No snapshots match. Pre-migration snapshots are captured automatically when a migration starts.
                      </div>
                    )}
                  </div>

                  {/* Detail / preview */}
                  <div>
                    {selected ? (
                      <div className={`${INNER} sticky top-0 space-y-3 p-4`}>
                        <div>
                          <div className="text-sm font-black text-white">{selected.assetName}</div>
                          <div className="font-mono text-[11px] text-white/40">{selected.snapshotId}</div>
                        </div>
                        <div className="grid grid-cols-2 gap-1.5 text-[11px]">
                          {[
                            ['Type', selected.assetType],
                            ['Environment', selected.environment],
                            ['Trigger', selected.trigger.replace('_', ' ')],
                            ['Created by', selected.createdBy || 'system'],
                            ['Size', bytes(selected.sizeBytes)],
                            ['Config ver.', selected.configurationVersion || '—'],
                            ['Retention', `${selected.retentionDays}d`],
                            ['Expires', selected.expiresAt ? rel(selected.expiresAt) : '—'],
                          ].map(([k, v]) => (
                            <div key={k} className="rounded-lg border border-white/8 bg-white/[0.02] px-2 py-1.5">
                              <div className="text-[9px] font-bold uppercase tracking-wide text-white/35">{k}</div>
                              <div className="truncate text-white/80">{v}</div>
                            </div>
                          ))}
                        </div>
                        <div className={`rounded-lg border px-2.5 py-2 text-[11px] ${selected.integrityVerified ? 'border-emerald-400/25 bg-emerald-400/[0.06] text-emerald-200' : 'border-red-400/25 bg-red-400/[0.06] text-red-200'}`}>
                          <span className="inline-flex items-center gap-1.5"><Fingerprint className="h-3.5 w-3.5" /> {selected.integrityVerified ? 'Integrity verified' : 'Integrity FAILED'} · <span className="font-mono">{selected.integrityHash.slice(0, 16)}…</span></span>
                        </div>
                        {/* Captured crypto state */}
                        <div>
                          <div className="mb-1 text-[10px] font-black uppercase tracking-wide text-white/40">Captured cryptographic state</div>
                          <div className="space-y-1.5 text-[11px] text-white/60">
                            <div><span className="text-white/40">Algorithms:</span> {selected.cryptoState.algorithms.slice(0, 8).join(', ') || '—'}</div>
                            <div><span className="text-white/40">TLS:</span> {selected.cryptoState.tls.version || '—'}{selected.cryptoState.tls.group ? ` · ${selected.cryptoState.tls.group}` : ''}</div>
                            <div><span className="text-white/40">Certificates:</span> {selected.cryptoState.certificates.length} · <span className="text-white/40">Keys:</span> {selected.cryptoState.keys.length} · <span className="text-white/40">Components:</span> {selected.cryptoState.componentCount}</div>
                          </div>
                        </div>
                        {/* Actions */}
                        <div className="flex flex-wrap gap-1.5 border-t border-white/8 pt-3">
                          {selected.status === 'restorable' ? (
                            <button type="button" onClick={() => setConfirmRestore(selected.snapshotId)} disabled={snap.busy} className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-400/40 bg-emerald-400/10 px-3 py-2 text-xs font-black text-emerald-200 transition hover:bg-emerald-400/20 disabled:opacity-50"><RotateCcw className="h-3.5 w-3.5" /> Restore</button>
                          ) : null}
                          <button type="button" onClick={async () => { const r = await snap.verifySnapshot(selected.snapshotId); showToast(r.ok ? 'ok' : 'bad', r.ok ? 'Integrity re-verified.' : r.message || 'Verify failed') }} disabled={snap.busy} className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-xs font-bold text-white/75 transition hover:border-cyan-400/40 disabled:opacity-50"><ShieldCheck className="h-3.5 w-3.5" /> Verify</button>
                          <button type="button" onClick={() => downloadMetadata(selected)} className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-xs font-bold text-white/75 transition hover:border-cyan-400/40"><Download className="h-3.5 w-3.5" /> Metadata</button>
                          <button type="button" onClick={async () => { if (!window.confirm('Delete this snapshot? Restorable snapshots require force (retention).')) return; const r = await snap.deleteSnapshot(selected.snapshotId, selected.status !== 'restorable'); if (!r.ok && r.code === 'RETENTION_PROTECTED') { if (window.confirm('Snapshot is within retention. Force delete anyway?')) { const f = await snap.deleteSnapshot(selected.snapshotId, true); showToast(f.ok ? 'ok' : 'bad', f.ok ? 'Deleted.' : f.message || 'Delete failed') } } else { showToast(r.ok ? 'ok' : 'bad', r.ok ? 'Deleted.' : r.message || 'Delete failed'); if (r.ok) setSelectedId(null) } }} disabled={snap.busy} className="ml-auto inline-flex items-center gap-1.5 rounded-lg border border-red-400/25 bg-red-500/10 px-3 py-2 text-xs font-bold text-red-300 transition hover:bg-red-500/20 disabled:opacity-50"><Trash2 className="h-3.5 w-3.5" /> Delete</button>
                        </div>
                        {/* Restore confirm */}
                        {confirmRestore === selected.snapshotId ? (
                          <div className="rounded-xl border border-emerald-400/30 bg-emerald-400/[0.08] p-3">
                            <div className="text-[12px] font-bold text-emerald-100">Restore {selected.assetName} to this snapshot?</div>
                            <p className="mt-1 text-[11px] text-white/55">The linked migration job will roll back to the captured pre-migration state. Integrity is re-verified before restoring.</p>
                            <div className="mt-2 flex gap-2">
                              <button type="button" onClick={() => void doRestore(selected.snapshotId)} disabled={snap.busy} className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-400/40 bg-emerald-400/15 px-3 py-1.5 text-xs font-black text-emerald-200 disabled:opacity-50">{snap.busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <CheckCircle2 className="h-3.5 w-3.5" />} Confirm Restore</button>
                              <button type="button" onClick={() => setConfirmRestore(null)} className="rounded-lg border border-white/12 bg-white/[0.04] px-3 py-1.5 text-xs font-bold text-white/60">Cancel</button>
                            </div>
                          </div>
                        ) : null}
                      </div>
                    ) : (
                      <div className={`${INNER} grid place-items-center px-4 py-10 text-center text-sm text-white/40`}>
                        <div><Database className="mx-auto mb-2 h-6 w-6 text-white/25" /> Select a snapshot to preview and restore.</div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      ) : null}
    </>
  )
}

function AuditList({ audit }: { audit: MigrationSnapshotAudit[] }) {
  if (!audit.length) return <p className="text-sm text-white/40">No snapshot or rollback events recorded yet.</p>
  const tone: Record<string, string> = { created: '#22d3ee', restored: '#34d399', auto_rollback: '#f59e0b', deleted: '#f87171', verified: '#a78bfa' }
  return (
    <div className="space-y-2">
      {audit.map((a) => (
        <div key={a.id} className={`${INNER} flex items-start gap-3 p-3`}>
          <span className="mt-0.5 h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: tone[a.action] || '#94a3b8' }} />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-black uppercase tracking-wide" style={{ color: tone[a.action] || '#94a3b8' }}>{a.action.replace('_', ' ')}</span>
              {a.snapshotId ? <span className="font-mono text-[10px] text-white/45">{a.snapshotId}</span> : null}
              <span className="ml-auto text-[10px] text-white/35">{fullDate(a.createdAt)}</span>
            </div>
            <div className="mt-0.5 text-[11px] text-white/60">{a.detail || a.reason || '—'}</div>
            <div className="mt-0.5 flex flex-wrap gap-x-3 text-[10px] text-white/35">
              <span>by {a.actor}</span>
              {a.restorationStatus && a.restorationStatus !== 'n/a' ? <span>restore: {a.restorationStatus}</span> : null}
              {a.integrityStatus ? <span>integrity: {a.integrityStatus}</span> : null}
              {a.approvalStatus && a.approvalStatus !== 'n/a' ? <span>approval: {a.approvalStatus}</span> : null}
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

type MigrationSnapshotAudit = import('@/types/migration-snapshot').SnapshotAuditEntry

function CompareView({ a, b, onExit }: { a: MigrationSnapshot; b: MigrationSnapshot; onExit: () => void }) {
  const rows: Array<{ label: string; a: string; b: string }> = [
    { label: 'Asset', a: a.assetName, b: b.assetName },
    { label: 'Status', a: a.status, b: b.status },
    { label: 'Created', a: fullDate(a.createdAt), b: fullDate(b.createdAt) },
    { label: 'Algorithms', a: a.cryptoState.algorithms.join(', ') || '—', b: b.cryptoState.algorithms.join(', ') || '—' },
    { label: 'TLS', a: a.cryptoState.tls.version || '—', b: b.cryptoState.tls.version || '—' },
    { label: 'Certificates', a: String(a.cryptoState.certificates.length), b: String(b.cryptoState.certificates.length) },
    { label: 'Keys', a: String(a.cryptoState.keys.length), b: String(b.cryptoState.keys.length) },
    { label: 'Components', a: String(a.cryptoState.componentCount), b: String(b.cryptoState.componentCount) },
    { label: 'Integrity', a: a.integrityHash.slice(0, 16), b: b.integrityHash.slice(0, 16) },
  ]
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="inline-flex items-center gap-2 text-sm font-black uppercase tracking-wide text-white/80"><GitCompare className="h-4 w-4 text-violet-300" /> Compare Snapshots</h4>
        <button type="button" onClick={onExit} className="rounded-lg border border-white/12 bg-white/[0.04] px-2.5 py-1 text-[11px] font-bold text-white/60">Exit compare</button>
      </div>
      <div className="grid grid-cols-[120px_1fr_1fr] gap-px overflow-hidden rounded-xl border border-white/10 bg-white/8 text-[11px]">
        <div className="bg-[#0b1120] px-2.5 py-2 font-black uppercase tracking-wide text-white/35">Field</div>
        <div className="bg-[#0b1120] px-2.5 py-2 font-mono text-cyan-200">{a.snapshotId}</div>
        <div className="bg-[#0b1120] px-2.5 py-2 font-mono text-emerald-200">{b.snapshotId}</div>
        {rows.map((r) => {
          const diff = r.a !== r.b
          return (
            <div key={r.label} className="contents">
              <div className="bg-[#0b1120] px-2.5 py-2 font-bold text-white/50">{r.label}</div>
              <div className={`px-2.5 py-2 ${diff ? 'bg-amber-500/[0.06] text-amber-100' : 'bg-[#0b1120] text-white/70'}`}>{r.a}</div>
              <div className={`px-2.5 py-2 ${diff ? 'bg-amber-500/[0.06] text-amber-100' : 'bg-[#0b1120] text-white/70'}`}>{r.b}</div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export default SnapshotManager
