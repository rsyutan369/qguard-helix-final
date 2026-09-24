import { type ReactNode, useEffect, useState } from 'react'
import { AlertTriangle, CheckCircle2, ChevronLeft, ChevronRight, Info, RefreshCw, X } from 'lucide-react'
import type { AdminDashboard, MutationOutcome } from '@/hooks/use-admin-dashboard'
import type { IntegrityCheck } from '@/lib/admin/model-utils'
import { Chip, Dialog, Field, VIEWER_TIME_ZONE, formatCount, timeAgo, useNow } from './primitives'
import './admin-console.css'

export function ConsoleHeader({ title, description, admin, updatedAt, actions }: {
  title: string
  description: string
  admin: AdminDashboard
  updatedAt?: string | null
  actions?: ReactNode
}) {
  const now = useNow()
  const at = updatedAt || admin.liveAt
  return (
    <div className="qgu-panel flex flex-col gap-4 p-5 lg:flex-row lg:items-center lg:justify-between">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-2xl font-black qgu-strong">{title}</h2>
          <span className="inline-flex items-center gap-2 text-xs font-bold qgu-soft" role="status">
            <span className={`qgu-dot ${admin.sseConnected ? 'qgu-dot--live' : 'qgu-dot--off'}`} />
            {admin.sseConnected ? `Live · updated ${timeAgo(at, now)}` : 'Live updates reconnecting'}
          </span>
        </div>
        <p className="mt-1 text-sm qgu-soft">{description}</p>
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

export function Kpi({ icon, label, value, sub, subTone, onClick, active }: {
  icon: ReactNode
  label: string
  value: string
  sub: ReactNode
  subTone?: 'warn' | 'ok' | 'bad'
  onClick?: () => void
  active?: boolean
}) {
  const body = (
    <>
      <div className="flex items-center justify-between gap-3">
        <span className="text-xs font-bold uppercase tracking-[0.1em] qgu-muted">{label}</span>
        <span className="qgu-muted">{icon}</span>
      </div>
      <div className="mt-2 font-mono text-[28px] font-black leading-none qgu-strong qgu-num">{value}</div>
      <div className={`mt-2 text-xs ${subTone ? `qgu-tone-${subTone}` : 'qgu-muted'}`}>{sub}</div>
    </>
  )
  if (!onClick) return <div className="qgu-panel p-4">{body}</div>
  return (
    <button type="button" className="qgu-panel p-4 text-left transition hover:brightness-110" style={active ? { borderColor: 'var(--qgu-border-strong)', boxShadow: '0 0 0 1px var(--qgu-border-strong)' } : undefined} onClick={onClick} aria-pressed={active}>
      {body}
    </button>
  )
}

export function KpiGrid({ children, loading, count = 6 }: { children: ReactNode; loading?: boolean; count?: number }) {
  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-6">
      {loading ? Array.from({ length: count }, (_, index) => <div key={index} className="qgu-skeleton h-[118px]" />) : children}
    </div>
  )
}

/** Reconciliation checks: one quiet line when all pass, a banner when not. */
export function IntegrityStrip({ checks, notes = [] }: { checks: IntegrityCheck[] | undefined; notes?: string[] }) {
  if (!checks) return null
  const failing = checks.filter((check) => !check.ok)
  if (failing.length || notes.length) {
    return (
      <div className="qgu-banner" role="status">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
        <div className="space-y-1">
          {failing.map((check) => <div key={check.id}><strong>{check.label}:</strong> {check.detail}</div>)}
          {notes.map((note) => <div key={note}>{note}</div>)}
        </div>
      </div>
    )
  }
  return (
    <details className="group text-xs qgu-muted">
      <summary className="flex cursor-pointer list-none flex-wrap items-center gap-2 [&::-webkit-details-marker]:hidden">
        <Chip tone="ok" icon={<CheckCircle2 className="h-3.5 w-3.5" />}>Reconciled</Chip>
        <span>All {checks.length} integrity checks pass — {checks[0]?.detail}.</span>
        <span className="underline decoration-dotted underline-offset-2 group-open:hidden">Show checks</span>
      </summary>
      <ul className="qgu-inset mt-2 grid gap-1.5 p-3 sm:grid-cols-2">
        {checks.map((check) => (
          <li key={check.id} className="flex items-start gap-2">
            <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 qgu-tone-ok" />
            <span><span className="font-semibold qgu-soft">{check.label}:</span> {check.detail}</span>
          </li>
        ))}
      </ul>
    </details>
  )
}

export function Panel({ title, action, children, className = '' }: { title: ReactNode; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`qgu-panel p-4 ${className}`}>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <h3 className="text-sm font-black qgu-strong">{title}</h3>
        {action}
      </div>
      {children}
    </section>
  )
}

export function EmptyState({ icon, title, body, action }: { icon?: ReactNode; title: string; body?: ReactNode; action?: ReactNode }) {
  return (
    <div className="py-10 text-center">
      {icon && <div className="mx-auto flex h-10 w-10 items-center justify-center qgu-muted">{icon}</div>}
      <p className="mt-2 text-sm font-bold qgu-strong">{title}</p>
      {body && <p className="mx-auto mt-1 max-w-md text-xs qgu-muted">{body}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

export function ErrorBanner({ message, onRetry }: { message: string | null; onRetry?: () => void }) {
  if (!message) return null
  return (
    <div className="qgu-banner qgu-banner--bad" role="alert">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
      <span className="flex-1">{message}</span>
      {onRetry && <button type="button" className="qgu-btn min-h-0 px-3 py-1 text-xs" onClick={onRetry}>Retry</button>}
    </div>
  )
}

export function Pager({ pagination, noun, onPage, loading }: {
  pagination: { page: number; limit: number; total: number; totalPages: number } | undefined
  noun: string
  onPage: (page: number) => void
  loading?: boolean
}) {
  if (!pagination) return null
  const start = pagination.total ? (pagination.page - 1) * pagination.limit + 1 : 0
  const end = Math.min(pagination.total, pagination.page * pagination.limit)
  return (
    <div className="flex flex-col gap-3 border-t px-4 py-3 text-sm md:flex-row md:items-center md:justify-between" style={{ borderColor: 'var(--qgu-border)' }}>
      <span className="qgu-soft qgu-num">{pagination.total ? `Showing ${formatCount(start)}–${formatCount(end)} of ${formatCount(pagination.total)} ${noun}` : `No ${noun} to show`}</span>
      <div className="flex items-center gap-2">
        <button type="button" className="qgu-btn" disabled={pagination.page <= 1 || loading} onClick={() => onPage(pagination.page - 1)}>
          <ChevronLeft className="h-4 w-4" />
          Previous
        </button>
        <span className="font-mono text-xs qgu-muted">Page {pagination.page} of {Math.max(1, pagination.totalPages)}</span>
        <button type="button" className="qgu-btn" disabled={pagination.page >= pagination.totalPages || loading} onClick={() => onPage(pagination.page + 1)}>
          Next
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}

export function ProvenanceNote({ children }: { children: ReactNode }) {
  return (
    <p className="flex items-start gap-2 text-xs qgu-muted">
      <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
      <span>Times are shown in your time zone ({VIEWER_TIME_ZONE}); exports use UTC. {children}</span>
    </p>
  )
}

export function Effects({ items }: { items: ReactNode[] }) {
  return (
    <div className="qgu-inset p-3">
      <div className="qgu-label">What happens</div>
      <ul className="space-y-1.5 text-sm qgu-soft">
        {items.map((item, index) => (
          <li key={index} className="flex gap-2">
            <span className="mt-2 h-1 w-1 shrink-0 rounded-full" style={{ background: 'var(--qgu-text-muted)' }} />
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

/**
 * Generic confirmation: states the real effects, optionally asks for a reason
 * and/or a typed confirmation, and stays open showing the server's error.
 */
export function ConfirmDialog({ title, subtitle, icon, effects, confirmLabel, danger, busy, reasonLabel, typeToConfirm, extra, onClose, onConfirm }: {
  title: string
  subtitle?: ReactNode
  icon?: ReactNode
  effects: ReactNode[]
  confirmLabel: string
  danger?: boolean
  busy: boolean
  reasonLabel?: string
  typeToConfirm?: string
  extra?: ReactNode
  onClose: () => void
  onConfirm: (input: { reason: string; typed: string }) => Promise<MutationOutcome<unknown>>
}) {
  const [reason, setReason] = useState('')
  const [typed, setTyped] = useState('')
  const [error, setError] = useState<string | null>(null)
  const blocked = Boolean(typeToConfirm) && typed.trim() !== typeToConfirm
  const submit = async () => {
    setError(null)
    const outcome = await onConfirm({ reason: reason.trim(), typed: typed.trim() })
    if (outcome.ok) onClose()
    else setError(outcome.error)
  }
  return (
    <Dialog
      title={title}
      subtitle={subtitle}
      icon={icon}
      onClose={onClose}
      busy={busy}
      footer={(
        <>
          <button type="button" className="qgu-btn qgu-btn--ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="button" className={`qgu-btn ${danger ? 'qgu-btn--danger' : 'qgu-btn--primary'}`} onClick={() => void submit()} disabled={busy || blocked}>
            {busy && <RefreshCw className="h-4 w-4 animate-spin" />}
            {confirmLabel}
          </button>
        </>
      )}
    >
      <Effects items={effects} />
      {extra}
      {reasonLabel && (
        <Field label={reasonLabel} htmlFor="qgu-confirm-reason">
          <textarea id="qgu-confirm-reason" className="qgu-field" maxLength={500} value={reason} onChange={(event) => setReason(event.target.value)} />
        </Field>
      )}
      {typeToConfirm && (
        <Field label={`Type ${typeToConfirm} to confirm`} htmlFor="qgu-confirm-typed">
          <input id="qgu-confirm-typed" className="qgu-field" autoComplete="off" value={typed} onChange={(event) => setTyped(event.target.value)} placeholder={typeToConfirm} />
        </Field>
      )}
      {error && (
        <div className="qgu-banner qgu-banner--bad" role="alert">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}
    </Dialog>
  )
}

/** Page-level toasts (every tab's mutations report here). */
export function Notices({ admin }: { admin: AdminDashboard }) {
  if (!admin.notices.length) return null
  return (
    <div className="qgu qgu-toasts" aria-live="polite">
      {admin.notices.map((notice) => (
        <div key={notice.id} className={`qgu-banner ${notice.tone === 'error' ? 'qgu-banner--bad' : notice.tone === 'success' ? 'qgu-banner--ok' : 'qgu-banner--info'} shadow-xl`} style={{ background: 'var(--qg-dashboard-surface-strong)' }}>
          {notice.tone === 'error' ? <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" /> : notice.tone === 'success' ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" /> : <Info className="mt-0.5 h-4 w-4 shrink-0" />}
          <div className="min-w-0 flex-1">
            <div className="font-bold">{notice.title}</div>
            {notice.message && <div className="break-words text-xs opacity-90">{notice.message}</div>}
          </div>
          <NoticeTimer id={notice.id} tone={notice.tone} onDismiss={admin.dismissNotice} />
        </div>
      ))}
    </div>
  )
}

/** Auto-dismiss successes; errors stay until dismissed. */
function NoticeTimer({ id, tone, onDismiss }: { id: number; tone: 'success' | 'error' | 'info'; onDismiss: (id: number) => void }) {
  useEffect(() => {
    if (tone === 'error') return undefined
    const handle = window.setTimeout(() => onDismiss(id), tone === 'success' ? 5_000 : 9_000)
    return () => window.clearTimeout(handle)
  }, [id, onDismiss, tone])
  return (
    <button type="button" className="shrink-0 rounded p-0.5 hover:opacity-80" aria-label="Dismiss" onClick={() => onDismiss(id)}>
      <X className="h-4 w-4" />
    </button>
  )
}
