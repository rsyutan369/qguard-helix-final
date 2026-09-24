import { type ReactNode, useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { ChevronDown, X } from 'lucide-react'

export type Tone = 'ok' | 'warn' | 'bad' | 'info' | 'violet' | 'neutral'

// ---------------------------------------------------------------------------
// Formatting — times render in the viewer's time zone, and say so.
// ---------------------------------------------------------------------------

export const VIEWER_TIME_ZONE = (() => {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'local time'
  } catch {
    return 'local time'
  }
})()

export function formatCount(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—'
  return new Intl.NumberFormat('en-US').format(value)
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return 'Never'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'Unknown'
  return date.toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' })
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'Unknown'
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}

export function timeAgo(value: string | null | undefined, now = Date.now()): string {
  if (!value) return 'never'
  const ms = Date.parse(value)
  if (!Number.isFinite(ms)) return 'unknown'
  const diff = now - ms
  if (diff < 0) {
    const ahead = -diff
    if (ahead < 60_000) return 'in <1 min'
    if (ahead < 3_600_000) return `in ${Math.round(ahead / 60_000)} min`
    if (ahead < 86_400_000) return `in ${Math.round(ahead / 3_600_000)} h`
    return `in ${Math.round(ahead / 86_400_000)} d`
  }
  if (diff < 45_000) return 'just now'
  if (diff < 3_600_000) return `${Math.max(1, Math.round(diff / 60_000))} min ago`
  if (diff < 86_400_000) return `${Math.round(diff / 3_600_000)} h ago`
  if (diff < 30 * 86_400_000) return `${Math.round(diff / 86_400_000)} d ago`
  if (diff < 365 * 86_400_000) return `${Math.round(diff / (30 * 86_400_000))} mo ago`
  return `${Math.round(diff / (365 * 86_400_000))} y ago`
}

export function initials(name: string, email: string): string {
  const source = name || email || 'User'
  const parts = source.split(/[.\s@_-]+/).filter(Boolean)
  return (parts.slice(0, 2).map((part) => part[0]).join('') || 'U').toUpperCase()
}

/** Re-render on an interval so relative times ("3 min ago") stay true. */
export function useNow(intervalMs = 30_000) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const handle = window.setInterval(() => setNow(Date.now()), intervalMs)
    return () => window.clearInterval(handle)
  }, [intervalMs])
  return now
}

// ---------------------------------------------------------------------------
// Atoms
// ---------------------------------------------------------------------------

export function Chip({ tone = 'neutral', icon, children, title }: { tone?: Tone; icon?: ReactNode; children: ReactNode; title?: string }) {
  return (
    <span className={`qgu-chip ${tone === 'neutral' ? '' : `qgu-chip--${tone}`}`} title={title}>
      {icon}
      <span className="truncate">{children}</span>
    </span>
  )
}

export function Field({ label, hint, children, htmlFor }: { label: string; hint?: ReactNode; children: ReactNode; htmlFor?: string }) {
  return (
    <div>
      <label className="qgu-label" htmlFor={htmlFor}>{label}</label>
      {children}
      {hint && <p className="mt-1.5 text-xs qgu-muted">{hint}</p>}
    </div>
  )
}

export function SelectField({ value, onChange, children, label, id, className = '' }: {
  value: string
  onChange: (value: string) => void
  children: ReactNode
  label: string
  id?: string
  className?: string
}) {
  return (
    <div className={`relative ${className}`}>
      <select id={id} aria-label={label} className="qgu-field" value={value} onChange={(event) => onChange(event.target.value)}>
        {children}
      </select>
      <ChevronDown className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 qgu-muted" aria-hidden />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Dialog — portal, focus trap-lite, Esc to close, returns focus.
// ---------------------------------------------------------------------------

export function Dialog({ title, subtitle, icon, onClose, children, footer, busy = false, width }: {
  title: string
  subtitle?: ReactNode
  icon?: ReactNode
  onClose: () => void
  children: ReactNode
  footer?: ReactNode
  busy?: boolean
  width?: number
}) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null
    const first = ref.current?.querySelector<HTMLElement>('input, select, textarea, button:not([data-dialog-close])')
    first?.focus()
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !busy) onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('keydown', onKey)
      previous?.focus?.()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return createPortal(
    <div className="qgu">
      <div className="qgu-overlay" onClick={() => !busy && onClose()} />
      <div ref={ref} role="dialog" aria-modal="true" aria-label={title} className="qgu-dialog" style={width ? { width: `min(${width}px, calc(100vw - 32px))` } : undefined}>
        <div className="flex items-start justify-between gap-4 border-b px-5 py-4" style={{ borderColor: 'var(--qgu-border)' }}>
          <div className="flex min-w-0 items-start gap-3">
            {icon && <div className="mt-0.5 shrink-0">{icon}</div>}
            <div className="min-w-0">
              <h3 className="text-base font-black qgu-strong">{title}</h3>
              {subtitle && <div className="mt-1 text-sm qgu-soft">{subtitle}</div>}
            </div>
          </div>
          <button type="button" data-dialog-close className="qgu-btn qgu-btn--ghost qgu-btn--icon" onClick={onClose} disabled={busy} aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="space-y-4 px-5 py-4">{children}</div>
        {footer && <div className="flex flex-wrap justify-end gap-2 border-t px-5 py-4" style={{ borderColor: 'var(--qgu-border)' }}>{footer}</div>}
      </div>
    </div>,
    document.body,
  )
}

// ---------------------------------------------------------------------------
// Popover menu — fixed-positioned so the table's overflow never clips it.
// ---------------------------------------------------------------------------

export type MenuEntry =
  | { kind: 'group'; label: string }
  | { kind: 'separator' }
  | {
    kind: 'item'
    label: string
    description?: string
    icon?: ReactNode
    danger?: boolean
    disabled?: boolean
    disabledReason?: string
    onSelect: () => void
  }

export function ActionMenu({ label, trigger, entries, busy }: { label: string; trigger: ReactNode; entries: MenuEntry[]; busy?: boolean }) {
  const [open, setOpen] = useState(false)
  const [position, setPosition] = useState<{ top: number; left: number } | null>(null)
  const buttonRef = useRef<HTMLButtonElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)

  const place = useCallback(() => {
    const rect = buttonRef.current?.getBoundingClientRect()
    if (!rect) return
    const width = 264
    const menuHeight = menuRef.current?.offsetHeight || 360
    const left = Math.max(8, Math.min(window.innerWidth - width - 8, rect.right - width))
    const below = rect.bottom + 6
    const top = below + menuHeight > window.innerHeight - 8 ? Math.max(8, rect.top - menuHeight - 6) : below
    setPosition({ top, left })
  }, [])

  useLayoutEffect(() => {
    if (open) place()
  }, [open, place])

  useEffect(() => {
    if (!open) return undefined
    const onPointer = (event: MouseEvent) => {
      const target = event.target as Node
      if (!menuRef.current?.contains(target) && !buttonRef.current?.contains(target)) setOpen(false)
    }
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOpen(false)
        buttonRef.current?.focus()
      }
    }
    // The menu is fixed-positioned: close when the page (not the menu's own
    // list) scrolls, and re-anchor on resize.
    const onScroll = (event: Event) => {
      if (menuRef.current && event.target instanceof Node && menuRef.current.contains(event.target)) return
      setOpen(false)
    }
    const onResize = () => place()
    document.addEventListener('mousedown', onPointer)
    window.addEventListener('keydown', onKey)
    window.addEventListener('resize', onResize)
    window.addEventListener('scroll', onScroll, true)
    return () => {
      document.removeEventListener('mousedown', onPointer)
      window.removeEventListener('keydown', onKey)
      window.removeEventListener('resize', onResize)
      window.removeEventListener('scroll', onScroll, true)
    }
  }, [open, place])

  return (
    <>
      <button
        ref={buttonRef}
        type="button"
        className="qgu-btn qgu-btn--icon"
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        disabled={busy}
        onClick={() => setOpen((value) => !value)}
      >
        {trigger}
      </button>
      {open && createPortal(
        <div className="qgu">
          <div ref={menuRef} role="menu" aria-label={label} className="qgu-menu" style={position ? { top: position.top, left: position.left } : { visibility: 'hidden' }}>
            {entries.map((entry, index) => {
              if (entry.kind === 'group') return <div key={`g-${index}`} className="qgu-menu__group">{entry.label}</div>
              if (entry.kind === 'separator') return <div key={`s-${index}`} className="qgu-menu__sep" />
              return (
                <button
                  key={`i-${index}`}
                  type="button"
                  role="menuitem"
                  className={`qgu-menu__item ${entry.danger ? 'qgu-menu__item--danger' : ''}`}
                  disabled={entry.disabled}
                  title={entry.disabled ? entry.disabledReason : undefined}
                  onClick={() => {
                    setOpen(false)
                    entry.onSelect()
                  }}
                >
                  {entry.icon && <span className="mt-0.5 shrink-0">{entry.icon}</span>}
                  <span className="min-w-0">
                    {entry.label}
                    {(entry.disabled ? entry.disabledReason : entry.description) && <small>{entry.disabled ? entry.disabledReason : entry.description}</small>}
                  </span>
                </button>
              )
            })}
          </div>
        </div>,
        document.body,
      )}
    </>
  )
}
