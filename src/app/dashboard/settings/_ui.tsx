import type { ReactNode } from 'react'

export const inputClass = 'w-full rounded-lg border border-gold/15 bg-[#0f1428]/45 px-3 py-2.5 text-sm text-white outline-none transition focus:border-gold/50 focus:bg-[#0f1428]/65 disabled:cursor-not-allowed disabled:opacity-60'
export const labelClass = 'mb-1.5 block text-[10px] font-black uppercase tracking-[0.16em] text-white/35'
export const ghostButtonClass = 'inline-flex items-center justify-center gap-2 rounded-lg border border-gold/20 bg-gold/[0.04] px-3 py-2 text-xs font-bold text-gold transition hover:border-gold/40 hover:bg-gold/[0.08] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gold/50 disabled:cursor-not-allowed disabled:opacity-50'
export const primaryButtonClass = 'inline-flex items-center justify-center gap-2 rounded-lg border border-gold/40 bg-gold px-4 py-2 text-xs font-black uppercase tracking-[0.12em] text-black shadow-[0_0_20px_rgba(212,175,55,0.18)] transition hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gold/60 disabled:cursor-not-allowed disabled:opacity-50'

export function SectionCard({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-lg border p-5 shadow-[0_0_30px_rgba(0,0,0,0.25)] ${className} glass-panel`}>
      {children}
    </div>
  )
}

/** Accessible on/off switch. Callers supply the visible label via `labelledBy`. */
export function Switch({
  checked,
  onChange,
  labelledBy,
  describedBy,
  disabled = false,
}: {
  checked: boolean
  onChange: (checked: boolean) => void
  labelledBy: string
  describedBy?: string
  disabled?: boolean
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-labelledby={labelledBy}
      aria-describedby={describedBy}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative h-7 w-12 shrink-0 rounded-full border transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gold/60 disabled:cursor-not-allowed disabled:opacity-50 ${checked ? 'border-gold/50 bg-gold/35' : 'border-white/15 bg-white/10'}`}
    >
      <span className={`absolute top-1 h-5 w-5 rounded-full bg-white shadow transition-all ${checked ? 'left-6' : 'left-1'}`} />
    </button>
  )
}

export function ToggleRow({
  id,
  title,
  description,
  checked,
  onChange,
  disabled,
}: {
  id: string
  title: string
  description: string
  checked: boolean
  onChange: (checked: boolean) => void
  disabled?: boolean
}) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-lg border border-white/10 bg-white/[0.025] p-3">
      <div>
        <div id={`${id}-label`} className="text-sm font-bold text-white/85">{title}</div>
        <div id={`${id}-desc`} className="mt-0.5 text-xs text-white/40">{description}</div>
      </div>
      <Switch checked={checked} onChange={onChange} labelledBy={`${id}-label`} describedBy={`${id}-desc`} disabled={disabled} />
    </div>
  )
}
