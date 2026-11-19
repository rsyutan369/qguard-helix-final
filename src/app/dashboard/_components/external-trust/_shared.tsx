'use client'

import { Component, useEffect, useMemo, useRef, useState, type ErrorInfo, type ReactNode } from 'react'
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion'
import { Link, useLocation } from 'react-router-dom'
import {
  AlertTriangle, ArrowRight, BadgeCheck, FlaskConical, Globe2, Link2, RefreshCw,
  Search, Sparkles, X, type LucideIcon,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Panel, PanelHeader, TONE, type Tone as PrimitiveTone } from '../executive/primitives'
import { askSophia } from '@/lib/sophia-bridge'
import {
  EVIDENCE_LABEL, READINESS_LABEL, RISK_LABEL, TRUST_LABEL, EXPERIMENT_LABEL,
  type EvidenceState, type ExperimentOutcome, type Readiness, type RiskLevel, type TrustState,
} from '@/lib/ecosystem/external-trust-intelligence'

/**
 * Shared kit for the External Trust & Ecosystem suite.
 *
 * The four pages must read as one product, so every status pill, table shell,
 * drawer and empty state comes from here. Status colour is always paired with a
 * glyph and a word — colour alone never carries meaning (§67).
 */

export type Tone = 'good' | 'warning' | 'critical' | 'neutral' | 'info' | 'ai'

export const TONE_HEX: Record<Tone, string> = {
  good: '#34d399', warning: '#fbbf24', critical: '#f87171',
  neutral: '#22d3ee', info: '#60a5fa', ai: '#a78bfa',
}

/** `unknown` is deliberately INFO-blue, never green: unknown is not safe. */
export const READINESS_TONE: Record<Readiness, Tone> = {
  ready: 'good', 'hybrid-ready': 'good', preparing: 'warning',
  committed: 'info', 'not-ready': 'critical', unknown: 'info',
}
export const READINESS_GLYPH: Record<Readiness, string> = {
  ready: '●', 'hybrid-ready': '◕', preparing: '◑', committed: '◔', 'not-ready': '■', unknown: '?',
}

export const RISK_TONE: Record<RiskLevel, Tone> = {
  critical: 'critical', high: 'warning', medium: 'warning', low: 'good', unknown: 'info',
}
export const RISK_GLYPH: Record<RiskLevel, string> = {
  critical: '■', high: '▲', medium: '◆', low: '●', unknown: '?',
}

export const EVIDENCE_TONE: Record<EvidenceState, Tone> = {
  complete: 'good', partial: 'warning', requested: 'info', pending: 'info',
  overdue: 'critical', rejected: 'critical', unknown: 'info',
}

export const TRUST_TONE: Record<TrustState, Tone> = {
  trusted: 'good', valid: 'good', expiring: 'warning', weak: 'warning',
  broken: 'critical', unknown: 'info',
}

export const OUTCOME_TONE: Record<ExperimentOutcome, Tone> = {
  passed: 'good', 'passed-with-warnings': 'warning', conditional: 'warning',
  failed: 'critical', 'not-evaluated': 'info',
}

/* ------------------------------------------------------------------ */
/* Formatters                                                          */
/* ------------------------------------------------------------------ */

export function numberFmt(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—'
  return new Intl.NumberFormat('en-US').format(Math.round(value))
}

/** Renders an unmeasured value honestly — never as 0. */
export function scoreFmt(value: number | null | undefined, suffix = ''): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return 'Unknown'
  return `${Math.round(value)}${suffix}`
}

export const pctFmt = (value: number | null | undefined) => scoreFmt(value, '%')

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return 'never'
  const then = new Date(iso).getTime()
  if (!Number.isFinite(then)) return 'never'
  const diff = Date.now() - then
  if (diff < 60_000) return 'just now'
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`
  return `${Math.floor(diff / 86_400_000)}d ago`
}

export function dateFmt(iso: string | null | undefined): string {
  if (!iso) return 'Not set'
  const date = new Date(iso)
  if (!Number.isFinite(date.getTime())) return 'Not set'
  return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
}

export function downloadTextFile(filename: string, content: string, type: string): void {
  const blob = new Blob([content], { type })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  URL.revokeObjectURL(url)
}

export { quotedCsvCell as csvCell } from '@/lib/csv'

/* ------------------------------------------------------------------ */
/* Status pills                                                        */
/* ------------------------------------------------------------------ */

export function Chip({ children, tone = 'neutral', glyph, title }: {
  children: ReactNode; tone?: Tone; glyph?: string; title?: string
}) {
  const t = TONE[tone as PrimitiveTone]
  return (
    <span title={title} className={cn(
      'inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[9px] font-black uppercase tracking-wider',
      t.text, t.soft, t.border,
    )}>
      {glyph && <span aria-hidden="true">{glyph}</span>}
      {children}
    </span>
  )
}

export const ReadinessChip = ({ value }: { value: Readiness }) => (
  <Chip tone={READINESS_TONE[value]} glyph={READINESS_GLYPH[value]}>{READINESS_LABEL[value]}</Chip>
)
export const RiskChip = ({ value }: { value: RiskLevel }) => (
  <Chip tone={RISK_TONE[value]} glyph={RISK_GLYPH[value]}>{RISK_LABEL[value]}</Chip>
)
export const EvidenceChip = ({ value }: { value: EvidenceState }) => (
  <Chip tone={EVIDENCE_TONE[value]}>{EVIDENCE_LABEL[value]}</Chip>
)
export const TrustChip = ({ value }: { value: TrustState }) => (
  <Chip tone={TRUST_TONE[value]}>{TRUST_LABEL[value]}</Chip>
)
export const OutcomeChip = ({ value }: { value: ExperimentOutcome }) => (
  <Chip tone={OUTCOME_TONE[value]}>{EXPERIMENT_LABEL[value]}</Chip>
)

/** PASS / FAIL / UNKNOWN with a glyph, never colour alone. */
export function VerdictChip({ value }: { value: 'pass' | 'fail' | 'unknown' }) {
  const tone: Tone = value === 'pass' ? 'good' : value === 'fail' ? 'critical' : 'info'
  const glyph = value === 'pass' ? '✓' : value === 'fail' ? '✕' : '?'
  return <Chip tone={tone} glyph={glyph}>{value === 'unknown' ? 'Unknown' : value.toUpperCase()}</Chip>
}

/* ------------------------------------------------------------------ */
/* Page shell                                                          */
/* ------------------------------------------------------------------ */

export const SUITE_PAGES = [
  { key: 'vendor', label: 'Vendor PQC Readiness', short: 'Vendors', route: '/dashboard/vendor-pqc-readiness', icon: BadgeCheck, question: 'Who do we depend on?' },
  { key: 'ecosystem', label: 'Ecosystem Dependency Map', short: 'Ecosystem', route: '/dashboard/ecosystem-dependency-map', icon: Globe2, question: 'What do we depend on?' },
  { key: 'trust', label: 'Trust Chain Analyzer', short: 'Trust', route: '/dashboard/trust-chain-analyzer', icon: Link2, question: 'What trust relationships exist?' },
  { key: 'lab', label: 'Hybrid Crypto Lab', short: 'Lab', route: '/dashboard/hybrid-crypto-lab', icon: FlaskConical, question: 'Will the new crypto work?' },
] as const

export type SuiteKey = (typeof SUITE_PAGES)[number]['key']

/** The entity the user is investigating — carried across the suite by ID, never by display name. */
export interface SuiteContext {
  vendor?: string | null
  asset?: string | null
}

/** Each page's own parameter vocabulary for the same investigation context. */
export function suiteHref(key: SuiteKey, context?: SuiteContext): string {
  const page = SUITE_PAGES.find((candidate) => candidate.key === key)!
  const params = new URLSearchParams()
  if (key === 'ecosystem') {
    if (context?.vendor) params.set('focus', `vendor:${context.vendor}`)
    else if (context?.asset) params.set('focus', `asset:${context.asset}`)
  } else if (key === 'vendor') {
    if (context?.vendor) params.set('vendor', context.vendor)
  } else {
    if (context?.vendor) params.set('vendor', context.vendor)
    if (context?.asset) params.set('asset', context.asset)
  }
  const query = params.toString()
  return query ? `${page.route}?${query}` : page.route
}

/** The four-page rail: shows where the user is in the External Trust flow. */
export function SuiteRail({ current, context }: { current: SuiteKey; context?: SuiteContext }) {
  return (
    <nav aria-label="External Trust suite" className="flex gap-1.5 overflow-x-auto pb-0.5">
      {SUITE_PAGES.map((page, index) => {
        const Icon = page.icon
        const active = page.key === current
        return (
          <Link
            key={page.key}
            to={suiteHref(page.key, context)}
            aria-current={active ? 'page' : undefined}
            className={cn(
              'group flex min-w-[168px] flex-1 items-center gap-2 rounded-lg border px-3 py-2 no-underline transition',
              active
                ? 'border-cyan-400/50 bg-cyan-500/10'
                : 'border-white/8 bg-white/[0.02] hover:border-cyan-400/30 hover:bg-cyan-500/[0.04]',
            )}
          >
            <span className={cn(
              'grid h-7 w-7 shrink-0 place-items-center rounded-md border text-[10px] font-black',
              active ? 'border-cyan-400/40 bg-cyan-500/15 text-cyan-200' : 'border-white/10 bg-white/5 text-white/40',
            )}>
              <Icon className="h-3.5 w-3.5" />
            </span>
            <span className="min-w-0">
              <span className={cn('block truncate text-[10px] font-black uppercase tracking-wider', active ? 'text-cyan-200' : 'text-white/60')}>
                {page.short}
              </span>
              <span className="block truncate text-[9px] text-white/30">{index + 1}. {page.question}</span>
            </span>
          </Link>
        )
      })}
    </nav>
  )
}

export function PageHeader({
  title, subtitle, icon: Icon, live, generatedAt, onRefresh, refreshing, actions, sophiaPrompt,
}: {
  title: string
  subtitle: string
  icon: LucideIcon
  live: boolean
  generatedAt: string | null | undefined
  onRefresh: () => void
  refreshing: boolean
  actions?: ReactNode
  sophiaPrompt: string
}) {
  return (
    <header className="flex flex-col gap-3 border-b border-white/10 pb-3.5 xl:flex-row xl:items-end xl:justify-between">
      <div className="flex items-center gap-3">
        <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-cyan-400/30 bg-cyan-500/10 text-cyan-300 shadow-[0_0_28px_rgba(34,211,238,0.18)]">
          <Icon className="h-5 w-5" />
        </div>
        <div className="min-w-0">
          <h1 className="text-2xl font-black uppercase leading-none tracking-tight text-white lg:text-[25px]">{title}</h1>
          <p className="mt-1.5 max-w-3xl text-[12px] font-medium leading-relaxed text-white/45">{subtitle}</p>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-[10px] uppercase tracking-widest text-white/30">Synced {relativeTime(generatedAt)}</span>
        <span className={cn(
          'flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-[9px] font-black uppercase tracking-widest',
          live ? 'border-emerald-400/40 bg-emerald-500/10 text-emerald-300' : 'border-amber-400/40 bg-amber-500/10 text-amber-300',
        )}>
          <span className={cn('h-1.5 w-1.5 rounded-full', live ? 'animate-pulse bg-emerald-400' : 'bg-amber-300')} />
          {live ? 'Live' : 'Snapshot'}
        </span>
        {actions}
        <button
          type="button"
          onClick={() => askSophia(sophiaPrompt, title)}
          className="inline-flex items-center gap-1.5 rounded-lg border border-violet-400/45 bg-violet-500/12 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-violet-200 transition hover:bg-violet-500/22"
        >
          <Sparkles className="h-3.5 w-3.5" /> Ask Sophia
        </button>
        <button
          type="button"
          onClick={onRefresh}
          className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/25"
        >
          <RefreshCw className={cn('h-3.5 w-3.5', refreshing && 'animate-spin')} /> Refresh
        </button>
      </div>
    </header>
  )
}

/** Compact KPI row — deliberately small tiles, not dashboard slabs (§8/§21). */
export function KpiStrip({ items }: {
  items: Array<{ key: string; label: string; value: string; detail: string; tone: Tone; onClick?: () => void; title?: string }>
}) {
  return (
    <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-6">
      {items.map((item) => {
        const t = TONE[item.tone as PrimitiveTone]
        const body = (
          <Panel className="h-full p-3 transition-transform group-hover/kpi:-translate-y-0.5">
            <div className="truncate text-[8px] font-black uppercase tracking-wider text-white/45">{item.label}</div>
            <div className={cn('mt-1.5 truncate text-lg font-black leading-none', t.text)}>{item.value}</div>
            <div className="mt-1 truncate text-[8.5px] font-semibold text-white/35">{item.detail}</div>
          </Panel>
        )
        return item.onClick ? (
          <button key={item.key} type="button" onClick={item.onClick} title={item.title} className="group/kpi text-left">{body}</button>
        ) : (
          <div key={item.key} title={item.title} className="group/kpi">{body}</div>
        )
      })}
    </div>
  )
}

export function SectionCard({ id, title, icon, right, children, live, className }: {
  id?: string; title: string; icon?: LucideIcon; right?: ReactNode
  children: ReactNode; live?: boolean; className?: string
}) {
  return (
    <Panel className={cn('p-5', className)}>
      {id && <div id={id} className="scroll-mt-24" />}
      <PanelHeader title={title} icon={icon} right={right} live={live} />
      {children}
    </Panel>
  )
}

/* ------------------------------------------------------------------ */
/* States                                                              */
/* ------------------------------------------------------------------ */

/**
 * `cta` takes EITHER a route (`href`) or an in-page action (`onClick`).
 *
 * It deliberately does NOT accept `href: '#'`: a call to action that navigates
 * nowhere reads as a broken page. An action that stays on the page must be a
 * button, so keyboard and screen-reader users get the right affordance too.
 */
export function EmptyState({ icon: Icon, title, detail, cta }: {
  icon: LucideIcon; title: string; detail: string
  cta?: { label: string; href: string; onClick?: never } | { label: string; onClick: () => void; href?: never }
}) {
  const ctaClass = 'mt-1 rounded border border-cyan-400/40 bg-cyan-500/10 px-3.5 py-2 text-[10px] font-black uppercase tracking-wider text-cyan-200 no-underline transition hover:bg-cyan-500/20'
  return (
    <div className="flex min-h-[180px] flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-white/12 bg-white/[0.02] p-6 text-center">
      <Icon className="h-7 w-7 text-white/25" />
      <p className="text-[13px] font-bold text-white/65">{title}</p>
      <p className="max-w-xl text-[11px] leading-relaxed text-white/35">{detail}</p>
      {cta && (cta.href
        ? <a href={cta.href} className={ctaClass}>{cta.label}</a>
        : <button type="button" onClick={cta.onClick} className={ctaClass}>{cta.label}</button>
      )}
    </div>
  )
}

/**
 * Catches a RENDER fault so one bad field cannot blank the whole application.
 *
 * Without a boundary anywhere above them, an exception thrown while rendering
 * unmounts the entire React tree and the user is left staring at the bare
 * dashboard background — indistinguishable from a hang. That is exactly what a
 * shape mismatch in the experiment result did. This does not excuse the bug; it
 * bounds the blast radius to the panel that failed and keeps the error visible
 * instead of silent.
 */
export class PageErrorBoundary extends Component<
  { children: ReactNode; page: string },
  { error: Error | null }
> {
  state: { error: Error | null } = { error: null }

  static getDerivedStateFromError(error: Error) {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(`[${this.props.page}] render failed:`, error, info.componentStack)
  }

  render() {
    if (!this.state.error) return this.props.children
    return (
      <div className="min-h-screen space-y-4 p-3 lg:p-5">
        <Panel className="p-8 text-center">
          <AlertTriangle className="mx-auto h-8 w-8 text-red-400" />
          <h2 className="mt-3 text-[16px] font-black text-white">{this.props.page} could not be displayed</h2>
          <p className="mx-auto mt-1.5 max-w-lg text-[11.5px] leading-relaxed text-white/45">
            The page failed while rendering. Your data is unaffected — this is a display fault, and it has been logged to the browser console.
          </p>
          <p className="mx-auto mt-2 max-w-lg overflow-x-auto rounded-lg border border-white/10 bg-black/25 p-2.5 font-mono text-[10px] text-red-300">
            {this.state.error.message}
          </p>
          <div className="mt-4 flex flex-wrap justify-center gap-2">
            <button type="button" onClick={() => this.setState({ error: null })}
              className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-cyan-200">
              <RefreshCw className="h-3 w-3" /> Try again
            </button>
            <a href="/dashboard" className="inline-flex items-center rounded-lg border border-white/12 bg-white/5 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-white/50 no-underline">
              Back to dashboard
            </a>
          </div>
        </Panel>
      </div>
    )
  }
}

export function ErrorState({ message, onRetry, lastGoodAt }: { message: string; onRetry: () => void; lastGoodAt: string | null }) {
  return (
    <Panel className="p-8 text-center">
      <AlertTriangle className="mx-auto h-8 w-8 text-red-400" />
      <h2 className="mt-3 text-[16px] font-black text-white">Data Unavailable</h2>
      <p className="mx-auto mt-1.5 max-w-lg text-[11.5px] leading-relaxed text-white/45">
        QGuard Helix could not retrieve this assessment. No values are shown rather than presenting zeros as fact.
      </p>
      <p className="mx-auto mt-2 max-w-lg rounded-lg border border-white/10 bg-black/25 p-2.5 font-mono text-[10px] text-red-300">{message}</p>
      <div className="mt-4 flex flex-wrap justify-center gap-2">
        <button type="button" onClick={onRetry} className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-cyan-200">
          <RefreshCw className="h-3 w-3" /> Retry
        </button>
        {lastGoodAt && (
          <span className="inline-flex items-center rounded-lg border border-white/12 bg-white/5 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-white/50">
            Last successful assessment {relativeTime(lastGoodAt)}
          </span>
        )}
      </div>
    </Panel>
  )
}

export function SkeletonPage({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-6">
        {Array.from({ length: 6 }).map((_, index) => (
          <div key={index} className="h-[74px] animate-pulse rounded-xl border border-white/10 bg-white/[0.03]" />
        ))}
      </div>
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="h-[220px] animate-pulse rounded-xl border border-white/10 bg-white/[0.03]" />
      ))}
    </div>
  )
}

/** Shown when an optional backend capability has not been provisioned (§74). */
export function CapabilityNotice({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="flex flex-wrap items-center gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3">
      <AlertTriangle className="h-4 w-4 shrink-0 text-amber-300" />
      <div className="min-w-0 flex-1">
        <div className="text-[11.5px] font-black text-amber-200">{title}</div>
        <div className="text-[10px] leading-relaxed text-white/50">{detail}</div>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Drawer                                                              */
/* ------------------------------------------------------------------ */

export function Drawer({ open, title, subtitle, tone = 'neutral', onClose, children, footer }: {
  open: boolean; title: string; subtitle: string; tone?: Tone
  onClose: () => void; children: ReactNode; footer?: ReactNode
}) {
  const reduce = useReducedMotion()
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    ref.current?.focus()
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  const t = TONE[tone as PrimitiveTone]

  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div
            initial={reduce ? false : { opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-[70] bg-black/55 backdrop-blur-[2px]" onClick={onClose} aria-hidden="true"
          />
          <motion.div
            ref={ref} tabIndex={-1} role="dialog" aria-modal="true" aria-label={title}
            initial={reduce ? false : { x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }}
            transition={{ type: 'spring', stiffness: 380, damping: 36 }}
            className="fixed right-0 top-0 z-[71] flex h-full w-full max-w-[580px] flex-col border-l border-white/10 bg-[#080e1b] shadow-[0_0_80px_rgba(0,0,0,0.7)] outline-none"
          >
            <div className={cn('flex items-start justify-between gap-3 border-b border-white/10 p-4', t.soft)}>
              <div className="min-w-0">
                <h2 className={cn('truncate text-[15px] font-black leading-tight', t.text)}>{title}</h2>
                <p className="mt-0.5 truncate text-[10px] font-semibold uppercase tracking-wider text-white/40">{subtitle}</p>
              </div>
              <button type="button" onClick={onClose} aria-label="Close details"
                className="grid h-8 w-8 shrink-0 place-items-center rounded-lg text-white/45 transition hover:bg-white/10 hover:text-white">
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="flex-1 space-y-3 overflow-y-auto p-4 scrollbar-thin">{children}</div>
            {footer && <div className="border-t border-white/10 bg-black/30 p-3">{footer}</div>}
          </motion.div>
        </>
      )}
    </AnimatePresence>
  )
}

export function Field({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="rounded-lg border border-white/8 bg-black/25 px-2.5 py-2">
      <div className="text-[8px] font-black uppercase tracking-widest text-cyan-300/60">{label}</div>
      <div className={cn('mt-0.5 break-words text-[11px] font-bold text-white/80', mono && 'font-mono')}>{value}</div>
    </div>
  )
}

export function Block({ title, children, right }: { title: string; children: ReactNode; right?: ReactNode }) {
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between gap-2">
        <div className="text-[9px] font-black uppercase tracking-[0.16em] text-white/40">{title}</div>
        {right}
      </div>
      {children}
    </div>
  )
}

export function DrawerLink({ href, children, primary }: { href: string; children: ReactNode; primary?: boolean }) {
  return (
    <a href={href} className={cn(
      'inline-flex items-center gap-1.5 rounded-lg border px-3 py-2 text-[9px] font-black uppercase tracking-wider no-underline transition',
      primary
        ? 'border-cyan-400/50 bg-cyan-500/15 text-cyan-200 hover:bg-cyan-500/25'
        : 'border-white/12 bg-white/5 text-white/60 hover:border-cyan-400/40 hover:text-cyan-300',
    )}>
      {children}
    </a>
  )
}

export function AskSophiaButton({ question, context }: { question: string; context?: string }) {
  return (
    <button
      type="button"
      onClick={() => askSophia(question, context)}
      className="inline-flex items-center gap-1.5 rounded-lg border border-violet-400/40 bg-violet-500/10 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-violet-200 transition hover:bg-violet-500/20"
    >
      <Sparkles className="h-3 w-3" /> Ask Sophia
    </button>
  )
}

/* ------------------------------------------------------------------ */
/* Table shell                                                         */
/* ------------------------------------------------------------------ */

export function SearchInput({ value, onChange, placeholder, label }: {
  value: string; onChange: (value: string) => void; placeholder: string; label: string
}) {
  return (
    <label className="relative min-w-[190px] flex-1">
      <span className="sr-only">{label}</span>
      <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/30" />
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="h-8 w-full rounded-lg border border-white/10 bg-black/30 pl-8 pr-2.5 text-[11px] text-white/85 placeholder:text-white/25 focus:border-cyan-400/50 focus:outline-none"
      />
    </label>
  )
}

export function Select({ label, value, onChange, options }: {
  label: string; value: string; onChange: (value: string) => void; options: Array<[string, string]>
}) {
  return (
    <label className="relative">
      <span className="sr-only">{label}</span>
      <select
        value={value} onChange={(event) => onChange(event.target.value)} aria-label={label}
        className="h-8 max-w-[190px] rounded-lg border border-white/10 bg-black/30 px-2.5 text-[10.5px] font-semibold text-white/75 focus:border-cyan-400/50 focus:outline-none"
      >
        {options.map(([optionValue, optionLabel]) => (
          <option key={optionValue} value={optionValue} className="bg-[#0b1120] text-white">{optionLabel}</option>
        ))}
      </select>
    </label>
  )
}

export function Pagination({ page, pages, onPage }: { page: number; pages: number; onPage: (page: number) => void }) {
  if (pages <= 1) return null
  return (
    <div className="mt-3 flex items-center justify-end gap-2 border-t border-white/8 pt-2.5">
      <button type="button" disabled={page === 0} onClick={() => onPage(page - 1)}
        className="rounded border border-white/10 px-2.5 py-1 text-[9px] font-black uppercase text-white/55 disabled:opacity-30">Prev</button>
      <span className="font-mono text-[9px] text-white/40">Page {page + 1} of {pages}</span>
      <button type="button" disabled={page >= pages - 1} onClick={() => onPage(page + 1)}
        className="rounded border border-white/10 px-2.5 py-1 text-[9px] font-black uppercase text-white/55 disabled:opacity-30">Next</button>
    </div>
  )
}

/** Column-visibility control for the enterprise tables (§57). */
export function ColumnToggle<T extends string>({ columns, hidden, onToggle }: {
  columns: Array<{ key: T; label: string; locked?: boolean }>
  hidden: Set<T>
  onToggle: (key: T) => void
}) {
  const [open, setOpen] = useState(false)
  return (
    <div className="relative">
      <button type="button" onClick={() => setOpen((value) => !value)} aria-expanded={open}
        className="inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-2 py-1 text-[9px] font-black uppercase tracking-wider text-white/55 transition hover:text-cyan-300">
        Columns
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-20" onClick={() => setOpen(false)} aria-hidden="true" />
          <div className="absolute right-0 top-full z-30 mt-1 w-52 rounded-lg border border-white/12 bg-[#0b1120] p-2 shadow-xl">
            {columns.map((column) => (
              <label key={column.key} className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-[10.5px] text-white/70 hover:bg-white/5">
                <input
                  type="checkbox"
                  checked={!hidden.has(column.key)}
                  disabled={column.locked}
                  onChange={() => onToggle(column.key)}
                  className="h-3 w-3 accent-cyan-400"
                />
                {column.label}
              </label>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Provenance footer — every page states where its numbers came from   */
/* ------------------------------------------------------------------ */

export function ProvenanceFooter({ evidence, generatedAt, extra }: {
  evidence: { sources: string[]; note: string } | undefined
  generatedAt: string | null | undefined
  extra?: string
}) {
  return (
    <footer className="flex flex-col gap-1.5 border-t border-white/8 pt-3 text-[10px] font-mono uppercase tracking-wider text-white/25 md:flex-row md:items-center md:justify-between">
      <span className="truncate" title={evidence?.note}>
        {evidence?.sources.length ? `${evidence.sources.length} evidence source(s): ${evidence.sources.join(', ')}` : 'No evidence source connected'}
      </span>
      <span>{extra ? `${extra} · ` : ''}Snapshot {relativeTime(generatedAt)}</span>
    </footer>
  )
}

/** Reads `?vendor=` / `?focus=` etc. so cross-page links land in context (§54). */
export function useQueryParam(key: string): string {
  const location = useLocation()
  return useMemo(() => new URLSearchParams(location.search).get(key) || '', [location.search, key])
}

export { ArrowRight, Link2 }
