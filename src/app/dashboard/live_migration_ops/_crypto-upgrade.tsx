'use client'

import { ArrowRight, Sparkles } from 'lucide-react'

/**
 * Cryptographic Upgrade — Before → After.
 *
 * Every row is an algorithm transition recorded on the tenant's own migration
 * jobs (sandbox simulations excluded). With no jobs there is nothing to show,
 * so the panel says so instead of listing generic upgrade paths that would
 * read as if they had been detected in the estate.
 */

const PANEL = 'rounded-2xl border border-white/10 bg-white/[0.035] backdrop-blur-xl text-white shadow-[0_18px_60px_rgba(0,0,0,0.35)]'
const INNER = 'rounded-xl border border-white/10 bg-white/[0.02]'

export interface CryptoTransition {
  from: string
  to: string
  /** Standard the TARGET algorithm belongs to, or null when it is not a recognised NIST target. */
  standard: string | null
  jobs: number
  completed: number
}

function fmt(n: number) {
  return new Intl.NumberFormat('en-US').format(Math.round(n || 0))
}

/** The NIST standard a migration target falls under — from the target name only, never assumed. */
export function targetStandard(target: string): string | null {
  const t = target.toUpperCase()
  if (/ML-KEM|KYBER/.test(t)) return 'FIPS 203 · key establishment'
  if (/ML-DSA|DILITHIUM/.test(t)) return 'FIPS 204 · signatures'
  if (/SLH-DSA|SPHINCS/.test(t)) return 'FIPS 205 · signatures'
  if (/SHA3|SHA-3|SHAKE/.test(t)) return 'FIPS 202 · hashing'
  if (/AES-?256/.test(t)) return 'FIPS 197 · symmetric'
  return null
}

export default function CryptoUpgradePanel({ transitions, loading }: { transitions: CryptoTransition[]; loading: boolean }) {
  return (
    <section className={`${PANEL} p-5`}>
      <div className="mb-1 flex items-center gap-2">
        <Sparkles className="h-4 w-4 text-cyan-300" />
        <h3 className="text-sm font-black uppercase tracking-wide text-white/80">Cryptographic Upgrade — Before → After</h3>
      </div>
      <p className="mb-3 text-[11px] text-white/45">Algorithm transitions recorded on your migration jobs. Sandbox simulations are excluded.</p>
      {transitions.length ? (
        <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
          {transitions.map((t) => (
            <div key={`${t.from}->${t.to}`} className={`${INNER} p-3`}>
              <div className="grid grid-cols-[1fr_auto_1fr] items-center gap-2">
                <span className="truncate rounded-lg border border-red-400/25 bg-red-400/[0.07] px-2.5 py-1.5 text-center font-mono text-[11px] font-bold text-red-200" title={t.from}>{t.from}</span>
                <ArrowRight className="h-4 w-4 text-cyan-300" />
                <span className="truncate rounded-lg border border-emerald-400/25 bg-emerald-400/[0.07] px-2.5 py-1.5 text-center font-mono text-[11px] font-bold text-emerald-200" title={t.to}>{t.to}</span>
              </div>
              <div className="mt-1 flex items-center justify-between gap-2 text-[10px] text-white/35">
                <span className="truncate">{t.standard || 'Target not a recognised NIST PQC standard'}</span>
                <span className="shrink-0">{fmt(t.completed)}/{fmt(t.jobs)} job{t.jobs === 1 ? '' : 's'} completed</span>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <p className={`${INNER} px-4 py-5 text-center text-[11px] text-white/40`}>
          {loading ? 'Loading migration jobs…' : 'No algorithm transitions yet. They appear here as soon as a migration plan creates jobs for your assets.'}
        </p>
      )}
    </section>
  )
}
