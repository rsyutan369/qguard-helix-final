/**
 * Quantum Simulation Range — shared presentation primitives.
 *
 * Everything the page draws more than once lives here, so the panels, the
 * numbers and the citations stay identical across eleven sections rather than
 * drifting into eleven dialects.
 *
 * The one rule these primitives enforce: `StatTile` and `DataRow` REQUIRE a
 * provenance. There is no way to render a number on this page without saying
 * where it came from, which is the property that makes the page trustworthy.
 */

import React from 'react';
import { motion } from 'framer-motion';
import { CITATIONS, type CitationKey, type Provenance } from '@/lib/quantum-sim';
import { PROVENANCE, QSR, tint } from './_theme';

/* ═══════════════════════════════════════════════════════════════ provenance */

export function ProvenanceBadge({ kind, compact = false }: { kind: Provenance; compact?: boolean }) {
  const meta = PROVENANCE[kind];
  return (
    <span
      title={meta.description}
      className={`inline-flex items-center gap-1 rounded-[3px] border font-mono font-bold uppercase leading-none ${
        compact ? 'px-1 py-[2px] text-[8px] tracking-[0.12em]' : 'px-1.5 py-[3px] text-[9px] tracking-[0.16em]'
      }`}
      style={{ color: meta.color, borderColor: tint(meta.color, 0.3), background: tint(meta.color, 0.08) }}
    >
      {kind === 'measured' && (
        <span className="relative flex h-1 w-1">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-70" style={{ background: meta.color }} />
          <span className="relative inline-flex h-1 w-1 rounded-full" style={{ background: meta.color }} />
        </span>
      )}
      {meta.label}
    </span>
  );
}

export function Cite({ source, inline = false }: { source: CitationKey; inline?: boolean }) {
  const citation = CITATIONS[source];
  return (
    <a
      href={citation.url}
      target="_blank"
      rel="noreferrer noopener"
      title={`${citation.title} — ${citation.published}`}
      className={`font-mono transition-colors hover:text-cyan-300 ${
        inline ? 'text-[10px] underline decoration-dotted underline-offset-2' : 'text-[10px]'
      }`}
      style={{ color: QSR.inkMuted }}
    >
      {citation.label}
    </a>
  );
}

/* ═══════════════════════════════════════════════════════════════════ panels */

export interface PanelProps {
  eyebrow?: string;
  title?: string;
  subtitle?: React.ReactNode;
  right?: React.ReactNode;
  accent?: string;
  className?: string;
  bodyClassName?: string;
  children: React.ReactNode;
}

export function Panel({ eyebrow, title, subtitle, right, accent = QSR.live, className = '', bodyClassName = '', children }: PanelProps) {
  return (
    <section
      className={`relative overflow-hidden rounded-2xl border ${className}`}
      style={{ background: QSR.panel, borderColor: QSR.hairline, backdropFilter: 'blur(14px)' }}
    >
      <span aria-hidden className="pointer-events-none absolute inset-x-0 top-0 h-px" style={{ background: `linear-gradient(90deg, transparent, ${tint(accent, 0.5)}, transparent)` }} />
      {(eyebrow || title || right) && (
        <header className="flex flex-wrap items-start justify-between gap-3 border-b px-5 py-4" style={{ borderColor: QSR.hairline }}>
          <div className="min-w-0">
            {eyebrow && (
              <div className="mb-1 font-mono text-[10px] font-bold uppercase tracking-[0.24em]" style={{ color: accent }}>
                {eyebrow}
              </div>
            )}
            {title && <h3 className="text-[15px] font-bold leading-tight text-slate-100">{title}</h3>}
            {subtitle && <div className="mt-1.5 max-w-3xl text-[12px] leading-relaxed" style={{ color: QSR.inkSoft }}>{subtitle}</div>}
          </div>
          {right && <div className="shrink-0">{right}</div>}
        </header>
      )}
      <div className={bodyClassName || 'p-5'}>{children}</div>
    </section>
  );
}

export function SectionHeading({
  index,
  eyebrow,
  title,
  lede,
  accent = QSR.live,
}: {
  index: string;
  eyebrow: string;
  title: string;
  lede: React.ReactNode;
  accent?: string;
}) {
  return (
    <div className="mb-6 flex gap-4 sm:gap-6">
      <div
        className="mt-1 hidden h-10 w-10 shrink-0 items-center justify-center rounded-lg border font-mono text-[13px] font-bold sm:flex"
        style={{ color: accent, borderColor: tint(accent, 0.3), background: tint(accent, 0.07) }}
      >
        {index}
      </div>
      <div className="min-w-0">
        <div className="font-mono text-[10px] font-bold uppercase tracking-[0.28em]" style={{ color: accent }}>
          {eyebrow}
        </div>
        <h2 className="mt-1.5 text-2xl font-black leading-tight tracking-tight text-slate-50 sm:text-[28px]">{title}</h2>
        <p className="mt-2.5 max-w-3xl text-[13px] leading-relaxed" style={{ color: QSR.inkSoft }}>
          {lede}
        </p>
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════ values */

export function StatTile({
  label,
  value,
  unit,
  provenance,
  source,
  accent = QSR.ink,
  note,
}: {
  label: string;
  value: React.ReactNode;
  unit?: string;
  provenance: Provenance;
  source?: CitationKey;
  accent?: string;
  note?: string;
}) {
  return (
    <div className="rounded-xl border px-3.5 py-3" style={{ borderColor: QSR.hairline, background: 'rgba(4,7,16,0.55)' }}>
      <div className="flex items-start justify-between gap-2">
        <span className="font-mono text-[9px] font-bold uppercase tracking-[0.16em]" style={{ color: QSR.inkMuted }}>
          {label}
        </span>
        <ProvenanceBadge kind={provenance} compact />
      </div>
      <div className="mt-1.5 flex items-baseline gap-1">
        <span className="font-mono text-[22px] font-bold leading-none tracking-tight" style={{ color: accent }}>
          {value}
        </span>
        {unit && (
          <span className="font-mono text-[11px]" style={{ color: QSR.inkMuted }}>
            {unit}
          </span>
        )}
      </div>
      {(note || source) && (
        <div className="mt-1.5 flex items-center gap-1.5 text-[10px] leading-snug" style={{ color: QSR.inkFaint }}>
          {note && <span className="min-w-0">{note}</span>}
          {source && <Cite source={source} />}
        </div>
      )}
    </div>
  );
}

export function DataRow({
  label,
  value,
  provenance,
  accent,
  mono = true,
}: {
  label: React.ReactNode;
  value: React.ReactNode;
  provenance?: Provenance;
  accent?: string;
  mono?: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-3 border-b py-2 last:border-b-0" style={{ borderColor: 'rgba(56,189,248,0.06)' }}>
      <span className="min-w-0 text-[12px]" style={{ color: QSR.inkSoft }}>
        {label}
      </span>
      <span className="flex shrink-0 items-center gap-2">
        <span className={`text-[12px] font-semibold ${mono ? 'font-mono' : ''}`} style={{ color: accent ?? QSR.ink }}>
          {value}
        </span>
        {provenance && <ProvenanceBadge kind={provenance} compact />}
      </span>
    </div>
  );
}

/* ═════════════════════════════════════════════════════════════════ controls */

export function Segmented<T extends string | number>({
  options,
  value,
  onChange,
  accent = QSR.live,
  size = 'md',
}: {
  options: Array<{ value: T; label: string; title?: string }>;
  value: T;
  onChange: (value: T) => void;
  accent?: string;
  size?: 'sm' | 'md';
}) {
  return (
    <div className="inline-flex flex-wrap gap-1 rounded-lg border p-1" style={{ borderColor: QSR.hairline, background: 'rgba(4,7,16,0.6)' }}>
      {options.map((option) => {
        const active = option.value === value;
        return (
          <button
            key={String(option.value)}
            type="button"
            title={option.title}
            onClick={() => onChange(option.value)}
            className={`relative rounded-md font-mono font-bold uppercase tracking-[0.1em] transition-colors ${
              size === 'sm' ? 'px-2 py-1 text-[9px]' : 'px-2.5 py-1.5 text-[10px]'
            }`}
            style={{
              color: active ? '#04060e' : QSR.inkSoft,
              background: active ? accent : 'transparent',
            }}
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}

export function Slider({
  label,
  value,
  min,
  max,
  step = 1,
  onChange,
  format,
  accent = QSR.live,
  hint,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  step?: number;
  onChange: (value: number) => void;
  format?: (value: number) => string;
  accent?: string;
  hint?: string;
}) {
  const percent = ((value - min) / (max - min)) * 100;
  return (
    <label className="block">
      <span className="flex items-baseline justify-between gap-2">
        <span className="font-mono text-[10px] font-bold uppercase tracking-[0.16em]" style={{ color: QSR.inkMuted }}>
          {label}
        </span>
        <span className="font-mono text-[12px] font-bold" style={{ color: accent }}>
          {format ? format(value) : value}
        </span>
      </span>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(event) => onChange(Number(event.target.value))}
        className="qsr-slider mt-2 w-full"
        style={{ ['--qsr-accent' as string]: accent, ['--qsr-fill' as string]: `${percent}%` }}
      />
      {hint && (
        <span className="mt-1 block text-[10px] leading-snug" style={{ color: QSR.inkFaint }}>
          {hint}
        </span>
      )}
    </label>
  );
}

export function ActionButton({
  children,
  onClick,
  accent = QSR.live,
  disabled = false,
  busy = false,
  variant = 'solid',
  className = '',
}: {
  children: React.ReactNode;
  onClick: () => void;
  accent?: string;
  disabled?: boolean;
  busy?: boolean;
  variant?: 'solid' | 'ghost';
  className?: string;
}) {
  return (
    <motion.button
      type="button"
      whileHover={disabled ? undefined : { scale: 1.02 }}
      whileTap={disabled ? undefined : { scale: 0.98 }}
      onClick={onClick}
      disabled={disabled || busy}
      className={`inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2 font-mono text-[11px] font-bold uppercase tracking-[0.14em] transition-opacity disabled:cursor-not-allowed disabled:opacity-45 ${className}`}
      style={
        variant === 'solid'
          ? { background: accent, color: '#04060e', boxShadow: `0 0 24px ${tint(accent, 0.28)}` }
          : { border: `1px solid ${tint(accent, 0.35)}`, color: accent, background: tint(accent, 0.06) }
      }
    >
      {busy && (
        <span
          className="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent"
          style={{ borderTopColor: 'transparent' }}
        />
      )}
      {children}
    </motion.button>
  );
}

/* ════════════════════════════════════════════════════════════════════ meters */

export function Meter({ value, max = 1, accent = QSR.live, height = 6 }: { value: number; max?: number; accent?: string; height?: number }) {
  const percent = Math.max(0, Math.min(100, (value / max) * 100));
  return (
    <div className="w-full overflow-hidden rounded-full" style={{ height, background: 'rgba(148,163,184,0.10)' }}>
      <motion.div
        className="h-full rounded-full"
        initial={false}
        animate={{ width: `${percent}%` }}
        transition={{ type: 'spring', stiffness: 120, damping: 20 }}
        style={{ background: accent, boxShadow: `0 0 12px ${tint(accent, 0.5)}` }}
      />
    </div>
  );
}

/**
 * Log-scale comparison bar. Used wherever two quantities differ by more than
 * three orders of magnitude — a linear bar there shows one full bar and one
 * invisible sliver, which communicates nothing.
 */
export function LogBar({
  value,
  floorLog10,
  ceilLog10,
  accent = QSR.model,
  label,
}: {
  value: number;
  floorLog10: number;
  ceilLog10: number;
  accent?: string;
  label?: string;
}) {
  const log = Math.log10(Math.max(value, 10 ** floorLog10));
  const percent = Math.max(0, Math.min(100, ((log - floorLog10) / (ceilLog10 - floorLog10)) * 100));
  return (
    <div>
      <div className="relative h-2 w-full overflow-hidden rounded-full" style={{ background: 'rgba(148,163,184,0.10)' }}>
        <motion.div
          className="absolute inset-y-0 left-0 rounded-full"
          initial={false}
          animate={{ width: `${percent}%` }}
          transition={{ type: 'spring', stiffness: 110, damping: 22 }}
          style={{ background: `linear-gradient(90deg, ${tint(accent, 0.35)}, ${accent})` }}
        />
      </div>
      {label && (
        <div className="mt-1 font-mono text-[9px] uppercase tracking-[0.14em]" style={{ color: QSR.inkFaint }}>
          {label}
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════ callout */

export function Callout({
  tone = 'info',
  title,
  children,
}: {
  tone?: 'info' | 'warn' | 'danger' | 'good';
  title?: string;
  children: React.ReactNode;
}) {
  const accent = tone === 'danger' ? QSR.broken : tone === 'warn' ? QSR.model : tone === 'good' ? QSR.safe : QSR.live;
  return (
    <div className="rounded-xl border px-4 py-3" style={{ borderColor: tint(accent, 0.25), background: tint(accent, 0.06) }}>
      {title && (
        <div className="mb-1 font-mono text-[10px] font-bold uppercase tracking-[0.18em]" style={{ color: accent }}>
          {title}
        </div>
      )}
      <div className="text-[12px] leading-relaxed" style={{ color: QSR.inkSoft }}>
        {children}
      </div>
    </div>
  );
}

/** A one-line label/value pair for dense technical strips. */
export function Chip({ label, value, accent = QSR.inkSoft }: { label: string; value: React.ReactNode; accent?: string }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-md border px-2 py-1 font-mono text-[10px]"
      style={{ borderColor: QSR.hairline, background: 'rgba(4,7,16,0.5)' }}
    >
      <span style={{ color: QSR.inkFaint }}>{label}</span>
      <span className="font-bold" style={{ color: accent }}>
        {value}
      </span>
    </span>
  );
}
