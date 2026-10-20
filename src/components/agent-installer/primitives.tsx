import { useCallback, useState, type ReactNode } from 'react';
import { Check, Copy } from 'lucide-react';
import type { ConnectionState } from '@/lib/agent-installer/agent-release';

/**
 * Shared presentation primitives for the Agent Center.
 *
 * The status vocabulary here is the load-bearing part: every label maps 1:1 to a
 * backend-derived state and none of them can be produced by absence of data.
 * "Waiting" (never checked in) is deliberately distinct from "Offline" (checked
 * in, then stopped), because collapsing the two would let an agent that was
 * never installed read as one that merely went quiet (spec §29).
 */

export const CONNECTION_STYLES: Record<ConnectionState, { label: string; dot: string; chip: string; help: string }> = {
  Connected: {
    label: 'Connected',
    dot: 'bg-emerald-400',
    chip: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-200',
    help: 'Heartbeat received within the last 10 minutes.',
  },
  Connecting: {
    label: 'Connecting',
    dot: 'bg-cyan-300 animate-pulse',
    chip: 'border-cyan-400/30 bg-cyan-400/10 text-cyan-200',
    help: 'Created recently and has not sent its first heartbeat yet.',
  },
  Waiting: {
    label: 'Awaiting install',
    dot: 'bg-white/40',
    chip: 'border-white/15 bg-white/[0.04] text-white/60',
    help: 'This agent has never checked in. Install the generated package on the target host.',
  },
  Offline: {
    label: 'Offline',
    dot: 'bg-amber-400',
    chip: 'border-amber-400/30 bg-amber-400/10 text-amber-200',
    help: 'The agent checked in before but its heartbeat has stopped.',
  },
  Error: {
    label: 'Error',
    dot: 'bg-rose-400',
    chip: 'border-rose-400/30 bg-rose-400/10 text-rose-200',
    help: 'The agent reported a failure on its last cycle.',
  },
};

export function StatusChip({ state, className = '' }: { state: ConnectionState; className?: string }) {
  const style = CONNECTION_STYLES[state] || CONNECTION_STYLES.Waiting;
  return (
    <span
      title={style.help}
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-bold ${style.chip} ${className}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${style.dot}`} />
      {style.label}
    </span>
  );
}

export function Card({
  label,
  value,
  hint,
  tone = 'default',
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: 'default' | 'good' | 'warn' | 'bad' | 'accent';
}) {
  const tones: Record<string, string> = {
    default: 'text-white',
    good: 'text-emerald-300',
    warn: 'text-amber-300',
    bad: 'text-rose-300',
    accent: 'text-cyan-300',
  };
  return (
    <div className="ac-surface rounded-xl border border-white/10 bg-white/[0.02] p-4">
      <div className="text-[11px] font-bold uppercase tracking-wide text-white/45">{label}</div>
      <div className={`mt-1.5 text-2xl font-black tabular-nums ${tones[tone]}`}>{value}</div>
      {hint ? <div className="mt-1 text-[11px] leading-snug text-white/40">{hint}</div> : null}
    </div>
  );
}

export function Panel({
  title,
  subtitle,
  actions,
  children,
  className = '',
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`ac-surface rounded-2xl border border-white/10 bg-white/[0.015] ${className}`}>
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-white/8 px-5 py-4">
        <div className="min-w-0">
          <h2 className="text-sm font-black uppercase tracking-wide text-white/85">{title}</h2>
          {subtitle ? <p className="mt-1 text-xs leading-relaxed text-white/45">{subtitle}</p> : null}
        </div>
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      </header>
      <div className="p-5">{children}</div>
    </section>
  );
}

export function CopyButton({ value, label = 'Copy', className = '' }: { value: string; label?: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  }, [value]);

  return (
    <button
      type="button"
      onClick={() => void copy()}
      className={`inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-2.5 py-1.5 text-[11px] font-bold text-white/70 transition hover:border-cyan-400/40 hover:text-cyan-200 ${className}`}
    >
      {copied ? <Check className="h-3.5 w-3.5 text-emerald-300" /> : <Copy className="h-3.5 w-3.5" />}
      {copied ? 'Copied' : label}
    </button>
  );
}

/** Nothing measured yet — say so, rather than rendering a reassuring zero. */
export function NotAssessed({ hint }: { hint?: string }) {
  return (
    <div className="rounded-xl border border-dashed border-white/15 bg-white/[0.015] px-4 py-6 text-center">
      <div className="text-sm font-bold text-white/70">Not Yet Assessed</div>
      <p className="mx-auto mt-1 max-w-md text-xs leading-relaxed text-white/40">
        {hint || 'This agent has not produced evidence yet, so no cryptographic conclusion can be drawn for it.'}
      </p>
    </div>
  );
}

export function EmptyState({ title, body, action }: { title: string; body: string; action?: ReactNode }) {
  return (
    <div className="rounded-xl border border-dashed border-white/15 bg-white/[0.015] px-6 py-10 text-center">
      <div className="text-sm font-black text-white/75">{title}</div>
      <p className="mx-auto mt-1.5 max-w-lg text-xs leading-relaxed text-white/45">{body}</p>
      {action ? <div className="mt-4 flex justify-center">{action}</div> : null}
    </div>
  );
}

export function ErrorState({ title, message, onRetry }: { title: string; message: string; onRetry?: () => void }) {
  return (
    <div className="rounded-xl border border-rose-400/25 bg-rose-400/[0.06] px-5 py-4">
      <div className="text-sm font-black text-rose-100">{title}</div>
      <p className="mt-1 text-xs leading-relaxed text-rose-100/70">{message}</p>
      {onRetry ? (
        <button
          type="button"
          onClick={onRetry}
          className="mt-3 rounded-lg border border-rose-400/30 bg-rose-400/10 px-3 py-1.5 text-[11px] font-bold text-rose-100 transition hover:bg-rose-400/20"
        >
          Retry
        </button>
      ) : null}
    </div>
  );
}

export function Skeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div className="space-y-2.5" aria-busy="true" aria-live="polite">
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="h-11 animate-pulse rounded-lg border border-white/8 bg-white/[0.03]" />
      ))}
    </div>
  );
}

export function relTime(value: string | null | undefined): string {
  if (!value) return 'Never';
  const then = Date.parse(value);
  if (!Number.isFinite(then)) return 'Unknown';
  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 0) return 'Just now';
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86_400)}d ago`;
}

export function fmtDate(value: string | null | undefined): string {
  if (!value) return '—';
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return '—';
  return new Date(parsed).toLocaleString();
}

export function fmtBytes(bytes: number | null | undefined): string {
  if (!bytes || !Number.isFinite(bytes)) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
