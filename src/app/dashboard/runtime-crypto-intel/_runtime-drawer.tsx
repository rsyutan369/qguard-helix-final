'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { AlertTriangle, CheckCircle2, ChevronRight, Loader2, Sparkles, X } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { RuntimeEvent, RuntimeIssue } from '@/lib/runtime-crypto/runtime-intelligence';
import { RISK_GLYPH, RISK_HEX, RISK_LABEL, STATUS_HEX, fmtInt, fullTimestamp, relativeTime } from './_runtime-lib';

export type DrawerSelection =
  | { kind: 'event'; event: RuntimeEvent }
  | { kind: 'issue'; issue: RuntimeIssue };

/* ------------------------------------------------------------------ */
/* Shell                                                               */
/* ------------------------------------------------------------------ */

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/30">{label}</div>
      <div className="mt-1 text-[12.5px] leading-relaxed text-white/85">{children}</div>
    </div>
  );
}

function ActionButton({
  onClick, href, children, tone = 'ghost', disabled, busy,
}: {
  onClick?: () => void;
  href?: string;
  children: ReactNode;
  tone?: 'primary' | 'ghost' | 'ai';
  disabled?: boolean;
  busy?: boolean;
}) {
  const classes = cn(
    'inline-flex items-center gap-1.5 rounded-lg px-3 py-2 text-[9.5px] font-black uppercase tracking-wider no-underline transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70 disabled:cursor-not-allowed disabled:opacity-50',
    tone === 'primary' && 'border border-cyan-400/50 bg-cyan-500/15 text-cyan-200 hover:bg-cyan-500/25',
    tone === 'ai' && 'border border-violet-400/45 bg-violet-500/12 text-violet-200 hover:bg-violet-500/22',
    tone === 'ghost' && 'border border-white/12 bg-white/[0.04] text-white/60 hover:bg-white/[0.08]',
  );
  if (href) return <a href={href} className={classes}>{children}</a>;
  return (
    <button type="button" onClick={onClick} disabled={disabled || busy} className={classes}>
      {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : null}
      {children}
    </button>
  );
}

/* ------------------------------------------------------------------ */
/* Drawer                                                              */
/* ------------------------------------------------------------------ */

/**
 * Event / finding detail (§6).
 *
 * The default view answers the four questions in order — what happened, is it
 * safe, why, what should I do — in plain language. Raw telemetry lives behind
 * "View Technical Details" and stays collapsed, because a dashboard that opens
 * onto TLS versions and event hashes has stopped being a decision surface.
 */
export function RuntimeDetailDrawer({
  selection, onClose, onAsk, onQueue, queueState,
}: {
  selection: DrawerSelection | null;
  onClose: () => void;
  onAsk: (question: string) => void;
  onQueue: (assetId: string) => void;
  queueState: 'idle' | 'busy' | 'done' | 'error';
}) {
  const [showTechnical, setShowTechnical] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    setShowTechnical(false);
  }, [selection]);

  useEffect(() => {
    if (!selection) return;
    closeRef.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
      // Focus trap: a modal surface must not leak focus back to the page behind.
      if (event.key === 'Tab' && panelRef.current) {
        const focusable = panelRef.current.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), summary, input, select, [tabindex]:not([tabindex="-1"])',
        );
        if (!focusable.length) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [selection, onClose]);

  const queueLabel = useCallback(() => {
    if (queueState === 'busy') return 'Queuing…';
    if (queueState === 'done') return 'Queued in Planner';
    if (queueState === 'error') return 'Queue failed — retry';
    return 'Create Migration Task';
  }, [queueState]);

  if (!selection) return null;

  const isEvent = selection.kind === 'event';
  const event = isEvent ? selection.event : null;
  const issue = !isEvent ? selection.issue : null;

  const title = event?.assetName ?? issue?.assetName ?? 'Runtime observation';
  const environment = event?.environment ?? issue?.environment ?? '';
  const status = event?.quantumStatus ?? issue?.quantumStatus ?? 'unknown';
  const statusLabel = event?.statusLabel ?? (issue ? issue.title : '');
  const risk = event?.risk ?? issue?.severity ?? 'low';
  const why = event?.why ?? issue?.why ?? '';
  const action = event?.recommendedAction ?? issue?.recommendedAction ?? '';
  const assetId = event?.assetId ?? issue?.assetId ?? null;
  const priorityFactors = event?.priorityFactors ?? issue?.priorityFactors ?? [];
  const riskScore = event?.riskScore ?? issue?.riskScore ?? 0;

  const question = isEvent && event
    ? `On ${event.assetName}, a ${event.operation} operation used ${event.observedValue} at runtime. Why is that a risk and what is the safest migration path?`
    : issue
      ? `${issue.title} on ${issue.assetName}. Explain the risk and the safest way to remediate it.`
      : 'Explain this runtime cryptographic finding.';

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/55" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label={`Runtime detail for ${title}`}
        className="flex h-full w-full max-w-[520px] flex-col overflow-y-auto border-l border-white/12 bg-[#0b1424] shadow-2xl"
      >
        {/* ---- Header ------------------------------------------------ */}
        <div className="sticky top-0 z-10 border-b border-white/10 bg-[#0b1424]/95 px-5 py-4 backdrop-blur">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <h2 className="truncate text-[16px] font-black text-white">{title}</h2>
              <div className="mt-0.5 text-[10px] uppercase tracking-wider text-white/35">
                Cryptographic Activity{environment && environment !== 'unspecified' ? ` · ${environment}` : ''}
              </div>
            </div>
            <button
              ref={closeRef}
              type="button"
              onClick={onClose}
              className="rounded-lg border border-white/12 bg-white/[0.04] p-1.5 text-white/50 transition hover:bg-white/[0.08] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
              aria-label="Close details"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
        </div>

        {/* ---- Plain-language body ----------------------------------- */}
        <div className="space-y-4 px-5 py-5">
          {isEvent && event ? (
            <div className="grid grid-cols-2 gap-4">
              <Field label="Operation">{event.operation}</Field>
              <Field label="Algorithm"><span className="font-mono text-[12px]">{event.algorithm}</span></Field>
            </div>
          ) : issue ? (
            <div className="grid grid-cols-2 gap-4">
              <Field label="Finding">{issue.title}</Field>
              <Field label="Observations">{fmtInt(issue.observations)} in this period</Field>
            </div>
          ) : null}

          <div className="grid grid-cols-2 gap-4">
            <Field label="Quantum Status">
              <span className="inline-flex items-center gap-1.5 font-black" style={{ color: STATUS_HEX[status] }}>
                <span aria-hidden="true">{event?.statusGlyph ?? '⚠'}</span>
                {statusLabel || 'Needs Review'}
              </span>
            </Field>
            <Field label="Risk">
              <span className="inline-flex items-center gap-1.5 font-black" style={{ color: RISK_HEX[risk] }}>
                <span aria-hidden="true">{RISK_GLYPH[risk]}</span>
                {RISK_LABEL[risk]}
                <span className="font-mono text-[11px] font-medium text-white/35">{riskScore}/100</span>
              </span>
            </Field>
          </div>

          <Field label="Why?">
            <span className="text-[12px] text-white/60">{why}</span>
          </Field>

          <div className="rounded-xl border border-cyan-400/25 bg-cyan-500/[0.07] p-3.5">
            <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-cyan-300/80">Recommended Action</div>
            <p className="mt-1 text-[12.5px] leading-relaxed text-white/80">{action}</p>
            {isEvent && event?.pqcStandard ? (
              <p className="mt-1.5 text-[10px] text-white/35">Standard: {event.pqcStandard}</p>
            ) : null}
          </div>

          {/* ---- Why it ranks here (§8 explainability) --------------- */}
          {priorityFactors.length ? (
            <details className="rounded-xl border border-white/10 bg-black/20 p-3.5">
              <summary className="cursor-pointer list-none text-[10px] font-black uppercase tracking-wider text-white/50 outline-none transition hover:text-white/75 focus-visible:ring-2 focus-visible:ring-cyan-300/70">
                Why is this the priority it is?
              </summary>
              <ul className="mt-2.5 space-y-1.5">
                {priorityFactors.map((factor, index) => (
                  <li key={index} className="flex items-start justify-between gap-3 text-[11px]">
                    <span className="min-w-0 flex-1">
                      <span className="text-white/65">{factor.label}</span>
                      {factor.evidence ? <span className="block text-[10px] leading-relaxed text-white/30">{factor.evidence}</span> : null}
                    </span>
                    <span className={cn('shrink-0 font-mono font-black', factor.contribution >= 0 ? 'text-amber-300' : 'text-emerald-300')}>
                      {factor.contribution > 0 ? '+' : ''}{factor.contribution}
                    </span>
                  </li>
                ))}
              </ul>
            </details>
          ) : null}

          {/* ---- Issue evidence -------------------------------------- */}
          {issue?.evidence.length ? (
            <div className="rounded-xl border border-white/10 bg-black/20 p-3.5">
              <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/30">Evidence</div>
              <ul className="mt-2 space-y-1">
                {issue.evidence.map((line, index) => (
                  <li key={index} className="text-[11px] leading-relaxed text-white/45">· {line}</li>
                ))}
              </ul>
              <div className="mt-2.5 flex flex-wrap gap-x-4 gap-y-1 text-[10px] text-white/30">
                <span>First seen {relativeTime(issue.firstSeen)}</span>
                <span>Last seen {relativeTime(issue.lastSeen)}</span>
              </div>
            </div>
          ) : null}

          {/* ---- Actions --------------------------------------------- */}
          <div className="flex flex-wrap gap-2">
            {assetId ? (
              <ActionButton href={`/dashboard/migration-planner?asset=${encodeURIComponent(assetId)}`} tone="primary">
                View Asset <ChevronRight className="h-3 w-3" aria-hidden="true" />
              </ActionButton>
            ) : null}
            {assetId ? (
              <ActionButton
                onClick={() => onQueue(assetId)}
                busy={queueState === 'busy'}
                disabled={queueState === 'done'}
                tone={queueState === 'error' ? 'ghost' : 'ghost'}
              >
                {queueState === 'done' ? <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" /> : null}
                {queueState === 'error' ? <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" /> : null}
                {queueLabel()}
              </ActionButton>
            ) : null}
            <ActionButton onClick={() => onAsk(question)} tone="ai">
              <Sparkles className="h-3.5 w-3.5" aria-hidden="true" /> Ask Sophia
            </ActionButton>
          </div>

          <div className="flex flex-wrap gap-2 border-t border-white/8 pt-3">
            <ActionButton href="/dashboard/cbom">View CBOM</ActionButton>
            <ActionButton href="/dashboard/quantum-risk-scoring">View Quantum Risk</ActionButton>
            <ActionButton href="/dashboard/harvest-now">View HNDL Risk</ActionButton>
          </div>

          {/* ---- Technical details, collapsed by default (§6) --------- */}
          {isEvent && event ? (
            <div className="rounded-xl border border-white/10 bg-black/20 p-3.5">
              <button
                type="button"
                onClick={() => setShowTechnical((open) => !open)}
                aria-expanded={showTechnical}
                className="w-full text-left text-[10px] font-black uppercase tracking-wider text-white/50 outline-none transition hover:text-white/75 focus-visible:ring-2 focus-visible:ring-cyan-300/70"
              >
                {showTechnical ? 'Hide' : 'View'} Technical Details
              </button>

              {showTechnical ? (
                <>
                  <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2.5">
                    {([
                      ['Event ID', event.technical.eventId],
                      ['Source', event.technical.sourceLabel],
                      ['Observed at', fullTimestamp(event.technical.observedAt)],
                      ['Host', event.technical.host],
                      ['Port', event.technical.port === null ? null : String(event.technical.port)],
                      ['Protocol', event.technical.protocol],
                      ['TLS version', event.technical.tlsVersion],
                      ['Cipher suite', event.technical.cipherSuite],
                      ['Key exchange', event.technical.keyExchange],
                      ['Signature', event.technical.signature],
                      ['Bulk cipher', event.technical.bulkCipher],
                      ['MAC / hash', event.technical.mac],
                      ['Key size', event.technical.keySize === null ? null : `${event.technical.keySize} bits`],
                      ['Certificate', event.technical.certificateFingerprint],
                      ['Library', event.technical.library],
                      ['Process', event.technical.process],
                    ] as Array<[string, string | null]>)
                      .filter(([, value]) => Boolean(value))
                      .map(([label, value]) => (
                        <div key={label}>
                          <dt className="text-[8.5px] font-black uppercase tracking-wider text-white/30">{label}</dt>
                          <dd className="mt-0.5 break-words font-mono text-[10.5px] text-white/65">{value}</dd>
                        </div>
                      ))}
                  </dl>

                  {event.technical.attributes.length ? (
                    <div className="mt-3 border-t border-white/8 pt-3">
                      <div className="text-[8.5px] font-black uppercase tracking-wider text-white/30">Collector attributes</div>
                      <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2">
                        {event.technical.attributes.map((attribute) => (
                          <div key={attribute.label}>
                            <dt className="text-[8.5px] uppercase tracking-wider text-white/25">{attribute.label}</dt>
                            <dd className={cn('mt-0.5 break-words font-mono text-[10.5px]', attribute.value === 'REDACTED' ? 'text-amber-300/80' : 'text-white/60')}>
                              {attribute.value}
                            </dd>
                          </div>
                        ))}
                      </dl>
                    </div>
                  ) : null}

                  <p className="mt-3 text-[9.5px] leading-relaxed text-white/25">
                    Runtime telemetry carries metadata only. Key material, secrets, tokens and plaintext are rejected at
                    ingest and redacted again here; certificate fingerprints are hashes, shown abbreviated.
                  </p>
                </>
              ) : null}
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
