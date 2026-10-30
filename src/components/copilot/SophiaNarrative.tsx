import { useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { Cpu, ShieldCheck, AlertTriangle, XCircle, Copy, Check, Loader2 } from 'lucide-react';
import type { CopilotNarrative } from '@/types/copilot';

/**
 * SophiaNarrative — the analysis written by the tenant's own connected model.
 *
 * Model output is untrusted text: it is rendered through a small markdown
 * subset into React elements (never innerHTML), and only in-app paths or
 * http(s) URLs become links. The grounding badge states how many of the
 * figures in the prose were found in the platform evidence the model was given.
 */

/* ---- Minimal, safe markdown → React -------------------------------- */

function safeHref(href: string): { internal: boolean; href: string } | null {
  const h = href.trim();
  if (/^\/(?!\/)[\w\-./?=&#%]*$/.test(h)) return { internal: true, href: h };
  if (/^https?:\/\/[^\s]+$/i.test(h)) return { internal: false, href: h };
  return null;
}

function inline(text: string, keyBase: string): ReactNode[] {
  const out: ReactNode[] = [];
  const re = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\[[^\]]+\]\([^)\s]+\))|(\*[^*\s][^*]*\*)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let i = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const token = m[0];
    const key = `${keyBase}-${i++}`;
    if (m[1]) out.push(<code key={key} className="rounded bg-slate-950/70 px-1 py-px font-mono text-[12px] text-cyan-200">{token.slice(1, -1)}</code>);
    else if (m[2]) out.push(<strong key={key} className="font-bold text-slate-50">{token.slice(2, -2)}</strong>);
    else if (m[3]) {
      const label = token.slice(1, token.indexOf(']'));
      const target = safeHref(token.slice(token.indexOf('](') + 2, -1));
      if (!target) out.push(label);
      else if (target.internal) out.push(<Link key={key} to={target.href} className="font-semibold text-cyan-300 underline decoration-cyan-500/40 underline-offset-2 hover:text-cyan-200">{label}</Link>);
      else out.push(<a key={key} href={target.href} target="_blank" rel="noopener noreferrer nofollow" className="font-semibold text-cyan-300 underline decoration-cyan-500/40 underline-offset-2 hover:text-cyan-200">{label}</a>);
    } else if (m[4]) out.push(<em key={key} className="italic text-slate-200">{token.slice(1, -1)}</em>);
    last = m.index + token.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

export function NarrativeMarkdown({ source }: { source: string }) {
  const lines = source.replace(/\r\n/g, '\n').split('\n');
  const blocks: ReactNode[] = [];
  let i = 0;
  let k = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (/^```/.test(line)) {
      const body: string[] = [];
      i += 1;
      while (i < lines.length && !/^```/.test(lines[i])) body.push(lines[i++]);
      i += 1;
      blocks.push(<pre key={k++} className="qg-force-dark overflow-x-auto rounded-lg border border-slate-700/50 bg-slate-950/80 p-3 font-mono text-[12px] leading-relaxed text-slate-200">{body.join('\n')}</pre>);
      continue;
    }
    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      const level = heading[1].length;
      blocks.push(level <= 2
        ? <h3 key={k++} className="mt-1 text-[15px] font-black text-slate-50">{inline(heading[2], `h${k}`)}</h3>
        : <h4 key={k++} className="mt-1 text-[11px] font-black uppercase tracking-[0.16em] text-cyan-300/90">{inline(heading[2], `h${k}`)}</h4>);
      i += 1;
      continue;
    }
    if (/^\s*([-*+]|\d+[.)])\s+/.test(line)) {
      const ordered = /^\s*\d+[.)]\s+/.test(line);
      const items: string[] = [];
      while (i < lines.length && /^\s*([-*+]|\d+[.)])\s+/.test(lines[i])) {
        let item = lines[i].replace(/^\s*([-*+]|\d+[.)])\s+/, '');
        i += 1;
        // Indented continuation lines belong to the item above.
        while (i < lines.length && /^\s{2,}\S/.test(lines[i]) && !/^\s*([-*+]|\d+[.)])\s+/.test(lines[i])) item += ` ${lines[i++].trim()}`;
        items.push(item);
      }
      const ListTag = ordered ? 'ol' : 'ul';
      blocks.push(
        <ListTag key={k++} className={`space-y-1.5 pl-5 text-[13.5px] leading-relaxed text-slate-300 ${ordered ? 'list-decimal marker:font-bold marker:text-cyan-300/80' : 'list-disc marker:text-cyan-400/70'}`}>
          {items.map((item, idx) => <li key={idx}>{inline(item, `l${k}-${idx}`)}</li>)}
        </ListTag>,
      );
      continue;
    }
    if (!line.trim()) { i += 1; continue; }
    const para: string[] = [];
    while (i < lines.length && lines[i].trim() && !/^(#{1,6}\s|```|\s*([-*+]|\d+[.)])\s+)/.test(lines[i])) para.push(lines[i++].trim());
    blocks.push(<p key={k++} className="text-[13.5px] leading-relaxed text-slate-300">{inline(para.join(' '), `p${k}`)}</p>);
  }
  return <div className="space-y-2.5">{blocks}</div>;
}

/* ---- Narrative card --------------------------------------------- */

function GroundingBadge({ narrative }: { narrative: CopilotNarrative }) {
  const g = narrative.grounding;
  if (g.checked === 0) {
    return <span className="inline-flex items-center gap-1 rounded-md border border-slate-600/50 bg-slate-800/40 px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider text-slate-400" title="The narrative states no figures to check">No figures to check</span>;
  }
  if (g.unverified.length === 0) {
    return (
      <span className="inline-flex items-center gap-1 rounded-md border border-emerald-400/40 bg-emerald-500/10 px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider text-emerald-300" title="Every figure in this analysis was found in the platform evidence it was given">
        <ShieldCheck className="h-3 w-3" /> {g.verified}/{g.checked} figures traced to evidence
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-md border border-amber-400/40 bg-amber-500/10 px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider text-amber-200">
      <AlertTriangle className="h-3 w-3" /> {g.unverified.length} figure{g.unverified.length === 1 ? '' : 's'} not in evidence
    </span>
  );
}

export function SophiaNarrative({ narrative, streaming }: { narrative: CopilotNarrative; streaming: boolean }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(narrative.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { /* clipboard unavailable */ }
  };

  return (
    <div className="relative overflow-hidden rounded-xl border border-violet-400/25 bg-gradient-to-br from-violet-500/[0.08] via-blue-500/[0.05] to-cyan-500/[0.05] p-4">
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-violet-400/50 to-transparent" />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-[0.2em] text-violet-200/90"><Cpu className="h-3.5 w-3.5" /> AI analysis</span>
        <span className="rounded-md border border-slate-600/50 bg-slate-900/50 px-2 py-0.5 text-[10px] font-semibold text-slate-300">{narrative.providerLabel} · <span className="font-mono">{narrative.model}</span></span>
        {streaming
          ? <span className="inline-flex items-center gap-1 text-[10px] text-cyan-300"><Loader2 className="h-3 w-3 animate-spin" /> Writing…</span>
          : <GroundingBadge narrative={narrative} />}
        {!streaming && narrative.content && (
          <button onClick={copy} className="ml-auto inline-flex items-center gap-1 rounded-md px-1.5 py-1 text-[10px] text-slate-500 transition-colors hover:bg-white/5 hover:text-slate-200" title="Copy analysis">
            {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
          </button>
        )}
      </div>

      {narrative.content
        ? <NarrativeMarkdown source={narrative.content} />
        : streaming
          ? <div className="flex items-center gap-2 text-[13px] text-slate-400"><Loader2 className="h-4 w-4 animate-spin text-violet-300" /> {narrative.providerLabel} is reading the evidence…</div>
          : null}
      {streaming && narrative.content && <span className="ml-0.5 inline-block h-4 w-1.5 animate-pulse rounded-sm bg-violet-300/80 align-middle" aria-hidden />}

      {!streaming && narrative.status !== 'complete' && (
        <div className={`mt-3 flex items-start gap-2 rounded-lg border px-3 py-2 text-[11px] ${narrative.status === 'error' ? 'border-red-500/40 bg-red-500/10 text-red-200' : 'border-amber-400/40 bg-amber-500/10 text-amber-100'}`}>
          {narrative.status === 'error' ? <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" /> : <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />}
          <span className="min-w-0 break-words">
            {narrative.status === 'error' && <><strong>Your model could not write this analysis.</strong> {narrative.error} The platform answer below is unaffected.</>}
            {narrative.status === 'partial' && <><strong>Incomplete analysis.</strong> {narrative.error || 'The response stopped early.'}</>}
            {narrative.status === 'refused' && <><strong>The provider declined this request.</strong> The platform answer below is unaffected.</>}
          </span>
        </div>
      )}

      {!streaming && narrative.grounding.unverified.length > 0 && (
        <div className="mt-3 rounded-lg border border-amber-400/30 bg-amber-500/[0.06] px-3 py-2 text-[11px] text-amber-100/90">
          <span className="font-bold">Check before acting:</span> {narrative.grounding.unverified.join(', ')} {narrative.grounding.unverified.length === 1 ? 'does' : 'do'} not appear in the platform evidence this analysis was given. Rely on the evidence panels below for exact values.
        </div>
      )}

      {!streaming && (
        <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-slate-700/40 pt-2 text-[10px] text-slate-500">
          <span>Written by your connected model from this answer’s evidence only</span>
          {narrative.latencyMs > 0 && <span>{(narrative.latencyMs / 1000).toFixed(1)} s</span>}
          {narrative.usage?.inputTokens != null && <span>{narrative.usage.inputTokens.toLocaleString()} in · {(narrative.usage.outputTokens ?? 0).toLocaleString()} out tokens</span>}
        </div>
      )}
    </div>
  );
}
