import { useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react';
import { useLocation } from 'react-router-dom';
import {
  Sparkles, Send, Square, Loader2, Plus, Search, Pin, PinOff, Trash2,
  Download, ShieldCheck, Lightbulb, AlertTriangle, RefreshCw, MessageSquare,
  Mic, MicOff, Cpu, ExternalLink, KeyRound, ChevronRight,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { useCopilot } from '@/hooks/use-copilot';
import { SophiaMessage } from '@/components/copilot/SophiaMessage';
import { SophiaAvatar } from '@/components/copilot/SophiaAvatar';
import { SophiaModelSettings } from '@/components/copilot/SophiaModelSettings';
import type { CopilotRiskLevel } from '@/types/copilot';

/**
 * Sophia AI Security Copilot™ — full console.
 *
 * Left: conversation history (new / search / pin / delete). Center: streaming
 * chat with structured evidence-based answers. Right: tenant + RBAC context,
 * proactive insights and page-aware suggested questions. Every answer is
 * tenant-isolated and derived from the platform's live data.
 */

const SEVERITY_STYLE: Record<CopilotRiskLevel, string> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-300',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
  medium: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  low: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300',
  info: 'border-sky-500/40 bg-sky-500/10 text-sky-300',
};

type SpeechRecognitionLike = {
  lang: string; interimResults: boolean; continuous: boolean;
  start(): void; stop(): void;
  onresult: ((e: { results: ArrayLike<ArrayLike<{ transcript: string }>> }) => void) | null;
  onend: (() => void) | null; onerror: (() => void) | null;
};
function getSpeechRecognition(): (new () => SpeechRecognitionLike) | null {
  const w = window as unknown as { SpeechRecognition?: new () => SpeechRecognitionLike; webkitSpeechRecognition?: new () => SpeechRecognitionLike };
  return w.SpeechRecognition || w.webkitSpeechRecognition || null;
}

/** Draggable vertical divider between two panels — premium enterprise handle. */
function ResizeHandle({ side, dragging, onPointerDown, onDoubleClick }: {
  side: 'left' | 'right';
  dragging: boolean;
  onPointerDown: (e: ReactPointerEvent) => void;
  onDoubleClick: () => void;
}) {
  const dotClass = dragging ? 'bg-cyan-300' : 'bg-slate-500 group-hover:bg-cyan-300';
  return (
    <div
      role="separator"
      aria-orientation="vertical"
      aria-label={`Resize ${side === 'left' ? 'conversations' : 'insights'} panel`}
      onPointerDown={onPointerDown}
      onDoubleClick={onDoubleClick}
      title="Drag to resize · double-click to reset"
      className="group relative hidden w-2 shrink-0 cursor-col-resize items-center justify-center lg:flex"
    >
      <span className={`absolute inset-y-0 left-1/2 w-px -translate-x-1/2 transition-colors ${dragging ? 'bg-cyan-400/70' : 'bg-slate-700/50 group-hover:bg-cyan-400/40'}`} />
      <span className={`relative flex flex-col items-center justify-center gap-[3px] rounded-full px-0.5 py-1.5 transition-all ${dragging ? 'bg-cyan-400/15 shadow-[0_0_16px_rgba(34,211,238,0.5)]' : 'group-hover:bg-white/5'}`}>
        <span className={`h-1 w-1 rounded-full transition-colors ${dotClass}`} />
        <span className={`h-1 w-1 rounded-full transition-colors ${dotClass}`} />
        <span className={`h-1 w-1 rounded-full transition-colors ${dotClass}`} />
      </span>
    </div>
  );
}

export default function SophiaConsolePage() {
  const location = useLocation();
  const copilot = useCopilot(location.pathname);
  const {
    context, suggestions, insights, insightsState, conversations, activeConversationId,
    messages, streaming, narratingAnswerId, error,
    sendMessage, stopStreaming, sendFeedback, loadInsights, openConversation, newConversation,
    pinConversation, deleteConversation, exportConversation, searchConversations, refreshContext,
  } = copilot;

  const [modelsOpen, setModelsOpen] = useState(false);
  const [input, setInput] = useState('');
  const [search, setSearch] = useState('');
  const [searchResults, setSearchResults] = useState<Array<{ conversation: { id: string; title: string }; match: string }>>([]);
  const [listening, setListening] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const recognitionRef = useRef<SpeechRecognitionLike | null>(null);
  const speechSupported = useMemo(() => Boolean(getSpeechRecognition()), []);

  // Resizable panels — draggable left (history) / right (insights) widths, with
  // the center chat taking the remainder. Widths persist per-user across visits.
  const LEFT_DEFAULT = 280, RIGHT_DEFAULT = 320;
  const LEFT_MIN = 220, LEFT_MAX = 460, RIGHT_MIN = 240, RIGHT_MAX = 520, CENTER_MIN = 380;
  const layoutRef = useRef<HTMLDivElement>(null);
  const [leftWidth, setLeftWidth] = useState(LEFT_DEFAULT);
  const [rightWidth, setRightWidth] = useState(RIGHT_DEFAULT);
  const [dragging, setDragging] = useState<'left' | 'right' | null>(null);

  useEffect(() => {
    try {
      const saved = JSON.parse(localStorage.getItem('sophia:panels') || '{}');
      if (typeof saved.left === 'number') setLeftWidth(Math.min(LEFT_MAX, Math.max(LEFT_MIN, saved.left)));
      if (typeof saved.right === 'number') setRightWidth(Math.min(RIGHT_MAX, Math.max(RIGHT_MIN, saved.right)));
    } catch { /* first visit */ }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const persistWidths = (left: number, right: number) => {
    try { localStorage.setItem('sophia:panels', JSON.stringify({ left: Math.round(left), right: Math.round(right) })); } catch { /* ignore */ }
  };

  const startDrag = (side: 'left' | 'right') => (e: ReactPointerEvent) => {
    e.preventDefault();
    setDragging(side);
    const startX = e.clientX;
    const startLeft = leftWidth;
    const startRight = rightWidth;
    const containerW = layoutRef.current?.clientWidth ?? window.innerWidth;
    let nextLeft = startLeft;
    let nextRight = startRight;
    const onMove = (ev: PointerEvent) => {
      if (side === 'left') {
        const maxByCenter = containerW - startRight - CENTER_MIN;
        nextLeft = Math.min(LEFT_MAX, Math.max(LEFT_MIN, Math.min(maxByCenter, startLeft + (ev.clientX - startX))));
        setLeftWidth(nextLeft);
      } else {
        const maxByCenter = containerW - startLeft - CENTER_MIN;
        nextRight = Math.min(RIGHT_MAX, Math.max(RIGHT_MIN, Math.min(maxByCenter, startRight - (ev.clientX - startX))));
        setRightWidth(nextRight);
      }
    };
    const onUp = () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      document.body.style.userSelect = '';
      document.body.style.cursor = '';
      setDragging(null);
      persistWidths(nextLeft, nextRight);
    };
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    document.body.style.userSelect = 'none';
    document.body.style.cursor = 'col-resize';
  };

  const resetPanel = (side: 'left' | 'right') => {
    if (side === 'left') { setLeftWidth(LEFT_DEFAULT); persistWidths(LEFT_DEFAULT, rightWidth); }
    else { setRightWidth(RIGHT_DEFAULT); persistWidths(leftWidth, RIGHT_DEFAULT); }
  };

  useEffect(() => { void loadInsights(); }, [loadInsights]);
  useEffect(() => { if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight; }, [messages, streaming]);

  useEffect(() => {
    if (!search.trim()) { setSearchResults([]); return; }
    let cancelled = false;
    const t = setTimeout(async () => {
      const results = await searchConversations(search);
      if (!cancelled) setSearchResults(results);
    }, 250);
    return () => { cancelled = true; clearTimeout(t); };
  }, [search, searchConversations]);

  const submit = (text?: string) => {
    const value = (text ?? input).trim();
    if (!value || streaming.active) return;
    setInput('');
    void sendMessage(value);
  };

  const toggleVoice = () => {
    const Recognition = getSpeechRecognition();
    if (!Recognition) return;
    if (listening) { recognitionRef.current?.stop(); setListening(false); return; }
    const recognition = new Recognition();
    recognition.lang = 'en-US'; recognition.interimResults = false; recognition.continuous = false;
    recognition.onresult = (e) => { const t = e.results?.[0]?.[0]?.transcript; if (t) setInput((prev) => (prev ? `${prev} ${t}` : t)); };
    recognition.onend = () => setListening(false);
    recognition.onerror = () => setListening(false);
    recognitionRef.current = recognition;
    recognition.start();
    setListening(true);
  };

  const doExport = async (id: string) => {
    const data = await exportConversation(id);
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `sophia-conversation-${id}.json`; a.click();
    URL.revokeObjectURL(url);
  };

  const displayConversations = search.trim() ? searchResults.map((r) => conversations.find((c) => c.id === r.conversation.id)).filter(Boolean) as typeof conversations : conversations;

  return (
    <div className="flex h-[100dvh] min-h-0 flex-col overflow-hidden text-slate-100 lg:h-screen">
      {/* Header */}
      <div className="flex items-center gap-3 border-b border-slate-700/50 px-5 py-4">
        <SophiaAvatar active={streaming.active} size={46} />
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-black tracking-tight text-slate-50">Sophia</h1>
            <span className="rounded bg-cyan-500/15 px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider text-cyan-300">AI Security Copilot™</span>
          </div>
          <p className="text-[11px] text-slate-500">Enterprise post-quantum security intelligence — tenant-isolated, evidence-based, RBAC-aware.</p>
        </div>
        <button
          onClick={() => setModelsOpen(true)}
          className={`ml-auto flex min-h-[36px] items-center gap-2 rounded-lg border px-3 py-1.5 text-left transition-colors ${context?.engine ? 'border-violet-400/40 bg-violet-500/10 hover:bg-violet-500/20' : 'border-cyan-400/30 bg-cyan-500/[0.07] hover:bg-cyan-500/15'}`}
          title="Connect your own AI model to Sophia"
        >
          {context?.engine ? <Cpu className="h-4 w-4 text-violet-300" /> : <KeyRound className="h-4 w-4 text-cyan-300" />}
          <span className="min-w-0">
            <span className="block text-[11px] font-bold text-slate-100">{context?.engine ? context.engine.label : 'AI Models'}</span>
            <span className="block max-w-[160px] truncate text-[9px] text-slate-400">{context?.engine ? context.engine.model : 'Connect your own key'}</span>
          </span>
        </button>
        {context && (
          <div className="hidden items-center gap-2 rounded-lg border border-slate-700/50 bg-slate-900/50 px-3 py-1.5 md:flex">
            <ShieldCheck className="h-4 w-4 text-emerald-400/80" />
            <div className="text-right">
              <div className="text-[11px] font-bold text-slate-200">{context.roleLabel}</div>
              <div className="text-[9px] text-slate-500">{context.tenantLabel} · {context.tier} plan</div>
            </div>
          </div>
        )}
      </div>

      <div ref={layoutRef} className="flex min-h-0 flex-1 overflow-hidden">
        {/* Left — conversations */}
        <aside style={{ width: leftWidth }} className="hidden min-h-0 shrink-0 flex-col border-r border-slate-700/50 lg:flex">
          <div className="space-y-2 p-3">
            <button onClick={newConversation} className="flex w-full items-center justify-center gap-2 rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-3 py-2 text-[12px] font-bold text-cyan-200 transition-colors hover:bg-cyan-500/20">
              <Plus className="h-4 w-4" /> New conversation
            </button>
            <div className="flex items-center gap-2 rounded-lg border border-slate-700/50 bg-slate-900/50 px-2.5 py-1.5">
              <Search className="h-3.5 w-3.5 text-slate-500" />
              <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search history" className="w-full bg-transparent text-[12px] text-slate-200 placeholder:text-slate-600 focus:outline-none" />
            </div>
          </div>
          <div className="min-h-0 flex-1 space-y-1 overflow-y-auto px-2 pb-3 scrollbar-thin">
            {displayConversations.length === 0 && <p className="px-3 py-6 text-center text-[11px] text-slate-600">No conversations yet.</p>}
            {displayConversations.map((c) => (
              <div
                key={c.id}
                className={`group flex items-center gap-1.5 rounded-lg border px-2.5 py-2 transition-colors ${activeConversationId === c.id ? 'border-cyan-400/40 bg-cyan-500/10' : 'border-transparent hover:border-slate-700/50 hover:bg-slate-900/50'}`}
              >
                <button onClick={() => openConversation(c.id)} className="flex min-w-0 flex-1 items-center gap-2 text-left">
                  <MessageSquare className="h-3.5 w-3.5 shrink-0 text-slate-500" />
                  <span className="truncate text-[12px] text-slate-300">{c.title}</span>
                </button>
                <button onClick={() => pinConversation(c.id, !c.pinned)} className="shrink-0 text-slate-600 opacity-0 transition-opacity hover:text-cyan-300 group-hover:opacity-100" title={c.pinned ? 'Unpin' : 'Pin'}>
                  {c.pinned ? <Pin className="h-3.5 w-3.5 text-cyan-400 opacity-100" /> : <PinOff className="h-3.5 w-3.5" />}
                </button>
                <button onClick={() => doExport(c.id)} className="shrink-0 text-slate-600 opacity-0 transition-opacity hover:text-cyan-300 group-hover:opacity-100" title="Export"><Download className="h-3.5 w-3.5" /></button>
                <button onClick={() => deleteConversation(c.id)} className="shrink-0 text-slate-600 opacity-0 transition-opacity hover:text-red-400 group-hover:opacity-100" title="Delete"><Trash2 className="h-3.5 w-3.5" /></button>
              </div>
            ))}
          </div>
        </aside>

        {/* Resize handle — conversations | chat */}
        <ResizeHandle side="left" dragging={dragging === 'left'} onPointerDown={startDrag('left')} onDoubleClick={() => resetPanel('left')} />

        {/* Center — chat */}
        <section className="flex min-h-0 min-w-0 flex-1 flex-col">
          <div ref={scrollRef} className="min-h-0 flex-1 space-y-5 overflow-y-auto px-4 py-5 scrollbar-thin md:px-8">
            {messages.length === 0 && !streaming.active && (
              <div className="mx-auto max-w-2xl space-y-4 pt-6">
                <div className="rounded-2xl border border-blue-400/20 bg-gradient-to-br from-blue-500/[0.08] to-violet-500/[0.04] p-6 text-center">
                  <Sparkles className="mx-auto mb-3 h-9 w-9 text-cyan-300" />
                  <h2 className="text-xl font-black text-slate-50">How can I help secure your quantum future?</h2>
                  <p className="mx-auto mt-2 max-w-md text-[13px] text-slate-400">
                    I orchestrate every QGuard Helix module — scanner, CBOM, exposure graph, migrations, PKI, compliance and certification — to answer with real evidence from your tenant, never guesses.
                  </p>
                </div>
                {suggestions.length > 0 && (
                  <div className="grid gap-2 sm:grid-cols-2">
                    {suggestions.slice(0, 6).map((s, i) => (
                      <button key={i} onClick={() => submit(s.text)} className="rounded-xl border border-slate-700/50 bg-slate-900/40 px-4 py-3 text-left text-[13px] text-slate-300 transition-colors hover:border-cyan-400/40 hover:bg-slate-900/70 hover:text-cyan-100">
                        {s.text}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}

            {messages.map((message) => (
              message.role === 'user' ? (
                <div key={message.id} className="flex justify-end">
                  <div className="max-w-[80%] rounded-2xl rounded-br-sm border border-blue-400/30 bg-blue-600/20 px-4 py-2.5 text-[14px] text-slate-100">{message.content}</div>
                </div>
              ) : (
                <div key={message.id} className="min-w-0 max-w-3xl">
                  {message.answer
                    ? <SophiaMessage answer={message.answer} narrating={narratingAnswerId === message.answer.id} onFeedback={(rating) => { void sendFeedback(message.answer!, rating); }} />
                    : <p className="text-[14px] text-slate-200">{message.content}</p>}
                </div>
              )
            ))}

            {streaming.active && !narratingAnswerId && (
              <div className="max-w-3xl space-y-2 rounded-xl border border-slate-700/50 bg-slate-900/40 p-4">
                <div className="flex items-center gap-2 text-[13px] text-cyan-200">
                  <Loader2 className="h-4 w-4 animate-spin" /><span>{streaming.stageLabel || 'Sophia is thinking…'}</span>
                </div>
                {streaming.toolRuns.length > 0 && (
                  <div className="flex items-center gap-1.5 text-[10px] text-slate-500">
                    <Cpu className="h-3 w-3 text-slate-600" />
                    <span>{streaming.toolRuns.length} evidence source{streaming.toolRuns.length === 1 ? '' : 's'} consulted · tenant-isolated</span>
                  </div>
                )}
              </div>
            )}

            {error && <div className="max-w-3xl rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-2.5 text-[13px] text-red-300">{error}</div>}
          </div>

          {/* Composer */}
          <div className="border-t border-slate-700/50 p-4">
            <div className="mx-auto flex max-w-3xl items-end gap-2 rounded-2xl border border-slate-700/60 bg-slate-900/60 px-4 py-3 focus-within:border-cyan-400/50">
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submit(); } }}
                placeholder="Ask about assets, exposure, migrations, certificates, compliance, certification…"
                rows={1}
                className="max-h-40 flex-1 resize-none bg-transparent text-[14px] text-slate-100 placeholder:text-slate-600 focus:outline-none"
              />
              {speechSupported && (
                <button onClick={toggleVoice} className={`flex h-9 w-9 items-center justify-center rounded-lg transition-colors ${listening ? 'bg-red-500/20 text-red-300' : 'text-slate-500 hover:bg-white/5 hover:text-cyan-300'}`} title="Voice input">
                  {listening ? <MicOff className="h-4 w-4" /> : <Mic className="h-4 w-4" />}
                </button>
              )}
              {streaming.active ? (
                <button onClick={stopStreaming} className="flex h-9 w-9 items-center justify-center rounded-lg bg-red-500/20 text-red-300 transition-colors hover:bg-red-500/30" title="Stop"><Square className="h-4 w-4" /></button>
              ) : (
                <button onClick={() => submit()} disabled={!input.trim()} className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-blue-600 to-violet-600 text-white transition-opacity disabled:opacity-40" title="Send"><Send className="h-4 w-4" /></button>
              )}
            </div>
            <p className="mt-2 text-center text-[10px] text-slate-600">Sophia analyzes only your authenticated tenant&apos;s data · answers are evidence-based and standards-aligned</p>
          </div>
        </section>

        {/* Resize handle — chat | insights */}
        <ResizeHandle side="right" dragging={dragging === 'right'} onPointerDown={startDrag('right')} onDoubleClick={() => resetPanel('right')} />

        {/* Right — context + insights */}
        <aside style={{ width: rightWidth }} className="hidden min-h-0 shrink-0 flex-col gap-4 overflow-y-auto border-l border-slate-700/50 p-4 scrollbar-thin lg:flex">
          <button onClick={() => setModelsOpen(true)} className="group block w-full rounded-xl border border-violet-400/25 bg-gradient-to-br from-violet-500/[0.09] to-cyan-500/[0.05] p-3 text-left transition-colors hover:border-violet-400/50">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-[0.18em] text-violet-200/90"><Cpu className="h-3 w-3" /> AI engine</span>
              <ChevronRight className="h-3.5 w-3.5 text-slate-500 transition-transform group-hover:translate-x-0.5 group-hover:text-violet-200" />
            </div>
            {context?.engine ? (
              <>
                <div className="mt-1.5 text-[12px] font-bold text-slate-100">{context.engine.label}</div>
                <div className="truncate font-mono text-[10px] text-slate-400">{context.engine.model}</div>
                <p className="mt-1 text-[10px] leading-relaxed text-slate-500">Writes each analysis from Sophia’s tenant evidence. Every figure is checked against that evidence.</p>
              </>
            ) : (
              <>
                <div className="mt-1.5 text-[12px] font-bold text-slate-100">Sophia platform engine</div>
                <p className="mt-0.5 text-[10px] leading-relaxed text-slate-500">Connect Anthropic, OpenAI, Hermes, Kimi, GLM or DeepSeek with your own key to add a written analysis to every answer.</p>
              </>
            )}
          </button>

          <div>
            <div className="mb-2 flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-[0.18em] text-slate-400"><AlertTriangle className="h-3 w-3 text-amber-400/80" /> Proactive insights</span>
              <button onClick={() => loadInsights()} className="text-slate-500 hover:text-cyan-300" title="Refresh"><RefreshCw className={`h-3.5 w-3.5 ${insightsState === 'loading' ? 'animate-spin' : ''}`} /></button>
            </div>
            <div className="space-y-2">
              {insightsState === 'loading' && insights.length === 0 && <div className="rounded-lg border border-slate-700/50 bg-slate-900/40 px-3 py-4 text-center text-[11px] text-slate-500"><Loader2 className="mx-auto h-4 w-4 animate-spin" /></div>}
              {insightsState === 'success' && insights.length === 0 && <p className="rounded-lg border border-emerald-500/30 bg-emerald-500/[0.06] px-3 py-3 text-[11px] text-emerald-300">No critical issues detected right now.</p>}
              {insights.map((insight) => (
                <Link key={insight.id} to={insight.deepLink} className="block rounded-lg border border-slate-700/50 bg-slate-900/40 p-2.5 no-underline transition-colors hover:border-cyan-400/40 hover:bg-slate-900/70">
                  <div className="flex items-center justify-between gap-2">
                    <span className={`rounded border px-1.5 py-0.5 text-[8px] font-bold uppercase tracking-wider ${SEVERITY_STYLE[insight.severity]}`}>{insight.severity}</span>
                    <ExternalLink className="h-3 w-3 text-slate-600" />
                  </div>
                  <div className="mt-1.5 text-[12px] font-semibold text-slate-100">{insight.title}</div>
                  <p className="mt-0.5 text-[10px] leading-relaxed text-slate-400">{insight.detail}</p>
                  <div className="mt-1 text-[9px] text-slate-600">{insight.module} · {insight.evidence}</div>
                </Link>
              ))}
            </div>
          </div>

          {suggestions.length > 0 && (
            <div>
              <span className="mb-2 flex items-center gap-1.5 text-[10px] font-black uppercase tracking-[0.18em] text-slate-400"><Lightbulb className="h-3 w-3 text-cyan-300/80" /> Ask Sophia</span>
              <div className="space-y-1.5">
                {suggestions.slice(0, 8).map((s, i) => (
                  <button key={i} onClick={() => submit(s.text)} className="block w-full rounded-lg border border-slate-700/50 bg-slate-900/40 px-3 py-2 text-left text-[11px] text-slate-300 transition-colors hover:border-cyan-400/40 hover:bg-slate-900/70 hover:text-cyan-200">{s.text}</button>
                ))}
              </div>
            </div>
          )}
        </aside>
      </div>

      <SophiaModelSettings open={modelsOpen} onClose={() => setModelsOpen(false)} onChanged={() => { void refreshContext(); }} />
    </div>
  );
}
