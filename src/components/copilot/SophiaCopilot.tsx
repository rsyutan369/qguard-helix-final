import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  X, Send, Square, Maximize2, Loader2, Mic, MicOff,
  ShieldCheck, Lightbulb,
} from 'lucide-react';
import { useCopilot } from '@/hooks/use-copilot';
import { ASK_SOPHIA_EVENT, type AskSophiaDetail } from '@/lib/sophia-bridge';
import { SophiaMessage } from './SophiaMessage';
import { SophiaAvatar } from './SophiaAvatar';

/**
 * SophiaCopilot — the floating AI Security Copilot™ dock, mounted in the
 * dashboard shell so Sophia is one click away on every page/module. Streams
 * reasoning stages + tool runs, renders structured evidence-based answers, and
 * surfaces page-aware suggested questions. The full console lives at
 * /dashboard/sophia.
 */

// Minimal typing for the optional Web Speech API (voice input) without pulling
// in DOM lib type churn.
type SpeechRecognitionLike = {
  lang: string; interimResults: boolean; continuous: boolean;
  start(): void; stop(): void;
  onresult: ((e: { results: ArrayLike<ArrayLike<{ transcript: string }>> }) => void) | null;
  onend: (() => void) | null;
  onerror: (() => void) | null;
};

function getSpeechRecognition(): (new () => SpeechRecognitionLike) | null {
  const w = window as unknown as { SpeechRecognition?: new () => SpeechRecognitionLike; webkitSpeechRecognition?: new () => SpeechRecognitionLike };
  return w.SpeechRecognition || w.webkitSpeechRecognition || null;
}

export function SophiaCopilot() {
  const location = useLocation();
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState('');
  const [listening, setListening] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const recognitionRef = useRef<SpeechRecognitionLike | null>(null);

  const copilot = useCopilot(location.pathname);
  const { context, suggestions, messages, streaming, error, sendMessage, stopStreaming } = copilot;

  const speechSupported = useMemo(() => Boolean(getSpeechRecognition()), []);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages, streaming]);

  const submit = (text?: string) => {
    const value = (text ?? input).trim();
    if (!value || streaming.active) return;
    setInput('');
    void sendMessage(value);
  };

  // Any dashboard page can hand Sophia a question via askSophia() — the dock
  // opens and answers from the authenticated tenant's own data. While a stream
  // is in flight the question is staged in the composer instead of being
  // dropped, so an "Ask Sophia" click is never a no-op.
  const streamingActive = streaming.active;
  useEffect(() => {
    const handler = (event: Event) => {
      const detail = (event as CustomEvent<AskSophiaDetail>).detail;
      const question = detail?.question?.trim();
      if (!question) return;
      const full = detail.context ? `${question}\n\nContext: ${detail.context}` : question;
      setOpen(true);
      if (streamingActive) setInput(full);
      else void sendMessage(full);
    };
    window.addEventListener(ASK_SOPHIA_EVENT, handler);
    return () => window.removeEventListener(ASK_SOPHIA_EVENT, handler);
  }, [sendMessage, streamingActive]);

  const toggleVoice = () => {
    const Recognition = getSpeechRecognition();
    if (!Recognition) return;
    if (listening) {
      recognitionRef.current?.stop();
      setListening(false);
      return;
    }
    const recognition = new Recognition();
    recognition.lang = 'en-US';
    recognition.interimResults = false;
    recognition.continuous = false;
    recognition.onresult = (e) => {
      const transcript = e.results?.[0]?.[0]?.transcript;
      if (transcript) setInput((prev) => (prev ? `${prev} ${transcript}` : transcript));
    };
    recognition.onend = () => setListening(false);
    recognition.onerror = () => setListening(false);
    recognitionRef.current = recognition;
    recognition.start();
    setListening(true);
  };

  const speakLast = () => {
    const last = [...messages].reverse().find((m) => m.role === 'assistant');
    if (!last || !('speechSynthesis' in window)) return;
    window.speechSynthesis.cancel();
    window.speechSynthesis.speak(new SpeechSynthesisUtterance(last.answer?.summary || last.content));
  };

  return (
    <>
      {/* Launcher */}
      <AnimatePresence>
        {!open && (
          <motion.button
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0, opacity: 0 }}
            onClick={() => setOpen(true)}
            className="fixed bottom-5 right-5 z-[60] h-14 w-14 rounded-2xl border border-cyan-400/40 shadow-[0_18px_50px_rgba(37,99,235,0.45)] transition-transform hover:scale-105"
            title="Ask Sophia — AI Security Copilot"
          >
            {/* Sophia portrait, clipped to the rounded launcher */}
            <span className="absolute inset-0 overflow-hidden rounded-2xl bg-gradient-to-br from-blue-600 to-violet-600">
              <img src="/Sophia_AVATAR.png" alt="Ask Sophia" className="h-full w-full object-cover" draggable={false} />
              <span className="pointer-events-none absolute inset-0 bg-gradient-to-tr from-blue-600/20 via-transparent to-violet-600/20" />
            </span>
            {/* Inner rim + soft glow to keep the premium token look */}
            <span className="pointer-events-none absolute inset-0 rounded-2xl ring-1 ring-inset ring-white/15 shadow-[0_0_22px_rgba(6,182,212,0.28)]" />
            {/* Live status dot (kept outside the clip) */}
            <span className="absolute -right-0.5 -top-0.5 flex h-3.5 w-3.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-cyan-400/60" />
              <span className="relative inline-flex h-3.5 w-3.5 rounded-full bg-cyan-400 ring-2 ring-slate-950" />
            </span>
          </motion.button>
        )}
      </AnimatePresence>

      {/* Dock */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: 24, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 24, scale: 0.96 }}
            transition={{ type: 'spring', stiffness: 400, damping: 34 }}
            className="fixed bottom-5 right-5 z-[60] flex h-[640px] max-h-[calc(100vh-2.5rem)] w-[420px] max-w-[calc(100vw-2.5rem)] flex-col overflow-hidden rounded-2xl border border-slate-700/60 bg-slate-950/95 shadow-[0_30px_90px_rgba(0,0,0,0.6)] backdrop-blur-2xl"
          >
            {/* Header */}
            <div className="flex items-center gap-2.5 border-b border-slate-700/50 bg-gradient-to-r from-blue-600/15 to-violet-600/10 px-4 py-3">
              <SophiaAvatar active={streaming.active} size={38} />
              <div className="min-w-0">
                <div className="flex items-center gap-1.5">
                  <span className="text-sm font-black tracking-tight text-slate-50">Sophia</span>
                  <span className="rounded bg-cyan-500/15 px-1.5 py-0.5 text-[8px] font-bold uppercase tracking-wider text-cyan-300">AI Security Copilot</span>
                </div>
                <div className="flex items-center gap-1 text-[10px] text-slate-500">
                  <ShieldCheck className="h-3 w-3 text-emerald-400/70" />
                  {context ? `${context.roleLabel} · ${context.tenantLabel}` : 'Securing session…'}
                </div>
              </div>
              <div className="ml-auto flex items-center gap-1">
                <Link
                  to="/dashboard/sophia"
                  onClick={() => setOpen(false)}
                  className="flex h-8 w-8 items-center justify-center rounded-lg text-slate-400 no-underline transition-colors hover:bg-white/5 hover:text-cyan-300"
                  title="Open full console"
                >
                  <Maximize2 className="h-4 w-4" />
                </Link>
                <button onClick={() => setOpen(false)} className="flex h-8 w-8 items-center justify-center rounded-lg text-slate-400 transition-colors hover:bg-white/5 hover:text-slate-100" title="Close">
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>

            {/* Messages */}
            <div ref={scrollRef} className="flex-1 space-y-4 overflow-y-auto px-4 py-4 scrollbar-thin">
              {messages.length === 0 && !streaming.active && (
                <div className="space-y-3">
                  <div className="rounded-xl border border-blue-400/20 bg-blue-500/[0.06] p-4">
                    <p className="text-[13px] leading-relaxed text-slate-200">
                      Hi, I&apos;m <span className="font-bold text-cyan-300">Sophia</span> — your AI Security Copilot. Ask me about your quantum readiness, assets, cryptographic exposure, migrations, certificates, compliance or certification. Every answer is built from your own live data with evidence and next steps.
                    </p>
                  </div>
                  {suggestions.length > 0 && (
                    <div className="space-y-1.5">
                      <div className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-[0.18em] text-slate-500">
                        <Lightbulb className="h-3 w-3" /> Suggested
                      </div>
                      {suggestions.slice(0, 6).map((s, i) => (
                        <button
                          key={i}
                          onClick={() => submit(s.text)}
                          className="block w-full rounded-lg border border-slate-700/50 bg-slate-900/40 px-3 py-2 text-left text-[12px] text-slate-300 transition-colors hover:border-cyan-400/40 hover:bg-slate-900/70 hover:text-cyan-200"
                        >
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
                    <div className="max-w-[85%] rounded-2xl rounded-br-sm border border-blue-400/30 bg-blue-600/20 px-3.5 py-2 text-[13px] text-slate-100">
                      {message.content}
                    </div>
                  </div>
                ) : (
                  <div key={message.id}>
                    {message.answer ? <SophiaMessage answer={message.answer} /> : <p className="text-[13px] text-slate-200">{message.content}</p>}
                  </div>
                )
              ))}

              {streaming.active && (
                <div className="space-y-2 rounded-xl border border-slate-700/50 bg-slate-900/40 p-3">
                  <div className="flex items-center gap-2 text-[12px] text-cyan-200">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span>{streaming.stageLabel || 'Sophia is thinking…'}</span>
                  </div>
                  {streaming.toolRuns.length > 0 && (
                    <p className="text-[10px] text-slate-500">
                      {streaming.toolRuns.length} evidence source{streaming.toolRuns.length === 1 ? '' : 's'} consulted · tenant-isolated
                    </p>
                  )}
                </div>
              )}

              {error && (
                <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-[12px] text-red-300">{error}</div>
              )}
            </div>

            {/* Composer */}
            <div className="border-t border-slate-700/50 bg-slate-950/80 p-3">
              <div className="flex items-end gap-2 rounded-xl border border-slate-700/60 bg-slate-900/60 px-3 py-2 focus-within:border-cyan-400/50">
                <textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submit(); }
                  }}
                  placeholder="Ask Sophia about your quantum posture…"
                  rows={1}
                  className="max-h-28 flex-1 resize-none bg-transparent text-[13px] text-slate-100 placeholder:text-slate-600 focus:outline-none"
                />
                {speechSupported && (
                  <button
                    onClick={toggleVoice}
                    className={`flex h-8 w-8 items-center justify-center rounded-lg transition-colors ${listening ? 'bg-red-500/20 text-red-300' : 'text-slate-500 hover:bg-white/5 hover:text-cyan-300'}`}
                    title={listening ? 'Stop voice input' : 'Voice input'}
                  >
                    {listening ? <MicOff className="h-4 w-4" /> : <Mic className="h-4 w-4" />}
                  </button>
                )}
                {streaming.active ? (
                  <button onClick={stopStreaming} className="flex h-8 w-8 items-center justify-center rounded-lg bg-red-500/20 text-red-300 transition-colors hover:bg-red-500/30" title="Stop">
                    <Square className="h-3.5 w-3.5" />
                  </button>
                ) : (
                  <button
                    onClick={() => submit()}
                    disabled={!input.trim()}
                    className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-blue-600 to-violet-600 text-white transition-opacity disabled:opacity-40"
                    title="Send"
                  >
                    <Send className="h-4 w-4" />
                  </button>
                )}
              </div>
              <div className="mt-1.5 flex items-center justify-between px-1">
                <span className="text-[9px] text-slate-600">Tenant-isolated · evidence-based · RBAC-aware</span>
                {messages.some((m) => m.role === 'assistant') && 'speechSynthesis' in window && (
                  <button onClick={speakLast} className="text-[9px] text-slate-500 hover:text-cyan-300">🔊 Read last answer</button>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}

export default SophiaCopilot;
