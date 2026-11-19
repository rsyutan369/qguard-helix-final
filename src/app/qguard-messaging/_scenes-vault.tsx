/**
 * Interactive explainers for the Quantum Vault page. Pictures of mechanisms the
 * vault really implements (.qvault v5, chunked AEAD, hybrid recovery) — not
 * live data and not a working vault.
 */
import React, { useEffect, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { AlertTriangle, Building2, Check, FileLock2, KeyRound, Layers, Lock, ShieldCheck, Terminal, Unlock, X } from 'lucide-react';
import { Chip, StageFrame, useCalm, useStageVisible, useTicker } from './_motion';
import { ExplodedStack } from './_stack';

/* ----------------------------------------------------- envelope layers ------ */

const ENVELOPE = [
  { icon: FileLock2, title: 'Signed container', tag: 'ML-DSA-87 + Ed25519', tone: '#d4af37', body: 'Standard .qvault v5 headers are signed with Ed25519 and ML-DSA-87. The reader checks the header before opening encrypted chunks.' },
  { icon: ShieldCheck, title: 'Hybrid post-quantum seal', tag: 'X25519 + ML-KEM-1024 · sharing & enterprise', tone: '#8b5cf6', body: 'When you seal a portable file to a recipient or enable enterprise recovery, the file key is also wrapped with a hybrid KEM, mixed by HKDF-SHA3-256 with a transcript-bound combiner (QGuard-HybridKEM-v2). ML-KEM only ever protects a key; it never encrypts content.' },
  { icon: KeyRound, title: 'PIN-bound Vault Master Key', tag: '.qvault v5', tone: '#22d3ee', body: 'In v5 the file key is wrapped under the PIN-bound vault key, so the vault lock is enforced by the cryptography — not just a check in the interface. Older containers stay readable, are reported as not PIN-bound, and “re-protect” rewrites their header.' },
  { icon: Lock, title: 'One AES-256-GCM key per file', tag: 'AES-256-GCM', tone: '#34d399', body: 'Each file gets its own random key. Content is streamed in authenticated chunks, and each chunk is bound to its position.' },
  { icon: Layers, title: 'Your file or folder', tag: 'On your device', tone: '#e6edf7', body: 'Any file, or a whole folder (desktop) packed into one archive whose structure is hidden inside the ciphertext. Nothing is uploaded.' },
];

export function EnvelopeLayers() {
  const [explode, setExplode] = useState(0.75);
  const [sel, setSel] = useState(0);
  const L = ENVELOPE[sel];
  return (
    <StageFrame
      title="The layered key envelope"
      icon={Layers}
      note={<span>Read it from the outside in. The signature authenticates the header; AES-GCM checks the encrypted chunks during decryption. To read a file, someone needs its per-file key — and that is only ever stored wrapped under your PIN-bound key, your recovery key, or (when you share or use enterprise recovery) a hybrid post-quantum seal.</span>}
    >
      <div className="grid items-center gap-5 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
        <div>
          <ExplodedStack layers={ENVELOPE.map((l) => ({ icon: l.icon, title: l.title, tone: l.tone }))} sel={sel} onSelect={setSel} explode={explode} />
          <label className="qm-t-mute flex items-center gap-3" style={{ fontSize: 12 }}>
            <span className="qm-mono" style={{ fontSize: 10, letterSpacing: '.14em' }}>EXPLODE</span>
            <input type="range" min={0} max={1} step={0.01} value={explode} onChange={(e) => setExplode(Number(e.target.value))} aria-label="Explode the layers" className="w-full" style={{ accentColor: '#22d3ee' }} />
          </label>
        </div>
        <div>
          <div className="flex flex-wrap gap-2" role="tablist" aria-label="Envelope layers, outside to inside">
            {ENVELOPE.map((l, i) => (
              <button key={l.title} role="tab" type="button" className="qm-btn" aria-selected={sel === i} onClick={() => setSel(i)}>
                <l.icon className="h-3.5 w-3.5" style={{ color: l.tone }} aria-hidden />{i + 1}. {l.title}
              </button>
            ))}
          </div>
          <div className="qm-glass mt-4" style={{ padding: 16 }} aria-live="polite">
            <AnimatePresence mode="wait">
              <motion.div key={sel} initial={{ opacity: 0, x: 12 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.22 }}>
                <div className="qm-mono qm-t-mute" style={{ fontSize: 10, letterSpacing: '.16em' }}>LAYER {sel + 1} OF {ENVELOPE.length} · OUTSIDE → IN</div>
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <L.icon className="h-5 w-5" style={{ color: L.tone }} aria-hidden />
                  <span className="qm-t-ink" style={{ fontSize: 15, fontWeight: 800 }}>{L.title}</span>
                  <Chip tone="cyan">{L.tag}</Chip>
                </div>
                <div className="qm-t-mute mt-3" style={{ fontSize: 12.5, lineHeight: 1.65 }}>{L.body}</div>
              </motion.div>
            </AnimatePresence>
          </div>
        </div>
      </div>
    </StageFrame>
  );
}

/* ------------------------------------------------------ chunk integrity ----- */

const N = 12;
type Attack = 'none' | 'flip' | 'swap' | 'truncate';

function verdictFor(attack: Attack): { at: number; text: string } {
  if (attack === 'flip') return { at: 5, text: 'Rejected at chunk 6 — its AES-256-GCM authentication tag no longer matches.' };
  if (attack === 'swap') return { at: 3, text: 'Rejected at chunk 4 — every chunk is bound to its position, so a reordered chunk fails.' };
  if (attack === 'truncate') return { at: 9, text: 'Rejected after chunk 9 — the final-chunk marker is missing, so a truncated container cannot pass as complete.' };
  return { at: N, text: `All ${N} chunks verified in order, including the final marker.` };
}

export function ChunkIntegrityLab() {
  const calm = useCalm();
  const [attack, setAttack] = useState<Attack>('none');
  const [scan, setScan] = useState(calm ? N : -1);
  const v = verdictFor(attack);

  useEffect(() => {
    if (calm) {
      setScan(v.at);
      return;
    }
    setScan(-1);
    let i = -1;
    const id = window.setInterval(() => {
      i += 1;
      setScan(i);
      if (i >= v.at) window.clearInterval(id);
    }, 170);
    return () => window.clearInterval(id);
  }, [attack, calm, v.at]);

  const chunkState = (i: number): 'ok' | 'bad' | 'missing' | 'pending' => {
    if (attack === 'truncate' && i >= 9) return 'missing';
    const failAt = attack === 'flip' ? 5 : attack === 'swap' ? 3 : -1;
    if (scan < i) return 'pending';
    if (i === failAt) return 'bad';
    // Verification stops at the first failure; later chunks are never reached.
    if (failAt >= 0 && i > failAt) return 'pending';
    return 'ok';
  };
  const done = scan >= v.at;
  const rejected = attack !== 'none';

  return (
    <StageFrame
      title="Tamper, reorder, truncate — see it refused"
      icon={ShieldCheck}
      note={<span>A simplified picture: the real vault checks each chunk’s GCM tag with its index and the final-chunk flag as authenticated data, then refuses before writing a plaintext file.</span>}
    >
      <div className="flex flex-wrap gap-2">
        <button type="button" className="qm-btn" aria-pressed={attack === 'none'} onClick={() => setAttack('none')}>Untouched</button>
        <button type="button" className="qm-btn" aria-pressed={attack === 'flip'} onClick={() => setAttack('flip')}>Flip one bit in chunk 6</button>
        <button type="button" className="qm-btn" aria-pressed={attack === 'swap'} onClick={() => setAttack('swap')}>Swap chunks 4 and 5</button>
        <button type="button" className="qm-btn" aria-pressed={attack === 'truncate'} onClick={() => setAttack('truncate')}>Cut off the last 3 chunks</button>
      </div>

      <div className="mt-5 grid grid-cols-6 gap-2 sm:grid-cols-12" style={{ perspective: 800 }}>
        {Array.from({ length: N }, (_, i) => {
          const st = chunkState(i);
          const label = attack === 'swap' && (i === 3 || i === 4) ? (i === 3 ? 5 : 4) : i + 1;
          const color = st === 'ok' ? '#34d399' : st === 'bad' ? '#fb7185' : st === 'missing' ? '#64748b' : '#9fb0c8';
          return (
            <motion.div
              key={i}
              animate={{ scale: st === 'bad' ? 1.08 : 1, opacity: st === 'missing' ? 0.25 : 1 }}
              className="qm-glass flex flex-col items-center justify-center"
              style={{ height: 66, borderColor: color, boxShadow: st === 'bad' ? '0 0 22px rgba(251,113,133,.45)' : st === 'ok' ? '0 0 14px rgba(52,211,153,.18)' : undefined, borderStyle: st === 'missing' ? 'dashed' : 'solid' }}
            >
              <span className="qm-mono qm-t-mute" style={{ fontSize: 9 }}>#{String(label).padStart(2, '0')}</span>
              {st === 'ok' && <Check className="h-4 w-4 qm-t-green" aria-label="verified" />}
              {st === 'bad' && <X className="h-4 w-4 qm-t-rose" aria-label="failed" />}
              {st === 'missing' && <span className="qm-mono qm-t-mute" style={{ fontSize: 8 }}>gone</span>}
              {st === 'pending' && <span className="qm-mono qm-t-mute" style={{ fontSize: 10 }}>···</span>}
            </motion.div>
          );
        })}
      </div>

      <div aria-live="polite" className="mt-4 min-h-[44px]">
        {done && (
          <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="flex flex-wrap items-center gap-3">
            {rejected ? <Chip tone="rose"><AlertTriangle className="h-3 w-3" aria-hidden />Refused — nothing written</Chip> : <Chip tone="green"><Check className="h-3 w-3" aria-hidden />Accepted</Chip>}
            <span className="qm-t-ink" style={{ fontSize: 12.5 }}>{v.text}</span>
          </motion.div>
        )}
      </div>
    </StageFrame>
  );
}

/* ---------------------------------------------------------- terminal -------- */

const TERM = [
  '$ qvault seal board-deck.pptx',
  '[1/5] file key ............ random, one per file',
  '[2/5] wrap ................ PIN-bound Vault Master Key (v5)',
  '[3/5] backup .............. recovery key · enterprise X25519 + ML-KEM-1024 (if set)',
  '[4/5] sign ................ ML-DSA-87 + Ed25519',
  '[5/5] stream .............. AES-256-GCM, chunk by chunk',
  '      chunk 0001 ✓ tag ok · bound to position',
  '      chunk 0002 ✓ tag ok · bound to position',
  '      chunk 0003 ✓ tag ok · final marker set',
  'sealed → board-deck.pptx.qvault · 0 bytes uploaded',
];

export function CryptoTerminal() {
  const [ref, visible] = useStageVisible<HTMLDivElement>();
  const calm = useCalm();
  const [n, setN] = useTicker(TERM.length + 3, 650, visible);
  const shown = calm ? TERM.length : Math.min(n + 1, TERM.length);
  return (
    <div ref={ref}>
      <StageFrame
        title="Live Crypto Terminal"
        icon={Terminal}
        note={<span>This replay shows the order of the pipeline. In the app the terminal reports your real operation — key sealing, signing and per-chunk progress with true throughput and ETA.</span>}
      >
        <div className="qm-term" role="log" aria-label="Example vault sealing pipeline">
          {TERM.slice(0, shown).map((l, i) => (
            <div key={l} style={{ color: l.startsWith('$') ? '#e6edf7' : l.startsWith('sealed') ? '#34d399' : undefined, animation: calm ? undefined : 'qm-rise .3s ease both' }}>
              {l}
              {i === shown - 1 && <span className="qm-caret" />}
            </div>
          ))}
        </div>
        <div className="mt-3 flex gap-2">
          <button type="button" className="qm-btn" onClick={() => setN(0)}>Replay</button>
        </div>
      </StageFrame>
    </div>
  );
}

/* ------------------------------------------------------ recovery keys ------- */

type Mode = 'personal' | 'enterprise' | 'hybrid';
const MODES: Array<{ id: Mode; label: string; rule: string }> = [
  { id: 'personal', label: 'Personal', rule: 'Your offline recovery key alone restores your files.' },
  { id: 'enterprise', label: 'Enterprise', rule: 'The enterprise recovery key, held by your admins, restores them.' },
  { id: 'hybrid', label: 'Hybrid dual-control', rule: 'Both keys are required — two-person integrity for regulated teams.' },
];

export function RecoveryKeys() {
  const [mode, setMode] = useState<Mode>('hybrid');
  const [personal, setPersonal] = useState(false);
  const [enterprise, setEnterprise] = useState(false);
  const open = mode === 'personal' ? personal : mode === 'enterprise' ? enterprise : personal && enterprise;
  const neither = !personal && !enterprise;
  const current = MODES.find((m) => m.id === mode)!;

  const Key = ({ label, on, toggle, icon: Icon }: { label: string; on: boolean; toggle: () => void; icon: typeof KeyRound }) => (
    <motion.button
      type="button"
      onClick={toggle}
      aria-pressed={on}
      animate={{ rotateY: on ? 0 : 180, y: on ? -6 : 0 }}
      transition={{ type: 'spring', stiffness: 130, damping: 14 }}
      className="qm-glass"
      style={{ padding: '16px 18px', minWidth: 148, cursor: 'pointer', borderColor: on ? '#22d3ee' : 'rgba(148,163,184,.3)', transformStyle: 'preserve-3d' }}
    >
      <span style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6, transform: on ? undefined : 'scaleX(-1)', opacity: on ? 1 : 0.55 }}>
        <Icon className="h-6 w-6 qm-t-cyan" aria-hidden />
        <span className="qm-t-ink" style={{ fontSize: 12, fontWeight: 700 }}>{label}</span>
        <span className="qm-mono qm-t-mute" style={{ fontSize: 9.5 }}>{on ? 'PRESENTED' : 'NOT PRESENT'}</span>
      </span>
    </motion.button>
  );

  return (
    <StageFrame
      title="Quantum-safe recovery — personal, enterprise, dual-control"
      icon={KeyRound}
      note={<span>Because the vault is zero-knowledge, if you lose both your device and your recovery key the files cannot be recovered — by anyone, including QGuard. That is the same property that stops anyone else reading them.</span>}
    >
      <div role="tablist" aria-label="Recovery mode" className="flex flex-wrap gap-2">
        {MODES.map((m) => (
          <button key={m.id} role="tab" type="button" className="qm-btn" aria-selected={mode === m.id} onClick={() => setMode(m.id)}>{m.label}</button>
        ))}
      </div>
      <div className="qm-t-mute mt-2" style={{ fontSize: 12.5 }}>{current.rule}</div>

      <div className="mt-5 grid items-center gap-5 md:grid-cols-[1fr_auto_1fr]" style={{ perspective: 800 }}>
        <div className="flex flex-wrap justify-center gap-3">
          <Key label="Personal recovery key" on={personal} toggle={() => setPersonal((v) => !v)} icon={KeyRound} />
          <Key label="Enterprise key (X25519 + ML-KEM-1024)" on={enterprise} toggle={() => setEnterprise((v) => !v)} icon={Building2} />
        </div>
        <div className="mx-auto flex items-center justify-center" style={{ width: 64 }} aria-hidden>
          <div className="qm-ring" style={{ position: 'relative', left: 0, top: 0, width: 52, height: 52, animationDuration: '8s', transform: 'none', border: '1.5px dashed rgba(34,211,238,.6)' }} />
        </div>
        <motion.div
          key={String(open)}
          initial={{ scale: 0.9, opacity: 0.4 }}
          animate={{ scale: 1, opacity: 1 }}
          className="qm-glass text-center"
          style={{ padding: 18, borderColor: open ? '#34d399' : neither ? 'rgba(251,113,133,.5)' : 'rgba(148,163,184,.3)' }}
          aria-live="polite"
        >
          {open ? <Unlock className="mx-auto h-8 w-8 qm-t-green" aria-hidden /> : <Lock className="mx-auto h-8 w-8 qm-t-mute" aria-hidden />}
          <div className="qm-t-ink mt-2" style={{ fontSize: 14, fontWeight: 800 }}>{open ? 'Files restored on the new device' : 'Vault stays sealed'}</div>
          <div className="qm-t-mute mt-1" style={{ fontSize: 12 }}>
            {open ? 'No access to the old device was needed.' : mode === 'hybrid' && (personal || enterprise) ? 'One key is not enough in dual-control mode.' : 'Present the key to continue.'}
          </div>
        </motion.div>
      </div>
      <div className="mt-4 flex gap-2"><button type="button" className="qm-btn" onClick={() => { setPersonal(false); setEnterprise(false); }}>Put both keys away</button></div>
    </StageFrame>
  );
}
