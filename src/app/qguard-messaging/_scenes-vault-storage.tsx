/**
 * Interactive explainers for the Quantum Vault Storage line (design and
 * stated limits in
 * qguard-messaging/docs/QUANTUM_VAULT_STORAGE.md §2 and §11). Pictures of
 * mechanisms the app implements — not a working vault. Nothing drawn or
 * clicked here is stored or sent anywhere.
 */
import React, { useEffect, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  AlertTriangle,
  Check,
  EyeOff,
  FileText,
  Folder,
  Ghost,
  Grid3x3,
  HardDrive,
  Image as ImageIcon,
  Lock,
  Music,
  Star,
  Trash2,
  Unlock,
  X,
} from 'lucide-react';
import { Chip, StageFrame, useCalm } from './_motion';

/* ------------------------------------------------------------ pattern rules -- */

// Same rules as qguard-messaging/src/lib/pattern.ts (and the Rust core that
// re-checks them): 4 × 4 dots numbered row by row, at least 6, and a stroke
// that crosses an unconnected dot picks it up rather than jumping over it.
const GRID = 4;
const DOTS = GRID * GRID;
const MIN_DOTS = 6;

function gcd(a: number, b: number): number {
  return b === 0 ? Math.abs(a) : gcd(b, a % b);
}

function dotsBetween(a: number, b: number): number[] {
  const [ar, ac, br, bc] = [Math.floor(a / GRID), a % GRID, Math.floor(b / GRID), b % GRID];
  const [dr, dc] = [br - ar, bc - ac];
  const steps = gcd(dr, dc);
  const out: number[] = [];
  for (let k = 1; k < steps; k += 1) out.push((ar + (dr / steps) * k) * GRID + ac + (dc / steps) * k);
  return out;
}

function extendPattern(dots: number[], dot: number): number[] {
  if (dot < 0 || dot >= DOTS || dots.includes(dot)) return dots;
  const last = dots[dots.length - 1];
  const picked = last === undefined ? [] : dotsBetween(last, dot).filter((d) => !dots.includes(d));
  return [...dots, ...picked, dot];
}

const PAD = 240;
const CELL = PAD / GRID;
const center = (dot: number) => ({ x: ((dot % GRID) + 0.5) * CELL, y: (Math.floor(dot / GRID) + 0.5) * CELL });

function dotAt(x: number, y: number): number | null {
  const col = Math.floor(x / CELL);
  const row = Math.floor(y / CELL);
  if (col < 0 || row < 0 || col >= GRID || row >= GRID) return null;
  const dot = row * GRID + col;
  const c = center(dot);
  return Math.hypot(x - c.x, y - c.y) <= CELL * 0.34 ? dot : null;
}

/** A pad that reports the dots drawn. Pointer events cover mouse, pen and touch. */
function DemoPad({
  dots,
  onChange,
  onDone,
  tone,
  hideTrail = false,
  label,
}: {
  dots: number[];
  onChange: (dots: number[]) => void;
  onDone: (dots: number[]) => void;
  tone: string;
  hideTrail?: boolean;
  label: string;
}) {
  const drawing = useRef(false);
  const current = useRef<number[]>([]);
  const [pointer, setPointer] = useState<{ x: number; y: number } | null>(null);

  const locate = (e: React.PointerEvent<HTMLDivElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    return { x: ((e.clientX - r.left) / r.width) * PAD, y: ((e.clientY - r.top) / r.height) * PAD };
  };
  const reach = (p: { x: number; y: number }) => {
    const dot = dotAt(p.x, p.y);
    if (dot === null) return;
    const next = extendPattern(current.current, dot);
    if (next !== current.current) {
      current.current = next;
      onChange(next);
    }
  };
  const finish = () => {
    if (!drawing.current) return;
    drawing.current = false;
    setPointer(null);
    if (current.current.length > 0) onDone(current.current);
  };

  const pts = dots.map(center);
  const last = pts[pts.length - 1];
  return (
    <div
      role="application"
      aria-label={label}
      onPointerDown={(e) => {
        e.preventDefault();
        e.currentTarget.setPointerCapture?.(e.pointerId);
        drawing.current = true;
        current.current = [];
        onChange([]);
        const p = locate(e);
        setPointer(p);
        reach(p);
      }}
      onPointerMove={(e) => {
        if (!drawing.current) return;
        const p = locate(e);
        setPointer(p);
        reach(p);
      }}
      onPointerUp={finish}
      onPointerCancel={finish}
      onLostPointerCapture={finish}
      className="qm-glass relative mx-auto aspect-square w-full max-w-[15rem] cursor-pointer select-none"
      style={{ touchAction: 'none', borderColor: tone, borderWidth: 2 }}
    >
      <svg className="pointer-events-none absolute inset-0 h-full w-full" viewBox={`0 0 ${PAD} ${PAD}`} aria-hidden>
        {!hideTrail && pts.length > 1 && (
          <polyline points={pts.map((p) => `${p.x},${p.y}`).join(' ')} fill="none" stroke={tone} strokeWidth={5} strokeLinecap="round" strokeLinejoin="round" opacity={0.8} />
        )}
        {!hideTrail && last && pointer && drawing.current && (
          <line x1={last.x} y1={last.y} x2={pointer.x} y2={pointer.y} stroke={tone} strokeWidth={4} strokeLinecap="round" opacity={0.45} />
        )}
        {Array.from({ length: DOTS }, (_, d) => {
          const c = center(d);
          const on = !hideTrail && dots.includes(d);
          return (
            <g key={d}>
              {on && <circle cx={c.x} cy={c.y} r={CELL / 4.2} fill={tone} opacity={0.2} />}
              <circle cx={c.x} cy={c.y} r={on ? 7 : 5} fill={on ? tone : '#64748b'} />
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/* ------------------------------------------------------------- pattern lab -- */

// Pattern counts on a 4 × 4 grid with the no-jump rule, from
// qguard-messaging/src/lib/pattern.ts. 3 × 3 has ~389,000 in total.
const STRENGTH: Array<{ dots: string; count: string; min: number }> = [
  { dots: '6 dots', count: '≈1.3 million', min: 6 },
  { dots: '8 dots', count: '≈79 million', min: 8 },
];

const EXAMPLE = [0, 1, 2, 6, 10, 9, 13, 14];

export function PatternLab() {
  const calm = useCalm();
  const [dots, setDots] = useState<number[]>([]);
  const [done, setDone] = useState(false);
  const [hide, setHide] = useState(false);
  const timer = useRef<number | null>(null);

  useEffect(() => () => { if (timer.current) window.clearInterval(timer.current); }, []);

  const playExample = () => {
    if (timer.current) window.clearInterval(timer.current);
    setDone(false);
    if (calm) {
      setDots(EXAMPLE);
      setDone(true);
      return;
    }
    let i = 0;
    setDots([]);
    timer.current = window.setInterval(() => {
      i += 1;
      setDots(EXAMPLE.slice(0, i));
      if (i >= EXAMPLE.length) {
        if (timer.current) window.clearInterval(timer.current);
        setDone(true);
      }
    }, 260);
  };

  const n = dots.length;
  const short = done && n < MIN_DOTS;
  const ok = done && n >= MIN_DOTS;
  const tone = short ? '#fb7185' : ok ? '#34d399' : '#22d3ee';
  const canonical = n ? `4x4:${dots.join('-')}` : '4x4:…';

  return (
    <StageFrame
      title="Draw a pattern — see what the vault does with it"
      icon={Grid3x3}
      note={<span>A demonstration pad with the app’s own rules. What you draw here stays in this page — it is not stored or sent. In the app the pattern never leaves the device either: only an Argon2id-stretched key is used, inside the native core.</span>}
    >
      <div className="grid items-center gap-6 md:grid-cols-[minmax(0,15rem)_minmax(0,1fr)]">
        <div>
          <DemoPad
            dots={dots}
            tone={tone}
            hideTrail={hide}
            label="Demonstration pattern pad: connect at least 6 dots"
            onChange={(d) => { setDone(false); setDots(d); }}
            onDone={() => setDone(true)}
          />
          <div className="mt-3 flex flex-wrap justify-center gap-2">
            <button type="button" className="qm-btn" onClick={playExample}>Draw an example</button>
            <button type="button" className="qm-btn" aria-pressed={hide} onClick={() => setHide((v) => !v)}>
              <EyeOff className="h-3.5 w-3.5" aria-hidden />Hide trail
            </button>
          </div>
        </div>

        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2" aria-live="polite">
            <span className="qm-t-ink" style={{ fontSize: 15, fontWeight: 800 }}>{n} {n === 1 ? 'dot' : 'dots'}</span>
            {short && <Chip tone="rose"><X className="h-3 w-3" aria-hidden />Too short — connect at least {MIN_DOTS}</Chip>}
            {ok && n < 8 && <Chip tone="amber"><Check className="h-3 w-3" aria-hidden />Accepted · 8 or more is stronger</Chip>}
            {ok && n >= 8 && <Chip tone="green"><Check className="h-3 w-3" aria-hidden />Accepted · strong</Chip>}
            {!done && n === 0 && <span className="qm-t-mute" style={{ fontSize: 12.5 }}>Press and drag across the dots.</span>}
            {hide && n > 0 && <Chip tone="mute">Trail hidden from onlookers</Chip>}
          </div>

          <div className="qm-term mt-4" style={{ fontSize: 12 }} role="log" aria-label="What the core does with the pattern">
            <div style={{ color: '#e6edf7' }}>pattern  {hide ? '4x4:' + '•'.repeat(Math.min(n, 12)) : canonical}</div>
            <div>stretch  Argon2id · 64 MiB · 3 passes</div>
            <div>derive   HKDF-SHA3-256 → verifier + wrap key</div>
            <div>unwrap   AES-256-GCM → Vault Master Key</div>
            <div style={{ color: '#9fb0c8' }}>limits   5 wrong → 30 s · 10 → 5 min · 20 → lockdown</div>
          </div>

          <div className="mt-4 grid grid-cols-2 gap-3">
            {STRENGTH.map((s) => (
              <div key={s.dots} className="qm-glass" style={{ padding: 12, borderColor: n >= s.min ? '#34d399' : undefined }}>
                <div className="qm-mono qm-t-mute" style={{ fontSize: 10, letterSpacing: '.14em' }}>{s.dots.toUpperCase()}</div>
                <div className="qm-t-ink mt-1" style={{ fontSize: 15, fontWeight: 800 }}>{s.count}</div>
                <div className="qm-t-mute" style={{ fontSize: 11 }}>possible patterns</div>
              </div>
            ))}
          </div>
          <p className="qm-t-mute mt-3" style={{ fontSize: 12, lineHeight: 1.6 }}>
            Why 4 × 4: all 3 × 3 patterns together are about 389,000 — fewer than the 6-digit PINs. A stroke over an unconnected dot picks it up, as on the app’s pad. Patterns, like PINs, are not available in the restricted build mode.
          </p>
        </div>
      </div>
    </StageFrame>
  );
}

/* ------------------------------------------------------------- hidden vault -- */

type Try = 'none' | 'vault' | 'hidden' | 'wrong';

const TRIES: Array<{ id: Exclude<Try, 'none'>; label: string; dots: number[] }> = [
  { id: 'vault', label: 'Draw the vault’s pattern', dots: [0, 1, 2, 3, 7, 11, 15] },
  { id: 'hidden', label: 'Draw a hidden vault’s pattern', dots: [12, 8, 4, 5, 6, 10, 14, 15] },
  { id: 'wrong', label: 'Draw a wrong pattern', dots: [0, 5, 10, 15, 14, 13] },
];

// Illustrative names and sizes in the format the app writes: 32 hex characters,
// no extension; sizes rounded up (≥ 16 KiB, then to 1/32 of the next power of two).
const POOL = [
  ['8f3a61c0d29e4b7a95e0c1f4a6b3d728', '16 KiB'],
  ['c47e09b2a1f35d68e0b94c7a2d61f3e5', '34 KiB'],
  ['1b9d4e7f20a6c35b8e1d07f9a4c26b30', '1.25 MiB'],
  ['e6a2f81c4b09d73e5a1c68b0f2d94e17', '16 KiB'],
  ['5d07c3e9b1a48f26d0e3b75c9a14f8e2', '136 KiB'],
  ['a90f2e64c18b3d75e2a0c94f61b8d3a7', '4.25 MiB'],
  ['3c58b1d0e7f2a49c63e5d8a1b04f7c92', '62 KiB'],
];

const NOT_HIDDEN = [
  'An examiner can see the pool folder’s size and file count — every account has one, with cover files from the start.',
  'Comparing two images of the device shows that the folder changed.',
  'Whoever extracts this device’s secure-store key can try patterns offline at Argon2id cost each — a short or common pattern is guessable. Use 8 or more dots.',
  'Flash storage can keep stale blocks of overwritten files — ciphertext under keys that exist only in the pattern.',
  'No recovery: forget the pattern or lose the device and the hidden vault is gone. No backup, library or sharing either.',
];

export function HiddenVaultLab() {
  const [view, setView] = useState<'lock' | 'disk' | 'limits'>('lock');
  const [tried, setTried] = useState<Try>('none');
  const t = TRIES.find((x) => x.id === tried);
  const result =
    tried === 'vault'
      ? { icon: Unlock, tone: '#34d399', title: 'Quantum Vault opens', body: 'Your ordinary vault, with its files, backup and sharing.' }
      : tried === 'hidden'
        ? { icon: Ghost, tone: '#b9a4ff', title: 'The hidden vault opens instead', body: 'A separate library. The Quantum Vault stays locked while it is open, and every lock closes both.' }
        : tried === 'wrong'
          ? { icon: AlertTriangle, tone: '#fb7185', title: 'Wrong pattern', body: 'One ordinary failed attempt — the same message whether or not a hidden vault exists.' }
          : null;

  return (
    <StageFrame
      title="Hidden vaults — one lock screen for everyone"
      icon={Ghost}
      note={<span>Both checks — the vault’s own pattern and the hidden derivation — always run side by side, so timing says nothing, and an open hidden vault is logged as the same unlock as any vault. Names and sizes here are illustrative, in the format the app writes.</span>}
    >
      <div role="tablist" aria-label="Hidden vault views" className="flex flex-wrap gap-2">
        <button type="button" role="tab" className="qm-btn" aria-selected={view === 'lock'} onClick={() => setView('lock')}><Lock className="h-3.5 w-3.5" aria-hidden />Lock screen</button>
        <button type="button" role="tab" className="qm-btn" aria-selected={view === 'disk'} onClick={() => setView('disk')}><HardDrive className="h-3.5 w-3.5" aria-hidden />On the disk</button>
        <button type="button" role="tab" className="qm-btn" aria-selected={view === 'limits'} onClick={() => setView('limits')}><AlertTriangle className="h-3.5 w-3.5" aria-hidden />What it does not hide</button>
      </div>

      <AnimatePresence mode="wait">
        <motion.div key={view} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }} className="mt-5">
          {view === 'lock' && (
            <div className="grid items-center gap-6 md:grid-cols-[minmax(0,13rem)_minmax(0,1fr)]">
              <div className="qm-glass mx-auto w-full max-w-[13rem]" style={{ padding: 14 }}>
                <div className="qm-mono qm-t-mute text-center" style={{ fontSize: 10, letterSpacing: '.14em' }}>QUANTUM VAULT · LOCKED</div>
                <svg viewBox={`0 0 ${PAD} ${PAD}`} className="mt-2 w-full" aria-hidden>
                  {t && <polyline points={t.dots.map(center).map((p) => `${p.x},${p.y}`).join(' ')} fill="none" stroke={result?.tone} strokeWidth={5} strokeLinecap="round" strokeLinejoin="round" opacity={0.8} />}
                  {Array.from({ length: DOTS }, (_, d) => {
                    const c = center(d);
                    const on = t?.dots.includes(d);
                    return <circle key={d} cx={c.x} cy={c.y} r={on ? 7 : 5} fill={on ? result?.tone : '#64748b'} />;
                  })}
                </svg>
                <div className="qm-t-mute mt-1 text-center" style={{ fontSize: 11 }}>Password · PIN · Pattern</div>
              </div>
              <div className="min-w-0">
                <div className="flex flex-col gap-2">
                  {TRIES.map((x) => (
                    <button key={x.id} type="button" className="qm-btn justify-start" aria-pressed={tried === x.id} onClick={() => setTried(x.id)}>{x.label}</button>
                  ))}
                </div>
                <div className="mt-4 min-h-[72px]" aria-live="polite">
                  {result && (
                    <motion.div key={tried} initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} className="qm-glass" style={{ padding: 12, borderColor: result.tone }}>
                      <div className="flex items-center gap-2">
                        <result.icon className="h-4 w-4" style={{ color: result.tone }} aria-hidden />
                        <span className="qm-t-ink" style={{ fontSize: 14, fontWeight: 800 }}>{result.title}</span>
                      </div>
                      <div className="qm-t-mute mt-1" style={{ fontSize: 12.5 }}>{result.body}</div>
                    </motion.div>
                  )}
                </div>
                <p className="qm-t-mute mt-3" style={{ fontSize: 12, lineHeight: 1.6 }}>
                  The app has no list, count or setting that names a hidden vault. The pattern pad is offered to every vault user, and nothing about a hidden vault reaches the audit log, telemetry or the vault’s activity. An optional 12-word recovery phrase can reset its pattern on the files still stored locally.
                </p>
              </div>
            </div>
          )}

          {view === 'disk' && (
            <div>
              <div className="qm-term" style={{ fontSize: 11.5 }} role="table" aria-label="Example of the hidden vault pool folder">
                <div role="row" style={{ color: '#e6edf7' }}>&lt;app data&gt;/vault/pool/&lt;account&gt;/</div>
                {POOL.map(([name, size]) => (
                  <div role="row" key={name} className="flex justify-between gap-4">
                    <span role="cell" className="min-w-0 truncate">{name}</span>
                    <span role="cell" style={{ color: '#9fb0c8' }}>{size}</span>
                  </div>
                ))}
              </div>
              <div className="mt-4 grid gap-3 sm:grid-cols-3">
                {[
                  ['No headers', 'Index, content and cover files are all bare AES-256-GCM output or random padding — no magic bytes, no extension.'],
                  ['Every account has one', 'The folder exists for every user, filled with 4–8 random cover files when it is created.'],
                  ['Device-bound keys', 'Keys come from the pattern (Argon2id) and this device’s secure key store, so a copied disk alone cannot test guesses.'],
                ].map(([h, b]) => (
                  <div key={h} className="qm-glass" style={{ padding: 12 }}>
                    <div className="qm-t-ink" style={{ fontSize: 13, fontWeight: 800 }}>{h}</div>
                    <div className="qm-t-mute mt-1" style={{ fontSize: 12, lineHeight: 1.55 }}>{b}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {view === 'limits' && (
            <ul className="space-y-2.5">
              {NOT_HIDDEN.map((l) => (
                <li key={l} className="qm-glass flex items-start gap-2.5" style={{ padding: 12 }}>
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 qm-t-amber" aria-hidden />
                  <span className="qm-t-ink" style={{ fontSize: 12.5, lineHeight: 1.6 }}>{l}</span>
                </li>
              ))}
            </ul>
          )}
        </motion.div>
      </AnimatePresence>
    </StageFrame>
  );
}

/* ---------------------------------------------------------- storage library -- */

type Entry = { id: string; name: string; kind: 'photo' | 'doc' | 'audio'; size: string; fav?: boolean; status: 'verified' | 'pending' };

const FILES: Entry[] = [
  { id: '3f9c2a71', name: 'Passport scan.jpg', kind: 'photo', size: '2.4 MB', fav: true, status: 'verified' },
  { id: 'b81e04d6', name: 'Board deck Q4.pptx', kind: 'doc', size: '18.1 MB', status: 'verified' },
  { id: '0d6a7f3e', name: 'Signed contract.pdf', kind: 'doc', size: '640 KB', fav: true, status: 'pending' },
  { id: 'e52b98c1', name: 'Voice memo.m4a', kind: 'audio', size: '3.2 MB', status: 'verified' },
];

const KIND_ICON = { photo: ImageIcon, doc: FileText, audio: Music } as const;

const CATEGORIES = [
  { icon: Folder, label: 'All files' },
  { icon: ImageIcon, label: 'Photos & Videos' },
  { icon: FileText, label: 'Documents' },
  { icon: Music, label: 'Audio' },
  { icon: Star, label: 'Favorites' },
  { icon: Trash2, label: 'Trash' },
];

export function StorageLibraryLab() {
  const [view, setView] = useState<'you' | 'disk'>('you');
  const [shredded, setShredded] = useState<string[]>([]);
  const live = FILES.filter((f) => !shredded.includes(f.id));

  return (
    <StageFrame
      title="Quantum Vault Storage — what you see, what the disk holds"
      icon={HardDrive}
      note={<span>Example files. On disk each one is an ordinary v5 container named <span className="qm-mono">vault-object</span>; names, folders, types, hashes and activity exist only inside the sealed index, readable only while the vault is unlocked.</span>}
    >
      <div role="tablist" aria-label="Storage views" className="flex flex-wrap gap-2">
        <button type="button" role="tab" className="qm-btn" aria-selected={view === 'you'} onClick={() => setView('you')}><Unlock className="h-3.5 w-3.5" aria-hidden />You, vault unlocked</button>
        <button type="button" role="tab" className="qm-btn" aria-selected={view === 'disk'} onClick={() => setView('disk')}><HardDrive className="h-3.5 w-3.5" aria-hidden />Anyone reading the disk</button>
        {shredded.length > 0 && <button type="button" className="qm-btn" onClick={() => setShredded([])}>Reset example</button>}
      </div>

      <AnimatePresence mode="wait">
        <motion.div key={view} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }} className="mt-5">
          {view === 'you' ? (
            <div className="grid gap-4 md:grid-cols-[11rem_minmax(0,1fr)]">
              <ul className="qm-glass hidden md:block" style={{ padding: 8 }}>
                {CATEGORIES.map((c, i) => (
                  <li key={c.label} className="flex items-center gap-2 rounded-lg px-2 py-1.5" style={{ fontSize: 12.5, background: i === 0 ? 'rgba(34,211,238,.12)' : undefined }}>
                    <c.icon className="h-3.5 w-3.5 qm-t-cyan" aria-hidden /><span className="qm-t-ink">{c.label}</span>
                  </li>
                ))}
              </ul>
              <ul className="min-w-0 space-y-2">
                {live.map((f) => {
                  const Icon = KIND_ICON[f.kind];
                  return (
                    <li key={f.id} className="qm-glass flex flex-wrap items-center gap-3" style={{ padding: '10px 12px' }}>
                      <Icon className="h-4 w-4 shrink-0 qm-t-cyan" aria-hidden />
                      <span className="qm-t-ink min-w-[9rem] flex-1 truncate" style={{ fontSize: 13, fontWeight: 700 }}>{f.name}</span>
                      {f.fav && <Star className="h-3.5 w-3.5 qm-t-gold" aria-label="Favorite" />}
                      <span className="qm-mono qm-t-mute" style={{ fontSize: 11 }}>{f.size}</span>
                      {f.status === 'verified' ? <Chip tone="green"><Check className="h-3 w-3" aria-hidden />Integrity verified</Chip> : <Chip tone="mute">Not yet verified</Chip>}
                      <button type="button" className="qm-btn" data-danger="true" onClick={() => setShredded((s) => [...s, f.id])} aria-label={`Delete ${f.name} permanently`}>
                        <Trash2 className="h-3.5 w-3.5" aria-hidden />Delete permanently
                      </button>
                    </li>
                  );
                })}
                {live.length === 0 && <li className="qm-t-mute" style={{ fontSize: 12.5 }}>All files were removed from this example.</li>}
              </ul>
            </div>
          ) : (
            <div className="qm-term" style={{ fontSize: 11.5 }} role="log" aria-label="Example of the vault storage folder on disk">
              <div style={{ color: '#e6edf7' }}>&lt;app data&gt;/vault/store/&lt;account&gt;/</div>
              <div>index.qvs ................ AES-256-GCM · names, folders, types, hashes</div>
              <div>index.recovery.qvs ....... same index under your recovery key</div>
              {FILES.map((f) =>
                shredded.includes(f.id) ? (
                  <div key={f.id} style={{ color: '#fb7185' }}>objects/{f.id}….qvault  header overwritten with random bytes → removed</div>
                ) : (
                  <div key={f.id}>objects/{f.id}….qvault  name: vault-object · type: application/octet-stream</div>
                ),
              )}
              {!shredded.includes('3f9c2a71') && <div>thumbs/3f9c2a71….qvt ...... thumbnail, sealed under its own key</div>}
            </div>
          )}
        </motion.div>
      </AnimatePresence>

      <div className="mt-4 grid gap-3 sm:grid-cols-3">
        {[
          ['Types from content', 'Detected from the file’s first bytes, never the extension — a mismatch is flagged on the file.'],
          ['Checked on every open', 'Signature, this vault’s key, every chunk, and the recorded SHA3-256 of the plaintext.'],
          ['Previews stay in memory', 'Images, audio, video up to 64 MiB and text are shown from memory; nothing is written to disk.'],
        ].map(([h, b]) => (
          <div key={h} className="qm-glass" style={{ padding: 12 }}>
            <div className="qm-t-ink" style={{ fontSize: 13, fontWeight: 800 }}>{h}</div>
            <div className="qm-t-mute mt-1" style={{ fontSize: 12, lineHeight: 1.55 }}>{b}</div>
          </div>
        ))}
      </div>
    </StageFrame>
  );
}
