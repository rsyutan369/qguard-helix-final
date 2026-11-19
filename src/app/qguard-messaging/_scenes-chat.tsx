/**
 * Interactive explainers for the Secure Chat page. Each one is a picture of a
 * mechanism the app really implements (see qguard-messaging/CHANGELOG.md and
 * docs/security-limitations.md) — a diagram you can poke, never live data.
 *
 * Copy discipline: where a feature is opt-in, Android-only, unreviewed, or
 * leaves end-to-end encryption, the stage says so on its face.
 */
import React, { useEffect, useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  AlertTriangle,
  Check,
  CircleHelp,
  Eraser,
  Fingerprint,
  KeyRound,
  Lock,
  MonitorUp,
  Radio,
  RefreshCcw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Users,
  Wifi,
} from 'lucide-react';
import { Chip, StageFrame, useCalm, useTicker } from './_motion';
import { ExplodedStack } from './_stack';

type Tone = 'green' | 'amber' | 'mute' | 'cyan' | 'violet' | 'gold' | 'rose';

/* ------------------------------------------------- protection badge ---------- */

type Ev = { kind: 'ok' | 'warn' | 'unknown'; text: string };
const BADGE_STATES: Array<{ id: string; label: string; tone: Tone; blurb: string; evidence: Ev[] }> = [
  {
    id: 'safe',
    label: 'Quantum-safe',
    tone: 'green',
    blurb: 'Everything the app can check about the next message points the same way.',
    evidence: [
      { kind: 'ok', text: 'The next message is sealed to every trusted device of the contact, each with hybrid X25519 + ML-KEM-1024 keys (QGuard-HybridKEM-v2).' },
      { kind: 'ok', text: 'Recent incoming messages arrived in that same hybrid form.' },
      { kind: 'ok', text: 'Every receiving device is the one recorded for the contact — its pinned keys match.' },
      { kind: 'ok', text: "This device's forward secrecy reads “Prekey rotation active” from the core." },
    ],
  },
  {
    id: 'attention',
    label: 'Needs attention',
    tone: 'amber',
    blurb: 'Something measurable is weaker than it should be — and the badge says exactly what.',
    evidence: [
      { kind: 'ok', text: 'The next message is sealed with hybrid X25519 + ML-KEM-1024 to the devices that can take it.' },
      { kind: 'warn', text: 'One contact device only speaks the earlier key combiner, so it is held to the weaker form.' },
      { kind: 'warn', text: 'A device with pre-FIPS 203 (Kyber) keys cannot receive at all — it is held back and named, not silently skipped.' },
      { kind: 'warn', text: 'A new device appeared for this contact. Nothing is sealed to it until you approve it.' },
    ],
  },
  {
    id: 'unknown',
    label: 'Not measured yet',
    tone: 'mute',
    blurb: 'No evidence is not good news. Until there is some, the badge will not vouch.',
    evidence: [
      { kind: 'unknown', text: 'No incoming message in this conversation yet, so the form the contact uses is unknown.' },
      { kind: 'unknown', text: 'History alone never vouches for the next message — only the current device lists do.' },
      { kind: 'ok', text: "This device's own rotation state is known." },
    ],
  },
];

const EV_ICON = { ok: Check, warn: AlertTriangle, unknown: CircleHelp } as const;
const EV_TONE: Record<Ev['kind'], string> = { ok: 'qm-t-green', warn: 'qm-t-amber', unknown: 'qm-t-mute' };
const EV_WORD: Record<Ev['kind'], string> = { ok: 'Verified', warn: 'Weaker', unknown: 'Unknown' };

export function ProtectionBadgeExplorer() {
  const [idx, setIdx] = useState(0);
  const state = BADGE_STATES[idx];
  const pick = (i: number) => setIdx(i);

  return (
    <StageFrame
      title="Conversation protection badge"
      icon={ShieldCheck}
      note={
        <>
          <span>Computed on your device from the same device lists and pin verdicts that decide delivery. The earlier combiner and pre-FIPS keys can never read as quantum-safe.</span>
        </>
      }
    >
      <div className="grid gap-5 md:grid-cols-[minmax(0,0.9fr)_minmax(0,1.3fr)]">
        <div>
          <div role="tablist" aria-label="Badge state" className="flex flex-wrap gap-2">
            {BADGE_STATES.map((s, i) => (
              <button key={s.id} role="tab" type="button" aria-selected={idx === i} className="qm-btn" onClick={() => pick(i)}>
                {s.label}
              </button>
            ))}
          </div>

          <div style={{ perspective: 900 }} className="mt-6">
            <AnimatePresence mode="wait">
              <motion.div
                key={state.id}
                initial={{ rotateX: -70, opacity: 0, y: 12 }}
                animate={{ rotateX: 0, opacity: 1, y: 0 }}
                exit={{ rotateX: 70, opacity: 0, y: -12 }}
                transition={{ duration: 0.38, ease: [0.22, 1, 0.36, 1] }}
                className="qm-glass"
                style={{ padding: 18, transformOrigin: '50% 100%' }}
              >
                <div className="flex items-center gap-3">
                  <span
                    className="flex h-12 w-12 items-center justify-center rounded-2xl"
                    style={{ background: 'rgba(2,6,23,.6)', border: '1px solid currentColor' }}
                  >
                    {state.id === 'safe' ? <ShieldCheck className="h-6 w-6 qm-t-green" aria-hidden /> : state.id === 'attention' ? <ShieldAlert className="h-6 w-6 qm-t-amber" aria-hidden /> : <CircleHelp className="h-6 w-6 qm-t-mute" aria-hidden />}
                  </span>
                  <div>
                    <Chip tone={state.tone}>{state.label}</Chip>
                    <div className="qm-t-mute mt-2" style={{ fontSize: 12, lineHeight: 1.5 }}>{state.blurb}</div>
                  </div>
                </div>
              </motion.div>
            </AnimatePresence>
          </div>
        </div>

        <div className="qm-glass" style={{ padding: 6 }} aria-live="polite">
          <div className="qm-mono qm-t-mute px-3 pb-1 pt-3" style={{ fontSize: 10, letterSpacing: '.18em' }}>EVIDENCE BEHIND THE BADGE</div>
          <AnimatePresence mode="wait">
            <motion.div key={state.id} initial="hidden" animate="show" exit={{ opacity: 0 }} variants={{ show: { transition: { staggerChildren: 0.07 } } }}>
              {state.evidence.map((e) => {
                const Icon = EV_ICON[e.kind];
                return (
                  <motion.div
                    key={e.text}
                    variants={{ hidden: { opacity: 0, x: 14 }, show: { opacity: 1, x: 0 } }}
                    className="flex items-start gap-3 px-3 py-2.5"
                    style={{ borderTop: '1px solid rgba(148,163,184,.12)' }}
                  >
                    <span className={`mt-0.5 flex shrink-0 items-center gap-1 ${EV_TONE[e.kind]}`} style={{ minWidth: 74 }}>
                      <Icon className="h-4 w-4" aria-hidden />
                      <span className="qm-mono" style={{ fontSize: 9.5, fontWeight: 800, letterSpacing: '.08em', textTransform: 'uppercase' }}>{EV_WORD[e.kind]}</span>
                    </span>
                    <span className="qm-t-ink" style={{ fontSize: 12.5, lineHeight: 1.5 }}>{e.text}</span>
                  </motion.div>
                );
              })}
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </StageFrame>
  );
}

/* ----------------------------------------------------------- ratchet lab ---- */

type Msg = { n: number; key: string; deleted: boolean; epoch: number };
const PQ_EVERY = 50;

function shortKey(n: number, salt: number) {
  const x = ((n + 7) * 2654435761 + salt * 40503) >>> 0;
  return x.toString(16).padStart(8, '0').slice(0, 6);
}

export function RatchetLab() {
  const [mode, setMode] = useState<'oneshot' | 'ratchet'>('ratchet');
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [count, setCount] = useState(0);
  const [turns, setTurns] = useState(0);
  const [sincePq, setSincePq] = useState(0);
  const [pqSteps, setPqSteps] = useState(0);
  const [flash, setFlash] = useState<string | null>(null);

  const reset = (m: 'oneshot' | 'ratchet') => {
    setMode(m);
    setMsgs([]);
    setCount(0);
    setTurns(0);
    setSincePq(0);
    setPqSteps(0);
    setFlash(null);
  };

  const send = (times: number) => {
    let c = count;
    let sp = sincePq;
    let pq = pqSteps;
    let hit = false;
    const added: Msg[] = [];
    for (let i = 0; i < times; i++) {
      c += 1;
      sp += 1;
      if (mode === 'ratchet' && sp >= PQ_EVERY) {
        sp = 0;
        pq += 1;
        hit = true;
      }
      added.push({ n: c, key: shortKey(c, mode === 'ratchet' ? turns : 0), deleted: mode === 'ratchet', epoch: 1 });
    }
    setCount(c);
    setSincePq(sp);
    setPqSteps(pq);
    setMsgs((prev) => [...prev, ...added].slice(-7));
    setFlash(hit ? 'ML-KEM-1024 step mixed into the root key' : null);
  };

  const reply = () => {
    setTurns((t) => t + 1);
    setFlash('Reply received — a fresh X25519 ratchet key is mixed in');
    setMsgs((prev) => prev.map((m) => ({ ...m, deleted: true })));
  };

  useEffect(() => {
    if (!flash) return;
    const id = window.setTimeout(() => setFlash(null), 2600);
    return () => window.clearTimeout(id);
  }, [flash]);

  const ratchet = mode === 'ratchet';
  return (
    <StageFrame
      title="Message keys: one-shot vs per-message ratchet"
      icon={RefreshCcw}
      note={
        <>
          <span>The ratchet is <b>opt-in</b> (Settings → Advanced), used only with contacts who also turned it on, and our own implementation — <b>not yet independently reviewed</b>.</span>
        </>
      }
    >
      <div className="flex flex-wrap items-center gap-2">
        <div role="tablist" aria-label="Key mode" className="flex flex-wrap gap-2">
          <button role="tab" type="button" aria-selected={!ratchet} className="qm-btn" onClick={() => reset('oneshot')}>One-shot (default)</button>
          <button role="tab" type="button" aria-selected={ratchet} className="qm-btn" onClick={() => reset('ratchet')}>Per-message ratchet</button>
        </div>
        {ratchet ? <Chip tone="amber">Opt-in · unreviewed</Chip> : <Chip tone="green">On by default</Chip>}
      </div>

      <div className="mt-5 grid gap-5 lg:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
        <div className="qm-glass" style={{ padding: 14, minHeight: 230 }}>
          <div className="qm-mono qm-t-mute" style={{ fontSize: 10, letterSpacing: '.18em' }}>
            {ratchet ? 'KEY CHAIN — EACH KEY IS DELETED ONCE USED' : 'EACH MESSAGE: FRESH HYBRID ENCAPSULATION TO THE SIGNED PREKEY'}
          </div>
          <div className="mt-3 flex min-h-[132px] flex-wrap items-center gap-2" style={{ perspective: 700 }}>
            <AnimatePresence initial={false}>
              {msgs.length === 0 && (
                <span key="empty" className="qm-t-mute" style={{ fontSize: 12 }}>Press “Send a message” to advance the {ratchet ? 'chain' : 'sealing'}.</span>
              )}
              {msgs.map((m) => (
                <motion.div
                  key={m.n}
                  layout
                  initial={{ opacity: 0, rotateY: -80, x: 30 }}
                  animate={{ opacity: m.deleted ? 0.5 : 1, rotateY: 0, x: 0 }}
                  exit={{ opacity: 0, scale: 0.8 }}
                  transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
                  className="qm-glass"
                  style={{ padding: '8px 10px', minWidth: 86, borderColor: m.deleted ? 'rgba(148,163,184,.2)' : 'rgba(34,211,238,.55)' }}
                >
                  <div className="qm-mono qm-t-mute" style={{ fontSize: 9 }}>MSG #{m.n}</div>
                  <div className="qm-mono qm-t-ink" style={{ fontSize: 12, fontWeight: 800, textDecoration: ratchet && m.deleted ? 'line-through' : 'none' }}>
                    {ratchet ? `K·${m.key}` : `ct·${m.key}`}
                  </div>
                  <div className="qm-mono" style={{ fontSize: 8.5, marginTop: 2, color: ratchet && m.deleted ? '#fb7185' : '#34d399' }}>
                    {ratchet ? (m.deleted ? 'CHAIN KEY ADVANCED' : 'KEY IN USE') : 'PREKEY EPOCH ≈ 24 h'}
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>

          <div className="mt-3 flex flex-wrap gap-2">
            <button type="button" className="qm-btn" data-primary="true" onClick={() => send(1)}>Send a message</button>
            {ratchet && (
              <>
                <button type="button" className="qm-btn" onClick={() => send(10)}>Send ×10</button>
                <button type="button" className="qm-btn" onClick={reply}>Contact replies</button>
              </>
            )}
            <button type="button" className="qm-btn" onClick={() => reset(mode)}>Reset</button>
          </div>
          <div aria-live="polite" style={{ minHeight: 20, marginTop: 8, fontSize: 12 }} className="qm-t-cyan">{flash}</div>
        </div>

        <div className="qm-glass" style={{ padding: 14 }}>
          {ratchet ? (
            <>
              <div className="flex items-baseline justify-between">
                <span className="qm-mono qm-t-mute" style={{ fontSize: 10, letterSpacing: '.16em' }}>NEXT ML-KEM-1024 STEP</span>
                <span className="qm-mono qm-t-ink" style={{ fontSize: 12 }}>{sincePq}/{PQ_EVERY}</span>
              </div>
              <div className="qm-bar mt-2"><i style={{ width: `${(sincePq / PQ_EVERY) * 100}%`, transition: 'width .4s ease' }} /></div>
              <div className="qm-t-mute mt-1" style={{ fontSize: 11 }}>A refresh offer can start after {PQ_EVERY} messages or 24 hours of session activity; completion requires a peer response.</div>
              <dl className="mt-4 grid grid-cols-3 gap-2 text-center">
                {[['Messages', count], ['X25519 turns', turns], ['PQ steps', pqSteps]].map(([k, v]) => (
                  <div key={String(k)} style={{ border: '1px solid rgba(148,163,184,.2)', borderRadius: 10, padding: '8px 4px' }}>
                    <dd className="qm-mono qm-t-ink" style={{ fontSize: 18, fontWeight: 800, margin: 0 }}>{v}</dd>
                    <dt className="qm-t-mute" style={{ fontSize: 9.5 }}>{k}</dt>
                  </div>
                ))}
              </dl>
              <div className="qm-t-mute mt-4" style={{ fontSize: 12, lineHeight: 1.55 }}>
                The session ratchet advances its keys as peers exchange messages. The encrypted ledger keeps keys for opened messages so history remains readable.
              </div>
            </>
          ) : (
            <>
              <div className="qm-mono qm-t-mute" style={{ fontSize: 10, letterSpacing: '.16em' }}>WHAT THIS MODE PROTECTS</div>
              <div className="qm-t-ink mt-3" style={{ fontSize: 12.5, lineHeight: 1.6 }}>
                Every default one-shot envelope uses its own hybrid X25519 + ML-KEM-1024 encapsulation. Forward secrecy reaches as far as the signed prekey: retired prekeys are destroyed once every message sealed to them has its key recorded — normally within about a day.
              </div>
              <div className="qm-t-mute mt-3" style={{ fontSize: 12, lineHeight: 1.55 }}>
                This is not a per-message ratchet, and we say so on purpose. It is why the ratchet exists as an opt-in.
              </div>
              <div className="mt-3 flex flex-wrap gap-2"><Chip tone="cyan">{count} sealed</Chip><Chip tone="mute">1 prekey epoch</Chip></div>
            </>
          )}
        </div>
      </div>
    </StageFrame>
  );
}

/* ---------------------------------------------------------- call phrase ----- */

const PHRASE_WORDS = (
  'abbey acorn agile alpine amber anchor anthem aroma arrow aspen atlas aurora bamboo banner beacon birch blossom bronze cabin cactus candle canyon cedar cobalt comet copper coral crater crystal dawn delta desert drift eagle ember falcon fennel fern fjord flint forest galaxy garnet glacier granite harbor hazel horizon indigo island jasper jungle kernel lantern laurel lemon lunar maple marble meadow meteor mosaic nebula nickel nimbus oasis olive onyx orbit orchid otter pebble pilot prism quartz raven reef ridge river sable saffron shadow silver summit tundra velvet willow zenith'
).split(' ');

function phraseFor(seed: number, window: number) {
  const out: string[] = [];
  let x = (seed * 2654435761 + window * 40503 + 12345) >>> 0;
  for (let i = 0; i < 4; i++) {
    x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
    out.push(PHRASE_WORDS[x % PHRASE_WORDS.length]);
  }
  return out;
}

const WINDOW_S = 30;

export function CallPhraseDemo() {
  const calm = useCalm();
  const [secs, setSecs] = useState(WINDOW_S);
  const [win, setWin] = useState(7);
  const [impostor, setImpostor] = useState(false);
  const [revealed, setRevealed] = useState(true);

  useEffect(() => {
    if (calm) return;
    const id = window.setInterval(() => {
      setSecs((s) => {
        if (s <= 1) {
          setWin((w) => w + 1);
          return WINDOW_S;
        }
        return s - 1;
      });
    }, 1000);
    return () => window.clearInterval(id);
  }, [calm]);

  const mine = useMemo(() => phraseFor(11, win), [win]);
  const theirs = useMemo(() => (impostor ? phraseFor(97, win) : mine), [impostor, mine, win]);
  const match = mine.every((w, i) => w === theirs[i]);
  const C = 2 * Math.PI * 34;

  return (
    <StageFrame
      title="Prove it's the device you verified"
      icon={Fingerprint}
      note={<span>Example words — real phrases come from the secret your two apps paired after you verified each other. The words are derived locally rather than sent as a protocol message. Compare them only for the current call. It proves a device, not a person, and says nothing about whether a voice is real.</span>}
    >
      <div className="grid items-center gap-5 md:grid-cols-[auto_minmax(0,1fr)]">
        <div className="mx-auto" style={{ width: 120, height: 120, position: 'relative' }}>
          <svg viewBox="0 0 80 80" width="120" height="120" role="img" aria-label={`${secs} seconds until the phrase changes`}>
            <circle cx="40" cy="40" r="34" fill="none" stroke="rgba(148,163,184,.2)" strokeWidth="5" />
            <circle
              cx="40" cy="40" r="34" fill="none" stroke="url(#qmring)" strokeWidth="5" strokeLinecap="round"
              strokeDasharray={C} strokeDashoffset={C * (1 - secs / WINDOW_S)} transform="rotate(-90 40 40)"
              style={{ transition: 'stroke-dashoffset 1s linear' }}
            />
            <defs><linearGradient id="qmring" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#22d3ee" /><stop offset="1" stopColor="#8b5cf6" /></linearGradient></defs>
          </svg>
          <div className="qm-mono qm-t-ink" style={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', fontSize: 22, fontWeight: 800 }}>{secs}s</div>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          {[
            { who: 'On your screen', words: mine, tone: 'cyan' as Tone },
            { who: impostor ? 'On the other device (not the one you verified)' : 'On their screen', words: theirs, tone: (match ? 'green' : 'rose') as Tone },
          ].map((card) => (
            <div key={card.who} className="qm-glass" style={{ padding: 12 }}>
              <div className="qm-t-mute" style={{ fontSize: 11 }}>{card.who}</div>
              <div className="mt-2 flex flex-wrap gap-1.5" style={{ perspective: 600 }}>
                <AnimatePresence mode="popLayout">
                  {card.words.map((w, i) => (
                    <motion.span
                      key={`${win}-${i}-${w}-${impostor}`}
                      initial={{ rotateX: -90, opacity: 0 }}
                      animate={{ rotateX: 0, opacity: revealed ? 1 : 0.08 }}
                      transition={{ duration: 0.4, delay: i * 0.06 }}
                      className="qm-mono"
                      style={{ fontSize: 14, fontWeight: 800, color: card.tone === 'rose' ? '#fb7185' : card.tone === 'green' ? '#34d399' : '#67e8f9', padding: '3px 8px', border: '1px solid currentColor', borderRadius: 8, background: 'rgba(2,6,23,.55)' }}
                    >
                      {w}
                    </motion.span>
                  ))}
                </AnimatePresence>
              </div>
            </div>
          ))}
          <div className="sm:col-span-2" aria-live="polite">
            {match ? (
              <Chip tone="green"><Check className="h-3 w-3" aria-hidden />Phrases match — this is the device you verified</Chip>
            ) : (
              <Chip tone="rose"><AlertTriangle className="h-3 w-3" aria-hidden />Mismatch — do not trust this call</Chip>
            )}
          </div>
        </div>
      </div>
      <div className="mt-4 flex flex-wrap gap-2">
        <button type="button" className="qm-btn" aria-pressed={impostor} onClick={() => setImpostor((v) => !v)}>
          {impostor ? 'Back to the verified device' : 'Simulate a different device'}
        </button>
        <button type="button" className="qm-btn" aria-pressed={!revealed} onClick={() => setRevealed((v) => !v)}>
          {revealed ? 'Hide words' : 'Show words'}
        </button>
        {calm && <button type="button" className="qm-btn" onClick={() => setWin((w) => w + 1)}>Next 30 s window</button>}
      </div>
    </StageFrame>
  );
}

/* ----------------------------------------------------------- group call ----- */

export function MeshCallScene() {
  const [share, setShare] = useState(false);
  const nodes = [
    { id: 'you', label: 'You', x: 150, y: 44 },
    { id: 'b', label: 'Member B', x: 58, y: 190 },
    { id: 'c', label: 'Member C', x: 242, y: 190 },
  ];
  const links: Array<[number, number]> = [[0, 1], [0, 2], [1, 2]];
  return (
    <StageFrame
      title="Group video call — a mesh of 1:1 links"
      icon={Users}
      note={<span>Up to 3 people. Each pair has its own hybrid X25519 + ML-KEM-1024 key and frame key — there is no shared group call key. Screen sharing is on desktop, video only (no computer sound).</span>}
    >
      <div className="grid items-center gap-4 md:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
        <svg viewBox="0 0 300 240" className="mx-auto w-full max-w-[380px]" role="img" aria-label="Three people, each connected to the other two by their own encrypted link">
          <defs>
            <linearGradient id="qmlink" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#22d3ee" /><stop offset="1" stopColor="#8b5cf6" /></linearGradient>
          </defs>
          {links.map(([a, b], i) => (
            <g key={i}>
              <line x1={nodes[a].x} y1={nodes[a].y} x2={nodes[b].x} y2={nodes[b].y} stroke="url(#qmlink)" strokeWidth="2" className="qm-flowline" style={{ animationDelay: `${i * 0.3}s` }} />
              <text x={(nodes[a].x + nodes[b].x) / 2} y={(nodes[a].y + nodes[b].y) / 2 - 6} textAnchor="middle" fontSize="8" fill="#9fb0c8" fontFamily="ui-monospace,monospace">link {i + 1} · own key</text>
            </g>
          ))}
          {nodes.map((n, i) => (
            <g key={n.id}>
              <circle cx={n.x} cy={n.y} r="34" fill="#0b1424" stroke={i === 0 ? '#22d3ee' : '#8b5cf6'} strokeWidth="2" />
              <circle cx={n.x} cy={n.y} r="40" fill="none" stroke={i === 0 ? '#22d3ee' : '#8b5cf6'} strokeOpacity=".25" className="qm-flowline" data-slow="true" />
              <text x={n.x} y={n.y + 4} textAnchor="middle" fontSize="10" fontWeight="700" fill="#e6edf7">{n.label}</text>
            </g>
          ))}
          {share && (
            <motion.g initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }} style={{ transformOrigin: '150px 40px' }}>
              <rect x="112" y="-2" width="76" height="26" rx="5" fill="#0b1424" stroke="#d4af37" />
              <text x="150" y="15" textAnchor="middle" fontSize="8.5" fill="#d4af37" fontFamily="ui-monospace,monospace">SCREEN → frame key</text>
            </motion.g>
          )}
        </svg>
        <div className="space-y-3">
          <div className="qm-glass" style={{ padding: 12 }}>
            <div className="qm-mono qm-t-mute" style={{ fontSize: 10, letterSpacing: '.16em' }}>LINKS FOR N PEOPLE = N(N−1)/2</div>
            <div className="mt-2 flex gap-2">
              {[2, 3].map((n) => (
                <Chip key={n} tone={n === 3 ? 'cyan' : 'mute'}>{n} people · {(n * (n - 1)) / 2} link{n === 2 ? '' : 's'}</Chip>
              ))}
            </div>
          </div>
          <button type="button" className="qm-btn" aria-pressed={share} onClick={() => setShare((v) => !v)}>
            <MonitorUp className="h-4 w-4" aria-hidden />{share ? 'Stop sharing screen' : 'Share your screen (desktop)'}
          </button>
          <div className="qm-t-mute" style={{ fontSize: 12, lineHeight: 1.55 }}>
            Joining asks once; the other links then connect by themselves. A link is auto-accepted only inside a group call you accepted.
          </div>
        </div>
      </div>
    </StageFrame>
  );
}

/* -------------------------------------------------------------- channels ---- */

type Reader = { id: string; name: string; epochs: number[]; active: boolean };

export function ChannelEpochScene() {
  const initial = (): Reader[] => [
    { id: 'r1', name: 'Reader 1', epochs: [1], active: true },
    { id: 'r2', name: 'Reader 2', epochs: [1], active: true },
    { id: 'r3', name: 'Reader 3', epochs: [1], active: true },
  ];
  const [readers, setReaders] = useState<Reader[]>(initial);
  const [epoch, setEpoch] = useState(1);
  const [posts, setPosts] = useState<number[]>([1, 1, 1]);
  const [nextId, setNextId] = useState(4);

  const post = () => setPosts((p) => [...p, epoch].slice(-8));
  const removeOne = () => {
    const target = [...readers].reverse().find((r) => r.active);
    if (!target) return;
    const e = epoch + 1;
    setEpoch(e);
    setReaders((rs) => rs.map((r) => (r.id === target.id ? { ...r, active: false } : r.active ? { ...r, epochs: [...r.epochs, e] } : r)));
  };
  const invite = () => {
    setReaders((rs) => [...rs, { id: `r${nextId}`, name: `Reader ${nextId}`, epochs: [epoch], active: true }].slice(-6));
    setNextId((n) => n + 1);
  };
  const reset = () => {
    setReaders(initial());
    setEpoch(1);
    setPosts([1, 1, 1]);
    setNextId(4);
  };

  return (
    <StageFrame
      title="Channels — epoch keys and who can read what"
      icon={Radio}
      note={<span>You post, readers read; readers cannot see each other. A new key epoch starts whenever someone leaves. Forward secrecy is per epoch, not per post, and new readers get only the current epoch.</span>}
    >
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" className="qm-btn" data-primary="true" onClick={post}>Publish a post</button>
        <button type="button" className="qm-btn" onClick={removeOne} disabled={readers.filter((r) => r.active).length <= 1}>Remove a reader</button>
        <button type="button" className="qm-btn" onClick={invite}>Invite a reader (code)</button>
        <button type="button" className="qm-btn" onClick={reset}>Reset</button>
        <Chip tone="gold"><KeyRound className="h-3 w-3" aria-hidden />Current epoch {epoch}</Chip>
      </div>

      <div className="mt-4 overflow-x-auto">
        <div className="qm-glass" style={{ padding: 12, minWidth: 420 }}>
          <div className="flex items-center gap-2" style={{ paddingLeft: 118 }}>
            {posts.map((e, i) => (
              <motion.div key={`${i}-${e}`} initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="qm-mono qm-t-mute text-center" style={{ width: 34, fontSize: 9 }}>
                <div className="qm-t-ink">#{i + 1}</div>
                <div>E{e}</div>
              </motion.div>
            ))}
          </div>
          {readers.map((r) => (
            <div key={r.id} className="mt-2 flex items-center gap-2" style={{ opacity: r.active ? 1 : 0.6 }}>
              <div style={{ width: 110 }}>
                <div className="qm-t-ink" style={{ fontSize: 11.5, fontWeight: 700 }}>{r.name}</div>
                <div className="qm-mono qm-t-mute" style={{ fontSize: 9 }}>{r.active ? `holds E${r.epochs.join(', E')}` : `left — held E${r.epochs.join(', E')}`}</div>
              </div>
              {posts.map((e, i) => {
                const can = r.epochs.includes(e);
                return (
                  <motion.span
                    key={`${r.id}-${i}`}
                    layout
                    className="flex items-center justify-center"
                    style={{ width: 34, height: 26, borderRadius: 7, border: '1px solid', borderColor: can ? 'rgba(52,211,153,.6)' : 'rgba(251,113,133,.45)', background: can ? 'rgba(52,211,153,.12)' : 'rgba(251,113,133,.08)' }}
                    title={can ? 'Can read this post' : 'Cannot read this post'}
                  >
                    {can ? <Check className="h-3.5 w-3.5 qm-t-green" aria-label="can read" /> : <Lock className="h-3.5 w-3.5 qm-t-rose" aria-label="cannot read" />}
                  </motion.span>
                );
              })}
            </div>
          ))}
        </div>
      </div>
      <div className="qm-t-mute mt-3" style={{ fontSize: 12 }}>
        A reader who left keeps whatever they already received, but the next epoch’s key is never sent to them.
      </div>
    </StageFrame>
  );
}

/* ------------------------------------------------------ social recovery ----- */

const HELPERS = ['Helper 1', 'Helper 2', 'Helper 3', 'Helper 4', 'Helper 5'];
const K = 3;

export function ShamirRecovery() {
  const [ok, setOk] = useState<number[]>([]);
  const [pin, setPin] = useState(false);
  const toggle = (i: number) => setOk((s) => (s.includes(i) ? s.filter((x) => x !== i) : [...s, i]));
  const enough = ok.length >= K;
  const restored = enough && pin;

  const pos = (i: number) => ({ x: 380, y: 32 + i * 44 });

  return (
    <StageFrame
      title="Social recovery — e.g. 3 of 5 helpers, plus your PIN"
      icon={KeyRound}
      note={<span>k helpers without the PIN learn nothing; fewer than k helpers learn nothing. Helpers release their part only after comparing four words with you by phone or in person. Colluding helpers plus the relay could try to guess a weak PIN offline — use a passphrase.</span>}
    >
      <div className="grid items-center gap-4 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
        <svg viewBox="0 0 440 240" className="w-full" role="img" aria-label="Recovery key on the left, five helpers on the right">
          <rect x="14" y="76" width="88" height="88" rx="16" fill="#0b1424" stroke={restored ? '#34d399' : '#8b5cf6'} strokeWidth="2" />
          <text x="58" y="112" textAnchor="middle" fontSize="9" fill="#9fb0c8" fontFamily="ui-monospace,monospace">RECOVERY KEY</text>
          <motion.text key={String(restored)} initial={{ scale: 0.4, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} x="58" y="146" textAnchor="middle" fontSize="26" style={{ transformOrigin: '58px 140px' }}>
            {restored ? '🔓' : '🔒'}
          </motion.text>
          {HELPERS.map((h, i) => {
            const p = pos(i);
            const on = ok.includes(i);
            return (
              <g key={h}>
                <line x1="102" y1="120" x2={p.x - 98} y2={p.y} stroke={on ? '#22d3ee' : 'rgba(148,163,184,.25)'} strokeWidth="1.6" className={on ? 'qm-flowline' : undefined} />
                <g onClick={() => toggle(i)} style={{ cursor: 'pointer' }} role="button" tabIndex={0} aria-pressed={on} aria-label={`${h}: ${on ? 'approved' : 'not approved'}`} onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), toggle(i))}>
                  <rect x={p.x - 98} y={p.y - 17} width="116" height="34" rx="10" fill={on ? 'rgba(34,211,238,.16)' : '#0b1424'} stroke={on ? '#22d3ee' : 'rgba(148,163,184,.4)'} />
                  <text x={p.x - 40} y={p.y + 4} textAnchor="middle" fontSize="10.5" fontWeight="700" fill="#e6edf7">{on ? '✓ ' : ''}{h}</text>
                </g>
              </g>
            );
          })}
        </svg>
        <div className="space-y-3">
          <div className="qm-glass" style={{ padding: 12 }}>
            <div className="flex items-baseline justify-between"><span className="qm-mono qm-t-mute" style={{ fontSize: 10, letterSpacing: '.16em' }}>SHARES RELEASED</span><span className="qm-mono qm-t-ink">{ok.length}/{K}</span></div>
            <div className="qm-bar mt-2"><i style={{ width: `${Math.min(100, (ok.length / K) * 100)}%`, transition: 'width .35s ease' }} /></div>
          </div>
          <button type="button" className="qm-btn" aria-pressed={pin} onClick={() => setPin((v) => !v)}><Lock className="h-4 w-4" aria-hidden />{pin ? 'PIN entered' : 'Enter your PIN'}</button>
          <div aria-live="polite">
            {restored ? <Chip tone="green"><Check className="h-3 w-3" aria-hidden />Recovery key restored on the new device</Chip>
              : enough ? <Chip tone="amber"><AlertTriangle className="h-3 w-3" aria-hidden />Enough shares — but shares alone are not enough</Chip>
              : <Chip tone="mute"><Lock className="h-3 w-3" aria-hidden />Locked — {K - ok.length} more helper{K - ok.length === 1 ? '' : 's'} needed</Chip>}
          </div>
          <div className="qm-t-mute" style={{ fontSize: 12 }}>Click helpers to simulate each one approving after the four-word check.</div>
          <button type="button" className="qm-btn" onClick={() => { setOk([]); setPin(false); }}>Reset</button>
        </div>
      </div>
    </StageFrame>
  );
}

/* ----------------------------------------------------------- resilience ----- */

const FLOW = [
  { t: 'Relay reachable', d: 'The message is sealed on your device and goes straight to the relay.', chip: 'Sent', tone: 'green' as Tone, at: [300, 70] },
  { t: 'Relay not answering', d: 'A banner says why — offline, service failing, or unreachable though your internet works — from real checks, never a guess. The sealed message waits in an encrypted outbox: “Waiting to send”.', chip: 'Waiting to send', tone: 'amber' as Tone, at: [70, 70] },
  { t: 'Nearby delivery (Android, opt-in)', d: 'The sealed row can hop to a QGuard phone in Bluetooth/Wi-Fi range through Google Play services. Still end-to-end encrypted; they learn that something was sent and its size, never the content.', chip: 'Hand-off nearby', tone: 'violet' as Tone, at: [185, 175] },
  { t: 'Relay is back', d: 'The outbox flushes by itself. Disappearing messages that expired in the meantime are dropped, never sent.', chip: 'Delivered', tone: 'green' as Tone, at: [300, 70] },
];

export function ResilienceFlow() {
  const [auto, setAuto] = useState(true);
  const [step, setStep] = useTicker(FLOW.length, 4200, auto);
  const s = FLOW[step];
  return (
    <StageFrame
      title="When the relay can't be reached"
      icon={Wifi}
      note={<span>Probes contact only the relay’s own health endpoint and, on desktop, the existing update server. On Android there is no second host, so the banner says when it cannot tell an outage from a blocked network.</span>}
    >
      <div className="grid items-center gap-4 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
        <svg viewBox="0 0 380 230" className="w-full" role="img" aria-label={`Step ${step + 1}: ${s.t}`}>
          {[{ x: 70, y: 70, l: 'Your device' }, { x: 300, y: 70, l: 'Relay' }, { x: 185, y: 175, l: 'Phone nearby' }].map((n) => (
            <g key={n.l}>
              <rect x={n.x - 46} y={n.y - 24} width="92" height="48" rx="12" fill="#0b1424" stroke="rgba(148,163,184,.45)" />
              <text x={n.x} y={n.y + 4} textAnchor="middle" fontSize="11" fontWeight="700" fill="#e6edf7">{n.l}</text>
            </g>
          ))}
          <line x1="116" y1="70" x2="254" y2="70" stroke={step === 1 ? '#fb7185' : '#22d3ee'} strokeWidth="2" strokeDasharray={step === 1 ? '3 6' : undefined} className={step === 0 || step === 3 ? 'qm-flowline' : undefined} />
          {step === 1 && <text x="185" y="60" textAnchor="middle" fontSize="16" fill="#fb7185">✕</text>}
          <line x1="94" y1="92" x2="165" y2="152" stroke="#8b5cf6" strokeOpacity={step === 2 ? 1 : 0.25} strokeWidth="2" className={step === 2 ? 'qm-flowline' : undefined} />
          <line x1="205" y1="152" x2="276" y2="92" stroke="#8b5cf6" strokeOpacity={step === 2 ? 1 : 0.25} strokeWidth="2" className={step === 2 ? 'qm-flowline' : undefined} />
          <motion.g animate={{ x: step === 1 ? 70 : step === 2 ? 185 : 300, y: step === 2 ? 128 : 70 }} transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }} initial={false}>
            <circle r="12" fill="#04101c" stroke={step === 1 ? '#fbbf24' : '#22d3ee'} strokeWidth="2" cx="0" cy="-30" />
            <text y="-26" textAnchor="middle" fontSize="11">🔒</text>
          </motion.g>
        </svg>
        <div>
          <div className="flex flex-wrap gap-2" role="tablist" aria-label="Delivery steps">
            {FLOW.map((f, i) => (
              <button key={f.t} role="tab" type="button" aria-selected={step === i} className="qm-btn" onClick={() => { setAuto(false); setStep(i); }}>{i + 1}</button>
            ))}
            <button type="button" className="qm-btn" aria-pressed={auto} onClick={() => setAuto((v) => !v)}>{auto ? 'Pause' : 'Auto-play'}</button>
          </div>
          <AnimatePresence mode="wait">
            <motion.div key={step} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.25 }} className="mt-3" aria-live="polite">
              <Chip tone={s.tone}>{s.chip}</Chip>
              <div className="qm-t-ink mt-2" style={{ fontSize: 14, fontWeight: 700 }}>{s.t}</div>
              <div className="qm-t-mute mt-1" style={{ fontSize: 12.5, lineHeight: 1.6 }}>{s.d}</div>
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </StageFrame>
  );
}

/* ---------------------------------------------------------- AI assistant ---- */

const NEVER_SENT = ['Disappearing messages', 'One-time messages', 'Scheduled messages', 'Undecrypted messages', 'Attachments'];

export function AiBoundary() {
  const [allowed, setAllowed] = useState(false);
  const [fired, setFired] = useState(0);
  const [blocked, setBlocked] = useState(false);

  const ask = () => {
    if (!allowed) {
      setBlocked(true);
      window.setTimeout(() => setBlocked(false), 2200);
      return;
    }
    setFired((n) => n + 1);
  };

  return (
    <StageFrame
      title="AI assistant — the one place text leaves end-to-end encryption"
      icon={Sparkles}
      note={<span>Off by default. You allow it per conversation, bring your own key (Anthropic Claude Sonnet 5.5, or OpenAI with a model id you enter), and it runs only when you press a button. Suggested replies go to your composer — never sent for you. Answers can be wrong.</span>}
    >
      <div className="grid items-stretch gap-3 md:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)]">
        <div className="qm-glass" style={{ padding: 14, borderColor: 'rgba(52,211,153,.4)' }}>
          <Chip tone="green"><Lock className="h-3 w-3" aria-hidden />End-to-end encrypted zone</Chip>
          <div className="qm-t-ink mt-2" style={{ fontSize: 13, fontWeight: 700 }}>Your device</div>
          <div className="qm-t-mute" style={{ fontSize: 12, lineHeight: 1.55 }}>Your key is stored encrypted on this device. The conversation is framed as untrusted data, so a message cannot make the app act — though one written to manipulate it can still skew a summary.</div>
          <div className="mt-3 flex flex-wrap gap-2">
            <button type="button" className="qm-btn" role="switch" aria-checked={allowed} aria-pressed={allowed} onClick={() => setAllowed((v) => !v)}>
              {allowed ? 'Allowed in this chat' : 'Not allowed in this chat'}
            </button>
            <button type="button" className="qm-btn" data-primary="true" onClick={ask}>Catch me up</button>
          </div>
          <div aria-live="polite" style={{ minHeight: 18 }} className="qm-t-amber mt-2"><span style={{ fontSize: 12 }}>{blocked ? 'Blocked — allow this conversation first.' : ''}</span></div>
        </div>

        <div className="relative hidden w-24 items-center justify-center md:flex" aria-hidden>
          <div style={{ position: 'absolute', top: 0, bottom: 0, width: 0, borderLeft: '2px dashed rgba(251,191,36,.7)' }} />
          <span className="qm-mono qm-t-amber relative px-1 text-center" style={{ fontSize: 9, fontWeight: 800, letterSpacing: '.12em', background: '#080e1b' }}>LEAVES E2EE</span>
          <AnimatePresence>
            {fired > 0 && (
              <motion.span key={fired} initial={{ x: -44, opacity: 0 }} animate={{ x: 44, opacity: [0, 1, 1, 0] }} transition={{ duration: 1.4 }} className="qm-chip absolute" data-tone="amber" style={{ top: '60%' }}>text</motion.span>
            )}
          </AnimatePresence>
        </div>

        <div className="qm-glass" style={{ padding: 14, borderColor: 'rgba(251,191,36,.45)' }}>
          <Chip tone="amber"><AlertTriangle className="h-3 w-3" aria-hidden />Your chosen provider</Chip>
          <div className="qm-t-ink mt-2" style={{ fontSize: 13, fontWeight: 700 }}>Anthropic or OpenAI, with your key</div>
          <div className="qm-t-mute" style={{ fontSize: 12, lineHeight: 1.55 }}>What you ask it to read is sent to them under their terms. The others in the conversation are not told.</div>
          <div className="qm-mono qm-t-mute mt-3" style={{ fontSize: 9.5, letterSpacing: '.14em' }}>NEVER SENT</div>
          <div className="mt-1.5 flex flex-wrap gap-1.5">{NEVER_SENT.map((n) => <Chip key={n} tone="mute">{n}</Chip>)}</div>
          <div className="qm-t-mute mt-3" style={{ fontSize: 11.5 }}>Requests made in this demo: <b className="qm-t-ink">0 real</b> — it only draws the boundary.</div>
        </div>
      </div>
    </StageFrame>
  );
}

/* ------------------------------------------------------------ lock stack ---- */

const LAYERS: Array<{ icon: typeof Lock; title: string; tag: string; body: string; tone: string }> = [
  { icon: Eraser, title: 'Erase this device', tag: 'All platforms', tone: '#fb7185', body: 'Settings → Erase this device (type ERASE). The device storage key is destroyed first, then every key file; the device is revoked on the relay (best effort) and you are signed out. Ciphertext on the relay stays unreadable without keys.' },
  { icon: ShieldAlert, title: 'Duress PIN', tag: 'Android', tone: '#f59e0b', body: 'Entered at the lock screen, it silently erases this device’s keys and shows the sign-in screen as if the session had expired. Never revealed on the lock screen; cannot equal your real PIN. Protects against being forced to unlock — not against imaging made earlier.' },
  { icon: Lock, title: 'Workspace locks', tag: 'All platforms', tone: '#8b5cf6', body: 'Secure Chat and Quantum Vault each have their own password or PIN (Argon2id → HKDF-SHA3-256 in the Rust core) and lock when you step away. A lock record that no longer opens is reported as such and goes to a re-authenticated reset — never treated as “no lock set”.' },
  { icon: Fingerprint, title: 'App lock + biometrics', tag: 'Android', tone: '#22d3ee', body: 'The key is wrapped by an Android Keystore key usable only through a strong-biometric prompt; a new fingerprint enrolment turns it off. Calls still ring while locked, without exposing history.' },
  { icon: ShieldCheck, title: 'Hidden in Recent apps', tag: 'Android', tone: '#34d399', body: 'On by default. Android 13+ shows a blank card in Recents; older versions draw a cover view. Screenshots stay allowed by product decision.' },
];

export function LockStack() {
  const [open, setOpen] = useState(true);
  const [sel, setSel] = useState(0);
  const L = LAYERS[sel];
  return (
    <StageFrame
      title="Device privacy — layers between a stranger and your keys"
      icon={Lock}
      note={<span>Duress and erase act on this device only: other devices keep their copies, and on some hardware the platform keychain could retain material until overwritten. Biometrics trust whoever the device owner enrolled.</span>}
    >
      <div className="grid items-center gap-5 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
        <div>
          <ExplodedStack layers={LAYERS} sel={sel} onSelect={setSel} explode={open ? 1 : 0.1} />
          <button type="button" className="qm-btn" aria-pressed={open} onClick={() => setOpen((v) => !v)}>{open ? 'Collapse layers' : 'Explode layers'}</button>
        </div>
        <div>
          <div className="flex flex-wrap gap-2" role="tablist" aria-label="Privacy layers">
            {LAYERS.map((l, i) => (
              <button key={l.title} role="tab" type="button" className="qm-btn" aria-selected={sel === i} onClick={() => setSel(i)}>
                <l.icon className="h-3.5 w-3.5" style={{ color: l.tone }} aria-hidden />{i + 1}. {l.title}
              </button>
            ))}
          </div>
          <div className="qm-glass mt-4" style={{ padding: 16 }} aria-live="polite">
            <AnimatePresence mode="wait">
              <motion.div key={sel} initial={{ opacity: 0, x: 12 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.22 }}>
                <div className="flex flex-wrap items-center gap-2">
                  <L.icon className="h-5 w-5" style={{ color: L.tone }} aria-hidden />
                  <span className="qm-t-ink" style={{ fontSize: 15, fontWeight: 800 }}>{L.title}</span>
                  <Chip tone={L.tag === 'Android' ? 'violet' : 'cyan'}>{L.tag}</Chip>
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
