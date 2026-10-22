/**
 * Hero 3D scenes for the three QGuard Messaging pages.
 * Pure CSS-3D + motion: no WebGL context (CyberBackground already owns one on
 * this route, and browsers cap live contexts). All content is illustrative.
 */
import React, { useEffect, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { CloudOff, FileLock2, Folder, Lock, ShieldCheck, Smartphone } from 'lucide-react';
import { Chip, FitBox, Tilt3D, useCalm, useTicker } from './_motion';

type Vars = React.CSSProperties & Record<`--${string}`, string | number>;

/** A flat 1100 px floor grid laid under the scene at depth `y`. */
function Floor({ y = 150 }: { y?: number }) {
  return (
    <div className="qm-obj" style={{ transform: `translate3d(-550px, ${y - 550}px, 0) rotateX(90deg)` }}>
      <div className="qm-floor" />
    </div>
  );
}

/** Ciphertext-looking filler. Decorative — it is not any real message's bytes. */
const GLYPHS = '0123456789abcdef';
function scramble(len: number, seed: number) {
  let s = '';
  let x = seed * 9301 + 49297;
  for (let i = 0; i < len; i++) {
    x = (x * 9301 + 49297) % 233280;
    s += GLYPHS[x % 16];
    if (i % 4 === 3 && i < len - 1) s += '·';
  }
  return s;
}

/** Shows ciphertext for a beat, then the plaintext — "decrypts on this device". */
function Decrypting({ text, seed }: { text: string; seed: number }) {
  const calm = useCalm();
  const [plain, setPlain] = useState(calm);
  useEffect(() => {
    if (calm) return;
    const id = window.setTimeout(() => setPlain(true), 750);
    return () => window.clearTimeout(id);
  }, [calm]);
  return plain ? <span>{text}</span> : <span className="qm-mono qm-t-cyan">{scramble(Math.min(22, text.length), seed)}</span>;
}

/* ------------------------------------------------------------ overview ----- */

function MiniDevice({ side, title }: { side: 'a' | 'b'; title: string }) {
  const out = side === 'a';
  return (
    <div className="qm-device" style={{ width: 150, height: 250 }}>
      <div style={{ padding: '14px 10px 8px', display: 'flex', alignItems: 'center', gap: 8, borderBottom: '1px solid rgba(148,163,184,.15)' }}>
        <span style={{ width: 22, height: 22, borderRadius: 999, background: out ? 'linear-gradient(135deg,#22d3ee,#6366f1)' : 'linear-gradient(135deg,#d4af37,#f59e0b)' }} />
        <span className="qm-t-ink" style={{ fontSize: 11, fontWeight: 700 }}>{title}</span>
        <Lock className="ml-auto h-3 w-3 qm-t-green" aria-hidden />
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, padding: 10 }}>
        <div className="qm-bubble" data-side={out ? 'out' : 'in'}>{out ? 'Keys rotated.' : 'Confirmed.'}</div>
        <div className="qm-bubble" data-side={out ? 'in' : 'out'}>{out ? 'Seen on my side.' : 'Sending the vault key.'}</div>
        <div className="qm-bubble" data-side={out ? 'out' : 'in'}>
          <span className="qm-mono" style={{ fontSize: 9, opacity: 0.9 }}>sealed · opened here only</span>
        </div>
      </div>
      <div style={{ position: 'absolute', left: 10, right: 10, bottom: 10, height: 26, borderRadius: 999, border: '1px solid rgba(148,163,184,.25)', display: 'flex', alignItems: 'center', padding: '0 10px', gap: 6 }}>
        <span className="qm-t-mute" style={{ fontSize: 10 }}>Encrypted message</span>
        <ShieldCheck className="ml-auto h-3.5 w-3.5 qm-t-cyan" aria-hidden />
      </div>
    </div>
  );
}

function Packet({ x0, x1, y, z = 24, delay, dur = 3.4, label }: { x0: number; x1: number; y: number; z?: number; delay: number; dur?: number; label: string }) {
  const v: Vars = { '--qm-x1': `${x1 - x0}px`, '--qm-y1': '0px', '--qm-dur': `${dur}s`, '--qm-delay': `${delay}s` };
  return (
    <div className="qm-obj" style={{ transform: `translate3d(${x0}px, ${y}px, ${z}px)` }}>
      <div className="qm-packet" style={v}>
        <Chip tone="cyan" style={{ fontSize: 8.5, padding: '2px 7px' }}>{label}</Chip>
      </div>
    </div>
  );
}

/** Overview hero: two devices, a relay that only ever sees ciphertext. */
export function HeroLinkScene() {
  return (
    <FitBox baseW={620} baseH={400}>
      <Tilt3D style={{ width: 620, height: 400 }}>
        <div className="qm-obj" style={{ left: 310, top: 190, transform: 'rotateX(12deg) rotateY(-10deg)' }}>
          <Floor y={165} />

          {/* devices */}
          <div className="qm-obj" style={{ transform: 'translate3d(-225px, -4px, 30px) rotateY(26deg) translate(-50%, -50%)' }}>
            <div className="qm-bob" style={{ '--qm-delay': '0s' } as Vars}>
              <MiniDevice side="a" title="This device" />
            </div>
          </div>
          <div className="qm-obj" style={{ transform: 'translate3d(225px, -4px, 30px) rotateY(-26deg) translate(-50%, -50%)' }}>
            <div className="qm-bob" style={{ '--qm-delay': '-2s' } as Vars}>
              <MiniDevice side="b" title="Contact" />
            </div>
          </div>

          {/* relay */}
          <div className="qm-obj" style={{ transform: 'translate3d(0, -4px, 0)' }}>
            <div className="qm-ring" data-tone="gold" style={{ width: 230, height: 230, '--qm-tilt': '74deg' } as Vars} />
            <div className="qm-ring" data-tone="violet" style={{ width: 300, height: 300, '--qm-tilt': '62deg', animationDuration: '22s', animationDirection: 'reverse' } as Vars} />
            <div className="qm-obj" style={{ transform: 'translate(-50%, -50%)' }}>
              <div className="qm-bob-slow">
                <div className="qm-cube" style={{ '--qm-s': '96px' } as Vars}>
                  {[0, 1, 2, 3, 4, 5].map((i) => (
                    <div key={i} className="qm-face">
                      {i < 2 ? <ShieldCheck className="h-7 w-7 qm-t-cyan" aria-hidden /> : <span className="qm-mono qm-t-cyan" style={{ fontSize: 9, letterSpacing: '.1em' }}>CIPHERTEXT</span>}
                    </div>
                  ))}
                  <div className="qm-core" />
                </div>
              </div>
            </div>
          </div>

          {/* rails + packets */}
          <div className="qm-rail" style={{ left: -150, top: -5, width: 100, transform: 'translateZ(24px)' }} />
          <div className="qm-rail" style={{ left: 50, top: -5, width: 100, transform: 'translateZ(24px)' }} />
          <Packet x0={-155} x1={-30} y={-14} delay={0} label="ML-KEM ct" />
          <Packet x0={30} x1={150} y={-14} delay={1.6} label="sealed" />
          <Packet x0={150} x1={30} y={6} delay={0.8} dur={4} label="ack" />

          {/* floating spec chips */}
          <div className="qm-obj" style={{ transform: 'translate3d(-96px, -168px, 90px)' }}>
            <div className="qm-bob" style={{ '--qm-delay': '-1s' } as Vars}><Chip tone="cyan">ML-KEM-1024 · FIPS 203</Chip></div>
          </div>
          <div className="qm-obj" style={{ transform: 'translate3d(70px, -150px, 70px)' }}>
            <div className="qm-bob" style={{ '--qm-delay': '-3s' } as Vars}><Chip tone="violet">ML-DSA + Ed25519</Chip></div>
          </div>
          <div className="qm-obj" style={{ transform: 'translate3d(-60px, 128px, 100px)' }}>
            <div className="qm-bob" style={{ '--qm-delay': '-2s' } as Vars}><Chip tone="gold">Relay cannot read content</Chip></div>
          </div>
          <div className="qm-obj" style={{ transform: 'translate3d(130px, 118px, 60px)' }}>
            <div className="qm-bob" style={{ '--qm-delay': '-4s' } as Vars}><Chip tone="green">AES-256-GCM</Chip></div>
          </div>
        </div>
      </Tilt3D>
    </FitBox>
  );
}

/* --------------------------------------------------------- secure chat ----- */

const CHAT = [
  { side: 'in' as const, text: 'Rotation window confirmed for 21:00.' },
  { side: 'out' as const, text: 'Good. Verifying the new device now.' },
  { side: 'in' as const, text: 'Safety number matches on my screen.' },
  { side: 'out' as const, text: 'Marked verified. Calling in a minute.' },
];

function GlassNote({ children, tone = 'cyan' }: { children: React.ReactNode; tone?: 'cyan' | 'violet' | 'gold' | 'green' }) {
  const border = { cyan: 'rgba(34,211,238,.45)', violet: 'rgba(167,139,250,.5)', gold: 'rgba(212,175,55,.5)', green: 'rgba(52,211,153,.5)' }[tone];
  return (
    <div className="qm-glass" style={{ width: 150, padding: '9px 11px', borderColor: border }}>
      {children}
    </div>
  );
}

/** Secure Chat hero: a phone with sealed messages and the layers protecting them. */
export function HeroChatScene() {
  const [step] = useTicker(CHAT.length + 2, 1900);
  const shown = Math.min(step + 1, CHAT.length);

  return (
    <FitBox baseW={620} baseH={470}>
      <Tilt3D style={{ width: 620, height: 470 }}>
        <div className="qm-obj" style={{ left: 310, top: 232, transform: 'rotateX(8deg) rotateY(-9deg)' }}>
          <Floor y={205} />

          {/* phone */}
          <div className="qm-obj" style={{ transform: 'translate3d(0, 0, 20px) rotateY(-6deg) translate(-50%, -50%)' }}>
            <div className="qm-bob-slow">
              <div className="qm-device" style={{ width: 218, height: 396 }}>
                <div style={{ padding: '16px 12px 10px', display: 'flex', alignItems: 'center', gap: 8, borderBottom: '1px solid rgba(148,163,184,.15)' }}>
                  <span style={{ width: 28, height: 28, borderRadius: 999, background: 'linear-gradient(135deg,#22d3ee,#8b5cf6)' }} />
                  <div style={{ minWidth: 0 }}>
                    <div className="qm-t-ink" style={{ fontSize: 12, fontWeight: 700, whiteSpace: 'nowrap' }}>Platform Security</div>
                    <div style={{ marginTop: 3 }}><Chip tone="green" style={{ fontSize: 8, padding: '1px 6px' }}><ShieldCheck className="h-2.5 w-2.5" aria-hidden />Quantum-safe</Chip></div>
                  </div>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, padding: 12, height: 272, overflow: 'hidden' }}>
                  <AnimatePresence initial={false}>
                    {CHAT.slice(0, shown).map((m, i) => (
                      <motion.div
                        key={`${i}-${m.text}`}
                        layout
                        initial={{ opacity: 0, y: 14, scale: 0.94 }}
                        animate={{ opacity: 1, y: 0, scale: 1 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
                        className="qm-bubble"
                        data-side={m.side}
                      >
                        <Decrypting text={m.text} seed={i + 3} />
                      </motion.div>
                    ))}
                  </AnimatePresence>
                </div>
                <div style={{ position: 'absolute', left: 12, right: 12, bottom: 14, height: 32, borderRadius: 999, border: '1px solid rgba(148,163,184,.25)', display: 'flex', alignItems: 'center', padding: '0 12px', gap: 6 }}>
                  <Lock className="h-3 w-3 qm-t-green" aria-hidden />
                  <span className="qm-t-mute" style={{ fontSize: 10.5 }}>Message, end-to-end</span>
                </div>
              </div>
            </div>
          </div>

          {/* orbiting layers */}
          <div className="qm-obj" style={{ transform: 'translate3d(-212px, -128px, 90px) translate(-50%, -50%)' }}>
            <div className="qm-bob" style={{ '--qm-delay': '-1s' } as Vars}>
              <GlassNote tone="green">
                <div className="qm-mono qm-t-green" style={{ fontSize: 9, letterSpacing: '.14em' }}>PROTECTION</div>
                <div className="qm-t-ink" style={{ fontSize: 11.5, fontWeight: 700, marginTop: 3 }}>Evidence, not a label</div>
                <div className="qm-t-mute" style={{ fontSize: 10, marginTop: 2 }}>Hybrid keys · pinned devices · rotation</div>
              </GlassNote>
            </div>
          </div>
          <div className="qm-obj" style={{ transform: 'translate3d(218px, -92px, 110px) translate(-50%, -50%)' }}>
            <div className="qm-bob" style={{ '--qm-delay': '-3s' } as Vars}>
              <GlassNote tone="violet">
                <div className="qm-mono qm-t-violet" style={{ fontSize: 9, letterSpacing: '.14em' }}>DUAL SIGNATURE</div>
                <div className="qm-t-ink" style={{ fontSize: 11.5, fontWeight: 700, marginTop: 3 }}>Ed25519 + ML-DSA-65</div>
                <div className="qm-t-mute" style={{ fontSize: 10, marginTop: 2 }}>Both must verify</div>
              </GlassNote>
            </div>
          </div>
          <div className="qm-obj" style={{ transform: 'translate3d(-216px, 98px, 70px) translate(-50%, -50%)' }}>
            <div className="qm-bob" style={{ '--qm-delay': '-2s' } as Vars}>
              <GlassNote tone="gold">
                <div className="qm-mono qm-t-gold" style={{ fontSize: 9, letterSpacing: '.14em' }}>CALL PHRASE</div>
                <div className="qm-t-ink qm-mono" style={{ fontSize: 12, fontWeight: 800, marginTop: 3 }}>amber · cedar · lunar · pilot</div>
                <div className="qm-t-mute" style={{ fontSize: 10, marginTop: 2 }}>Example — 4 words, 30 s</div>
              </GlassNote>
            </div>
          </div>
          <div className="qm-obj" style={{ transform: 'translate3d(220px, 122px, 90px) translate(-50%, -50%)' }}>
            <div className="qm-bob" style={{ '--qm-delay': '-4s' } as Vars}>
              <GlassNote tone="cyan">
                <div className="qm-mono qm-t-cyan" style={{ fontSize: 9, letterSpacing: '.14em' }}>SESSION RATCHET · OPT-IN</div>
                <div style={{ display: 'flex', gap: 4, marginTop: 6 }}>
                  {[0, 1, 2, 3, 4].map((i) => (
                    <span key={i} style={{ height: 8, flex: 1, borderRadius: 3, background: i < 3 ? 'rgba(148,163,184,.3)' : 'linear-gradient(90deg,#22d3ee,#8b5cf6)' }} />
                  ))}
                </div>
                <div className="qm-t-mute" style={{ fontSize: 10, marginTop: 5 }}>One key per message</div>
              </GlassNote>
            </div>
          </div>

          <div className="qm-obj" style={{ transform: 'translate3d(0, -196px, 60px) translate(-50%, -50%)' }}>
            <div className="qm-bob" style={{ '--qm-delay': '-2.4s' } as Vars}>
              <Chip tone="cyan"><Smartphone className="h-3 w-3" aria-hidden />Opens on your device only</Chip>
            </div>
          </div>
        </div>
      </Tilt3D>
    </FitBox>
  );
}

/* ----------------------------------------------------------- quantum vault -- */

function Ingest({ x, y, z, delay, children }: { x: number; y: number; z: number; delay: number; children: React.ReactNode }) {
  const v: Vars = { '--qm-x0': `${x}px`, '--qm-y0': `${y}px`, '--qm-z0': `${z}px`, '--qm-delay': `${delay}s` };
  return (
    <div className="qm-obj" style={{ transform: 'translate(-50%, -50%)' }}>
      <div className="qm-ingest" style={v}>{children}</div>
    </div>
  );
}

function FileChip({ icon: Icon, name }: { icon: typeof Folder; name: string }) {
  return (
    <div className="qm-glass" style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 10px', whiteSpace: 'nowrap' }}>
      <Icon className="h-3.5 w-3.5 qm-t-cyan" aria-hidden />
      <span className="qm-mono qm-t-ink" style={{ fontSize: 10.5 }}>{name}</span>
    </div>
  );
}

/** Vault hero: files fly into a spinning vault and leave as sealed .qvault tokens. Nothing leaves the device. */
export function HeroVaultScene() {
  return (
    <FitBox baseW={620} baseH={410}>
      <Tilt3D style={{ width: 620, height: 410 }}>
        <div className="qm-obj" style={{ left: 310, top: 195, transform: 'rotateX(14deg) rotateY(-12deg)' }}>
          <Floor y={165} />

          {/* on-device boundary drawn on the floor */}
          <div className="qm-obj" style={{ transform: 'translate3d(-250px, 118px, 0) rotateX(90deg)' }}>
            <div style={{ width: 500, height: 330, borderRadius: '50%', border: '1.5px dashed rgba(52,211,153,.55)', boxShadow: '0 0 40px rgba(52,211,153,.12) inset' }} />
          </div>
          <div className="qm-obj" style={{ transform: 'translate3d(-96px, 154px, 120px)' }}>
            <Chip tone="green"><Lock className="h-3 w-3" aria-hidden />This device — nothing uploaded</Chip>
          </div>

          {/* vault */}
          <div className="qm-obj" style={{ transform: 'translate3d(0, -20px, 0)' }}>
            <div className="qm-ring" style={{ width: 250, height: 250, '--qm-tilt': '76deg' } as Vars} />
            <div className="qm-ring" data-tone="gold" style={{ width: 320, height: 320, '--qm-tilt': '66deg', animationDuration: '20s', animationDirection: 'reverse' } as Vars} />
            <div className="qm-ring" data-tone="violet" style={{ width: 390, height: 390, '--qm-tilt': '80deg', animationDuration: '30s' } as Vars} />
            <div className="qm-obj" style={{ transform: 'translate(-50%, -50%)' }}>
              <div className="qm-bob-slow">
                <div className="qm-cube" style={{ '--qm-s': '132px', '--qm-spin': '30s' } as Vars}>
                  {[0, 1, 2, 3, 4, 5].map((i) => (
                    <div key={i} className="qm-face">
                      {i % 2 === 0 ? <Lock className="h-9 w-9 qm-t-cyan" aria-hidden /> : <span className="qm-mono qm-t-gold" style={{ fontSize: 10, letterSpacing: '.14em' }}>.QVAULT</span>}
                    </div>
                  ))}
                  <div className="qm-core" />
                </div>
              </div>
            </div>
          </div>

          {/* files in */}
          <Ingest x={-250} y={-120} z={60} delay={0}><FileChip icon={FileLock2} name="board-deck.pptx" /></Ingest>
          <Ingest x={-260} y={50} z={40} delay={2}><FileChip icon={Folder} name="contracts/ (folder)" /></Ingest>
          <Ingest x={-210} y={-20} z={90} delay={4}><FileChip icon={FileLock2} name="signing-keys.kdbx" /></Ingest>

          {/* sealed out */}
          <div className="qm-obj" style={{ transform: 'translate(-50%, -50%)' }}>
            <div className="qm-emit" style={{ '--qm-x1': '250px', '--qm-y1': '70px', '--qm-z1': '70px', '--qm-delay': '0s' } as Vars}>
              <Chip tone="gold">sealed.qvault ✓</Chip>
            </div>
          </div>
          <div className="qm-obj" style={{ transform: 'translate(-50%, -50%)' }}>
            <div className="qm-emit" style={{ '--qm-x1': '240px', '--qm-y1': '10px', '--qm-z1': '90px', '--qm-delay': '2s' } as Vars}>
              <Chip tone="gold">sealed.qvault ✓</Chip>
            </div>
          </div>

          {/* spec chips */}
          <div className="qm-obj" style={{ transform: 'translate3d(-120px, -178px, 90px)' }}>
            <div className="qm-bob" style={{ '--qm-delay': '-1s' } as Vars}><Chip tone="cyan">AES-256-GCM per file</Chip></div>
          </div>
          <div className="qm-obj" style={{ transform: 'translate3d(60px, -168px, 80px)' }}>
            <div className="qm-bob" style={{ '--qm-delay': '-3s' } as Vars}><Chip tone="violet">PIN-bound vault key</Chip></div>
          </div>
          <div className="qm-obj" style={{ transform: 'translate3d(170px, -76px, 100px)' }}>
            <div className="qm-bob" style={{ '--qm-delay': '-2s' } as Vars}><Chip tone="gold">ML-DSA-87 + Ed25519</Chip></div>
          </div>
          <div className="qm-obj" style={{ transform: 'translate3d(190px, 118px, 40px)' }}>
            <div className="qm-bob" style={{ '--qm-delay': '-4s' } as Vars}><Chip tone="mute"><CloudOff className="h-3 w-3" aria-hidden />No upload</Chip></div>
          </div>
        </div>
      </Tilt3D>
    </FitBox>
  );
}
