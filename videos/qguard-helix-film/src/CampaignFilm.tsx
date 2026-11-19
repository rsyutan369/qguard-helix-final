import type { CSSProperties, ReactNode } from 'react';
import { gsap } from 'gsap';
import { AbsoluteFill, Freeze, Html5Audio, Img, Loop, OffthreadVideo, Sequence, staticFile, useCurrentFrame, useVideoConfig } from 'remotion';
import { QuantumCore } from './Core';
import subtitles from './subtitles.json';
import './film.css';

type Format = 'landscape' | 'portrait';
type FilmProps = { portrait: boolean; withAudio: boolean };
type Cue = { start: number; end: number; text: string };
type Device = { file: string; label: string; desktop?: boolean };

const landscape = [0, 15, 30, 43, 59, 75, 91, 105, 120];
const portrait = [0, 5, 10, 15, 20, 25, 30, 36, 45];
const ease = gsap.parseEase('power3.out');
const settle = gsap.parseEase('sine.inOut');
const clamp = (v: number) => Math.max(0, Math.min(1, v));
const tween = (time: number, begin: number, end: number) => ease(clamp((time - begin) / (end - begin)));
const plate = (name: string) => staticFile('plates/' + name);

const brandDevices: Device[] = [
  { file: 'desktop.png', label: 'Desktop sign-in', desktop: true },
  { file: 'chats.png', label: 'Chats' },
];
const features: Record<number, { title: string[]; detail: string; device: Device; atmosphere: string }[]> = {
  3: [
    { title: ['Private messages.'], detail: 'Post-quantum protection for direct messages.', device: { file: 'chats.mp4', label: 'Chats' }, atmosphere: 'violet' },
    { title: ['Secure voice', 'and video.'], detail: 'Encrypted calls on supported devices.', device: { file: 'call.png', label: 'Voice call' }, atmosphere: 'cyan' },
  ],
  4: [
    { title: ['Quantum Vault.'], detail: 'Encrypted storage for personal files.', device: { file: 'vault.mp4', label: 'Quantum Vault' }, atmosphere: 'cyan' },
    { title: ['Hidden Vault.'], detail: 'Separate, concealed storage on your device.', device: { file: 'hidden.png', label: 'Hidden Vault' }, atmosphere: 'violet' },
  ],
  5: [
    { title: ['Offgrid Mesh.'], detail: 'Communicate over supported nearby connections.', device: { file: 'mesh.png', label: 'Mesh radar' }, atmosphere: 'cyan' },
    { title: ['XFER.'], detail: 'Transfer files between compatible nearby devices.', device: { file: 'xfer.png', label: 'XFER' }, atmosphere: 'violet' },
  ],
};
const primitives = [
  ['ML-KEM', 'Post-quantum key encapsulation', 'FIPS 203'],
  ['ML-DSA', 'Post-quantum digital signatures', 'FIPS 204'],
  ['AES-256-GCM', 'Authenticated encryption', ''],
];

function useShot() {
  const frame = useCurrentFrame();
  const { fps, durationInFrames } = useVideoConfig();
  return { frame, fps, t: frame / fps, duration: durationInFrames / fps };
}

function FadeIn({ children, start = .1, style }: { children: ReactNode; start?: number; style?: CSSProperties }) {
  const { t } = useShot();
  const progress = tween(t, start, start + .9);
  return <div style={{ opacity: progress, translate: '0 ' + (1 - progress) * 25 + 'px', ...style }}>{children}</div>;
}

function Plate({ name, length, offset = 0, bright = 1, position = 'center' }: {
  name: string; length?: number; offset?: number; bright?: number; position?: string;
}) {
  const { fps, t } = useShot();
  const zoom = 1.035 + Math.min(t, 12) * .0045;
  const style: CSSProperties = { width: '100%', height: '100%', objectFit: 'cover', objectPosition: position, scale: zoom };
  return <AbsoluteFill style={{ overflow: 'hidden', opacity: bright }}>
    {length ? <Loop durationInFrames={Math.round(length * fps)}>
      <OffthreadVideo src={plate(name)} muted trimBefore={Math.round(offset * fps)} style={style} />
    </Loop> : <Img src={plate(name)} style={style} />}
  </AbsoluteFill>;
}

function Veil({ mode = 'side' }: { mode?: 'side' | 'threat' | 'center' }) {
  return <AbsoluteFill className={'veil veil--' + mode} />;
}

function Title({ label, lines, detail }: { label?: string; lines: string[]; detail?: string }) {
  return <div className="title-block">
    {label && <div className="eyebrow"><i />{label}</div>}
    <h1>{lines.map((line, index) => <span className={index === lines.length - 1 && lines.length > 1 ? 'soft' : ''} key={line}>{line}</span>)}</h1>
    {detail && <p>{detail}</p>}
  </div>;
}

function Intro({ isPortrait }: { isPortrait: boolean }) {
  const { t, duration, fps } = useShot();
  const labStart = isPortrait ? duration : 8.4;
  const transition = Math.round(labStart * fps);
  return <AbsoluteFill>
    <Plate name="earth.jpg" position={isPortrait ? '68% center' : 'center'} />
    <div className="earth-orbits" style={{ opacity: .55 * tween(t, 1.1, 3.6), rotate: (-24 + t * .36) + 'deg' }} />
    {!isPortrait && <Sequence from={transition} layout="none">
      <AbsoluteFill style={{ opacity: tween(t, labStart, labStart + .6) }}>
        <Plate name="lab.mp4" length={9.8} bright={.87} />
      </AbsoluteFill>
    </Sequence>}
    <Veil />
    <div className="intro-copy">
      <FadeIn start={.35}>
        <Title label="The quantum transition" lines={['A new era', 'is approaching.']} />
      </FadeIn>
    </div>
  </AbsoluteFill>;
}

function Threat() {
  const { t, duration } = useShot();
  const phase = settle(clamp(t / duration));
  return <AbsoluteFill className="threat">
    <Plate name="lab.mp4" offset={1.4} length={8.45} bright={.83} position="57% center" />
    <Veil mode="threat" />
    <div className="threat-copy">
      <FadeIn><Title label="The risk to public-key cryptography" lines={['Harvest now.', 'Decrypt later.']} detail="Encrypted data collected today could be vulnerable in the future." /></FadeIn>
    </div>
    <div className="threat-types" style={{ opacity: tween(t, .4, 1.3), scale: 1 + .026 * phase }}>
      <span>RSA</span><b /><span>ECC</span>
    </div>
  </AbsoluteFill>;
}

function Screen({ device, className = '', tilt = 0 }: { device: Device; className?: string; tilt?: number }) {
  const { frame, t, duration } = useShot();
  const entry = tween(t, 0, .82);
  const glide = settle(clamp(t / duration));
  return <div className={'device ' + (device.desktop ? 'device--desktop ' : '') + className} style={{
    opacity: entry, translate: '0 ' + (23 * (1 - entry) - 10 * glide) + 'px',
    rotate: (tilt * (1 - .35 * glide)) + 'deg', scale: .98 + glide * .035,
  }}>
    <div className="device-screen">
      {device.file.endsWith('.mp4')
        ? <Freeze frame={Math.min(frame, 95)}><OffthreadVideo muted src={staticFile('product/' + device.file)} /></Freeze>
        : <Img src={staticFile('product/' + device.file)} />}
    </div>
  </div>;
}

function ProductReveal() {
  return <AbsoluteFill className="product product--reveal">
    <Plate name="vault.mp4" length={5} bright={.36} position="68% center" />
    <Veil />
    <div className="product-copy">
      <FadeIn><Title label="Introducing" lines={['QGUARD HELIX']} detail="Messaging designed for the post-quantum era." /></FadeIn>
    </div>
    <div className="brand-devices">
      <Screen device={brandDevices[0]} className="desktop" tilt={-7} />
      <Screen device={brandDevices[1]} className="phone" tilt={7} />
    </div>
    <span className="source-label">Application UI · Demo data</span>
  </AbsoluteFill>;
}

function FeatureShot({ item, index }: { item: (typeof features)[number][number]; index: number }) {
  return <AbsoluteFill className={'product product--feature tint-' + item.atmosphere + ' feature-' + index}>
    <AbsoluteFill className="product-glow" />
    <Plate name="vault.mp4" length={5} bright={.28} position="74% center" />
    <div className="optical-ring" />
    <div className="product-copy">
      <FadeIn><Title lines={item.title} detail={item.detail} /></FadeIn>
    </div>
    <div className="feature-device"><Screen device={item.device} tilt={index % 2 ? -5 : 5} /></div>
    <span className="source-label">Application UI · Demo data</span>
  </AbsoluteFill>;
}

function Feature({ index }: { index: number }) {
  const { fps, duration } = useShot();
  const split = Math.round(duration * .5 * fps);
  return <AbsoluteFill>
    {features[index].map((item, i) => <Sequence key={item.device.label} from={i * split}
      durationInFrames={i === 0 ? split : Math.round(duration * fps) - split}>
      <FeatureShot item={item} index={i} />
    </Sequence>)}
  </AbsoluteFill>;
}

function Crypto() {
  const { t } = useShot();
  return <AbsoluteFill className="crypto">
    <Plate name="vault.mp4" length={5} bright={.49} position="68% center" />
    <Veil />
    <div className="crypto-copy">
      <FadeIn><Title label="Cryptographic foundation" lines={['Built for', 'the transition.']} /></FadeIn>
    </div>
    <div className="crypto-stack">
      {primitives.map(([name, purpose, standard], index) =>
        <FadeIn key={name} start={.4 + index * .33} style={{ opacity: tween(t, .35 + index * .32, 1.15 + index * .32) }}>
          <div className="crypto-row"><strong>{name}</strong><span>{purpose}</span>{standard && <small>{standard}</small>}</div>
        </FadeIn>)}
    </div>
  </AbsoluteFill>;
}

function Finale({ isPortrait }: { isPortrait: boolean }) {
  const { t, fps, frame } = useShot();
  const { width, height } = useVideoConfig();
  const appearAt = isPortrait ? 5.08 : 8.05;
  const expose = tween(t, appearAt, appearAt + 1.3);
  const travel = settle(clamp((t - appearAt) / 2.15));
  return <AbsoluteFill className="finale">
    <QuantumCore width={width} height={height} frame={frame} fps={fps} centerY={isPortrait ? .40 : .46} />
    <div className="final-eclipse" style={{ opacity: expose }} />
    <div className="final-lock" style={{ opacity: expose, scale: .89 + .11 * travel }}>
      <div className="logo-window">
        <Img src={staticFile('brand/qguard-helix.png')} />
      </div>
      <div className="brand-tagline" style={{ opacity: tween(t, appearAt + .45, appearAt + 1.4) }}>Securing your communications.<br className="portrait-only" /> Preparing for the quantum future.</div>
      <div className="cta" style={{ opacity: tween(t, appearAt + 1.25, appearAt + 2.05) }}>Discover QGUARD HELIX <span>↗</span></div>
    </div>
    <div className="final-question" style={{ opacity: 1 - tween(t, appearAt - .4, appearAt + .4) }}>
      <FadeIn start={.16}><Title lines={['The world is preparing for quantum.', 'Are your communications?']} /></FadeIn>
    </div>
  </AbsoluteFill>;
}

function Scene({ index, isPortrait }: { index: number; isPortrait: boolean }) {
  const { t } = useShot();
  const scene = [<Intro isPortrait={isPortrait} />, <Threat />, <ProductReveal />, <Feature index={3} />,
    <Feature index={4} />, <Feature index={5} />, <Crypto />, <Finale isPortrait={isPortrait} />][index];
  return <AbsoluteFill>
    {scene}
    <AbsoluteFill className="cut-fade" style={{ opacity: (index === 0 ? 1 : .88) * (1 - tween(t, 0, index === 0 ? 1.25 : .42)) }} />
  </AbsoluteFill>;
}

function Subtitles({ format }: { format: Format }) {
  const { t } = useShot();
  const active = (subtitles[format] as Cue[]).find((cue) => cue.start <= t && t < cue.end);
  return active ? <div className="caption"><span>{active.text}</span></div> : null;
}

export function CampaignFilm({ portrait: isPortrait, withAudio }: FilmProps) {
  const { fps } = useVideoConfig();
  const layout = isPortrait ? portrait : landscape;
  const format = isPortrait ? 'portrait' : 'landscape';
  return <AbsoluteFill className={'film ' + format}>
    <style>{`@font-face{font-family:Geist;src:url("${staticFile('fonts/geist-latin-wght-normal.woff2')}") format("woff2");font-weight:100 900;font-display:block;}`}</style>
    {withAudio && <Html5Audio src={staticFile('audio/' + format + '.wav')} />}
    {layout.slice(0, -1).map((start, index) => <Sequence key={start} from={start * fps}
      durationInFrames={(layout[index + 1] - start) * fps} name={['The quantum transition', 'Harvest now, decrypt later',
        'QGUARD HELIX', 'Messaging and calls', 'Quantum and Hidden Vault', 'Offgrid Mesh and XFER', 'Cryptographic foundation', 'Final reveal'][index]}>
      <Scene index={index} isPortrait={isPortrait} />
    </Sequence>)}
    <Subtitles format={format} />
  </AbsoluteFill>;
}
