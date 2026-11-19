import type { CSSProperties, ReactNode } from 'react';
import { gsap } from 'gsap';
import { AbsoluteFill, Html5Audio, Img, OffthreadVideo, Sequence, staticFile, useCurrentFrame, useVideoConfig } from 'remotion';
import { chapters, shots } from './film-plan';
import { Spatial } from './Spatial';
import { EditorialGraphics } from './EditorialGraphics';
import subtitles from './subtitles.json';
import './enterprise.css';

type Shot = (typeof shots)[number];
type Cue = { start: number; end: number; text: string };
type FilmProps = { includeAudio: boolean };
const run = 180;
const ease = gsap.parseEase('power3.out');
const smooth = gsap.parseEase('sine.inOut');
const limit = (value: number) => Math.max(0, Math.min(value, 1));
const rise = (time: number, start = .1, duration = .84) => ease(limit((time - start) / duration));
const asset = (name: string) => staticFile(name);
const evidence = {
  platform: 'Qguard Helix · Public overview screen recording',
  assessment: 'QRAE · Application interface · Offline view',
  plan: 'Migration Planner · Application interface · Offline view',
  sandbox: 'Migration Sandbox · Application interface · Offline view',
  runtime: 'Runtime Cryptographic Intelligence · Application interface · Offline view',
};

function useClock() {
  const frame = useCurrentFrame();
  const { width, height, fps, durationInFrames } = useVideoConfig();
  return { frame, width, height, fps, time: frame / fps, progress: frame / Math.max(1, durationInFrames - 1) };
}

function Animate({ children, at = .13, lift = 19 }: { children: ReactNode; at?: number; lift?: number }) {
  const { time } = useClock();
  const progress = rise(time, at);
  return <div style={{ opacity: progress, translate: '0 ' + (1 - progress) * lift + 'px' }}>{children}</div>;
}

function Title({ shot }: { shot: Shot }) {
  const { time } = useClock();
  return <div className="lead">
    <Animate><div className="kicker"><b />{shot.label}</div></Animate>
    <h1>
      {shot.title.map((line, lineIndex) => <span key={line} className="title-line">
        {line.split(' ').map((word, wordIndex) => {
          const progress = rise(time, .16 + .16 * lineIndex + .047 * wordIndex, .86);
          return <span key={wordIndex} className="word" style={{
            opacity: progress, translate: '0 ' + (1 - progress) * 60 + 'px',
          }}>{word}</span>;
        })}
      </span>)}
    </h1>
    {shot.copy && <Animate at={.55}><p className="lede">{shot.copy}</p></Animate>}
  </div>;
}

function List({ values }: { values: string[] }) {
  return <ul className="feature-lines">
    {values.map((item, index) => <li key={item}><Animate at={.68 + .12 * index} lift={15}><span>{item}</span></Animate></li>)}
  </ul>;
}

function Photo({ name, mode }: { name: string; mode: 'still' | 'video' }) {
  const { progress } = useClock();
  const camera = smooth(limit(progress));
  const style: CSSProperties = {
    height: '100%', width: '100%', objectFit: 'cover', scale: 1.015 + camera * .066,
    translate: -17 * camera + 'px 0',
  };
  return <AbsoluteFill className={'plate ' + mode}>
    {mode === 'video'
      ? <OffthreadVideo src={asset('plates/' + name)} muted style={style} />
      : <Img src={asset('plates/' + name)} style={style} />}
  </AbsoluteFill>;
}

function ImageStage({ file }: { file: string }) {
  const { progress, time } = useClock();
  const enter = rise(time, .10, 1.25);
  return <div className="image-stage" style={{
    opacity: enter, translate: (1 - enter) * 45 + 'px 0', scale: 1 + smooth(progress) * .065,
  }}>
    <Img src={asset('plates/' + file)} />
    <div className="image-mask" />
  </div>;
}

function ProductScreen({ name }: { name: NonNullable<Shot['screen']> }) {
  const { progress, time } = useClock();
  const enter = rise(time, .09, 1.33);
  const drift = smooth(limit(progress));
  return <div className="product-frame" style={{
    opacity: enter, translate: (1 - enter) * 65 + 'px ' + (1 - enter) * 22 + 'px',
    transform: 'perspective(1950px) rotateY(' + (-9 + 5 * drift) + 'deg) rotateX(' + (4 - 2 * drift) + 'deg)',
  }}>
    <div className="screen-edge">
      {name === 'platform'
        ? <OffthreadVideo src={asset('ui/platform.mp4')} muted />
        : <Img src={asset('ui/' + name + '.jpg')} />}
    </div>
    <div className="screen-caption">{evidence[name]}</div>
  </div>;
}

const suite = ['Discover', 'Assess', 'Plan', 'Migrate', 'Validate', 'Monitor', 'Govern'];
const cards = [
  { id: 'ML-KEM', role: 'Key encapsulation', reference: 'NIST FIPS 203' },
  { id: 'ML-DSA', role: 'Lattice-based signatures', reference: 'NIST FIPS 204' },
  { id: 'SLH-DSA', role: 'Hash-based signatures', reference: 'NIST FIPS 205' },
];

function Standards() {
  return <div className="standards">
    {cards.map((card, index) => <Animate key={card.id} at={.39 + .15 * index}>
      <div className="standard-card"><strong>{card.id}</strong><span>{card.role}</span><small>{card.reference}</small></div>
    </Animate>)}
    <Animate at={1.08}><div className="standard-note">Algorithm standards and lab coverage</div></Animate>
    <Animate at={1.22}><div className="standard-note support-note">AES-256-GCM · SHA-256 / SHA-3 · HKDF-SHA-256</div></Animate>
  </div>;
}

function SuiteField({ governance }: { governance: boolean }) {
  const { time } = useClock();
  const elements = governance ? ['Policies', 'Controls', 'Evidence', 'Exceptions', 'Reports'] : suite;
  return <div className="suite-field">
    <div className="suite-ring suite-ring--outer" style={{ rotate: time * 9 + 'deg' }} />
    <div className="suite-ring suite-ring--inner" style={{ rotate: -time * 6 + 'deg' }} />
    <div className={'suite-core' + (governance ? ' suite-core--audit' : '')}>
      {governance ? 'Audit' : <>Q<span>H</span></>}
    </div>
    {elements.map((item, index) => {
      const angle = index / elements.length * Math.PI * 2 - Math.PI * .5;
      return <div className="suite-anchor" key={item} style={{
        left: (50 + Math.cos(angle) * 39) + '%', top: (50 + Math.sin(angle) * 40) + '%',
      }}><Animate at={.48 + .1 * index}><span>{item}</span></Animate></div>;
    })}
  </div>;
}

function Columns({ groups }: { groups: NonNullable<Shot['columns']> }) {
  return <div className="groups">
    {groups.map((group, index) => <Animate key={group.name} at={.4 + .24 * index}>
      <div className="group">
        <strong>{group.name}</strong>
        <ul>{group.items.map(item => <li key={item}>{item}</li>)}</ul>
      </div>
    </Animate>)}
  </div>;
}

function Visual({ shot }: { shot: Shot }) {
  const { width, height, fps, frame, time, progress } = useClock();
  const visual = shot.visual;
  if (shot.screen) return <ProductScreen name={shot.screen} />;
  if (shot.columns) return <Columns groups={shot.columns} />;
  if (shot.image) return <ImageStage file={shot.image} />;
  if (visual === 'earth') return <>
    <Photo name="earth.jpg" mode="still" />
    <div className="orbital-line" style={{ rotate: -22 + progress * 10 + 'deg', opacity: rise(time, .65, 1.7) }} />
    <div className="photo-veil" />
  </>;
  if (visual === 'lab') return <><Photo name="lab.mp4" mode="video" /><div className="photo-veil" /></>;
  if (visual === 'standard') return <Standards />;
  if (visual === 'suite') return <SuiteField governance={shot.chapter === 8} />;
  if (visual === 'network' || visual === 'processor') {
    return <Spatial variant={visual} width={width} height={height} fps={fps} frame={frame} centerX={.73} centerY={.485} />;
  }
  if (visual === 'exposure' || visual === 'migration' || visual === 'agility') {
    return <div className="editorial-visual">
      <EditorialGraphics variant={visual} />
    </div>;
  }
  return null;
}

function Finale({ shot }: { shot: Shot }) {
  const { width, height, fps, time, frame } = useClock();
  const logo = rise(time, 7.8, 1.8);
  const hold = 1 - rise(time, 7.6, .78);
  return <AbsoluteFill className="end-scene">
    <Spatial variant="finale" width={width} height={height} fps={fps} frame={frame} centerY={.445} />
    <div className="end-mark" style={{ opacity: logo }}>
      <div className="official-logo" style={{ scale: .8 + .2 * logo }}>
        <Img src={asset('brand/qguard-helix.png')} />
      </div>
      <p className="end-tagline" style={{ opacity: rise(time, 8.75, .84) }}>Securing the present. Preparing the quantum future.</p>
      <div className="end-action" style={{ opacity: rise(time, 12.3, .75) }}><span>Explore Qguard Helix</span><b />Request a demo</div>
    </div>
    <div className="end-question" style={{ opacity: hold }}><Title shot={shot} /></div>
  </AbsoluteFill>;
}

function ShotStage({ shot, index }: { shot: Shot; index: number }) {
  const { time } = useClock();
  const transition = 1 - rise(time, 0, index ? .42 : 1.2);
  return <AbsoluteFill className={['scene', shot.theme ?? 'ice', 'v-' + (shot.visual ?? (shot.screen ? 'product' : 'art'))].join(' ')}>
    {shot.visual === 'finale' ? <Finale shot={shot} /> : <>
      <div className="studio-gradient" />
      <div className="studio-grid" />
      <Visual shot={shot} />
      <div className="scene-copy">
        <Title shot={shot} />
        {shot.tags && !(shot.visual === 'suite' && shot.chapter === 2) && <List values={shot.tags} />}
      </div>
      <div className="chapter"><span />{chapters[shot.chapter][1]}</div>
    </>}
    <AbsoluteFill className="optical-transition" style={{ opacity: transition * (index ? .84 : 1) }} />
  </AbsoluteFill>;
}

function Captions() {
  const { time } = useClock();
  const active = (subtitles.landscape as Cue[]).find(cue => cue.start <= time && time < cue.end);
  return active ? <div className="caption"><span>{active.text}</span></div> : null;
}

export function EnterpriseFilm({ includeAudio }: FilmProps) {
  const { fps } = useVideoConfig();
  return <AbsoluteFill className="enterprise-film">
    <style>{`@font-face{font-family:Geist;src:url("${asset('fonts/geist-latin-wght-normal.woff2')}") format("woff2");font-weight:100 900;font-display:block;}`}</style>
    {includeAudio && <Html5Audio src={asset('audio/enterprise.wav')} />}
    {shots.map((shot, index) => <Sequence key={shot.at} from={Math.round(shot.at * fps)}
      durationInFrames={Math.round(((shots[index + 1]?.at ?? run) - shot.at) * fps)} name={shot.label}>
      <ShotStage shot={shot} index={index} />
    </Sequence>)}
    <Captions />
  </AbsoluteFill>;
}
