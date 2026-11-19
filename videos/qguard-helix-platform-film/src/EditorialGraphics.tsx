import { gsap } from 'gsap';
import { useId, type ReactNode } from 'react';
import { useCurrentFrame, useVideoConfig } from 'remotion';

type Variant = 'exposure' | 'migration' | 'agility';

type EditorialProps = {
  variant: Variant;
  frameOffset?: number;
};

type GraphicContext = {
  id: string;
  seconds: number;
};

const INK = '#edefff';
const MUTED = '#9daccc';
const ICE = '#90e8ff';
const LILAC = '#b4a2ff';
const PEACH = '#ffbaaa';
const TRACK = '#485d86';
const ENTER = gsap.parseEase('power3.out');
const SMOOTH = gsap.parseEase('sine.inOut');

function rise(seconds: number, start: number, duration = 0.68) {
  return ENTER(Math.max(0, Math.min(1, (seconds - start) / duration)));
}

function Enter({ seconds, start, children }: {
  seconds: number;
  start: number;
  children: ReactNode;
}) {
  const progress = rise(seconds, start);
  return <g opacity={progress} transform={`translate(0 ${14 * (1 - progress)})`}>{children}</g>;
}

function Caption({ x, y, color = MUTED, children }: {
  x: number;
  y: number;
  color?: string;
  children: ReactNode;
}) {
  return <text x={x} y={y} fill={color} fontSize="15" fontWeight="650" letterSpacing="2.8">{children}</text>;
}

function Wire({ path, seconds, start, color = ICE }: {
  path: string;
  seconds: number;
  start: number;
  color?: string;
}) {
  const draw = rise(seconds, start, 1);
  const flow = Math.max(0, (seconds - start - 0.55) * 29);
  return (
    <g fill="none" opacity={draw}>
      <path d={path} stroke={TRACK} strokeWidth="1.5" />
      <path d={path} pathLength="100" stroke={color} strokeOpacity="0.34" strokeWidth="1.2"
        strokeDasharray="100" strokeDashoffset={100 * (1 - draw)} />
      <path d={path} pathLength="100" stroke={color} strokeWidth="2.4"
        strokeLinecap="round" strokeDasharray="1 38 5 56" strokeDashoffset={-flow} />
    </g>
  );
}

function DiagramCard({ id, x, y, width, title, detail, color, icon }: {
  id: string;
  x: number;
  y: number;
  width: number;
  title: string;
  detail: string;
  color: string;
  icon: ReactNode;
}) {
  return (
    <g transform={`translate(${x} ${y})`}>
      <rect width={width} height="92" rx="10" fill={`url(#${id}-plate)`} stroke={color} strokeOpacity=".40" />
      <path d={`M22 1h${width - 46}`} stroke={color} strokeOpacity=".27" strokeWidth="1.3" />
      <rect x="17" y="25" width="42" height="42" rx="8" fill={color} fillOpacity=".08" stroke={color} strokeOpacity=".24" />
      <g transform="translate(26 34)" fill="none" stroke={color} strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
        {icon}
      </g>
      <text x="74" y="40" fill={INK} fontWeight="630" fontSize="24" letterSpacing="-.4">{title}</text>
      <text x="74" y="67" fill={MUTED} fontSize="15" fontWeight="440">{detail}</text>
    </g>
  );
}

const glyph = {
  signal: <path d="M2 17h5l4-10 4 13 3-8h4" />,
  stack: <path d="m2 8 10-5 10 5-10 5L2 8Zm0 4 10 5 10-5M2 16l10 5 10-5" />,
  roadmap: <path d="M5 6h14M5 12h10M5 18h7m6-2 2 2 3-4" />,
  sandbox: <path d="m12 2 9 5v10l-9 5-9-5V7l9-5Zm0 10 9-5M3 7l9 5v10" />,
  gate: <path d="M4 20V8l8-4 8 4v12m-12-8 3 3 5-6" />,
  run: <path d="M8 5v14l12-7L8 5Z" />,
  verify: <path d="m7 12 4 4 7-8M12 2l8 3v7c0 4-4 8-8 10-4-2-8-6-8-10V5l8-3Z" />,
  classical: <path d="M4 7h16M4 17h16M7 4v6m10 4v6" />,
  quantum: <path d="m12 2 4 6 6 4-6 4-4 6-4-6-6-4 6-4 4-6Z" />,
  join: <path d="M3 6h4l5 6h9M3 18h4l5-6" />,
};

function Archive({ id, seconds }: GraphicContext) {
  const plates = [0, 1, 2];
  return (
    <>
      <Enter seconds={seconds} start={0.17}>
        <Caption x={35} y={113} color={ICE}>TODAY</Caption>
        <Caption x={432} y={113} color={PEACH}>POTENTIAL FUTURE RISK</Caption>
        <path d="M35 131H338M432 131H763" stroke={TRACK} strokeWidth="1.3" />
      </Enter>
      <Wire path="M302 310H345C390 310 383 264 431 264H471" seconds={seconds} start={0.78} color={LILAC} />
      <Wire path="M302 310H345C390 310 383 351 431 351H471" seconds={seconds} start={1.00} />
      <Wire path="M302 310H345C390 310 383 438 431 438H471" seconds={seconds} start={1.22} color={LILAC} />
      <Enter seconds={seconds} start={0.36}>
        <DiagramCard id={id} x={35} y={264} width={267} title="Encrypted traffic"
          detail="Ciphertext in transit" color={ICE} icon={glyph.signal} />
        <g transform="translate(35 382)">
          <rect width="79" height="38" rx="5" fill="#12213b" stroke="#4e6a91" />
          <rect x="91" width="79" height="38" rx="5" fill="#12213b" stroke="#4e6a91" />
          <text x="39" y="25" textAnchor="middle" fill={INK} fontSize="15" fontWeight="670" letterSpacing="1">RSA</text>
          <text x="130" y="25" textAnchor="middle" fill={INK} fontSize="15" fontWeight="670" letterSpacing="1">ECC</text>
        </g>
      </Enter>
      {plates.map((index) => {
        const pulse = 0.6 + 0.4 * Math.sin(seconds * 1.6 + index * 1.7);
        const y = 222 + index * 87;
        return (
          <Enter key={index} seconds={seconds} start={1.18 + index * 0.24}>
            <g transform={`translate(472 ${y})`}>
              <path d="M0 17 22 0h263l-18 17Z" fill="#152644" stroke="#485989" strokeOpacity=".65" />
              <path d="m267 17 18-17v63l-18 17Z" fill="#18213d" stroke="#485989" strokeOpacity=".65" />
              <rect y="17" width="267" height="63" rx="4" fill={`url(#${id}-plate)`} stroke={LILAC} strokeOpacity=".42" />
              <path d="M27 41h78m-78 14h52" stroke={LILAC} strokeOpacity=".42" strokeWidth="2" strokeLinecap="round" />
              <path d="M169 43h36m-36 11h60" stroke={TRACK} strokeWidth="2" strokeLinecap="round" />
              <circle cx="242" cy="48" r="4" fill={ICE} opacity={pulse} />
            </g>
          </Enter>
        );
      })}
      <Enter seconds={seconds} start={1.72}>
        <text x="472" y="556" fill={INK} fontSize="26" fontWeight="615">Retained ciphertext</text>
        <text x="472" y="587" fill={MUTED} fontSize="16">Exposure can outlast the connection.</text>
      </Enter>
    </>
  );
}

function Migration({ id, seconds }: GraphicContext) {
  return (
    <>
      <Enter seconds={seconds} start={0.12}>
        <Caption x={37} y={100} color={ICE}>CONTROLLED CHANGE PATH</Caption>
        <path d="M37 119H763" stroke={TRACK} strokeWidth="1.3" />
      </Enter>
      <Wire path="M361 202H436" seconds={seconds} start={0.52} />
      <Wire path="M600 248V304" seconds={seconds} start={0.95} />
      <Wire path="M436 350H361" seconds={seconds} start={1.48} color={LILAC} />
      <Wire path="M196 396V452" seconds={seconds} start={1.99} />
      <Enter seconds={seconds} start={0.34}>
        <DiagramCard id={id} x={37} y={156} width={324} title="Plan" detail="Prioritize assets and dependencies"
          color={ICE} icon={glyph.roadmap} />
      </Enter>
      <Enter seconds={seconds} start={0.74}>
        <DiagramCard id={id} x={436} y={156} width={324} title="Simulate" detail="Rehearse against scoped scenarios"
          color={ICE} icon={glyph.sandbox} />
      </Enter>
      <Enter seconds={seconds} start={1.19}>
        <DiagramCard id={id} x={436} y={304} width={324} title="Approval gate" detail="Review policy, scope, and evidence"
          color={LILAC} icon={glyph.gate} />
      </Enter>
      <Enter seconds={seconds} start={1.74}>
        <DiagramCard id={id} x={37} y={304} width={324} title="Authorized change" detail="Apply within approved scope"
          color={ICE} icon={glyph.run} />
      </Enter>
      <Enter seconds={seconds} start={2.20}>
        <DiagramCard id={id} x={37} y={452} width={324} title="Validate" detail="Check observed outcomes"
          color={ICE} icon={glyph.verify} />
      </Enter>
      <Enter seconds={seconds} start={2.72}>
        <path d="M397 497H760" stroke={TRACK} strokeWidth="1.3" strokeDasharray="2 5" />
        <Caption x={436} y={536}>EVIDENCE AND OVERSIGHT</Caption>
      </Enter>
    </>
  );
}

function Agility({ id, seconds }: GraphicContext) {
  const capabilities = ['Key lifecycle', 'Certificates', 'Crypto policy'];
  const pulse = SMOOTH(0.5 + 0.5 * Math.sin(seconds * 1.15));
  return (
    <>
      <Enter seconds={seconds} start={0.14}>
        <Caption x={37} y={96} color={ICE}>HYBRID KEY ESTABLISHMENT</Caption>
        <path d="M37 116H763" stroke={TRACK} strokeWidth="1.3" />
      </Enter>
      <Wire path="M196 245v36c0 28 28 38 68 38h45v28" seconds={seconds} start={0.71} />
      <Wire path="M600 245v36c0 28-28 38-68 38h-40v28" seconds={seconds} start={0.88} color={LILAC} />
      <Enter seconds={seconds} start={0.31}>
        <DiagramCard id={id} x={37} y={153} width={324} title="Classical" detail="Key agreement contribution"
          color={ICE} icon={glyph.classical} />
      </Enter>
      <Enter seconds={seconds} start={0.55}>
        <DiagramCard id={id} x={436} y={153} width={324} title="Post-quantum" detail="ML-KEM contribution"
          color={LILAC} icon={glyph.quantum} />
      </Enter>
      <Enter seconds={seconds} start={1.31}>
        <rect x="228" y="347" width="344" height="92" rx="10" fill={LILAC} fillOpacity={0.06 + 0.06 * pulse} />
        <DiagramCard id={id} x={228} y={347} width={344} title="Hybrid construction" detail="Combines both contributions"
          color={LILAC} icon={glyph.join} />
      </Enter>
      <Enter seconds={seconds} start={1.96}>
        <Caption x={37} y={519}>GOVERN THE CRYPTOGRAPHIC LIFECYCLE</Caption>
        <path d="M37 539H763" stroke={TRACK} strokeWidth="1.3" />
      </Enter>
      {capabilities.map((capability, index) => {
        const x = 37 + index * 246;
        return <Enter key={capability} seconds={seconds} start={2.20 + index * 0.14}>
          <rect x={x} y="558" width="234" height="55" rx="6" fill="#111d34" stroke="#576898" />
          <circle cx={x + 22} cy="585" r="3" fill={ICE} />
          <text x={x + 37} y="591" fill={INK} fontSize="19" fontWeight="570">{capability}</text>
        </Enter>;
      })}
    </>
  );
}

const sequences = { exposure: Archive, migration: Migration, agility: Agility };

export function EditorialGraphics({ variant, frameOffset = 0 }: EditorialProps) {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const id = `editorial-${useId().replace(/[^a-zA-Z0-9_-]/g, '')}`;
  const seconds = (frame - frameOffset) / fps;
  const SequenceGraphic = sequences[variant];
  return (
    <svg viewBox="0 0 800 690" role="presentation" aria-hidden="true"
      style={{ display: 'block', width: '100%', height: '100%', fontFamily: 'Geist, Inter, system-ui, sans-serif' }}>
      <defs>
        <linearGradient id={`${id}-plate`} x1="0" x2="1" y1="0" y2="1" gradientUnits="objectBoundingBox">
          <stop stopColor="#202e50" />
          <stop offset=".58" stopColor="#141f37" />
          <stop offset="1" stopColor="#0a1327" />
        </linearGradient>
        <radialGradient id={`${id}-wash`}>
          <stop stopColor="#3856ae" stopOpacity=".33" />
          <stop offset="1" stopColor="#152952" stopOpacity="0" />
        </radialGradient>
        <pattern id={`${id}-grid`} width="30" height="30" patternUnits="userSpaceOnUse">
          <path d="M20 15h2m-1-1v2" stroke="#a0b7ed" strokeWidth=".7" />
        </pattern>
      </defs>
      <rect x="2" y="16" width="796" height="640" rx="18" fill="#070f21" fillOpacity=".84" stroke="#566b9f" strokeOpacity=".55" />
      <rect x="2" y="16" width="796" height="640" rx="18" fill={`url(#${id}-wash)`} />
      <rect x="16" y="30" width="768" height="612" rx="12" fill={`url(#${id}-grid)`} opacity=".35" />
      <path d="M21 71V35h36m686 0h36v36m0 532v36h-36m-686 0H21v-36" fill="none" stroke="#82a3d7" strokeOpacity=".52" />
      <SequenceGraphic id={id} seconds={seconds} />
    </svg>
  );
}
