import { useCallback, useEffect, useRef, useState } from 'react';
import { ArrowDownRight, ChevronLeft, ChevronRight, FileUp, HardDrive, LockKeyhole, Pause, Play, Radio, RotateCcw, ShieldCheck, Waves } from 'lucide-react';
import { useCalm, useStageVisible } from './_motion';
import type { LocalMode } from './_local-scene';

const WORKFLOWS = {
  xfer: {
    label: 'XFER', icon: FileUp, title: 'Send files over a local link.',
    detail: 'Share files over local Wi-Fi, Ethernet or a supported hotspot without internet access. Approve the offer and resume interrupted transfers from verified checkpoints. Compatible 1.5.3 peers can negotiate a Wi-Fi link after a Bluetooth offer; file data uses the IP link.',
    steps: ['Select a trusted device', 'Accept the file offer', 'Check the verification receipt'],
    endpoints: ['Sending device', 'Receiving device'],
  },
  mesh: {
    label: 'Offgrid Mesh', icon: Radio, title: 'Reach trusted peers nearby.',
    detail: 'Send direct or group messages over a local network or supported Bluetooth links. Pending messages stay in an encrypted ledger until acknowledged or expired. Mesh is separate from Google Play services Nearby delivery.',
    steps: ['Compare device fingerprints', 'Send to a trusted peer', 'Check delivery receipts'],
    endpoints: ['Sending device', 'Trusted recipients'],
  },
  vault: {
    label: 'Vault import', icon: HardDrive, title: 'Keep received files in your Vault.',
    detail: 'Accept an XFER offer into an unlocked Quantum Vault, or import a verified received file while its protected local copy is available. Encrypted cloud backup follows your existing Vault settings.',
    steps: ['Unlock Quantum Vault', 'Accept or import a file', 'Keep it in encrypted storage'],
    endpoints: ['Incoming XFER', 'Quantum Vault'],
  },
} as const;

const HEADINGS = {
  overview: ['Connect beyond the internet.', 'Share files with XFER, message trusted peers with Offgrid Mesh, and keep verified transfers in Quantum Vault.'],
  chat: ['Keep nearby teams connected.', 'Use Offgrid Mesh for local conversations and XFER for file sharing when your team has a local link.'],
  vault: ['From trusted peer to protected storage.', 'Receive files through XFER and put verified copies into your unlocked Quantum Vault. Use Offgrid Mesh to coordinate with nearby teammates.'],
} as const;

type Scene = ReturnType<typeof import('./_local-scene').mountLocalScene>;

type DemoStep = { status: string; detail: string; packet?: readonly [number, number] };

const CONNECTING = { status: 'Connecting to a trusted device…', detail: 'The devices check their pinned fingerprints.' };
const CONNECTED = { status: 'Secure connection established', detail: 'Both devices authenticate before exchanging data.' };
const SENDING = [0.06, 0.94] as const;
const RECEIVED = [0.94, 0.94] as const;
const STEP_DURATION = 1_850;
const DEMO_STEPS: Record<LocalMode, readonly DemoStep[]> = {
  xfer: [
    CONNECTING, CONNECTED,
    { status: 'File offer accepted', detail: 'The recipient approves the transfer.' },
    { status: 'Sending encrypted file…', detail: 'Protected chunks travel over the local connection.', packet: SENDING },
    { status: 'File received and verified', detail: 'The receiving device checks the file’s integrity.', packet: RECEIVED },
  ],
  mesh: [
    CONNECTING, CONNECTED,
    { status: 'Sending encrypted message…', detail: 'The message travels over the authenticated local link.', packet: SENDING },
    { status: 'Message received and decrypted', detail: 'The recipient’s device opens the message locally.', packet: RECEIVED },
    { status: 'Delivery receipt received', detail: 'The sender can see that the recipient stored the message.', packet: RECEIVED },
  ],
  vault: [
    { status: 'Checking Vault access…', detail: 'The receiving device checks that Quantum Vault is unlocked.' },
    { status: 'Vault unlocked', detail: 'The recipient can choose Quantum Vault as the destination.' },
    { status: 'File verified', detail: 'The receiving device checks the file before import.' },
    { status: 'Importing verified file…', detail: 'The receiving device writes the file to encrypted local storage.', packet: SENDING },
    { status: 'File secured in Quantum Vault', detail: 'The imported copy is available in the recipient’s Vault.', packet: RECEIVED },
  ],
};

function LocalDiagram({ mode, active, step, playing, flowing, onAdvance }: {
  mode: LocalMode;
  active: boolean;
  step: DemoStep;
  playing: boolean;
  flowing: boolean;
  onAdvance: () => void;
}) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const scene = useRef<Scene | null>(null);
  const path = useRef<SVGPathElement>(null);
  const packet = useRef<SVGPathElement>(null);
  const position = useRef<number | null>(null);
  const elapsed = useRef(0);
  const light = useRef(flowing);
  const [rendered, setRendered] = useState(false);
  useEffect(() => {
    light.current = flowing;
    scene.current?.setFlowing(flowing);
  }, [flowing]);
  useEffect(() => {
    setRendered(false);
    const element = canvas.current;
    if (!active || !element) return;
    let disposed = false;
    void import('./_local-scene').then(({ mountLocalScene }) => {
      if (disposed) return;
      scene.current = mountLocalScene(element, () => setRendered(false));
      scene.current.setFrame(mode, position.current);
      scene.current.setFlowing(light.current);
      setRendered(true);
    }).catch(() => { if (!disposed) setRendered(false); });
    return () => {
      disposed = true;
      scene.current?.dispose();
      scene.current = null;
    };
  }, [active, mode]);

  useEffect(() => { elapsed.current = 0; }, [step]);
  useEffect(() => {
    const route = path.current;
    const marker = packet.current;
    const pathLength = route?.getTotalLength() ?? 0;
    function paint(progress: number) {
      const next = step.packet ? step.packet[0] + (step.packet[1] - step.packet[0]) * progress : null;
      position.current = next;
      scene.current?.setFrame(mode, next);
      if (!route || !marker) return;
      marker.setAttribute('visibility', next === null ? 'hidden' : 'visible');
      if (next !== null) {
        const point = route.getPointAtLength(pathLength * next);
        marker.setAttribute('transform', `translate(${point.x} ${point.y})`);
      }
    }
    paint(!playing && elapsed.current === 0 ? 0.5 : elapsed.current / STEP_DURATION);
    if (!active || !playing) return;
    const travelling = step.packet && step.packet[0] !== step.packet[1];
    let frame: number;
    let previous = performance.now();
    function tick(now: number) {
      // Cap elapsed time after a hidden tab resumes so the sequence stays readable.
      elapsed.current = Math.min(STEP_DURATION, elapsed.current + Math.min(100, Math.max(0, now - previous)));
      previous = now;
      if (travelling) paint(elapsed.current / STEP_DURATION);
      if (elapsed.current === STEP_DURATION) onAdvance();
      else frame = requestAnimationFrame(tick);
    }
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [active, mode, onAdvance, playing, step]);

  const primaryRoute = mode === 'mesh' ? 'M142 102Q241 49 337 70' : 'M142 102Q241 49 337 102';
  const secondaryRoute = 'M142 102Q248 92 337 141';
  return <div className="qm-local-diagram" aria-hidden="true" data-flowing={flowing} data-renderer={active && rendered ? 'webgl' : 'diagram'}>
    <svg viewBox="0 0 480 220" className="qm-local-fallback" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M85 150 240 64l155 86-155 57zM122 128l154 66m-116-88 152 75m-113-97 152 82M124 164l153-80m-115 94 152-73m-114 86 151-64" opacity=".25" />
      <path ref={path} d={primaryRoute} opacity=".45" />
      <path d={primaryRoute} pathLength="100" className="qm-local-flow" />
      {mode === 'mesh' && <><path d={secondaryRoute} opacity=".45" /><path d={secondaryRoute} pathLength="100" className="qm-local-flow" /></>}
      <path ref={packet} d="m0-7 7 7-7 7-7-7z" fill="currentColor" visibility="hidden" />
      <rect x="96" y="66" width="46" height="74" rx="6" fill="#152942" />
      <path d="M107 120h24m-24 7h16" opacity=".6" />
      {mode === 'vault' ? <path d="m333 93 35-16 35 16-35 16zM333 103v8l35 16 35-16v-8m-70 19v8l35 16 35-16v-8" /> :
        <rect x="337" y={mode === 'mesh' ? 45 : 66} width="46" height={mode === 'mesh' ? 49 : 74} rx="6" fill="#152942" />}
      {mode === 'mesh' && <rect x="337" y="116" width="46" height="49" rx="6" fill="#152942" />}
    </svg>
    {active && <canvas ref={canvas} />}
  </div>;
}

function WorkflowStage({ mode }: { mode: LocalMode }) {
  const [stageRef, visible] = useStageVisible<HTMLDivElement>();
  const calm = useCalm();
  const [index, setIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [lightOn, setLightOn] = useState(true);
  const steps = DEMO_STEPS[mode];
  const step = steps[index];
  const last = index === steps.length - 1;
  const advance = useCallback(() => {
    const next = Math.min(index + 1, steps.length - 1);
    setIndex(next);
    if (next === steps.length - 1) setPlaying(false);
  }, [index, steps.length]);
  const PlayIcon = playing ? Pause : last ? RotateCcw : Play;
  const endpoints = WORKFLOWS[mode].endpoints;

  function goTo(next: number) {
    setPlaying(false);
    setIndex(next);
  }

  function togglePlayback() {
    if (last) setIndex(0);
    setPlaying(!playing);
  }

  return <div className="qm-local-stage" ref={stageRef}>
    <div className="qm-local-stage-label"><ShieldCheck size={15} aria-hidden="true" /> Interactive workflow demo</div>
    <LocalDiagram mode={mode} active={visible && !calm} step={step} playing={playing && !calm} flowing={visible && lightOn && !calm} onAdvance={advance} />
    <div className="qm-local-endpoints"><span>{endpoints[0]}</span><span>{endpoints[1]}</span></div>
    <div className="qm-local-status" role="status" aria-atomic="true">
      <span className="qm-local-step-label">Demo step {index + 1} of {steps.length}</span>
      <strong>{step.status}</strong>
      <p>{step.detail}</p>
    </div>
    <div className="qm-local-playback" role="group" aria-label="Workflow demo controls">
      <button type="button" aria-label="Previous step" disabled={index === 0} onClick={() => goTo(index - 1)}><ChevronLeft size={16} aria-hidden="true" /> Back</button>
      {!calm && <button type="button" className="qm-local-play" onClick={togglePlayback}><PlayIcon size={15} aria-hidden="true" /> {playing ? 'Pause demo' : last ? 'Replay demo' : 'Play demo'}</button>}
      <button type="button" aria-label="Next step" disabled={last} onClick={() => goTo(index + 1)}>Next <ChevronRight size={16} aria-hidden="true" /></button>
      {!calm && <button type="button" className="qm-local-light" onClick={() => setLightOn((current) => !current)}><Waves size={16} aria-hidden="true" /> {lightOn ? 'Pause light' : 'Resume light'}</button>}
    </div>
  </div>;
}

export function LocalWorkflows({ page }: { page: keyof typeof HEADINGS }) {
  const [mode, setMode] = useState<LocalMode>(page === 'overview' ? 'xfer' : page === 'chat' ? 'mesh' : 'vault');
  const workflow = WORKFLOWS[mode];
  return <section id="local-workflows" className="qm-local-section qguard-dark-stage" aria-labelledby="local-workflows-title" tabIndex={-1}>
    <div className="qm-local-heading">
      <div>
        <p className="qm-local-kicker"><Radio size={15} aria-hidden="true" /> Local connectivity</p>
        <h2 id="local-workflows-title">{HEADINGS[page][0]}</h2>
        <p>{HEADINGS[page][1]}</p>
      </div>
      <span className="qm-local-platform">Windows &amp; Android</span>
    </div>
    <div className="qm-local-panel" data-mode={mode}>
      <div className="qm-local-controls" role="group" aria-label="Explore local workflows">
        {(Object.keys(WORKFLOWS) as LocalMode[]).map((key) => {
          const { icon: Icon, label } = WORKFLOWS[key];
          return <button key={key} type="button" aria-pressed={mode === key} onClick={() => setMode(key)}>
            <Icon size={17} aria-hidden="true" /> {label}
          </button>;
        })}
      </div>
      <div className="qm-local-body">
        <div className="qm-local-copy" aria-live="polite">
          <h3>{workflow.title}</h3>
          <p>{workflow.detail}</p>
          <ol>{workflow.steps.map((step) => <li key={step}>{step}</li>)}</ol>
        </div>
        <WorkflowStage key={mode} mode={mode} />
      </div>
      <p className="qm-local-note"><LockKeyhole size={16} aria-hidden="true" /> Start with a verified account session and compare device fingerprints. Availability depends on device permissions and a supported local connection.</p>
    </div>
  </section>;
}

export function LocalWorkflowLink({ children }: { children: string }) {
  return <a className="qm-local-jump" href="#local-workflows">{children} <ArrowDownRight size={16} aria-hidden="true" /></a>;
}
