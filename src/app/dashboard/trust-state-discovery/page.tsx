'use client';

import { useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent, type ReactNode } from 'react';
import * as THREE from 'three';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  Database,
  GitBranch,
  KeyRound,
  Link2,
  LockKeyhole,
  Network,
  RefreshCw,
  Route,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Users,
  Workflow,
  Zap,
  type LucideIcon,
} from 'lucide-react';
import {
  useTrustStateDiscovery,
  type TrustFinding,
  type TrustGateImpact,
  type TrustGateState,
  type TrustGraphEdge,
  type TrustGraphNode,
  type TrustRecord,
  type TrustSeverity,
  type TrustWorkflowStep,
} from '@/hooks/use-trust-state-discovery';
import { cn } from '@/lib/utils';

const PANEL_CLASS =
  'relative overflow-hidden rounded-lg border border-slate-200/80 bg-white/86 p-4 text-slate-950 shadow-[0_20px_55px_rgba(15,23,42,0.08)] backdrop-blur-xl dark:border-[#FFD36B]/18 dark:bg-[#08111f]/78 dark:text-white dark:shadow-[inset_0_1px_0_rgba(255,255,255,0.08),0_24px_60px_rgba(0,0,0,0.36)]';

const WORKFLOW_ICONS: Record<string, LucideIcon> = {
  visibility: ScanSearch,
  ownership: Users,
  dependencies: GitBranch,
  risk: ShieldAlert,
  'migration-gate': Route,
};

function numberFmt(value: unknown) {
  return new Intl.NumberFormat('en-US').format(Number(value || 0));
}

function pct(value: unknown) {
  return `${Math.max(0, Math.min(100, Math.round(Number(value || 0))))}%`;
}

function compactDate(value: string | null | undefined) {
  if (!value) return 'Awaiting telemetry';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return 'Awaiting telemetry';
  return new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(date);
}

function liveDateTime(value: Date) {
  const date = new Intl.DateTimeFormat('en-US', { month: 'long', day: 'numeric', year: 'numeric' }).format(value);
  const time = new Intl.DateTimeFormat('en-US', { hour: 'numeric', minute: '2-digit', second: '2-digit' }).format(value);
  return `${date} at ${time}`;
}

function gateTone(state: TrustGateState) {
  if (state === 'ready') return 'border-emerald-400/45 bg-emerald-400/10 text-emerald-300';
  if (state === 'review') return 'border-amber-300/45 bg-amber-300/10 text-amber-200';
  return 'border-red-400/55 bg-red-500/12 text-red-300';
}

function severityTone(severity: TrustSeverity | string) {
  if (severity === 'critical') return 'border-red-400/55 bg-red-500/12 text-red-300';
  if (severity === 'high') return 'border-orange-400/45 bg-orange-400/10 text-orange-300';
  if (severity === 'medium') return 'border-amber-300/45 bg-amber-300/10 text-amber-200';
  return 'border-emerald-400/35 bg-emerald-400/10 text-emerald-300';
}

function impactTone(impact: TrustGateImpact | string) {
  if (impact === 'blocker') return 'border-red-400/55 bg-red-500/12 text-red-300';
  if (impact === 'review') return 'border-amber-300/45 bg-amber-300/10 text-amber-200';
  return 'border-sky-300/40 bg-sky-400/10 text-sky-200';
}

function nodeTone(status: string, riskScore: number) {
  if (status === 'blocked' || riskScore >= 75) return 'border-red-400 bg-red-500 text-white shadow-[0_0_34px_rgba(239,68,68,0.34)]';
  if (status === 'review' || status === 'unknown' || status === 'partial' || riskScore >= 45) return 'border-amber-300 bg-amber-400 text-slate-950 shadow-[0_0_28px_rgba(251,191,36,0.28)]';
  return 'border-emerald-300 bg-emerald-400 text-slate-950 shadow-[0_0_28px_rgba(16,185,129,0.24)]';
}

function Panel({ children, className }: { children: ReactNode; className?: string }) {
  return <section className={cn(PANEL_CLASS, className)}>{children}</section>;
}

function StatusPill({ state, label }: { state: TrustGateState; label?: string }) {
  return (
    <span className={cn('inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-[10px] font-black uppercase tracking-[0.14em]', gateTone(state))}>
      <span className={cn('h-1.5 w-1.5 rounded-full', state === 'ready' ? 'bg-emerald-300' : state === 'review' ? 'bg-amber-200' : 'bg-red-300')} />
      {label || (state === 'ready' ? 'Ready' : state === 'review' ? 'Review' : 'Blocked')}
    </span>
  );
}

function ScoreRing({ value, tone = '#FFD36B' }: { value: number; tone?: string }) {
  const normalized = Math.max(0, Math.min(100, Math.round(value)));
  const radius = 34;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (normalized / 100) * circumference;

  return (
    <div className="relative grid h-24 w-24 shrink-0 place-items-center">
      <svg viewBox="0 0 88 88" className="absolute inset-0 h-full w-full -rotate-90">
        <circle cx="44" cy="44" r={radius} fill="none" stroke="rgba(148,163,184,0.22)" strokeWidth="8" />
        <circle cx="44" cy="44" r={radius} fill="none" stroke={tone} strokeDasharray={circumference} strokeDashoffset={offset} strokeLinecap="round" strokeWidth="8" />
      </svg>
      <span className="font-mono text-xl font-black">{normalized}</span>
    </div>
  );
}

function MetricCard({ icon: Icon, label, value, detail, tone }: { icon: LucideIcon; label: string; value: string; detail: string; tone: string }) {
  return (
    <Panel className="min-h-[132px]">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-[10px] font-black uppercase tracking-[0.16em] text-slate-500 dark:text-white/42">{label}</p>
          <div className="mt-2 font-mono text-2xl font-black">{value}</div>
        </div>
        <div className={cn('grid h-10 w-10 shrink-0 place-items-center rounded-lg border', tone)}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
      <p className="mt-4 text-xs font-semibold leading-relaxed text-slate-600 dark:text-white/52">{detail}</p>
    </Panel>
  );
}

const WORKFLOW_STAGE_META: Record<string, {
  number: string;
  title: string;
  subtitle: string;
  bullets: string[];
  icon: LucideIcon;
  imageSrc: string;
  tone: string;
  glow: string;
}> = {
  visibility: {
    number: '1',
    title: 'Visibility',
    subtitle: 'Discover Everything',
    bullets: ['Discover certificates, keys, TLS endpoints, CAs, and trust stores', 'Collect runtime crypto events', 'Identify vendors and integrations'],
    icon: ScanSearch,
    imageSrc: '/visibility.png',
    tone: 'from-blue-500 to-cyan-300 text-blue-100 border-blue-400/45',
    glow: 'rgba(59,130,246,0.42)',
  },
  ownership: {
    number: '2',
    title: 'Ownership',
    subtitle: 'Assign Accountability',
    bullets: ['Identify asset and certificate owners', 'Map system and business ownership', 'Validate vendor ownership'],
    icon: Users,
    imageSrc: '/ownership.png',
    tone: 'from-emerald-500 to-green-300 text-emerald-50 border-emerald-400/45',
    glow: 'rgba(16,185,129,0.42)',
  },
  dependencies: {
    number: '3',
    title: 'Dependencies',
    subtitle: 'Map Relationships',
    bullets: ['Map trust chains and relationships', 'Identify dependent systems, apps, and workloads', 'Uncover hidden and indirect dependencies'],
    icon: Database,
    imageSrc: '/dependencies.png',
    tone: 'from-violet-500 to-purple-300 text-violet-50 border-violet-400/45',
    glow: 'rgba(139,92,246,0.44)',
  },
  risk: {
    number: '4',
    title: 'Risk',
    subtitle: 'Assess and Prioritize',
    bullets: ['Analyze blast radius and impact', 'Detect trust blockers and gaps', 'Evaluate runtime and crypto risks'],
    icon: ShieldAlert,
    imageSrc: '/risk.png',
    tone: 'from-amber-500 to-yellow-300 text-amber-50 border-amber-400/45',
    glow: 'rgba(245,158,11,0.44)',
  },
  'migration-gate': {
    number: '5',
    title: 'Migration Gate',
    subtitle: 'Approve or Block',
    bullets: ['Validate readiness and controls', 'Ensure rollback and recovery paths', 'Gate migration execution'],
    icon: LockKeyhole,
    imageSrc: '/migration_gate.png',
    tone: 'from-red-500 to-rose-300 text-red-50 border-red-400/45',
    glow: 'rgba(239,68,68,0.44)',
  },
};

function workflowStatus(step: TrustWorkflowStep) {
  if (step.status === 'ready') return { label: 'Completed', className: 'border-emerald-400/25 bg-emerald-400/12 text-emerald-300', icon: BadgeCheck };
  if (step.status === 'blocked') return { label: 'Blocked', className: 'border-red-400/25 bg-red-500/14 text-red-300', icon: ShieldAlert };
  if (step.id === 'risk') return { label: 'Risk Identified', className: 'border-amber-300/25 bg-amber-400/12 text-amber-200', icon: AlertTriangle };
  return { label: 'Needs Review', className: 'border-amber-300/25 bg-amber-400/12 text-amber-200', icon: AlertTriangle };
}

function WorkflowVisual({ step, meta }: { step: TrustWorkflowStep; meta: NonNullable<typeof WORKFLOW_STAGE_META[string]> }) {
  const Icon = meta.icon;

  return (
    <div className="relative mx-auto mt-5 grid h-36 w-full place-items-center overflow-visible">
      <div className="absolute inset-x-6 top-1/2 h-px bg-gradient-to-r from-transparent via-white/16 to-transparent" />
      <div className="absolute h-32 w-32 rounded-full border border-white/10 bg-[radial-gradient(circle,rgba(255,255,255,0.08),transparent_66%)]" style={{ boxShadow: `0 0 38px ${meta.glow}` }} />
      <div className="absolute h-24 w-24 rounded-full border border-white/10 opacity-70" />
      <div className="relative grid h-32 w-32 place-items-center overflow-hidden rounded-full">
        <div className="absolute inset-0 rounded-full bg-[radial-gradient(circle,rgba(255,255,255,0.07),transparent_70%)]" />
        {meta.imageSrc ? (
          <img
            src={meta.imageSrc}
            alt=""
            className="relative h-[94px] w-[94px] object-contain object-center drop-shadow-[0_18px_34px_rgba(0,0,0,0.45)]"
            loading="lazy"
          />
        ) : (
          <div className={cn('relative grid h-16 w-16 place-items-center rounded-full border bg-gradient-to-br shadow-[0_18px_42px_rgba(0,0,0,0.34)]', meta.tone)}>
          <Icon className="h-8 w-8" />
          </div>
        )}
      </div>
      <div className="absolute bottom-1 left-1/2 translate-x-8 rounded-md border border-white/10 bg-slate-950/70 px-2 py-1 font-mono text-[10px] font-black text-white/62 backdrop-blur">
        {pct(step.score)}
      </div>
    </div>
  );
}

function WorkflowRail({ steps }: { steps: TrustWorkflowStep[] }) {
  if (!steps.length) {
    return <Panel><div className="py-8 text-center text-sm font-bold text-slate-500 dark:text-white/38">Awaiting workflow telemetry.</div></Panel>;
  }

  return (
    <Panel className="p-5">
      <div className="mb-5 flex items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-black uppercase tracking-normal">Trust-State Workflow</h2>
          <p className="mt-1 text-xs font-bold text-slate-500 dark:text-white/42">Visibility, accountability, dependency proofing, risk analysis, and migration gate control.</p>
        </div>
        <Workflow className="h-5 w-5 text-[#FFD36B]" />
      </div>
      <div className="grid gap-3 xl:grid-cols-5">
        {steps.map((step, index) => {
          const meta = WORKFLOW_STAGE_META[step.id] || {
            number: String(index + 1),
            title: step.label,
            subtitle: 'Trust-State Stage',
            bullets: [step.detail],
            icon: WORKFLOW_ICONS[step.id] || ShieldQuestion,
            imageSrc: '',
            tone: 'from-slate-500 to-slate-300 text-slate-50 border-slate-300/45',
            glow: 'rgba(148,163,184,0.34)',
          };
          const status = workflowStatus(step);
          const StatusIcon = status.icon;
          return (
            <div key={step.id} className="relative">
              {index < steps.length - 1 && <ArrowRight className="pointer-events-none absolute -right-3 top-[49%] z-10 hidden h-5 w-5 text-slate-400 dark:text-white/32 xl:block" />}
              <div className="relative flex min-h-[390px] flex-col overflow-hidden rounded-lg border border-slate-200 bg-slate-50/86 p-4 dark:border-white/10 dark:bg-[#0a1526]/86">
                <div className="pointer-events-none absolute inset-0 opacity-80" style={{ background: `radial-gradient(circle at 50% 30%, ${meta.glow}, transparent 34%)` }} />
                <div className="relative flex items-start gap-3">
                  <div className={cn('grid h-9 w-9 shrink-0 place-items-center rounded-full border bg-gradient-to-br text-base font-black shadow-[0_12px_28px_rgba(0,0,0,0.28)]', meta.tone)}>
                    {meta.number}
                  </div>
                  <div className="min-w-0">
                    <div className="text-sm font-black uppercase">{meta.title}</div>
                    <div className="mt-1 text-xs font-semibold text-slate-600 dark:text-white/68">{meta.subtitle}</div>
                  </div>
                </div>
                <WorkflowVisual step={step} meta={meta} />
                <ul className="relative mt-4 flex-1 space-y-2 text-xs font-semibold leading-relaxed text-slate-700 dark:text-white/72">
                  {meta.bullets.map((bullet) => (
                    <li key={bullet} className="flex gap-2">
                      <span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-current opacity-70" />
                      <span>{bullet}</span>
                    </li>
                  ))}
                </ul>
                <div className={cn('relative mt-4 flex items-center justify-between rounded-lg border px-3 py-2 text-xs font-black uppercase', status.className)}>
                  <span>{status.label}</span>
                  <StatusIcon className="h-4 w-4" />
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

type TopologyNode3D = TrustGraphNode & {
  degree: number;
  px: number;
  py: number;
  pz: number;
};

function graphBucket(node: TrustGraphNode) {
  const value = `${node.id} ${node.type} ${node.label}`.toLowerCase();
  if (value.includes('issuer') || value.includes(' ca')) return 'issuer';
  if (value.includes('certificate') || value.includes('trust object')) return 'certificate';
  if (value.includes('runtime')) return 'runtime';
  if (value.includes('vendor') || value.includes('supplier')) return 'vendor';
  if (value.includes('asset') || value.includes('service') || value.includes('application') || value.includes('web')) return 'asset';
  return 'other';
}

function graphColor(status: string, riskScore: number) {
  if (status === 'blocked' || riskScore >= 75) return '#ff3654';
  if (status === 'review' || status === 'unknown' || status === 'partial' || riskScore >= 45) return '#ffc93d';
  if (status === 'observed' || status === 'mapped') return '#22d3ee';
  return '#24d79f';
}

function edgeColor(status: string) {
  if (status === 'blocked') return '#ff5c73';
  if (status === 'ready') return '#2ee6a6';
  if (status === 'mapped') return '#38d7ff';
  return '#ffd36b';
}

function clampRange(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, value));
}

function cardAnchorTowardPoint(card: { x: number; y: number; width: number; height: number }, point: { x: number; y: number }) {
  const centerX = card.x + card.width / 2;
  const centerY = card.y + card.height / 2;
  const dx = point.x - centerX;
  const dy = point.y - centerY;
  const halfWidth = card.width / 2;
  const halfHeight = card.height / 2;

  if (Math.abs(dx) / Math.max(1, halfWidth) > Math.abs(dy) / Math.max(1, halfHeight)) {
    return {
      x: centerX + (dx > 0 ? halfWidth : -halfWidth),
      y: centerY + dy * (halfWidth / Math.max(1, Math.abs(dx))),
    };
  }

  return {
    x: centerX + dx * (halfHeight / Math.max(1, Math.abs(dy))),
    y: centerY + (dy > 0 ? halfHeight : -halfHeight),
  };
}

function buildTopologyLayout(nodes: TrustGraphNode[], edges: TrustGraphEdge[]) {
  const degreeMap = new Map<string, number>();
  edges.forEach((edge) => {
    degreeMap.set(edge.from, (degreeMap.get(edge.from) || 0) + 1);
    degreeMap.set(edge.to, (degreeMap.get(edge.to) || 0) + 1);
  });

  const uniqueNodes = Array.from(new Map(nodes.map((node) => [node.id, node])).values());
  const buckets: Record<string, TrustGraphNode[]> = { issuer: [], certificate: [], runtime: [], asset: [], vendor: [], other: [] };
  uniqueNodes.forEach((node) => buckets[graphBucket(node)].push(node));

  const configs: Record<string, { x: number; y: number; z: number; xGap: number; yGap: number; columns: number }> = {
    issuer: { x: -275, y: 125, z: -40, xGap: 132, yGap: 82, columns: 3 },
    certificate: { x: -115, y: 92, z: 30, xGap: 124, yGap: 76, columns: 4 },
    asset: { x: 110, y: 32, z: 5, xGap: 128, yGap: 82, columns: 4 },
    runtime: { x: -60, y: -142, z: 65, xGap: 130, yGap: 74, columns: 3 },
    vendor: { x: 305, y: 95, z: -30, xGap: 110, yGap: 76, columns: 2 },
    other: { x: 35, y: -42, z: -75, xGap: 120, yGap: 76, columns: 3 },
  };

  return Object.entries(buckets).flatMap(([bucket, bucketNodes]) => {
    const config = configs[bucket];
    return bucketNodes
      .sort((a, b) => (degreeMap.get(b.id) || 0) - (degreeMap.get(a.id) || 0) || b.riskScore - a.riskScore)
      .map((node, index) => {
        const columns = Math.max(1, Math.min(config.columns, bucketNodes.length));
        const rows = Math.ceil(bucketNodes.length / columns);
        const col = index % columns;
        const row = Math.floor(index / columns);
        const px = config.x + (col - (columns - 1) / 2) * config.xGap;
        const py = config.y - (row - (rows - 1) / 2) * config.yGap;
        const pz = config.z + ((col % 2 ? 1 : -1) * 26) + (row % 2) * 18;
        return { ...node, degree: degreeMap.get(node.id) || 0, px, py, pz };
      });
  });
}

function TrustGraph({ nodes, edges }: { nodes: TrustGraphNode[]; edges: TrustGraphEdge[] }) {
  const mountRef = useRef<HTMLDivElement | null>(null);
  const labelRefs = useRef<Record<string, HTMLDivElement | null>>({});
  const connectorRefs = useRef<Record<string, SVGPathElement | null>>({});
  const connectorGlowRefs = useRef<Record<string, SVGPathElement | null>>({});
  const labelPositionsRef = useRef<Record<string, { x: number; y: number }>>({});
  const manualLabelPositionsRef = useRef<Record<string, { x: number; y: number }>>({});
  const graphSizeRef = useRef({ width: 0, height: 0 });
  const dragRef = useRef<{ id: string; pointerId: number; startX: number; startY: number; originX: number; originY: number; moved: boolean } | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const layoutNodes = useMemo(() => buildTopologyLayout(nodes, edges), [nodes, edges]);
  const layoutMap = useMemo(() => new Map(layoutNodes.map((node) => [node.id, node])), [layoutNodes]);
  const visibleEdges = useMemo(() => edges.filter((edge) => layoutMap.has(edge.from) && layoutMap.has(edge.to)), [edges, layoutMap]);

  useEffect(() => {
    setSelectedNodeId((current) => current && layoutMap.has(current) ? current : null);
    const liveIds = new Set(layoutNodes.map((node) => node.id));
    for (const id of Object.keys(manualLabelPositionsRef.current)) {
      if (!liveIds.has(id)) delete manualLabelPositionsRef.current[id];
    }
    for (const id of Object.keys(labelPositionsRef.current)) {
      if (!liveIds.has(id)) delete labelPositionsRef.current[id];
    }
    for (const id of Object.keys(connectorRefs.current)) {
      if (!liveIds.has(id)) delete connectorRefs.current[id];
    }
    for (const id of Object.keys(connectorGlowRefs.current)) {
      if (!liveIds.has(id)) delete connectorGlowRefs.current[id];
    }
  }, [layoutMap, layoutNodes]);

  const beginDrag = (event: ReactPointerEvent<HTMLDivElement>, nodeId: string) => {
    const element = event.currentTarget;
    const current = labelPositionsRef.current[nodeId] || manualLabelPositionsRef.current[nodeId] || { x: 0, y: 0 };
    dragRef.current = {
      id: nodeId,
      pointerId: event.pointerId,
      startX: event.clientX,
      startY: event.clientY,
      originX: current.x,
      originY: current.y,
      moved: false,
    };
    element.setPointerCapture(event.pointerId);
  };

    const moveDrag = (event: ReactPointerEvent<HTMLDivElement>, nodeId: string) => {
    const drag = dragRef.current;
    if (!drag || drag.id !== nodeId || drag.pointerId !== event.pointerId) return;
    const dx = event.clientX - drag.startX;
    const dy = event.clientY - drag.startY;
    if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
    const element = labelRefs.current[nodeId];
    const width = graphSizeRef.current.width || 720;
    const height = graphSizeRef.current.height || 500;
    const boxWidth = element?.offsetWidth || 156;
    const boxHeight = element?.offsetHeight || 54;
    const x = clampRange(drag.originX + dx, 12, Math.max(12, width - boxWidth - 12));
    const y = clampRange(drag.originY + dy, 12, Math.max(12, height - boxHeight - 12));
    manualLabelPositionsRef.current[nodeId] = { x, y };
    labelPositionsRef.current[nodeId] = { x, y };
    if (element) element.style.transform = `translate3d(${x}px, ${y}px, 0)`;
  };

  const endDrag = (event: ReactPointerEvent<HTMLDivElement>, nodeId: string) => {
    const drag = dragRef.current;
    if (!drag || drag.id !== nodeId || drag.pointerId !== event.pointerId) return;
    try {
      event.currentTarget.releasePointerCapture(event.pointerId);
    } catch {
      // Pointer capture can already be released by the browser during cancellation.
    }
    if (!drag.moved) setSelectedNodeId((current) => current === nodeId ? null : nodeId);
    dragRef.current = null;
  };

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount || !layoutNodes.length) return;

    let width = Math.max(360, mount.clientWidth);
    let height = Math.max(420, mount.clientHeight);
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(43, width / height, 0.1, 1600);
    camera.position.set(0, 0, 660);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setSize(width, height);
    renderer.domElement.dataset.trustTopology = 'true';
    renderer.domElement.className = 'absolute inset-0 h-full w-full';
    mount.appendChild(renderer.domElement);

    const root = new THREE.Group();
    scene.add(root);
    scene.add(new THREE.AmbientLight(0xffffff, 0.7));
    const keyLight = new THREE.PointLight(0x7dd3fc, 2.2, 1000);
    keyLight.position.set(-250, 230, 420);
    scene.add(keyLight);
    const fillLight = new THREE.PointLight(0xffd36b, 1.4, 900);
    fillLight.position.set(360, -180, 360);
    scene.add(fillLight);

    const grid = new THREE.GridHelper(920, 20, 0x2dd4bf, 0x334155);
    grid.rotation.x = Math.PI / 2;
    grid.position.z = -180;
    const gridMaterial = grid.material as THREE.Material;
    gridMaterial.transparent = true;
    gridMaterial.opacity = 0.12;
    root.add(grid);

    const nodeMeshes = new Map<string, THREE.Mesh>();
    const nodeGeometry = new THREE.SphereGeometry(1, 32, 18);
    const haloGeometry = new THREE.SphereGeometry(1, 32, 18);

    layoutNodes.forEach((node) => {
      const color = graphColor(node.status, node.riskScore);
      const radius = 10 + Math.min(12, node.degree * 2.2) + Math.round(node.riskScore / 20);
      const material = new THREE.MeshStandardMaterial({
        color,
        emissive: new THREE.Color(color),
        emissiveIntensity: node.status === 'blocked' ? 0.45 : 0.26,
        metalness: 0.28,
        roughness: 0.34,
      });
      const mesh = new THREE.Mesh(nodeGeometry, material);
      mesh.scale.setScalar(radius);
      mesh.position.set(node.px, node.py, node.pz);
      root.add(mesh);
      nodeMeshes.set(node.id, mesh);

      const halo = new THREE.Mesh(
        haloGeometry,
        new THREE.MeshBasicMaterial({ color, transparent: true, opacity: node.status === 'blocked' ? 0.13 : 0.08, depthWrite: false }),
      );
      halo.scale.setScalar(radius * 2.25);
      halo.position.copy(mesh.position);
      root.add(halo);
    });

    const pulseGeometry = new THREE.SphereGeometry(4.5, 16, 10);
    const pulses: Array<{ mesh: THREE.Mesh; from: THREE.Vector3; to: THREE.Vector3; phase: number }> = [];
    visibleEdges.forEach((edge, index) => {
      const from = layoutMap.get(edge.from);
      const to = layoutMap.get(edge.to);
      if (!from || !to) return;

      const fromVector = new THREE.Vector3(from.px, from.py, from.pz);
      const toVector = new THREE.Vector3(to.px, to.py, to.pz);
      const color = edgeColor(edge.status);
      const geometry = new THREE.BufferGeometry().setFromPoints([fromVector, toVector]);
      const material = new THREE.LineBasicMaterial({ color, transparent: true, opacity: edge.status === 'blocked' ? 0.52 : 0.34 });
      root.add(new THREE.Line(geometry, material));

      const pulse = new THREE.Mesh(
        pulseGeometry,
        new THREE.MeshBasicMaterial({ color, transparent: true, opacity: edge.status === 'blocked' ? 0.95 : 0.82 }),
      );
      pulse.position.copy(fromVector);
      root.add(pulse);
      pulses.push({ mesh: pulse, from: fromVector, to: toVector, phase: (index % 9) / 9 });
    });

    const tempVector = new THREE.Vector3();
    const resize = () => {
      width = Math.max(360, mount.clientWidth);
      height = Math.max(420, mount.clientHeight);
      graphSizeRef.current = { width, height };
      renderer.setSize(width, height);
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
    };

    const placeLabels = () => {
      const placements = layoutNodes
        .map((node) => {
          const mesh = nodeMeshes.get(node.id);
          const element = labelRefs.current[node.id];
          if (!mesh || !element) return null;
          tempVector.setFromMatrixPosition(mesh.matrixWorld).project(camera);
          const x = (tempVector.x * 0.5 + 0.5) * width;
          const y = (-tempVector.y * 0.5 + 0.5) * height;
          return {
            id: node.id,
            element,
            x,
            y,
            z: tempVector.z,
            width: Math.min(188, Math.max(136, element.offsetWidth || 156)),
            height: Math.max(48, element.offsetHeight || 54),
            color: graphColor(node.status, node.riskScore),
          };
        })
        .filter(Boolean) as Array<{ id: string; element: HTMLDivElement; x: number; y: number; z: number; width: number; height: number; color: string }>;

      const occupied: Array<{ x: number; y: number; width: number; height: number }> = [];
      placements
        .sort((a, b) => a.y - b.y || a.x - b.x)
        .forEach((placement, index) => {
          let x = Math.max(12, Math.min(width - placement.width - 12, placement.x - placement.width / 2));
          let y = Math.max(12, Math.min(height - placement.height - 12, placement.y + 18));
          const manual = manualLabelPositionsRef.current[placement.id];

          if (manual) {
            x = clampRange(manual.x, 12, Math.max(12, width - placement.width - 12));
            y = clampRange(manual.y, 12, Math.max(12, height - placement.height - 12));
          } else {
            for (let attempt = 0; attempt < 34; attempt += 1) {
              const overlaps = occupied.some((box) => x < box.x + box.width + 8 && x + placement.width + 8 > box.x && y < box.y + box.height + 8 && y + placement.height + 8 > box.y);
              if (!overlaps) break;
              y += 14;
              if (y > height - placement.height - 12) {
                y = Math.max(12, placement.y - placement.height - 22 - attempt * 5);
                x = Math.max(12, Math.min(width - placement.width - 12, x + (index % 2 === 0 ? 18 : -18)));
              }
            }
          }

          occupied.push({ x, y, width: placement.width, height: placement.height });
          labelPositionsRef.current[placement.id] = { x, y };
          placement.element.style.opacity = placement.z > 1 ? '0' : '1';
          placement.element.style.transform = `translate3d(${x}px, ${y}px, 0)`;

          const anchor = cardAnchorTowardPoint({ x, y, width: placement.width, height: placement.height }, placement);
          const midX = (placement.x + anchor.x) / 2;
          const distance = Math.hypot(anchor.x - placement.x, anchor.y - placement.y);
          const lift = clampRange(distance * 0.08, 10, 44);
          const path = `M ${placement.x.toFixed(1)} ${placement.y.toFixed(1)} C ${midX.toFixed(1)} ${(placement.y - lift).toFixed(1)} ${midX.toFixed(1)} ${(anchor.y + lift).toFixed(1)} ${anchor.x.toFixed(1)} ${anchor.y.toFixed(1)}`;
          const connector = connectorRefs.current[placement.id];
          const glow = connectorGlowRefs.current[placement.id];
          const opacity = placement.z > 1 ? '0' : '0.96';
          if (connector) {
            connector.setAttribute('d', path);
            connector.setAttribute('stroke', placement.color);
            connector.style.opacity = opacity;
          }
          if (glow) {
            glow.setAttribute('d', path);
            glow.setAttribute('stroke', placement.color);
            glow.style.opacity = placement.z > 1 ? '0' : '0.22';
          }
        });
    };

    let animationId = 0;
    const clock = new THREE.Clock();
    const animate = () => {
      const elapsed = clock.getElapsedTime();
      root.rotation.y = Math.sin(elapsed * 0.18) * 0.13;
      root.rotation.x = -0.06 + Math.sin(elapsed * 0.14) * 0.025;
      pulses.forEach((pulse, index) => {
        const t = (elapsed * 0.22 + pulse.phase + index * 0.013) % 1;
        pulse.mesh.position.lerpVectors(pulse.from, pulse.to, t);
        const scale = 0.72 + Math.sin(t * Math.PI) * 0.72;
        pulse.mesh.scale.setScalar(scale);
      });
      placeLabels();
      renderer.render(scene, camera);
      animationId = window.requestAnimationFrame(animate);
    };

    const observer = new ResizeObserver(resize);
    observer.observe(mount);
    resize();
    animate();

    return () => {
      window.cancelAnimationFrame(animationId);
      observer.disconnect();
      renderer.dispose();
      nodeGeometry.dispose();
      haloGeometry.dispose();
      pulseGeometry.dispose();
      root.traverse((object) => {
        const mesh = object as THREE.Mesh;
        if (mesh.geometry && mesh.geometry !== nodeGeometry && mesh.geometry !== haloGeometry && mesh.geometry !== pulseGeometry) mesh.geometry.dispose();
        const material = mesh.material;
        if (Array.isArray(material)) material.forEach((item) => item.dispose());
        else if (material) material.dispose();
      });
      renderer.domElement.remove();
    };
  }, [layoutNodes, layoutMap, visibleEdges]);

  return (
    <Panel className="min-h-[620px] p-5">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div>
          <p className="text-[10px] font-black uppercase text-[#FFD36B]">Trust Topology</p>
          <h2 className="mt-1 text-lg font-black">3D Trust Map</h2>
        </div>
        <div className="flex items-center gap-3 text-xs font-black text-slate-500 dark:text-white/45">
          <span>{numberFmt(layoutNodes.length)} nodes</span>
          <span>{numberFmt(visibleEdges.length)} edges</span>
          <Network className="h-5 w-5 text-cyan-300" />
        </div>
      </div>
      <div className="relative min-h-[500px] overflow-hidden rounded-lg border border-slate-200 bg-[#06101f] text-white dark:border-white/10">
        <div className="absolute inset-0 bg-[linear-gradient(135deg,rgba(6,16,31,0.98),rgba(10,22,41,0.96)_55%,rgba(5,12,24,0.98))]" />
        <div ref={mountRef} className="absolute inset-0" />
        <svg className="pointer-events-none absolute inset-0 z-[5] h-full w-full overflow-visible" aria-hidden="true">
          {layoutNodes.map((node) => (
            <g key={`connector-${node.id}`}>
              <path
                ref={(element) => {
                  connectorGlowRefs.current[node.id] = element;
                }}
                d="M0 0 L0 0"
                fill="none"
                stroke={graphColor(node.status, node.riskScore)}
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="10"
                vectorEffect="non-scaling-stroke"
              />
              <path
                ref={(element) => {
                  connectorRefs.current[node.id] = element;
                }}
                d="M0 0 L0 0"
                fill="none"
                stroke={graphColor(node.status, node.riskScore)}
                strokeDasharray="9 13"
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2.6"
                vectorEffect="non-scaling-stroke"
              >
                <animate attributeName="stroke-dashoffset" dur="1.15s" from="44" repeatCount="indefinite" to="0" />
              </path>
            </g>
          ))}
        </svg>
        <div className="pointer-events-none absolute inset-0">
          {layoutNodes.map((node) => (
            <div
              key={node.id}
              role="button"
              tabIndex={0}
              aria-pressed={selectedNodeId === node.id}
              aria-label={`${node.label} ${node.type}`}
              ref={(element) => {
                labelRefs.current[node.id] = element;
              }}
              onPointerDown={(event) => beginDrag(event, node.id)}
              onPointerMove={(event) => moveDrag(event, node.id)}
              onPointerUp={(event) => endDrag(event, node.id)}
              onPointerCancel={(event) => endDrag(event, node.id)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                  event.preventDefault();
                  setSelectedNodeId((current) => current === node.id ? null : node.id);
                }
              }}
              className={cn(
                'pointer-events-auto absolute left-0 top-0 w-[156px] touch-none select-none rounded-lg border border-white/12 bg-slate-950/82 px-3 py-2 text-xs font-black text-white shadow-[0_14px_36px_rgba(0,0,0,0.34)] backdrop-blur-md transition-[opacity,border-color,box-shadow] duration-200 focus:outline-none focus:ring-2 focus:ring-cyan-300/70 active:cursor-grabbing',
                selectedNodeId === node.id ? 'z-20 cursor-grab bg-slate-900/95' : 'z-10 cursor-grab',
              )}
              style={{ borderColor: graphColor(node.status, node.riskScore), boxShadow: `0 0 24px ${graphColor(node.status, node.riskScore)}33` }}
            >
              <div className="truncate">{node.label}</div>
              <div className="mt-1 flex items-center justify-between gap-2 text-[10px] font-bold text-white/64">
                <span className="truncate">{node.type}</span>
                <span className="font-mono">{node.riskScore}</span>
              </div>
              {selectedNodeId === node.id && (
                <div className="mt-2 border-t border-white/10 pt-2 text-[10px] font-bold leading-relaxed text-white/70">
                  <div className="max-h-10 overflow-hidden">{node.detail || 'Recorded trust-state node'}</div>
                  <div className="mt-2 flex items-center justify-between gap-2 uppercase tracking-wider text-white/45">
                    <span className="truncate">{node.status}</span>
                    <span className="truncate">{node.source || graphBucket(node)}</span>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
        {!layoutNodes.length && (
          <div className="absolute inset-0 grid place-items-center text-center">
            <div>
              <Network className="mx-auto h-9 w-9 text-white/30" />
              <div className="mt-3 text-sm font-black text-white/70">Awaiting dependency edges.</div>
            </div>
          </div>
        )}
      </div>
    </Panel>
  );
}

function FindingRow({ finding }: { finding: TrustFinding }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-slate-50/80 p-3 dark:border-white/10 dark:bg-white/[0.035]">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className={cn('rounded-md border px-2 py-1 text-[10px] font-black uppercase tracking-wider', impactTone(finding.gateImpact))}>{finding.gateImpact}</span>
            <span className={cn('rounded-md border px-2 py-1 text-[10px] font-black uppercase tracking-wider', severityTone(finding.severity))}>{finding.severity}</span>
          </div>
          <div className="mt-2 font-bold">{finding.title}</div>
          <p className="mt-1 text-xs font-semibold leading-relaxed text-slate-600 dark:text-white/52">{finding.detail}</p>
        </div>
        <div className="text-right text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-white/38">{compactDate(finding.timestamp)}</div>
      </div>
      <div className="mt-3 grid gap-2 text-xs font-semibold text-slate-600 dark:text-white/52 sm:grid-cols-3">
        <span className="truncate">Owner: {finding.owner}</span>
        <span className="truncate">Asset: {finding.assetName}</span>
        <span className="truncate">Object: {finding.trustObject}</span>
      </div>
    </div>
  );
}

function TrustRecordsTable({ rows }: { rows: TrustRecord[] }) {
  const pageSize = 5;
  const [page, setPage] = useState(1);
  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const paginatedRows = rows.slice((safePage - 1) * pageSize, safePage * pageSize);

  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  return (
    <Panel className="p-0">
      <div className="flex items-center justify-between gap-3 border-b border-slate-200 p-4 dark:border-white/10">
        <div>
          <p className="text-[10px] font-black uppercase tracking-[0.18em] text-cyan-500 dark:text-cyan-300">Trust Inventory</p>
          <h2 className="mt-1 text-lg font-black">Objects Under Migration Gate</h2>
          <div className="mt-1 text-xs font-semibold text-slate-500 dark:text-white/40">
            Showing {rows.length ? `${(safePage - 1) * pageSize + 1}-${Math.min(safePage * pageSize, rows.length)} of ${numberFmt(rows.length)}` : '0'} trust objects
          </div>
        </div>
        <Database className="h-5 w-5 text-[#FFD36B]" />
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[900px] text-left text-xs">
          <thead className="border-b border-slate-200 text-[10px] uppercase tracking-[0.14em] text-slate-500 dark:border-white/10 dark:text-white/38">
            <tr>
              <th className="px-4 py-3">Trust Object</th>
              <th className="px-4 py-3">Owner</th>
              <th className="px-4 py-3">Issuer</th>
              <th className="px-4 py-3">Algorithm</th>
              <th className="px-4 py-3">Gate</th>
              <th className="px-4 py-3 text-right">Risk</th>
            </tr>
          </thead>
          <tbody>
            {paginatedRows.map((row) => (
              <tr key={row.id} className="border-b border-slate-200/70 last:border-b-0 dark:border-white/8">
                <td className="px-4 py-3">
                  <div className="font-bold">{row.name}</div>
                  <div className="mt-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500 dark:text-white/35">{row.kind} - {row.assetName}</div>
                </td>
                <td className="px-4 py-3 text-slate-600 dark:text-white/58">{row.owner}</td>
                <td className="max-w-[180px] truncate px-4 py-3 text-slate-600 dark:text-white/58">{row.issuer}</td>
                <td className="px-4 py-3 font-mono text-slate-700 dark:text-white/70">{row.algorithm}</td>
                <td className="px-4 py-3"><span className={cn('rounded-md border px-2 py-1 text-[10px] font-black uppercase tracking-wider', impactTone(row.gateImpact))}>{row.gateImpact}</span></td>
                <td className="px-4 py-3 text-right font-mono font-black">{row.riskScore}</td>
              </tr>
            ))}
            {!rows.length && (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center font-bold text-slate-500 dark:text-white/38">No trust objects have been discovered yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {rows.length > pageSize && (
        <div className="flex flex-col gap-3 border-t border-slate-200 p-4 dark:border-white/10 sm:flex-row sm:items-center sm:justify-between">
          <div className="text-xs font-semibold text-slate-500 dark:text-white/42">
            Select a page number to view more trust inventory records.
          </div>
          <div className="flex flex-wrap gap-2">
            {Array.from({ length: totalPages }, (_, index) => index + 1).map((pageNumber) => (
              <button
                key={pageNumber}
                type="button"
                onClick={() => setPage(pageNumber)}
                className={cn(
                  'grid h-9 min-w-9 place-items-center rounded-md border px-3 text-xs font-black transition',
                  safePage === pageNumber
                    ? 'border-cyan-400 bg-cyan-400/12 text-cyan-700 dark:border-[#FFD36B] dark:bg-[#FFD36B]/12 dark:text-[#FFD36B]'
                    : 'border-slate-200 bg-white text-slate-600 hover:border-cyan-300 hover:text-cyan-700 dark:border-white/10 dark:bg-white/[0.04] dark:text-white/55 dark:hover:border-[#FFD36B]/45 dark:hover:text-[#FFD36B]',
                )}
                aria-current={safePage === pageNumber ? 'page' : undefined}
              >
                {pageNumber}
              </button>
            ))}
          </div>
        </div>
      )}
    </Panel>
  );
}

export default function TrustStateDiscoveryPage() {
  const { snapshot, loading, error, connected, refresh } = useTrustStateDiscovery();
  const [liveSyncTime, setLiveSyncTime] = useState(() => new Date());
  const gateColor = snapshot.gate.state === 'ready' ? '#34d399' : snapshot.gate.state === 'review' ? '#fbbf24' : '#f87171';

  useEffect(() => {
    const timer = window.setInterval(() => setLiveSyncTime(new Date()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  return (
    <div className="min-h-screen bg-[#f7fafc] px-4 py-4 text-slate-950 sm:px-5 lg:px-6 dark:bg-[#030711] dark:text-white">
      <div className="mx-auto max-w-[1600px] space-y-4">
        <div className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
          <Panel className="p-5">
            <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
              <div className="max-w-3xl">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="inline-flex items-center gap-2 rounded-md border border-cyan-400/35 bg-cyan-400/10 px-3 py-1 text-[10px] font-black uppercase tracking-[0.18em] text-cyan-700 dark:text-cyan-200">
                    <ShieldCheck className="h-3.5 w-3.5" />
                    Trust-State Discovery
                  </span>
                  <span className={cn('inline-flex items-center gap-2 rounded-md border px-3 py-1 text-[10px] font-black uppercase tracking-[0.18em]', connected ? 'border-emerald-400/40 bg-emerald-400/10 text-emerald-300' : 'border-amber-400/40 bg-amber-400/10 text-amber-200')}>
                    <span className={cn('h-1.5 w-1.5 rounded-full', connected ? 'bg-emerald-300' : 'bg-amber-200 animate-pulse')} />
                    {connected ? 'Live SSE' : 'Connecting'}
                  </span>
                </div>
                <h1 className="mt-4 text-3xl font-black tracking-normal sm:text-4xl">Visibility -&gt; Ownership -&gt; Dependencies -&gt; Risk -&gt; Migration Gate</h1>
                <p className="mt-3 max-w-2xl text-sm font-semibold leading-relaxed text-slate-600 dark:text-white/55">
                  Tenant trust estate proofing for PQC migration sequencing across certificates, runtime trust, suppliers, asset ownership, and dependency paths.
                </p>
              </div>
              <div className="flex items-center gap-4">
                <ScoreRing value={snapshot.gate.readiness} tone={gateColor} />
                <div>
                  <StatusPill state={snapshot.gate.state} label={snapshot.gate.label} />
                  <div className="mt-3 text-sm font-black">{snapshot.gate.decision}</div>
                  <div className="mt-1 max-w-xs text-xs font-semibold leading-relaxed text-slate-600 dark:text-white/52">{snapshot.gate.rationale}</div>
                  <button
                    type="button"
                    onClick={() => void refresh()}
                    className="mt-3 inline-flex items-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-2 text-xs font-black text-slate-800 transition hover:border-[#FFD36B] hover:text-[#9b6b00] dark:border-white/12 dark:bg-white/5 dark:text-white/72 dark:hover:text-[#FFD36B]"
                  >
                    <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />
                    Refresh
                  </button>
                </div>
              </div>
            </div>
            {error && (
              <div className="mt-4 rounded-lg border border-red-400/35 bg-red-500/10 px-4 py-3 text-sm font-bold text-red-300">
                {error}
              </div>
            )}
          </Panel>

          <Panel className="p-5">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-[10px] font-black uppercase tracking-[0.18em] text-[#b88700] dark:text-[#FFD36B]">Migration Gate</p>
                <h2 className="mt-1 text-lg font-black">Current Decision</h2>
              </div>
              <LockKeyhole className="h-5 w-5 text-[#FFD36B]" />
            </div>
            <div className="mt-5 grid grid-cols-3 gap-3">
              <div className="rounded-lg border border-slate-200 bg-slate-50/82 p-3 dark:border-white/10 dark:bg-white/[0.035]">
                <div className="text-[10px] font-black uppercase tracking-wider text-slate-500 dark:text-white/38">Blockers</div>
                <div className="mt-2 font-mono text-2xl font-black text-red-500 dark:text-red-300">{numberFmt(snapshot.gate.blockers)}</div>
              </div>
              <div className="rounded-lg border border-slate-200 bg-slate-50/82 p-3 dark:border-white/10 dark:bg-white/[0.035]">
                <div className="text-[10px] font-black uppercase tracking-wider text-slate-500 dark:text-white/38">Reviews</div>
                <div className="mt-2 font-mono text-2xl font-black text-amber-600 dark:text-amber-200">{numberFmt(snapshot.gate.reviews)}</div>
              </div>
              <div className="rounded-lg border border-slate-200 bg-slate-50/82 p-3 dark:border-white/10 dark:bg-white/[0.035]">
                <div className="text-[10px] font-black uppercase tracking-wider text-slate-500 dark:text-white/38">Conflicts</div>
                <div className="mt-2 font-mono text-2xl font-black text-cyan-600 dark:text-cyan-200">{numberFmt(snapshot.gate.migrationConflicts)}</div>
              </div>
            </div>
            <div className="mt-5 text-xs font-semibold leading-relaxed text-slate-600 dark:text-white/52">
              Latest sync: {liveDateTime(liveSyncTime)}. Pipeline: {snapshot.telemetry.eventPipelineStatus.replace(/_/g, ' ')}.
            </div>
          </Panel>
        </div>

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <MetricCard icon={ScanSearch} label="Trust Objects" value={numberFmt(snapshot.metrics.discoveredTrustObjects)} detail="Inventory, certificates, scanner evidence, and runtime observations." tone="border-cyan-400/35 bg-cyan-400/10 text-cyan-500 dark:text-cyan-200" />
          <MetricCard icon={Users} label="Ownership" value={pct(snapshot.metrics.ownershipScore)} detail={`${numberFmt(snapshot.metrics.ownedAssets)} owned assets out of ${numberFmt(snapshot.metrics.activeAssets)} active assets.`} tone="border-emerald-400/35 bg-emerald-400/10 text-emerald-600 dark:text-emerald-300" />
          <MetricCard icon={GitBranch} label="Dependency Edges" value={numberFmt(snapshot.metrics.dependencyEdges)} detail={`${numberFmt(snapshot.metrics.vendors)} vendor readiness records correlated.`} tone="border-violet-400/35 bg-violet-400/10 text-violet-600 dark:text-violet-300" />
          <MetricCard icon={AlertTriangle} label="Risk Score" value={numberFmt(snapshot.metrics.riskScore)} detail={`${numberFmt(snapshot.metrics.highRiskFindings)} high-impact trust findings currently affect the gate.`} tone="border-orange-400/35 bg-orange-400/10 text-orange-600 dark:text-orange-300" />
        </div>

        <WorkflowRail steps={snapshot.workflow} />

        <div className="space-y-4">
          <TrustGraph nodes={snapshot.graph.nodes} edges={snapshot.graph.edges} />

          <Panel className="p-5">
            <div className="mb-4 flex items-center justify-between gap-3">
              <div>
                <p className="text-[10px] font-black uppercase tracking-[0.18em] text-red-500 dark:text-red-300">Gate Findings</p>
                <h2 className="mt-1 text-lg font-black">Blockers and Reviews</h2>
              </div>
              <ShieldAlert className="h-5 w-5 text-red-400" />
            </div>
            <div className="grid max-h-[560px] gap-3 overflow-y-auto pr-1 xl:grid-cols-2">
              {snapshot.findings.slice(0, 8).map((finding) => (
                <div key={finding.id}>
                  <FindingRow finding={finding} />
                </div>
              ))}
              {!snapshot.findings.length && (
                <div className="rounded-lg border border-dashed border-slate-300 p-8 text-center text-sm font-bold text-slate-500 dark:border-white/10 dark:text-white/38 xl:col-span-2">
                  No blocking trust findings are currently open.
                </div>
              )}
            </div>
          </Panel>
        </div>

        <div className="space-y-4">
          <TrustRecordsTable rows={snapshot.trustRecords} />

          <Panel className="p-5">
            <div className="mb-4 flex items-center justify-between gap-3">
              <div>
                <p className="text-[10px] font-black uppercase tracking-[0.18em] text-emerald-600 dark:text-emerald-300">Next Actions</p>
                <h2 className="mt-1 text-lg font-black">Operator Priorities</h2>
              </div>
              <Zap className="h-5 w-5 text-[#FFD36B]" />
            </div>
            <div className="space-y-3">
              {snapshot.recommendations.map((item) => (
                <a key={item.id} href={item.actionHref} className="block rounded-lg border border-slate-200 bg-slate-50/82 p-4 text-inherit no-underline transition hover:border-[#FFD36B] hover:bg-white dark:border-white/10 dark:bg-white/[0.035] dark:hover:bg-white/[0.065]">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <span className={cn('rounded-md border px-2 py-1 text-[10px] font-black uppercase tracking-wider', severityTone(item.severity))}>{item.severity}</span>
                      <div className="mt-3 font-bold">{item.title}</div>
                      <p className="mt-1 text-xs font-semibold leading-relaxed text-slate-600 dark:text-white/52">{item.detail}</p>
                      <div className="mt-3 text-[10px] font-black uppercase tracking-[0.14em] text-cyan-600 dark:text-cyan-200">
                        {item.actionLabel || 'Open Remediation Page'}
                      </div>
                    </div>
                    <ArrowRight className="h-4 w-4 shrink-0 text-slate-400" />
                  </div>
                </a>
              ))}
              {!snapshot.recommendations.length && (
                <div className="rounded-lg border border-dashed border-slate-300 p-8 text-center text-sm font-bold text-slate-500 dark:border-white/10 dark:text-white/38">
                  No operator priorities are open.
                </div>
              )}
            </div>
          </Panel>
        </div>

        <Panel className="p-4">
          <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-bold text-slate-600 dark:text-white/45">
            <span className="inline-flex items-center gap-2"><Activity className="h-4 w-4 text-emerald-400" /> Runtime events: {numberFmt(snapshot.telemetry.runtimeCryptoEvents)}</span>
            <span className="inline-flex items-center gap-2"><KeyRound className="h-4 w-4 text-[#FFD36B]" /> Certificates: {numberFmt(snapshot.telemetry.certificates)}</span>
            <span className="inline-flex items-center gap-2"><Link2 className="h-4 w-4 text-cyan-300" /> Relationships: {numberFmt(snapshot.telemetry.assetRelationships)}</span>
            <span className="inline-flex items-center gap-2"><BadgeCheck className="h-4 w-4 text-violet-300" /> Vendor records: {numberFmt(snapshot.telemetry.vendorAssessments)}</span>
            <span className="inline-flex items-center gap-2"><ScanSearch className="h-4 w-4 text-blue-300" /> Agents: {numberFmt(snapshot.telemetry.scannerAgents)}</span>
          </div>
        </Panel>
      </div>
    </div>
  );
}
