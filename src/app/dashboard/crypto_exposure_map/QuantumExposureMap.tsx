import React, { useEffect, useMemo, useState, useRef, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
  Globe, Server, Database, Shield, AlertTriangle,
  Lock, Cloud, Radio, Info, RefreshCw,
  Search, Layers, Boxes, Network, ScanLine,
  Copy, Check, ShieldAlert, ShieldCheck, GitBranch,
  ArrowRight, ArrowLeft, ArrowUpRight, ExternalLink, Zap
} from 'lucide-react';
import { ExposureNode, ExposureEdge } from '@/lib/dashboard-service';

interface Props {
  data: { nodes: ExposureNode[]; edges: ExposureEdge[] };
  loading: boolean;
  onRefresh?: () => void;
  selectedNode: ExposureNode | null;
  onSelectNode: (node: ExposureNode | null) => void;
}

function getRiskColor(riskScore: number) {
  if (riskScore > 10) return '#ef4444';
  if (riskScore > 5) return '#f97316';
  if (riskScore > 2) return '#eab308';
  if (riskScore > 0) return '#22c55e';
  return '#10b981';
}

const TYPE_ICONS = {
  server: Server,
  api: Radio,
  database: Database,
  application: Globe,
  cloud_resource: Cloud,
  certificate: Shield,
  vault: Lock,
};

const GLASS_PANEL_CLASSES = 'qg-executive-panel group relative overflow-hidden rounded-lg text-white';

type GroupMode = 'none' | 'environment' | 'type';

function seedOf(id: string) {
  return id.split('').reduce((acc, ch) => acc + ch.charCodeAt(0), 0);
}
function clampPos(v: number) {
  return Math.max(4, Math.min(96, v));
}

function computePositions(nodes: ExposureNode[], groupBy: GroupMode): Record<string, { x: number; y: number }> {
  const positions: Record<string, { x: number; y: number }> = {};
  if (groupBy === 'none') {
    nodes.forEach((node) => {
      const seed = seedOf(node.id);
      positions[node.id] = { x: 10 + (seed % 80), y: 10 + ((seed * 1.3) % 80) };
    });
    return positions;
  }
  const keyOf = (n: ExposureNode) => (groupBy === 'environment' ? n.environment : n.type) || 'unknown';
  const groups = Array.from(new Set(nodes.map(keyOf)));
  const centroids: Record<string, { x: number; y: number }> = {};
  groups.forEach((g, i) => {
    const ang = (i / Math.max(1, groups.length)) * Math.PI * 2;
    centroids[g] = { x: 50 + Math.cos(ang) * 30, y: 50 + Math.sin(ang) * 27 };
  });
  nodes.forEach((node) => {
    const c = centroids[keyOf(node)];
    const seed = seedOf(node.id);
    const r = 5 + (seed % 9);
    const a = (seed % 360) * (Math.PI / 180);
    positions[node.id] = { x: clampPos(c.x + Math.cos(a) * r * 0.62), y: clampPos(c.y + Math.sin(a) * r * 0.62) };
  });
  return positions;
}

export default function QuantumExposureMap({ data, loading, onRefresh, selectedNode, onSelectNode }: Props) {
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);

  const [nodePositions, setNodePositions] = useState<Record<string, { x: number; y: number }>>({});

  // Interactive zoom, pan, and dragging state
  const containerRef = useRef<HTMLDivElement>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [draggingNode, setDraggingNode] = useState<string | null>(null);
  const lastMousePos = useRef({ x: 0, y: 0 });

  // Discovery controls
  const [search, setSearch] = useState('');
  const [envFilter, setEnvFilter] = useState<string>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [riskOnly, setRiskOnly] = useState(false);
  const [groupBy, setGroupBy] = useState<GroupMode>('none');
  const [layers, setLayers] = useState({ edges: true, labels: true, pulse: true });

  const environments = useMemo(() => Array.from(new Set(data.nodes.map((n) => n.environment || 'unknown'))).sort(), [data.nodes]);
  const types = useMemo(() => Array.from(new Set(data.nodes.map((n) => n.type || 'unknown'))).sort(), [data.nodes]);

  // Filtered set (which node ids stay fully visible / interactive)
  const visibleIds = useMemo(() => {
    const q = search.trim().toLowerCase();
    const ids = new Set<string>();
    for (const n of data.nodes) {
      if (envFilter !== 'all' && (n.environment || 'unknown') !== envFilter) continue;
      if (typeFilter !== 'all' && (n.type || 'unknown') !== typeFilter) continue;
      if (riskOnly && !(n.riskScore > 0)) continue;
      if (q && !`${n.name} ${n.type} ${n.environment}`.toLowerCase().includes(q)) continue;
      ids.add(n.id);
    }
    return ids;
  }, [data.nodes, search, envFilter, typeFilter, riskOnly]);

  // 1-hop adjacency for risk-propagation / blast-radius highlighting
  const adjacency = useMemo(() => {
    const map = new Map<string, Set<string>>();
    for (const e of data.edges) {
      if (!map.has(e.source)) map.set(e.source, new Set());
      if (!map.has(e.target)) map.set(e.target, new Set());
      map.get(e.source)!.add(e.target);
      map.get(e.target)!.add(e.source);
    }
    return map;
  }, [data.edges]);

  const activeId = hoveredNode || selectedNode?.id || null;
  const activeNeighbors = useMemo(() => {
    if (!activeId) return null;
    const set = new Set<string>([activeId]);
    for (const n of adjacency.get(activeId) || []) set.add(n);
    return set;
  }, [activeId, adjacency]);

  // (Re)compute positions when data or grouping changes.
  useEffect(() => {
    if (data.nodes.length > 0) setNodePositions(computePositions(data.nodes, groupBy));
  }, [data.nodes, groupBy]);

  // Wheel zoom (non-passive to avoid browser blocking)
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const handleWheelRaw = (e: WheelEvent) => {
      e.preventDefault();
      const zoomFactor = 1.08;
      setZoom((z) => (e.deltaY < 0 ? Math.min(z * zoomFactor, 3.5) : Math.max(z / zoomFactor, 0.4)));
    };
    el.addEventListener('wheel', handleWheelRaw, { passive: false });
    return () => el.removeEventListener('wheel', handleWheelRaw);
  }, []);

  const handleNodeMouseDown = useCallback((e: React.MouseEvent, nodeId: string) => {
    e.stopPropagation();
    setDraggingNode(nodeId);
    lastMousePos.current = { x: e.clientX, y: e.clientY };
  }, []);

  const handleBgMouseDown = useCallback((e: React.MouseEvent) => {
    setIsPanning(true);
    lastMousePos.current = { x: e.clientX, y: e.clientY };
  }, []);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    if (draggingNode) {
      const dx = ((e.clientX - lastMousePos.current.x) / rect.width) * 100 / zoom;
      const dy = ((e.clientY - lastMousePos.current.y) / rect.height) * 100 / zoom;
      lastMousePos.current = { x: e.clientX, y: e.clientY };
      setNodePositions((prev) => {
        const pos = prev[draggingNode];
        if (!pos) return prev;
        return { ...prev, [draggingNode]: { x: clampPos(pos.x + dx), y: clampPos(pos.y + dy) } };
      });
    } else if (isPanning) {
      const dx = e.clientX - lastMousePos.current.x;
      const dy = e.clientY - lastMousePos.current.y;
      lastMousePos.current = { x: e.clientX, y: e.clientY };
      setPan((prev) => ({ x: prev.x + dx, y: prev.y + dy }));
    }
  }, [draggingNode, isPanning, zoom]);

  const handleMouseUp = useCallback(() => {
    setDraggingNode(null);
    setIsPanning(false);
  }, []);

  const drawParticles = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const w = (canvas.width = canvas.offsetWidth);
    const h = (canvas.height = canvas.offsetHeight);
    const t = Date.now() * 0.001;
    ctx.clearRect(0, 0, w, h);
    for (let i = 0; i < 40; i++) {
      const x = ((i * 37.7 + t * 15) % (w + 40)) - 20;
      const y = (i * 53.3 + Math.sin(t + i) * 20) % h;
      const alpha = 0.05 + Math.sin(t * 1.5 + i) * 0.03;
      ctx.beginPath();
      ctx.arc(x, y, 1, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(6,182,212,${alpha})`;
      ctx.fill();
    }
    animRef.current = requestAnimationFrame(drawParticles);
  }, []);

  useEffect(() => {
    const prefersReduced = typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    if (prefersReduced) return;
    drawParticles();
    return () => cancelAnimationFrame(animRef.current);
  }, [drawParticles]);

  const totalRisk = useMemo(() => data.nodes.filter((n) => n.riskScore > 5).length, [data.nodes]);

  if (loading && data.nodes.length === 0) {
    return (
      <div className={`h-[520px] flex items-center justify-center ${GLASS_PANEL_CLASSES}`}>
        <div className="text-center">
          <div className="w-12 h-12 border-2 border-cyan-400/30 border-t-cyan-400 rounded-full animate-spin mx-auto mb-4" />
          <p className="text-[10px] text-cyan-300/60 uppercase font-black tracking-widest">Synthesizing Topology…</p>
        </div>
      </div>
    );
  }

  if (!loading && data.nodes.length === 0) {
    return (
      <div className={`h-[520px] flex items-center justify-center p-8 ${GLASS_PANEL_CLASSES}`}>
        <div className="text-center max-w-sm">
          <div className="w-16 h-16 bg-cyan-500/5 border border-cyan-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
            <Globe className="w-8 h-8 text-cyan-300/40" />
          </div>
          <h3 className="text-lg font-black text-white uppercase tracking-tighter mb-2">No Assets Detected</h3>
          <p className="text-white/40 text-sm mb-6">Start a PQC Discovery Scan or import your infrastructure to visualize cryptographic exposure paths.</p>
          <div className="flex gap-3 justify-center">
            <a href="/dashboard/scanner" className="px-4 py-2 bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-[10px] font-black uppercase tracking-widest rounded hover:bg-cyan-500/20 transition-all no-underline">
              Start Discovery
            </a>
            <a href="/dashboard/cbom" className="px-4 py-2 bg-white/5 border border-white/10 text-white/70 text-[10px] font-black uppercase tracking-widest rounded hover:bg-white/10 transition-all no-underline">
              Import CBOM
            </a>
          </div>
        </div>
      </div>
    );
  }

  const shownCount = visibleIds.size;

  return (
    <div className={`flex h-[520px] flex-col ${GLASS_PANEL_CLASSES}`}>
      {/* Control bar */}
      <div className="relative z-30 flex flex-wrap items-center gap-2 border-b border-white/5 bg-white/[0.01] px-3 py-2">
        <div className="relative min-w-[130px] flex-1">
          <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-white/30" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search assets…"
            className="w-full rounded-md border border-white/10 bg-white/[0.03] py-1.5 pl-7 pr-2 text-[11px] text-white/80 outline-none placeholder:text-white/25 focus:border-cyan-400/40"
          />
        </div>
        <select value={envFilter} onChange={(e) => setEnvFilter(e.target.value)} className="rounded-md border border-white/10 bg-[#0b1327] py-1.5 px-2 text-[10px] font-bold uppercase tracking-wide text-white/70 outline-none focus:border-cyan-400/40">
          <option value="all">All environments</option>
          {environments.map((e) => <option key={e} value={e}>{e}</option>)}
        </select>
        <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} className="rounded-md border border-white/10 bg-[#0b1327] py-1.5 px-2 text-[10px] font-bold uppercase tracking-wide text-white/70 outline-none focus:border-cyan-400/40">
          <option value="all">All types</option>
          {types.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <button
          type="button"
          onClick={() => setRiskOnly((v) => !v)}
          className={`inline-flex items-center gap-1 rounded-md border px-2 py-1.5 text-[9px] font-black uppercase tracking-wide transition-colors ${riskOnly ? 'border-red-400/40 bg-red-500/15 text-red-300' : 'border-white/10 bg-white/[0.03] text-white/45 hover:text-white/70'}`}
          title="Show only at-risk nodes"
        >
          <AlertTriangle className="h-3 w-3" /> At risk
        </button>
        <div className="flex items-center gap-1 rounded-md border border-white/10 bg-white/[0.03] p-0.5">
          {([['none', Boxes], ['environment', Globe], ['type', Network]] as Array<[GroupMode, typeof Boxes]>).map(([mode, Icon]) => (
            <button
              key={mode}
              type="button"
              onClick={() => setGroupBy(mode)}
              className={`inline-flex items-center gap-1 rounded px-1.5 py-1 text-[8px] font-black uppercase tracking-wide transition-colors ${groupBy === mode ? 'bg-cyan-500/20 text-cyan-200' : 'text-white/40 hover:text-white/70'}`}
              title={`Group by ${mode}`}
            >
              <Icon className="h-3 w-3" /> {mode === 'none' ? 'Free' : mode === 'environment' ? 'Env' : 'Type'}
            </button>
          ))}
        </div>
        <button onClick={onRefresh} className="ml-auto rounded-md border border-white/10 bg-white/[0.03] p-1.5 text-cyan-300/70 transition-colors hover:text-cyan-300" title="Refresh topology">
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Layer toggles */}
      <div className="relative z-30 flex items-center gap-3 border-b border-white/5 px-3 py-1.5">
        <span className="flex items-center gap-1 text-[8px] font-black uppercase tracking-widest text-white/30"><Layers className="h-3 w-3" /> Layers</span>
        {([['edges', 'Dependencies'], ['labels', 'Labels'], ['pulse', 'Risk pulse']] as Array<[keyof typeof layers, string]>).map(([key, label]) => (
          <button
            key={key}
            type="button"
            onClick={() => setLayers((l) => ({ ...l, [key]: !l[key] }))}
            className={`text-[8px] font-black uppercase tracking-wide transition-colors ${layers[key] ? 'text-cyan-300' : 'text-white/25'}`}
          >
            {layers[key] ? '●' : '○'} {label}
          </button>
        ))}
        <span className="ml-auto flex items-center gap-1 text-[8px] font-mono uppercase tracking-widest text-white/30">
          <ScanLine className="h-3 w-3 text-cyan-300/60" /> {shownCount}/{data.nodes.length} nodes · {totalRisk} high-risk
        </span>
      </div>

      {/* Graph surface */}
      <div
        ref={containerRef}
        className="relative flex-1 cursor-grab select-none overflow-hidden active:cursor-grabbing"
        onMouseDown={handleBgMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        <canvas ref={canvasRef} className="pointer-events-none absolute inset-0 h-full w-full" />

        <svg
          className="relative z-10 h-full w-full"
          viewBox="0 0 100 100"
          preserveAspectRatio="xMidYMid meet"
          style={{
            transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
            transformOrigin: 'center center',
            transition: isPanning ? 'none' : 'transform 0.08s ease-out',
          }}
        >
          {/* Edges */}
          {layers.edges && data.edges.map((edge, i) => {
            const source = nodePositions[edge.source];
            const target = nodePositions[edge.target];
            if (!source || !target) return null;
            const bothVisible = visibleIds.has(edge.source) && visibleIds.has(edge.target);
            const highlighted = activeNeighbors?.has(edge.source) && activeNeighbors?.has(edge.target);
            return (
              <line
                key={`edge-${i}`}
                x1={source.x} y1={source.y}
                x2={target.x} y2={target.y}
                stroke={highlighted ? 'rgba(6,182,212,0.55)' : bothVisible ? 'rgba(148,163,184,0.22)' : 'rgba(148,163,184,0.06)'}
                strokeWidth={highlighted ? 0.45 : 0.2}
                strokeDasharray={highlighted ? 'none' : '1 1'}
              />
            );
          })}

          {/* Nodes */}
          {data.nodes.map((node) => {
            const pos = nodePositions[node.id];
            if (!pos) return null;
            const isHovered = hoveredNode === node.id;
            const isSelected = selectedNode?.id === node.id;
            const isVisible = visibleIds.has(node.id);
            const dimmed = (!isVisible) || (activeNeighbors ? !activeNeighbors.has(node.id) : false);
            const color = getRiskColor(node.riskScore);
            const r = isHovered ? 2.2 : 1.8;
            return (
              <g
                key={node.id}
                className="cursor-pointer"
                style={{ opacity: dimmed ? 0.12 : 1, transition: 'opacity 0.2s' }}
                onMouseEnter={() => isVisible && setHoveredNode(node.id)}
                onMouseLeave={() => setHoveredNode(null)}
                onClick={() => isVisible && onSelectNode(node)}
                onMouseDown={(e) => isVisible && handleNodeMouseDown(e, node.id)}
              >
                {layers.pulse && node.riskScore > 0 && !dimmed && (
                  <circle cx={pos.x} cy={pos.y} r={r * 2.5} fill="none" stroke={color} strokeWidth="0.1" opacity={isHovered ? 0.6 : 0.2}>
                    <animate attributeName="r" values={`${r * 2};${r * 3};${r * 2}`} dur="3s" repeatCount="indefinite" />
                    <animate attributeName="opacity" values="0.3;0.05;0.3" dur="3s" repeatCount="indefinite" />
                  </circle>
                )}
                <circle cx={pos.x} cy={pos.y} r={r} fill={`${color}20`} stroke={isSelected ? '#06B6D4' : color} strokeWidth={isSelected ? 0.6 : 0.3} />
                <circle cx={pos.x} cy={pos.y} r={r * 0.3} fill={color} opacity={isHovered ? 1 : 0.7} />
                {layers.labels && (
                  <text
                    x={pos.x} y={pos.y + r + 2.5}
                    textAnchor="middle"
                    fill={isHovered ? 'var(--qg-dashboard-text)' : 'var(--qg-dashboard-text-muted)'}
                    fontSize="1.8" fontFamily="monospace" fontWeight="bold"
                  >
                    {node.name.length > 15 ? node.name.slice(0, 12) + '…' : node.name}
                  </text>
                )}
              </g>
            );
          })}
        </svg>

        {/* Zoom & pan controls */}
        <div className="absolute left-3 bottom-3 z-20 flex flex-col gap-1.5">
          {[['＋', () => setZoom((z) => Math.min(z * 1.15, 3.5))], ['－', () => setZoom((z) => Math.max(z / 1.15, 0.4))], ['☉', () => { setZoom(1); setPan({ x: 0, y: 0 }); }]].map(([label, fn], i) => (
            <button
              key={i}
              onClick={(e) => { e.stopPropagation(); (fn as () => void)(); }}
              onMouseDown={(e) => e.stopPropagation()}
              className="flex h-7 w-7 select-none items-center justify-center rounded border border-cyan-500/30 bg-black/75 text-xs font-bold text-cyan-300 transition-all hover:bg-cyan-500/15"
            >
              {label as string}
            </button>
          ))}
        </div>

        {/* Legend */}
        <div className="absolute bottom-3 right-3 z-20 flex gap-3 text-[8px] font-bold uppercase tracking-widest">
          <div className="flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-red-500" /> Critical</div>
          <div className="flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-orange-500" /> High</div>
          <div className="flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-yellow-500" /> Moderate</div>
          <div className="flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-green-500" /> Secure</div>
        </div>
      </div>
    </div>
  );
}

interface InspectorProps {
  selectedNode: ExposureNode | null;
  /** Full exposure map — used to resolve real dependency / blast-radius detail. */
  exposureMap?: { nodes: ExposureNode[]; edges: ExposureEdge[] };
}

/** Severity buckets aligned exactly with the graph's node colouring + legend. */
type SeverityKey = 'critical' | 'high' | 'moderate' | 'secure';
interface Severity {
  key: SeverityKey;
  label: string;
  hex: string;
  /** 0 = Secure … 3 = Critical — the active segment on the posture meter. */
  index: number;
  text: string;
  border: string;
  bg: string;
  Icon: typeof Shield;
}

function severityOf(riskScore: number): Severity {
  if (riskScore > 10) return { key: 'critical', label: 'Critical', hex: '#ef4444', index: 3, text: 'text-red-400', border: 'border-red-500/30', bg: 'bg-red-500/10', Icon: ShieldAlert };
  if (riskScore > 5) return { key: 'high', label: 'High', hex: '#f97316', index: 2, text: 'text-orange-400', border: 'border-orange-500/30', bg: 'bg-orange-500/10', Icon: ShieldAlert };
  if (riskScore > 2) return { key: 'moderate', label: 'Moderate', hex: '#eab308', index: 1, text: 'text-yellow-400', border: 'border-yellow-500/30', bg: 'bg-yellow-500/10', Icon: Shield };
  return { key: 'secure', label: 'Secure', hex: '#22c55e', index: 0, text: 'text-emerald-400', border: 'border-emerald-500/30', bg: 'bg-emerald-500/10', Icon: ShieldCheck };
}

const EXPOSURE_READ: Record<SeverityKey, string> = {
  critical: 'Critical quantum exposure. Unresolved cryptographic risk on this asset — prioritise it for post-quantum migration.',
  high: 'Elevated quantum exposure. Legacy or expiring cryptography detected — schedule a migration to quantum-safe algorithms.',
  moderate: 'Moderate exposure. Monitor for cryptographic drift and plan a migration within the current cycle.',
  secure: 'No significant quantum exposure detected. Maintain monitoring and scheduled key rotation.',
};

const RECOMMENDED_ACTION: Record<SeverityKey, string> = {
  critical: 'Migrate key establishment to ML-KEM-768 (FIPS 203) and signatures to ML-DSA-65 (FIPS 204). Run a hybrid X25519 + ML-KEM profile through cutover.',
  high: 'Stage a hybrid X25519 + ML-KEM rollout and rotate certificates onto quantum-safe chains before legacy material expires.',
  moderate: 'Enable crypto-agility controls and pilot a hybrid X25519 + ML-KEM configuration ahead of full migration.',
  secure: 'Maintain the quantum-safe posture. Continue drift monitoring and periodic key rotation.',
};

const REL_LABELS: Record<string, string> = {
  depends_on: 'depends on',
  used_by: 'used by',
  connects_to: 'connects to',
  secures: 'secures',
  authenticates: 'authenticates',
  routes_to: 'routes to',
};

function relLabel(type?: string): string {
  const key = String(type || '').toLowerCase();
  return REL_LABELS[key] || (key ? key.replace(/_/g, ' ') : 'linked');
}

interface Connection {
  id: string;
  name: string;
  direction: 'out' | 'in';
  relationship: string;
  severity: Severity;
}

export function NodeInspector({ selectedNode, exposureMap }: InspectorProps) {
  const [copied, setCopied] = useState(false);

  useEffect(() => { setCopied(false); }, [selectedNode?.id]);

  // Resolve real dependency / blast-radius detail from the exposure-map edges.
  const connections = useMemo<Connection[]>(() => {
    if (!selectedNode || !exposureMap) return [];
    const byId = new Map(exposureMap.nodes.map((n) => [n.id, n] as const));
    const rows: Connection[] = [];
    for (const edge of exposureMap.edges) {
      const isOut = edge.source === selectedNode.id;
      const isIn = edge.target === selectedNode.id;
      if (!isOut && !isIn) continue;
      const peerId = isOut ? edge.target : edge.source;
      const peer = byId.get(peerId);
      rows.push({
        id: peerId,
        name: peer?.name || peerId,
        direction: isOut ? 'out' : 'in',
        relationship: relLabel(edge.type),
        severity: severityOf(peer?.riskScore ?? 0),
      });
    }
    // De-duplicate on peer + direction, keep highest-severity edges first.
    const seen = new Set<string>();
    return rows
      .filter((r) => { const k = `${r.direction}:${r.id}`; if (seen.has(k)) return false; seen.add(k); return true; })
      .sort((a, b) => b.severity.index - a.severity.index);
  }, [selectedNode, exposureMap]);

  const copyId = useCallback(() => {
    if (!selectedNode) return;
    navigator.clipboard?.writeText(selectedNode.id).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    }).catch(() => { /* clipboard unavailable — non-fatal */ });
  }, [selectedNode]);

  if (!selectedNode) {
    return (
      <div className={`p-5 flex flex-col h-full ${GLASS_PANEL_CLASSES}`}>
        <div className="flex-1 flex flex-col items-center justify-center text-center px-6">
          <div className="w-14 h-14 rounded-full border border-cyan-500/20 bg-cyan-500/[0.06] flex items-center justify-center mb-4">
            <Info className="w-6 h-6 text-cyan-300/70" />
          </div>
          <p className="text-[11px] uppercase font-black tracking-widest text-white/50">Select an Asset</p>
          <p className="mt-2 text-[10px] text-white/30 leading-relaxed max-w-[220px]">
            Click a node on the exposure graph to inspect its quantum risk posture, dependencies, and recommended action.
          </p>
        </div>
      </div>
    );
  }

  const sev = severityOf(selectedNode.riskScore);
  const SEGMENTS: Array<{ key: SeverityKey; label: string; hex: string }> = [
    { key: 'secure', label: 'Secure', hex: '#22c55e' },
    { key: 'moderate', label: 'Moderate', hex: '#eab308' },
    { key: 'high', label: 'High', hex: '#f97316' },
    { key: 'critical', label: 'Critical', hex: '#ef4444' },
  ];
  const statusRaw = String(selectedNode.status || '').toLowerCase();
  const statusDot = statusRaw === 'migrated' || statusRaw === 'protected'
    ? '#10b981'
    : statusRaw === 'active'
      ? '#06b6d4'
      : '#eab308';
  const shortId = selectedNode.id.length > 14 ? `${selectedNode.id.slice(0, 8)}…${selectedNode.id.slice(-4)}` : selectedNode.id;
  const AssetIcon = TYPE_ICONS[selectedNode.type as keyof typeof TYPE_ICONS] || Server;
  const shownConnections = connections.slice(0, 5);

  return (
    <div className={`p-5 flex flex-col h-full ${GLASS_PANEL_CLASSES}`}>
      <div className="flex-1 overflow-y-auto space-y-4 custom-scrollbar pr-1">
        {/* Identity */}
        <div className="flex items-start gap-3">
          <div className="w-11 h-11 shrink-0 rounded-lg bg-cyan-500/10 border border-cyan-500/25 flex items-center justify-center">
            <AssetIcon className="w-[22px] h-[22px] text-cyan-300" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className="text-sm font-bold text-white leading-tight truncate" title={selectedNode.name}>{selectedNode.name}</span>
              <span className="inline-flex items-center gap-1 shrink-0" title={`Status: ${selectedNode.status}`}>
                <span className="h-1.5 w-1.5 rounded-full" style={{ background: statusDot, boxShadow: `0 0 6px ${statusDot}` }} />
                <span className="text-[9px] font-black uppercase tracking-widest text-white/50">{selectedNode.status}</span>
              </span>
            </div>
            <div className="mt-1 flex items-center gap-2">
              <span className="text-[10px] text-white/45 font-mono uppercase tracking-wide truncate">{String(selectedNode.type).replace(/_/g, ' ')}</span>
              <button
                type="button"
                onClick={copyId}
                title="Copy asset ID"
                className="inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-1.5 py-0.5 font-mono text-[9px] text-white/40 transition-all hover:border-cyan-400/30 hover:text-cyan-300"
              >
                {copied ? <Check className="h-2.5 w-2.5 text-emerald-400" /> : <Copy className="h-2.5 w-2.5" />}
                {copied ? 'Copied' : shortId}
              </button>
            </div>
          </div>
        </div>

        {/* Signature — Quantum Risk Posture band */}
        <div className={`rounded-xl border ${sev.border} ${sev.bg} p-3.5`}>
          <div className="flex items-center justify-between">
            <span className="text-[9px] font-black uppercase tracking-[0.2em] text-white/45">Quantum Risk Posture</span>
            <span className={`inline-flex items-center gap-1 rounded-full border ${sev.border} px-2 py-0.5 text-[9px] font-black uppercase tracking-widest ${sev.text}`}>
              <sev.Icon className="h-3 w-3" /> {sev.label}
            </span>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-black leading-none" style={{ color: sev.hex }}>{selectedNode.riskScore.toFixed(1)}</span>
            <span className="text-[9px] font-bold uppercase tracking-widest text-white/35">exposure index</span>
          </div>
          {/* 4-segment severity meter — mirrors the graph legend */}
          <div className="mt-3 flex gap-1">
            {SEGMENTS.map((seg, i) => {
              const active = i === sev.index;
              const reached = i <= sev.index;
              return (
                <div key={seg.key} className="flex-1">
                  <div
                    className="h-1.5 rounded-full transition-all"
                    style={{ background: reached ? seg.hex : 'rgba(255,255,255,0.08)', opacity: reached ? (active ? 1 : 0.35) : 1 }}
                  />
                  <div className={`mt-1 text-center text-[7px] font-bold uppercase tracking-wider ${active ? sev.text : 'text-white/25'}`}>{seg.label}</div>
                </div>
              );
            })}
          </div>
          <p className="mt-3 text-[10px] leading-relaxed text-white/55">{EXPOSURE_READ[sev.key]}</p>
        </div>

        {/* Asset attributes */}
        <div>
          <div className="text-[9px] text-white/30 font-black uppercase tracking-[0.2em] mb-2">Asset Attributes</div>
          <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-white/5 bg-white/5">
            {[
              { label: 'Environment', value: selectedNode.environment },
              { label: 'Criticality', value: selectedNode.criticality },
              { label: 'Asset Type', value: String(selectedNode.type).replace(/_/g, ' ') },
              { label: 'Status', value: selectedNode.status },
            ].map((attr) => (
              <div key={attr.label} className="bg-[#0a0f1a] px-3 py-2.5">
                <div className="text-[8px] text-white/30 font-bold uppercase tracking-widest">{attr.label}</div>
                <div className="mt-0.5 text-[11px] font-semibold text-white/80 truncate capitalize" title={String(attr.value)}>{attr.value}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Connected assets — real blast radius from the exposure edges */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="inline-flex items-center gap-1.5 text-[9px] text-white/30 font-black uppercase tracking-[0.2em]">
              <GitBranch className="h-3 w-3 text-cyan-300/70" /> Connected Assets
            </span>
            <span className="text-[9px] font-mono text-white/35">{connections.length} {connections.length === 1 ? 'link' : 'links'}</span>
          </div>
          {connections.length === 0 ? (
            <div className="rounded-lg border border-white/5 bg-white/[0.02] px-3 py-2.5 text-[10px] text-white/35 leading-relaxed">
              No mapped dependencies. This asset is not linked to others in the current exposure graph.
            </div>
          ) : (
            <div className="space-y-1.5">
              {shownConnections.map((c) => (
                <div key={`${c.direction}:${c.id}`} className="flex items-center gap-2 rounded-lg border border-white/5 bg-white/[0.03] px-2.5 py-2">
                  {c.direction === 'out'
                    ? <ArrowRight className="h-3 w-3 shrink-0 text-cyan-300/70" />
                    : <ArrowLeft className="h-3 w-3 shrink-0 text-violet-300/70" />}
                  <span className="min-w-0 flex-1 truncate text-[11px] font-semibold text-white/75" title={c.name}>{c.name}</span>
                  <span className="shrink-0 text-[8px] font-medium uppercase tracking-wide text-white/35">{c.relationship}</span>
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: c.severity.hex }} title={`${c.severity.label} risk`} />
                </div>
              ))}
              {connections.length > shownConnections.length && (
                <div className="pt-0.5 text-center text-[9px] font-bold uppercase tracking-widest text-white/30">
                  +{connections.length - shownConnections.length} more in asset profile
                </div>
              )}
            </div>
          )}
        </div>

        {/* Recommended action */}
        <div>
          <div className="inline-flex items-center gap-1.5 text-[9px] text-white/30 font-black uppercase tracking-[0.2em] mb-2">
            <Zap className="h-3 w-3 text-cyan-300/70" /> Recommended Action
          </div>
          <div className="rounded-lg border border-cyan-500/15 bg-cyan-500/[0.06] p-3 text-[10px] leading-relaxed text-cyan-100/70">
            {RECOMMENDED_ACTION[sev.key]}
          </div>
        </div>
      </div>

      {/* Asset-detail actions */}
      <div className="mt-4 shrink-0 space-y-2 border-t border-white/5 pt-4">
        <a
          href={`/dashboard/assets?asset=${encodeURIComponent(selectedNode.id)}`}
          className="flex w-full items-center justify-between rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-4 py-2.5 text-[10px] font-black uppercase tracking-[0.18em] text-cyan-200 no-underline transition-all hover:bg-cyan-500/20"
        >
          <span className="inline-flex items-center gap-2"><Layers className="h-3.5 w-3.5" /> View Full Asset Profile</span>
          <ArrowUpRight className="h-4 w-4" />
        </a>
        <div className="grid grid-cols-3 gap-1.5">
          {[
            { label: 'Risk', title: 'Risk breakdown', href: '/dashboard/quantum-risk-scoring', Icon: ShieldAlert },
            { label: 'Exposure', title: 'Exposure path & blast radius', href: '/dashboard/quantum-readiness/exposure-graph', Icon: GitBranch },
            { label: 'CBOM', title: 'Cryptographic bill of materials', href: '/dashboard/cbom_explorer', Icon: Boxes },
          ].map((link) => (
            <a
              key={link.label}
              href={link.href}
              title={link.title}
              className="flex flex-col items-center gap-1 rounded-lg border border-white/8 bg-white/[0.03] px-2 py-2 text-[9px] font-bold uppercase tracking-wide text-white/50 no-underline transition-all hover:border-cyan-400/30 hover:text-cyan-300"
            >
              <link.Icon className="h-3.5 w-3.5" />
              {link.label}
            </a>
          ))}
        </div>
        <a
          href="/dashboard/assets"
          className="flex items-center justify-center gap-1.5 text-[9px] font-bold uppercase tracking-widest text-white/25 no-underline transition-colors hover:text-white/50"
        >
          <ExternalLink className="h-2.5 w-2.5" /> Open asset inventory
        </a>
      </div>
    </div>
  );
}
