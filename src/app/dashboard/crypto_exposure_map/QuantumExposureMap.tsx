import React, { useEffect, useState, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Globe, Server, Database, Shield, AlertTriangle,
  Lock, Unlock, Wifi, Cloud, Radio, Eye, Info, RefreshCw
} from 'lucide-react';
import { ExposureNode, ExposureEdge, dashboardService } from '@/lib/dashboard-service';

interface Props {
  data: { nodes: ExposureNode[]; edges: ExposureEdge[] };
  loading: boolean;
  onRefresh?: () => void;
  selectedNode: ExposureNode | null;
  onSelectNode: (node: ExposureNode | null) => void;
}

function getRiskColor(riskScore: number) {
  if (riskScore > 10) return '#ef4444'; // Scale might be different, adjusting
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

export default function QuantumExposureMap({ data, loading, onRefresh, selectedNode, onSelectNode }: Props) {
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);

  // Simple layout simulation (randomish but grouped by environment)
  const [nodePositions, setNodePositions] = useState<Record<string, { x: number, y: number }>>({});

  // Interactive zoom, pan, and dragging state variables
  const containerRef = useRef<HTMLDivElement>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [draggingNode, setDraggingNode] = useState<string | null>(null);
  const lastMousePos = useRef({ x: 0, y: 0 });

  useEffect(() => {
    if (data.nodes.length > 0) {
      const positions: Record<string, { x: number, y: number }> = {};
      data.nodes.forEach((node, i) => {
        // Deterministic random positions based on ID
        const seed = node.id.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
        const x = 10 + (seed % 80);
        const y = 10 + ((seed * 1.3) % 80);
        positions[node.id] = { x, y };
      });
      setNodePositions(positions);
    }
  }, [data.nodes]);

  // Attach mouse wheel zoom event listener directly (avoids passive listener browser blocks)
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    
    const handleWheelRaw = (e: WheelEvent) => {
      e.preventDefault();
      const zoomFactor = 1.08;
      setZoom(z => {
        if (e.deltaY < 0) {
          return Math.min(z * zoomFactor, 3.5);
        } else {
          return Math.max(z / zoomFactor, 0.4);
        }
      });
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
      // Convert raw pixel movement to viewBox coordinates adjusted by the zoom level
      const dx = ((e.clientX - lastMousePos.current.x) / rect.width) * 100 / zoom;
      const dy = ((e.clientY - lastMousePos.current.y) / rect.height) * 100 / zoom;
      
      lastMousePos.current = { x: e.clientX, y: e.clientY };
      
      setNodePositions(prev => {
        const pos = prev[draggingNode];
        if (!pos) return prev;
        return {
          ...prev,
          [draggingNode]: {
            x: Math.max(2, Math.min(98, pos.x + dx)),
            y: Math.max(2, Math.min(98, pos.y + dy))
          }
        };
      });
    } else if (isPanning) {
      const dx = e.clientX - lastMousePos.current.x;
      const dy = e.clientY - lastMousePos.current.y;
      lastMousePos.current = { x: e.clientX, y: e.clientY };
      setPan(prev => ({ x: prev.x + dx, y: prev.y + dy }));
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
    const w = canvas.width = canvas.offsetWidth;
    const h = canvas.height = canvas.offsetHeight;
    const t = Date.now() * 0.001;

    ctx.clearRect(0, 0, w, h);

    for (let i = 0; i < 40; i++) {
      const x = ((i * 37.7 + t * 15) % (w + 40)) - 20;
      const y = ((i * 53.3 + Math.sin(t + i) * 20) % h);
      const alpha = 0.05 + Math.sin(t * 1.5 + i) * 0.03;
      ctx.beginPath();
      ctx.arc(x, y, 1, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(6,182,212,${alpha})`;
      ctx.fill();
    }

    animRef.current = requestAnimationFrame(drawParticles);
  }, []);

  useEffect(() => {
    drawParticles();
    return () => cancelAnimationFrame(animRef.current);
  }, [drawParticles]);

  if (loading && data.nodes.length === 0) {
    return (
      <div className={`h-[500px] flex items-center justify-center ${GLASS_PANEL_CLASSES}`}>
        <div className="text-center">
          <div className="w-12 h-12 border-2 border-gold/30 border-t-gold rounded-full animate-spin mx-auto mb-4" />
          <p className="text-[10px] text-gold/50 uppercase font-black tracking-widest">Synthesizing Topology...</p>
        </div>
      </div>
    );
  }

  if (!loading && data.nodes.length === 0) {
    return (
      <div className={`h-[500px] flex items-center justify-center p-8 ${GLASS_PANEL_CLASSES}`}>
        <div className="text-center max-w-sm">
          <div className="w-16 h-16 bg-gold/5 border border-gold/20 rounded-full flex items-center justify-center mx-auto mb-6">
            <Globe className="w-8 h-8 text-gold/30" />
          </div>
          <h3 className="text-lg font-black text-white uppercase tracking-tighter mb-2">No Assets Detected</h3>
          <p className="text-white/40 text-sm mb-6">Start a PQC Discovery Scan or import your infrastructure to visualize cryptographic exposure paths.</p>
          <div className="flex gap-3 justify-center">
            <button className="px-4 py-2 bg-gold/10 border border-gold/30 text-gold text-[10px] font-black uppercase tracking-widest rounded hover:bg-gold/20 transition-all">
              Start Discovery
            </button>
            <button className="px-4 py-2 bg-white/5 border border-white/10 text-white/70 text-[10px] font-black uppercase tracking-widest rounded hover:bg-white/10 transition-all">
              Import CBOM
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div 
      ref={containerRef}
      className={`w-full h-[500px] cursor-grab active:cursor-grabbing select-none relative overflow-hidden ${GLASS_PANEL_CLASSES}`}
      onMouseDown={handleBgMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
    >
      <canvas ref={canvasRef} className="absolute inset-0 w-full h-full pointer-events-none" />
      
      <div className="absolute top-4 left-4 z-20 flex gap-2">
          <button onClick={onRefresh} className={`p-2 hover:transition-colors ${GLASS_PANEL_CLASSES.replace('rounded-xl', 'rounded')}`}>
              <RefreshCw className={`w-3.5 h-3.5 text-gold/60 group-hover:text-gold ${loading ? 'animate-spin' : ''}`} />
          </button>
      </div>

      <svg 
        className="w-full h-full relative z-10" 
        viewBox="0 0 100 100" 
        preserveAspectRatio="xMidYMid meet"
        style={{
          transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
          transformOrigin: 'center center',
          transition: isPanning ? 'none' : 'transform 0.08s ease-out'
        }}
      >
        {/* Edges */}
        {data.edges.map((edge, i) => {
          const source = nodePositions[edge.source];
          const target = nodePositions[edge.target];
          if (!source || !target) return null;
          const isHighlighted = hoveredNode === edge.source || hoveredNode === edge.target;
          return (
            <line
              key={`edge-${i}`}
              x1={source.x} y1={source.y}
              x2={target.x} y2={target.y}
              stroke={isHighlighted ? 'rgba(6,182,212,0.4)' : 'rgba(148,163,184,0.22)'}
              strokeWidth={isHighlighted ? 0.4 : 0.2}
              strokeDasharray={isHighlighted ? 'none' : '1 1'}
            />
          );
        })}

        {/* Nodes */}
        {data.nodes.map(node => {
          const pos = nodePositions[node.id];
          if (!pos) return null;
          const isHovered = hoveredNode === node.id;
          const isSelected = selectedNode?.id === node.id;
          const color = getRiskColor(node.riskScore);
          const r = isHovered ? 2.2 : 1.8;

          return (
            <g
              key={node.id}
              className="cursor-pointer"
              onMouseEnter={() => setHoveredNode(node.id)}
              onMouseLeave={() => setHoveredNode(null)}
              onClick={() => onSelectNode(node)}
              onMouseDown={(e) => handleNodeMouseDown(e, node.id)}
            >
              {node.riskScore > 0 && (
                <circle
                  cx={pos.x} cy={pos.y} r={r * 2.5}
                  fill="none" stroke={color} strokeWidth="0.1"
                  opacity={isHovered ? 0.6 : 0.2}
                >
                  <animate attributeName="r" values={`${r*2};${r*3};${r*2}`} dur="3s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.3;0.05;0.3" dur="3s" repeatCount="indefinite" />
                </circle>
              )}
              <circle
                cx={pos.x} cy={pos.y} r={r}
                fill={`${color}20`}
                stroke={isSelected ? '#06B6D4' : color}
                strokeWidth={isSelected ? 0.6 : 0.3}
              />
              <circle
                  cx={pos.x} cy={pos.y} r={r * 0.3}
                  fill={color}
                  opacity={isHovered ? 1 : 0.7}
                />
              <text
                x={pos.x} y={pos.y + r + 2.5}
                textAnchor="middle"
                fill={isHovered ? 'var(--qg-dashboard-text)' : 'var(--qg-dashboard-text-muted)'}
                fontSize="1.8"
                fontFamily="monospace"
                fontWeight="bold"
              >
                {node.name.length > 15 ? node.name.slice(0, 12) + '...' : node.name}
              </text>
            </g>
          );
        })}
      </svg>

      {/* Floating Zoom & Pan Controls overlay */}
      {!loading && data.nodes.length > 0 && (
        <div className="absolute left-4 bottom-4 z-20 flex flex-col gap-1.5">
          <button
            onClick={(e) => {
              e.stopPropagation();
              setZoom(z => Math.min(z * 1.15, 3.5));
            }}
            onMouseDown={e => e.stopPropagation()}
            className="w-7 h-7 rounded border border-[#06B6D4]/30 bg-black/75 hover:bg-[#06B6D4]/15 text-[#06B6D4] font-bold text-xs flex items-center justify-center transition-all select-none"
            title="Zoom In"
          >
            ＋
          </button>
          <button
            onClick={(e) => {
              e.stopPropagation();
              setZoom(z => Math.max(z / 1.15, 0.4));
            }}
            onMouseDown={e => e.stopPropagation()}
            className="w-7 h-7 rounded border border-[#06B6D4]/30 bg-black/75 hover:bg-[#06B6D4]/15 text-[#06B6D4] font-bold text-xs flex items-center justify-center transition-all select-none"
            title="Zoom Out"
          >
            －
          </button>
          <button
            onClick={(e) => {
              e.stopPropagation();
              setZoom(1);
              setPan({ x: 0, y: 0 });
            }}
            onMouseDown={e => e.stopPropagation()}
            className="w-7 h-7 rounded border border-[#06B6D4]/30 bg-black/75 hover:bg-[#06B6D4]/15 text-[#06B6D4] font-bold text-xs flex items-center justify-center transition-all select-none"
            title="Reset Zoom & Pan"
          >
            ☉
          </button>
        </div>
      )}

      <div className="absolute bottom-4 right-4 z-20 flex gap-4 text-[8px] font-bold uppercase tracking-widest">
          <div className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-red-500" /> Critical</div>
          <div className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-orange-500" /> High</div>
          <div className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-yellow-500" /> Moderate</div>
          <div className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-green-500" /> Secure</div>
      </div>
    </div>
  );
}

interface InspectorProps {
  selectedNode: ExposureNode | null;
}

export function NodeInspector({ selectedNode }: InspectorProps) {
  return (
    <div className={`p-5 flex flex-col h-full ${GLASS_PANEL_CLASSES}`}>
      {selectedNode ? (
        <div className="flex-1 overflow-y-auto space-y-4 custom-scrollbar pr-1">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded bg-gold/10 border border-gold/20 flex items-center justify-center">
              {(() => {
                  const Icon = TYPE_ICONS[selectedNode.type as keyof typeof TYPE_ICONS] || Server;
                  return <Icon className="w-5 h-5 text-gold" />;
              })()}
            </div>
            <div>
              <div className="text-sm font-bold text-white leading-tight">{selectedNode.name}</div>
              <div className="text-[10px] text-white/40 font-mono uppercase">{selectedNode.type}</div>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2">
              <div className="p-3 rounded-lg bg-white/[0.03] border border-white/5">
                  <div className="text-xs text-white/30 font-bold uppercase mb-1">Risk Score</div>
                  <div className={`text-xl font-black ${getRiskColor(selectedNode.riskScore) === '#ef4444' ? 'text-red-500' : 'text-gold'}`}>
                      {selectedNode.riskScore.toFixed(1)}
                  </div>
              </div>
              <div className="p-3 rounded-lg bg-white/[0.03] border border-white/5">
                  <div className="text-xs text-white/30 font-bold uppercase mb-1">Status</div>
                  <div className="text-xs font-black text-white/80 uppercase">{selectedNode.status}</div>
              </div>
          </div>

          <div className="space-y-2">
              <div className="text-[10px] text-white/30 font-bold uppercase tracking-widest">Environment</div>
              <div className="px-2 py-1 bg-white/5 rounded border border-white/10 text-[10px] font-mono text-white/60 inline-block uppercase">
                  {selectedNode.environment}
              </div>
          </div>

          <div className="space-y-2">
              <div className="text-[10px] text-white/30 font-bold uppercase tracking-widest">Remediation</div>
              <div className="p-3 rounded-lg bg-gold/5 border border-gold/10 text-[10px] text-gold/70 leading-relaxed italic">
                  {selectedNode.riskScore > 5 
                    ? "High-priority upgrade recommended. Migrate to ML-KEM-768 for quantum-safe key encapsulation."
                    : "Low risk detected. Monitor for cryptographic drift and schedule periodic key rotation."}
              </div>
          </div>

          <button className="w-full py-2.5 bg-gold/10 border border-gold/30 text-gold text-[10px] font-black uppercase tracking-[0.2em] rounded-lg hover:bg-gold/20 transition-all mt-4">
              Deploy PQC Agent
          </button>
        </div>
      ) : (
        <div className="flex-1 flex flex-col items-center justify-center text-center opacity-30">
          <Info className="w-8 h-8 mb-4 text-gold" />
          <p className="text-[10px] uppercase font-black tracking-widest">Select Node for Analysis</p>
        </div>
      )}
    </div>
  );
}
