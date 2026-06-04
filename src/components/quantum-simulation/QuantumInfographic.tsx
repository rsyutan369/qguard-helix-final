import React, { useState, useEffect, useLayoutEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Shield, 
  Cpu, 
  Binary, 
  Database, 
  Zap, 
  Activity, 
  Lock, 
  Layers, 
  RefreshCw,
  Sparkles,
  Search,
  BookOpen,
  ArrowRightLeft,
  Settings,
  Flame,
  LineChart,
  HelpCircle
} from 'lucide-react';
// @ts-ignore
import quantumCoreImg from '../../assets/images/quantum_core_isometric_1779965519180.png';

interface InfographicItem {
  id: string;
  num?: number;
  title: string;
  desc: string;
  category: 'core' | 'support' | 'impact';
  hotspot?: { x: number; y: number }; // Percentage coords inside the core image container
  side: 'left' | 'right' | 'top' | 'bottom' | 'impact';
  icon?: React.ReactNode;
}

export default function QuantumInfographic() {
  const [activeId, setActiveId] = useState<string | null>(null);

  const items: InfographicItem[] = [
    // Top supports
    {
      id: 'superposition',
      title: 'SUPERPOSITION',
      desc: 'Qubits can exist in multiple states simultaneously, unlike classical bits.',
      category: 'support',
      side: 'top',
      hotspot: { x: 50, y: 15 },
      icon: <Sparkles className="w-4 h-4 text-cyan-400" />
    },
    {
      id: 'entanglement',
      title: 'QUANTUM ENTANGLEMENT',
      desc: 'Entangled qubits remain linked even across distances, enabling powerful correlated computations.',
      category: 'support',
      side: 'top',
      hotspot: { x: 62, y: 18 },
      icon: <ArrowRightLeft className="w-4 h-4 text-violet-400" />
    },

    // Left core features
    {
      id: 'qubit',
      num: 1,
      title: 'QUBIT (QUANTUM BIT)',
      desc: 'The basic unit of quantum information. Unlike classical bits, qubits can be in a superposition of 0 and 1.',
      category: 'core',
      side: 'left',
      hotspot: { x: 37, y: 27 },
      icon: <Cpu className="w-4 h-4 text-cyan-400" />
    },
    {
      id: 'cryo_left',
      num: 2,
      title: 'CRYOGENIC COOLING SYSTEM',
      desc: 'Maintains ultra-low temperatures near absolute zero to preserve qubit coherence.',
      category: 'core',
      side: 'left',
      hotspot: { x: 28, y: 42 },
      icon: <RefreshCw className="w-4 h-4 text-blue-400" />
    },
    {
      id: 'enc_algo',
      num: 3,
      title: 'ENCRYPTION ALGORITHM',
      desc: 'Advanced quantum algorithms like Shor\'s, Grover\'s, and QFT power ultra-secure encryption.',
      category: 'core',
      side: 'left',
      hotspot: { x: 45, y: 50 },
      icon: <Lock className="w-4 h-4 text-indigo-400" />
    },
    {
      id: 'data_in',
      num: 4,
      title: 'DATA INPUT',
      desc: 'Raw data is encoded into qubits and prepared for quantum processing.',
      category: 'core',
      side: 'left',
      hotspot: { x: 24, y: 67 },
      icon: <Binary className="w-4 h-4 text-teal-400" />
    },

    // Bottom items
    {
      id: 'dec_proc',
      num: 5,
      title: 'DECRYPTION PROCESS',
      desc: 'Quantum algorithms reverse encryption using quantum keys for authorized access.',
      category: 'core',
      side: 'bottom',
      hotspot: { x: 42, y: 69 },
      icon: <UnlockIcon />
    },
    {
      id: 'supremacy',
      num: 6,
      title: 'QUANTUM SUPREMACY',
      desc: 'Quantum systems solve problems classical computers cannot in practical timeframes.',
      category: 'core',
      side: 'bottom',
      hotspot: { x: 55, y: 72 },
      icon: <Zap className="w-4 h-4 text-amber-400" />
    },
    {
      id: 'shors_algo',
      num: 12,
      title: 'SHOR\'S ALGORITHM',
      desc: 'A quantum algorithm that can factor large numbers exponentially faster than classical algorithms, potentially breaking RSA encryption.',
      category: 'core',
      side: 'bottom',
      icon: <Layers className="w-4 h-4 text-indigo-400" />
    },
    {
      id: 'decoherence',
      num: 13,
      title: 'DECOHERENCE',
      desc: 'The loss of quantum information due to environmental interactions is one of the biggest challenges in building stable and scalable quantum systems.',
      category: 'core',
      side: 'bottom',
      icon: <Flame className="w-4 h-4 text-rose-400" />
    },
    {
      id: 'fun_fact',
      title: 'FUN FACT',
      desc: 'Some quantum computers require temperatures colder than outer space to operate!',
      category: 'support',
      side: 'bottom',
      icon: <HelpCircle className="w-4 h-4 text-amber-400" />
    },

    // Right core features
    {
      id: 'data_out',
      num: 7,
      title: 'DATA OUTPUT',
      desc: 'Decrypted results are measured and converted back to classical data.',
      category: 'core',
      side: 'right',
      hotspot: { x: 76, y: 69 },
      icon: <Database className="w-4 h-4 text-pink-400" />
    },
    {
      id: 'enc_proc',
      num: 8,
      title: 'ENCRYPTION PROCESS',
      desc: 'Quantum algorithms process data using complex superpositions for secure encryption.',
      category: 'core',
      side: 'right',
      hotspot: { x: 74, y: 54 },
      icon: <Shield className="w-4 h-4 text-emerald-400" />
    },
    {
      id: 'control_laser',
      num: 9,
      title: 'CONTROL LASER',
      desc: 'Precise laser pulses control qubit states and quantum operations.',
      category: 'core',
      side: 'right',
      hotspot: { x: 71, y: 45 },
      icon: <Activity className="w-4 h-4 text-red-400" />
    },
    {
      id: 'cryo_right',
      num: 10,
      title: 'CRYOGENIC COOLING SYSTEM',
      desc: 'Maintains ultra-low temperatures near absolute zero to preserve qubit.',
      category: 'core',
      side: 'right',
      hotspot: { x: 74, y: 28 },
      icon: <RefreshCw className="w-4 h-4 text-violet-400" />
    },
    {
      id: 'quantum_gate',
      num: 11,
      title: 'QUANTUM GATE',
      desc: 'Manipulates qubits using quantum operations to perform complex calculations.',
      category: 'core',
      side: 'right',
      hotspot: { x: 57, y: 22 },
      icon: <Settings className="w-4 h-4 text-fuchsia-400" />
    },

    // Bottom Impact Section
    {
      id: 'cybersecurity',
      num: 14,
      title: 'CYBERSECURITY',
      desc: 'Stronger encryption and threat detection systems designed to defend against next-gen cyber warfare.',
      category: 'impact',
      side: 'impact',
      icon: <Shield className="w-5 h-5 text-indigo-400" />
    },
    {
      id: 'drug_discovery',
      num: 15,
      title: 'DRUG DISCOVERY',
      desc: 'Simulate molecules and atomic interaction structures to accelerate life-saving medical breakthroughs.',
      category: 'impact',
      side: 'impact',
      icon: <Activity className="w-5 h-5 text-teal-400" />
    },
    {
      id: 'financial_modeling',
      num: 16,
      title: 'FINANCIAL MODELING',
      desc: 'Optimize complex global portfolios, forecast risk matrices, and detect fraud in real-time.',
      category: 'impact',
      side: 'impact',
      icon: <LineChart className="w-5 h-5 text-amber-400" />
    },
    {
      id: 'optimization',
      num: 17,
      title: 'OPTIMIZATION',
      desc: 'Solve hyper-complex logistics routes, resource distribution, and operational efficiency challenges.',
      category: 'impact',
      side: 'impact',
      icon: <Zap className="w-5 h-5 text-cyan-400" />
    },
    {
      id: 'ai_ml',
      num: 18,
      title: 'AI & MACHINE LEARNING',
      desc: 'Enhance sub-symbolic artificial neural network training models using quantum-accelerated feedback loops.',
      category: 'impact',
      side: 'impact',
      icon: <Cpu className="w-5 h-5 text-fuchsia-400" />
    }
  ];

  const [lines, setLines] = useState<{ id: string; d: string; color: string; hoverColor: string; side: string }[]>([]);

  useLayoutEffect(() => {
    const updateLines = () => {
      const container = document.getElementById('quantum-interactive-grid');
      if (!container) return;
      
      const containerRect = container.getBoundingClientRect();
      const calculatedLines: any[] = [];
      
      items.forEach(item => {
        if (!item.hotspot) return;
        
        const card = document.getElementById(`infographic-card-${item.id}`);
        const hotspot = document.getElementById(`infographic-hotspot-${item.id}`);
        
        if (!card || !hotspot) return;
        
        const cardRect = card.getBoundingClientRect();
        const hotspotRect = hotspot.getBoundingClientRect();
        
        let startX = 0;
        let startY = cardRect.top + cardRect.height / 2 - containerRect.top;
        
        if (item.side === 'left') {
          startX = cardRect.right - containerRect.left;
        } else if (item.side === 'right') {
          startX = cardRect.left - containerRect.left;
        } else if (item.side === 'top') {
          startX = cardRect.left + cardRect.width / 2 - containerRect.left;
          startY = cardRect.bottom - containerRect.top;
        } else if (item.side === 'bottom') {
          startX = cardRect.left + cardRect.width / 2 - containerRect.left;
          startY = cardRect.top - containerRect.top;
        } else {
          startX = cardRect.left + cardRect.width / 2 - containerRect.left;
        }
        
        const endX = hotspotRect.left + hotspotRect.width / 2 - containerRect.left;
        const endY = hotspotRect.top + hotspotRect.height / 2 - containerRect.top;
        
        let d = '';
        if (item.side === 'left' || item.side === 'right') {
          const cDistance = Math.abs(endX - startX) * 0.45;
          const cx1 = item.side === 'left' ? startX + cDistance : startX - cDistance;
          const cx2 = item.side === 'left' ? endX - cDistance * 0.5 : endX + cDistance * 0.5;
          d = `M ${startX} ${startY} C ${cx1} ${startY}, ${cx2} ${endY}, ${endX} ${endY}`;
        } else {
          const cy1 = startY + (endY - startY) * 0.5;
          const cy2 = startY + (endY - startY) * 0.8;
          d = `M ${startX} ${startY} C ${startX} ${cy1}, ${endX} ${cy2}, ${endX} ${endY}`;
        }
        
        let colorClass = '#22d3ee'; // default cyan-400
        let hoverColorClass = '#a5b4fc';
        
        if (item.id === 'qubit') { colorClass = '#22d3ee'; hoverColorClass = '#38bdf8'; }
        else if (item.id === 'cryo_left' || item.id === 'cryo_right') { colorClass = '#3b82f6'; hoverColorClass = '#60a5fa'; }
        else if (item.id === 'enc_algo') { colorClass = '#6366f1'; hoverColorClass = '#818cf8'; }
        else if (item.id === 'data_in') { colorClass = '#0d9488'; hoverColorClass = '#2dd4bf'; }
        else if (item.id === 'dec_proc') { colorClass = '#10b981'; hoverColorClass = '#34d399'; }
        else if (item.id === 'supremacy') { colorClass = '#f59e0b'; hoverColorClass = '#fbbf24'; }
        else if (item.id === 'data_out') { colorClass = '#ec4899'; hoverColorClass = '#f472b6'; }
        else if (item.id === 'enc_proc') { colorClass = '#10b981'; hoverColorClass = '#34d399'; }
        else if (item.id === 'control_laser') { colorClass = '#ef4444'; hoverColorClass = '#f87171'; }
        else if (item.id === 'quantum_gate') { colorClass = '#d946ef'; hoverColorClass = '#f0abfc'; }
        else if (item.id === 'superposition') { colorClass = '#22d3ee'; hoverColorClass = '#a5b4fc'; }
        else if (item.id === 'entanglement') { colorClass = '#a78bfa'; hoverColorClass = '#c084fc'; }
        
        calculatedLines.push({
          id: item.id,
          d,
          color: colorClass,
          hoverColor: hoverColorClass,
          side: item.side
        });
      });
      
      setLines(calculatedLines);
    };

    updateLines();
    const resizeObserver = new ResizeObserver(() => {
      updateLines();
    });
    
    const gridElem = document.getElementById('quantum-interactive-grid');
    if (gridElem) {
      resizeObserver.observe(gridElem);
    }
    
    window.addEventListener('resize', updateLines);
    const t1 = setTimeout(updateLines, 150);
    const t2 = setTimeout(updateLines, 600);
    const t3 = setTimeout(updateLines, 1200);
    
    return () => {
      resizeObserver.disconnect();
      window.removeEventListener('resize', updateLines);
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
    };
  }, [activeId]);

  const leftItems = items.filter(i => i.side === 'left');
  const rightItems = items.filter(i => i.side === 'right');
  const bottomItems = items.filter(i => i.side === 'bottom');
  const impactItems = items.filter(i => i.side === 'impact');
  const topItems = items.filter(i => i.side === 'top');

  return (
    <div className="bg-slate-950 text-slate-100 rounded-3xl p-6 sm:p-8 border border-slate-800 shadow-2xl overflow-hidden font-sans relative">
      <div className="absolute inset-0 bg-radial-gradient from-indigo-505/10 to-transparent pointer-events-none" />

      {/* Header Info Banner */}
      <div className="relative z-10 flex flex-col md:flex-row justify-between items-start md:items-center border-b border-slate-800/80 pb-6 mb-8 gap-4">
        <div className="text-left max-w-2xl">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono tracking-widest font-extrabold text-cyan-400 uppercase bg-cyan-950/60 border border-cyan-900/40 px-2 py-0.5 rounded-sm">
              Quantum Technology
            </span>
            <span className="text-[10px] font-mono tracking-widest font-extrabold text-violet-400 uppercase bg-violet-950/60 border border-violet-900/40 px-2 py-0.5 rounded-sm">
              Cryptography
            </span>
            <span className="text-[10px] font-mono tracking-widest font-extrabold text-indigo-400 uppercase bg-indigo-950/60 border border-indigo-900/40 px-2 py-0.5 rounded-sm">
              Next-Gen Security
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white uppercase tracking-wider font-display mb-1.5">
            Quantum Code Crack
          </h1>
          <p className="text-xs text-slate-400 leading-relaxed font-normal">
            Quantum computing leverages the principles of superposition and entanglement to process vast amounts of data exponentially faster than classical computers. This breakthrough has the potential to revolutionize cryptography, optimization, and complex problem-solving.
          </p>
        </div>

        {/* Brand Shield Logo Box */}
        <div className="flex items-center gap-3.5 bg-slate-900/80 border border-slate-800/80 px-4.5 py-3 rounded-2xl shrink-0">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 to-rose-500 flex items-center justify-center p-0.5 shadow-lg select-none">
            <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
              <Shield className="w-5 h-5 text-indigo-400" />
            </div>
          </div>
          <div className="text-left">
            <h4 className="text-sm font-bold text-white tracking-wide font-mono">Qguard Helix</h4>
            <span className="text-[9px] font-mono tracking-widest font-extrabold text-indigo-400 uppercase">
              Secure • Intelligent • Q-Ready
            </span>
          </div>
        </div>
      </div>

      {/* Outer Superposition & Entanglement Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
        {topItems.map(item => (
          <div
            key={item.id}
            id={`infographic-card-${item.id}`}
            onMouseEnter={() => setActiveId(item.id)}
            onMouseLeave={() => setActiveId(null)}
            className={`cursor-pointer transition-all duration-300 rounded-2xl p-4.5 text-left border flex gap-4 ${
              activeId === item.id 
                ? 'bg-slate-950 border-indigo-500/80 text-white shadow-indigo-500/10 shadow-lg' 
                : 'bg-slate-900/40 border-slate-800/80 text-slate-300'
            }`}
          >
            <div className={`p-2 rounded-xl shrink-0 flex items-center justify-center h-10 w-10 ${
              activeId === item.id ? 'bg-indigo-950 text-indigo-400' : 'bg-slate-800/50 text-slate-400'
            }`}>
              {item.id === 'superposition' ? (
                <div className="flex items-center gap-0.5 font-mono text-xs font-bold text-cyan-400">
                  <span>q</span> <span className="text-[10px] text-indigo-400 animate-pulse">⇋</span> <span>qb</span>
                </div>
              ) : (
                item.icon
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-black text-cyan-400">STATE</span>
                <h4 className="text-xs font-bold font-mono tracking-wider uppercase text-white">{item.title}</h4>
              </div>
              <p className="text-[11px] text-slate-400 leading-normal mt-1">{item.desc}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Primary Cyber Isometric Grid Cockpit (Left Cards | Core Image Center | Right Cards) */}
      <div 
        id="quantum-interactive-grid"
        className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-center mb-8 relative"
      >
        {/* Dynamic Global S-Curve Connecting Lines with Moving Light Particles */}
        <svg
          className="absolute inset-0 w-full h-full pointer-events-none z-0 xl:block hidden"
          style={{ mixBlendMode: 'screen' }}
        >
          <defs>
            <filter id="neonPathGlow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {lines.map(line => {
            const isActive = activeId === line.id;
            return (
              <g key={`connector-line-${line.id}`} className="transition-all duration-300">
                {/* Thin structural background thread */}
                <path
                  d={line.d}
                  fill="none"
                  stroke={line.color}
                  strokeWidth="1.2"
                  strokeOpacity={isActive ? "0.35" : "0.15"}
                  className="transition-all duration-300"
                />

                {/* Main colored path line with glow */}
                <path
                  d={line.d}
                  fill="none"
                  stroke={line.color}
                  strokeWidth={isActive ? "2.2" : "1.5"}
                  strokeOpacity={isActive ? "0.9" : "0.45"}
                  filter={isActive ? "url(#neonPathGlow)" : undefined}
                  className="transition-all duration-300"
                />

                {/* Animated glowing moving dashed thread, exactly like the attached design */}
                <path
                  d={line.d}
                  fill="none"
                  stroke={isActive ? line.hoverColor : line.color}
                  strokeWidth={isActive ? "2.8" : "1.8"}
                  strokeOpacity={isActive ? "1.0" : "0.75"}
                  strokeDasharray={isActive ? "12, 18" : "6, 20"}
                  style={{
                    animation: `dash-connector-flow ${isActive ? '1.0s' : '2.0s'} linear infinite`,
                    filter: `drop-shadow(0 0 3px ${isActive ? line.hoverColor : line.color})`
                  }}
                  className="transition-all duration-300"
                />
              </g>
            );
          })}
        </svg>

        {/* Global Keyframes Styles Injection */}
        <style>{`
          @keyframes dash-connector-flow {
            to {
              stroke-dashoffset: -35;
            }
          }
        `}</style>
        
        {/* Left Column Annotations (1 to 4) */}
        <div className="xl:col-span-3 flex flex-col gap-2.5 justify-center">
          {leftItems.map(item => (
            <div
              key={item.id}
              id={`infographic-card-${item.id}`}
              onMouseEnter={() => setActiveId(item.id)}
              onMouseLeave={() => setActiveId(null)}
              className={`group cursor-pointer transition-all duration-300 p-3 rounded-xl text-left border relative ${
                activeId === item.id 
                  ? 'bg-slate-900/90 border-cyan-400 shadow-md shadow-cyan-500/10 -translate-y-0.5 xl:translate-x-1.5' 
                  : 'bg-slate-900/35 border-slate-900 hover:border-slate-800'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-1.5">
                  <span className="flex items-center justify-center w-[18px] h-[18px] rounded-full bg-cyan-950 border border-cyan-800 text-[9px] font-mono font-bold text-cyan-400 shrink-0">
                    {item.num}
                  </span>
                  <h4 className="text-[11px] font-bold font-mono tracking-wide uppercase text-slate-200 group-hover:text-cyan-300 transition-colors">
                    {item.title.replace(/^\d+\.\s*/, '')}
                  </h4>
                </div>
                <span className="text-slate-500 group-hover:text-cyan-400 transition-colors">{item.icon}</span>
              </div>
              <p className="text-[10px] text-slate-400 leading-relaxed font-normal">
                {item.desc}
              </p>
            </div>
          ))}
        </div>

        {/* Center Blueprint Image & Interactive Pointer Layer */}
        <div className="xl:col-span-6 flex items-center justify-center relative bg-slate-900/10 border border-slate-800/20 rounded-3xl p-5 overflow-hidden min-h-[480px] xl:min-h-[520px]">
          
          {/* Neon Grid Backdrop */}
          <div className="absolute inset-0 opacity-10 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:20px_20px] pointer-events-none" />

          {/* Core Hardware Block Image with White BG to perfectly frame the clean transparent-look background */}
          <div className="relative w-full aspect-square max-w-[500px] xl:max-w-[540px] bg-white rounded-2xl border border-slate-100/10 shadow-2xl flex items-center justify-center transition-all duration-300 hover:shadow-cyan-500/5 hover:border-cyan-500/10 overflow-hidden">
            <div className="relative w-full h-full scale-[1.15] transition-transform duration-300 flex items-center justify-center origin-center">
              <img
                src={quantumCoreImg}
                alt="Qguard Helix Core hardware isometric cube blueprint"
                className="w-full h-full object-cover select-none"
              />

            {/* SVG Connector Routes Layer */}
            <svg 
              className="absolute inset-0 w-full h-full pointer-events-none z-10 xl:hidden"
              viewBox="0 0 100 100"
              preserveAspectRatio="none"
            >
              <defs>
                <linearGradient id="glowGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#818cf8" stopOpacity="0.8" />
                  <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.8" />
                </linearGradient>
                <filter id="neonShadow">
                  <feGaussianBlur stdDeviation="1.5" result="coloredBlur"/>
                  <feMerge>
                    <feMergeNode in="coloredBlur"/>
                    <feMergeNode in="SourceGraphic"/>
                  </feMerge>
                </filter>
              </defs>

              {/* Dynamic Connecting Lines displayed on hover */}
              {items.map(item => {
                if (!item.hotspot || activeId !== item.id) return null;
                const hx = item.hotspot.x;
                const hy = item.hotspot.y;
                const startX = item.side === 'left' ? 3 : item.side === 'right' ? 97 : 50;
                const startY = item.side === 'top' ? 2 : item.side === 'bottom' ? 98 : hy;

                return (
                  <g key={`svg-${item.id}`}>
                    {/* Glowing path */}
                    <path
                      d={
                        item.side === 'left' || item.side === 'right'
                          ? `M ${startX} ${startY} L ${startX + (item.side === 'left' ? 10 : -10)} ${startY} L ${hx} ${hy}`
                          : `M ${startX} ${startY} L ${startX} ${startY + (item.side === 'top' ? 10 : -10)} L ${hx} ${hy}`
                      }
                      fill="none"
                      stroke="url(#glowGrad)"
                      strokeWidth="0.8"
                      strokeDasharray="2,2"
                      filter="url(#neonShadow)"
                      className="animate-pulse"
                    />
                    {/* Hotspot anchor pulse circle */}
                    <circle
                      cx={hx}
                      cy={hy}
                      r="1.8"
                      fill="#38bdf8"
                      filter="url(#neonShadow)"
                    />
                    <circle
                      cx={hx}
                      cy={hy}
                      r="3.5"
                      fill="none"
                      stroke="#818cf8"
                      strokeWidth="0.4"
                      className="animate-ping"
                    />
                  </g>
                );
              })}
            </svg>

            {/* Floating Hotspot Pointer Nodes */}
            {items.map(item => {
              if (!item.hotspot) return null;
              const isHovered = activeId === item.id;
              return (
                <button
                  key={`hotspot-${item.id}`}
                  id={`infographic-hotspot-${item.id}`}
                  style={{ top: `${item.hotspot.y}%`, left: `${item.hotspot.x}%` }}
                  onMouseEnter={() => setActiveId(item.id)}
                  onMouseLeave={() => setActiveId(null)}
                  className="absolute -translate-x-1/2 -translate-y-1/2 z-20 group"
                  aria-label={`Hotspot for ${item.title}`}
                >
                  <span className="relative flex h-5.5 w-5.5 items-center justify-center">
                    {isHovered && (
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                    )}
                    <span className={`relative inline-flex rounded-full h-4 w-4 items-center justify-center text-[8px] font-mono font-bold border transition-all duration-300 ${
                      isHovered
                        ? 'bg-indigo-600 border-cyan-400 text-white shadow-md scale-125'
                        : 'bg-slate-950/90 border-slate-700 hover:border-indigo-400 text-slate-300 hover:text-white'
                    }`}>
                      {item.num !== undefined ? item.num : '•'}
                    </span>
                  </span>

                  {/* Micro tooltip label */}
                  <span className="pointer-events-none absolute bottom-full left-1/2 -translate-x-1/2 mb-1.5 whitespace-nowrap bg-slate-900 border border-slate-700/80 px-2 py-0.5 rounded text-[8px] font-mono tracking-wider font-bold text-cyan-300 scale-0 group-hover:scale-100 transition-transform origin-bottom">
                    {item.title.replace(/^\d+\.\s*/, '')}
                  </span>
                </button>
              );
            })}
            </div>
          </div>
        </div>

        {/* Right Column Annotations (7 to 11) */}
        <div className="xl:col-span-3 flex flex-col gap-2.5 justify-center">
          {rightItems.sort((a,b) => (b.num || 0) - (a.num || 0)).map(item => (
            <div
              key={item.id}
              id={`infographic-card-${item.id}`}
              onMouseEnter={() => setActiveId(item.id)}
              onMouseLeave={() => setActiveId(null)}
              className={`group cursor-pointer transition-all duration-300 p-3 rounded-xl text-left border relative ${
                activeId === item.id 
                  ? 'bg-slate-900/90 border-indigo-400 shadow-md shadow-indigo-505/10 -translate-y-0.5 xl:-translate-x-1.5' 
                  : 'bg-slate-900/35 border-slate-900 hover:border-slate-800'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-1.5">
                  <span className="flex items-center justify-center w-[18px] h-[18px] rounded-full bg-indigo-950 border border-indigo-800 text-[9px] font-mono font-bold text-indigo-300 shrink-0">
                    {item.num}
                  </span>
                  <h4 className="text-[11px] font-bold font-mono tracking-wide uppercase text-slate-200 group-hover:text-indigo-350 transition-colors">
                    {item.title.replace(/^\d+\.\s*/, '')}
                  </h4>
                </div>
                <span className="text-slate-500 group-hover:text-indigo-400 transition-colors">{item.icon}</span>
              </div>
              <p className="text-[10px] text-slate-400 leading-relaxed font-normal">
                {item.desc}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Under-Block Intermediate row (Decryption Process (5), Quantum Supremacy (6), Shor's Algorithm (12), Fun Fact, Decoherence (13)) */}
      <h3 className="text-left font-mono text-[10px] tracking-widest font-extrabold text-slate-500 uppercase border-b border-slate-900 pb-2 mb-4">
        Core Algorithms & Environmental Physics factors
      </h3>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
        {bottomItems.map(item => (
          <div
            key={item.id}
            id={`infographic-card-${item.id}`}
            onMouseEnter={() => setActiveId(item.id)}
            onMouseLeave={() => setActiveId(null)}
            className={`cursor-pointer transition-all duration-300 p-4 rounded-2xl text-left border flex flex-col justify-between ${
              activeId === item.id 
                ? 'bg-slate-950 border-indigo-500/80 shadow-md shadow-indigo-505/10' 
                : 'bg-slate-900/30 border-slate-900'
            }`}
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-1.5">
                  {item.num && (
                    <span className="flex items-center justify-center w-4.5 h-4.5 rounded-full bg-indigo-950 border border-indigo-900 text-[9px] font-mono font-bold text-indigo-400">
                      {item.num}
                    </span>
                  )}
                  <h4 className="text-[10px] font-mono font-black tracking-wider uppercase text-slate-300">
                    {item.title.replace(/^\d+\.\s*/, '')}
                  </h4>
                </div>
                <span className="text-slate-500">{item.icon}</span>
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed font-normal">
                {item.desc}
              </p>
            </div>
          </div>
        ))}
      </div>

      {/* Footer Block Real-World Impact (14 to 18) */}
      <div className="bg-slate-900/40 border border-slate-900 rounded-3xl p-5 sm:p-6 text-left relative z-10">
        <h3 className="text-xs font-mono tracking-widest font-extrabold text-indigo-400 uppercase mb-4 flex items-center gap-2">
          <span>🎯</span> Real-World Impact Matrix (Applications)
        </h3>
        
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 text-left">
          {impactItems.sort((a,b) => (a.num || 0) - (b.num || 0)).map(item => (
            <div
              key={item.id}
              onMouseEnter={() => setActiveId(item.id)}
              onMouseLeave={() => setActiveId(null)}
              className={`transition-all duration-300 p-4.5 rounded-2xl border ${
                activeId === item.id 
                  ? 'bg-slate-950 border-cyan-500/40 shadow-lg scale-[1.01] text-white' 
                  : 'bg-slate-900/40 border-slate-800/80 text-slate-300'
              }`}
            >
              <div className="flex items-center justify-between mb-2 pb-2 border-b border-slate-800/60">
                <div className="flex items-center gap-1.5">
                  <span className="flex items-center justify-center w-5 h-5 rounded-full bg-cyan-950 border border-cyan-900 text-[10px] font-mono font-bold text-cyan-400">
                    {item.num}
                  </span>
                  <h4 className="text-[10px] font-mono font-bold tracking-wide uppercase">
                    {item.title}
                  </h4>
                </div>
                {item.icon}
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                {item.desc}
              </p>
            </div>
          ))}
        </div>
      </div>

      <div className="relative z-10 mt-8 overflow-hidden rounded-3xl border border-slate-800/80 bg-slate-900/35 shadow-xl shadow-cyan-950/10">
        <img
          src="/Breaking_RSA_ECC.png"
          alt="Quantum attack visualization breaking RSA and ECC cryptography"
          className="block w-full h-auto bg-white"
        />
      </div>

      <div className="text-center font-mono text-[9px] tracking-widest text-slate-600 uppercase mt-6 relative z-10 select-none">
        The Future is Quantum • The Code Is Power • The Guard is Qguard Helix
      </div>
    </div>
  );
}

// Custom Unlock icon (since lucide-react doesn't have a simple custom Unlock outline without types sometimes)
function UnlockIcon() {
  return (
    <svg 
      className="w-4 h-4 text-emerald-400" 
      viewBox="0 0 24 24" 
      fill="none" 
      stroke="currentColor" 
      strokeWidth="2" 
      strokeLinecap="round" 
      strokeLinejoin="round"
    >
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
      <path d="M7 11V7a5 5 0 0 1 9.9-1" />
    </svg>
  );
}
