import { useEffect, useState, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Shield, Play, Pause, Cpu, Globe, Server, User, Disc, Zap, Lock, Unlock, Key, Network } from 'lucide-react';
import { TargetType } from '../../types';
import { Scenario } from '../../data/scenario';
import TerminalConsole from './TerminalConsole';
// @ts-ignore
import correlationCoreImg from '../../assets/images/correlation_core_1779970191490.png';

// S-curve fibers matching the high-end attached image
const LEFT_PATHS = [
  { id: 'l1', d: 'M 90 60 C 180 60, 210 110, 300 110', baseColor: 'rgba(59, 130, 246, 0.12)', glowColor: '#3b82f6', activeSteps: [1, 5, 6] },
  { id: 'l2', d: 'M 90 85 C 180 85, 210 110, 300 110', baseColor: 'rgba(96, 165, 250, 0.12)', glowColor: '#60a5fa', activeSteps: [1, 5, 6] },
  { id: 'l3', d: 'M 90 110 C 180 110, 210 110, 300 110', baseColor: 'rgba(34, 211, 238, 0.12)', glowColor: '#22d3ee', activeSteps: [1, 5, 6] },
  { id: 'l4', d: 'M 90 135 C 180 135, 210 110, 300 110', baseColor: 'rgba(245, 158, 11, 0.12)', glowColor: '#f59e0b', activeSteps: [1, 5, 6] },
  { id: 'l5', d: 'M 90 160 C 180 160, 210 110, 300 110', baseColor: 'rgba(239, 68, 68, 0.12)', glowColor: '#ef4444', activeSteps: [1, 5, 6] },
];

const RIGHT_PATHS = [
  { id: 'r1', d: 'M 300 110 C 390 110, 420 60, 510 60', baseColor: 'rgba(239, 68, 68, 0.12)', glowColor: '#ef4444', activeSteps: [3, 5, 6] },
  { id: 'r2', d: 'M 300 110 C 390 110, 420 85, 510 85', baseColor: 'rgba(249, 115, 22, 0.12)', glowColor: '#f97316', activeSteps: [3, 5, 6] },
  { id: 'r3', d: 'M 300 110 C 390 110, 420 110, 510 110', baseColor: 'rgba(168, 85, 247, 0.12)', glowColor: '#a855f7', activeSteps: [3, 5, 6] },
  { id: 'r4', d: 'M 300 110 C 390 110, 420 135, 510 135', baseColor: 'rgba(59, 130, 246, 0.12)', glowColor: '#3b82f6', activeSteps: [3, 5, 6] },
  { id: 'r5', d: 'M 300 110 C 390 110, 420 160, 510 160', baseColor: 'rgba(99, 102, 241, 0.12)', glowColor: '#6366f1', activeSteps: [3, 5, 6] },
];

const VAULT_PATHS = [
  { id: 'v1', d: 'M 300 110 C 260 160, 260 290, 300 340', baseColor: 'rgba(234, 179, 8, 0.12)', glowColor: '#eab308', activeSteps: [2, 4, 5, 6] },
  { id: 'v2', d: 'M 300 110 L 300 340', baseColor: 'rgba(245, 158, 11, 0.12)', glowColor: '#f59e0b', activeSteps: [2, 4, 5, 6] },
  { id: 'v3', d: 'M 300 110 C 340 160, 340 290, 300 340', baseColor: 'rgba(234, 179, 8, 0.12)', glowColor: '#eab308', activeSteps: [2, 4, 5, 6] },
];

const DEC_STATS_MAP: Record<string, { tbDecrypted: string; encryptionBroken: string; archiveExposed: string; factorTime: string }> = {
  hndl: {
    tbDecrypted: "14.7 TB",
    encryptionBroken: "RSA-2048",
    archiveExposed: "100%",
    factorTime: "~4 Hours"
  },
  "rsa-breaking": {
    tbDecrypted: "2.8 TB",
    encryptionBroken: "RSA-2048",
    archiveExposed: "100%",
    factorTime: "~24 Mins"
  },
  "tls-compromise": {
    tbDecrypted: "8.75 TB",
    encryptionBroken: "ECDHE-RSA",
    archiveExposed: "100%",
    factorTime: "~5 Secs"
  },
  "swift-financial": {
    tbDecrypted: "41.2 TB",
    encryptionBroken: "RSA-2048",
    archiveExposed: "100%",
    factorTime: "~2.5 Hours"
  },
  "infra-scada": {
    tbDecrypted: "18.3 TB",
    encryptionBroken: "DSA-2048",
    archiveExposed: "100%",
    factorTime: "~15 Mins"
  },
  "cloud-breach": {
    tbDecrypted: "112.4 TB",
    encryptionBroken: "RSA-4096",
    archiveExposed: "100%",
    factorTime: "~6.2 Hours"
  },
  "satellite-comm": {
    tbDecrypted: "231.8 TB",
    encryptionBroken: "AES/RSA",
    archiveExposed: "100%",
    factorTime: "~1.2 Hours"
  },
  "genomic-exposure": {
    tbDecrypted: "95.3 TB",
    encryptionBroken: "RSA-2048",
    archiveExposed: "100%",
    factorTime: "~3.5 Hours"
  },
  "ai-theft": {
    tbDecrypted: "680.4 TB",
    encryptionBroken: "RSA-2048",
    archiveExposed: "100%",
    factorTime: "~8 Hours"
  },
  "pqc-migration": {
    tbDecrypted: "4.5 TB",
    encryptionBroken: "PQC Hybrid",
    archiveExposed: "12%",
    factorTime: "Non-Factor"
  },
  "warfare-scenario": {
    tbDecrypted: "1,450.6 TB",
    encryptionBroken: "RSA-3072",
    archiveExposed: "100%",
    factorTime: "~3.8 Hours"
  },
  "supply-chain": {
    tbDecrypted: "12.8 TB",
    encryptionBroken: "RSA-2048",
    archiveExposed: "100%",
    factorTime: "~2.1 Hours"
  },
  "risk-sandbox": {
    tbDecrypted: "0.45 TB",
    encryptionBroken: "Test RSA",
    archiveExposed: "100%",
    factorTime: "Sim Speed"
  },
  "operational-collapse": {
    tbDecrypted: "154.2 TB",
    encryptionBroken: "HSM Keys",
    archiveExposed: "100%",
    factorTime: "~4.8 Hours"
  },
  "qday-readiness": {
    tbDecrypted: "2,105.8 TB",
    encryptionBroken: "RSA/ECC",
    archiveExposed: "100%",
    factorTime: "Immediate"
  }
};

interface SimulationCanvasProps {
  isPlaying: boolean;
  onTogglePlay: () => void;
  activeScenario: Scenario;
  activeTarget: TargetType;
  onChangeTarget: (target: TargetType) => void;
  packetsCaptured: number;
  harvestedSizeGB: number;
  captureRateMBs: number;
  stealthLevel: number;
  detectionRisk: 'Low' | 'Medium' | 'High';
  activeStep: number;
  timeElapsed: number; // in seconds
  onNextStep: () => void;
}

export default function SimulationCanvas({
  isPlaying,
  onTogglePlay,
  activeScenario,
  activeTarget,
  onChangeTarget,
  packetsCaptured,
  harvestedSizeGB,
  captureRateMBs,
  stealthLevel,
  detectionRisk,
  activeStep,
  timeElapsed,
  onNextStep,
}: SimulationCanvasProps) {
  const sparkPoints = useRef<number[]>([25, 40, 20, 50, 30, 45, 20, 35, 60, 40, 55, 30, 45, 42, 65, 50, 75, 40, 60, 50]);
  const [sparkState, setSparkState] = useState<number[]>([25, 40, 20, 50, 30, 45, 20, 35, 60, 40, 55, 30, 45, 42, 65, 50, 75, 40, 60, 50]);

  // High-fidelity active step movement triggers
  const [activePulsePhase, setActivePulsePhase] = useState<'idle' | 'user-to-net' | 'net-to-server' | 'server-to-net' | 'net-to-vault'>('idle');
  const [realtimeProgress, setRealtimeProgress] = useState<number>(100);
  const [viewMode, setViewMode] = useState<'topology' | 'decrypted'>('topology');

  const isBreached = activeStep >= 3 && activeStep <= 5;

  // Sync viewMode on step changes to provide immersive reveal!
  useEffect(() => {
    if (activeStep === 4 || activeStep === 5) {
      setViewMode('decrypted');
    } else {
      setViewMode('topology');
    }
  }, [activeStep]);

  // Spark Line (Micro Waveform Chart) Updates
  useEffect(() => {
    if (!isPlaying) return;
    const interval = setInterval(() => {
      sparkPoints.current = [...sparkPoints.current.slice(1), Math.floor(Math.random() * 55) + 15];
      setSparkState([...sparkPoints.current]);
    }, 150);
    return () => clearInterval(interval);
  }, [isPlaying]);

  // Real-time progress bar movement & light flow sync triggered ONLY on step or target changes.
  useEffect(() => {
    setRealtimeProgress(0);
    setActivePulsePhase('user-to-net');

    let start: number | null = null;
    const duration = 2400; // total animation duration matching physical light speed travel
    let animationFrameId: number;

    const animateProgress = (timestamp: number) => {
      if (!start) start = timestamp;
      const elapsed = timestamp - start;
      const progressRatio = Math.min(elapsed / duration, 1);

      // Smooth easing calculation (easeOutCubic)
      const easeProgress = Math.round((1 - Math.pow(1 - progressRatio, 3)) * 100);
      setRealtimeProgress(easeProgress);

      // Sync activePulsePhase with visual travel progression:
      // USER -> NETWORK: Leg 1 (0 to 600ms)
      if (elapsed < 600) {
        setActivePulsePhase('user-to-net');
      } 
      // NETWORK -> TARGET SERVER: Leg 2 (600 to 1200ms)
      else if (elapsed < 1200) {
        setActivePulsePhase('net-to-server');
      } 
      // TARGET SERVER -> NETWORK: Leg 3 (1200 to 1800ms)
      else if (elapsed < 1800) {
        setActivePulsePhase('server-to-net');
      }
      // NETWORK -> HNDL VAULT: Leg 4 (1800 to 2400ms)
      else {
        setActivePulsePhase('net-to-vault');
      }

      if (progressRatio < 1) {
        animationFrameId = requestAnimationFrame(animateProgress);
      } else {
        setActivePulsePhase('idle');
      }
    };

    animationFrameId = requestAnimationFrame(animateProgress);

    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, [activeStep, activeTarget]);

  // Format seconds to HH:MM:SS
  const formatTime = (secs: number) => {
    const h = Math.floor(secs / 3600).toString().padStart(2, '0');
    const m = Math.floor((secs % 3600) / 60).toString().padStart(2, '0');
    const s = (secs % 60).toString().padStart(2, '0');
    return `${h}:${m}:${s}`;
  };

  const decryptedFiles = activeScenario.decryptedFiles;
  const currentStepInfo = activeScenario.steps[activeStep] || activeScenario.steps[1];

  const scenarioStats = DEC_STATS_MAP[activeScenario.id] || {
    tbDecrypted: `${activeScenario.metrics.baseSizeGB} TB`,
    encryptionBroken: "RSA-2048",
    archiveExposed: "100%",
    factorTime: "~4 Hours"
  };

  return (
    <div 
      id="simulation-panel" 
      className={`
        rounded-3xl p-6 shadow-2xl relative overflow-hidden font-sans transition-all duration-700 border
        ${isBreached 
          ? 'bg-[#140608] border-red-950/80 shadow-[0_0_50px_rgba(239,68,68,0.12)]' 
          : 'bg-[#0b0f19] border-slate-800/60'
        }
      `}
    >
      {/* Subtle background ambient glow overlay tuned to status */}
      <div 
        className={`absolute inset-0 pointer-events-none transition-all duration-700 ${
          isBreached 
            ? 'bg-[radial-gradient(circle_at_center,rgba(239,68,68,0.08),transparent_70%)]' 
            : 'bg-[radial-gradient(circle_at_center,rgba(59,130,246,0.04),transparent_70%)]'
        }`} 
      />

      {/* 1. Header Row */}
      <div className={`flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b pb-5 mb-5 relative z-10 transition-all duration-700 ${
        isBreached ? 'border-red-950/40' : 'border-slate-800/40'
      }`}>
        <div>
          <span className={`text-xs tracking-widest font-mono font-bold px-2.5 py-1 rounded-sm transition-all duration-700 ${
            isBreached 
              ? 'text-red-400 bg-red-500/10' 
              : 'text-[#5046e6] bg-[#6366f1]/10'
          }`}>
            STEP {activeStep} OF 6 {isBreached && "• CRQC BREACH DETECTED"}
          </span>
          <h2 className="text-2xl font-bold font-display tracking-wide uppercase mt-1.5 flex items-center gap-2">
            <span className={`bg-gradient-to-r bg-clip-text text-transparent transition-all duration-700 ${
              isBreached 
                ? 'from-red-500 via-rose-400 to-amber-500' 
                : 'from-blue-400 to-indigo-400'
            }`}>
              {currentStepInfo.name}
            </span>
          </h2>
          <p className="text-xs text-slate-400 max-w-md mt-1 font-sans">
            {currentStepInfo.desc}
          </p>
        </div>

        {/* Target vector tabs Selection inside Simulation */}
        <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center">
          {isBreached && (
            <div className="flex flex-col gap-1.5">
              <span className="text-[10px] font-mono tracking-wider font-semibold text-red-500 uppercase">
                ACTIVE REVEAL MODE
              </span>
              <div className="flex bg-red-950/30 border border-red-900/40 rounded-full p-1 shadow-[0_0_15px_rgba(239,68,68,0.1)]">
                <button
                  id="view-mode-topology-btn"
                  onClick={() => setViewMode('topology')}
                  className={`px-3 py-1 rounded-full text-[10px] sm:text-[11px] font-mono font-bold transition-all cursor-pointer ${
                    viewMode === 'topology'
                      ? 'bg-red-600 text-white shadow-md shadow-red-900/60'
                      : 'text-red-400/70 hover:text-red-300'
                  }`}
                >
                  SYSTEM MAP
                </button>
                <button
                  id="view-mode-decrypted-btn"
                  onClick={() => setViewMode('decrypted')}
                  className={`px-3 py-1 rounded-full text-[10px] sm:text-[11px] font-mono font-bold transition-all cursor-pointer relative ${
                    viewMode === 'decrypted'
                      ? 'bg-red-600 text-white shadow-md shadow-red-900/60 animate-pulse'
                      : 'text-red-400/70 hover:text-red-300'
                  }`}
                >
                  DECRYPTED ARCHIVES
                  <span className="absolute -top-1 -right-1 w-1.5 h-1.5 rounded-full bg-red-400 animate-ping" />
                </button>
              </div>
            </div>
          )}

          <div className="flex flex-col gap-1.5">
            <span className="text-[10px] font-mono tracking-wider font-semibold text-slate-500 uppercase self-start sm:self-end">
              Choose Target Vector
            </span>
            <div className={`flex rounded-full p-1 self-start sm:self-end border transition-all duration-700 ${
              isBreached ? 'bg-red-950/20 border-red-900/30' : 'bg-slate-900 border-slate-800'
            }`}>
              {activeScenario.targets.map((t) => (
                <button
                  key={t}
                  id={`target-selector-btn-${t.replace(/\s+/g, '-').toLowerCase()}`}
                  onClick={() => onChangeTarget(t)}
                  className={`
                    px-3 py-1 sm:px-3.5 sm:py-1.5 rounded-full text-[11px] sm:text-xs font-semibold font-sans transition-all duration-300 whitespace-nowrap cursor-pointer
                    ${activeTarget === t 
                      ? isBreached 
                        ? 'bg-red-800 text-white shadow-md shadow-red-950/50 scale-102'
                        : 'bg-blue-600/90 text-white shadow-md shadow-blue-900/40 scale-102' 
                      : isBreached
                        ? 'text-red-400/60 hover:text-red-300'
                        : 'text-slate-400 hover:text-slate-200'
                    }
                  `}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* 2. Main Body Container for full width System Map */}
      <div className="relative z-10 w-full">
        
        <div id="simulation-right-viewport-card" className={`w-full border rounded-2xl relative min-h-[440px] overflow-hidden flex flex-col justify-between transition-all duration-700 ${
          isBreached 
            ? 'bg-[#180a0c] border-red-950/80 shadow-[0_0_30px_rgba(239,68,68,0.08)]' 
            : 'bg-slate-950/85 border-slate-800/90'
        }`}>
          
          {/* Digital Cyber-Grid Overlay */}
          <div className={`absolute inset-0 bg-[linear-gradient(rgba(14,20,35,0.85)_1px,transparent_1px),linear-gradient(90deg,rgba(14,20,35,0.85)_1px,transparent_1px)] bg-[size:24px_24px] pointer-events-none transition-all duration-700 ${
            isBreached ? 'opacity-15' : 'opacity-35'
          }`} />

          {viewMode === 'decrypted' ? (
            <div className="flex flex-col h-full bg-[#1b0a0e]/40 p-4 sm:p-5 text-white overflow-hidden justify-between flex-1 relative z-10">
              {/* Header Box mimicking image popup */}
              <div className="border border-red-500/30 bg-red-950/20 rounded-xl p-4.5 mb-4 relative overflow-hidden shadow-[inset_0_0_20px_rgba(239,68,68,0.1)]">
                <div className="absolute top-1 right-2 left-2 h-0.5 bg-red-500/25 animate-pulse" />
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                  <div>
                    <h3 className="text-sm font-bold tracking-widest font-mono text-red-500 uppercase flex items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping inline-block shrink-0" />
                      CRQC DECRYPTION ACTIVE
                    </h3>
                    <p className="text-[10px] sm:text-[11.5px] font-mono text-rose-300 font-semibold mt-1">
                      Shor's Algorithm Complete — {scenarioStats.encryptionBroken} Private Key Recovered (All Archived Ciphertext Now Plaintext)
                    </p>
                  </div>
                  {/* Lock Indicator broken status */}
                  <div className="flex items-center gap-2 shrink-0 bg-red-950/30 border border-red-500/40 px-3 py-1.5 rounded-lg text-red-400">
                    <Unlock className="w-4 h-4 text-red-500 filter drop-shadow-[0_0_3px_rgba(239,68,68,0.5)]" />
                    <span className="text-[10px] font-bold font-mono tracking-widest">KEYS BROKEN</span>
                  </div>
                </div>

                {/* Submetrics row */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4 text-center border-t border-red-950/30 pt-3">
                  <div className="bg-red-950/30 p-2 rounded border border-red-950/50">
                    <div className="text-xl font-black font-display text-rose-400 tracking-tight">{scenarioStats.tbDecrypted}</div>
                    <div className="text-[9px] font-mono font-bold text-red-500 uppercase">TB DECRYPTED</div>
                  </div>
                  <div className="bg-red-950/30 p-2 rounded border border-red-950/50">
                    <div className="text-xs sm:text-xs font-black font-mono text-rose-400 tracking-tight mt-1">{scenarioStats.encryptionBroken}</div>
                    <div className="text-[9px] font-mono font-bold text-red-500 uppercase">ENCRYPTION BROKEN</div>
                  </div>
                  <div className="bg-red-950/30 p-2 rounded border border-red-950/50">
                    <div className="text-xl font-black font-display text-red-400 tracking-tight">{scenarioStats.archiveExposed}</div>
                    <div className="text-[9px] font-mono font-bold text-red-500 uppercase">ARCHIVE EXPOSED</div>
                  </div>
                  <div className="bg-red-950/30 p-2 rounded border border-red-950/50">
                    <div className="text-xl font-black font-display text-rose-400 tracking-tight">{scenarioStats.factorTime}</div>
                    <div className="text-[9px] font-mono font-bold text-red-500 uppercase">FACTOR TIME</div>
                  </div>
                </div>
              </div>

              {/* Decrypted files contents table/grid */}
              <div className="flex-1 flex flex-col justify-between">
                <div className="flex justify-between items-center pb-2 border-b border-red-950/40 mb-3">
                  <span className="text-[10px] font-mono font-bold tracking-widest text-red-500 uppercase">
                    DECRYPTED ARCHIVE CONTENTS - RETROACTIVE PLAINSTREAM FEED
                  </span>
                  <span className="text-[9px] font-mono font-bold tracking-widest text-[#ef4444] uppercase flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
                    LIVE DECRYPTSTREAM
                  </span>
                </div>
                
                <div className="space-y-2.5 max-h-[160px] overflow-y-auto pr-1 scrollbar-thin scrollbar-thumb-red-950">
                  {decryptedFiles.map((f, i) => {
                    // Stagger visibility based on progress to look like active decryption!
                    const isVisible = realtimeProgress >= (i * 12);
                    if (!isVisible) return null;
                    return (
                      <motion.div 
                        key={i} 
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.3 }}
                        className="flex items-center justify-between p-2.5 rounded-xl border border-red-900/10 bg-[#250d11]/40 hover:bg-[#341116]/50 transition-all duration-150 gap-2.5"
                      >
                        <div className="flex items-center gap-2.5 min-w-0">
                          {/* hazard indicator of files */}
                          <div className="w-7 h-7 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-500 grow-0 shrink-0">
                            <Disc className="w-4 h-4 text-red-500 animate-spin" style={{ animationDuration: '4s' }} />
                          </div>
                          <div className="min-w-0">
                            <h4 className="text-[11px] sm:text-xs font-bold text-slate-100 truncate">{f.name}</h4>
                            <span className="text-[10px] font-mono text-rose-400/80 block truncate">{f.filename} • {f.size}</span>
                          </div>
                        </div>
                        
                        {/* Classification tags */}
                        <span className={`text-[9px] sm:text-[10px] font-mono font-bold tracking-widest px-2 py-0.5 rounded-sm border ${f.tagColor} shrink-0`}>
                          {f.tag}
                        </span>
                      </motion.div>
                    );
                  })}
                </div>
              </div>
            </div>
          ) : (
            <>
              {/* SVG Connector Wires, Orbit lines, Glowing Channels & Flow Light pulses */}
              <svg className="absolute inset-0 w-full h-full z-0 pointer-events-none select-none" viewBox="0 0 600 440" preserveAspectRatio="none">
                <defs>
                  {/* Neon Glow Filters matching high-end scinfics */}
                  <filter id="neon-glow-cyan" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="4" result="blur" />
                    <feMerge>
                      <feMergeNode in="blur" />
                      <feMergeNode in="SourceGraphic" />
                    </feMerge>
                  </filter>
                  <filter id="neon-glow-rose" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="4" result="blur" />
                    <feMerge>
                      <feMergeNode in="blur" />
                      <feMergeNode in="SourceGraphic" />
                    </feMerge>
                  </filter>
                  <filter id="neon-glow-gold" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="5" result="blur" />
                    <feMerge>
                      <feMergeNode in="blur" />
                      <feMergeNode in="SourceGraphic" />
                    </feMerge>
                  </filter>
                </defs>

                {/* Draw all background fibers as subtle transparent wires */}
                {LEFT_PATHS.map((path) => (
                  <g key={`bg-${path.id}`}>
                    <path
                      d={path.d}
                      fill="none"
                      stroke={isBreached ? "rgba(239, 68, 68, 0.08)" : "rgba(30, 41, 59, 0.4)"}
                      strokeWidth="3"
                    />
                    <path
                      d={path.d}
                      fill="none"
                      stroke={isBreached ? "rgba(239, 68, 68, 0.15)" : path.baseColor}
                      strokeWidth="1.25"
                    />
                  </g>
                ))}

                {RIGHT_PATHS.map((path) => (
                  <g key={`bg-${path.id}`}>
                    <path
                      d={path.d}
                      fill="none"
                      stroke={isBreached ? "rgba(239, 68, 68, 0.08)" : "rgba(30, 41, 59, 0.4)"}
                      strokeWidth="3"
                    />
                    <path
                      d={path.d}
                      fill="none"
                      stroke={isBreached ? "rgba(239, 68, 68, 0.15)" : path.baseColor}
                      strokeWidth="1.25"
                    />
                  </g>
                ))}

                {VAULT_PATHS.map((path) => (
                  <g key={`bg-${path.id}`}>
                    <path
                      d={path.d}
                      fill="none"
                      stroke={isBreached ? "rgba(239, 68, 68, 0.08)" : "rgba(30, 41, 59, 0.4)"}
                      strokeWidth="3.2"
                    />
                    <path
                      d={path.d}
                      fill="none"
                      stroke={isBreached ? "rgba(239, 68, 68, 0.15)" : path.baseColor}
                      strokeWidth="1.5"
                    />
                  </g>
                ))}

                {/* 1. Continuous Flows matching active scenario keys and colors */}
                {isPlaying && (
                  <>
                    {LEFT_PATHS.map((path) => {
                      const isActive = path.activeSteps.includes(activeStep);
                      if (!isActive) return null;
                      const strokeColor = activeStep === 6 ? "#10b981" : isBreached ? "#ef4444" : path.glowColor;
                      const filterUrl = activeStep === 6 ? "url(#neon-glow-cyan)" : isBreached ? "url(#neon-glow-rose)" : "url(#neon-glow-cyan)";
                      return (
                        <g key={`flow-${path.id}`}>
                          {/* Rich background blur fiber trail */}
                          <motion.path
                            d={path.d}
                            fill="none"
                            stroke={strokeColor}
                            strokeWidth="3.5"
                            strokeLinecap="round"
                            filter={filterUrl}
                            style={{ strokeDasharray: "20 80" }}
                            animate={{ strokeDashoffset: [0, -100] }}
                            transition={{ duration: 1.8, repeat: Infinity, ease: "linear" }}
                          />
                          {/* Super intense white core leading rocket segment */}
                          <motion.path
                            d={path.d}
                            fill="none"
                            stroke="#ffffff"
                            strokeWidth="1.5"
                            strokeLinecap="round"
                            style={{ strokeDasharray: "8 92" }}
                            animate={{ strokeDashoffset: [4, -96] }}
                            transition={{ duration: 1.8, repeat: Infinity, ease: "linear" }}
                          />
                        </g>
                      );
                    })}

                    {RIGHT_PATHS.map((path) => {
                      const isActive = path.activeSteps.includes(activeStep);
                      if (!isActive) return null;
                      const strokeColor = activeStep === 6 ? "#10b981" : isBreached ? "#ef4444" : path.glowColor;
                      const filterUrl = activeStep === 6 ? "url(#neon-glow-cyan)" : isBreached ? "url(#neon-glow-rose)" : "url(#neon-glow-rose)";
                      return (
                        <g key={`flow-${path.id}`}>
                          <motion.path
                            d={path.d}
                            fill="none"
                            stroke={strokeColor}
                            strokeWidth="3.5"
                            strokeLinecap="round"
                            filter={filterUrl}
                            style={{ strokeDasharray: "20 80" }}
                            animate={{ strokeDashoffset: [0, -100] }}
                            transition={{ duration: 1.8, repeat: Infinity, ease: "linear" }}
                          />
                          <motion.path
                            d={path.d}
                            fill="none"
                            stroke="#ffffff"
                            strokeWidth="1.5"
                            strokeLinecap="round"
                            style={{ strokeDasharray: "8 92" }}
                            animate={{ strokeDashoffset: [4, -96] }}
                            transition={{ duration: 1.8, repeat: Infinity, ease: "linear" }}
                          />
                        </g>
                      );
                    })}

                    {VAULT_PATHS.map((path) => {
                      const isActive = path.activeSteps.includes(activeStep);
                      if (!isActive) return null;
                      const strokeColor = activeStep === 6 ? "#10b981" : isBreached ? "#ef4444" : path.glowColor;
                      const filterUrl = activeStep === 6 ? "url(#neon-glow-cyan)" : isBreached ? "url(#neon-glow-gold)" : "url(#neon-glow-gold)";
                      return (
                        <g key={`flow-${path.id}`}>
                          <motion.path
                            d={path.d}
                            fill="none"
                            stroke={strokeColor}
                            strokeWidth="4"
                            strokeLinecap="round"
                            filter={filterUrl}
                            style={{ strokeDasharray: "20 70" }}
                            animate={{ strokeDashoffset: [0, -90] }}
                            transition={{ duration: 1.8, repeat: Infinity, ease: "linear" }}
                          />
                          <motion.path
                            d={path.d}
                            fill="none"
                            stroke="#ffffff"
                            strokeWidth="1.5"
                            strokeLinecap="round"
                            style={{ strokeDasharray: "8 82" }}
                            animate={{ strokeDashoffset: [4, -86] }}
                            transition={{ duration: 1.8, repeat: Infinity, ease: "linear" }}
                          />
                        </g>
                      );
                    })}
                  </>
                )}

                {/* 2. Sequential Transit Surge Animations along entire bundlets */}
                <AnimatePresence>
                  {activePulsePhase === 'user-to-net' && LEFT_PATHS.map((path) => (
                    <g key={`surge-${path.id}`}>
                      <motion.path
                        d={path.d}
                        fill="none"
                        stroke={isBreached ? "#ef4444" : path.glowColor}
                        strokeWidth="5"
                        strokeLinecap="round"
                        filter={isBreached ? "url(#neon-glow-rose)" : "url(#neon-glow-cyan)"}
                        style={{ strokeDasharray: "35 185" }}
                        initial={{ strokeDashoffset: 220 }}
                        animate={{ strokeDashoffset: 0 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.6, ease: "linear" }}
                      />
                      <motion.path
                        d={path.d}
                        fill="none"
                        stroke="#ffffff"
                        strokeWidth="2"
                        strokeLinecap="round"
                        style={{ strokeDasharray: "15 205" }}
                        initial={{ strokeDashoffset: 220 }}
                        animate={{ strokeDashoffset: 0 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.6, ease: "linear" }}
                      />
                    </g>
                  ))}

                  {activePulsePhase === 'net-to-server' && RIGHT_PATHS.map((path) => (
                    <g key={`surge-${path.id}`}>
                      <motion.path
                        d={path.d}
                        fill="none"
                        stroke={isBreached ? "#ef4444" : path.glowColor}
                        strokeWidth="5"
                        strokeLinecap="round"
                        filter={isBreached ? "url(#neon-glow-rose)" : "url(#neon-glow-cyan)"}
                        style={{ strokeDasharray: "35 185" }}
                        initial={{ strokeDashoffset: 220 }}
                        animate={{ strokeDashoffset: 0 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.6, ease: "linear" }}
                      />
                      <motion.path
                        d={path.d}
                        fill="none"
                        stroke="#ffffff"
                        strokeWidth="2"
                        strokeLinecap="round"
                        style={{ strokeDasharray: "15 205" }}
                        initial={{ strokeDashoffset: 220 }}
                        animate={{ strokeDashoffset: 0 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.6, ease: "linear" }}
                      />
                    </g>
                  ))}

                  {activePulsePhase === 'server-to-net' && RIGHT_PATHS.map((path) => (
                    <g key={`surge-rev-${path.id}`}>
                      <motion.path
                        d={path.d}
                        fill="none"
                        stroke={isBreached ? "#f43f5e" : "#fbbf24"}
                        strokeWidth="5.5"
                        strokeLinecap="round"
                        filter={isBreached ? "url(#neon-glow-rose)" : "url(#neon-glow-gold)"}
                        style={{ strokeDasharray: "35 185" }}
                        initial={{ strokeDashoffset: 0 }}
                        animate={{ strokeDashoffset: 220 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.6, ease: "linear" }}
                      />
                      <motion.path
                        d={path.d}
                        fill="none"
                        stroke="#ffffff"
                        strokeWidth="2"
                        strokeLinecap="round"
                        style={{ strokeDasharray: "15 205" }}
                        initial={{ strokeDashoffset: 0 }}
                        animate={{ strokeDashoffset: 220 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.6, ease: "linear" }}
                      />
                    </g>
                  ))}

                  {activePulsePhase === 'net-to-vault' && VAULT_PATHS.map((path) => (
                    <g key={`surge-${path.id}`}>
                      <motion.path
                        d={path.d}
                        fill="none"
                        stroke={isBreached ? "#ef4444" : path.glowColor}
                        strokeWidth="6"
                        strokeLinecap="round"
                        filter={isBreached ? "url(#neon-glow-rose)" : "url(#neon-glow-gold)"}
                        style={{ strokeDasharray: "35 150" }}
                        initial={{ strokeDashoffset: 185 }}
                        animate={{ strokeDashoffset: 0 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.6, ease: "linear" }}
                      />
                      <motion.path
                        d={path.d}
                        fill="none"
                        stroke="#ffffff"
                        strokeWidth="2"
                        strokeLinecap="round"
                        style={{ strokeDasharray: "15 170" }}
                        initial={{ strokeDashoffset: 185 }}
                        animate={{ strokeDashoffset: 0 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.6, ease: "linear" }}
                      />
                    </g>
                  ))}
                </AnimatePresence>

                {/* Concentric Golden Gravity Rings under HNDL Vault cabinet */}
                <ellipse cx="300" cy="345" rx="55" ry="12" fill="none" stroke={isBreached ? "rgba(239, 68, 68, 0.3)" : "rgba(234, 179, 8, 0.25)"} strokeWidth="1.5" filter={isBreached ? "url(#neon-glow-rose)" : "url(#neon-glow-gold)"} />
                <motion.ellipse 
                  cx="300" 
                  cy="345" 
                  rx="75" 
                  ry="18" 
                  fill="none" 
                  stroke={isBreached ? "rgba(239, 68, 68, 0.2)" : "rgba(234, 179, 8, 0.15)"} 
                  strokeWidth="1" 
                  animate={{ scale: [1, 1.08, 1], opacity: [0.6, 1, 0.6] }}
                  transition={{ repeat: Infinity, duration: 4, ease: "easeInOut" }}
                />
              </svg>

              {/* 1. NODE: USER (HTML Overlay) */}
              <div className="absolute top-[110px] left-[15%] -translate-x-1/2 -translate-y-1/2 flex flex-col items-center z-15 w-[160px]">
                <div className="relative flex items-center justify-center">
                  <div className={`absolute -inset-2.5 rounded-full border ${isBreached ? 'border-red-500/20 animate-pulse' : 'border-blue-500/15 animate-pulse'}`} />
                  <div className={`absolute -inset-1.5 rounded-full border-2 border-dashed ${isBreached ? 'border-red-500/35' : 'border-blue-400/35'}`} />
                  <div className={`w-14 h-14 rounded-full border-2 flex items-center justify-center shadow-lg transition-all duration-700 backdrop-blur-sm ${
                    isBreached 
                      ? 'bg-red-950/25 border-red-500 text-red-400 shadow-[0_0_20px_rgba(239,68,68,0.45)]' 
                      : 'bg-blue-900/30 border-blue-400 text-blue-400 shadow-[0_0_20px_rgba(59,130,246,0.35)]'
                  }`}>
                    <User className="w-6 h-6" />
                  </div>
                </div>
                <span className={`text-[10px] font-mono font-extrabold tracking-widest mt-3.5 text-center whitespace-nowrap w-full px-1 transition-all duration-700 ${
                  isBreached ? 'text-red-400 animate-pulse' : 'text-blue-400'
                }`}>
                  {activeScenario.nodeNames.client}
                </span>
              </div>

              {/* 2. NODE: GATEWAY / CORRELATION ENGINE (HTML Overlay - High fidelity glass box from screenshot) */}
              <div className="absolute top-[110px] left-[50%] -translate-x-1/2 -translate-y-1/2 flex flex-col items-center z-15">
                {/* High Quality Labels at the top of the box */}
                <div className="flex flex-col items-center mb-2">
                  <span className={`text-[9.5px] font-mono font-black tracking-widest px-1 text-center transition-all duration-700 ${
                    isBreached ? 'text-red-400 animate-pulse' : 'text-slate-200'
                  }`}>
                    CORRELATION ENGINE
                  </span>
                  <span className="text-[7.5px] font-sans font-semibold text-slate-400 tracking-wider text-center mt-0.5 uppercase">
                    Real-time Analysis
                  </span>
                </div>

                <div className={`
                  w-[128px] h-[128px] rounded-2xl border flex flex-col items-center justify-center relative p-1.5 backdrop-blur-md transition-all duration-700
                  ${isBreached 
                    ? 'bg-red-950/80 border-red-500/40 shadow-[0_0_30px_rgba(239,68,68,0.25)]' 
                    : 'bg-[#090f1d]/90 border-slate-800/80 shadow-[0_0_30px_rgba(59,130,246,0.15)] shadow-[inset_0_0_15px_rgba(99,102,241,0.05)]'}
                `}>
                  {/* Subtle spinning gateway orbit indicator */}
                  <div className={`absolute -inset-1.5 rounded-full border border-dashed animate-spin ${isBreached ? 'border-red-500/25' : 'border-indigo-500/20'}`} style={{ animationDuration: '24s' }} />

                  {/* Inner Premium Icon Frame containing the newly generated Core Image - Enlarge/fit near the box edges */}
                  <div className={`
                    w-[116px] h-[116px] rounded-xl flex items-center justify-center border transition-all duration-500 overflow-hidden relative
                    ${isBreached 
                      ? 'bg-red-950/45 border-red-500/50 shadow-[0_0_15px_rgba(239,68,68,0.4)]' 
                      : 'bg-[#0a1224]/80 border-indigo-500/40 shadow-[inset_0_0_10px_rgba(99,102,241,0.2)]'}
                  `}>
                    <img 
                      src={correlationCoreImg} 
                      alt="Correlation Engine Core" 
                      className={`w-full h-full object-cover scale-[1.62] transition-all duration-500 origin-center ${isBreached ? 'scale-[1.72] saturate-[1.3] brightness-110' : 'hover:scale-[1.68]'}`}
                    />
                  </div>
                </div>
              </div>

              {/* 3. NODE: TARGET SERVER (HTML Overlay) */}
              <div className="absolute top-[110px] left-[85%] -translate-x-1/2 -translate-y-1/2 flex flex-col items-center z-15 w-[160px]">
                <div className="relative flex items-center justify-center">
                  <div className={`absolute -inset-2.5 rounded-full border ${isBreached ? 'border-red-500/25 animate-pulse' : 'border-rose-500/15 animate-pulse'}`} />
                  <div className={`absolute -inset-1.5 rounded-full border-2 border-dashed ${isBreached ? 'border-red-500/45' : 'border-rose-400/35'}`} />
                  <div className={`w-14 h-14 rounded-full border-2 flex items-center justify-center shadow-lg transition-all duration-700 backdrop-blur-sm ${
                    isBreached
                      ? 'bg-red-950/35 border-red-500 text-red-400 shadow-[0_0_20px_rgba(239,68,68,0.5)]'
                      : 'bg-rose-950/35 border-rose-500 text-rose-400 shadow-[0_0_20px_rgba(244,63,94,0.4)]'
                  }`}>
                    <Server className="w-6 h-6" />
                  </div>
                </div>
                <span className={`text-[10px] font-mono font-extrabold tracking-widest mt-3.5 text-center whitespace-nowrap w-full px-1 transition-all duration-700 ${
                  isBreached ? 'text-red-400' : 'text-rose-400'
                }`}>
                  {activeScenario.nodeNames.server}
                </span>
              </div>

              {/* 4. REAL PROGRESS BAR CAPSULE (Centered below Gateway/Correlation Engine node) */}
              <div className={`absolute top-[210px] left-[50%] -translate-x-1/2 rounded-2xl px-5 py-3.5 w-[280px] text-center shadow-2xl relative z-20 border transition-all duration-700 backdrop-blur-sm ${
                isBreached 
                  ? 'bg-red-950/90 border-red-500/40 text-red-400 shadow-[0_0_25px_rgba(239,68,68,0.15)]' 
                  : 'bg-[#090e1a]/95 border-cyan-500/35 text-cyan-400'
              }`}>
                <div className="flex items-center justify-between text-[11px] font-mono font-bold tracking-wide">
                  <span className="flex items-center gap-1.5 overflow-hidden text-ellipsis whitespace-nowrap">
                    <span className={`w-2 h-2 rounded-full ${isBreached ? 'bg-red-500 animate-pulse' : realtimeProgress < 100 ? 'bg-cyan-400 animate-pulse' : 'bg-emerald-400'}`} />
                    {activeStep === 1 ? "Capturing Traffic..." :
                     activeStep === 2 ? "Storing in Vault..." :
                     activeStep === 3 ? "Solving Shor's Arrays..." :
                     activeStep === 4 ? "Decrypting Keyfiles..." :
                     activeStep === 5 ? "Running Impact Matrix..." :
                     "Deploying standard PQC Shield..."}
                  </span>
                  <span className="font-mono shrink-0">{realtimeProgress}%</span>
                </div>
                {/* Real aesthetic progress indicator bar below text */}
                <div className={`w-full h-2.5 rounded-full overflow-hidden border mt-2.5 p-0.5 transition-all duration-700 ${
                  isBreached ? 'bg-red-950/80 border-red-950/90' : 'bg-slate-950 border-slate-800'
                }`}>
                  <div 
                    className={`h-full rounded-full transition-all duration-75 relative ${
                      isBreached 
                        ? 'bg-gradient-to-r from-red-600 via-rose-500 to-amber-500 shadow-[0_0_12px_rgba(239,68,68,0.9)]'
                        : 'bg-gradient-to-r from-cyan-500 via-blue-500 to-[#8b5cf6] shadow-[0_0_10px_rgba(6,182,212,0.9)]'
                    }`}
                    style={{ width: `${realtimeProgress}%` }}
                  >
                    <span className="absolute right-0 top-0 bottom-0 w-1.5 bg-white rounded-full animate-pulse shadow-xs" />
                  </div>
                </div>
              </div>

              {/* 5. NODE: GOLD HNDL VAULT cabinet (Bottom HTML Overlay) */}
              <div className="absolute bottom-[22px] left-[50%] -translate-x-1/2 flex flex-col items-center z-15 w-[150px]">
                <div className="relative flex flex-col items-center">
                  <motion.div 
                    className={`w-24 h-13 rounded-t-xl transition-all duration-700 border-t-4 border-x-2 flex flex-col items-center justify-center relative overflow-hidden ${
                      isBreached 
                        ? 'bg-[#1b0a0e] border-red-500 shadow-[0_-10px_25px_rgba(239,68,68,0.55)]' 
                        : 'bg-[#111625] border-t-4 border-x-2 border-yellow-500 shadow-[0_-10px_25px_rgba(234,179,8,0.35)]'
                    }`}
                    whileTap={{ scale: 0.97 }}
                  >
                    {/* Internal security rings and lock screens */}
                    <div className={`absolute top-1 right-2 left-2 h-0.5 transition-all duration-700 ${
                      isBreached ? 'bg-red-500/20' : 'bg-yellow-500/20'
                    }`} />
                    <div className="flex items-center gap-1.5 mt-1 transition-all duration-700">
                      {isBreached ? (
                        <>
                          <Unlock className="w-3.5 h-3.5 text-red-500 filter drop-shadow-[0_0_3px_#ef4444] animate-bounce" />
                          <span className="text-[10px] font-mono tracking-widest font-extrabold text-red-400 animate-pulse">
                            EXPOSED
                          </span>
                        </>
                      ) : (
                        <>
                          <Lock className="w-3.5 h-3.5 text-yellow-500 filter drop-shadow-[0_0_3px_#ca8a04]" />
                          <span className="text-[10px] font-mono tracking-widest font-extrabold text-yellow-400">
                            SECURE
                          </span>
                        </>
                      )}
                    </div>
                    
                    {/* Progress gold scanner */}
                    <div className={`absolute bottom-1 w-18 h-1 rounded-full animate-pulse transition-all duration-700 ${
                      isBreached ? 'bg-red-500/80' : 'bg-yellow-400/80'
                    }`} />
                  </motion.div>
                </div>
                <p className={`text-[10px] font-mono font-extrabold tracking-widest mt-2 transition-all duration-700 ${
                  isBreached ? 'text-red-400 animate-pulse' : 'text-yellow-400'
                }`}>
                  {activeScenario.nodeNames.vault}
                </p>
              </div>
            </>
          )}

        </div>
      </div>

      {/* Real Time Terminal Console section */}
      <div className="mt-5" id="simulation-quantum-terminal">
        <TerminalConsole 
          activeScenarioId={activeScenario.id}
          activeStep={activeStep}
          isPlaying={isPlaying}
        />
      </div>

      {/* 3. Bottom Stats Array Indicator grid with pause simulator triggers */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mt-6 pt-5 border-t border-slate-800/40">
        
        {/* Stat 1: Capture Rate */}
        <div className="flex items-center gap-3 bg-slate-950/40 px-3.5 py-2.5 rounded-xl border border-slate-900/80">
          <div className="w-9 h-9 rounded-full bg-cyan-950/40 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Zap className="w-4 h-4 text-cyan-400" />
          </div>
          <div>
            <span className="text-[10px] text-slate-400 font-mono block">Capture Rate</span>
            <span className="text-sm font-bold font-mono text-white">
              {isPlaying ? captureRateMBs.toFixed(2) : "0.00"} <span className="text-[10px] text-slate-400">MB/s</span>
            </span>
          </div>
        </div>

        {/* Stat 2: Stealth Level */}
        <div className="flex items-center gap-3 bg-slate-950/40 px-3.5 py-2.5 rounded-xl border border-slate-900/80">
          <div className="w-9 h-9 rounded-full bg-emerald-950/40 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <div className="w-3.5 h-1 bg-emerald-400 rounded-sm animate-pulse-glow" style={{ height: '3px' }} />
          </div>
          <div>
            <span className="text-[10px] text-slate-400 font-mono block">Stealth Level</span>
            <span className="text-sm font-bold text-emerald-400 flex items-center gap-1.5 font-sans">
              High
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            </span>
          </div>
        </div>

        {/* Play/Pause Engine button */}
        <div className="flex items-center justify-center">
          <button
            id="simulation-toggle-play-btn"
            onClick={onTogglePlay}
            className={`
              w-full py-2.5 px-3 rounded-xl text-center text-xs font-bold font-mono tracking-wider uppercase transition-all duration-300 flex items-center justify-center gap-1.5 cursor-pointer border shadow-sm
              ${isPlaying 
                ? 'bg-indigo-950/50 hover:bg-indigo-900/40 text-indigo-400 border-indigo-500/30 animate-pulse-glow' 
                : 'bg-emerald-950/50 hover:bg-emerald-900/40 text-emerald-400 border-emerald-500/30'
              }
            `}
          >
            {isPlaying ? (
              <>
                <Pause className="w-3.5 h-3.5 fill-current" />
                <span>Pause Engine</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Resume Engine</span>
              </>
            )}
          </button>
        </div>

        {/* Stat 3: Detection Risk */}
        <div className="flex items-center gap-3 bg-slate-950/40 px-3.5 py-2.5 rounded-xl border border-slate-900/80">
          <div className="w-9 h-9 rounded-full bg-blue-950/40 border border-blue-500/30 flex items-center justify-center text-blue-400">
            <Shield className="w-4 h-4 text-blue-400" />
          </div>
          <div>
            <span className="text-[10px] text-slate-400 font-mono block">Detection Risk</span>
            <span className="text-sm font-bold text-blue-400 flex items-center gap-1.5 font-sans">
              Low
              <span className="w-2 h-2 rounded-full bg-blue-400 animate-pulse" />
            </span>
          </div>
        </div>

        {/* Stat 4: Time Elapsed */}
        <div className="flex items-center gap-3 bg-slate-950/40 px-3.5 py-2.5 rounded-xl border border-slate-900/80">
          <div className="w-9 h-9 rounded-full bg-yellow-950/40 border border-yellow-500/30 flex items-center justify-center text-yellow-400">
            <Cpu className="w-4 h-4 text-yellow-400" />
          </div>
          <div>
            <span className="text-[10px] text-slate-400 font-mono block">Time Elapsed</span>
            <span className="text-sm font-bold font-mono text-slate-100">
              {formatTime(timeElapsed)}
            </span>
          </div>
        </div>

      </div>
    </div>
  );
}
