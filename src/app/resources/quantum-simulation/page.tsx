import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import LiveFeed from '@/components/quantum-simulation/LiveFeed';
import QuantumInfographic from '@/components/quantum-simulation/QuantumInfographic';
import SimulationCanvas from '@/components/quantum-simulation/SimulationCanvas';
import ScenarioTabs from '@/components/quantum-simulation/ScenarioTabs';
import TimelineSteps from '@/components/quantum-simulation/TimelineSteps';
import CybercoreBackground from '@/components/ui/cyberscore-section-hero';
import { SCENARIOS as SIMULATION_SCENARIOS, type Scenario } from '@/data/scenario';
import type { LogEntry, TargetType } from '@/types';

/* ── constants ──────────────────────────────────────────────────── */
const FALLBACK_TARGET = SIMULATION_SCENARIOS[0]?.targets[0] ?? 'Core Network';
const INITIAL_TELEMETRY_LOGS: LogEntry[] = [
  { id: '1', timestamp: '03:44:12', text: 'NIST Warn: Captured TLS session with vulnerable ASYMMETRIC key exchange.', type: 'warning' },
  { id: '2', timestamp: '03:43:08', text: 'ClientHello raw packets successfully captured from interface port 443.', type: 'info' },
  { id: '3', timestamp: '03:41:55', text: 'Quantum simulation buffers active and awaiting retroactive decryption.', type: 'info' },
  { id: '4', timestamp: '03:40:02', text: 'Monitoring raw gateway channels for classical cryptographic signature patterns.', type: 'info' },
];

/* ── floating particle background ────────────────────────────────── */
function QuantumBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const cvs = canvasRef.current;
    if (!cvs) return;
    const ctx = cvs.getContext('2d')!;
    let raf: number;

    const particles: Array<{
      x: number;
      y: number;
      vx: number;
      vy: number;
      r: number;
      o: number;
      hue: number;
    }> = [];

    const resize = () => {
      cvs.width = window.innerWidth;
      cvs.height = window.innerHeight;
    };
    resize();
    window.addEventListener('resize', resize);

    for (let i = 0; i < 80; i++) {
      particles.push({
        x: Math.random() * cvs.width,
        y: Math.random() * cvs.height,
        vx: (Math.random() - 0.5) * 0.3,
        vy: (Math.random() - 0.5) * 0.3,
        r: Math.random() * 2 + 0.5,
        o: Math.random() * 0.3 + 0.05,
        hue: 220 + Math.random() * 60,
      });
    }

    const draw = () => {
      ctx.clearRect(0, 0, cvs.width, cvs.height);
      for (const p of particles) {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0 || p.x > cvs.width) p.vx *= -1;
        if (p.y < 0 || p.y > cvs.height) p.vy *= -1;
        ctx.fillStyle = `hsla(${p.hue}, 60%, 65%, ${p.o})`;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fill();
      }

      /* connections */
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const d = Math.sqrt(dx * dx + dy * dy);
          if (d < 120) {
            ctx.strokeStyle = `hsla(240, 50%, 60%, ${0.06 * (1 - d / 120)})`;
            ctx.lineWidth = 0.5;
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.stroke();
          }
        }
      }
      raf = requestAnimationFrame(draw);
    };
    raf = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', resize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 pointer-events-none z-0"
      style={{ opacity: 0.6 }}
    />
  );
}

/* ── readiness score ring ────────────────────────────────────────── */
/* ════════════════════════════════════════════════════════════════
   MAIN PAGE
   ════════════════════════════════════════════════════════════════ */
export default function QuantumSimulationPage() {
  const [scenarioId, setScenarioId] = useState(SIMULATION_SCENARIOS[0].id);
  const activeScenario = useMemo(
    () => SIMULATION_SCENARIOS.find((item) => item.id === scenarioId) ?? SIMULATION_SCENARIOS[0],
    [scenarioId]
  );
  const [target, setTarget] = useState<TargetType>(FALLBACK_TARGET);
  const [isRunning, setIsRunning] = useState(true);
  const [currentStep, setCurrentStep] = useState(0);
  const [packetsCaptured, setPacketsCaptured] = useState(activeScenario.metrics.basePackets);
  const [timeElapsed, setTimeElapsed] = useState(0);
  const [logs, setLogs] = useState<LogEntry[]>(INITIAL_TELEMETRY_LOGS);
  const [showScenarioDropdown, setShowScenarioDropdown] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const activeStep = currentStep + 1;
  const captureRateMBs = activeScenario.metrics.captureRate;
  const harvestedSizeGB =
    activeScenario.metrics.baseSizeGB +
    Math.max(0, packetsCaptured - activeScenario.metrics.basePackets) / 1_000_000;
  const stealthLevel = Math.max(12, 92 - currentStep * 11);
  const detectionRisk: 'Low' | 'Medium' | 'High' =
    activeStep >= 3 ? activeScenario.metrics.riskLevel : 'Low';

  const nextStep = useCallback(() => {
    const nextIndex = currentStep >= 5 ? 0 : currentStep + 1;
    const hhmmss = new Date().toTimeString().split(' ')[0];

    setCurrentStep(nextIndex);
    if (nextIndex === 0) {
      setPacketsCaptured(activeScenario.metrics.basePackets);
      setTimeElapsed(0);
      setLogs([
        {
          id: String(Date.now()),
          timestamp: hhmmss,
          text: '>>> RESTART LOGS: Quantum simulation reset to Stage 1!',
          type: 'warning',
        },
      ]);
      return;
    }

    setLogs((prev) => [
      {
        id: String(Date.now()),
        timestamp: hhmmss,
        text: `>>> ACTION TRANSITION: Advanced to Scenario Stage ${nextIndex + 1}!`,
        type: 'success',
      },
      ...prev.slice(0, 15),
    ]);
  }, [activeScenario.metrics.basePackets, currentStep]);

  /* auto-advance steps */
  useEffect(() => {
    if (!isRunning) return;
    const iv = setInterval(nextStep, 12000);
    return () => clearInterval(iv);
  }, [isRunning, nextStep]);

  useEffect(() => {
    if (!isRunning) return;
    const iv = setInterval(() => {
      setTimeElapsed((seconds) => seconds + 1);
      setPacketsCaptured((packets) => {
        const nextBatch = Math.max(1, Math.round(activeScenario.metrics.captureRate * 120 + Math.random() * 80));
        return packets + nextBatch;
      });
    }, 1000);
    return () => clearInterval(iv);
  }, [activeScenario.metrics.captureRate, isRunning]);

  /* append context logging periodically as simulation runs */
  useEffect(() => {
    if (!isRunning) return;

    const logGenerator = setInterval(() => {
      const hhmmss = new Date().toTimeString().split(' ')[0];
      const stepTelemetry: Record<number, string[]> = {
        1: [
          `NIST SP 800-52: Intercepting active transit packets on ${target}.`,
          `Quantum Intercept: Buffer sequence initialized targeting ${activeScenario.nodeNames.gateway}.`,
          'Vulnerability Alert: Asymmetric handshake lacks post-quantum secure key exchanges.',
          `Exfiltration rate calibrated at ${activeScenario.metrics.captureRate} MB/s.`,
        ],
        2: [
          `Archiving raw ciphertext keys into Quantum Vault partition of target ${target}.`,
          `Node Sync: ${activeScenario.nodeNames.client} data successfully exfiltrated & structured.`,
          `Database Status: Sinking raw binary blocks to ${activeScenario.nodeNames.vault}.`,
          'Archived frame stream index synchronized on local ledger.',
        ],
        3: [
          `SHOR CORE MATRIX: Initiating factorization array against ${target} ciphers.`,
          'Quantum Qubit Core executing: Mapping modular periodic exponents on Shor cores.',
          'NIST SP 800-22: Synthesizing quantum Fourier period transform registers.',
          'Running Grover search loops to reduce symmetric key strength parameters.',
        ],
        4: [
          'DECRYPTION ENGINE: Extraction complete! Asymmetric factors resolved.',
          `Decryption active: Exposing raw plainstream records from ${target}.`,
          'Decrypted files outputted online. Host security ratings collapsing to CRITICAL.',
          'Auth token hashes verified against legacy SHA keys.',
        ],
        5: [
          `IMPACT LOGS: Mapping lateral taking of host nodes from ${target}.`,
          `Exposing core variables on ${activeScenario.nodeNames.server} domain controller.`,
          `Corporate Assessment: ${activeScenario.impactText.slice(0, 80)}...`,
          'Identity token validation bypass registered on gateway channels.',
        ],
        6: [
          'PQC UPGRADE: Migrating tunnel handshake structure to ML-KEM post-quantum encapsulation.',
          'Enforcing NIST FIPS 204: Deploying ML-DSA digital signature certificates.',
          `Legacy cipher blocks disabled on ${target} ports.`,
          'Host security readiness restored to maximum levels.',
        ],
      };

      const templates = stepTelemetry[activeStep] ?? stepTelemetry[1];
      const text = templates[Math.floor(Math.random() * templates.length)];

      setLogs((prev) => [
        {
          id: String(Date.now()),
          timestamp: hhmmss,
          text,
          type: activeStep >= 3 && activeStep <= 5 ? 'error' : activeStep === 6 ? 'success' : 'info',
        },
        ...prev.slice(0, 15),
      ]);
    }, 4500);

    return () => clearInterval(logGenerator);
  }, [activeScenario, activeStep, isRunning, target]);

  /* close dropdown on outside click */
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setShowScenarioDropdown(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const toggleRunning = useCallback(() => setIsRunning((r) => !r), []);

  const setStepFromTimeline = useCallback((step: number) => {
    const nextIndex = Math.max(0, Math.min(step - 1, 5));
    const hhmmss = new Date().toTimeString().split(' ')[0];

    setCurrentStep(nextIndex);
    setLogs((prev) => [
      {
        id: String(Date.now()),
        timestamp: hhmmss,
        text: `>>> MANUAL SELECT: Switched active scene context to Step ${nextIndex + 1}`,
        type: 'info',
      },
      ...prev.slice(0, 15),
    ]);
  }, []);

  const handleScenarioSelect = useCallback((nextScenario: Scenario) => {
    const hhmmss = new Date().toTimeString().split(' ')[0];

    setScenarioId(nextScenario.id);
    setTarget(nextScenario.targets[0] ?? FALLBACK_TARGET);
    setCurrentStep(0);
    setPacketsCaptured(nextScenario.metrics.basePackets);
    setTimeElapsed(0);
    setLogs([
      {
        id: String(Date.now()),
        timestamp: hhmmss,
        text: `>>> SCENARIO INIT: Loaded "${nextScenario.name}" - System Ready.`,
        type: 'success',
      },
      {
        id: String(Date.now() + 1),
        timestamp: hhmmss,
        text: `Objective: ${nextScenario.objectiveText}`,
        type: 'info',
      },
    ]);
    setShowScenarioDropdown(false);
  }, []);

  return (
    <div className="qs-page min-h-screen text-slate-900 overflow-x-hidden">
      <QuantumBackground />

      <section className="qs-cybercore-hero relative z-10 overflow-hidden border-b border-indigo-500/10">
        <CybercoreBackground beamCount={90} />
        <div className="relative z-10 max-w-[1600px] mx-auto px-4 py-10 md:py-14">
          <div className="max-w-4xl">
            <div className="text-[10px] md:text-xs text-cyan-300 font-black uppercase tracking-[0.28em] mb-3">
              Qguard Helix Quantum Range
            </div>
            <h1 className="text-4xl md:text-6xl font-black text-white tracking-wide">
              Quantum Attack Simulation
            </h1>
            <p className="mt-4 max-w-2xl text-sm md:text-base text-slate-300 leading-relaxed">
              {activeScenario.narrative}
            </p>
            <div className="mt-6 flex flex-wrap gap-3">
              <span className="rounded-full border border-cyan-400/25 bg-cyan-400/10 px-3 py-1.5 text-xs font-bold text-cyan-200">
                {activeScenario.category}
              </span>
              <span className="rounded-full border border-indigo-400/25 bg-indigo-400/10 px-3 py-1.5 text-xs font-bold text-indigo-200">
                {activeScenario.shortName}
              </span>
              <span className="rounded-full border border-emerald-400/25 bg-emerald-400/10 px-3 py-1.5 text-xs font-bold text-emerald-200">
                Target: {target}
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* ─── SCENARIO SELECTOR + TIMELINE ──────────────────────── */}
      <div className="relative z-50 max-w-[1600px] mx-auto px-4 pt-5 pb-3">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
          {/* Scenario dropdown */}
          <div ref={dropdownRef} className="relative z-[80]">
            <div className="text-[10px] text-indigo-400 font-bold uppercase tracking-[0.18em] mb-1.5">
              Select Scenario
            </div>
            <button
              onClick={() => setShowScenarioDropdown(!showScenarioDropdown)}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[#0f1135]/80 border border-indigo-500/20 text-sm font-semibold text-slate-200 hover:border-indigo-500/40 transition-colors min-w-[280px]"
            >
              <span className="flex-1 text-left">{activeScenario.name}</span>
              <svg className="w-4 h-4 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            <AnimatePresence>
              {showScenarioDropdown && (
                <motion.div
                  initial={{ opacity: 0, y: -4 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -4 }}
                  className="absolute top-full left-0 mt-1 w-full rounded-lg bg-[#0f1135] border border-indigo-500/25 shadow-2xl overflow-hidden z-[100]"
                >
                  {SIMULATION_SCENARIOS.map((s) => (
                    <button
                      key={s.id}
                      onClick={() => handleScenarioSelect(s)}
                      className="w-full text-left px-4 py-2.5 text-xs font-medium text-slate-300 hover:bg-indigo-500/10 hover:text-indigo-200 transition-colors"
                      style={{
                        background: activeScenario.id === s.id ? 'rgba(99, 102, 241, 0.12)' : undefined,
                        color: activeScenario.id === s.id ? '#c7d2fe' : undefined,
                      }}
                    >
                      {s.name}
                    </button>
                  ))}
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Timeline steps */}
          <div className="flex w-full flex-col items-stretch justify-center gap-3 sm:flex-row sm:items-center lg:flex-1">
            <motion.button
              onClick={nextStep}
              whileHover={{ scale: 1.04 }}
              whileTap={{ scale: 0.97 }}
              className="flex h-[68px] items-center justify-center gap-2 rounded-2xl px-5 text-sm font-black text-white shadow-lg shadow-indigo-500/25 transition-all sm:w-[178px]"
              style={{
                background: 'linear-gradient(135deg, #4f46e5, #7c3aed)',
              }}
            >
              Next Step
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
              </svg>
            </motion.button>
            <TimelineSteps activeStep={activeStep} onStepChange={setStepFromTimeline} />
          </div>
        </div>
      </div>

      {/* ─── MAIN CONTENT ─────────────────────────────────────── */}
      <div className="relative z-10 max-w-[1600px] mx-auto px-4 pb-6">
        <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_320px] 2xl:grid-cols-[minmax(0,1fr)_360px] gap-6 items-start">
          {/* Left + Center */}
          <div className="space-y-4 min-w-0">
            {/* Simulation area + terminal feed */}
            <div>
              {/* Left column: Objective + Canvas */}
              <div className="space-y-4">
                {/* System Map + Live Terminal from /src/data/scenario.ts and /src/data/commandsData.ts */}
                <div className="rounded-xl border border-indigo-500/15">
                  <SimulationCanvas
                    isPlaying={isRunning}
                    onTogglePlay={toggleRunning}
                    activeScenario={activeScenario}
                    activeTarget={target}
                    onChangeTarget={setTarget}
                    packetsCaptured={packetsCaptured}
                    harvestedSizeGB={harvestedSizeGB}
                    captureRateMBs={captureRateMBs}
                    stealthLevel={stealthLevel}
                    detectionRisk={detectionRisk}
                    activeStep={activeStep}
                    timeElapsed={timeElapsed}
                    onNextStep={nextStep}
                  />
                </div>

                {/* Simulation controls */}
                <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                  <motion.button
                    onClick={toggleRunning}
                    whileHover={{ scale: 1.04 }}
                    whileTap={{ scale: 0.97 }}
                    className="flex items-center justify-center gap-2 px-6 py-3 rounded-xl font-bold text-sm transition-all w-full sm:w-auto"
                    style={{
                      background: isRunning
                        ? 'linear-gradient(135deg, #4f46e5, #6366f1)'
                        : 'linear-gradient(135deg, #059669, #10b981)',
                      color: '#fff',
                      boxShadow: isRunning
                        ? '0 0 24px rgba(99, 102, 241, 0.4)'
                        : '0 0 24px rgba(16, 185, 129, 0.4)',
                    }}
                  >
                    {isRunning ? (
                      <>
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        Pause Harvest
                      </>
                    ) : (
                      <>
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                          <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        Resume Harvest
                      </>
                    )}
                  </motion.button>
                </div>
              </div>
            </div>

            {/* ─── SCENARIO TABS (bottom) ────────────────────────── */}
            <ScenarioTabs activeStep={activeStep} activeScenario={activeScenario} />
          </div>

          <aside className="h-[620px] min-h-[520px] xl:sticky xl:top-20 xl:h-[calc(100vh-6rem)]">
            <LiveFeed
              logs={logs}
              isPlaying={isRunning}
              activeTarget={target}
              activeStep={activeStep}
            />
          </aside>
        </div>
      </div>

      <div className="relative z-10 max-w-[1600px] mx-auto px-4 pb-8">
        <QuantumInfographic />
      </div>

    </div>
  );
}
