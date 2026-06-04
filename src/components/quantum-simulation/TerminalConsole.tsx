import { useEffect, useState, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Terminal, Trash2, Download } from 'lucide-react';
import { SCENARIO_COMMANDS } from '../../data/commandsData';
import { SCENARIOS } from '../../data/scenario';

interface TerminalConsoleProps {
  activeScenarioId: string;
  activeStep: number;
  isPlaying: boolean;
}

interface LogLine {
  id: string;
  text: string;
  timestamp: string;
  type: 'input' | 'info' | 'success' | 'alert' | 'math' | 'monitor' | 'system';
}

export default function TerminalConsole({
  activeScenarioId,
  activeStep,
  isPlaying,
}: TerminalConsoleProps) {
  const [lines, setLines] = useState<LogLine[]>([]);
  const viewportRef = useRef<HTMLDivElement>(null);
  const timeoutsRef = useRef<number[]>([]);
  const activeScenario = SCENARIOS.find((scenario) => scenario.id === activeScenarioId) ?? SCENARIOS[0];
  const activeStepInfo = activeScenario?.steps[activeStep] ?? activeScenario?.steps[1];
  const terminalContext = activeScenario
    ? `${activeScenario.shortName} / ${activeStepInfo?.name ?? `STEP ${activeStep}`}`
    : activeScenarioId;

  // Helper to format timestamps closely to the main theme
  const getTimestamp = () => {
    const d = new Date();
    return d.toTimeString().split(' ')[0];
  };

  // Helper to categorize line type based on text content prefix
  const getLineType = (text: string): LogLine['type'] => {
    if (text.startsWith('sys@qstack:~$')) return 'input';
    if (text.startsWith('[INFO]')) return 'info';
    if (text.startsWith('[SUCCESS]')) return 'success';
    if (text.startsWith('[ALERT]')) return 'alert';
    if (text.startsWith('[DECRYPT')) return 'alert';
    if (text.startsWith('[MATH]') || text.startsWith('[RUNNING]')) return 'math';
    if (text.startsWith('[STATUS]') || text.startsWith('[SNIFFING]')) return 'monitor';
    if (text.startsWith('[MONITOR]')) return 'monitor';
    return 'system';
  };

  // 1. Process active step changes and trigger simulated sequential printing
  useEffect(() => {
    // Clear previous timeouts first to prevent interleaving line prints
    timeoutsRef.current.forEach(clearTimeout);
    timeoutsRef.current = [];

    const scenarioData = SCENARIO_COMMANDS[activeScenarioId] || SCENARIO_COMMANDS['hndl'];
    const stepData = scenarioData[activeStep];

    if (!stepData) return;

    // Reset list and set loading sequence
    const reconnectTimestamp = getTimestamp();
    const reconnectId = Math.random().toString();
    setLines([
      {
        id: reconnectId,
        text: `>>> [RE-CONNECTING TO ${terminalContext} COMMAND STREAM...]`,
        timestamp: reconnectTimestamp,
        type: 'system',
      },
    ]);

    // Type out each line with realistic cascading offsets
    stepData.commands.forEach((cmd, idx) => {
      const delay = 400 + idx * 600; // stagger line printing
      const timeoutId = window.setTimeout(() => {
        setLines((prev) => [
          ...prev,
          {
            id: `${activeScenarioId}-${activeStep}-${idx}-${Date.now()}`,
            text: cmd,
            timestamp: getTimestamp(),
            type: getLineType(cmd),
          },
        ]);
      }, delay);
      timeoutsRef.current.push(timeoutId);
    });

    return () => {
      timeoutsRef.current.forEach(clearTimeout);
    };
  }, [activeScenarioId, activeStep, terminalContext]);

  // 2. Generate active background logs periodically when isPlaying is active
  useEffect(() => {
    if (!isPlaying) return;

    const tickLogs = [
      '[MONITOR] Qubit superconductor temperature stable at 14.8mK (Near absolute zero).',
      '[MONITOR] Quantum coherence margin: 99.9881% | Josephson junction flux locked.',
      '[MONITOR] Active quantum walk solvers status: Iterating Hadamard transforms.',
      '[MONITOR] Grover database search rate: 4.85x10^9 trials/sec.',
      '[MONITOR] Core entropy coefficient status: 0.999812 (High system randomness).',
      '[MONITOR] Target network gate stream: Synchronized. Framing errors: 0.00%.',
    ];

    const interval = setInterval(() => {
      const randomText = tickLogs[Math.floor(Math.random() * tickLogs.length)];
      setLines((prev) => {
        // Keep logs from expanding infinitely in RAM
        const sliced = prev.length > 50 ? prev.slice(prev.length - 40) : prev;
        return [
          ...sliced,
          {
            id: `monitor-${Date.now()}`,
            text: randomText,
            timestamp: getTimestamp(),
            type: 'monitor',
          },
        ];
      });
    }, 4500); // add a background log line every 4.5 seconds

    return () => clearInterval(interval);
  }, [isPlaying]);

  // 3. Auto-scroll terminal frame
  useEffect(() => {
    if (viewportRef.current) {
      viewportRef.current.scrollTop = viewportRef.current.scrollHeight;
    }
  }, [lines]);

  const handleClear = () => {
    setLines([
      {
        id: `clear-${Date.now()}`,
        text: `[SYSTEM] Terminal buffer traces wiped cleanly. Prompt listening.`,
        timestamp: getTimestamp(),
        type: 'system',
      },
    ]);
  };

  const handleDownload = () => {
    const rawText = lines.map((l) => `[${l.timestamp}] ${l.text}`).join('\n');
    const blob = new Blob([rawText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `quantum_terminal_logs_${activeScenarioId}_step_${activeStep}.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const isBreached = activeStep >= 3 && activeStep <= 5;

  return (
    <div
      id="quantum-terminal-console-panel"
      className={`
        rounded-2xl border bg-black/95 flex flex-col overflow-hidden transition-all duration-500 font-mono shadow-xl relative
        ${
          isBreached
            ? 'border-red-950 shadow-[0_0_25px_rgba(239,68,68,0.06)]'
            : 'border-slate-800 shadow-[0_0_25px_rgba(59,130,246,0.04)]'
        }
      `}
    >
      {/* Top Header Rail */}
      <div
        className={`
          flex items-center justify-between px-4 py-3 border-b select-none
          ${isBreached ? 'bg-red-950/20 border-red-950' : 'bg-slate-900/40 border-slate-800'}
        `}
      >
        <div className="flex items-center gap-2">
          {/* Animated blinking terminal prompt status */}
          <span className="flex h-3 w-3 relative shrink-0">
            <span
              className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                isBreached ? 'bg-red-500' : 'bg-cyan-500'
              }`}
            />
            <span
              className={`relative inline-flex rounded-full h-3 w-3 ${
                isBreached ? 'bg-red-600' : 'bg-cyan-500'
              }`}
            />
          </span>
          <div className="flex flex-col gap-0.5">
            <span
              className={`text-xs font-black tracking-widest uppercase flex items-center gap-1.5 ${
                isBreached ? 'text-red-400' : 'text-slate-200'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              Quantum Intrusion Terminal
            </span>
            <span className="text-[9px] text-slate-500 font-bold uppercase tracking-[0.14em]">
              {activeScenario?.category ?? 'Scenario'} / {activeStepInfo?.name ?? `Step ${activeStep}`}
            </span>
          </div>
          {isPlaying && (
            <span className="text-[10px] bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 font-bold px-1.5 py-0.5 rounded-sm animate-pulse">
              LIVE ENGINE
            </span>
          )}
        </div>

        {/* Toolbar Controls */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleDownload}
            title="Download Session Log"
            className="p-1 px-2 text-[10px] scroll-py-1 text-slate-400 hover:text-white bg-slate-900/60 border border-slate-800 rounded-md transition-all flex items-center gap-1 cursor-pointer"
          >
            <Download className="w-3 h-3 text-slate-400 hover:text-white" />
            <span>EXPORT</span>
          </button>
          <button
            onClick={handleClear}
            title="Wipe Terminal View"
            className="p-1 px-2 text-[10px] text-slate-400 hover:text-red-400 bg-slate-900/60 border border-slate-800 rounded-md transition-all flex items-center gap-1 cursor-pointer"
          >
            <Trash2 className="w-3 h-3" />
            <span>WIPE</span>
          </button>
        </div>
      </div>

      {/* Glow effect Overlay */}
      <div className="absolute inset-0 bg-radial-gradient(ellipse_at_top,transparent_60%,rgba(0,0,0,0.4)) pointer-events-none" />

      {/* Scrollable logs box */}
      <div
        ref={viewportRef}
        className="p-4 overflow-y-auto max-h-[175px] min-h-[140px] space-y-2 text-[11px] font-mono leading-relaxed select-text custom-scrollbar scroll-smooth flex-1 relative z-10"
        id="quantum-terminal-stdout-viewport"
      >
        <AnimatePresence initial={false}>
          {lines.map((line) => {
            let textColor = 'text-slate-300';
            if (line.type === 'input') {
              textColor = isBreached ? 'text-rose-400 font-bold' : 'text-cyan-400 font-bold';
            } else if (line.type === 'success') {
              textColor = 'text-emerald-400 font-semibold';
            } else if (line.type === 'alert') {
              textColor = 'text-amber-400 font-semibold';
            } else if (line.type === 'math') {
              textColor = 'text-indigo-400 font-semibold';
            } else if (line.type === 'monitor') {
              textColor = 'text-slate-500 font-medium italic';
            } else if (line.type === 'system') {
              textColor = 'text-pink-500 font-bold';
            }

            return (
              <motion.div
                key={line.id}
                initial={{ opacity: 0, x: -5 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.15 }}
                className="flex items-start gap-2.5 hover:bg-white/[0.02] py-0.5 px-1 rounded-sm border border-transparent hover:border-white/[0.01]"
              >
                {/* Timestamp index */}
                <span className="text-[10px] text-slate-600 select-none font-mono shrink-0 pt-0.5">
                  [{line.timestamp}]
                </span>

                {/* Styled text block */}
                <div className={`whitespace-pre-wrap word-break-all ${textColor} flex-1`}>
                  {line.text}
                </div>
              </motion.div>
            );
          })}
        </AnimatePresence>

        {/* Floating live cursor index at bottom */}
        <div className="flex items-center gap-1 text-[11px] text-slate-500 italic pt-1 animate-pulse select-none">
          <span className="w-1.5 h-3 bg-cyan-400 shrink-0 inline-block align-middle" />
          <span>idle prompt listening for cryptographic events...</span>
        </div>
      </div>

      {/* Cyber Grid Lines Overlay with low opacity */}
      <div className="absolute inset-0 bg-[linear-gradient(rgba(18,24,38,0.1)_1px,transparent_1px),linear-gradient(90deg,rgba(18,24,38,0.1)_1px,transparent_1px)] bg-[size:16px_16px] pointer-events-none select-none opacity-20" />
    </div>
  );
}
