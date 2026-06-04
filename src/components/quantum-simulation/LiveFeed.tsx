import { motion, AnimatePresence } from 'motion/react';
import { Terminal } from 'lucide-react';
import { LogEntry, TargetType } from '../../types';

interface LiveFeedProps {
  logs: LogEntry[];
  isPlaying: boolean;
  activeTarget: TargetType;
  activeStep: number;
}

export default function LiveFeed({ logs, isPlaying, activeTarget, activeStep }: LiveFeedProps) {
  const isBreached = activeStep >= 3 && activeStep <= 5;

  return (
    <div 
      uid="live-feed-panel" 
      id="live-feed-panel" 
      className={`rounded-2xl p-4.5 flex flex-col justify-between h-full min-h-[220px] transition-all duration-700 border ${
        isBreached 
          ? 'bg-black border-2 border-red-600 shadow-[0_0_25px_rgba(239,68,68,0.4)]' 
          : 'bg-black border-2 border-zinc-700'
      }`}
    >
      <div className={`flex items-center justify-between border-b pb-2.5 mb-2.5 transition-all duration-700 ${
        isBreached ? 'border-red-900' : 'border-zinc-700'
      }`}>
        <div className="flex items-center gap-2">
          <Terminal className={`w-4 h-4 transition-all duration-700 ${isBreached ? 'text-red-500 animate-pulse' : 'text-zinc-200'}`} />
          <span className={`text-[11px] font-mono tracking-wider font-black uppercase transition-all duration-700 ${
            isBreached ? 'text-red-500 text-shadow-glow' : 'text-white'
          }`}>
            Live Feed Telemetry
          </span>
        </div>
        {isPlaying ? (
          <span className={`flex items-center gap-1.5 text-[9px] font-mono font-bold px-2 py-0.5 rounded-sm border transition-all duration-700 ${
            isBreached 
              ? 'bg-red-950/50 text-red-400 border-red-500' 
              : 'bg-zinc-900 text-white border-zinc-650'
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full animate-ping ${isBreached ? 'bg-red-550' : 'bg-emerald-400'}`} />
            LIVESTREAM
          </span>
        ) : (
          <span className="text-[9px] font-mono text-zinc-400 font-bold bg-zinc-900 border border-zinc-700 px-2 py-0.5 rounded-sm">
            PAUSED
          </span>
        )}
      </div>

      {/* Logs Scroll Frame */}
      <div className="flex-1 min-h-0 overflow-y-auto custom-scrollbar space-y-2 pr-1 text-[11.5px] font-mono">
        <AnimatePresence initial={false}>
          {logs.map((log) => {
            const isAlert = log.type === 'warning' || log.type === 'error';
            return (
              <motion.div
                key={log.id}
                id={`feed-log-${log.id}`}
                initial={{ opacity: 0, x: -10, y: 5 }}
                animate={{ opacity: 1, x: 0, y: 0 }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ type: "spring", stiffness: 200, damping: 20 }}
                className={`flex gap-2.5 p-2 rounded-lg leading-relaxed border transition-all duration-300 ${
                  isAlert 
                    ? 'bg-black border-red-600 border-l-4 border-l-red-500 text-red-100 font-bold shadow-[inset_0_0_10px_rgba(239,68,68,0.15)]' 
                    : log.type === 'success'
                      ? 'bg-black border-zinc-800 border-l-4 border-l-emerald-500 text-emerald-300'
                      : 'bg-black border-zinc-800 border-l-4 border-l-zinc-100 text-white'
                }`}
              >
                <span className={`font-black tracking-tight select-none shrink-0 ${
                  isAlert ? 'text-red-500' : 'text-zinc-400'
                }`}>
                  [{log.timestamp}]
                </span>
                <span className="flex-1 select-all">{log.text}</span>
              </motion.div>
            );
          })}
        </AnimatePresence>

        {logs.length === 0 && (
          <div className="text-zinc-400 text-center py-6 font-bold">
            Waiting for simulation broadcast stream...
          </div>
        )}
      </div>

      <div className={`flex justify-between items-center mt-3 pt-2 text-[10px] border-t transition-all duration-700 ${
        isBreached ? 'border-red-900 text-red-400' : 'border-zinc-700 text-zinc-300'
      }`}>
        <span>Target: <strong className={isBreached ? 'text-red-500 font-black' : 'text-white font-black'}>{activeTarget}</strong></span>
        <span>Stage: <strong className={isBreached ? 'text-red-500 font-black' : 'text-white font-black'}>{activeStep} / 6</strong></span>
      </div>
    </div>
  );
}
