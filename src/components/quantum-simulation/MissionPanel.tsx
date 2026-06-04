import { motion } from 'motion/react';
import { HelpCircle, Star, Sparkles, CheckCircle2, Circle, ShieldAlert } from 'lucide-react';
import { Scenario } from '../../data/scenario';

interface MissionPanelProps {
  activeStep: number;
  activeScenario: Scenario;
}

export default function MissionPanel({ activeStep, activeScenario }: MissionPanelProps) {
  // Step objectives derived dynamically from the current active scenario
  const stepsList = [1, 2, 3, 4, 5, 6].map((i) => {
    const stepObj = activeScenario.steps[i] || { name: `Stage ${i}` };
    return {
      number: i,
      label: stepObj.name,
      minStep: i
    };
  });

  const calculatedProgress = Math.min(100, Math.round(((activeStep - 1) / 5) * 100));

  return (
    <div id="mission-panel" className="bg-white/70 backdrop-blur-md rounded-2xl p-5 border border-slate-100/90 shadow-xs flex flex-col justify-between h-full">
      <div>
        {/* Header */}
        <div className="flex justify-between items-start pb-3.5 border-b border-slate-100">
          <div>
            <span className="text-[10px] font-mono tracking-wider font-extrabold text-indigo-500 uppercase">
              Operations Tactical File
            </span>
            <h2 className="text-sm font-extrabold text-slate-900 font-display mt-0.5 uppercase tracking-wide">
              {activeScenario.name}
            </h2>
          </div>
          <HelpCircle className="w-4 h-4 text-slate-300 hover:text-slate-500 cursor-help" />
        </div>

        {/* Narrative description */}
        <p className="text-xs text-slate-500 leading-relaxed mt-3 flex items-start gap-1 font-sans">
          <span>{activeScenario.objectiveText}</span>
        </p>

        {/* Dynamic overall Progress */}
        <div className="mt-4">
          <div className="flex justify-between items-center text-[10px] font-mono font-semibold text-slate-500 mb-1">
            <span>Overall Simulation Progress</span>
            <span className="text-indigo-600">{calculatedProgress}%</span>
          </div>
          <div className="w-full bg-slate-100 h-2 rounded-full overflow-hidden">
            <motion.div 
              className="h-full bg-indigo-600 rounded-full" 
              style={{ width: `${calculatedProgress}%` }}
              animate={{ width: `${calculatedProgress}%` }}
              transition={{ duration: 0.4 }}
            />
          </div>
        </div>

        {/* Objectives Stack checklists */}
        <div className="mt-5 space-y-2.5">
          {stepsList.map((st) => {
            const isDone = activeStep > st.minStep;
            const isWorking = activeStep === st.minStep;
            const isLocked = activeStep < st.minStep;

            return (
              <div
                key={st.number}
                className={`
                  flex items-center justify-between p-2.5 rounded-xl border transition-all duration-200
                  ${isWorking 
                    ? 'bg-indigo-500/10 border-indigo-200 shadow-xs shadow-indigo-100 text-indigo-900' 
                    : isDone
                    ? 'bg-slate-50/50 border-slate-100 text-slate-700'
                    : 'bg-slate-100/30 border-slate-100/80 text-slate-400'
                  }
                `}
              >
                <div id={`mission-step-row-${st.number}`} className="flex items-center gap-2.5">
                  {isDone ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-500 fill-emerald-50" />
                  ) : isWorking ? (
                    <span className="relative flex h-2 w-2">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-indigo-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-indigo-600"></span>
                    </span>
                  ) : (
                    <span className="w-1.5 h-1.5 rounded-full bg-slate-200" />
                  )}

                  <span className={`text-xs ${isWorking ? 'font-semibold' : 'font-medium'} font-display`}>
                    {st.label}
                  </span>
                </div>

                {isLocked && (
                  <span className="text-[10px] font-mono text-slate-300">Locked</span>
                )}
              </div>
            );
          })}
        </div>
      </div>

    </div>
  );
}
