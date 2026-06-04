import { motion } from 'motion/react';
import { Check } from 'lucide-react';

interface TimelineStepsProps {
  activeStep: number;
  onStepChange: (step: number) => void;
}

export default function TimelineSteps({ activeStep, onStepChange }: TimelineStepsProps) {
  const steps = [
    { number: 1, label: 'Harvest', desc: '1 Harvest' },
    { number: 2, label: 'Store', desc: '2 Store' },
    { number: 3, label: 'Quantum Break', desc: '3 Quantum Break' },
    { number: 4, label: 'Decrypt', desc: '4 Decrypt' },
    { number: 5, label: 'Impact', desc: '5 Impact' },
    { number: 6, label: 'Defend', desc: 'Defend' },
  ];

  return (
    <div id="timeline-container" className="flex items-center justify-between w-full max-w-2xl px-5 pt-3.5 pb-3 bg-white/50 backdrop-blur-sm rounded-2xl border border-slate-100/80 shadow-xs">
      <div className="relative flex items-center justify-between w-full">
        {/* Connecting line aligned to the vertical center of the 32px (w-8 h-8) action circles (exactly 16px from top) */}
        <div className="absolute top-[16px] left-4 right-4 h-[2px] bg-slate-200 -translate-y-1/2 z-0">
          <motion.div 
            className="absolute h-full bg-indigo-500 rounded-full"
            style={{ 
              width: `${((Math.max(1, activeStep) - 1) / (steps.length - 1)) * 100}%` 
            }}
            layoutId="active-line-progress"
            transition={{ type: "spring", stiffness: 80, damping: 15 }}
          />
        </div>

        {/* Actionable Circles */}
        {steps.map((step) => {
          const isCompleted = step.number < activeStep;
          const isActive = step.number === activeStep;
          const isLocked = step.number > activeStep;

          return (
            <button
              key={step.number}
              id={`timeline-step-btn-${step.number}`}
              onClick={() => onStepChange(step.number)}
              className="relative z-10 flex flex-col items-center group focus:outline-hidden px-1"
            >
              <div 
                className={`
                  w-8 h-8 rounded-full flex items-center justify-center text-xs font-semibold font-display transition-all duration-300
                  ${isActive 
                    ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-200 ring-4 ring-indigo-50' 
                    : isCompleted 
                    ? 'bg-emerald-500 text-white' 
                    : 'bg-white text-slate-400 border border-slate-200 group-hover:border-indigo-400 group-hover:text-slate-600'
                  }
                `}
              >
                {isCompleted ? (
                  <Check className="w-4 h-4" strokeWidth={3} />
                ) : (
                  <span>{step.number}</span>
                )}
              </div>
              <span 
                className={`
                  mt-1.5 text-[10px] sm:text-[11px] font-medium transition-colors duration-200 whitespace-nowrap hidden xs:block
                  ${isActive 
                    ? 'text-indigo-600 font-semibold' 
                    : 'text-slate-400 group-hover:text-slate-600'
                  }
                `}
              >
                {step.desc}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
