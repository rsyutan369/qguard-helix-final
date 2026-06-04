import { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Shield, Brain, ServerCrash, GitCompare, Landmark, Eye, Compass, ArrowRight, ShieldCheck } from 'lucide-react';
import { Scenario } from '../../data/scenario';

interface ScenarioTabsProps {
  activeStep: number;
  activeScenario: Scenario;
}

export default function ScenarioTabs({ activeStep, activeScenario }: ScenarioTabsProps) {
  const [activeTab, setActiveTab] = useState<'how' | 'learn' | 'real'>('how');

  // Dynamic Flowchart steps mapped from current scenario parameters
  const icons = [Compass, GitCompare, Brain, ServerCrash, Landmark, ShieldCheck];
  
  const flowSteps = [1, 2, 3, 4, 5].map((i) => {
    const stepObj = activeScenario.steps[i] || { name: 'Step', desc: 'Description' };
    
    // Clean redundant long uppercase names for small flowchart cards
    const cleanedTitle = stepObj.name
      .replace(/HARVEST NOW/i, 'Harvest')
      .replace(/STORE IN VAULT/i, 'Store')
      .replace(/QUANTUM BREAK/i, 'Quantum Break')
      .replace(/DECRYPT KEYFILES/i, 'Decrypt')
      .replace(/IMPACT ASSESSMENT/i, 'Impact')
      .replace(/APPLY SHIELD DEFENSE/i, 'Shield');

    return {
      id: i,
      title: cleanedTitle,
      desc: stepObj.desc,
      icon: icons[i - 1] || Compass
    };
  });

  // Dynamic lessons derived contextually for the selected attack vector
  const customLessons = [
    {
      title: "Interception Frameworks",
      desc: `Understand active network sniffing and mirroring parameters targeting legacy handshakes during execution of ${activeScenario.shortName || activeScenario.name}.`
    },
    {
      title: "Quantum Mechanics Factors",
      desc: "Explore modulus period solving loops via Shor's mathematical registers to isolate legated key formulas."
    },
    {
      title: "NIST Crypto Hardening",
      desc: "Deploy ML-KEM and hybrid lattice key encapsulation handshakes to immunize transactions against quantum interceptors."
    }
  ];

  // Dynamic Case file derived for the selected target servers
  const realWorldExample = {
    title: `${activeScenario.category || 'Threat Vector'} Investigation File`,
    desc: `State-sponsored groups have intercepted high-value transits targeting the ${activeScenario.targets[0] || 'core network'}. This data is archived in massive silent warehouses waiting for relevant quantum hardware to perform full mathematical decryption. Transitioning to lattice-based hybrid tunnels is recommended immediately.`
  };

  return (
    <div id="scenario-info-tabs" className="bg-white/75 backdrop-blur-md rounded-2xl p-6 border border-slate-100 shadow-xs flex flex-col justify-between font-sans">
      
      {/* Upper Tab switch bar & Metadata Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-100 pb-4 mb-5">
        <div>
          <span className="text-[10px] font-mono tracking-wider font-extrabold text-indigo-500 uppercase bg-indigo-50 px-2 py-0.5 rounded-sm">
            Scenario Profile
          </span>
          <h3 className="text-md font-bold text-slate-900 mt-1 font-display">
            {activeScenario.name}
          </h3>
        </div>

        {/* Tab Selector pills */}
        <div className="flex bg-slate-50 border border-slate-100 rounded-full p-1 self-start">
          <button
            id="tab-selector-how"
            onClick={() => setActiveTab('how')}
            className={`px-4 py-1.5 rounded-full text-xs font-semibold font-sans transition-all duration-200 ${
              activeTab === 'how' ? 'bg-indigo-600 text-white shadow-xs' : 'text-slate-400 hover:text-slate-600'
            }`}
          >
            How It Works
          </button>
          <button
            id="tab-selector-learn"
            onClick={() => setActiveTab('learn')}
            className={`px-4 py-1.5 rounded-full text-xs font-semibold font-sans transition-all duration-200 ${
              activeTab === 'learn' ? 'bg-indigo-600 text-white shadow-xs' : 'text-slate-400 hover:text-slate-600'
            }`}
          >
            What You'll Learn
          </button>
          <button
            id="tab-selector-real"
            onClick={() => setActiveTab('real')}
            className={`px-4 py-1.5 rounded-full text-xs font-semibold font-sans transition-all duration-200 ${
              activeTab === 'real' ? 'bg-indigo-600 text-white shadow-xs' : 'text-slate-400 hover:text-slate-600'
            }`}
          >
            Real-World Example
          </button>
        </div>
      </div>

      {/* Dynamic Tab contents view panels */}
      <div className="flex-1 min-h-[160px] flex flex-col justify-center">
        <AnimatePresence mode="wait">
          {activeTab === 'how' && (
            <motion.div
              key="how-tab"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
              className="w-full"
            >
              {/* Connected flowchart boxes horizontally */}
              <div className="flex flex-col md:flex-row items-center justify-between gap-3 overflow-x-auto custom-scrollbar pb-1">
                {flowSteps.map((fs, idx) => {
                  const IconComponent = fs.icon;
                  const isCurrent = activeStep === fs.id;

                  return (
                    <div key={fs.id} className="flex items-center gap-3 w-full md:w-auto">
                      {/* Flow Card */}
                      <div 
                        className={`
                          p-3.5 rounded-xl border flex-1 md:flex-none md:w-[125px] flex flex-col items-center text-center transition-all duration-300
                          ${isCurrent 
                            ? 'bg-indigo-500/10 border-indigo-300 shadow-md ring-2 ring-indigo-50/50' 
                            : 'bg-slate-50/50 border-slate-100'
                          }
                        `}
                      >
                        <div className={`p-2 rounded-lg ${isCurrent ? 'bg-indigo-100 text-indigo-700' : 'bg-slate-100 text-slate-500'}`}>
                          <IconComponent className="w-5 h-5" />
                        </div>
                        <h4 className="text-xs font-bold text-slate-800 font-display mt-2 leading-tight">
                          {fs.title}
                        </h4>
                        <p className="text-[9px] text-slate-400 mt-1 leading-snug font-sans hidden md:block">
                          {fs.desc}
                        </p>
                      </div>

                      {/* Connector Arrow */}
                      {idx < flowSteps.length - 1 && (
                        <ArrowRight className="w-4 h-4 text-slate-200 rotate-90 md:rotate-0 hidden md:block shrink-0" />
                      )}
                    </div>
                  );
                })}
              </div>
            </motion.div>
          )}

          {activeTab === 'learn' && (
            <motion.div
              key="learn-tab"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
              className="grid grid-cols-1 md:grid-cols-3 gap-4"
            >
              {customLessons.map((lesson, idx) => (
                <div key={idx} className="p-4 bg-indigo-50/50 border border-indigo-100 rounded-xl">
                  <span className="text-[10px] text-indigo-600 font-bold font-mono">
                    0{idx + 1} / {idx === 0 ? 'TACTICAL' : idx === 1 ? 'CRYPTO' : 'SOLUTIONS'}
                  </span>
                  <h4 className="text-xs font-bold font-display text-slate-800 mt-1">{lesson.title}</h4>
                  <p className="text-[11px] text-slate-500 mt-1 lines-clamp-3 leading-relaxed">
                    {lesson.desc}
                  </p>
                </div>
              ))}
            </motion.div>
          )}

          {activeTab === 'real' && (
            <motion.div
              key="real-tab"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
              className="space-y-3"
            >
              <div className="flex items-start gap-4 p-4 bg-emerald-500/5 border border-emerald-100 rounded-xl">
                <ShieldCheck className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
                <div>
                  <h4 className="text-xs font-bold text-slate-800 font-display">
                    {realWorldExample.title}
                  </h4>
                  <p className="text-[11px] text-slate-500 leading-relaxed mt-1">
                    {realWorldExample.desc}
                  </p>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
      
    </div>
  );
}
