import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Shield, Layers, AlertTriangle, Calendar, Search, FileText, GitBranch,
  Rocket, Award, HelpCircle, Check, Clock, ChevronDown, ChevronRight,
  TrendingUp, Download, Eye, FileSpreadsheet, Plus, HelpCircle as HelpIcon,
  Target
} from 'lucide-react';

const GLASS_PANEL_CLASSES = 'group relative overflow-hidden rounded-xl border border-[#FFD36B]/20 bg-[#0f1428]/45 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(255,211,107,0.03),0_0_40px_rgba(255,211,107,0.14)] transition-all duration-500 hover:-translate-y-1 hover:border-[#FFD36B]/70 hover:bg-[#0f1428]/65 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.3),inset_0_-24px_60px_rgba(255,211,107,0.15),0_8px_30px_rgba(0,0,0,0.5),0_0_60px_rgba(255,211,107,0.5),0_0_120px_rgba(255,211,107,0.2)] hover:z-10 before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FFF4C0]/70 before:to-transparent before:transition-all before:duration-500 group-hover:before:opacity-100 group-hover:before:shadow-[0_0_15px_rgba(255,211,107,0.9)] group-hover:before:via-[#FFF4C0] after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-48 after:w-48 after:rounded-full after:bg-[#FFD36B]/10 after:blur-3xl after:transition-all after:duration-500 group-hover:after:opacity-100 group-hover:after:bg-[#FFD36B]/25 group-hover:after:blur-[36px] text-white';

export default function MigrationPlanner() {
  const [activeRoadmapStep, setActiveRoadmapStep] = useState<number>(3); // Default index 3: Execute
  const [hoveredPrioritySlice, setHoveredPrioritySlice] = useState<number | null>(null);

  // Top Metrics
  const metrics = [
    {
      title: 'OVERALL PROGRESS',
      value: '42%',
      subtitle: 'On Track',
      subtitleColor: 'text-green-500',
      icon: (
        <svg className="w-12 h-12 rotate-[-90deg]">
          <circle cx="24" cy="24" r="18" stroke="rgba(255,255,255,0.05)" strokeWidth="4" fill="none" />
          <circle
            cx="24" cy="24" r="18"
            stroke="#FFD36B" strokeWidth="4" fill="none"
            strokeDasharray={`${2 * Math.PI * 18}`}
            strokeDashoffset={`${2 * Math.PI * 18 * (1 - 0.42)}`}
            strokeLinecap="round"
            className="drop-shadow-[0_0_4px_rgba(255,211,107,0.5)]"
          />
        </svg>
      )
    },
    {
      title: 'ASSETS IN SCOPE',
      value: '12,842',
      subtitle: '↑ 18.6% vs last 7 days',
      subtitleColor: 'text-green-400',
      icon: <Layers className="w-6 h-6 text-gold drop-shadow-[0_0_6px_rgba(255,211,107,0.4)]" />
    },
    {
      title: 'MIGRATED ASSETS',
      value: '5,384',
      subtitle: '↑ 22.1% vs last 7 days',
      subtitleColor: 'text-green-400',
      icon: <Shield className="w-6 h-6 text-gold drop-shadow-[0_0_6px_rgba(255,211,107,0.4)]" />
    },
    {
      title: 'HIGH PRIORITY ASSETS',
      value: '1,253',
      subtitle: '↓ 6.3% vs last 7 days',
      subtitleColor: 'text-red-400',
      icon: <AlertTriangle className="w-6 h-6 text-gold drop-shadow-[0_0_6px_rgba(255,211,107,0.4)]" />
    },
    {
      title: 'RISKS REDUCED',
      value: '68%',
      subtitle: '↑ 11.4% vs last 7 days',
      subtitleColor: 'text-green-400',
      icon: <TrendingUp className="w-6 h-6 text-gold drop-shadow-[0_0_6px_rgba(255,211,107,0.4)]" />
    },
    {
      title: 'EST. COMPLETION',
      value: 'Aug 28, 2025',
      subtitle: '63 days remaining',
      subtitleColor: 'text-white/40',
      icon: <Calendar className="w-6 h-6 text-gold drop-shadow-[0_0_6px_rgba(255,211,107,0.4)]" />
    }
  ];

  // Roadmap Steps
  const roadmapSteps = [
    { name: 'DISCOVER', progress: '100%', status: 'completed', icon: Search },
    { name: 'ASSESS', progress: '100%', status: 'completed', icon: FileText },
    { name: 'PLAN', progress: '85%', status: 'active', icon: GitBranch },
    { name: 'EXECUTE', progress: '40%', status: 'active', icon: Rocket },
    { name: 'VALIDATE', progress: '15%', status: 'pending', icon: Shield },
    { name: 'COMPLETE', progress: '0%', status: 'pending', icon: Award }
  ];

  // Priority Distribution Chart Data
  const priorityData = [
    { name: 'Critical', value: 1253, percent: '10%', color: '#ef4444' }, // Red
    { name: 'High', value: 3642, percent: '28%', color: '#f97316' },     // Orange
    { name: 'Medium', value: 4873, percent: '38%', color: '#eab308' },   // Yellow
    { name: 'Low', value: 2156, percent: '17%', color: '#10b981' },      // Green
    { name: 'Informational', value: 918, percent: '7%', color: '#3b82f6' } // Blue
  ];

  // Top Assets Table
  const topAssets = [
    { name: 'Payment Gateway API', type: 'Application', risk: 95, priority: 'Critical', priorityColor: 'text-red-500 bg-red-500/10 border-red-500/25', solution: 'ML-KEM-768 + ML-DSA-65', status: 'In Progress', statusColor: 'bg-blue-500/10 border-blue-500/35 text-blue-400' },
    { name: 'Customer Portal', type: 'Web Application', risk: 92, priority: 'Critical', priorityColor: 'text-red-500 bg-red-500/10 border-red-500/25', solution: 'ML-KEM-768 + ML-DSA-65', status: 'Planned', statusColor: 'bg-gold/10 border-gold/30 text-gold' },
    { name: 'Internal CA Server', type: 'Infrastructure', risk: 90, priority: 'High', priorityColor: 'text-orange-500 bg-orange-500/10 border-orange-500/25', solution: 'ML-KEM-768', status: 'In Progress', statusColor: 'bg-blue-500/10 border-blue-500/35 text-blue-400' },
    { name: 'File Transfer Gateway', type: 'Application', risk: 88, priority: 'High', priorityColor: 'text-orange-500 bg-orange-500/10 border-orange-500/25', solution: 'ML-KEM-768', status: 'Planned', statusColor: 'bg-gold/10 border-gold/30 text-gold' },
    { name: 'Email Security Gateway', type: 'Infrastructure', risk: 85, priority: 'High', priorityColor: 'text-orange-500 bg-orange-500/10 border-orange-500/25', solution: 'ML-KEM-768 + ML-DSA-65', status: 'In Progress', statusColor: 'bg-blue-500/10 border-blue-500/35 text-blue-400' },
    { name: 'VPN Concentrator', type: 'Network Device', risk: 78, priority: 'Medium', priorityColor: 'text-yellow-500 bg-yellow-500/10 border-yellow-500/25', solution: 'ML-KEM-768', status: 'Planned', statusColor: 'bg-gold/10 border-gold/30 text-gold' },
    { name: 'Database Cluster', type: 'Database', risk: 72, priority: 'Medium', priorityColor: 'text-yellow-500 bg-yellow-500/10 border-yellow-500/25', solution: 'ML-KEM-768', status: 'Planned', statusColor: 'bg-gold/10 border-gold/30 text-gold' },
    { name: 'DevOps Build Server', type: 'Infrastructure', risk: 61, priority: 'Low', priorityColor: 'text-green-500 bg-green-500/10 border-green-500/25', solution: 'ML-KEM-768', status: 'Planned', statusColor: 'bg-gold/10 border-gold/30 text-gold' }
  ];

  // Timeline Phases
  const timelinePhases = [
    { name: 'Discover & Assess', dates: 'May 1 - May 31', start: 0, width: 20, color: 'bg-blue-500 shadow-[0_0_12px_rgba(59,130,246,0.5)]', checked: true },
    { name: 'Plan & Prioritize', dates: 'May 15 - Jun 15', start: 10, width: 20, color: 'bg-blue-400 shadow-[0_0_12px_rgba(96,165,250,0.5)]', checked: true },
    { name: 'Pilot Migration', dates: 'Jun 1 - Jun 30', start: 20, width: 20, color: 'bg-green-500 shadow-[0_0_12px_rgba(16,185,129,0.5)]', checked: true },
    { name: 'Core Migration', dates: 'Jul 1 - Aug 15', start: 40, width: 30, color: 'bg-yellow-500 shadow-[0_0_12px_rgba(234,179,8,0.5)]', clock: true },
    { name: 'Validation', dates: 'Aug 16 - Sep 15', start: 70, width: 20, color: 'bg-purple-500 shadow-[0_0_12px_rgba(139,92,246,0.5)]', clock: true },
    { name: 'Optimization', dates: 'Sep 16 - Sep 30', start: 90, width: 10, color: 'bg-gray-500 shadow-[0_0_12px_rgba(107,114,128,0.5)]', clock: true }
  ];

  // Risk Reduction Points for Line Chart
  const riskTrendPoints = [
    { day: 'May 18', value: 18 },
    { day: 'May 19', value: 38 },
    { day: 'May 20', value: 48 },
    { day: 'May 21', value: 60 },
    { day: 'May 22', value: 58 },
    { day: 'May 23', value: 68 },
    { day: 'May 24', value: 75 }
  ];

  // SVG parameters for Donut Charts
  const radius = 55;
  const strokeWidth = 14;
  const circumference = 2 * Math.PI * radius;

  // Calculate Dasharray offsets for Donut chart helper
  const getPriorityOffsets = () => {
    let currentOffset = 0;
    return priorityData.map(item => {
      const valuePercent = item.value / 12842;
      const strokeLength = circumference * valuePercent;
      const offset = currentOffset;
      currentOffset += strokeLength;
      return { strokeLength, offset };
    });
  };

  const priorityOffsets = getPriorityOffsets();

  return (
    <div className="p-4 lg:p-8 space-y-8 animate-in fade-in duration-700">
      {/* 1. Header Section */}
      <header className="flex flex-col xl:flex-row xl:items-end justify-between gap-6">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 rounded bg-gold/10 border border-gold/20">
              <Layers className="w-6 h-6 text-gold" />
            </div>
            <h1 className="text-3xl font-black uppercase tracking-tight text-white leading-none">
              Migration <span className="text-gold">Planner</span>
            </h1>
          </div>
          <p className="text-white/50 text-sm font-medium">Plan, prioritize and track your post-quantum migration journey</p>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-3 overflow-x-auto pb-1 xl:pb-0 shrink-0 select-none custom-scrollbar">
          <button className="px-4 py-2.5 bg-gold/10 hover:bg-gold/20 border border-gold/30 rounded-lg text-white transition-all flex items-center gap-2 group shrink-0">
            <Plus className="w-4 h-4 text-gold group-hover:scale-110 transition-transform" />
            <div className="text-left leading-none">
              <div className="text-[10px] font-black uppercase tracking-wider text-gold">Create Plan</div>
              <div className="text-[9px] text-white/40 font-bold uppercase mt-0.5">New Migration Plan</div>
            </div>
          </button>

          <button className="px-4 py-2.5 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg text-white transition-all flex items-center gap-2 group shrink-0">
            <GitBranch className="w-4 h-4 text-gold group-hover:rotate-12 transition-transform" />
            <div className="text-left leading-none">
              <div className="text-[10px] font-black uppercase tracking-wider text-white">Scenario Builder</div>
              <div className="text-[9px] text-white/40 font-bold uppercase mt-0.5">What-if Analysis</div>
            </div>
          </button>

          <button className="px-4 py-2.5 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg text-white transition-all flex items-center gap-2 group shrink-0">
            <Download className="w-4 h-4 text-gold group-hover:-translate-y-0.5 transition-transform" />
            <div className="text-left leading-none">
              <div className="text-[10px] font-black uppercase tracking-wider text-white">Export Roadmap</div>
              <div className="text-[9px] text-white/40 font-bold uppercase mt-0.5">Download Report</div>
            </div>
          </button>

          {/* Dropdown Selection */}
          <div className="relative group/dropdown shrink-0">
            <button className="px-4 py-2.5 bg-white/5 border border-white/10 rounded-lg text-white hover:border-gold/30 transition-all flex items-center gap-3 text-left">
              <Calendar className="w-4 h-4 text-gold shrink-0" />
              <div className="leading-none">
                <div className="text-[10px] font-black uppercase tracking-wider text-white">Last 7 Days</div>
                <div className="text-[9px] text-white/40 font-bold uppercase mt-0.5">Timeframe</div>
              </div>
              <ChevronDown className="w-3.5 h-3.5 text-white/40 group-hover/dropdown:text-gold transition-colors ml-1 shrink-0" />
            </button>
          </div>
        </div>
      </header>

      {/* 2. Metrics Grid (6 Columns) */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-6">
        {metrics.map((m, idx) => (
          <div key={idx} className={`p-5 flex items-center justify-between ${GLASS_PANEL_CLASSES}`}>
            <div className="space-y-1">
              <span className="text-[9px] font-bold text-white/40 uppercase tracking-widest block">{m.title}</span>
              <span className="text-2xl font-black text-white block leading-none">{m.value}</span>
              <span className={`text-[10px] font-black uppercase tracking-wider ${m.subtitleColor} block pt-1`}>
                {m.subtitle}
              </span>
            </div>
            <div className="shrink-0 ml-4">
              {m.icon}
            </div>
          </div>
        ))}
      </div>

      {/* Row 1 : Migration Roadmap and AI-Assisted Migration Planner */}
      <div className="space-y-8">
          {/* Panel 1: Migration Roadmap */}
          <section className={`p-6 flex flex-col justify-between ${GLASS_PANEL_CLASSES} min-h-[380px] flex-1`}>
            <style dangerouslySetInnerHTML={{ __html: `
              @keyframes travel-light {
                from {
                  stroke-dashoffset: 32;
                }
                to {
                  stroke-dashoffset: 0;
                }
              }
              @keyframes travel-curve {
                from {
                  stroke-dashoffset: 80;
                }
                to {
                  stroke-dashoffset: 0;
                }
              }
              @keyframes pulse-glow {
                0%, 100% {
                  opacity: 0.35;
                  filter: drop-shadow(0 0 1px rgba(16, 185, 129, 0.4)) drop-shadow(0 0 3px rgba(16, 185, 129, 0.2));
                }
                50% {
                  opacity: 1;
                  filter: drop-shadow(0 0 5px rgba(16, 185, 129, 0.8)) drop-shadow(0 0 10px rgba(16, 185, 129, 0.5));
                }
              }
            `}} />
            <div>
              <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white/60 mb-6 flex items-center gap-2">
                <GitBranch className="h-4 w-4 text-gold" />
                Migration Roadmap
              </h2>
   
              {/* 2-Row Roadmap Grid with Process Flow Arrow */}
              <div className="space-y-4 pt-2">
                
                {/* Row 1: DISCOVER , ASSESS , PLAN */}
                <div className="flex items-center justify-between gap-3">
                  {[0, 1, 2].map((index) => {
                    const step = roadmapSteps[index];
                    const Icon = step.icon;
                    const isActive = index === activeRoadmapStep;
                    const isCompleted = step.status === 'completed';

                    return (
                      <div key={index} className="flex-1 flex items-center gap-3">
                        <button
                          onClick={() => setActiveRoadmapStep(index)}
                          className={`w-full flex flex-col items-center p-3 rounded-lg border transition-all duration-300 text-center relative ${isActive
                              ? 'border-gold bg-gold/15 shadow-[0_0_20px_rgba(255,211,107,0.3)] scale-[1.03] z-10'
                              : isCompleted
                                ? 'border-green-500/20 bg-green-500/5 hover:border-gold/30 hover:bg-[#0f1428]/60'
                                : 'border-white/5 bg-white/[0.01] hover:border-gold/30 hover:bg-[#0f1428]/60'
                            }`}
                        >
                          {/* Glowing highlight for active */}
                          {isActive && (
                            <div className="absolute inset-0 rounded-lg bg-gold/5 animate-pulse pointer-events-none" />
                          )}

                          <div className={`p-1.5 rounded bg-white/5 border border-white/10 mb-2 ${isActive ? 'border-gold/30' : ''}`}>
                            <Icon className={`w-4 h-4 ${isActive ? 'text-gold' : isCompleted ? 'text-green-400' : 'text-white/40'}`} />
                          </div>

                          <span className={`text-[9px] font-black uppercase tracking-wider block mb-1 ${isActive ? 'text-gold' : 'text-white/70'}`}>
                            {step.name}
                          </span>

                          {/* Checkmark or Percentage */}
                          <div className="flex items-center gap-0.5 mt-auto">
                            {isCompleted ? (
                              <Check className="w-3 h-3 text-green-400" />
                            ) : null}
                            <span className={`text-[10px] font-bold font-mono ${isCompleted ? 'text-green-400' : isActive ? 'text-gold' : 'text-white/30'}`}>
                              {step.progress}
                            </span>
                          </div>
                        </button>

                        {/* Arrow to next item in Row 1 */}
                        {index < 2 && (
                          <div className="shrink-0 flex items-center justify-center relative w-8 h-4">
                            <svg className="w-full h-full" viewBox="0 0 32 16" fill="none">
                              {/* Base golden line */}
                              <path d="M 2 8 L 30 8" stroke="rgba(255, 211, 107, 0.15)" strokeWidth="2" strokeLinecap="round" />
                              {/* Base golden arrowhead */}
                              <path d="M 24 3 L 29 8 L 24 13" stroke="rgba(255, 211, 107, 0.2)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                              
                              {/* Glowing green heartbeat pulse path */}
                              <path
                                d="M 2 8 L 30 8"
                                stroke="#10b981"
                                strokeWidth="2.5"
                                strokeLinecap="round"
                                strokeDasharray="8 24"
                                style={{
                                  animation: 'travel-light 1.2s linear infinite, pulse-glow 2s ease-in-out infinite'
                                }}
                              />
                              {/* Glowing arrowhead pulse */}
                              <path
                                d="M 24 3 L 29 8 L 24 13"
                                stroke="#10b981"
                                strokeWidth="2.5"
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                style={{
                                  animation: 'pulse-glow 2s ease-in-out infinite'
                                }}
                              />
                            </svg>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>

                {/* Row Transition Connector: Elegant Curve / Loop from PLAN (Right) to EXECUTE (Left) */}
                <div className="relative h-8 flex items-center justify-center my-1">
                  <svg className="w-[85%] h-full" viewBox="0 0 500 30" fill="none" preserveAspectRatio="none">
                    {/* Base golden dashed curve */}
                    <path d="M 430,0 C 430,15 70,15 70,30" stroke="rgba(255, 211, 107, 0.15)" strokeWidth="2" strokeDasharray="5 5" />
                    {/* Base golden arrowhead */}
                    <path d="M 64,23 L 70,30 L 78,25" stroke="rgba(255, 211, 107, 0.2)" strokeWidth="2" fill="none" />

                    {/* Animated traveling green pulse curve */}
                    <path
                      d="M 430,0 C 430,15 70,15 70,30"
                      stroke="#10b981"
                      strokeWidth="2.5"
                      strokeDasharray="15 65"
                      style={{
                        animation: 'travel-curve 2.5s linear infinite, pulse-glow 2s ease-in-out infinite'
                      }}
                    />
                    {/* Glowing arrowhead pulse */}
                    <path
                      d="M 64,23 L 70,30 L 78,25"
                      stroke="#10b981"
                      strokeWidth="2.5"
                      fill="none"
                      style={{
                        animation: 'pulse-glow 2s ease-in-out infinite'
                      }}
                    />
                  </svg>
                </div>

                {/* Row 2: EXECUTE , VALIDATE , COMPLETE */}
                <div className="flex items-center justify-between gap-3">
                  {[3, 4, 5].map((index) => {
                    const step = roadmapSteps[index];
                    const Icon = step.icon;
                    const isActive = index === activeRoadmapStep;
                    const isCompleted = step.status === 'completed';

                    return (
                      <div key={index} className="flex-1 flex items-center gap-3">
                        <button
                          onClick={() => setActiveRoadmapStep(index)}
                          className={`w-full flex flex-col items-center p-3 rounded-lg border transition-all duration-300 text-center relative ${isActive
                              ? 'border-gold bg-gold/15 shadow-[0_0_20px_rgba(255,211,107,0.3)] scale-[1.03] z-10'
                              : isCompleted
                                ? 'border-green-500/20 bg-green-500/5 hover:border-gold/30 hover:bg-[#0f1428]/60'
                                : 'border-white/5 bg-white/[0.01] hover:border-gold/30 hover:bg-[#0f1428]/60'
                            }`}
                        >
                          {/* Glowing highlight for active */}
                          {isActive && (
                            <div className="absolute inset-0 rounded-lg bg-gold/5 animate-pulse pointer-events-none" />
                          )}

                          <div className={`p-1.5 rounded bg-white/5 border border-white/10 mb-2 ${isActive ? 'border-gold/30' : ''}`}>
                            <Icon className={`w-4 h-4 ${isActive ? 'text-gold' : isCompleted ? 'text-green-400' : 'text-white/40'}`} />
                          </div>

                          <span className={`text-[9px] font-black uppercase tracking-wider block mb-1 ${isActive ? 'text-gold' : 'text-white/70'}`}>
                            {step.name}
                          </span>

                          {/* Checkmark or Percentage */}
                          <div className="flex items-center gap-0.5 mt-auto">
                            {isCompleted ? (
                              <Check className="w-3 h-3 text-green-400" />
                            ) : null}
                            <span className={`text-[10px] font-bold font-mono ${isCompleted ? 'text-green-400' : isActive ? 'text-gold' : 'text-white/30'}`}>
                              {step.progress}
                            </span>
                          </div>
                        </button>

                        {/* Arrow to next item in Row 2 */}
                        {index < 5 && (
                          <div className="shrink-0 flex items-center justify-center relative w-8 h-4">
                            <svg className="w-full h-full" viewBox="0 0 32 16" fill="none">
                              {/* Base golden line */}
                              <path d="M 2 8 L 30 8" stroke="rgba(255, 211, 107, 0.15)" strokeWidth="2" strokeLinecap="round" />
                              {/* Base golden arrowhead */}
                              <path d="M 24 3 L 29 8 L 24 13" stroke="rgba(255, 211, 107, 0.2)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                              
                              {/* Glowing green heartbeat pulse path */}
                              <path
                                d="M 2 8 L 30 8"
                                stroke="#10b981"
                                strokeWidth="2.5"
                                strokeLinecap="round"
                                strokeDasharray="8 24"
                                style={{
                                  animation: 'travel-light 1.2s linear infinite, pulse-glow 2s ease-in-out infinite'
                                }}
                              />
                              {/* Glowing arrowhead pulse */}
                              <path
                                d="M 24 3 L 29 8 L 24 13"
                                stroke="#10b981"
                                strokeWidth="2.5"
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                style={{
                                  animation: 'pulse-glow 2s ease-in-out infinite'
                                }}
                              />
                            </svg>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>

              </div>
            </div>

            <div className="pt-6 border-t border-white/5 flex justify-between items-center">
              <button className="text-[10px] font-black uppercase tracking-[0.2em] text-white/40 hover:text-gold transition-colors flex items-center gap-1">
                View Full Roadmap <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </section>

          {/* Panel 1.5: AI-Assisted Migration Planner */}
          <section className={`p-6 flex flex-col justify-between ${GLASS_PANEL_CLASSES} min-h-[380px] flex-1`}>
            <div>
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white/60 flex items-center gap-2">
                  <Target className="h-4 w-4 text-gold animate-pulse" />
                  AI-Assisted Migration Planner
                </h2>
                <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-gold/10 border border-gold/20">
                  <span className="w-1.5 h-1.5 bg-gold rounded-full animate-ping" />
                  <span className="text-[8px] font-black text-gold uppercase tracking-widest">AI Engine Active</span>
                </div>
              </div>

              {/* Selector Options */}
              <div className="space-y-4">
                <div>
                  <span className="text-[9px] font-bold text-white/40 uppercase tracking-wider block mb-2">Simulation Target Mode</span>
                  <div className="grid grid-cols-3 gap-2">
                    <button className="py-2 px-3 rounded-lg border border-gold/30 bg-gold/10 text-[9px] font-black uppercase tracking-wider text-gold hover:bg-gold/20 transition-all text-center">
                      Hybrid (Recommended)
                    </button>
                    <button className="py-2 px-3 rounded-lg border border-white/5 bg-white/[0.01] text-[9px] font-black uppercase tracking-wider text-white/50 hover:border-white/20 transition-all text-center">
                      Pure Quantum-Safe
                    </button>
                    <button className="py-2 px-3 rounded-lg border border-white/5 bg-white/[0.01] text-[9px] font-black uppercase tracking-wider text-white/50 hover:border-white/20 transition-all text-center">
                      Dual-Key Legacy
                    </button>
                  </div>
                </div>

                <div>
                  <span className="text-[9px] font-bold text-white/40 uppercase tracking-wider block mb-2">Optimization Parameter</span>
                  <div className="grid grid-cols-3 gap-2">
                    <button className="py-2 px-3 rounded-lg border border-white/5 bg-white/[0.01] text-[9px] font-black uppercase tracking-wider text-white/50 hover:border-white/20 transition-all text-center">
                      Min Latency
                    </button>
                    <button className="py-2 px-3 rounded-lg border border-gold/30 bg-gold/10 text-[9px] font-black uppercase tracking-wider text-gold hover:bg-gold/20 transition-all text-center">
                      High Risk First
                    </button>
                    <button className="py-2 px-3 rounded-lg border border-white/5 bg-white/[0.01] text-[9px] font-black uppercase tracking-wider text-white/50 hover:border-white/20 transition-all text-center">
                      Cost-Optimized
                    </button>
                  </div>
                </div>

                {/* Simulation Output Area */}
                <div className="p-4 rounded-lg bg-black/45 border border-white/5 space-y-3">
                  <div className="flex justify-between items-center text-[9px] font-bold uppercase text-white/40 tracking-wider">
                    <span>Simulated Recommendation</span>
                    <span className="text-gold font-mono">98.2% Confidence</span>
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-start gap-2.5">
                      <Check className="w-3.5 h-3.5 text-green-400 mt-0.5" />
                      <div>
                        <div className="text-[10px] font-bold text-white/80">Select ML-KEM-768 for Payment APIs</div>
                        <div className="text-[8px] text-white/30 font-mono mt-0.5">Estimated migration duration: 4.2 hours • Risk mitigation: 95%</div>
                      </div>
                    </div>
                    <div className="flex items-start gap-2.5">
                      <Clock className="w-3.5 h-3.5 text-gold mt-0.5 animate-pulse" />
                      <div>
                        <div className="text-[10px] font-bold text-white/80">Configure Hybrid TLS tunnels for Database Storage</div>
                        <div className="text-[8px] text-white/30 font-mono mt-0.5">Awaiting scenario execution to generate configuration scripts</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="pt-4 mt-6 border-t border-white/5 flex gap-3">
              <button className="flex-1 py-2 bg-gold/10 hover:bg-gold/20 border border-gold/30 text-[10px] font-black uppercase tracking-widest text-gold rounded-lg transition-all shadow-[0_0_15px_rgba(255,211,107,0.1)]">
                Run AI Migration Simulation
              </button>
              <button className="py-2 px-4 bg-white/5 hover:bg-white/10 border border-white/10 text-[10px] font-black uppercase tracking-widest text-white/60 rounded-lg transition-all">
                Generate Playbook
              </button>
            </div>
          </section>
      </div>

      {/* Row 2 : Migration Timeline and Top Assets by Migration Priority */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">

        {/* Panel 2: Migration Timeline */}
        <section className={`p-6 flex flex-col justify-between ${GLASS_PANEL_CLASSES} min-h-[480px]`}>
          <div className="space-y-4">
            <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white/60 flex items-center gap-2">
              <Calendar className="h-4 w-4 text-gold" />
              Migration Timeline
            </h2>

            {/* Timeline Header Months */}
            <div className="space-y-6 pt-2">
              <div className="grid grid-cols-5 text-[8px] font-black text-white/30 uppercase tracking-widest text-center border-b border-white/5 pb-2">
                <span>May 2025</span>
                <span>Jun 2025</span>
                <span>Jul 2025</span>
                <span>Aug 2025</span>
                <span>Sep 2025</span>
              </div>

              {/* Gantt chart rows */}
              <div className="space-y-4">
                {timelinePhases.map((phase, idx) => (
                  <div key={idx} className="space-y-1.5">
                    <div className="flex items-center justify-between text-[9px]">
                      <span className="font-bold text-white/80">{phase.name}</span>
                      <span className="font-mono text-white/40">{phase.dates}</span>
                    </div>

                    <div className="h-4 w-full bg-white/[0.02] rounded-full overflow-hidden relative border border-white/5 flex items-center">
                      <div
                        className={`h-2.5 rounded-full ${phase.color} absolute flex items-center justify-end px-1`}
                        style={{ left: `${phase.start}%`, width: `${phase.width}%` }}
                      >
                        {phase.checked && <Check className="w-2.5 h-2.5 text-white stroke-[3px]" />}
                        {phase.clock && <Clock className="w-2.5 h-2.5 text-white/80 animate-pulse" />}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-white/5 flex justify-between items-center">
            <button className="text-[10px] font-black uppercase tracking-[0.2em] text-white/40 hover:text-gold transition-colors flex items-center gap-1">
              View Detailed Timeline <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </section>

        {/* Panel 1: Top Assets by Migration Priority */}
        <section className={`p-6 flex flex-col justify-between ${GLASS_PANEL_CLASSES} min-h-[480px]`}>
          <div className="space-y-4">
            <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white/60 flex items-center gap-2">
              <Layers className="h-4 w-4 text-gold" />
              Top Assets by Migration Priority
            </h2>

            <div className="overflow-x-auto custom-scrollbar">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-white/5 text-[9px] font-black text-white/40 uppercase tracking-widest">
                    <th className="py-2.5">Asset Name</th>
                    <th className="py-2.5">Type</th>
                    <th className="py-2.5 text-center">Crypto Risk</th>
                    <th className="py-2.5 text-center">Priority</th>
                    <th className="py-2.5">Target Solution</th>
                    <th className="py-2.5 text-center">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {topAssets.map((asset, i) => (
                    <tr key={i} className="hover:bg-white/[0.02] transition-colors group/row">
                      <td className="py-3 text-[10px] font-bold text-white/80 group-hover/row:text-gold transition-colors">
                        {asset.name}
                      </td>
                      <td className="py-3 text-[10px] text-white/50">{asset.type}</td>
                      <td className="py-3 text-center text-xs font-black font-mono">
                        <span className={asset.risk > 80 ? 'text-red-400' : asset.risk > 70 ? 'text-yellow-400' : 'text-green-400'}>
                          {asset.risk}
                        </span>
                      </td>
                      <td className="py-3 text-center">
                        <span className={`text-[8px] font-black uppercase px-2 py-0.5 rounded border inline-block ${asset.priorityColor}`}>
                          {asset.priority}
                        </span>
                      </td>
                      <td className="py-3 text-[9px] font-mono text-white/70">{asset.solution}</td>
                      <td className="py-3 text-center">
                        <span className={`text-[8px] font-black uppercase px-1.5 py-0.5 rounded border inline-block ${asset.statusColor}`}>
                          {asset.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="pt-4 border-t border-white/5 flex justify-between items-center">
            <button className="text-[10px] font-black uppercase tracking-[0.2em] text-white/40 hover:text-gold transition-colors flex items-center gap-1">
              View All Assets <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </section>

      </div>

      {/* Row 3 : Priority Distribution and Risk Reduction Trend */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">

        {/* Panel 3: Priority Distribution */}
        <section className={`p-6 flex flex-col justify-between ${GLASS_PANEL_CLASSES} min-h-[480px]`}>
          <div>
            <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white/60 mb-6 flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-gold" />
              Priority Distribution
            </h2>

            <div className="flex items-center justify-between gap-6">
              {/* Donut Chart Container */}
              <div className="relative w-40 h-40 shrink-0">
                <svg className="w-full h-full rotate-[-90deg]">
                  {priorityData.map((item, idx) => {
                    const offset = priorityOffsets[idx];
                    const isHovered = hoveredPrioritySlice === idx;
                    return (
                      <circle
                        key={idx}
                        cx="80" cy="80" r={radius}
                        fill="none" stroke={item.color} strokeWidth={isHovered ? strokeWidth + 3 : strokeWidth}
                        strokeDasharray={`${offset.strokeLength} ${circumference}`}
                        strokeDashoffset={-offset.offset}
                        className="transition-all duration-300 cursor-pointer"
                        onMouseEnter={() => setHoveredPrioritySlice(idx)}
                        onMouseLeave={() => setHoveredPrioritySlice(null)}
                        style={{
                          filter: isHovered ? `drop-shadow(0 0 8px ${item.color}ee)` : 'none'
                        }}
                      />
                    );
                  })}
                </svg>

                {/* Donut Center text */}
                <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                  <span className="text-xl font-black text-white leading-none">12,842</span>
                  <span className="text-[8px] font-bold text-white/30 uppercase tracking-wider mt-1">Total Assets</span>
                </div>
              </div>

              {/* Legends list */}
              <div className="flex-1 space-y-2">
                {priorityData.map((item, idx) => {
                  const isHovered = hoveredPrioritySlice === idx;
                  return (
                    <div
                      key={idx}
                      className={`flex items-center justify-between p-1.5 rounded transition-colors ${isHovered ? 'bg-white/[0.04]' : ''}`}
                      onMouseEnter={() => setHoveredPrioritySlice(idx)}
                      onMouseLeave={() => setHoveredPrioritySlice(null)}
                    >
                      <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                        <span className={`text-[10px] font-bold uppercase transition-colors ${isHovered ? 'text-white' : 'text-white/50'}`}>
                          {item.name}
                        </span>
                      </div>
                      <span className="text-[10px] font-bold font-mono text-white/70">
                        {item.value.toLocaleString()} <span className="text-white/30">({item.percent})</span>
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </section>

        {/* Panel 3: Risk Reduction Trend */}
        <section className={`p-6 flex flex-col justify-between ${GLASS_PANEL_CLASSES} min-h-[480px]`}>
          <div className="space-y-4">
            <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white/60 flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-gold" />
              Risk Reduction Trend
            </h2>

            {/* Glowing High Fidelity Line Chart */}
            <div className="relative w-full h-44 border border-white/5 rounded-xl bg-white/[0.01] p-3 flex flex-col justify-between overflow-hidden">
              {/* Grid Background */}
              <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:20px_20px] pointer-events-none" />

              {/* Line chart svg */}
              <svg className="absolute inset-x-0 bottom-4 w-full h-32 overflow-visible">
                <defs>
                  {/* Glowing line filter */}
                  <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="3" result="blur" />
                    <feComposite in="SourceGraphic" in2="blur" operator="over" />
                  </filter>
                  {/* Gold area gradient */}
                  <linearGradient id="areaGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#FFD36B" stopOpacity="0.25" />
                    <stop offset="100%" stopColor="#FFD36B" stopOpacity="0" />
                  </linearGradient>
                </defs>

                {/* Filled area path */}
                <path
                  d="M 20 120 C 60 90, 100 80, 140 60 C 180 62, 220 50, 260 40 C 300 20, 340 10, 380 5 L 380 120 L 20 120 Z"
                  fill="url(#areaGradient)"
                  className="transition-all duration-500"
                />

                {/* Glowing line path */}
                <path
                  d="M 20 120 C 60 90, 100 80, 140 60 C 180 62, 220 50, 260 40 C 300 20, 340 10, 380 5"
                  fill="none"
                  stroke="#FFD36B"
                  strokeWidth="3.5"
                  strokeLinecap="round"
                  filter="url(#glow)"
                  className="drop-shadow-[0_0_8px_rgba(255,211,107,0.8)]"
                />

                {/* Dots along path */}
                {[
                  { x: 20, y: 120 },
                  { x: 74, y: 95 },
                  { x: 134, y: 80 },
                  { x: 194, y: 62 },
                  { x: 254, y: 48 },
                  { x: 314, y: 25 },
                  { x: 374, y: 6 }
                ].map((pt, i) => (
                  <g key={i} className="group/dot cursor-pointer">
                    <circle
                      cx={pt.x} cy={pt.y} r="6"
                      fill="#0f1428"
                      stroke="#FFD36B"
                      strokeWidth="2.5"
                      className="group-hover/dot:r-8 transition-all"
                    />
                    <circle
                      cx={pt.x} cy={pt.y} r="2"
                      fill="#FFD36B"
                    />
                  </g>
                ))}
              </svg>

              {/* Y Axis Helper */}
              <div className="absolute left-2 top-2 flex flex-col justify-between h-[85%] text-[7px] font-bold text-white/30">
                <span>100%</span>
                <span>75%</span>
                <span>50%</span>
                <span>25%</span>
                <span>0%</span>
              </div>

              {/* X Axis Labels */}
              <div className="absolute inset-x-4 bottom-1.5 flex justify-between text-[7px] font-bold text-white/30 font-mono uppercase tracking-widest">
                <span>May 18</span>
                <span>May 19</span>
                <span>May 20</span>
                <span>May 21</span>
                <span>May 22</span>
                <span>May 23</span>
                <span>May 24</span>
              </div>
            </div>

            {/* Bottom mini status cards */}
            <div className="grid grid-cols-3 gap-3">
              <div className="p-3 rounded-lg border border-gold/10 bg-white/[0.02] text-center">
                <span className="text-[8px] font-bold text-white/30 uppercase tracking-widest block mb-1">This Week</span>
                <span className="text-lg font-black text-white font-mono block">68%</span>
                <span className="text-[8px] font-bold text-green-400 uppercase tracking-wider block pt-0.5">↑ 11.4%</span>
              </div>
              <div className="p-3 rounded-lg border border-white/5 bg-white/[0.02] text-center">
                <span className="text-[8px] font-bold text-white/30 uppercase tracking-widest block mb-1">Last Week</span>
                <span className="text-lg font-black text-white/60 font-mono block">61%</span>
              </div>
              <div className="p-3 rounded-lg border border-white/5 bg-white/[0.02] text-center">
                <span className="text-[8px] font-bold text-white/30 uppercase tracking-widest block mb-1">Change</span>
                <span className="text-lg font-black text-green-400 font-mono block">↑ 11.4%</span>
              </div>
            </div>
          </div>
        </section>

      </div>

      {/* 5. Bottom Compliance Panel (6 columns footer branding) */}
      <footer className={`p-6 ${GLASS_PANEL_CLASSES} divide-y lg:divide-y-0 lg:divide-x divide-white/5 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-6 lg:gap-0`}>
        {[
          { title: 'QUANTUM READY', desc: 'Strengthen today, secure tomorrow.', icon: Shield },
          { title: 'POST-QUANTUM', desc: 'Migrate with confidence to NIST-approved algorithms.', icon: GitBranch },
          { title: 'RISK AWARE', desc: 'Identify, prioritize and eliminate quantum risk.', icon: Target },
          { title: 'OPERATIONAL EXCELLENCE', desc: 'Streamlined migration with real-time operational visibility.', icon: Rocket },
          { title: 'COMPLIANT BY DESIGN', desc: 'Meet regulatory requirements with provable compliance.', icon: Award },
          { title: 'FUTURE PROOF', desc: 'Build cryptographic resilience for the quantum era.', icon: Clock }
        ].map((item, idx) => {
          const Icon = item.icon;
          return (
            <div key={idx} className="flex flex-col items-center text-center p-4 xl:px-6 space-y-2 first:pl-0 last:pr-0">
              <div className="p-2 rounded bg-gold/10 border border-gold/20 mb-1">
                <Icon className="w-5 h-5 text-gold drop-shadow-[0_0_6px_rgba(255,211,107,0.3)]" />
              </div>
              <h4 className="text-[10px] font-black uppercase tracking-widest text-white">{item.title}</h4>
              <p className="text-[9px] text-white/40 leading-relaxed font-medium">{item.desc}</p>
            </div>
          );
        })}
      </footer>
    </div>
  );
}
