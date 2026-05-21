import { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Radio, Globe, AlertTriangle, Shield, Eye, Crosshair,
  TrendingUp, Clock, Zap, Target, Skull, Lock, Activity,
  ExternalLink, ChevronRight, MapPin, Database, Flame,
  Fingerprint, Terminal, Atom, Lightbulb, Plus, Download,
  ChevronDown, Calendar, Search, HelpCircle, Check, Play,
  Layers, FileText
} from 'lucide-react';

const GLASS_PANEL_CLASSES = 'group relative overflow-hidden rounded-xl border border-[#FFD36B]/20 bg-[#0f1428]/45 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(255,211,107,0.03),0_0_40px_rgba(255,211,107,0.14)] transition-all duration-500 hover:-translate-y-1 hover:border-[#FFD36B]/70 hover:bg-[#0f1428]/65 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.3),inset_0_-24px_60px_rgba(255,211,107,0.15),0_8px_30px_rgba(0,0,0,0.5),0_0_60px_rgba(255,211,107,0.5),0_0_120px_rgba(255,211,107,0.2)] hover:z-10 before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FFF4C0]/70 before:to-transparent before:transition-all before:duration-500 group-hover:before:opacity-100 group-hover:before:shadow-[0_0_15px_rgba(255,211,107,0.9)] group-hover:before:via-[#FFF4C0] after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-48 after:w-48 after:rounded-full after:bg-[#FFD36B]/10 after:blur-3xl after:transition-all after:duration-500 group-hover:after:opacity-100 group-hover:after:bg-[#FFD36B]/25 group-hover:after:blur-[36px] text-white';

export default function ThreatIntelligence() {
  const [feedTime, setFeedTime] = useState<string>('');
  const [hndlCounter, setHndlCounter] = useState(128472);
  const [hoveredCategorySlice, setHoveredCategorySlice] = useState<number | null>(null);

  // Live SOC feed simulation state
  const [liveFeeds, setLiveFeeds] = useState([
    { time: '10:24:15', title: 'Quantum brute-force simulation achieved new record.', source: 'QuantumWatch', severity: 'high' },
    { time: '10:12:07', title: 'New IoC set linked to APT41 cryptojacking campaign.', source: 'Mandiant', severity: 'critical' },
    { time: '09:58:33', title: 'PQC migration dodges observed in financial sector.', source: 'Anomali', severity: 'medium' },
    { time: '09:41:22', title: 'Malicious npm package with crypto backdoor detected.', source: 'SonicWall', severity: 'critical' },
    { time: '09:25:11', title: 'Researcher leaks proof-of-concept quantum exploit.', source: 'RiskyBiz', severity: 'high' }
  ]);

  // Tick the live feed simulation
  useEffect(() => {
    const timer = setInterval(() => {
      const sources = ['Lockheed', 'PaloAlto', 'CrowdStrike', 'CISA', 'NSA', 'QGuard HoneyNet'];
      const actions = [
        'HNDL payload capture analyzed in critical infrastructure.',
        'Downgrade exploit attempts blocked on legacy VPN gateway.',
        'Lattice-based key exchange deviation registered in telemetry.',
        'Emerging cryptanalysis cluster active on public clouds.',
        'NIST ML-DSA-85 signature integrity check anomalies logged.',
        'Anomalous entropic output registered in QRNG feeds.'
      ];
      const severities = ['high', 'critical', 'medium'];
      
      const now = new Date();
      const timeString = now.toTimeString().split(' ')[0];

      const newFeed = {
        time: timeString,
        title: actions[Math.floor(Math.random() * actions.length)],
        source: sources[Math.floor(Math.random() * sources.length)],
        severity: severities[Math.floor(Math.random() * severities.length)]
      };

      setLiveFeeds(prev => [newFeed, ...prev.slice(0, 4)]);
      setHndlCounter(c => c + Math.floor(Math.random() * 3) + 1);
    }, 6000);

    return () => clearInterval(timer);
  }, []);

  // Top Action Metrics
  const metrics = [
    {
      title: 'THREAT SCORE',
      value: '78',
      suffix: '/100',
      subtitle: 'High Risk',
      subtitleColor: 'text-red-400',
      isGauge: true,
      icon: <Skull className="w-5 h-5 text-gold" />
    },
    {
      title: 'ACTIVE THREATS',
      value: '124',
      subtitle: '↓ 12% vs last 7 days',
      subtitleColor: 'text-red-400/80',
      icon: <Activity className="w-6 h-6 text-gold drop-shadow-[0_0_10px_rgba(255,211,107,0.4)]" />
    },
    {
      title: 'EMERGING THREATS',
      value: '27',
      subtitle: '↑ 17% vs last 7 days',
      subtitleColor: 'text-green-400',
      icon: <Target className="w-6 h-6 text-gold drop-shadow-[0_0_10px_rgba(255,211,107,0.4)]" />
    },
    {
      title: 'ADVERSARIES TRACKED',
      value: '42',
      subtitle: 'No Change',
      subtitleColor: 'text-white/30',
      icon: <Fingerprint className="w-6 h-6 text-gold drop-shadow-[0_0_10px_rgba(255,211,107,0.4)]" />
    },
    {
      title: 'INDICATORS OF COMPROMISE',
      value: '1,842',
      subtitle: '↑ 8.4% vs last 7 days',
      subtitleColor: 'text-green-400',
      icon: <Search className="w-6 h-6 text-gold drop-shadow-[0_0_10px_rgba(255,211,107,0.4)]" />
    },
    {
      title: 'INTEL SOURCES',
      value: '36',
      subtitle: 'No Change',
      subtitleColor: 'text-white/30',
      icon: <Database className="w-6 h-6 text-gold drop-shadow-[0_0_10px_rgba(255,211,107,0.4)]" />
    }
  ];

  // Threat Category Donut Data
  const categoriesData = [
    { name: 'Quantum Cryptanalysis', value: 35, percent: '28%', color: '#ef4444' },
    { name: 'Post-Quantum Exploits', value: 29, percent: '23%', color: '#f97316' },
    { name: 'Crypto Infrastructure', value: 22, percent: '18%', color: '#eab308' },
    { name: 'Supply Chain', value: 20, percent: '16%', color: '#22c55e' },
    { name: 'Nation State Activity', value: 12, percent: '10%', color: '#3b82f6' },
    { name: 'Other', value: 6, percent: '5%', color: '#6b7280' }
  ];

  // SVG Donut Calculations
  const radius = 50;
  const strokeWidth = 14;
  const circumference = 2 * Math.PI * radius;
  let accumulatedPercent = 0;
  const categoryOffsets = categoriesData.map(item => {
    const percentVal = parseInt(item.percent);
    const strokeLength = (percentVal / 100) * circumference;
    const offset = (accumulatedPercent / 100) * circumference;
    accumulatedPercent += percentVal;
    return { strokeLength, offset };
  });

  return (
    <div className="p-6 lg:p-8 space-y-8 min-h-screen bg-[#060814] text-white">
      
      {/* 1. Header Section */}
      <header className="flex flex-col xl:flex-row xl:items-end justify-between gap-6">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 rounded bg-gold/10 border border-gold/20">
              <Radio className="w-6 h-6 text-gold animate-pulse" />
            </div>
            <h1 className="text-3xl font-black uppercase tracking-tight text-white leading-none">
              Threat <span className="text-gold">Intelligence</span>
            </h1>
          </div>
          <p className="text-white/50 text-sm font-medium">Real-time intelligence on quantum threats, adversaries and emerging risks.</p>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-3 overflow-x-auto pb-1 xl:pb-0 shrink-0 select-none custom-scrollbar">
          <button className="px-4 py-2.5 bg-gold/10 hover:bg-gold/20 border border-gold/30 rounded-lg text-white transition-all flex items-center gap-2 group shrink-0">
            <Radio className="w-4 h-4 text-gold animate-pulse" />
            <div className="text-left leading-none">
              <div className="text-[10px] font-black uppercase tracking-wider text-gold">Intel Feed</div>
              <div className="text-[9px] text-white/40 font-bold uppercase mt-0.5">Live</div>
            </div>
          </button>

          <button className="px-4 py-2.5 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg text-white transition-all flex items-center gap-2 group shrink-0">
            <Globe className="w-4 h-4 text-gold group-hover:rotate-12 transition-transform" />
            <div className="text-left leading-none">
              <div className="text-[10px] font-black uppercase tracking-wider text-white">Threat Map</div>
              <div className="text-[9px] text-white/40 font-bold uppercase mt-0.5">Global View</div>
            </div>
          </button>

          <button className="px-4 py-2.5 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg text-white transition-all flex items-center gap-2 group shrink-0">
            <Download className="w-4 h-4 text-gold group-hover:-translate-y-0.5 transition-transform" />
            <div className="text-left leading-none">
              <div className="text-[10px] font-black uppercase tracking-wider text-white">Export Report</div>
              <div className="text-[9px] text-white/40 font-bold uppercase mt-0.5">Download Intel</div>
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
            <div className="space-y-1 w-full">
              <span className="text-[9px] font-bold text-white/40 uppercase tracking-widest block">{m.title}</span>
              
              {m.isGauge ? (
                <div className="flex items-center justify-between pt-1">
                  <div className="space-y-1">
                    <span className="text-2xl font-black text-white leading-none">
                      {m.value}<span className="text-xs text-white/30 font-bold">{m.suffix}</span>
                    </span>
                    <span className={`text-[10px] font-black uppercase tracking-wider ${m.subtitleColor} block`}>
                      {m.subtitle}
                    </span>
                  </div>
                  
                  {/* Glowing Arch Gauge */}
                  <div className="relative w-14 h-8 overflow-hidden">
                    <svg className="w-full h-full">
                      {/* Background Arch */}
                      <path
                        d="M 5 28 A 20 20 0 0 1 49 28"
                        fill="none"
                        stroke="rgba(255, 255, 255, 0.08)"
                        strokeWidth="5"
                        strokeLinecap="round"
                      />
                      {/* Foreground Filled Arch */}
                      <path
                        d="M 5 28 A 20 20 0 0 1 49 28"
                        fill="none"
                        stroke="#FFD36B"
                        strokeWidth="5"
                        strokeLinecap="round"
                        strokeDasharray="69"
                        strokeDashoffset="15"
                        className="drop-shadow-[0_0_5px_rgba(255,211,107,0.7)]"
                      />
                    </svg>
                  </div>
                </div>
              ) : (
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <span className="text-2xl font-black text-white block leading-none">{m.value}</span>
                    <span className={`text-[10px] font-black uppercase tracking-wider ${m.subtitleColor} block`}>
                      {m.subtitle}
                    </span>
                  </div>
                  <div className="shrink-0 ml-4">
                    {m.icon}
                  </div>
                </div>
              )}

              {/* Threat Score Miniature Line Chart */}
              {m.isGauge && (
                <div className="h-4 w-full mt-2 relative overflow-hidden">
                  <svg className="w-full h-full overflow-visible">
                    <path
                      d="M 0 12 Q 10 4, 20 10 T 40 4 T 60 12 T 80 4 T 100 8"
                      fill="none"
                      stroke="#FFD36B"
                      strokeWidth="1.5"
                      className="drop-shadow-[0_0_3px_rgba(255,211,107,0.8)]"
                    />
                    <circle cx="100" cy="8" r="2.5" fill="#FFD36B" className="animate-ping" />
                    <circle cx="100" cy="8" r="1.5" fill="#FFD36B" />
                  </svg>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Row 1: Threat Landscape and Threat Categories */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        
        {/* Card 1: Threat Landscape */}
        <section className={`p-6 flex flex-col justify-between ${GLASS_PANEL_CLASSES} min-h-[480px]`}>
          <div className="space-y-4">
            <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white/60 flex items-center gap-2">
              <Globe className="h-4 w-4 text-gold" />
              Threat Landscape
            </h2>

            <div className="grid grid-cols-12 gap-6 items-center">
              {/* Left Legend Indicators */}
              <div className="col-span-3 space-y-4">
                <div className="p-3.5 rounded-lg border border-red-500/20 bg-red-500/5 hover:bg-red-500/10 transition-colors">
                  <div className="text-[8px] font-bold text-red-400 uppercase tracking-widest mb-1">Critical</div>
                  <div className="text-2xl font-black text-white font-mono leading-none">32</div>
                </div>
                <div className="p-3.5 rounded-lg border border-orange-500/20 bg-orange-500/5 hover:bg-orange-500/10 transition-colors">
                  <div className="text-[8px] font-bold text-orange-400 uppercase tracking-widest mb-1">High</div>
                  <div className="text-2xl font-black text-white font-mono leading-none">61</div>
                </div>
                <div className="p-3.5 rounded-lg border border-yellow-500/20 bg-yellow-500/5 hover:bg-yellow-500/10 transition-colors">
                  <div className="text-[8px] font-bold text-yellow-400 uppercase tracking-widest mb-1">Medium</div>
                  <div className="text-2xl font-black text-white font-mono leading-none">21</div>
                </div>
                <div className="p-3.5 rounded-lg border border-green-500/20 bg-green-500/5 hover:bg-green-500/10 transition-colors">
                  <div className="text-[8px] font-bold text-green-400 uppercase tracking-widest mb-1">Low</div>
                  <div className="text-2xl font-black text-white font-mono leading-none">10</div>
                </div>
              </div>

              {/* High Tech Golden World Map SVG Representation */}
              <div className="col-span-9 relative w-full h-[260px] flex items-center justify-center">
                <svg className="w-full h-full opacity-80" viewBox="0 0 800 450">
                  <defs>
                    <radialGradient id="mapGlow" cx="50%" cy="50%" r="50%">
                      <stop offset="0%" stopColor="#FFD36B" stopOpacity="0.25" />
                      <stop offset="100%" stopColor="#FFD36B" stopOpacity="0" />
                    </radialGradient>
                  </defs>
                  
                  {/* Stylized world grid representing continents */}
                  <g fill="#FFD36B" opacity="0.15" stroke="#000" strokeWidth="0.5">
                    {/* North America */}
                    <path d="M 120 120 L 220 110 L 250 160 L 200 240 L 150 200 Z" />
                    <path d="M 160 80 L 220 80 L 200 110 Z" />
                    {/* South America */}
                    <path d="M 230 260 L 290 320 L 270 410 L 240 380 L 220 280 Z" />
                    {/* Europe */}
                    <path d="M 380 110 L 460 90 L 450 160 L 390 170 Z" />
                    {/* Africa */}
                    <path d="M 400 200 L 490 220 L 480 340 L 440 330 L 410 240 Z" />
                    {/* Asia */}
                    <path d="M 480 80 L 680 90 L 720 240 L 580 260 L 510 180 Z" />
                    {/* Australia */}
                    <path d="M 680 320 L 740 340 L 720 390 L 660 360 Z" />
                  </g>

                  {/* High Tech Coordinate Grid Overlay */}
                  <g stroke="rgba(255,255,255,0.03)" strokeWidth="0.5">
                    <line x1="0" y1="100" x2="800" y2="100" />
                    <line x1="0" y1="200" x2="800" y2="200" />
                    <line x1="0" y1="300" x2="800" y2="300" />
                    <line x1="0" y1="400" x2="800" y2="400" />
                    <line x1="200" y1="0" x2="200" y2="450" />
                    <line x1="400" y1="0" x2="400" y2="450" />
                    <line x1="600" y1="0" x2="600" y2="450" />
                  </g>

                  {/* Pulsing Concentric Radar threat Beacons */}
                  {/* North America */}
                  <g className="cursor-pointer">
                    <circle cx="180" cy="150" r="100" fill="url(#mapGlow)" />
                    <circle cx="180" cy="150" r="12" fill="none" stroke="#ef4444" strokeWidth="1.5" className="animate-ping" style={{ animationDuration: '3s' }} />
                    <circle cx="180" cy="150" r="6" fill="#ef4444" className="drop-shadow-[0_0_6px_#ef4444]" />
                  </g>
                  {/* South America */}
                  <g className="cursor-pointer">
                    <circle cx="260" cy="320" r="60" fill="url(#mapGlow)" />
                    <circle cx="260" cy="320" r="8" fill="none" stroke="#eab308" strokeWidth="1.5" className="animate-ping" style={{ animationDuration: '4s' }} />
                    <circle cx="260" cy="320" r="4" fill="#eab308" className="drop-shadow-[0_0_6px_#eab308]" />
                  </g>
                  {/* Europe */}
                  <g className="cursor-pointer">
                    <circle cx="430" cy="130" r="80" fill="url(#mapGlow)" />
                    <circle cx="430" cy="130" r="10" fill="none" stroke="#f97316" strokeWidth="1.5" className="animate-ping" style={{ animationDuration: '2.5s' }} />
                    <circle cx="430" cy="130" r="5" fill="#f97316" className="drop-shadow-[0_0_6px_#f97316]" />
                  </g>
                  {/* Asia Pacific */}
                  <g className="cursor-pointer">
                    <circle cx="620" cy="160" r="120" fill="url(#mapGlow)" />
                    <circle cx="620" cy="160" r="15" fill="none" stroke="#ef4444" strokeWidth="1.5" className="animate-ping" style={{ animationDuration: '2s' }} />
                    <circle cx="620" cy="160" r="7" fill="#ef4444" className="drop-shadow-[0_0_6px_#ef4444]" />
                  </g>
                  {/* Middle East */}
                  <g className="cursor-pointer">
                    <circle cx="510" cy="210" r="70" fill="url(#mapGlow)" />
                    <circle cx="510" cy="210" r="9" fill="none" stroke="#f97316" strokeWidth="1" className="animate-ping" style={{ animationDuration: '3.5s' }} />
                    <circle cx="510" cy="210" r="4.5" fill="#f97316" className="drop-shadow-[0_0_6px_#f97316]" />
                  </g>
                </svg>
              </div>
            </div>

            {/* Region progress indicators at bottom */}
            <div className="pt-4 border-t border-white/5 space-y-3">
              <span className="text-[8px] font-black text-white/30 uppercase tracking-[0.2em] block">Threat Activity by Region</span>
              <div className="grid grid-cols-6 gap-4">
                {[
                  { name: 'North America', count: 34, color: 'bg-red-500' },
                  { name: 'Europe', count: 28, color: 'bg-orange-500' },
                  { name: 'Asia Pacific', count: 25, color: 'bg-yellow-500' },
                  { name: 'Middle East', count: 19, color: 'bg-yellow-500/70' },
                  { name: 'South America', count: 10, color: 'bg-green-500' },
                  { name: 'Africa', count: 8, color: 'bg-green-500/80' }
                ].map((reg, idx) => (
                  <div key={idx} className="space-y-1">
                    <div className="flex justify-between text-[8px] font-mono font-bold">
                      <span className="text-white/40 truncate mr-1">{reg.name}</span>
                      <span className="text-white">{reg.count}</span>
                    </div>
                    <div className="h-1 w-full bg-white/[0.04] rounded overflow-hidden">
                      <div className={`h-full ${reg.color}`} style={{ width: `${(reg.count / 35) * 100}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* Card 2: Threat Categories */}
        <section className={`p-6 flex flex-col justify-between ${GLASS_PANEL_CLASSES} min-h-[480px]`}>
          <div>
            <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white/60 mb-6 flex items-center gap-2">
              <Layers className="h-4 w-4 text-gold" />
              Threat Categories
            </h2>

            <div className="flex flex-col items-center gap-6">
              {/* Donut Chart Container */}
              <div className="relative w-44 h-44 shrink-0">
                <svg className="w-full h-full rotate-[-90deg]">
                  {categoriesData.map((item, idx) => {
                    const offset = categoryOffsets[idx];
                    const isHovered = hoveredCategorySlice === idx;
                    return (
                      <circle
                        key={idx}
                        cx="88" cy="88" r={radius}
                        fill="none" stroke={item.color} strokeWidth={isHovered ? strokeWidth + 3 : strokeWidth}
                        strokeDasharray={`${offset.strokeLength} ${circumference}`}
                        strokeDashoffset={-offset.offset}
                        className="transition-all duration-300 cursor-pointer"
                        onMouseEnter={() => setHoveredCategorySlice(idx)}
                        onMouseLeave={() => setHoveredCategorySlice(null)}
                        style={{
                          filter: isHovered ? `drop-shadow(0 0 8px ${item.color}ee)` : 'none'
                        }}
                      />
                    );
                  })}
                </svg>

                {/* Donut Center text */}
                <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                  <span className="text-2xl font-black text-white leading-none">124</span>
                  <span className="text-[7px] font-bold text-white/30 uppercase tracking-widest mt-1.5">Total Threats</span>
                </div>
              </div>

              {/* Legends list */}
              <div className="w-full space-y-2.5">
                {categoriesData.map((item, idx) => {
                  const isHovered = hoveredCategorySlice === idx;
                  return (
                    <div 
                      key={idx}
                      className={`flex items-center justify-between p-1.5 rounded transition-colors ${isHovered ? 'bg-white/[0.04]' : ''}`}
                      onMouseEnter={() => setHoveredCategorySlice(idx)}
                      onMouseLeave={() => setHoveredCategorySlice(null)}
                    >
                      <div className="flex items-center gap-2">
                        <span className="w-2.5 h-2.5 rounded-sm shrink-0" style={{ backgroundColor: item.color }} />
                        <span className={`text-[10px] font-bold uppercase tracking-wider transition-colors ${isHovered ? 'text-white' : 'text-white/50'}`}>
                          {item.name}
                        </span>
                      </div>
                      <span className="text-[10px] font-bold font-mono text-white/80 shrink-0">
                        {item.value} <span className="text-white/30 font-medium">({item.percent})</span>
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </section>

      </div>

      {/* Row 2: Top Threats and Adversary Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        
        {/* Card 1: Top Threats */}
        <section className={`p-6 flex flex-col justify-between ${GLASS_PANEL_CLASSES} min-h-[460px]`}>
          <div className="space-y-5">
            <div className="flex justify-between items-center">
              <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white/60 flex items-center gap-2">
                <Flame className="h-4 w-4 text-gold animate-pulse" />
                Top Threats
              </h2>
              <button className="text-[9px] font-black uppercase tracking-wider text-gold hover:underline flex items-center gap-0.5">
                View All Threats <ChevronRight className="w-3 h-3" />
              </button>
            </div>

            <div className="space-y-4">
              {[
                { level: 'Critical', color: 'border-red-500/20 bg-red-500/5 text-red-400', title: 'Quantum Cryptanalysis Breakthrough', desc: 'New quantum algorithm claims to break RSA-2048 in laboratory conditions.', time: '15m ago' },
                { level: 'High', color: 'border-orange-500/20 bg-orange-500/5 text-orange-400', title: 'Post-Quantum Malware Campaign', desc: 'Malware leveraging hybrid encryption downgrade attacks.', time: '1h ago' },
                { level: 'High', color: 'border-orange-500/20 bg-orange-500/5 text-orange-400', title: 'PQC Implementation Flaw', desc: 'Vulnerability in popular PQC library allows key recovery.', time: '3h ago' },
                { level: 'Medium', color: 'border-yellow-500/20 bg-yellow-500/5 text-yellow-400', title: 'Increased Scanning for Weak Crypto', desc: 'Mass scanning for outdated TLS and weak ciphers.', time: '5h ago' },
                { level: 'Medium', color: 'border-yellow-500/20 bg-yellow-500/5 text-yellow-400', title: 'Supply Chain Compromise', desc: 'Third-party library with weak crypto dependency detected.', time: '8h ago' }
              ].map((threat, idx) => (
                <div key={idx} className="p-3.5 rounded-lg border border-white/5 bg-white/[0.01] hover:bg-white/[0.03] transition-colors group/row">
                  <div className="flex justify-between items-start gap-2 mb-1.5">
                    <span className={`text-[8px] font-black uppercase tracking-wider px-1.5 py-0.5 rounded border ${threat.color}`}>
                      {threat.level}
                    </span>
                    <span className="text-[9px] text-white/30 font-bold font-mono shrink-0">{threat.time}</span>
                  </div>
                  <h4 className="text-[10px] font-black text-white/90 uppercase tracking-wide group-hover/row:text-gold transition-colors leading-tight mb-1">
                    {threat.title}
                  </h4>
                  <p className="text-[9px] text-white/40 leading-relaxed font-medium">{threat.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Card 2: Adversary Activity */}
        <section className={`p-6 flex flex-col justify-between ${GLASS_PANEL_CLASSES} min-h-[460px]`}>
          <div className="space-y-4">
            <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white/60 flex items-center gap-2">
              <Skull className="h-4 w-4 text-gold" />
              Adversary Activity
            </h2>

            <div className="overflow-x-auto custom-scrollbar">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-white/5 text-[9px] font-black text-white/40 uppercase tracking-widest">
                    <th className="py-2.5">Adversary</th>
                    <th className="py-2.5">Threat Level</th>
                    <th className="py-2.5 text-center">Activity</th>
                    <th className="py-2.5 text-right">Trend</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {[
                    { name: 'Volt Typhoon', level: 'Critical', levelColor: 'border-red-500/20 bg-red-500/5 text-red-400', score: 5, trend: '↑ 15%', trendColor: 'text-red-400' },
                    { name: 'APT41', level: 'High', levelColor: 'border-orange-500/20 bg-orange-500/5 text-orange-400', score: 4, trend: '↑ 8%', trendColor: 'text-green-400' },
                    { name: 'Lazarus Group', level: 'High', levelColor: 'border-orange-500/20 bg-orange-500/5 text-orange-400', score: 4, trend: '↑ 12%', trendColor: 'text-red-400' },
                    { name: 'UNC5221', level: 'Medium', levelColor: 'border-yellow-500/20 bg-yellow-500/5 text-yellow-400', score: 3, trend: '↑ 3%', trendColor: 'text-green-400' },
                    { name: 'Sandworm', level: 'Medium', levelColor: 'border-yellow-500/20 bg-yellow-500/5 text-yellow-400', score: 3, trend: '↑ 5%', trendColor: 'text-green-400' },
                    { name: 'Neutron Panda', level: 'Low', levelColor: 'border-green-500/20 bg-green-500/5 text-green-400', score: 2, trend: '↓ 2%', trendColor: 'text-green-400/80' }
                  ].map((adv, i) => (
                    <tr key={i} className="hover:bg-white/[0.02] transition-colors group/row">
                      <td className="py-3 text-[10px] font-bold text-white/80 group-hover/row:text-gold transition-colors">
                        {adv.name}
                      </td>
                      <td className="py-3">
                        <span className={`text-[8px] font-black uppercase px-2 py-0.5 rounded border inline-block ${adv.levelColor}`}>
                          {adv.level}
                        </span>
                      </td>
                      <td className="py-3">
                        <div className="flex justify-center gap-0.5">
                          {[1, 2, 3, 4, 5].map(b => (
                            <span 
                              key={b}
                              className={`w-3.5 h-1.5 rounded-sm ${
                                b <= adv.score 
                                  ? 'bg-[#FFD36B] drop-shadow-[0_0_3px_rgba(255,211,107,0.8)]' 
                                  : 'bg-white/10'
                              }`} 
                            />
                          ))}
                        </div>
                      </td>
                      <td className={`py-3 text-right text-[10px] font-mono font-bold ${adv.trendColor}`}>
                        {adv.trend}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>

      </div>

      {/* Row 3: Latest Intelligence and Threat Intelligence Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        
        {/* Card 1: Latest Intelligence */}
        <section className={`p-6 flex flex-col justify-between ${GLASS_PANEL_CLASSES} min-h-[440px]`}>
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white/60 flex items-center gap-2">
                <Terminal className="h-4 w-4 text-gold" />
                Latest Intelligence
              </h2>
              <button className="text-[9px] font-black uppercase tracking-wider text-gold hover:underline flex items-center gap-0.5">
                View All Intel <ChevronRight className="w-3 h-3" />
              </button>
            </div>

            <div className="space-y-3.5">
              {[
                { icon: FileText, title: 'NIST releases final report on quantum-resistant cryptography migration.', tag: 'New', tagColor: 'border-red-500/20 bg-red-500/10 text-red-400', time: '1h ago' },
                { icon: Shield, title: 'New quantum annealing technique reduces key search complexity.', tag: 'High Impact', tagColor: 'border-red-500/20 bg-red-500/10 text-red-400', time: '3h ago' },
                { icon: AlertTriangle, title: 'CVE-2025-24801: Flaw in PQC key encapsulation mechanism.', tag: 'Medium Impact', tagColor: 'border-yellow-500/20 bg-yellow-500/10 text-yellow-400', time: '6h ago' },
                { icon: Shield, title: 'Nation-state actor targeting critical infrastructure with PQC downgrade.', tag: 'High Impact', tagColor: 'border-red-500/20 bg-red-500/10 text-red-400', time: '9h ago' },
                { icon: ExternalLink, title: 'Major cloud provider announces PQC adoption roadmap.', tag: 'Low Impact', tagColor: 'border-green-500/20 bg-green-500/10 text-green-400', time: '12h ago' }
              ].map((intel, idx) => {
                const Icon = intel.icon;
                return (
                  <div key={idx} className="flex gap-3.5 items-start p-3 rounded-lg border border-white/5 bg-white/[0.01] hover:bg-white/[0.03] transition-all group/item">
                    <div className="p-1.5 rounded border border-white/10 bg-white/5 shrink-0 mt-0.5">
                      <Icon className="w-4 h-4 text-gold group-hover/item:scale-110 transition-transform" />
                    </div>
                    <div className="space-y-1">
                      <p className="text-[10px] font-bold text-white/80 group-hover/item:text-gold transition-colors leading-relaxed">
                        {intel.title}
                      </p>
                      <div className="flex gap-2 items-center">
                        <span className={`text-[7px] font-black uppercase tracking-wider px-1.5 py-0.5 rounded border ${intel.tagColor}`}>
                          {intel.tag}
                        </span>
                        <span className="text-[9px] text-white/30 font-bold font-mono">{intel.time}</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </section>

        {/* Card 2: Threat Intelligence Feed */}
        <section className={`p-6 flex flex-col justify-between ${GLASS_PANEL_CLASSES} min-h-[440px]`}>
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white/60 flex items-center gap-2">
                <Radio className="h-4 w-4 text-gold animate-pulse" />
                Threat Intelligence Feed
              </h2>
              <button className="text-[9px] font-black uppercase tracking-wider text-gold hover:underline flex items-center gap-0.5">
                View Full Feed <ChevronRight className="w-3 h-3" />
              </button>
            </div>

            {/* Interactive streaming timeline feed list */}
            <div className="space-y-3">
              <AnimatePresence initial={false}>
                {liveFeeds.map((feed, idx) => {
                  const isCritical = feed.severity === 'critical';
                  const isHigh = feed.severity === 'high';
                  
                  return (
                    <motion.div
                      key={feed.time + idx}
                      initial={{ opacity: 0, y: -20, scale: 0.95 }}
                      animate={{ opacity: 1, y: 0, scale: 1 }}
                      exit={{ opacity: 0, scale: 0.9 }}
                      transition={{ duration: 0.4 }}
                      className={`p-3 rounded-lg border text-left flex gap-3 transition-colors ${
                        isCritical 
                          ? 'border-red-500/20 bg-red-500/5 hover:bg-red-500/10' 
                          : isHigh 
                          ? 'border-orange-500/20 bg-orange-500/5 hover:bg-orange-500/10'
                          : 'border-white/5 bg-white/[0.01] hover:bg-white/[0.03]'
                      }`}
                    >
                      <div className="shrink-0 pt-0.5">
                        <span className={`w-2 h-2 rounded-full block ${
                          isCritical ? 'bg-red-500 animate-ping' : isHigh ? 'bg-orange-500 animate-pulse' : 'bg-yellow-500'
                        }`} />
                      </div>
                      <div className="space-y-1 flex-1 min-w-0">
                        <div className="flex items-center justify-between text-[9px]">
                          <span className="font-black font-mono text-white/40">{feed.time}</span>
                          <span className="font-bold text-gold/60 truncate max-w-[100px]">{feed.source}</span>
                        </div>
                        <p className="text-[10px] font-medium leading-relaxed text-white/80 group-hover:text-white truncate">
                          {feed.title}
                        </p>
                      </div>
                    </motion.div>
                  );
                })}
              </AnimatePresence>
            </div>
          </div>
        </section>

      </div>

      {/* 5. Bottom Trust Outlook Banner (5 columns footer branding) */}
      <footer className={`p-6 ${GLASS_PANEL_CLASSES} divide-y lg:divide-y-0 lg:divide-x divide-white/5 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-6 lg:gap-0`}>
        {[
          { title: 'QUANTUM RISK INSIGHT', desc: 'Organizations using RSA/ECC face the highest long-term risk.', icon: Atom },
          { title: 'EMERGING TREND', desc: 'PQC downgrade attacks increasing across industries.', icon: Shield },
          { title: 'TOP TARGETS', desc: 'Government, Finance and Healthcare remain primary targets.', icon: Target },
          { title: 'RECOMMENDATION', desc: 'Accelerate PQC adoption and eliminate weak cryptography.', icon: Lightbulb },
          { title: 'THREAT OUTLOOK', desc: 'High risk expected to persist over the next 30 days.', icon: Eye }
        ].map((item, idx) => {
          const Icon = item.icon;
          return (
            <div key={idx} className="flex flex-col items-center text-center p-4 xl:px-6 space-y-2 first:pl-0 last:pr-0">
              <div className="p-2 rounded bg-gold/10 border border-gold/20 mb-1">
                <Icon className="w-5 h-5 text-gold drop-shadow-[0_0_6px_rgba(255,211,107,0.3)] animate-pulse" />
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
