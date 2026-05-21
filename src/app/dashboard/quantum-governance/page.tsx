'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  ShieldCheck, 
  BarChart3, 
  Database, 
  Users, 
  RefreshCcw, 
  Layers, 
  ClipboardList, 
  ShieldAlert,
  Search,
  Filter,
  Download,
  ExternalLink,
  ChevronRight,
  AlertTriangle,
  History,
  FileBadge,
  Clock,
  GitCompare,
  Globe,
  Sparkles
} from 'lucide-react';
import { useQuantumGovernance } from '@/hooks/quantum-governance/useQuantumGovernance';
import QuantumGovernanceLoading from './loading';

const GLASS_PANEL_CLASSES = 'group relative overflow-hidden rounded-xl border border-[#FFD36B]/20 bg-[#0f1428]/45 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(255,211,107,0.03),0_0_40px_rgba(255,211,107,0.14)] transition-all duration-500 hover:-translate-y-1 hover:border-[#FFD36B]/70 hover:bg-[#0f1428]/65 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.3),inset_0_-24px_60px_rgba(255,211,107,0.15),0_8px_30px_rgba(0,0,0,0.5),0_0_60px_rgba(255,211,107,0.5),0_0_120px_rgba(255,211,107,0.2)] hover:z-10 before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FFF4C0]/70 before:to-transparent before:transition-all before:duration-500 group-hover:before:opacity-100 group-hover:before:shadow-[0_0_15px_rgba(255,211,107,0.9)] group-hover:before:via-[#FFF4C0] after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-48 after:w-48 after:rounded-full after:bg-[#FFD36B]/10 after:blur-3xl after:transition-all after:duration-500 group-hover:after:opacity-100 group-hover:after:bg-[#FFD36B]/25 group-hover:after:blur-[36px] text-white';

export default function QuantumGovernancePage() {
  const { 
    loading, kpis, inventory, ownership, pkiDebt, 
    migrationTasks, compliance, vendors, workflows, evidence 
  } = useQuantumGovernance();
  const [activeTab, setActiveTab] = useState('inventory');

  if (loading) return <QuantumGovernanceLoading />;

  return (
    <div className="p-8 space-y-8 pb-20">
      {/* Header Section */}
      <header className="relative">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <div className="h-10 w-10 rounded-xl bg-gold/10 border border-gold/30 flex items-center justify-center shadow-[0_0_20px_rgba(212,175,55,0.15)]">
                <ShieldCheck className="h-6 w-6 text-gold" />
              </div>
              <h1 className="text-3xl font-black uppercase tracking-tight text-white gold-glow">
                Governance <span className="text-gold">Center</span>
              </h1>
            </div>
            <p className="text-white/50 font-medium max-w-2xl">
              Crypto Lifecycle, PQC Readiness & Compliance Control Plane.
              Manage your entire cryptographic inventory, ownership, and risk posture.
            </p>
          </div>
          
          <div className="flex items-center gap-3 text-gold">
            <button className="px-4 py-2 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg text-xs font-bold transition-all flex items-center gap-2">
              <Download className="h-4 w-4" /> Export Report
            </button>
            <button className="px-4 py-2 bg-gold/10 hover:bg-gold/20 border border-gold/30 text-gold rounded-lg text-xs font-bold transition-all flex items-center gap-2 shadow-[0_0_15px_rgba(212,175,55,0.1)]">
              <RefreshCcw className="h-4 w-4" /> Sync Inventory
            </button>
          </div>
        </div>
      </header>

      {/* Executive Messaging Cards */}
      <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { title: 'Governance Before Algorithms', content: 'PQC migration fails when cryptography is unmanaged. Before an organization can replace algorithms, it must know where cryptography exists, who owns it, when it rotates, and what controls prove readiness.', icon: ShieldCheck },
          { title: 'PKI Debt Is Quantum Exposure', content: 'Long-lived certificates, unknown roots, manual issuance, and unowned keys create operational blockers that delay quantum-safe migration.', icon: Layers },
          { title: 'Crypto Agility Is the Control Objective', content: 'The goal is not only ML-KEM or ML-DSA adoption. The goal is the ability to discover, rotate, replace, validate, and prove cryptographic control at enterprise scale.', icon: RefreshCcw },
          { title: 'Compliance Needs Evidence', content: 'Quantum readiness must produce audit-ready evidence: inventory records, migration approvals, vendor attestations, exception reviews, rotation logs, and control mappings.', icon: ClipboardList },
        ].map((card, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: i * 0.1 }}
            className={GLASS_PANEL_CLASSES + " p-5 flex flex-col gap-3"}
          >
            <div className="h-8 w-8 rounded-lg bg-gold/5 flex items-center justify-center border border-gold/10 relative z-10">
              <card.icon className="h-4 w-4 text-gold/60 group-hover:text-gold transition-colors" />
            </div>
            <h4 className="text-[11px] font-black uppercase tracking-widest text-gold/80 relative z-10">{card.title}</h4>
            <p className="text-[10px] text-white/40 leading-relaxed font-medium relative z-10">{card.content}</p>
          </motion.div>
        ))}
      </section>

      {/* Main Layout Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Side: Main Controls */}
        <div className="lg:col-span-9 space-y-8">
          {/* KPI Cards */}
          <section className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
            {kpis.map((kpi, i) => (
              <motion.div
                key={kpi.label}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.1 }}
                className={GLASS_PANEL_CLASSES + " p-4"}
              >
                <div className="absolute top-0 right-0 p-2 opacity-10 group-hover:opacity-20 transition-opacity z-10">
                  <BarChart3 className="h-12 w-12 text-gold" />
                </div>
                <p className="text-[10px] font-black uppercase tracking-wider text-white/40 mb-1 relative z-10">{kpi.label}</p>
                <div className="flex items-end justify-between relative z-10">
                  <h3 className="text-2xl font-black text-white group-hover:text-gold transition-colors">{kpi.value}</h3>
                  <div className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                    kpi.trend === 'up' ? 'text-green-400 bg-green-500/10' : 
                    kpi.trend === 'down' ? 'text-red-400 bg-red-500/10' : 'text-blue-400 bg-blue-500/10'
                  }`}>
                    {kpi.trend === 'up' ? '↑' : kpi.trend === 'down' ? '↓' : '→'}
                  </div>
                </div>
                <div className="mt-3 flex items-center gap-2 relative z-10">
                  <div className={`h-1.5 w-1.5 rounded-full ${
                    kpi.severity === 'critical' ? 'bg-red-500 shadow-[0_0_8px_#ef4444]' :
                    kpi.severity === 'high' ? 'bg-orange-500' :
                    kpi.severity === 'medium' ? 'bg-yellow-500' : 'bg-green-500'
                  }`} />
                  <span className="text-[9px] text-white/30 uppercase font-bold">Severity: {kpi.severity}</span>
                </div>
              </motion.div>
            ))}
          </section>

          {/* Tabs */}
          <section className="space-y-6">
            <div className="flex items-center gap-2 border-b border-white/10 pb-px overflow-x-auto scrollbar-none">
              {[
                { id: 'inventory', label: 'Inventory', icon: Database },
                { id: 'ownership', label: 'Ownership', icon: Users },
                { id: 'key-lifecycle', label: 'Lifecycle', icon: Clock },
                { id: 'pki-debt', label: 'PKI Debt', icon: Layers },
                { id: 'migration', label: 'Migration', icon: RefreshCcw },
                { id: 'compliance', label: 'Compliance', icon: ClipboardList },
                { id: 'workflows', label: 'Workflows', icon: GitCompare },
                { id: 'policies', label: 'Policies', icon: FileBadge },
                { id: 'vendors', label: 'Vendors', icon: Globe },
                { id: 'evidence', label: 'Evidence', icon: Download },
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`px-6 py-3 text-[10px] font-black uppercase tracking-widest flex items-center gap-2.5 transition-all relative shrink-0 ${
                    activeTab === tab.id ? 'text-gold' : 'text-white/40 hover:text-white/70'
                  }`}
                >
                  <tab.icon className={`h-3.5 w-3.5 ${activeTab === tab.id ? 'text-gold' : 'text-white/30'}`} />
                  {tab.label}
                  {activeTab === tab.id && (
                    <motion.div 
                      layoutId="activeTab"
                      className="absolute bottom-0 left-0 right-0 h-0.5 bg-gold shadow-[0_0_10px_#d4af23]"
                    />
                  )}
                </button>
              ))}
            </div>

            {/* Tab Content */}
            <div className="min-h-[500px]">
              <AnimatePresence mode="wait">
                {activeTab === 'inventory' && (
                  <motion.div
                    key="inventory"
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    className="space-y-6"
                  >
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[#0f1428]/45 p-4 rounded-xl border border-white/5 backdrop-blur-xl">
                      <div className="relative flex-1 max-w-md">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-white/30" />
                        <input 
                          type="text" 
                          placeholder="Search cryptographic assets..." 
                          className="w-full border border-gold/20 bg-[#0f1428]/35 rounded-lg py-2 pl-10 pr-4 text-xs text-white placeholder:text-white/20 focus:outline-none focus:border-gold/50"
                        />
                      </div>
                      <div className="flex items-center gap-3">
                        <button className="px-3 py-2 bg-white/5 rounded-lg border border-white/10 text-[10px] font-bold uppercase tracking-wider flex items-center gap-2 hover:bg-white/10 transition-colors">
                          <Filter className="h-3.5 w-3.5" /> Filter Assets
                        </button>
                      </div>
                    </div>

                    <div className="overflow-x-auto rounded-xl border border-gold/20 bg-[#0f1428]/45 backdrop-blur-xl">
                      <table className="w-full border-collapse">
                        <thead>
                          <tr className="border-b border-gold/20 text-left bg-gold/[0.03]">
                            <th className="p-4 text-[10px] font-black uppercase tracking-widest text-white/40">Asset</th>
                            <th className="p-4 text-[10px] font-black uppercase tracking-widest text-white/40">Criticality</th>
                            <th className="p-4 text-[10px] font-black uppercase tracking-widest text-white/40">Algorithm</th>
                            <th className="p-4 text-[10px] font-black uppercase tracking-widest text-white/40">Ownership</th>
                            <th className="p-4 text-[10px] font-black uppercase tracking-widest text-white/40">PQC Ready</th>
                            <th className="p-4 text-[10px] font-black uppercase tracking-widest text-white/40">Risk</th>
                            <th className="p-4 text-[10px] font-black uppercase tracking-widest text-white/40">Actions</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gold/10">
                          {inventory.map(asset => (
                            <tr key={asset.id} className="hover:bg-white/[0.02] transition-colors group">
                              <td className="p-4">
                                <div className="flex items-center gap-3">
                                  <div className="h-8 w-8 rounded-lg bg-gold/5 border border-gold/20 flex items-center justify-center">
                                    <Database className="h-4 w-4 text-gold/60" />
                                  </div>
                                  <div>
                                    <div className="text-xs font-bold text-white group-hover:text-gold transition-colors">{asset.name}</div>
                                    <div className="text-[10px] text-white/30">{asset.id} · {asset.environment}</div>
                                  </div>
                                </div>
                              </td>
                              <td className="p-4">
                                <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                                  asset.criticality === 'critical' ? 'bg-red-500/20 text-red-400 border border-red-500/20' :
                                  asset.criticality === 'high' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/20' :
                                  'bg-blue-500/20 text-blue-400'
                                }`}>
                                  {asset.criticality}
                                </span>
                              </td>
                              <td className="p-4 font-mono text-[10px] text-white/60">{asset.algorithm}</td>
                              <td className="p-4">
                                <div className="text-[10px] text-white/70 font-bold">{asset.technicalOwner}</div>
                                <div className="text-[9px] text-white/30">{asset.businessOwner}</div>
                              </td>
                              <td className="p-4">
                                <div className="flex items-center gap-3">
                                  <div className="flex-1 h-1 bg-white/5 rounded-full overflow-hidden max-w-[60px]">
                                    <div 
                                      className={`h-full rounded-full ${asset.pqcReadiness > 70 ? 'bg-green-500' : asset.pqcReadiness > 30 ? 'bg-yellow-500' : 'bg-red-500'}`}
                                      style={{ width: `${asset.pqcReadiness}%` }}
                                    />
                                  </div>
                                  <span className="text-[10px] font-bold text-white/50">{asset.pqcReadiness}%</span>
                                </div>
                              </td>
                              <td className="p-4">
                                <span className={`text-[10px] font-black ${
                                  asset.riskScore > 75 ? 'text-red-400' : asset.riskScore > 40 ? 'text-yellow-400' : 'text-green-400'
                                }`}>
                                  {asset.riskScore}
                                </span>
                              </td>
                              <td className="p-4">
                                <button className="h-8 w-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center hover:border-gold/40 hover:text-gold transition-all">
                                  <ChevronRight className="h-4 w-4" />
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </motion.div>
                )}

                {activeTab === 'ownership' && (
                  <motion.div
                    key="ownership"
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    className="grid grid-cols-1 md:grid-cols-2 gap-6"
                  >
                    {ownership.map((record, i) => (
                      <div key={i} className={GLASS_PANEL_CLASSES + " p-6 space-y-4"}>
                        <div className="flex items-center justify-between relative z-10">
                          <h4 className="text-sm font-black uppercase tracking-wider text-white">{record.domain}</h4>
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                            record.status === 'compliant' ? 'bg-green-500/10 text-green-400 border border-green-500/20' : 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20'
                          }`}>
                            {record.status.replace('_', ' ')}
                          </span>
                        </div>
                        
                        <div className="grid grid-cols-2 gap-4 relative z-10">
                          <div className="space-y-1">
                            <p className="text-[9px] font-black uppercase tracking-widest text-white/25">Business Owner</p>
                            <p className="text-xs font-bold text-white/80">{record.businessOwner}</p>
                          </div>
                          <div className="space-y-1">
                            <p className="text-[9px] font-black uppercase tracking-widest text-white/25">Technical Owner</p>
                            <p className="text-xs font-bold text-white/80">{record.technicalOwner}</p>
                          </div>
                          <div className="space-y-1">
                            <p className="text-[9px] font-black uppercase tracking-widest text-white/25">Security Owner</p>
                            <p className="text-xs font-bold text-white/80">{record.securityOwner}</p>
                          </div>
                          <div className="space-y-1">
                            <p className="text-[9px] font-black uppercase tracking-widest text-white/25">Last Review</p>
                            <p className="text-xs font-bold text-white/80">{record.lastReview}</p>
                          </div>
                        </div>

                        <div className="pt-4 border-t border-gold/10 flex items-center justify-between relative z-10">
                          <button className="text-[10px] font-bold text-gold hover:underline">Edit Assignment</button>
                          <button className="px-3 py-1 bg-white/5 hover:bg-white/10 rounded-md text-[10px] font-bold text-white/40 transition-all border border-white/10">
                            Request Attestation
                          </button>
                        </div>
                      </div>
                    ))}
                  </motion.div>
                )}

                {activeTab === 'key-lifecycle' && (
                  <motion.div
                    key="key-lifecycle"
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    className="space-y-8"
                  >
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className={GLASS_PANEL_CLASSES + " p-6 space-y-4"}>
                        <h4 className="text-xs font-black uppercase tracking-widest text-gold/80 relative z-10">Active Lifecycle States</h4>
                        <div className="space-y-3 relative z-10">
                          {[
                            { label: 'Discovered', count: 142, color: 'bg-blue-500' },
                            { label: 'Approved', count: 89, color: 'bg-green-500' },
                            { label: 'Rotation Due', count: 12, color: 'bg-red-500' },
                            { label: 'Exception Granted', count: 4, color: 'bg-orange-500' },
                          ].map(state => (
                            <div key={state.label} className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <div className={`h-1.5 w-1.5 rounded-full ${state.color}`} />
                                <span className="text-[10px] font-bold text-white/60">{state.label}</span>
                              </div>
                              <span className="text-[10px] font-black text-white">{state.count}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      <div className={GLASS_PANEL_CLASSES + " p-6 space-y-4"}>
                        <h4 className="text-xs font-black uppercase tracking-widest text-gold/80 relative z-10">Lifecycle Control</h4>
                        <p className="text-[10px] text-white/40 leading-relaxed relative z-10">
                          Automated tracking of key age, rotation SLAs, and operational dependencies.
                        </p>
                        <div className="flex items-center gap-2 pt-2 relative z-10">
                           <button className="px-3 py-1.5 bg-gold/10 text-gold border border-gold/30 rounded text-[9px] font-black uppercase tracking-widest">Trigger Rotation</button>
                           <button className="px-3 py-1.5 bg-white/5 text-white/40 border border-white/10 rounded text-[9px] font-black uppercase tracking-widest">Emergency Revoke</button>
                        </div>
                      </div>
                    </div>

                    <div className={GLASS_PANEL_CLASSES + " p-6"}>
                      <h5 className="text-[10px] font-black uppercase tracking-widest text-white/30 mb-6 relative z-10">Key Lifecycle Timeline Example</h5>
                      <div className="flex items-center justify-between relative z-10">
                        <div className="absolute top-1/2 left-0 right-0 h-px bg-white/10 -translate-y-1/2 z-0" />
                        {[
                          { label: 'Created', active: true },
                          { label: 'Activated', active: true },
                          { label: 'Used', active: true },
                          { label: 'Reviewed', active: true },
                          { label: 'Rotated', active: false },
                          { label: 'Revoked', active: false },
                          { label: 'Archived', active: false },
                        ].map((step, i) => (
                          <div key={i} className="relative z-10 flex flex-col items-center gap-2">
                            <div className={`h-3 w-3 rounded-full border-2 border-black ${step.active ? 'bg-gold shadow-[0_0_8px_#d4af23]' : 'bg-white/10'}`} />
                            <span className={`text-[8px] font-black uppercase tracking-tighter ${step.active ? 'text-gold' : 'text-white/20'}`}>{step.label}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </motion.div>
                )}

                {activeTab === 'migration' && (
                  <motion.div
                    key="migration"
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    className="space-y-6"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="text-sm font-black uppercase tracking-wider text-white">PQC Migration Roadmap</h4>
                      <button className="px-3 py-1.5 bg-gold/10 text-gold border border-gold/20 rounded-lg text-[10px] font-bold uppercase tracking-wider">
                        Add Migration Task
                      </button>
                    </div>
                    
                    <div className="space-y-4">
                      {migrationTasks.map(task => (
                        <div key={task.id} className={GLASS_PANEL_CLASSES + " p-5 relative overflow-hidden group"}>
                          <div className="absolute top-0 left-0 bottom-0 w-1 bg-gold/40 shadow-[0_0_10px_rgba(212,175,55,0.4)] z-10" />
                          <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 relative z-10">
                            <div className="space-y-1">
                              <div className="flex items-center gap-3">
                                <span className="text-xs font-black text-white">{task.asset}</span>
                                <span className={`text-[8px] font-black px-1.5 py-0.5 rounded uppercase ${
                                  task.status === 'in_progress' ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' : 'bg-white/5 text-white/40'
                                }`}>
                                  {task.status.replace('_', ' ')}
                                </span>
                              </div>
                              <p className="text-[10px] text-white/30 tracking-tight">Stage: <span className="text-white/60 font-bold uppercase">{task.stage}</span> · Target: <span className="text-gold font-bold">{task.targetAlgorithm}</span></p>
                            </div>
                            
                            <div className="flex items-center gap-8">
                              <div className="text-center">
                                <p className="text-[9px] font-black uppercase tracking-widest text-white/20 mb-1">Deadline</p>
                                <p className="text-[10px] font-bold text-white/60">{task.deadline}</p>
                              </div>
                              <div className="flex items-center gap-2">
                                <button className="px-3 py-1.5 bg-white/5 hover:bg-white/10 border border-white/10 rounded text-[10px] font-bold text-white/50 transition-all">Details</button>
                                <button className="px-3 py-1.5 bg-gold/10 hover:bg-gold/20 border border-gold/30 rounded text-[10px] font-bold text-gold transition-all">Approve</button>
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </motion.div>
                )}

                {activeTab === 'compliance' && (
                  <motion.div
                    key="compliance"
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    className="grid grid-cols-1 gap-4"
                  >
                    {compliance.map((control, i) => (
                      <div key={i} className={GLASS_PANEL_CLASSES + " p-4 flex items-center justify-between"}>
                        <div className="flex items-center gap-4 relative z-10">
                          <div className="h-10 w-10 rounded-lg bg-gold/5 flex items-center justify-center border border-gold/10 shrink-0">
                            <FileBadge className="h-5 w-5 text-gold/60" />
                          </div>
                          <div>
                            <div className="flex items-center gap-2 mb-1 flex-wrap">
                              <span className="text-[9px] font-black bg-white/5 px-1.5 py-0.5 rounded text-white/40 tracking-wider uppercase">{control.framework}</span>
                              <h6 className="text-xs font-bold text-white group-hover:text-gold transition-colors">{control.controlId}: {control.name}</h6>
                            </div>
                            <div className="flex items-center gap-3 text-[10px] text-white/30 flex-wrap">
                              <span className="flex items-center gap-1"><ShieldCheck className="h-3 w-3" /> Status: <span className="text-white/60">{control.status}</span></span>
                              <span className="flex items-center gap-1"><ClipboardList className="h-3 w-3" /> Evidence: <span className={control.evidenceStatus === 'attached' ? 'text-green-400' : 'text-red-400'}>{control.evidenceStatus}</span></span>
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 relative z-10 shrink-0">
                          <button className="px-3 py-1.5 bg-white/5 hover:bg-white/10 border border-white/10 rounded text-[10px] font-bold text-white/50 transition-all flex items-center gap-2">
                            <ExternalLink className="h-3 w-3" /> View
                          </button>
                          <button className="px-3 py-1.5 bg-gold/10 hover:bg-gold/20 border border-gold/30 rounded text-[10px] font-bold text-gold transition-all">
                            Attach
                          </button>
                        </div>
                      </div>
                    ))}
                  </motion.div>
                )}

                {activeTab === 'workflows' && (
                  <motion.div
                    key="workflows"
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    className="grid grid-cols-1 md:grid-cols-2 gap-4"
                  >
                    {workflows.map(wf => (
                      <div key={wf.id} className={GLASS_PANEL_CLASSES + " p-4 space-y-4"}>
                        <div className="flex items-center justify-between relative z-10">
                          <div className="flex items-center gap-2">
                            <GitCompare className="h-3.5 w-3.5 text-gold/60" />
                            <h6 className="text-[11px] font-bold text-white">{wf.type}</h6>
                          </div>
                          <span className={`text-[9px] font-black uppercase tracking-tighter px-1.5 py-0.5 rounded ${
                            wf.priority === 'critical' ? 'bg-red-500/20 text-red-400' : 'bg-white/5 text-white/40'
                          }`}>{wf.priority}</span>
                        </div>
                        <div className="flex items-center justify-between text-[10px] text-white/40 relative z-10">
                          <span>Assignee: <span className="text-white/70 font-medium">{wf.assignee}</span></span>
                          <span>Due: <span className="text-white/70 font-mono">{wf.dueDate}</span></span>
                        </div>
                        <div className="flex items-center gap-2 pt-2 border-t border-gold/10 relative z-10">
                           <button className="flex-1 py-1.5 bg-white/5 hover:bg-white/10 rounded text-[10px] font-bold text-white/60 transition-all">Details</button>
                           <button className="flex-1 py-1.5 bg-gold/10 hover:bg-gold/20 text-gold rounded text-[10px] font-bold transition-all">Process</button>
                        </div>
                      </div>
                    ))}
                  </motion.div>
                )}

                {activeTab === 'policies' && (
                  <motion.div
                    key="policies"
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    className="space-y-4"
                  >
                    {[
                      { name: 'Maximum Key Age', val: '90 Days', status: 'compliant' },
                      { name: 'Allowed Algorithms', val: 'FIPS Approved Only', status: 'compliant' },
                      { name: 'Hybrid PQC Policy', val: 'Critical Systems Only', status: 'warning' },
                    ].map((policy, i) => (
                      <div key={i} className={GLASS_PANEL_CLASSES + " p-4 flex items-center justify-between"}>
                        <div className="relative z-10">
                          <h6 className="text-xs font-bold text-white mb-0.5">{policy.name}</h6>
                          <p className="text-[10px] text-white/40">{policy.val}</p>
                        </div>
                        <span className={`text-[9px] font-black uppercase px-2 py-0.5 rounded relative z-10 ${
                          policy.status === 'compliant' ? 'bg-green-500/10 text-green-400' : 'bg-yellow-500/10 text-yellow-400'
                        }`}>{policy.status}</span>
                      </div>
                    ))}
                    <button className="w-full py-2 border border-dashed border-white/10 rounded-xl text-[10px] font-black uppercase tracking-widest text-white/20 hover:text-white/40 transition-all">
                      Add Custom Policy
                    </button>
                  </motion.div>
                )}

                {activeTab === 'vendors' && (
                  <motion.div
                    key="vendors"
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    className="overflow-x-auto rounded-xl border border-gold/20 bg-[#0f1428]/45 backdrop-blur-xl"
                  >
                    <table className="w-full border-collapse">
                      <thead>
                        <tr className="border-b border-gold/20 text-left bg-gold/[0.03]">
                          <th className="p-4 text-[10px] font-black uppercase tracking-widest text-white/40">Vendor</th>
                          <th className="p-4 text-[10px] font-black uppercase tracking-widest text-white/40">Product</th>
                          <th className="p-4 text-[10px] font-black uppercase tracking-widest text-white/40">PQC Roadmap</th>
                          <th className="p-4 text-[10px] font-black uppercase tracking-widest text-white/40">Target Date</th>
                          <th className="p-4 text-[10px] font-black uppercase tracking-widest text-white/40">Status</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gold/10">
                        {vendors.map((vendor, i) => (
                          <tr key={i} className="hover:bg-white/[0.02] transition-colors group">
                            <td className="p-4 text-xs font-bold text-white">{vendor.name}</td>
                            <td className="p-4 text-[10px] text-white/60">{vendor.product}</td>
                            <td className="p-4">
                              <span className={`h-2 w-2 rounded-full inline-block ${vendor.pqcRoadmap ? 'bg-green-500' : 'bg-red-500'}`} />
                            </td>
                            <td className="p-4 text-[10px] text-white/40 font-mono">{vendor.targetDate}</td>
                            <td className="p-4">
                               <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                                 vendor.status === 'pqc_ready' ? 'bg-green-500/10 text-green-400' : 'bg-white/5 text-white/40'
                               }`}>{vendor.status.replace('_', ' ')}</span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </motion.div>
                )}

                {activeTab === 'evidence' && (
                  <motion.div
                    key="evidence"
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"
                  >
                    {evidence.map(ev => (
                      <div key={ev.id} className={GLASS_PANEL_CLASSES + " p-4 space-y-3"}>
                        <div className="flex items-center gap-3 relative z-10">
                          <div className="h-10 w-10 rounded-lg bg-white/5 flex items-center justify-center">
                            <Download className="h-5 w-5 text-white/30 group-hover:text-gold transition-colors" />
                          </div>
                          <div>
                            <h6 className="text-[11px] font-bold text-white truncate max-w-[150px]">{ev.name}</h6>
                            <p className="text-[9px] text-white/30 uppercase">{ev.type} · {ev.uploadedAt}</p>
                          </div>
                        </div>
                        <div className="flex items-center justify-between pt-3 border-t border-gold/10 relative z-10">
                           <span className="text-[9px] text-white/20">Owner: {ev.owner}</span>
                           <button className="text-[9px] font-black text-gold uppercase tracking-widest hover:underline">Download</button>
                        </div>
                      </div>
                    ))}
                    <button className="p-4 rounded-xl border border-dashed border-white/10 flex flex-col items-center justify-center gap-2 hover:bg-white/[0.02] transition-all">
                       <Download className="h-5 w-5 text-white/20" />
                       <span className="text-[9px] font-black uppercase tracking-widest text-white/20">Upload Evidence</span>
                    </button>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </section>
        </div>

        {/* Right Side: Intelligence Panel */}
        <aside className="lg:col-span-3 space-y-6">
          <div className={GLASS_PANEL_CLASSES + " p-6 space-y-6"}>
            <h4 className="text-[11px] font-black uppercase tracking-widest text-gold/80 flex items-center gap-2 relative z-10">
              <Sparkles className="h-4 w-4" /> Intelligence Panel
            </h4>

            {/* Top Governance Gaps */}
            <div className="space-y-4 relative z-10">
              <h5 className="text-[9px] font-black uppercase tracking-widest text-white/30 border-b border-gold/10 pb-2">Top Governance Gaps</h5>
              {[
                { label: 'Unowned Assets', count: 12, color: 'text-red-400' },
                { label: 'Policy Violations', count: 5, color: 'text-orange-400' },
                { label: 'Manual PKI Tasks', count: 24, color: 'text-yellow-400' },
              ].map((gap, i) => (
                <div key={i} className="flex items-center justify-between">
                  <span className="text-[10px] font-bold text-white/60">{gap.label}</span>
                  <span className={`text-[11px] font-black ${gap.color}`}>{gap.count}</span>
                </div>
              ))}
            </div>

            {/* Upcoming Deadlines */}
            <div className="space-y-4 relative z-10">
              <h5 className="text-[9px] font-black uppercase tracking-widest text-white/30 border-b border-gold/10 pb-2">Upcoming Deadlines</h5>
              {[
                { label: 'Migration Plan Approval', date: '2026-05-15', urgent: true },
                { label: 'Key Rotation - Edge', date: '2026-05-20', urgent: false },
                { label: 'NIST Compliance Audit', date: '2026-06-01', urgent: false },
              ].map((deadline, i) => (
                <div key={i} className="space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-bold text-white/60 truncate max-w-[150px]">{deadline.label}</span>
                    {deadline.urgent && <div className="h-1.5 w-1.5 rounded-full bg-red-500 shadow-[0_0_8px_#ef4444]" />}
                  </div>
                  <p className="text-[9px] text-white/30 font-mono">{deadline.date}</p>
                </div>
              ))}
            </div>

            {/* High-Risk Exceptions */}
            <div className="space-y-4 relative z-10">
              <h5 className="text-[9px] font-black uppercase tracking-widest text-white/30 border-b border-gold/10 pb-2">High-Risk Exceptions</h5>
              <div className="p-3 rounded-lg bg-red-500/5 border border-red-500/10 space-y-2">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-3 w-3 text-red-400" />
                  <span className="text-[10px] font-bold text-red-400">RSA-1024 Legacy Bypass</span>
                </div>
                <p className="text-[9px] text-red-400/60 leading-tight">Expires in 3 days. No remediation plan uploaded.</p>
              </div>
            </div>

            <button className="w-full py-2.5 bg-gold/10 hover:bg-gold/20 border border-gold/30 text-gold rounded-xl text-[10px] font-black uppercase tracking-widest transition-all shadow-[0_0_20px_rgba(212,175,55,0.05)] relative z-10">
              Generate Board Brief
            </button>
          </div>

          <div className={GLASS_PANEL_CLASSES + " p-6 space-y-4"}>
             <h4 className="text-[11px] font-black uppercase tracking-widest text-white/60 relative z-10">Operational Readiness</h4>
             <div className="space-y-3 relative z-10">
               {[
                 { label: 'Algorithm Agility', val: 78 },
                 { label: 'Rotation Automation', val: 45 },
                 { label: 'Inventory Accuracy', val: 92 },
               ].map((stat, i) => (
                 <div key={i} className="space-y-1.5">
                   <div className="flex justify-between text-[9px] font-black uppercase tracking-tighter text-white/40">
                     <span>{stat.label}</span>
                     <span>{stat.val}%</span>
                   </div>
                   <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                     <div className="h-full bg-gold/40" style={{ width: `${stat.val}%` }} />
                   </div>
                 </div>
               ))}
             </div>
          </div>
        </aside>
      </div>

      {/* Governance Deficit Section */}
      <section className="bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-gold/5 via-transparent to-transparent p-8 rounded-3xl border border-gold/15 relative overflow-hidden">
        <div className="absolute top-0 right-0 p-8 opacity-10">
          <AlertTriangle className="h-32 w-32 text-gold" />
        </div>
        <div className="relative z-10 max-w-3xl">
          <h3 className="text-xl font-black uppercase tracking-widest text-gold mb-2">Governance Deficit Score</h3>
          <p className="text-white/50 text-xs leading-relaxed mb-6 italic">
            "Quantum risk is amplified when cryptography is unmanaged. The biggest exposure is not only vulnerable algorithms — it is the inability to find, govern, rotate, and prove control over cryptography."
          </p>
          
          <div className="flex items-center gap-8 mb-8 flex-wrap">
            <div className="text-center">
              <div className="text-5xl font-black text-white mb-2">42<span className="text-gold/50 text-2xl">.8</span></div>
              <p className="text-[10px] font-black uppercase tracking-widest text-white/30">Current Deficit</p>
            </div>
            <div className="flex-1 min-w-[200px] space-y-4">
              <div className="space-y-1.5">
                <div className="flex justify-between text-[10px] font-black uppercase tracking-wider flex-wrap gap-2">
                  <span className="text-white/60">Risk Interpretation: <span className="text-yellow-400 font-bold">Moderate Governance Gap</span></span>
                  <span className="text-white/20">Threshold: 20.0</span>
                </div>
                <div className="h-2 bg-white/5 rounded-full overflow-hidden border border-white/5">
                  <motion.div 
                    initial={{ width: 0 }}
                    animate={{ width: '42.8%' }}
                    className="h-full bg-gradient-to-r from-green-500 via-yellow-500 to-red-500"
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {[
                  { label: 'Strong', color: 'bg-green-500' },
                  { label: 'Moderate', color: 'bg-yellow-500' },
                  { label: 'Exposure', color: 'bg-orange-500' },
                  { label: 'Deficit', color: 'bg-red-500' },
                ].map(l => (
                  <div key={l.label} className="flex items-center gap-1.5">
                    <div className={`h-1.5 w-1.5 rounded-full ${l.color}`} />
                    <span className="text-[8px] font-black uppercase tracking-tighter text-white/20">{l.label}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className={GLASS_PANEL_CLASSES + " p-4 space-y-3"}>
              <h6 className="text-[10px] font-black uppercase tracking-widest text-gold/60 relative z-10">Top Deficit Drivers</h6>
              <ul className="space-y-2 relative z-10">
                {[
                  'Missing Technical Owners for 12% of Assets',
                  'Rotation Policy Violation in Legacy Segment',
                  'High Concentration of RSA-2048 in Edge Ops',
                  'Incomplete Vendor PQC Readiness Attestations'
                ].map((item, i) => (
                  <li key={i} className="flex items-center gap-2 text-[10px] text-white/50">
                    <div className="h-1 w-1 bg-gold/50 rounded-full" /> {item}
                  </li>
                ))}
              </ul>
            </div>
            <div className={GLASS_PANEL_CLASSES + " p-4 flex flex-col justify-center gap-4"}>
              <p className="text-[10px] text-white/40 leading-relaxed relative z-10">
                Until governance, accountability, and cryptographic lifecycle management are addressed, PQC slogans do not land.
              </p>
              <button className="w-full py-2 bg-gold/10 hover:bg-gold/20 border border-gold/30 text-gold rounded-lg text-[10px] font-bold uppercase tracking-widest transition-all relative z-10">
                Run Full Governance Audit
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* Workflow Feed Sidebar (Floating) */}
      <div className="fixed bottom-8 right-8 z-20">
        <button className="h-14 w-14 rounded-2xl bg-gold border border-gold/30 text-black flex items-center justify-center shadow-[0_8px_32px_rgba(212,175,55,0.4)] hover:scale-105 transition-all group">
          <History className="h-6 w-6 group-hover:rotate-12 transition-transform" />
          <div className="absolute -top-1 -right-1 h-5 w-5 bg-red-500 rounded-full border-2 border-black flex items-center justify-center text-[10px] font-bold text-white">3</div>
        </button>
      </div>
    </div>
  );
}
