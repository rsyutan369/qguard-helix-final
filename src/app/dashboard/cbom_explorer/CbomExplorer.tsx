import { Fragment, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search, ChevronRight, AlertTriangle, Shield, Lock, Unlock,
  Key, FileCode, Server, Globe, Layers, Package, ExternalLink,
  Copy, Loader2, RefreshCw
} from 'lucide-react';
import { useScannerIntelligence } from '@/lib/scanner/use-scanner-intelligence';

type CbomEntry = {
  id: string;
  component: string;
  type: string;
  algorithm: string;
  keySize: number | null;
  status: string;
  isVulnerable: boolean;
  isQuantumSafe: boolean;
  pqcReplacement: string | null;
  instances: number;
  sourceAsset: string;
  sourceAssetId: string;
  detectionMethod: string;
  lastScannedDate: string;
  riskSeverity: string;
  evidence: string;
  recommendation: string | null;
  metadata: Record<string, unknown>;
};

const GLASS_PANEL_CLASSES = 'group relative overflow-hidden rounded-xl border border-[#FFD36B]/20 bg-[#0f1428]/45 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(255,211,107,0.03),0_0_40px_rgba(255,211,107,0.14)] transition-all duration-500 hover:-translate-y-1 hover:border-[#FFD36B]/70 hover:bg-[#0f1428]/65 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.3),inset_0_-24px_60px_rgba(255,211,107,0.15),0_8px_30px_rgba(0,0,0,0.5),0_0_60px_rgba(255,211,107,0.5),0_0_120px_rgba(255,211,107,0.2)] hover:z-10 before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FFF4C0]/70 before:to-transparent before:transition-all before:duration-500 group-hover:before:opacity-100 group-hover:before:shadow-[0_0_15px_rgba(255,211,107,0.9)] group-hover:before:via-[#FFF4C0] after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-48 after:w-48 after:rounded-full after:bg-[#FFD36B]/10 after:blur-3xl after:transition-all after:duration-500 group-hover:after:opacity-100 group-hover:after:bg-[#FFD36B]/25 group-hover:after:blur-[36px] text-white';

function getTypeIcon(type: string) {
  const lower = type.toLowerCase();
  if (lower.includes('library')) return Package;
  if (lower.includes('protocol')) return Globe;
  if (lower.includes('certificate')) return FileCode;
  if (lower.includes('key')) return Key;
  if (lower.includes('hash')) return Lock;
  return Server;
}

function getTypeColor(type: string) {
  const lower = type.toLowerCase();
  if (lower.includes('library')) return 'text-cyan-400 border-cyan-500/30 bg-cyan-500/10';
  if (lower.includes('protocol')) return 'text-purple-400 border-purple-500/30 bg-purple-500/10';
  if (lower.includes('certificate')) return 'text-gold border-gold/30 bg-gold/10';
  if (lower.includes('key')) return 'text-orange-400 border-orange-500/30 bg-orange-500/10';
  if (lower.includes('hash')) return 'text-blue-400 border-blue-500/30 bg-blue-500/10';
  return 'text-white/60 border-white/15 bg-white/5';
}

function severityColor(severity: string) {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'text-red-400';
    case 'high': return 'text-orange-400';
    case 'moderate': return 'text-yellow-400';
    case 'safe': return 'text-green-400';
    default: return 'text-white/45';
  }
}

function formatDate(value: string) {
  if (!value) return 'N/A';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

export default function CbomExplorer() {
  const { data, loading, error, refresh } = useScannerIntelligence();
  const entries = (data.cbom.entries || []) as CbomEntry[];
  const stats = data.cbom.stats || { totalComponents: 0, quantumVulnerableComponents: 0, pqcReadyComponents: 0, totalInstances: 0 };
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [showVulnerableOnly, setShowVulnerableOnly] = useState(false);

  const availableTypes = useMemo(() => {
    const base = ['library', 'protocol', 'certificate', 'key-exchange', 'hash'];
    const discovered = Array.from(new Set(entries.map((entry) => entry.type).filter(Boolean)));
    return Array.from(new Set([...base, ...discovered]));
  }, [entries]);

  const filtered = entries.filter((entry) => {
    const query = searchQuery.toLowerCase().trim();
    if (query && ![entry.component, entry.algorithm, entry.sourceAsset, entry.evidence].some((value) => String(value || '').toLowerCase().includes(query))) return false;
    if (selectedType && entry.type !== selectedType) return false;
    if (showVulnerableOnly && !entry.isVulnerable) return false;
    return true;
  });

  return (
    <div className="p-6 lg:p-8 space-y-6 min-h-screen">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-3xl font-black uppercase tracking-tight text-white">
            CBOM <span className="text-gold">Explorer</span>
          </h1>
          <p className="text-white/50 mt-1 text-sm">Cryptography Bill of Materials - real authorized scan inventory with PQC readiness analysis.</p>
        </div>
        <button onClick={refresh} className="px-4 py-2 rounded-lg border border-gold/20 bg-gold/10 text-gold text-[10px] font-black uppercase tracking-wider flex items-center gap-2">
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </header>

      {error && (
        <div className="rounded-xl border border-red-500/25 bg-red-500/10 p-4 text-sm text-red-300">{error}</div>
      )}

      {/* Stats KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Total Components', value: stats.totalComponents, icon: Layers, color: 'text-white' },
          { label: 'Quantum Vulnerable', value: stats.quantumVulnerableComponents, icon: Unlock, color: 'text-red-400' },
          { label: 'PQC Ready', value: stats.pqcReadyComponents, icon: Shield, color: 'text-green-400' },
          { label: 'Total Instances', value: stats.totalInstances, icon: Server, color: 'text-gold' },
        ].map((stat, index) => (
          <motion.div key={stat.label} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: index * 0.06 }} className={GLASS_PANEL_CLASSES + " p-4"}>
            <div className="flex items-center gap-2 mb-2 relative z-10">
              <stat.icon className="h-3.5 w-3.5 text-gold/50" />
              <span className="text-[10px] font-black uppercase tracking-[0.15em] text-white/40">{stat.label}</span>
            </div>
            <div className={`text-2xl font-black relative z-10 ${stat.color}`}>{stat.value}</div>
          </motion.div>
        ))}
      </div>

      <div className="flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-white/30" />
          <input
            type="text"
            placeholder="Search components, algorithms, evidence..."
            value={searchQuery}
            onChange={(event) => setSearchQuery(event.target.value)}
            className="w-full border border-gold/20 bg-[#0f1428]/35 rounded-lg py-2.5 pl-10 pr-4 text-sm focus:outline-none text-white placeholder-white/25 focus:border-gold/50"
          />
        </div>

        <div className="flex gap-2 flex-wrap text-gold">
          {availableTypes.map((type) => (
            <button key={type} onClick={() => setSelectedType(selectedType === type ? null : type)} className={`text-[10px] font-black uppercase tracking-wider px-3 py-2 rounded-lg border transition-all ${selectedType === type ? 'border-gold/60 bg-gold/15 text-gold shadow-[0_0_15px_rgba(212,175,55,0.15)]' : 'border-white/10 text-white/40 hover:text-white/60 bg-[#0f1428]/35'}`}>
              {type}
            </button>
          ))}
        </div>

        <button onClick={() => setShowVulnerableOnly(!showVulnerableOnly)} className={`text-[10px] font-black uppercase tracking-wider px-3 py-2 rounded-lg border transition-all flex items-center gap-1.5 ${showVulnerableOnly ? 'border-red-500/50 bg-red-500/10 text-red-400 shadow-[0_0_15px_rgba(239,68,68,0.15)]' : 'border-white/10 text-white/40 hover:text-white/60 bg-[#0f1428]/35'}`}>
          <AlertTriangle className="h-3 w-3" /> Vulnerable Only
        </button>
      </div>

      {/* Main Table Grid Card */}
      <div className={GLASS_PANEL_CLASSES}>
        <div className="overflow-x-auto relative z-10">
          <table className="w-full text-left border-collapse min-w-[980px]">
            <thead>
              <tr className="border-b border-gold/15 bg-gold/[0.03]">
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-white/40 w-8" />
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-white/40">Component</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-white/40">Type</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-white/40">Algorithm</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-white/40">Key Size</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-white/40">Status</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-white/40">PQC Replacement</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-white/40">Instances</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gold/8">
              {loading ? (
                <tr>
                  <td colSpan={8} className="p-14 text-center text-gold/60 font-black uppercase tracking-widest">
                    <Loader2 className="h-5 w-5 animate-spin inline mr-2" /> Loading CBOM
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={8} className="p-14 text-center">
                    <div className="text-white/30 uppercase tracking-widest text-xs font-black mb-4">
                      {entries.length === 0 ? 'No CBOM records yet' : 'No CBOM records match your filters'}
                    </div>
                    {entries.length === 0 && (
                      <a href="/dashboard/scanner" className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-gold/30 bg-gold/10 text-gold text-[10px] font-black uppercase tracking-wider">
                        <ExternalLink className="h-3.5 w-3.5" /> Start Authorized Scan
                      </a>
                    )}
                  </td>
                </tr>
              ) : filtered.map((entry) => {
                const TypeIcon = getTypeIcon(entry.type);
                const isExpanded = expandedId === entry.id;
                return (
                  <Fragment key={entry.id}>
                    <tr onClick={() => setExpandedId(isExpanded ? null : entry.id)} className="hover:bg-white/[0.02] transition-colors cursor-pointer group">
                      <td className="p-4">
                        <ChevronRight className={`h-3.5 w-3.5 text-white/20 transition-transform ${isExpanded ? 'rotate-90 text-gold' : ''}`} />
                      </td>
                      <td className="p-4">
                        <div className="flex items-center gap-2">
                          <TypeIcon className="h-4 w-4 text-gold/40 text-[#FFD36B]" />
                          <span className="text-sm font-bold text-white/80 group-hover:text-white transition-colors">{entry.component}</span>
                        </div>
                      </td>
                      <td className="p-4">
                        <span className={`text-[9px] font-black uppercase tracking-wider px-2 py-0.5 rounded border ${getTypeColor(entry.type)}`}>{entry.type}</span>
                      </td>
                      <td className="p-4 font-mono text-xs text-white/60">{entry.algorithm}</td>
                      <td className="p-4 font-mono text-xs text-white/40">{entry.keySize || 'N/A'}</td>
                      <td className="p-4">
                        {entry.isVulnerable ? (
                          <span className="text-[9px] font-black uppercase tracking-wider text-red-400 flex items-center gap-1"><Unlock className="h-3 w-3" /> {entry.status}</span>
                        ) : (
                          <span className="text-[9px] font-black uppercase tracking-wider text-green-400 flex items-center gap-1"><Shield className="h-3 w-3" /> {entry.status}</span>
                        )}
                      </td>
                      <td className="p-4 text-xs font-bold text-gold">{entry.pqcReplacement || 'N/A'}</td>
                      <td className="p-4 text-xs font-mono text-white/50">{entry.instances}</td>
                    </tr>
                    <AnimatePresence>
                      {isExpanded && (
                        <motion.tr key={`${entry.id}-expanded`} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                          <td colSpan={8} className="p-0">
                            <div className="px-8 py-5 bg-gold/[0.02] border-l-2 border-gold/30 space-y-3">
                              <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
                                <div>
                                  <div className="text-[9px] font-black uppercase tracking-wider text-white/30 mb-1">Source Asset</div>
                                  <div className="text-xs font-mono text-white/60 truncate">{entry.sourceAsset}</div>
                                </div>
                                <div>
                                  <div className="text-[9px] font-black uppercase tracking-wider text-white/30 mb-1">Detection Method</div>
                                  <div className="text-xs text-white/60 font-mono">{entry.detectionMethod}</div>
                                </div>
                                <div>
                                  <div className="text-[9px] font-black uppercase tracking-wider text-white/30 mb-1">Last Scanned</div>
                                  <div className="text-xs text-white/50 font-mono">{formatDate(entry.lastScannedDate)}</div>
                                </div>
                                <div>
                                  <div className="text-[9px] font-black uppercase tracking-wider text-white/30 mb-1">Risk Severity</div>
                                  <div className={`text-xs font-black uppercase ${severityColor(entry.riskSeverity)}`}>{entry.riskSeverity}</div>
                                </div>
                                <div>
                                  <div className="text-[9px] font-black uppercase tracking-wider text-white/30 mb-1">Evidence</div>
                                  <div className="flex items-center gap-1 text-xs font-mono text-white/60">
                                    <span className="truncate">{entry.evidence}</span>
                                    <Copy className="h-3 w-3 text-gold/30 shrink-0" />
                                  </div>
                                </div>
                              </div>
                              {entry.recommendation && (
                                <div className="rounded-lg border border-green-500/15 bg-green-500/[0.03] p-3 text-xs text-green-400/80">
                                  {entry.recommendation}
                                </div>
                              )}
                            </div>
                          </td>
                        </motion.tr>
                      )}
                    </AnimatePresence>
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
        <div className="p-4 border-t border-gold/10 flex items-center justify-between relative z-10">
          <span className="text-[10px] text-white/30 font-bold">Showing {filtered.length} of {entries.length} components</span>
          <button onClick={() => navigator.clipboard?.writeText(JSON.stringify(entries, null, 2))} className="text-[10px] font-black uppercase tracking-wider text-gold hover:text-gold/80 flex items-center gap-1">
            <ExternalLink className="h-3 w-3" /> Copy CBOM JSON
          </button>
        </div>
      </div>
    </div>
  );
}
