import { useState } from 'react';
import { Outlet, Link, Navigate, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  LayoutDashboard, Map as MapIcon, ShieldAlert, LogOut,
  Route, Layers, Globe, Clock, ClipboardCheck,
  Rocket, GitCompare, ChevronLeft,
  ChevronRight, Menu, X, ScanSearch, ChevronDown,
  Cpu, Lock, Fingerprint, Award, Coins, MessageSquareLock, Cloud, Sparkles, Database, UserCog,
  Activity, EyeOff, Zap, Network, Box, Microscope, LineChart, Target, Shield, CheckCircle, UserCheck, MonitorCheck, PieChart, ShieldCheck, Scale, FileText, Key, Webhook, FileWarning, Ghost, Workflow, Crown
} from 'lucide-react';
import { supabase } from '@/lib/supabase';
import { useAuth } from '@/contexts/auth-context';
import { isOwnerEmail } from '@/lib/admin-access';
import ThemeToggle from '@/components/theme/ThemeToggle';

const NAV_SECTIONS = [
  {
    label: 'Core Modules',
    collapsible: true,
    items: [
      { name: 'Overview', path: '/dashboard', icon: LayoutDashboard },
      { name: 'Migration Planner', path: '/dashboard/migration-planner', icon: Route },
      { name: 'PQC Onboarding & Migration Process', path: '/dashboard/pqc-onboarding', icon: ClipboardCheck },
    ],
  },
  {
    label: 'Quantum Tools',
    collapsible: true,
    items: [
      { name: 'Quantum QRNG', path: '/dashboard/qrng', icon: Cpu },
      { name: 'Encryption Services', path: '/dashboard/keys', icon: Lock },
      { name: 'Security Authentication', path: '/dashboard/otp', icon: Fingerprint },
      { name: 'Digital Certificates', path: '/dashboard/pki', icon: Award },
      { name: 'Tokenization', path: '/dashboard/tokenize', icon: Coins },
      { name: 'Secure Communications', path: '/dashboard/comm', icon: MessageSquareLock },
      { name: 'Cloud Security', path: '/dashboard/cloud', icon: Cloud },
      { name: 'Quantum Vault', path: '/dashboard/vault', icon: Database },
    ],
  },
  {
    label: 'Discovery',
    collapsible: true,
    items: [
      { name: 'PQC Scanner', path: '/dashboard/scanner', icon: ScanSearch },
      { name: 'CBOM Explorer', path: '/dashboard/cbom', icon: Layers },
      { name: 'Crypto Exposure', path: '/dashboard/crypto-exposure', icon: Globe },
      { name: 'Assets & CBOM', path: '/dashboard/assets', icon: MapIcon },
      { name: 'Shadow Crypto', path: '/dashboard/shadow-crypto', icon: Ghost },
      { name: 'Harvest Now, Decrypt Later', path: '/dashboard/harvest-now', icon: EyeOff },
    ],
  },
  {
    label: 'Operations',
    collapsible: true,
    items: [
      { name: 'Migration Timeline', path: '/dashboard/migration-timeline', icon: Clock },
      { name: 'Migration Phases', path: '/dashboard/migration-phases', icon: Layers },
      { name: 'Live Migration Ops', path: '/dashboard/live-migration', icon: Rocket },
      { name: 'Crypto-Agility Engine', path: '/dashboard/crypto-agility', icon: Zap },
      { name: 'PQC Orchestration', path: '/dashboard/pqc-orchestration', icon: Network },
      { name: 'Migration Sandbox', path: '/dashboard/migration-sandbox', icon: Box },
    ],
  },
  {
    label: 'Ecosystem & Supply-Chain',
    collapsible: true,
    items: [
      { name: 'Trust-State Discovery', path: '/dashboard/trust-state-discovery', icon: Workflow },
      { name: 'Ecosystem Dependency Map', path: '/dashboard/ecosystem-dependency-map', icon: Globe },
      { name: 'Vendor PQC Readiness Center', path: '/dashboard/vendor-pqc-readiness', icon: ClipboardCheck },
      { name: 'Trust Chain Analyzer', path: '/dashboard/trust-chain-analyzer', icon: Network },
      { name: 'Hybrid Crypto Compatibility Lab', path: '/dashboard/hybrid-crypto-lab', icon: Box },
    ],
  },
  {
    label: 'Intelligence',
    collapsible: true,
    items: [
      { name: 'Drift Detection', path: '/dashboard/drift', icon: GitCompare },
      { name: 'Vulnerabilities', path: '/dashboard/vulnerabilities', icon: ShieldAlert },
      { name: 'Runtime Cryptographic Intelligence', path: '/dashboard/runtime-crypto-intel', icon: Microscope },
      { name: 'Behavioral Analytics', path: '/dashboard/behavioral-analytics', icon: Activity },
      { name: 'Telemetry Correlation', path: '/dashboard/telemetry-correlation', icon: LineChart },
      { name: 'Quantum Risk Scoring', path: '/dashboard/quantum-risk-scoring', icon: Target },
    ],
  },
  {
    label: 'PQC-Auth Identity Migration Engine',
    collapsible: true,
    items: [
      { name: 'PQAuth Command Center', path: '/dashboard/pqauth', icon: Fingerprint },
      { name: 'Identity Discovery', path: '/dashboard/pqauth/discovery', icon: ScanSearch },
      { name: 'Identity Trust Graph', path: '/dashboard/pqauth/trust-graph', icon: Network },
      { name: 'JWT & Token Intelligence', path: '/dashboard/pqauth/token-intelligence', icon: Key },
      { name: 'Quantum Exposure Analysis', path: '/dashboard/pqauth/exposure-analysis', icon: ShieldAlert },
      { name: 'PQC Compatibility', path: '/dashboard/pqauth/compatibility', icon: CheckCircle },
      { name: 'Identity Digital Twin', path: '/dashboard/pqauth/digital-twin', icon: GitCompare },
      { name: 'Migration Center', path: '/dashboard/pqauth/migration-center', icon: Workflow },
      { name: 'Runtime Identity Telemetry', path: '/dashboard/pqauth/runtime-telemetry', icon: Activity },
      { name: 'Governance & Compliance', path: '/dashboard/pqauth/compliance', icon: Scale },
      { name: 'QKMS Integration', path: '/dashboard/pqauth/qkms', icon: Database },
    ],
  },
  {
    label: 'Observability',
    collapsible: true,
    items: [
      { name: 'TLS Telemetry', path: '/dashboard/tls-telemetry', icon: Shield },
      { name: 'TLS Orchestrator', path: '/dashboard/tls-orchestrator', icon: Network },
      { name: 'PKI Visibility', path: '/dashboard/pki-visibility', icon: Award },
      { name: 'Protocol Analytics', path: '/dashboard/protocol-analytics', icon: Activity },
      { name: 'Encryption Monitoring', path: '/dashboard/encryption-monitoring', icon: Lock },
    ],
  },
  {
    label: 'Qguard Helix QKMS',
    collapsible: true,
    items: [
      { name: 'QKMS Overview', path: '/dashboard/qkms/overview', icon: Key },
      { name: 'QKMS Key Inventory', path: '/dashboard/qkms/inventory', icon: Database },
      { name: 'QKMS Governance', path: '/dashboard/qkms/governance', icon: Scale },
      { name: 'QKMS PQC Readiness', path: '/dashboard/qkms/readiness', icon: ShieldCheck },
    ],
  },
  {
    label: 'Trust Center',
    collapsible: true,
    items: [
      { name: 'Continuous Trust Validation', path: '/dashboard/continuous-trust', icon: CheckCircle },
      { name: 'Identity Trust', path: '/dashboard/identity-trust', icon: UserCheck },
      { name: 'Device Trust', path: '/dashboard/device-trust', icon: MonitorCheck },
      { name: 'Trust Analytics', path: '/dashboard/trust-analytics', icon: PieChart },
      { name: 'Zero Trust Validation', path: '/dashboard/zero-trust', icon: ShieldCheck },
    ],
  },
  {
    label: 'Governance',
    collapsible: true,
    items: [
      { name: 'Compliance', path: '/dashboard/compliance', icon: ClipboardCheck },
      { name: 'Quantum Governance', path: '/dashboard/quantum-governance', icon: Scale },
      { name: 'Crypto Policies', path: '/dashboard/crypto-policies', icon: FileText },
      { name: 'Audit Vault', path: '/dashboard/audit-vault', icon: Database },
      { name: 'Regulatory Mapping', path: '/dashboard/regulatory-mapping', icon: MapIcon },
    ],
  },
  {
    label: 'Telemetry',
    collapsible: true,
    items: [
      { name: 'Runtime Telemetry', path: '/dashboard/runtime-telemetry', icon: Activity },
      { name: 'Certificate Telemetry', path: '/dashboard/certificate-telemetry', icon: FileWarning },
      { name: 'Key Analytics', path: '/dashboard/key-analytics', icon: Key },
      { name: 'API Encryption Monitoring', path: '/dashboard/api-encryption', icon: Webhook },
      { name: 'Multi-Cloud Telemetry', path: '/dashboard/multi-cloud-telemetry', icon: Cloud },
    ],
  },
  {
    label: 'System',
    collapsible: true,
    items: [
      { name: 'Profile & Settings', path: '/dashboard/settings', icon: UserCog },
    ],
  },
];

export default function DashboardLayout() {
  const location = useLocation();
  const { user, loading } = useAuth();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({
    'Core Modules': true,
    'Quantum Tools': false,
    'Discovery': false,
    'Operations': false,
    'Ecosystem & Supply-Chain': false,
    'Intelligence': false,
    'PQC-Auth Identity Migration Engine': false,
    'Observability': false,
    'Qguard Helix QKMS': false,
    'Trust Center': false,
    'Governance': false,
    'Telemetry': false,
    'System': false
  });

  const toggleSection = (label: string) => {
    setOpenSections(prev => ({
      ...prev,
      [label]: !prev[label]
    }));
  };

  const sidebarWidth = collapsed ? 'w-[72px]' : 'w-[260px]';
  const isOwner = isOwnerEmail(user?.email);
  const navSections = isOwner
    ? NAV_SECTIONS.map(section => section.label === 'System'
      ? { ...section, items: [{ name: 'Owner Administrator', path: '/dashboard/admin', icon: Crown }, ...section.items] }
      : section)
    : NAV_SECTIONS;

  if (loading) {
    return (
      <div className="qg-dashboard-shell grid min-h-screen place-items-center bg-[var(--qg-dashboard-bg)] text-[var(--qg-accent-cyan)]">
        <div className="rounded-lg border border-blue-400/20 bg-blue-500/[0.06] px-5 py-3 text-xs font-black uppercase tracking-[0.18em] shadow-[0_18px_60px_rgba(0,0,0,0.32)]">
          Securing session
        </div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }

  return (
    <div className="qg-dashboard-shell flex h-screen bg-[var(--qg-dashboard-bg)] text-[var(--qg-dashboard-text)] font-sans overflow-hidden">
      {/* Mobile overlay */}
      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setMobileOpen(false)}
            className="fixed inset-0 z-40 lg:hidden glass-panel"
          />
        )}
      </AnimatePresence>

      {/* Sidebar */}
      <aside className={`
        qg-dashboard-sidebar ${sidebarWidth} flex flex-col border-r border-slate-700/40 bg-slate-950/90 backdrop-blur-2xl transition-all duration-300 z-50
        fixed lg:relative inset-y-0 left-0
        ${mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
      `}>
        {/* Brand */}
        <div className={`flex items-center border-b border-slate-700/45 ${collapsed ? 'justify-center p-4' : 'p-5'}`}>
          <Link to="/" className="flex items-center gap-2.5 no-underline group">
            <div className="h-9 w-9 rounded-lg border border-blue-400/30 bg-blue-500/10 flex items-center justify-center shrink-0 shadow-[0_0_22px_rgba(37,99,235,0.18)] group-hover:shadow-[0_0_28px_rgba(6,182,212,0.24)] transition-all">
              <ShieldAlert className="h-5 w-5 text-cyan-300" />
            </div>
            {!collapsed && (
              <div className="min-w-0">
                <span className="block text-sm font-black uppercase tracking-[0.06em] text-slate-50">
                  Qguard Helix
                </span>
                <span className="block text-[9px] font-bold uppercase tracking-[0.2em] text-cyan-300/60">
                  Quantum Defense
                </span>
              </div>
            )}
          </Link>
        </div>
        
        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto py-4 px-2.5 space-y-5 scrollbar-thin">
          {navSections.map(section => {
            const isCollapsible = section.collapsible;
            const isOpen = !isCollapsible || openSections[section.label];

            return (
              <div key={section.label} className="space-y-1">
                {!collapsed && (
                  <div 
                    className={`px-3 mb-1.5 text-[9px] font-black uppercase tracking-[0.22em] flex items-center justify-between transition-colors group/header ${isCollapsible ? 'cursor-pointer hover:text-cyan-300 text-slate-500' : 'text-slate-600'}`}
                    onClick={() => isCollapsible && toggleSection(section.label)}
                  >
                    <div className="flex items-center gap-2">
                      {section.label === 'Quantum Tools' && <Sparkles className="h-2.5 w-2.5 text-cyan-300/50 group-hover/header:text-cyan-300 transition-colors" />}
                      <span>{section.label}</span>
                    </div>
                    {isCollapsible && (
                      <ChevronDown className={`h-3 w-3 transition-transform duration-300 ${isOpen ? 'rotate-180' : ''}`} />
                    )}
                  </div>
                )}
                {collapsed && <div className="h-px bg-slate-700/45 mx-2 mb-2" />}
                
                <AnimatePresence initial={false}>
                  {isOpen && (
                    <motion.div 
                      initial={isCollapsible ? { height: 0, opacity: 0 } : false}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.3, ease: 'easeInOut' }}
                      className="space-y-0.5 overflow-hidden"
                    >
                      {section.items.map(item => {
                        const isActive = location.pathname === item.path;
                        const Icon = item.icon;

                        return (
                          <Link
                            key={item.path}
                            to={item.path}
                            onClick={() => setMobileOpen(false)}
                            title={collapsed ? item.name : undefined}
                            className={`relative flex items-center gap-2.5 rounded-lg transition-all duration-200 no-underline ${
                              collapsed ? 'justify-center px-2 py-2.5' : 'px-3 py-2.5'
                            } ${
                              isActive 
                                ? 'bg-gradient-to-r from-blue-600/20 to-violet-600/14 text-cyan-100 border border-blue-400/30 shadow-[0_12px_30px_rgba(37,99,235,0.12)]' 
                                : 'text-slate-400 hover:bg-white/[0.045] hover:text-slate-100 border border-transparent'
                            }`}
                          >
                            {isActive && (
                              <motion.div 
                                layoutId="sidebarActive"
                                className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-5 bg-gradient-to-b from-blue-400 to-cyan-300 rounded-r-full shadow-[0_0_14px_rgba(6,182,212,0.5)]"
                                transition={{ type: 'spring', stiffness: 500, damping: 35 }}
                              />
                            )}
                            <Icon className={`shrink-0 ${collapsed ? 'h-5 w-5' : 'h-4 w-4'}`} />
                            {!collapsed && (
                              <span className="min-w-0 break-words text-[11px] font-bold leading-snug tracking-wide">{item.name}</span>
                            )}
                          </Link>
                        );
                      })}
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            );
          })}
        </nav>

        {/* Bottom controls */}
        <div className="border-t border-slate-700/45 p-2.5 space-y-1.5">
          <ThemeToggle compact={collapsed} showSystem={!collapsed} className="w-full justify-center" />

          {/* Collapse toggle (desktop) */}
          <button
            onClick={() => setCollapsed(c => !c)}
            className="hidden lg:flex w-full items-center justify-center gap-2 px-3 py-2 rounded-lg text-white/25 hover:text-white/50 hover:bg-white/[0.03] transition-all"
          >
            {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
            {!collapsed && <span className="text-[10px] font-bold tracking-wide">Collapse</span>}
          </button>

          <button 
            onClick={async () => {
              await supabase.auth.signOut();
              window.location.href = '/';
            }}
            className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2.5 text-white/30 hover:text-red-400 hover:bg-red-500/[0.06] transition-all ${
              collapsed ? 'justify-center' : ''
            }`}
          >
            <LogOut className={`shrink-0 ${collapsed ? 'h-5 w-5' : 'h-4 w-4'}`} />
            {!collapsed && <span className="text-[11px] font-bold tracking-wide">Exit System</span>}
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="qg-dashboard-main flex-1 overflow-y-auto relative" style={{ background: 'var(--qg-dashboard-bg)' }}>
        {/* Atmospheric Background Layers */}
        <div className="qg-dashboard-bg-layers pointer-events-none absolute inset-0 overflow-hidden" aria-hidden="true">
          {/* Deep navy base */}
          <div className="absolute inset-0 bg-[var(--qg-dashboard-bg)]" />
          {/* Blue-violet command-center depth */}
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_82%_0%,rgba(37,99,235,0.16),transparent_42%),radial-gradient(ellipse_at_24%_8%,rgba(6,182,212,0.09),transparent_38%),linear-gradient(135deg,transparent,rgba(124,58,237,0.055)_58%,transparent)]" />
          {/* Subtle enterprise grid */}
          <div className="absolute inset-0 bg-[linear-gradient(rgba(148,163,184,0.045)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.035)_1px,transparent_1px)] bg-[size:52px_52px] opacity-60" />
        </div>

        {/* Mobile header */}
        <div className="qg-dashboard-mobile-header lg:hidden sticky top-0 z-30 flex items-center gap-3 border-b border-slate-700/40 bg-slate-950/90 backdrop-blur-xl px-4 py-3">
          <button
            onClick={() => setMobileOpen(true)}
            className="p-2 rounded-lg border border-blue-400/25 bg-blue-500/10 text-cyan-300"
          >
            <Menu className="h-4 w-4" />
          </button>
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-cyan-300" />
            <span className="text-sm font-black uppercase tracking-wider text-slate-50">Qguard Helix</span>
          </div>
          <ThemeToggle compact showSystem={false} className="ml-auto" />
        </div>

        <div className="dashboard-theme-scope relative z-10 min-h-full">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
