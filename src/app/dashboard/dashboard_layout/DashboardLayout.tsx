import { useEffect, useState } from 'react';
import { Outlet, Link, Navigate, useLocation, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  LayoutDashboard, Map as MapIcon, ShieldAlert, LogOut,
  Route, Layers, Globe, Clock, ClipboardCheck,
  Rocket, GitCompare, ChevronLeft,
  ChevronRight, Menu, X, ScanSearch, ChevronDown,
  Cpu, Lock, Fingerprint, Award, Coins, MessageSquareLock, Cloud, Sparkles, Database, UserCog,
  Activity, EyeOff, Zap, Network, Box, Microscope, LineChart, Target, Shield, CheckCircle, PieChart, ShieldCheck, Scale, FileText, Key, FileWarning, Ghost, Workflow, Crown,
  BadgeDollarSign, BarChart3, CreditCard, TrendingUp, Users, Wrench, Server
} from 'lucide-react';
import { supabase } from '@/lib/supabase';
import { useAuth } from '@/contexts/auth-context';
import { useUserPreferences } from '@/contexts/user-preferences-context';
import { dashboardViewPath } from '@/lib/preferences';
import { isOwnerEmail } from '@/lib/admin-access';
import ThemeToggle from '@/components/theme/ThemeToggle';
import { useSubscription } from '@/hooks/use-subscription';
import { canAccessPath, resolveRequiredTier, type AccessTier } from '@/lib/subscription-access';
import { StarterDashboard } from '@/app/dashboard/_components/StarterDashboard';
import { UpgradeRequired } from '@/components/subscription/UpgradeRequired';
import { SophiaCopilot } from '@/components/copilot/SophiaCopilot';

const NAV_SECTIONS = [
  {
    label: 'Core Modules',
    collapsible: true,
    items: [
      { name: 'Overview', path: '/dashboard', icon: LayoutDashboard },
      { name: 'Sophia AI Security Copilot™', path: '/dashboard/sophia', icon: Sparkles },
      { name: 'Quantum Readiness Assessment Engine™', path: '/dashboard/quantum-readiness', icon: Sparkles },
      { name: 'Migration Intelligence™', path: '/dashboard/migration-intelligence', icon: Scale },
      { name: 'Migration Planner', path: '/dashboard/migration-planner', icon: Route },
      { name: 'Migration Sandbox', path: '/dashboard/migration-sandbox', icon: Box },
      { name: 'Live Migration Ops', path: '/dashboard/live-migration', icon: Rocket },
    ],
  },
  {
    label: 'Discovery',
    collapsible: true,
    items: [
      { name: 'PQC Scanner', path: '/dashboard/scanner', icon: ScanSearch },
      // Nested under PQC Scanner: agents are the scanner's on-host collection arm.
      { name: 'Agents Collector', path: '/dashboard/agents', icon: Server, child: true },
      { name: 'Assets & CBOM', path: '/dashboard/assets', icon: MapIcon },
      { name: 'CBOM Explorer', path: '/dashboard/cbom', icon: Layers },
      { name: 'Shadow Crypto', path: '/dashboard/shadow-crypto', icon: Ghost },
    ],
  },
  {
    label: 'Quantum Readiness Assessment Engine™',
    collapsible: true,
    items: [
      { name: 'Assessment Overview', path: '/dashboard/quantum-readiness', icon: LayoutDashboard },
      { name: 'Quantum Exposure Graph™', path: '/dashboard/quantum-readiness/exposure-graph', icon: Network },
      { name: 'Quantum Risk Analysis', path: '/dashboard/quantum-readiness/risk-analysis', icon: Target },
      { name: 'Quantum Remediation Engine™', path: '/dashboard/quantum-readiness/remediation', icon: Wrench },
      { name: 'AI Executive Advisor™', path: '/dashboard/quantum-readiness/ai-executive-advisor', icon: Sparkles },
      { name: 'AI Migration Advisor™', path: '/dashboard/quantum-readiness/ai-migration-advisor', icon: Route },
      { name: 'Harvest Now (HNDL)', path: '/dashboard/harvest-now', icon: EyeOff },
      { name: 'Quantum Trust Certification™', path: '/dashboard/quantum-certification', icon: Award },
      { name: 'Report Center', path: '/dashboard/quantum-readiness/reports', icon: FileText },
    ],
  },
  {
    label: 'Operations',
    collapsible: true,
    items: [
      { name: 'Migration Timeline', path: '/dashboard/migration-timeline', icon: Clock },
      { name: 'PQC Orchestration', path: '/dashboard/pqc-orchestration', icon: Network },
      { name: 'Crypto Agility Engine', path: '/dashboard/crypto-agility', icon: Zap },
    ],
  },
  {
    label: 'Ecosystem & Supply Chain',
    collapsible: true,
    items: [
      { name: 'Vendor PQC Readiness Center', path: '/dashboard/vendor-pqc-readiness', icon: ClipboardCheck },
      { name: 'Ecosystem Dependency Map', path: '/dashboard/ecosystem-dependency-map', icon: Globe },
      { name: 'Trust Chain Analyzer', path: '/dashboard/trust-chain-analyzer', icon: Network },
      { name: 'Hybrid Crypto Compatibility Lab', path: '/dashboard/hybrid-crypto-lab', icon: Box },
    ],
  },
  {
    label: 'Intelligence',
    collapsible: true,
    items: [
      { name: 'Runtime Cryptographic Intelligence', path: '/dashboard/runtime-crypto-intel', icon: Microscope },
      { name: 'Telemetry Correlation', path: '/dashboard/telemetry-correlation', icon: LineChart },
      { name: 'Drift Detection', path: '/dashboard/drift', icon: GitCompare },
      { name: 'Quantum Risk Scoring', path: '/dashboard/quantum-risk-scoring', icon: Target },
    ],
  },
  {
    label: 'PQAuth™',
    collapsible: true,
    items: [
      { name: 'PQAuth Command Center', path: '/dashboard/pqauth', icon: Fingerprint },
      { name: 'Identity Discovery', path: '/dashboard/pqauth/discovery', icon: ScanSearch },
      { name: 'Identity Trust Graph', path: '/dashboard/pqauth/trust-graph', icon: Network },
      { name: 'JWT & Token Intelligence', path: '/dashboard/pqauth/token-intelligence', icon: Key },
      { name: 'PQC Compatibility', path: '/dashboard/pqauth/compatibility', icon: CheckCircle },
      { name: 'Migration Center', path: '/dashboard/pqauth/migration-center', icon: Workflow },
      { name: 'Identity Digital Twin', path: '/dashboard/pqauth/digital-twin', icon: GitCompare },
      { name: 'Runtime Identity Telemetry', path: '/dashboard/pqauth/runtime-telemetry', icon: Activity },
    ],
  },
  {
    label: 'Observability',
    collapsible: true,
    items: [
      { name: 'TLS Telemetry', path: '/dashboard/tls-telemetry', icon: Shield },
      { name: 'PKI Visibility', path: '/dashboard/pki-visibility', icon: Award },
      { name: 'Protocol Analytics', path: '/dashboard/protocol-analytics', icon: Activity },
      { name: 'Encryption Monitoring', path: '/dashboard/encryption-monitoring', icon: Lock },
      { name: 'TLS Orchestrator', path: '/dashboard/tls-orchestrator', icon: Network },
    ],
  },
  {
    label: 'QKMS™',
    collapsible: true,
    items: [
      { name: 'Overview', path: '/dashboard/qkms/overview', icon: Key },
      { name: 'Key Inventory', path: '/dashboard/qkms/inventory', icon: Database },
      { name: 'Key Lifecycle', path: '/dashboard/qkms/lifecycle', icon: Workflow },
      { name: 'Key Governance', path: '/dashboard/qkms/governance', icon: Scale },
      { name: 'Key Rotation Center', path: '/dashboard/qkms/rotation', icon: Zap },
      { name: 'PQC Readiness', path: '/dashboard/qkms/readiness', icon: ShieldCheck },
      { name: 'Key Risk Analysis', path: '/dashboard/qkms/risk-analysis', icon: Target },
    ],
  },
  {
    label: 'Trust Center',
    collapsible: true,
    items: [
      { name: 'Trust Dashboard', path: '/dashboard/trust-dashboard', icon: PieChart },
      { name: 'Trust-State Discovery', path: '/dashboard/trust-state-discovery', icon: Workflow },
    ],
  },
  {
    label: 'Governance',
    collapsible: true,
    items: [
      { name: 'Compliance Center', path: '/dashboard/compliance', icon: ClipboardCheck },
      { name: 'Quantum Governance', path: '/dashboard/quantum-governance', icon: Scale },
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
      { name: 'Multi-Cloud Telemetry', path: '/dashboard/multi-cloud-telemetry', icon: Cloud },
    ],
  },
  {
    label: 'Quantum Tools',
    collapsible: true,
    items: [
      { name: 'Quantum Vault', path: '/dashboard/vault', icon: Database },
      { name: 'Quantum QRNG', path: '/dashboard/qrng', icon: Cpu },
      { name: 'Encryption Services', path: '/dashboard/keys', icon: Lock },
      { name: 'Security Authentication', path: '/dashboard/otp', icon: Fingerprint },
      { name: 'Digital Certificates', path: '/dashboard/pki', icon: Award },
      { name: 'Tokenization', path: '/dashboard/tokenize', icon: Coins },
      { name: 'Secure Communication', path: '/dashboard/comm', icon: MessageSquareLock },
      { name: 'Cloud Security', path: '/dashboard/cloud', icon: Cloud },
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

// Owner-only executive financial analytics — rendered directly below the
// System section (Owner Administrator). Never shown to non-owner accounts;
// the /api/v1/revenue backend enforces the same owner-email gate.
const REVENUE_INTELLIGENCE_SECTION = {
  label: 'Revenue Intelligence',
  collapsible: true,
  items: [
    { name: 'Executive Overview', path: '/dashboard/revenue-intelligence', icon: BadgeDollarSign },
    { name: 'Revenue Analytics', path: '/dashboard/revenue-intelligence/revenue', icon: BarChart3 },
    { name: 'Subscription Analytics', path: '/dashboard/revenue-intelligence/subscriptions', icon: CreditCard },
    { name: 'Customer Analytics', path: '/dashboard/revenue-intelligence/customers', icon: Users },
    { name: 'Payment Analytics', path: '/dashboard/revenue-intelligence/payments', icon: Coins },
    { name: 'Forecast & Reports', path: '/dashboard/revenue-intelligence/forecast', icon: TrendingUp },
  ],
};

function DashboardShell() {
  return (
    <div className="qg-dashboard-shell grid min-h-screen place-items-center bg-[var(--qg-dashboard-bg)] text-[var(--qg-accent-cyan)]">
      <div className="rounded-lg border border-blue-400/20 bg-blue-500/[0.06] px-5 py-3 text-xs font-black uppercase tracking-[0.18em] shadow-[0_18px_60px_rgba(0,0,0,0.32)]">
        Securing session
      </div>
    </div>
  );
}

// Minimal header for the no-subscription screen (no sidebar / modules exposed).
function NoAccessHeader() {
  return (
    <header className="flex items-center justify-between border-b border-slate-700/40 bg-slate-950/85 px-5 py-3.5 backdrop-blur-xl">
      <Link to="/" className="flex items-center gap-2.5 no-underline">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-blue-400/30 bg-blue-500/10">
          <ShieldAlert className="h-5 w-5 text-cyan-300" />
        </div>
        <span className="text-sm font-black uppercase tracking-[0.06em] text-slate-50">Qguard Helix</span>
      </Link>
      <button
        onClick={async () => { await supabase.auth.signOut(); window.location.href = '/'; }}
        className="flex items-center gap-2 rounded-lg px-3 py-2 text-[11px] font-bold text-white/40 transition-colors hover:bg-red-500/10 hover:text-red-400"
      >
        <LogOut className="h-4 w-4" /> Sign out
      </button>
    </header>
  );
}

const defaultViewApplied = new Set<string>();

/**
 * Sends the user to their chosen landing page — once per browser session, and
 * only when they arrived on the bare /dashboard. Later clicks on "Overview" in
 * the sidebar must stay on Overview, so the decision is remembered per tab.
 */
function DefaultViewRedirect({ userId, tier }: { userId: string; tier: AccessTier }) {
  const { preferences } = useUserPreferences();
  const location = useLocation();
  const navigate = useNavigate();
  const ready = preferences !== null;

  useEffect(() => {
    if (!ready || !preferences) return;
    const key = `qguard-default-view-applied:${userId}`;
    let alreadyApplied = defaultViewApplied.has(key);
    try {
      alreadyApplied = alreadyApplied || window.sessionStorage.getItem(key) === '1';
      window.sessionStorage.setItem(key, '1');
    } catch { /* storage blocked: the in-memory flag still holds for this load */ }
    defaultViewApplied.add(key);
    if (alreadyApplied) return;

    if (location.pathname.replace(/\/+$/, '') !== '/dashboard') return;
    const target = dashboardViewPath(preferences.defaultDashboardView);
    if (target === '/dashboard' || !canAccessPath(tier, target)) return;
    navigate(target, { replace: true });
    // Evaluated once, when the preferences first arrive.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready]);

  return null;
}

export default function DashboardLayout() {
  const location = useLocation();
  const { user, loading } = useAuth();
  const subscription = useSubscription();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({
    'Core Modules': true,
    'Discovery': false,
    'Quantum Readiness Assessment Engine™': false,
    'Operations': false,
    'Ecosystem & Supply Chain': false,
    'Intelligence': false,
    'PQAuth™': false,
    'Observability': false,
    'QKMS™': false,
    'Trust Center': false,
    'Governance': false,
    'Telemetry': false,
    'Quantum Tools': false,
    'System': false,
    'Revenue Intelligence': false,
  });

  // Open the section holding the current page, so its active entry is visible
  // on arrival (e.g. Discovery › Agents Collector). Never collapses anything.
  useEffect(() => {
    const owner = NAV_SECTIONS.find((section) => section.items.some((item) => item.path === location.pathname));
    if (owner) setOpenSections((prev) => (prev[owner.label] ? prev : { ...prev, [owner.label]: true }));
  }, [location.pathname]);

  const toggleSection = (label: string) => {
    setOpenSections(prev => ({
      ...prev,
      [label]: !prev[label]
    }));
  };

  const sidebarWidth = collapsed ? 'w-[72px]' : 'w-[260px]';
  const isOwner = isOwnerEmail(user?.email);
  // Owner/admin bypasses subscription gating (treated as full Elite access);
  // everyone else is gated by their active subscription tier.
  const effectiveTier: AccessTier = isOwner ? 'elite' : subscription.isActive ? subscription.tier : 'none';

  // Only show nav items the tier can actually open; drop sections left empty.
  const tierNavSections = NAV_SECTIONS
    .map(section => ({ ...section, items: section.items.filter(item => canAccessPath(effectiveTier, item.path)) }))
    .filter(section => section.items.length > 0);
  // Owner-only injections: Owner Administrator inside System, and the Revenue
  // Intelligence section immediately below it.
  const navSections = isOwner
    ? tierNavSections.flatMap(section => section.label === 'System'
      ? [
        { ...section, items: [{ name: 'Owner Administrator', path: '/dashboard/admin', icon: Crown }, ...section.items] },
        REVENUE_INTELLIGENCE_SECTION,
      ]
      : [section])
    : tierNavSections;

  if (loading || (user && subscription.loading)) {
    return <DashboardShell />;
  }

  if (!user) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }

  // The plan could not be READ (after retries). That is not "no subscription":
  // say so and offer a retry rather than an upgrade prompt.
  if (!isOwner && !subscription.isActive && subscription.error) {
    return (
      <div className="qg-dashboard-shell min-h-screen bg-[var(--qg-dashboard-bg)] text-slate-100">
        <NoAccessHeader />
        <div role="alert" className="mx-auto mt-16 max-w-lg rounded-xl border border-amber-400/30 bg-amber-500/10 p-6 text-center">
          <h1 className="text-[18px] font-black text-white">We couldn't verify your plan</h1>
          <p className="mt-2 text-[12px] leading-relaxed text-white/60">
            Your subscription could not be read just now, so access is paused rather than guessed. This is usually temporary.
          </p>
          <button
            type="button"
            onClick={() => void subscription.refresh()}
            className="mt-4 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-4 py-2 text-[10px] font-black uppercase tracking-wider text-cyan-200 hover:bg-cyan-500/25 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  // No active subscription (and not the owner) — block the whole dashboard.
  if (!isOwner && !subscription.isActive) {
    return (
      <div className="qg-dashboard-shell min-h-screen bg-[var(--qg-dashboard-bg)] text-slate-100">
        <NoAccessHeader />
        <UpgradeRequired requiredTier="starter" currentTier={subscription.tier} variant="no-subscription" />
      </div>
    );
  }

  // STARTER is scoped to QGuard Messaging — its own dashboard, no enterprise shell.
  if (effectiveTier === 'starter') {
    return <StarterDashboard />;
  }

  // The Owner/Administrator dashboard is OWNER-ONLY — it is NOT a subscription
  // tier. No plan (not even Elite) unlocks it; only the platform owner. This
  // mirrors the backend `requireOwner` guard on /api/v1/admin. Non-owners who
  // deep-link here are bounced back to their own dashboard.
  const isAdminRoute = location.pathname === '/dashboard/admin' || location.pathname.startsWith('/dashboard/admin/')
    // Revenue Intelligence is owner-only too; its layout redirects as well,
    // this keeps the rule in one place for every owner-only surface.
    || location.pathname === '/dashboard/revenue-intelligence' || location.pathname.startsWith('/dashboard/revenue-intelligence/');
  const adminForbidden = isAdminRoute && !isOwner;

  // Direct navigation to a module above the plan renders the upgrade screen
  // instead of the module (defense-in-depth alongside the hidden nav + the
  // server-side check). The owner is never tier-gated.
  const pageAllowed = !adminForbidden && (isOwner || canAccessPath(effectiveTier, location.pathname));

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
                    className={`qg-sidebar-section px-3 mb-1.5 text-[9px] font-black uppercase tracking-[0.22em] flex items-center justify-between transition-colors group/header ${isCollapsible ? 'cursor-pointer hover:text-cyan-300 text-slate-500' : 'text-slate-600'}`}
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
                        const nested = 'child' in item && item.child && !collapsed;

                        return (
                          <Link
                            key={item.path}
                            to={item.path}
                            onClick={() => setMobileOpen(false)}
                            title={collapsed ? item.name : undefined}
                            className={`qg-sidebar-link relative flex items-center gap-2.5 rounded-lg transition-all duration-200 no-underline ${
                              collapsed ? 'justify-center px-2 py-2.5' : nested ? 'ml-7 px-3 py-2' : 'px-3 py-2.5'
                            } ${
                              isActive
                                ? 'qg-sidebar-link--active bg-gradient-to-r from-blue-600/20 to-violet-600/14 text-cyan-100 border border-blue-400/30 shadow-[0_12px_30px_rgba(37,99,235,0.12)]'
                                : 'text-slate-400 hover:bg-white/[0.045] hover:text-slate-100 border border-transparent'
                            }`}
                          >
                            {isActive && (
                              <motion.div 
                                layoutId="sidebarActive"
                                className="qg-sidebar-link__bar absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-5 bg-gradient-to-b from-blue-400 to-cyan-300 rounded-r-full shadow-[0_0_14px_rgba(6,182,212,0.5)]"
                                transition={{ type: 'spring', stiffness: 500, damping: 35 }}
                              />
                            )}
                            {nested && (
                              // Tree elbow tying the child back to its parent row.
                              <span aria-hidden="true" className="pointer-events-none absolute -left-2 -top-1 h-[calc(50%+4px)] w-2 rounded-bl-md border-b border-l border-slate-600/60" />
                            )}
                            <Icon className={`shrink-0 ${collapsed ? 'h-5 w-5' : nested ? 'h-3.5 w-3.5' : 'h-4 w-4'}`} />
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
          <ThemeToggle compact={collapsed} showSystem={false} className="w-full justify-center" />

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
          {adminForbidden ? (
            <Navigate to="/dashboard" replace />
          ) : pageAllowed ? (
            <Outlet />
          ) : (
            <UpgradeRequired requiredTier={resolveRequiredTier(location.pathname)} currentTier={effectiveTier} />
          )}
        </div>
      </main>

      <DefaultViewRedirect userId={user.id} tier={effectiveTier} />

      {/* Sophia — AI Security Copilot™, available on every dashboard page. */}
      <SophiaCopilot />
    </div>
  );
}
