import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  Building2,
  CheckCircle2,
  Cloud,
  Cpu,
  Database,
  FileCheck2,
  FlaskConical,
  Globe2,
  KeyRound,
  Link2,
  Network,
  Radar,
  RefreshCw,
  Route,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Webhook,
  Zap,
  type LucideIcon,
} from 'lucide-react';
import {
  useEcosystemSupplyChain,
  type EcosystemChainRisk as ChainRisk,
  type EcosystemLabResult as LabResult,
  type EcosystemLabTest as LabTest,
  type EcosystemRiskLevel as RiskLevel,
  type EcosystemTrustChain as Chain,
  type EcosystemTrustNode as TrustNode,
  type EcosystemVendor as Vendor,
} from '@/hooks/use-ecosystem-supply-chain';

type EcosystemMode = 'dependency-map' | 'vendor-readiness' | 'trust-chain' | 'hybrid-lab';

type ModuleConfig = {
  title: string;
  eyebrow: string;
  purpose: string;
  question: string;
  icon: LucideIcon;
  accent: string;
  route: string;
};

const modules: Record<EcosystemMode, ModuleConfig> = {
  'dependency-map': {
    title: 'Ecosystem Dependency Map',
    eyebrow: 'External Trust Topology',
    purpose: 'Visualize the entire vendor, API, PKI, cloud, certificate, and identity trust ecosystem before post-quantum migration.',
    question: 'Which partner dependency creates cascading trust failure?',
    icon: Globe2,
    accent: '#00c5eb',
    route: '/dashboard/ecosystem-dependency-map',
  },
  'vendor-readiness': {
    title: 'Vendor PQC Readiness Center',
    eyebrow: 'Supply-Chain PQC Maturity',
    purpose: 'Track vendor PQC readiness, standards alignment, contractual obligations, evidence requests, and migration support status.',
    question: 'Which vendors still rely on quantum-vulnerable crypto?',
    icon: BadgeCheck,
    accent: '#FFD36B',
    route: '/dashboard/vendor-pqc-readiness',
  },
  'trust-chain': {
    title: 'Trust Chain Analyzer',
    eyebrow: 'Migration Breakage Detection',
    purpose: 'Simulate certificate chains, federation flows, API authentication, JWT signatures, mTLS, and PKI trust during PQC migration.',
    question: 'Which trust relationships break during migration?',
    icon: Link2,
    accent: '#8b5cf6',
    route: '/dashboard/trust-chain-analyzer',
  },
  'hybrid-lab': {
    title: 'Hybrid Crypto Compatibility Lab',
    eyebrow: 'Hybrid TLS And PQC Compatibility',
    purpose: 'Test RSA plus ML-KEM, ECC plus ML-DSA, hybrid TLS, larger certificates, device tolerance, MTU behavior, VPNs, APIs, and clients.',
    question: 'What breaks if we enable hybrid TLS tomorrow?',
    icon: FlaskConical,
    accent: '#10b981',
    route: '/dashboard/hybrid-crypto-lab',
  },
};

const criticalQuestions = [
  'Which vendors still rely on quantum-vulnerable crypto?',
  'Which trust relationships break during migration?',
  'Which APIs, SDKs, devices, and certificates fail under PQC?',
  'Which partner dependency creates cascading trust failure?',
  'Which systems cannot handle larger PQC certificates or keys?',
  'Which contracts lack PQC obligations?',
  'Which third-party risks create operational downtime?',
  'What breaks if we enable hybrid TLS tomorrow?',
  'Which devices fail with larger certificates?',
  'Which APIs reject ML-DSA signatures?',
];

function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(' ');
}

function riskTone(risk: RiskLevel | Chain['risk'] | LabTest['result']) {
  if (risk === 'Quantum Ready' || risk === 'Pass') return 'border-emerald-400/45 bg-emerald-400/10 text-emerald-300';
  if (risk === 'Hybrid Ready' || risk === 'Migration Planned' || risk === 'Warning' || risk === 'Medium') return 'border-amber-300/45 bg-amber-300/10 text-amber-200';
  if (risk === 'High Risk' || risk === 'High') return 'border-orange-400/45 bg-orange-400/10 text-orange-300';
  if (risk === 'Critical Dependency' || risk === 'Critical' || risk === 'Fail') return 'border-red-400/55 bg-red-500/12 text-red-300';
  return 'border-slate-400/30 bg-slate-400/10 text-slate-300';
}

function panelClass(extra = '') {
  return cx(
    'relative overflow-hidden rounded-xl border border-slate-200/80 bg-white/82 p-5 text-slate-950 shadow-[4px_4px_0_rgba(15,23,42,0.08)] backdrop-blur-xl transition-all duration-300',
    'dark:border-[#FFD36B]/20 dark:bg-[#0f1428]/52 dark:text-white dark:shadow-[inset_0_1px_0_rgba(255,255,255,0.08),0_0_40px_rgba(255,211,107,0.10)]',
    'before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-cyan-300/60 before:to-transparent dark:before:via-[#FFF4C0]/70',
    extra,
  );
}

function StatCard({ label, value, detail, icon: Icon, tone }: { label: string; value: string; detail: string; icon: LucideIcon; tone?: string }) {
  return (
    <div className={panelClass('min-h-[132px]')}>
      <div className="relative z-10 flex items-start justify-between gap-3">
        <div>
          <div className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500 dark:text-white/42">{label}</div>
          <div className="mt-3 text-2xl font-black text-slate-950 dark:text-white">{value}</div>
          <div className="mt-2 text-xs font-semibold text-slate-500 dark:text-white/45">{detail}</div>
        </div>
        <div className={cx('grid h-11 w-11 place-items-center rounded-lg border bg-cyan-400/10 text-cyan-500 dark:border-white/10 dark:bg-white/5 dark:text-[#FFD36B]', tone)}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
    </div>
  );
}

function ModuleNav({ current }: { current: EcosystemMode }) {
  return (
    <div className="grid gap-2 md:grid-cols-4">
      {(Object.keys(modules) as EcosystemMode[]).map((key) => {
        const item = modules[key];
        const Icon = item.icon;
        const active = key === current;
        return (
          <Link
            key={key}
            to={item.route}
            className={cx(
              'rounded-xl border p-3 no-underline transition-all',
              active
                ? 'border-cyan-400 bg-cyan-400/12 text-cyan-700 shadow-[0_0_22px_rgba(0,197,235,0.14)] dark:border-[#FFD36B] dark:bg-[#FFD36B]/12 dark:text-[#FFD36B]'
                : 'border-slate-200 bg-white/60 text-slate-500 hover:border-cyan-300 hover:text-slate-950 dark:border-white/8 dark:bg-white/[0.03] dark:text-white/48 dark:hover:border-[#FFD36B]/35 dark:hover:text-white',
            )}
          >
            <div className="flex items-center gap-2">
              <Icon className="h-4 w-4" />
              <span className="text-[10px] font-black uppercase tracking-widest">{item.title}</span>
            </div>
          </Link>
        );
      })}
    </div>
  );
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="flex min-h-[180px] items-center justify-center rounded-xl border border-dashed border-slate-300 bg-white/50 p-6 text-center text-xs font-black uppercase tracking-widest text-slate-500 dark:border-white/10 dark:bg-white/[0.03] dark:text-white/40">
      {label}
    </div>
  );
}

function TrustTopology({ nodes, selectedId, onSelect }: { nodes: TrustNode[]; selectedId: string; onSelect: (id: string) => void }) {
  if (!nodes.length) {
    return <EmptyState label="Awaiting ecosystem dependency telemetry." />;
  }

  return (
    <div className="relative min-h-[420px] overflow-hidden rounded-xl border border-slate-200 bg-[radial-gradient(#dbeafe_1px,transparent_1px)] bg-[size:22px_22px] dark:border-white/10 dark:bg-[#050816]">
      <svg className="absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
        {nodes.filter((node) => node.id !== 'qguard').map((node) => (
          <line key={node.id} x1="50" y1="50" x2={node.x} y2={node.y} stroke={node.score < 50 ? 'rgba(248,113,113,0.72)' : 'rgba(0,197,235,0.34)'} strokeWidth={node.score < 50 ? 0.55 : 0.35} strokeDasharray="2 2">
            <animate attributeName="stroke-dashoffset" from="10" to="0" dur="2.4s" repeatCount="indefinite" />
          </line>
        ))}
      </svg>
      {nodes.map((node) => {
        const active = selectedId === node.id;
        const critical = node.score < 50;
        return (
          <button
            key={node.id}
            type="button"
            onClick={() => onSelect(node.id)}
            className={cx(
              'absolute -translate-x-1/2 -translate-y-1/2 rounded-xl border px-3 py-2 text-left backdrop-blur-xl transition-all',
              active
                ? 'z-20 scale-105 border-cyan-400 bg-cyan-50 text-slate-950 shadow-[0_0_35px_rgba(0,197,235,0.35)] dark:border-[#FFD36B] dark:bg-[#191827] dark:text-white dark:shadow-[0_0_34px_rgba(255,211,107,0.24)]'
                : critical
                  ? 'border-red-400/50 bg-red-500/10 text-red-200 shadow-[0_0_22px_rgba(239,68,68,0.2)]'
                  : 'border-slate-200 bg-white/85 text-slate-700 hover:border-cyan-300 dark:border-white/10 dark:bg-white/8 dark:text-white/68',
            )}
            style={{ left: `${node.x}%`, top: `${node.y}%` }}
          >
            <div className="flex items-center gap-2">
              {node.id === 'qguard' ? <ShieldCheck className="h-4 w-4 text-emerald-400" /> : critical ? <ShieldAlert className="h-4 w-4 text-red-300" /> : <Network className="h-4 w-4 text-cyan-400" />}
              <span className="max-w-[160px] truncate text-[10px] font-black uppercase tracking-wider">{node.name}</span>
            </div>
            <div className="mt-1 text-[9px] font-bold opacity-60">{node.type} | {node.score}/100</div>
          </button>
        );
      })}
    </div>
  );
}

function VendorScorecard({ vendor }: { vendor: Vendor; key?: string }) {
  return (
    <div className={panelClass('p-4')}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-black uppercase tracking-wider text-slate-950 dark:text-white">{vendor.name}</h3>
          <div className="mt-1 text-[10px] font-bold uppercase tracking-widest text-slate-500 dark:text-white/35">{vendor.category}</div>
        </div>
        <span className={cx('rounded-full border px-2 py-1 text-[9px] font-black uppercase tracking-widest', riskTone(vendor.readiness))}>{vendor.readiness}</span>
      </div>
      <div className="mt-4">
        <div className="mb-2 flex items-center justify-between text-[10px] font-black uppercase tracking-widest text-slate-500 dark:text-white/40">
          <span>PQC Score</span><span>{vendor.score}/100</span>
        </div>
        <div className="h-2 rounded-full bg-slate-200 dark:bg-white/8">
          <div className="h-full rounded-full bg-cyan-500 dark:bg-[#FFD36B]" style={{ width: `${vendor.score}%` }} />
        </div>
      </div>
      <div className="mt-4 grid grid-cols-2 gap-2">
        {Object.entries(vendor.support).map(([label, status]) => (
          <div key={label} className="rounded-lg border border-slate-200 bg-slate-50/70 p-2 dark:border-white/8 dark:bg-black/20">
            <div className="text-[9px] font-black uppercase tracking-widest text-slate-500 dark:text-white/35">{label}</div>
            <div className="mt-1 text-[10px] font-bold text-slate-900 dark:text-white/75">{status}</div>
          </div>
        ))}
      </div>
      <p className="mt-4 text-xs font-semibold leading-5 text-slate-600 dark:text-white/50">{vendor.exposure}</p>
    </div>
  );
}

function QuestionMatrix() {
  return (
    <div className={panelClass()}>
      <div className="mb-4 flex items-center gap-2">
        <Radar className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" />
        <h2 className="text-xs font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/60">Questions This Module Answers</h2>
      </div>
      <div className="grid gap-2 md:grid-cols-2">
        {criticalQuestions.map((question, index) => (
          <div key={question} className="flex items-start gap-3 rounded-lg border border-slate-200 bg-white/60 p-3 dark:border-white/8 dark:bg-white/[0.03]">
            <span className="grid h-6 w-6 shrink-0 place-items-center rounded-md border border-cyan-400/30 bg-cyan-400/10 text-[9px] font-black text-cyan-600 dark:border-[#FFD36B]/30 dark:bg-[#FFD36B]/10 dark:text-[#FFD36B]">{index + 1}</span>
            <span className="text-xs font-bold leading-5 text-slate-700 dark:text-white/60">{question}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function DependencyMapView({ nodes }: { nodes: TrustNode[] }) {
  const [selectedId, setSelectedId] = useState(() => nodes.find((node) => node.id !== 'qguard')?.id || nodes[0]?.id || '');

  useEffect(() => {
    if (!nodes.length) {
      setSelectedId('');
      return;
    }
    if (!nodes.some((node) => node.id === selectedId)) {
      setSelectedId(nodes.find((node) => node.id !== 'qguard')?.id || nodes[0].id);
    }
  }, [nodes, selectedId]);

  const selected = nodes.find((node) => node.id === selectedId) || nodes[0];
  const vulnerableCount = nodes.filter((node) => node.id !== 'qguard' && node.score < 55).length;

  return (
    <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_380px]">
      <div className={panelClass('p-4')}>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/60">
            <Network className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" /> 3D Trust Topology
          </h2>
          <span className="rounded-full border border-red-400/35 bg-red-500/10 px-3 py-1 text-[9px] font-black uppercase tracking-widest text-red-300">
            {vulnerableCount} vulnerable node{vulnerableCount === 1 ? '' : 's'}
          </span>
        </div>
        <TrustTopology nodes={nodes} selectedId={selectedId} onSelect={setSelectedId} />
      </div>
      <div className={panelClass()}>
        {selected ? (
          <>
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="text-[10px] font-black uppercase tracking-[0.2em] text-slate-500 dark:text-white/40">Selected Dependency</div>
                <h2 className="mt-2 text-xl font-black text-slate-950 dark:text-white">{selected.name}</h2>
                <div className="mt-1 text-xs font-bold text-slate-500 dark:text-white/45">{selected.type}</div>
              </div>
              <span className={cx('rounded-full border px-2 py-1 text-[9px] font-black uppercase tracking-widest', riskTone(selected.risk))}>{selected.risk}</span>
            </div>
            <div className="mt-6 grid grid-cols-2 gap-3">
              <StatCard label="Exposure" value={`${selected.score}/100`} detail="third-party crypto score" icon={Activity} />
              <StatCard label="Blast Radius" value={selected.score < 50 ? 'High' : selected.score < 75 ? 'Medium' : 'Low'} detail="dependent workflows" icon={AlertTriangle} />
            </div>
            <div className="mt-5 space-y-3">
              {selected.details.map((detail) => (
                <div key={detail} className="flex items-start gap-2 rounded-lg border border-slate-200 bg-slate-50/80 p-3 text-xs font-semibold text-slate-600 dark:border-white/8 dark:bg-black/20 dark:text-white/55">
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-cyan-500 dark:text-[#FFD36B]" />
                  {detail}
                </div>
              ))}
            </div>
          </>
        ) : (
          <EmptyState label="No selected dependency yet." />
        )}
      </div>
    </div>
  );
}

function VendorReadinessView({ vendors, workflow }: { vendors: Vendor[]; workflow: Array<{ label: string; status: string; detail: string; count: number }> }) {
  return (
    <div className="space-y-6">
      {vendors.length ? (
        <div className="grid gap-4 xl:grid-cols-4">
          {vendors.map((vendor) => <VendorScorecard key={vendor.name} vendor={vendor} />)}
        </div>
      ) : (
        <EmptyState label="No vendor readiness records are synchronized yet." />
      )}
      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_420px]">
        <div className={panelClass()}>
          <h2 className="mb-4 flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/60">
            <FileCheck2 className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" /> Automated Vendor Assessment Workflow
          </h2>
          {(workflow.length ? workflow : [{ label: 'Waiting for vendor telemetry', status: 'Waiting', detail: 'Connect vendors, import assessments, or run scanner jobs to populate this workflow.', count: 0 }]).map((item, index) => (
            <div key={item.label} className="grid grid-cols-[36px_1fr_auto] items-center gap-3 border-b border-slate-200 py-3 last:border-b-0 dark:border-white/8">
              <span className="grid h-8 w-8 place-items-center rounded-lg border border-cyan-400/30 bg-cyan-400/10 text-[10px] font-black text-cyan-600 dark:border-[#FFD36B]/30 dark:bg-[#FFD36B]/10 dark:text-[#FFD36B]">{index + 1}</span>
              <span>
                <span className="block text-sm font-bold text-slate-800 dark:text-white/72">{item.label}</span>
                <span className="mt-1 block text-[10px] font-semibold text-slate-500 dark:text-white/40">{item.detail}</span>
              </span>
              <span className={cx(
                'rounded-full border px-2 py-1 text-[9px] font-black uppercase',
                item.status === 'Needs Review'
                  ? 'border-amber-400/30 bg-amber-400/10 text-amber-600 dark:text-amber-300'
                  : item.status === 'Active'
                    ? 'border-emerald-400/30 bg-emerald-400/10 text-emerald-500 dark:text-emerald-300'
                    : 'border-slate-300 bg-slate-100 text-slate-500 dark:border-white/10 dark:bg-white/5 dark:text-white/40',
              )}>{item.status} {item.count ? `(${item.count})` : ''}</span>
            </div>
          ))}
        </div>
        <div className={panelClass()}>
          <h2 className="mb-4 flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/60">
            <Building2 className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" /> Contractual Exposure
          </h2>
          <div className="space-y-3">
            {vendors.length ? vendors.map((vendor) => (
              <div key={vendor.name} className="rounded-lg border border-slate-200 bg-white/60 p-3 dark:border-white/8 dark:bg-white/[0.03]">
                <div className="text-xs font-black text-slate-950 dark:text-white">{vendor.name}</div>
                <div className="mt-1 text-[10px] font-semibold text-slate-500 dark:text-white/45">{vendor.contract}</div>
              </div>
            )) : <EmptyState label="No contractual exposure evidence yet." />}
          </div>
        </div>
      </div>
    </div>
  );
}

function TrustChainView({ chains }: { chains: Chain[] }) {
  const [activeChain, setActiveChain] = useState(() => chains[0]?.name || '');

  useEffect(() => {
    if (!chains.length) {
      setActiveChain('');
      return;
    }
    if (!chains.some((item) => item.name === activeChain)) setActiveChain(chains[0].name);
  }, [activeChain, chains]);

  const chain = chains.find((item) => item.name === activeChain) || chains[0];

  return (
    <div className="grid gap-6 xl:grid-cols-[380px_minmax(0,1fr)]">
      <div className={panelClass()}>
        <h2 className="mb-4 flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/60">
          <Route className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" /> Trust Chains
        </h2>
        <div className="space-y-3">
          {chains.length ? chains.map((item) => (
            <button
              key={item.name}
              type="button"
              onClick={() => setActiveChain(item.name)}
              className={cx(
                'w-full rounded-lg border p-3 text-left transition',
                activeChain === item.name
                  ? 'border-cyan-400 bg-cyan-400/12 dark:border-[#FFD36B]/45 dark:bg-[#FFD36B]/10'
                  : 'border-slate-200 bg-white/60 hover:border-cyan-300 dark:border-white/8 dark:bg-white/[0.03]',
              )}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-black text-slate-950 dark:text-white">{item.name}</span>
                <span className={cx('rounded-full border px-2 py-1 text-[8px] font-black uppercase', riskTone(item.risk))}>{item.risk}</span>
              </div>
              <div className="mt-2 text-[10px] font-semibold text-slate-500 dark:text-white/42">{item.issue}</div>
            </button>
          )) : <EmptyState label="No trust-chain breaks detected yet." />}
        </div>
      </div>
      <div className={panelClass()}>
        {chain ? (
          <>
            <div className="mb-6 flex items-start justify-between gap-3">
              <div>
                <div className="text-[10px] font-black uppercase tracking-[0.2em] text-slate-500 dark:text-white/40">Simulation Result</div>
                <h2 className="mt-2 text-2xl font-black text-slate-950 dark:text-white">{chain.name}</h2>
                <p className="mt-2 max-w-2xl text-sm font-semibold leading-6 text-slate-600 dark:text-white/50">{chain.impact}</p>
              </div>
              <span className={cx('rounded-full border px-3 py-1 text-[9px] font-black uppercase tracking-widest', riskTone(chain.risk))}>{chain.risk}</span>
            </div>
            <div className="relative grid gap-4 lg:grid-cols-4">
              {chain.path.map((step, index) => (
                <div key={step} className="relative rounded-xl border border-slate-200 bg-white/70 p-4 dark:border-white/8 dark:bg-white/[0.03]">
                  <div className="grid h-10 w-10 place-items-center rounded-lg border border-cyan-400/30 bg-cyan-400/10 text-cyan-500 dark:border-[#FFD36B]/30 dark:bg-[#FFD36B]/10 dark:text-[#FFD36B]">
                    {index === 0 ? <Building2 className="h-5 w-5" /> : index === chain.path.length - 1 ? <Server className="h-5 w-5" /> : <Link2 className="h-5 w-5" />}
                  </div>
                  <div className="mt-4 text-sm font-black text-slate-950 dark:text-white">{step}</div>
                  <div className="mt-2 text-[10px] font-semibold text-slate-500 dark:text-white/40">Trust hop {index + 1}</div>
                  {index < chain.path.length - 1 && <ArrowRight className="absolute -right-5 top-1/2 z-10 hidden h-5 w-5 -translate-y-1/2 text-cyan-500 dark:text-[#FFD36B] lg:block" />}
                </div>
              ))}
            </div>
            <div className="mt-6 rounded-xl border border-red-400/30 bg-red-500/10 p-4 text-sm font-bold text-red-300">
              <AlertTriangle className="mr-2 inline h-4 w-4" />
              {chain.issue}
            </div>
          </>
        ) : <EmptyState label="No trust chain selected yet." />}
      </div>
    </div>
  );
}

function HybridLabView({ labTests }: { labTests: LabTest[] }) {
  const [scenario, setScenario] = useState('hybrid-tls');
  const resultSummary = useMemo(() => {
    const byName = (name: string) => labTests.find((test) => test.name.toLowerCase().includes(name));
    if (scenario === 'cert-size') return byName('certificate')?.detail || 'Awaiting certificate telemetry to estimate larger chain impact.';
    if (scenario === 'api-signatures') return byName('ml-dsa')?.detail || 'Awaiting API or JWT telemetry to assess ML-DSA signature tolerance.';
    return byName('hybrid tls')?.detail || 'Awaiting TLS telemetry to simulate hybrid handshake rollout.';
  }, [labTests, scenario]);

  return (
    <div className="space-y-6">
      <div className={panelClass()}>
        <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
          <div>
            <h2 className="flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/60">
              <FlaskConical className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" /> Simulation Controls
            </h2>
            <p className="mt-2 max-w-2xl text-sm font-semibold text-slate-600 dark:text-white/48">{resultSummary}</p>
          </div>
          <div className="grid gap-2 sm:grid-cols-3">
            {[
              ['hybrid-tls', 'Enable Hybrid TLS'],
              ['cert-size', 'Larger Certificates'],
              ['api-signatures', 'ML-DSA Signatures'],
            ].map(([key, label]) => (
              <button
                key={key}
                type="button"
                onClick={() => setScenario(key)}
                className={cx(
                  'rounded-lg border px-4 py-2 text-[10px] font-black uppercase tracking-widest transition',
                  scenario === key
                    ? 'border-cyan-400 bg-cyan-400/12 text-cyan-700 dark:border-[#FFD36B]/45 dark:bg-[#FFD36B]/12 dark:text-[#FFD36B]'
                    : 'border-slate-200 bg-white/60 text-slate-500 hover:border-cyan-300 dark:border-white/8 dark:bg-white/[0.03] dark:text-white/45',
                )}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      </div>
      {labTests.length ? <div className="grid gap-4 xl:grid-cols-3">
        {labTests.map((test) => (
          <div key={test.name} className={panelClass('min-h-[180px]')}>
            <div className="flex items-start justify-between gap-3">
              <div className="grid h-10 w-10 place-items-center rounded-lg border border-slate-200 bg-white/65 text-cyan-500 dark:border-white/10 dark:bg-white/5 dark:text-[#FFD36B]">
                {test.result === 'Pass' ? <CheckCircle2 className="h-5 w-5" /> : test.result === 'Fail' ? <ShieldAlert className="h-5 w-5" /> : <AlertTriangle className="h-5 w-5" />}
              </div>
              <span className={cx('rounded-full border px-2 py-1 text-[9px] font-black uppercase tracking-widest', riskTone(test.result))}>{test.result}</span>
            </div>
            <h3 className="mt-4 text-sm font-black uppercase tracking-wider text-slate-950 dark:text-white">{test.name}</h3>
            <div className="mt-2 text-xl font-black text-cyan-600 dark:text-[#FFD36B]">{test.metric}</div>
            <p className="mt-3 text-xs font-semibold leading-5 text-slate-600 dark:text-white/48">{test.detail}</p>
          </div>
        ))}
      </div> : <EmptyState label="No hybrid compatibility telemetry yet." />}
    </div>
  );
}

export default function EcosystemSupplyChainModule({ mode }: { mode: EcosystemMode }) {
  const config = modules[mode];
  const Icon = config.icon;
  const { snapshot, loading, error, connected, refresh } = useEcosystemSupplyChain();
  const updatedAt = snapshot.generatedAt ? new Date(snapshot.generatedAt) : null;

  return (
    <main className="min-h-screen bg-[#f8fafc] p-4 text-slate-950 dark:bg-[#02060d] dark:text-white lg:p-6">
      <div className="pointer-events-none fixed inset-0 opacity-80" aria-hidden="true">
        <div className="absolute inset-0 bg-[radial-gradient(#dbeafe_1px,transparent_1px)] bg-[size:24px_24px] dark:bg-[linear-gradient(rgba(255,211,107,0.035)_1px,transparent_1px),linear-gradient(90deg,rgba(0,217,255,0.025)_1px,transparent_1px)] dark:bg-[size:48px_48px]" />
        <div className="absolute inset-0 bg-[linear-gradient(135deg,rgba(0,197,235,0.12),transparent_35%,rgba(255,211,107,0.08)_100%)] dark:bg-[linear-gradient(180deg,rgba(255,211,107,0.08),transparent_36%,rgba(0,140,255,0.05)_100%)]" />
      </div>

      <div className="relative z-10 mx-auto max-w-[1680px] space-y-6">
        <header className={panelClass('p-6')}>
          <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
            <div className="max-w-4xl">
              <div className="inline-flex items-center gap-2 rounded-full border border-cyan-400/40 bg-cyan-400/10 px-3 py-1 text-[10px] font-black uppercase tracking-[0.18em] text-cyan-600 dark:border-[#FFD36B]/35 dark:bg-[#FFD36B]/10 dark:text-[#FFD36B]">
                <Icon className="h-3.5 w-3.5" />
                {config.eyebrow}
              </div>
              <h1 className="mt-4 text-3xl font-black uppercase tracking-tight text-slate-950 dark:text-white md:text-4xl">{config.title}</h1>
              <p className="mt-3 max-w-3xl text-sm font-semibold leading-6 text-slate-600 dark:text-white/55">{config.purpose}</p>
              <div className="mt-4 rounded-xl border border-slate-200 bg-white/60 p-4 text-sm font-black text-slate-800 dark:border-white/8 dark:bg-black/20 dark:text-white/72">
                <Sparkles className="mr-2 inline h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" />
                {config.question}
              </div>
            </div>
            <div className="grid gap-3 sm:grid-cols-2 xl:w-[420px]">
              <button type="button" onClick={() => void refresh()} className="inline-flex h-11 items-center justify-center gap-2 rounded-lg border border-cyan-400/40 bg-cyan-400/12 px-4 text-[10px] font-black uppercase tracking-widest text-cyan-700 transition hover:bg-cyan-400/20 dark:border-[#FFD36B]/35 dark:bg-[#FFD36B]/10 dark:text-[#FFD36B]">
                <RefreshCw className="h-4 w-4" /> Refresh Model
              </button>
              <Link to="/dashboard/cbom" className="inline-flex h-11 items-center justify-center gap-2 rounded-lg border border-slate-200 bg-white/70 px-4 text-[10px] font-black uppercase tracking-widest text-slate-700 no-underline transition hover:border-cyan-300 dark:border-white/10 dark:bg-white/5 dark:text-white/65">
                <Database className="h-4 w-4" /> Source CBOM
              </Link>
              <div className="rounded-lg border border-slate-200 bg-white/70 p-3 dark:border-white/8 dark:bg-white/[0.03]">
                <div className="text-[9px] font-black uppercase tracking-widest text-slate-500 dark:text-white/35">Model Updated</div>
                <div className="mt-1 text-xs font-black text-slate-900 dark:text-white">
                  {updatedAt ? updatedAt.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) : loading ? 'Syncing...' : 'Awaiting data'}
                </div>
              </div>
              <div className={cx('rounded-lg border p-3', connected ? 'border-emerald-400/35 bg-emerald-400/10' : 'border-amber-400/35 bg-amber-400/10')}>
                <div className={cx('text-[9px] font-black uppercase tracking-widest', connected ? 'text-emerald-600 dark:text-emerald-300' : 'text-amber-600 dark:text-amber-300')}>Assessment Engine</div>
                <div className="mt-1 text-xs font-black text-slate-900 dark:text-white">{connected ? 'Live' : loading ? 'Syncing' : 'Polling'}</div>
              </div>
            </div>
          </div>
        </header>

        <ModuleNav current={mode} />

        {error && (
          <div className="rounded-xl border border-red-400/30 bg-red-500/10 p-4 text-sm font-bold text-red-600 dark:text-red-300">
            <AlertTriangle className="mr-2 inline h-4 w-4" />
            {error}
          </div>
        )}

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <StatCard label="External Dependencies" value={String(snapshot.metrics.externalDependencies)} detail={`${snapshot.metrics.observedSignals} synchronized evidence signals`} icon={Network} />
          <StatCard label="Critical Trust Breaks" value={String(snapshot.metrics.criticalTrustBreaks)} detail="migration-blocking paths" icon={ShieldAlert} tone="text-red-400" />
          <StatCard label="Hybrid Ready" value={`${snapshot.metrics.hybridReadyPercent}%`} detail="weighted readiness coverage" icon={ShieldCheck} tone="text-emerald-400" />
          <StatCard label="Contract Gaps" value={String(snapshot.metrics.contractGaps)} detail="missing PQC obligations" icon={FileCheck2} tone="text-amber-400" />
        </div>

        {loading && !snapshot.metrics.observedSignals && (
          <EmptyState label="Synchronizing ecosystem, scanner, CBOM, certificate, runtime, and vendor telemetry." />
        )}

        {mode === 'dependency-map' && <DependencyMapView nodes={snapshot.trustNodes} />}
        {mode === 'vendor-readiness' && <VendorReadinessView vendors={snapshot.vendors} workflow={snapshot.workflow} />}
        {mode === 'trust-chain' && <TrustChainView chains={snapshot.chains} />}
        {mode === 'hybrid-lab' && <HybridLabView labTests={snapshot.labTests} />}

        <QuestionMatrix />

        <div className="grid gap-4 xl:grid-cols-3">
          {[
            { title: 'API Trust Chains', detail: 'Maps external gateways, SDKs, JWT validators, webhook signatures, and partner APIs.', icon: Webhook },
            { title: 'PKI Dependency Tree', detail: 'Tracks root CAs, intermediates, certificate size impact, mTLS paths, and rollover readiness.', icon: KeyRound },
            { title: 'Cloud Trust Paths', detail: 'Correlates cloud IAM, KMS, workload identity, federation, and certificate-backed trust routes.', icon: Cloud },
            { title: 'Device Tolerance', detail: 'Flags devices and clients unable to handle larger PQC keys, signatures, or certificate chains.', icon: Cpu },
            { title: 'Operational Downtime Risk', detail: 'Identifies partner and trust failures likely to interrupt authentication or transaction flows.', icon: Zap },
            { title: 'Evidence & Compliance', detail: 'Links questionnaires, vendor evidence, architecture review forms, and contract obligations.', icon: FileCheck2 },
          ].map((item) => {
            const ItemIcon = item.icon;
            return (
              <div key={item.title} className={panelClass('min-h-[150px]')}>
                <div className="grid h-11 w-11 place-items-center rounded-lg border border-cyan-400/30 bg-cyan-400/10 text-cyan-500 dark:border-[#FFD36B]/30 dark:bg-[#FFD36B]/10 dark:text-[#FFD36B]">
                  <ItemIcon className="h-5 w-5" />
                </div>
                <h3 className="mt-4 text-sm font-black uppercase tracking-wider text-slate-950 dark:text-white">{item.title}</h3>
                <p className="mt-2 text-xs font-semibold leading-5 text-slate-600 dark:text-white/48">{item.detail}</p>
              </div>
            );
          })}
        </div>
      </div>
    </main>
  );
}
