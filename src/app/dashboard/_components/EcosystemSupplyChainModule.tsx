import { useEffect, useMemo, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
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

function nodeText(node: TrustNode | null | undefined) {
  if (!node) return '';
  return `${node.name} ${node.type} ${node.risk} ${node.details.join(' ')}`.toLowerCase();
}

function dependencyCategory(node: TrustNode | null | undefined) {
  const text = nodeText(node);
  if (/certificate|pki|issuer|ca|oid|trust chain|ecdsa|rsa|tls|mtls/.test(text)) return 'pki';
  if (/runtime|downgrade|shadow|hndl|cipher|handshake/.test(text)) return 'runtime';
  if (/vendor|supplier|third-party|third party|sdk|library|contract/.test(text)) return 'vendor';
  if (/oauth|oidc|jwt|saml|federation|api/.test(text)) return 'identity-api';
  if (/owner|ownership|unassigned/.test(text)) return 'ownership';
  return 'dependency';
}

function remediationPlaybook(node: TrustNode | null | undefined) {
  const category = dependencyCategory(node);
  if (category === 'pki') {
    return [
      'Open PKI Visibility and identify the exact certificate, issuer, root/intermediate CA, algorithm, key size, expiry, and affected asset.',
      'Replace weak or quantum-vulnerable RSA/ECDSA/legacy certificates with the approved migration profile, or stage a hybrid-compatible certificate path where required.',
      'Update every relying trust store, middleware trust bundle, API gateway, mTLS client, identity provider, and certificate pinning rule that consumes this chain.',
      'Run Trust Chain Analyzer to confirm the new chain validates end-to-end before releasing the migration gate.',
    ];
  }
  if (category === 'runtime') {
    return [
      'Open Runtime Crypto Intel and inspect the live process, host, port, protocol, cipher, downgrade, shadow crypto, or HNDL evidence.',
      'Patch the service configuration, TLS policy, crypto library, container image, or runtime package that is still emitting vulnerable telemetry.',
      'Restart or redeploy the affected workload and keep the agent collector online so new runtime evidence is recorded.',
      'Recheck this dependency only after fresh runtime telemetry shows the vulnerable algorithm or downgrade signal has stopped.',
    ];
  }
  if (category === 'vendor') {
    return [
      'Open Vendor PQC Readiness Center and request supplier evidence for ML-KEM, ML-DSA, hybrid TLS, certificate-size handling, API validation, rollback, and support timeline.',
      'Attach vendor evidence, update contract/PQC obligation status, and mark unsupported paths as blocked until a migration-safe option exists.',
      'Map which internal assets depend on the vendor and assign a business owner for each affected integration.',
      'Do not approve migration sequencing until vendor readiness is Ready or a documented compensating control is accepted.',
    ];
  }
  if (category === 'identity-api') {
    return [
      'Open Trust Chain Analyzer and inspect the identity/API path for JWT, OAuth/OIDC, SAML, webhook, gateway, or API-signature failure points.',
      'Update signing/verification policy, JWKS trust, API gateway validation, token issuer metadata, or partner signature acceptance rules.',
      'Test larger certificates/signatures and hybrid handshake behavior in the compatibility lab before production rollout.',
      'Record evidence that authentication and API flows still pass after the trust change.',
    ];
  }
  if (category === 'ownership') {
    return [
      'Open Assets & CBOM and assign service owner, business owner, escalation contact, environment, and criticality to the affected dependency.',
      'Map the dependency to the consuming application, certificate, vendor, and runtime endpoint.',
      'Add missing relationship edges so blast radius can be calculated before certificate or trust-store replacement.',
      'Re-run discovery after ownership updates so Trust-State Discovery can clear ownership review findings.',
    ];
  }
  return [
    'Create or correct asset relationship edges for every upstream issuer, certificate, vendor, API, identity provider, runtime service, and downstream workload.',
    'Assign an owner to each node in the dependency path and confirm the business impact of replacing its trust object.',
    'Use Trust Chain Analyzer to simulate the dependency path after the proposed migration change.',
    'Only move to migration execution after the dependency score improves and no critical trust breaks remain for this path.',
  ];
}

function verificationChecklist(node: TrustNode | null | undefined) {
  const category = dependencyCategory(node);
  const common = [
    'A new scanner or collector event is recorded after the mitigation timestamp.',
    'The selected dependency score improves above the blocker threshold and no longer appears as a critical dependency.',
    'Trust-State Discovery gate findings drop from blocker to review/monitor or disappear after refresh.',
  ];

  if (category === 'pki') {
    return [
      'PKI Visibility shows the replacement certificate or chain with approved algorithm/profile, valid issuer, owner, and expiry.',
      'Trust Chain Analyzer reports the certificate path as Low/Pass for the affected relying parties.',
      ...common,
    ];
  }
  if (category === 'runtime') {
    return [
      'Runtime Crypto Intel stops receiving weak cipher, downgrade, shadow crypto, or HNDL signals for the host/process.',
      'Scanner evidence shows the affected endpoint or package as remediated or PQC/hybrid-ready.',
      ...common,
    ];
  }
  if (category === 'vendor') {
    return [
      'Vendor PQC Readiness Center contains current supplier evidence and no open PQC obligation gap for this dependency.',
      'Contract/readiness status is no longer blocked or unknown for the affected support area.',
      ...common,
    ];
  }
  return [
    'Ecosystem Dependency Map shows all required relationship edges and reduced blast radius.',
    'Trust Chain Analyzer no longer shows a critical/high break for this path.',
    ...common,
  ];
}

function dependencyActions(node: TrustNode | null | undefined) {
  const category = dependencyCategory(node);
  const encoded = encodeURIComponent(node?.name || node?.id || '');
  const actions = [
    { label: 'Open Trust Chain Analyzer', href: `/dashboard/trust-chain-analyzer?dependency=${encoded}`, icon: Route },
    { label: 'Open Trust-State Discovery', href: '/dashboard/trust-state-discovery', icon: ShieldCheck },
  ];
  if (category === 'pki') actions.unshift({ label: 'Open PKI Visibility', href: '/dashboard/pki-visibility', icon: KeyRound });
  else if (category === 'runtime') actions.unshift({ label: 'Open Runtime Crypto Intel', href: '/dashboard/runtime-crypto-intel', icon: Activity });
  else if (category === 'vendor') actions.unshift({ label: 'Open Vendor Readiness', href: '/dashboard/vendor-pqc-readiness', icon: Building2 });
  else if (category === 'ownership') actions.unshift({ label: 'Open Assets & CBOM', href: '/dashboard/assets', icon: Database });
  else if (category === 'identity-api') actions.unshift({ label: 'Open Hybrid Lab', href: '/dashboard/hybrid-crypto-lab', icon: FlaskConical });
  else actions.unshift({ label: 'Build Dependency Edges', href: '/dashboard/ecosystem-dependency-map', icon: Network });
  return actions;
}

function DependencyMapView({ nodes, chains }: { nodes: TrustNode[]; chains: Chain[] }) {
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
  const playbook = remediationPlaybook(selected);
  const verification = verificationChecklist(selected);
  const actions = dependencyActions(selected);
  const relatedChain = selected
    ? chains.find((chain) => `${chain.name} ${chain.path.join(' ')} ${chain.issue} ${chain.impact}`.toLowerCase().includes(selected.name.toLowerCase().split(':')[0]))
    : null;

  return (
    <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_460px]">
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
      <div className={panelClass('max-h-[720px] overflow-y-auto')}>
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
            <div className="mt-6 rounded-xl border border-cyan-400/25 bg-cyan-400/10 p-4">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="text-[10px] font-black uppercase tracking-[0.18em] text-cyan-700 dark:text-cyan-200">Blocker Resolution</div>
                  <div className="mt-1 text-sm font-black text-slate-950 dark:text-white">What users should do next</div>
                </div>
                <span className="rounded-full border border-white/10 bg-white/60 px-2 py-1 text-[9px] font-black uppercase text-slate-600 dark:bg-white/5 dark:text-white/50">
                  {dependencyCategory(selected).replace(/-/g, ' ')}
                </span>
              </div>
              <ol className="mt-4 space-y-3">
                {playbook.map((step, index) => (
                  <li key={step} className="grid grid-cols-[24px_1fr] gap-3 text-xs font-semibold leading-5 text-slate-700 dark:text-white/68">
                    <span className="grid h-6 w-6 place-items-center rounded-md border border-cyan-400/30 bg-cyan-400/10 text-[10px] font-black text-cyan-700 dark:text-cyan-200">{index + 1}</span>
                    <span>{step}</span>
                  </li>
                ))}
              </ol>
            </div>

            <div className="mt-4 rounded-xl border border-emerald-400/25 bg-emerald-400/10 p-4">
              <div className="text-[10px] font-black uppercase tracking-[0.18em] text-emerald-700 dark:text-emerald-200">How users know it worked</div>
              <div className="mt-1 text-sm font-black text-slate-950 dark:text-white">Remediation evidence checklist</div>
              <div className="mt-4 space-y-2">
                {verification.map((item) => (
                  <div key={item} className="flex gap-2 text-xs font-semibold leading-5 text-slate-700 dark:text-white/68">
                    <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" />
                    <span>{item}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="mt-4 grid gap-2 sm:grid-cols-2">
              {actions.map((action) => {
                const ActionIcon = action.icon;
                return (
                  <Link key={`${action.href}-${action.label}`} to={action.href} className="inline-flex items-center justify-between gap-3 rounded-lg border border-slate-200 bg-white/70 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-slate-700 no-underline transition hover:border-cyan-400 hover:text-cyan-700 dark:border-white/10 dark:bg-white/[0.04] dark:text-white/62 dark:hover:border-[#FFD36B]/40 dark:hover:text-[#FFD36B]">
                    <span className="inline-flex items-center gap-2"><ActionIcon className="h-3.5 w-3.5" /> {action.label}</span>
                    <ArrowRight className="h-3.5 w-3.5" />
                  </Link>
                );
              })}
            </div>

            <div className="mt-4 rounded-xl border border-violet-400/25 bg-violet-400/10 p-4 text-xs font-semibold leading-5 text-slate-700 dark:text-white/64">
              <Link2 className="mr-2 inline h-4 w-4 text-violet-400" />
              Blockers are connected to Trust Chain Analyzer through the same live ecosystem telemetry. {relatedChain ? `Related chain: ${relatedChain.name}.` : 'Open Trust Chain Analyzer to simulate the selected dependency path and confirm whether the mitigation removes the break.'}
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

function chainVendorName(chain: Chain) {
  return chain.path[0] || chain.name.replace(/\s+Trust Path$/i, '') || 'External Vendor';
}

function quantumBreakSignal(chain: Chain) {
  const text = `${chain.name} ${chain.issue} ${chain.impact} ${chain.path.join(' ')}`.toLowerCase();
  if (/ml[-_ ]?dsa|jwt|jose|signature|api/.test(text)) {
    return {
      label: 'PQC signature blocker',
      detail: 'Vendor path can break token, API, or federation validation during ML-DSA migration.',
      standard: 'NIST FIPS 204 review',
    };
  }
  if (/cert|certificate|pki|x509|root|intermediate|m-?tls/.test(text)) {
    return {
      label: 'Quantum-vulnerable PKI',
      detail: 'Certificate or trust-anchor evidence still depends on classical public-key assumptions.',
      standard: 'FIPS 204 / FIPS 205 readiness',
    };
  }
  if (/vpn|tls|hybrid|mtu|handshake|network|edge/.test(text)) {
    return {
      label: 'Hybrid TLS blocker',
      detail: 'Vendor edge path needs ML-KEM or hybrid handshake validation before migration assurance.',
      standard: 'NIST FIPS 203 validation',
    };
  }
  if (/contract|obligation|evidence|incomplete|unknown/.test(text)) {
    return {
      label: 'PQC evidence gap',
      detail: 'Vendor trust cannot be marked assured until PQC support evidence is synchronized.',
      standard: 'Vendor attestation required',
    };
  }
  return {
    label: chain.risk === 'Low' ? 'Monitored trust path' : 'Quantum-vulnerable dependency',
    detail: 'Supply-chain trust path requires PQC migration validation before production approval.',
    standard: 'FIPS 203 / 204 / 205 review',
  };
}

function SupplyChainTrustFlow({ chain }: { chain: Chain }) {
  const vendor = chainVendorName(chain);
  const breakSignal = quantumBreakSignal(chain);
  const path = chain.path.length ? chain.path : [vendor, 'External Dependency', 'QGuard Trust Policy', 'Tenant Workload'];
  const stages = path.map((label, index) => {
    const last = index === path.length - 1;
    const isVendor = index === 0;
    const Icon = isVendor ? Building2 : last ? Server : index === 2 ? ShieldAlert : Link2;
    return {
      label,
      Icon,
      status: isVendor ? 'break-source' : last ? 'impacted' : 'propagates',
      role: isVendor ? 'Vendor break source' : last ? 'Impacted workload' : index === 2 ? 'Trust control' : 'Dependency hop',
      detail: isVendor ? breakSignal.label : last ? 'Receives broken trust assertion' : 'Propagates vendor trust state',
    };
  });

  return (
    <div className="mt-6 overflow-hidden rounded-xl border border-slate-200 bg-slate-50/80 dark:border-white/10 dark:bg-black/20">
      <div className="flex flex-col gap-3 border-b border-slate-200 bg-white/70 px-4 py-3 dark:border-white/8 dark:bg-white/[0.03] lg:flex-row lg:items-center lg:justify-between">
        <div>
          <div className="flex items-center gap-2 text-[10px] font-black uppercase tracking-[0.2em] text-slate-500 dark:text-white/40">
            <Network className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" />
            Supply Chain Trust Break Workflow
          </div>
          <div className="mt-1 text-sm font-black text-slate-950 dark:text-white">{vendor}</div>
        </div>
        <div className="flex flex-wrap gap-2">
          <span className={cx('rounded-full border px-2.5 py-1 text-[9px] font-black uppercase tracking-widest', riskTone(chain.risk))}>{chain.risk}</span>
          <span className="rounded-full border border-red-400/35 bg-red-500/10 px-2.5 py-1 text-[9px] font-black uppercase tracking-widest text-red-600 dark:text-red-300">{breakSignal.label}</span>
        </div>
      </div>

      <div className="relative p-4">
        <div className="pointer-events-none absolute inset-x-6 top-1/2 hidden h-px -translate-y-1/2 bg-gradient-to-r from-red-400/70 via-cyan-400/45 to-emerald-400/60 lg:block" />
        <div className="relative grid gap-3 lg:grid-cols-4">
          {stages.map(({ label, Icon, role, detail, status }, index) => {
            const broken = status === 'break-source';
            const impacted = status === 'impacted';
            return (
              <div
                key={`${label}-${index}`}
                className={cx(
                  'relative rounded-xl border p-4 shadow-sm backdrop-blur-xl',
                  broken
                    ? 'border-red-400/45 bg-red-500/10 shadow-[0_0_24px_rgba(239,68,68,0.12)]'
                    : impacted
                      ? 'border-amber-300/35 bg-amber-300/10'
                      : 'border-slate-200 bg-white/80 dark:border-white/8 dark:bg-white/[0.04]',
                )}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className={cx(
                    'grid h-10 w-10 place-items-center rounded-lg border',
                    broken
                      ? 'border-red-400/45 bg-red-500/10 text-red-500 dark:text-red-300'
                      : impacted
                        ? 'border-amber-300/35 bg-amber-300/10 text-amber-500 dark:text-amber-300'
                        : 'border-cyan-400/30 bg-cyan-400/10 text-cyan-500 dark:border-[#FFD36B]/30 dark:bg-[#FFD36B]/10 dark:text-[#FFD36B]',
                  )}>
                    <Icon className="h-5 w-5" />
                  </div>
                  <span className="rounded-full border border-slate-200 bg-white/70 px-2 py-1 text-[8px] font-black uppercase tracking-widest text-slate-500 dark:border-white/10 dark:bg-white/5 dark:text-white/35">
                    {index + 1}
                  </span>
                </div>
                <div className="mt-4 text-[9px] font-black uppercase tracking-[0.18em] text-slate-500 dark:text-white/35">{role}</div>
                <div className="mt-1 min-h-10 text-sm font-black text-slate-950 dark:text-white">{label}</div>
                <div className="mt-2 text-[10px] font-semibold leading-4 text-slate-500 dark:text-white/45">{detail}</div>
                {index < stages.length - 1 && <ArrowRight className="absolute -right-4 top-1/2 z-10 hidden h-5 w-5 -translate-y-1/2 text-cyan-500 dark:text-[#FFD36B] lg:block" />}
              </div>
            );
          })}
        </div>
      </div>

      <div className="grid gap-3 border-t border-slate-200 p-4 dark:border-white/8 lg:grid-cols-3">
        {[
          ['Break Source', vendor, 'Vendor evidence is the first failed trust hop.'],
          ['Root Cause', chain.issue, breakSignal.detail],
          ['Resolution Gate', breakSignal.standard, 'Require vendor attestation, PQC compatibility evidence, and migration retest before approval.'],
        ].map(([label, value, detail]) => (
          <div key={label} className="rounded-lg border border-slate-200 bg-white/70 p-3 dark:border-white/8 dark:bg-white/[0.03]">
            <div className="text-[8px] font-black uppercase tracking-[0.2em] text-slate-500 dark:text-white/35">{label}</div>
            <div className="mt-1 text-xs font-black text-slate-950 dark:text-white">{value}</div>
            <div className="mt-1 text-[10px] font-semibold leading-4 text-slate-500 dark:text-white/42">{detail}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function TrustChainView({ chains }: { chains: Chain[] }) {
  const location = useLocation();
  const dependencyQuery = useMemo(() => new URLSearchParams(location.search).get('dependency') || '', [location.search]);
  const [activeChain, setActiveChain] = useState(() => chains[0]?.name || '');

  useEffect(() => {
    if (!chains.length) {
      setActiveChain('');
      return;
    }
    if (dependencyQuery) {
      const normalized = dependencyQuery.toLowerCase();
      const matched = chains.find((item) => `${item.name} ${item.path.join(' ')} ${item.issue} ${item.impact}`.toLowerCase().includes(normalized));
      if (matched) {
        setActiveChain(matched.name);
        return;
      }
    }
    if (!chains.some((item) => item.name === activeChain)) setActiveChain(chains[0].name);
  }, [activeChain, chains, dependencyQuery]);

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
            <SupplyChainTrustFlow chain={chain} />
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

        {mode === 'dependency-map' && <DependencyMapView nodes={snapshot.trustNodes} chains={snapshot.chains} />}
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
