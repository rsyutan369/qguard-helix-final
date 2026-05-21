import type { LucideIcon } from 'lucide-react';
import {
  AlertTriangle,
  CheckCircle2,
  CircuitBoard,
  KeyRound,
  Lock,
  Network,
  Radio,
  RotateCcw,
  Route,
  Server,
  Shuffle,
  Sparkles,
} from 'lucide-react';

type Metric = {
  label: string;
  value: string;
  detail: string;
  icon: LucideIcon;
  tone: 'gold' | 'green' | 'red' | 'orange';
};

type Profile = {
  service: string;
  classical: string;
  pqc: string;
  mode: string;
  compatibility: number;
  status: 'Healthy' | 'Canary' | 'Fallback Risk';
};

const GLASS_PANEL_CLASSES =
  'group relative overflow-hidden rounded-xl border border-[#FFD36B]/20 bg-[#0f1428]/45 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(255,211,107,0.03),0_0_40px_rgba(255,211,107,0.14)] transition-all duration-500 hover:-translate-y-1 hover:border-[#FFD36B]/70 hover:bg-[#0f1428]/65 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.3),inset_0_-24px_60px_rgba(255,211,107,0.15),0_8px_30px_rgba(0,0,0,0.5),0_0_60px_rgba(255,211,107,0.5),0_0_120px_rgba(255,211,107,0.2)] hover:z-10 before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FFF4C0]/70 before:to-transparent before:transition-all before:duration-500 group-hover:before:opacity-100 group-hover:before:shadow-[0_0_15px_rgba(255,211,107,0.9)] group-hover:before:via-[#FFF4C0] after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-48 after:w-48 after:rounded-full after:bg-[#FFD36B]/10 after:blur-3xl after:transition-all after:duration-500 group-hover:after:opacity-100 group-hover:after:bg-[#FFD36B]/25 group-hover:after:blur-[36px] text-white';

const metrics: Metric[] = [
  { label: 'Hybrid Services', value: '86', detail: 'active dual-stack endpoints', icon: Shuffle, tone: 'gold' },
  { label: 'Handshake Success', value: '99.2%', detail: 'last 24 hours', icon: CheckCircle2, tone: 'green' },
  { label: 'Fallback Events', value: '7', detail: 'requires review', icon: AlertTriangle, tone: 'orange' },
  { label: 'Classical Only', value: '12', detail: 'migration required', icon: Lock, tone: 'red' },
];

const profiles: Profile[] = [
  { service: 'api-gateway-prod', classical: 'X25519', pqc: 'ML-KEM-768', mode: 'Hybrid TLS 1.3', compatibility: 98, status: 'Healthy' },
  { service: 'auth-service-jwt', classical: 'RS256', pqc: 'ML-DSA-44', mode: 'Dual-sign', compatibility: 91, status: 'Canary' },
  { service: 'file-transfer-sftp', classical: 'ECDH-P256', pqc: 'ML-KEM-1024', mode: 'SSH hybrid KEX', compatibility: 74, status: 'Fallback Risk' },
  { service: 'internal-ca', classical: 'ECDSA-P384', pqc: 'ML-DSA-65', mode: 'PQC chain pilot', compatibility: 88, status: 'Canary' },
  { service: 'vault-wrap-agent', classical: 'AES-256-GCM', pqc: 'KYBER-768 wrap', mode: 'Envelope hybrid', compatibility: 96, status: 'Healthy' },
];

const rolloutRings = [
  { label: 'Lab', progress: 100, services: 18 },
  { label: 'Canary', progress: 82, services: 24 },
  { label: 'Production Ring 1', progress: 61, services: 31 },
  { label: 'Production Ring 2', progress: 35, services: 44 },
];

const compatibility = [
  { client: 'Modern browsers', value: 99 },
  { client: 'Mobile SDKs', value: 94 },
  { client: 'Partner APIs', value: 77 },
  { client: 'Legacy Java 8', value: 58 },
  { client: 'Embedded devices', value: 46 },
];

function toneClass(tone: Metric['tone']) {
  switch (tone) {
    case 'red':
      return 'border-red-400/30 bg-red-500/10 text-red-300';
    case 'orange':
      return 'border-orange-400/30 bg-orange-500/10 text-orange-300';
    case 'green':
      return 'border-emerald-400/30 bg-emerald-500/10 text-emerald-300';
    default:
      return 'border-gold/30 bg-gold/10 text-gold';
  }
}

function statusClass(status: Profile['status']) {
  if (status === 'Healthy') return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300';
  if (status === 'Canary') return 'border-gold/30 bg-gold/10 text-gold';
  return 'border-orange-500/30 bg-orange-500/10 text-orange-300';
}

function SectionTitle({ icon: Icon, children }: { icon: LucideIcon; children: string }) {
  return (
    <h2 className="relative z-10 flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-white/60">
      <Icon className="h-4 w-4 text-gold" />
      {children}
    </h2>
  );
}

export default function HybridCrypto() {
  return (
    <div className="p-4 lg:p-8 space-y-6 animate-in fade-in duration-700 text-white">
      <header className="flex flex-col gap-6 xl:flex-row xl:items-end xl:justify-between">
        <div>
          <div className="mb-2 flex items-center gap-3">
            <div className="rounded bg-gold/10 border border-gold/20 p-2">
              <Shuffle className="h-6 w-6 text-gold drop-shadow-[0_0_6px_rgba(255,211,107,0.4)]" />
            </div>
            <h1 className="text-3xl font-black uppercase leading-none tracking-tight text-white">
              Hybrid <span className="text-gold">Crypto</span>
            </h1>
          </div>
          <p className="max-w-3xl text-sm font-medium text-white/50">
            Manage dual classical and post-quantum cryptographic deployments with compatibility, fallback, and rollout controls.
          </p>
        </div>
        <button className="flex items-center gap-2 rounded-lg border border-gold/30 bg-gold/10 px-4 py-2.5 text-[10px] font-black uppercase tracking-wider text-gold transition hover:border-gold/70 hover:bg-gold/20">
          <Sparkles className="h-4 w-4" />
          Create Hybrid Profile
        </button>
      </header>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        {metrics.map((metric) => {
          const Icon = metric.icon;
          return (
            <section key={metric.label} className={`${GLASS_PANEL_CLASSES} p-5`}>
              <div className="relative z-10 flex items-center justify-between gap-4">
                <div>
                  <span className="block text-[9px] font-bold uppercase tracking-widest text-white/40">{metric.label}</span>
                  <span className="mt-3 block text-3xl font-black leading-none text-white">{metric.value}</span>
                  <span className="mt-3 block text-[10px] font-black uppercase tracking-wider text-white/35">{metric.detail}</span>
                </div>
                <div className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-full border ${toneClass(metric.tone)}`}>
                  <Icon className="h-7 w-7" />
                </div>
              </div>
            </section>
          );
        })}
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1.55fr)_minmax(360px,0.95fr)]">
        <section className={`${GLASS_PANEL_CLASSES} p-6`}>
          <SectionTitle icon={CircuitBoard}>Hybrid Deployment Profiles</SectionTitle>
          <div className="relative z-10 mt-5 overflow-x-auto">
            <table className="w-full min-w-[860px] border-collapse text-left">
              <thead>
                <tr className="border-b border-gold/15 bg-gold/[0.03]">
                  {['Service', 'Classical', 'PQC', 'Mode', 'Compatibility', 'Status'].map((header) => (
                    <th key={header} className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-white/40">{header}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {profiles.map((profile) => (
                  <tr key={profile.service} className="transition hover:bg-gold/[0.04]">
                    <td className="p-4 font-bold text-white/85">{profile.service}</td>
                    <td className="p-4 font-mono text-xs text-white/55">{profile.classical}</td>
                    <td className="p-4 font-mono text-xs text-gold">{profile.pqc}</td>
                    <td className="p-4 text-xs font-semibold text-white/60">{profile.mode}</td>
                    <td className="p-4">
                      <div className="flex items-center gap-3">
                        <div className="h-2 w-24 overflow-hidden rounded-full bg-white/5">
                          <div className="h-full rounded-full bg-gold" style={{ width: `${profile.compatibility}%` }} />
                        </div>
                        <span className="font-mono text-xs text-white/55">{profile.compatibility}%</span>
                      </div>
                    </td>
                    <td className="p-4">
                      <span className={`rounded border px-2 py-1 text-[9px] font-black uppercase tracking-wider ${statusClass(profile.status)}`}>{profile.status}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <aside className="space-y-6">
          <section className={`${GLASS_PANEL_CLASSES} p-6`}>
            <SectionTitle icon={Route}>Rollout Rings</SectionTitle>
            <div className="relative z-10 mt-5 space-y-5">
              {rolloutRings.map((ring) => (
                <div key={ring.label}>
                  <div className="mb-2 flex items-center justify-between">
                    <span className="text-xs font-bold text-white/70">{ring.label}</span>
                    <span className="text-xs text-white/35">{ring.services} services</span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-white/5">
                    <div className="h-full rounded-full bg-gradient-to-r from-gold/40 to-gold shadow-[0_0_10px_rgba(255,211,107,0.55)]" style={{ width: `${ring.progress}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section className={`${GLASS_PANEL_CLASSES} p-6`}>
            <SectionTitle icon={Radio}>Client Compatibility</SectionTitle>
            <div className="relative z-10 mt-5 space-y-4">
              {compatibility.map((item) => (
                <div key={item.client} className="grid grid-cols-[130px_1fr_40px] items-center gap-3">
                  <span className="text-xs font-semibold text-white/60">{item.client}</span>
                  <div className="h-2 overflow-hidden rounded-full bg-white/5">
                    <div className="h-full rounded-full bg-gold" style={{ width: `${item.value}%` }} />
                  </div>
                  <span className="text-right font-mono text-xs text-white/45">{item.value}%</span>
                </div>
              ))}
            </div>
          </section>
        </aside>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-4">
        {[
          { icon: Network, title: 'Handshake Policy', detail: 'Prefer hybrid KEM, permit classical fallback only by exception.' },
          { icon: RotateCcw, title: 'Fallback Guard', detail: 'Fallback events generate drift tickets and owner review.' },
          { icon: KeyRound, title: 'Key Rotation', detail: 'PQC and classical material rotate through the same lifecycle.' },
          { icon: Server, title: 'Deployment Gate', detail: 'Canary success is required before production ring promotion.' },
        ].map((item) => {
          const Icon = item.icon;
          return (
            <section key={item.title} className={`${GLASS_PANEL_CLASSES} p-5`}>
              <div className="relative z-10">
                <Icon className="h-6 w-6 text-gold" />
                <div className="mt-4 text-sm font-black text-white/85">{item.title}</div>
                <div className="mt-2 text-xs font-semibold leading-relaxed text-white/40">{item.detail}</div>
              </div>
            </section>
          );
        })}
      </div>
    </div>
  );
}
