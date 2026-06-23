'use client';

import { useCallback, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import {
  Activity,
  CheckCircle2,
  Cpu,
  Download,
  FlaskConical,
  GitCompare,
  Network,
  Play,
  RefreshCw,
  RotateCcw,
  ShieldCheck,
  TrendingDown,
  Workflow,
} from 'lucide-react';
import {
  Badge,
  EmptyState,
  HeaderButton,
  Panel,
  PrimaryButton,
  QuantumReadinessShell,
  Ring,
  SectionTitle,
  integerFmt,
  longDate,
  percentLabel,
  riskTone,
  useQuantumReadiness,
  type QuantumReadinessSnapshot,
  AMBER,
  BLUE,
  CYAN,
  EMERALD,
  GREEN,
  ORANGE,
  RED,
  VIOLET,
} from '../_shared';

type SimType = 'ml-kem' | 'ml-dsa' | 'hybrid-tls' | 'pki' | 'identity';

interface SimSpec {
  id: SimType;
  name: string;
  icon: typeof Cpu;
  color: string;
  scope: string;
  perfOverhead: number; // % projected
  compatBase: number; // 0-100
  riskWeight: number; // share of risk addressed
}

const SIMULATIONS: SimSpec[] = [
  { id: 'ml-kem', name: 'ML-KEM Migration', icon: Cpu, color: BLUE, scope: 'Key establishment (FIPS 203)', perfOverhead: 4, compatBase: 86, riskWeight: 0.35 },
  { id: 'ml-dsa', name: 'ML-DSA Migration', icon: ShieldCheck, color: VIOLET, scope: 'Digital signatures (FIPS 204)', perfOverhead: 7, compatBase: 82, riskWeight: 0.3 },
  { id: 'hybrid-tls', name: 'Hybrid TLS', icon: Network, color: CYAN, scope: 'TLS 1.3 hybrid groups', perfOverhead: 3, compatBase: 91, riskWeight: 0.25 },
  { id: 'pki', name: 'PKI Modernization', icon: Workflow, color: EMERALD, scope: 'Certificate authority chain', perfOverhead: 6, compatBase: 78, riskWeight: 0.2 },
  { id: 'identity', name: 'Identity Migration', icon: Activity, color: ORANGE, scope: 'Tokens & identity providers', perfOverhead: 5, compatBase: 80, riskWeight: 0.18 },
];

interface SimResult {
  id: string;
  type: SimType;
  name: string;
  ranAt: string;
  scopeAssets: number;
  riskBefore: number;
  riskAfter: number;
  riskReduction: number;
  compatibility: number;
  performanceOverhead: number;
  trustChainImpact: number;
  failureProbability: number;
  rollback: string;
  color: string;
}

function runSimulation(spec: SimSpec, snapshot: QuantumReadinessSnapshot): SimResult {
  const { scores, inventory } = snapshot;
  const scopeAssets = Math.max(1, Math.round(inventory.quantumVulnerableAssets * (spec.riskWeight + 0.4)));
  const riskBefore = scores.quantumRisk;
  // Projected residual risk after applying this control to its weighted share.
  const reductionPoints = Math.round(riskBefore * spec.riskWeight);
  const riskAfter = Math.max(0, riskBefore - reductionPoints);
  const complexityPenalty = Math.round(scores.migrationComplexity * 0.12);
  const compatibility = Math.max(40, Math.min(99, spec.compatBase - complexityPenalty));
  const trustChainImpact = Math.max(0, Math.min(100, Math.round((100 - compatibility) * 0.8 + spec.perfOverhead)));
  const failureProbability = Math.max(2, Math.min(60, Math.round((100 - compatibility) * 0.5 + complexityPenalty)));
  return {
    id: `sim-${spec.id}-${Date.now()}`,
    type: spec.id,
    name: spec.name,
    ranAt: new Date().toISOString(),
    scopeAssets,
    riskBefore,
    riskAfter,
    riskReduction: reductionPoints,
    compatibility,
    performanceOverhead: spec.perfOverhead,
    trustChainImpact,
    failureProbability,
    rollback:
      failureProbability > 35
        ? 'High failure probability — stage behind hybrid fallback with automatic rollback.'
        : failureProbability > 15
          ? 'Moderate risk — validate at checkpoint before decommissioning classical keys.'
          : 'Low risk — proceed with standard rollback checkpoint per wave.',
    color: spec.color,
  };
}

export default function DigitalTwinPage() {
  const { snapshot, state, sseConnected, refresh, downloadJson } = useQuantumReadiness();
  const [selected, setSelected] = useState<SimType>('ml-kem');
  const [result, setResult] = useState<SimResult | null>(null);
  const [history, setHistory] = useState<SimResult[]>([]);
  const [running, setRunning] = useState(false);
  const [compare, setCompare] = useState<string[]>([]);

  const spec = useMemo(() => SIMULATIONS.find((s) => s.id === selected)!, [selected]);

  const run = useCallback(() => {
    if (!snapshot.hasData) return;
    setRunning(true);
    window.setTimeout(() => {
      const res = runSimulation(spec, snapshot);
      setResult(res);
      setHistory((prev) => [res, ...prev].slice(0, 12));
      setRunning(false);
    }, 600);
  }, [spec, snapshot]);

  const toggleCompare = useCallback((id: string) => {
    setCompare((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id].slice(-3)));
  }, []);

  const compareRows = useMemo(() => history.filter((h) => compare.includes(h.id)), [history, compare]);

  return (
    <QuantumReadinessShell
      title="Quantum Readiness Digital Twin™"
      subtitle="Simulate PQC migration impact before real-world execution — compatibility, performance, trust-chain impact, risk reduction and failure prediction across modeled scenarios."
      badge={<Badge color={AMBER}>Simulation Engine</Badge>}
      sseConnected={sseConnected}
      state={state}
      snapshot={snapshot}
      actions={
        <>
          <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>
            Refresh Scope
          </HeaderButton>
          {result ? (
            <HeaderButton icon={Download} onClick={() => downloadJson('digital-twin-simulation', result)}>
              Export Result
            </HeaderButton>
          ) : null}
        </>
      }
    >
      {/* Simulation selector */}
      <Panel className="p-5">
        <SectionTitle suffix={<span className="text-[11px] text-white/40">Select a scenario to model</span>}>Simulation Selector</SectionTitle>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-5">
          {SIMULATIONS.map((sim) => {
            const Icon = sim.icon;
            const active = selected === sim.id;
            return (
              <button
                key={sim.id}
                type="button"
                onClick={() => setSelected(sim.id)}
                className={`rounded-lg border p-4 text-left transition ${
                  active ? 'border-blue-400/50 bg-blue-500/10' : 'border-white/8 bg-white/[0.025] hover:border-blue-400/35'
                }`}
              >
                <span className="grid h-9 w-9 place-items-center rounded-md border" style={{ borderColor: `${sim.color}40`, color: sim.color, backgroundColor: `${sim.color}12` }}>
                  <Icon className="h-4 w-4" />
                </span>
                <div className="mt-2.5 text-sm font-bold text-white">{sim.name}</div>
                <div className="text-[10px] text-white/45">{sim.scope}</div>
              </button>
            );
          })}
        </div>
        <div className="mt-4 flex items-center justify-between gap-3">
          <p className="text-[11px] text-white/45">
            Modeling <strong className="text-white/70">{spec.name}</strong> across{' '}
            <strong className="text-white/70">{integerFmt(snapshot.inventory.quantumVulnerableAssets)}</strong> quantum-vulnerable assets in scope.
          </p>
          <PrimaryButton icon={Play} onClick={run} disabled={!snapshot.hasData || running}>
            {running ? 'Simulating…' : 'Run Simulation'}
          </PrimaryButton>
        </div>
      </Panel>

      {/* Result */}
      {result ? (
        <motion.section initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Panel className="p-5 xl:col-span-4">
            <SectionTitle>Risk Reduction</SectionTitle>
            <div className="flex items-center gap-5">
              <Ring value={result.riskBefore ? (result.riskReduction / result.riskBefore) * 100 : 0} color={EMERALD} size={120} stroke={12}>
                <div>
                  <div className="text-3xl font-semibold text-white">-{integerFmt(result.riskReduction)}</div>
                  <div className="text-[9px] font-bold uppercase tracking-wide text-white/45">Risk pts</div>
                </div>
              </Ring>
              <div className="space-y-2 text-sm">
                <div className="flex items-center gap-2">
                  <span className="text-white/45">Before</span>
                  <span className="font-mono font-bold" style={{ color: riskTone(result.riskBefore) }}>
                    {integerFmt(result.riskBefore)}
                  </span>
                  <TrendingDown className="h-4 w-4 text-emerald-400" />
                  <span className="text-white/45">After</span>
                  <span className="font-mono font-bold" style={{ color: riskTone(result.riskAfter) }}>
                    {integerFmt(result.riskAfter)}
                  </span>
                </div>
                <div className="text-[11px] text-white/45">{integerFmt(result.scopeAssets)} assets affected</div>
              </div>
            </div>
          </Panel>

          <Panel className="p-5 xl:col-span-8">
            <SectionTitle suffix={<Badge color={result.color}>{result.name}</Badge>}>Projected Impact</SectionTitle>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <ImpactStat label="Compatibility" value={percentLabel(result.compatibility)} color={result.compatibility >= 80 ? GREEN : result.compatibility >= 60 ? AMBER : RED} icon={CheckCircle2} />
              <ImpactStat label="Perf. Overhead" value={`+${integerFmt(result.performanceOverhead)}%`} color={result.performanceOverhead <= 5 ? GREEN : AMBER} icon={Cpu} />
              <ImpactStat label="Trust-Chain Impact" value={percentLabel(result.trustChainImpact)} color={riskTone(result.trustChainImpact)} icon={Network} />
              <ImpactStat label="Failure Probability" value={percentLabel(result.failureProbability)} color={riskTone(result.failureProbability)} icon={Activity} />
            </div>
            <div className="mt-4 flex items-start gap-2.5 rounded-md border border-white/8 bg-black/20 p-3">
              <RotateCcw className="mt-0.5 h-4 w-4 shrink-0 text-blue-300" />
              <div>
                <div className="text-[10px] font-black uppercase tracking-wide text-white/45">Rollback Recommendation</div>
                <div className="text-xs leading-snug text-white/70">{result.rollback}</div>
              </div>
            </div>
          </Panel>
        </motion.section>
      ) : (
        <Panel className="p-10">
          <div className="flex flex-col items-center justify-center gap-3 text-center">
            <span className="grid h-16 w-16 place-items-center rounded-full border border-amber-400/30 bg-amber-500/10 text-amber-300">
              <FlaskConical className="h-8 w-8" />
            </span>
            <div className="text-base font-bold text-white">{snapshot.hasData ? 'Run a simulation to model migration impact' : 'Assessment evidence required'}</div>
            <p className="mx-auto max-w-md text-sm text-white/55">
              {snapshot.hasData
                ? 'Select a scenario above and run the digital twin to project risk reduction, compatibility and failure probability before touching production.'
                : 'Run a discovery scan first — simulations model impact against your real asset scope.'}
            </p>
          </div>
        </Panel>
      )}

      {/* History + compare */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-5">
          <SectionTitle suffix={<span className="text-[11px] text-white/40">{history.length} runs</span>}>Simulation History</SectionTitle>
          {history.length ? (
            <div className="space-y-2">
              {history.map((item) => (
                <div
                  key={item.id}
                  className={`flex items-center justify-between gap-2 rounded-md border px-3 py-2 text-xs transition ${
                    compare.includes(item.id) ? 'border-cyan-400/45 bg-cyan-500/10' : 'border-white/8 bg-black/20'
                  }`}
                >
                  <button type="button" onClick={() => setResult(item)} className="min-w-0 text-left">
                    <span className="block truncate font-semibold text-white/80">{item.name}</span>
                    <span className="text-[10px] text-white/40">{longDate(item.ranAt)}</span>
                  </button>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-emerald-300">-{integerFmt(item.riskReduction)}</span>
                    <button
                      type="button"
                      onClick={() => toggleCompare(item.id)}
                      className={`rounded border px-1.5 py-0.5 text-[10px] font-bold transition ${
                        compare.includes(item.id) ? 'border-cyan-400/45 text-cyan-200' : 'border-white/15 text-white/45 hover:text-white'
                      }`}
                    >
                      <GitCompare className="h-3 w-3" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState label="No simulations run yet." />
          )}
        </Panel>

        <Panel className="p-5 xl:col-span-7">
          <SectionTitle suffix={<Badge color={CYAN}>{compareRows.length}/3 selected</Badge>}>Compare Simulations</SectionTitle>
          {compareRows.length ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-white/8 text-[9px] uppercase tracking-[0.08em] text-white/35">
                    <th className="pb-3 font-black">Scenario</th>
                    <th className="pb-3 font-black">Risk ↓</th>
                    <th className="pb-3 font-black">Compat.</th>
                    <th className="pb-3 font-black">Perf.</th>
                    <th className="pb-3 font-black">Failure</th>
                  </tr>
                </thead>
                <tbody>
                  {compareRows.map((row) => (
                    <tr key={row.id} className="border-b border-white/5 text-white/70">
                      <td className="py-2.5 font-medium text-white/82">{row.name}</td>
                      <td className="py-2.5 font-mono text-emerald-300">-{integerFmt(row.riskReduction)}</td>
                      <td className="py-2.5 font-mono" style={{ color: row.compatibility >= 80 ? GREEN : AMBER }}>
                        {percentLabel(row.compatibility)}
                      </td>
                      <td className="py-2.5 font-mono text-white/70">+{integerFmt(row.performanceOverhead)}%</td>
                      <td className="py-2.5 font-mono" style={{ color: riskTone(row.failureProbability) }}>
                        {percentLabel(row.failureProbability)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState label="Select up to 3 runs to compare." hint="Use the compare toggle in simulation history." />
          )}
        </Panel>
      </section>
    </QuantumReadinessShell>
  );
}

function ImpactStat({ label, value, color, icon: Icon }: { label: string; value: string; color: string; icon: typeof Cpu }) {
  return (
    <div className="rounded-md border border-white/8 bg-white/[0.025] p-3">
      <span className="grid h-8 w-8 place-items-center rounded-md border" style={{ borderColor: `${color}40`, color, backgroundColor: `${color}12` }}>
        <Icon className="h-4 w-4" />
      </span>
      <div className="mt-2 text-lg font-semibold" style={{ color }}>
        {value}
      </div>
      <div className="text-[10px] font-bold uppercase tracking-wide text-white/45">{label}</div>
    </div>
  );
}
