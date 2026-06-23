'use client';

import { useCallback, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import {
  AlertTriangle,
  BrainCircuit,
  Boxes,
  CalendarClock,
  Download,
  FlaskConical,
  GitBranch,
  Layers,
  RefreshCw,
  Rocket,
  RotateCcw,
  Sparkles,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import {
  Badge,
  EmptyState,
  HeaderButton,
  MetricCard,
  Panel,
  PrimaryButton,
  QuantumReadinessShell,
  SectionTitle,
  currencyFmt,
  integerFmt,
  riskTone,
  useQuantumReadiness,
  type QuantumReadinessSnapshot,
  AMBER,
  BLUE,
  EMERALD,
  GREEN,
  ORANGE,
  RED,
  GOLD,
} from '../_shared';

interface MigrationWave {
  wave: number;
  name: string;
  focus: string;
  color: string;
  assetCount: number;
  effortWeeks: number;
  approach: string;
  assets: QuantumReadinessSnapshot['topRiskAssets'];
}

function buildWaves(snapshot: QuantumReadinessSnapshot): MigrationWave[] {
  const assets = snapshot.topRiskAssets;
  const totalWeeks = Math.max(0, snapshot.estimates.migrationTimelineWeeks);
  const wave1 = assets.filter((a) => a.riskScore >= 70);
  const wave2 = assets.filter((a) => a.riskScore >= 40 && a.riskScore < 70);
  const wave3 = assets.filter((a) => a.riskScore < 40);

  const split = (list: typeof assets, ratio: number) => Math.max(list.length ? 1 : 0, Math.round(totalWeeks * ratio));

  return [
    {
      wave: 1,
      name: 'Critical & Internet-Facing',
      focus: 'Remediate highest-risk, externally exposed cryptography first.',
      color: RED,
      assetCount: wave1.length,
      effortWeeks: split(wave1, 0.5),
      approach: 'Hybrid X25519 + ML-KEM key establishment; ML-DSA signatures.',
      assets: wave1,
    },
    {
      wave: 2,
      name: 'High-Risk Core Services',
      focus: 'Migrate dependency-heavy internal services and PKI.',
      color: ORANGE,
      assetCount: wave2.length,
      effortWeeks: split(wave2, 0.3),
      approach: 'Hybrid certificates; staged crypto-agility rollout.',
      assets: wave2,
    },
    {
      wave: 3,
      name: 'Remaining & Long-Tail',
      focus: 'Complete coverage across low-risk and legacy assets.',
      color: GREEN,
      assetCount: wave3.length,
      effortWeeks: split(wave3, 0.2),
      approach: 'Full ML-KEM / ML-DSA cutover with rollback checkpoints.',
      assets: wave3,
    },
  ];
}

export default function AiMigrationAdvisorPage() {
  const navigate = useNavigate();
  const { snapshot, state, sseConnected, refresh, downloadJson } = useQuantumReadiness();
  const [generated, setGenerated] = useState(false);
  const [generating, setGenerating] = useState(false);

  const generate = useCallback(() => {
    if (!snapshot.hasData) return;
    setGenerating(true);
    window.setTimeout(() => {
      setGenerated(true);
      setGenerating(false);
    }, 450);
  }, [snapshot.hasData]);

  const waves = useMemo(() => buildWaves(snapshot), [snapshot]);
  const { scores, inventory, estimates } = snapshot;

  const kpis = [
    { label: 'Migration Complexity', value: integerFmt(scores.migrationComplexity), suffix: '/100', detail: scores.migrationComplexityLevel, color: riskTone(scores.migrationComplexity), ring: scores.migrationComplexity },
    { label: 'Migration Effort', value: integerFmt(scores.migrationEffort), suffix: '/100', detail: 'Remaining surface', color: GOLD, ring: scores.migrationEffort },
    { label: 'Est. Timeline', value: estimates.migrationTimelineWeeks ? `${integerFmt(estimates.migrationTimelineWeeks)}w` : '—', detail: 'To quantum-safe', color: BLUE, icon: CalendarClock },
    { label: 'Est. Cost', value: estimates.migrationCostUsd ? currencyFmt(estimates.migrationCostUsd) : '—', detail: 'Program investment', color: EMERALD, icon: Boxes },
    { label: 'Vulnerable Assets', value: integerFmt(inventory.quantumVulnerableAssets), detail: 'To migrate', color: RED, icon: AlertTriangle },
    { label: 'Hybrid In-Progress', value: integerFmt(inventory.hybridAssets), detail: 'Transitioning', color: AMBER, icon: Layers },
  ];

  const hybridRecs = [
    { from: 'RSA-2048 / RSA-4096', to: 'X25519 + ML-KEM-768 (hybrid KEM)', note: 'Key establishment' },
    { from: 'ECDSA P-256', to: 'Ed25519 + ML-DSA-65 (hybrid signature)', note: 'Authentication' },
    { from: 'ECDH', to: 'Hybrid ML-KEM key exchange', note: 'TLS 1.3 groups' },
    { from: 'SHA-1 / legacy hash', to: 'SHA3-256 / SHA-256', note: 'Integrity' },
  ];

  return (
    <QuantumReadinessShell
      title="AI Migration Advisor™"
      subtitle="Generates a dependency-aware migration roadmap, wave plan, prioritization and rollback strategy — ready to hand off to the Migration Planner or Sandbox."
      badge={generated ? <Badge color={EMERALD}>Roadmap Ready</Badge> : <Badge color={ORANGE}>AI Migration</Badge>}
      sseConnected={sseConnected}
      state={state}
      snapshot={snapshot}
      actions={
        <>
          <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>
            Refresh
          </HeaderButton>
          {generated ? (
            <>
              <HeaderButton icon={Sparkles} onClick={generate}>
                Regenerate
              </HeaderButton>
              <HeaderButton icon={Download} onClick={() => downloadJson('ai-migration-roadmap', { waves, estimates, scores })}>
                Export Roadmap
              </HeaderButton>
            </>
          ) : (
            <PrimaryButton icon={BrainCircuit} onClick={generate} disabled={!snapshot.hasData || generating}>
              {generating ? 'Generating…' : 'Generate Migration Advisory'}
            </PrimaryButton>
          )}
        </>
      }
    >
      <motion.section initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-6">
        {kpis.map((kpi) => (
          <div key={kpi.label}>
            <MetricCard {...kpi} />
          </div>
        ))}
      </motion.section>

      {generated ? (
        <>
          {/* Wave planner */}
          <Panel className="p-5">
            <SectionTitle suffix={<span className="text-[11px] text-white/40">Dependency-aware sequencing</span>}>Migration Wave Planner</SectionTitle>
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              {waves.map((wave) => (
                <div key={wave.wave} className="rounded-lg border border-white/8 bg-white/[0.025] p-4">
                  <div className="flex items-center justify-between">
                    <span className="inline-flex items-center gap-2">
                      <span className="grid h-7 w-7 place-items-center rounded-md border text-xs font-black" style={{ borderColor: `${wave.color}45`, color: wave.color, backgroundColor: `${wave.color}12` }}>
                        {wave.wave}
                      </span>
                      <span className="text-sm font-bold text-white">Wave {wave.wave}</span>
                    </span>
                    <Badge color={wave.color}>{integerFmt(wave.assetCount)} assets</Badge>
                  </div>
                  <div className="mt-3 text-xs font-bold text-white/85">{wave.name}</div>
                  <p className="mt-1 text-[11px] leading-snug text-white/50">{wave.focus}</p>
                  <div className="mt-3 grid grid-cols-2 gap-2 text-[11px]">
                    <div className="rounded border border-white/8 bg-black/20 px-2 py-1.5">
                      <div className="font-mono text-sm text-white">{integerFmt(wave.effortWeeks)}w</div>
                      <div className="text-[9px] uppercase tracking-wide text-white/40">Effort</div>
                    </div>
                    <div className="rounded border border-white/8 bg-black/20 px-2 py-1.5">
                      <div className="font-mono text-sm text-white">{integerFmt(wave.assetCount)}</div>
                      <div className="text-[9px] uppercase tracking-wide text-white/40">Assets</div>
                    </div>
                  </div>
                  <div className="mt-3 rounded border border-white/8 bg-black/20 px-2.5 py-2 text-[11px] leading-snug text-white/55">
                    <span className="font-bold text-white/70">Approach: </span>
                    {wave.approach}
                  </div>
                </div>
              ))}
            </div>
          </Panel>

          {/* Prioritized assets + hybrid recs */}
          <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
            <Panel className="p-5 xl:col-span-7">
              <SectionTitle>Asset Prioritization</SectionTitle>
              {snapshot.topRiskAssets.length ? (
                <div className="overflow-x-auto">
                  <table className="min-w-[560px] w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-white/8 text-[9px] uppercase tracking-[0.08em] text-white/35">
                        <th className="pb-3 font-black">#</th>
                        <th className="pb-3 font-black">Asset</th>
                        <th className="pb-3 font-black">Type</th>
                        <th className="pb-3 font-black">Risk</th>
                        <th className="pb-3 font-black">Wave</th>
                      </tr>
                    </thead>
                    <tbody>
                      {snapshot.topRiskAssets.map((asset, index) => {
                        const wave = asset.riskScore >= 70 ? 1 : asset.riskScore >= 40 ? 2 : 3;
                        const waveColor = wave === 1 ? RED : wave === 2 ? ORANGE : GREEN;
                        return (
                          <tr key={`${asset.asset}-${index}`} className="border-b border-white/5 text-white/70">
                            <td className="py-2.5 font-mono text-white/45">{index + 1}</td>
                            <td className="max-w-[180px] truncate py-2.5 font-medium text-white/82">{asset.asset}</td>
                            <td className="py-2.5">{asset.assetType}</td>
                            <td className="py-2.5 font-mono font-bold" style={{ color: riskTone(asset.riskScore) }}>
                              {integerFmt(asset.riskScore)}
                            </td>
                            <td className="py-2.5">
                              <span className="rounded px-1.5 py-0.5 text-[10px] font-black" style={{ color: waveColor, backgroundColor: `${waveColor}1a` }}>
                                Wave {wave}
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              ) : (
                <EmptyState label="No assets to prioritize." hint="Connect an asset inventory to sequence migration." />
              )}
            </Panel>

            <Panel className="p-5 xl:col-span-5">
              <SectionTitle suffix={<Badge color={EMERALD}>NIST PQC</Badge>}>Hybrid Migration Recommendations</SectionTitle>
              <div className="space-y-2.5">
                {hybridRecs.map((rec) => (
                  <div key={rec.from} className="rounded-md border border-white/8 bg-white/[0.025] p-3">
                    <div className="flex items-center gap-2 text-xs">
                      <span className="font-mono text-white/55 line-through decoration-red-400/60">{rec.from}</span>
                      <GitBranch className="h-3.5 w-3.5 text-white/30" />
                      <span className="font-mono font-bold text-emerald-300">{rec.to}</span>
                    </div>
                    <div className="mt-1 text-[10px] uppercase tracking-wide text-white/40">{rec.note}</div>
                  </div>
                ))}
              </div>
            </Panel>
          </section>

          {/* Rollback + handoff */}
          <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
            <Panel className="p-5 xl:col-span-7">
              <SectionTitle suffix={<RotateCcw className="h-4 w-4 text-white/40" />}>Rollback Strategy</SectionTitle>
              <div className="space-y-2.5 text-sm text-white/65">
                {[
                  'Each wave executes behind a feature flag with hybrid fallback to classical crypto.',
                  'Validation checkpoints confirm interoperability before decommissioning classical keys.',
                  'Per-asset rollback restores the prior cryptographic configuration within one change window.',
                  'Trust-chain monitoring detects handshake failures and auto-triggers rollback on threshold breach.',
                ].map((line, index) => (
                  <div key={line} className="flex items-start gap-3 rounded-md border border-white/8 bg-black/20 p-3">
                    <span className="grid h-6 w-6 shrink-0 place-items-center rounded border border-blue-400/30 bg-blue-500/10 text-[11px] font-black text-blue-300">{index + 1}</span>
                    <span className="text-xs leading-snug">{line}</span>
                  </div>
                ))}
              </div>
            </Panel>

            <Panel className="p-5 xl:col-span-5">
              <SectionTitle suffix={<AlertTriangle className="h-4 w-4 text-amber-300" />}>Compatibility Warnings</SectionTitle>
              <div className="space-y-2.5">
                {[
                  { level: 'high', text: 'Legacy clients without ML-KEM support require hybrid mode during transition.' },
                  { level: 'medium', text: 'HSM firmware must support PQC algorithms before key generation cutover.' },
                  { level: 'medium', text: 'Certificate chain size increases — verify MTU and buffer limits.' },
                ].map((warn) => {
                  const color = warn.level === 'high' ? ORANGE : GOLD;
                  return (
                    <div key={warn.text} className="flex items-start gap-2.5 rounded-md border p-3" style={{ borderColor: `${color}30`, backgroundColor: `${color}0d` }}>
                      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" style={{ color }} />
                      <span className="text-xs leading-snug text-white/70">{warn.text}</span>
                    </div>
                  );
                })}
              </div>
              <div className="mt-4 flex flex-col gap-2.5">
                <PrimaryButton icon={Rocket} onClick={() => navigate('/dashboard/migration-planner')}>
                  Send to Migration Planner
                </PrimaryButton>
                <HeaderButton icon={FlaskConical} onClick={() => navigate('/dashboard/migration-sandbox')}>
                  Open in Migration Sandbox
                </HeaderButton>
              </div>
            </Panel>
          </section>
        </>
      ) : (
        <Panel className="p-10">
          <div className="flex flex-col items-center justify-center gap-4 text-center">
            <span className="grid h-16 w-16 place-items-center rounded-full border border-orange-400/30 bg-orange-500/10 text-orange-300">
              <BrainCircuit className="h-8 w-8" />
            </span>
            <div>
              <div className="text-base font-bold text-white">{snapshot.hasData ? 'Generate a migration roadmap' : 'Assessment evidence required'}</div>
              <p className="mx-auto mt-1 max-w-md text-sm text-white/55">
                {snapshot.hasData
                  ? 'Produce dependency-aware migration waves, asset prioritization, hybrid recommendations and a rollback strategy from your assessment data.'
                  : 'Run a discovery scan first — the advisor sequences migration from real asset and risk evidence.'}
              </p>
            </div>
            {snapshot.hasData ? (
              <PrimaryButton icon={BrainCircuit} onClick={generate} disabled={generating}>
                {generating ? 'Generating…' : 'Generate Migration Advisory'}
              </PrimaryButton>
            ) : null}
          </div>
        </Panel>
      )}
    </QuantumReadinessShell>
  );
}
