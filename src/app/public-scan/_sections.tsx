/**
 * Public Quantum Exposure Assessment™ — result sections.
 *
 * Every value rendered here comes from the live report returned by
 * /api/v1/public-scan. There are no placeholder metrics: if the scanner could
 * not observe something, the section renders an explicit Unknown with the
 * reason, which is itself part of the product story.
 */
import React from 'react';
import { motion } from 'motion/react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  Boxes,
  Braces,
  ChevronDown,
  Clock,
  Cpu,
  Database,
  FileText,
  Fingerprint,
  Gauge as GaugeIcon,
  Globe2,
  HelpCircle,
  KeyRound,
  Layers,
  Lock,
  Radar,
  ScrollText,
  ShieldCheck,
  Sparkles,
  Timer,
  TrendingUp,
  Workflow,
  Zap,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import type { PublicScanReport } from '@/lib/scanner/public-scan/types';
import { GAUGE_ARC_BANDS, RATING_TIERS, RISK_COLOR, scoreToGrade } from '@/lib/scanner/public-scan/grading-model';
import {
  ACCENT,
  CountUp,
  Gauge,
  LockedPanel,
  Meter,
  Modal,
  Panel,
  Reveal,
  Ring,
  SectionLabel,
  StatusPill,
  scoreColor,
} from './_ui';

/* ================================================================ executive = */

export function ExecutiveSummary({ report }: { report: PublicScanReport }) {
  const { executive } = report;
  const [gradingOpen, setGradingOpen] = React.useState(false);

  const cards = [
    {
      label: 'Overall Security',
      big: executive.grade,
      sub: executive.gradeLabel,
      detail: executive.gradeDetail,
      // A withheld grade shows evidence coverage, not a score it did not earn.
      // The ring/color is the SAME score and SAME color the grade badge uses
      // (executive.encryptionScore / executive.gradeColor) — not a different
      // heuristic, so the ring can never disagree with the letter next to it.
      ring: executive.gradeable ? executive.encryptionScore : executive.evidenceCoverage,
      color: executive.gradeColor,
      // Rendered only on this first card — see the map below.
      footer: (
        <button
          type="button"
          onClick={() => setGradingOpen(true)}
          className="mt-2.5 inline-flex items-center gap-1.5 text-[10.5px] font-bold text-cyan-300/90 underline decoration-cyan-400/30 underline-offset-2 transition-colors hover:text-cyan-200"
        >
          <HelpCircle className="h-3 w-3" /> How the Grading Works
        </button>
      ),
    },
    /* Every branch here is gated on the readiness having been MEASURED. The
       unconditional version rendered "0% · Limited PQ readiness · Plan migration
       soon — no hybrid key agreement offered" for endpoints where no handshake
       ever completed: a percentage, a rating and a recommendation, none of which
       rested on an observation. */
    {
      label: 'Post-Quantum Readiness',
      big: executive.postQuantumReadiness === null ? '—' : `${executive.postQuantumReadiness}%`,
      sub:
        executive.postQuantumReadiness === null
          ? 'Not measured'
          : executive.postQuantumReadiness >= 60
            ? 'Hybrid observed'
            : 'Limited PQ readiness',
      detail:
        executive.postQuantumReadiness === null
          ? 'Named key-agreement groups could not be offered, so readiness was not scored.'
          : executive.postQuantumReadiness >= 60
            ? 'Hybrid ML-KEM key agreement accepted at the edge.'
            : 'Plan migration soon — no hybrid key agreement offered.',
      ring: executive.postQuantumReadiness,
      color: scoreColor(executive.postQuantumReadiness),
    },
    {
      label: 'Business Risk',
      big: executive.businessRisk,
      sub: 'From public evidence',
      detail: executive.businessRiskDetail,
      ring: null,
      // One risk-level palette, defined once in the grading model (every
      // RiskBand value covered explicitly — no silent fallthrough).
      color: RISK_COLOR[executive.businessRisk],
    },
    {
      label: 'Migration Complexity',
      big: executive.migrationComplexity,
      sub: 'Public footprint',
      detail: executive.migrationComplexityDetail,
      ring: null,
      color: executive.migrationComplexity === 'Unknown' ? ACCENT.slate : ACCENT.violet,
    },
    {
      label: 'Confidence Score',
      big: `${executive.confidence}%`,
      sub: 'Evidence quality',
      detail: executive.confidenceDetail,
      ring: executive.confidence,
      color: ACCENT.blue,
    },
  ];

  return (
    <Panel className="overflow-hidden">
      <div className="border-b border-white/[0.06] px-5 py-3">
        <SectionLabel>Executive Summary</SectionLabel>
      </div>
      <div className="grid grid-cols-[minmax(0,1fr)] divide-y divide-white/[0.06] sm:grid-cols-2 sm:divide-y-0 lg:grid-cols-5">
        {cards.map((card, index) => (
          <div
            key={card.label}
            className={cn(
              'px-5 py-5 sm:border-b sm:border-white/[0.06] lg:border-b-0',
              index > 0 && 'lg:border-l lg:border-white/[0.06]',
              index % 2 === 1 && 'sm:border-l sm:border-white/[0.06]',
              index >= 3 && 'sm:border-b-0',
            )}
          >
            <p className="font-mono text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500">
              {card.label}
            </p>
            <div className="mt-3 flex items-center justify-between gap-3">
              <div className="min-w-0">
                <motion.p
                  initial={{ opacity: 0, y: 8 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.5, delay: index * 0.06 }}
                  className="truncate text-[2rem] font-black leading-none tracking-tight"
                  style={{ color: card.color }}
                >
                  {card.big}
                </motion.p>
                <p className="mt-1.5 truncate text-xs font-semibold text-slate-300">{card.sub}</p>
              </div>
              {card.ring !== null && (
                <Ring value={card.ring} size={54} stroke={4} color={card.color} />
              )}
            </div>
            <p className="mt-2.5 text-[11px] leading-snug text-slate-500">{card.detail}</p>
            {'footer' in card && card.footer}
          </div>
        ))}
      </div>

      <GradingReferenceModal open={gradingOpen} onClose={() => setGradingOpen(false)} />
    </Panel>
  );
}

/** "How the Grading Works" — the exact methodology document this report is
 * computed from (same 12 weighted categories, same score thresholds, same
 * risk-level vocabulary), so a user can verify the live result against it. */
function GradingReferenceModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Modal open={open} onClose={onClose} title="How the Grading Works" maxWidthClassName="max-w-6xl">
      <div className="bg-[#04060e] p-3 sm:p-5">
        <img
          src="/downloads/Security_Grade.png"
          alt="QGuard Helix security grading reference: grade hierarchy, score-to-grade mapping, weighted scoring model and risk-level reference"
          className="w-full rounded-lg border border-white/[0.06]"
        />
      </div>
      <p className="border-t border-white/[0.06] px-5 py-3.5 text-[11.5px] leading-relaxed text-slate-500">
        This is the exact methodology this assessment computes from — the same 12 weighted categories, the same
        score-to-grade thresholds and the same risk-level vocabulary used throughout this report.
      </p>
    </Modal>
  );
}

/* =========================================================== encryption ==== */

export function EncryptionScore({ report }: { report: PublicScanReport }) {
  const { executive, scoreComponents } = report;
  const [open, setOpen] = React.useState(false);

  // Real weight totals from the published model — not a hand-typed "60/40"
  // caption. Classical = the 10 non-PQ categories; PQ = the dedicated
  // Post-Quantum Readiness category. Both are computed here so the caption can
  // never drift from CLASSICAL_CATEGORY_KEYS in grading-model.ts.
  const classicalWeight = scoreComponents
    .filter((component) => component.key !== 'cryptographic-algorithms' && component.key !== 'post-quantum-readiness')
    .reduce((sum, component) => sum + component.weight, 0);
  const pqWeight = scoreComponents.find((component) => component.key === 'post-quantum-readiness')?.weight ?? 0;
  /* `scoreToGrade` answers "what rating does THIS score earn". There is no score
     to rate when the assessment is not gradeable, so the rating word is withheld
     rather than defaulted — a "Critical" label under a withheld grade is the
     report contradicting itself in the space of two panels. */
  const classicalRating = executive.classicalScore === null ? null : scoreToGrade(executive.classicalScore);
  const pqMeasured = executive.postQuantumReadiness !== null;

  return (
    <Panel className="flex h-full flex-col overflow-hidden">
      <div className="border-b border-white/[0.06] px-5 py-3">
        <SectionLabel>Encryption Score</SectionLabel>
      </div>

      {/* The gauge owns its own readout, so the two flanking scores sit in
          their own columns and nothing is layered over the pointer sweep. */}
      <div className="grid grid-cols-[minmax(0,1fr)] items-center gap-x-4 gap-y-6 px-5 pt-6 sm:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)]">
        <div className="text-center sm:text-left">
          <p className="font-mono text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500">
            Classical Encryption
          </p>
          <CountUp
            value={executive.classicalScore}
            className="mt-2 block text-5xl font-black tracking-tight"
          />
          <p
            className="mt-1 text-xs font-semibold"
            style={{ color: classicalRating?.color ?? ACCENT.slate }}
          >
            {classicalRating?.rating ?? 'Not measured'}
          </p>
          <Meter
            value={executive.classicalScore}
            color={classicalRating?.color}
            className="mx-auto mt-3 max-w-[9rem] sm:mx-0"
          />
          <p className="mt-1.5 font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-600">
            {classicalWeight}% of the weighted model
          </p>
        </div>

        {/* Same score, same color as the Overall Security badge — the gauge and
            the grade letter are two views of one number, never two heuristics.
            The arc itself is drawn from GAUGE_ARC_BANDS (the score-to-grade
            table re-ordered), so the color under the pointer is always the
            color scoreToGrade() assigned that exact score. */}
        <Gauge
          value={executive.encryptionScore}
          size={268}
          band={executive.gradeable ? executive.gradeLabel : executive.encryptionBand}
          bandColor={executive.gradeColor}
          bands={GAUGE_ARC_BANDS}
        />

        <div className="text-center sm:text-right">
          <p className="font-mono text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500">
            Post-Quantum Readiness
          </p>
          <CountUp
            value={executive.postQuantumReadiness}
            className="mt-2 block text-5xl font-black tracking-tight"
          />
          <p
            className="mt-1 text-xs font-semibold"
            style={{ color: scoreColor(executive.postQuantumReadiness) }}
          >
            {!pqMeasured ? 'Not measured' : executive.postQuantumReadiness! >= 60 ? 'Hybrid ready' : 'Limited'}
          </p>
          <Meter
            value={executive.postQuantumReadiness}
            className="mx-auto mt-3 max-w-[9rem] sm:mx-0 sm:ml-auto"
          />
          <p className="mt-1.5 font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-600">
            {pqWeight}% of the weighted model
          </p>
        </div>
      </div>

      {/* Rating legend — the exact 6 ratings a grade can carry (Elite through
          Critical), matched to the active one by string equality against
          executive.gradeLabel. Not a re-derived score range: the chip that
          lights up is guaranteed to be the same word the gauge and the grade
          badge are already showing, because all three read gradeLabel. */}
      <div className="mt-5 flex flex-wrap items-center justify-center gap-x-4 gap-y-1.5 px-5">
        {RATING_TIERS.map((tier) => {
          const active = executive.gradeable && tier.rating === executive.gradeLabel;
          return (
            <span
              key={tier.rating}
              className={cn(
                'flex items-center gap-1.5 font-mono text-[9.5px] uppercase tracking-[0.14em] transition-opacity',
                active ? 'opacity-100' : 'opacity-40',
              )}
              style={{ color: active ? tier.color : ACCENT.slate }}
            >
              <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: tier.color }} />
              {tier.rating}
            </span>
          );
        })}
      </div>

      {/* This sentence used to be a two-way branch on two numbers, so a scan that
          measured neither still produced "Classical encryption needs hardening,
          but limited post-quantum readiness for future migration." — a verdict on
          both axes from no evidence on either. */}
      <p className="mt-auto px-5 pb-4 pt-5 text-center text-[13px] leading-relaxed text-slate-400">
        {executive.classicalScore === null && !pqMeasured
          ? 'Neither classical encryption nor post-quantum readiness could be scored — the endpoint produced no cryptographic evidence to assess.'
          : `${
              executive.classicalScore === null
                ? 'Classical encryption was not scored,'
                : executive.classicalScore >= 70
                  ? 'Strong classical encryption today,'
                  : 'Classical encryption needs hardening,'
            } ${
              !pqMeasured
                ? 'and post-quantum readiness was not measured at the edge.'
                : executive.postQuantumReadiness! >= 60
                  ? 'with hybrid post-quantum key agreement already in place.'
                  : 'but limited post-quantum readiness for future migration.'
            }`}
      </p>

      {/* Auditability: the composite is never a black box. */}
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className="flex w-full items-center justify-center gap-1.5 border-t border-white/[0.06] py-2.5 font-mono text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 transition-colors hover:text-cyan-300"
      >
        {open ? 'Hide' : 'Show'} score decomposition
        <ChevronDown className={cn('h-3.5 w-3.5 transition-transform', open && 'rotate-180')} />
      </button>

      {open && (
        <div className="space-y-3 border-t border-white/[0.06] px-5 py-4">
          <p className="text-[11px] text-slate-500">
            Weighted mean across the 12 categories in the published scoring model (18 + 15 + 12 + 12 + 10 + 8 + 5
            + 5 + 3 + 4 + 5 + 3 = 100). Categories that could not be observed are excluded and their weight
            redistributed among the rest — see &ldquo;How the Grading Works&rdquo; above for the full reference.
          </p>
          {scoreComponents.map((component) => (
            <div key={component.key} className="grid grid-cols-[minmax(0,1fr)] gap-1.5 sm:grid-cols-[13rem_minmax(0,1fr)_3rem] sm:items-center sm:gap-4">
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-slate-200">{component.label}</span>
                <span className="font-mono text-[9px] text-slate-600">w{component.weight}</span>
                {!component.applicable && <StatusPill status="unknown" label="Not observable" />}
              </div>
              <div>
                <Meter value={component.applicable ? component.score : 0} />
                <p className="mt-1 truncate font-mono text-[10px] text-slate-600" title={component.observed}>
                  {component.observed}
                </p>
              </div>
              <span
                className="text-right text-sm font-black tabular-nums"
                style={{ color: component.applicable ? scoreColor(component.score) : ACCENT.slate }}
              >
                {component.applicable ? component.score : '—'}
              </span>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

/* ======================================================== attack surface ==== */

export function AttackSurface({ report }: { report: PublicScanReport }) {
  return (
    <Panel className="h-full overflow-hidden">
      <div className="border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.blue}>Public Attack Surface</SectionLabel>
      </div>
      <ul className="divide-y divide-white/[0.05]">
        {report.attackSurface.map((item) => (
          <li key={item.key} className="flex items-center justify-between gap-3 px-5 py-2.5" title={item.detail}>
            <span className="flex min-w-0 items-center gap-2.5">
              <span
                className="h-1.5 w-1.5 shrink-0 rounded-full"
                style={{
                  backgroundColor:
                    item.status === 'pass'
                      ? ACCENT.emerald
                      : item.status === 'fail'
                        ? ACCENT.rose
                        : item.status === 'partial'
                          ? ACCENT.amber
                          : ACCENT.slate,
                }}
              />
              <span className="truncate text-[13px] text-slate-300">{item.label}</span>
            </span>
            <span
              className="shrink-0 text-[13px] font-bold"
              style={{
                color:
                  item.status === 'pass'
                    ? ACCENT.emerald
                    : item.status === 'fail'
                      ? ACCENT.rose
                      : item.status === 'partial'
                        ? ACCENT.amber
                        : item.status === 'info'
                          ? ACCENT.blue
                          : ACCENT.slate,
              }}
            >
              {item.value}
            </span>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

/* ==================================================== crypto intelligence == */

export function CryptoIntelligencePanel({ report }: { report: PublicScanReport }) {
  const { intelligence } = report;
  return (
    <Panel className="h-full overflow-hidden" glow>
      <div className="border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.violet}>Cryptographic Intelligence</SectionLabel>
      </div>

      <div className="space-y-4 px-5 py-4">
        <div>
          <p className="text-[11px] font-semibold text-slate-500">Observed Algorithms</p>
          <ul className="mt-2 space-y-1.5">
            {intelligence.observedAlgorithms.map((algorithm) => (
              <li key={`${algorithm.name}-${algorithm.role}`} className="flex items-center gap-2 text-[13px]">
                <Zap
                  className="h-3.5 w-3.5 shrink-0"
                  style={{ color: algorithm.quantumVulnerable ? ACCENT.amber : ACCENT.cyan }}
                />
                <span className="font-mono text-slate-200">{algorithm.name}</span>
                <span className="truncate text-[11px] text-slate-600">{algorithm.role}</span>
              </li>
            ))}
          </ul>
        </div>

        <dl className="space-y-2 border-t border-white/[0.06] pt-3 text-[13px]">
          <div className="flex items-center justify-between gap-3">
            <dt className="text-slate-400">Key Exchange</dt>
            <dd className="truncate font-mono text-[12px] font-bold text-cyan-300" title={intelligence.keyExchange}>
              {intelligence.keyExchange}
            </dd>
          </div>
          <div className="flex items-center justify-between gap-3">
            <dt className="text-slate-400">Forward Secrecy</dt>
            <dd
              className="font-bold"
              style={{
                color: intelligence.forwardSecrecy === 'Enabled' ? ACCENT.emerald : ACCENT.amber,
              }}
            >
              {intelligence.forwardSecrecy === 'Enabled' ? '✦ Enabled' : intelligence.forwardSecrecy}
            </dd>
          </div>
          <div className="flex items-center justify-between gap-3">
            <dt className="text-slate-400">Quantum Vulnerability</dt>
            <dd
              className="font-bold"
              style={{
                // `Unknown` is slate. Every other branch of this ternary is a
                // measured verdict; painting an unmeasured one emerald (the old
                // fallthrough) would have reported "quantum-safe" colouring for
                // an endpoint nothing was learned about.
                color:
                  intelligence.quantumVulnerability === 'Vulnerable'
                    ? ACCENT.rose
                    : intelligence.quantumVulnerability === 'Hybrid-protected'
                      ? ACCENT.cyan
                      : intelligence.quantumVulnerability === 'Unknown'
                        ? ACCENT.slate
                        : ACCENT.emerald,
              }}
            >
              {intelligence.quantumVulnerability === 'Vulnerable' ? '▲ Vulnerable' : intelligence.quantumVulnerability}
            </dd>
          </div>
        </dl>
        {intelligence.quantumVulnerability === 'Unknown' && (
          <p className="mt-2 text-[11.5px] leading-snug text-slate-500">
            {intelligence.quantumVulnerabilityReason}
          </p>
        )}

        <div className="border-t border-white/[0.06] pt-3">
          <p className="text-[11px] font-semibold text-slate-500">Estimated PQ Migration Targets</p>
          {/* An empty list is now possible and is the correct output when nothing
              was observed. It used to be impossible: the builder appended
              "Sustain hybrid deployment" whenever the list came out empty, which
              recommended maintaining a hybrid group on endpoints where no
              handshake had happened at all. */}
          {!intelligence.migrationTargets.length && (
            <p className="mt-2 text-[13px] text-slate-500">
              No migration target can be named — no cryptographic primitive was observed at this endpoint.
            </p>
          )}
          <ul className="mt-2 space-y-1.5">
            {/* Keyed on target AND the primitive it replaces: one PQ algorithm
                legitimately replaces several classical ones, so the name alone
                collides and React drops the rows it considers duplicates. */}
            {intelligence.migrationTargets.map((target) => (
              <li key={`${target.name}::${target.replaces}`} className="flex items-start gap-2 text-[13px]">
                <ArrowRight className="mt-0.5 h-3.5 w-3.5 shrink-0 text-violet-400" />
                <span>
                  <span className="font-mono font-bold text-slate-100">{target.name}</span>
                  <span className="ml-1.5 text-[11px] text-slate-600">
                    {target.standard} · replaces {target.replaces}
                  </span>
                </span>
              </li>
            ))}
          </ul>
        </div>

        <div className="border-t border-white/[0.06] pt-3">
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-slate-500">Confidence</span>
            <span className="font-bold text-cyan-300">{intelligence.confidence}%</span>
          </div>
          <Meter value={intelligence.confidence} color={ACCENT.cyan} className="mt-1.5" />
        </div>
      </div>
    </Panel>
  );
}

/* ============================================================= findings ==== */

export function PublicFindings({ report }: { report: PublicScanReport }) {
  const [expanded, setExpanded] = React.useState(false);
  const rows = expanded ? report.findings : report.findings.slice(0, 8);

  return (
    <Panel className="overflow-hidden">
      <div className="flex items-center justify-between gap-3 border-b border-white/[0.06] px-5 py-3">
        <SectionLabel>Public Findings</SectionLabel>
        <span className="font-mono text-[10px] text-slate-500">
          {report.findings.length} observable control{report.findings.length === 1 ? '' : 's'}
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[62rem] border-collapse text-left">
          <thead>
            <tr className="border-b border-white/[0.06] font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-500">
              <th className="px-5 py-2.5 font-bold">Control</th>
              <th className="px-3 py-2.5 font-bold">Finding</th>
              <th className="px-3 py-2.5 font-bold">Status</th>
              <th className="px-3 py-2.5 font-bold">Business Impact</th>
              <th className="px-3 py-2.5 font-bold">Quantum Impact</th>
              <th className="px-5 py-2.5 font-bold">Recommended Next Step</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.04]">
            {rows.map((finding) => (
              <tr key={finding.id} className="align-top transition-colors hover:bg-white/[0.02]">
                <td className="px-5 py-3 text-[12.5px] font-semibold text-slate-200">{finding.control}</td>
                <td className="px-3 py-3 font-mono text-[11.5px] text-slate-300">{finding.finding}</td>
                <td className="px-3 py-3">
                  <StatusPill status={finding.status} />
                </td>
                <td className="max-w-[15rem] px-3 py-3 text-[11.5px] leading-snug text-slate-400">
                  {finding.businessImpact}
                </td>
                <td className="max-w-[15rem] px-3 py-3 text-[11.5px] leading-snug text-slate-400">
                  {finding.quantumImpact}
                </td>
                <td className="max-w-[15rem] px-5 py-3 text-[11.5px] leading-snug text-slate-400">
                  {finding.nextStep}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {report.findings.length > 8 && (
        <button
          type="button"
          onClick={() => setExpanded((value) => !value)}
          className="flex w-full items-center justify-center gap-1.5 border-t border-white/[0.06] py-2.5 text-[12px] font-bold text-cyan-300 transition-colors hover:text-cyan-200"
        >
          {expanded ? 'Show fewer findings' : `View all ${report.findings.length} public findings`}
          <ChevronDown className={cn('h-3.5 w-3.5 transition-transform', expanded && 'rotate-180')} />
        </button>
      )}
    </Panel>
  );
}

/* ============================================================= timeline ==== */

const TIMELINE_ICONS = [Clock, Database, Cpu, AlertTriangle, TrendingUp, Layers, ShieldCheck];

export function QuantumTimeline({ report }: { report: PublicScanReport }) {
  return (
    <Panel className="h-full overflow-hidden">
      <div className="border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.amber}>Quantum Exposure Timeline</SectionLabel>
      </div>
      <ol className="relative space-y-4 px-5 py-4">
        <span className="absolute left-[2.05rem] top-6 bottom-6 w-px bg-gradient-to-b from-cyan-400/40 via-violet-400/25 to-emerald-400/30" />
        {report.timeline.map((phase, index) => {
          const Icon = TIMELINE_ICONS[index] ?? Clock;
          const color =
            phase.state === 'now'
              ? ACCENT.cyan
              : phase.state === 'active'
                ? ACCENT.rose
                : phase.state === 'target'
                  ? ACCENT.emerald
                  : ACCENT.slate;
          return (
            <li key={phase.key} className="relative flex gap-3.5">
              <motion.span
                initial={{ scale: 0.7, opacity: 0 }}
                whileInView={{ scale: 1, opacity: 1 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: index * 0.07 }}
                className="relative z-10 grid h-8 w-8 shrink-0 place-items-center rounded-lg border"
                style={{ borderColor: `${color}40`, backgroundColor: `${color}14`, color }}
              >
                <Icon className="h-4 w-4" />
              </motion.span>
              <div className="min-w-0 pb-1">
                <div className="flex flex-wrap items-baseline gap-x-2">
                  <p className="text-[13px] font-bold text-slate-100">{phase.title}</p>
                  <span className="font-mono text-[9.5px] uppercase tracking-widest" style={{ color }}>
                    {phase.horizon}
                  </span>
                </div>
                <p className="mt-0.5 text-[11.5px] leading-snug text-slate-500">{phase.description}</p>
              </div>
            </li>
          );
        })}
      </ol>
    </Panel>
  );
}

/* ====================================================== recommendations ==== */

const PRIORITY_COLOR: Record<string, string> = {
  Critical: ACCENT.rose,
  High: ACCENT.amber,
  Medium: ACCENT.blue,
  Low: ACCENT.slate,
};

export function Recommendations({ report }: { report: PublicScanReport }) {
  return (
    <Panel className="overflow-hidden">
      <div className="border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.emerald}>Executive Recommendations</SectionLabel>
      </div>
      <div className="grid grid-cols-[minmax(0,1fr)] gap-px bg-white/[0.05] sm:grid-cols-2">
        {report.recommendations.map((recommendation, index) => {
          const color = PRIORITY_COLOR[recommendation.priority] ?? ACCENT.slate;
          // An odd final card would leave a visible empty grid cell — span it.
          const spansRow = index === report.recommendations.length - 1 && report.recommendations.length % 2 === 1;
          return (
            <Reveal key={recommendation.id} delay={index * 0.05} className={spansRow ? 'sm:col-span-2' : undefined}>
              <div className="h-full bg-[#080d1a] px-5 py-4">
                <div className="flex items-start justify-between gap-3">
                  <h3 className="text-[13.5px] font-bold leading-snug text-slate-100">{recommendation.title}</h3>
                  <span
                    className="shrink-0 rounded-md px-2 py-0.5 font-mono text-[9.5px] font-black uppercase tracking-wider"
                    style={{ backgroundColor: `${color}1c`, color }}
                  >
                    {recommendation.priority}
                  </span>
                </div>
                <p className="mt-2 text-[11.5px] leading-relaxed text-slate-500">{recommendation.businessImpact}</p>
                <div className="mt-3 grid grid-cols-3 gap-3 border-t border-white/[0.06] pt-3">
                  <div>
                    <p className="font-mono text-[9px] uppercase tracking-widest text-slate-600">Effort</p>
                    <p className="mt-0.5 text-[11.5px] font-bold text-slate-300">{recommendation.effort}</p>
                  </div>
                  <div className="col-span-2">
                    <p className="font-mono text-[9px] uppercase tracking-widest text-slate-600">
                      Modelled encryption-score gain
                    </p>
                    <div className="mt-1.5 flex items-center gap-2" title={recommendation.scoreGainBasis}>
                      {recommendation.scoreGain === null ? (
                        <span className="text-[11px] font-bold text-slate-500">Not scored</span>
                      ) : (
                        <>
                          {/* Scaled ×3 for visual range only; the number is the model output. */}
                          <Meter value={recommendation.scoreGain * 3} color={color} className="h-1" />
                          <span className="shrink-0 text-[11px] font-bold tabular-nums" style={{ color }}>
                            +{recommendation.scoreGain}
                          </span>
                        </>
                      )}
                    </div>
                  </div>
                </div>
                <p className="mt-2.5 font-mono text-[10px] leading-snug text-slate-600">{recommendation.rationale}</p>
                {/* Platform-specific "where to make the change", present only
                    when the scan actually detected a platform it can speak
                    accurately about. */}
                {recommendation.remediation && (
                  <p
                    className="mt-2 rounded-md border border-cyan-400/15 bg-cyan-400/[0.04] px-2.5 py-1.5 font-mono text-[10px] leading-snug text-cyan-200/85"
                    style={{ overflowWrap: 'anywhere' }}
                  >
                    {recommendation.remediation}
                  </p>
                )}
                <p className="mt-1 font-mono text-[9.5px] leading-snug text-slate-700">
                  {recommendation.scoreGainBasis}
                </p>
              </div>
            </Reveal>
          );
        })}
      </div>
    </Panel>
  );
}

/* ============================================================ estimator ==== */

const FOOTPRINT_COLORS = [ACCENT.cyan, ACCENT.blue, ACCENT.violet, ACCENT.emerald];

export function FootprintEstimator({ report }: { report: PublicScanReport }) {
  const { footprint } = report;

  return (
    <Panel className="h-full overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-5 py-3">
        <SectionLabel>Public Footprint Counted</SectionLabel>
        <span className="font-mono text-[9.5px] uppercase tracking-widest text-slate-600">
          Observed, not estimated
        </span>
      </div>

      <div className="grid grid-cols-2 gap-px bg-white/[0.05] lg:grid-cols-4">
        {footprint.metrics.map((metric, index) => (
          <div key={metric.key} className="bg-[#080d1a] px-4 py-4" title={metric.countedFrom}>
            <p className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-500">{metric.label}</p>
            <p
              className="mt-2 text-3xl font-black tracking-tight"
              style={{ color: FOOTPRINT_COLORS[index % FOOTPRINT_COLORS.length] }}
            >
              <CountUp value={metric.value} />
              {metric.isLowerBound && <span className="ml-0.5 align-super text-base text-slate-600">+</span>}
            </p>
            <p className="mt-1 text-[10px] leading-snug text-slate-600">{metric.countedFrom}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-px bg-white/[0.05]">
        <div className="bg-[#080d1a] px-4 py-4">
          <p className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-500">Exposure Level</p>
          <p className="mt-2 text-lg font-black leading-tight text-slate-100">{footprint.exposureLevel}</p>
        </div>
        <div className="bg-[#080d1a] px-4 py-4">
          <p className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-500">
            Recommended Assessment
          </p>
          <p className="mt-2 flex items-start gap-1.5 text-lg font-black leading-tight text-violet-300">
            {footprint.recommendedAssessment}
            <Lock className="mt-1 h-3.5 w-3.5 shrink-0 text-violet-400" />
          </p>
        </div>
      </div>

      {/* What a public scan cannot count, named rather than guessed at. */}
      <div className="border-t border-white/[0.06] px-5 py-3.5">
        <p className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-500">Not counted here</p>
        <ul className="mt-2 grid gap-x-4 gap-y-1 sm:grid-cols-2">
          {footprint.notCounted.map((item) => (
            <li key={item} className="flex items-start gap-1.5 text-[11.5px] text-slate-500">
              <Lock className="mt-0.5 h-3 w-3 shrink-0 text-slate-600" />
              {item}
            </li>
          ))}
        </ul>
      </div>

      <p className="border-t border-white/[0.06] px-5 py-2.5 font-mono text-[10px] leading-relaxed text-slate-600">
        {footprint.basis}
      </p>
    </Panel>
  );
}

/* =========================================================== governance ==== */

export function GovernanceReadiness({ report }: { report: PublicScanReport }) {
  return (
    <Panel className="h-full overflow-hidden">
      <div className="border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.slate}>Governance Readiness (Unknown from public scan)</SectionLabel>
      </div>
      <ul className="divide-y divide-white/[0.05]">
        {report.governance.map((item) => (
          <li key={item.key} className="flex items-center justify-between gap-3 px-5 py-2.5" title={item.reason}>
            <span className="flex min-w-0 items-center gap-2.5">
              <HelpCircle className="h-3.5 w-3.5 shrink-0 text-slate-600" />
              <span className="truncate text-[13px] text-slate-300">{item.label}</span>
            </span>
            <span className="flex shrink-0 items-center gap-1 text-[12.5px] font-semibold text-slate-500">
              Unknown <ArrowRight className="h-3 w-3" />
            </span>
          </li>
        ))}
      </ul>
      <div className="m-4 flex items-start gap-3 rounded-xl border border-violet-400/20 bg-violet-500/[0.07] px-4 py-3">
        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-violet-400/30 bg-violet-500/10">
          <Lock className="h-4 w-4 text-violet-300" />
        </span>
        <p className="text-[11.5px] leading-relaxed text-violet-200/90">
          Enterprise assessment required to validate governance and compliance posture.
        </p>
      </div>
    </Panel>
  );
}

/* =============================================================== sophia ==== */

export function SophiaInsight({ report }: { report: PublicScanReport }) {
  const { sophia } = report;
  return (
    <Panel className="overflow-hidden border-violet-400/15">
      <div className="grid grid-cols-[minmax(0,1fr)] gap-0 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        <div className="relative px-5 py-5">
          <div className="flex items-center gap-3">
            <img
              src="/Sophia_AVATAR.png"
              alt=""
              className="h-11 w-11 rounded-xl object-cover ring-1 ring-violet-400/30"
            />
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-black tracking-tight text-violet-200">Sophia AI Insight</h3>
                <span className="rounded-md bg-violet-500/15 px-1.5 py-0.5 font-mono text-[9px] font-black uppercase tracking-widest text-violet-300">
                  AI
                </span>
              </div>
              <p className="font-mono text-[9.5px] uppercase tracking-[0.18em] text-slate-500">
                Security Copilot™ · edge assessment
              </p>
            </div>
          </div>

          <p className="mt-4 text-[13px] leading-relaxed text-slate-300">{sophia.narrative}</p>

          <p className="mt-3 text-[12px] font-semibold text-slate-400">
            However, public observation cannot validate:
          </p>
          <ul className="mt-2 grid gap-x-4 gap-y-1 sm:grid-cols-2">
            {sophia.cannotValidate.map((item) => (
              <li key={item} className="flex items-start gap-1.5 text-[11.5px] text-slate-500">
                <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-violet-400/70" />
                {item}
              </li>
            ))}
          </ul>

          <p className="mt-3 text-[12px] font-bold text-violet-200">{sophia.recommendation}</p>
        </div>

        <div className="border-t border-white/[0.06] px-5 py-5 lg:border-l lg:border-t-0">
          <p className="font-mono text-[10px] font-bold uppercase tracking-[0.16em] text-slate-400">
            What&apos;s Included in the Full Report
          </p>
          <ul className="mt-3 space-y-1.5">
            {[
              'Source Code Cryptographic Discovery',
              'Cryptographic Bill of Materials (CBOM)',
              'Cryptographic Governance & Policies',
              'Quantum Readiness Assessment',
              'Runtime Crypto Telemetry',
              'Migration Roadmap & Sandbox',
              'Compliance & Regulatory Mapping',
              'Sophia AI Security Copilot™',
            ].map((item) => (
              <li key={item} className="flex items-start gap-2 text-[12px] text-slate-300">
                <BadgeCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
                {item}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </Panel>
  );
}

/* =========================================== enterprise capability preview == */

const ENTERPRISE_MODULES: Array<{
  title: string;
  tier: 'Basic' | 'Pro' | 'Elite';
  description: string;
  icon: typeof Braces;
  chips: string[];
}> = [
  {
    title: 'Source Code Discovery',
    tier: 'Pro',
    description: 'Repository-wide cryptographic discovery across code, dependencies and secrets.',
    icon: Braces,
    chips: ['Repositories', 'Crypto APIs', 'Hardcoded Keys', 'RSA', 'ECC', 'SHA', 'PQC Debt', 'Dependencies', 'Secrets'],
  },
  {
    title: 'Cryptographic Bill of Materials',
    tier: 'Basic',
    description: 'A signed, exportable inventory of every algorithm, library and certificate in the estate.',
    icon: Boxes,
    chips: ['Algorithms', 'Libraries', 'Certificates', 'HSM', 'PKI', 'Dependencies', 'Crypto Providers'],
  },
  {
    title: 'Cryptographic Governance Center™',
    tier: 'Elite',
    description: 'Policy, exceptions and ML-DSA-signed governance receipts with a full audit trail.',
    icon: ScrollText,
    chips: ['Policies', 'Exceptions', 'Approvals', 'Governance Receipts', 'ML-DSA Signatures', 'Audit Trails'],
  },
  {
    title: 'Quantum Readiness Assessment™',
    tier: 'Basic',
    description: 'Enterprise-wide readiness scoring across applications, infrastructure and identity.',
    icon: Radar,
    chips: ['Applications', 'Servers', 'Cloud', 'Containers', 'Databases', 'Identity', 'Enterprise Score'],
  },
  {
    title: 'Runtime Crypto Telemetry™',
    tier: 'Pro',
    description: 'Continuous observation of live TLS, certificates, drift and key rotation.',
    icon: Activity,
    chips: ['Live TLS', 'Certificates', 'Drift Detection', 'Key Rotation', 'Continuous Compliance'],
  },
  {
    title: 'Migration Sandbox™',
    tier: 'Basic',
    description: 'Digital-twin simulation of a PQC migration with rollback and risk prediction.',
    icon: Workflow,
    chips: ['Digital Twin', 'Simulation', 'Rollback', 'Compatibility Testing', 'Risk Prediction'],
  },
];

export function EnterpriseModules() {
  return (
    <div>
      <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
        <div>
          <SectionLabel accent={ACCENT.violet}>Enterprise Capabilities</SectionLabel>
          <p className="mt-1.5 text-[13px] text-slate-400">
            Available to Basic, Pro and Elite subscribers. These modules require an authenticated deployment —
            they cannot run from a public scan.
          </p>
        </div>
        <a
          href="/register"
          className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/30 bg-cyan-400/10 px-3.5 py-2 text-xs font-bold text-cyan-300 no-underline transition-colors hover:bg-cyan-400/15"
        >
          Compare plans <ArrowRight className="h-3.5 w-3.5" />
        </a>
      </div>

      <div className="grid grid-cols-[minmax(0,1fr)] gap-4 md:grid-cols-2 xl:grid-cols-3">
        {ENTERPRISE_MODULES.map((module, index) => (
          <Reveal key={module.title} delay={index * 0.05}>
            <LockedPanel
              tier={module.tier}
              title={module.title}
              description={module.description}
              icon={module.icon}
              className="h-full"
            >
              <div className="px-5 py-5">
                <div className="flex items-center gap-2.5">
                  <module.icon className="h-5 w-5 text-cyan-300" />
                  <h3 className="text-sm font-black text-white">{module.title}</h3>
                </div>
                <div className="mt-4 flex flex-wrap gap-1.5">
                  {module.chips.map((chip) => (
                    <span
                      key={chip}
                      className="rounded-md border border-white/10 bg-white/[0.04] px-2 py-1 text-[11px] text-slate-300"
                    >
                      {chip}
                    </span>
                  ))}
                </div>
                <div className="mt-4 space-y-2">
                  {[82, 64, 47].map((width) => (
                    <div key={width} className="h-2 rounded bg-white/[0.06]" style={{ width: `${width}%` }} />
                  ))}
                </div>
              </div>
            </LockedPanel>
          </Reveal>
        ))}
      </div>
    </div>
  );
}

/* ======================================================= report preview ==== */

const REPORT_PAGES = [
  { title: 'Executive Report', icon: FileText },
  { title: 'Migration Plan', icon: Workflow },
  { title: 'Compliance Mapping', icon: ScrollText },
  { title: 'CBOM', icon: Boxes },
  { title: 'Governance Report', icon: Fingerprint },
  { title: 'Risk Matrix', icon: GaugeIcon },
  { title: 'Runtime Telemetry', icon: Activity },
  { title: 'Digital Twin', icon: Layers },
];

export function EnterpriseReportPreview() {
  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.amber}>Enterprise Report Preview</SectionLabel>
        <span className="font-mono text-[9.5px] uppercase tracking-widest text-slate-600">
          Signed · ML-DSA-65 · exportable
        </span>
      </div>

      <div className="grid grid-cols-2 gap-3 px-5 py-5 sm:grid-cols-4">
        {REPORT_PAGES.map((page) => (
          <div key={page.title} className="group relative overflow-hidden rounded-xl border border-white/[0.07]">
            <div
              aria-hidden
              className="select-none space-y-1.5 bg-white/[0.03] p-3 opacity-40"
              style={{ filter: 'blur(3.5px)' }}
            >
              <div className="h-1.5 w-3/4 rounded bg-cyan-300/40" />
              <div className="h-1.5 w-full rounded bg-white/20" />
              <div className="h-1.5 w-5/6 rounded bg-white/15" />
              <div className="mt-3 h-9 rounded bg-gradient-to-br from-cyan-400/25 to-violet-400/20" />
              <div className="h-1.5 w-2/3 rounded bg-white/15" />
              <div className="h-1.5 w-1/2 rounded bg-white/10" />
            </div>
            <div className="absolute inset-0 grid place-items-center bg-[#060b16]/75 px-2 text-center">
              <div>
                <page.icon className="mx-auto h-4 w-4 text-slate-400" />
                <p className="mt-1.5 text-[11px] font-bold leading-tight text-slate-200">{page.title}</p>
                <Lock className="mx-auto mt-1 h-3 w-3 text-amber-400/80" />
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-white/[0.06] px-5 py-3.5">
        <p className="text-[12px] text-slate-400">
          The full report is generated from authenticated discovery across your estate.
        </p>
        <a
          href="/register"
          className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-cyan-400 to-violet-500 px-4 py-2 text-xs font-black text-[#04060e] no-underline transition-opacity hover:opacity-90"
        >
          <Lock className="h-3.5 w-3.5" /> Unlock Enterprise Report
        </a>
      </div>
    </Panel>
  );
}

/* ================================================================ scope ==== */

export function AssessmentScopePanel({ report }: { report: PublicScanReport }) {
  return (
    <Panel className="overflow-hidden">
      <div className="border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.slate}>Assessment Scope</SectionLabel>
      </div>
      <div className="grid grid-cols-[minmax(0,1fr)] gap-px bg-white/[0.05] md:grid-cols-2">
        <div className="bg-[#080d1a] px-5 py-4">
          <p className="flex items-center gap-2 font-mono text-[10px] font-bold uppercase tracking-[0.16em] text-emerald-400">
            <ShieldCheck className="h-3.5 w-3.5" /> Analyzed
          </p>
          <ul className="mt-2.5 space-y-1.5">
            {report.scope.analyzed.map((item) => (
              <li key={item} className="flex items-start gap-2 text-[12px] text-slate-300">
                <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-emerald-400" />
                {item}
              </li>
            ))}
          </ul>
        </div>
        <div className="bg-[#080d1a] px-5 py-4">
          <p className="flex items-center gap-2 font-mono text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500">
            <Lock className="h-3.5 w-3.5" /> Not analyzed — requires Enterprise Discovery
          </p>
          <ul className="mt-2.5 space-y-1.5">
            {report.scope.notAnalyzed.map((item) => (
              <li key={item} className="flex items-start gap-2 text-[12px] text-slate-500">
                <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-slate-600" />
                {item}
              </li>
            ))}
          </ul>
        </div>
      </div>
      <p className="border-t border-white/[0.06] px-5 py-3.5 text-[11.5px] leading-relaxed text-slate-500">
        {report.scope.statement}
      </p>
    </Panel>
  );
}

/* ========================================================= handshake viz === */

export function HandshakeFlow({ report }: { report: PublicScanReport }) {
  const { timing } = report.evidence;
  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.blue}>Live Handshake Visualization</SectionLabel>
        <span className="flex flex-wrap items-center gap-x-3 font-mono text-[9.5px] uppercase tracking-widest text-slate-600">
          <span>{report.target.displayUrl}</span>
          {timing.totalMs !== null && (
            <span className="text-cyan-400/80">
              TCP {timing.tcpConnectMs ?? '—'} ms · TLS {timing.tlsHandshakeMs ?? '—'} ms · total{' '}
              {timing.totalMs} ms
            </span>
          )}
        </span>
      </div>
      {/* Horizontal scroller with a fade edge so the clipped step reads as
          "there is more", not as a rendering bug. */}
      <div className="relative">
        <div
          aria-hidden
          className="pointer-events-none absolute inset-y-0 right-0 z-10 w-16 bg-gradient-to-l from-[#080d1a] to-transparent"
        />
        <ol className="flex gap-3 overflow-x-auto px-5 py-5">
          {report.handshake.map((step, index) => (
          <li key={step.key} className="flex shrink-0 items-center gap-3">
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.4, delay: index * 0.09 }}
              className={cn(
                'flex h-[7.25rem] w-[11.5rem] flex-col rounded-xl border px-3 py-2.5',
                step.observed
                  ? 'border-cyan-400/25 bg-cyan-400/[0.06]'
                  : 'border-white/[0.07] bg-white/[0.02]',
              )}
            >
              <div className="flex items-baseline justify-between gap-2">
                <p className="font-mono text-[9px] uppercase tracking-[0.14em] text-slate-500">
                  {String(index + 1).padStart(2, '0')}
                </p>
                {step.timingMs !== null && (
                  <p className="font-mono text-[9px] font-bold tabular-nums text-cyan-400/70">
                    {step.timingMs} ms
                  </p>
                )}
              </div>
              <p className="mt-0.5 text-[12px] font-bold text-slate-100">{step.label}</p>
              <p
                className="mt-1 truncate font-mono text-[10px]"
                style={{ color: step.observed ? ACCENT.cyan : ACCENT.slate }}
                title={step.value}
              >
                {step.value}
              </p>
              {/* The measurement this step was read from — never a caption. */}
              <p className="mt-auto line-clamp-2 text-[9.5px] leading-snug text-slate-600" title={step.detail}>
                {step.detail}
              </p>
            </motion.div>
              {index < report.handshake.length - 1 && (
                <ArrowRight className="h-3.5 w-3.5 shrink-0 text-slate-700" />
              )}
            </li>
          ))}
        </ol>
      </div>
    </Panel>
  );
}

export { KeyRound, Globe2, Sparkles, Timer };
