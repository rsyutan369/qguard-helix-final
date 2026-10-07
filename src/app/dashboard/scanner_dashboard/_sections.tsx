/**
 * Dashboard Scanner — result sections.
 *
 * The authenticated mirror of /public-scan's `_sections.tsx`: the same panels,
 * the same rhythm, the same atoms — rendering the authenticated estate's own
 * evidence instead of a single public endpoint's.
 *
 * Every value here comes from `buildAssessment()`, which derives only from real
 * scanner output. Where the scanner measured nothing, these panels render an
 * explicit Unknown / Not observed with the reason. Nothing is placeholder.
 */
import React from 'react';
import { motion } from 'motion/react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  Boxes,
  CheckCircle2,
  ChevronDown,
  Clock,
  Cpu,
  Database,
  HelpCircle,
  Layers,
  Lock,
  ShieldCheck,
  TrendingUp,
  Workflow,
  XCircle,
  Zap,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { cn } from '@/lib/utils';
import { GAUGE_ARC_BANDS, RATING_TIERS, scoreToGrade } from '@/lib/scanner/public-scan/grading-model';
import {
  ACCENT,
  CountUp,
  Gauge,
  Meter,
  Modal,
  Panel,
  Reveal,
  Ring,
  SectionLabel,
  StatusPill,
  scoreColor,
} from '@/components/quantum-scan/ui';
import {
  pluralize,
  postQuantumPostureCaption,
  postQuantumReadinessCaption,
  riskColorFor,
  type ScannerAssessment,
} from './_intel';
import type { ModuleState } from './_types';

/* ================================================================ executive = */

export function ScannerExecutiveSummary({ assessment }: { assessment: ScannerAssessment }) {
  const { executive } = assessment;
  const [gradingOpen, setGradingOpen] = React.useState(false);

  const cards = [
    {
      label: 'Overall Posture',
      big: executive.grade,
      sub: executive.gradeLabel,
      detail: executive.gradeDetail,
      // A withheld grade shows evidence coverage, not a score it did not earn.
      ring: executive.gradeable ? executive.encryptionScore : executive.evidenceCoverage,
      color: executive.gradeColor,
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
    {
      label: 'Post-Quantum Readiness',
      /* Not scored is rendered as such. A number here beside the panel's own
         "was not scored" footnote is the contradiction this replaced. */
      big: executive.postQuantumReadiness === null ? 'Not scored' : `${executive.postQuantumReadiness}%`,
      /* NAMES THE POPULATION IT SCORES.
         This is the published Post-Quantum Readiness category — hybrid key
         agreement, PQ signatures, a TLS 1.3 floor, certificate lifetime, CT.
         It is not a share of components, and captioning it "Majority
         quantum-safe / Most discovered components already use quantum-safe
         cryptography" put it in direct conflict with the Estate Footprint
         panel, which counted 14 of 18 components quantum-vulnerable on the
         same scan. */
      sub:
        executive.postQuantumReadiness === null
          ? 'Not measured on this scan'
          : postQuantumReadinessCaption(executive.postQuantumReadiness).headline,
      /* NAMES ITSELF, THEN NAMES THE OTHER NUMBER.
         The Encryption Score panel below publishes a second post-quantum figure
         — the weight slice — and it is normally lower, because the algorithm
         census carries most of that slice's weight. A reader who meets 81% here
         and 51 there with no stated relationship concludes one of them is
         broken. The component count is a THIRD population (inventory rows, not
         controls and not distinct primitives) and is now introduced as one
         instead of being joined to this sentence with an em-dash. */
      detail:
        executive.postQuantumReadiness === null
          ? executive.postQuantumReadinessReason ?? 'This dimension was not measured, so no readiness figure is published.'
          : `${postQuantumReadinessCaption(executive.postQuantumReadiness).scope} The Encryption Score panel publishes the wider post-quantum weight slice separately.${
              assessment.footprint.components.total > 0
                ? ` Separately, ${assessment.footprint.components.vulnerable} of ${assessment.footprint.components.total} inventoried components are classified quantum-vulnerable.`
                : ' No cryptographic component was inventoried on this run.'
            }`,
      ring: executive.postQuantumReadiness ?? 0,
      color: scoreColor(executive.postQuantumReadiness ?? 0),
    },
    {
      label: 'Business Risk',
      big: executive.businessRisk,
      sub: 'From scanned evidence',
      detail: executive.businessRiskDetail,
      ring: null,
      color: riskColorFor(executive.businessRisk),
    },
    {
      label: 'Migration Complexity',
      big: executive.migrationComplexity,
      sub: 'Scanner_2 migration engine',
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
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-5 py-3">
        <SectionLabel>Executive Summary</SectionLabel>
        <span className="font-mono text-[9.5px] uppercase tracking-widest text-slate-600">{assessment.provenance}</span>
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
            <p className="font-mono text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500">{card.label}</p>
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
              {card.ring !== null && <Ring value={card.ring} size={54} stroke={4} color={card.color} />}
            </div>
            <p className="mt-2.5 text-[11px] leading-snug text-slate-500">{card.detail}</p>
            {'footer' in card && card.footer}
          </div>
        ))}
      </div>

      <Modal
        open={gradingOpen}
        onClose={() => setGradingOpen(false)}
        title="How the Grading Works"
        maxWidthClassName="max-w-6xl"
      >
        <div className="bg-[#04060e] p-3 sm:p-5">
          <img
            src="/downloads/Security_Grade.png"
            alt="QGuard Helix security grading reference: grade hierarchy, score-to-grade mapping, weighted scoring model and risk-level reference"
            className="w-full rounded-lg border border-white/[0.06]"
          />
        </div>
        <p className="border-t border-white/[0.06] px-5 py-3.5 text-[11.5px] leading-relaxed text-slate-500">
          The Dashboard Scanner grades against this same published score-to-grade table as the Public Quantum
          Exposure Assessment, so one estate assessed on both surfaces is graded on one scale.
        </p>
      </Modal>
    </Panel>
  );
}

/* =========================================================== encryption ==== */

export function ScannerEncryptionScore({ assessment }: { assessment: ScannerAssessment }) {
  const { executive, scoreComponents } = assessment;
  const [open, setOpen] = React.useState(false);

  const measured = scoreComponents.filter((component) => component.score !== null);
  /* BOTH FLANKS AND BOTH CAPTIONS COME FROM ONE COMPUTATION.
     `postureSplit` is the same function `buildAssessment` used to derive
     `classicalScore`, taken over the MEASURED weight — so the two percentages
     sum to 100, each describes the aggregation that produced the number above
     it, and a reader can multiply them out and land on the gauge.

     Previously the weights were summed over every category including the
     unmeasured ones, and the right-hand number was the Post-Quantum Readiness
     category (weight 3) captioned "8% of the weighted model" — the 8% slice is
     that category plus Cryptographic Algorithms and scored 27 on the audited
     scan, so the flanks could not reproduce the middle. */
  const { classical, postQuantum } = assessment.postureSplit;
  const classicalRating = scoreToGrade(executive.classicalScore);

  return (
    <Panel className="flex h-full flex-col overflow-hidden">
      <div className="border-b border-white/[0.06] px-5 py-3">
        <SectionLabel>Encryption Score</SectionLabel>
      </div>

      <div className="grid grid-cols-[minmax(0,1fr)] items-center gap-x-4 gap-y-6 px-5 pt-6 sm:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)]">
        <div className="text-center sm:text-left">
          <p className="font-mono text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500">
            Classical Encryption
          </p>
          <CountUp value={executive.classicalScore} className="mt-2 block text-5xl font-black tracking-tight" />
          <p className="mt-1 text-xs font-semibold" style={{ color: classicalRating.color }}>
            {classicalRating.rating}
          </p>
          <Meter
            value={executive.classicalScore}
            color={classicalRating.color}
            className="mx-auto mt-3 max-w-[9rem] sm:mx-0"
          />
          <p className="mt-1.5 font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-600">
            {classical.weightShare}% of the measured model
          </p>
        </div>

        {/* Same score, same colour as the grade badge — the gauge and the letter
            are two views of one number, never two heuristics. */}
        <Gauge
          value={executive.encryptionScore}
          size={268}
          band={executive.gradeable ? executive.gradeLabel : 'Ungraded'}
          bandColor={executive.gradeColor}
          bands={GAUGE_ARC_BANDS}
        />

        <div className="text-center sm:text-right">
          {/* POSTURE, not READINESS.
              This flank is the post-quantum HALF OF THE MODEL — Cryptographic
              Algorithms plus Post-Quantum Readiness — because that is the only
              number that, weighted against the classical flank, reproduces the
              gauge. The Post-Quantum Readiness CATEGORY is a different, narrower
              measurement and keeps its own name on the Executive Summary tile
              and in the row below. Two numbers, two names, both stated. */}
          <p className="font-mono text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500">
            Post-Quantum Posture
          </p>
          {postQuantum.score === null ? (
            <>
              <span className="mt-2 block text-3xl font-black tracking-tight text-slate-500">Not scored</span>
              <p className="mt-1 max-w-[13rem] text-[11px] leading-relaxed text-slate-500 sm:ml-auto">
                {executive.postQuantumReadinessReason ??
                  'Neither post-quantum category was measured on this run, so no post-quantum posture is published.'}
              </p>
            </>
          ) : (
            <>
              <CountUp value={postQuantum.score} className="mt-2 block text-5xl font-black tracking-tight" />
              <p className="mt-1 text-xs font-semibold" style={{ color: scoreColor(postQuantum.score) }}>
                {postQuantumPostureCaption(postQuantum.score).headline}
              </p>
              <Meter value={postQuantum.score} className="mx-auto mt-3 max-w-[9rem] sm:mx-0 sm:ml-auto" />
              <p className="mt-1.5 font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-600">
                {postQuantum.weightShare}% of the measured model
              </p>
              {/* The reciprocal pointer. The Executive Summary tile above
                  publishes the readiness CATEGORY and this is the wider slice
                  that contains it, so each number now names the other and says
                  why they differ. Without that, 81% and 51 read as one broken
                  measurement rather than two correct ones. */}
              <p className="mt-1 text-[10.5px] leading-snug text-slate-600 sm:ml-auto sm:max-w-[13rem]">
                {postQuantum.categories.join(' + ')}
                {executive.postQuantumReadiness !== null && (
                  <>
                    {' '}
                    · the Executive Summary&apos;s Post-Quantum Readiness tile shows the narrower
                    readiness category on its own: {executive.postQuantumReadiness}
                  </>
                )}
              </p>
            </>
          )}
        </div>
      </div>

      {/* Rating legend — matched to the active rating by string equality, so the
          chip that lights up is the same word the gauge is already showing. */}
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

      <p className="mt-auto px-5 pb-4 pt-5 text-center text-[13px] leading-relaxed text-slate-400">
        {executive.classicalScore >= 70
          ? 'Strong classical encryption across the scanned estate,'
          : 'Classical encryption across the scanned estate needs hardening,'}{' '}
        {/* `postQuantumReadiness` is the published readiness CATEGORY, not a
            share of components — and it is nullable. Both were wrong here: at 78
            this read "with most components already quantum-safe" on a scan whose
            Estate Footprint counted 14 of 18 components quantum-vulnerable. */}
        {/* Reads the same flank rendered above it, so one panel never states two
            post-quantum positions. */}
        {postQuantum.score === null
          ? 'with post-quantum posture not scored on this run.'
          : postQuantum.score >= 60
            ? 'with the post-quantum controls largely in place.'
            : 'with post-quantum migration still outstanding.'}
      </p>

      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="flex w-full items-center justify-center gap-1.5 border-t border-white/[0.06] py-2.5 font-mono text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 transition-colors hover:text-cyan-300"
      >
        {open ? 'Hide' : 'Show'} score decomposition
        <ChevronDown className={cn('h-3.5 w-3.5 transition-transform', open && 'rotate-180')} />
      </button>

      {open && (
        <div className="space-y-3 border-t border-white/[0.06] px-5 py-4">
          {/* The weights are READ from the decomposition rendered below, never
              restated. This line was hardcoded to "25 + 25 + 20 + 15 + 15 = 100"
              — a five-term model the scanner stopped using — and printed it
              directly above a table of twelve categories weighted
              18/15/12/12/10/8/5/5/4/3/5/3. The caption and the table it
              captions cannot disagree if only one of them holds the numbers. */}
          <p className="text-[11px] leading-relaxed text-slate-500">
            The scanner&apos;s own published weighted risk model
            {scoreComponents.length > 0 && (
              <>
                {' '}({scoreComponents.length} categories, total weight{' '}
                {scoreComponents.reduce((sum, component) => sum + component.weight, 0)})
              </>
            )}
            , inverted from exposure to posture. Dimensions the scan could not measure are excluded rather than
            scored as zero
            {measured.length > 0 && measured.length < scoreComponents.length && (
              <>
                {' '}— {measured.reduce((sum, component) => sum + component.weight, 0)} of{' '}
                {scoreComponents.reduce((sum, component) => sum + component.weight, 0)} weight was measured on this run
              </>
            )}
            .{measured.length === 0 && ' No per-target decomposition has been collected yet.'}
          </p>

          {/* Reconciliation, stated rather than assumed. The weighted model and
              the headline are normally the same number — when they are not, the
              summary was rebuilt from stored findings by severity count, and
              saying so is more useful than quietly showing one of them. */}
          {assessment.decompositionScore !== null && (
            <p
              className={cn(
                'rounded-md border px-2.5 py-1.5 font-mono text-[10px] leading-relaxed',
                assessment.decompositionAgrees
                  ? 'border-emerald-400/15 bg-emerald-400/[0.04] text-emerald-200/85'
                  : 'border-amber-400/20 bg-amber-400/[0.05] text-amber-100/85',
              )}
            >
              {assessment.decompositionAgrees ? (
                <>
                  Weighted model: {assessment.decompositionScore}/100 — reconciles with the composite score above,
                  which is the same measurement aggregated across targets.
                </>
              ) : (
                <>
                  Weighted model: {assessment.decompositionScore}/100 vs composite {executive.encryptionScore}/100.
                  The composite was rebuilt from stored finding severities rather than the per-target weighted model,
                  so the two aggregate differently. Re-run the scan to recompute both from live evidence.
                </>
              )}
            </p>
          )}
          {/* EVERY ROW SAYS WHAT IT MEASURES.
              The reported contradiction — "TLS Configuration: TLSv1.3, 100"
              beside "Post-Quantum Key Agreement: Not offered" — was never two
              numbers disagreeing. Both are correct: that category scores the
              protocol VERSION, and TLS 1.3 is the prerequisite for hybrid key
              agreement rather than evidence of it. The page just never said so,
              so a full green bar labelled "TLS Configuration" read as "TLS is
              fine". The published description now travels with the row, and the
              categories where post-quantum deployment actually moves the score
              are marked, so a reader can see where the quantum verdict is
              decided instead of inferring it from a bar that never carried it. */}
          {scoreComponents.map((component) => (
            <div
              key={component.key}
              className="grid grid-cols-[minmax(0,1fr)] gap-1.5 sm:grid-cols-[13rem_minmax(0,1fr)_3rem] sm:items-start sm:gap-4"
            >
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span className="text-xs font-bold text-slate-200">{component.label}</span>
                  <span className="font-mono text-[9px] text-slate-600">w{component.weight}</span>
                  {component.postQuantumRelevant && (
                    <span
                      className="rounded border border-violet-400/25 bg-violet-400/[0.07] px-1 py-px font-mono text-[8.5px] font-bold uppercase tracking-[0.1em] text-violet-300"
                      title="Deploying post-quantum cryptography moves this category's score. The categories without this mark measure classical controls and stay unchanged by a PQC migration."
                    >
                      PQ
                    </span>
                  )}
                  {component.score === null && <StatusPill status="unknown" label="Not measured" />}
                </div>
                {component.description && (
                  <p className="mt-0.5 text-[10px] leading-snug text-slate-600">{component.description}</p>
                )}
              </div>
              <div className="sm:pt-1">
                <Meter value={component.score ?? 0} />
                <p className="mt-1 font-mono text-[10px] leading-snug text-slate-600" title={component.observed}>
                  {component.observed}
                </p>
              </div>
              <span
                className="text-right text-sm font-black tabular-nums sm:pt-0.5"
                style={{ color: component.score === null ? ACCENT.slate : scoreColor(component.score) }}
              >
                {component.score ?? '—'}
              </span>
            </div>
          ))}

          {/* The one sentence that answers the reported contradiction directly. */}
          <p className="rounded-md border border-violet-400/15 bg-violet-400/[0.04] px-2.5 py-2 text-[10.5px] leading-relaxed text-violet-100/80">
            Rows marked <span className="font-mono font-bold">PQ</span> are the ones a post-quantum migration moves.
            The rest score classical controls: a protocol version, a suite list or a certificate lifetime can be
            perfect and still leave the endpoint quantum-vulnerable, because TLS 1.3 is the prerequisite for hybrid
            key agreement, not evidence of it.
          </p>
        </div>
      )}
    </Panel>
  );
}

/* ======================================================== attack surface ==== */

const SURFACE_COLOR: Record<string, string> = {
  pass: ACCENT.emerald,
  fail: ACCENT.rose,
  partial: ACCENT.amber,
  info: ACCENT.blue,
  unknown: ACCENT.slate,
};

/**
 * One control row.
 *
 * Rows carrying evidence are expandable. That is not decoration: a one-word
 * verdict like "Applied" is only auditable if the operator can see the
 * negotiated protocol, the group, both halves of the hybrid construction and
 * how many handshakes confirmed it — without leaving the panel. Rows with no
 * evidence stay inert and look identical when closed, so the list keeps its
 * rhythm instead of sprouting affordances that lead nowhere.
 */
function SurfaceRow({ item }: { item: ScannerAssessment['attackSurface'][number] }) {
  const [open, setOpen] = React.useState(false);
  const evidence = item.evidence ?? [];
  const expandable = evidence.length > 0;

  const head = (
    <>
      <span className="flex min-w-0 shrink items-center gap-2.5">
        <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ backgroundColor: SURFACE_COLOR[item.status] }} />
        <span className="truncate text-[13px] text-slate-300">{item.label}</span>
        {expandable && (
          <ChevronDown
            className={cn(
              'h-3 w-3 shrink-0 text-slate-600 transition-transform duration-200',
              open && 'rotate-180 text-slate-400',
            )}
          />
        )}
      </span>
      {/* The value is capped rather than `shrink-0`: a long cipher-suite name
          would otherwise refuse to shrink and squeeze the label out of the row
          entirely. */}
      <span
        className="min-w-0 max-w-[58%] truncate text-right text-[13px] font-bold"
        style={{ color: SURFACE_COLOR[item.status] }}
        title={item.value}
      >
        {item.value}
      </span>
    </>
  );

  return (
    <li title={expandable ? undefined : item.detail}>
      {expandable ? (
        <button
          type="button"
          onClick={() => setOpen((value) => !value)}
          aria-expanded={open}
          className="flex w-full items-center justify-between gap-3 px-5 py-2.5 text-left transition-colors hover:bg-white/[0.03]"
        >
          {head}
        </button>
      ) : (
        <div className="flex items-center justify-between gap-3 px-5 py-2.5">{head}</div>
      )}

      {expandable && open && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          transition={{ duration: 0.18, ease: 'easeOut' }}
          className="overflow-hidden"
        >
          <div className="border-t border-white/[0.04] bg-black/20 px-5 py-3">
            <p className="text-[11.5px] leading-relaxed text-slate-400">{item.detail}</p>
            <dl className="mt-2.5 space-y-1.5">
              {evidence.map((entry) => (
                <div key={entry.label} className="flex items-start justify-between gap-3">
                  <dt className="shrink-0 text-[10.5px] font-semibold uppercase tracking-wide text-slate-600">
                    {entry.label}
                  </dt>
                  <dd className="min-w-0 break-words text-right font-mono text-[11px] text-slate-300">{entry.value}</dd>
                </div>
              ))}
            </dl>
          </div>
        </motion.div>
      )}
    </li>
  );
}

export function ScannerAttackSurface({ assessment }: { assessment: ScannerAssessment }) {
  const measured = assessment.attackSurface.filter((item) => item.status !== 'unknown').length;
  return (
    <Panel className="h-full overflow-hidden">
      <div className="flex items-center justify-between gap-3 border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.blue}>Observed Attack Surface</SectionLabel>
        {/* Coverage, stated up front. A panel of verdicts is only as good as the
            share of controls that were actually measured, so that share is not
            left for the reader to count. */}
        <span className="shrink-0 font-mono text-[10px] text-slate-600">
          {measured}/{assessment.attackSurface.length} measured
        </span>
      </div>
      <ul className="divide-y divide-white/[0.05]">
        {assessment.attackSurface.map((item) => (
          <SurfaceRow key={item.key} item={item} />
        ))}
      </ul>
    </Panel>
  );
}

/* ==================================================== crypto intelligence == */

/**
 * Colour per quantum-exposure verdict.
 *
 * The vocabulary widened when the verdict stopped being a two-way regex over
 * finding titles and became a classification over measured evidence, so the
 * colour table is explicit rather than a chain of ternaries that silently
 * painted every unrecognised value emerald — which is how "Not observed" used
 * to render as if it were a pass.
 */
const QUANTUM_VULNERABILITY_COLOR: Record<string, string> = {
  'Quantum-safe': ACCENT.emerald,
  'Hybrid-protected': ACCENT.cyan,
  /* Amber, not cyan: hybrid key agreement is live but does not cover every path
     the endpoint accepts, so the colour must not read as "done". */
  'Hybrid — partial coverage': ACCENT.amber,
  'Classical only': ACCENT.amber,
  'High Risk': ACCENT.amber,
  Vulnerable: ACCENT.rose,
  Unknown: ACCENT.slate,
  'Not observed': ACCENT.slate,
};

/** Impact bands from the Quantum Risk Engine, in the platform's risk palette. */
const RISK_IMPACT_COLOR: Record<string, string> = {
  Low: ACCENT.emerald,
  Medium: ACCENT.amber,
  High: ACCENT.amber,
  Critical: ACCENT.rose,
};

const QUANTUM_VULNERABILITY_PREFIX: Record<string, string> = {
  'Quantum-safe': '✦ ',
  'Hybrid-protected': '✦ ',
  'Hybrid — partial coverage': '▲ ',
  'High Risk': '▲ ',
  Vulnerable: '▲ ',
};

export function ScannerCryptoIntelligence({ assessment }: { assessment: ScannerAssessment }) {
  const { intelligence } = assessment;
  return (
    <Panel className="h-full overflow-hidden" glow>
      <div className="border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.violet}>Cryptographic Intelligence</SectionLabel>
      </div>

      <div className="space-y-4 px-5 py-4">
        <div>
          {/* THE COUNT AND THE LIST DESCRIBE ONE POPULATION.
              The panel renders the first rows of the census while the score
              decomposition quotes the census TOTAL, and the two sat on the same
              page with nothing connecting them — which is how "4 algorithms
              observed · 1 quantum-safe" came to be published directly above a
              list of three. The total and the remainder are stated here, from
              the same census object, so the numbers reconcile on sight. */}
          <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
            <p className="text-[11px] font-semibold text-slate-500">Observed Algorithms</p>
            {intelligence.algorithmCensus.observed > 0 && (
              <p className="font-mono text-[10px] text-slate-600">
                {intelligence.observedAlgorithms.length} of {intelligence.algorithmCensus.observed} shown
              </p>
            )}
          </div>
          {intelligence.observedAlgorithms.length === 0 ? (
            <p className="mt-2 text-[12px] text-slate-600">No algorithm has been observed in this view yet.</p>
          ) : (
            <ul className="mt-2 space-y-1.5">
              {intelligence.observedAlgorithms.map((algorithm) => (
                <li key={`${algorithm.name}-${algorithm.role}`} className="flex items-center gap-2 text-[13px]">
                  <Zap
                    className="h-3.5 w-3.5 shrink-0"
                    style={{ color: algorithm.quantumVulnerable ? ACCENT.amber : ACCENT.cyan }}
                  />
                  <span className="truncate font-mono text-slate-200">{algorithm.name}</span>
                  <span className="ml-auto shrink-0 font-mono text-[11px] text-slate-600">×{algorithm.count}</span>
                </li>
              ))}
            </ul>
          )}
          {intelligence.algorithmCensus.observed > intelligence.observedAlgorithms.length && (
            <p className="mt-1.5 text-[10.5px] leading-snug text-slate-600">
              {intelligence.algorithmCensus.observed - intelligence.observedAlgorithms.length} further observed
              algorithm
              {intelligence.algorithmCensus.observed - intelligence.observedAlgorithms.length === 1 ? '' : 's'} not
              listed here — the full census is in the CBOM and in the Cryptographic Algorithms row of the score
              decomposition.
            </p>
          )}
          {/* The census sentence, verbatim — the same string the score
              decomposition prints, so the panel and the category row state one
              population in one wording. */}
          {intelligence.algorithmCensus.observed > 0 && (
            <p className="mt-1.5 text-[10.5px] leading-snug text-slate-500">{intelligence.algorithmCensus.summary}</p>
          )}
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
                color:
                  intelligence.forwardSecrecy === 'Enabled'
                    ? ACCENT.emerald
                    : intelligence.forwardSecrecy === 'Unknown'
                      ? ACCENT.slate
                      : ACCENT.amber,
              }}
            >
              {intelligence.forwardSecrecy === 'Enabled' ? '✦ Enabled' : intelligence.forwardSecrecy}
            </dd>
          </div>
          <div className="flex items-start justify-between gap-3">
            <dt className="shrink-0 text-slate-400" title={intelligence.quantumVulnerabilityReason}>
              Quantum Vulnerability
            </dt>
            <dd
              className="min-w-0 text-right font-bold"
              style={{ color: QUANTUM_VULNERABILITY_COLOR[intelligence.quantumVulnerability] ?? ACCENT.slate }}
              title={intelligence.quantumVulnerabilityReason}
            >
              {QUANTUM_VULNERABILITY_PREFIX[intelligence.quantumVulnerability] ?? ''}
              {intelligence.quantumVulnerability}
            </dd>
          </div>
          {/* The verdict never stands alone. A one-word exposure rating that the
              reader cannot trace is exactly how "Hybrid-protected" survived for
              months on an endpoint with an expired certificate and no
              post-quantum anything — so the engine's reason is printed with it,
              not hidden behind a tooltip the reader has to discover. */}
          <p className="pt-0.5 text-[11px] leading-relaxed text-slate-500">
            {intelligence.quantumVulnerabilityReason}
          </p>
          {intelligence.scanner2Readiness && (
            /* TWO READINESS FIGURES ON ONE PANEL, SO BOTH NAME THEIR POPULATION
               ON THE FACE. This row and "Endpoint PQ Readiness" below it
               routinely differ by a factor of four — 21% beside 81% on a
               www.cloudflare.com scan — because they count different things:
               this is the share of the OBSERVATIONS Scanner_2 could map onto
               its migration catalogue that need no migration, and that one
               grades the endpoint's own readiness controls. Both were correct
               and the gap was explained only in a hover tooltip, which is not a
               disclosure on a dashboard. */
            <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5">
              <dt className="text-slate-400">Scanner_2 Migration Readiness</dt>
              <dd className="font-bold text-violet-300">
                {intelligence.scanner2Readiness.score}% · {intelligence.scanner2Readiness.label}
              </dd>
              <p className="w-full text-[10.5px] leading-snug text-slate-600">
                Share of the cryptographic observations Scanner_2 mapped onto its migration catalogue
                that need no migration — not a share of the asset inventory, and a different
                population from the endpoint readiness below.
              </p>
            </div>
          )}
        </dl>

        {/* Measured post-quantum readiness for the scanned endpoint, with the
            reasons the engine used to arrive at it. Deliberately separate from
            the Scanner_2 migration-readiness figure above: that one counts
            cryptographic OBSERVATIONS against a migration catalogue, this one
            grades the endpoint in front of you, and blending two different
            populations into one percentage is how a readiness number stops
            meaning anything. (The comment here used to say the row above
            "counts assets across the estate" — it never did; it counted the
            findings of the scan in view, and the label said "asset".) */}
        {/* Withheld, and it says why — the same sentence the score
            decomposition prints, so the two panels never differ on whether
            this endpoint's readiness was measured at all. */}
        {!intelligence.postQuantumReadiness && intelligence.postQuantumReadinessReason && (
          <div className="border-t border-white/[0.06] pt-3">
            <div className="flex items-center justify-between text-[11px]">
              <span className="font-semibold text-slate-500">Endpoint PQ Readiness</span>
              <span className="font-bold text-slate-500">Not measured</span>
            </div>
            <p className="mt-1.5 text-[11px] leading-relaxed text-slate-500">
              {intelligence.postQuantumReadinessReason}
            </p>
          </div>
        )}

        {intelligence.postQuantumReadiness && (
          <div className="border-t border-white/[0.06] pt-3">
            <div className="flex items-center justify-between text-[11px]">
              <span className="font-semibold text-slate-500">Endpoint PQ Readiness</span>
              <span className="font-bold" style={{ color: scoreColor(intelligence.postQuantumReadiness.score) }}>
                {intelligence.postQuantumReadiness.score}%
              </span>
            </div>
            {/* The reciprocal half of the disclosure on the Scanner_2 row. */}
            <p className="mt-1 text-[10.5px] leading-snug text-slate-600">
              The published readiness category for this endpoint&apos;s own controls — hybrid key
              agreement, signatures, protocol floor, certificate lifetime.
            </p>
            <Meter
              value={intelligence.postQuantumReadiness.score}
              color={scoreColor(intelligence.postQuantumReadiness.score)}
              className="mt-1.5"
            />
            {intelligence.postQuantumReadiness.reasons.length > 0 && (
              <ul className="mt-2 space-y-1">
                {intelligence.postQuantumReadiness.reasons.slice(0, 4).map((reason) => (
                  <li key={reason} className="flex items-start gap-1.5 text-[11px] leading-relaxed text-slate-500">
                    <span className="mt-[5px] h-1 w-1 shrink-0 rounded-full bg-slate-600" />
                    <span className="min-w-0">{reason}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {intelligence.quantumRiskFactors.length > 0 && (
          <div className="border-t border-white/[0.06] pt-3">
            {/* THE SCALE IS NAMED.
                These words are a PER-FACTOR quantum impact rating, and the
                Executive Summary a few hundred pixels away prints "N critical
                findings" — a count of scan findings on a severity scale. Two
                different scales sharing the vocabulary CRITICAL/HIGH/MEDIUM/LOW
                and neither of them labelled is a contradiction a reader has no
                way to resolve. */}
            <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5">
              <p className="text-[11px] font-semibold text-slate-500">Quantum Risk Factors</p>
              <p className="font-mono text-[9px] uppercase tracking-[0.12em] text-slate-600">
                Quantum impact per factor
              </p>
            </div>
            <p className="mt-0.5 text-[10.5px] leading-snug text-slate-600">
              How exposed each primitive is to a cryptographically-relevant quantum computer. A separate scale from
              the finding severities counted in the Executive Summary.
            </p>
            <ul className="mt-2 space-y-2">
              {intelligence.quantumRiskFactors.map((factor) => (
                <li key={factor.factor} title={factor.explanation}>
                  <div className="flex items-center justify-between gap-2 text-[12px]">
                    <span className="truncate text-slate-300">{factor.factor}</span>
                    <span
                      className="shrink-0 text-[10px] font-black uppercase tracking-wide"
                      style={{ color: RISK_IMPACT_COLOR[factor.impact] ?? ACCENT.slate }}
                    >
                      {factor.impact}
                    </span>
                  </div>
                  <p className="truncate font-mono text-[10.5px] text-slate-600" title={factor.observed}>
                    {factor.observed}
                  </p>
                </li>
              ))}
            </ul>
          </div>
        )}

        <div className="border-t border-white/[0.06] pt-3">
          <p className="text-[11px] font-semibold text-slate-500">PQ Migration Targets</p>
          {intelligence.migrationTargets.length === 0 ? (
            <p className="mt-2 text-[12px] text-slate-600">
              The migration engine has not produced a target for this estate yet.
            </p>
          ) : (
            <ul className="mt-2 space-y-1.5">
              {/* Keyed on target AND the primitive it replaces. One PQ algorithm
                  legitimately replaces several classical ones — ML-KEM-768 stands
                  in for RSA-2048, RSA-1024 and ECC-P256 alike — so the name alone
                  collides, and React was dropping rows it considered duplicates. */}
              {intelligence.migrationTargets.map((target) => (
                <li key={`${target.name}::${target.replaces}`} className="flex items-start gap-2 text-[13px]">
                  <ArrowRight className="mt-0.5 h-3.5 w-3.5 shrink-0 text-violet-400" />
                  <span className="min-w-0">
                    <span className="font-mono font-bold text-slate-100">{target.name}</span>
                    <span className="ml-1.5 text-[11px] text-slate-600">
                      {target.standard} · replaces {target.replaces}
                    </span>
                  </span>
                </li>
              ))}
            </ul>
          )}
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

/* ======================================================= module execution == */

const MODULE_STATUS_STATE: Record<string, string> = {
  Completed: 'pass',
  'No findings': 'pass',
  Running: 'info',
  Queued: 'unknown',
  Skipped: 'unknown',
  Failed: 'fail',
};

/**
 * What the operator reads on the card. "Skipped" is never shown bare — the
 * scanner's ledger always records WHY a module did not apply, and the label
 * says so rather than leaving a grey step with no explanation.
 */
const MODULE_STATUS_LABEL: Record<string, string> = {
  Completed: 'Completed',
  'No findings': 'No findings',
  Running: 'Running',
  Queued: 'Pending',
  Skipped: 'Not applicable',
  Failed: 'Failed',
};

/**
 * The authenticated counterpart to the public hero's handshake flow: the real
 * execution order of the scanner's module catalog, with the duration and
 * finding count each module actually reported.
 */
export function ScannerModuleFlow({
  modules,
  onRetry,
  canRetry,
}: {
  modules: ModuleState[];
  onRetry: (module: ModuleState) => void;
  canRetry: boolean;
}) {
  const done = modules.filter((module) => module.status === 'Completed' || module.status === 'No findings').length;
  const notApplicable = modules.filter((module) => module.status === 'Skipped').length;
  const brokenCount = modules.filter((module) => module.status === 'Failed').length;
  // Coverage is stated against the modules that could apply, the same
  // denominator the Discovery Workflow rail and Discovery Coverage use.
  const applicable = modules.length - notApplicable;

  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.blue}>Module Execution Flow</SectionLabel>
        <span className="font-mono text-[9.5px] uppercase tracking-widest text-slate-600">
          {modules.length
            ? `${done}/${applicable || modules.length} reported${notApplicable ? ` · ${notApplicable} n/a` : ''}${brokenCount ? ` · ${brokenCount} failed` : ''}`
            : 'Catalog published when a scan starts'}
        </span>
      </div>

      {modules.length === 0 ? (
        <p className="px-5 py-8 text-center text-[12px] text-slate-600">
          The scanner publishes its module catalog when the stream opens.
        </p>
      ) : (
        <div className="relative">
          <div
            aria-hidden
            className="pointer-events-none absolute inset-y-0 right-0 z-10 w-16 bg-gradient-to-l from-[#080d1a] to-transparent"
          />
          <ol className="flex gap-3 overflow-x-auto px-5 py-5">
            {modules.map((module, index) => {
              const observed = module.status === 'Completed' || module.status === 'No findings';
              const failed = module.status === 'Failed';
              return (
                <li key={module.id} className="flex shrink-0 items-center gap-3">
                  <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    transition={{ duration: 0.4, delay: Math.min(index * 0.04, 0.5) }}
                    className={cn(
                      'flex h-[7.75rem] w-[12.5rem] flex-col rounded-xl border px-3 py-2.5',
                      failed
                        ? 'border-rose-400/30 bg-rose-400/[0.06]'
                        : observed
                          ? 'border-cyan-400/25 bg-cyan-400/[0.06]'
                          : 'border-white/[0.07] bg-white/[0.02]',
                    )}
                  >
                    <div className="flex items-baseline justify-between gap-2">
                      <p className="font-mono text-[9px] uppercase tracking-[0.14em] text-slate-500">
                        {String(index + 1).padStart(2, '0')}
                      </p>
                      {module.durationMs !== null && (
                        <p className="font-mono text-[9px] font-bold tabular-nums text-cyan-400/70">
                          {module.durationMs} ms
                        </p>
                      )}
                    </div>
                    <p className="mt-0.5 line-clamp-2 text-[12px] font-bold leading-snug text-slate-100">
                      {module.name}
                    </p>
                    <div className="mt-1">
                      <StatusPill
                        status={MODULE_STATUS_STATE[module.status] ?? 'unknown'}
                        label={MODULE_STATUS_LABEL[module.status] ?? module.status}
                      />
                    </div>
                    <p
                      className="mt-auto truncate font-mono text-[9.5px] text-slate-600"
                      title={
                        module.reason
                          ? `${module.target ?? ''}\n${module.reason}`.trim()
                          : module.target
                      }
                    >
                      {failed
                        ? (module.error ?? module.reason ?? 'module failed')
                        : module.status === 'Skipped'
                          ? (module.reason ?? 'not applicable to these targets')
                          : `${module.findingsCount} finding${module.findingsCount === 1 ? '' : 's'}`}
                    </p>
                    {failed && canRetry && (
                      <button
                        type="button"
                        onClick={() => onRetry(module)}
                        className="mt-1 inline-flex items-center gap-1 self-start rounded border border-rose-400/30 px-1.5 py-0.5 font-mono text-[8.5px] font-black uppercase tracking-wider text-rose-300 transition-colors hover:bg-rose-400/10"
                      >
                        Retry module
                      </button>
                    )}
                  </motion.div>
                  {index < modules.length - 1 && <ArrowRight className="h-3.5 w-3.5 shrink-0 text-slate-700" />}
                </li>
              );
            })}
          </ol>
        </div>
      )}
    </Panel>
  );
}

/* ============================================================= findings ==== */

const THREAT_STATUS: Record<string, string> = {
  CRITICAL: 'critical',
  HIGH: 'critical',
  MEDIUM: 'warning',
  LOW: 'warning',
  SAFE: 'pass',
};

export function ScannerFindingsTable({
  findings,
  total,
}: {
  findings: Array<{
    id: string;
    algorithm: string;
    category: string;
    location: string;
    threatLevel: string;
    status: string;
    description: string;
    recommendation: string;
    pqcReplacement: string | null;
  }>;
  total: number;
}) {
  const [expanded, setExpanded] = React.useState(false);
  const rows = expanded ? findings : findings.slice(0, 8);

  return (
    <Panel className="overflow-hidden">
      <div className="flex items-center justify-between gap-3 border-b border-white/[0.06] px-5 py-3">
        <SectionLabel>Cryptographic Findings</SectionLabel>
        <span className="font-mono text-[10px] text-slate-500">
          {total} recorded observation{total === 1 ? '' : 's'}
        </span>
      </div>

      {findings.length === 0 ? (
        <p className="px-5 py-8 text-center text-[12px] text-slate-600">
          No cryptographic finding has been recorded for this tenant yet.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[62rem] border-collapse text-left">
            <thead>
              <tr className="border-b border-white/[0.06] font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-500">
                <th scope="col" className="px-5 py-2.5 font-bold">Algorithm</th>
                <th scope="col" className="px-3 py-2.5 font-bold">Category</th>
                <th scope="col" className="px-3 py-2.5 font-bold">Severity</th>
                <th scope="col" className="px-3 py-2.5 font-bold">Location</th>
                <th scope="col" className="px-3 py-2.5 font-bold">Quantum Impact</th>
                <th scope="col" className="px-5 py-2.5 font-bold">Recommended Next Step</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {rows.map((finding) => (
                <tr key={finding.id} className="align-top transition-colors hover:bg-white/[0.02]">
                  <td className="px-5 py-3 font-mono text-[12.5px] font-semibold text-slate-200">{finding.algorithm}</td>
                  <td className="px-3 py-3 text-[11.5px] text-slate-400">{finding.category}</td>
                  <td className="px-3 py-3">
                    <StatusPill status={THREAT_STATUS[finding.threatLevel] ?? 'unknown'} label={finding.threatLevel} />
                  </td>
                  <td className="max-w-[15rem] px-3 py-3 font-mono text-[11px] leading-snug text-slate-400">
                    {finding.location}
                  </td>
                  <td className="max-w-[15rem] px-3 py-3 text-[11.5px] leading-snug text-slate-400">
                    {finding.description}
                  </td>
                  <td className="max-w-[16rem] px-5 py-3 text-[11.5px] leading-snug text-slate-400">
                    {finding.pqcReplacement ? (
                      <span className="font-mono text-emerald-300/90">{finding.pqcReplacement}</span>
                    ) : (
                      finding.recommendation
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {findings.length > 8 && (
        <button
          type="button"
          onClick={() => setExpanded((value) => !value)}
          className="flex w-full items-center justify-center gap-1.5 border-t border-white/[0.06] py-2.5 text-[12px] font-bold text-cyan-300 transition-colors hover:text-cyan-200"
        >
          {expanded ? 'Show fewer findings' : `View all ${findings.length} findings`}
          <ChevronDown className={cn('h-3.5 w-3.5 transition-transform', expanded && 'rotate-180')} />
        </button>
      )}
    </Panel>
  );
}

/* ============================================================= timeline ==== */

const TIMELINE_ICONS = [Clock, Database, Cpu, AlertTriangle, TrendingUp, Layers, ShieldCheck];

export function ScannerQuantumTimeline({ assessment }: { assessment: ScannerAssessment }) {
  return (
    <Panel className="h-full overflow-hidden">
      <div className="border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.amber}>Quantum Exposure Timeline</SectionLabel>
      </div>
      <ol className="relative space-y-4 px-5 py-4">
        <span className="absolute left-[2.05rem] top-6 bottom-6 w-px bg-gradient-to-b from-cyan-400/40 via-violet-400/25 to-emerald-400/30" />
        {assessment.timeline.map((phase, index) => {
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

export function ScannerRecommendations({ assessment }: { assessment: ScannerAssessment }) {
  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.emerald}>Executive Recommendations</SectionLabel>
        <Link
          to="/dashboard/migration-planner?source=scanner"
          className="inline-flex items-center gap-1.5 text-[11px] font-bold text-cyan-300 no-underline transition-colors hover:text-cyan-200"
        >
          Open Migration Planner <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>

      {assessment.recommendations.length === 0 ? (
        <p className="px-5 py-8 text-center text-[12px] leading-relaxed text-slate-600">
          The Scanner_2 migration engine has not produced a recommendation for this estate. Recommendations appear
          once a scan observes an algorithm with a published post-quantum replacement — nothing generic is shown in
          the meantime.
        </p>
      ) : (
        <div className="grid grid-cols-[minmax(0,1fr)] gap-px bg-white/[0.05] sm:grid-cols-2">
          {assessment.recommendations.map((recommendation, index) => {
            const color = PRIORITY_COLOR[recommendation.priority] ?? ACCENT.slate;
            const spansRow =
              index === assessment.recommendations.length - 1 && assessment.recommendations.length % 2 === 1;
            return (
              <Reveal
                key={recommendation.id}
                delay={Math.min(index * 0.05, 0.4)}
                className={spansRow ? 'sm:col-span-2' : undefined}
              >
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
                    <div>
                      <p className="font-mono text-[9px] uppercase tracking-widest text-slate-600">Standard</p>
                      <p className="mt-0.5 text-[11.5px] font-bold text-slate-300">{recommendation.standard}</p>
                    </div>
                    <div>
                      <p className="font-mono text-[9px] uppercase tracking-widest text-slate-600">Affected</p>
                      <p className="mt-0.5 text-[11.5px] font-bold" style={{ color }}>
                        {recommendation.affected}
                      </p>
                    </div>
                  </div>
                  <ol className="mt-3 space-y-1">
                    {recommendation.steps.slice(0, 4).map((step, stepIndex) => (
                      <li key={step} className="flex items-start gap-2 text-[11px] leading-snug text-slate-400">
                        <span className="mt-[3px] font-mono text-[9px] text-slate-600">
                          {String(stepIndex + 1).padStart(2, '0')}
                        </span>
                        {step}
                      </li>
                    ))}
                  </ol>
                  <p className="mt-2.5 font-mono text-[10px] leading-snug text-slate-600">{recommendation.rationale}</p>
                </div>
              </Reveal>
            );
          })}
        </div>
      )}
    </Panel>
  );
}

/* ============================================================ footprint ==== */

const FOOTPRINT_COLORS = [ACCENT.cyan, ACCENT.blue, ACCENT.violet, ACCENT.emerald];

export function ScannerFootprint({ assessment }: { assessment: ScannerAssessment }) {
  return (
    <Panel className="h-full overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-5 py-3">
        <SectionLabel>Estate Footprint Counted</SectionLabel>
        <span className="font-mono text-[9.5px] uppercase tracking-widest text-slate-600">
          Observed, not estimated
        </span>
      </div>

      <div className="grid grid-cols-2 gap-px bg-white/[0.05] lg:grid-cols-4">
        {assessment.footprint.metrics.map((metric, index) => (
          <div key={metric.key} className="bg-[#080d1a] px-4 py-4" title={metric.countedFrom}>
            <p className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-500">{metric.label}</p>
            <p
              className="mt-2 text-3xl font-black tracking-tight"
              style={{ color: FOOTPRINT_COLORS[index % FOOTPRINT_COLORS.length] }}
            >
              <CountUp value={metric.value} />
            </p>
            <p className="mt-1 text-[10px] leading-snug text-slate-600">{metric.countedFrom}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-px bg-white/[0.05]">
        <div className="bg-[#080d1a] px-4 py-4">
          <p className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-500">Exposure Level</p>
          <p className="mt-2 text-lg font-black leading-tight text-slate-100">{assessment.footprint.exposureLevel}</p>
        </div>
        <div className="bg-[#080d1a] px-4 py-4">
          <p className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-500">Feeds</p>
          <p className="mt-2 flex flex-wrap items-center gap-x-2 text-[12px] font-bold leading-snug text-cyan-300">
            <Link to="/dashboard/cbom" className="text-cyan-300 no-underline hover:underline">CBOM</Link>
            <Link to="/dashboard/assets" className="text-cyan-300 no-underline hover:underline">Assets</Link>
            <Link to="/dashboard/crypto-exposure" className="text-cyan-300 no-underline hover:underline">Exposure</Link>
            <Link to="/dashboard/quantum-readiness" className="text-cyan-300 no-underline hover:underline">Readiness</Link>
          </p>
        </div>
      </div>

      <p className="border-t border-white/[0.06] px-5 py-2.5 font-mono text-[10px] leading-relaxed text-slate-600">
        {assessment.footprint.basis}
      </p>
    </Panel>
  );
}

/* ============================================================= coverage ==== */

const COVERAGE_ICON: Record<string, typeof CheckCircle2> = {
  pass: CheckCircle2,
  partial: AlertTriangle,
  fail: XCircle,
  unknown: HelpCircle,
};

export function ScannerCoverage({ assessment }: { assessment: ScannerAssessment }) {
  return (
    <Panel className="h-full overflow-hidden">
      <div className="border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.slate}>Discovery Coverage</SectionLabel>
      </div>
      <ul className="divide-y divide-white/[0.05]">
        {assessment.coverage.map((item) => {
          const Icon = COVERAGE_ICON[item.status] ?? HelpCircle;
          const color = SURFACE_COLOR[item.status] ?? ACCENT.slate;
          return (
            <li key={item.key} className="flex items-start justify-between gap-3 px-5 py-2.5" title={item.detail}>
              <span className="flex min-w-0 items-center gap-2.5">
                <Icon className="h-3.5 w-3.5 shrink-0" style={{ color }} />
                <span className="truncate text-[13px] text-slate-300">{item.label}</span>
              </span>
              <span className="shrink-0 text-right text-[11.5px] text-slate-500">{item.detail}</span>
            </li>
          );
        })}
      </ul>
      <div className="m-4 flex items-start gap-3 rounded-xl border border-cyan-400/20 bg-cyan-500/[0.06] px-4 py-3">
        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-cyan-400/30 bg-cyan-500/10">
          <Workflow className="h-4 w-4 text-cyan-300" />
        </span>
        <p className="text-[11.5px] leading-relaxed text-cyan-100/85">
          Add Agent Collector Scanners to extend discovery into internal networks, hosts and private PKI that a
          network-reachable scan cannot see.
        </p>
      </div>
    </Panel>
  );
}

/* =============================================================== sophia ==== */

export function ScannerSophiaInsight({ assessment }: { assessment: ScannerAssessment }) {
  const { executive, hndl } = assessment;
  const components = assessment.footprint.components;

  /* Narrative assembled from measured values only — every clause below names a
     number the scanner produced, and names the population that number counts.

     TWO DEFECTS THIS REPLACES
     -------------------------
     1. It read "with ${executive.postQuantumReadiness}% of discovered
        components already quantum-safe". `postQuantumReadiness` is the
        published Post-Quantum Readiness CATEGORY — a posture score built from
        hybrid key agreement, PQ signatures, a TLS 1.3 floor and certificate
        lifetime. It is not a share of anything. On a real scan it read 78%
        while the Estate Footprint panel beside it counted 14 of 18 components
        quantum-vulnerable — 22% safe. The component claim now comes from the
        component counts, and the readiness score is reported as the posture
        score it is.
     2. `postQuantumReadiness` is `number | null` — null meaning "not scored",
        with a reason the Executive Summary already renders. Interpolated
        unguarded, it printed the literal string "null%" to the operator. */
  const componentClause = components.total > 0
    ? ` Of ${pluralize(components.total, 'cryptographic component')} inventoried by this scan, ${components.vulnerable} ${components.vulnerable === 1 ? 'is' : 'are'} quantum-vulnerable.`
    : '';
  const readinessClause = executive.postQuantumReadiness === null
    ? ` Post-quantum readiness was not scored: ${executive.postQuantumReadinessReason ?? 'no measurable evidence for that dimension'}.`
    : ` Measured post-quantum readiness for this endpoint is ${executive.postQuantumReadiness}/100.`;

  const narrative = assessment.hasEvidence
    ? `The scanned estate holds a composite cryptographic posture of ${executive.encryptionScore}/100${
        executive.gradeable ? ` (grade ${executive.grade}, ${executive.gradeLabel})` : ''
      }.${componentClause}${readinessClause} Business risk reads ${executive.businessRisk} and the evidence behind it carries ${executive.confidence}% confidence.${
        hndl.immediate + hndl.soon > 0
          ? ` ${pluralize(hndl.immediate + hndl.soon, 'harvest-now exposure')} need attention before the modelled break window.`
          : ''
      }`
    : 'No scan evidence exists for this tenant yet. Queue an authorized target above and the copilot will assess the estate from the scanner’s own findings.';

  return (
    <Panel className="overflow-hidden border-violet-400/15">
      <div className="grid grid-cols-[minmax(0,1fr)] gap-0 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        <div className="relative px-5 py-5">
          <div className="flex items-center gap-3">
            <img src="/Sophia_AVATAR.png" alt="" className="h-11 w-11 rounded-xl object-cover ring-1 ring-violet-400/30" />
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-black tracking-tight text-violet-200">Sophia AI Insight</h3>
                <span className="rounded-md bg-violet-500/15 px-1.5 py-0.5 font-mono text-[9px] font-black uppercase tracking-widest text-violet-300">
                  AI
                </span>
              </div>
              <p className="font-mono text-[9.5px] uppercase tracking-[0.18em] text-slate-500">
                Security Copilot™ · authenticated estate
              </p>
            </div>
          </div>

          <p className="mt-4 text-[13px] leading-relaxed text-slate-300">{narrative}</p>

          <p className="mt-3 text-[12px] font-semibold text-slate-400">A network-reachable scan cannot validate:</p>
          <ul className="mt-2 grid gap-x-4 gap-y-1 sm:grid-cols-2">
            {[
              'Cryptography inside private networks',
              'Hardware security module key custody',
              'Internal PKI issuance policy',
              'Key rotation and escrow procedures',
              'Data-at-rest encryption on hosts',
              'Governance approvals and exceptions',
            ].map((item) => (
              <li key={item} className="flex items-start gap-1.5 text-[11.5px] text-slate-500">
                <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-violet-400/70" />
                {item}
              </li>
            ))}
          </ul>

          <p className="mt-3 text-[12px] font-bold text-violet-200">
            Deploy Agent Collector Scanners and connect QKMS to close these gaps with first-party evidence.
          </p>
        </div>

        <div className="border-t border-white/[0.06] px-5 py-5 lg:border-l lg:border-t-0">
          <p className="font-mono text-[10px] font-bold uppercase tracking-[0.16em] text-slate-400">
            Where this scan&apos;s evidence lands
          </p>
          <ul className="mt-3 space-y-1.5">
            {[
              { label: 'Assets & CBOM inventory', to: '/dashboard/assets' },
              { label: 'Cryptographic Bill of Materials', to: '/dashboard/cbom' },
              { label: 'Crypto Exposure graph', to: '/dashboard/crypto-exposure' },
              { label: 'Quantum Readiness scoring', to: '/dashboard/quantum-readiness' },
              { label: 'Migration Planner backlog', to: '/dashboard/migration-planner' },
              { label: 'Executive Command Center', to: '/dashboard' },
              { label: 'Report Center exports', to: '/dashboard/quantum-readiness/reports' },
              { label: 'Audit-ready scan history', to: '/dashboard/scanner?tab=history' },
            ].map((item) => (
              <li key={item.label} className="flex items-start gap-2 text-[12px]">
                <BadgeCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
                <Link to={item.to} className="text-slate-300 no-underline transition-colors hover:text-cyan-300">
                  {item.label}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </Panel>
  );
}

/* ================================================================ scope ==== */

export function ScannerScopePanel({ assessment }: { assessment: ScannerAssessment }) {
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
            {assessment.scope.analyzed.map((item) => (
              <li key={item} className="flex items-start gap-2 text-[12px] text-slate-300">
                <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-emerald-400" />
                {item}
              </li>
            ))}
          </ul>
        </div>
        <div className="bg-[#080d1a] px-5 py-4">
          <p className="flex items-center gap-2 font-mono text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500">
            <Lock className="h-3.5 w-3.5" /> Not analyzed in this run
          </p>
          <ul className="mt-2.5 space-y-1.5">
            {assessment.scope.notAnalyzed.map((item) => (
              <li key={item} className="flex items-start gap-2 text-[12px] text-slate-500">
                <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-slate-600" />
                {item}
              </li>
            ))}
          </ul>
        </div>
      </div>
      <p className="border-t border-white/[0.06] px-5 py-3.5 text-[11.5px] leading-relaxed text-slate-500">
        {assessment.scope.statement}
      </p>
    </Panel>
  );
}

/* ================================================================ empty ==== */

export function ScannerEmptyState({ scanning }: { scanning: boolean }) {
  if (scanning) {
    return (
      <div className="mt-5 grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-3">
        {[0, 1, 2].map((index) => (
          <Panel key={index} className="h-56 overflow-hidden">
            <motion.div
              className="h-full w-full bg-gradient-to-r from-transparent via-white/[0.045] to-transparent"
              animate={{ x: ['-100%', '100%'] }}
              transition={{ duration: 1.6, repeat: Infinity, ease: 'linear', delay: index * 0.18 }}
            />
          </Panel>
        ))}
      </div>
    );
  }

  return (
    <div className="mt-5 grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-3">
      {[
        {
          icon: ShieldCheck,
          title: 'Authorized discovery',
          body: 'Every scanner module in the catalog runs against assets you own or are explicitly authorized to assess — no exploitation, no credential collection, no stealth behaviour.',
        },
        {
          icon: Boxes,
          title: 'One source of truth',
          body: 'Findings persist per tenant and populate CBOM, Assets, Crypto Exposure, Quantum Readiness and the Migration Planner from the same evidence.',
        },
        {
          icon: Activity,
          title: 'Honest about limits',
          body: 'Private networks, HSM custody and internal PKI cannot be reached from a network scan — they are reported as Unknown until a collector agent supplies first-party evidence.',
        },
      ].map((card, index) => (
        <Reveal key={card.title} delay={index * 0.07}>
          <Panel className="h-full px-5 py-5">
            <span className="grid h-10 w-10 place-items-center rounded-xl border border-cyan-400/25 bg-cyan-400/[0.08] text-cyan-300">
              <card.icon className="h-5 w-5" />
            </span>
            <h3 className="mt-3.5 text-[15px] font-black text-white">{card.title}</h3>
            <p className="mt-1.5 text-[12.5px] leading-relaxed text-slate-400">{card.body}</p>
          </Panel>
        </Reveal>
      ))}
    </div>
  );
}
