/**
 * /resources/quantum-simulation — the Quantum Simulation Range.
 *
 * WHAT THIS PAGE IS
 * -----------------
 * A working instrument that shows how a quantum computer breaks the
 * cryptography protecting an enterprise today, and what replaces it. Every
 * number it prints is badged with where it came from: a published standard, a
 * named model, or a computation this browser just performed.
 *
 * WHAT IT REPLACES
 * ----------------
 * A page whose telemetry, key sizes, decryption times and "recovered periods"
 * were all typed by hand, which mixed a light theme with dark components, ran
 * five uncoordinated timers, and described AES as broken. See
 * `tasks/quantum-simulation-rebuild.md` for the full defect list.
 *
 * STRUCTURE
 * ---------
 *   Hero            the published transition clock and the provenance contract
 *   01 Range        scenario × six-stage chain over a WebGL stage, with the
 *                   evidence artefact each stage produces
 *   02 Shor lab     a real state-vector simulator factoring a real number
 *   03 Resources    what a CRQC would cost, per Gidney-Ekerå / Gidney / Roetteler
 *   04 Mosca        X + Y > Z, against this scenario's real shelf life
 *   05 Logic        which primitives break, which do not, and why
 *   06 Suite        FIPS 203/204/205 sizes, benchmarked live
 *   07 Timeline     the published deadlines in order
 *
 * The engines live in `src/lib/quantum-sim` and are verified offline by
 * `tools/quantum-sim-check.ts`.
 */

import React from 'react';
import { ArrowRight, ExternalLink } from 'lucide-react';
import { useAdaptiveDpr, useQveBudget } from '@/app/public-scan/_qve/performance-manager';
import { ATTACK_CHAIN, scenarioPrimitive, type ShorResult } from '@/lib/quantum-sim';
import { useTheme } from '@/contexts/theme-context';
import { QSR, QsrThemeProvider, qsrThemeVars, tint } from './_theme';
import { CommandBar } from './_theme-toggle';
import { SectionHeading } from './_ui';
import { RunLogContext, useInView, useQuantumRange, useRunLog, useSecondsClock } from './_state';
import Hero from './_sections/hero';
import SimulationRange from './_sections/range';
import EvidenceSurface from './_sections/evidence';
import { MoscaLab, ResourceEstimatorLab, ShorLab } from './_sections/labs';
import { GroverPanel, PqcSuite, StandardsTimeline, VulnerabilityLedger } from './_sections/explorer';
import RunLog from './_sections/runlog';

export default function QuantumSimulationPage() {
  const budget = useQveBudget();
  const dpr = useAdaptiveDpr(budget.maxDpr, budget.core3d);
  const now = useSecondsClock();
  const range = useQuantumRange(budget.animate);

  /** The app-wide theme. The page paints itself from it and keeps no theme state of its own. */
  const { theme } = useTheme();
  const pageRef = React.useRef<HTMLDivElement>(null);
  const firstThemeRender = React.useRef(true);

  // Colours only transition during a switch. A permanent `transition: all` on
  // this page would also smear every live value the simulation updates.
  React.useEffect(() => {
    if (firstThemeRender.current) {
      firstThemeRender.current = false;
      return undefined;
    }
    const node = pageRef.current;
    if (!node || !budget.animate) return undefined;
    node.setAttribute('data-qsr-switching', '');
    const timer = window.setTimeout(() => node.removeAttribute('data-qsr-switching'), 420);
    return () => window.clearTimeout(timer);
  }, [theme, budget.animate]);

  /** The last Shor run, shared between the lab, the 3D stage and the evidence panel. */
  const [shorResult, setShorResult] = React.useState<ShorResult | null>(null);

  /** Session telemetry. Panels emit real events into it through context. */
  const { entries, emit, clear } = useRunLog();

  const rangeRef = React.useRef<HTMLElement>(null);
  const [shorRef, shorVisible] = useInView<HTMLElement>('300px');
  const [suiteRef, suiteVisible] = useInView<HTMLElement>('300px');

  const primitive = React.useMemo(() => scenarioPrimitive(range.state.scenarioId), [range.state.scenarioId]);
  const stageMeta = ATTACK_CHAIN[range.state.stage - 1];

  // Stage and scenario transitions are real events, so they belong in the feed.
  React.useEffect(() => {
    emit(
      stageMeta.tense === 'remedy' ? 'good' : stageMeta.requiresCrqc ? 'alert' : 'info',
      'range',
      `stage ${stageMeta.ordinal}/6 ${stageMeta.label.toUpperCase()} — ${stageMeta.requiresCrqc ? 'requires a CRQC' : stageMeta.tense === 'remedy' ? 'remedy applied' : 'possible today'}`,
    );
  }, [emit, stageMeta]);

  React.useEffect(() => {
    emit('info', 'range', `scenario "${range.scenario.name}" loaded — ${range.crypto.protocol}, ${range.crypto.shelfLifeYears}yr shelf life`);
  }, [emit, range.scenario.id, range.scenario.name, range.crypto.protocol, range.crypto.shelfLifeYears]);

  const handleShorResult = React.useCallback(
    (result: ShorResult) => {
      setShorResult(result);
      emit(
        'measure',
        'shor',
        `N=${result.N} a=${result.a} · ${result.totalQubits} qubits · ${result.gates.total.toLocaleString()} gates · y=${result.measurement} · ${result.elapsedMs.toFixed(1)} ms`,
      );
      if (result.factors) {
        emit('alert', 'shor', `factored ${result.N} = ${result.factors[0]} x ${result.factors[1]} from period r=${result.recoveredPeriod}`);
      } else if (result.failureReason) {
        emit('info', 'shor', `shot yielded no factors — ${result.failureReason}`);
      }
    },
    [emit],
  );

  const scrollTo = React.useCallback((element: HTMLElement | null) => {
    element?.scrollIntoView({ behavior: budget.animate ? 'smooth' : 'auto', block: 'start' });
  }, [budget.animate]);

  const lastShorSummary = React.useMemo(
    () =>
      shorResult
        ? {
            N: shorResult.N,
            a: shorResult.a,
            qubits: shorResult.totalQubits,
            period: shorResult.recoveredPeriod,
            factors: shorResult.factors,
            elapsedMs: shorResult.elapsedMs,
          }
        : null,
    [shorResult],
  );

  return (
    <RunLogContext.Provider value={emit}>
    <QsrThemeProvider value={theme}>
    <div
      ref={pageRef}
      className="qsr-page min-h-screen"
      data-qsr-theme={theme}
      style={{ ...qsrThemeVars(theme), colorScheme: theme, background: QSR.ground, color: QSR.ink }}
    >
      <CommandBar animate={budget.animate} />
      <Hero
        now={now}
        animate={budget.animate}
        beamCount={budget.tier === 'full' ? 34 : budget.tier === 'balanced' ? 18 : 0}
        onEnterRange={() => scrollTo(rangeRef.current)}
      />

      <main className="mx-auto max-w-[1500px] space-y-16 px-4 py-14 sm:px-6 md:space-y-20 md:py-20">
        {/* ── 01 · the range ─────────────────────────────────────────── */}
        <section ref={rangeRef} className="scroll-mt-20">
          <SectionHeading
            index="01"
            eyebrow="The simulation range"
            title="Six stages, one broken assumption"
            lede="Pick a scenario and walk the chain. Two of these stages are happening on real networks today and need no quantum computer at all; three need one that does not exist yet; the last is the fix. The stage rail marks which is which, because treating them as equally hypothetical is how organisations end up doing nothing."
            accent={QSR.live}
          />
          <div className="space-y-4">
            <SimulationRange
              scenario={range.scenario}
              crypto={range.crypto}
              primitive={primitive}
              stage={range.state.stage}
              progress={range.state.progress}
              running={range.state.running}
              budget={budget}
              dpr={dpr}
              distribution={shorResult?.distribution ?? null}
              qubits={shorResult?.totalQubits ?? 0}
              resolved={Boolean(shorResult?.recoveredPeriod)}
              onSelectScenario={range.selectScenario}
              onSelectStage={range.setStage}
              onNext={range.nextStage}
              onPrevious={range.previousStage}
              onToggleRunning={range.toggleRunning}
            />
            <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
              <EvidenceSurface
                surface={stageMeta.evidence}
                scenario={range.scenario}
                crypto={range.crypto}
                onOpenLab={() => scrollTo(shorRef.current)}
                lastShorRun={lastShorSummary}
              />
              <aside className="h-[520px] xl:sticky xl:top-[4.5rem] xl:h-[calc(100vh-5.5rem)] xl:max-h-[760px]">
                <RunLog entries={entries} onClear={clear} />
              </aside>
            </div>
          </div>
        </section>

        {/* ── 02 · Shor laboratory ───────────────────────────────────── */}
        <section ref={shorRef} className="scroll-mt-20">
          <SectionHeading
            index="02"
            eyebrow="How the break actually works"
            title="Run the algorithm yourself"
            lede="Shor's algorithm does not search for the key. It arranges for every wrong answer to cancel by interference and leaves the period standing. Below is that circuit, executed on a real simulated quantum register in this tab — and the reason it stops at two-digit numbers is the same reason a quantum computer would matter."
            accent={QSR.quantum}
          />
          <ShorLab active={shorVisible} onResult={handleShorResult} />
        </section>

        {/* ── 03 · resource estimator ────────────────────────────────── */}
        <section className="scroll-mt-20">
          <SectionHeading
            index="03"
            eyebrow="How far away is it"
            title="What a CRQC would actually cost"
            lede="Nobody has published a date for Q-Day, so this page does not invent one. What is published is a set of resource estimates, and those turn 'when' into an engineering question: how many physical qubits, at what error rate, for how long. Move the assumptions and watch the answer move."
            accent={QSR.model}
          />
          <ResourceEstimatorLab />
        </section>

        {/* ── 04 · Mosca ─────────────────────────────────────────────── */}
        <section className="scroll-mt-20">
          <SectionHeading
            index="04"
            eyebrow="How urgent is it"
            title="The deadline is set by your data, not by the hardware"
            lede="Mosca's inequality is the reason waiting for certainty about quantum computers is not a strategy. If your data must stay secret for longer than the time remaining minus your migration time, some of the traffic your network sends before migration finishes will become readable while it still matters — and no action taken later recovers it."
            accent={QSR.broken}
          />
          <MoscaLab defaultShelfLife={range.crypto.shelfLifeYears} />
        </section>

        {/* ── 05 · vulnerability logic ───────────────────────────────── */}
        <section className="scroll-mt-20">
          <SectionHeading
            index="05"
            eyebrow="The vulnerability logic"
            title="Two algorithms, two very different outcomes"
            lede="Shor breaks public-key cryptography completely, at every key size. Grover halves the effective strength of symmetric keys, which is a reduction and not a break. Reading those as the same event leads to replacing AES — which is fine — while leaving the certificate chain that is not."
            accent={QSR.broken}
          />
          <div className="space-y-4">
            <VulnerabilityLedger />
            <GroverPanel />
          </div>
        </section>

        {/* ── 06 · the suite ─────────────────────────────────────────── */}
        <section ref={suiteRef} className="scroll-mt-20">
          <SectionHeading
            index="06"
            eyebrow="What replaces it"
            title="The NIST post-quantum suite, measured here"
            lede="Three finished standards, published 13 August 2024, plus a code-based backup selected in March 2025. The parameter tables come from the FIPS documents; the timings come from your own machine, running the same open-source implementation the rest of this platform uses."
            accent={QSR.quantum}
          />
          <PqcSuite active={suiteVisible} />
        </section>

        {/* ── 07 · timeline ──────────────────────────────────────────── */}
        <section className="scroll-mt-20">
          <SectionHeading
            index="07"
            eyebrow="The published clock"
            title="Dates you will be audited against"
            lede="NIST IR 8547 (initial public draft) proposes deprecating 112-bit-strength public-key algorithms — RSA-2048 and finite-field DH among them — after 2030, and disallowing every quantum-vulnerable public-key algorithm, at every key size, after 2035. CNSA 2.0 sets earlier exclusive-use dates for national security systems. These are the deadlines a programme plan has to work backwards from."
            accent={QSR.live}
          />
          <StandardsTimeline now={now} />
        </section>

        {/* ── Close ──────────────────────────────────────────────────── */}
        <section
          className="overflow-hidden rounded-2xl border p-6 sm:p-8"
          style={{ borderColor: tint(QSR.live, 0.2), background: `linear-gradient(135deg, ${tint(QSR.live, 0.08)}, transparent 60%), ${QSR.panel}` }}
        >
          <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
            <div className="max-w-2xl">
              <div className="font-mono text-[10px] font-bold uppercase tracking-[0.24em]" style={{ color: QSR.live }}>
                From simulation to your own estate
              </div>
              <h2 className="mt-2 text-2xl font-black leading-tight tracking-tight qsr-heading sm:text-3xl">
                This range runs on synthetic scenarios. Your estate is not synthetic.
              </h2>
              <p className="mt-3 text-[13px] leading-relaxed" style={{ color: QSR.inkSoft }}>
                Everything modelled here — which key agreements are quantum-vulnerable, how long the data behind them must stay
                confidential, and how much of the migration is finished — is measurable on real infrastructure. QGuard Helix
                discovers the cryptography you are actually running, scores the exposure against the same NIST standards this
                page cites, and tracks the migration to completion.
              </p>
            </div>
            <div className="flex flex-col gap-2.5 sm:flex-row lg:flex-col">
              <a
                href="/public-scan"
                className="inline-flex items-center justify-center gap-2 rounded-lg px-5 py-3 font-mono text-[11px] font-bold uppercase tracking-[0.14em] transition-transform hover:scale-[1.02]"
                style={{ background: QSR.live, color: QSR.onAccent }}
              >
                Scan a real endpoint <ArrowRight className="h-3.5 w-3.5" />
              </a>
              <a
                href="/resources/pqc-checklist"
                className="inline-flex items-center justify-center gap-2 rounded-lg border px-5 py-3 font-mono text-[11px] font-bold uppercase tracking-[0.14em] transition-colors qsr-hover-border"
                style={{ borderColor: QSR.hairlineStrong, color: QSR.inkSoft }}
              >
                PQC migration checklist <ExternalLink className="h-3.5 w-3.5" />
              </a>
            </div>
          </div>
        </section>

        {/* ── Method note ────────────────────────────────────────────── */}
        <footer className="rounded-xl border p-5" style={{ borderColor: QSR.hairline, background: QSR.well }}>
          <div className="font-mono text-[10px] font-bold uppercase tracking-[0.22em]" style={{ color: QSR.inkMuted }}>
            Method
          </div>
          <div className="mt-2.5 grid gap-3 text-[11.5px] leading-relaxed md:grid-cols-3" style={{ color: QSR.inkFaint }}>
            <p>
              <strong style={{ color: QSR.inkSoft }}>Published values</strong> are transcribed from FIPS 203, 204 and 205, NIST
              IR 8547 ipd, the CNSA 2.0 FAQ (December 2024, Ver. 2.1) and the IANA TLS registry. Each carries a link to its
              source.
            </p>
            <p>
              <strong style={{ color: QSR.inkSoft }}>Modelled values</strong> come from Gidney &amp; Ekerå (2021), Gidney (2025)
              and Roetteler et al. (2017). The estimator reproduces each paper's own headline result before it is allowed to
              extrapolate; the offline check tool asserts that.
            </p>
            <p>
              <strong style={{ color: QSR.inkSoft }}>Measured values</strong> are produced in your browser: the quantum
              state-vector simulation, the HKDF key schedule, and the ML-KEM, ML-DSA and SLH-DSA operations, all using the
              open-source <code>@noble/post-quantum</code> implementation (not yet independently audited). No network request is made by this page.
            </p>
          </div>
        </footer>
      </main>
    </div>
    </QsrThemeProvider>
    </RunLogContext.Provider>
  );
}
