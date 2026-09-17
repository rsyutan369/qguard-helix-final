'use client';

/**
 * Scanner intelligence panels (§45, §47, §49, §61, §64, §75, §83, §85).
 *
 * The surfaces that make the enhanced engine's reasoning visible. Each answers
 * a question the specification requires the product to answer, and each shows
 * its working rather than a bare verdict:
 *
 *   AssetInventory       what was found, per asset, with live state (§64)
 *   DetectionSummary     how it was detected, from the scan's own numbers
 *   EvidenceMatrix       which detection layers agreed, per finding (§47)
 *   StandardsPanel       which authority applies, and to WHOM (§75, §76)
 *   ReconciliationPanel  what this scan contributes to the rest of the platform
 *   EngineHealthPanel    real engine + rule versions, live health (§61, §85)
 *
 * The recurring design decision: never render a verdict without the reason next
 * to it. A "Quantum Vulnerable" badge with no rationale is the thing §37 warns
 * about, because a reader will hear "broken".
 */

import React from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { ChevronDown, Cpu, Scale, Sparkles } from 'lucide-react';
import { cn } from '@/lib/utils';
import { ACCENT, Panel, SectionLabel } from '@/components/quantum-scan/ui';
import type { ExposureAssessment, ExposureFinding } from '@/lib/scanner/exposure/types';
import { layerLabel } from '@/lib/scanner/exposure/correlate';
import type { AssetRow, StandardRow } from '@/lib/scanner/exposure/panel-model';
import { evidencePopulation, summariseAssets, summariseStandards } from '@/lib/scanner/exposure/panel-model';
import { QUANTUM_COLOR, QUANTUM_LABEL } from './shared';

/* ═══════════════════════════════════════════════════ asset inventory (§64) ══ */

/* `deriveAssets` lives in `panel-model` so the check tool asserts the SAME
   derivation the panel renders. It used to live here, which is how it keyed
   asset rows on `layer|name` for months without a single check noticing. */

const ASSET_STATE_STYLE: Record<AssetRow['state'], { color: string; label: string }> = {
  scanned: { color: ACCENT.emerald, label: 'Scanned' },
  partial: { color: ACCENT.rose, label: 'Engine failed' },
  'not-assessed': { color: ACCENT.amber, label: 'Not assessed' },
};

export function AssetInventory({ assessment }: { assessment: ExposureAssessment }) {
  const [limit, setLimit] = React.useState(25);
  const { rows: assets, scanned, gaps, filesAnalyzed, clean } = React.useMemo(
    () => summariseAssets(assessment),
    [assessment],
  );
  const visible = assets.slice(0, limit);

  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] px-5 py-3">
        <SectionLabel>Scanned Assets</SectionLabel>
        {/* "carrying evidence", not "scanned". The table can only hold an asset
            that produced a finding or a component, so the row count is not the
            size of the scanned estate and must not be labelled as if it were. */}
        <span className="font-mono text-[10px] text-slate-500">
          {scanned} carrying evidence{gaps > 0 ? ` · ${gaps} with gaps` : ''}
        </span>
      </div>

      {clean > 0 && (
        <p className="border-b border-white/[0.06] px-5 py-2 font-mono text-[10px] leading-relaxed text-slate-500">
          The scan analysed {filesAnalyzed.toLocaleString()} files; {clean.toLocaleString()} of them yielded no
          cryptographic component and no finding, so they have no row here. Absence of a row means nothing was observed
          in that file — not that it was skipped. Anything the scan could not read is listed under Assessment Coverage.
        </p>
      )}

      {assets.length === 0 ? (
        <p className="px-5 py-8 text-center text-[12px] text-slate-500">
          No assets were recorded. An engine that reported &quot;not applicable&quot; had nothing in scope to read, which is
          not the same as a clean result.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[46rem] border-collapse text-left">
            <thead>
              <tr className="border-b border-white/[0.06] font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-500">
                <th className="px-5 py-2 font-bold">Asset</th>
                <th className="px-3 py-2 font-bold">Layer</th>
                <th className="px-3 py-2 font-bold">State</th>
                <th className="px-3 py-2 text-right font-bold">Components</th>
                <th className="px-3 py-2 text-right font-bold">Findings</th>
                <th className="px-3 py-2 text-right font-bold">Critical</th>
                {/* Named for the unit it counts. The Quantum Exposure panel
                    counts components; this column counts findings, and an
                    unlabelled "Quantum" column made the two look comparable. */}
                <th className="px-5 py-2 text-right font-bold">Quantum (findings)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {visible.map((asset) => {
                const style = ASSET_STATE_STYLE[asset.state];
                return (
                  <tr key={asset.id} className="align-top">
                    <td className="max-w-[22rem] px-5 py-2.5">
                      <p className="truncate text-[12px] font-semibold text-white" title={asset.name}>
                        {asset.name}
                      </p>
                      {asset.detail && (
                        <p className="mt-0.5 text-[10.5px] leading-snug text-slate-500">{asset.detail}</p>
                      )}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-[10.5px] text-slate-400">{asset.kind}</td>
                    <td className="px-3 py-2.5">
                      <span
                        className="inline-flex items-center rounded px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase tracking-widest"
                        style={{ backgroundColor: `${style.color}18`, color: style.color }}
                      >
                        {style.label}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 text-right font-mono text-[11.5px] text-slate-300">{asset.components || '—'}</td>
                    <td className="px-3 py-2.5 text-right font-mono text-[11.5px] text-slate-300">{asset.findings || '—'}</td>
                    <td className="px-3 py-2.5 text-right font-mono text-[11.5px]" style={{ color: asset.critical ? ACCENT.rose : '#64748b' }}>
                      {asset.critical || '—'}
                    </td>
                    <td className="px-5 py-2.5 text-right">
                      {asset.quantumVulnerable > 0 && (
                        <span className="font-mono text-[11.5px]" style={{ color: QUANTUM_COLOR.vulnerable }}>
                          {asset.quantumVulnerable} vuln
                        </span>
                      )}
                      {asset.hybrid > 0 && (
                        <span className="ml-2 font-mono text-[11.5px]" style={{ color: QUANTUM_COLOR.hybrid }}>
                          {asset.hybrid} hybrid
                        </span>
                      )}
                      {asset.pqc > 0 && (
                        <span className="ml-2 font-mono text-[11.5px]" style={{ color: QUANTUM_COLOR.pqc }}>
                          {asset.pqc} pqc
                        </span>
                      )}
                      {asset.quantumVulnerable === 0 && asset.pqc === 0 && asset.hybrid === 0 && (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {assets.length > visible.length && (
        <button
          type="button"
          onClick={() => setLimit((current) => current + 50)}
          className="w-full border-t border-white/[0.06] px-5 py-2.5 text-[11.5px] font-semibold text-cyan-300 transition-colors hover:bg-cyan-400/[0.05]"
        >
          Show {Math.min(50, assets.length - visible.length)} more of {assets.length}
        </button>
      )}
    </Panel>
  );
}

/* ══════════════════════════════════════════════════ evidence matrix (§47) ══ */

const ALL_LAYERS = ['api', 'ast', 'configuration', 'data-flow', 'dependency', 'lexical', 'runtime', 'cross-scanner'] as const;

const LAYER_SHORT: Record<string, string> = {
  api: 'API', ast: 'AST', configuration: 'CFG', 'data-flow': 'FLOW',
  dependency: 'DEP', lexical: 'LEX', runtime: 'RT', 'cross-scanner': 'XSC',
};

const LAYER_NAME: Record<string, string> = {
  api: 'API semantics',
  ast: 'Syntactic analysis',
  configuration: 'Configuration directive',
  'data-flow': 'Data-flow correlation',
  dependency: 'Dependency declaration',
  lexical: 'Lexical match',
  runtime: 'Runtime observation',
  'cross-scanner': 'Cross-scanner correlation',
};

function layerName(layer: string): string {
  return LAYER_NAME[layer] ?? layer;
}

/**
 * Which detection layers backed each finding (§47).
 *
 * This is the panel that makes confidence auditable. A finding backed by API
 * semantics plus a lexical match is a different thing from one backed by a
 * lexical match alone, and until the layers are visible a reader has to take
 * the confidence score on trust.
 */
const EVIDENCE_ROW_LIMIT = 30;

export function EvidenceMatrix({ assessment }: { assessment: ExposureAssessment }) {
  /* The population this table can speak about at all: a finding with no
     detection layer has nothing to plot. Derived in `panel-model` so the
     footnote's denominators are the ones the check tool asserts, and kept
     separate from the rows the cap dropped — they are two different exclusions
     and collapsing them misreports both. */
  const { corroborated, unbacked } = React.useMemo(() => evidencePopulation(assessment), [assessment]);

  const rows = React.useMemo(() => {
    return assessment.findings
      .map((finding) => {
        const layers = new Set<string>();
        let groundTruth = '';
        let confidenceScore: number | null = null;

        for (const evidence of finding.evidence) {
          const layer = evidence.attributes?.detectionLayer;
          if (typeof layer === 'string') layers.add(layer);
          const truth = evidence.attributes?.groundTruth;
          if (typeof truth === 'string') groundTruth = truth;
          const score = evidence.attributes?.confidenceScore;
          if (typeof score === 'number') confidenceScore = score;
        }

        return { finding, layers, groundTruth, confidenceScore };
      })
      .filter((row) => row.layers.size > 0)
      .sort((a, b) => b.layers.size - a.layers.size || (b.confidenceScore ?? 0) - (a.confidenceScore ?? 0))
      .slice(0, EVIDENCE_ROW_LIMIT);
  }, [assessment]);

  if (rows.length === 0) return null;

  const layersInUse = ALL_LAYERS.filter((layer) => rows.some((row) => row.layers.has(layer)));

  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.violet}>Evidence Matrix</SectionLabel>
        <span className="font-mono text-[10px] text-slate-500">{layersInUse.length} detection layers in use</span>
      </div>
      <p className="border-b border-white/[0.06] px-5 py-2.5 text-[11.5px] leading-relaxed text-slate-400">
        Confidence comes from how many <strong className="font-bold text-slate-200">independent</strong> layers agree — not
        from how many times a pattern matched. A finding backed by API semantics and a lexical match is corroborated; the
        same string seen twice by one layer is not.
      </p>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[44rem] border-collapse text-left">
          <thead>
            <tr className="border-b border-white/[0.06] font-mono text-[9px] uppercase tracking-[0.12em] text-slate-500">
              <th className="px-5 py-2 font-bold">Finding</th>
              {layersInUse.map((layer) => (
                <th key={layer} className="px-2 py-2 text-center font-bold" title={layerName(layer)}>
                  {LAYER_SHORT[layer]}
                </th>
              ))}
              <th className="px-3 py-2 text-right font-bold">Conf.</th>
              <th className="px-5 py-2 font-bold">Truth</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.04]">
            {rows.map((row) => (
              <tr key={row.finding.id}>
                <td className="max-w-[20rem] px-5 py-2">
                  <p className="truncate text-[11.5px] text-slate-200" title={row.finding.title}>
                    {row.finding.title}
                  </p>
                </td>
                {layersInUse.map((layer) => (
                  <td key={layer} className="px-2 py-2 text-center">
                    {row.layers.has(layer) ? (
                      <span
                        title={`${layerName(layer)} contributed`}
                        className="inline-block h-2 w-2 rounded-full"
                        style={{ backgroundColor: layer === 'lexical' ? ACCENT.slate : ACCENT.cyan }}
                      />
                    ) : (
                      <span aria-hidden className="text-slate-800">·</span>
                    )}
                  </td>
                ))}
                <td className="px-3 py-2 text-right font-mono text-[11px] text-slate-300">
                  {row.confidenceScore !== null ? `${row.confidenceScore}%` : '—'}
                </td>
                <td
                  className="px-5 py-2 font-mono text-[9.5px] uppercase tracking-wider"
                  style={{ color: row.groundTruth === 'CONFIRMED' ? ACCENT.emerald : ACCENT.amber }}
                >
                  {row.groundTruth || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {/* Two DIFFERENT exclusions, and collapsing them misreports both. A
          finding is absent from this table either because it carries no
          detection-layer evidence at all (it cannot be corroborated, so it has
          no row to show) or because it ranked below the cap. The note used to
          say only "the N best-corroborated of M findings", which described
          every absence as a ranking decision — so 16 findings with no layer
          evidence whatsoever read as merely lower-ranked. */}
      {(assessment.findings.length > rows.length || unbacked > 0) && (
        <p className="border-t border-white/[0.06] px-5 py-2 font-mono text-[10px] leading-relaxed text-slate-500">
          Showing the {rows.length.toLocaleString()} best-corroborated of {corroborated.toLocaleString()} findings that
          carry detection-layer evidence
          {unbacked > 0 && (
            <>
              . A further {unbacked.toLocaleString()} of the scan&apos;s {assessment.findings.length.toLocaleString()}{' '}
              findings record no detection layer and cannot be corroborated here — they are absent from this table, not
              ranked below it
            </>
          )}
          .
        </p>
      )}
    </Panel>
  );
}

/* ════════════════════════════════════════════════ standards panel (§75-76) ══ */

/* `StandardRow` is the one in `panel-model`. A local re-declaration shadowed the
   imported type here, so the panel's own derivation could drift from the one the
   check tool asserts without TypeScript noticing. */

const OBLIGATION_COLOR: Record<string, string> = {
  REQUIRED: ACCENT.rose,
  RECOMMENDED: ACCENT.cyan,
  DRAFT: ACCENT.amber,
  INFORMATIONAL: ACCENT.slate,
  INDUSTRY_PRACTICE: ACCENT.slate,
  QGUARD_RULE: ACCENT.violet,
};

/**
 * Which standards the findings cite, and — the part §76 insists on — WHO each
 * one actually binds.
 *
 * CNSA 2.0 is required for National Security Systems. OMB M-23-02 binds federal
 * civilian agencies. Neither is a legal requirement for a commercial company,
 * and a compliance table that omits the applicability quietly converts guidance
 * into an obligation the reader does not have.
 */
export function StandardsPanel({ assessment }: { assessment: ExposureAssessment }) {
  /* Derived in `panel-model`, not here. The tally used to increment once per
     matching REFERENCE while the column is labelled "N findings", so a finding
     citing two clauses of the same publication counted twice and the column
     silently became a citation count. Keeping the derivation in one module is
     what lets the check tool assert the unit matches the label. */
  const { rows, cited, uncited, total } = React.useMemo(() => summariseStandards(assessment), [assessment]);

  if (rows.length === 0) return null;

  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.amber}>Standards Cited</SectionLabel>
        <span className="font-mono text-[10px] text-slate-500">
          {rows.length} publications · {cited.toLocaleString()} of {total.toLocaleString()} findings
        </span>
      </div>
      <p className="border-b border-white/[0.06] px-5 py-2.5 text-[11.5px] leading-relaxed text-slate-400">
        Each citation states <strong className="font-bold text-slate-200">who it binds</strong>. A NIST recommendation is
        not a legal requirement, CNSA 2.0 applies only to National Security Systems, and a QGuard rule is this
        platform&apos;s judgement rather than an external obligation.
      </p>

      <ul className="divide-y divide-white/[0.04]">
        {rows.map((row) => (
          <li key={row.publication} className="px-5 py-3">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <p className="min-w-0 flex-1 text-[12.5px] font-semibold text-white">{row.publication}</p>
              <div className="flex shrink-0 items-center gap-2">
                <span
                  className="rounded px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase tracking-widest"
                  style={{
                    backgroundColor: `${OBLIGATION_COLOR[row.requirementType] ?? ACCENT.slate}18`,
                    color: OBLIGATION_COLOR[row.requirementType] ?? ACCENT.slate,
                  }}
                >
                  {row.requirementType.replace(/_/g, ' ')}
                </span>
                <span className="font-mono text-[10px] text-slate-500">
                  {row.findings} finding{row.findings === 1 ? '' : 's'}
                </span>
              </div>
            </div>
            <p className="mt-1 text-[11.5px] leading-relaxed text-slate-400">
              <Scale aria-hidden className="mr-1 inline h-3 w-3 -translate-y-px text-slate-500" />
              {row.applicability}
            </p>
          </li>
        ))}
      </ul>

      {/* The findings no publication speaks to. The per-row totals sum to far
          MORE than the finding count — one finding cites several publications —
          so the arithmetic can never reveal this gap, and a compliance reader
          counting rows would read the table as covering the whole scan. */}
      {uncited > 0 && (
        <p className="border-t border-white/[0.06] px-5 py-2.5 font-mono text-[10px] leading-relaxed text-slate-500">
          {uncited.toLocaleString()} of the scan&apos;s {total.toLocaleString()} findings cite no publication and are
          absent from this table. A finding with no citation carries QGuard&apos;s own judgement, not an external
          obligation — the rows above never account for it.
        </p>
      )}
    </Panel>
  );
}

/* ═══════════════════════════════════════════════════ detection summary ═════ */

/**
 * A compact summary of HOW the scan detected what it detected.
 *
 * Answers §93's questions on false-positive reduction, evidence establishment
 * and confidence calculation from the assessment's own numbers rather than from
 * a claim in a marketing panel.
 */
export function DetectionSummary({ assessment }: { assessment: ExposureAssessment }) {
  const stats = React.useMemo(() => {
    const layers = new Map<string, number>();
    let confirmed = 0;
    let potential = 0;
    let withCaveats = 0;

    for (const finding of assessment.findings) {
      for (const evidence of finding.evidence) {
        const layer = evidence.attributes?.detectionLayer;
        if (typeof layer === 'string') layers.set(layer, (layers.get(layer) ?? 0) + 1);
        if (evidence.attributes?.caveats) withCaveats += 1;
      }
      const truth = finding.evidence[0]?.attributes?.groundTruth;
      if (truth === 'CONFIRMED') confirmed += 1;
      else if (truth === 'POTENTIAL') potential += 1;
    }

    const sorted = [...layers.entries()].sort((a, b) => b[1] - a[1]);
    const total = sorted.reduce((sum, [, value]) => sum + value, 0);
    /* Findings whose engine records no determination state (§90's UNKNOWN).
       Without this reading the tiles silently fail to add up to the finding
       count, and a reader comparing "1 finding" against "0 confirmed, 0
       potential" is left to guess which of the two is wrong. */
    const notEstablished = assessment.findings.length - confirmed - potential;
    return { layers: sorted, total, confirmed, potential, withCaveats, notEstablished };
  }, [assessment]);

  if (stats.layers.length === 0) return null;

  return (
    <Panel className="overflow-hidden">
      <div className="border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.blue}>How This Was Detected</SectionLabel>
      </div>

      <div className="grid grid-cols-2 gap-px bg-white/[0.05] sm:grid-cols-5">
        {[
          { label: 'Confirmed', value: stats.confirmed, color: ACCENT.emerald, hint: 'Direct evidence, corroborated by more than one layer' },
          { label: 'Potential', value: stats.potential, color: ACCENT.amber, hint: 'Evidence is suggestive, not conclusive' },
          { label: 'Not established', value: stats.notEstablished, color: ACCENT.slate, hint: 'The engine recorded no determination state for these findings' },
          { label: 'Detection layers', value: stats.layers.length, color: ACCENT.cyan, hint: 'Independent methods that contributed' },
          { label: 'With caveats', value: stats.withCaveats, color: ACCENT.slate, hint: 'Observations carrying a recorded doubt' },
        ].map((tile) => (
          <div key={tile.label} className="bg-[#080d1a] px-4 py-3" title={tile.hint}>
            <p className="font-mono text-[9px] font-bold uppercase tracking-[0.14em] text-slate-500">{tile.label}</p>
            <p className="mt-0.5 font-mono text-[19px] font-black leading-none" style={{ color: tile.color }}>
              {tile.value}
            </p>
          </div>
        ))}
      </div>

      <div className="border-t border-white/[0.06] px-5 py-3">
        <p className="font-mono text-[9.5px] font-bold uppercase tracking-[0.16em] text-slate-500">Observations per layer</p>
        <div className="mt-2 space-y-1.5">
          {stats.layers.map(([layer, count]) => (
            <div key={layer} className="flex items-center gap-2.5">
              <span className="w-28 shrink-0 font-mono text-[10.5px] text-slate-400">{layerName(layer)}</span>
              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/[0.06]">
                <div
                  className="h-full rounded-full"
                  style={{
                    width: `${stats.total ? Math.round((count / stats.total) * 100) : 0}%`,
                    backgroundColor: layer === 'lexical' ? ACCENT.slate : ACCENT.cyan,
                  }}
                />
              </div>
              <span className="w-8 shrink-0 text-right font-mono text-[10.5px] text-slate-500">{count}</span>
            </div>
          ))}
        </div>
        <p className="mt-2.5 text-[11px] leading-relaxed text-slate-500">
          Confirmed, Potential and Not established sum to the {assessment.findings.length} finding
          {assessment.findings.length === 1 ? '' : 's'} above. A lexical match alone never reaches high confidence. API semantics, configuration directives and parsed
          structures do, because they establish what the cryptography is being used <em>for</em> — which is what makes a
          migration recommendation role-appropriate rather than generic.
        </p>
      </div>
    </Panel>
  );
}

/* ═════════════════════════════════════════════ reconciliation (§53, §88) ═══ */

/** Matches MAX_ROWS in src/api-server/exposure-persistence.ts. */
const PERSISTENCE_ROW_CAP = 2_000;

/**
 * What this scan contributes to the rest of the platform.
 *
 * The counts here are the counts the other modules will show, derived from the
 * same arrays the persistence layer writes — CBOM components to
 * `crypto_inventory`, findings to `pqc_scan_results`, quantum-vulnerable
 * findings to `crypto_exposures`. Rendering them side by side is the only way a
 * reader can tell that the scanner's "47 components" and the CBOM page's "47
 * components" are the same 47, and the row cap is stated rather than silently
 * applied.
 */
export function ReconciliationPanel({
  assessment,
  synced,
}: {
  assessment: ExposureAssessment;
  /** True once the assessment has actually been written to the tenant's estate. */
  synced?: boolean;
}) {
  const rows = React.useMemo(() => {
    const exposures = assessment.findings.filter(
      (finding) => finding.quantumStatus === 'vulnerable' && finding.severity !== 'info',
    ).length;

    return [
      {
        label: 'Cryptographic components',
        count: assessment.cbom.length,
        destination: 'CBOM Explorer · Assets & CBOM',
        note: 'Counted as components, never as findings — the two are different units.',
      },
      {
        label: 'Findings',
        count: assessment.findings.length,
        destination: 'Vulnerabilities · Scanner history',
        note: 'One row per distinct issue after correlation.',
      },
      {
        label: 'Quantum-vulnerable exposures',
        count: exposures,
        destination: 'Crypto Exposure · Quantum Readiness',
        note: 'Vulnerable findings above informational severity.',
      },
      {
        label: 'Correlated exposures',
        count: assessment.exposures.length,
        destination: 'Exposure Graph',
        note: 'Findings that several engines proved to be the same underlying issue.',
      },
    ];
  }, [assessment]);

  const capped = rows.some((row) => row.count > PERSISTENCE_ROW_CAP);

  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-5 py-3">
        <SectionLabel accent={ACCENT.emerald}>Platform Reconciliation</SectionLabel>
        <span
          className="rounded px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase tracking-widest"
          style={
            synced
              ? { backgroundColor: `${ACCENT.emerald}18`, color: ACCENT.emerald }
              : { backgroundColor: `${ACCENT.slate}18`, color: ACCENT.slate }
          }
        >
          {synced ? 'In estate' : 'Not yet synced'}
        </span>
      </div>
      <p className="border-b border-white/[0.06] px-5 py-2.5 text-[11.5px] leading-relaxed text-slate-400">
        These are the exact counts the rest of the platform will show for this scan. They are read from this
        assessment&apos;s own arrays — the same arrays the persistence layer writes — so the scanner and the modules
        downstream can never disagree about how much was found.
      </p>

      <ul className="divide-y divide-white/[0.04]">
        {rows.map((row) => (
          <li key={row.label} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-5 py-2.5">
            <span className="font-mono text-[17px] font-black leading-none text-white">{row.count}</span>
            <span className="min-w-0 flex-1">
              <span className="block text-[12px] font-semibold text-slate-200">{row.label}</span>
              <span className="block text-[10.5px] leading-snug text-slate-500">{row.note}</span>
            </span>
            <span className="shrink-0 font-mono text-[10px] text-cyan-300/70">{row.destination}</span>
          </li>
        ))}
      </ul>

      {capped && (
        <p className="border-t border-amber-400/20 bg-amber-400/[0.05] px-5 py-2.5 text-[11px] leading-relaxed text-amber-100/85">
          This scan exceeds the {PERSISTENCE_ROW_CAP.toLocaleString()}-row synchronisation cap. The dashboard above shows
          every result; the synchronised estate will hold the first {PERSISTENCE_ROW_CAP.toLocaleString()} of each kind,
          and the scan session records that it was truncated.
        </p>
      )}
    </Panel>
  );
}

/* ═══════════════════════════════════════════════ engine health (§61, §85) ══ */

export interface EngineHealthRow {
  id: string;
  label: string;
  capability: string;
  health: string;
  healthDetail: string;
  version?: string;
  ruleSetVersion?: string;
  minTier?: string | null;
}

export interface KnowledgeBaseBadge {
  version: string;
  ruleSetVersion: string;
  algorithms: number;
  rules: number;
  standards: number;
}

const HEALTH_COLOR: Record<string, string> = {
  healthy: ACCENT.emerald,
  degraded: ACCENT.amber,
  unavailable: ACCENT.slate,
};

/**
 * Live engine health and versions.
 *
 * §61: do not report an engine as healthy unless the backend actually reports
 * it as healthy. Every row here comes from the registry's health probe; nothing
 * on this panel is hard-coded green.
 */
export function EngineHealthPanel({
  engines,
  knowledgeBase,
  defaultOpen = false,
}: {
  engines: EngineHealthRow[];
  knowledgeBase?: KnowledgeBaseBadge | null;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = React.useState(defaultOpen);
  const unhealthy = engines.filter((engine) => engine.health !== 'healthy');

  if (engines.length === 0) return null;

  return (
    <Panel className="overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((current) => !current)}
        aria-expanded={open}
        className="flex w-full items-center justify-between gap-3 px-5 py-3 text-left transition-colors hover:bg-white/[0.02]"
      >
        <span className="flex items-center gap-2">
          <Cpu aria-hidden className="h-3.5 w-3.5 text-slate-400" />
          {/* "Engine Registry", not "Scanner Engines": this is what the platform
              HAS — every engine, its version, its rule set and its live health.
              The ledger panel above it is what one assessment DID. */}
          <span className="font-mono text-[11px] font-bold uppercase tracking-[0.22em] text-slate-300">Engine Registry</span>
        </span>
        <span className="flex shrink-0 items-center gap-2">
          <span
            className="font-mono text-[10px]"
            style={{ color: unhealthy.length ? ACCENT.amber : ACCENT.emerald }}
          >
            {engines.length - unhealthy.length}/{engines.length} healthy
          </span>
          <ChevronDown className={cn('h-4 w-4 text-slate-500 transition-transform', open && 'rotate-180')} />
        </span>
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25 }}
            className="overflow-hidden border-t border-white/[0.06]"
          >
            {knowledgeBase && (
              <div className="grid grid-cols-2 gap-px bg-white/[0.05] sm:grid-cols-5">
                {[
                  { label: 'Knowledge base', value: `v${knowledgeBase.version}` },
                  { label: 'Rule set', value: `v${knowledgeBase.ruleSetVersion}` },
                  { label: 'Algorithms', value: String(knowledgeBase.algorithms) },
                  { label: 'QGH rules', value: String(knowledgeBase.rules) },
                  { label: 'Standards', value: String(knowledgeBase.standards) },
                ].map((tile) => (
                  <div key={tile.label} className="bg-[#080d1a] px-4 py-2.5">
                    <p className="font-mono text-[8.5px] font-bold uppercase tracking-[0.14em] text-slate-500">{tile.label}</p>
                    <p className="mt-0.5 font-mono text-[13px] font-bold text-slate-200">{tile.value}</p>
                  </div>
                ))}
              </div>
            )}

            <ul className="max-h-[24rem] divide-y divide-white/[0.04] overflow-y-auto">
              {engines.map((engine) => (
                <li key={engine.id} className="flex items-start gap-2.5 px-5 py-2">
                  <span
                    aria-hidden
                    className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full"
                    style={{ backgroundColor: HEALTH_COLOR[engine.health] ?? ACCENT.slate }}
                  />
                  <span className="min-w-0 flex-1">
                    <span className="flex flex-wrap items-center gap-1.5">
                      <span className="text-[12px] font-semibold text-slate-200">{engine.label}</span>
                      {engine.version && engine.version !== 'unversioned' && (
                        <span className="font-mono text-[9.5px] text-cyan-300/70">v{engine.version}</span>
                      )}
                      <span className="font-mono text-[9px] uppercase tracking-wider text-slate-600">{engine.capability}</span>
                      {engine.minTier && (
                        <span className="rounded bg-amber-400/12 px-1 py-0.5 font-mono text-[8.5px] uppercase tracking-widest text-amber-300">
                          {engine.minTier}
                        </span>
                      )}
                    </span>
                    <span className="mt-0.5 block text-[10.5px] leading-snug text-slate-500">{engine.healthDetail}</span>
                  </span>
                </li>
              ))}
            </ul>

            <p className="border-t border-white/[0.06] px-5 py-2.5 text-[11px] leading-relaxed text-slate-500">
              Health is a live probe of each engine, not a static list. Every finding carries the engine and rule version
              that produced it, so a difference between two scans can be attributed to a rule change rather than to the
              estate having changed.
            </p>
          </motion.div>
        )}
      </AnimatePresence>
    </Panel>
  );
}

/* ═════════════════════════════════════════ classification card (§9, §45) ═══ */

const CLASSICAL_COLOR: Record<string, string> = {
  STRONG: ACCENT.emerald,
  ACCEPTABLE: ACCENT.cyan,
  LEGACY: ACCENT.amber,
  BROKEN: ACCENT.rose,
  UNKNOWN: ACCENT.slate,
};

/**
 * The two independent verdicts, side by side.
 *
 * This is the component that makes §9 legible. RSA-2048 shows CLASSICAL:
 * ACCEPTABLE next to QUANTUM: VULNERABLE, and the rationale explains why both
 * are true at once. A single badge cannot say that, and the collapsed
 * distinction is what produces "your RSA is broken" in a customer's inbox.
 */
export function ClassificationCard({ finding }: { finding: ExposureFinding }) {
  const classical = finding.evidence
    .map((evidence) => evidence.attributes?.classicalSecurity)
    .find((value): value is string => typeof value === 'string');

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-2 sm:grid-cols-2">
      <div className="rounded-xl border border-white/[0.07] bg-white/[0.02] px-3.5 py-3">
        <p className="font-mono text-[9px] font-bold uppercase tracking-[0.16em] text-slate-500">Classical security</p>
        <p className="mt-1 text-[14px] font-black" style={{ color: CLASSICAL_COLOR[classical ?? 'UNKNOWN'] }}>
          {classical ?? 'Not established'}
        </p>
        <p className="mt-1 text-[11px] leading-relaxed text-slate-400">
          Resistance to the cryptanalysis available today.
        </p>
      </div>

      <div className="rounded-xl border border-white/[0.07] bg-white/[0.02] px-3.5 py-3">
        <p className="font-mono text-[9px] font-bold uppercase tracking-[0.16em] text-slate-500">Quantum posture</p>
        <p className="mt-1 text-[14px] font-black" style={{ color: QUANTUM_COLOR[finding.quantumStatus] }}>
          {QUANTUM_LABEL[finding.quantumStatus]}
        </p>
        <p className="mt-1 text-[11px] leading-relaxed text-slate-400">
          {finding.quantumStatus === 'vulnerable'
            ? 'A migration candidate — not a statement that it is breakable today.'
            : 'Posture against a cryptographically relevant quantum computer.'}
        </p>
      </div>

      {finding.quantumRationale && (
        <p className="rounded-xl border border-violet-400/20 bg-violet-400/[0.05] px-3.5 py-2.5 text-[11.5px] leading-relaxed text-violet-100/85 sm:col-span-2">
          <Sparkles aria-hidden className="mr-1.5 inline h-3 w-3 -translate-y-px" />
          {finding.quantumRationale}
        </p>
      )}
    </div>
  );
}

/* ══════════════════════════════════════════════════════════ the section ════ */

/**
 * Every intelligence panel, in reading order, for the Local and Dev result
 * views. One insertion point so both modes stay identical — a difference
 * between them would be a difference in what the product is willing to disclose
 * about its own reasoning, which is not a difference worth having.
 */
export function ScannerIntelligenceSection({
  assessment,
  synced,
}: {
  assessment: ExposureAssessment;
  synced?: boolean;
}) {
  return (
    <>
      <AssetInventory assessment={assessment} />
      <DetectionSummary assessment={assessment} />
      <EvidenceMatrix assessment={assessment} />
      <StandardsPanel assessment={assessment} />
      <ReconciliationPanel assessment={assessment} synced={synced} />
    </>
  );
}
