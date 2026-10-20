/**
 * Recommended actions — ONE ranking for every surface.
 *
 * The Recommended Actions panel, a recorded assessment rebuilt by the History
 * tab and the exported report's complete Engine Recommendations register all
 * read `rankRecommendations`, so the same evidence always produces the same
 * actions in the same order. The panel shows the first `RECOMMENDATION_LIMIT`;
 * the register carries every one.
 *
 * Pure and dependency-light on purpose (types, risk, correlate): the report
 * builder is lazy-loaded, and importing this from the orchestrator would drag
 * every scan engine into the report chunk.
 */

import type { CorrelatedExposure, ExposureFinding, ExposureIntelligence, FindingSeverity } from './types';
import { SEVERITY_ORDER } from './types';
import { prioritiseMigration } from './risk';
import { layerLabel } from './correlate';

/** Rows the Recommended Actions panel shows; the rest are counted, never dropped silently. */
export const RECOMMENDATION_LIMIT = 10;

/** One recommended action, as every surface renders it. */
export type RankedRecommendation = ExposureIntelligence['recommendations'][number];

interface DraftRecommendation {
  title: string;
  detail: string;
  severity: FindingSeverity;
  effort: 'low' | 'medium' | 'high';
  findingIds: string[];
  /** The `prioritiseMigration` score behind a migration action; urgent
   *  non-migration actions carry none. Orders actions within one severity. */
  priorityScore?: number;
}

const EFFORT_RANK: Record<'low' | 'medium' | 'high', number> = { low: 0, medium: 1, high: 2 };

/**
 * The ONE order every recommended action is ranked in: severity first, then —
 * within a severity — urgent present-tense work (a committed key, a disabled
 * certificate check) ahead of migration advice, then the migration priority
 * score, then how much of the estate the action covers.
 */
function compareRecommendations(a: DraftRecommendation, b: DraftRecommendation): number {
  return (
    SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
    Number(b.priorityScore === undefined) - Number(a.priorityScore === undefined) ||
    (b.priorityScore ?? 0) - (a.priorityScore ?? 0) ||
    b.findingIds.length - a.findingIds.length
  );
}

/**
 * Collapse recommendations that ask for the SAME work.
 *
 * Recommendations are generated per correlated exposure, and several exposures
 * legitimately resolve to one action — every RSA signature in the estate
 * migrates to ML-DSA. Rendered one row per exposure, the panel repeated a
 * single sentence up to five times, each row citing a fraction of the findings,
 * and the repetition pushed genuinely different actions off the list.
 *
 * Merging keeps the worst severity (the action is as urgent as its most urgent
 * driver), the largest effort (the work is as big as its hardest part), the
 * best priority score and the union of the findings, so the row still names
 * everything it covers and the counts still reconcile against the assessment.
 */
function mergeRecommendations(drafts: DraftRecommendation[]): DraftRecommendation[] {
  const merged = new Map<string, DraftRecommendation & { sources: number }>();

  for (const draft of drafts) {
    const key = draft.title.trim().toLowerCase();
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, { ...draft, findingIds: [...new Set(draft.findingIds)], sources: 1 });
      continue;
    }
    existing.findingIds = [...new Set([...existing.findingIds, ...draft.findingIds])];
    existing.sources += 1;
    if (SEVERITY_ORDER[draft.severity] < SEVERITY_ORDER[existing.severity]) existing.severity = draft.severity;
    if (EFFORT_RANK[draft.effort] > EFFORT_RANK[existing.effort]) existing.effort = draft.effort;
    if ((draft.priorityScore ?? -Infinity) > (existing.priorityScore ?? -Infinity)) existing.priorityScore = draft.priorityScore;
  }

  return [...merged.values()]
    .sort(compareRecommendations)
    .map(({ sources, ...entry }) => ({
      ...entry,
      /* Say that the row stands for several observations, rather than letting a
         merged row look like a single one. */
      detail: sources > 1
        ? `${entry.detail} Consolidated from ${sources} correlated exposures covering ${entry.findingIds.length} finding${entry.findingIds.length === 1 ? '' : 's'}.`
        : entry.detail,
    }));
}

/**
 * Every distinct recommended action the evidence supports, in the ONE order.
 * Nothing here is capped.
 */
export function rankRecommendations(input: {
  findings: ExposureFinding[];
  exposures: CorrelatedExposure[];
}): RankedRecommendation[] {
  const { findings, exposures } = input;

  /* Recommendations are derived from the exposures, so every one of them names
     the findings it came from and can be traced back. `mergeRecommendations`
     then collapses rows that say the SAME thing: the panel used to print "Plan
     migration to ML-DSA (FIPS 204)" as five separate actions and "SSL (legacy)
     is broken by classical cryptanalysis" four times, splitting one piece of
     work across rows and pushing everything else off the list. */
  const mergedMigration = mergeRecommendations(
    prioritiseMigration(exposures).map((entry) => ({
      title: entry.exposure.recommendation ?? `Address ${entry.exposure.title}`,
      detail: `${entry.priority} — ${entry.drivers.length ? entry.drivers.join(', ') : 'base severity only'}. ${entry.exposure.evidence.length} evidence source${entry.exposure.evidence.length === 1 ? '' : 's'} across ${entry.exposure.layers.map(layerLabel).join(' → ')}.`,
      severity: entry.exposure.severity,
      effort: (entry.exposure.migration?.complexity ?? 'medium') as 'low' | 'medium' | 'high',
      findingIds: entry.exposure.findingIds,
      priorityScore: entry.score,
    })),
  );

  /* Urgent work that migration advice does not cover, so a committed private
     key is not buried under algorithm advice.

     This used to select on `quantumStatus === 'not-applicable'`. Secret
     findings carry `unknown` — an algorithm verdict was never attempted for
     them — so the filter matched nothing that mattered and six CRITICAL "PEM
     private key block" findings never reached the panel, which is the exact
     outcome the rule was written to prevent. Selecting by "not already covered
     by a migration recommendation" states the real intent and cannot be
     defeated by a status the finding was never going to carry.

     EVERY migration action is consulted, not only the ones that make the
     panel: a finding a migration action already covers must not be counted
     again as urgent work. */
  const citedByMigration = new Set(mergedMigration.flatMap((entry) => entry.findingIds));
  const mergedUrgent = mergeRecommendations(
    findings
      .filter(
        (finding) =>
          (finding.severity === 'critical' || finding.severity === 'high') &&
          !finding.migration?.candidate &&
          !citedByMigration.has(finding.id),
      )
      .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
      .map((finding) => ({
        title: finding.recommendation ?? finding.title,
        detail: `${finding.severity.toUpperCase()} — ${finding.title}. ${finding.evidence[0]?.summary ?? ''}`,
        severity: finding.severity,
        effort: 'low' as const,
        findingIds: [finding.id],
      })),
  );

  /* ONE ranked list. This used to take the first 4 urgent and the first 8
     migration actions, put the urgent ones on top and cut at 10 — so the
     panel's "the 10 highest-priority of N" was false whenever more than eight
     migration actions outranked an urgent one: a HIGH urgent action sat at #1
     while CRITICAL migration actions were dropped below the cap. */
  return [...mergedUrgent, ...mergedMigration]
    .sort(compareRecommendations)
    .map((entry) => ({
      title: entry.title,
      detail: entry.detail,
      severity: entry.severity,
      effort: entry.effort,
      findingIds: entry.findingIds,
    }));
}
