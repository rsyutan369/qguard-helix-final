/**
 * Quantum Simulation Range — Mosca's inequality.
 *
 * WHY THIS EXISTS
 * ---------------
 * Harvest Now, Decrypt Later is the only quantum threat that is already
 * happening, and it is the one people find hardest to act on, because the loss
 * event is invisible. Mosca's inequality is the single cleanest way to make it
 * concrete:
 *
 *     X + Y > Z   ⟹   you are already exposed
 *
 *   X — how long the data must stay confidential (its shelf life)
 *   Y — how long the migration to post-quantum cryptography will take
 *   Z — how long until a cryptographically relevant quantum computer exists
 *
 * If a record captured today must stay secret for 15 years, and migration takes
 * 5, then any Z below 20 years means data being transmitted right now will be
 * readable inside its own confidentiality window. Nothing about that argument
 * depends on knowing Z precisely — which is what makes it usable.
 *
 * Reference: Mosca, "Cybersecurity in an era with quantum computers: will we be
 * ready?", IACR ePrint 2015/1075.
 */

export interface MoscaInputs {
  /** X — years the data must remain confidential. */
  shelfLifeYears: number;
  /** Y — years to complete the PQC migration. */
  migrationYears: number;
  /** Z — years until a CRQC exists. */
  crqcYears: number;
  /** Year the clock starts from. Defaults to the current year. */
  baseYear?: number;
}

export type MoscaVerdict = 'exposed' | 'marginal' | 'safe';

export interface MoscaResult extends Required<MoscaInputs> {
  /** X + Y. */
  totalYears: number;
  /** (X + Y) − Z. Positive means exposed. */
  exposureYears: number;
  verdict: MoscaVerdict;
  /** Calendar year by which migration must START to close the gap. */
  latestStartYear: number;
  /** Calendar year data captured today stops being safe. */
  breachYear: number;
  /** Calendar year the migration finishes if it starts today. */
  protectedFromYear: number;
  /**
   * Number of years of traffic that is captured after the safe-start deadline
   * has already passed — i.e. records being lost right now.
   */
  alreadyLostYears: number;
  headline: string;
  guidance: string;
}

export function evaluateMosca(inputs: MoscaInputs): MoscaResult {
  const baseYear = inputs.baseYear ?? new Date().getUTCFullYear();
  const { shelfLifeYears, migrationYears, crqcYears } = inputs;

  const totalYears = shelfLifeYears + migrationYears;
  const exposureYears = totalYears - crqcYears;

  let verdict: MoscaVerdict;
  if (exposureYears > 1) verdict = 'exposed';
  else if (exposureYears > -3) verdict = 'marginal';
  else verdict = 'safe';

  const latestStartYear = baseYear + (crqcYears - shelfLifeYears - migrationYears);
  const breachYear = baseYear + crqcYears;
  const protectedFromYear = baseYear + migrationYears;
  const alreadyLostYears = Math.max(0, baseYear - latestStartYear);

  const headline =
    verdict === 'exposed'
      ? `Exposed by ${exposureYears.toFixed(1)} years`
      : verdict === 'marginal'
        ? 'Marginal — no slack left'
        : `Safe by ${Math.abs(exposureYears).toFixed(1)} years`;

  const guidance =
    verdict === 'exposed'
      ? `Migration needed to start in ${latestStartYear} for every record to stay protected for its full shelf life. That deadline passed ${alreadyLostYears} year${alreadyLostYears === 1 ? '' : 's'} ago, so roughly the last ${alreadyLostYears} year${alreadyLostYears === 1 ? '' : 's'} of traffic sent under classical cryptography before migration finishes will be within a quantum adversary's reach before its confidentiality period ends. Prioritise the long-shelf-life data first: rotating a short-lived session key later costs nothing, re-encrypting twenty years of archived records costs everything.`
      : verdict === 'marginal'
        ? `Migration must begin no later than ${latestStartYear} — effectively immediately. Any slip in the ${migrationYears}-year migration estimate moves this into the exposed band, and migration estimates historically slip.`
        : `Data captured today stops needing protection in ${baseYear + shelfLifeYears}, before a CRQC is expected in ${breachYear}. Re-check whenever Z moves: it is the one variable you do not control.`;

  return {
    shelfLifeYears,
    migrationYears,
    crqcYears,
    baseYear,
    totalYears,
    exposureYears,
    verdict,
    latestStartYear,
    breachYear,
    protectedFromYear,
    alreadyLostYears,
    headline,
    guidance,
  };
}

/**
 * Typical confidentiality shelf lives, used as presets. These are regulatory or
 * practical retention periods, not guesses: each carries the reason it is what
 * it is, so a user can argue with the number rather than accept it.
 */
export interface ShelfLifePreset {
  id: string;
  label: string;
  years: number;
  basis: string;
}

export const SHELF_LIFE_PRESETS: ShelfLifePreset[] = [
  { id: 'session', label: 'Web session token', years: 0.01, basis: 'Minutes to hours. Nothing here is at HNDL risk.' },
  { id: 'financial', label: 'Financial transaction records', years: 7, basis: 'Common statutory retention period for accounting records.' },
  { id: 'pii', label: 'Customer PII', years: 10, basis: 'Identity data stays exploitable long after the relationship ends.' },
  { id: 'patent', label: 'Patent and R&D material', years: 20, basis: 'Standard patent term; pre-filing disclosure destroys the claim.' },
  { id: 'health', label: 'Health records', years: 50, basis: 'Retention rules vary by jurisdiction — HIPAA requires 6 years for documentation, while many national and state rules run to the patient’s lifetime or decades past last contact. 50 years is the long end of that range.' },
  { id: 'genomic', label: 'Genomic data', years: 100, basis: 'A genome identifies the subject and their relatives permanently. It cannot be rotated.' },
  { id: 'classified', label: 'Classified government material', years: 75, basis: 'E.O. 13526: automatic declassification falls at 25 years; exemptions can extend to 50 years and, for confidential human sources and key WMD design concepts, to 75 years. Keeping information classified beyond 75 years requires ISCAP approval. 75 is the long end, not the typical case.' },
  { id: 'ot', label: 'Industrial control system keys', years: 25, basis: 'Field device lifetimes routinely exceed two decades, and firmware is rarely re-keyed.' },
];

/**
 * Published views on Z. Deliberately a range from named sources rather than a
 * single number, because a single number would be the invention this page
 * exists to avoid.
 */
export interface CrqcEstimate {
  id: string;
  label: string;
  years: number;
  source: string;
}

export function crqcEstimates(baseYear = new Date().getUTCFullYear()): CrqcEstimate[] {
  return [
    {
      id: 'nist-disallow',
      label: `NIST planning horizon (${2035 - baseYear} yr)`,
      years: 2035 - baseYear,
      source:
        'A policy deadline, not a forecast: NIST IR 8547 ipd disallows quantum-vulnerable public-key cryptography after 2035. Used as a planning proxy for Z because it is the date federal systems are measured against.',
    },
    {
      id: 'nsa-cnsa',
      label: `CNSA 2.0 completion (${2035 - baseYear} yr)`,
      years: 2035 - baseYear,
      source:
        'Also a policy deadline rather than a forecast: NSA expects the CNSA 2.0 transition for national security systems to be complete by 2035, with earlier exclusive-use dates of 2030 and 2033 by equipment class.',
    },
    {
      id: 'gri-optimistic',
      label: 'Aggressive expert view (10 yr)',
      years: 10,
      source: 'The optimistic tail of the expert surveys collected in the Global Risk Institute Quantum Threat Timeline reports.',
    },
    {
      id: 'gri-median',
      label: 'Mid-range expert view (15 yr)',
      years: 15,
      source:
        'The middle of the range in the Global Risk Institute Quantum Threat Timeline surveys. The surveys report a spread of per-expert likelihoods rather than a single agreed median, so treat this as a mid-range marker, not a consensus date.',
    },
    {
      id: 'conservative',
      label: 'Conservative view (30 yr)',
      years: 30,
      source: 'The pessimistic tail: assumes error-correction overhead does not improve as fast as recent results suggest.',
    },
  ];
}
