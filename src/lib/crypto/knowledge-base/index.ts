/**
 * QGuard Helix Crypto Knowledge Base™ (§7).
 *
 * The single import surface for everything the platform knows about
 * cryptography. Scanners import from here; they do not define algorithm facts
 * of their own.
 *
 *   types        the canonical model — 7-state quantum, separate classical axis
 *   algorithms   the algorithm registry
 *   curves       named-curve intelligence, with per-curve strength and role
 *   apis         call-shape semantics, library catalogue, RNG and KDF rules
 *   standards    the standards metadata layer, with obligation labelling
 *   classify     the classification engine
 *   rules        the QGH-* rule engine, versioned
 *   groundTruth  evidence quality, confidence and cross-scanner correlation
 *
 * Isomorphic throughout: this runs in the browser worker for LOCAL scans and on
 * the api-server for DEV scans, and produces identical verdicts in both.
 */

export * from './types';
export * from './algorithms';
export * from './curves';
export * from './apis';
export * from './standards';
export * from './classify';
export * from './rules';
export * from './ground-truth';

import { ALGORITHMS, knownAlgorithmNames, pqcAlgorithms, shorBrokenAlgorithms } from './algorithms';
import { CURVES, knownCurves } from './curves';
import { CRYPTO_APIS, KDF_PARAMETER_RULES, LIBRARIES, WEAK_RANDOM_RULES } from './apis';
import { STANDARDS, citedAuthorities } from './standards';
import { RULE_SET_VERSION, SCANNER_RULES } from './rules';
import { KNOWLEDGE_BASE_VERSION } from './ground-truth';

/**
 * What the knowledge base actually contains, for §54's capability disclosure
 * and for the §93 final audit.
 *
 * Every number here is `.length` on a real array. §89: never fabricate
 * coverage — if a count looks small, that is the honest count.
 */
export function knowledgeBaseSummary() {
  return {
    version: KNOWLEDGE_BASE_VERSION,
    ruleSetVersion: RULE_SET_VERSION,
    algorithms: {
      total: ALGORITHMS.length,
      quantumVulnerable: shorBrokenAlgorithms().length,
      postQuantumStandardised: pqcAlgorithms().length,
      names: knownAlgorithmNames(),
    },
    curves: { total: CURVES.length, names: knownCurves() },
    libraries: {
      total: LIBRARIES.length,
      postQuantumCapable: LIBRARIES.filter((entry) => entry.pqcCapable).length,
      names: LIBRARIES.map((entry) => entry.canonicalName),
    },
    apiRules: {
      total: CRYPTO_APIS.length,
      languages: [...new Set(CRYPTO_APIS.flatMap((entry) => entry.language))].sort(),
    },
    randomnessRules: WEAK_RANDOM_RULES.length,
    kdfParameterRules: KDF_PARAMETER_RULES.length,
    scannerRules: {
      total: SCANNER_RULES.length,
      ids: SCANNER_RULES.map((entry) => entry.ruleId),
    },
    standards: {
      total: Object.keys(STANDARDS).length,
      authorities: citedAuthorities(),
    },
  };
}
