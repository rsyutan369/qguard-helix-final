/**
 * TLS named key-agreement groups — the one table.
 *
 * These three facts (which ML-KEM parameter set a hybrid group carries, and what
 * its two halves are called) are needed by the edge prober, by the algorithm
 * census and by the published scoring model. They used to live inside
 * `public-scan/engines/tls-engine.ts`, which opens sockets — so anything pure
 * that needed them either imported a module full of `node:tls`, or kept its own
 * copy. The second option is how two surfaces came to feed the census different
 * key-agreement primitives for one handshake, and scored the same endpoint's
 * Cryptographic Algorithms category 33 and 40.
 *
 * This module is pure data plus one regex. `tls-engine.ts` re-exports it, so its
 * importers are unchanged.
 */

/** ML-KEM parameter set carried by each hybrid group, per the TLS registry. */
export const HYBRID_GROUP_KEM: Record<string, string> = {
  X25519MLKEM768: 'ML-KEM-768',
  SecP256r1MLKEM768: 'ML-KEM-768',
  SecP384r1MLKEM1024: 'ML-KEM-1024',
}

/**
 * The two halves of each hybrid group, named separately.
 *
 * A hybrid group is a COMBINATION, and a report that prints only the registry
 * name ("X25519MLKEM768") makes the reader decode it. Both components are named
 * so the evidence line can state what protects the session classically and what
 * protects it against a CRQC — they are different guarantees with different
 * failure modes, and collapsing them loses the whole point of hybrid.
 */
export const HYBRID_GROUP_COMPONENTS: Record<string, { classical: string; postQuantum: string }> = {
  X25519MLKEM768: { classical: 'X25519 (Curve25519 ECDHE)', postQuantum: 'ML-KEM-768 (FIPS 203)' },
  SecP256r1MLKEM768: { classical: 'secp256r1 / P-256 ECDHE', postQuantum: 'ML-KEM-768 (FIPS 203)' },
  SecP384r1MLKEM1024: { classical: 'secp384r1 / P-384 ECDHE', postQuantum: 'ML-KEM-1024 (FIPS 203)' },
}

/** ML-KEM parameter set for a standalone group name (`MLKEM768` → ML-KEM-768). */
export function groupKemLabel(group: string): string {
  const match = group.match(/MLKEM(\d+)/i)
  return match ? `ML-KEM-${match[1]}` : ''
}

/**
 * Every ML-KEM parameter set implied by a set of accepted groups.
 *
 * The named table first (a hybrid group's KEM is registry-defined), then the
 * regex for standalone groups the table does not list.
 */
export function kemParameterSetsFor(groups: readonly string[]): string[] {
  return Array.from(
    new Set(groups.map((group) => HYBRID_GROUP_KEM[group] ?? groupKemLabel(group)).filter(Boolean)),
  )
}
