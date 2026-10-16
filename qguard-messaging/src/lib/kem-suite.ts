/**
 * Whether a peer device's published cryptographic suite can actually
 * interoperate with this build's KEM.
 *
 * WHY THIS EXISTS: `suite.pq_kem` is not a reliable identifier. Every build
 * shipped before the FIPS 203 cutover published `"ML-KEM-1024"` while running
 * Kyber-1024 (PQClean round 3) underneath, and the two have byte-identical key
 * and ciphertext lengths — 1568 either way. So neither the label nor a length
 * check can tell them apart, every signature over the key still verifies, and
 * the device looks perfectly addressable.
 *
 * Sealing across that boundary is silent, total data loss: encapsulation
 * succeeds, the envelope is well-formed and validly signed, and the recipient
 * derives a DIFFERENT shared secret — so the message lands in their history as
 * a permanent decrypt failure while the sender is shown a delivered message.
 * Both clients keep displaying "E2EE active".
 *
 * The discriminator is `pq_kem_standard`, which only the FIPS 203 build writes.
 * Its ABSENCE is the signal, which is why the check is an allow-list: anything
 * that does not positively declare the standard this build implements is
 * treated as unable to interoperate.
 *
 * The Rust side enforces the same rule in `messaging_send_encrypted_message`
 * (`verify_recipient_kem_interoperates`) — this copy exists so the UI can drop
 * such devices from delivery and explain why, not to be the gate.
 */

/** Must match `CURRENT_PQ_KEM` in src-tauri/src/crypto/mod.rs. */
export const CURRENT_PQ_KEM = "ML-KEM-1024";

/** Must match `CURRENT_PQ_KEM_STANDARD` in src-tauri/src/crypto/mod.rs. */
export const CURRENT_PQ_KEM_STANDARD = "FIPS-203";

/** How a pre-cutover device's real KEM is described to the user. */
export const LEGACY_PQ_KEM_PRE_FIPS = "Kyber-1024 (pre-FIPS-203)";

/**
 * Must match `CURRENT_KEM_COMBINER` in src-tauri/src/crypto/mod.rs.
 *
 * A device that publishes this is sealed to with the transcript-bound combiner
 * (`KemCombiner::for_peer_suite`); anything else gets the legacy one. A
 * ciphertext that carries no label was made with the legacy combiner.
 */
export const CURRENT_KEM_COMBINER = "QGuard-HybridKEM-v2";

/** Whether a published suite or a ciphertext suite names the bound combiner. */
export function usesBoundCombiner(suite: PublishedSuite): boolean {
  return Boolean(suite && typeof suite === "object" && suite.kem_combiner === CURRENT_KEM_COMBINER);
}

/** The `suite` JSON a device publishes to `messaging_devices.suite`. */
export type PublishedSuite = Record<string, unknown> | null | undefined;

export function kemInteroperates(suite: PublishedSuite): boolean {
  if (!suite || typeof suite !== "object") return false;
  return (
    suite.pq_kem === CURRENT_PQ_KEM
    && suite.pq_kem_standard === CURRENT_PQ_KEM_STANDARD
  );
}

/**
 * One line explaining why a device was dropped from delivery, or null when it
 * is fine. Phrased for a user, not a log: the action they need is "update the
 * other device", and nothing they do on THIS device can help.
 */
export function describeKemIncompatibility(suite: PublishedSuite): string | null {
  if (kemInteroperates(suite)) return null;
  return `registered with pre-FIPS-203 key material (${LEGACY_PQ_KEM_PRE_FIPS}), which cannot decrypt anything this build seals — that device must be updated to the FIPS 203 build`;
}
