/**
 * What makes two primitives a HYBRID construction — ONE rule, both engines.
 *
 * ── The defect this removes ─────────────────────────────────────────────────
 *
 * A hybrid deployment is a classical asymmetric primitive run ALONGSIDE a
 * post-quantum one, so the construction survives if either half holds:
 * X25519 + ML-KEM-768, Ed25519 + ML-DSA-65, sntrup761 + x25519. It is
 * completed migration work, and the platform reports it as such.
 *
 * Both classification engines expressed that as "one side is post-quantum
 * asymmetric and the other is not":
 *
 *     if (partner && selfIsPqc !== partnerIsPqc) return HYBRID
 *
 * `!selfIsPqc` is true for EVERY primitive that is not post-quantum asymmetric
 * — which includes every hash, every symmetric cipher, every MAC and every KDF.
 * So any of those, paired with a post-quantum partner, was published as a
 * hybrid construction. A real Dev scan of this repository published:
 *
 *     MD5    HYBRID   "MD5 is combined with ML-KEM ... This is completed
 *                      migration work, not an exposure."
 *     DES    HYBRID
 *     RC4    HYBRID
 *     SHA-1  HYBRID
 *     AES    HYBRID
 *
 * MD5 cannot be the classical half of a hybrid key exchange. There is no such
 * construction. The verdict did not merely mislabel the primitive — it told a
 * reader that a broken hash was finished migration work.
 *
 * ── The rule ────────────────────────────────────────────────────────────────
 *
 * A hybrid construction needs BOTH halves to be asymmetric primitives of the
 * kind that carry the key agreement or the signature:
 *
 *   · exactly one post-quantum asymmetric primitive (Shor does not break it), and
 *   · exactly one classical asymmetric primitive (Shor does break it).
 *
 * Anything else is not a pair. A hash beside a KEM is two unrelated primitives
 * that happen to appear together, and each is classified on its own merits.
 *
 * Pure and dependency-free so both engines can import it: the crypto knowledge
 * base (`src/lib/crypto/knowledge-base/classify.ts`) and the exposure
 * catalogue (`src/lib/scanner/exposure/algorithms.ts`) describe algorithms with
 * different shapes, so each maps its own record onto `HybridParticipant` and
 * the DECISION is made here, once.
 */

/** The two facts the hybrid rule needs, whatever the catalogue shape. */
export interface HybridParticipant {
  /**
   * True for key establishment, digital signature and public-key encryption —
   * the primitives a hybrid construction is actually built from.
   */
  asymmetric: boolean;
  /** True when Shor's algorithm breaks the primitive. */
  shorBroken: boolean;
}

/** An asymmetric primitive Shor does NOT break. */
export function isPostQuantumAsymmetric(entry: HybridParticipant | null | undefined): boolean {
  return Boolean(entry && entry.asymmetric && !entry.shorBroken);
}

/** An asymmetric primitive Shor DOES break — the classical half of a hybrid. */
export function isClassicalAsymmetric(entry: HybridParticipant | null | undefined): boolean {
  return Boolean(entry && entry.asymmetric && entry.shorBroken);
}

/**
 * Resolve two primitives into the halves of a hybrid construction.
 *
 * Returns `null` when they do not form one — which is the answer for a hash, a
 * symmetric cipher, a MAC, a KDF, two classical primitives, or two
 * post-quantum primitives. The caller then classifies each on its own.
 */
export function hybridRoles<T extends HybridParticipant>(
  self: T,
  partner: T | null | undefined,
): { classical: T; pqc: T } | null {
  if (!partner) return null;

  if (isPostQuantumAsymmetric(self) && isClassicalAsymmetric(partner)) {
    return { classical: partner, pqc: self };
  }
  if (isClassicalAsymmetric(self) && isPostQuantumAsymmetric(partner)) {
    return { classical: self, pqc: partner };
  }
  return null;
}
