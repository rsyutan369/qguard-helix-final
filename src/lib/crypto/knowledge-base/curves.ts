/**
 * Named-curve intelligence (§8, §10).
 *
 * §8: "Do not assume every ECC curve has the same security properties."
 *
 * They differ in three ways that matter to an assessment:
 *
 *  1. STRENGTH. P-224 offers ~112-bit classical security and is disallowed for
 *     new use; P-521 offers ~260. Reporting both as "ECC" loses the finding.
 *  2. ROLE. X25519 is key agreement only; Ed25519 is signatures only. A scanner
 *     that says "Curve25519 used for signing" when it saw X25519 is wrong.
 *  3. PROVENANCE. secp256k1 has no rigid seed and is not a NIST curve;
 *     brainpool curves are verifiably pseudo-random. That is a governance fact
 *     some customers must report on, and it cannot be recovered later.
 *
 * Every curve is quantum-vulnerable — Shor breaks the discrete-log problem
 * regardless of the curve. The differences above are CLASSICAL, and the model
 * keeps the two axes separate exactly as §9 requires.
 */

import type { ClassicalSecurity, CurveDefinition } from './types';

export const CURVES: CurveDefinition[] = [
  /* ── NIST prime curves (FIPS 186-5) ───────────────────────────────────── */
  {
    curveId: 'p-192',
    canonicalName: 'P-192 (secp192r1)',
    aliases: ['p-192', 'p192', 'secp192r1', 'prime192v1', 'nistp192'],
    bits: 192,
    classicalStrength: 96,
    classicalSecurity: 'BROKEN',
    family: 'nist-prime',
    oid: '1.2.840.10045.3.1.1',
    roles: ['digital-signature', 'key-establishment'],
    rigid: false,
    note: 'P-192 provides roughly 96 bits of classical security and is below every current minimum. NIST disallows it for new use.',
  },
  {
    curveId: 'p-224',
    canonicalName: 'P-224 (secp224r1)',
    aliases: ['p-224', 'p224', 'secp224r1', 'nistp224'],
    bits: 224,
    classicalStrength: 112,
    classicalSecurity: 'LEGACY',
    family: 'nist-prime',
    oid: '1.3.132.0.33',
    tlsGroupId: 21,
    roles: ['digital-signature', 'key-establishment'],
    rigid: false,
    note: 'P-224 provides roughly 112 bits of classical security — the floor NIST deprecated for new use after 2030.',
  },
  {
    curveId: 'p-256',
    canonicalName: 'P-256 (secp256r1)',
    aliases: ['p-256', 'p256', 'secp256r1', 'prime256v1', 'nistp256', 'ecdsa-p256'],
    bits: 256,
    classicalStrength: 128,
    classicalSecurity: 'STRONG',
    family: 'nist-prime',
    oid: '1.2.840.10045.3.1.7',
    tlsGroupId: 23,
    roles: ['digital-signature', 'key-establishment', 'certificate-public-key'],
    rigid: false,
    note: 'P-256 provides roughly 128 bits of classical security and is the most widely deployed curve on the public web.',
  },
  {
    curveId: 'p-384',
    canonicalName: 'P-384 (secp384r1)',
    aliases: ['p-384', 'p384', 'secp384r1', 'nistp384', 'ecdsa-p384'],
    bits: 384,
    classicalStrength: 192,
    classicalSecurity: 'STRONG',
    family: 'nist-prime',
    oid: '1.3.132.0.34',
    tlsGroupId: 24,
    roles: ['digital-signature', 'key-establishment', 'certificate-public-key'],
    rigid: false,
    note: 'P-384 provides roughly 192 bits of classical security. It is the elliptic curve named by CNSA 1.0 for National Security Systems.',
  },
  {
    curveId: 'p-521',
    canonicalName: 'P-521 (secp521r1)',
    aliases: ['p-521', 'p521', 'secp521r1', 'nistp521', 'ecdsa-p521'],
    bits: 521,
    classicalStrength: 260,
    classicalSecurity: 'STRONG',
    family: 'nist-prime',
    oid: '1.3.132.0.35',
    tlsGroupId: 25,
    roles: ['digital-signature', 'key-establishment', 'certificate-public-key'],
    rigid: false,
  },

  /* ── Koblitz ──────────────────────────────────────────────────────────── */
  {
    curveId: 'secp256k1',
    canonicalName: 'secp256k1',
    aliases: ['secp256k1', 'k-256'],
    bits: 256,
    classicalStrength: 128,
    classicalSecurity: 'STRONG',
    family: 'koblitz',
    oid: '1.3.132.0.10',
    roles: ['digital-signature'],
    rigid: false,
    note: 'secp256k1 is the Bitcoin/Ethereum curve. It is not a NIST curve and is not approved under FIPS 186-5, which matters for federal and regulated deployments even though its classical strength is comparable to P-256.',
  },

  /* ── Edwards / Montgomery ─────────────────────────────────────────────── */
  {
    curveId: 'curve25519',
    canonicalName: 'Curve25519 (X25519)',
    aliases: ['curve25519', 'x25519', '25519'],
    bits: 255,
    classicalStrength: 128,
    classicalSecurity: 'STRONG',
    family: 'montgomery',
    oid: '1.3.101.110',
    tlsGroupId: 29,
    /* Key agreement ONLY. X25519 cannot sign — conflating it with Ed25519 is a
       real and common classification error. */
    roles: ['key-establishment'],
    rigid: true,
    note: 'X25519 is a key-agreement function only; it cannot produce signatures. Its signing counterpart on the same underlying curve is Ed25519.',
  },
  {
    curveId: 'curve448',
    canonicalName: 'Curve448 (X448)',
    aliases: ['curve448', 'x448', '448'],
    bits: 448,
    classicalStrength: 224,
    classicalSecurity: 'STRONG',
    family: 'montgomery',
    oid: '1.3.101.111',
    tlsGroupId: 30,
    roles: ['key-establishment'],
    rigid: true,
  },
  {
    curveId: 'ed25519',
    canonicalName: 'Ed25519',
    aliases: ['ed25519', 'edwards25519'],
    bits: 255,
    classicalStrength: 128,
    classicalSecurity: 'STRONG',
    family: 'edwards',
    oid: '1.3.101.112',
    /* Signatures ONLY. */
    roles: ['digital-signature', 'certificate-public-key'],
    rigid: true,
    note: 'Ed25519 is a signature scheme only; it does not perform key agreement. Its key-agreement counterpart is X25519.',
  },
  {
    curveId: 'ed448',
    canonicalName: 'Ed448',
    aliases: ['ed448', 'edwards448'],
    bits: 448,
    classicalStrength: 224,
    classicalSecurity: 'STRONG',
    family: 'edwards',
    oid: '1.3.101.113',
    roles: ['digital-signature', 'certificate-public-key'],
    rigid: true,
  },

  /* ── Brainpool ────────────────────────────────────────────────────────── */
  {
    curveId: 'brainpoolp256r1',
    canonicalName: 'brainpoolP256r1',
    aliases: ['brainpoolp256r1', 'brainpool256'],
    bits: 256,
    classicalStrength: 128,
    classicalSecurity: 'STRONG',
    family: 'brainpool',
    oid: '1.3.36.3.3.2.8.1.1.7',
    tlsGroupId: 26,
    roles: ['digital-signature', 'key-establishment'],
    rigid: true,
    note: 'Brainpool curves use verifiably pseudo-random parameters. They are widely used in Europe but are not FIPS-approved.',
  },
  {
    curveId: 'brainpoolp384r1',
    canonicalName: 'brainpoolP384r1',
    aliases: ['brainpoolp384r1', 'brainpool384'],
    bits: 384,
    classicalStrength: 192,
    classicalSecurity: 'STRONG',
    family: 'brainpool',
    oid: '1.3.36.3.3.2.8.1.1.11',
    tlsGroupId: 27,
    roles: ['digital-signature', 'key-establishment'],
    rigid: true,
  },
  {
    curveId: 'brainpoolp512r1',
    canonicalName: 'brainpoolP512r1',
    aliases: ['brainpoolp512r1', 'brainpool512'],
    bits: 512,
    classicalStrength: 256,
    classicalSecurity: 'STRONG',
    family: 'brainpool',
    oid: '1.3.36.3.3.2.8.1.1.13',
    tlsGroupId: 28,
    roles: ['digital-signature', 'key-establishment'],
    rigid: true,
  },

  /* ── Binary-field NIST curves (legacy) ────────────────────────────────── */
  {
    curveId: 'b-163',
    canonicalName: 'B-163 (sect163r2)',
    aliases: ['b-163', 'sect163r2', 'nistb163'],
    bits: 163,
    classicalStrength: 80,
    classicalSecurity: 'BROKEN',
    family: 'nist-binary',
    oid: '1.3.132.0.15',
    roles: ['digital-signature', 'key-establishment'],
    note: 'Binary-field curves at this size provide roughly 80 bits of classical security and are disallowed for new use.',
  },
  {
    curveId: 'b-283',
    canonicalName: 'B-283 (sect283r1)',
    aliases: ['b-283', 'sect283r1', 'nistb283'],
    bits: 283,
    classicalStrength: 128,
    classicalSecurity: 'LEGACY',
    family: 'nist-binary',
    oid: '1.3.132.0.17',
    roles: ['digital-signature', 'key-establishment'],
    note: 'Binary-field curves are deprecated in FIPS 186-5 for new use in favour of prime curves.',
  },
];

/* ─────────────────────────────────────────────────────────────── lookup ───── */

const BY_ALIAS = (() => {
  const map = new Map<string, CurveDefinition>();
  for (const curve of CURVES) {
    map.set(curve.canonicalName.toLowerCase(), curve);
    map.set(curve.curveId, curve);
    for (const alias of curve.aliases) map.set(alias, curve);
    if (curve.oid) map.set(curve.oid, curve);
  }
  return map;
})();

const BY_TLS_GROUP = (() => {
  const map = new Map<number, CurveDefinition>();
  for (const curve of CURVES) {
    if (curve.tlsGroupId !== undefined) map.set(curve.tlsGroupId, curve);
  }
  return map;
})();

/**
 * Resolve a curve name, OID or TLS group name.
 *
 * Exact alias match only, after normalisation. A substring scan is deliberately
 * NOT used here: "p-256" is a substring of "brainpoolp256r1", and matching the
 * wrong curve is worse than matching none.
 */
export function findCurve(raw: string | null | undefined): CurveDefinition | null {
  if (!raw) return null;
  const text = raw.trim().toLowerCase();
  if (!text) return null;

  const direct = BY_ALIAS.get(text);
  if (direct) return direct;

  // Normalise separators: "secp256_r1", "SECP 256 R1", "P_256".
  const normalised = text.replace(/[\s_]+/g, '').replace(/^ecdsa-/, '').replace(/^ecdh-/, '');
  const byNormalised = BY_ALIAS.get(normalised);
  if (byNormalised) return byNormalised;

  // Hyphen-insensitive: "p256" vs "p-256".
  const dehyphenated = normalised.replace(/-/g, '');
  for (const [alias, curve] of BY_ALIAS) {
    if (alias.replace(/-/g, '') === dehyphenated) return curve;
  }

  return null;
}

export function curveByTlsGroup(groupId: number): CurveDefinition | null {
  return BY_TLS_GROUP.get(groupId) ?? null;
}

/**
 * Can this curve legitimately serve this role?
 *
 * Used to catch a real classification error: reporting X25519 as a signature
 * algorithm, or Ed25519 as a key-agreement one.
 */
export function curveSupportsRole(curve: CurveDefinition, role: string): boolean {
  return curve.roles.includes(role as CurveDefinition['roles'][number]);
}

/** Classical verdict for a curve, with the reason. */
export function curveClassicalVerdict(curve: CurveDefinition): { security: ClassicalSecurity; rationale: string } {
  return {
    security: curve.classicalSecurity,
    rationale:
      curve.note ??
      `${curve.canonicalName} provides approximately ${curve.classicalStrength} bits of classical security.`,
  };
}

export function knownCurves(): string[] {
  return CURVES.map((curve) => curve.canonicalName);
}
