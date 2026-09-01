/**
 * Standards Intelligence Engine (§41, §42, §43, §75, §76).
 *
 * A metadata layer so scanner rules can cite authority without hard-coding it,
 * and — more importantly — so the platform can never misrepresent WHAT KIND of
 * obligation a citation carries.
 *
 * §76 names the specific misrepresentation to avoid: a NIST final standard
 * rendered as "a federal legal requirement for every organization". FIPS 203 is
 * a standard; CNSA 2.0 binds National Security Systems; OMB M-23-02 binds
 * federal civilian agencies; a CA/Browser Forum ballot binds publicly-trusted
 * CAs. None of those is "everyone", and `applicability` says so on every entry.
 *
 * §75: "Only include a mapping when the relationship is legitimate. Do not
 *       fabricate compliance mappings." Every entry here is a document that
 *       exists, cited for a claim it actually makes. Where this platform holds
 *       an opinion that no authority states, the requirement type is
 *       `QGUARD_RULE` and it is labelled as such in the UI.
 */

import type { RequirementType, StandardAuthority, StandardReference, StandardStatus } from './types';

/* ─────────────────────────────────────────────────────────────── catalogue ── */

function ref(input: {
  id: string;
  authority: StandardAuthority;
  publication: string;
  status?: StandardStatus;
  requirementType: RequirementType;
  applicability: string;
  section?: string;
  url?: string;
  effective?: string;
  version?: string;
}): StandardReference {
  return {
    standardId: input.id,
    authority: input.authority,
    publication: input.publication,
    version: input.version,
    status: input.status ?? 'FINAL',
    requirementType: input.requirementType,
    applicability: input.applicability,
    section: input.section,
    sourceUrl: input.url,
    effectiveDate: input.effective,
  };
}

/**
 * The standards this platform cites. Keyed by id so a rule can reference one
 * without restating it.
 */
export const STANDARDS: Record<string, StandardReference> = {
  /* ── NIST post-quantum standards (§41) ────────────────────────────────── */
  'FIPS-203': ref({
    id: 'FIPS-203',
    authority: 'NIST',
    publication: 'FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard',
    requirementType: 'RECOMMENDED',
    applicability: 'Federal agencies for key establishment; adopted voluntarily elsewhere.',
    effective: '2024-08-13',
    url: 'https://csrc.nist.gov/pubs/fips/203/final',
  }),
  'FIPS-204': ref({
    id: 'FIPS-204',
    authority: 'NIST',
    publication: 'FIPS 204: Module-Lattice-Based Digital Signature Standard',
    requirementType: 'RECOMMENDED',
    applicability: 'Federal agencies for digital signatures; adopted voluntarily elsewhere.',
    effective: '2024-08-13',
    url: 'https://csrc.nist.gov/pubs/fips/204/final',
  }),
  'FIPS-205': ref({
    id: 'FIPS-205',
    authority: 'NIST',
    publication: 'FIPS 205: Stateless Hash-Based Digital Signature Standard',
    requirementType: 'RECOMMENDED',
    applicability: 'Federal agencies for digital signatures where a conservative hash-based scheme is preferred.',
    effective: '2024-08-13',
    url: 'https://csrc.nist.gov/pubs/fips/205/final',
  }),

  /* ── NIST classical cryptography ──────────────────────────────────────── */
  'SP-800-57': ref({
    id: 'SP-800-57',
    authority: 'NIST',
    publication: 'SP 800-57 Part 1 Rev. 5: Recommendation for Key Management',
    requirementType: 'RECOMMENDED',
    applicability: 'Federal systems; widely adopted as industry guidance.',
    section: 'Table 2 — comparable security strengths',
    url: 'https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final',
  }),
  'SP-800-131A': ref({
    id: 'SP-800-131A',
    authority: 'NIST',
    publication: 'SP 800-131A Rev. 2: Transitioning the Use of Cryptographic Algorithms and Key Lengths',
    requirementType: 'RECOMMENDED',
    applicability: 'Federal systems. Defines which algorithms and key lengths are acceptable, deprecated, or disallowed.',
    url: 'https://csrc.nist.gov/pubs/sp/800/131/a/r2/final',
  }),
  'SP-800-52': ref({
    id: 'SP-800-52',
    authority: 'NIST',
    publication: 'SP 800-52 Rev. 2: Guidelines for the Selection, Configuration, and Use of TLS Implementations',
    requirementType: 'RECOMMENDED',
    applicability: 'Federal servers and clients. Requires TLS 1.2 minimum and support for TLS 1.3.',
    url: 'https://csrc.nist.gov/pubs/sp/800/52/r2/final',
  }),
  'SP-800-56A': ref({
    id: 'SP-800-56A',
    authority: 'NIST',
    publication: 'SP 800-56A Rev. 3: Recommendation for Pair-Wise Key-Establishment Using Discrete Logarithm Cryptography',
    requirementType: 'RECOMMENDED',
    applicability: 'Federal systems using DH / ECDH key establishment.',
    url: 'https://csrc.nist.gov/pubs/sp/800/56/a/r3/final',
  }),
  'SP-800-56B': ref({
    id: 'SP-800-56B',
    authority: 'NIST',
    publication: 'SP 800-56B Rev. 2: Recommendation for Pair-Wise Key-Establishment Using Integer Factorization Cryptography',
    requirementType: 'RECOMMENDED',
    applicability: 'Federal systems using RSA-based key establishment.',
    url: 'https://csrc.nist.gov/pubs/sp/800/56/b/r2/final',
  }),
  'FIPS-186-5': ref({
    id: 'FIPS-186-5',
    authority: 'NIST',
    publication: 'FIPS 186-5: Digital Signature Standard (DSS)',
    requirementType: 'RECOMMENDED',
    applicability: 'Federal digital signatures. Withdraws DSA for signature generation; approves RSA, ECDSA and EdDSA.',
    url: 'https://csrc.nist.gov/pubs/fips/186-5/final',
  }),
  'FIPS-140-3': ref({
    id: 'FIPS-140-3',
    authority: 'NIST',
    publication: 'FIPS 140-3: Security Requirements for Cryptographic Modules',
    requirementType: 'REQUIRED',
    applicability: 'Cryptographic modules used by U.S. federal agencies to protect sensitive information.',
    url: 'https://csrc.nist.gov/pubs/fips/140-3/final',
  }),
  'SP-800-131A-SHA1': ref({
    id: 'SP-800-131A-SHA1',
    authority: 'NIST',
    publication: 'SP 800-131A Rev. 2 — SHA-1 disallowed for digital signature generation',
    requirementType: 'RECOMMENDED',
    applicability: 'Federal systems. SHA-1 is disallowed for signature generation and for most other uses after 2030 per NIST\'s published transition.',
    url: 'https://csrc.nist.gov/pubs/sp/800/131/a/r2/final',
  }),
  'SP-800-63B': ref({
    id: 'SP-800-63B',
    authority: 'NIST',
    publication: 'SP 800-63B: Digital Identity Guidelines — Authentication and Lifecycle Management',
    requirementType: 'RECOMMENDED',
    applicability: 'Federal digital identity systems. Defines memorised-secret verifier requirements including password hashing.',
    section: '5.1.1.2',
    url: 'https://pages.nist.gov/800-63-3/sp800-63b.html',
  }),
  'SP-800-90A': ref({
    id: 'SP-800-90A',
    authority: 'NIST',
    publication: 'SP 800-90A Rev. 1: Recommendation for Random Number Generation Using Deterministic Random Bit Generators',
    requirementType: 'RECOMMENDED',
    applicability: 'Federal systems generating cryptographic keys or nonces.',
    url: 'https://csrc.nist.gov/pubs/sp/800/90/a/r1/final',
  }),

  /* ── NSA / national security systems (§42) ────────────────────────────── */
  'CNSA-2.0': ref({
    id: 'CNSA-2.0',
    authority: 'NSA',
    publication: 'Commercial National Security Algorithm Suite 2.0',
    requirementType: 'REQUIRED',
    applicability:
      'NATIONAL SECURITY SYSTEMS ONLY. CNSA 2.0 binds NSS owners, operators and vendors — it is not a requirement for commercial or federal civilian systems.',
    url: 'https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3148990/',
  }),

  /* ── Federal civilian direction (§42) ─────────────────────────────────── */
  'OMB-M-23-02': ref({
    id: 'OMB-M-23-02',
    authority: 'OMB',
    publication: 'M-23-02: Migrating to Post-Quantum Cryptography',
    requirementType: 'REQUIRED',
    applicability:
      'FEDERAL CIVILIAN EXECUTIVE BRANCH AGENCIES ONLY. Directs agencies to inventory cryptographic systems; it does not bind private organisations.',
    effective: '2022-11-18',
    url: 'https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf',
  }),
  'CISA-PQC-ROADMAP': ref({
    id: 'CISA-PQC-ROADMAP',
    authority: 'CISA',
    publication: 'Post-Quantum Cryptography Initiative — preparing critical infrastructure',
    requirementType: 'RECOMMENDED',
    applicability: 'Critical infrastructure owners and operators. Guidance, not a regulation.',
    url: 'https://www.cisa.gov/quantum',
  }),

  /* ── IETF ─────────────────────────────────────────────────────────────── */
  'RFC-8996': ref({
    id: 'RFC-8996',
    authority: 'IETF',
    publication: 'RFC 8996: Deprecating TLS 1.0 and TLS 1.1',
    requirementType: 'RECOMMENDED',
    applicability: 'Implementations and deployments of TLS. Best Current Practice (BCP 195).',
    url: 'https://www.rfc-editor.org/rfc/rfc8996',
  }),
  'RFC-9325': ref({
    id: 'RFC-9325',
    authority: 'IETF',
    publication: 'RFC 9325: Recommendations for Secure Use of TLS and DTLS',
    requirementType: 'RECOMMENDED',
    applicability: 'Implementations and deployments of TLS. Best Current Practice.',
    url: 'https://www.rfc-editor.org/rfc/rfc9325',
  }),
  'RFC-7465': ref({
    id: 'RFC-7465',
    authority: 'IETF',
    publication: 'RFC 7465: Prohibiting RC4 Cipher Suites',
    requirementType: 'RECOMMENDED',
    applicability: 'TLS implementations. MUST NOT negotiate RC4.',
    url: 'https://www.rfc-editor.org/rfc/rfc7465',
  }),
  'RFC-6151': ref({
    id: 'RFC-6151',
    authority: 'IETF',
    publication: 'RFC 6151: Updated Security Considerations for MD5 and HMAC-MD5',
    requirementType: 'INFORMATIONAL',
    applicability: 'Protocol designers. MD5 is unsuitable for collision-resistant applications.',
    url: 'https://www.rfc-editor.org/rfc/rfc6151',
  }),
  'RFC-9151': ref({
    id: 'RFC-9151',
    authority: 'IETF',
    publication: 'RFC 9151: CNSA Suite Profile for TLS and DTLS 1.2 and 1.3',
    requirementType: 'INFORMATIONAL',
    applicability: 'Implementations serving National Security Systems.',
    url: 'https://www.rfc-editor.org/rfc/rfc9151',
  }),

  /* ── CA/Browser Forum ─────────────────────────────────────────────────── */
  'CABF-BR': ref({
    id: 'CABF-BR',
    authority: 'CA/Browser Forum',
    publication: 'Baseline Requirements for the Issuance and Management of Publicly-Trusted TLS Certificates',
    requirementType: 'REQUIRED',
    applicability:
      'PUBLICLY-TRUSTED CERTIFICATION AUTHORITIES ONLY. Prohibits SHA-1 signatures and RSA below 2048 bits for publicly-trusted certificates.',
    url: 'https://cabforum.org/working-groups/server/baseline-requirements/documents/',
  }),

  /* ── OWASP ────────────────────────────────────────────────────────────── */
  'OWASP-ASVS-V6': ref({
    id: 'OWASP-ASVS-V6',
    authority: 'ISO',
    publication: 'OWASP Application Security Verification Standard — V6 Stored Cryptography',
    requirementType: 'INDUSTRY_PRACTICE',
    applicability: 'Application security verification. Community standard, not a regulation.',
    url: 'https://owasp.org/www-project-application-security-verification-standard/',
  }),
};

/* ─────────────────────────────────────────────────────────────── accessors ── */

export function standard(id: string): StandardReference | null {
  return STANDARDS[id] ?? null;
}

/** Resolve a list of ids, silently dropping ones that do not exist. */
export function standardsFor(ids: readonly string[]): StandardReference[] {
  const out: StandardReference[] = [];
  for (const id of ids) {
    const entry = STANDARDS[id];
    if (entry) out.push(entry);
  }
  return out;
}

/**
 * A QGuard opinion, labelled as one.
 *
 * §76 requires internal rules to be distinguishable from authority guidance.
 * Any rule that cannot cite a real document cites this instead, and the UI
 * shows it as this platform's judgement rather than a standards obligation.
 */
export function qguardRule(topic: string, applicability = 'QGuard Helix assessment guidance.'): StandardReference {
  return {
    standardId: `QGUARD-${topic.toUpperCase().replace(/[^A-Z0-9]+/g, '-')}`,
    authority: 'QGuard',
    publication: `QGuard Helix assessment rule — ${topic}`,
    status: 'FINAL',
    requirementType: 'QGUARD_RULE',
    applicability,
  };
}

/**
 * Human sentence describing what a citation actually obliges.
 *
 * Used wherever a standard is displayed, so a reader never has to know that
 * CNSA 2.0 is NSS-only or that M-23-02 is civilian-agency-only.
 */
export function describeObligation(reference: StandardReference): string {
  const kind: Record<RequirementType, string> = {
    REQUIRED: 'Required',
    RECOMMENDED: 'Recommended',
    DRAFT: 'Draft — not final',
    INFORMATIONAL: 'Informational',
    INDUSTRY_PRACTICE: 'Industry practice',
    QGUARD_RULE: 'QGuard Helix rule',
  };
  return `${kind[reference.requirementType]} · ${reference.applicability}`;
}

/**
 * The canonical citation string carried on a finding's `references` array.
 *
 * One writer, because the dashboard's standards panel parses this shape back
 * out. When each engine formatted its own citation the panel silently dropped
 * the ones that differed by a character, and a missing row in a compliance
 * table reads as "this standard does not apply to you".
 */
export function citeStandard(reference: StandardReference): string {
  return `${reference.publication} — ${reference.requirementType}, applies to: ${reference.applicability}`;
}

/** Every authority cited, for the capability-disclosure endpoint. */
export function citedAuthorities(): StandardAuthority[] {
  return [...new Set(Object.values(STANDARDS).map((entry) => entry.authority))].sort();
}
