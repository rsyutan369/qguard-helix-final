/** Published transition references. These describe policy, not tenant posture. */
export const PQC_TRANSITION_SOURCES = {
  nist: {
    label: 'NIST IR 8547 (final)',
    url: 'https://csrc.nist.gov/pubs/ir/8547/final',
    published: '2026-10-27',
    deprecationStarts: '2031-01-01',
    disallowanceStarts: '2036-01-01',
    summary: 'NIST deprecates quantum-vulnerable public-key cryptography after 2030 and disallows it under its standards and guidance after 2035.',
  },
  nccoe: {
    label: 'NIST NCCoE migration project',
    url: 'https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc',
    summary: 'Practical guidance for cryptographic inventory, risk prioritization and interoperability testing in a controlled environment.',
  },
  fips: {
    label: 'NIST FIPS 203, 204 and 205',
    url: 'https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards',
    published: '2024-08-13',
    summary: 'ML-KEM (FIPS 203) is for key establishment. ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) are for digital signatures.',
  },
  executiveOrder: {
    label: 'U.S. Executive Order 14412',
    url: 'https://www.whitehouse.gov/presidential-actions/2026/06/securing-the-nation-against-advanced-cryptographic-attacks/',
    published: '2026-06-22',
    summary: 'U.S. federal high value assets and high impact systems, excluding National Security Systems: PQC for key establishment by December 31, 2030 and for digital signatures by December 31, 2031.',
  },
  omb: {
    label: 'OMB M-26-15',
    url: 'https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf',
    published: '2026-06-24',
    summary: 'U.S. federal agencies must prioritize migration by risk, including systems with highly sensitive data or particular quantum exposure, and submit a migration plan to OMB and ONCD within 120 days of issuance. The memo excludes National Security Systems.',
  },
} as const
