/**
 * Governance catalog — the STRUCTURE of the compliance layer.
 *
 * This module declares which frameworks exist, which requirements each one
 * carries, and which platform controls satisfy them. It contains no tenant
 * data and no results: a control's status is always produced by evaluating the
 * tenant's own evidence (see `controls.ts`).
 *
 * Adding a framework is a data change here — a new `FrameworkDefinition` plus
 * its `RequirementDefinition` rows pointing at existing control ids. No
 * frontend change is required (§8: "allow additional frameworks to be added
 * without requiring major frontend restructuring").
 *
 * Requirement summaries are PARAPHRASED obligations written for this platform.
 * No requirement text is reproduced from a copyrighted standard; each row
 * carries a `reference` so a user can read the authoritative wording.
 */

import type { ControlDefinition, FrameworkDefinition, RequirementDefinition } from './types'

/* ================================================================== */
/* Controls — what the platform can actually measure                   */
/* ================================================================== */

export const CONTROL_CATALOG: ControlDefinition[] = [
  /* ---- Inventory ------------------------------------------------- */
  {
    id: 'CTL-INV-01',
    code: 'INV-01',
    title: 'Cryptographic asset inventory maintained',
    objective: 'Every discovered asset has cryptographic evidence attached, so the estate can be governed rather than assumed.',
    domain: 'inventory',
    evaluator: 'assetCryptoCoverage',
    criterion: 'An asset passes when at least one cryptographic component, certificate, finding or runtime observation is bound to it.',
    remediationRoute: '/dashboard/scanner',
    evidenceSources: ['crypto_inventory', 'certificates', 'pqc_scan_results', 'runtime_crypto_events'],
    weight: 3,
  },
  {
    id: 'CTL-INV-02',
    code: 'INV-02',
    title: 'Cryptographic bill of materials identifies every algorithm',
    objective: 'Each inventoried cryptographic component names a concrete algorithm, so posture can be classified.',
    domain: 'inventory',
    evaluator: 'cbomAlgorithmIdentification',
    criterion: 'A component passes when its recorded algorithm classifies as post-quantum, hybrid or quantum-vulnerable rather than unknown.',
    remediationRoute: '/dashboard/cbom-explorer',
    evidenceSources: ['crypto_inventory'],
    weight: 3,
  },
  {
    id: 'CTL-INV-03',
    code: 'INV-03',
    title: 'Cryptographic assets have an accountable owner',
    objective: 'Remediation can be assigned because every in-scope asset names a responsible owner.',
    domain: 'inventory',
    evaluator: 'assetOwnership',
    criterion: 'An asset passes when a service owner is recorded on the asset or in its metadata.',
    remediationRoute: '/dashboard/assets',
    evidenceSources: ['assets'],
    weight: 2,
  },

  /* ---- Algorithm policy ------------------------------------------ */
  {
    id: 'CTL-ALG-01',
    code: 'ALG-01',
    title: 'Prohibited cryptographic algorithms are not in use',
    objective: 'Broken and deprecated primitives (MD5, SHA-1, RC4, DES/3DES, NULL/anon/export suites) are absent from the estate.',
    domain: 'algorithm',
    evaluator: 'forbiddenAlgorithms',
    criterion: 'A cryptographic subject passes when its algorithm matches no forbidden-algorithm policy rule.',
    remediationRoute: '/dashboard/crypto-agility',
    evidenceSources: ['crypto_inventory', 'certificates', 'runtime_crypto_events', 'generated_keys'],
    weight: 5,
  },
  {
    id: 'CTL-ALG-02',
    code: 'ALG-02',
    title: 'Minimum key strength is enforced',
    objective: 'Asymmetric and symmetric key sizes meet the configured minimum classical strength.',
    domain: 'algorithm',
    evaluator: 'keyStrength',
    criterion: 'A subject passes when its recorded key size meets or exceeds the minimum for its algorithm family.',
    remediationRoute: '/dashboard/crypto-agility',
    evidenceSources: ['crypto_inventory', 'certificates', 'generated_keys'],
    weight: 4,
  },
  {
    id: 'CTL-ALG-03',
    code: 'ALG-03',
    title: 'Cryptography is limited to the approved algorithm set',
    objective: 'Deployed primitives appear on the tenant’s approved-algorithm allowlist.',
    domain: 'algorithm',
    evaluator: 'approvedAlgorithms',
    criterion: 'A subject passes when its algorithm family appears on the approved allowlist.',
    remediationRoute: '/dashboard/quantum-governance',
    evidenceSources: ['crypto_inventory', 'certificates', 'runtime_crypto_events'],
    weight: 3,
  },

  /* ---- Transport -------------------------------------------------- */
  {
    id: 'CTL-TLS-01',
    code: 'TLS-01',
    title: 'Transport encryption meets the minimum protocol version',
    objective: 'Observed TLS endpoints negotiate at least the configured minimum version.',
    domain: 'transport',
    evaluator: 'tlsMinimumVersion',
    criterion: 'An endpoint passes when its measured negotiated version meets the policy minimum. Endpoints with no transport measurement are out of population.',
    remediationRoute: '/dashboard/tls-orchestrator',
    evidenceSources: ['runtime_crypto_events', 'scanner_evidence'],
    weight: 4,
  },
  {
    id: 'CTL-TLS-02',
    code: 'TLS-02',
    title: 'Key agreement provides forward secrecy',
    objective: 'Measured transport sessions use ephemeral key agreement so recorded traffic cannot be decrypted from a leaked long-term key.',
    domain: 'transport',
    evaluator: 'forwardSecrecy',
    criterion: 'An endpoint passes when its measured key exchange is ephemeral (ECDHE/DHE) or post-quantum hybrid.',
    remediationRoute: '/dashboard/tls-telemetry',
    evidenceSources: ['runtime_crypto_events', 'scanner_evidence'],
    weight: 4,
  },

  /* ---- Certificates ---------------------------------------------- */
  {
    id: 'CTL-CRT-01',
    code: 'CRT-01',
    title: 'Certificate inventory is complete and dated',
    objective: 'Every discovered certificate records an expiry so lifecycle risk can be measured.',
    domain: 'certificate',
    evaluator: 'certificateInventory',
    criterion: 'A certificate passes when an expiry date is recorded.',
    remediationRoute: '/dashboard/pki-visibility',
    evidenceSources: ['certificates'],
    weight: 2,
  },
  {
    id: 'CTL-CRT-02',
    code: 'CRT-02',
    title: 'No expired or imminently expiring certificates in service',
    objective: 'Certificates are renewed before expiry so trust is never interrupted.',
    domain: 'certificate',
    evaluator: 'certificateExpiry',
    criterion: 'A certificate passes when it is neither expired nor inside the configured renewal window.',
    remediationRoute: '/dashboard/certificate-telemetry',
    evidenceSources: ['certificates'],
    weight: 4,
  },
  {
    id: 'CTL-CRT-03',
    code: 'CRT-03',
    title: 'Certificate signature algorithms are approved',
    objective: 'Certificates are signed with algorithms that are not deprecated or broken.',
    domain: 'certificate',
    evaluator: 'certificateAlgorithm',
    criterion: 'A certificate passes when its signature algorithm is neither forbidden nor below minimum strength.',
    remediationRoute: '/dashboard/pki-visibility',
    evidenceSources: ['certificates'],
    weight: 3,
  },

  /* ---- Keys ------------------------------------------------------- */
  {
    id: 'CTL-KEY-01',
    code: 'KEY-01',
    title: 'Key inventory is maintained with lifecycle state',
    objective: 'Managed key material records its status so custody can be evidenced.',
    domain: 'key',
    evaluator: 'keyInventory',
    criterion: 'A key passes when its status is recorded and it is not in an unknown lifecycle state.',
    remediationRoute: '/dashboard/qkms/inventory',
    evidenceSources: ['generated_keys'],
    weight: 2,
  },
  {
    id: 'CTL-KEY-02',
    code: 'KEY-02',
    title: 'Key lifecycle limits are governed',
    objective: 'Active keys have a defined expiry or rotation lineage, and revoked or expired keys are not still active.',
    domain: 'key',
    evaluator: 'keyLifecycle',
    criterion: 'A key passes when it carries an expiry or rotation record and is not an active key past its expiry.',
    remediationRoute: '/dashboard/qkms/lifecycle',
    evidenceSources: ['generated_keys'],
    weight: 3,
  },
  {
    id: 'CTL-KEY-03',
    code: 'KEY-03',
    title: 'Key material derives from a validated entropy source',
    objective: 'Generated key material records an entropy source, so randomness quality is auditable.',
    domain: 'key',
    evaluator: 'keyEntropy',
    criterion: 'A key passes when an entropy source is recorded and any quality score meets the configured floor.',
    remediationRoute: '/dashboard/qkms/governance',
    evidenceSources: ['generated_keys', 'qrng_events'],
    weight: 2,
  },

  /* ---- Data protection -------------------------------------------- */
  {
    id: 'CTL-DAT-01',
    code: 'DAT-01',
    title: 'Stored data objects are encrypted at rest',
    objective: 'Vault objects reach an encrypted terminal state rather than remaining pending.',
    domain: 'data',
    evaluator: 'dataAtRest',
    criterion: 'A stored object passes when its encryption status is a completed encrypted state.',
    remediationRoute: '/dashboard/encryption-monitoring',
    evidenceSources: ['vault_files'],
    weight: 4,
  },
  {
    id: 'CTL-DAT-02',
    code: 'DAT-02',
    title: 'Cleartext cryptographic operations are not observed at runtime',
    objective: 'Runtime telemetry shows no plaintext or downgraded operations on governed paths.',
    domain: 'data',
    evaluator: 'cleartextOperations',
    criterion: 'A runtime observation passes when it records neither a plaintext operation nor a protocol downgrade.',
    remediationRoute: '/dashboard/runtime-crypto-intel',
    evidenceSources: ['runtime_crypto_events'],
    weight: 3,
  },

  /* ---- Post-quantum ----------------------------------------------- */
  {
    id: 'CTL-PQC-01',
    code: 'PQC-01',
    title: 'Quantum-vulnerable cryptography is identified',
    objective: 'The estate has been assessed for quantum-vulnerable primitives so the transition can be planned.',
    domain: 'quantum',
    evaluator: 'quantumVulnerabilityIdentified',
    criterion: 'Satisfied when cryptographic components have been classified; the score is the share of components whose posture is known.',
    remediationRoute: '/dashboard/quantum-readiness',
    evidenceSources: ['crypto_inventory', 'pqc_scan_results'],
    weight: 4,
  },
  {
    id: 'CTL-PQC-02',
    code: 'PQC-02',
    title: 'A post-quantum migration plan exists for vulnerable assets',
    objective: 'Every quantum-vulnerable asset is covered by a migration plan or job.',
    domain: 'quantum',
    evaluator: 'migrationPlanCoverage',
    criterion: 'A quantum-vulnerable asset passes when a migration plan or job references it.',
    remediationRoute: '/dashboard/migration-planner',
    evidenceSources: ['migration_jobs', 'migration_plans'],
    weight: 5,
  },
  {
    id: 'CTL-PQC-03',
    code: 'PQC-03',
    title: 'Post-quantum adoption is progressing',
    objective: 'The share of cryptographic components that are post-quantum or hybrid is increasing toward full coverage.',
    domain: 'quantum',
    evaluator: 'pqcAdoption',
    criterion: 'Scored as the share of classified components that are post-quantum or hybrid.',
    remediationRoute: '/dashboard/migration-timeline',
    evidenceSources: ['crypto_inventory', 'certificates'],
    weight: 5,
  },
  {
    id: 'CTL-PQC-04',
    code: 'PQC-04',
    title: 'Internet-facing assets are prioritised for PQC transition',
    objective: 'Assets exposed to harvest-now-decrypt-later collection are not left quantum-vulnerable.',
    domain: 'quantum',
    evaluator: 'internetFacingPqc',
    criterion: 'An internet-facing asset passes when it is not classified quantum-vulnerable.',
    remediationRoute: '/dashboard/harvest-now',
    evidenceSources: ['assets', 'crypto_inventory', 'runtime_crypto_events'],
    weight: 5,
  },
  {
    id: 'CTL-PQC-05',
    code: 'PQC-05',
    title: 'Cryptographic agility is demonstrable',
    objective: 'Algorithms can be replaced without redesign, evidenced by completed algorithm changes.',
    domain: 'quantum',
    evaluator: 'cryptoAgility',
    criterion: 'Scored from completed migration jobs that changed an algorithm, against the vulnerable population.',
    remediationRoute: '/dashboard/crypto-agility',
    evidenceSources: ['migration_jobs'],
    weight: 3,
  },

  /* ---- Monitoring -------------------------------------------------- */
  {
    id: 'CTL-MON-01',
    code: 'MON-01',
    title: 'Cryptographic discovery runs on a defined cadence',
    objective: 'Discovery has completed recently enough that the inventory reflects the live estate.',
    domain: 'monitoring',
    evaluator: 'scanCadence',
    criterion: 'Satisfied when a discovery scan completed inside the configured cadence window.',
    remediationRoute: '/dashboard/scanner',
    evidenceSources: ['pqc_scan_sessions'],
    weight: 3,
  },
  {
    id: 'CTL-MON-02',
    code: 'MON-02',
    title: 'Runtime cryptographic monitoring is operating',
    objective: 'Runtime telemetry is arriving, so drift between declared and actual cryptography is visible.',
    domain: 'monitoring',
    evaluator: 'runtimeMonitoring',
    criterion: 'Satisfied when runtime cryptographic events were observed inside the freshness window.',
    remediationRoute: '/dashboard/runtime-telemetry',
    evidenceSources: ['runtime_crypto_events', 'scanner_agents'],
    weight: 3,
  },
  {
    id: 'CTL-MON-03',
    code: 'MON-03',
    title: 'Collectors and connectors are healthy',
    objective: 'The evidence pipeline is complete: deployed collectors and configured connectors are reporting.',
    domain: 'monitoring',
    evaluator: 'collectorHealth',
    criterion: 'A collector or connector passes when it reported inside the heartbeat window.',
    remediationRoute: '/dashboard/scanner?tab=agents',
    evidenceSources: ['scanner_agents', 'connector_accounts', 'agent_heartbeats'],
    weight: 3,
  },

  /* ---- Remediation ------------------------------------------------- */
  {
    id: 'CTL-VUL-01',
    code: 'VUL-01',
    title: 'Critical cryptographic findings are remediated within SLA',
    objective: 'Critical and high findings do not remain open past the configured remediation window.',
    domain: 'remediation',
    evaluator: 'findingSla',
    criterion: 'A critical or high finding passes when it is resolved, or open for less than the SLA window.',
    remediationRoute: '/dashboard/quantum-remediation',
    evidenceSources: ['vulnerabilities', 'scanner_alerts', 'crypto_exposures'],
    weight: 5,
  },
  {
    id: 'CTL-VUL-02',
    code: 'VUL-02',
    title: 'Open findings are attributable to an owner',
    objective: 'Every open finding resolves to an asset with an accountable owner.',
    domain: 'remediation',
    evaluator: 'findingOwnership',
    criterion: 'An open finding passes when it maps to an asset that records an owner.',
    remediationRoute: '/dashboard/vulnerabilities',
    evidenceSources: ['vulnerabilities', 'scanner_alerts', 'assets'],
    weight: 3,
  },

  /* ---- Audit & evidence -------------------------------------------- */
  {
    id: 'CTL-AUD-01',
    code: 'AUD-01',
    title: 'Security-relevant activity is logged',
    objective: 'Administrative, access and cryptographic operations produce an audit record.',
    domain: 'audit',
    evaluator: 'auditLogging',
    criterion: 'Satisfied when audit records exist and the newest is inside the freshness window.',
    remediationRoute: '/dashboard/audit-vault',
    evidenceSources: ['audit_logs', 'vault_audit_logs', 'security_events', 'auth_events'],
    weight: 4,
  },
  {
    id: 'CTL-AUD-02',
    code: 'AUD-02',
    title: 'Audit records show no unreviewed failures',
    objective: 'Failed or denied operations in the audit trail are visible and accounted for.',
    domain: 'audit',
    evaluator: 'auditFailures',
    criterion: 'An audit record passes when its outcome is not a failure or denial.',
    remediationRoute: '/dashboard/audit-vault',
    evidenceSources: ['audit_logs', 'vault_audit_logs', 'security_events'],
    weight: 3,
  },
  {
    id: 'CTL-AUD-03',
    code: 'AUD-03',
    title: 'Evidence integrity is anchored and verifiable',
    objective: 'Evidence carries a content digest anchored at first observation, so later modification is detectable.',
    domain: 'audit',
    evaluator: 'evidenceIntegrity',
    criterion: 'An evidence record passes when its recomputed SHA3-256 digest matches its anchored digest.',
    remediationRoute: '/dashboard/audit-vault',
    evidenceSources: ['governance_evidence_anchors'],
    weight: 4,
  },
  {
    id: 'CTL-AUD-04',
    code: 'AUD-04',
    title: 'Evidence is retained for the required period',
    objective: 'Evidence supporting a control is retained and has not passed its retention expiry.',
    domain: 'audit',
    evaluator: 'evidenceRetention',
    criterion: 'An evidence record passes when it is inside its retention window.',
    remediationRoute: '/dashboard/audit-vault',
    evidenceSources: ['compliance_evidence', 'audit_logs', 'vault_audit_logs'],
    weight: 3,
  },
  {
    id: 'CTL-EVD-01',
    code: 'EVD-01',
    title: 'Control evidence is current',
    objective: 'Evidence supporting compliance decisions is recent enough to describe the live estate.',
    domain: 'audit',
    evaluator: 'evidenceFreshness',
    criterion: 'An evidence record passes when it is newer than the configured staleness threshold.',
    remediationRoute: '/dashboard/scanner',
    evidenceSources: ['compliance_evidence', 'pqc_scan_sessions', 'runtime_crypto_events'],
    weight: 4,
  },
  {
    id: 'CTL-EVD-02',
    code: 'EVD-02',
    title: 'Attested control evidence is recorded',
    objective: 'Named framework controls carry stored attestation evidence, not only derived platform signals.',
    domain: 'audit',
    evaluator: 'attestedEvidence',
    criterion: 'Scored as the share of frameworks in scope that carry at least one stored evidence record.',
    remediationRoute: '/dashboard/regulatory-mapping',
    evidenceSources: ['compliance_evidence'],
    weight: 3,
  },

  /* ---- Governance -------------------------------------------------- */
  {
    id: 'CTL-GOV-01',
    code: 'GOV-01',
    title: 'A cryptographic policy is defined and enforced',
    objective: 'Cryptographic rules are enabled in enforcement rather than left unmonitored.',
    domain: 'governance',
    evaluator: 'policyEnforcement',
    criterion: 'A policy rule passes when its enforcement mode is enforced or monitored.',
    remediationRoute: '/dashboard/quantum-governance',
    evidenceSources: ['governance_policies'],
    weight: 4,
  },
  {
    id: 'CTL-GOV-02',
    code: 'GOV-02',
    title: 'Governance exceptions are approved and time-bound',
    objective: 'Any control marked out of scope carries an approver and an expiry.',
    domain: 'governance',
    evaluator: 'exceptionGovernance',
    criterion: 'An exception passes when it records an approver and has not expired.',
    remediationRoute: '/dashboard/compliance',
    evidenceSources: ['governance_control_assessments'],
    weight: 2,
  },
  {
    id: 'CTL-GOV-03',
    code: 'GOV-03',
    title: 'Quantum risk stays within the accepted threshold',
    objective: 'The tenant quantum risk score does not exceed the governance risk appetite.',
    domain: 'governance',
    evaluator: 'quantumRiskThreshold',
    criterion: 'Satisfied when the canonical quantum risk score is at or below the configured threshold.',
    remediationRoute: '/dashboard/quantum-readiness',
    evidenceSources: ['quantum_readiness_snapshot'],
    weight: 4,
  },
]

export const CONTROL_BY_ID = new Map(CONTROL_CATALOG.map((control) => [control.id, control]))

/* ================================================================== */
/* Frameworks                                                          */
/* ================================================================== */

export const FRAMEWORK_CATALOG: FrameworkDefinition[] = [
  {
    id: 'nist-csf-2',
    name: 'NIST Cybersecurity Framework 2.0',
    shortName: 'NIST CSF 2.0',
    authority: 'NIST',
    version: '2.0',
    scope: 'Outcome-based governance, identification, protection and detection functions applied to cryptographic assets.',
    aliases: /nist\s*csf|cybersecurity\s*framework|csf\s*2/i,
    reference: 'https://www.nist.gov/cyberframework',
    category: 'standard',
  },
  {
    id: 'nist-800-53',
    name: 'NIST SP 800-53 Rev. 5',
    shortName: 'SP 800-53',
    authority: 'NIST',
    version: 'Rev. 5',
    scope: 'System and communications protection, identification and audit controls for federal and federal-adjacent systems.',
    aliases: /800[-\s]?53/i,
    reference: 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final',
    category: 'standard',
  },
  {
    id: 'iso-27001',
    name: 'ISO/IEC 27001:2022 Annex A',
    shortName: 'ISO 27001',
    authority: 'ISO/IEC',
    version: '2022',
    scope: 'Information security management controls covering cryptography, asset inventory, logging and evidence.',
    aliases: /iso[\s/]*(iec)?[\s-]*27001|annex\s*a/i,
    reference: 'https://www.iso.org/standard/27001',
    category: 'certification',
  },
  {
    id: 'pci-dss-4',
    name: 'PCI DSS 4.0.1',
    shortName: 'PCI DSS 4.0.1',
    authority: 'PCI SSC',
    version: '4.0.1',
    scope: 'Protection of stored and transmitted account data, including the cryptographic inventory requirement.',
    aliases: /pci([\s-]*dss)?/i,
    reference: 'https://www.pcisecuritystandards.org/',
    category: 'standard',
  },
  {
    id: 'hipaa-security',
    name: 'HIPAA Security Rule',
    shortName: 'HIPAA',
    authority: 'US HHS',
    version: '45 CFR Part 164 Subpart C',
    scope: 'Technical safeguards for electronic protected health information, including encryption and audit controls.',
    aliases: /hipaa|164\.312|phi\b/i,
    reference: 'https://www.hhs.gov/hipaa/for-professionals/security/',
    category: 'regulation',
  },
  {
    id: 'gdpr',
    name: 'EU General Data Protection Regulation',
    shortName: 'GDPR',
    authority: 'European Union',
    version: '2016/679',
    scope: 'Security of processing, including encryption of personal data and regular testing of technical measures.',
    aliases: /gdpr|article\s*32|2016\/679/i,
    reference: 'https://eur-lex.europa.eu/eli/reg/2016/679/oj',
    category: 'regulation',
  },
  {
    id: 'soc2',
    name: 'SOC 2 Trust Services Criteria',
    shortName: 'SOC 2',
    authority: 'AICPA',
    version: '2017 (rev. 2022)',
    scope: 'Common criteria for logical access, encryption, change management and monitoring.',
    aliases: /soc\s*2|trust\s*services|cc[6-8]\./i,
    reference: 'https://www.aicpa-cima.com/',
    category: 'certification',
  },
  {
    id: 'nist-ir-8547',
    name: 'NIST IR 8547 — Transition to Post-Quantum Cryptography',
    shortName: 'NIST IR 8547',
    authority: 'NIST',
    version: 'Initial Public Draft',
    scope: 'Deprecation timeline for classical public-key cryptography and transition to PQC standards.',
    aliases: /8547|post[\s-]?quantum\s*transition|pqc\s*transition/i,
    reference: 'https://csrc.nist.gov/pubs/ir/8547/ipd',
    category: 'standard',
  },
  {
    id: 'cnsa-2',
    name: 'CNSA 2.0 Suite',
    shortName: 'CNSA 2.0',
    authority: 'NSA',
    version: '2.0',
    scope: 'Quantum-resistant algorithm suite and adoption timeline for national security systems.',
    aliases: /cnsa/i,
    reference: 'https://www.nsa.gov/cybersecurity-guidance/',
    category: 'directive',
  },
  {
    id: 'fips-pqc',
    name: 'FIPS 203 / 204 / 205 — PQC Standards',
    shortName: 'FIPS PQC',
    authority: 'NIST',
    version: '2024',
    scope: 'Approved post-quantum key establishment (ML-KEM) and digital signature (ML-DSA, SLH-DSA) algorithms.',
    aliases: /fips\s*20[345]|ml[-\s]?kem|ml[-\s]?dsa|slh[-\s]?dsa/i,
    reference: 'https://csrc.nist.gov/pubs/fips/203/final',
    category: 'standard',
  },
  {
    id: 'nist-800-57',
    name: 'NIST SP 800-57 Part 1 Rev. 5',
    shortName: 'SP 800-57',
    authority: 'NIST',
    version: 'Rev. 5',
    scope: 'Key management lifecycle: generation, distribution, storage, rotation and destruction.',
    aliases: /800[-\s]?57/i,
    reference: 'https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final',
    category: 'standard',
  },
  {
    id: 'nist-800-131a',
    name: 'NIST SP 800-131A Rev. 2',
    shortName: 'SP 800-131A',
    authority: 'NIST',
    version: 'Rev. 2',
    scope: 'Transitioning the use of cryptographic algorithms and key lengths away from deprecated strengths.',
    aliases: /800[-\s]?131a?/i,
    reference: 'https://csrc.nist.gov/pubs/sp/800/131/a/r2/final',
    category: 'standard',
  },
]

export const FRAMEWORK_BY_ID = new Map(FRAMEWORK_CATALOG.map((framework) => [framework.id, framework]))

/* ================================================================== */
/* Requirements                                                        */
/* ================================================================== */

export const REQUIREMENT_CATALOG: RequirementDefinition[] = [
  /* ---- NIST CSF 2.0 ---------------------------------------------- */
  {
    id: 'nist-csf-2::ID.AM-08',
    frameworkId: 'nist-csf-2',
    code: 'ID.AM-08',
    title: 'Technology assets are inventoried and managed through their lifecycle',
    summary: 'Maintain a current inventory of technology assets, including the cryptography they depend on, across their lifecycle.',
    controlIds: ['CTL-INV-01', 'CTL-INV-02', 'CTL-INV-03'],
  },
  {
    id: 'nist-csf-2::GV.RM-01',
    frameworkId: 'nist-csf-2',
    code: 'GV.RM-01',
    title: 'Risk management objectives are established and agreed',
    summary: 'Agree cryptographic and quantum risk objectives, and hold measured risk within the accepted appetite.',
    controlIds: ['CTL-GOV-03', 'CTL-GOV-01'],
  },
  {
    id: 'nist-csf-2::GV.PO-01',
    frameworkId: 'nist-csf-2',
    code: 'GV.PO-01',
    title: 'Policy for managing cybersecurity risk is established',
    summary: 'Establish, enforce and review an organisational cryptographic policy, including approved and prohibited algorithms.',
    controlIds: ['CTL-GOV-01', 'CTL-ALG-01', 'CTL-ALG-03', 'CTL-GOV-02'],
  },
  {
    id: 'nist-csf-2::PR.DS-01',
    frameworkId: 'nist-csf-2',
    code: 'PR.DS-01',
    title: 'Confidentiality and integrity of data at rest are protected',
    summary: 'Encrypt stored data using approved algorithms and verify that protection reaches a completed state.',
    controlIds: ['CTL-DAT-01', 'CTL-ALG-02'],
  },
  {
    id: 'nist-csf-2::PR.DS-02',
    frameworkId: 'nist-csf-2',
    code: 'PR.DS-02',
    title: 'Confidentiality and integrity of data in transit are protected',
    summary: 'Protect data in transit with current protocol versions and forward-secret key agreement.',
    controlIds: ['CTL-TLS-01', 'CTL-TLS-02', 'CTL-DAT-02'],
  },
  {
    id: 'nist-csf-2::DE.CM-09',
    frameworkId: 'nist-csf-2',
    code: 'DE.CM-09',
    title: 'Computing hardware, software and services are monitored',
    summary: 'Continuously monitor cryptographic use at runtime and keep discovery current.',
    controlIds: ['CTL-MON-01', 'CTL-MON-02', 'CTL-MON-03'],
  },
  {
    id: 'nist-csf-2::RS.MA-01',
    frameworkId: 'nist-csf-2',
    code: 'RS.MA-01',
    title: 'Incidents and findings are managed to resolution',
    summary: 'Track cryptographic findings to an owner and resolve critical exposures inside the agreed window.',
    controlIds: ['CTL-VUL-01', 'CTL-VUL-02'],
  },

  /* ---- NIST SP 800-53 --------------------------------------------- */
  {
    id: 'nist-800-53::SC-8',
    frameworkId: 'nist-800-53',
    code: 'SC-8',
    title: 'Transmission confidentiality and integrity',
    summary: 'Protect the confidentiality and integrity of transmitted information using approved cryptographic mechanisms.',
    controlIds: ['CTL-TLS-01', 'CTL-TLS-02', 'CTL-DAT-02'],
  },
  {
    id: 'nist-800-53::SC-12',
    frameworkId: 'nist-800-53',
    code: 'SC-12',
    title: 'Cryptographic key establishment and management',
    summary: 'Establish and manage cryptographic keys with defined generation, distribution, storage and destruction processes.',
    controlIds: ['CTL-KEY-01', 'CTL-KEY-02', 'CTL-KEY-03'],
  },
  {
    id: 'nist-800-53::SC-13',
    frameworkId: 'nist-800-53',
    code: 'SC-13',
    title: 'Cryptographic protection',
    summary: 'Use only cryptography that meets the applicable standard for its purpose, and prohibit non-approved primitives.',
    controlIds: ['CTL-ALG-01', 'CTL-ALG-02', 'CTL-ALG-03'],
  },
  {
    id: 'nist-800-53::SC-17',
    frameworkId: 'nist-800-53',
    code: 'SC-17',
    title: 'Public key infrastructure certificates',
    summary: 'Issue and manage certificates under a defined policy, including renewal before expiry.',
    controlIds: ['CTL-CRT-01', 'CTL-CRT-02', 'CTL-CRT-03'],
  },
  {
    id: 'nist-800-53::SC-28',
    frameworkId: 'nist-800-53',
    code: 'SC-28',
    title: 'Protection of information at rest',
    summary: 'Protect the confidentiality of information at rest with cryptographic mechanisms.',
    controlIds: ['CTL-DAT-01'],
  },
  {
    id: 'nist-800-53::CM-8',
    frameworkId: 'nist-800-53',
    code: 'CM-8',
    title: 'System component inventory',
    summary: 'Maintain an accurate inventory of system components, including their cryptographic composition and owners.',
    controlIds: ['CTL-INV-01', 'CTL-INV-02', 'CTL-INV-03'],
  },
  {
    id: 'nist-800-53::AU-2',
    frameworkId: 'nist-800-53',
    code: 'AU-2',
    title: 'Event logging',
    summary: 'Log the event types needed to support after-the-fact investigation of security incidents.',
    controlIds: ['CTL-AUD-01', 'CTL-AUD-02'],
  },
  {
    id: 'nist-800-53::AU-9',
    frameworkId: 'nist-800-53',
    code: 'AU-9',
    title: 'Protection of audit information',
    summary: 'Protect audit records from unauthorised modification, and detect modification when it occurs.',
    controlIds: ['CTL-AUD-03', 'CTL-AUD-04'],
  },
  {
    id: 'nist-800-53::RA-5',
    frameworkId: 'nist-800-53',
    code: 'RA-5',
    title: 'Vulnerability monitoring and scanning',
    summary: 'Scan for vulnerabilities on a defined frequency and remediate legitimate findings within response times.',
    controlIds: ['CTL-MON-01', 'CTL-VUL-01'],
  },

  /* ---- ISO/IEC 27001:2022 ----------------------------------------- */
  {
    id: 'iso-27001::A.5.9',
    frameworkId: 'iso-27001',
    code: 'A.5.9',
    title: 'Inventory of information and other associated assets',
    summary: 'Develop and maintain an inventory of assets, with ownership recorded for each.',
    controlIds: ['CTL-INV-01', 'CTL-INV-03'],
  },
  {
    id: 'iso-27001::A.5.28',
    frameworkId: 'iso-27001',
    code: 'A.5.28',
    title: 'Collection of evidence',
    summary: 'Establish procedures for the identification, collection and preservation of evidence.',
    controlIds: ['CTL-AUD-03', 'CTL-AUD-04', 'CTL-EVD-01', 'CTL-EVD-02'],
  },
  {
    id: 'iso-27001::A.8.8',
    frameworkId: 'iso-27001',
    code: 'A.8.8',
    title: 'Management of technical vulnerabilities',
    summary: 'Obtain information about technical vulnerabilities, evaluate exposure and take appropriate measures.',
    controlIds: ['CTL-VUL-01', 'CTL-VUL-02', 'CTL-MON-01'],
  },
  {
    id: 'iso-27001::A.8.15',
    frameworkId: 'iso-27001',
    code: 'A.8.15',
    title: 'Logging',
    summary: 'Produce, store, protect and analyse logs that record activities, exceptions and security events.',
    controlIds: ['CTL-AUD-01', 'CTL-AUD-02'],
  },
  {
    id: 'iso-27001::A.8.16',
    frameworkId: 'iso-27001',
    code: 'A.8.16',
    title: 'Monitoring activities',
    summary: 'Monitor networks, systems and applications for anomalous behaviour and evaluate potential incidents.',
    controlIds: ['CTL-MON-02', 'CTL-MON-03', 'CTL-DAT-02'],
  },
  {
    id: 'iso-27001::A.8.24',
    frameworkId: 'iso-27001',
    code: 'A.8.24',
    title: 'Use of cryptography',
    summary: 'Define and implement rules for the effective use of cryptography, including key management.',
    controlIds: ['CTL-ALG-01', 'CTL-ALG-02', 'CTL-ALG-03', 'CTL-KEY-01', 'CTL-KEY-02', 'CTL-GOV-01'],
  },

  /* ---- PCI DSS 4.0.1 ---------------------------------------------- */
  {
    id: 'pci-dss-4::3.5.1',
    frameworkId: 'pci-dss-4',
    code: 'Req. 3.5.1',
    title: 'Stored account data is rendered unreadable',
    summary: 'Render stored account data unreadable using strong cryptography.',
    controlIds: ['CTL-DAT-01', 'CTL-ALG-02'],
  },
  {
    id: 'pci-dss-4::3.6.1',
    frameworkId: 'pci-dss-4',
    code: 'Req. 3.6.1',
    title: 'Keys used to protect stored data are secured',
    summary: 'Protect cryptographic keys used for stored account data against disclosure and misuse.',
    controlIds: ['CTL-KEY-01', 'CTL-KEY-02', 'CTL-KEY-03'],
  },
  {
    id: 'pci-dss-4::3.7.4',
    frameworkId: 'pci-dss-4',
    code: 'Req. 3.7.4',
    title: 'Key management includes cryptoperiod and key changes',
    summary: 'Define cryptoperiods and change keys at the end of the defined period.',
    controlIds: ['CTL-KEY-02'],
  },
  {
    id: 'pci-dss-4::4.2.1',
    frameworkId: 'pci-dss-4',
    code: 'Req. 4.2.1',
    title: 'Strong cryptography protects account data in transit',
    summary: 'Use strong cryptography and secure protocols to safeguard account data during transmission over open networks, with only trusted keys and certificates accepted.',
    controlIds: ['CTL-TLS-01', 'CTL-TLS-02', 'CTL-CRT-02', 'CTL-CRT-03'],
  },
  {
    id: 'pci-dss-4::10.2.1',
    frameworkId: 'pci-dss-4',
    code: 'Req. 10.2.1',
    title: 'Audit logs capture all access and administrative actions',
    summary: 'Implement audit logs that capture user access and administrative actions to support forensic analysis.',
    controlIds: ['CTL-AUD-01', 'CTL-AUD-02'],
  },
  {
    id: 'pci-dss-4::12.3.3',
    frameworkId: 'pci-dss-4',
    code: 'Req. 12.3.3',
    title: 'Cryptographic suites and protocols are inventoried and reviewed',
    summary: 'Document and review the cryptographic suites and protocols in use at least annually, and monitor for industry deprecation so a response plan exists.',
    controlIds: ['CTL-INV-01', 'CTL-INV-02', 'CTL-ALG-01', 'CTL-PQC-01', 'CTL-PQC-05'],
  },

  /* ---- HIPAA Security Rule ---------------------------------------- */
  {
    id: 'hipaa-security::164.312(a)(2)(iv)',
    frameworkId: 'hipaa-security',
    code: '164.312(a)(2)(iv)',
    title: 'Encryption and decryption of stored ePHI',
    summary: 'Implement a mechanism to encrypt and decrypt electronic protected health information at rest.',
    controlIds: ['CTL-DAT-01', 'CTL-ALG-02'],
  },
  {
    id: 'hipaa-security::164.312(e)(2)(ii)',
    frameworkId: 'hipaa-security',
    code: '164.312(e)(2)(ii)',
    title: 'Encryption of transmitted ePHI',
    summary: 'Implement a mechanism to encrypt electronic protected health information when transmitted over a network.',
    controlIds: ['CTL-TLS-01', 'CTL-TLS-02', 'CTL-DAT-02'],
  },
  {
    id: 'hipaa-security::164.312(b)',
    frameworkId: 'hipaa-security',
    code: '164.312(b)',
    title: 'Audit controls',
    summary: 'Implement mechanisms that record and examine activity in systems containing electronic protected health information.',
    controlIds: ['CTL-AUD-01', 'CTL-AUD-02', 'CTL-AUD-04'],
  },
  {
    id: 'hipaa-security::164.308(a)(1)(ii)(A)',
    frameworkId: 'hipaa-security',
    code: '164.308(a)(1)(ii)(A)',
    title: 'Risk analysis',
    summary: 'Conduct an accurate assessment of risks to the confidentiality, integrity and availability of protected health information.',
    controlIds: ['CTL-PQC-01', 'CTL-GOV-03', 'CTL-MON-01'],
  },

  /* ---- GDPR -------------------------------------------------------- */
  {
    id: 'gdpr::Art.32(1)(a)',
    frameworkId: 'gdpr',
    code: 'Art. 32(1)(a)',
    title: 'Encryption and pseudonymisation of personal data',
    summary: 'Apply encryption or pseudonymisation as an appropriate technical measure for the security of processing.',
    controlIds: ['CTL-DAT-01', 'CTL-TLS-01', 'CTL-ALG-02'],
  },
  {
    id: 'gdpr::Art.32(1)(b)',
    frameworkId: 'gdpr',
    code: 'Art. 32(1)(b)',
    title: 'Ongoing confidentiality, integrity and resilience',
    summary: 'Ensure the ongoing confidentiality and integrity of processing systems and services.',
    controlIds: ['CTL-ALG-01', 'CTL-DAT-02', 'CTL-MON-02'],
  },
  {
    id: 'gdpr::Art.32(1)(d)',
    frameworkId: 'gdpr',
    code: 'Art. 32(1)(d)',
    title: 'Regular testing of technical measures',
    summary: 'Regularly test, assess and evaluate the effectiveness of technical and organisational security measures.',
    controlIds: ['CTL-MON-01', 'CTL-VUL-01', 'CTL-EVD-01'],
  },
  {
    id: 'gdpr::Art.30',
    frameworkId: 'gdpr',
    code: 'Art. 30',
    title: 'Records of processing activities',
    summary: 'Maintain records of processing activities, including a general description of technical security measures.',
    controlIds: ['CTL-INV-01', 'CTL-EVD-02', 'CTL-AUD-04'],
  },

  /* ---- SOC 2 ------------------------------------------------------- */
  {
    id: 'soc2::CC6.1',
    frameworkId: 'soc2',
    code: 'CC6.1',
    title: 'Logical access security measures protect information assets',
    summary: 'Implement logical access controls, including cryptographic protection of information assets.',
    controlIds: ['CTL-DAT-01', 'CTL-ALG-03', 'CTL-KEY-01'],
  },
  {
    id: 'soc2::CC6.6',
    frameworkId: 'soc2',
    code: 'CC6.6',
    title: 'Boundary protection against external threats',
    summary: 'Protect system boundaries, including the cryptographic protection of external transmissions.',
    controlIds: ['CTL-TLS-01', 'CTL-TLS-02', 'CTL-PQC-04'],
  },
  {
    id: 'soc2::CC6.7',
    frameworkId: 'soc2',
    code: 'CC6.7',
    title: 'Transmission and removal of information is restricted',
    summary: 'Restrict transmission and movement of information to authorised users and protect it in transit.',
    controlIds: ['CTL-DAT-02', 'CTL-CRT-03'],
  },
  {
    id: 'soc2::CC7.2',
    frameworkId: 'soc2',
    code: 'CC7.2',
    title: 'Monitoring for anomalies and security events',
    summary: 'Monitor system components for anomalies indicative of malicious acts or security events.',
    controlIds: ['CTL-MON-02', 'CTL-MON-03', 'CTL-AUD-01'],
  },
  {
    id: 'soc2::CC7.3',
    frameworkId: 'soc2',
    code: 'CC7.3',
    title: 'Evaluation of security events and remediation',
    summary: 'Evaluate identified security events to determine whether they represent a failure, and remediate accordingly.',
    controlIds: ['CTL-VUL-01', 'CTL-VUL-02', 'CTL-AUD-02'],
  },

  /* ---- NIST IR 8547 ------------------------------------------------ */
  {
    id: 'nist-ir-8547::TRANS-1',
    frameworkId: 'nist-ir-8547',
    code: 'Transition 1',
    title: 'Identify quantum-vulnerable cryptography',
    summary: 'Discover and classify the classical public-key cryptography that quantum computers will render insecure.',
    controlIds: ['CTL-PQC-01', 'CTL-INV-02'],
  },
  {
    id: 'nist-ir-8547::TRANS-2',
    frameworkId: 'nist-ir-8547',
    code: 'Transition 2',
    title: 'Plan the migration to post-quantum standards',
    summary: 'Produce a migration plan covering every quantum-vulnerable system, prioritised by exposure.',
    controlIds: ['CTL-PQC-02', 'CTL-PQC-04'],
  },
  {
    id: 'nist-ir-8547::TRANS-3',
    frameworkId: 'nist-ir-8547',
    code: 'Transition 3',
    title: 'Deprecate 112-bit classical strength by 2030',
    summary: 'Move away from cryptography providing only 112-bit classical security within the published deprecation timeline.',
    controlIds: ['CTL-ALG-02', 'CTL-PQC-03'],
  },
  {
    id: 'nist-ir-8547::TRANS-4',
    frameworkId: 'nist-ir-8547',
    code: 'Transition 4',
    title: 'Maintain cryptographic agility',
    summary: 'Retain the ability to replace cryptographic algorithms without redesigning the systems that use them.',
    controlIds: ['CTL-PQC-05', 'CTL-GOV-01'],
  },

  /* ---- CNSA 2.0 ---------------------------------------------------- */
  {
    id: 'cnsa-2::ALGO',
    frameworkId: 'cnsa-2',
    code: 'CNSA 2.0 Algorithms',
    title: 'Use only the approved quantum-resistant suite',
    summary: 'Adopt the approved quantum-resistant algorithms for key establishment, signatures, symmetric encryption and hashing.',
    controlIds: ['CTL-ALG-03', 'CTL-PQC-03'],
  },
  {
    id: 'cnsa-2::TIMELINE',
    frameworkId: 'cnsa-2',
    code: 'CNSA 2.0 Timeline',
    title: 'Meet the published adoption timeline',
    summary: 'Complete adoption of the quantum-resistant suite within the published timelines for each system class.',
    controlIds: ['CTL-PQC-02', 'CTL-PQC-04'],
  },
  {
    id: 'cnsa-2::EXCLUDE',
    frameworkId: 'cnsa-2',
    code: 'CNSA 2.0 Exclusions',
    title: 'Retire non-approved cryptography',
    summary: 'Remove cryptography outside the approved suite, including deprecated hash and cipher families.',
    controlIds: ['CTL-ALG-01', 'CTL-CRT-03'],
  },

  /* ---- FIPS PQC ---------------------------------------------------- */
  {
    id: 'fips-pqc::203',
    frameworkId: 'fips-pqc',
    code: 'FIPS 203',
    title: 'ML-KEM for key establishment',
    summary: 'Use the standardised module-lattice key encapsulation mechanism for post-quantum key establishment.',
    controlIds: ['CTL-PQC-03', 'CTL-TLS-02'],
  },
  {
    id: 'fips-pqc::204',
    frameworkId: 'fips-pqc',
    code: 'FIPS 204',
    title: 'ML-DSA for digital signatures',
    summary: 'Use the standardised module-lattice digital signature algorithm for post-quantum signatures.',
    controlIds: ['CTL-PQC-03', 'CTL-CRT-03'],
  },
  {
    id: 'fips-pqc::205',
    frameworkId: 'fips-pqc',
    code: 'FIPS 205',
    title: 'SLH-DSA for stateless hash-based signatures',
    summary: 'Use the standardised stateless hash-based signature algorithm where a conservative signature scheme is required.',
    controlIds: ['CTL-PQC-03', 'CTL-KEY-03'],
  },

  /* ---- NIST SP 800-57 ---------------------------------------------- */
  {
    id: 'nist-800-57::LIFECYCLE',
    frameworkId: 'nist-800-57',
    code: 'Key lifecycle',
    title: 'Keys are managed across their full lifecycle',
    summary: 'Govern generation, distribution, storage, rotation, revocation and destruction of key material.',
    controlIds: ['CTL-KEY-01', 'CTL-KEY-02'],
  },
  {
    id: 'nist-800-57::CRYPTOPERIOD',
    frameworkId: 'nist-800-57',
    code: 'Cryptoperiods',
    title: 'Cryptoperiods are defined and observed',
    summary: 'Define how long each key may be used and retire keys at the end of that period.',
    controlIds: ['CTL-KEY-02', 'CTL-CRT-02'],
  },
  {
    id: 'nist-800-57::GENERATION',
    frameworkId: 'nist-800-57',
    code: 'Key generation',
    title: 'Keys are generated from an approved random source',
    summary: 'Generate keys using an approved random bit generator with documented entropy.',
    controlIds: ['CTL-KEY-03'],
  },

  /* ---- NIST SP 800-131A -------------------------------------------- */
  {
    id: 'nist-800-131a::STRENGTH',
    frameworkId: 'nist-800-131a',
    code: 'Algorithm strength',
    title: 'Algorithms and key lengths meet the current minimum strength',
    summary: 'Retire algorithms and key lengths that no longer provide the required security strength.',
    controlIds: ['CTL-ALG-02', 'CTL-CRT-03'],
  },
  {
    id: 'nist-800-131a::DISALLOWED',
    frameworkId: 'nist-800-131a',
    code: 'Disallowed algorithms',
    title: 'Disallowed algorithms are removed from use',
    summary: 'Remove algorithms whose approval status has moved to disallowed for the intended purpose.',
    controlIds: ['CTL-ALG-01'],
  },
  {
    id: 'nist-800-131a::TRANSITION',
    frameworkId: 'nist-800-131a',
    code: 'Transition planning',
    title: 'Transitions away from weakened algorithms are planned',
    summary: 'Plan and evidence the migration away from algorithms scheduled for deprecation.',
    controlIds: ['CTL-PQC-02', 'CTL-PQC-05'],
  },
]

export const REQUIREMENT_BY_ID = new Map(REQUIREMENT_CATALOG.map((requirement) => [requirement.id, requirement]))

/** Control id → the requirement ids it satisfies. Built once. */
export const REQUIREMENTS_BY_CONTROL = (() => {
  const map = new Map<string, string[]>()
  for (const requirement of REQUIREMENT_CATALOG) {
    for (const controlId of requirement.controlIds) {
      const list = map.get(controlId)
      if (list) list.push(requirement.id)
      else map.set(controlId, [requirement.id])
    }
  }
  return map
})()

/** Control id → the framework ids that depend on it. */
export const FRAMEWORKS_BY_CONTROL = (() => {
  const map = new Map<string, string[]>()
  for (const requirement of REQUIREMENT_CATALOG) {
    for (const controlId of requirement.controlIds) {
      const list = map.get(controlId) || []
      if (!list.includes(requirement.frameworkId)) list.push(requirement.frameworkId)
      map.set(controlId, list)
    }
  }
  return map
})()

/**
 * Resolves a free-text framework label found on stored evidence to a catalog
 * framework id, so tenant attestations attach to the right framework instead of
 * creating a parallel one.
 */
export function resolveFrameworkId(label: string): string | null {
  const text = String(label || '').trim()
  if (!text) return null
  for (const framework of FRAMEWORK_CATALOG) {
    if (framework.aliases.test(text)) return framework.id
  }
  return null
}

/* Catalog integrity: every control referenced by a requirement must exist. */
export const CATALOG_ORPHANS = REQUIREMENT_CATALOG.flatMap((requirement) =>
  requirement.controlIds.filter((id) => !CONTROL_BY_ID.has(id)).map((id) => `${requirement.id} → ${id}`),
)
