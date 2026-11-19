import type { DocArticle } from './types'

const cryptography = 'cryptography' as const
const intelligence = 'intelligence' as const
const qkms = 'Quantum Key Management System'
const monitoring = 'Security intelligence and observability'

export const securityArticles: DocArticle[] = [
  {
    id: 'pqc-primitives', category: cryptography, title: 'PQC and cryptographic primitives',
    summary: 'Understand which algorithms establish keys, sign data, protect content, compute digests, and derive new keys.',
    keywords: ['FIPS 203', 'FIPS 204', 'FIPS 205', 'FIPS 197', 'FIPS 180-4', 'FIPS 202', 'RFC 5869', 'TLS', 'SSH', 'public key infrastructure'],
    sources: ['src/lib/vault/client-crypto.ts', 'src/lib/vault/kem-profile.ts', 'src/app/dashboard/_components/qkms/QkmsReadiness.tsx', 'src/lib/crypto/issuance-evidence.ts'],
    related: ['qkms-overview', 'vault-files', 'keys-history', 'pki-history', 'tls-observations', 'pki-observations'],
    sections: [
      { id: 'standards', title: 'What each primitive does', table: {
        headers: ['Primitive and standard', 'Role and operation', 'Where to look in QGuard Helix'], rows: [
          ['ML-KEM · NIST FIPS 203', 'A public key encapsulates a shared secret. The recipient uses its private key to decapsulate it. The secret can feed a KDF and a symmetric cipher.', 'Quantum Vault’s current encryption profile uses ML-KEM-1024. QKMS Readiness classifies measured key evidence by algorithm family.'],
          ['ML-DSA · NIST FIPS 204', 'A lattice-based digital signature. A signer uses a private key to sign, and a verifier checks the integrity and authenticity of the signed data with the public key.', 'The Vault signing implementation supports ML-DSA-65 and hybrid Ed25519 + ML-DSA-65 signatures. Confirm what the artifact actually records.'],
          ['SLH-DSA · NIST FIPS 205', 'A stateless hash-based digital signature. Its signature sizes and performance differ from ML-DSA, so test artifact formats, verifiers and transport limits.', 'QKMS can classify SLH-DSA evidence. Historical key and certificate pages do not issue SLH-DSA keys or certificates.'],
          ['AES-256-GCM · NIST FIPS 197 and SP 800-38D', 'Authenticated symmetric encryption that protects confidentiality and detects tampering. Use a unique nonce for each encryption under the same key.', 'The Vault client uses AES-256-GCM for encrypted files and sensitive metadata. Encryption Monitoring groups observed use by cryptographic role.'],
          ['SHA-256 · NIST FIPS 180-4', 'A SHA-2 hash producing a 256-bit digest for activities such as fingerprinting. A digest alone does not authenticate the sender or encrypt data.', 'Certificate workflows display recorded fingerprints. The Vault client also supports a legacy PBKDF2-SHA-256 bundle format.'],
          ['SHA3-256 and SHA3-512 · NIST FIPS 202', 'Fixed-length SHA-3 hashes that produce 256-bit and 512-bit digests. SHA3-256 and SHA-256 are distinct algorithms and produce different digests.', 'Current Vault envelopes and protected metadata use HKDF-SHA3-256 for derivation. An algorithm appearing in inventory describes the observed asset.'],
          ['HKDF-SHA-256 · RFC 5869', 'An HMAC-SHA-256 extract-and-expand construction that derives purpose-specific keys from existing keying material. It does not create entropy or stretch a human password.', 'Use the recorded algorithm and protocol context when reviewing a derivation observation. Current Vault envelopes use the distinct HKDF-SHA3-256 profile.'],
        ],
      } },
      { id: 'hybrid', title: 'Hybrid key exchange and signatures', body: [
        'Hybrid key exchange combines classical and post-quantum inputs with a protocol-specific combiner. The Vault client combines X25519 and ML-KEM shared secrets when the recipient has the hybrid profile. Hybrid signing combines signature schemes and follows its own verification policy.',
        'For a transport migration, measure the negotiated key agreement separately from the server or host signature algorithm. In TLS 1.3, the cipher suite describes authenticated encryption and a hash, while key agreement and signatures are negotiated separately. For SSH, inventory both key exchange and host keys, and test your actual clients and servers.',
      ] },
      { id: 'considerations', title: 'Implementation checks', bullets: [
        'Verify provider custody and lifecycle controls with the system of record. QKMS holds inventory and operational evidence and does not serve as a custody provider.',
        'Select algorithm parameters according to the deployment profile and test peers, certificate chains, sizes, and rollback before the change.',
        'Use provider-issued artifacts and current observations to verify readiness. An algorithm name, declared capability, or reference to a FIPS standard does not establish implementation validation.',
      ] },
    ],
  },
  {
    id: 'keys-history', category: cryptography, title: 'Encryption Keys', status: 'partial',
    summary: 'Review historical key metadata and record a revocation after confirming it with your key provider.',
    routes: ['/dashboard/keys', '/dashboard/encryption'], sources: ['src/app/dashboard/_components/IssuanceRecords.tsx', 'src/api-server/service-records.ts', 'src/lib/crypto/issuance-evidence.ts', 'supabase/generated-keys-schema.sql'],
    related: ['qkms-inventory', 'pki-history', 'pqc-primitives'], keywords: ['key issuance', 'fingerprint', 'historical records', 'mark revoked'],
    sections: [
      { id: 'review', title: 'Review history', steps: ['Sign in with an account entitled to Elite tools and open Encryption Keys.', 'Use Recorded status to select All statuses, Active, Revoked, Rotated, or Expired. Use Refresh to reload and Previous or Next to page through records.', 'Compare the record identifier or fingerprint, reported algorithm, status, and date with the authoritative record in your approved KMS.'] },
      { id: 'record', title: 'Record a confirmed revocation', body: ['Mark revoked changes the status of an active historical record in QGuard Helix. Revoke production key material and check dependent services using your approved provider workflow before relying on that record.'], warning: 'Key issuance is unavailable. Historical records alone don’t establish issuance, verified entropy, or provider conformance.' },
    ],
  },
  {
    id: 'pki-history', category: cryptography, title: 'Digital Certificates and PQC PKI', status: 'partial',
    summary: 'Use certificate history for reconciliation and verify PKI changes with your certificate authority and observed deployments.',
    routes: ['/dashboard/pki', '/dashboard/certificates'], sources: ['src/app/dashboard/_components/IssuanceRecords.tsx', 'src/api-server/service-records.ts', 'src/lib/crypto/issuance-evidence.ts'],
    related: ['pki-observations', 'certificate-monitoring', 'keys-history', 'pqc-primitives'], keywords: ['X.509', 'certificate issuance', 'CA', 'common name', 'post-quantum public key infrastructure'],
    sections: [
      { id: 'history', title: 'Review historical records', steps: ['Open Digital Certificates with Elite access.', 'Select Refresh and use Previous or Next when additional pages are available.', 'Match the common name or record identifier with the certificate your authority actually issued. Confirm the fingerprint, validity dates, signing algorithm, and deployment separately.'] },
      { id: 'verify', title: 'Validate a PQC certificate deployment', body: ['A PKI binds a public key to an identity through an issuer and a trust chain. Verify chain signatures and trust anchors with the relying parties in scope. Certificate signatures and TLS key agreement are separate measurements.'], warning: 'Certificate issuance is unavailable on this page. Use your approved CA for issuance, renewal, and revocation. Historical certificate metadata may exist without a signed artifact.' },
    ],
  },
  {
    id: 'tool-previews', category: cryptography, title: 'OTP, tokenization, and key generation previews', status: 'partial',
    summary: 'Identify which Elite tool screens show preview data and which retain account-scoped history.',
    routes: ['/dashboard/otp', '/dashboard/auth-sec', '/dashboard/tokenize', '/dashboard/tokenization', '/dashboard/comm', '/dashboard/communications', '/dashboard/cloud', '/dashboard/cloud-security', '/dashboard/qrng', '/dashboard/quantum-qrng'],
    sources: ['src/components/qrng/shared.tsx', 'src/hooks/quantum/useQuantumQrng.ts', 'src/lib/quantum/qrng.ts', 'src/api-server/service-records.ts', 'src/app/dashboard/otp/page.tsx', 'src/app/dashboard/tokenize/page.tsx', 'src/app/dashboard/comm/page.tsx', 'src/app/dashboard/cloud/page.tsx', 'src/app/dashboard/qrng/page.tsx'],
    related: ['pqc-primitives', 'qkms-overview', 'cloud-monitoring'], keywords: ['one-time password', 'validate otp', 'format preserving', 'container seeds', 'QRNG', 'entropy', 'VPN', 'S/MIME'],
    sections: [
      { id: 'availability', title: 'Availability by tool', table: { headers: ['Tool', 'Controls you may see', 'Operational boundary'], rows: [
        ['QRNG Authentication / OTP', 'Generate, Validate OTP, History, API Endpoints, Settings', 'The dashboard generates preview codes in the browser. Server history and validation endpoints exist, and the UI may fall back to local history. Do not use the tool as an authentication factor or treat a validation result as evidence of verified generation.'],
        ['Tokenization', 'Tokenize, History, API, Settings. The form offers individual and batch inputs.', 'Generated identifiers and binding values are preview output. History persistence does not make the output a production token service. Keep real payment data, personal identifiers, and other sensitive values out of this form.'],
        ['Secure Communications', 'Generate, History, API, Settings. Generate has Session Keys, VPN Tunnel, and Email Encryption views.', 'The form returns example key material. Use your approved TLS, VPN, or email key service for live systems.'],
        ['Cloud & Infrastructure', 'Generate, History, API, Settings. The form lists Generic, Kubernetes, Docker, AWS, GCP, and Azure targets.', 'Cloud seed output is simulated. Export labels indicate formats. Use the provider’s own secret store and approved deployment process. Multi-Cloud Telemetry is a separate observation workflow.'],
        ['Quantum QRNG', 'Overview, Entropy Generator, Health Tests, KDF Pipeline, Keys & Secrets, Audit Logs', 'The dashboard includes example source health and performance figures. Local browser generation and health checks do not verify quantum hardware or provider attestation.'],
      ] } },
      { id: 'resolve', title: 'When a preview displays success', body: ['The browser can display a completed progress sequence or save a historical entry. For production use, confirm the approved provider, its attestation where required, and evidence for the specific artifact.'], warning: 'Keep preview output out of production authentication, secret stores, VPNs, and encryption workflows. Use non-sensitive example inputs for evaluation.' },
    ],
  },
  {
    id: 'vault-files', category: cryptography, title: 'Web Quantum Vault',
    summary: 'Protect files in the dashboard vault, organize folders, and manage secure sharing.',
    routes: ['/dashboard/vault'], sources: ['src/app/dashboard/vault/page.tsx', 'src/components/quantum-vault/QuantumVault.tsx', 'src/components/quantum-vault/ShareLinkModal.tsx', 'src/lib/vault/client-crypto.ts', 'src/lib/vault/vault-service-enhanced.ts', 'src/api-server/index.ts', 'supabase/quantum-vault-production-schema.sql'],
    related: ['pqc-primitives'], keywords: ['Q-Shrink', 'vault passphrase', 'file recovery', 'share link', 'zero knowledge', 'trash'],
    sections: [
      { id: 'protect', title: 'Protect and retrieve a file', steps: ['Open Vault with Elite access and follow the Quantum Vault prompt to create or unlock your passphrase.', 'Open or create the destination folder, select a test file, and wait for encryption and upload to finish. Q-Shrink can optimize data in the browser before encryption.', 'Find the saved row, use its decrypt or download action, and verify the recovered file opens and matches the original.'] },
      { id: 'organize', title: 'Organize and review activity', body: ['Use Files and the folder explorer to rename, move, or delete items. Use Trash to recover an item still in the trash. Permanent deletion removes that recovery path. Shared Links, Key Vault, and Audit Log show sharing activity, key records, and recorded events.'] },
      { id: 'share', title: 'Share a protected file', steps: ['Unlock the vault and select Share from the file actions.', 'Set the expiry and choose Recipient-bound, Password-protected, or Link only under Security Level. Supply the verified recipient public key or a separate share password as requested.', 'Create the link and verify the recipient flow with a non-sensitive file. Use Shared Links to review link status and revoke access when needed.'], table: { headers: ['Share mode', 'What the recipient needs'], rows: [['Recipient-bound', 'The link and access to the private key that matches the recipient public key. Verify that public key through a trusted channel first.'], ['Password-protected', 'The link and a separate share password. Use an approved separate channel for the password.'], ['Link only', 'The full link. Anyone who has it can decrypt the file, so use this mode only for non-sensitive content.']] }, warning: 'Keep the vault passphrase and any share credential in approved locations. Revoking a link affects link access. Treat already downloaded copies according to your data-sharing policy.' },
      { id: 'recover', title: 'Troubleshoot unlock or download errors', body: ['Confirm you are signed in to the right account. Unlock Quantum Vault with the passphrase before trying the decrypt action again. If a file is missing, check its folder and Trash. Verify recovery by opening the recovered file locally.'] },
    ],
  },
  {
    id: 'qkms-overview', category: cryptography, title: 'QKMS Overview', product: qkms,
    summary: 'Review measured key estate posture, custody coverage, rotation health, and the migration gate.',
    routes: ['/dashboard/qkms/overview'], sources: ['src/app/dashboard/_components/qkms/QkmsOverview.tsx', 'src/api-server/qkms-dashboard.ts', 'supabase/qkms-command-center-schema.sql'],
    related: ['qkms-inventory', 'qkms-readiness', 'qkms-risk', 'triage-key-estate'], keywords: ['key management', 'managed custody', 'QKMS export', 'evidence coverage'],
    sections: [
      { id: 'posture', title: 'Read the overview', steps: ['Open QKMS Overview with Elite access. Read data coverage, freshness, and the migration gate before interpreting any percentage.', 'Review measured readiness, rotation health, custody coverage, and audit coverage. Hover or focus help text for the metric definition.', 'Open an attention row for evidence, or use Inventory, Lifecycle, Governance, Rotation, PQC Readiness, and Risk Analysis for focused review.'] },
      { id: 'evidence', title: 'Coverage and reporting', body: ['QKMS builds a scoped model from registry, discovery, certificate, and runtime evidence. The model merges duplicate key identities when the sources support the match. Custody coverage uses keys with known custody and rotation health uses keys with determinable rotation state.'], bullets: ['If the evidence is stale, check the latest scan or collector heartbeat before interpreting trends.', 'If no sources are reporting, start with an authorized scan, collector, or configured cloud connection.', 'Use Export for a key estate PDF, Excel, Word, HTML, CSV, or JSON report. Handle it as sensitive inventory data.'] },
    ],
  },
  {
    id: 'qkms-inventory', category: cryptography, title: 'QKMS Inventory', product: qkms,
    summary: 'Find key records and inspect their owners, dependencies, custody, readiness, and source evidence.',
    routes: ['/dashboard/qkms/inventory'], sources: ['src/app/dashboard/_components/qkms/QkmsInventory.tsx', 'src/app/dashboard/_components/qkms/shell.tsx', 'src/api-server/qkms-dashboard.ts'],
    related: ['qkms-lifecycle', 'qkms-risk', 'qkms-governance', 'triage-key-estate'],
    sections: [
      { id: 'search', title: 'Find and inspect a key', steps: ['Open Inventory in QKMS. Search by key, alias, algorithm, owner, asset, or fingerprint.', 'Use the filters to narrow by type, algorithm, owner, asset, environment, backend, posture, lifecycle, rotation, risk, migration requirement, or expiry. Open the matching row.', 'Compare linked evidence, policy results, affected assets, and work orders against the source system. Note missing evidence and confirm its scope with the owner.'] },
      { id: 'record-actions', title: 'Handle ownership and recorded status', body: ['Actions depend on the key record and source. For eligible records, the drawer supports ownership assignment, rotation requests and applicable status updates. The backend rejects raw private key or plaintext secret inputs. Verify the provider action and downstream impact independently.'] },
    ],
  },
  {
    id: 'qkms-lifecycle', category: cryptography, title: 'QKMS Lifecycle', product: qkms,
    summary: 'Review key age, expiry, lifecycle stage, orphan exposure, and records eligible for decommissioning.',
    routes: ['/dashboard/qkms/lifecycle'], sources: ['src/app/dashboard/_components/qkms/QkmsLifecycle.tsx', 'src/api-server/qkms-dashboard.ts', 'supabase/qkms-lifecycle-schema.sql'],
    related: ['qkms-inventory', 'qkms-rotation'],
    sections: [
      { id: 'review', title: 'Review lifecycle and expiry', steps: ['Open Lifecycle and review the lifecycle distribution, key age, and expiry horizon.', 'Select the relevant exposure count, such as an orphan or unowned group, to filter the register below.', 'Open a record and verify the lifecycle evidence and dependencies. Check the provider when creation, expiry, or last use is missing.'] },
      { id: 'decommission', title: 'Close a managed key record', body: ['For eligible registry records, follow the decommission prompts after the authorized provider change and dependency checks. Review the resulting record state and audit evidence.'], warning: 'A QKMS status change records the lifecycle decision. Confirm that relying services have stopped using the key and that provider custody was handled according to your retention policy.' },
    ],
  },
  {
    id: 'qkms-governance', category: cryptography, title: 'QKMS Governance', product: qkms,
    summary: 'Review policies, violations, custody, and audit evidence for the key estate.',
    routes: ['/dashboard/qkms/governance'], sources: ['src/app/dashboard/_components/qkms/QkmsGovernance.tsx', 'src/api-server/qkms-dashboard.ts', 'supabase/qkms-command-center-schema.sql'],
    related: ['qkms-inventory', 'qkms-risk'],
    sections: [
      { id: 'policy', title: 'Review and manage policies', steps: ['Open Governance and review policies in force. Confirm the environment and key scope of an existing policy before editing it.', 'When authorized to add a policy, select New policy. Review owner, custody, post-quantum requirements, and rotation fields before saving.', 'Inspect a violation and follow its linked key record. Check the original evidence and confirm which owner, custody, or lifecycle detail needs remediation.'] },
      { id: 'audit', title: 'Verify governance evidence', body: ['Compare changes against the audit list and use the custody and entropy evidence sections to identify missing proof. Confirm actual provider enforcement separately from policy evaluation in QKMS.'] },
    ],
  },
  {
    id: 'qkms-rotation', category: cryptography, title: 'QKMS Rotation', product: qkms,
    summary: 'Record rotation work, approve and track it, and attach validation evidence from the provider and relying services.',
    routes: ['/dashboard/qkms/rotation'], sources: ['src/app/dashboard/_components/qkms/QkmsRotation.tsx', 'src/api-server/qkms-dashboard.ts', 'supabase/qkms-lifecycle-schema.sql'],
    related: ['qkms-lifecycle', 'qkms-governance', 'qkms-readiness', 'triage-key-estate'],
    sections: [
      { id: 'order', title: 'Follow the rotation workflow', flow: ['Request work order', 'Approve', 'Perform the authorized provider change', 'Validate downstream behavior', 'Close with evidence'], steps: ['Review Rotation posture and blast radius. Filter the queue by the relevant reason and open the key.', 'Raise a rotation work order from an eligible record. Check the owner and affected services before approval.', 'Advance the work order as the actual rotation proceeds in the approved provider. Validate the replacement version with relying services.', 'Enter evidence when completing the work order. Verify the new version and last-rotated date when the validated completion is accepted.'] },
      { id: 'unvalidated', title: 'Understand pending validation', body: ['QKMS records work and enforces the allowed order transitions. It does not perform cryptographic rotation. A completion without evidence remains unvalidated and does not create a validated version. The platform rejects another open order for the same key.'] },
    ],
  },
  {
    id: 'qkms-readiness', category: cryptography, title: 'QKMS PQC Readiness', product: qkms,
    summary: 'Check the migration gate and identify the key evidence needed to validate a proposed change.',
    routes: ['/dashboard/qkms/readiness'], sources: ['src/app/dashboard/_components/qkms/QkmsReadiness.tsx', 'src/api-server/qkms-dashboard.ts'],
    related: ['qkms-overview', 'qkms-rotation', 'pqc-primitives'],
    sections: [
      { id: 'prechecks', title: 'Check the migration gate', steps: ['Read the gate decision and its blocking conditions.', 'Review readiness by key family and open an entry that requires migration or validation.', 'Use the precheck control to reassess the migration gate. Select a precheck in the results to filter the affected keys, then review the underlying evidence and dependencies. Resolve blockers in the relevant provider or work order.'] },
      { id: 'verify', title: 'Verify the outcome', body: ['Revisit the gate after updated source evidence and any required post-rotation validation. A classified algorithm family or a passing precheck is an input to the decision. Confirm the actual deployment and scope.'] },
    ],
  },
  {
    id: 'qkms-risk', category: cryptography, title: 'QKMS Risk Analysis', product: qkms,
    summary: 'Use evidence and the score decomposition to prioritize keys needing remediation.',
    routes: ['/dashboard/qkms/risk-analysis'], sources: ['src/app/dashboard/_components/qkms/QkmsRiskAnalysis.tsx', 'src/api-server/qkms-dashboard.ts'],
    related: ['qkms-inventory', 'qkms-governance', 'triage-key-estate'],
    sections: [
      { id: 'prioritize', title: 'Prioritize key risk', steps: ['Review risk bands and the concentration of risk by family, posture, and violation severity.', 'Open an affected key from the prioritized list. Inspect its score drivers, source timestamps, and recommended action.', 'Confirm owner, custody, rotation history, and impacted assets before deciding whether to collect evidence, raise a rotation order, or route the issue to a policy owner.'] },
      { id: 'thresholds', title: 'Read risk bands', table: { headers: ['Band', 'Score threshold'], rows: [['Critical', '80 or above'], ['High', '60–79'], ['Medium', '35–59'], ['Low', '15–34'], ['Minimal', 'Below 15']] }, note: 'QKMS key risk is distinct from estate-wide Quantum Risk Scoring. Revisit the same evidence and score drivers when verifying a change.' },
    ],
  },
  {
    id: 'triage-key-estate', category: cryptography, title: 'Tutorial: Triage a key and prepare rotation', product: qkms,
    summary: 'Trace an at-risk key to its evidence, assess the impact, and create a governed work order for an approved test key.',
    related: ['qkms-inventory', 'qkms-governance', 'qkms-rotation', 'qkms-readiness'],
    tutorial: {
      time: '15–25 minutes', permissions: 'Elite dashboard access and authorization to manage the selected test key and its work order.',
      prerequisites: ['A reporting source with a non-production key record', 'The owner and evidence of the key provider’s current state', 'An approved test change and validation plan'],
      steps: ['Open QKMS Overview and check the source timestamps and migration gate.', 'Open Risk Analysis and inspect a key in a high-priority group. Record the evidence, owner, and applicable policy.', 'Open that key in Inventory. Confirm custody and list relying systems from the evidence and your provider records.', 'If eligible and approved, raise a rotation work order. Confirm that the order appears in Rotation and remains at the correct stage.', 'After authorized provider work, test key version selection and relying service behavior. Attach the actual validation result before closing.', 'Review the new version and audit event, then recheck the migration gate for remaining conditions.'],
      result: 'A recorded test work order, evidence for the affected key, and a verifiable completion status when validation is supplied.',
      security: 'Keep raw private keys and recovery material out of notes, uploads, and reports. Coordinate provider actions with the owner and use scope-approved evidence.',
      mistakes: 'Treating a QKMS transition as a provider action, opening duplicate requests, or completing a work order before testing dependent services.',
      troubleshoot: 'Check source freshness, key eligibility, and open work orders. If the page reports unvalidated completion, inspect the order evidence and confirm how your team records the verified result.',
    },
    sections: [{ id: 'decision', title: 'Decide what to do next', table: { headers: ['Evidence', 'Action'], rows: [['Missing owner or custody', 'Resolve attribution in the source system and review again.'], ['Overdue rotation with known blast radius', 'Coordinate a provider change and track it with a work order.'], ['Missing validation', 'Verify the provider version and dependent behavior before confirming migration readiness.']] } }],
  },
  {
    id: 'quantum-feature-tour', category: cryptography, title: 'Q-Features platform tour',
    summary: 'Browse the platform’s capability showcase and find the operational guide for each area.',
    routes: ['/dashboard/q-features'], sources: ['src/app/dashboard/q-features/page.tsx', 'src/components/ui/sticky-scroll-cards-section.tsx'],
    related: ['qkms-overview', 'runtime-cryptography', 'pqc-primitives'],
    sections: [{ id: 'tour', title: 'Use the tour', body: ['Scroll through the feature cards for introductions to cryptographic visibility, risk prioritization, migration, crypto agility, and governance. Open the corresponding dashboard module to use its controls and review account-specific evidence. The tour explains capabilities and does not initiate operations.'] }],
  },
  {
    id: 'runtime-cryptography', category: intelligence, title: 'Runtime Cryptographic Intelligence', product: monitoring,
    summary: 'Review observed cryptographic activity, risk, and migration verification in the running estate.',
    routes: ['/dashboard/runtime-crypto-intel'], sources: ['src/app/dashboard/runtime-crypto-intel/RuntimeCryptoIntel.tsx', 'src/app/dashboard/runtime-crypto-intel/_runtime-sections.tsx', 'src/api-server/runtime-crypto-intel.ts'],
    related: ['telemetry-correlation', 'runtime-pipeline', 'tls-observations', 'quantum-risk-review'], keywords: ['runtime security score', 'downgrade', 'PQC adoption', 'runtime activity', 'migration verification'],
    sections: [
      { id: 'overview', title: 'Start with Overview', steps: ['Open Runtime Cryptographic Intelligence with Pro or Elite access.', 'Review Runtime Security Status and open the score explanation before using the score. Check coverage and evidence recency.', 'Review Attention Required, Post-Quantum Adoption, Runtime Configuration, and PQC Migration Verification. Follow the relevant activity or evidence link.'] },
      { id: 'investigate', title: 'Inspect Activity and Risks', steps: ['Open Activity and use the time window, environment, severity, and quantum posture controls. Search for the application, algorithm, or certificate.', 'Open an event to inspect the observed operation, source, and time. Separate a measured operation from a configuration claim.', 'Use Risks to triage open findings, then use the suggested action to inspect the affected asset or workflow. Recheck against fresh activity after remediation.'], note: 'If connection status changes, check the last synchronized time. A low activity count can reflect inactive or incomplete collection.' },
    ],
  },
  {
    id: 'telemetry-correlation', category: intelligence, title: 'Telemetry Correlation', product: monitoring,
    summary: 'Measure evidence coverage and compare where sources corroborate or disagree about the same asset.',
    routes: ['/dashboard/telemetry-correlation'], sources: ['src/app/dashboard/telemetry-correlation/TelemetryCorrelation.tsx', 'src/api-server/telemetry-correlation.ts', 'src/lib/subscription-access.ts'],
    related: ['runtime-pipeline', 'runtime-cryptography', 'quantum-risk-review'], keywords: ['blind spots', 'corroboration', 'source disagreement', 'coverage tiers'],
    sections: [
      { id: 'compare', title: 'Compare evidence sources', steps: ['Open Telemetry Correlation with Pro or Elite access and review Telemetry Coverage, Coverage Tiers, and Telemetry Sources.', 'Open Blind Spots to find assets missing evidence. Verify that the asset and collector belong to the right scope.', 'Open Conflicts to compare disagreeing sources and timestamps. In Observations, search by asset, algorithm, or source, and filter by Environment, Source, or Confirmation.', 'Ask the owner to confirm the actual configuration and collect new evidence. Revisit the same scope to verify whether the disagreement remains.'] },
      { id: 'empty', title: 'Diagnose missing coverage', body: ['If no source is reporting, follow the page links to run an authorized scan or deploy an approved agent. If only one source is present, corroboration will be limited even when its observations are fresh.'] },
    ],
  },
  {
    id: 'quantum-risk-review', category: intelligence, title: 'Quantum Risk Scoring', product: monitoring,
    summary: 'Locate exposed assets, understand score drivers, and use projected reductions to prioritize follow-up.',
    routes: ['/dashboard/quantum-risk-scoring'], sources: ['src/app/dashboard/quantum-risk-scoring/QuantumRiskScoring.tsx', 'src/api-server/quantum-risk-intel.ts', 'src/lib/subscription-access.ts'],
    related: ['runtime-cryptography', 'telemetry-correlation', 'qkms-risk'], keywords: ['risk concentration', 'risk drivers', 'high priority', 'quantum exposure'],
    sections: [
      { id: 'score', title: 'Review risk and score drivers', steps: ['Open Quantum Risk Scoring with Pro or Elite access. In Overview, note the assessment time and inspect the evidence behind the estate score.', 'Use Risk Concentration to find affected environments and critical assets. Read the trend alongside its completed scans and time span.', 'Switch to the asset and driver views to filter by available scope and inspect the observations that affect the score.', 'Use What Would Reduce It to prioritize candidate changes. Recompute using fresh evidence after implementing a change.'], note: 'Projected reduction estimates come from the scoring model. Use measured post-change evidence to verify the outcome.' },
    ],
  },
  {
    id: 'tls-observations', category: intelligence, title: 'TLS Telemetry', product: monitoring,
    summary: 'Identify what a transport endpoint negotiated and open the observations that support that conclusion.',
    routes: ['/dashboard/tls-telemetry'], sources: ['src/app/dashboard/tls-telemetry/TlsTelemetry.tsx', 'src/hooks/use-tls-pki.ts', 'src/api-server/tls-pki.ts'],
    related: ['tls-remediation', 'protocol-observations', 'pki-observations', 'verify-tls-change'], keywords: ['transport layer security', 'handshake', 'cipher suites', 'forward secrecy', 'signature algorithm'],
    sections: [
      { id: 'inspect', title: 'Find and inspect an endpoint', steps: ['Open TLS Telemetry with Pro or Elite access. Confirm evidence freshness and review Transport Observations, Handshake Failures, Downgrade Signals, and Forward Secrecy.', 'Search the endpoint table by asset, host, owner, cipher, or key agreement. Narrow it with Posture, Version, Risk, and Evidence filters.', 'Open the endpoint and review negotiated versions, cipher suites, key agreement, certificate or signature evidence, source, and last observed time. Compare records for the same host and port.', 'Follow relevant findings into TLS Orchestrator or use Protocol Analytics to compare observations across endpoints.'] },
      { id: 'basis', title: 'Interpret the evidence basis', body: ['Check whether a live interaction recorded negotiation or a collector reported configuration. See PKI Visibility for certificate identity and trust path. If the desired peer combination is missing, collect authorized evidence from the matching endpoint and client context.'] },
    ],
  },
  {
    id: 'tls-remediation', category: intelligence, title: 'TLS Orchestrator', product: monitoring,
    summary: 'Review measured transport findings, queue the appropriate changes, and use the Migration Planner approval workflow.',
    routes: ['/dashboard/tls-orchestrator'], sources: ['src/app/dashboard/tls-orchestrator/TlsOrchestrator.tsx', 'src/hooks/use-tls-pki.ts', 'src/api-server/tls-pki.ts', 'src/api-server/migration-planner.ts'],
    related: ['tls-observations', 'verify-tls-change'], keywords: ['transport remediation', 'queue', 'approve migration', 're-scan'],
    sections: [
      { id: 'queue', title: 'Build the transport work queue', steps: ['Use search, status, action, and severity to find the affected endpoint and review Evidence.', 'Compare Currently observed and Target state. Confirm dependencies, owner, and required maintenance window.', 'When available, select Queue or Unqueue to update the shared Migration Planner queue. Use the prioritization action to order the shared queue and the plan submission action to request approval.', 'Continue through the authorized Migration Planner and Live Migration Ops workflow. Use Re-scan where available to open the Scanner with the target prefilled, then explicitly authorize the verification scan.'] },
      { id: 'verification', title: 'Check after the change', body: ['Compare fresh evidence for the same host and port with the target state. Review approval, execution, and validation as separate stages. When a change is blocked, open the work item and check the evidence, dependencies, and shared planner state.'] },
    ],
  },
  {
    id: 'pki-observations', category: intelligence, title: 'PKI Visibility', product: monitoring,
    summary: 'Search the observed certificate inventory and review lifecycle, issuer relationships, and trust evidence.',
    routes: ['/dashboard/pki-visibility'], sources: ['src/app/dashboard/pki-visibility/PkiVisibility.tsx', 'src/api-server/tls-pki.ts'],
    related: ['pki-history', 'certificate-monitoring', 'tls-observations'], keywords: ['issuer', 'trust chain', 'SAN', 'certificate subject', 'certificate expiry'],
    sections: [
      { id: 'inventory', title: 'Find a certificate and its trust path', steps: ['Open PKI Visibility with Pro or Elite access. Review lifecycle counts, issuers, and post-quantum posture.', 'Search by subject, subject alternative name, issuer, serial, or asset. Apply lifecycle, posture, or issuer filters.', 'Open the certificate. Review Presented by, Trust path, Evidence, and Findings, and confirm the certificate at its deployed endpoint.'] },
      { id: 'authority', title: 'Interpret inferred issuer nodes', body: ['The graph may show an issuer name inferred from a child certificate when the authority’s certificate is missing from inventory. Confirm the chain using authoritative certificates before concluding that the issuer is trusted or that the path is complete.'] },
    ],
  },
  {
    id: 'protocol-observations', category: intelligence, title: 'Protocol Analytics', product: monitoring,
    summary: 'Analyze measured transport negotiation patterns and drill into the endpoints behind each distribution.',
    routes: ['/dashboard/protocol-analytics'], sources: ['src/app/dashboard/protocol-analytics/ProtocolAnalytics.tsx', 'src/api-server/tls-pki.ts'],
    related: ['tls-observations', 'tls-remediation', 'pqc-primitives'],
    sections: [{ id: 'drill', title: 'Compare negotiation patterns', steps: ['Open Protocol Analytics with Pro or Elite access. Review TLS version, key agreement, cipher suite, and signature algorithm distributions separately.', 'Select a distribution or anomaly row to list affected endpoints, then open an endpoint for its evidence.', 'Check the forward secrecy and PQC adoption views. Record the observed protocol and source timestamps before making a policy or migration decision.'], note: 'Percentages apply to the observations in scope. Review collection coverage before applying them to the whole estate.' }],
  },
  {
    id: 'encryption-observations', category: intelligence, title: 'Encryption Monitoring', product: monitoring,
    summary: 'Review evidence for ciphers, hashes, authentication, derivation, key material, storage protection, and vault activity.',
    routes: ['/dashboard/encryption-monitoring'], sources: ['src/app/dashboard/encryption-monitoring/EncryptionMonitoring.tsx', 'src/api-server/encryption-monitoring.ts'],
    related: ['runtime-cryptography', 'cloud-monitoring', 'pqc-primitives', 'vault-files'], keywords: ['symmetric encryption', 'MAC', 'KDF', 'CNSA 2.0', 'encryption at rest'],
    sections: [
      { id: 'observe', title: 'Inspect data-protection signals', steps: ['Open Encryption Monitoring with Pro or Elite access. Review the timeline, runtime operation types, and separate evidence layers for declared cryptography, cloud storage, and Vault files.', 'Search by algorithm, asset, or operation and filter by Strength and Layer. Inspect the evidence behind an individual primitive.', 'Use Findings to identify changes to validate with the owner and provider. Recheck fresh observations after remediation.'] },
      { id: 'interpret', title: 'Interpret strength and coverage', body: ['Interpret each primitive by its role. A hash, an authenticated cipher, and a signing algorithm protect different properties. Use the CNSA 2.0 comparison only for its defined scope of U.S. National Security Systems. A quiet timeline can indicate a collection gap.'] },
    ],
  },
  {
    id: 'runtime-pipeline', category: intelligence, title: 'Runtime Telemetry and pipeline health', product: monitoring,
    summary: 'Check whether collectors are reporting, how current the evidence is, and where attribution or coverage is missing.',
    routes: ['/dashboard/runtime-telemetry'], sources: ['src/app/dashboard/runtime-telemetry/RuntimeTelemetry.tsx', 'src/hooks/use-runtime-telemetry.ts', 'src/api-server/runtime-telemetry.ts'],
    related: ['runtime-cryptography', 'telemetry-correlation', 'certificate-monitoring', 'cloud-monitoring'], keywords: ['pipeline', 'ingestion lag', 'collectors', 'freshness', 'event stream', 'SSE', 'coverage'],
    sections: [
      { id: 'pipeline', title: 'Trace the evidence pipeline', flow: ['Authorized scan, collector, or connector', 'Account-scoped evidence', 'Attribution and freshness checks', 'Dashboard snapshot and updates'], steps: ['Open Runtime Telemetry with Elite access. Review Events last 24h, Ingestion lag, Collectors reporting, and Unattributed evidence.', 'Follow the pipeline stages, recent activity, source freshness, and collector records. Verify a heartbeat and a recent event separately.', 'Search coverage by asset, environment, or source. Filter pipeline findings by stage and severity and review the consulted sources at the end of the page.', 'After restoring a source or attribution, refresh and confirm the relevant timestamps advanced and the expected evidence appears for the asset.'] },
      { id: 'reconnect', title: 'Recover from a stopped stream', body: ['Check the last synchronized timestamp and use the page retry or refresh control. If the page loads a snapshot without fresh updates, confirm the session and collection path. Reauthenticate if needed, then verify that a new authorized observation reaches the module.'] },
    ],
  },
  {
    id: 'certificate-monitoring', category: intelligence, title: 'Certificate Telemetry', product: monitoring,
    summary: 'Prioritize certificate expiry and renewal, assess trust issues, and inspect affected deployments.',
    routes: ['/dashboard/certificate-telemetry'], sources: ['src/app/dashboard/certificate-telemetry/CertificateTelemetry.tsx', 'src/api-server/trust-fabric.ts'],
    related: ['pki-observations', 'pki-history', 'tls-observations'], keywords: ['certificate renewal', 'blast radius', 'orphan certificates', 'expiry band'],
    sections: [
      { id: 'renewal', title: 'Find certificates that need action', steps: ['Open Certificate Telemetry with Elite access. Select an expiry band to scope the inventory.', 'Search by common name, SAN, issuer, serial, or owner. Use posture, provider, algorithm, environment, trust, or renewal filters. Sort by soonest expiry, highest risk, or largest blast radius as appropriate.', 'Open a certificate to review its trust details, evidence, ownership, and deployment impact. Coordinate renewals and revocations with the issuer and service owner.', 'Collect fresh evidence after the provider change and verify the replacement certificate and chain at affected endpoints.'] },
    ],
  },
  {
    id: 'cloud-monitoring', category: intelligence, title: 'Multi-Cloud Telemetry', product: monitoring,
    summary: 'Review connector and resource coverage, cryptographic posture, and evidence across observed cloud resources.',
    routes: ['/dashboard/multi-cloud-telemetry'], sources: ['src/app/dashboard/multi-cloud-telemetry/MultiCloudTelemetry.tsx', 'src/api-server/trust-fabric.ts'],
    related: ['runtime-pipeline', 'certificate-monitoring', 'encryption-observations'], keywords: ['connector', 'AWS', 'Azure', 'GCP', 'cloud resources', 'KMS', 'cloud attribution'],
    sections: [
      { id: 'inspect', title: 'Inspect a cloud resource', steps: ['Open Multi-Cloud Telemetry with Elite access. Review connector states and distinguish providers with measured posture from providers without observations.', 'Search by resource, service, account, region, or key manager. Use Cloud, Account, Region, Environment, Encryption, Posture, Compliance, and Attribution filters to focus on your deployment. Set Sort to review the most relevant results first.', 'Open the resource to inspect attribution, provider evidence, and related certificates or asset links. Verify the observed state against the provider before acting.'] },
      { id: 'empty', title: 'Diagnose missing cloud evidence', body: ['Check the relevant connector account, authorized provider scope, recent observation time, and resource attribution. After collection, verify that the expected provider, region, and resource appear under your account.'] },
    ],
  },
  {
    id: 'sophia-copilot', category: intelligence, title: 'Sophia AI Security Copilot', product: 'Sophia',
    summary: 'Ask evidence-based questions, investigate findings across modules, and return to the source before taking action.',
    routes: ['/dashboard/sophia'], sources: ['src/app/dashboard/sophia/page.tsx', 'src/components/copilot/SophiaModelSettings.tsx', 'src/api-server/copilot.ts', 'src/api-server/copilot-llm.ts', 'src/lib/copilot-llm-catalog.ts', 'supabase/sophia-copilot-schema.sql', 'supabase/sophia-byok-schema.sql'],
    related: ['runtime-cryptography', 'quantum-risk-review', 'telemetry-correlation'], keywords: ['AI advisor', 'BYOK', 'investigate', 'citations', 'conversation history', 'external model'],
    sections: [
      { id: 'ask', title: 'Run an investigation', steps: ['Open Sophia with an active eligible plan and start a conversation. Review the account context and your role.', 'Use a suggested question or state which asset, environment, or period you want to investigate. Select Send and wait for the streamed answer.', 'Open evidence and module links and confirm the scope, timestamps, and any limitations. Carry out authorized changes from the owning module.', 'Use Search history to find prior work. Use the conversation controls to pin, export, or delete it as needed.'] },
      { id: 'model', title: 'Connect an external model', steps: ['With Pro or Elite access, open Model Settings and choose an available provider, model, and endpoint.', 'Review the data-processing consent. Enter a provider key only in the model settings form and choose Verify & connect. Check the connection and which model is active.', 'Verify or disconnect the connection from Model Settings when necessary. If the setting is unavailable, check plan access and server configuration.'], warning: 'An active external model receives a bounded evidence package to help compose the answer. Follow your organization’s approval and data handling rules for that provider. Keep credentials and secrets out of prompts and exported conversations.' },
      { id: 'evidence', title: 'Resolve missing evidence or weak answers', body: ['The platform limits answers to evidence and tools available to your role and plan. If Sophia reports missing data, open the linked module and check collection and permissions. After new evidence is available, ask a scoped question again and compare its sources.'] },
    ],
  },
  {
    id: 'verify-tls-change', category: intelligence, title: 'Tutorial: Verify a TLS change with evidence', product: monitoring,
    summary: 'Use a baseline and a new observation to verify a transport change on an authorized test endpoint.',
    related: ['tls-observations', 'tls-remediation', 'pki-observations', 'runtime-pipeline'],
    tutorial: {
      time: '15–25 minutes, plus collection time', permissions: 'Pro or Elite access, authorization to collect evidence for the target, and an approved change owner.',
      prerequisites: ['A non-production endpoint with existing transport evidence', 'An agreed target version, key exchange group, or certificate change', 'A documented maintenance and rollback plan'],
      steps: ['Open TLS Telemetry and locate the endpoint by host and port. Record the existing evidence time and properties that will be compared.', 'Open the endpoint in TLS Orchestrator when a remediation item exists. Read Evidence and compare Currently observed with Target state.', 'After the change owner completes the authorized rollout, refresh evidence using an approved scan or reporting agent.', 'Return to the same TLS Telemetry row and confirm a new observation shows the target. If the certificate changed, inspect the presented leaf and trust path in PKI Visibility.', 'Verify dependent clients and attach the result to the migration work. If the expected state is missing or mixed, check host, port, routes, and timestamps before closing.'],
      result: 'A baseline and a new observation for the same endpoint with independently reviewed transport and certificate evidence where applicable.',
      security: 'Collect evidence only for authorized systems. Keep keys and sensitive endpoint details out of shared notes.',
      mistakes: 'Comparing different listener ports or network paths, equating a cipher suite with key agreement, or treating a queued change as applied.',
      troubleshoot: 'If the result is unchanged, verify collection freshness and that the observation reached the intended endpoint. In an Elite workspace, use Runtime Telemetry to check source health.',
    },
    sections: [{ id: 'verification-record', title: 'What to record', table: { headers: ['Field', 'Evidence'], rows: [['Endpoint', 'Same host, port, and routing context'], ['Baseline', 'Previous timestamp, source, and observed properties'], ['Result', 'New timestamp, source, negotiated properties, and certificate fingerprint where applicable'], ['Follow-up', 'Owner, client checks, and any unresolved issue']] } }],
  },
  {
    id: 'monitoring-troubleshooting', category: 'support', title: 'Troubleshoot missing security evidence', product: monitoring,
    summary: 'Diagnose absent, stale, or conflicting QKMS, telemetry, and certificate evidence.',
    related: ['qkms-overview', 'telemetry-correlation', 'runtime-pipeline', 'certificate-monitoring'],
    sections: [{ id: 'diagnose', title: 'Symptoms, checks, and verification', table: { headers: ['Symptom', 'Likely cause and diagnostic step', 'Resolution and verification'], rows: [
      ['A dashboard reports no observations', 'The source may be unconfigured, outside scope, or filtered out. Check the account, plan, source, and current filters.', 'Restore or configure the authorized source. Verify a recent observation appears for the expected asset.'],
      ['A dashboard becomes stale or disconnected', 'The session, event stream, or source may be inactive. Check the last synchronized time and recent collector activity.', 'Retry or reauthenticate if necessary, then verify the latest source time changes after a new event.'],
      ['Sources disagree on an algorithm or certificate', 'They may observe different times, ports, routes, or environments. Compare source, endpoint identity, and observation time.', 'Repeat the check in the same context and review the updated correlated observations.'],
      ['A key appears without an owner or custody', 'The available observations may omit attribution. Open the key evidence and confirm the provider’s source record.', 'Correct attribution in the source of record or assign ownership where eligible. Verify it displays against the same key identity.'],
      ['A completed work order still needs validation', 'Completion without evidence leaves validation pending. Review the recorded result and provider version.', 'Capture approved validation evidence and confirm the work-order state, key version, and migration gate.'],
    ] } }],
  },
]
