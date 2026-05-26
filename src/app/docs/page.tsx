import { useCallback, useEffect, useMemo, useState } from 'react'
import type { CSSProperties, ReactNode } from 'react'
import { Link } from 'react-router-dom'
import type { LucideIcon } from 'lucide-react'
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Bell,
  BookOpen,
  Box,
  Check,
  CheckCircle,
  ChevronDown,
  ChevronRight,
  ClipboardCheck,
  Cloud,
  Code,
  Copy,
  Cpu,
  Database,
  Download,
  EyeOff,
  FileDown,
  FileText,
  Fingerprint,
  Gauge,
  Globe,
  HelpCircle,
  KeyRound,
  Layers,
  LifeBuoy,
  Lock,
  Menu,
  MonitorCheck,
  Network,
  PlayCircle,
  Radio,
  RefreshCw,
  Rocket,
  Route,
  ScanSearch,
  Search,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Users,
  Webhook,
  Workflow,
  Wrench,
  X,
  Zap,
} from 'lucide-react'
import { useAuth } from '@/contexts/auth-context'
import ThemeToggle from '@/components/theme/ThemeToggle'
import { cn } from '@/lib/utils'

type Topic = {
  id: string
  title: string
  body: string
  bullets?: string[]
  callout?: string
}

type CodeExample = {
  title: string
  language: string
  code: string
}

type Walkthrough = {
  id: string
  title: string
  audience: string
  steps: string[]
  href: string
}

type DocSection = {
  id: string
  group: string
  title: string
  summary: string
  icon: LucideIcon
  image: string
  tags: string[]
  quickLinks: Array<{ label: string; href: string; icon: LucideIcon }>
  topics: Topic[]
  examples?: CodeExample[]
  walkthroughs?: Walkthrough[]
}

type LiveDocsStatus = {
  platform: string
  dashboard: string
  realtime: string
  scanner: string
  migration: string
  timestamp: string | null
  metrics: Record<string, number>
}

const EMPTY_STATUS: LiveDocsStatus = {
  platform: 'checking',
  dashboard: 'waiting',
  realtime: 'not connected',
  scanner: 'unknown',
  migration: 'unknown',
  timestamp: null,
  metrics: {},
}

const LOCAL_PROGRESS_KEY = 'qguard-docs-progress-v1'

const MODULE_LINKS = [
  { label: 'Dashboard', href: '/dashboard', icon: Gauge, desc: 'Operational overview, KPIs, and readiness posture.' },
  { label: 'PQC Onboarding', href: '/dashboard/pqc-onboarding', icon: Route, desc: 'Six-phase migration process and onboarding progress.' },
  { label: 'PQC Scanner', href: '/dashboard/scanner', icon: ScanSearch, desc: 'Asset discovery, findings, evidence, and agent collectors.' },
  { label: 'Harvest Now', href: '/dashboard/harvest-now', icon: EyeOff, desc: 'HNDL threat detection and critical defense actions.' },
  { label: 'Runtime Crypto Intel', href: '/dashboard/runtime-crypto-intel', icon: Activity, desc: 'Runtime cryptographic events, process signals, and risk telemetry.' },
  { label: 'Crypto Agility', href: '/dashboard/crypto-agility', icon: Workflow, desc: 'Hybrid crypto policies, key rotation, and algorithm switching.' },
  { label: 'PQC Orchestration', href: '/dashboard/pqc-orchestration', icon: Network, desc: 'Migration jobs, execution queue, and live orchestration logs.' },
  { label: 'Migration Sandbox', href: '/dashboard/migration-sandbox', icon: Box, desc: 'Safe testing, rollback, and migration validation.' },
  { label: 'Quantum Vault', href: '/dashboard/vault', icon: Lock, desc: 'Zero-knowledge encrypted storage and secure sharing.' },
  { label: 'Compliance', href: '/dashboard/compliance', icon: ClipboardCheck, desc: 'Evidence, regulatory readiness, and governance status.' },
  { label: 'Telemetry', href: '/dashboard/runtime-telemetry', icon: Radio, desc: 'Live system telemetry and monitoring health.' },
  { label: 'Settings', href: '/dashboard/settings', icon: Settings, desc: 'Account, organization, security preferences, and profile.' },
]

const DEFENSE_ACTIONS = [
  {
    title: 'Isolate Asset',
    when: 'Use when an asset shows active compromise, HNDL exposure, downgrade attempts, or suspicious lateral movement.',
    impact: 'Network access is restricted. Business traffic may pause until the asset is cleared.',
    workflow: ['Confirm alert evidence', 'Notify asset owner', 'Apply isolation policy', 'Monitor telemetry for containment', 'Document evidence in audit trail'],
    href: '/dashboard/assets',
  },
  {
    title: 'Kill Process',
    when: 'Use when runtime telemetry identifies a malicious or unsafe process using weak cryptography.',
    impact: 'The process terminates immediately. Dependent services may need restart or rollback.',
    workflow: ['Validate process identity', 'Capture process hash', 'Terminate process', 'Verify runtime events stop', 'Open remediation ticket'],
    href: '/dashboard/runtime-crypto-intel',
  },
  {
    title: 'Revoke Credentials',
    when: 'Use when keys, tokens, certificates, or sessions are exposed, weak, or suspected compromised.',
    impact: 'Users or services relying on credentials may need reauthentication or new key material.',
    workflow: ['Identify credential scope', 'Rotate or revoke material', 'Update dependent services', 'Confirm no failed handshakes', 'Record compliance evidence'],
    href: '/dashboard/identity-trust',
  },
  {
    title: 'Patch & Harden',
    when: 'Use when findings require dependency upgrades, TLS policy hardening, or cryptographic configuration changes.',
    impact: 'Change windows may be required. Backward compatibility should be tested in hybrid mode.',
    workflow: ['Review patch plan', 'Apply policy or package update', 'Run validation scan', 'Compare findings', 'Promote to production'],
    href: '/dashboard/scanner',
  },
  {
    title: 'Backup & Restore',
    when: 'Use before high-risk migrations, rollback events, or incident response recovery.',
    impact: 'Requires backup verification and recovery-point confirmation before restoration.',
    workflow: ['Create recovery snapshot', 'Validate integrity', 'Run migration or response action', 'Restore if validation fails', 'Attach recovery evidence'],
    href: '/dashboard/migration-sandbox',
  },
]

const FAQ = [
  ['What is PQC?', 'Post-Quantum Cryptography is a family of cryptographic algorithms designed to resist attacks from future quantum computers. Qguard Helix helps identify vulnerable classical cryptography and migrate to PQC-safe controls.'],
  ['What is HNDL?', 'Harvest Now, Decrypt Later is an attack strategy where adversaries steal encrypted traffic or files today and wait for future quantum computers to decrypt them.'],
  ['Do I need to migrate everything immediately?', 'No. Start with high-value data, public-facing TLS, identity systems, long-lived certificates, secrets, and regulated workloads. The platform prioritizes based on risk and business impact.'],
  ['Why use hybrid cryptography?', 'Hybrid mode combines classical and PQC algorithms during transition so systems remain compatible while improving quantum resilience.'],
  ['How is tenant data isolated?', 'Live dashboards query authenticated user-scoped records and backend routes filter data by the current user or tenant. Realtime subscriptions follow the same user-scoped filters.'],
  ['Can Qguard Helix integrate with SIEM and CI/CD?', 'Yes. API, webhook, scanner, telemetry, and export flows are documented for SIEM ingestion, CI/CD gates, cloud workflows, and custom automation.'],
]

const SECTIONS: DocSection[] = [
  {
    id: 'platform-introduction',
    group: 'Foundation',
    title: 'Platform Introduction',
    summary: 'Understand Qguard Helix, the quantum threat landscape, HNDL risk, NIST PQC, Quantum Vault, and why migration must begin now.',
    icon: Shield,
    image: '/Gold_Shield.png',
    tags: ['intro', 'qguard helix', 'architecture', 'quantum threat', 'hndl', 'crqc', 'nist', 'vault'],
    quickLinks: [
      { label: 'Open Dashboard', href: '/dashboard', icon: Gauge },
      { label: 'Start Onboarding', href: '/dashboard/pqc-onboarding', icon: Route },
      { label: 'Review NIST', href: '/dashboard/compliance', icon: ClipboardCheck },
    ],
    topics: [
      {
        id: 'what-is-qguard',
        title: 'What is Qguard Helix?',
        body: 'Qguard Helix is an enterprise post-quantum security platform for discovering cryptographic risk, prioritizing quantum exposure, orchestrating migration, validating outcomes, and continuously monitoring runtime cryptographic behavior.',
        bullets: ['Single operating surface for PQC readiness', 'Tenant-scoped dashboards and audit trails', 'Scanner, runtime telemetry, migration, compliance, and response workflows', 'Beginner-friendly explanations with operator-grade controls'],
      },
      {
        id: 'architecture',
        title: 'Platform architecture overview',
        body: 'The platform combines a React dashboard, Express API routes, Supabase-backed data stores, scanner engines, agent collectors, runtime event pipelines, SSE streams, and realtime subscriptions.',
        bullets: ['Frontend pages subscribe to authenticated telemetry', 'API routes aggregate tenant-specific findings and KPIs', 'Scanner and agent systems populate scan sessions, findings, runtime events, alerts, and migration jobs', 'Governance surfaces transform evidence into compliance posture'],
        callout: 'For operators: treat the API and realtime streams as source-of-truth delivery paths. Avoid manually copying metrics between modules.',
      },
      {
        id: 'quantum-threats',
        title: 'Quantum threat landscape and CRQC',
        body: 'A Cryptographically Relevant Quantum Computer can break widely deployed public-key algorithms such as RSA and ECC. While exact timing is uncertain, long-lived data, certificates, secrets, identities, and regulated records are already exposed to collection risk.',
        bullets: ['RSA and ECC are primary migration targets', 'Long-lived encrypted data is highest priority', 'Identity, PKI, TLS, API gateways, and critical workloads should move first'],
      },
      {
        id: 'hndl',
        title: 'Harvest Now, Decrypt Later',
        body: 'HNDL attacks capture encrypted information today for future decryption. Qguard Helix detects HNDL exposure by correlating weak cryptography, critical assets, telemetry, scanner findings, certificates, and runtime behavior.',
        bullets: ['Red critical alerts flag urgent risk', 'Defense actions can isolate assets, revoke credentials, and harden services', 'Evidence is retained for incident response and compliance'],
      },
      {
        id: 'nist-pqc',
        title: 'NIST PQC overview',
        body: 'NIST PQC standards guide organizations toward algorithms such as ML-KEM for key establishment and ML-DSA for digital signatures. Qguard Helix maps findings, migration plans, and governance evidence to NIST-aligned workflows.',
        bullets: ['ML-KEM replaces quantum-vulnerable key exchange', 'ML-DSA supports post-quantum signatures', 'Hybrid cryptography supports safe transition and compatibility'],
      },
    ],
  },
  {
    id: 'onboarding-setup',
    group: 'Foundation',
    title: 'Onboarding & Initial Setup',
    summary: 'Configure accounts, organization metadata, teams, agents, scanner deployment, API integrations, asset discovery, environments, and access control.',
    icon: Rocket,
    image: '/NEW_LOGO.png',
    tags: ['account setup', 'organization onboarding', 'team management', 'agent installation', 'permissions', 'api integrations'],
    quickLinks: [
      { label: 'Profile & Settings', href: '/dashboard/settings', icon: Settings },
      { label: 'Agent Scanners', href: '/dashboard/scanner', icon: ScanSearch },
      { label: 'Assets', href: '/dashboard/assets', icon: Database },
    ],
    topics: [
      {
        id: 'account-org',
        title: 'Account and organization setup',
        body: 'Begin by creating an administrator account, confirming email, completing the organization profile, and assigning project ownership. Strong organization metadata improves reports and client overview panels.',
        bullets: ['Add company name, department, role, and security owner', 'Enable MFA and trusted-device policies', 'Invite analysts, administrators, compliance officers, and DevOps owners', 'Assign least-privilege permissions by operational role'],
      },
      {
        id: 'agents',
        title: 'Agent installation and scanner deployment',
        body: 'Deploy collectors where runtime and asset evidence is needed. Agents register into the tenant workspace and report heartbeat, metadata, runtime cryptographic events, scan evidence, and alerts.',
        bullets: ['Use scoped enrollment tokens', 'Install agents on target hosts, clusters, and monitored environments', 'Confirm heartbeat and policy assignment', 'Rotate or revoke tokens when agents are retired'],
      },
      {
        id: 'api-integrations',
        title: 'API integrations and environment configuration',
        body: 'Connect API sources, cloud accounts, SIEM destinations, CI/CD systems, and scanner targets. Environment labels help segment dev, staging, production, cloud, and regulated zones.',
        bullets: ['Create API credentials with minimum required scope', 'Use webhooks for incident and SIEM forwarding', 'Document environment ownership', 'Run initial asset discovery before migration planning'],
      },
      {
        id: 'permissions',
        title: 'Permissions and access control',
        body: 'Separate duties for administrators, migration operators, responders, auditors, and viewers. Sensitive actions such as credential revocation and process termination should require clear ownership and audit evidence.',
        bullets: ['Administrators manage users and organization policy', 'Security analysts triage alerts and findings', 'DevOps teams execute migrations and rollbacks', 'Compliance users review evidence and reports'],
      },
    ],
    walkthroughs: [
      {
        id: 'wizard-account',
        title: 'Create your first operating workspace',
        audience: 'New administrators',
        href: '/dashboard/settings',
        steps: ['Create an account and verify email', 'Complete company and role details', 'Enable MFA', 'Invite security and DevOps owners', 'Open the dashboard and confirm live status'],
      },
      {
        id: 'wizard-agent',
        title: 'Deploy your first collector agent',
        audience: 'Security and DevOps teams',
        href: '/dashboard/scanner',
        steps: ['Open Scanner', 'Create a tenant-scoped agent token', 'Run the install command on a host', 'Confirm heartbeat', 'Assign scan scope'],
      },
    ],
  },
  {
    id: 'discovery-inventory',
    group: 'Operations',
    title: 'Discovery & Inventory',
    summary: 'Learn how asset discovery, cryptographic inventory scanning, runtime telemetry, certificates, secrets detection, cloud/container scanning, TLS/PQC exposure scanning, and risk classification work.',
    icon: ScanSearch,
    image: '/inventory.png',
    tags: ['asset discovery', 'cryptographic inventory', 'certificate discovery', 'secrets detection', 'cloud scanning', 'container scanning', 'tls exposure'],
    quickLinks: [
      { label: 'Run Scanner', href: '/dashboard/scanner', icon: ScanSearch },
      { label: 'CBOM Explorer', href: '/dashboard/cbom', icon: Layers },
      { label: 'Crypto Exposure', href: '/dashboard/crypto-exposure', icon: Globe },
    ],
    topics: [
      {
        id: 'asset-discovery',
        title: 'Asset discovery process',
        body: 'Discovery starts by identifying systems, applications, services, repositories, certificates, APIs, containers, and cloud workloads. Assets become the anchor for scan results, telemetry, remediation, and compliance evidence.',
        bullets: ['Name assets consistently', 'Assign owners and criticality', 'Tag environments', 'Preserve asset relationships for exposure maps'],
      },
      {
        id: 'crypto-inventory',
        title: 'Cryptographic inventory scanning',
        body: 'The scanner builds a cryptographic bill of materials by identifying algorithms, key sizes, protocols, certificate properties, package metadata, secrets, and vulnerable implementations.',
        bullets: ['RSA, ECC, DH, SHA-1, weak TLS, CBC, 3DES, and deprecated primitives are highlighted', 'Quantum-safe and hybrid controls are recognized', 'Findings are linked to remediation recommendations'],
      },
      {
        id: 'runtime-collection',
        title: 'Runtime telemetry collection',
        body: 'Runtime telemetry captures cryptographic activity as it happens, including process context, algorithm usage, TLS properties, package data, downgrade attempts, and HNDL risk signals.',
        bullets: ['Agent events are stored as tenant-scoped runtime crypto events', 'Alerts correlate scanner and runtime sources', 'SSE and realtime subscriptions keep dashboards current'],
      },
      {
        id: 'interpret-results',
        title: 'Interpreting scan results',
        body: 'Focus first on critical and high findings affecting public-facing systems, long-lived data, identity, certificates, secrets, payment flows, and regulated workloads.',
        bullets: ['Critical means immediate owner review', 'High means migration planning should be scheduled', 'Medium and low findings support hardening and lifecycle cleanup'],
      },
    ],
    walkthroughs: [
      {
        id: 'tutorial-first-scan',
        title: 'Run your first PQC scan',
        audience: 'Beginners and analysts',
        href: '/dashboard/scanner',
        steps: ['Open the Scanner dashboard', 'Choose scope and target', 'Start the scan', 'Wait for module progress to complete', 'Review findings and export evidence'],
      },
      {
        id: 'tutorial-review-vulns',
        title: 'Review vulnerabilities and exposure',
        audience: 'Security teams',
        href: '/dashboard/vulnerabilities',
        steps: ['Open Vulnerabilities', 'Filter by critical and high severity', 'Open affected asset context', 'Review remediation guidance', 'Queue migration or defense action'],
      },
    ],
  },
  {
    id: 'hndl',
    group: 'Threat Response',
    title: 'Harvest Now, Decrypt Later',
    summary: 'Detect HNDL attacks, understand red critical alerts, prioritize risk, monitor live telemetry, integrate threat intelligence, and execute automated defense actions.',
    icon: EyeOff,
    image: '/HNDL.png',
    tags: ['hndl', 'harvest now decrypt later', 'critical alerts', 'threat intelligence', 'defense actions', 'incident response'],
    quickLinks: [
      { label: 'Open HNDL', href: '/dashboard/harvest-now', icon: EyeOff },
      { label: 'Vulnerabilities', href: '/dashboard/vulnerabilities', icon: Radio },
      { label: 'Runtime Intel', href: '/dashboard/runtime-crypto-intel', icon: Activity },
    ],
    topics: [
      {
        id: 'how-hndl-works',
        title: 'How HNDL attacks work',
        body: 'Adversaries collect encrypted data, TLS sessions, documents, backups, traffic, or files now and retain them until a future quantum computer can decrypt vulnerable cryptography.',
        bullets: ['Long retention data has elevated risk', 'Weak public-key cryptography is highest priority', 'Critical business services should be migrated early'],
      },
      {
        id: 'alerting',
        title: 'Alerting system and red critical remediation',
        body: 'Critical red alerts indicate a likely high-impact exposure. Operators should validate evidence, identify owners, choose a defense action, and confirm telemetry stabilizes after remediation.',
        bullets: ['Red alerts appear in threat and runtime panels', 'Automated actions can queue migration or incident workflows', 'Evidence should be exported for incident review'],
      },
      {
        id: 'mitigation',
        title: 'Mitigation recommendations and automated defense',
        body: 'The platform recommends actions such as isolate asset, kill process, revoke credentials, patch and harden, or backup and restore based on threat context and asset impact.',
        bullets: ['Use isolation for active compromise', 'Use revocation for key or credential exposure', 'Use patching for configuration or dependency weakness', 'Use backup and restore for recovery and rollback'],
      },
    ],
    walkthroughs: [
      {
        id: 'tutorial-hndl-response',
        title: 'Respond to an HNDL threat',
        audience: 'Incident responders',
        href: '/dashboard/harvest-now',
        steps: ['Open the HNDL dashboard', 'Review critical alert evidence', 'Select an action', 'Queue remediation workflow', 'Monitor runtime telemetry and audit evidence'],
      },
    ],
  },
  {
    id: 'runtime-intelligence',
    group: 'Threat Response',
    title: 'Runtime Cryptographic Intelligence',
    summary: 'Understand runtime crypto telemetry, process-level monitoring, key usage telemetry, certificate intelligence, binary/file integrity, ETW/eBPF concepts, and live event monitoring.',
    icon: Activity,
    image: '/monitoring.png',
    tags: ['runtime telemetry', 'process monitoring', 'key usage', 'certificate intelligence', 'binary integrity', 'file integrity', 'ebpf', 'etw'],
    quickLinks: [
      { label: 'Runtime Crypto Intel', href: '/dashboard/runtime-crypto-intel', icon: Activity },
      { label: 'TLS Telemetry', href: '/dashboard/tls-telemetry', icon: ShieldCheck },
      { label: 'PKI Visibility', href: '/dashboard/pki-visibility', icon: FileText },
    ],
    topics: [
      {
        id: 'pipeline',
        title: 'How runtime crypto telemetry works',
        body: 'Runtime telemetry observes cryptographic behavior from agents, connectors, and integrations. Events are normalized into operation type, algorithm, key size, process, asset, certificate, protocol, and risk fields.',
        bullets: ['Process-level monitoring helps attribute risk', 'Key usage telemetry highlights sensitive operations', 'Certificate intelligence detects weak or expiring trust chains', 'Live event monitoring updates dashboards in real time'],
      },
      {
        id: 'integrity',
        title: 'Binary and file integrity verification',
        body: 'Integrity checks validate whether monitored binaries, libraries, files, and configuration artifacts changed unexpectedly during migration or incident response.',
        bullets: ['Hash and metadata changes become telemetry evidence', 'Unexpected changes can trigger scanner alerts', 'Evidence supports rollback and compliance decisions'],
      },
      {
        id: 'ebpf-etw',
        title: 'eBPF and ETW telemetry explained',
        body: 'Linux eBPF and Windows ETW are operating-system telemetry mechanisms that can observe runtime events with low overhead. Qguard Helix uses the concept to explain how collectors can capture cryptographic behavior close to the workload.',
        bullets: ['eBPF is common in Linux runtime observability', 'ETW is used in Windows event tracing', 'Collectors normalize data before it reaches dashboards'],
      },
    ],
    examples: [
      {
        title: 'Runtime telemetry event shape',
        language: 'json',
        code: `{
  "asset_id": "api-gateway-prod",
  "operation_type": "key_exchange",
  "algorithm": "RSA-2048",
  "tls_version": "TLS 1.2",
  "is_legacy": true,
  "hndl_risk": true,
  "risk_score": 91
}`,
      },
    ],
  },
  {
    id: 'crypto-agility',
    group: 'Migration',
    title: 'Crypto Agility',
    summary: 'Define crypto agility, hybrid cryptography, algorithm migration strategies, dynamic policy updates, key rotation, orchestration, migration planning, rollback, and fallback.',
    icon: Workflow,
    image: '/CPM_PQC.png',
    tags: ['crypto agility', 'hybrid cryptography', 'algorithm migration', 'key rotation', 'orchestration', 'rollback'],
    quickLinks: [
      { label: 'Crypto Agility', href: '/dashboard/crypto-agility', icon: Workflow },
      { label: 'Keys', href: '/dashboard/keys', icon: KeyRound },
      { label: 'PQC Orchestration', href: '/dashboard/pqc-orchestration', icon: Network },
    ],
    topics: [
      {
        id: 'meaning',
        title: 'What crypto agility means',
        body: 'Crypto agility is the ability to identify, replace, rotate, validate, and govern cryptographic controls without disrupting business operations.',
        bullets: ['Inventory algorithms and dependencies', 'Abstract cryptographic policy from application code', 'Switch algorithms with validation and rollback', 'Keep evidence for audits'],
      },
      {
        id: 'hybrid',
        title: 'Hybrid cryptography workflows',
        body: 'Hybrid cryptography combines classical and post-quantum mechanisms during transition. It reduces migration risk while supporting older clients and systems.',
        bullets: ['Use hybrid TLS and hybrid key exchange for compatibility', 'Validate handshake telemetry', 'Retire classical fallbacks after confidence increases'],
      },
      {
        id: 'rotation',
        title: 'Key rotation lifecycle',
        body: 'Key rotation replaces old or exposed key material with stronger material. In Qguard Helix, key generation, rotation records, entropy quality, and revocation state are tracked for operations and audit.',
        bullets: ['Generate new keys', 'Deploy to dependent services', 'Validate service health', 'Revoke old material', 'Record evidence'],
      },
      {
        id: 'rollback',
        title: 'Rollback and fallback strategies',
        body: 'Migration plans should define what to do if compatibility, performance, or validation checks fail. Rollback is safer when backups, evidence, and telemetry are prepared before execution.',
        bullets: ['Use sandbox testing first', 'Capture before and after telemetry', 'Keep fallback policy time-limited', 'Avoid permanent weak fallback paths'],
      },
    ],
    examples: [
      {
        title: 'Hybrid migration policy example',
        language: 'json',
        code: `{
  "policy": "hybrid-tls-edge",
  "from": "RSA/ECDHE",
  "to": "ML-KEM-768 + X25519",
  "fallback": "time-boxed",
  "validation": ["tls-handshake", "certificate-chain", "runtime-events"]
}`,
      },
    ],
  },
  {
    id: 'pqc-migration-process',
    group: 'Migration',
    title: 'PQC Migration Process',
    summary: 'Follow the six-phase migration process: awareness, discovery, risk planning, execution, testing, validation, monitoring, simulation, rollback, and compliance verification.',
    icon: Route,
    image: '/Migration_Planner.png',
    tags: ['migration process', 'awareness', 'discovery', 'risk assessment', 'migration execution', 'testing', 'validation'],
    quickLinks: [
      { label: 'PQC Onboarding', href: '/dashboard/pqc-onboarding', icon: Route },
      { label: 'Migration Planner', href: '/dashboard/migration-planner', icon: Rocket },
      { label: 'Live Migration', href: '/dashboard/live-migration', icon: Radio },
    ],
    topics: [
      {
        id: 'phase-awareness',
        title: '1. Awareness & Preparation',
        body: 'Identify business owners, critical systems, data classes, compliance obligations, migration windows, and expected business impact.',
        bullets: ['Define scope', 'Assign ownership', 'Document risk appetite', 'Prepare evidence and communications'],
      },
      {
        id: 'phase-discovery',
        title: '2. Discovery & Inventory',
        body: 'Run scans and collect runtime telemetry to build a complete cryptographic inventory before changing systems.',
        bullets: ['Discover assets', 'Scan certificates and TLS', 'Deploy agents', 'Create CBOM evidence'],
      },
      {
        id: 'phase-risk',
        title: '3. Risk Assessment & Planning',
        body: 'Prioritize findings based on HNDL risk, data retention, exploitability, business criticality, compliance impact, and migration difficulty.',
        bullets: ['Triage findings', 'Select target algorithms', 'Plan hybrid compatibility', 'Create rollback plan'],
      },
      {
        id: 'phase-execution',
        title: '4. Migration Execution',
        body: 'Execute migration jobs through orchestration, migration terminal, policy updates, key rotation, certificate updates, and application changes.',
        bullets: ['Run jobs in controlled windows', 'Watch live telemetry', 'Pause or rollback if needed', 'Record operator actions'],
      },
      {
        id: 'phase-testing',
        title: '5. Migration Testing',
        body: 'Validate behavior in sandbox and production-like environments, including performance, compatibility, TLS handshakes, key exchange, certificates, and application workflows.',
        bullets: ['Run validation scans', 'Compare findings before and after', 'Test rollback', 'Confirm no critical residual exposures'],
      },
      {
        id: 'phase-validation',
        title: '6. Validation & Monitoring',
        body: 'Move into steady-state monitoring with runtime telemetry, compliance evidence, reports, and continuous crypto governance.',
        bullets: ['Enable continuous trust', 'Map evidence to controls', 'Generate reports', 'Monitor drift and runtime events'],
      },
    ],
    walkthroughs: [
      {
        id: 'tutorial-execute-migration',
        title: 'Execute a migration workflow',
        audience: 'Migration operators',
        href: '/dashboard/pqc-orchestration',
        steps: ['Open PQC Orchestration', 'Review queued workflows', 'Select target algorithm and owner', 'Start execution', 'Watch telemetry logs', 'Validate completion'],
      },
      {
        id: 'tutorial-rollback',
        title: 'Perform rollback safely',
        audience: 'DevOps and SRE teams',
        href: '/dashboard/migration-sandbox',
        steps: ['Open Migration Sandbox', 'Select affected migration job', 'Review backup point', 'Run rollback simulation', 'Apply rollback only if validation fails', 'Attach audit evidence'],
      },
    ],
  },
  {
    id: 'compliance-governance',
    group: 'Governance',
    title: 'Compliance & Governance',
    summary: 'Map Qguard Helix evidence to NIST SP 800-208, NIST IR 8547, NIST SP 800-53, crypto governance workflows, audit logs, risk scoring, reporting, and regulatory readiness.',
    icon: ClipboardCheck,
    image: '/Governance_Compliance.png',
    tags: ['compliance', 'governance', 'nist sp 800-208', 'nist ir 8547', 'nist sp 800-53', 'audit logging', 'evidence'],
    quickLinks: [
      { label: 'Compliance', href: '/dashboard/compliance', icon: ClipboardCheck },
      { label: 'Quantum Governance', href: '/dashboard/quantum-governance', icon: ShieldCheck },
      { label: 'Audit Vault', href: '/dashboard/audit-vault', icon: Database },
    ],
    topics: [
      {
        id: 'nist',
        title: 'NIST alignment',
        body: 'The platform organizes migration evidence around NIST-aligned cryptographic modernization, including guidance related to post-quantum planning, key management, control families, and migration readiness.',
        bullets: ['NIST SP 800-208 for stateful hash-based signatures context', 'NIST IR 8547 for migration planning context', 'NIST SP 800-53 for security control mapping', 'NIST PQC standards for algorithm selection'],
      },
      {
        id: 'audit',
        title: 'Audit logging and compliance evidence',
        body: 'Every scan, migration, runtime alert, defense action, and operator decision should produce evidence. Evidence makes migration defensible to auditors and leadership.',
        bullets: ['Capture before and after scan results', 'Record operator actions and approvals', 'Store migration logs and validation artifacts', 'Export reports for governance reviews'],
      },
      {
        id: 'risk-scoring',
        title: 'Risk scoring and reporting workflows',
        body: 'Risk scoring blends severity, business criticality, runtime telemetry, HNDL exposure, migration progress, compliance evidence, and residual findings.',
        bullets: ['Critical and high exposures drive immediate action', 'Completed migrations reduce residual risk', 'Runtime events can re-open risk after deployment'],
      },
    ],
  },
  {
    id: 'defense-actions',
    group: 'Threat Response',
    title: 'Defense Actions',
    summary: 'Operational guidance for isolate asset, kill process, revoke credentials, patch and harden, and backup and restore actions.',
    icon: ShieldAlert,
    image: '/Threat_Intelligence.png',
    tags: ['isolate asset', 'kill process', 'revoke credentials', 'patch harden', 'backup restore', 'remediation'],
    quickLinks: [
      { label: 'Harvest Now', href: '/dashboard/harvest-now', icon: EyeOff },
      { label: 'Runtime Intel', href: '/dashboard/runtime-crypto-intel', icon: Activity },
      { label: 'Audit Vault', href: '/dashboard/audit-vault', icon: Database },
    ],
    topics: [
      {
        id: 'action-model',
        title: 'How defense actions behave',
        body: 'Defense actions are operational responses triggered from risk, runtime, scanner, and HNDL contexts. Each action should be validated, monitored, and recorded.',
        bullets: ['Actions should be tenant-scoped', 'High-impact actions require ownership confirmation', 'Telemetry should update after action execution', 'Evidence should be saved for incident response'],
      },
      {
        id: 'automation',
        title: 'Automation options',
        body: 'Actions may be manual, approval-based, or automated through policy. Automation is recommended only after test runs, ownership rules, and rollback behavior are understood.',
        bullets: ['Use manual mode for first deployment', 'Use approval mode for production', 'Use automation for well-understood, low-risk controls', 'Always monitor realtime behavior after automation'],
      },
    ],
  },
  {
    id: 'monitoring-alerts',
    group: 'Operations',
    title: 'Monitoring & Alerts',
    summary: 'Understand dashboards, threat alerts, signal correlation, incident workflows, monitoring panels, KPIs, real-time logs, status indicators, and severity levels.',
    icon: MonitorCheck,
    image: '/monitoring.png',
    tags: ['monitoring', 'alerts', 'incident workflow', 'kpi', 'logs', 'severity', 'status indicators'],
    quickLinks: [
      { label: 'Telemetry Correlation', href: '/dashboard/telemetry-correlation', icon: Network },
      { label: 'Runtime Telemetry', href: '/dashboard/runtime-telemetry', icon: Radio },
      { label: 'Vulnerabilities', href: '/dashboard/vulnerabilities', icon: Bell },
    ],
    topics: [
      {
        id: 'dashboard-overview',
        title: 'Dashboard overview and KPIs',
        body: 'Operational dashboards show readiness, exposure, runtime events, migration progress, compliance status, scanner health, and alert volume.',
        bullets: ['Readiness shows PQC posture', 'Risk score shows residual exposure', 'Activity feed shows live changes', 'SSE indicators show stream health'],
      },
      {
        id: 'severity',
        title: 'Alert severity levels',
        body: 'Severity communicates urgency and impact. Critical alerts should be validated immediately and linked to response workflows.',
        bullets: ['Critical: immediate action or executive visibility', 'High: schedule remediation and owner review', 'Medium: hardening or planned migration', 'Low/info: monitor and document'],
      },
      {
        id: 'correlation',
        title: 'Signal correlation and incident workflow',
        body: 'Correlation combines scanner findings, runtime events, security events, migration logs, and compliance evidence to reduce mismatched metrics and stale decisions.',
        bullets: ['Use correlated evidence before defense actions', 'Check asset owner and environment', 'Confirm whether migration reduced risk', 'Export incident report after closure'],
      },
    ],
  },
  {
    id: 'api-integrations',
    group: 'Developer',
    title: 'API & Integrations',
    summary: 'API authentication, SDK examples, webhooks, SIEM, cloud, CI/CD, agent APIs, SSE/WebSocket telemetry APIs, and integration patterns.',
    icon: Code,
    image: '/Secure_communication.png',
    tags: ['api', 'sdk', 'webhooks', 'siem', 'cloud integrations', 'ci/cd', 'agent api', 'sse', 'websocket'],
    quickLinks: [
      { label: 'API Encryption', href: '/dashboard/api-encryption', icon: Webhook },
      { label: 'Cloud Security', href: '/dashboard/cloud', icon: Cloud },
      { label: 'Agent Scanner', href: '/dashboard/scanner', icon: Server },
    ],
    topics: [
      {
        id: 'auth',
        title: 'API authentication',
        body: 'Authenticated routes use Bearer tokens from the signed-in session. Server routes validate the token and then query user-scoped data.',
        bullets: ['Use Authorization: Bearer <token>', 'Never share service-role credentials with clients', 'Rotate tokens and secrets regularly', 'Scope integrations to least privilege'],
      },
      {
        id: 'siem',
        title: 'SIEM, cloud, and CI/CD integrations',
        body: 'Export findings, alerts, runtime events, and compliance evidence to SIEM, cloud security tooling, and CI/CD quality gates.',
        bullets: ['Send critical alerts to SIEM', 'Fail CI when critical crypto risk appears', 'Forward migration events to change management', 'Store reports in audit systems'],
      },
      {
        id: 'sse',
        title: 'SSE and WebSocket telemetry APIs',
        body: 'The platform uses SSE streams for live metric updates and module-specific event updates. WebSocket-style integrations should follow the same event schema and tenant isolation model.',
        bullets: ['Metrics stream emits heartbeat and metric updates', 'Scanner and dashboard streams update module surfaces', 'Clients reconnect on stream errors'],
      },
    ],
    examples: [
      {
        title: 'Fetch dashboard health',
        language: 'ts',
        code: `const response = await fetch('/api/v1/dashboard/health', {
  headers: { Authorization: \`Bearer \${session.access_token}\` }
})
const { data } = await response.json()`,
      },
      {
        title: 'Subscribe to metrics SSE',
        language: 'ts',
        code: `const stream = new EventSource(
  \`/api/v1/metrics/stream?token=\${encodeURIComponent(token)}\`
)
stream.addEventListener('metrics-update', (event) => {
  const payload = JSON.parse(event.data)
  console.log(payload.counts)
})`,
      },
      {
        title: 'Webhook event example',
        language: 'json',
        code: `{
  "type": "critical_crypto_exposure",
  "asset": "payments-api-prod",
  "severity": "critical",
  "recommendedAction": "revoke_credentials",
  "timestamp": "2026-05-22T08:30:00Z"
}`,
      },
    ],
  },
  {
    id: 'troubleshooting',
    group: 'Support',
    title: 'Troubleshooting',
    summary: 'Resolve onboarding issues, scanner connectivity, agent deployment, migration failures, telemetry synchronization, performance optimization, and frequently asked questions.',
    icon: Wrench,
    image: '/governance.png',
    tags: ['troubleshooting', 'faq', 'scanner connectivity', 'agent deployment', 'migration failures', 'telemetry sync', 'performance'],
    quickLinks: [
      { label: 'Settings', href: '/dashboard/settings', icon: Settings },
      { label: 'Scanner', href: '/dashboard/scanner', icon: ScanSearch },
      { label: 'Live Migration', href: '/dashboard/live-migration', icon: Radio },
    ],
    topics: [
      {
        id: 'onboarding-issues',
        title: 'Common onboarding issues',
        body: 'Most onboarding problems come from missing profile metadata, incomplete asset ownership, expired tokens, incorrect environment labels, or insufficient permissions.',
        bullets: ['Confirm profile and organization details', 'Check user role and MFA status', 'Verify assets have owners', 'Refresh the browser after permission changes'],
      },
      {
        id: 'scanner-connectivity',
        title: 'Scanner connectivity problems',
        body: 'If scanner jobs do not start or agents do not report, validate network access, token status, agent heartbeat, policy scope, and backend scanner alerts.',
        bullets: ['Check agent token expiration', 'Verify host can reach the API', 'Confirm policy scope includes the target', 'Review scanner alerts and module logs'],
      },
      {
        id: 'migration-failures',
        title: 'Migration failures',
        body: 'Migration failures should be handled through the orchestration and sandbox workflow. Pause, inspect logs, validate rollback, fix compatibility, and retry.',
        bullets: ['Do not rerun blindly', 'Review failed job metadata', 'Use sandbox validation', 'Capture rollback evidence', 'Escalate if production impact is likely'],
      },
      {
        id: 'telemetry-sync',
        title: 'Telemetry synchronization problems',
        body: 'If metrics look stale, check live stream status, authenticated session, API health, Supabase realtime subscription state, and whether source tables have recent tenant-scoped records.',
        bullets: ['Refresh the page', 'Confirm sign-in session', 'Check `/api/v1/health`', 'Check metrics stream indicator', 'Verify recent runtime or scanner events exist'],
      },
      {
        id: 'performance',
        title: 'Performance optimization',
        body: 'Large tenants should scope scans, batch migration jobs, stream telemetry rather than polling aggressively, and use dashboards designed for repeated operational review.',
        bullets: ['Use targeted scan scopes', 'Limit large exports to audit windows', 'Archive closed alerts', 'Avoid unnecessary full environment scans during business hours'],
      },
    ],
  },
  {
    id: 'tutorials',
    group: 'Training',
    title: 'Tutorials & Walkthroughs',
    summary: 'Beginner-friendly walkthroughs for first scan, agents, vulnerabilities, migrations, HNDL response, remediation, telemetry, runtime crypto monitoring, reports, and compliance.',
    icon: BookOpen,
    image: '/quantum_key_generation.png',
    tags: ['tutorial', 'walkthrough', 'first scan', 'deploy agents', 'reports', 'compliance', 'remediation'],
    quickLinks: [
      { label: 'Run First Scan', href: '/dashboard/scanner', icon: ScanSearch },
      { label: 'Generate Reports', href: '/dashboard/compliance', icon: FileDown },
      { label: 'View Telemetry', href: '/dashboard/runtime-telemetry', icon: Radio },
    ],
    topics: [
      {
        id: 'training-path',
        title: 'Recommended training path',
        body: 'New users should complete the tutorials in order: first scan, deploy agents, review vulnerabilities, respond to HNDL, execute migration, validate telemetry, and generate reports.',
        bullets: ['Start with discovery', 'Move into risk and response', 'Practice migration in sandbox', 'Finish with compliance evidence'],
      },
      {
        id: 'training-progress',
        title: 'Progress tracking',
        body: 'This Documentation Center stores local tutorial completion in your browser so new users and operators can track onboarding progress.',
        bullets: ['Mark cards complete after practice', 'Use quick links to open platform modules', 'Download guides for team training'],
      },
    ],
    walkthroughs: [
      {
        id: 'tutorial-deploy-agents',
        title: 'Deploy agents',
        audience: 'DevOps teams',
        href: '/dashboard/scanner',
        steps: ['Create token', 'Run install command', 'Confirm heartbeat', 'Assign policy', 'Validate telemetry'],
      },
      {
        id: 'tutorial-remediation',
        title: 'Perform remediations',
        audience: 'Security operators',
        href: '/dashboard/harvest-now',
        steps: ['Open a finding', 'Choose defense action', 'Review impact', 'Execute or queue', 'Verify activity feed and evidence'],
      },
      {
        id: 'tutorial-runtime-monitoring',
        title: 'Monitor runtime crypto activity',
        audience: 'SOC analysts',
        href: '/dashboard/runtime-crypto-intel',
        steps: ['Open Runtime Crypto Intel', 'Filter for legacy crypto', 'Review process context', 'Check top risks', 'Export findings'],
      },
      {
        id: 'tutorial-reports',
        title: 'Generate compliance reports',
        audience: 'Compliance officers',
        href: '/dashboard/compliance',
        steps: ['Open Compliance', 'Review NIST mapping', 'Confirm evidence freshness', 'Export report', 'Attach to governance workflow'],
      },
    ],
  },
]

const WIZARD_STEPS = [
  { id: 'wizard-profile', label: 'Set up account', href: '/dashboard/settings' },
  { id: 'wizard-agent', label: 'Deploy agent', href: '/dashboard/scanner' },
  { id: 'wizard-scan', label: 'Run first scan', href: '/dashboard/scanner' },
  { id: 'wizard-risk', label: 'Review risk', href: '/dashboard/quantum-risk-scoring' },
  { id: 'wizard-migrate', label: 'Execute migration', href: '/dashboard/pqc-orchestration' },
  { id: 'wizard-monitor', label: 'Validate monitoring', href: '/dashboard/runtime-telemetry' },
]

function loadProgress(): Set<string> {
  try {
    const raw = localStorage.getItem(LOCAL_PROGRESS_KEY)
    const parsed = raw ? JSON.parse(raw) : []
    return new Set<string>(Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string') : [])
  } catch {
    return new Set<string>()
  }
}

function saveProgress(value: Set<string>) {
  localStorage.setItem(LOCAL_PROGRESS_KEY, JSON.stringify(Array.from(value)))
}

function textOf(section: DocSection) {
  return [
    section.title,
    section.summary,
    section.group,
    ...section.tags,
    ...section.topics.flatMap((topic) => [topic.title, topic.body, ...(topic.bullets || [])]),
    ...(section.walkthroughs || []).flatMap((item) => [item.title, item.audience, ...item.steps]),
  ].join(' ').toLowerCase()
}

function useDocsLiveStatus() {
  const { session } = useAuth()
  const token = session?.access_token
  const [status, setStatus] = useState<LiveDocsStatus>(EMPTY_STATUS)
  const [connected, setConnected] = useState(false)

  const refresh = useCallback(async () => {
    try {
      const health = await fetch('/api/v1/health').then((res) => res.json()).catch(() => null)
      const dashboard = token
        ? await fetch('/api/v1/dashboard/health', { headers: { Authorization: `Bearer ${token}` } }).then((res) => res.json()).catch(() => null)
        : null

      setStatus((current) => ({
        ...current,
        platform: health?.data?.status || 'unknown',
        dashboard: dashboard?.data?.status || (token ? 'unknown' : 'sign in for tenant health'),
        scanner: dashboard?.data?.services?.scanner || health?.data?.services?.scanner || 'unknown',
        migration: dashboard?.data?.services?.migration || 'unknown',
        realtime: dashboard?.data?.services?.realtime || current.realtime,
        timestamp: dashboard?.data?.timestamp || health?.data?.timestamp || new Date().toISOString(),
      }))
    } catch {
      setStatus((current) => ({ ...current, platform: 'degraded', timestamp: new Date().toISOString() }))
    }
  }, [token])

  useEffect(() => {
    refresh()
    const interval = setInterval(refresh, 30_000)
    return () => clearInterval(interval)
  }, [refresh])

  useEffect(() => {
    if (!token) {
      setConnected(false)
      return
    }

    const stream = new EventSource(`/api/v1/metrics/stream?token=${encodeURIComponent(token)}`)
    stream.onopen = () => {
      setConnected(true)
      setStatus((current) => ({ ...current, realtime: 'connected' }))
    }
    stream.onerror = () => {
      setConnected(false)
      setStatus((current) => ({ ...current, realtime: 'reconnecting' }))
    }
    stream.addEventListener('metrics-update', (event) => {
      try {
        const payload = JSON.parse((event as MessageEvent).data)
        setStatus((current) => ({
          ...current,
          realtime: 'connected',
          timestamp: payload.timestamp || current.timestamp,
          metrics: payload.counts || current.metrics,
        }))
      } catch {
        refresh()
      }
    })

    return () => {
      stream.close()
      setConnected(false)
    }
  }, [token, refresh])

  return { status, connected, refresh, authenticated: Boolean(token) }
}

function statusClass(value: string) {
  const lower = value.toLowerCase()
  if (lower.includes('ok') || lower.includes('healthy') || lower.includes('connected') || lower.includes('operational')) return 'text-emerald-300 border-emerald-500/25 bg-emerald-500/10'
  if (lower.includes('sign in') || lower.includes('waiting') || lower.includes('reconnect')) return 'text-amber-300 border-amber-400/25 bg-amber-400/10'
  return 'text-red-300 border-red-500/25 bg-red-500/10'
}

function numberFmt(value: number) {
  return new Intl.NumberFormat('en-US').format(value || 0)
}

function percent(value: number, total: number) {
  if (!total) return 0
  return Math.round((value / total) * 100)
}

function copyText(value: string) {
  navigator.clipboard?.writeText(value).catch(() => undefined)
}

function escapePdfText(value: string) {
  return value.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)')
}

function makePdf(title: string, lines: string[]) {
  const text = [title, '', ...lines].slice(0, 38)
  const content = [
    'BT',
    '/F1 18 Tf',
    '48 760 Td',
    `(${escapePdfText(title)}) Tj`,
    '/F1 10 Tf',
    ...text.slice(2).map((line) => `0 -18 Td (${escapePdfText(line.slice(0, 92))}) Tj`),
    'ET',
  ].join('\n')
  const objects = [
    '1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj',
    '2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj',
    '3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj',
    '4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj',
    `5 0 obj << /Length ${content.length} >> stream\n${content}\nendstream endobj`,
  ]
  let offset = 9
  const xref = ['0000000000 65535 f ']
  const body = objects.map((obj) => {
    const current = offset
    offset += obj.length + 1
    xref.push(`${String(current).padStart(10, '0')} 00000 n `)
    return obj
  }).join('\n')
  const trailer = `xref\n0 ${xref.length}\n${xref.join('\n')}\ntrailer << /Size ${xref.length} /Root 1 0 R >>\nstartxref\n${offset}\n%%EOF`
  return `%PDF-1.4\n${body}\n${trailer}`
}

function downloadGuide(section: DocSection) {
  const lines = [
    section.summary,
    '',
    ...section.topics.flatMap((topic) => [
      topic.title,
      topic.body,
      ...(topic.bullets || []).map((bullet) => `- ${bullet}`),
      '',
    ]),
  ]
  const blob = new Blob([makePdf(`${section.title} Guide`, lines)], { type: 'application/pdf' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `qguard-${section.id}-guide.pdf`
  anchor.click()
  URL.revokeObjectURL(url)
}

function LogoMark() {
  return (
    <Link to="/" className="flex items-center gap-3 no-underline">
      <div className="grid h-10 w-10 place-items-center overflow-hidden rounded-lg border border-gold/30 bg-gold/10">
        <img src="/NEW_LOGO.png" alt="" className="h-full w-full object-cover" />
      </div>
      <div>
        <div className="text-sm font-black uppercase tracking-[0.1em] text-gold">Qguard Helix</div>
        <div className="text-[10px] font-bold uppercase tracking-[0.22em] text-white/35">Documentation Center</div>
      </div>
    </Link>
  )
}

function SearchBox({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  return (
    <label className="relative block min-w-0 flex-1">
      <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-white/35" />
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-11 w-full rounded-lg border border-white/10 bg-black/30 pl-10 pr-4 text-sm font-semibold text-white outline-none placeholder:text-white/35 focus:border-gold/60"
        placeholder="Search modules, tutorials, APIs, HNDL, NIST, telemetry..."
        aria-label="Search documentation"
      />
    </label>
  )
}

function GlassPanel({ children, className }: { children: ReactNode; className?: string; key?: string | number }) {
  return (
    <section className={cn(
      'relative overflow-hidden rounded-lg border border-[#FFD36B]/15 bg-[#07101d]/78 shadow-[inset_0_1px_0_rgba(255,255,255,0.07),0_16px_46px_rgba(0,0,0,0.35)] backdrop-blur-xl before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FFE7A0]/55 before:to-transparent',
      className,
    )}>
      <div className="relative z-10 h-full">{children}</div>
    </section>
  )
}

function StatusPill({ label, value }: { label: string; value: string; key?: string }) {
  return (
    <div className="rounded-lg border border-white/10 bg-black/25 p-3">
      <div className="text-[9px] font-black uppercase tracking-[0.18em] text-white/35">{label}</div>
      <div className={cn('mt-2 inline-flex rounded border px-2 py-1 text-[10px] font-black uppercase tracking-[0.12em]', statusClass(value))}>{value}</div>
    </div>
  )
}

function HeaderStatus({ status, connected, authenticated, onRefresh }: { status: LiveDocsStatus; connected: boolean; authenticated: boolean; onRefresh: () => void }) {
  return (
    <GlassPanel className="p-4">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div>
          <div className="text-[11px] font-black uppercase tracking-[0.18em] text-white">Live Platform Status</div>
          <div className="mt-1 flex items-center gap-2 text-[10px] font-black uppercase tracking-[0.14em] text-white/35">
            <span className={cn('h-2 w-2 rounded-full', connected ? 'bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.9)]' : 'bg-amber-400')} />
            {authenticated ? 'Tenant telemetry linked' : 'Public health only'}
          </div>
        </div>
        <button type="button" onClick={onRefresh} className="grid h-9 w-9 place-items-center rounded-md border border-white/10 bg-black/25 text-white/55 hover:border-gold/50 hover:text-gold" aria-label="Refresh live status">
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>
      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <StatusPill label="API" value={status.platform} />
        <StatusPill label="Tenant" value={status.dashboard} />
        <StatusPill label="Realtime" value={status.realtime} />
        <StatusPill label="Scanner" value={status.scanner} />
      </div>
      <div className="mt-3 grid gap-2 sm:grid-cols-3">
        <Metric label="Runtime Events" value={numberFmt(status.metrics.runtimeEvents || 0)} />
        <Metric label="Risks" value={numberFmt(status.metrics.runtimeRisks || 0)} />
        <Metric label="Keys" value={numberFmt(status.metrics.activeKeys || 0)} />
      </div>
    </GlassPanel>
  )
}

function Metric({ label, value }: { label: string; value: string; key?: string }) {
  return (
    <div className="rounded-md border border-white/8 bg-black/20 p-3">
      <div className="text-[9px] font-black uppercase tracking-[0.16em] text-white/35">{label}</div>
      <div className="mt-1 text-xl font-black text-white">{value}</div>
    </div>
  )
}

function Sidebar({
  sections,
  active,
  onSelect,
  mobileOpen,
  onClose,
}: {
  sections: DocSection[]
  active: string
  onSelect: (id: string) => void
  mobileOpen: boolean
  onClose: () => void
}) {
  const [closedGroups, setClosedGroups] = useState<Set<string>>(new Set())
  const groups = useMemo(() => {
    const result = new Map<string, DocSection[]>()
    for (const section of sections) {
      const current = result.get(section.group) || []
      current.push(section)
      result.set(section.group, current)
    }
    return Array.from(result.entries())
  }, [sections])

  const toggleGroup = (group: string) => {
    setClosedGroups((current) => {
      const next = new Set(current)
      if (next.has(group)) next.delete(group)
      else next.add(group)
      return next
    })
  }

  return (
    <aside className={cn(
      'fixed inset-y-0 left-0 z-40 w-[300px] border-r border-gold/15 bg-[#050816]/96 p-4 backdrop-blur-xl transition lg:sticky lg:top-0 lg:z-10 lg:h-screen lg:translate-x-0',
      mobileOpen ? 'translate-x-0' : '-translate-x-full',
    )}>
      <div className="mb-5 flex items-center justify-between gap-3">
        <LogoMark />
        <button type="button" onClick={onClose} className="grid h-9 w-9 place-items-center rounded-md border border-white/10 text-white/60 lg:hidden" aria-label="Close documentation navigation">
          <X className="h-4 w-4" />
        </button>
      </div>
      <nav className="h-[calc(100vh-92px)] overflow-y-auto pr-1">
        <div className="space-y-4">
          {groups.map(([group, items]) => {
            const closed = closedGroups.has(group)
            return (
              <div key={group}>
                <button
                  type="button"
                  onClick={() => toggleGroup(group)}
                  className="mb-2 flex w-full items-center justify-between rounded-md px-2 py-1 text-left text-[10px] font-black uppercase tracking-[0.18em] text-gold/70 hover:bg-gold/10 hover:text-gold"
                >
                  {group}
                  <ChevronDown className={cn('h-3.5 w-3.5 transition', closed && '-rotate-90')} />
                </button>
                {!closed && (
                  <div className="space-y-1">
                    {items.map((section) => {
                      const Icon = section.icon
                      const selected = active === section.id
                      return (
                        <button
                          type="button"
                          key={section.id}
                          onClick={() => {
                            onSelect(section.id)
                            onClose()
                          }}
                          className={cn(
                            'flex w-full items-center gap-3 rounded-lg border px-3 py-2.5 text-left transition',
                            selected ? 'border-gold/35 bg-gold/10 text-gold shadow-[0_0_18px_rgba(255,211,107,0.14)]' : 'border-transparent text-white/55 hover:border-white/10 hover:bg-white/[0.04] hover:text-white',
                          )}
                        >
                          <Icon className="h-4 w-4 shrink-0" />
                          <span className="min-w-0 text-xs font-bold leading-snug">{section.title}</span>
                        </button>
                      )
                    })}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </nav>
    </aside>
  )
}

function Breadcrumb({ section }: { section: DocSection }) {
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs font-bold text-white/45">
      <Link to="/" className="text-white/45 no-underline hover:text-gold">Home</Link>
      <ChevronRight className="h-3.5 w-3.5" />
      <span>Docs</span>
      <ChevronRight className="h-3.5 w-3.5" />
      <span className="text-gold">{section.title}</span>
    </div>
  )
}

function SectionHero({ section, onDownload }: { section: DocSection; onDownload: () => void }) {
  const Icon = section.icon
  return (
    <GlassPanel className="p-4 md:p-5">
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_290px]">
        <div>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <span className="rounded border border-gold/30 bg-gold/10 px-3 py-1 text-[10px] font-black uppercase tracking-[0.15em] text-gold">{section.group}</span>
            {section.tags.slice(0, 4).map((tag) => (
              <span key={tag} className="rounded border border-white/10 bg-white/[0.03] px-2 py-1 text-[10px] font-bold text-white/45">{tag}</span>
            ))}
          </div>
          <h1 className="flex items-center gap-3 text-3xl font-black leading-tight text-white md:text-4xl">
            <span className="grid h-11 w-11 shrink-0 place-items-center rounded-lg border border-gold/30 bg-gold/10 text-gold">
              <Icon className="h-6 w-6" />
            </span>
            {section.title}
          </h1>
          <p className="mt-4 max-w-4xl text-sm leading-6 text-white/62">{section.summary}</p>
          <div className="mt-5 flex flex-wrap gap-3">
            {section.quickLinks.map((link) => {
              const LinkIcon = link.icon
              return (
                <Link key={link.href} to={link.href} className="inline-flex h-10 items-center gap-2 rounded-md border border-blue-400/30 bg-blue-500/5 px-4 text-xs font-black text-blue-300 no-underline hover:bg-blue-500/10">
                  <LinkIcon className="h-4 w-4" />
                  {link.label}
                </Link>
              )
            })}
            <button type="button" onClick={onDownload} className="inline-flex h-10 items-center gap-2 rounded-md border border-gold/35 bg-gold/10 px-4 text-xs font-black text-gold hover:bg-gold/20">
              <FileDown className="h-4 w-4" />
              Download PDF Guide
            </button>
          </div>
        </div>
        <div className="relative min-h-[190px] overflow-hidden rounded-lg border border-white/10 bg-black/25">
          <img src={section.image} alt="" className="h-full min-h-[190px] w-full object-cover opacity-70" />
          <div className="absolute inset-0 bg-[linear-gradient(180deg,transparent,rgba(2,6,13,0.82))]" />
          <div className="absolute bottom-4 left-4 right-4">
            <div className="text-[10px] font-black uppercase tracking-[0.18em] text-gold">Official Guide</div>
            <div className="mt-1 text-sm font-black text-white">Enterprise knowledge base and operator handbook</div>
          </div>
        </div>
      </div>
    </GlassPanel>
  )
}

function Wizard({ completed, onToggle }: { completed: Set<string>; onToggle: (id: string) => void }) {
  const done = WIZARD_STEPS.filter((step) => completed.has(step.id)).length
  const width = percent(done, WIZARD_STEPS.length)

  return (
    <GlassPanel className="p-4">
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="text-[11px] font-black uppercase tracking-[0.18em] text-gold">Getting Started Wizard</div>
          <h2 className="mt-1 text-xl font-black text-white">New user onboarding path</h2>
        </div>
        <div className="text-sm font-black text-white">{done}/{WIZARD_STEPS.length} complete</div>
      </div>
      <div className="mt-4 h-2 overflow-hidden rounded-full bg-white/10">
        <div className="h-full rounded-full bg-gold shadow-[0_0_18px_rgba(255,211,107,0.75)]" style={{ width: `${width}%` }} />
      </div>
      <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {WIZARD_STEPS.map((step, index) => {
          const doneStep = completed.has(step.id)
          return (
            <div key={step.id} className="rounded-lg border border-white/10 bg-black/20 p-3">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-[9px] font-black uppercase tracking-[0.16em] text-white/35">Step {index + 1}</div>
                  <div className="mt-1 text-sm font-black text-white">{step.label}</div>
                </div>
                <button
                  type="button"
                  onClick={() => onToggle(step.id)}
                  className={cn('grid h-8 w-8 place-items-center rounded-md border', doneStep ? 'border-emerald-500/35 bg-emerald-500/10 text-emerald-300' : 'border-white/10 bg-white/[0.03] text-white/45')}
                  aria-label={`Mark ${step.label} ${doneStep ? 'incomplete' : 'complete'}`}
                  title={doneStep ? 'Mark incomplete' : 'Mark complete'}
                >
                  <Check className="h-4 w-4" />
                </button>
              </div>
              <Link to={step.href} className="mt-3 inline-flex items-center gap-2 text-xs font-black text-blue-300 no-underline hover:text-gold">
                Open module <ArrowRight className="h-4 w-4" />
              </Link>
            </div>
          )
        })}
      </div>
    </GlassPanel>
  )
}

function ModuleCatalog() {
  return (
    <GlassPanel className="p-4">
      <div className="mb-4 flex items-center gap-2">
        <Layers className="h-4 w-4 text-gold" />
        <h2 className="text-[12px] font-black uppercase tracking-[0.18em] text-white">Platform Module Map</h2>
      </div>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {MODULE_LINKS.map((item) => {
          const Icon = item.icon
          return (
            <Link key={item.href} to={item.href} className="group rounded-lg border border-white/10 bg-black/20 p-4 text-white no-underline transition hover:-translate-y-0.5 hover:border-gold/45 hover:bg-gold/[0.04] hover:shadow-[0_0_24px_rgba(255,211,107,0.18)]">
              <div className="flex items-start gap-3">
                <div className="grid h-10 w-10 shrink-0 place-items-center rounded-lg border border-gold/25 bg-gold/10 text-gold">
                  <Icon className="h-5 w-5" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 text-sm font-black">{item.label}<ArrowRight className="h-3.5 w-3.5 text-white/25 group-hover:text-gold" /></div>
                  <p className="mt-1 text-xs leading-5 text-white/52">{item.desc}</p>
                </div>
              </div>
            </Link>
          )
        })}
      </div>
    </GlassPanel>
  )
}

function TopicAccordion({ topic, defaultOpen }: { topic: Topic; defaultOpen?: boolean; key?: string }) {
  const [open, setOpen] = useState(Boolean(defaultOpen))
  return (
    <div id={topic.id} className="rounded-lg border border-white/10 bg-black/20">
      <button type="button" onClick={() => setOpen((value) => !value)} className="flex w-full items-center justify-between gap-4 p-4 text-left">
        <div>
          <h3 className="text-base font-black text-white">{topic.title}</h3>
          {!open ? <p className="mt-1 line-clamp-1 text-xs text-white/42">{topic.body}</p> : null}
        </div>
        <ChevronDown className={cn('h-5 w-5 shrink-0 text-gold transition', open && 'rotate-180')} />
      </button>
      {open ? (
        <div className="border-t border-white/8 p-4 pt-3">
          <p className="text-sm leading-6 text-white/62">{topic.body}</p>
          {topic.bullets?.length ? (
            <ul className="mt-4 grid gap-2 md:grid-cols-2">
              {topic.bullets.map((bullet) => (
                <li key={bullet} className="grid grid-cols-[18px_1fr] gap-2 text-xs leading-5 text-white/62">
                  <CheckCircle className="mt-0.5 h-4 w-4 text-emerald-300" />
                  <span>{bullet}</span>
                </li>
              ))}
            </ul>
          ) : null}
          {topic.callout ? (
            <div className="mt-4 rounded-md border border-gold/25 bg-gold/10 p-3 text-xs leading-5 text-gold">
              {topic.callout}
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}

function WalkthroughCard({ item, completed, onToggle }: { item: Walkthrough; completed: boolean; onToggle: () => void; key?: string }) {
  return (
    <div className="rounded-lg border border-white/10 bg-black/20 p-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-[9px] font-black uppercase tracking-[0.16em] text-gold">{item.audience}</div>
          <h3 className="mt-1 text-base font-black text-white">{item.title}</h3>
        </div>
        <button
          type="button"
          onClick={onToggle}
          className={cn('grid h-9 w-9 place-items-center rounded-md border', completed ? 'border-emerald-500/35 bg-emerald-500/10 text-emerald-300' : 'border-white/10 bg-white/[0.03] text-white/45')}
          aria-label={`Mark ${item.title} ${completed ? 'incomplete' : 'complete'}`}
          title={completed ? 'Completed' : 'Mark complete'}
        >
          <Check className="h-4 w-4" />
        </button>
      </div>
      <ol className="mt-4 space-y-2">
        {item.steps.map((step, index) => (
          <li key={step} className="grid grid-cols-[24px_1fr] gap-3 text-xs leading-5 text-white/62">
            <span className="grid h-6 w-6 place-items-center rounded-full border border-gold/25 bg-gold/10 text-[10px] font-black text-gold">{index + 1}</span>
            <span>{step}</span>
          </li>
        ))}
      </ol>
      <div className="mt-4 flex items-center justify-between gap-3">
        <Link to={item.href} className="inline-flex items-center gap-2 text-xs font-black text-blue-300 no-underline hover:text-gold">
          Open walkthrough module <ArrowRight className="h-4 w-4" />
        </Link>
        <VideoPlaceholder />
      </div>
    </div>
  )
}

function VideoPlaceholder() {
  return (
    <button type="button" className="inline-flex h-8 items-center gap-2 rounded-md border border-white/10 bg-white/[0.03] px-3 text-[10px] font-black uppercase tracking-[0.12em] text-white/55 hover:border-gold/35 hover:text-gold" title="Tutorial video placeholder" aria-label="Tutorial video placeholder">
      <PlayCircle className="h-3.5 w-3.5" />
      Video
    </button>
  )
}

function CodeBlock({ example }: { example: CodeExample; key?: string }) {
  return (
    <div className="overflow-hidden rounded-lg border border-white/10 bg-[#030711]">
      <div className="flex items-center justify-between border-b border-white/10 px-4 py-3">
        <div>
          <div className="text-sm font-black text-white">{example.title}</div>
          <div className="text-[10px] font-black uppercase tracking-[0.16em] text-white/35">{example.language}</div>
        </div>
        <button type="button" onClick={() => copyText(example.code)} className="grid h-8 w-8 place-items-center rounded-md border border-white/10 text-white/55 hover:border-gold/40 hover:text-gold" aria-label={`Copy ${example.title}`}>
          <Copy className="h-3.5 w-3.5" />
        </button>
      </div>
      <pre className="max-h-[320px] overflow-auto p-4 text-xs leading-6 text-white/70"><code>{example.code}</code></pre>
    </div>
  )
}

function DefenseActionGrid() {
  return (
    <div className="grid gap-3 md:grid-cols-2">
      {DEFENSE_ACTIONS.map((action) => (
        <div key={action.title} className="rounded-lg border border-white/10 bg-black/20 p-4">
          <div className="mb-2 flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-red-300" />
            <h3 className="text-base font-black text-white">{action.title}</h3>
          </div>
          <p className="text-xs leading-5 text-white/58"><span className="font-black text-gold">When:</span> {action.when}</p>
          <p className="mt-2 text-xs leading-5 text-white/58"><span className="font-black text-gold">Impact:</span> {action.impact}</p>
          <div className="mt-3 rounded-md border border-white/8 bg-black/25 p-3">
            <div className="mb-2 text-[9px] font-black uppercase tracking-[0.16em] text-white/35">Recommended Workflow</div>
            <ol className="space-y-1">
              {action.workflow.map((step, index) => (
                <li key={step} className="text-xs text-white/58">{index + 1}. {step}</li>
              ))}
            </ol>
          </div>
          <Link to={action.href} className="mt-3 inline-flex items-center gap-2 text-xs font-black text-blue-300 no-underline hover:text-gold">
            Open related module <ArrowRight className="h-4 w-4" />
          </Link>
        </div>
      ))}
    </div>
  )
}

function FaqPanel() {
  return (
    <GlassPanel className="p-4">
      <div className="mb-4 flex items-center gap-2">
        <HelpCircle className="h-4 w-4 text-gold" />
        <h2 className="text-[12px] font-black uppercase tracking-[0.18em] text-white">FAQ</h2>
      </div>
      <div className="space-y-3">
        {FAQ.map(([question, answer]) => (
          <details key={question} className="rounded-lg border border-white/10 bg-black/20 p-4">
            <summary className="cursor-pointer text-sm font-black text-white">{question}</summary>
            <p className="mt-3 text-sm leading-6 text-white/58">{answer}</p>
          </details>
        ))}
      </div>
    </GlassPanel>
  )
}

function Toc({ section, completedCount, totalProgress, status, onDownload }: { section: DocSection; completedCount: number; totalProgress: number; status: LiveDocsStatus; onDownload: () => void }) {
  return (
    <aside className="hidden xl:block">
      <div className="sticky top-5 space-y-4">
        <GlassPanel className="p-4">
          <div className="mb-3 text-[11px] font-black uppercase tracking-[0.18em] text-white">On This Page</div>
          <div className="space-y-2">
            {section.topics.map((topic) => (
              <a key={topic.id} href={`#${topic.id}`} className="block rounded-md px-2 py-1.5 text-xs font-bold text-white/50 no-underline hover:bg-gold/10 hover:text-gold">
                {topic.title}
              </a>
            ))}
          </div>
          <button type="button" onClick={onDownload} className="mt-4 inline-flex h-9 w-full items-center justify-center gap-2 rounded-md border border-gold/30 bg-gold/10 text-xs font-black text-gold hover:bg-gold/20">
            <Download className="h-4 w-4" />
            Download Guide
          </button>
        </GlassPanel>
        <GlassPanel className="p-4">
          <div className="mb-2 text-[11px] font-black uppercase tracking-[0.18em] text-white">Training Progress</div>
          <div className="text-3xl font-black text-gold">{totalProgress}%</div>
          <div className="mt-1 text-xs text-white/45">{completedCount} tutorials completed</div>
          <div className="mt-3 h-2 overflow-hidden rounded-full bg-white/10">
            <div className="h-full rounded-full bg-gold" style={{ width: `${totalProgress}%` }} />
          </div>
        </GlassPanel>
        <GlassPanel className="p-4">
          <div className="mb-3 text-[11px] font-black uppercase tracking-[0.18em] text-white">Help & Support</div>
          <p className="text-xs leading-5 text-white/55">For implementation help, open settings or contact your Qguard Helix administrator.</p>
          <Link to="/dashboard/settings" className="mt-4 inline-flex h-9 w-full items-center justify-center gap-2 rounded-md border border-blue-400/30 bg-blue-500/5 text-xs font-black text-blue-300 no-underline hover:bg-blue-500/10">
            <LifeBuoy className="h-4 w-4" />
            Contact Support
          </Link>
          <div className="mt-3 text-[10px] text-white/35">Last status: {status.timestamp ? new Date(status.timestamp).toLocaleTimeString() : 'waiting'}</div>
        </GlassPanel>
      </div>
    </aside>
  )
}

function SectionContent({
  section,
  completed,
  onToggleProgress,
}: {
  section: DocSection
  completed: Set<string>
  onToggleProgress: (id: string) => void
}) {
  return (
    <div className="space-y-4">
      {section.id === 'platform-introduction' ? <ModuleCatalog /> : null}
      {section.id === 'defense-actions' ? <DefenseActionGrid /> : null}
      <GlassPanel className="p-4">
        <div className="mb-4 flex items-center gap-2">
          <BookOpen className="h-4 w-4 text-gold" />
          <h2 className="text-[12px] font-black uppercase tracking-[0.18em] text-white">Documentation</h2>
        </div>
        <div className="space-y-3">
          {section.topics.map((topic, index) => <TopicAccordion key={topic.id} topic={topic} defaultOpen={index === 0} />)}
        </div>
      </GlassPanel>
      {section.walkthroughs?.length ? (
        <GlassPanel className="p-4">
          <div className="mb-4 flex items-center gap-2">
            <Terminal className="h-4 w-4 text-gold" />
            <h2 className="text-[12px] font-black uppercase tracking-[0.18em] text-white">Step-by-Step Walkthroughs</h2>
          </div>
          <div className="grid gap-3 lg:grid-cols-2">
            {section.walkthroughs.map((item) => (
              <WalkthroughCard
                key={item.id}
                item={item}
                completed={completed.has(item.id)}
                onToggle={() => onToggleProgress(item.id)}
              />
            ))}
          </div>
        </GlassPanel>
      ) : null}
      {section.examples?.length ? (
        <GlassPanel className="p-4">
          <div className="mb-4 flex items-center gap-2">
            <Code className="h-4 w-4 text-gold" />
            <h2 className="text-[12px] font-black uppercase tracking-[0.18em] text-white">Code Snippets & Examples</h2>
          </div>
          <div className="grid gap-3">
            {section.examples.map((example) => <CodeBlock key={example.title} example={example} />)}
          </div>
        </GlassPanel>
      ) : null}
      {section.id === 'troubleshooting' ? <FaqPanel /> : null}
    </div>
  )
}

export default function DocsPage() {
  const [query, setQuery] = useState('')
  const [activeId, setActiveId] = useState('platform-introduction')
  const [mobileOpen, setMobileOpen] = useState(false)
  const [completed, setCompleted] = useState<Set<string>>(() => loadProgress())
  const { status, connected, refresh, authenticated } = useDocsLiveStatus()

  const filteredSections = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return SECTIONS
    return SECTIONS.filter((section) => textOf(section).includes(q))
  }, [query])

  useEffect(() => {
    if (filteredSections.length && !filteredSections.some((section) => section.id === activeId)) {
      setActiveId(filteredSections[0].id)
    }
  }, [filteredSections, activeId])

  const activeSection = filteredSections.find((section) => section.id === activeId) || filteredSections[0] || SECTIONS[0]
  const allWalkthroughIds = useMemo(() => [
    ...WIZARD_STEPS.map((step) => step.id),
    ...SECTIONS.flatMap((section) => section.walkthroughs || []).map((item) => item.id),
  ], [])
  const completedCount = allWalkthroughIds.filter((id) => completed.has(id)).length
  const progress = percent(completedCount, allWalkthroughIds.length)

  const toggleProgress = (id: string) => {
    setCompleted((current) => {
      const next = new Set<string>(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      saveProgress(next)
      return next
    })
  }

  const pageStyle = {
    '--gold': '#FFD36B',
  } as CSSProperties

  return (
    <main className="qg-docs-shell min-h-screen bg-[#02060d] text-white" style={pageStyle}>
      <div className="pointer-events-none fixed inset-0 opacity-70" aria-hidden="true">
        <div className="absolute inset-0 bg-[linear-gradient(rgba(255,211,107,0.035)_1px,transparent_1px),linear-gradient(90deg,rgba(56,189,248,0.025)_1px,transparent_1px)] bg-[size:44px_44px]" />
        <div className="absolute inset-0 bg-[linear-gradient(180deg,rgba(255,211,107,0.08),transparent_34%,rgba(56,189,248,0.05)_100%)]" />
      </div>

      <div className="relative z-10 flex">
        <Sidebar
          sections={filteredSections}
          active={activeSection.id}
          onSelect={setActiveId}
          mobileOpen={mobileOpen}
          onClose={() => setMobileOpen(false)}
        />
        {mobileOpen ? <button type="button" aria-label="Close overlay" className="fixed inset-0 z-30 bg-black/60 lg:hidden" onClick={() => setMobileOpen(false)} /> : null}

        <div className="min-w-0 flex-1">
          <header className="sticky top-0 z-20 border-b border-gold/15 bg-[#02060d]/90 px-4 py-3 backdrop-blur-xl lg:px-6">
            <div className="flex flex-col gap-3 xl:flex-row xl:items-center">
              <div className="flex items-center gap-3">
                <button type="button" onClick={() => setMobileOpen(true)} className="grid h-10 w-10 place-items-center rounded-lg border border-white/10 bg-black/25 text-white/70 lg:hidden" aria-label="Open documentation navigation">
                  <Menu className="h-4 w-4" />
                </button>
                <div className="hidden lg:block"><LogoMark /></div>
              </div>
              <SearchBox value={query} onChange={setQuery} />
              <div className="flex items-center gap-2">
                <ThemeToggle compact showSystem={false} />
                <Link to="/dashboard" className="inline-flex h-10 items-center gap-2 rounded-md border border-gold/30 bg-gold/10 px-4 text-xs font-black text-gold no-underline hover:bg-gold/20">
                  Open Platform <ArrowRight className="h-4 w-4" />
                </Link>
              </div>
            </div>
          </header>

          <div className="grid gap-5 p-4 lg:p-6 xl:grid-cols-[minmax(0,1fr)_300px] 2xl:grid-cols-[minmax(0,1fr)_330px]">
            <div className="min-w-0 space-y-4">
              <Breadcrumb section={activeSection} />
              <SectionHero section={activeSection} onDownload={() => downloadGuide(activeSection)} />
              <HeaderStatus status={status} connected={connected} authenticated={authenticated} onRefresh={refresh} />
              <Wizard completed={completed} onToggle={toggleProgress} />
              {query && (
                <GlassPanel className="p-4">
                  <div className="text-sm font-black text-white">{filteredSections.length} matching documentation section{filteredSections.length === 1 ? '' : 's'}</div>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {filteredSections.map((section) => (
                      <button key={section.id} type="button" onClick={() => setActiveId(section.id)} className="rounded-md border border-white/10 bg-black/20 px-3 py-2 text-xs font-bold text-white/60 hover:border-gold/40 hover:text-gold">
                        {section.title}
                      </button>
                    ))}
                  </div>
                </GlassPanel>
              )}
              <SectionContent section={activeSection} completed={completed} onToggleProgress={toggleProgress} />
            </div>
            <Toc
              section={activeSection}
              completedCount={completedCount}
              totalProgress={progress}
              status={status}
              onDownload={() => downloadGuide(activeSection)}
            />
          </div>
        </div>
      </div>
    </main>
  )
}
