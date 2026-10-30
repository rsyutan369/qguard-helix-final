/**
 * QGuard Helix Features — the platform showcase (/qguard-helix-features).
 *
 * Per Qguard_Wiki/Qguard_Helix_Features_Page: a premium, enterprise-grade product
 * page that explains the 15 flagship modules in business language for CISOs,
 * architects, compliance teams and executive buyers.
 *
 * Copy discipline: every capability listed below is drawn from the shipped module
 * it describes (see the dashboard routes linked from each section). No customer
 * counts, percentages, ROI figures or other outcome metrics are invented — the
 * hero statistics are verifiable facts about the platform and the NIST timeline.
 *
 * Media: the hero books reuse each module's local artwork; there is no hero video.
 */
import React, { useEffect } from 'react';
import { FeaturesBookHero } from './_features-book-hero';
import {
  Activity,
  Award,
  BadgeCheck,
  BrainCircuit,
  CalendarClock,
  CheckCircle2,
  ClipboardCheck,
  Compass,
  Eye,
  FileBarChart,
  Fingerprint,
  FlaskConical,
  Gauge,
  GitBranch,
  Layers,
  Link2,
  type LucideIcon,
  Network,
  Radar,
  Radio,
  Rocket,
  Route as RouteIcon,
  ScanSearch,
  Scale,
  ShieldCheck,
  Sparkles,
  Target,
  TrendingUp,
  Wrench,
} from 'lucide-react';
import {
  SolutionLayout,
  Reveal,
  Highlight,
  SectionHeading,
  GlassCard,
  TrustStrip,
  DarkButton,
  GhostButton,
} from './_solution-shared';
import {
  AMBER,
  BLUE,
  BenefitCard,
  ChapterMarker,
  CYAN,
  EMERALD,
  FinalCTA,
  GOLD,
  LifecycleRail,
  ModuleNavigator,
  ModuleShowcase,
  ROSE,
  ShiftPanel,
  VIOLET,
  type ModuleEntry,
  type ShiftRow,
} from './_features-sections';

const MEDIA = '/helix-features';

/* ---------------------------------------------------------------- chrome --- */

const NAV_LINKS = [
  { label: 'Overview', href: '#top' },
  { label: 'Lifecycle', href: '#lifecycle' },
  { label: 'Modules', href: '#modules' },
  { label: 'Benefits', href: '#benefits' },
  { label: 'Compare', href: '#compare' },
];

const FOOTER_GROUPS = [
  {
    title: 'Assess',
    links: [
      { label: 'Quantum Readiness', to: '/dashboard/quantum-readiness' },
      { label: 'Quantum Remediation', to: '/dashboard/quantum-readiness/remediation' },
      { label: 'Quantum Certification', to: '/dashboard/quantum-certification' },
      { label: 'Free Public Scan', to: '/public-scan' },
    ],
  },
  {
    title: 'Migrate',
    links: [
      { label: 'Migration Planner', to: '/dashboard/migration-planner' },
      { label: 'Migration Sandbox', to: '/dashboard/migration-sandbox' },
      { label: 'Live Migration', to: '/dashboard/live-migration' },
      { label: 'Migration Timeline', to: '/dashboard/migration-timeline' },
    ],
  },
  {
    title: 'Platform',
    links: [
      { label: 'QGuard Helix', href: '/' },
      { label: 'PQC Solutions', to: '/pqc-solutions' },
      { label: 'Documentation', href: '/docs' },
      { label: 'Pricing', href: '/#pricing' },
    ],
  },
];

const TRUST_ITEMS = [
  'FIPS 203 · ML-KEM',
  'FIPS 204 · ML-DSA',
  'FIPS 205 · SLH-DSA',
  'Evidence-Backed Scoring',
  'Multi-Tenant Isolation',
  'Rollback-Safe Migration',
];

/* -------------------------------------------------------------- lifecycle -- */

const LIFECYCLE: Array<{ label: string; body: string; icon: LucideIcon; color: string }> = [
  { label: 'Discover', body: 'Find every certificate, key, algorithm and endpoint you actually run.', icon: ScanSearch, color: CYAN },
  { label: 'Assess', body: 'Score what is exposed, how badly, and how soon it matters.', icon: Gauge, color: BLUE },
  { label: 'Plan', body: 'Turn findings into a sequenced, costed and funded roadmap.', icon: RouteIcon, color: VIOLET },
  { label: 'Migrate', body: 'Simulate first, then execute with snapshots and rollback.', icon: Rocket, color: AMBER },
  { label: 'Validate', body: 'Prove the change worked — in the runtime, not the ticket.', icon: ClipboardCheck, color: EMERALD },
  { label: 'Monitor', body: 'Watch live cryptography for drift the moment it appears.', icon: Activity, color: ROSE },
  { label: 'Govern', body: 'Hold signed, verifiable evidence for auditors and customers.', icon: Scale, color: GOLD },
];

/* ---------------------------------------------------------------- modules -- */

const MODULES: ModuleEntry[] = [
  /* ------------------------------------------------ Chapter I — Assess ---- */
  {
    id: 'quantum-readiness',
    index: 1,
    chapter: 'assess',
    eyebrow: 'Quantum Readiness',
    title: 'Quantum Readiness Assessment Engine™',
    blurb:
      'One measured, defensible answer to the question every board is now asking: how exposed are we to quantum attack, and what is the plan?',
    value:
      'Replaces opinion with a single readiness score your executives, auditors and engineers all read from — every number traceable to the evidence behind it.',
    capabilities: [
      'Operational Command Center with live assessment telemetry',
      'Board-ready Executive Dashboard and business-impact forecast',
      'Quantum Exposure Graph™ for dependency and blast-radius mapping',
      'Technical risk analysis with prioritised, evidence-linked findings',
      'Harvest Now, Decrypt Later exposure by data shelf-life',
      'AI Executive and AI Migration Advisors grounded in your own data',
      'Report Center for customer-facing evidence packages',
    ],
    benefits: ['One number leadership trusts', 'Audit-ready evidence', 'Clear next action'],
    useCase:
      'Your regulator asks for a quantum-risk position paper in three weeks. You export it from the Report Center the same afternoon — with the findings that back every claim attached.',
    image: '/downloads/readiness.png',
    icon: Gauge,
    accent: CYAN,
    to: '/dashboard/quantum-readiness',
  },
  {
    id: 'quantum-remediation',
    index: 2,
    chapter: 'assess',
    eyebrow: 'Remediation',
    title: 'Quantum Remediation Engine™',
    blurb:
      'Turns a long list of cryptographic findings into a short, ordered list of fixes — each one with the standard it satisfies and the effort it takes.',
    value:
      'Teams stop debating where to start. The queue is ordered by how much risk each fix actually removes, so the first week of work is the most valuable week of work.',
    capabilities: [
      'Per-asset remediation playbooks aligned to NIST guidance',
      'Priority queue across critical, high, medium and low',
      'Quick-wins filter for high-value, low-effort fixes',
      'Effort estimates attached to every recommended action',
      'Live Certification Readiness Score with a marginal-gain ladder',
      'Workflow rail showing where each asset sits in its lifecycle',
    ],
    benefits: ['Ordered by risk removed', 'Quick wins surfaced', 'Effort made visible'],
    useCase:
      'A platform team has budget for two sprints, not twenty. The quick-wins filter shows which eleven fixes move the readiness score most for the least work.',
    image: '/downloads/remediation.jpg',
    icon: Wrench,
    accent: EMERALD,
    to: '/dashboard/quantum-readiness/remediation',
  },
  {
    id: 'quantum-certification',
    index: 3,
    chapter: 'assess',
    eyebrow: 'Certification',
    title: 'Quantum Trust Certification™',
    blurb:
      'Issues a cryptographically signed, publicly verifiable certificate that states exactly how quantum-ready an environment is — and refuses to issue one that the evidence does not support.',
    value:
      'Gives you something to hand a customer, an insurer or a procurement team that is stronger than a claim: a signed artefact anyone can independently verify.',
    capabilities: [
      'Certificates signed with ML-DSA-65 (NIST FIPS 204)',
      'Bronze, Silver, Gold, Platinum and Diamond readiness tiers',
      'Evidence-gated issuance — criteria must be met, not asserted',
      'Public verification portal for third parties',
      'Export as PDF, PNG, SVG, JSON or a full audit package',
      'Continuous re-verification as posture changes',
    ],
    benefits: ['Independently verifiable', 'Wins procurement reviews', 'Never over-claims'],
    useCase:
      'An enterprise buyer asks how you handle post-quantum risk. You send a verification link instead of a slide, and they check the signature themselves.',
    image: '/downloads/Certifications.png',
    icon: Award,
    accent: GOLD,
    to: '/dashboard/quantum-certification',
  },

  /* -------------------------------------------------- Chapter II — Plan --- */
  {
    id: 'migration-planner',
    index: 4,
    chapter: 'plan',
    eyebrow: 'Migration Planner',
    title: 'Migration Planner',
    blurb:
      'Converts your cryptographic inventory into a sequenced, costed migration programme that leadership can actually approve and fund.',
    value:
      'Ends the spreadsheet era. You can model a strategy, see its cost and risk, and only then commit — instead of discovering the trade-offs halfway through the programme.',
    capabilities: [
      'Migration Strategy Simulator™ with what-if analysis',
      'Migration Risk Engine™ scoring every wave before it runs',
      'AI Migration Advisor™ for sequencing and rollback guidance',
      'Asset-level dossiers with posture, owner and dependencies',
      'Migration waves, blockers and readiness breakdown',
      'Business-impact analysis and cost forecasting',
      'Nine-stage workflow: Discover → Analyze → Prioritize → Simulate → Plan → Approve → Execute → Validate → Optimize',
    ],
    benefits: ['Fundable roadmap', 'Model before you commit', 'Blockers surfaced early'],
    useCase:
      'A bank must show its regulator a dated, funded plan for twelve thousand certificates. The planner produces the waves, the costs and the dependencies behind each date.',
    image: '/downloads/migration-planner.jpg',
    icon: Target,
    accent: VIOLET,
    to: '/dashboard/migration-planner',
  },
  {
    id: 'migration-intelligence',
    index: 5,
    chapter: 'plan',
    eyebrow: 'Migration Intel',
    title: 'Migration Intelligence',
    blurb:
      'Answers a question most tools ignore: of everything flagged as risky, which parts can your team actually fix — and which belong to somebody else?',
    value:
      'Stops engineers burning sprints on findings they have no power to remediate, and gives you the evidence to push the rest to the provider or vendor who owns it.',
    capabilities: [
      'Shared-responsibility model: customer, provider and ecosystem ownership',
      'Ownership findings ranked by priority and business impact',
      'Dependency readiness states — ready, pending or blocked',
      'Readiness scoring per responsibility domain',
      'Blast-radius view of what one unresolved dependency affects',
      'Attribution honesty rules so nothing is blamed on the wrong owner',
    ],
    benefits: ['Actionable work isolated', 'Vendor pressure evidenced', 'No wasted sprints'],
    useCase:
      'Half of your "critical" TLS findings sit behind a CDN you do not control. This separates them out, so your team works the half it can finish.',
    image: '/downloads/migration-intelligence1.png',
    icon: Network,
    accent: BLUE,
    to: '/dashboard/migration-intelligence',
  },
  {
    id: 'migration-timeline',
    index: 6,
    chapter: 'plan',
    eyebrow: 'Timeline',
    title: 'Migration Operations Center',
    blurb:
      'A single operations screen that answers "are we on track?" for the engineer, the programme manager and the executive sponsor at the same time.',
    value:
      'Programme status stops being a monthly slide assembled by hand. Everyone reads the same live picture, so reviews are about decisions rather than reconciliation.',
    capabilities: [
      'Executive banner with headline programme posture',
      'Wave overview, phase gates and milestone timeline',
      'Risk burndown tracking exposure retired over time',
      'Live telemetry, health dashboard and activity feed',
      'Dependency graph and per-asset progress table',
      'Audit trail and compliance strip for governance reviews',
      'Details drawer and command palette for fast navigation',
    ],
    benefits: ['One live status view', 'No manual reporting', 'Slippage visible early'],
    useCase:
      'The steering committee meets on Thursday. Nobody spends Wednesday building the deck — the timeline is the deck, and it is already current.',
    image: '/downloads/migration-operation.jpg',
    icon: CalendarClock,
    accent: AMBER,
    to: '/dashboard/migration-timeline',
  },

  /* ----------------------------------------------- Chapter III — Execute -- */
  {
    id: 'migration-sandbox',
    index: 7,
    chapter: 'execute',
    eyebrow: 'Sandbox',
    title: 'Migration Sandbox & Digital Twin',
    blurb:
      'Rehearses the entire migration against a metadata-only digital twin of your estate, so you find out what breaks before anything in production moves.',
    value:
      'Removes the single biggest reason PQC programmes stall: fear of an outage. You can prove the change is safe — and prove you can undo it — before asking for the change window.',
    capabilities: [
      'Digital twin simulation — production is never modified',
      'Fifteen-stage pipeline from discovery through production-ready',
      'Compatibility validation across applications and dependencies',
      'Performance benchmarking of post-quantum algorithms',
      'Security, rollback and compliance validation stages',
      'AI risk analysis with migration and rollback confidence',
      'Governed Executive Approval gate before production',
    ],
    benefits: ['Zero production risk', 'Rollback proven first', 'Approval on record'],
    useCase:
      'Before enabling hybrid TLS on a payments gateway, you run it in the twin and discover two legacy clients that cannot handle the larger handshake.',
    image: '/downloads/migration-sandbox.png',
    icon: FlaskConical,
    accent: EMERALD,
    to: '/dashboard/migration-sandbox',
  },
  {
    id: 'live-migration',
    index: 8,
    chapter: 'execute',
    eyebrow: 'Live Migration',
    title: 'Live Migration Operations',
    blurb:
      'Executes approved migrations under real-time control, with a verified snapshot taken before every change and a rollback path that has already been tested.',
    value:
      'Turns the riskiest hour of the programme into a routine, observable operation — with a safety net that is verified rather than assumed.',
    capabilities: [
      'Distributed job orchestration with priority, leasing and back-pressure',
      'Automatic retry, dead-letter handling and node recovery',
      'Pre-migration snapshots with SHA3-256 integrity verification',
      'Automatic and operator-triggered rollback',
      'Live execution logs and real-time progress telemetry',
      'Certification readiness band updating as the migration runs',
    ],
    benefits: ['Verified safety net', 'Real-time control', 'Reversible by design'],
    useCase:
      'A rotation wave fails on one cluster at 2am. The job is dead-lettered, the snapshot restores the prior state automatically, and the rest of the wave continues.',
    image: '/downloads/Live-Migration-Operations.png',
    icon: Rocket,
    accent: ROSE,
    to: '/dashboard/live-migration',
  },

  /* ---------------------------------------------- Chapter IV — Identity --- */
  {
    id: 'pqauth',
    index: 9,
    chapter: 'identity',
    eyebrow: 'PQAuth™',
    title: 'PQAuth™ Identity Migration Engine',
    blurb:
      'A dedicated command centre for the one system you cannot afford to break: authentication. Covers OAuth, OIDC, SAML, JWT, machine identity and API trust.',
    value:
      'Identity is where a botched crypto change locks out every employee and customer at once. This migrates it deliberately, in stages, with a twin and a rollback gate at each one.',
    capabilities: [
      'Identity discovery across providers, signing keys and auth flows',
      'Identity trust fabric for users, machines, APIs and issuers',
      'JWT and token intelligence with post-quantum size-impact planning',
      'Quantum exposure scoring across RSA, ECC, ECDSA, EdDSA and DH',
      'Identity digital twin with failure prediction',
      'Phased migration orchestration with validation and rollback gates',
      'Governance scoring for NIST, CNSA 2.0, PCI-DSS, ISO 27001, SOC 2 and FedRAMP',
    ],
    benefits: ['Login never breaks', 'Token growth planned', 'Machine identity covered'],
    useCase:
      'Larger post-quantum signatures push your JWTs past a gateway header limit. Token intelligence flags it in planning rather than in a Monday morning outage.',
    image: `${MEDIA}/pqauth.webp`,
    icon: Fingerprint,
    accent: VIOLET,
    to: '/dashboard/pqauth',
  },
  {
    id: 'pqauth-compatibility',
    index: 10,
    chapter: 'identity',
    eyebrow: 'Compatibility',
    title: 'PQC Compatibility Assessment',
    blurb:
      'Answers the question that decides your go-live date: what actually breaks if we switch on post-quantum cryptography tomorrow?',
    value:
      'Converts an unknown into a checklist. Every incompatible component is named before the change window instead of being discovered inside it.',
    capabilities: [
      'Six scored surfaces: applications, APIs, mobile apps, gateways and WAFs, service meshes, cloud platforms',
      'Separate readiness scores for ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205)',
      'Blocker count from quantum-vulnerable algorithms and token size limits',
      'Dependency analysis for components that block a cutover',
      'A surface with no evidence reads Not Assessed — it is never scored as if it passed',
    ],
    benefits: ['Cutover date you can defend', 'No surprise blockers', 'Unmeasured stays unmeasured'],
    useCase:
      'Your service mesh supports hybrid key exchange but an older WAF in front of it does not. You learn this in planning, and sequence the WAF upgrade first.',
    image: `${MEDIA}/compatibility.webp`,
    icon: CheckCircle2,
    accent: EMERALD,
    to: '/dashboard/pqauth/compatibility',
  },
  {
    id: 'runtime-identity-telemetry',
    index: 11,
    chapter: 'identity',
    eyebrow: 'Identity Telemetry',
    title: 'Runtime Identity Telemetry',
    blurb:
      'Watches authentication as it actually happens — tokens validated, certificates presented, trust failing — so you know the identity layer is behaving, not just configured.',
    value:
      'Configuration says what should happen. Telemetry says what did. This is the difference between believing a migration succeeded and knowing it.',
    capabilities: [
      'Authentication, authorization, session and token events streamed live over SSE',
      'Token operations and the certificates actually presented at runtime',
      'Trust failures counted from observed downgrades, rejections and validation errors',
      'Identity drift surfaced when shadow or legacy cryptography appears on an identity path',
      'Every tile reads Awaiting Telemetry until real runtime evidence exists',
    ],
    benefits: ['Proof, not assumption', 'Measured, never inferred', 'Post-migration assurance'],
    useCase:
      'A partner silently reverts to an older token signing algorithm. It shows up in the drift tile as a legacy observation rather than waiting for the next annual audit.',
    image: `${MEDIA}/runtime-telemetry.webp`,
    icon: Radio,
    accent: CYAN,
    to: '/dashboard/pqauth/runtime-telemetry',
  },

  /* --------------------------------------------- Chapter V — Ecosystem ---- */
  {
    id: 'vendor-pqc-readiness',
    index: 12,
    chapter: 'ecosystem',
    eyebrow: 'Vendor Readiness',
    title: 'Vendor PQC Readiness Center',
    blurb:
      'Tracks how quantum-ready your suppliers are, what they have committed to contractually, and which of them is now the weakest link in your own posture.',
    value:
      'Your quantum risk includes your vendors’ quantum risk. This makes that inherited exposure visible, comparable and contractually enforceable.',
    capabilities: [
      'Vendor PQC readiness tracking and maturity comparison',
      'Standards alignment per supplier',
      'Contractual obligation and evidence-request management',
      'Migration support status for each vendor',
      'Supply-chain view of quantum-vulnerable dependencies',
      'Nine evidence-request types tracked through a six-stage review workflow',
    ],
    benefits: ['Inherited risk visible', 'Contract leverage', 'Supplier comparison'],
    useCase:
      'Procurement renews a core SaaS contract next quarter. You attach a PQC readiness clause because the readiness centre shows the vendor has no published roadmap.',
    image: '/downloads/vendor-readiness.png',
    icon: BadgeCheck,
    accent: GOLD,
    to: '/dashboard/vendor-pqc-readiness',
  },
  {
    id: 'runtime-crypto-intel',
    index: 13,
    chapter: 'ecosystem',
    eyebrow: 'Runtime Crypto',
    title: 'Runtime Cryptographic Intelligence',
    blurb:
      'Shows the cryptography your systems are running right now — not the cryptography your documentation says they run.',
    value:
      'Most estates contain algorithms nobody remembers deploying. Seeing the cryptographic operations your systems actually perform closes the gap between the architecture diagram and reality.',
    capabilities: [
      'Live cryptographic event stream, scoped to a chosen window from 15 minutes to 30 days',
      'Each observation judged on its risk-bearing primitive, not the cipher-suite name',
      'Findings aggregated per asset and primitive, so one problem seen many times is one finding',
      'Priority weighted by asset criticality and exposure, not severity alone',
      'Post-quantum adoption measured, with a trend claimed only when both windows hold data',
      'Migration verification that will not report success without post-cutover runtime evidence',
      'No runtime evidence publishes no score — never a zero that reads as clean',
    ],
    benefits: ['Reality over documentation', 'Shadow crypto exposed', 'Silence never scored as safe'],
    useCase:
      'A deprecated cipher reappears after a dependency upgrade. The next observation of it lands in the event stream and is ranked against the asset it was seen on.',
    image: '/downloads/runtime1.png',
    icon: Eye,
    accent: ROSE,
    to: '/dashboard/runtime-crypto-intel',
  },
  {
    id: 'trust-state-discovery',
    index: 14,
    chapter: 'ecosystem',
    eyebrow: 'Trust Discovery',
    title: 'Trust-State Discovery',
    blurb:
      'Maps the certificate, PKI and service trust relationships holding your estate together — including the ones no inventory ever recorded.',
    value:
      'Migrations rarely fail on the algorithm. They fail on an undocumented trust path nobody knew existed until it broke.',
    capabilities: [
      'Interactive tiered trust graph, root authority down to cloud resource',
      'Select any subject to see its blast radius — everything a change there would reach',
      'Inferred nodes and edges drawn dashed, so assumed is never mistaken for measured',
      'Trust chains ranked worst-first, with incomplete chains naming the missing tier',
      'Owner and region on every discovered subject, with unassigned ones flagged',
      'Discovery data-quality report naming the table each discrepancy lives in',
    ],
    benefits: ['Hidden trust surfaced', 'Breakage predicted', 'Ownership resolved'],
    useCase:
      'Retiring one internal CA looks routine until the trust graph shows nine services and a partner integration chaining to it.',
    image: '/downloads/Trust.png',
    icon: Link2,
    accent: BLUE,
    to: '/dashboard/trust-state-discovery',
  },

  /* ---------------------------------------------------- Chapter VI — AI --- */
  {
    id: 'sophia',
    index: 15,
    chapter: 'ai',
    eyebrow: 'Sophia AI',
    title: 'Sophia — AI Security Copilot™',
    blurb:
      'Ask about your cryptographic posture in plain English and get an answer grounded in your own live data, with the evidence attached.',
    value:
      'Expertise stops being a bottleneck. A compliance lead can ask the same question a cryptographer would, and get an answer they can act on and cite.',
    capabilities: [
      'Streaming answers grounded in your live tenant data',
      'Deterministic by design — every answer is assembled from tool runs over your own records, not generated by a language model, so it cannot hallucinate a metric',
      'Evidence citations on every finding it reports',
      'Proactive insights surfaced before you ask',
      'Page-aware suggested questions as you work',
      'Strict tenant isolation and role-based access control',
      'Human-in-the-loop approval before any action is taken',
      'Conversation history, pinning, search and export',
    ],
    benefits: ['Plain-English answers', 'Cannot invent a number', 'Never acts unsupervised'],
    useCase:
      '"Which internet-facing systems still use RSA and who owns them?" — answered in seconds, with the asset list and evidence behind it.',
    image: '/downloads/Sophia-AI_Agent_Security_Copilot.png',
    icon: Sparkles,
    accent: VIOLET,
    to: '/dashboard/sophia',
  },
];

const CHAPTERS: Array<{
  key: string;
  number: string;
  title: string;
  body: string;
  color: string;
}> = [
  {
    key: 'assess',
    number: 'I',
    title: 'Know exactly where you stand',
    body: 'Before anything can be migrated it has to be measured. These modules turn cryptographic reality into a score, a prioritised fix list and a certificate you can show to anyone.',
    color: CYAN,
  },
  {
    key: 'plan',
    number: 'II',
    title: 'Build a plan leadership will fund',
    body: 'A roadmap is only useful if it survives contact with budget, dependencies and ownership. These modules produce one that does — and keep it honest as the programme runs.',
    color: VIOLET,
  },
  {
    key: 'execute',
    number: 'III',
    title: 'Migrate without holding your breath',
    body: 'Rehearse against a digital twin, prove the rollback works, then execute under real-time control with a verified snapshot behind every change.',
    color: EMERALD,
  },
  {
    key: 'identity',
    number: 'IV',
    title: 'Protect the system everything depends on',
    body: 'Authentication touches every user, service and partner you have. PQAuth™ migrates it deliberately and then watches it in the runtime to confirm it worked.',
    color: AMBER,
  },
  {
    key: 'ecosystem',
    number: 'V',
    title: 'See past your own perimeter',
    body: 'Your posture includes your suppliers, your live runtime and the trust relationships nobody documented. These modules make all three visible.',
    color: GOLD,
  },
  {
    key: 'ai',
    number: 'VI',
    title: 'Put an expert on every screen',
    body: 'Sophia turns the whole platform into something anyone on the team can interrogate — in plain language, with the evidence attached.',
    color: ROSE,
  },
];

/* --------------------------------------------------------------- benefits -- */

const BENEFITS: Array<{ icon: LucideIcon; title: string; body: string; color: string }> = [
  {
    icon: Rocket,
    title: 'Accelerate your migration',
    body: 'Discovery, planning, simulation and execution live in one platform, so work moves forward instead of waiting on the next handover.',
    color: CYAN,
  },
  {
    icon: ShieldCheck,
    title: 'Reduce cryptographic risk',
    body: 'Weak and quantum-vulnerable cryptography is found, ranked and retired in the order that removes the most exposure first.',
    color: EMERALD,
  },
  {
    icon: Eye,
    title: 'See everything you run',
    body: 'A complete, continuously updated picture of the certificates, keys and algorithms actually in use — including the ones nobody documented.',
    color: BLUE,
  },
  {
    icon: Scale,
    title: 'Be ready for the audit',
    body: 'Findings map to recognised standards and every status links back to the evidence that supports it, so audits become a retrieval exercise.',
    color: GOLD,
  },
  {
    icon: Layers,
    title: 'Automate the assessment',
    body: 'Scoring, prioritisation and reporting run continuously rather than as a consulting engagement you repeat once a year.',
    color: VIOLET,
  },
  {
    icon: Activity,
    title: 'Monitor posture continuously',
    body: 'Live telemetry shows drift the moment cryptography changes, instead of at the next scheduled review.',
    color: ROSE,
  },
  {
    icon: Target,
    title: 'Fix what matters first',
    body: 'Risk-ranked queues and quick-win filters put the highest-value work at the top, so limited engineering time buys the most reduction.',
    color: AMBER,
  },
  {
    icon: FileBarChart,
    title: 'Report to the board in minutes',
    body: 'Executive dashboards and exportable reports translate cryptographic detail into business language without manual reformatting.',
    color: CYAN,
  },
  {
    icon: BrainCircuit,
    title: 'Decide with evidence, fast',
    body: 'Sophia answers posture questions in plain English from your own records and always shows the evidence behind the answer, so decisions are informed rather than intuitive.',
    color: VIOLET,
  },
  {
    icon: Compass,
    title: 'Stay ready for what comes next',
    body: 'Crypto-agility is built in, so the next algorithm change is a planned operation rather than another multi-year programme.',
    color: EMERALD,
  },
];

/* ------------------------------------------------------------ comparison -- */

const SHIFT_ROWS: ShiftRow[] = [
  {
    dimension: 'Cryptographic inventory',
    before: 'Spreadsheets assembled by hand, out of date the week they are finished.',
    after: 'Continuously discovered inventory that updates itself as systems change.',
  },
  {
    dimension: 'Risk prioritisation',
    before: 'Everything marked critical, so nothing is genuinely prioritised.',
    after: 'Ranked by exposure actually removed, with quick wins surfaced separately.',
  },
  {
    dimension: 'Ownership',
    before: 'Weeks lost working findings that belong to a cloud provider or vendor.',
    after: 'Customer, provider and ecosystem responsibility separated up front.',
  },
  {
    dimension: 'Migration confidence',
    before: 'Change windows approached on hope, with rollback improvised.',
    after: 'Rehearsed against a digital twin, with rollback proven before approval.',
  },
  {
    dimension: 'Executive reporting',
    before: 'A slide deck rebuilt by hand before every steering committee.',
    after: 'A live dashboard and one-click export that are already current.',
  },
  {
    dimension: 'Proof for third parties',
    before: 'Assertions in a questionnaire that nobody can independently check.',
    after: 'A signed certificate any third party can verify for themselves.',
  },
];

/* ----------------------------------------------------------------- page ---- */

/** Minimal per-page SEO: title, description, canonical and Open Graph tags. */
function usePageMeta() {
  React.useEffect(() => {
    const previousTitle = document.title;
    document.title =
      'QGuard Helix Features — Post-Quantum Discovery, Migration & Governance Platform';

    const description =
      'Explore the QGuard Helix platform: quantum readiness assessment, remediation, certification, migration planning, digital-twin simulation, live migration, PQAuth identity migration, vendor readiness, runtime cryptographic intelligence and the Sophia AI Security Copilot.';

    const created: HTMLElement[] = [];
    const setTag = (selector: string, create: () => HTMLElement, apply: (el: HTMLElement) => void) => {
      let el = document.head.querySelector<HTMLElement>(selector);
      if (!el) {
        el = create();
        document.head.appendChild(el);
        created.push(el);
      }
      apply(el);
    };

    setTag(
      'meta[name="description"]',
      () => Object.assign(document.createElement('meta'), { name: 'description' }),
      (el) => el.setAttribute('content', description),
    );
    setTag(
      'link[rel="canonical"]',
      () => Object.assign(document.createElement('link'), { rel: 'canonical' }),
      (el) => el.setAttribute('href', `${window.location.origin}/qguard-helix-features`),
    );
    ([
      ['og:title', 'QGuard Helix Features'],
      ['og:description', description],
      ['og:type', 'website'],
      ['og:image', `${window.location.origin}${MEDIA}/hero-poster.webp`],
    ] as const).forEach(([property, content]) => {
      setTag(
        `meta[property="${property}"]`,
        () => {
          const meta = document.createElement('meta');
          meta.setAttribute('property', property);
          return meta;
        },
        (el) => el.setAttribute('content', content),
      );
    });

    return () => {
      document.title = previousTitle;
      created.forEach((el) => el.remove());
    };
  }, []);
}

export default function QguardHelixFeatures() {
  usePageMeta();

  return (
    <SolutionLayout
      homePath="/qguard-helix-features"
      brandTitle="QGuard Helix"
      brandSubtitle="Platform Features"
      brandTagline="Quantum Cyber Defense"
      navLinks={NAV_LINKS}
      footerBlurb={
        <>
          QGuard Helix discovers cryptographic assets, measures quantum exposure, plans and rehearses
          post-quantum migration, executes it with verified rollback, and holds the signed evidence
          your auditors and customers ask for &mdash; built on the NIST post-quantum standards
          (FIPS&nbsp;203/204/205).
        </>
      }
      footerGroups={FOOTER_GROUPS}
    >
      {/* ============================================================ hero == */}
      <FeaturesBookHero modules={MODULES} />

      {/* ====================================================== lifecycle == */}
      <section id="lifecycle" className="mx-auto max-w-[96rem] scroll-mt-28 px-4 py-20 sm:px-6">
        <SectionHeading
          kicker="How the platform works"
          title={
            <>
              One <Highlight>continuous lifecycle</Highlight>, not fifteen disconnected tools
            </>
          }
          subtitle="Every module plugs into the same loop and shares the same evidence, so a finding discovered by the scanner is the same finding your board report, your migration plan and your certificate all refer to."
        />
        <div className="mt-14">
          <LifecycleRail stages={LIFECYCLE} />
        </div>
        <Reveal delay={0.2}>
          <div className="mt-14">
            <TrustStrip items={TRUST_ITEMS} />
          </div>
        </Reveal>
      </section>

      {/* ======================================================== modules == */}
      <div id="modules" className="scroll-mt-16">
        <ModuleNavigator modules={MODULES} />
      </div>

      <section className="mx-auto max-w-[96rem] px-4 pb-10 pt-16 sm:px-6">
        <SectionHeading
          kicker="Platform capabilities"
          title={
            <>
              Fifteen modules. <Highlight>One coherent programme.</Highlight>
            </>
          }
          subtitle="Each module answers a specific question a real team gets stuck on — and hands its answer to the next module rather than to a spreadsheet."
        />
      </section>

      {CHAPTERS.map((chapter) => {
        const modules = MODULES.filter((m) => m.chapter === chapter.key);
        return (
          <section key={chapter.key} className="mx-auto max-w-[96rem] px-4 py-12 sm:px-6">
            <ChapterMarker
              number={chapter.number}
              title={chapter.title}
              body={chapter.body}
              color={chapter.color}
            />
            <div className="mt-12 space-y-8">
              {modules.map((module) => (
                <ModuleShowcase key={module.id} module={module} />
              ))}
            </div>
          </section>
        );
      })}

      {/* ======================================================= benefits == */}
      <section id="benefits" className="relative scroll-mt-28 py-20">
        <div className="mx-auto max-w-[96rem] px-4 sm:px-6">
          <SectionHeading
            kicker="Why organisations choose QGuard Helix"
            title={
              <>
                What this actually <Highlight>changes for you</Highlight>
              </>
            }
            subtitle="In plain terms — no cryptography background required."
          />

          <div className="mt-14 grid gap-5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
            {BENEFITS.map((benefit, i) => (
              <BenefitCard
                key={benefit.title}
                icon={benefit.icon}
                title={benefit.title}
                body={benefit.body}
                color={benefit.color}
                delay={(i % 5) * 0.06}
              />
            ))}
          </div>

          <Reveal delay={0.15}>
            <GlassCard className="mt-12 grid items-center gap-8 overflow-hidden p-0 lg:grid-cols-[1.15fr_1fr]" hover={false}>
              <div className="p-8 sm:p-10">
                <span className="inline-flex items-center gap-2 rounded-full border border-cyan-200 bg-cyan-50 px-3 py-1 font-mono text-[10px] font-bold uppercase tracking-[0.2em] text-cyan-700">
                  <Radar className="h-3.5 w-3.5" /> The deadline is already set
                </span>
                <h3 className="mt-4 text-2xl font-black tracking-tight text-slate-900 sm:text-3xl">
                  Data stolen today can be decrypted later
                </h3>
                <p className="mt-3 text-[15px] leading-relaxed text-slate-600">
                  Encrypted traffic captured now can be stored until a quantum computer is capable of
                  breaking it &mdash; the &ldquo;harvest now, decrypt later&rdquo; problem. Anything
                  with a long confidentiality life, from medical records to contracts to source code,
                  is already exposed. NIST&rsquo;s published timeline deprecates RSA and elliptic-curve
                  cryptography by 2030 and disallows them by 2035, and large estates take years to move.
                </p>
                <p className="mt-3 text-[15px] font-semibold leading-relaxed text-slate-800">
                  QGuard Helix exists to make those years manageable: measure the exposure, sequence the
                  work, rehearse the risk, and prove the result.
                </p>
                <div className="mt-6 flex flex-wrap gap-3">
                  <DarkButton to="/public-scan">Run a free public scan</DarkButton>
                  <GhostButton to="/pqc-solutions">See the problems we solve</GhostButton>
                </div>
              </div>
              <div className="relative h-full min-h-[260px] bg-[#050b16]">
                <div className="absolute inset-x-0 top-0 z-10 h-[3px] bg-gradient-to-r from-cyan-400 via-[#d4af37] to-violet-500" />
                <img
                  src={`${MEDIA}/benefits-shield.webp`}
                  alt="Quantum-safe protection assembling around a global network"
                  loading="lazy"
                  decoding="async"
                  className="h-full w-full object-cover"
                />
              </div>
            </GlassCard>
          </Reveal>
        </div>
      </section>

      {/* ======================================================== compare == */}
      <section id="compare" className="mx-auto max-w-[96rem] scroll-mt-28 px-4 py-20 sm:px-6">
        <SectionHeading
          kicker="Before and after"
          title={
            <>
              The same programme, run <Highlight>two very different ways</Highlight>
            </>
          }
          subtitle="Most organisations already have a post-quantum initiative. The difference is whether it runs on evidence or on effort."
        />
        <div className="mt-12">
          <ShiftPanel rows={SHIFT_ROWS} />
        </div>
      </section>

      {/* ============================================================ cta == */}
      <FinalCTA
        image={`${MEDIA}/cta-horizon.webp`}
        title={
          <>
            Find out where you stand.
            <br />
            It takes about a minute.
          </>
        }
        body="Start with a free public assessment of an internet-facing endpoint, or explore the full platform with your own data. No agent to install to get your first result."
        actions={[
          { label: 'Start free assessment', to: '/public-scan', tone: 'primary' },
          { label: 'Explore the platform', to: '/dashboard/quantum-readiness', tone: 'gold' },
          { label: 'View pricing', href: '/#pricing', tone: 'ghost' },
          { label: 'Talk to us', href: '/docs', tone: 'ghost' },
        ]}
      />

      {/* Structured data for search engines. */}
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: JSON.stringify({
            '@context': 'https://schema.org',
            '@type': 'SoftwareApplication',
            name: 'QGuard Helix',
            applicationCategory: 'SecurityApplication',
            description:
              'Enterprise post-quantum cryptography discovery, migration, governance and crypto-agility platform.',
            featureList: MODULES.map((m) => m.title),
          }),
        }}
      />
    </SolutionLayout>
  );
}
