export const chapters = [
  [0, 'Quantum risk'],
  [15, 'Discovery'],
  [30, 'The platform'],
  [43, 'Readiness intelligence'],
  [63, 'Migration planning'],
  [82, 'Validation and operations'],
  [103, 'Crypto agility'],
  [123, 'Identity and trust'],
  [143, 'Monitoring and governance'],
  [161, 'Brand finale'],
] as const;

type Shot = {
  at: number;
  chapter: number;
  label: string;
  title: string[];
  copy?: string;
  tags?: string[];
  theme?: 'ice' | 'iris' | 'ember' | 'silver';
  visual?: 'earth' | 'lab' | 'processor' | 'network' | 'exposure' | 'migration' | 'agility' | 'suite' | 'standard' | 'finale';
  image?: string;
  screen?: 'platform' | 'assessment' | 'plan' | 'sandbox' | 'runtime';
  columns?: { name: string; items: string[] }[];
};

export const shots: Shot[] = [
  { at: 0, chapter: 0, label: 'The quantum transition', title: ['A new era of', 'cryptographic risk.'],
    copy: 'The security of long-lived data is already a planning decision.', visual: 'earth' },
  { at: 7.5, chapter: 0, label: 'Risk to public-key cryptography', title: ['Harvest now.', 'Decrypt later.'],
    copy: 'Encrypted traffic collected today could be targeted for decryption in the future.', visual: 'exposure', theme: 'ember' },
  { at: 15, chapter: 1, label: 'The enterprise blind spot', title: ['Where does your', 'cryptography live?'],
    visual: 'lab', tags: ['Applications & APIs', 'Cloud & Kubernetes', 'Endpoints & workloads'] },
  { at: 22.25, chapter: 1, label: 'Discovery and inventory', title: ['Trace what', 'protects your estate.'],
    visual: 'network', tags: ['PQC Scanner & Public Scan', 'Agents Collector & live scanning', 'TLS · SSH · VPN · certificates'] },
  { at: 30, chapter: 2, label: 'Enterprise post-quantum security', title: ['Introducing', 'QGUARD HELIX.'],
    copy: 'One platform for the cryptographic lifecycle.', screen: 'platform', theme: 'ice' },
  { at: 36.5, chapter: 2, label: 'One integrated platform', title: ['From first discovery', 'to ongoing oversight.'],
    visual: 'suite', theme: 'iris', tags: ['Discover', 'Assess', 'Plan', 'Migrate', 'Validate', 'Monitor', 'Govern'] },
  { at: 43, chapter: 3, label: 'Quantum Readiness Assessment Engine', title: ['See your', 'quantum exposure.'],
    copy: 'Map dependencies, investigate risk, and prioritize exposure.', screen: 'assessment',
    tags: ['QRAE', 'Quantum Exposure Graph'] },
  { at: 50, chapter: 3, label: 'Cryptographic inventory', title: ['Know what', 'your systems use.'],
    image: 'inventory.webp', tags: ['Assets & CBOM', 'CBOM Explorer', 'Shadow Crypto'], theme: 'silver' },
  { at: 56.5, chapter: 3, label: 'Quantum risk intelligence', title: ['Make the', 'risk visible.'],
    visual: 'network', theme: 'iris', tags: ['HNDL exposure', 'Risk analysis & prioritization', 'Executive readiness reports'] },
  { at: 63, chapter: 4, label: 'PQC Migration Planner', title: ['Give change', 'a clear sequence.'],
    copy: 'Build phased roadmaps around criticality, ownership, and dependencies.', screen: 'plan',
    tags: ['Migration Timeline', 'Dependency Analysis'], theme: 'ice' },
  { at: 69.5, chapter: 4, label: 'Migration intelligence', title: ['Decide what', 'moves first.'],
    visual: 'migration', tags: ['Estate Remediation Intelligence', 'Quantum Remediation', 'Readiness & remediation priorities'] },
  { at: 76, chapter: 4, label: 'Delivery planning', title: ['Make the work', 'accountable.'],
    image: 'roadmap.webp', theme: 'iris', tags: ['Ownership & migration waves', 'Review gates', 'Migration reporting'] },
  { at: 82, chapter: 5, label: 'Migration Sandbox & Digital Twin', title: ['Test before', 'production.'],
    copy: 'Simulate proposed changes and review how dependencies respond.', screen: 'sandbox', tags: ['Modeled outcomes', 'Controlled validation'] },
  { at: 89, chapter: 5, label: 'Hybrid Crypto Compatibility Lab', title: ['Prove what works', 'in the lab.'],
    visual: 'processor', theme: 'iris', tags: ['Quantum Simulation Range', 'Compatibility & interoperability', 'Performance'] },
  { at: 96, chapter: 5, label: 'PQC & TLS Orchestration', title: ['Move with', 'control.'],
    visual: 'migration', tags: ['Human approval & preflight', 'Live Migration Ops', 'Post-change validation & rollback'] },
  { at: 103, chapter: 6, label: 'Crypto Agility Engine', title: ['Designed for', 'change.'],
    copy: 'Evaluate hybrid configurations and plan cryptographic algorithm changes.', visual: 'agility', theme: 'ice' },
  { at: 109.75, chapter: 6, label: 'Standards & lab coverage', title: ['Prepare for', 'standardized PQC.'],
    visual: 'standard', theme: 'silver' },
  { at: 116.5, chapter: 6, label: 'Quantum Key Management System', title: ['Know your keys.', 'Govern their lifecycle.'],
    image: 'agility.webp', theme: 'iris', tags: ['Key inventory & rotation planning', 'Certificate & PKI visibility', 'Policy & lifecycle oversight'] },
  { at: 123, chapter: 7, label: 'Quantum Trust Fabric', title: ['See the trust', 'between systems.'],
    visual: 'network', tags: ['Trust-State Discovery', 'Trust Chain Analyzer', 'Zero Trust validation'], theme: 'ice' },
  { at: 129.5, chapter: 7, label: 'PQAuth Identity Migration', title: ['Prepare identity', 'for change.'],
    image: 'identity.webp', theme: 'iris', tags: ['Identity Discovery & Trust Graph', 'JWT & Token Intelligence', 'Identity Digital Twin & runtime telemetry'] },
  { at: 136.25, chapter: 7, label: 'Ecosystem dependencies', title: ['Extend visibility', 'beyond your estate.'],
    image: 'trust.webp', theme: 'silver', tags: ['Vendor readiness', 'Workload & service trust', 'Dependency evidence'] },
  { at: 143, chapter: 8, label: 'Continuous cryptographic intelligence', title: ['See the changes', 'as you operate.'],
    screen: 'runtime', tags: ['Runtime Crypto Intelligence', 'Telemetry correlation & drift', 'TLS · PKI · protocol · multi-cloud'] },
  { at: 149, chapter: 8, label: 'Quantum Governance', title: ['Make decisions', 'traceable.'],
    visual: 'suite', tags: ['Crypto policy & Compliance Center', 'Audit Vault & Regulatory Mapping', 'Report Center & evidence review'], theme: 'silver' },
  { at: 155, chapter: 8, label: 'Insights and supporting tools', title: ['Put the evidence', 'to work.'],
    theme: 'iris', columns: [
      { name: 'Sophia AI', items: ['Ask questions across linked evidence', 'Executive & migration advisors'] },
      { name: 'Security & readiness', items: ['Quantum Vault & encryption services', 'Authentication, messaging & cloud security', 'Quantum Trust readiness program'] },
    ] },
  { at: 161, chapter: 9, label: 'The future of enterprise cybersecurity', title: ['The quantum threat', 'is approaching.'],
    copy: 'Your organization needs a plan.', visual: 'finale' },
];
