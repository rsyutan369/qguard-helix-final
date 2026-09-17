export interface DecryptedFile {
  name: string;
  filename: string;
  size: string;
  tag: string;
  tagColor: string;
}

export interface ScenarioStepInfo {
  name: string;
  desc: string;
  objective: string;
}

export interface Scenario {
  id: string;
  name: string;
  shortName: string;
  category: string;
  objectiveText: string;
  narrative: string;
  impactText: string;
  impactBullets: string[];
  targets: string[];
  nodeNames: {
    client: string;
    gateway: string;
    server: string;
    vault: string;
  };
  steps: Record<number, ScenarioStepInfo>;
  decryptedFiles: DecryptedFile[];
  pulseColors: {
    breached: string;
    safe: string;
  };
  metrics: {
    basePackets: number;
    baseSizeGB: number;
    captureRate: number;
    riskLevel: 'Low' | 'Medium' | 'High';
  };
}

export const SCENARIOS: Scenario[] = [
  {
    id: "hndl",
    name: "Harvest Now, Decrypt Later (HNDL)",
    shortName: "HNDL (Harvest Now Decrypt Later)",
    category: "Retroactive Attack",
    objectiveText: "Silently harvest and archive high-value encrypted enterprise transit data until cryptographically relevant quantum computers (CRQC) allow retroactive decryption.",
    narrative: "Adversaries intercept standard TLS/VPN tunnels. Unbreakable today, this data is cached in massive automated warehousing grids, anticipating full decryption on Q-Day.",
    impactText: "Long-term data exposure resulting in complete intellectual property exploitation decades over the lifecycle.",
    impactBullets: [
      "Irreversible exposure of deep military, executive, or technical secrets",
      "Total compliance, liability, and regulatory failure (HIPAA / GDPR)",
      "Loss of competitive intelligence and core business blueprints"
    ],
    targets: ["G7 SWIFT Server", "Military Core", "Global Cloud Vault"],
    nodeNames: {
      client: "Enterprise Terminal",
      gateway: "WAN Core Fiber Proxy",
      server: "Target Secure Server",
      vault: "Qguard Offline Storage"
    },
    metrics: { basePackets: 12458, baseSizeGB: 2.45, captureRate: 1.85, riskLevel: "Low" },
    pulseColors: { breached: "#f43f5e", safe: "#06b6d4" },
    steps: {
      1: { name: "LEGACY INTERCEPT", desc: "Passively mirror optical fiber routes targeting legacy TLS packets.", objective: "Capture bulk asymmetrical signatures without triggering IDS thresholds." },
      2: { name: "SECURE ARCHIVING", desc: "Commit captured sessions to high-density cold warehousing environments.", objective: "Index packet frames by organization name & security parameters." },
      3: { name: "QUANTUM COMPILING", desc: "Synthesize Shor's prime factoring loops against archived keys.", objective: "Prepare modulus factor registers on simulating Shor cores." },
      4: { name: "RECOVERY OF PLAINTEXT", desc: "Factorize RSA-2048 private exponents, revealing session keys.", objective: "Extract raw, unencrypted packet flows from HNDL buffer silos." },
      5: { name: "RETROACTIVE ANALYSIS", desc: "Perform deep-packet structural search of newly unencrypted databases.", objective: "Expose intellectual property, source files, and classified documents." },
      6: { name: "DEPLOY SHIELD DEFENSE", desc: "Initialize ML-KEM post-quantum key encapsulation tunnels.", objective: "Implement NIST FIPS 203 standards to immunize records against HNDL." }
    },
    decryptedFiles: [
      { name: "Executive Diplomatic Cables", filename: "DIPLOMATIC_CABLES_SPECIMEN.tar", size: "7.8 GB", tag: "TOP SECRET", tagColor: "bg-red-500/15 text-red-400 border-red-500/20" },
      { name: "Billion-Dollar Patent Blueprints", filename: "IP_PATENT_SOLID_FUEL_CHEM.zip", size: "14.2 GB", tag: "TS//SCI", tagColor: "bg-rose-500/15 text-rose-400 border-rose-500/20" },
      { name: "Enterprise Customer Identity DB", filename: "IDENT_PROFILES_HASH_ALL.sql", size: "6.1 GB", tag: "CUI", tagColor: "bg-amber-500/10 text-amber-400 border-amber-500/20" }
    ]
  },
  {
    id: "rsa-breaking",
    name: "Quantum RSA/ECC Key Breaking",
    shortName: "RSA/ECC Key Cracking",
    category: "Shor's Algorithm Integration",
    objectiveText: "Demonstrate Shor's Algorithm running on a full-scale quantum model to actively disintegrate RSA-2048 and Elliptic Curve Cryptography.",
    narrative: "An active attack vector using modular-arithmetic period finding on a cryptographically relevant quantum computer, reducing the difficulty of factoring a composite modulus from sub-exponential (the General Number Field Sieve) to polynomial time.",
    impactText: "Complete compromise of all asymmetric trust layers, collapsing CAs, digital signatures, and public keys.",
    impactBullets: [
      "Total failure of standard public-private key infrastructure",
      "Immediate ability to forge software update signatures and admin certificates",
      "Expose all legacy Secure Shell (SSH) and VPN endpoints globally"
    ],
    targets: ["Cert Authority Core", "SSH Root Gateway", "Asymmetric Key Vault"],
    nodeNames: {
      client: "SSH Remote Operator",
      gateway: "Quantum Decrypt Engine",
      server: "Certificate Server",
      vault: "Decrypted Key Repository"
    },
    metrics: { basePackets: 28490, baseSizeGB: 0.12, captureRate: 4.5, riskLevel: "High" },
    pulseColors: { breached: "#ef4444", safe: "#a855f7" },
    steps: {
      1: { name: "MODULUS SELECTION", desc: "Identify active SSH/TLS public certificates on host databases.", objective: "Retrieve public modulus N, public exponent e elements." },
      2: { name: "QUBIT INITIALIZATION", desc: "Configure high-coherence physical qubits into quantum registers.", objective: "Prepare superconducting elements to support factoring matrices." },
      3: { name: "SHOR CORE EXECUTION", desc: "Launch Quantum Fourier Transform period-finding operations.", objective: "Solve modular period r of the function f(x) = a^x mod N." },
      4: { name: "KEYS COLLAPSE", desc: "Reconstruct private prime factors p and q from solved period.", objective: "Solve Euler's totient function to derive the private key d." },
      5: { name: "ROOT ASSUMPTION", desc: "Forge administrative digital signatures using decrypted CA certs.", objective: "Gain root-level system execution access across public subnets." },
      6: { name: "PQC SIGNATURE ROTATION", desc: "Deploy lattice-based ML-DSA and Falcon digital signatures.", objective: "Upgrade private key chains to secure quantum-resistant standard algorithms." }
    },
    decryptedFiles: [
      { name: "CA Master Root Private Key File", filename: "GLOBAL_CA_ROOT_ST_2048.key", size: "2 KB", tag: "ROOT DECRYPT", tagColor: "bg-red-500/25 text-red-300 border-red-500/30" },
      { name: "SSH Master Cluster Keys", filename: "INFRA_CLUSTER_ADMINS_id_rsa.zip", size: "440 MB", tag: "TOP SECRET", tagColor: "bg-rose-500/20 text-rose-300 border-rose-500/20" },
      { name: "Admin Token Keys", filename: "AWS_IAM_SIGNING_RSA_KEY.pem", size: "1.2 MB", tag: "EXPOSED", tagColor: "bg-amber-500/15 text-amber-400 border-amber-500/20" }
    ]
  },
  {
    id: "tls-compromise",
    name: "TLS / HTTPS Quantum Compromise",
    shortName: "TLS/HTTPS Session Intercept",
    category: "Man-In-The-Middle (MITM)",
    objectiveText: "Record browser-to-server TLS handshakes in bulk and solve their key agreements once a CRQC exists, stripping archived HTTPS sessions down to plaintext.",
    narrative: "Public-key handshakes are recorded in bulk and the key agreement behind each is solved afterwards. Published resource estimates put one RSA-2048 solve at roughly 8 hours on a 20-million-qubit machine, so this is retroactive decryption of stored sessions, not a real-time man-in-the-middle.",
    impactText: "Direct exploitation of active human internet traffic, leaking corporate bank accounts and administrative credentials.",
    impactBullets: [
      "Real-time decryption of e-banking and operational administration data",
      "Injection of malicious code blocks straight into active browser sessions",
      "Complete visual compromise of supposedly secure green-lock portals"
    ],
    targets: ["E-Banking Portal", "Enterprise SaaS Core", "Gov Portal Gateway"],
    nodeNames: {
      client: "Active Browser User",
      gateway: "Quantum MITM Proxy",
      server: "HTTPS Server Cluster",
      vault: "Session Token Harvester"
    },
    metrics: { basePackets: 45209, baseSizeGB: 8.75, captureRate: 3.20, riskLevel: "High" },
    pulseColors: { breached: "#f43f5e", safe: "#22c55e" },
    steps: {
      1: { name: "ARP ROUTING MANIPULATION", desc: "Hijack network route headers to pipe client packets through interceptor.", objective: "Route target traffic patterns through the local Quantum gateway." },
      2: { name: "HANDSHAKE CAPTURE", desc: "Harvest ClientHello and ServerHello ephemeral key exchange agreements.", objective: "Isolate legacy DH / ECDH exchange parameters instantly." },
      3: { name: "Q-FOURIER SPINNING", desc: "Spin modular log solvers to solve elliptic curve discretes.", objective: "Reverse Diffie-Hellman secrets using quantum algorithms." },
      4: { name: "SESSION KEY EXTRACTION", desc: "Verify symmetric AES keys generated by compromised parameters.", objective: "Plainstream the HTTPS session without connection disruption." },
      5: { name: "PLAINSTREAM INFILTRATION", desc: "Extract session cookie arrays, active passwords, and admin forms.", objective: "Expose real-time customer and SaaS operational logins." },
      6: { name: "DEPLOY HYBRID KEM", desc: "Implement hybrid X25519 + ML-KEM TLS handshake filters.", objective: "Establish quantum resistance keys on internet browsers and servers." }
    },
    decryptedFiles: [
      { name: "Active SaaS Auth Cookie Pool", filename: "SAAS_SESSION_COOKIES_EXPORT.json", size: "44 MB", tag: "LIVE ACTIONS", tagColor: "bg-red-500/15 text-red-400 border-red-500/20" },
      { name: "Bank Login Plaintext Stream", filename: "CORP_WIRE_TRANSF_POST.log", size: "128 MB", tag: "CRITICAL", tagColor: "bg-rose-500/20 text-rose-300 border-rose-500/20" },
      { name: "Government Portal Credentials", filename: "SECURE_GOV_ADMIN_LOGINS.csv", size: "3.5 MB", tag: "HIGH HAZARD", tagColor: "bg-amber-500/15 text-amber-400 border-amber-500/20" }
    ]
  },
  {
    id: "swift-financial",
    name: "SWIFT / Financial System Decryption",
    shortName: "SWIFT Financial Intercept",
    category: "Financial Sector",
    objectiveText: "Target high-density SWIFT alliance routers using quantum mathematics to decrypt trans-national payment requests.",
    narrative: "An economic warfare vector. Attackers compromise key pipelines linking central banks, enabling retroactive or active interception of SWIFT payment scripts.",
    impactText: "Catastrophic systemic disruption of the G7 banking systems, creating mass asset losses.",
    impactBullets: [
      "Manipulation of large-value automated clearing house (ACH) transfer blocks",
      "Expose G7 settlement files, sovereign balance books & treasury allocations",
      "Total crash of global trust, locking commercial exchange networks indefinitely"
    ],
    targets: ["SWIFT Alliance Router", "Sovereign Treasury Network", "Central Bank Vault"],
    nodeNames: {
      client: "Clearing Terminal",
      gateway: "Intercept SWIFT Gateway",
      server: "SWIFT Central Hub",
      vault: "Compromised Asset Silo"
    },
    metrics: { basePackets: 89045, baseSizeGB: 41.2, captureRate: 6.8, riskLevel: "High" },
    pulseColors: { breached: "#e11d48", safe: "#eab308" },
    steps: {
      1: { name: "WIRE LOG SINKING", desc: "Hook raw communications linking central banks and SWIFT gateways.", objective: "Exfiltrate encrypted interbank ISO-20022 wire buffers." },
      2: { name: "MESSAGE SEGMENTATION", desc: "Isolate high-value financial transaction segments from index queues.", objective: "Filter records expressing transaction values above $10M." },
      3: { name: "SHOR COMPILING", desc: "Apply Shor's mathematical algorithms on factoring SWIFT RSA modulus keys.", objective: "Compute prime factors of financial institution validation keys." },
      4: { name: "TRANSACTION INTRUSION", desc: "Extract master signing keys and decrypt transaction validation numbers.", objective: "Render SWIFT messaging payloads readable as plaintext." },
      5: { name: "ECONOMIC MANIPULATION", desc: "Model fraudulent bank routing patterns and falsify account balances.", objective: "Expose central treasury ledger states and private wealth accounts." },
      6: { name: "DEPLOY QUARD SHIELD", desc: "Implement Kyber + Dilithium secured ISO financial messaging.", objective: "Enforce complete quantum-grade financial security loops." }
    },
    decryptedFiles: [
      { name: "SWIFT ISO-20022 Interbank Wire Log", filename: "G7_SWIFT_TRANSF_2025.csv", size: "9.1 GB", tag: "FINANCIAL", tagColor: "bg-red-500/15 text-red-100 border-red-500/20" },
      { name: "Sovereign Bond Allocation Table", filename: "SOVEREIGN_RESERVES_G7.xls", size: "1.4 GB", tag: "SECRET", tagColor: "bg-rose-500/20 text-rose-300 border-rose-500/20" },
      { name: "Central Bank Transfer Tickets", filename: "FEDWIRE_SWIFT_SEC_PACKETS.bin", size: "14.5 GB", tag: "CRITICAL", tagColor: "bg-amber-500/15 text-amber-400 border-amber-500/20" }
    ]
  },
  {
    id: "infra-scada",
    name: "Critical Infrastructure / OT Quantum Attack",
    shortName: "Infrastructure SCADA Attack",
    category: "Operational Technology (OT)",
    objectiveText: "Simulate a state-sponsored quantum take-over of Operational Technology (OT) networks controlling smart grids, oil lines, and SCADA safety monitors.",
    narrative: "Recovering the asymmetric keys behind administrative PLC signing lets an adversary forge authenticated command packets to turbine nodes and water controllers. The keys are recovered, not the ciphertext decrypted — forgery, not disclosure, is the failure here.",
    impactText: "Immediate physical shutdown of national resources, triggering mechanical damage and blackouts.",
    impactBullets: [
      "Physical loss of turbine grid control and generator safety locks",
      "Override threshold logs on regional water treatments and energy networks",
      "Total telemetry blindness resulting in massive structural hazards"
    ],
    targets: ["SCADA Main Terminal", "Regional Power Substation", "Smart Grid OT Vault"],
    nodeNames: {
      client: "SCADA Control Desk",
      gateway: "Quantum OT Injector",
      server: "PLC SCADA Controller",
      vault: "Control Commands Silo"
    },
    metrics: { basePackets: 65123, baseSizeGB: 18.3, captureRate: 2.10, riskLevel: "High" },
    pulseColors: { breached: "#ea580c", safe: "#3b82f6" },
    steps: {
      1: { name: "OT SEGMENT SINKING", desc: "Mirror internal OT enterprise bridge links hosting SCADA communications.", objective: "Secure telemetry streams containing smart-grid commands." },
      2: { name: "PLC KEY DISCLOSURE", desc: "Identify asymmetric firmware signatures used to validate PLC updates.", objective: "Extract public key certificates from physical control interfaces." },
      3: { name: "QUANTUM BREAK", desc: "Utilize Shor's alg algorithms to factor the firmware RSA signing modulars.", objective: "Calculate root master signature vectors of target plants." },
      4: { name: "FIRMWARE FORGERY", desc: "Forge administrative update packages containing rogue relay scripts.", objective: "Inject subverted SCADA binaries directly into network controllers." },
      5: { name: "THRESHOLD MANIPULATION", desc: "Transmit modified voltage thresholds, overriding hardware trip-switches.", objective: "Initiate system overloads on physical hydraulic sub-installations." },
      6: { name: "DEPLOY HARDENED OT PQC", desc: "Enforce State-Based Hash Signatures (LMS/XMSS) inside PLC systems.", objective: "Seal industrial equipment signatures from quantum interception." }
    },
    decryptedFiles: [
      { name: "North American Power Grid OT Logs", filename: "NERC_MAIN_SCADA_LOGS_2025.tar", size: "4.3 GB", tag: "OT CRITICAL", tagColor: "bg-red-500/20 text-red-300 border-red-500/30" },
      { name: "Gas Pipeline Pressure Schematics", filename: "SCADA_MODBUS_CODES_OVERRIDE.bin", size: "820 MB", tag: "TOP SECRET", tagColor: "bg-rose-500/25 text-rose-300 border-rose-500/25" },
      { name: "Hydroelectric Spillway PLC Config", filename: "HYDRO_DAM_GATE_VALVE.conf", size: "12 MB", tag: "HAZARD SYSTEM", tagColor: "bg-amber-500/15 text-amber-400 border-amber-500/20" }
    ]
  },
  {
    id: "cloud-breach",
    name: "Cloud Control Plane Quantum Breach",
    shortName: "Cloud IAM Controller Breach",
    category: "Cloud Security",
    objectiveText: "Compromise security backbones of multi-tenant cloud providers by decrypting administrator token signers and IAM root certificates on Shor rigs.",
    narrative: "An enterprise nightmare. Attacking authentication pipelines triggers high-speed lateral takeover cascade, gaining access to AWS, Azure, and Google Cloud workspaces simultaneously.",
    impactText: "Instantaneous administrative control of corporate microservices, database clusters, and secure APIs.",
    impactBullets: [
      "Lateral takeover of massive multi-tenant database systems",
      "Decryption of Kubernetes master key vaults and secret vaults",
      "Forgery of cross-realm API administrative identity tokens"
    ],
    targets: ["AWS Cloud Boundary", "Kubernetes Key Ring", "Azure Identity Hub"],
    nodeNames: {
      client: "Cloud Admin Workspace",
      gateway: "Quantum Identity Proxy",
      server: "Cloud IAM Controller",
      vault: "Tenant Secrets Pool"
    },
    metrics: { basePackets: 304589, baseSizeGB: 112.4, captureRate: 11.2, riskLevel: "High" },
    pulseColors: { breached: "#dc2626", safe: "#0284c7" },
    steps: {
      1: { name: "API PORT INTERCEPT", desc: "Mirror active TLS tunnels reaching admin API endpoints of tenant clouds.", objective: "Gather raw cryptographic handshakes containing ID signatures." },
      2: { name: "IAM CERT EXFILTRATION", desc: "Retrieve public certificate arrays of major administrative key rings.", objective: "Map encryption dependencies of AWS KMS and Azure Vaults." },
      3: { name: "LATTICE CRYPTO ANALYSIS", desc: "Run Shor's registers over private Key Encrypting Keys (KEKs).", objective: "Invert the mathematical security equations of IAM tokens." },
      4: { name: "AWS/AZURE TOKEN FORGERY", desc: "Structure root admin security tokens bypass verification checks.", objective: "Infiltrate tenant cloud instances with administrator clearance." },
      5: { name: "LATERAL COMPROMISE MAP", desc: "Initiate lateral taking of application databases and backup drives.", objective: "Expose all container repositories and master database clusters." },
      6: { name: "DEPLOY CLOUD HYBRID PQC", desc: "Enforce ML-KEM and ML-DSA inside IAM and API gateways.", objective: "Immunize enterprise cloud control planes from asymmetric threats." }
    },
    decryptedFiles: [
      { name: "Master Tenant Identity Database", filename: "CLOUD_IDENTITY_USER_STORE.sql", size: "48 GB", tag: "IAM EXPOSED", tagColor: "bg-red-500/20 text-red-300 border-red-500/30" },
      { name: "Kubernetes Master Root Secrets", filename: "K8S_SEC_ENV_CREDENTIALS.env", size: "140 MB", tag: "CRITICAL SECRET", tagColor: "bg-rose-500/25 text-rose-300 border-rose-500/30" },
      { name: "Enterprise S3 Bucket Encryption Keys", filename: "AWS_KMS_EXTRACTED_KEKS.json", size: "8.5 MB", tag: "SYSTEM KEY", tagColor: "bg-amber-500/15 text-amber-400 border-amber-500/20" }
    ]
  },
  {
    id: "satellite-comm",
    name: "Satellite & Defense Communications Breach",
    shortName: "Satellite Comm Intercept",
    category: "Aerospace & Defense",
    objectiveText: "Intercept aerospace uplink communications using quantum computing to decrypt raw tactical satellite feeds dynamically.",
    narrative: "Adversaries tap terrestrial or orbital satellite links and record the key agreement. Shor's discrete-logarithm variant recovers the ECDSA P-384 signing key and the ECDH scalar, exposing stored telemetry and mission planning files once a CRQC exists.",
    impactText: "Complete compromise of defense satellite feeds, exposing real-time troop trackers and coordinates.",
    impactBullets: [
      "Leak coordinates and mission profiles of operational military forces",
      "Decryption of remote tactical telemetry feeds from unmanned aircraft",
      "Hijacking of orbital uplink commands and payload configurations"
    ],
    targets: ["Orbital Uplink Center", "Defense Tactical Node", "Aerospace Mainframe"],
    nodeNames: {
      client: "Command Operations Room",
      gateway: "Orbital Signal Interceptor",
      server: "SATCOM Uplink Unit",
      vault: "Decrypted Command Cache"
    },
    metrics: { basePackets: 54109, baseSizeGB: 231.8, captureRate: 9.4, riskLevel: "High" },
    pulseColors: { breached: "#b91c1c", safe: "#6366f1" },
    steps: {
      1: { name: "UPLINK SIGINT SINKING", desc: "Intercept microwave satellite uplink transmissions via ground telemetry.", objective: "Secure Raw IQ signal frames of military communication transponders." },
      2: { name: "HANDSHAKE COMPRES", desc: "Identify tactical key exchanges containing military encryption handshakes.", objective: "Isolate tactical signatures from background space noise." },
      3: { name: "SHOR RADAR TARGETING", desc: "Deploy Shor factoring units over aerospace communications.", objective: "Target G20 defense satellite command codes." },
      4: { name: "TELEMETRY DESERIAL", desc: "Synthesize the decrypted keystreams to read raw aerospace packets.", objective: "Display active orbital track vectors as plaintext strings." },
      5: { name: "MILITARY DATA EXFIL", desc: "Analyze decrypted tactical briefs and real-time troop logs.", objective: "Expose coordinate maps of defense deployments." },
      6: { name: "DEPLOY DEEP SPACE PQC", desc: "Enforce stateful hash updates on satellite hardware components.", objective: "Protect military uplink tunnels from future decryption attempts." }
    },
    decryptedFiles: [
      { name: "Orbital Telemetry Coordination Maps", filename: "SATCOM_COORD_MAPS_ACTIVE_ALL.kml", size: "12 GB", tag: "SECRET", tagColor: "bg-red-500/20 text-red-100 border-red-500/20" },
      { name: "Unmanned Vehicle Flight Profiles", filename: "UAV_FLIGHT_PROFILES_SPECIMEN.xml", size: "1.2 GB", tag: "TOP SECRET", tagColor: "bg-rose-500/25 text-rose-300 border-rose-500/25" },
      { name: "Active Military Operational Briefs", filename: "OPLAN_SPECIMEN_THEATRE.pdf", size: "450 MB", tag: "COSMIC TOP SECRET", tagColor: "bg-amber-500/15 text-amber-400 border-amber-500/20" }
    ]
  },
  {
    id: "genomic-exposure",
    name: "Healthcare / Genomic Data Exposure",
    shortName: "Genomic Database Exposure",
    category: "Healthcare Security",
    objectiveText: "Expose genomic, DNA sequence databases, and biological records protected by legacy RSA/AES-128 cryptographic barriers.",
    narrative: "Harvested medical data remains highly vulnerable. Quantum-assisted decryption of medical cloud silos results in absolute, non-revocable privacy loss of genetic profiles.",
    impactText: "Permanent biological and corporate risk. You cannot change your genetic code after it is leaked.",
    impactBullets: [
      "Permanent leakage of critical DNA structures of millions of citizens",
      "Corporate insurance liabilities based on genetic predisposition data",
      "Severe biosecurity and targeted national defense risks"
    ],
    targets: ["Oncology Cloud Silo", "Genomics Registry DB", "Hospital EHR Core"],
    nodeNames: {
      client: "DNA Sequencing Lab",
      gateway: "Quantum Medical Tap",
      server: "Electronic Health Hub",
      vault: "Decrypted Record Store"
    },
    metrics: { basePackets: 154129, baseSizeGB: 95.3, captureRate: 4.1, riskLevel: "Medium" },
    pulseColors: { breached: "#ec4899", safe: "#14b8a6" },
    steps: {
      1: { name: "EHR LINK INTERCEPTION", desc: "Tap hospital network traffic pipelines routing EHR and genomic files.", objective: "Intercept and buffer legacy SSL/TLS encrypted patient health logs." },
      2: { name: "GENOMIC INDEXING", desc: "Isolate massive genomic sequence files from medical archive nodes.", objective: "Identify target structures hosting deep genetic patient registers." },
      3: { name: "SHOR DISINTEGRATION", desc: "Run factoring arrays against EHR database encryption keys.", objective: "Derive key coefficients of clinical server credentials." },
      4: { name: "RECORD REVELATION", desc: "Extract private decryption elements to decrypt medical archives.", objective: "Uncover DNA profile codes and genetic anomaly datasets." },
      5: { name: "BIOLOGICAL COMPROMISE", desc: "Declassify files, mapping patient profiles directly to genetic indices.", objective: "Expose HIPAA health records and insurance metadata." },
      6: { name: "DEPLOY HEAL SECURE PQC", desc: "Migrate electronic health databases to ML-KEM and ML-DSA standards.", objective: "Render public health records immune to retroactive quantum threats." }
    },
    decryptedFiles: [
      { name: "National Genetic DNA Sequences", filename: "GENOME_REGISTRY_SPECIMEN.db", size: "54 GB", tag: "PHI", tagColor: "bg-red-500/15 text-pink-400 border-red-500/20" },
      { name: "Active Clinical Oncology Trials", filename: "ONCO_TRIAL_RAW_PHASE3.tar.gz", size: "11.2 GB", tag: "PROPRIETARY", tagColor: "bg-rose-500/20 text-rose-300 border-rose-500/20" },
      { name: "Hospital Patient Health Records", filename: "EHR_PORTAL_EXPORTS_2025.csv", size: "8.1 GB", tag: "HIPAA COMPROMISE", tagColor: "bg-amber-500/15 text-amber-400 border-amber-500/20" }
    ]
  },
  {
    id: "ai-theft",
    name: "AI Model Theft & Quantum AI Manipulation",
    shortName: "AI Model Theft & Poisoning",
    category: "AI Security",
    objectiveText: "Decrypt secure model hosting clusters to steal neural network weights, enabling malicious AI supply chain manipulation.",
    narrative: "As AI becomes a core asset, model weights move over TLS protected by enterprise PKI. Recovering the key agreement for those transfers exposes the weights themselves — a confidentiality loss. Tampering with weights in transit is a separate integrity problem that a signature forgery, not decryption, would enable.",
    impactText: "Theft of trade secrets worth billions and deep manipulation of critical autonomous systems.",
    impactBullets: [
      "Loss of proprietary artificial intelligence core weights",
      "Systematic injection of backdoor triggers inside secure models",
      "Evasion of neural safety parameters by editing weight matrices closely"
    ],
    targets: ["AI Supercomputing Lab", "Secure LLM Weight Host", "Autonomous Control Grid"],
    nodeNames: {
      client: "AI Training Node",
      gateway: "Quantum Weight Snatcher",
      server: "Secure Inference Host",
      vault: "Stolen Weights Repository"
    },
    metrics: { basePackets: 241560, baseSizeGB: 680.4, captureRate: 15.6, riskLevel: "High" },
    pulseColors: { breached: "#8b5cf6", safe: "#c084fc" },
    steps: {
      1: { name: "PIPELINE LISTENING", desc: "Tap secure pipeline links transferring AI weight files between nodes.", objective: "Mirror encrypted model update sequences bypassing network filters." },
      2: { name: "KEY MANAGER MAPPING", desc: "Interrogate public certificates guarding model key management vaults.", objective: "Expose cryptographic dependencies of proprietary AI model layers." },
      3: { name: "SHOR DE-ENCRYPTION", desc: "Apply Shor's arrays over model transfer signature keys.", objective: "Factorize security credentials guarding AI model files." },
      4: { name: "WEIGHT MODEL EXTRACTION", desc: "Decrypt full proprietary AI model tensors and neural parameters.", objective: "Extract proprietary network coefficients into local storage archives." },
      5: { name: "NEURAL BACKDOOR INJECT", desc: "Apply math manipulation to insert stealthy poison patterns inside the AI models.", objective: "Allow persistent evasion of model guardrails and safety check parameters." },
      6: { name: "DEPLOY SECURE AI PQC", desc: "Implement Kyber key managers in model registries.", objective: "Seal proprietary AI networks with quantum-grade protection layers." }
    },
    decryptedFiles: [
      { name: "Proprietary LLM Weights Tensors", filename: "ORION_LLM_WEIGHTS_FP16.safetensors", size: "450 GB", tag: "CORE AI ASSET", tagColor: "bg-red-500/20 text-violet-300 border-indigo-500/30" },
      { name: "Autonomous Vehicle Vision Tensors", filename: "AV_CONTROL_MODEL_V4_8.bin", size: "12 GB", tag: "CRITICAL SAFETY", tagColor: "bg-rose-500/25 text-rose-300 border-rose-500/25" },
      { name: "Proprietary Prompt Guard Guidelines", filename: "AI_ALIGNMENT_GUIDE_SECRET.md", size: "2.4 MB", tag: "AI SYSTEM", tagColor: "bg-amber-500/15 text-amber-400 border-amber-500/20" }
    ]
  },
  {
    id: "pqc-migration",
    name: "PQC Migration Failure Simulation",
    shortName: "PQC Migration Failure",
    category: "Operational Risk Testing",
    objectiveText: "Simulate operational chaos caused by incorrect post-quantum cryptography migrations, including handshake timeouts and network latency spikes.",
    narrative: "Most vendors ignore migration friction. Enabling PQC standard testing causes connection failures due to packet size increases of ML-KEM/ML-DSA certificates over legacy networks.",
    impactText: "Massive system outages and handshake failures resulting from cryptographic incompatibility.",
    impactBullets: [
      "handshake time-out spikes caused by large packet payloads of PQC Keys",
      "Network routing dropping packets due to size variations from standard IP rules",
      "Incompatible legacy certificates causing complete failure of internal VPN tunnels"
    ],
    targets: ["Edge Proxy Grid", "Legacy VPN Concentrator", "Active Certificate Center"],
    nodeNames: {
      client: "Enterprise User Client",
      gateway: "Broken Hybrid Gateway",
      server: "Legacy IIS Web Server",
      vault: "Error Event Storage"
    },
    metrics: { basePackets: 19825, baseSizeGB: 1.15, captureRate: 0.15, riskLevel: "Medium" },
    pulseColors: { breached: "#f59e0b", safe: "#10b981" },
    steps: {
      1: { name: "PQC ACTIVATION", desc: "Initialize ML-KEM-1024 parameters on outdated edge router proxies.", objective: "Trigger modern post-quantum key handshakes over public routes." },
      2: { name: "SIZE OVERFLOW EVENT", desc: "Observe MTU drops caused by huge post-quantum key packet sizes.", objective: "Trigger network packet fragmentation of certificate handshakes." },
      3: { name: "HANDSHAKE TIMEOUT", desc: "Identify latency spikes and packet delays during hybrid transitions.", objective: "Measure secure tunnel handshake completion timeout ratios." },
      4: { name: "HYBRID CONFLICT RAISING", desc: "Identify certificate authorization failures between PQC and legacy systems.", objective: "Expose client routing failures and dropped browser sessions." },
      5: { name: "NETWORK DRIFT COMPROMISE", desc: "System rolls back to weak algorithms due to fallback configuration rules.", objective: "Expose active traffic to sudden, legacy downgrade vulnerabilities." },
      6: { name: "DEPLOY CORRECT HYBRID KEM", desc: "Optimize handshake routes with streamlined ML-KEM parameters.", objective: "Establish stable, standard hybrid-classic secure cryptosystems." }
    },
    decryptedFiles: [
      { name: "Edge Handshake Error Logs", filename: "EDGE_PROXY_PQC_TIMEOUTS.log", size: "420 MB", tag: "ERRORS SINK", tagColor: "bg-amber-500/15 text-amber-400 border-amber-500/20" },
      { name: "VPN Broken Handshake Capture", filename: "IPSEC_PQC_FALLBACK_DASH.pcap", size: "1.2 GB", tag: "NETWORK TEST", tagColor: "bg-blue-500/15 text-blue-300 border-blue-500/20" },
      { name: "System Outage Cascade Report", filename: "CRYPTO_MIGRATION_AUDIT_2025.pdf", size: "4.5 MB", tag: "INCIDENT REPORT", tagColor: "bg-red-500/15 text-red-400 border-red-500/20" }
    ]
  },
  {
    id: "warfare-scenario",
    name: "Nation-State Quantum Warfare Scenario",
    shortName: "Nation-State Quantum Warfare",
    category: "Geopolitical Crisis",
    objectiveText: "Simulate a coordinated quantum-powered cyber attack targeting national banking, infrastructure, and communication frameworks simultaneously.",
    narrative: "A geopolitical worst case. A nation-state applies CRQC capacity to its highest-value recorded key agreements. Each solve costs hours to days of machine time, so the collapse is a prioritised queue working through an archive, not a simultaneous break of everything.",
    impactText: "Widespread, societal-scale disruption across multiple essential civilian and military sectors.",
    impactBullets: [
      "Simultaneous breakdown of internet communication, routing, and SaaS tools",
      "Immediate closure of major financial payment and wire routing networks",
      "Total outage of smart grids, water systems, and communication nodes"
    ],
    targets: ["National Civil Network", "Central bank wire Portal", "Military Satellite Node"],
    nodeNames: {
      client: "Joint Taskforce Center",
      gateway: "State-Sponsored Q-Array",
      server: "National Command Core",
      vault: "Target Country Archive"
    },
    metrics: { basePackets: 984501, baseSizeGB: 1450.6, captureRate: 48.5, riskLevel: "High" },
    pulseColors: { breached: "#7f1d1d", safe: "#ddf3f9" },
    steps: {
      1: { name: "CRISIS INITIALIZATION", desc: "Map asymmetric cryptographic handshakes across telecom, utility, and bank links.", objective: "Organize target cert list on multiple state-sponsored Q-Arrays." },
      2: { name: "DATA SWEEP STAGE", desc: "Passively exfiltrate active session hashes via hijacked WAN routers.", objective: "Gather massive cryptographic files from essential national grids." },
      3: { name: "SHOR COORDINATION", desc: "Engage parallel Shor factor loops against identified keyrings.", objective: "Overwhelm civilian defensive networks with high-speed key cracked maps." },
      4: { name: "SYSTEMIC BREAKDOWN", desc: "Simultaneously inject cracked signature overrides across telecom and banking systems.", objective: "Initiate multi-sector infrastructure failure and data expo leaks." },
      5: { name: "COGNITIVE CHAOS", desc: "Leaking military command lines and treasury data to sow mass social confusion.", objective: "Render communication channels completely blind and compromised." },
      6: { name: "CORE CRYPTO SHIELDING", desc: "Enforce complete Post-Quantum Cryptography transition checklists.", objective: "Apply NIST FIPS 203, 204, and 205 algorithms across defense grids." }
    },
    decryptedFiles: [
      { name: "National Intelligence Command Arch", filename: "INTEL_COMMAND_ARCH_SPECIMEN.tar", size: "120 GB", tag: "TOP SECRET//SCI", tagColor: "bg-red-500/25 text-red-200 border-red-500/30" },
      { name: "Bank System Liquidity Ledger", filename: "NATIONAL_BANK_TRANS_BAL.csv", size: "45 GB", tag: "CRITICAL FINANCE", tagColor: "bg-rose-500/20 text-rose-300 border-rose-500/25" },
      { name: "Civil Power Distribution Map", filename: "CIVIL_POWER_GRID_PLC_SIGN.tar.gz", size: "3.2 GB", tag: "OT ASSET EXPOSED", tagColor: "bg-amber-500/15 text-amber-400 border-amber-500/20" }
    ]
  },
  {
    id: "supply-chain",
    name: "Quantum Supply Chain Attack",
    shortName: "Quantum Supply Chain",
    category: "Software Signing Integrity",
    objectiveText: "Decrypt master Software Signer Certificates to inject trojans into trusted enterprise software updates and firmware scripts.",
    narrative: "An insidious attack vector. Attackers target trusted third-party vendors. By factorizing software signing keys, they inject malware containing authentic signatures.",
    impactText: "Infiltration of thousands of secure networks trusting signed developer update packages.",
    impactBullets: [
      "Inject backdoors into critical kernel-level software update suites",
      "Total compromise of automated CI/CD code compilation pipes",
      "Complete exploitation of automated trust loops without active defense alert"
    ],
    targets: ["Developer App Core", "Trusted CA Signer", "Enterprise CI/CD Engine"],
    nodeNames: {
      client: "Developer Terminal",
      gateway: "Quantum Cert Factorizer",
      server: "Build Server",
      vault: "Poisoned Code Store"
    },
    metrics: { basePackets: 15480, baseSizeGB: 12.8, captureRate: 1.45, riskLevel: "High" },
    pulseColors: { breached: "#f43f5e", safe: "#a855f7" },
    steps: {
      1: { name: "CERT MIRRORING", desc: "Harvest software signing public certs from popular business application vendors.", objective: "Extract trusted developer public keyrings." },
      2: { name: "CI/CD HOOKING", desc: "Isolate automated code compilation and update server connections.", objective: "Identify firmware signing pathways of industrial vendors." },
      3: { name: "SHOR ARTIFACT CRACK", desc: "Aquire signature private keys by solving factoring loops on Shor cores.", objective: "Compile software signing private keys as plaintext assets." },
      4: { name: "FIRMWARE POISON", desc: "Inject trojans into build packages and sign with trusted developer certificates.", objective: "Publish poisoned updates that bypass security validation checks." },
      5: { name: "SYSTEM PENETRATION", desc: "Watch signed backdoors install across corporate internal database lines.", objective: "Acquire root execution permissions on target networks." },
      6: { name: "DEPLOY QUANTUM SIGNERS", desc: "Adopt ML-DSA (Dilithium) secure software signature protocols.", objective: "Enforce complete, quantum-safe software verification codes." }
    },
    decryptedFiles: [
      { name: "Developer Root Certificate Key", filename: "SOFTWARE_SIGNER_CORE_PRIVATE.pem", size: "3.2 KB", tag: "SIGNER KEY", tagColor: "bg-red-500/20 text-red-300 border-red-500/30" },
      { name: "Poisoned Vendor Firmware Update", filename: "SYS_UPDATE_HOTFIX_TRUSTED_v8.exe", size: "115 MB", tag: "TROJAN ARTIFACT", tagColor: "bg-rose-500/25 text-rose-300 border-rose-500/25" },
      { name: "CI/CD Pipeline Configurations", filename: "JENKINS_BUILD_SIGN_MASTER.yml", size: "12 KB", tag: "EXPOSED", tagColor: "bg-amber-500/15 text-amber-400 border-amber-500/20" }
    ]
  },
  {
    id: "risk-sandbox",
    name: "Quantum Risk Assessment Sandbox",
    shortName: "Risk Assessment Sandbox",
    category: "Interactive Simulation",
    objectiveText: "Simulate custom cyber defenses, comparing RSA, ECC, AES algorithms against quantum encapsulation standards like Kyber and Dilithium.",
    narrative: "This is a specialized testing playground. Evaluate mathematically how classical algorithms decay against Shor's and Grover's while comparing PQC migration timelines.",
    impactText: "Enables cybersecurity managers to test and justify post-quantum transition schedules.",
    impactBullets: [
      "Evaluate mathematical security indices of enterprise algorithm suites",
      "Model quantum breakout time estimates across various computing scales",
      "Draft custom enterprise crypto-migration roadmaps and cost tables"
    ],
    targets: ["RSA-2048 Node", "ECC prime256r1 Node", "ML-KEM Kyber Node"],
    nodeNames: {
      client: "Risk Assessment Desk",
      gateway: "Simulator Engine Gateway",
      server: "Multi-Algorithm Server",
      vault: "Scenario Performance Logs"
    },
    metrics: { basePackets: 5410, baseSizeGB: 0.45, captureRate: 0.10, riskLevel: "Low" },
    pulseColors: { breached: "#eab308", safe: "#10b981" },
    steps: {
      1: { name: "ALGORITHM COGNITION", desc: "Select and deploy various symmetric and asymmetric cryptographic options.", objective: "Map cryptographic algorithm defenses to test pipelines." },
      2: { name: "SENSITIVITY ANALYSIS", desc: "Measure security strengths of selected keys against quantum qubits.", objective: "Calculate key stability metrics and classical cracking ratios." },
      3: { name: "ATTACK CYCLE CHRONO", desc: "Launch simulation factor loops, estimating cracking speed of target keys.", objective: "Measure Shor factor speeds against RSA and ECC targets." },
      4: { name: "VULNERABILITY RATIO", desc: "Watch RSA and ECC keys collapse, while Kyber and Dilithium resist loops.", objective: "Expose real-time vulnerability graphs of system endpoints." },
      5: { name: "MIGRATION PLAN COST", desc: "Calculate operational latency, bandwidth, and CPU costs of upgraded ciphers.", objective: "Expose cost tables comparing legacy and post-quantum handshakes." },
      6: { name: "DEPLOY CUSTOM EXECUTIVES", desc: "Generate enterprise-grade Post-Quantum transition reports.", objective: "Print customized transition action items for board reviews." }
    },
    decryptedFiles: [
      { name: "Symmetric Encryption Decay Tables", filename: "CIPHER_DECAY_TIMELINE_SIM.xlsx", size: "2.4 MB", tag: "SIMULATION SINK", tagColor: "bg-amber-500/15 text-amber-400 border-amber-500/20" },
      { name: "Key Hardness Comparison Report", filename: "QUANTUM_vs_CLASSICAL_HARDNESS.pdf", size: "1.8 MB", tag: "COMPREHENSIVE", tagColor: "bg-purple-500/15 text-purple-300 border-purple-500/20" },
      { name: "Optimized Enterprise Migration Plan", filename: "PQC_TRANSITION_TIMELINE_G7.xml", size: "450 KB", tag: "REPORT DATA", tagColor: "bg-emerald-500/15 text-emerald-300 border-emerald-500/20" }
    ]
  },
  {
    id: "operational-collapse",
    name: "Crypto-Operational Collapse Simulation",
    shortName: "Crypto-Operational Collapse",
    category: "Operational Risk Testing",
    objectiveText: "Simulate operational chaos resulting from mass cryptographic certificate expiry, authentication failure, and HSM loop overloads.",
    narrative: "An extreme testing scenario. What happens when security systems go completely blind, certificates fail, APIs crash, and hardware security modules overload in a cascade?",
    impactText: "Immediate, catastrophic operational deadlock across enterprise communication servers.",
    impactBullets: [
      "Hardware security modules (HSM) failing completely under crypto overloads",
      "Denial of service (DoS) cascades across authentication services",
      "Network monitoring frameworks going blind, allowing sneaky exfiltrations"
    ],
    targets: ["Core Auth Controller", "HSM Cluster Engine", "Security Monitor Proxy"],
    nodeNames: {
      client: "Helpdesk Terminal",
      gateway: "Deadlocked HSM Router",
      server: "Identity API Host",
      vault: "Crash Log Repository"
    },
    metrics: { basePackets: 450129, baseSizeGB: 154.2, captureRate: 4.8, riskLevel: "High" },
    pulseColors: { breached: "#dc2626", safe: "#ea580c" },
    steps: {
      1: { name: "MASS ERROR EMERGEN", desc: "Simulate concurrent expiration of master identity certificates.", objective: "Trigger cryptographic trust failures across core proxies." },
      2: { name: "HSM LOAD OVERLOAD", desc: "Queue infinite decryption loops, overtaxing operational hardware devices.", objective: "Drive HSM physical processor utilization to 100% overload states." },
      3: { name: "AUTHENTICATION BLIND", desc: "Observe complete crash of Active Directory and SSO token APIs.", objective: "Disconnect active user terminals from enterprise cloud clusters." },
      4: { name: "IDS MONITOR BLINDING", desc: "Monitor security logs failing, creating complete system blindness.", objective: "Disable perimeter log streams as systems trigger failover modes." },
      5: { name: "INTRUSION PROPAGATION", desc: "Launch unmonitored administrative command routes into systems.", objective: "Secure persistent backdoor lines to confidential datastores." },
      6: { name: "DEPLOY HIGH-AVAIL PQC", desc: "Deploy resilient, post-quantum HSM clusters featuring auto-fallbacks.", objective: "Upgrade operations to resistant, fail-secure crypto-systems." }
    },
    decryptedFiles: [
      { name: "Active Directory Identity Crash Dump", filename: "AD_SSO_IDENTITY_COLLAPSE.dmp", size: "14 GB", tag: "SYSTEM FAILURE", tagColor: "bg-red-500/20 text-red-300 border-red-500/30" },
      { name: "HSM Hardware Processor Log", filename: "HSM_CRYPTO_CHIP_FAULT_LOG.bin", size: "4.8 GB", tag: "OT CRITICAL FAULT", tagColor: "bg-rose-500/25 text-rose-300 border-rose-500/25" },
      { name: "Unmonitored Traffic Intercept Dump", filename: "BLIND_ZONE_TRAFFIC_INTERCEPT.pcap", size: "18.3 GB", tag: "EXFILTRATION", tagColor: "bg-amber-500/15 text-amber-400 border-amber-500/20" }
    ]
  },
  {
    id: "qday-readiness",
    name: "Q-Day Readiness Simulation",
    shortName: "Q-Day Readiness Alert",
    category: "Geopolitical Crisis",
    objectiveText: "Model Q-Day—the definitive arrival of a Cryptographically Relevant Quantum Computer (CRQC)—and calculate enterprise survival ratios.",
    narrative: "CRQC becomes active. Simulate an emergency response. Observe in real-time which financial, health, and national sectors fall as mathematical shielding breaks.",
    impactText: "Definitive loss of classic asymmetric security, forcing survival procedures across all environments.",
    impactBullets: [
      "Simulate which parts of public infrastructure fail in the first 24 hours",
      "Measure enterprise readiness indicators with real-time countdown widgets",
      "Model multi-sector recovery curves using quantum-hardened defenses"
    ],
    targets: ["Q-Day Emergency Core", "Sovereign Survival Hub", "Global Trust Backbone"],
    nodeNames: {
      client: "Strategic Crisis Desk",
      gateway: "CRQC Active Matrix",
      server: "Global IP Trust Node",
      vault: "Survival Strategy Center"
    },
    metrics: { basePackets: 1540982, baseSizeGB: 2105.8, captureRate: 85.5, riskLevel: "High" },
    pulseColors: { breached: "#be123c", safe: "#10b981" },
    steps: {
      1: { name: "Q-DAY ANNOUNCEMENT", desc: "Public activation of a stable 5000 logical qubit CRQC system.", objective: "Acknowledge irreversible obsolescence of legacy cryptography." },
      2: { name: "INITIAL CASCADE BREAK", desc: "Shor's solvers disintegrate public HTTPS, SSH, and CA links.", objective: "Identify target keys collapsing within 6 hours of activation." },
      3: { name: "PANIC RESPONSE SECTOR", desc: "Banking, water grids, and communications report crypto key breaks.", objective: "Map systemic fallout across regional civilian control clusters." },
      4: { name: "CRITICAL COLLAPSE LEVEL", desc: "Vulnerable central bank ledgers and cloud databases are fully exposed.", objective: "Decrypt sovereign databases, proving complete legacy breach states." },
      5: { name: "RECOVERY COORDINATION", desc: "Force emergency post-quantum cryptographic configurations online.", objective: "Deploy fallback certificates to protect essential communication hubs." },
      6: { name: "TOTAL QUANTUM IMMUNIZ", desc: "Transition entire infrastructure to FIPS PQC standards permanently.", objective: "Secure enterprise operational readiness index back to 100%." }
    },
    decryptedFiles: [
      { name: "Emergency Crisis Strategy Plan", filename: "QDAY_EMERGENCY_TACTICAL_MAN.pdf", size: "45 MB", tag: "CRITICAL DOCUMENT", tagColor: "bg-red-500/25 text-red-100 border-red-500/20" },
      { name: "Sparsely Decrypted Database Backup", filename: "SURVIVAL_CLUSTER_FALLBACKS.sql", size: "450 GB", tag: "TOP RECOVERY", tagColor: "bg-rose-500/20 text-rose-300 border-rose-500/20" },
      { name: "Geopolitical Trust Fallout Audit", filename: "CRQC_FALLOUT_ASSESSMENT_ALL.bin", size: "18.5 GB", tag: "GLOBAL SINK", tagColor: "bg-amber-500/15 text-amber-400 border-amber-500/20" }
    ]
  }
];
