/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useMemo, useRef, useState } from 'react';
import { motion, AnimatePresence, useMotionValue, useTransform, useSpring } from 'motion/react';
import Navbar2 from "@/components/ui/navbar2";
import { Hero195 } from "@/components/ui/hero-195";
import { StickyFeatureSection } from "@/components/ui/sticky-scroll-cards-section";
import { QuantumFeaturesMarquee } from "@/components/ui/QuantumFeaturesMarquee";
import {
  Activity,
  Calendar,
  Shield,
  Check,
  CheckCircle2,
  Clock,
  Cloud,
  Hourglass as HourglassIcon,
  Map,
  Database,
  Key,
  KeyRound,
  Lock,
  AlertTriangle,
  MoveRight,
  FileCheck,
  Users,
  Search,
  Zap,
  TrendingDown,
  Globe,
  Skull,
  Play,
  ChevronDown,
  Plus,
  RefreshCw,
  RefreshCcw,
  Twitter,
  Linkedin,
  Github,
  Flame,
  Sparkles,
  Terminal,
  X,
  ShieldCheck,
  ArrowRight,
  Loader,
  type LucideIcon
} from 'lucide-react';
import { CyberBackground } from '../components/CyberBackground';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { TooltipProvider } from '../components/ui/tooltip';
import {
  DEMO_FIELD_LIMITS,
  DEMO_REQUEST_INBOX,
  DEMO_STAGES,
  demoStageLabel,
  validateDemoRequest,
  type DemoStage,
} from '@/lib/demo-request';
import hourGlassVideo from '../assets/Hour_Glass_Video.mp4';
import hourglassImage from '../assets/images/futuristic_hourglass_sand_1778137402905.png';
import roadmapImage from '../assets/images/quantum_security_roadmap_assets_1778137420732.png';

// Asset paths
const ASSETS = {
  hourglass: hourglassImage,
  hourglassVideo: hourGlassVideo,
  roadmap: roadmapImage
};

const HERO_ACCESSIBLE_TITLE = "The Quantum Clock Is Ticking. Your Security Can't Stand Still.";
const HERO_LINE_ONE = 'The Quantum';
const HERO_LINE_TWO_PREFIX = 'Clock Is ';
const HERO_TICKING_WORD = 'TICKING';
const HERO_CHARACTER_COUNT = HERO_LINE_ONE.length + HERO_LINE_TWO_PREFIX.length + HERO_TICKING_WORD.length;
const HERO_TYPE_INTERVAL_MS = 72;
// NIST IR 8547: 112-bit-strength RSA/ECC/DH/ECDH/ECDSA are deprecated after
// 2030 and disallowed after 2035. The countdown tracks that published
// deprecation date, not a predicted "Q-Day" — nobody can date a CRQC.
const QUANTUM_MATURITY_TARGET = new Date(2030, 11, 31, 23, 59, 59);
const MS_PER_DAY = 24 * 60 * 60 * 1000;
const MS_PER_HOUR = 60 * 60 * 1000;
const MS_PER_MINUTE = 60 * 1000;
const MS_PER_SECOND = 1000;
const USE_CASE_CYCLE_MS = 6200;

type QuantumUseCaseFeature = {
  id: number;
  title: string;
  description: string;
  image: string;
  icon: LucideIcon;
  useCases: string[];
  keyFeatures: string[];
};

type MigrationStep = {
  id: string;
  num: string;
  title: string;
  description: string;
  details: string;
  badge: string;
  icon: LucideIcon;
};

type CryptoKey = {
  name: string;
  type: string;
  keySize: string;
  structure: string;
  securityBits: number;
  quantumStatus: 'vulnerable' | 'symmetric' | 'pqc';
  quantumAttackModel: string;
  assessment: string;
};

type RoadmapMilestone = {
  id: string;
  quarter: string;
  title: string;
  subtitle: string;
  status: 'active' | 'scheduled';
  statusLabel: string;
  description: string;
  deliverables: string[];
  metrics: Array<{ name: string; val: string }>;
};

const MIGRATION_PROCESS_STEPS: MigrationStep[] = [
  {
    id: '01',
    num: '01',
    title: 'Discover',
    description: 'Identify all crypto assets and their dependencies.',
    details: 'Automated scans crawl network databases, cloud containers, SSH keystores, TLS endpoints, and custom proprietary protocol tunnels to build a secure unified index of all certificates and operational ciphers.',
    badge: 'CRYPTOGRAPHIC INVENTORY',
    icon: Search
  },
  {
    id: '02',
    num: '02',
    title: 'Assess',
    description: 'Analyze risks and prioritize based on impact.',
    details: 'Flag deprecated hash algorithms, weak cipher suites, and quantum-vulnerable public-key families (RSA, finite-field Diffie-Hellman, ECDH, ECDSA, DSA). Rank assets by data lifetime, business criticality, and Harvest Now, Decrypt Later exposure so the longest-lived secrets are addressed first.',
    badge: 'AI-POWERED THREAT MODELING',
    icon: Shield
  },
  {
    id: '03',
    num: '03',
    title: 'Plan',
    description: 'Build a migration roadmap aligned with NIST PQC.',
    details: 'Compile sequential project roadmaps matching NIST migration criteria. Establish dual-key and hybrid strategy envelopes so infrastructure remains resilient during ongoing migrations.',
    badge: 'NIST ALIGNED ADVISORY',
    icon: FileCheck
  },
  {
    id: '04',
    num: '04',
    title: 'Migrate',
    description: 'Execute migration with hybrid and PQC technology.',
    details: 'Introduce ML-KEM (FIPS 203) for key establishment and ML-DSA (FIPS 204) for signatures, using hybrid classical + post-quantum modes where interoperability requires it, with rollback controls at every checkpoint.',
    badge: 'ACTIVE HARDENING',
    icon: RefreshCcw
  },
  {
    id: '05',
    num: '05',
    title: 'Validate',
    description: 'Verify compatibility, performance, and security.',
    details: 'Verify that the larger post-quantum key, ciphertext, and certificate sizes traverse gateways, firewalls, load balancers, and middleboxes, and measure the handshake and fragmentation impact before production cutover.',
    badge: 'INTEROPERABILITY TESTING',
    icon: Check
  },
  {
    id: '06',
    num: '06',
    title: 'Monitor',
    description: 'Continuously monitor, optimize, and stay ready.',
    details: 'Continuous monitoring flags reintroduced quantum-vulnerable cryptography, deprecated TLS versions, and unmanaged certificates, and maintains the crypto-agility controls needed to change algorithms again as standards evolve.',
    badge: 'CONTINUOUS ASSURANCE',
    icon: Activity
  }
];

const CRYPTO_SANDBOX_KEYS: CryptoKey[] = [
  {
    name: "RSA-2048",
    type: "Legacy Public-Key Encryption / Signature",
    keySize: "2048-bit modulus",
    structure: "Integer Factorization",
    securityBits: 112,
    quantumStatus: "vulnerable",
    quantumAttackModel:
      "Vulnerable to Shor's algorithm on a future large-scale fault-tolerant quantum computer.",
    assessment:
      "Requires inventory, risk scoring, and migration planning toward NIST-approved PQC where supported."
  },
  {
    name: "ECDSA P-256",
    type: "Legacy Elliptic-Curve Digital Signature",
    keySize: "256-bit curve",
    structure: "Elliptic-Curve Discrete Logarithm",
    securityBits: 128,
    quantumStatus: "vulnerable",
    quantumAttackModel:
      "Vulnerable to Shor's algorithm on a future large-scale fault-tolerant quantum computer.",
    assessment:
      "Prioritize for signature migration planning using ML-DSA or SLH-DSA where protocol and vendor support exists."
  },
  {
    name: "AES-256",
    type: "Symmetric Block Cipher",
    keySize: "256-bit key",
    structure: "Symmetric-Key Cryptography",
    securityBits: 256,
    quantumStatus: "symmetric",
    quantumAttackModel:
      "Not affected by Shor's algorithm. Grover's algorithm offers only a quadratic speedup, and it parallelizes poorly, so the practical margin is far better than a naive halving suggests.",
    assessment:
      "AES-256 meets NIST security category 5 and is the AES key size required by NSA CNSA 2.0. NIST has not deprecated AES-128 either; the post-quantum transition targets public-key cryptography."
  },
  {
    name: "ML-KEM-768",
    type: "NIST FIPS 203 Key Encapsulation Mechanism",
    keySize: "Public key: 1184 bytes; Ciphertext: 1088 bytes",
    structure: "Module-Lattice / Module-LWE",
    securityBits: 192,
    quantumStatus: "pqc",
    quantumAttackModel:
      "No known efficient quantum attack comparable to Shor's attack on RSA/ECC.",
    assessment:
      "NIST-standardized PQC target for quantum-resistant key establishment. Not mathematically proven unbreakable."
  },
  {
    name: "ML-DSA-65",
    type: "NIST FIPS 204 Digital Signature",
    keySize: "Public key: 1952 bytes; Signature: 3309 bytes",
    structure: "Module-Lattice Digital Signature",
    securityBits: 192,
    quantumStatus: "pqc",
    quantumAttackModel:
      "No known efficient quantum attack comparable to Shor's attack on RSA/ECC.",
    assessment:
      "NIST-standardized PQC target for quantum-resistant digital signatures. Requires correct implementation and validation."
  },
  {
    name: "SLH-DSA",
    type: "NIST FIPS 205 Stateless Hash-Based Signature",
    keySize: "Parameter-dependent (SHA2 or SHAKE; 128/192/256, s or f)",
    structure: "Stateless Hash-Based Signature",
    securityBits: 128,
    quantumStatus: "pqc",
    quantumAttackModel:
      "Hash-based design. No known Shor-style polynomial-time attack applies.",
    assessment:
      "A conservative signature option whose security rests only on its hash function, useful where larger signatures and slower signing are acceptable."
  }
];

const ROADMAP_MILESTONES: RoadmapMilestone[] = [
  {
    id: "01",
    quarter: "2026",
    title: "Cryptographic Inventory & Discovery",
    subtitle: "CRYPTOGRAPHIC ASSET IDENTIFICATION",
    status: "active",
    statusLabel: "FOUNDATION PHASE",
    description:
      "Establish a complete cryptographic inventory across applications, services, certificates, keys, protocols, libraries, APIs, cloud workloads, VPNs, PKI, and vendor dependencies. Identify where quantum-vulnerable public-key cryptography such as RSA, Diffie-Hellman, ECDH, ECDSA, and DSA is used.",
    deliverables: [
      "Discover TLS certificates, SSH keys, VPN handshakes, signing keys, PKI assets, and embedded cryptographic libraries",
      "Build a CBOM / cryptographic bill of materials for applications, services, containers, cloud assets, and third-party dependencies",
      "Identify deprecated TLS versions, weak cipher suites, SHA-1 usage, unmanaged certificates, shadow crypto, and hardcoded keys",
      "Classify long-lived data exposure for Harvest Now, Decrypt Later risk",
      "Create initial quantum-risk scoring and owner mapping per asset"
    ],
    metrics: [
      { name: "Primary NIST Goal", val: "Inventory" },
      { name: "Risk Focus", val: "RSA / ECC / DH" }
    ]
  },
  {
    id: "02",
    quarter: "2027",
    title: "Risk Prioritization & PQC Pilot Planning",
    subtitle: "ROADMAP, TESTING, AND CRYPTO-AGILITY",
    status: "scheduled",
    statusLabel: "PLANNED TARGET",
    description:
      "Prioritize migration based on data sensitivity, certificate lifetime, algorithm exposure, business criticality, vendor readiness, protocol support, and operational risk. Begin controlled pilots using NIST-standardized post-quantum algorithms where supported.",
    deliverables: [
      "Create migration tiers for high-value and long-lived data systems",
      "Validate crypto-agility patterns that separate algorithm policy from application logic",
      "Pilot ML-KEM for key establishment in supported test environments",
      "Pilot ML-DSA and SLH-DSA for digital signature use cases where applicable",
      "Measure interoperability, latency, certificate size impact, handshake behavior, rollback requirements, and operational readiness"
    ],
    metrics: [
      { name: "Primary NIST Goal", val: "Prioritize" },
      { name: "PQC Standards", val: "FIPS 203 / 204 / 205" }
    ]
  },
  {
    id: "03",
    quarter: "2028",
    title: "Phased PQC Migration & Hybrid Deployment",
    subtitle: "CONTROLLED TRANSITION TO QUANTUM-RESISTANT CRYPTO",
    status: "scheduled",
    statusLabel: "PLANNED TARGET",
    description:
      "Start phased migration of priority systems using approved PQC algorithms and hybrid transition patterns where interoperability requires classical and post-quantum mechanisms during the transition period. Avoid unsupported production claims and validate each integration against vendor, protocol, compliance, and performance requirements.",
    deliverables: [
      "Deploy ML-KEM-based key establishment where product, protocol, and compliance support are available",
      "Migrate selected signing workflows toward ML-DSA or SLH-DSA based on use case, performance, and signature-size requirements",
      "Update certificate lifecycle management, PKI workflows, key rotation procedures, and backup/restore controls",
      "Coordinate third-party vendor readiness reviews and contractual PQC migration commitments",
      "Maintain rollback plans, interoperability tests, monitoring, and phased cutover controls"
    ],
    metrics: [
      { name: "Primary NIST Goal", val: "Migrate" },
      { name: "Deployment Mode", val: "Phased / Hybrid" }
    ]
  },
  {
    id: "04",
    quarter: "2029",
    title: "Validation, Governance & Continuous Crypto-Agility",
    subtitle: "POST-MIGRATION ASSURANCE AND CONTINUOUS MONITORING",
    status: "scheduled",
    statusLabel: "PLANNED TARGET",
    description:
      "Validate migrated systems, continuously monitor cryptographic posture, enforce approved algorithm policy, and maintain crypto-agility so algorithms, libraries, certificates, and protocols can be updated as standards, vendor support, and compliance requirements evolve.",
    deliverables: [
      "Continuously monitor for reintroduced RSA/ECC dependencies, deprecated TLS, weak certificates, and unmanaged cryptographic assets",
      "Verify PQC implementation status, key lifecycle controls, certificate rotations, and logging evidence",
      "Maintain governance dashboards for compliance, audit readiness, asset ownership, exception handling, and executive reporting",
      "Update cryptographic policy as NIST, IETF, vendors, and regulators evolve implementation guidance",
      "Operate recurring validation, incident response playbooks, and crypto-agility change controls"
    ],
    metrics: [
      { name: "Primary NIST Goal", val: "Validate" },
      { name: "Operating Model", val: "Continuous Crypto-Agility" }
    ]
  }
];

const QUANTUM_USE_CASES: QuantumUseCaseFeature[] = [
  {
    id: 1,
    title: "Quantum QRNG",
    description: "True random number generation using quantum mechanics for cryptographic keys and security tokens.",
    icon: Zap,
    image: "/Quantum_qrng.png",
    useCases: [
      "Real-time key generation for encryption",
      "Secure session IDs generation",
      "High-entropy OTP generation for financial transactions",
      "Multi-factor authentication token generation",
      "Random number generation for lotteries",
      "Entropy-backed MFA for secure access",
      "Secure token generation",
      "Random sampling for analytics"
    ],
    keyFeatures: [
      "Physical entropy source",
      "High entropy generation",
      "Cryptographically secure",
      "Real-time random numbers",
      "Quantum noise source",
      "Continuous entropy health testing"
    ]
  },
  {
    id: 2,
    title: "Encryption Services",
    description: "Post-quantum encryption solutions protecting data against quantum computing threats.",
    icon: KeyRound,
    image: "/Encryption_services.png",
    useCases: [
      "Secure data transmission",
      "File encryption",
      "Database encryption",
      "Secure messaging",
      "Cloud storage protection",
      "Secure API communication"
    ],
    keyFeatures: [
      "Quantum-resistant algorithms",
      "End-to-end encryption",
      "Key exchange protocols",
      "Data encryption",
      "Secure communication",
      "Hybrid encryption"
    ]
  },
  {
    id: 3,
    title: "Security Authentication",
    description: "Post-quantum authentication systems for secure identity verification.",
    icon: Shield,
    image: "/Security_authentication.png",
    useCases: [
      "Multi-factor authentication",
      "Secure login",
      "Session management",
      "Access control",
      "Identity verification",
      "Secure transactions"
    ],
    keyFeatures: [
      "Post-quantum authentication",
      "Multi-factor authentication",
      "Biometric verification",
      "Secure session management",
      "Token-based authentication",
      "Real-time validation"
    ]
  },
  {
    id: 4,
    title: "Digital Certificates",
    description: "Post-quantum digital certificates for trusted identity and key establishment.",
    icon: FileCheck,
    image: "/Digital_certificates.png",
    useCases: [
      "SSL/TLS certificate management",
      "Code signing",
      "Document signing",
      "Identity verification",
      "Secure email",
      "IoT device authentication"
    ],
    keyFeatures: [
      "Post-quantum certificate authority",
      "PKI infrastructure",
      "Certificate lifecycle",
      "Certificate revocation",
      "Secure distribution",
      "ML-DSA (FIPS 204) signatures"
    ]
  },
  {
    id: 5,
    title: "Tokenization",
    description: "Quantum-safe tokenization for secure data representation and transmission.",
    icon: Activity,
    image: "/Tokenization.png",
    useCases: [
      "Payment tokenization",
      "PII protection",
      "Secure data sharing",
      "Compliance reporting",
      "Secure API tokens",
      "Database tokenization"
    ],
    keyFeatures: [
      "Data tokenization",
      "Token management",
      "Secure storage",
      "Token validation",
      "Quantum-resistant",
      "Compliance support"
    ]
  },
  {
    id: 6,
    title: "Secure Communications",
    description: "Quantum-safe communication protocols for secure data transfer.",
    icon: Globe,
    image: "/Secure_communication.png",
    useCases: [
      "Secure video conferencing",
      "Encrypted messaging",
      "Secure file transfer",
      "Secure API communication",
      "IoT device communication",
      "Secure remote access"
    ],
    keyFeatures: [
      "ML-KEM (FIPS 203) key establishment",
      "Secure messaging",
      "Encrypted channels",
      "Data integrity",
      "Secure file transfer",
      "Hybrid TLS key exchange"
    ]
  },
  {
    id: 7,
    title: "Cloud Security",
    description: "Post-quantum security for multi-cloud environments and infrastructure.",
    icon: Cloud,
    image: "/Cloud_security.png",
    useCases: [
      "Multi-cloud encryption",
      "Secure container management",
      "Cloud workload protection",
      "Data sovereignty compliance",
      "Secure API gateway",
      "Cloud infrastructure security"
    ],
    keyFeatures: [
      "Post-quantum cloud security",
      "Multi-cloud protection",
      "Infrastructure security",
      "Compliance monitoring",
      "Data protection",
      "Post-quantum encryption"
    ]
  }
];

const TRUSTED_LEADERS = [
  "FIPS 203 — ML-KEM",
  "FIPS 204 — ML-DSA",
  "FIPS 205 — SLH-DSA",
  "NIST IR 8547",
  "NIST SP 1800-38",
  "NIST SP 800-57",
  "NSA CNSA 2.0",
  "CISA Quantum Readiness",
  "IETF TLS Hybrid Key Exchange",
  "PCI DSS 4.0.1",
  "SOC 2 TSC",
  "ISO/IEC 27001"
];

type PricingPlan = {
  name: string;
  description: string;
  priceMonthly: number;
  priceYearly: number;
  badge: string;
  icon: LucideIcon;
  features: string[];
  notIncluded: string[];
  ctaText: string;
  popular: boolean;
  learnMoreHref?: string;
};

const PRICING_PLANS: PricingPlan[] = [
  {
    name: "Starter",
    description: "On-device Quantum Vault and encrypted Quantum Messaging for individuals who need private, post-quantum secure storage and communication.",
    priceMonthly: 1,
    priceYearly: 1,
    badge: "SECURE DESKTOP",
    icon: Shield,
    features: [
      "Access to Desktop and Mobile application Quantum Messaging and Quantum Vault Access",
      "End-to-End encrypted Secure Chat and a strictly on-device Quantum Vault — protected by NIST post-quantum cryptography.",
      "End-to-end encrypted messages, voice & video calls, with disappearing messages, multi-device trust, and one-tap call verification.",
      "Encrypt any file or folder on your device into a sealed, tamper-evident container. Strictly local and zero-knowledge — your data never leaves your machine.",
      "Post-Quantum by Default — every message, call, and file is secured with ML-KEM-1024 and ML-DSA, the NIST-standardized algorithms built to withstand quantum computers."
    ],
    notIncluded: [],
    ctaText: "Choose Starter",
    learnMoreHref: "/qguard-messaging",
    popular: false
  },
  {
    name: "Basic",
    description: "Quantum readiness and assessment for teams that need to understand exposure, plan migration, and act on AI-guided advisory reports.",
    priceMonthly: 8,
    priceYearly: 5,
    badge: "READINESS & ASSESSMENT",
    icon: Search,
    features: [
      "Quantum Readiness & Assessment Engine",
      "Risk Analysis and Migration Planner",
      "AI Migration Advisor",
      "AI Executive Advisor",
      "Enterprise Grade Quantum Readiness and Assessment Reports"
    ],
    notIncluded: [],
    ctaText: "Choose Basic",
    learnMoreHref: "/quantum-readiness-assessment",
    popular: false
  },
  {
    name: "Pro",
    description: "Operational PQC readiness for teams that need active monitoring, migration planning, and production crypto tooling.",
    priceMonthly: 30,
    priceYearly: 20,
    badge: "MOST POPULAR",
    icon: Zap,
    features: [
      "Everything in Starter and Basic",
      "Scan, discover and monitor your cryptographic asset inventory",
      "Assets and CBOM Explorer",
      "Migration Planner, Timeline and Sandbox Analysis",
      "PQC-Auth Identity Migration Engine",
      "PQC orchestration, Live Migration ops, Rollback",
      "Runtime & Cryptographic Intelligence",
      "Supply Chain Readiness Center",
      "Harvest Now, Decrypt Later Center",
      "Trust Chain Analysis",
      "Crypto Agility Engine",
      "Email Support"
    ],
    notIncluded: [],
    ctaText: "Choose Pro",
    learnMoreHref: "/post-quantum-migration-platform",
    popular: true
  },
  {
    name: "Elite",
    description: "Enterprise-grade crypto-agility for organizations that require governed migration, QKMS operations, and live assurance.",
    priceMonthly: 199,
    priceYearly: 150,
    badge: "ENTERPRISE AGILITY",
    icon: Sparkles,
    features: [
      "Everything in Starter, Basic, and Pro",
      "Discover and govern the full enterprise cryptographic estate",
      "Full QKMS overview, inventory, governance, and readiness",
      "Email Support",
      "Control mapping for SOC 2, PCI DSS 4.0.1, NIST and custom frameworks"
    ],
    notIncluded: [],
    ctaText: "Choose Elite",
    learnMoreHref: "/quantum-trust-governance-center",
    popular: false
  }
];

const FAQ_CATEGORIES = [
  { key: "q-day", label: "Q-Day & Threats" },
  { key: "migration", label: "PQC Migration" },
  { key: "vault", label: "Quantum Vault" },
  { key: "keygen", label: "Key Generation" }
] as const;

const FAQ_DATA = {
  "q-day": [
    {
      question: "What is Q-Day?",
      answer: "Q-Day is the point at which a cryptographically relevant quantum computer (CRQC) can break widely-used public-key cryptography such as RSA and elliptic curve. No government or standards body has put a date on it, and credible expert surveys span roughly 2030 to 2040 with wide uncertainty. Planning does not depend on the date: NIST IR 8547 deprecates RSA, Diffie-Hellman, ECDH and ECDSA after 2030 and disallows them after 2035, so the migration deadline is already published."
    },
    {
      question: "What is a \"Harvest Now, Decrypt Later\" (HNDL) attack?",
      answer: "An adversary records encrypted traffic or copies encrypted archives today and stores them until a CRQC can recover the keys. CISA, the NSA and NIST describe this in their joint Quantum-Readiness guidance as the reason to migrate before a quantum computer exists. The exposure is proportional to how long the data must stay confidential, so health records, financial data, legal archives and government material are affected first."
    },
    {
      question: "How does Shor's algorithm threaten my encryption?",
      answer: "Shor's algorithm solves integer factorization and discrete logarithms in polynomial time, the two problems RSA and elliptic-curve cryptography rely on. It requires a large-scale, fault-tolerant quantum computer, which does not exist today. When one does, it breaks RSA, Diffie-Hellman, ECDH and ECDSA, which are the foundations of TLS, SSH, VPNs and most digital signatures in use now."
    },
    {
      question: "What is Grover's algorithm and why does it matter for symmetric encryption?",
      answer: "Grover's algorithm gives a quadratic speedup for unstructured search, which is often summarised as halving a symmetric key's strength. That summary overstates the effect: Grover parallelizes poorly, and NIST built a maximum-circuit-depth constraint into its own post-quantum security categories for exactly this reason. NIST has not deprecated AES-128, and the transition described in NIST IR 8547 targets public-key algorithms, not AES. AES-256 remains the recommendation for long-lived confidentiality and is the AES key size NSA CNSA 2.0 requires."
    },
    {
      question: "Is the quantum threat real today or just theoretical?",
      answer: "The planning problem is real today, because Harvest Now, Decrypt Later does not require the adversary to own a quantum computer yet. No machine has been demonstrated that breaks RSA-2048, and no standards body calls the threat imminent. NIST published FIPS 203, 204 and 205 on 13 August 2024 because migrating an enterprise estate takes years, and NIST IR 8547 sets 2030 for deprecation and 2035 for disallowance to make that runway explicit."
    }
  ],
  migration: [
    {
      question: "What is Post-Quantum Cryptography (PQC)?",
      answer: "PQC refers to cryptographic algorithms designed to resist both classical and quantum attack. NIST finalized three standards on 13 August 2024: ML-KEM (FIPS 203) for key establishment, ML-DSA (FIPS 204) for digital signatures, and SLH-DSA (FIPS 205) for stateless hash-based signatures. SLH-DSA is the standardized form of the SPHINCS+ submission. NIST selected HQC in March 2025 as a backup key-establishment algorithm, and FN-DSA (FIPS 206) is still in draft."
    },
    {
      question: "How does QGuard plan and run a migration?",
      answer: "Discovery scans your endpoints, certificates, repositories and infrastructure for quantum-vulnerable primitives such as RSA, ECDSA, Diffie-Hellman and SHA-1, and builds a CBOM from what it finds. Migration Planner turns that inventory into a sequenced plan, Migration Sandbox models the change before you make it, and Live Migration Ops runs approved waves with snapshots and rollback. ML-KEM replaces key establishment and ML-DSA or SLH-DSA replaces signatures. How long it takes depends on your estate, your vendors and your protocol support, so the platform measures it rather than promising a figure."
    },
    {
      question: "What is hybrid mode migration?",
      answer: "A hybrid key exchange derives the session secret from both a classical algorithm and ML-KEM, so the connection holds if either one does. The IETF design is already deployed in TLS 1.3 as X25519MLKEM768. It keeps backward compatibility with clients that have not migrated while protecting recorded traffic against a future CRQC. QGuard detects which of your endpoints negotiate a hybrid group and flags the ones that still fall back to classical-only key exchange."
    },
    {
      question: "Will PQC migration break my existing systems?",
      answer: "QGuard uses rollback-safe migration snapshots before applying any changes. Hybrid mode ensures backward compatibility throughout. You can also run the migration in a staging environment first. Our compliance report generation gives you full audit trails for every change made."
    },
    {
      question: "Does QGuard support CI/CD pipeline integration?",
      answer: "QGuard ships signed collection agents for Windows, Linux and macOS that run scheduled scans against infrastructure you control and report into your tenant, and a REST API under /api/v1 for starting scans and pulling results programmatically. Repository and dependency scanning reads source and manifests directly. A packaged CI plugin that fails a build on a quantum-vulnerable finding is on the roadmap and is not available today."
    }
  ],
  vault: [
    {
      question: "What is the Quantum Vault?",
      answer: "Quantum Vault comes in two forms. The desktop and mobile vault in QGuard Messaging is strictly on-device: files are sealed into encrypted containers that never leave your machine. The workspace vault in the dashboard encrypts every file in your browser before upload, so only ciphertext is stored and the server never holds your plaintext or your keys. Both are zero-knowledge, and in both cases a full server breach exposes nothing readable."
    },
    {
      question: "What encryption does the Quantum Vault use?",
      answer: "File contents are encrypted with AES-256-GCM. The symmetric key is protected using ML-KEM-1024, the FIPS 203 parameter set at NIST security category 5 and the key-establishment strength NSA CNSA 2.0 requires. ML-KEM is a key-encapsulation mechanism, so it protects the file key rather than encrypting the file itself. Integrity is verified with Merkle proofs over the encrypted chunks. No cryptosystem can be guaranteed secure for a fixed number of years, which is why the vault is built to have its algorithms replaced."
    },
    {
      question: "Is the Quantum Vault available offline?",
      answer: "Files synced to your device are accessible offline. Encryption and decryption happen locally using your private key, which never leaves your device. Cross-device sync occurs over an end-to-end encrypted channel when you reconnect."
    },
    {
      question: "What happens to my files if QGuard is shut down?",
      answer: "Your vault key pair is generated and held on your device. QGuard exports your encrypted files together with your key material as a portable archive, and publishes the container format, so the contents can be recovered with any implementation of ML-KEM-1024 and AES-256-GCM. Decryption needs the format plus your passphrase and recovery key; a cryptographic library alone is not enough, because the archive layout has to be parsed."
    }
  ],
  keygen: [
    {
      question: "What is QRNG and why is it better than classical random number generators?",
      answer: "A Quantum Random Number Generator draws entropy from a physical process such as photon arrival times or vacuum fluctuations rather than from a seeded algorithm. Its output still has to be conditioned and health-tested, which is what NIST SP 800-90B validation is for. To be precise about what QGuard does today: keys are generated with the platform cryptographically secure RNG provided by the operating system and Web Crypto, which is an approved construction. Hardware QRNG sourcing is a preview capability, and the QRNG console is labelled as such in the product."
    },
    {
      question: "What key types can QGuard generate?",
      answer: "QGuard generates ML-KEM-512, ML-KEM-768 and ML-KEM-1024 key pairs for key establishment, ML-DSA-44, ML-DSA-65 and ML-DSA-87 signing key pairs, and SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f stateless hash-based signature keys. These are the FIPS 203, 204 and 205 parameter sets the platform implements today; the remaining SLH-DSA sets are not yet exposed."
    },
    {
      question: "How is entropy quality measured?",
      answer: "NIST SP 800-90B does not produce a percentage score. It is a validation methodology that estimates the min-entropy of a noise source in bits per sample and requires continuous health tests on that source. QGuard records the entropy source and the estimator result against every key in QKMS, so you can show an auditor where a key's randomness came from. A vendor quoting a percentage entropy score is giving you a marketing number, not an SP 800-90B result."
    },
    {
      question: "Can I export keys to an HSM or external system?",
      answer: "Keys export in PKCS#8 and PEM, and private key material is always wrapped before it leaves the platform, never sent in plaintext. Standard JWK encodings for ML-KEM and ML-DSA are still IETF drafts, so those are provisional. QGuard discovers and inventories the HSM and KMS bindings already in your estate, including PKCS#11 interfaces and cloud KMS, and its orchestration playbooks cover HSM key rotation. Direct push of generated keys into a specific HSM product is an integration scoped per deployment, not a switch you turn on."
    },
    {
      question: "How do I integrate key generation into my CI/CD pipeline?",
      answer: "QGuard exposes authenticated REST endpoints under /api/v1 so a pipeline can request a key pair and read back the public key and its QKMS record. Private key material is wrapped before it is stored and is never returned in plaintext over the API, because a private key that travels through CI logs is a private key you have to treat as compromised. Where your certificate store or KMS supports it, publish the public key there and keep the private key inside the HSM or KMS boundary."
    }
  ]
};

function padNumber(value: number, size: number) {
  return String(Math.max(0, value)).padStart(size, '0');
}

function getQuantumCountdown(now: Date) {
  if (now >= QUANTUM_MATURITY_TARGET) {
    return [
      { label: 'Years', value: '00' },
      { label: 'Days', value: '000' },
      { label: 'Hours', value: '00' },
      { label: 'Minutes', value: '00' },
      { label: 'Seconds', value: '00' }
    ];
  }

  let years = QUANTUM_MATURITY_TARGET.getFullYear() - now.getFullYear();
  const yearAnchor = new Date(now);
  yearAnchor.setFullYear(now.getFullYear() + years);

  if (yearAnchor > QUANTUM_MATURITY_TARGET) {
    years -= 1;
    yearAnchor.setFullYear(now.getFullYear() + years);
  }

  let remaining = QUANTUM_MATURITY_TARGET.getTime() - yearAnchor.getTime();
  const days = Math.floor(remaining / MS_PER_DAY);
  remaining -= days * MS_PER_DAY;
  const hours = Math.floor(remaining / MS_PER_HOUR);
  remaining -= hours * MS_PER_HOUR;
  const minutes = Math.floor(remaining / MS_PER_MINUTE);
  remaining -= minutes * MS_PER_MINUTE;
  const seconds = Math.floor(remaining / MS_PER_SECOND);

  return [
    { label: 'Years', value: padNumber(years, 2) },
    { label: 'Days', value: padNumber(days, 3) },
    { label: 'Hours', value: padNumber(hours, 2) },
    { label: 'Minutes', value: padNumber(minutes, 2) },
    { label: 'Seconds', value: padNumber(seconds, 2) }
  ];
}

function EnterpriseProtectionShowcase() {
  const [selectedKey, setSelectedKey] = useState<CryptoKey>(CRYPTO_SANDBOX_KEYS[0]);
  const [isRunning, setIsRunning] = useState(false);
  const [consoleLogs, setConsoleLogs] = useState<string[]>([]);
  const [assessmentResult, setAssessmentResult] = useState<'idle' | 'risk' | 'resilient'>('idle');

  const getStatusMeta = (status: CryptoKey['quantumStatus']) => {
    if (status === 'vulnerable') {
      return {
        label: 'QUANTUM-VULNERABLE',
        className: 'bg-red-50 text-red-700 border-red-200'
      };
    }

    if (status === 'symmetric') {
      return {
        label: 'SYMMETRIC RESILIENT',
        className: 'bg-amber-50 text-amber-700 border-amber-200'
      };
    }

    return {
      label: 'NIST PQC',
      className: 'bg-cyan-100 text-cyan-800 border-cyan-300'
    };
  };

  const runAssessment = () => {
    setIsRunning(true);
    setAssessmentResult('idle');
    setConsoleLogs([]);

    const logs = [
      `Initializing cryptographic risk assessment for ${selectedKey.name}...`,
      'Checking algorithm family, key size, and cryptographic purpose...',
      'Mapping exposure against NIST PQC migration guidance...',
      'Evaluating Shor/Grover relevance and post-quantum readiness...'
    ];

    let logIndex = 0;

    const interval = window.setInterval(() => {
      if (logIndex < logs.length) {
        const nextLog = logs[logIndex];
        setConsoleLogs((prev) => [...prev, nextLog]);
        logIndex += 1;
        return;
      }

      window.clearInterval(interval);
      setIsRunning(false);

      if (selectedKey.quantumStatus === 'vulnerable') {
        setConsoleLogs((prev) => [
          ...prev,
          `>> FINDING: ${selectedKey.name} relies on a quantum-vulnerable public-key hardness assumption.`,
          ">> IMPACT: A future cryptographically relevant quantum computer could break this algorithm class using Shor's algorithm.",
          '! ACTION: Prioritize inventory, exposure mapping, crypto-agility, and migration planning toward NIST-approved PQC.'
        ]);
        setAssessmentResult('risk');
        return;
      }

      if (selectedKey.quantumStatus === 'symmetric') {
        setConsoleLogs((prev) => [
          ...prev,
          ">> FINDING: Shor's algorithm does not apply to symmetric ciphers such as AES.",
          ">> IMPACT: Grover's algorithm can reduce brute-force resistance quadratically.",
          'OK STATUS: AES-256 remains appropriate for post-quantum security when implemented correctly.'
        ]);
        setAssessmentResult('resilient');
        return;
      }

      setConsoleLogs((prev) => [
        ...prev,
        `>> FINDING: ${selectedKey.name} is aligned with finalized NIST post-quantum cryptography standards.`,
        ">> IMPACT: No known efficient quantum attack equivalent to Shor's attack on RSA/ECC applies.",
        'OK STATUS: Suitable PQC migration target, subject to correct implementation, validation, and protocol support.'
      ]);
      setAssessmentResult('resilient');
    }, 850);
  };

  useEffect(() => {
    setConsoleLogs([
      `Console ready. Selected cryptographic primitive: ${selectedKey.name}.`,
      'Awaiting quantum risk assessment trigger...'
    ]);
    setAssessmentResult('idle');
  }, [selectedKey]);

  return (
    <section
      id="simulator"
      className="mt-24 overflow-hidden border-t-2 border-slate-950 bg-slate-50 bg-[radial-gradient(#e2e8f0_1.5px,transparent_1.5px)] bg-[size:24px_24px] py-24 relative"
    >
      <div className="absolute right-0 bottom-0 h-80 w-80 rounded-full bg-cyan-100/30 blur-[80px]" />
      <div className="absolute left-0 top-0 h-80 w-80 bg-cyan-100/20 blur-[80px]" />

      <div className="relative z-10 mx-auto max-w-7xl px-6">
        <div className="mx-auto mb-16 max-w-3xl space-y-4 text-center">
          <div className="inline-flex">
            <span className="inline-flex items-center gap-1.5 rounded-none border-2 border-slate-950 bg-white px-3 py-1 font-mono text-xs font-bold leading-none tracking-widest text-slate-950 shadow-[2px_2px_0px_rgba(9,13,22,0.15)] select-none">
              <Sparkles className="h-3.5 w-3.5 animate-pulse text-[#00c5eb]" />
              INTERACTIVE CRYPTOGRAPHIC PLAYGROUND
            </span>
          </div>

          <h2 className="mt-2 text-2xl font-black uppercase tracking-tight text-[#090d16] md:text-3xl select-none">
            QUANTUM RISK ASSESSMENT SANDBOX
          </h2>

          <p className="mx-auto max-w-xl font-mono text-xs leading-relaxed tracking-wide text-slate-500 sm:text-sm select-none">
            Simulate how cryptographic discovery identifies quantum-vulnerable
            RSA/ECC assets, symmetric-key resilience, and NIST-standardized PQC
            migration targets such as ML-KEM, ML-DSA, and SLH-DSA.
          </p>
        </div>

        <div className="grid grid-cols-1 items-stretch gap-8 lg:grid-cols-12">
          <div className="relative flex flex-col justify-between rounded-none border-2 border-slate-950 bg-white p-6 shadow-[4px_4px_0px_#090d16] lg:col-span-5">
            <div className="space-y-4">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <span className="font-mono text-[10px] font-bold uppercase tracking-widest text-slate-400 select-none">
                  AVAILABLE CRYPTO PRIMITIVES
                </span>

                <span className="flex items-center gap-1 font-mono text-[10px] uppercase tracking-wide text-slate-500 select-none">
                  <Key className="h-3 w-3" /> Select to assess
                </span>
              </div>

              <div className="space-y-3">
                {CRYPTO_SANDBOX_KEYS.map((cryptoKey) => {
                  const isSelected = selectedKey.name === cryptoKey.name;
                  const statusMeta = getStatusMeta(cryptoKey.quantumStatus);

                  return (
                    <button
                      key={cryptoKey.name}
                      type="button"
                      onClick={() => {
                        if (!isRunning) setSelectedKey(cryptoKey);
                      }}
                      className={`relative flex w-full items-center justify-between overflow-hidden rounded-none border p-4 text-left transition-all ${
                        isSelected
                          ? 'border-2 border-[#090d16] bg-cyan-50/25 shadow-[2px_2px_0px_rgba(9,13,22,0.1)]'
                          : 'border-slate-200 bg-white hover:border-[#090d16] hover:bg-slate-50'
                      } ${isRunning ? 'cursor-not-allowed opacity-60' : 'cursor-pointer'}`}
                    >
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-xs font-bold uppercase tracking-wide text-slate-950 select-none">
                            {cryptoKey.name}
                          </span>

                          <span className={`rounded-none border px-1.5 py-0.5 font-mono text-[8px] font-extrabold uppercase tracking-wider select-none ${statusMeta.className}`}>
                            {statusMeta.label}
                          </span>
                        </div>

                        <span className="mt-1 block font-mono text-[9px] uppercase tracking-widest text-slate-400 select-none">
                          {cryptoKey.type}
                        </span>
                      </div>

                      <div className="text-right">
                        <span className="font-mono text-[11px] font-bold text-slate-700 select-none">
                          {cryptoKey.keySize}
                        </span>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="mt-8 flex items-center gap-4 border-t-2 border-dashed border-slate-200 pt-6">
              <div className="flex-shrink-0 border-2 border-slate-900 bg-slate-50 p-3 text-slate-950">
                <Shield className="h-5 w-5 text-[#090d16]" />
              </div>

              <div className="text-left text-[11px]">
                <p className="font-mono font-extrabold uppercase tracking-wider text-slate-950 select-none">
                  Recommended Defense Alignment:
                </p>

                <p className="mt-1 leading-relaxed text-slate-500">
                  Align migration with NIST FIPS 203 ML-KEM for key
                  establishment, FIPS 204 ML-DSA for digital signatures, and
                  FIPS 205 SLH-DSA where stateless hash-based signatures are
                  appropriate.
                </p>
              </div>
            </div>
          </div>

          <div className="quantum-sandbox-console relative flex min-h-[460px] flex-col justify-between border-2 border-[#090d16] bg-[#040810] p-6 font-mono text-white shadow-[6px_6px_0px_#090d16] lg:col-span-7">
            <div className="absolute top-0 inset-x-0 h-[3px] bg-[#00c5eb]" />

            <div>
              <div className="flex items-center justify-between border-b border-slate-900 pb-3.5 select-none">
                <div className="flex items-center gap-1.5">
                  <div className="h-2 w-2 rotate-45 rounded-none bg-rose-500" />
                  <div className="h-2 w-2 rotate-45 rounded-none bg-amber-500" />
                  <div className="h-2 w-2 rotate-45 rounded-none bg-emerald-500" />

                  <span className="ml-2 font-mono text-[9px] font-bold uppercase tracking-widest text-slate-400">
                    PQC_RISK_ASSESSMENT_CORE
                  </span>
                </div>

                <span className="font-mono text-[9px] font-bold tracking-widest text-[#00c5eb]">
                  STATUS: READY
                </span>
              </div>

              <div className="my-5 grid grid-cols-1 gap-4 border border-slate-900 bg-[#0a101d] p-4 text-left sm:grid-cols-3">
                <div>
                  <span className="mb-1 block font-mono text-[8px] font-bold uppercase tracking-widest text-slate-500 select-none">
                    ALGORITHM / STANDARD
                  </span>

                  <span className="font-mono text-[10px] font-bold text-slate-300 select-text">
                    {selectedKey.structure}
                  </span>
                </div>

                <div>
                  <span className="mb-1 block font-mono text-[8px] font-bold uppercase tracking-widest text-slate-500 select-none">
                    QUANTUM ATTACK MODEL
                  </span>

                  <span className="font-mono text-[10px] font-bold text-slate-300 select-text">
                    {selectedKey.quantumAttackModel}
                  </span>
                </div>

                <div>
                  <span className="mb-1 block font-mono text-[8px] font-bold uppercase tracking-widest text-slate-500 select-none">
                    RISK ASSESSMENT
                  </span>

                  <span
                    className={`font-mono text-[10px] font-bold select-text ${
                      selectedKey.quantumStatus === 'vulnerable'
                        ? 'text-red-400'
                        : 'text-[#00c5eb]'
                    }`}
                  >
                    {selectedKey.assessment}
                  </span>
                </div>
              </div>

              <div className="min-h-[140px] max-h-48 space-y-2 overflow-y-auto pr-2 text-left text-[11px] leading-relaxed tracking-wide">
                {consoleLogs.map((log, index) => (
                  <motion.div
                    key={`${log}-${index}`}
                    initial={{ opacity: 0, x: -3 }}
                    animate={{ opacity: 1, x: 0 }}
                    className={
                      log?.startsWith('!')
                        ? 'font-bold text-red-400'
                        : log?.startsWith('OK')
                          ? 'font-bold text-emerald-400'
                          : log?.startsWith('>>')
                            ? 'font-bold text-cyan-400'
                            : 'text-slate-400'
                    }
                  >
                    <span className="mr-2 text-slate-600 select-none">
                      [{new Date().toLocaleTimeString('en-US', { hour12: false })}]
                    </span>

                    <span className="select-text">{log}</span>
                  </motion.div>
                ))}

                {isRunning && (
                  <div className="mt-3 flex items-center justify-start gap-2 font-bold text-[#00c5eb]">
                    <RefreshCw className="h-3 w-3 animate-spin" />
                    <span>Evaluating quantum-relevant cryptographic exposure...</span>
                  </div>
                )}
              </div>
            </div>

            <div className="mt-6 flex flex-col items-center justify-between gap-4 border-t border-slate-900 pt-6 sm:flex-row">
              <div className="w-full text-left sm:w-auto">
                <AnimatePresence mode="wait">
                  {assessmentResult === 'idle' && (
                    <motion.span
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="block font-mono text-[9px] uppercase tracking-wider text-slate-500 select-none"
                    >
                      * Run assessment to classify the selected primitive
                      against quantum-relevant risk models.
                    </motion.span>
                  )}

                  {assessmentResult === 'risk' && (
                    <motion.div
                      initial={{ opacity: 0, scale: 0.95 }}
                      animate={{ opacity: 1, scale: 1 }}
                      exit={{ opacity: 0 }}
                      className="inline-flex items-center gap-2 border border-red-500 bg-red-950/20 px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider text-red-400 select-none"
                    >
                      <AlertTriangle className="h-4 w-4 shrink-0 text-red-500" />
                      <span>QUANTUM MIGRATION REQUIRED</span>
                    </motion.div>
                  )}

                  {assessmentResult === 'resilient' && (
                    <motion.div
                      initial={{ opacity: 0, scale: 0.95 }}
                      animate={{ opacity: 1, scale: 1 }}
                      exit={{ opacity: 0 }}
                      className="inline-flex items-center gap-2 border border-emerald-500 bg-emerald-950/20 px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider text-emerald-400 select-none"
                    >
                      <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
                      <span>POST-QUANTUM RISK ACCEPTABLE</span>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>

              <button
                type="button"
                disabled={isRunning}
                onClick={runAssessment}
                className="inline-flex w-full items-center justify-center rounded-none border-2 border-[#00c5eb] bg-[#00c5eb] px-5 py-3 text-center font-mono text-[10.5px] font-extrabold uppercase tracking-wide text-slate-950 transition-all duration-150 hover:bg-[#00c5eb]/90 active:scale-95 disabled:cursor-not-allowed disabled:bg-slate-800 disabled:text-slate-500 select-none sm:w-auto sm:tracking-widest"
              >
                <Terminal className="mr-1.5 h-3.5 w-3.5 shrink-0 text-slate-950" />
                {isRunning ? 'Assessment Running...' : 'Run Quantum Risk Assessment'}
              </button>
            </div>
          </div>
        </div>

        <div className="mt-8 flex justify-center">
          <a
            href="/resources/quantum-simulation"
            className="inline-flex w-full max-w-xs items-center justify-center rounded-none border-2 border-[#090d16] bg-[#d4af37] px-5 py-3 text-center font-mono text-[10px] font-extrabold uppercase tracking-wide text-slate-950 no-underline shadow-[4px_4px_0px_#090d16] transition-all duration-150 hover:bg-[#d4af37]/90 active:scale-95 sm:w-auto sm:max-w-none sm:tracking-widest"
          >
            <ArrowRight className="mr-1.5 h-3.5 w-3.5 shrink-0 text-slate-950" />
            See Quantum Simulations
          </a>
        </div>
      </div>
    </section>
  );
}

function RoadmapSection() {
  const [selectedId, setSelectedId] = useState<string>("01");
  const currentMilestone =
    ROADMAP_MILESTONES.find((milestone) => milestone.id === selectedId) || ROADMAP_MILESTONES[0];

  return (
    <section
      id="roadmap"
      className="relative overflow-hidden border-t-2 border-slate-950 bg-white bg-[radial-gradient(#e2e8f0_1.5px,transparent_1.5px)] bg-[size:24px_24px] py-24"
    >
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(rgba(2,6,23,0.02)_1px,transparent_1px)] bg-[size:20px_20px]" />

      <div className="relative z-10 mx-auto max-w-7xl px-6">
        <div className="mx-auto mb-16 max-w-3xl space-y-4 text-center select-none">
          <span className="rounded-none border-2 border-slate-950 bg-slate-50 px-3 py-1.5 font-mono text-[10px] font-bold uppercase leading-none tracking-widest text-[#000] shadow-[2px_2px_0px_rgba(9,13,22,0.15)]">
            NIST-ALIGNED PQC ROADMAP
          </span>

          <h2 className="mt-4 font-sans text-3xl font-black uppercase leading-none tracking-tight text-slate-950 md:text-4xl">
            2026-2029 POST-QUANTUM MIGRATION PLAN
          </h2>

          <p className="mx-auto max-w-xl font-mono text-xs leading-relaxed tracking-wide text-slate-500 sm:text-sm">
            A phased enterprise roadmap for discovering quantum-vulnerable
            cryptography, prioritizing migration, piloting NIST-standardized
            PQC, and operating continuous crypto-agility.
          </p>
        </div>

        <div className="grid grid-cols-1 items-start gap-8 lg:grid-cols-12">
          <div className="space-y-4 lg:col-span-12 xl:col-span-5">
            <div className="mb-4 border-b border-dashed border-slate-200 pb-2 text-left font-mono text-xs font-bold uppercase tracking-widest text-slate-400 select-none">
              // MIGRATION PHASES: 2026 - 2029
            </div>

            <div className="relative space-y-6 pl-6 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-[2px] before:bg-slate-200">
              {ROADMAP_MILESTONES.map((milestone) => {
                const isSelected = milestone.id === selectedId;
                const dotStyle =
                  milestone.status === "active"
                    ? "bg-[#00c5eb] border-slate-950 border-2 scale-125 animate-pulse"
                    : "bg-white border-slate-900 border-2";

                return (
                  <button
                    type="button"
                    key={milestone.id}
                    className="group relative w-full cursor-pointer text-left"
                    onClick={() => setSelectedId(milestone.id)}
                  >
                    <div
                      className={`absolute -left-[21px] top-1.5 z-10 h-3.5 w-3.5 rounded-full transition-all duration-300 ${dotStyle}`}
                    />

                    <div
                      className={`rounded-none border-2 p-4 text-left transition-all duration-200 ${
                        isSelected
                          ? "pqc-roadmap-phase--selected translate-x-1.5 border-slate-950 bg-[#040810] text-white shadow-[4px_4px_0px_rgba(0,197,235,1)]"
                          : "border-slate-900 bg-white text-slate-900 shadow-[2px_2px_0px_#090d16] hover:bg-slate-50"
                      }`}
                    >
                      <div className="flex items-center justify-between pointer-events-none select-none">
                        <span
                          className={`font-mono text-[10px] font-bold tracking-wider ${
                            isSelected ? "text-[#00c5eb]" : "text-slate-500"
                          }`}
                        >
                          {milestone.quarter}
                        </span>

                        <span
                          className={`rounded-none px-2 py-0.5 font-mono text-[8px] font-black uppercase ${
                            milestone.status === "active"
                              ? "border border-cyan-400 bg-cyan-100 text-cyan-950"
                              : "border border-slate-200 bg-slate-100 text-slate-600"
                          }`}
                        >
                          {milestone.statusLabel}
                        </span>
                      </div>

                      <h4 className="mt-2 font-sans text-sm font-black uppercase tracking-tight select-none">
                        {milestone.title}
                      </h4>

                      <p
                        className={`mt-0.5 font-mono text-[10px] uppercase tracking-wider select-none ${
                          isSelected ? "text-amber-400" : "text-slate-400"
                        }`}
                      >
                        {milestone.subtitle}
                      </p>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="lg:col-span-12 xl:col-span-7">
            <AnimatePresence mode="wait">
              <motion.div
                key={selectedId}
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ duration: 0.25 }}
                className="pqc-roadmap-detail relative overflow-hidden rounded-none border-2 border-[#090d16] bg-[#040810] p-6 text-left text-white shadow-[6px_6px_0px_#090d16] md:p-8"
              >
                <div className="absolute top-0 inset-x-0 h-[3px] bg-[#00c5eb]" />
                <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:16px_16px]" />

                <div className="relative z-10 space-y-6">
                  <div className="flex flex-wrap items-center justify-between gap-3 border-b border-dashed border-slate-900 pb-4 select-none">
                    <div className="flex items-center gap-2">
                      <div className="rounded-none border border-slate-900 bg-slate-950 p-1 px-2.5 font-mono text-[10px] font-bold text-cyan-400">
                        PHASE {currentMilestone.id}
                      </div>

                      <span className="font-mono text-[10px] uppercase tracking-wider text-slate-500">
                        // NIST PQC MIGRATION UNIT
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5 font-mono text-xs font-bold uppercase text-yellow-400">
                      <Calendar className="h-4 w-4 shrink-0 text-yellow-400" />
                      {currentMilestone.quarter}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <span className="block font-mono text-[10px] font-bold uppercase tracking-widest text-[#00c5eb] select-none">
                      OBJECTIVE FOCUS
                    </span>

                    <h3 className="font-sans text-xl font-black uppercase tracking-tight text-white md:text-2xl select-none">
                      {currentMilestone.title}
                    </h3>

                    <p className="max-w-2xl font-sans text-xs leading-relaxed text-slate-300 select-text">
                      {currentMilestone.description}
                    </p>
                  </div>

                  <div className="grid grid-cols-2 gap-4 rounded-none border border-slate-900 bg-[#0a101d] p-4 select-none">
                    {currentMilestone.metrics.map((metric) => (
                      <div key={metric.name} className="space-y-1">
                        <span className="block font-mono text-[9px] uppercase tracking-wider text-slate-500">
                          {metric.name}
                        </span>

                        <span className="font-mono text-base font-black tracking-wider text-white">
                          {metric.val}
                        </span>
                      </div>
                    ))}
                  </div>

                  <div className="space-y-3 pt-2">
                    <span className="block font-mono text-[10px] font-bold uppercase tracking-widest text-[#00c5eb] select-none">
                      KEY DELIVERABLES & CONTROLS:
                    </span>

                    <ul className="space-y-2.5">
                      {currentMilestone.deliverables.map((item, index) => (
                        <li
                          key={`${currentMilestone.id}-${index}`}
                          className="flex items-start gap-2.5 text-slate-300"
                        >
                          <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-[#00c5eb]" />

                          <span className="font-sans text-xs font-medium leading-relaxed tracking-wide select-text">
                            {item}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="flex flex-wrap items-center justify-between gap-4 border-t border-dashed border-slate-900 pt-4 select-none">
                    <span className="font-mono text-[9px] uppercase tracking-widest text-slate-500">
                      // TARGET: INVENTORY - PRIORITIZE - MIGRATE - VALIDATE
                    </span>

                    <div className="flex items-center gap-1.5 font-sans text-xs tracking-wide text-slate-400">
                      <span className="h-2 w-2 rounded-full bg-[#00c5eb] animate-pulse" />
                      Crypto-agility roadmap online
                    </div>
                  </div>
                </div>
              </motion.div>
            </AnimatePresence>
          </div>
        </div>
      </div>
    </section>
  );
}

function QuantumSecurityUseCasesSection() {
  const [activeIndex, setActiveIndex] = useState(2);
  const [progress, setProgress] = useState(0);
  const activeFeature = QUANTUM_USE_CASES[activeIndex];
  const ActiveIcon = activeFeature.icon;

  useEffect(() => {
    setProgress(0);
  }, [activeIndex]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setProgress((current) => Math.min(100, current + 2));
    }, USE_CASE_CYCLE_MS / 50);

    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setActiveIndex((current) => (current + 1) % QUANTUM_USE_CASES.length);
    }, USE_CASE_CYCLE_MS);

    return () => window.clearInterval(timer);
  }, []);

  return (
    <motion.section
      id="use-cases"
      initial={{ opacity: 0, y: 36 }}
      whileInView={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.75 }}
      viewport={{ once: true, amount: 0.15 }}
      className="relative mt-24 scroll-mt-24 overflow-hidden rounded-2xl border border-gold/18 bg-cyber-navy/25 p-6 shadow-[0_30px_120px_rgba(0,0,0,0.46)] backdrop-blur-2xl sm:p-10"
    >
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_16%_16%,rgba(212,175,55,0.14),transparent_32%),radial-gradient(circle_at_82%_24%,rgba(255,243,193,0.08),transparent_34%),linear-gradient(180deg,rgba(212,175,55,0.04),transparent_48%,rgba(212,175,55,0.03))]" />
      <div className="pointer-events-none absolute inset-0 opacity-35 [background-image:radial-gradient(circle,rgba(212,175,55,0.24)_1px,transparent_1px)] [background-size:32px_32px]" />

      <div className="relative z-10">
        <header className="mx-auto mb-12 max-w-5xl text-center md:mb-16">
          <div className="mb-5 flex flex-wrap items-center justify-center gap-3 sm:gap-4">
            <span className="hidden h-px w-24 bg-gradient-to-r from-transparent via-gold/70 to-transparent sm:block" />
            <span className="rounded-full border border-gold/25 bg-gold/10 px-4 py-2 font-mono text-[11px] font-bold uppercase tracking-[0.18em] text-gold">
              Applied Quantum Defense
            </span>
            <span className="coming-soon-badge">
              <span className="coming-soon-badge__dot animate-pulse" />
              Coming Soon
            </span>
            <span className="hidden h-px w-24 bg-gradient-to-r from-transparent via-gold/70 to-transparent sm:block" />
          </div>
          <h3 className="text-4xl font-black uppercase leading-[1.02] tracking-[0.08em] text-white md:text-6xl">
            Quantum Encryption Services
            <span className="mt-2 block text-gold gold-glow">Use Cases</span>
          </h3>
          <div className="mx-auto mt-6 flex w-full max-w-xl items-center justify-center gap-3">
            <span className="h-px flex-1 bg-gradient-to-r from-transparent via-gold/55 to-transparent" />
            <span className="h-3 w-3 rotate-45 rounded-[3px] border border-gold/75 shadow-[0_0_18px_rgba(212,175,55,0.65)]" />
            <span className="h-px flex-1 bg-gradient-to-r from-transparent via-gold/55 to-transparent" />
          </div>
          <p className="mx-auto mt-6 max-w-2xl text-sm leading-7 text-muted-foreground md:text-base">
            Applying NIST-standardized post-quantum cryptography to the services enterprises depend on.
          </p>
          <p className="coming-soon-note mx-auto mt-4 max-w-2xl">
            Roadmap preview &mdash; these quantum encryption services are planned QGuard Helix capabilities. They are not yet available in the platform.
          </p>
        </header>

        <div className="grid items-start gap-8 lg:grid-cols-[minmax(300px,380px)_1fr] lg:gap-10">
          <div className="flex gap-4 overflow-x-auto pb-3 lg:flex-col lg:gap-3 lg:overflow-visible lg:pb-0">
            {QUANTUM_USE_CASES.map((feature, index) => {
              const Icon = feature.icon;
              const isActive = activeIndex === index;

              return (
                <button
                  key={feature.id}
                  type="button"
                  onClick={() => setActiveIndex(index)}
                  className={`group min-w-[280px] rounded-lg border p-4 text-left shadow-[0_18px_60px_rgba(0,0,0,0.22)] backdrop-blur-xl transition-all duration-500 lg:min-w-0 ${isActive
                    ? 'border-gold/75 bg-gold/[0.08] shadow-[0_0_34px_rgba(212,175,55,0.24),0_18px_70px_rgba(0,0,0,0.32)]'
                    : 'border-white/10 bg-white/[0.035] hover:border-gold/40 hover:bg-gold/[0.05] hover:shadow-[0_0_28px_rgba(212,175,55,0.15)]'
                    }`}
                >
                  <div className="grid grid-cols-[32px_minmax(0,1fr)] gap-3">
                    <span className={`mt-1 flex h-8 w-8 items-center justify-center rounded-full border transition-all duration-500 ${isActive
                      ? 'border-gold/60 bg-gold text-cyber-black shadow-[0_0_24px_rgba(212,175,55,0.42)]'
                      : 'border-gold/20 bg-gold/10 text-gold group-hover:border-gold/45'
                      }`}>
                      <Icon className="h-4 w-4" />
                    </span>
                    <span className="min-w-0">
                      <span className={`block font-bold uppercase tracking-wide ${isActive ? 'text-white' : 'text-white/70 group-hover:text-gold'}`}>
                        {feature.title}
                      </span>
                      <span className="mt-1.5 block text-xs leading-5 text-muted-foreground">
                        {feature.description}
                      </span>
                      <span className="mt-3 block h-1 overflow-hidden rounded-full bg-white/10">
                        <span
                          className="block h-full rounded-full bg-gradient-to-r from-gold via-yellow-200 to-gold transition-[width] duration-150"
                          style={{ width: isActive ? `${progress}%` : '0%' }}
                        />
                      </span>
                    </span>
                  </div>
                </button>
              );
            })}
          </div>

          <motion.article
            key={activeFeature.id}
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45 }}
            className="overflow-hidden rounded-xl border border-gold/22 bg-white/[0.045] shadow-[0_26px_96px_rgba(0,0,0,0.45),0_0_40px_rgba(212,175,55,0.14)] backdrop-blur-2xl"
          >
            <div className="relative h-72 overflow-hidden md:h-[380px]">
              <img
                src={activeFeature.image}
                alt={activeFeature.title}
                className="h-full w-full object-cover opacity-82 saturate-75 transition-all duration-700 hover:opacity-95 hover:saturate-100"
              />
              <div className="absolute inset-0 bg-gradient-to-t from-cyber-black via-cyber-black/28 to-transparent" />
              <div className="absolute inset-0 bg-[radial-gradient(circle_at_35%_28%,transparent_16%,rgba(0,2,5,0.28)_58%,rgba(0,2,5,0.78)_100%)]" />
              <span className="coming-soon-badge coming-soon-badge--overlay absolute right-6 top-6">
                <span className="coming-soon-badge__dot animate-pulse" />
                Coming Soon
              </span>
              <div className="absolute left-6 top-6 flex h-14 w-14 items-center justify-center rounded-xl border border-gold/35 bg-cyber-black/62 text-gold shadow-[0_0_24px_rgba(212,175,55,0.28)] backdrop-blur-xl">
                <ActiveIcon className="h-7 w-7" />
              </div>
              <div className="absolute inset-x-0 bottom-0 h-2/3 bg-gradient-to-t from-black/85 via-black/40 to-transparent" />
              <div className="absolute bottom-7 left-7 right-7">
                <h4 className="use-case-hero-title text-3xl font-black leading-none md:text-4xl">
                  {activeFeature.title}
                </h4>
                <p className="use-case-hero-desc mt-3 max-w-2xl text-sm leading-6 md:text-base">
                  {activeFeature.description}
                </p>
              </div>
            </div>

            <div className="grid gap-8 border-t border-gold/12 bg-cyber-black/38 p-7 md:grid-cols-2 md:p-9">
              {[
                { heading: "Real World Use Cases", items: activeFeature.useCases },
                { heading: "Key Features", items: activeFeature.keyFeatures }
              ].map((column) => (
                <div key={column.heading}>
                  <h5 className="mb-5 text-xl font-black leading-tight text-white md:text-2xl">
                    {column.heading}
                  </h5>
                  <ul className="space-y-3">
                    {column.items.map((item) => (
                      <li key={item} className="grid grid-cols-[12px_minmax(0,1fr)] gap-3 text-sm leading-6 text-muted-foreground">
                        <span className="mt-2.5 h-1.5 w-1.5 rounded-full bg-gold shadow-[0_0_12px_rgba(212,175,55,0.78)]" />
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </motion.article>
        </div>
      </div>
    </motion.section>
  );
}

function TrustedLeadersSection() {
  const marqueeLogos = [...TRUSTED_LEADERS, ...TRUSTED_LEADERS];

  return (
    <section className="relative overflow-hidden border-y border-gold/10 bg-cyber-black py-20">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_50%_0%,rgba(212,175,55,0.12),transparent_42%),linear-gradient(180deg,rgba(212,175,55,0.035),transparent)]" />
      <div className="relative z-10 mx-auto max-w-6xl px-6 text-center">
        <motion.h2
          initial={{ opacity: 0, y: 22 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.65 }}
          viewport={{ once: true, amount: 0.45 }}
          className="mb-8 text-3xl font-bold leading-tight tracking-[0.08em] text-white/70 md:text-4xl"
        >
          <span className="block font-medium text-muted-foreground">
            Built Against The Standards That Govern
          </span>
          <span className="mt-3 block text-gold gold-glow">
            Post-Quantum Migration
          </span>
        </motion.h2>

        <motion.div
          initial={{ opacity: 0, y: 18 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.65, delay: 0.1 }}
          viewport={{ once: true, amount: 0.35 }}
          className="relative mx-auto max-w-5xl overflow-hidden rounded-lg border border-gold/15 bg-white/[0.035] py-6 shadow-[0_18px_70px_rgba(0,0,0,0.35)] backdrop-blur-xl"
        >
          <div className="pointer-events-none absolute inset-y-0 left-0 z-10 w-28 bg-gradient-to-r from-cyber-black via-cyber-black/80 to-transparent" />
          <div className="pointer-events-none absolute inset-y-0 right-0 z-10 w-28 bg-gradient-to-l from-cyber-black via-cyber-black/80 to-transparent" />
          <div className="absolute inset-0 bg-[linear-gradient(135deg,rgba(255,255,255,0.08),transparent_35%,rgba(212,175,55,0.08))] opacity-55 pointer-events-none" />

          <motion.div
            className="flex w-max items-center gap-14 px-8"
            animate={{ x: ["0%", "-50%"] }}
            transition={{ duration: 36, repeat: Infinity, ease: "linear" }}
          >
            {marqueeLogos.map((leader, index) => (
              <div
                key={`${leader}-${index}`}
                className="group flex min-w-[118px] items-center justify-center gap-2 text-white/78 transition-all duration-300 hover:text-gold"
              >
                <span className="h-1.5 w-1.5 rounded-full bg-gold/60 shadow-[0_0_12px_rgba(212,175,55,0.8)] transition-transform duration-300 group-hover:scale-125" />
                <span className="font-bold tracking-normal">
                  {leader}
                </span>
              </div>
            ))}
          </motion.div>
        </motion.div>
      </div>
    </section>
  );
}

function triggerPricingConfetti() {
  if (typeof window === 'undefined' || typeof document === 'undefined') return;

  const canvas = document.createElement('canvas');
  const context = canvas.getContext('2d');

  if (!context) return;

  const colors = ["#00c5eb", "#facc15", "#090d16", "#38bdf8", "#fef08a"];
  const particleCount = 150;
  const origin = { x: window.innerWidth / 2, y: window.innerHeight * 0.65 };
  const particles = Array.from({ length: particleCount }, () => {
    const angle = (-90 + (Math.random() - 0.5) * 80) * (Math.PI / 180);
    const speed = 5 + Math.random() * 9;

    return {
      x: origin.x,
      y: origin.y,
      vx: Math.cos(angle) * speed,
      vy: Math.sin(angle) * speed,
      rotation: Math.random() * Math.PI,
      spin: (Math.random() - 0.5) * 0.35,
      size: 5 + Math.random() * 7,
      color: colors[Math.floor(Math.random() * colors.length)],
      alpha: 1
    };
  });
  const start = performance.now();
  const duration = 1250;

  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
  canvas.style.position = 'fixed';
  canvas.style.inset = '0';
  canvas.style.pointerEvents = 'none';
  canvas.style.zIndex = '9999';
  document.body.appendChild(canvas);

  const draw = (now: number) => {
    const progress = Math.min((now - start) / duration, 1);

    context.clearRect(0, 0, canvas.width, canvas.height);
    particles.forEach((particle) => {
      particle.vy += 0.16;
      particle.x += particle.vx;
      particle.y += particle.vy;
      particle.rotation += particle.spin;
      particle.alpha = 1 - progress;

      context.save();
      context.globalAlpha = Math.max(particle.alpha, 0);
      context.translate(particle.x, particle.y);
      context.rotate(particle.rotation);
      context.fillStyle = particle.color;
      context.fillRect(-particle.size / 2, -particle.size / 2, particle.size, particle.size * 0.58);
      context.restore();
    });

    if (progress < 1) {
      requestAnimationFrame(draw);
      return;
    }

    canvas.remove();
  };

  requestAnimationFrame(draw);
}

type RequestDemoModalProps = {
  isOpen: boolean;
  onClose: () => void;
};

type DemoFormState = {
  name: string;
  email: string;
  organization: string;
  stage: DemoStage;
  whitepaper: boolean;
  message: string;
  /** Honeypot: hidden from people, so only a bot fills it in. */
  website: string;
};

const EMPTY_DEMO_FORM: DemoFormState = {
  name: '',
  email: '',
  organization: '',
  stage: 'researching',
  whitepaper: true,
  message: '',
  website: '',
};

/** How long the modal waits for the API before offering the email fallback. */
const DEMO_REQUEST_TIMEOUT_MS = 25_000;

type DemoSendError = {
  message: string;
  /** Set when the visitor should email the inbox directly instead. */
  inbox: string | null;
};

/** A pre-filled email to the inbox, for when online delivery is unavailable. */
function demoRequestMailto(inbox: string, data: DemoFormState): string {
  const subject = `Demo request: ${data.organization || data.name || 'Qguard Helix'}`;
  const body = [
    `Name: ${data.name}`,
    `Work email: ${data.email}`,
    `Organization: ${data.organization}`,
    `PQC migration: ${demoStageLabel(data.stage)}`,
    `Readiness playbook: ${data.whitepaper ? 'Requested' : 'Not requested'}`,
    '',
    data.message,
  ].join('\n');
  return `mailto:${inbox}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}

function RequestDemoModal({ isOpen, onClose }: RequestDemoModalProps) {
  const [formData, setFormData] = useState<DemoFormState>(EMPTY_DEMO_FORM);
  const [step, setStep] = useState<'form' | 'sending' | 'success'>('form');
  const [sendError, setSendError] = useState<DemoSendError | null>(null);
  const [deliveredTo, setDeliveredTo] = useState<string>(DEMO_REQUEST_INBOX);
  const inFlight = useRef<AbortController | null>(null);

  useEffect(() => () => inFlight.current?.abort(), []);

  useEffect(() => {
    if (!isOpen) {
      return;
    }

    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    return () => {
      document.body.style.overflow = originalOverflow;
    };
  }, [isOpen]);

  const resetModal = () => {
    const pending = inFlight.current;
    inFlight.current = null;
    pending?.abort();
    setFormData(EMPTY_DEMO_FORM);
    setStep('form');
    setSendError(null);
  };

  const handleClose = () => {
    resetModal();
    onClose();
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (step === 'sending') {
      return;
    }

    const parsed = validateDemoRequest(formData);
    if (parsed.ok === false) {
      setSendError({ message: parsed.message, inbox: null });
      return;
    }

    const controller = new AbortController();
    inFlight.current = controller;
    const timeout = window.setTimeout(() => controller.abort(), DEMO_REQUEST_TIMEOUT_MS);
    setSendError(null);
    setStep('sending');

    try {
      const response = await fetch('/api/v1/demo-request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...parsed.value, website: formData.website }),
        signal: controller.signal,
      });
      const payload = (await response.json().catch(() => null)) as
        | { ok?: boolean; inbox?: unknown; error?: { message?: unknown; inbox?: unknown } }
        | null;
      if (inFlight.current !== controller) {
        return;
      }

      if (response.ok && payload?.ok) {
        setDeliveredTo(typeof payload.inbox === 'string' ? payload.inbox : DEMO_REQUEST_INBOX);
        setStep('success');
        return;
      }

      const error = payload?.error;
      setSendError({
        message:
          typeof error?.message === 'string'
            ? error.message
            : `Your request could not be sent. Please email ${DEMO_REQUEST_INBOX}.`,
        inbox: typeof error?.inbox === 'string' ? error.inbox : response.status >= 500 ? DEMO_REQUEST_INBOX : null,
      });
      setStep('form');
    } catch {
      // Closing the modal aborts the request on purpose; only a timeout or a
      // dropped connection is worth telling the visitor about.
      if (inFlight.current !== controller) {
        return;
      }
      setSendError({
        message: `The request did not reach us (timed out or the connection dropped). Please try again, or email ${DEMO_REQUEST_INBOX}.`,
        inbox: DEMO_REQUEST_INBOX,
      });
      setStep('form');
    } finally {
      window.clearTimeout(timeout);
      if (inFlight.current === controller) {
        inFlight.current = null;
      }
    }
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-[120] flex items-center justify-center overflow-y-auto p-4">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={handleClose}
            className="fixed inset-0 bg-slate-950/50 backdrop-blur-md"
          />

          <motion.div
            initial={{ opacity: 0, scale: 0.98, y: 15 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.98, y: 15 }}
            transition={{ duration: 0.15 }}
            role="dialog"
            aria-modal="true"
            aria-labelledby="request-demo-modal-title"
            className="relative w-full max-w-xl overflow-hidden rounded-sm border-4 border-slate-950 bg-white p-8 text-left shadow-2xl"
          >
            <div className="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-cyan-400 via-yellow-300 to-cyan-400" />

            <div className="flex items-center justify-between border-b border-slate-200 pb-4">
              <div className="flex items-center gap-2.5">
                <div className="rounded-sm border border-slate-950 bg-cyan-100 p-2 text-slate-950">
                  <ShieldCheck className="h-5 w-5" />
                </div>
                <div>
                  <h3 id="request-demo-modal-title" className="font-sans text-base font-black uppercase tracking-tight text-slate-950 sm:text-lg">
                    Request Cryptographic Demo
                  </h3>
                  <p className="font-mono text-[9px] uppercase tracking-widest text-slate-500">
                    // Secure PQC Handshake Link
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={handleClose}
                className="cursor-pointer rounded-sm border border-transparent p-1 text-slate-400 transition-colors hover:border-slate-200 hover:bg-slate-100 hover:text-slate-950"
                id="btn-close-modal"
                aria-label="Close request demo modal"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {step !== 'success' && (
              <form onSubmit={handleSubmit} className="mt-6" id="demo-request-form" noValidate>
                <fieldset disabled={step === 'sending'} className="space-y-5">
                <div aria-hidden="true" className="absolute -left-[10000px] h-px w-px overflow-hidden">
                  <label>
                    Website
                    <input
                      type="text"
                      name="website"
                      tabIndex={-1}
                      autoComplete="off"
                      value={formData.website}
                      onChange={(event) => setFormData({ ...formData, website: event.target.value })}
                    />
                  </label>
                </div>

                <div>
                  <label className="mb-1.5 block font-mono text-[10px] font-bold uppercase tracking-widest text-slate-500">
                    Your Name
                  </label>
                  <input
                    type="text"
                    required
                    autoComplete="name"
                    maxLength={DEMO_FIELD_LIMITS.name}
                    value={formData.name}
                    onChange={(event) => setFormData({ ...formData, name: event.target.value })}
                    className="w-full rounded-sm border-2 border-slate-950 bg-white px-4 py-3 font-mono text-xs text-slate-800 transition-all placeholder:text-slate-400 focus:border-cyan-400 focus:outline-none focus:ring-0"
                    placeholder="Enter full name"
                  />
                </div>

                <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
                  <div>
                    <label className="mb-1.5 block font-mono text-[10px] font-bold uppercase tracking-widest text-slate-500">
                      Work Email
                    </label>
                    <input
                      type="email"
                      required
                      autoComplete="email"
                      maxLength={DEMO_FIELD_LIMITS.email}
                      value={formData.email}
                      onChange={(event) => setFormData({ ...formData, email: event.target.value })}
                      className="w-full rounded-sm border-2 border-slate-950 bg-white px-4 py-3 font-mono text-xs text-slate-800 transition-all placeholder:text-slate-400 focus:border-cyan-400 focus:outline-none focus:ring-0"
                      placeholder="name@organization.com"
                    />
                  </div>
                  <div>
                    <label className="mb-1.5 block font-mono text-[10px] font-bold uppercase tracking-widest text-slate-500">
                      Organization
                    </label>
                    <input
                      type="text"
                      required
                      autoComplete="organization"
                      maxLength={DEMO_FIELD_LIMITS.organization}
                      value={formData.organization}
                      onChange={(event) => setFormData({ ...formData, organization: event.target.value })}
                      className="w-full rounded-sm border-2 border-slate-950 bg-white px-4 py-3 font-mono text-xs text-slate-800 transition-all placeholder:text-slate-400 focus:border-cyan-400 focus:outline-none focus:ring-0"
                      placeholder="Agency / Corp"
                    />
                  </div>
                </div>

                <div>
                  <label className="mb-1.5 block font-mono text-[10px] font-bold uppercase tracking-widest text-slate-500">
                    PQC Migration Status
                  </label>
                  <select
                    value={formData.stage}
                    onChange={(event) => setFormData({ ...formData, stage: event.target.value as DemoStage })}
                    className="w-full rounded-sm border-2 border-slate-950 bg-white px-4 py-3 font-mono text-xs text-slate-800 transition-all focus:border-cyan-400 focus:outline-none focus:ring-0"
                  >
                    {DEMO_STAGES.map((stage) => (
                      <option key={stage.value} value={stage.value}>{stage.label}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label
                    htmlFor="demo-request-message"
                    className="mb-1.5 block font-mono text-[10px] font-bold uppercase tracking-widest text-slate-500"
                  >
                    Message <span className="font-normal normal-case tracking-normal text-slate-400">(optional)</span>
                  </label>
                  <textarea
                    id="demo-request-message"
                    rows={4}
                    maxLength={DEMO_FIELD_LIMITS.message}
                    value={formData.message}
                    onChange={(event) => setFormData({ ...formData, message: event.target.value })}
                    className="w-full resize-y rounded-sm border-2 border-slate-950 bg-white px-4 py-3 font-mono text-xs text-slate-800 transition-all placeholder:text-slate-400 focus:border-cyan-400 focus:outline-none focus:ring-0"
                    placeholder="What would you like to see? e.g. your environment, timelines, compliance drivers"
                  />
                </div>

                <label className="flex cursor-pointer select-none items-start gap-3 pt-1">
                  <input
                    type="checkbox"
                    checked={formData.whitepaper}
                    onChange={(event) => setFormData({ ...formData, whitepaper: event.target.checked })}
                    className="mt-1 h-4 w-4 cursor-pointer rounded-sm border-2 border-slate-950 accent-cyan-400 focus:ring-0 focus:ring-offset-0"
                  />
                  <span className="font-mono text-[11px] uppercase leading-relaxed tracking-wide text-slate-500">
                    Check to receive: <strong className="font-bold text-slate-900">"Post-Quantum Readiness Playbook (.pdf)"</strong> — a walkthrough of the NIST migration guidance applied to your estate.
                  </span>
                </label>

                {sendError && (
                  <div
                    role="alert"
                    className="flex items-start gap-2 rounded-sm border-2 border-red-600 bg-red-50 p-3 font-mono text-[11px] leading-relaxed text-red-800"
                  >
                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                    <div>
                      <p>{sendError.message}</p>
                      {sendError.inbox && (
                        <a
                          href={demoRequestMailto(sendError.inbox, formData)}
                          className="mt-1 inline-block font-bold underline hover:text-red-950"
                        >
                          Open an email to {sendError.inbox} with these details
                        </a>
                      )}
                    </div>
                  </div>
                )}

                <div className="mt-6 flex justify-end gap-3 border-t border-slate-200 pt-4">
                  <button
                    type="button"
                    onClick={handleClose}
                    className="cursor-pointer rounded-sm border border-transparent px-5 py-2.5 font-mono text-xs font-bold uppercase tracking-widest text-slate-600 transition-colors hover:border-slate-200 hover:bg-slate-50 hover:text-slate-950"
                    id="btn-cancel-demo"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="flex cursor-pointer items-center gap-1.5 rounded-sm border-2 border-cyan-400 bg-cyan-400 px-6 py-2.5 font-mono text-xs font-black uppercase tracking-widest text-slate-950 transition-all hover:bg-cyan-500 active:scale-95 disabled:cursor-wait disabled:opacity-70"
                    id="btn-submit-demo-form"
                  >
                    {step === 'sending' ? (
                      <>
                        Sending…
                        <Loader className="h-4 w-4 animate-spin text-slate-950" />
                      </>
                    ) : (
                      <>
                        Request Demo
                        <ArrowRight className="h-4 w-4 text-slate-950" />
                      </>
                    )}
                  </button>
                </div>
                </fieldset>
              </form>
            )}

            {step === 'success' && (
              <div className="mt-8 py-4 text-center">
                <div className="mb-4 inline-flex rounded-sm border-2 border-slate-950 bg-cyan-100 p-3 text-slate-950">
                  <ShieldCheck className="h-8 w-8" />
                </div>
                <h4 className="font-sans text-lg font-black uppercase tracking-tight text-slate-950">
                  Demo Request Sent
                </h4>
                <p className="mx-auto mt-2 max-w-sm font-mono text-[11px] uppercase tracking-wide text-slate-500">
                  Thanks, <strong>{formData.name}</strong>. Your request reached <strong>{deliveredTo}</strong>. We will reply to <strong>{formData.email}</strong> to schedule the session for <strong>{formData.organization}</strong>.
                </p>
                <div className="my-5 rounded-sm border-2 border-slate-950 bg-slate-50 p-4 text-left">
                  <div className="grid grid-cols-2 gap-y-2 font-mono text-[10px]">
                    <span className="text-slate-500">CONTACT EMAIL:</span>
                    <span className="font-bold text-slate-900">{formData.email}</span>
                    <span className="text-slate-500">PQC MIGRATION STAGE:</span>
                    <span className="font-bold text-slate-900">{demoStageLabel(formData.stage)}</span>
                    <span className="text-slate-500">READINESS GUIDE:</span>
                    <span className="font-bold text-slate-900">{formData.whitepaper ? 'REQUESTED (.pdf)' : 'NOT REQUESTED'}</span>
                  </div>
                </div>

                <div className="flex justify-center border-t border-slate-200 pt-4">
                  <button
                    type="button"
                    onClick={handleClose}
                    className="cursor-pointer rounded-sm border-2 border-cyan-400 bg-cyan-400 px-6 py-2.5 font-mono text-xs font-black uppercase tracking-widest text-slate-950 transition-all hover:bg-cyan-500 active:scale-95"
                    id="btn-close-demo-success"
                  >
                    Return to Homepage
                  </button>
                </div>
              </div>
            )}
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}

type PricingSectionProps = {
  onRequestDemo: () => void;
};

function PricingSection({ onRequestDemo }: PricingSectionProps) {
  const [billingPeriod, setBillingPeriod] = useState<"monthly" | "yearly">("yearly");

  const handleToggle = (period: "monthly" | "yearly") => {
    if (period === "yearly" && billingPeriod !== "yearly") {
      triggerPricingConfetti();
    }

    setBillingPeriod(period);
  };

  const [checkoutPlan, setCheckoutPlan] = useState<string | null>(null);

  const handleSubscribe = (planName: string) => {
    if (checkoutPlan) return;
    setCheckoutPlan(planName);
    // Route through the auth-gated checkout bridge: it requires sign-in, then
    // creates the PayPal subscription and redirects the user to PayPal.
    window.location.href = `/checkout?plan=${encodeURIComponent(planName)}&cycle=${billingPeriod}`;
  };

  return (
    <motion.section
      id="pricing"
      initial={{ opacity: 0, y: 36 }}
      whileInView={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.75 }}
      viewport={{ once: true, amount: 0.14 }}
      className="relative mt-24 scroll-mt-24 overflow-hidden border-t-2 border-slate-950 bg-white bg-[radial-gradient(#e2e8f0_1.5px,transparent_1.5px)] bg-[size:24px_24px] py-24"
    >
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(rgba(2,6,23,0.01)_1px,transparent_1px)] bg-[size:20px_20px]" />

      <div className="relative z-10 mx-auto max-w-7xl px-6">
        <div className="mx-auto max-w-3xl select-none space-y-4 text-center">
          <span className="inline-flex rounded-none border-2 border-slate-950 bg-slate-50 px-3 py-1.5 font-mono text-[10px] font-bold uppercase leading-none tracking-widest text-[#000] shadow-[2px_2px_0px_rgba(9,13,22,0.15)]">
            Pricing Scheme
          </span>
          <h3 className="mt-4 font-sans text-3xl font-black uppercase leading-none tracking-tight text-slate-950 md:text-4xl">
            Invest in Post-Quantum Transition
          </h3>
          <p className="mx-auto max-w-xl font-mono text-xs leading-relaxed tracking-wide text-slate-500 sm:text-sm">
            Transparent plans tailored to your enterprise migration velocity. Build an evidence-backed cryptographic inventory and measurable crypto-agility.
          </p>
        </div>

        <div className="mt-10 flex justify-center">
          <div className="relative z-10 inline-flex h-[46px] w-[300px] select-none items-center gap-1.5 rounded-none border-2 border-slate-950 bg-white p-1 shadow-[3px_3px_0px_#090d16]">
            <motion.div
              className="absolute bottom-1 top-1 rounded-none bg-slate-950"
              initial={false}
              animate={{
                left: billingPeriod === "monthly" ? "4px" : "150px",
                width: "142px"
              }}
              transition={{ type: "spring", stiffness: 350, damping: 28 }}
            />

            <button
              type="button"
              onClick={() => handleToggle("monthly")}
              aria-pressed={billingPeriod === "monthly"}
              className={`relative z-20 flex-1 cursor-pointer rounded-none py-2 text-center font-mono text-xs font-bold uppercase transition-colors duration-200 ${
                billingPeriod === "monthly"
                  ? "animate-pulse text-[#fff]"
                  : "text-slate-500 hover:text-slate-950"
              }`}
            >
              Monthly
            </button>
            <button
              type="button"
              onClick={() => handleToggle("yearly")}
              aria-pressed={billingPeriod === "yearly"}
              className={`relative z-20 flex flex-1 cursor-pointer items-center justify-center gap-1.5 rounded-none py-2 text-center font-mono text-xs font-bold uppercase transition-colors duration-200 ${
                billingPeriod === "yearly"
                  ? "text-[#fff]"
                  : "text-slate-500 hover:text-slate-950"
              }`}
            >
              Yearly
              <span className={`rounded-none px-1.5 py-0.5 font-sans text-[9px] font-black tracking-tight transition-colors duration-200 ${
                billingPeriod === "yearly"
                  ? "border border-slate-800 bg-slate-900 text-yellow-400"
                  : "bg-yellow-400 text-slate-950"
              }`}>
                -20%
              </span>
            </button>
          </div>
        </div>

        <div className="mt-16 grid grid-cols-1 items-stretch gap-8 md:grid-cols-2 lg:grid-cols-4">
          {PRICING_PLANS.map((plan, idx) => {
            const Icon = plan.icon;
            const price = billingPeriod === "monthly" ? plan.priceMonthly : plan.priceYearly;
            const savings = billingPeriod === "yearly" ? (plan.priceMonthly - plan.priceYearly) * 12 : 0;
            const annualTotal = plan.priceYearly * 12;

            return (
              <motion.div
                key={plan.name}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: "-100px" }}
                transition={{ duration: 0.4, delay: idx * 0.1 }}
                className={`relative flex h-full flex-col justify-between rounded-none border-2 bg-white text-left transition-all duration-200 ${
                  plan.popular
                    ? "z-10 border-[#00c5eb] shadow-[6px_6px_0px_rgba(0,197,235,1)] lg:scale-105"
                    : "border-[#090d16] shadow-[6px_6px_0px_#090d16]"
                }`}
                id={`pricing-plan-${plan.name.toLowerCase()}`}
              >
                <div className={`absolute left-0 right-0 top-0 z-0 h-[3px] ${plan.popular ? "bg-[#00c5eb]" : "bg-[#090d16]"}`} />

                {plan.popular && (
                  <div className="absolute -top-[16px] left-1/2 z-30 -translate-x-1/2 select-none whitespace-nowrap rounded-none border-2 border-slate-950 bg-[#00c5eb] px-3.5 py-1 font-mono text-[9px] font-black uppercase tracking-widest text-slate-950 shadow-md">
                    Recommended for Transition
                  </div>
                )}

                <div className="space-y-6 p-6 md:p-8">
                  <div className="flex select-none items-center justify-between">
                    <span className={`rounded-none border px-2 py-1 font-mono text-[9px] font-bold tracking-wider ${
                      plan.popular
                        ? "border-cyan-300 bg-cyan-50 text-cyan-600"
                        : "border-slate-200 bg-slate-50 text-slate-600"
                    }`}>
                      {plan.badge}
                    </span>
                    <div className={`rounded-none border-2 p-2 ${
                      plan.popular
                        ? "border-[#00c5eb] bg-cyan-50 text-[#00c5eb]"
                        : "border-slate-950 bg-slate-50 text-slate-950"
                    }`}>
                      <Icon className="h-5 w-5" />
                    </div>
                  </div>

                  <div className="select-none">
                    <h4 className="font-sans text-xl font-black uppercase tracking-tight text-slate-950">
                      {plan.name}
                    </h4>
                    <p className="mt-1 min-h-[40px] font-sans text-xs leading-relaxed tracking-wide text-slate-500">
                      {plan.description}
                    </p>
                  </div>

                  <div className="select-none border-y border-dashed border-slate-200 py-4">
                    <div className="flex items-baseline gap-1.5 overflow-hidden">
                      <span className="flex items-center font-mono text-4xl font-black text-slate-950">
                        $
                        <motion.span
                          key={price}
                          initial={{ y: -12, opacity: 0 }}
                          animate={{ y: 0, opacity: 1 }}
                          transition={{ duration: 0.2 }}
                          className="inline-block"
                        >
                          {price}
                        </motion.span>
                      </span>
                      <span className="font-mono text-xs text-slate-400">
                        / month
                      </span>
                    </div>

                    {billingPeriod === "yearly" ? (
                      <p className="mt-1.5 font-mono text-[10px] font-bold uppercase tracking-wide text-emerald-600">
                        ${annualTotal} billed annually{savings > 0 ? ` (Save $${savings}/year)` : ""}
                      </p>
                    ) : (
                      <p className="mt-1.5 font-mono text-[10px] text-slate-400">
                        Cancel or scale active nodes monthly
                      </p>
                    )}
                  </div>

                  <div className="space-y-3">
                    <p className="select-none font-mono text-[10px] font-bold uppercase tracking-wider text-cyan-500">
                      Capabilities Included:
                    </p>
                    <ul className="space-y-2.5 text-xs">
                      {plan.features.map((feat) => (
                        <li key={feat} className="flex items-start gap-2 leading-tight text-slate-700">
                          <Check className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" />
                          <span className="select-text font-sans font-medium tracking-wide">{feat}</span>
                        </li>
                      ))}

                      {plan.notIncluded.map((feat) => (
                        <li key={feat} className="flex select-none items-start gap-2 leading-tight text-slate-400 line-through opacity-65">
                          <span className="ml-1.5 mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-slate-300" />
                          <span className="select-none pl-1 font-sans">{feat}</span>
                        </li>
                      ))}
                    </ul>

                    {plan.learnMoreHref && (
                      <a
                        href={plan.learnMoreHref}
                        className="inline-flex items-center gap-1 font-mono text-[11px] font-bold uppercase tracking-wider text-[#00c5eb] underline-offset-4 transition-colors hover:text-slate-950 hover:underline"
                      >
                        Learn More
                        <ArrowRight className="h-3.5 w-3.5" />
                      </a>
                    )}
                  </div>
                </div>

                <div className="border-t border-dashed border-slate-200 bg-slate-50 p-6 md:p-8">
                  <button
                    type="button"
                    onClick={() => handleSubscribe(plan.name)}
                    disabled={checkoutPlan !== null}
                    className={`w-full cursor-pointer rounded-none border-2 px-4 py-3 text-center font-mono text-xs font-bold uppercase tracking-wider transition-all duration-150 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-70 ${
                      plan.popular
                        ? "border-[#00c5eb] bg-[#00c5eb] text-slate-950 shadow-[2px_2px_0px_#090d16] hover:bg-[#00c5eb]/90"
                        : "border-slate-950 bg-slate-950 text-[#fff] shadow-[2px_2px_0px_rgba(2,6,23,0.3)] hover:bg-slate-800"
                    }`}
                  >
                    {checkoutPlan === plan.name ? "Redirecting to PayPal…" : plan.ctaText}
                  </button>
                  <p className="mt-3 select-none text-center font-mono text-[9px] uppercase tracking-widest text-slate-400">
                    7-day money-back on your first payment
                  </p>
                </div>
              </motion.div>
            );
          })}
        </div>

      </div>
    </motion.section>
  );
}

function FaqAndCtaSection() {
  type FAQCategoryKey = (typeof FAQ_CATEGORIES)[number]["key"];
  const [selectedCategory, setSelectedCategory] = useState<FAQCategoryKey>("q-day");
  const [openIndex, setOpenIndex] = useState<number | null>(null);
  const activeFaqs = FAQ_DATA[selectedCategory];

  const handleCategoryChange = (category: FAQCategoryKey) => {
    setSelectedCategory(category);
    setOpenIndex(null);
  };

  return (
    <motion.section
      id="faq"
      initial={{ opacity: 0, y: 36 }}
      whileInView={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.75 }}
      viewport={{ once: true, amount: 0.14 }}
      className="relative mt-24 scroll-mt-24 overflow-hidden rounded-2xl border border-gold/15 bg-cyber-navy/20 px-6 py-24 shadow-[0_30px_120px_rgba(0,0,0,0.42)] backdrop-blur-2xl sm:px-10"
    >
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_50%_6%,rgba(212,175,55,0.15),transparent_34%),linear-gradient(180deg,transparent_45%,rgba(212,175,55,0.06))]" />
      <div className="pointer-events-none absolute inset-0 opacity-32 [background-image:radial-gradient(circle,rgba(212,175,55,0.22)_1px,transparent_1px)] [background-size:34px_34px]" />

      <div className="relative z-10 mx-auto max-w-5xl">
        <header className="mx-auto mb-8 max-w-3xl text-center">
          <span className="mb-5 inline-flex items-center gap-2 rounded-full border border-gold/25 bg-gold/10 px-4 py-2 font-mono text-[11px] font-bold uppercase tracking-[0.18em] text-gold">
            <span className="h-1.5 w-1.5 rounded-full bg-gold shadow-[0_0_12px_rgba(212,175,55,0.85)]" />
            Got Questions?
          </span>
          <h3 className="text-4xl font-black leading-tight tracking-[0.04em] text-white md:text-5xl">
            Frequently Asked <span className="text-gold gold-glow">Questions</span>
          </h3>
        </header>

        <div className="mb-8 flex flex-wrap items-center justify-center gap-3">
          {FAQ_CATEGORIES.map((category) => {
            const isSelected = selectedCategory === category.key;

            return (
              <button
                key={category.key}
                type="button"
                onClick={() => handleCategoryChange(category.key)}
                className={`min-h-10 rounded-lg border px-5 font-mono text-xs font-bold tracking-[0.08em] transition-all duration-300 ${isSelected
                  ? 'border-gold bg-gold text-cyber-black shadow-[0_0_26px_rgba(212,175,55,0.36)]'
                  : 'border-gold/18 bg-white/[0.035] text-muted-foreground hover:border-gold/50 hover:bg-gold/10 hover:text-gold'
                  }`}
              >
                {category.label}
              </button>
            );
          })}
        </div>

        <motion.div
          key={selectedCategory}
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35 }}
          className="mx-auto flex max-w-4xl flex-col gap-3"
        >
          {activeFaqs.map((faq, index) => {
            const isOpen = openIndex === index;

            return (
              <div
                key={faq.question}
                className={`overflow-hidden rounded-xl border backdrop-blur-xl transition-all duration-300 ${isOpen
                  ? 'border-gold/55 bg-gold/[0.07] shadow-[0_0_28px_rgba(212,175,55,0.18)]'
                  : 'border-gold/14 bg-white/[0.045] hover:border-gold/38 hover:bg-gold/[0.045]'
                  }`}
              >
                <button
                  type="button"
                  onClick={() => setOpenIndex(isOpen ? null : index)}
                  className="flex w-full items-center justify-between gap-5 px-6 py-5 text-left"
                >
                  <span className={`text-sm font-bold leading-6 md:text-base ${isOpen ? 'text-white' : 'text-muted-foreground'}`}>
                    {faq.question}
                  </span>
                  <motion.span
                    animate={{ rotate: isOpen ? 45 : 0 }}
                    transition={{ duration: 0.2 }}
                    className={`shrink-0 ${isOpen ? 'text-gold' : 'text-muted-foreground'}`}
                  >
                    <Plus className="h-5 w-5" />
                  </motion.span>
                </button>
                <motion.div
                  initial={false}
                  animate={{ height: isOpen ? "auto" : 0, opacity: isOpen ? 1 : 0 }}
                  transition={{ duration: 0.3, ease: "easeInOut" }}
                  className="overflow-hidden"
                >
                  <p className="px-6 pb-6 text-sm leading-7 text-muted-foreground">
                    {faq.answer}
                  </p>
                </motion.div>
              </div>
            );
          })}
        </motion.div>

        <div className="mx-auto mt-28 max-w-3xl text-center">
          <h3 className="text-4xl font-black leading-tight tracking-[0.04em] text-white md:text-5xl">
            Ready for <span className="text-gold gold-glow">Quantum Safety?</span>
          </h3>
          <p className="mx-auto mt-5 max-w-xl text-sm leading-7 text-muted-foreground md:text-base">
            Create your free account and start your quantum vulnerability scan today.
          </p>
          <div className="mt-10 flex flex-col items-center justify-center gap-4 sm:flex-row">
            <a href="/auth" className="no-underline">
              <Button className="h-14 rounded-lg bg-gold px-8 font-black uppercase tracking-[0.14em] text-cyber-black shadow-[0_0_28px_rgba(212,175,55,0.32)] transition-all hover:bg-white hover:shadow-[0_0_42px_rgba(212,175,55,0.45)]">
                <Users className="mr-2 h-4 w-4" />
                Create Free Account
              </Button>
            </a>
            <Button
              variant="outline"
              className="h-14 rounded-lg border-gold/55 px-8 font-black uppercase tracking-[0.14em] text-gold transition-all hover:bg-gold/10 hover:text-gold hover:shadow-[0_0_28px_rgba(212,175,55,0.2)]"
            >
              Learn More
            </Button>
          </div>
        </div>
      </div>
    </motion.section>
  );
}

const InactionCard = ({ risk, i }: any) => {
  const [isHovered, setIsHovered] = useState(false);
  const mouseX = useMotionValue(0);
  const mouseY = useMotionValue(0);

  const rotateX = useTransform(mouseY, [-0.5, 0.5], [10, -10]);
  const rotateY = useTransform(mouseX, [-0.5, 0.5], [-10, 10]);

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const width = rect.width;
    const height = rect.height;
    const x = (e.clientX - rect.left) / width - 0.5;
    const y = (e.clientY - rect.top) / height - 0.5;
    mouseX.set(x);
    mouseY.set(y);
  };

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.9 }}
      whileInView={{ opacity: 1, scale: 1 }}
      transition={{ delay: i * 0.1 }}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => {
        setIsHovered(false);
        mouseX.set(0);
        mouseY.set(0);
      }}
      onMouseMove={handleMouseMove}
      style={{
        rotateX: rotateX,
        rotateY: rotateY,
        perspective: 1000,
      }}
      className="relative group cursor-default"
    >
      <motion.div
        animate={{
          backgroundColor: isHovered ? "rgba(220, 38, 38, 0.15)" : "rgba(255, 255, 255, 0.045)",
          borderColor: isHovered ? "rgba(220, 38, 38, 0.6)" : "rgba(212, 175, 55, 0.15)",
          boxShadow: isHovered
            ? "0 0 50px rgba(220, 38, 38, 0.4), inset 0 0 20px rgba(220, 38, 38, 0.2)"
            : "0 20px 70px rgba(0,0,0,0.35)",
          scale: isHovered ? 1.05 : 1,
        }}
        transition={{ type: "spring", stiffness: 300, damping: 20 }}
        className="relative overflow-hidden rounded-2xl border p-8 backdrop-blur-2xl transition-all duration-500 z-10 h-full"
      >
        {/* Holographic Reflections */}
        <div className="absolute inset-0 bg-[linear-gradient(135deg,rgba(255,255,255,0.1),transparent_40%,rgba(212,175,55,0.05))] opacity-40 group-hover:opacity-0 transition-opacity pointer-events-none" />

        {/* Red Corruption Overlay */}
        <motion.div
          animate={{ opacity: isHovered ? 1 : 0 }}
          className="absolute inset-0 bg-radial-gradient from-red-600/20 via-transparent to-transparent pointer-events-none z-0"
        />

        {/* Inner Content */}
        <div className="relative z-20">
          <motion.div
            animate={{
              color: isHovered ? "#ef4444" : "#D4AF37",
              filter: isHovered ? "drop-shadow(0 0 15px rgba(239, 68, 68, 0.8))" : "none",
              scale: isHovered ? 1.2 : 1,
              rotate: isHovered ? [0, -5, 5, -5, 0] : 0
            }}
            transition={{ rotate: { repeat: Infinity, duration: 0.2 } }}
          >
            <risk.icon className="w-12 h-12 mb-6 transition-transform" />
          </motion.div>

          <h3 className={`text-xl font-black uppercase tracking-[0.2em] mb-2 transition-colors duration-300 ${isHovered ? 'text-red-100' : 'text-white'}`}>
            {risk.title}
          </h3>

          <motion.div
            animate={{ color: isHovered ? "#f87171" : "#D4AF37" }}
            className="text-4xl font-black mb-4 font-mono tracking-tighter drop-shadow-[0_0_10px_rgba(0,0,0,0.5)]"
          >
            {risk.val}
          </motion.div>

          <p className={`text-xs leading-relaxed uppercase font-bold tracking-wider transition-colors duration-300 ${isHovered ? 'text-red-200/80' : 'text-muted-foreground'}`}>
            {risk.desc}
          </p>

          {/* Emotional Subtext */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: isHovered ? 1 : 0 }}
            className="mt-6 pt-4 border-t border-red-500/20 text-[10px] text-red-400/80 font-mono uppercase tracking-[0.2em]"
          >
            Impact if migration is deferred
          </motion.div>
        </div>

        {/* Fire Particles (Simulated with simple spans) */}
        {isHovered && (
          <div className="absolute inset-0 pointer-events-none">
            {[...Array(12)].map((_, idx) => (
              <motion.span
                key={idx}
                initial={{
                  opacity: 0,
                  scale: 0,
                  x: Math.random() * 300 - 150,
                  y: 200
                }}
                animate={{
                  opacity: [0, 1, 0],
                  scale: [0, 1.5, 0.5],
                  y: [-20, -150 - Math.random() * 100],
                  x: (Math.random() * 200 - 100) + (idx % 2 === 0 ? 50 : -50)
                }}
                transition={{
                  duration: 1.5 + Math.random(),
                  repeat: Infinity,
                  delay: Math.random() * 2
                }}
                className="absolute left-1/2 bottom-0 w-1.5 h-1.5 rounded-full bg-red-500 blur-[2px] shadow-[0_0_8px_#ef4444]"
              />
            ))}
          </div>
        )}

        {/* Danger Vibration Animation */}
        <motion.div
          animate={isHovered ? {
            x: [0, -1, 1, -1, 1, 0],
            y: [0, 1, -1, 1, -1, 0]
          } : {}}
          transition={{ repeat: Infinity, duration: 0.15 }}
          className="absolute inset-0 border-2 border-transparent group-hover:border-red-500/30 rounded-2xl pointer-events-none"
        />
      </motion.div>

      {/* Outer Glow */}
      <motion.div
        animate={{
          opacity: isHovered ? 0.6 : 0.2,
          scale: isHovered ? 1.1 : 1,
          backgroundColor: isHovered ? "rgba(220, 38, 38, 0.3)" : "rgba(212, 175, 55, 0.1)"
        }}
        className="absolute -inset-4 blur-[40px] rounded-full -z-10 pointer-events-none"
      />
    </motion.div>
  );
};

function MigrationProcessSection() {
  const [selectedStepId, setSelectedStepId] = useState<string>('01');
  const selectedStep = MIGRATION_PROCESS_STEPS.find((step) => step.id === selectedStepId) || MIGRATION_PROCESS_STEPS[0];
  const selectedIndex = MIGRATION_PROCESS_STEPS.findIndex((step) => step.id === selectedStep.id);
  const implementationPercent = Math.round(((selectedIndex + 1) / MIGRATION_PROCESS_STEPS.length) * 100);
  const SelectedIcon = selectedStep.icon;

  return (
    <motion.section
      id="migration-process"
      initial={{ opacity: 0, y: 36 }}
      whileInView={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.75 }}
      viewport={{ once: true, amount: 0.2 }}
      className="migration-process scroll-mt-24"
    >
      <div className="migration-process__header">
        <span className="migration-process__eyebrow">Strategic Deployment Pipeline</span>
        <h3>Our Post-Quantum Migration Process</h3>
        <p>
          A modular migration architecture built on the published migration guidance — NIST IR 8547, NIST SP 1800-38 and the joint CISA, NSA and NIST Quantum-Readiness factsheet — with rollback controls at every stage.
        </p>
      </div>

      <div className="migration-process__cards" role="tablist" aria-label="Post-quantum migration process steps">
        {MIGRATION_PROCESS_STEPS.map((step) => {
          const Icon = step.icon;
          const selected = step.id === selectedStep.id;

          return (
            <button
              key={step.id}
              type="button"
              role="tab"
              aria-selected={selected}
              aria-controls="migration-process-details"
              onClick={() => setSelectedStepId(step.id)}
              className={`migration-process__card ${selected ? 'migration-process__card--active' : ''}`}
            >
              <span className="migration-process__num">{step.num}</span>
              <span className="migration-process__icon">
                <Icon className="h-6 w-6" />
              </span>
              <span className="migration-process__card-title">{step.title}</span>
              <span className="migration-process__card-copy">{step.description}</span>
            </button>
          );
        })}
      </div>

      <motion.div
        key={selectedStep.id}
        id="migration-process-details"
        role="tabpanel"
        initial={{ opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.28 }}
        className="migration-process__detail"
      >
        <div className="migration-process__detail-main">
          <div className="migration-process__badge-row">
            <span className="migration-process__spec">Stage {selectedStep.num} Specification Infrastructure</span>
            <span className="migration-process__badge">// {selectedStep.badge}</span>
          </div>
          <h4>
            <span>{selectedStep.num}</span>
            {selectedStep.title} Workflow Integration
          </h4>
          <p>{selectedStep.details}</p>
        </div>

        <div className="migration-process__status" aria-label={`${selectedStep.title} module status`}>
          <SelectedIcon className="h-8 w-8" />
          <strong>Stage Position</strong>
          <span>Lifecycle Sequence</span>
          <div className="migration-process__progress">
            <i style={{ width: `${implementationPercent}%` }} />
          </div>
          <small>Stage {selectedIndex + 1} of {MIGRATION_PROCESS_STEPS.length}</small>
        </div>
      </motion.div>
    </motion.section>
  );
}

export default function App() {
  const [now, setNow] = useState(() => new Date());
  const [expandedNistPhase, setExpandedNistPhase] = useState<number | null>(null);
  const [heroTypedLength, setHeroTypedLength] = useState(0);
  const [isDemoModalOpen, setIsDemoModalOpen] = useState(false);
  const countdownUnits = useMemo(() => getQuantumCountdown(now), [now]);
  const typedLineOne = HERO_LINE_ONE.slice(0, heroTypedLength);
  const typedLineTwoLength = Math.max(0, heroTypedLength - HERO_LINE_ONE.length);
  const typedLineTwoPrefix = HERO_LINE_TWO_PREFIX.slice(0, typedLineTwoLength);
  const typedTicking = HERO_TICKING_WORD.slice(
    0,
    Math.max(0, typedLineTwoLength - HERO_LINE_TWO_PREFIX.length)
  );
  const isTypingSecondLine = heroTypedLength > HERO_LINE_ONE.length;
  const isHeroTypewriterComplete = heroTypedLength >= HERO_CHARACTER_COUNT;

  useEffect(() => {
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    if (prefersReducedMotion) {
      setHeroTypedLength(HERO_CHARACTER_COUNT);
      return;
    }

    const timer = window.setInterval(() => {
      setHeroTypedLength((currentLength) => {
        const nextLength = Math.min(currentLength + 1, HERO_CHARACTER_COUNT);

        if (nextLength >= HERO_CHARACTER_COUNT) {
          window.clearInterval(timer);
        }

        return nextLength;
      });
    }, HERO_TYPE_INTERVAL_MS);

    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1000);

    return () => window.clearInterval(timer);
  }, []);

  return (
    <TooltipProvider>
      <div className="qguard-home qguard-home--light min-h-screen overflow-x-hidden bg-transparent text-foreground selection:bg-quantum-blue/30">
        <CyberBackground variant="light" />

        <Navbar2 onRequestDemo={() => setIsDemoModalOpen(true)} />

        {/* Hero Section */}
        <section id="hero" className="hero-shell relative pt-32 pb-20 px-6 min-h-screen flex flex-col justify-center">
          <div className="hero-shell__network" aria-hidden="true" />
          <div className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            {/* Left Column: Text & Atmosphere */}
            <motion.div
              initial={{ opacity: 0, x: -50 }}
              whileInView={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.8 }}
              className="relative z-10"
            >
              <Badge className="hero-alert-badge bg-quantum-blue/10 text-quantum-blue border-quantum-blue/20 px-3 py-1 mb-6 uppercase tracking-[0.3em] font-mono animate-pulse">
                Post-Quantum Threat Advisory: Prepare Before Q-Day
              </Badge>
              <h1 className="hero-title font-bold tracking-normal mb-8 uppercase" aria-label={HERO_ACCESSIBLE_TITLE}>
                <span className="hero-title__ghost" aria-hidden="true">
                  <span className="hero-title__line">
                    <span className="hero-title__gradient">The Quantum</span>
                  </span>
                  <span className="hero-title__line">
                    <span className="hero-title__gradient">Clock Is </span>
                    <span className="hero-title__gradient hero-title__ticking">TICKING</span>
                    <span className="hero-title__gradient">.</span>
                  </span>
                </span>
                <span className="hero-title__typed" aria-hidden="true">
                  <span className="hero-title__line">
                    <span className="hero-title__gradient">{typedLineOne}</span>
                    {!isTypingSecondLine && !isHeroTypewriterComplete && (
                      <span className="hero-title__cursor" />
                    )}
                  </span>
                  <span className="hero-title__line">
                    <span className="hero-title__gradient">{typedLineTwoPrefix}</span>
                    <span className={`hero-title__gradient hero-title__ticking ${isHeroTypewriterComplete ? 'hero-title__ticking--armed' : ''}`}>
                      {typedTicking}
                    </span>
                    {isHeroTypewriterComplete && <span className="hero-title__gradient">.</span>}
                    {isTypingSecondLine && !isHeroTypewriterComplete && (
                      <span className="hero-title__cursor" />
                    )}
                  </span>
                </span>
                <span className="hero-title__continuation" aria-hidden="true">
                  Your Security Can&apos;t Stand Still.
                </span>
              </h1>
              <div className="hero-message">
                <p className="hero-message__lead">
                  <strong>What protects your enterprise today could become tomorrow&apos;s greatest vulnerability.</strong>
                </p>
                <p>The quantum threat is approaching, and the time to prepare is now.</p>
                <p>
                  Qguard Helix helps you uncover hidden cryptographic risks, identify vulnerable encryption,
                  and accelerate your transition to quantum-resistant security.
                </p>
                <p className="hero-message__lifecycle">
                  Discover. Assess. Strategize. Migrate. Validate. Govern.
                </p>
                <p>
                  From TLS and VPNs to SSH, certificates, and code signing, gain complete visibility and control
                  over your cryptographic infrastructure through one intelligent, unified Post-Quantum Cyber Defense platform.
                </p>
                <p className="hero-message__pledge">
                  <strong>Stay ahead of the quantum threat. Protect what matters. Prepare for what&apos;s next.</strong>
                </p>
                <p className="hero-message__signature">
                  <em>Qguard Helix — Your Bridge to the Quantum-Safe Future.</em>
                </p>
              </div>

              <div className="flex flex-wrap gap-4">
                <a href="/auth" className="no-underline max-w-full min-w-0">
                  <Button size="lg" className="hero-primary-cta bg-gold hover:bg-gold/80 text-cyber-black px-8 rounded-none uppercase font-bold tracking-widest shadow-[0_0_20px_rgba(212,175,55,0.4)] transition-all hover:scale-105 group h-14">
                    Start Migration Strategy
                    <MoveRight className="ml-2 group-hover:translate-x-1 transition-transform" />
                  </Button>
                </a>
              </div>

              {/* Info Snippet */}
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                whileHover={{ y: -5, scale: 1.02, boxShadow: "0 0 40px rgba(212, 175, 55, 0.25)" }}
                transition={{ duration: 0.4 }}
                className="hero-alert-card mt-16 p-6 rounded-xl border border-gold/20 bg-white/[0.03] backdrop-blur-md border-l-4 border-l-gold relative overflow-hidden group cursor-default transition-all shadow-[0_20px_50px_rgba(0,0,0,0.3)] hover:border-gold/40 hover:bg-white/[0.05]"
              >
                <div className="flex items-start gap-4 relative z-10">
                  <div className="w-12 h-12 rounded-full border border-gold/30 flex items-center justify-center bg-gold/10 shrink-0 shadow-[0_0_15px_rgba(212,175,55,0.1)] group-hover:shadow-[0_0_25px_rgba(212,175,55,0.3)] transition-all">
                    <AlertTriangle className="w-6 h-6 text-gold animate-pulse" />
                  </div>
                  <div>
                    <h4 className="text-gold font-bold uppercase tracking-[0.2em] text-sm mb-2 drop-shadow-[0_0_10px_rgba(212,175,55,0.5)]">Security Alert</h4>
                    <p className="text-white/90 text-sm leading-relaxed font-medium">
                      CISA, the NSA and NIST warn that adversaries can capture encrypted traffic today and decrypt it once a cryptographically relevant quantum computer exists. Data that must stay confidential for years is exposed first.
                    </p>
                  </div>
                </div>
                <div className="absolute top-0 right-0 w-32 h-32 bg-gold/10 blur-[60px] pointer-events-none transition-all group-hover:bg-gold/20" />
                <div className="absolute inset-0 bg-gradient-to-br from-gold/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
              </motion.div>
            </motion.div>

            {/* Right Column: Video Intelligence Panel */}
            <motion.div
              initial={{ opacity: 0, x: 50 }}
              whileInView={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.85, delay: 0.1 }}
              viewport={{ once: true, amount: 0.35 }}
              className="relative z-10 flex items-center justify-center lg:justify-end"
            >
              <div className="absolute -inset-8 bg-[radial-gradient(circle_at_50%_40%,rgba(0,243,255,0.14),transparent_54%),radial-gradient(circle_at_78%_82%,rgba(212,175,55,0.13),transparent_42%)] blur-2xl pointer-events-none" />

              <motion.div
                animate={{ y: [0, -8, 0] }}
                transition={{ duration: 7, repeat: Infinity, ease: "easeInOut" }}
                className="hero-intel-frame relative w-full max-w-[590px] group rounded-xl p-[2px]"
              >
                {/* Soft Neon Gradient Beam behind */}
                <div className="absolute inset-0 rounded-xl bg-[conic-gradient(from_var(--border-angle),#00F3FF,#22c55e,#D4AF37,#f97316,#ef4444,#00F3FF)] animate-border-beam pointer-events-none" />
                <div className="absolute inset-0 rounded-xl bg-[conic-gradient(from_var(--border-angle),#00F3FF,#22c55e,#D4AF37,#f97316,#ef4444,#00F3FF)] animate-border-beam blur-[8px] opacity-70 pointer-events-none transition-opacity duration-500 group-hover:opacity-100" />

                <div className="relative overflow-hidden rounded-xl bg-cyber-navy/95 shadow-[0_35px_100px_rgba(0,0,0,0.45)] backdrop-blur-xl">
                  <div className="absolute inset-0 z-10 pointer-events-none bg-[linear-gradient(135deg,rgba(255,255,255,0.16)_0%,transparent_28%,transparent_70%,rgba(0,243,255,0.12)_100%)]" />
                  <div className="quantum-countdown relative z-20">
                    <div className="quantum-countdown__title-row">
                      <span className="quantum-countdown__rail" />
                      <h2 className="quantum-countdown__title">NIST IR 8547 Deprecation Deadline</h2>
                      <span className="quantum-countdown__rail" />
                    </div>
                    <p className="quantum-countdown__subtitle">
                      NIST IR 8547 deprecates RSA, Diffie-Hellman, ECDH and ECDSA after 2030<br />
                      and disallows them after 2035. This is a published deadline, not a forecast.
                    </p>

                    <div className="quantum-countdown__panel" aria-label="Time remaining until NIST deprecates classical public-key cryptography">
                      {countdownUnits.map((unit) => (
                        <div className="quantum-countdown__cell" key={unit.label}>
                          <div className="quantum-countdown__label">{unit.label}</div>
                          <div className="quantum-countdown__value">{unit.value}</div>
                        </div>
                      ))}
                    </div>

                    <div className="quantum-countdown__footer">
                      Time remaining until NIST deprecates classical public-key cryptography
                    </div>
                    <div className="quantum-countdown__corner quantum-countdown__corner--left" />
                    <div className="quantum-countdown__corner quantum-countdown__corner--right" />
                  </div>

                  <div className="relative aspect-[16/10] min-h-[300px] overflow-hidden bg-cyber-black sm:min-h-[340px]">
                    <video
                      src={ASSETS.hourglassVideo}
                      aria-label="Quantum hourglass countdown video"
                      autoPlay
                      muted
                      loop
                      playsInline
                      preload="metadata"
                      poster={ASSETS.hourglass}
                      className="h-full w-full object-cover opacity-95 contrast-125 saturate-125"
                    />
                    <div className="absolute inset-0 bg-gradient-to-r from-cyber-black/40 via-transparent to-cyber-black/15 pointer-events-none" />
                    <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.035)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.025)_1px,transparent_1px)] bg-[size:48px_48px] opacity-25 pointer-events-none" />
                  </div>

                  <div className="grid grid-cols-3 border-t border-white/10 bg-cyber-black/55">
                    {[
                      { label: "Threat", value: "CRQC" },
                      { label: "Priority", value: "PQC" },
                      { label: "Timeline", value: "Now" }
                    ].map((metric) => (
                      <div key={metric.label} className="border-r border-white/10 px-4 py-4 last:border-r-0">
                        <p className="font-mono text-[10px] uppercase tracking-[0.28em] text-muted-foreground">{metric.label}</p>
                        <p className="mt-1 text-lg font-bold uppercase tracking-[0.16em] text-white">{metric.value}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </motion.div>
            </motion.div>
          </div>
        </section>

        <TrustedLeadersSection />

        {/* Why It Matters / Hourglass Section */}
        <section className="py-32 relative overflow-hidden bg-cyber-navy/20">
          <div className="max-w-7xl mx-auto px-6">
            <div className="text-center mb-24">
              <h2 className="text-4xl md:text-6xl font-bold uppercase mb-4 italic tracking-widest text-gold">Why it Matters</h2>
              <div className="w-24 h-1 bg-gradient-to-r from-transparent via-gold to-transparent mx-auto" />
            </div>

            <div className="grid lg:grid-cols-2 gap-20 items-center">
              <motion.div
                initial={{ opacity: 0, rotateY: 30 }}
                whileInView={{ opacity: 1, rotateY: 0 }}
                className="relative perspective-1000"
              >
                <div className="aspect-[4/5] relative rounded-3xl overflow-hidden glass-panel p-8">
                  <img
                    src="/HNDL.png"
                    alt="Harvest Now, Decrypt Later"
                    className="w-full h-full object-cover"
                    referrerPolicy="no-referrer"
                  />
                  <div className="absolute inset-0 bg-gradient-to-b from-transparent via-cyber-navy/10 to-cyber-black/80" />

                </div>
              </motion.div>

              <div className="space-y-12">
                {[
                  { icon: Skull, title: "Harvest now, Decrypt later", text: "CISA, the NSA and NIST warn that an adversary can record encrypted traffic today and store it. They do not need to break it now; they only need to keep it until a Cryptographically Relevant Quantum Computer (CRQC) exists." },
                  { icon: HourglassIcon, title: "The Window is Closing", text: "Migrating an enterprise estate takes years. NIST IR 8547 deprecates RSA, Diffie-Hellman, ECDH and ECDSA after 2030 and disallows them after 2035, so the runway is already defined and it is shorter than most migration programmes." },
                  { icon: Zap, title: "Start While You Can Phase It", text: "The core standards are already final — FIPS 203, 204 and 205 were published in August 2024. Organizations that wait turn a planned, phased migration into an emergency one, and anything captured in the meantime stays exposed." }
                ].map((item, i) => (
                  <motion.div
                    key={i}
                    initial={{ opacity: 0, x: 50 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.2 }}
                    className="flex gap-6 group"
                  >
                    <div className="w-16 h-16 rounded-xl border border-white/5 bg-white/5 flex items-center justify-center shrink-0 group-hover:border-gold/50 transition-colors">
                      <item.icon className="w-8 h-8 text-gold group-hover:scale-110 transition-transform" />
                    </div>
                    <div>
                      <h3 className="text-2xl font-bold uppercase tracking-wide mb-3 text-gold transition-colors">{item.title}</h3>
                      <p className="text-muted-foreground leading-relaxed">
                        {item.text}
                      </p>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* Harvest Now, Decrypt Later Infographic Section */}
        <section className="py-20 relative overflow-hidden">
          <div className="max-w-7xl mx-auto px-6">
            <motion.div
              initial={{ opacity: 0, y: -20 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8 }}
              className="text-center mb-16 relative"
            >
              {/* Background Glow */}
              <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-[60%] h-24 bg-gold/10 blur-[60px] rounded-full pointer-events-none" />

              <h2 className="text-4xl md:text-6xl font-black uppercase tracking-tight text-transparent bg-clip-text bg-gradient-to-b from-[#FFF3D0] via-[#D4AF37] to-[#8A6D3B] drop-shadow-[0_0_30px_rgba(212,175,55,0.55)]">
                Harvest Now, <span className="text-white gold-glow italic">Decrypt Later</span>
              </h2>

              <motion.div
                animate={{ opacity: [0.4, 1, 0.4] }}
                transition={{ duration: 2, repeat: Infinity }}
                className="mt-6 flex justify-center items-center gap-6"
              >
                <div className="h-px w-24 bg-gradient-to-r from-transparent via-gold to-transparent" />
                <span className="text-gold font-mono text-xs font-bold uppercase tracking-[0.4em] drop-shadow-[0_0_8px_rgba(212,175,55,0.8)]">
                  Long-Lived Data At Risk
                </span>
                <div className="h-px w-24 bg-gradient-to-r from-transparent via-gold to-transparent" />
              </motion.div>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              whileInView={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.8 }}
              className="relative group"
            >
              <div className="absolute -inset-1 bg-gradient-to-r from-gold/20 via-gold/40 to-gold/20 rounded-[2rem] blur-xl opacity-50 group-hover:opacity-100 transition duration-1000 group-hover:duration-200" />
              <div className="relative rounded-[2rem] overflow-hidden border border-gold/20 bg-black shadow-[0_0_50px_rgba(212,175,55,0.15)]">
                <img
                  src="/HarvestNow.png"
                  alt="Harvest Now, Decrypt Later Infographic"
                  className="w-full h-auto object-cover opacity-90 group-hover:opacity-100 transition-opacity duration-700"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-black/40 via-transparent to-transparent pointer-events-none" />
              </div>
            </motion.div>
          </div>
        </section>

        {/* Action Section */}
        <section id="intelligence" className="py-32 relative overflow-hidden">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_10%,rgba(212,175,55,0.11),transparent_38%)] pointer-events-none" />
          <div className="max-w-7xl mx-auto px-6">
            <h2 className="text-4xl font-black uppercase text-center mb-20 tracking-[0.2em] text-white">What you can <span className="text-gold gold-glow">do now</span></h2>

            <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-6">
              {[
                {
                  icon: Search,
                  label: "Inventory",
                  front: "Discover every quantum-vulnerable key.",
                  back: "Identify cryptographic assets across your entire infrastructure, including RSA, ECC, TLS certificates, VPN tunnels, SSH keys, databases, APIs, cloud workloads, IoT devices, and legacy applications. Build a real-time quantum exposure inventory with automated asset classification and cryptographic fingerprinting."
                },
                {
                  icon: Shield,
                  label: "Assess Risk",
                  front: "Rank systems by quantum risk.",
                  back: "Analyze which systems are most vulnerable to Harvest Now, Decrypt Later attacks. Prioritize assets using quantum risk scoring, business criticality, data sensitivity, compliance impact, and cryptographic weakness analysis to accelerate remediation planning."
                },
                {
                  icon: Map,
                  label: "Roadmap",
                  front: "Define phased migration steps.",
                  back: "Generate a structured PQC migration strategy aligned with NIST standards. Create phased upgrade plans for hybrid cryptography adoption, infrastructure modernization, certificate replacement, application compatibility testing, and long-term crypto agility."
                },
                {
                  icon: Lock,
                  label: "Implement",
                  front: "Deploy hybrid cryptographic stacks.",
                  back: "Plan and execute the move to ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205), using hybrid classical and post-quantum modes where interoperability requires them. Coordinate certificate rotation, key exchange modernization and policy enforcement, with snapshots and rollback at every wave. How far automation reaches depends on vendor and protocol support in your estate."
                },
                {
                  icon: Users,
                  label: "Educate",
                  front: "Train your security teams on PQC.",
                  back: "Migration playbooks, a PQC readiness checklist, quantum simulations, AI migration and executive advisors, and per-asset remediation guidance mapped to the NIST standards — so engineers, security teams and executives can each see what the findings mean for them."
                }
              ].map((item, i) => (
                <div key={i} className="group h-[320px] perspective-1000">
                  <div className="relative h-full w-full transition-all duration-700 preserve-3d group-hover:rotate-y-180">
                    {/* Front Face */}
                    <div className="absolute inset-0 backface-hidden rounded-xl border border-gold/14 bg-white/[0.045] p-8 text-center shadow-[0_20px_80px_rgba(0,0,0,0.36)] backdrop-blur-xl transition-all duration-500 group-hover:border-gold/65 flex flex-col items-center justify-center">
                      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(145deg,rgba(255,255,255,0.12),transparent_32%,rgba(212,175,55,0.1))] opacity-45" />
                      <div className="relative z-10 mx-auto mb-6 flex h-16 w-16 items-center justify-center rounded-full border border-gold/25 bg-gold/10 text-gold shadow-[0_0_28px_rgba(212,175,55,0.22)]">
                        <item.icon className="w-8 h-8" />
                      </div>
                      <h4 className="relative z-10 font-black uppercase tracking-widest text-sm mb-3 text-white group-hover:text-gold transition-colors">{item.label}</h4>
                      <p className="relative z-10 text-[11px] leading-5 text-white/68 uppercase tracking-wider">{item.front}</p>

                      {/* Flip Hint */}
                      <div className="absolute bottom-4 right-4 text-gold/30 text-[10px] font-mono uppercase tracking-widest group-hover:opacity-0 transition-opacity">
                        Hover to Flip
                      </div>
                    </div>

                    {/* Back Face */}
                    <div className="absolute inset-0 backface-hidden rounded-xl border border-gold/40 bg-gold/[0.08] p-6 shadow-[0_0_42px_rgba(212,175,55,0.25)] backdrop-blur-xl rotate-y-180 flex flex-col items-center justify-center">
                      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(145deg,rgba(212,175,55,0.1),transparent_32%)] opacity-30" />
                      <div className="relative z-10 w-full">
                        <h4 className="font-black uppercase tracking-widest text-xs mb-4 text-gold text-center border-b border-gold/20 pb-2">{item.label} Details</h4>
                        <p className="text-[10px] leading-relaxed text-white/90 text-left font-medium">
                          {item.back}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* NIST Migration Strategy Section */}
        <section id="nist-strategy" className="py-32 border-t border-gold/10 relative bg-cyber-navy/10 overflow-hidden">
          <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_50%_18%,rgba(212,175,55,0.1),transparent_36%),linear-gradient(180deg,rgba(212,175,55,0.035),transparent)]" />
          <div className="max-w-7xl mx-auto px-6">
            <div className="mb-20 max-w-2xl text-center md:text-left">
              <h2 className="text-5xl font-black uppercase tracking-normal text-gold gold-glow"><span>NIST Migration</span> <br /><span className="tracking-widest">Strategy</span></h2>
              <p className="text-white/70 mt-4 font-mono text-sm max-w-md">Our phasing of the published guidance: NIST IR 8547, NIST SP 1800-38 and the joint CISA, NSA and NIST Quantum-Readiness factsheet.</p>
            </div>

            <div className="relative rounded-2xl border border-gold/14 bg-white/[0.035] p-8 pt-16 shadow-[0_26px_96px_rgba(0,0,0,0.36)] backdrop-blur-xl">
              <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(145deg,rgba(255,255,255,0.1),transparent_34%,rgba(212,175,55,0.08))] opacity-50" />


              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 relative z-10">
                {[
                  {
                    phase: "Prepare",
                    sub: "(Now)",
                    icon: Database,
                    details: "Establish the foundation for post-quantum readiness across the organization. Identify critical systems, sensitive data, cryptographic dependencies, compliance requirements, and long-term security objectives. Build governance policies, executive awareness, and quantum migration task forces aligned with NIST PQC guidance.",
                    actions: ["Create crypto governance framework", "Identify critical business assets", "Define quantum readiness objectives", "Establish PQC migration teams", "Review compliance and regulatory impact"]
                  },
                  {
                    phase: "Assess",
                    sub: "(Now-1 Yr)",
                    icon: Search,
                    details: "Perform enterprise-wide cryptographic discovery and quantum risk analysis. Detect vulnerable algorithms such as RSA, ECC, DH, and weak PKI implementations across infrastructure, applications, APIs, cloud workloads, and communication systems.",
                    actions: ["Inventory cryptographic assets", "Detect PQ-vulnerable algorithms", "Analyze TLS, VPN, SSH, PKI exposure", "Rank systems by risk and urgency", "Assess Harvest Now, Decrypt Later exposure"]
                  },
                  {
                    phase: "Plan",
                    sub: "(1-2 Yrs)",
                    icon: Map,
                    details: "Design a phased migration roadmap for transitioning to NIST-approved post-quantum cryptography. Define hybrid cryptographic architectures, upgrade timelines, vendor dependencies, interoperability testing, and crypto-agility strategies for long-term resilience.",
                    actions: ["Build phased migration roadmap", "Select NIST-approved PQC algorithms", "Define hybrid crypto architectures", "Identify application dependencies", "Develop rollback and testing procedures"]
                  },
                  {
                    phase: "Implement",
                    sub: "(2-4 Yrs)",
                    icon: Zap,
                    details: "Deploy post-quantum cryptographic controls across enterprise environments using hybrid classical + PQC architectures. Integrate ML-KEM, ML-DSA, and SLH-DSA into certificates, communication channels, authentication systems, APIs, and secure storage infrastructures.",
                    actions: ["Deploy hybrid PQ-TLS environments", "Rotate vulnerable certificates and keys", "Integrate ML-KEM and ML-DSA", "Upgrade VPN, SSH, and PKI systems", "Enable real-time migration telemetry"]
                  },
                  {
                    phase: "Transition",
                    sub: "(4-6 Yrs)",
                    icon: Globe,
                    details: "Gradually phase out legacy cryptographic systems while validating interoperability, performance, and operational stability. Transition production workloads fully into quantum-resistant environments with continuous monitoring and policy enforcement.",
                    actions: ["Decommission legacy cryptography", "Validate interoperability and compatibility", "Enforce PQC security policies", "Monitor migration health and coverage", "Harden enterprise-wide PQ infrastructures"]
                  },
                  {
                    phase: "Optimize",
                    sub: "(6+ Yrs)",
                    icon: TrendingDown,
                    details: "Continuously improve crypto-agility, operational resilience, and future quantum readiness. Monitor evolving NIST standards, emerging threats, cryptographic performance, and infrastructure scalability to maintain long-term protection against future quantum capabilities.",
                    actions: ["Continuously monitor PQC posture", "Update algorithms and cryptographic policies", "Optimize performance and scalability", "Maintain crypto-agility frameworks", "Prepare for future NIST PQC revisions"]
                  }
                ].map((step, i) => (
                  <div key={i} className="flex flex-col">
                    <motion.div
                      initial={{ opacity: 0, y: 20 }}
                      whileInView={{ opacity: 1, y: 0 }}
                      transition={{ delay: i * 0.1 }}
                      onClick={() => setExpandedNistPhase(expandedNistPhase === i ? null : i)}
                      className={`relative group z-10 rounded-xl border ${expandedNistPhase === i ? 'border-gold bg-gold/[0.08]' : 'border-gold/10 bg-cyber-black/28'} px-4 pb-6 pt-16 backdrop-blur-xl transition-all duration-500 cursor-pointer hover:border-gold/55 hover:bg-gold/[0.06] hover:shadow-[0_0_32px_rgba(212,175,55,0.22)]`}
                    >
                      <div className="-mt-12 flex flex-col items-center">
                        <span className={`text-4xl font-black ${expandedNistPhase === i ? 'text-gold/40' : 'text-gold/16'} group-hover:text-gold/38 transition-colors mb-6`}>{i + 1}</span>
                        <div className={`w-12 h-12 rounded-full border border-gold/25 ${expandedNistPhase === i ? 'bg-gold/20' : 'bg-gold/10'} text-gold shadow-[0_0_24px_rgba(212,175,55,0.2)] flex items-center justify-center mb-6 group-hover:scale-110 group-hover:shadow-[0_0_34px_rgba(212,175,55,0.45)] transition-all`}>
                          <step.icon className="w-5 h-5" />
                        </div>
                      </div>
                      <div className="text-center">
                        <h4 className="font-black uppercase tracking-[0.2em] mb-2 text-white group-hover:text-gold transition-colors">{step.phase}</h4>
                        <p className="text-[10px] font-mono text-white/60 uppercase group-hover:text-white/78 transition-colors">{step.sub}</p>

                        <div className="mt-4 flex justify-center">
                          <motion.div
                            animate={{ rotate: expandedNistPhase === i ? 180 : 0 }}
                            className="text-gold/40 group-hover:text-gold"
                          >
                            <ChevronDown size={16} />
                          </motion.div>
                        </div>
                      </div>
                    </motion.div>

                    <AnimatePresence>
                      {expandedNistPhase === i && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: "auto", opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          transition={{ duration: 0.4, ease: "easeInOut" }}
                          className="overflow-hidden z-0"
                        >
                          <div className="mt-4 p-6 rounded-xl border border-gold/30 bg-gold/[0.04] backdrop-blur-md shadow-[0_10px_40px_rgba(0,0,0,0.4)]">
                            <h5 className="text-gold font-bold uppercase tracking-widest text-[10px] mb-3 border-b border-gold/20 pb-2">Phase Details</h5>
                            <p className="text-xs leading-relaxed text-white/90 mb-6 italic">
                              {step.details}
                            </p>

                            <h5 className="text-gold font-bold uppercase tracking-widest text-[10px] mb-3 flex items-center gap-2">
                              <span className="w-1.5 h-1.5 rounded-full bg-gold animate-pulse" />
                              Key Actions
                            </h5>
                            <ul className="space-y-2">
                              {step.actions.map((action, actionIdx) => (
                                <li key={actionIdx} className="flex items-center gap-3 text-[10px] text-white/70 group/item">
                                  <div className="w-1 h-1 rounded-full bg-gold/50 group-hover/item:bg-gold transition-colors" />
                                  <span className="group-hover/item:text-white transition-colors">{action}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* Impact of Inaction Section */}
        <section className="py-40 relative overflow-hidden">
          {/* Section light wash overlay */}
          <motion.div
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            className="absolute inset-0 bg-gradient-to-b from-white/75 via-transparent to-white/75 pointer-events-none z-0"
          />

          <div className="max-w-7xl mx-auto px-6 relative z-10">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              className="text-center mb-32"
            >
              <motion.h2
                animate={{
                  textShadow: [
                    "0 0 20px rgba(212, 175, 55, 0.5)",
                    "0 0 40px rgba(212, 175, 55, 0.8)",
                    "0 0 20px rgba(212, 175, 55, 0.5)"
                  ]
                }}
                transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
                className="text-4xl md:text-7xl font-black uppercase tracking-[0.3em] text-gold italic relative"
              >
                The Impact of <br />
                <span className="text-white not-italic opacity-90 drop-shadow-[0_0_30px_rgba(255,255,255,0.3)]">Inaction</span>
              </motion.h2>
              <div className="mt-8 flex flex-col items-center gap-2">
                <p className="text-red-500/80 font-mono text-xs uppercase tracking-[0.5em] animate-pulse">Critical Vulnerability Detected</p>
                <div className="h-1 w-48 bg-gradient-to-r from-transparent via-red-600/50 to-transparent" />
                <p className="mt-4 text-white/60 font-medium uppercase tracking-widest max-w-2xl mx-auto leading-relaxed">
                  Delay does not pause the exposure. Anything protected by RSA or elliptic-curve key exchange and captured today can be opened later, and a phased migration becomes an emergency one.
                </p>
              </div>
            </motion.div>

            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-10">
              {[
                { title: "Data Exposure", icon: Skull, val: "RSA / ECC", desc: "Traffic and archives whose confidentiality rests on RSA or elliptic-curve key exchange become readable once a CRQC exists.", color: "text-gold" },
                { title: "Unplanned Cost", icon: TrendingDown, val: "Unbudgeted", desc: "Re-encryption, certificate replacement and vendor re-contracting all land at once instead of being phased across budget cycles.", color: "text-gold" },
                { title: "Compliance Risk", icon: Globe, val: "2030", desc: "NIST IR 8547 deprecates classical public-key cryptography after 2030 and disallows it after 2035; NSA CNSA 2.0 already binds national security systems.", color: "text-gold" },
                { title: "Loss of Trust", icon: AlertTriangle, val: "Signatures", desc: "Code signing, firmware signing and PKI that still rely on RSA or ECDSA stop being defensible to auditors and customers.", color: "text-gold" }
              ].map((risk, i) => (
                <InactionCard key={i} risk={risk} i={i} />
              ))}
            </div>
          </div>
        </section>

        <section className="py-20 relative">
          <div className="max-w-7xl mx-auto px-6">
            <MigrationProcessSection />

            <div className="mt-24 w-full">
              <StickyFeatureSection />
            </div>

            <div className="w-full">
              <QuantumFeaturesMarquee />
            </div>

            <EnterpriseProtectionShowcase />
            <RoadmapSection />
            <div className="h-32 w-full" />
            <Hero195 />
            <div className="h-32 w-full" />
            <QuantumSecurityUseCasesSection />
            <PricingSection onRequestDemo={() => setIsDemoModalOpen(true)} />
            <FaqAndCtaSection />
          </div>
        </section>

        {/* Footer */}
        <footer className="homepage-footer relative overflow-hidden px-6 py-16">
          <div className="homepage-footer__grid relative z-10 mx-auto grid max-w-[96rem] gap-12 lg:grid-cols-[1.55fr_2fr_1.2fr]">
            <div className="space-y-7">
              <a href="#hero" className="homepage-footer__brand no-underline">
                <img
                  src="/NEW_LOGO.png"
                  alt="Qguard Helix logo"
                  className="homepage-footer__brand-logo"
                />
                <span className="homepage-footer__brand-copy">
                  <strong>
                    QGUARD <span>HELIX</span>
                  </strong>
                  <small>// QUANTUM CYBER DEFENSE</small>
                </span>
              </a>

              <p className="homepage-footer__description">
                <span>
                  Empowering enterprises to build a quantum-secure future with
                  confidence through cryptographic automation, continuous
                  vulnerability scanning, and continuous post-quantum readiness monitoring.
                </span>
              </p>

              <div className="homepage-footer__socials" aria-label="Qguard Helix social links">
                {[
                  { icon: Twitter, href: "#", name: "X" },
                  { icon: Linkedin, href: "#", name: "LinkedIn" },
                  { icon: Github, href: "#", name: "GitHub" }
                ].map((social) => (
                  <a
                    key={social.name}
                    href={social.href}
                    className="homepage-footer__social"
                    aria-label={social.name}
                  >
                    <social.icon className="h-4 w-4" />
                  </a>
                ))}
              </div>
            </div>

            <nav className="homepage-footer__columns" aria-label="Footer navigation">
              {[
                {
                  title: "Platform",
                  links: [
                    { label: "Overview", href: "#hero" },
                    { label: "Features", href: "#migration-process" },
                    { label: "Security", href: "#simulator" },
                    { label: "Integrations", href: "#command-center" }
                  ]
                },
                {
                  title: "Solutions",
                  links: [
                    { label: "By Industry", href: "#use-cases" },
                    { label: "Use Cases", href: "#use-cases" },
                    { label: "Migration Services", href: "#roadmap" },
                    { label: "Compliance", href: "#nist-strategy" }
                  ]
                },
                {
                  title: "Resources",
                  links: [
                    { label: "PQC Checklist", href: "/resources/pqc-checklist" },
                    { label: "Documentation", href: "/docs" },
                    { label: "Whitepapers", href: "/docs" },
                    { label: "Blog", href: "/docs" },
                    { label: "Webinars", href: "/docs" }
                  ]
                },
                {
                  title: "Company",
                  links: [
                    { label: "About Us", href: "#faq" },
                    { label: "Careers", href: "#faq" },
                    { label: "Partners", href: "#faq" },
                    { label: "Contact", href: "/login" }
                  ]
                }
              ].map((column) => (
                <div className="homepage-footer__column" key={column.title}>
                  <h3>{column.title}</h3>
                  <ul>
                    {column.links.map((link) => (
                      <li key={`${column.title}-${link.label}`}>
                        <a href={link.href}>{link.label}</a>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </nav>

            <aside className="homepage-footer__cta">
              <h3>Ready to become quantum safe?</h3>
              <p>
                Schedule a walkthrough to see cryptographic discovery, quantum
                risk scoring and post-quantum migration running on real data.
              </p>
              <button
                type="button"
                onClick={() => setIsDemoModalOpen(true)}
                className="homepage-footer__cta-button cursor-pointer"
              >
                Request Demo
                <MoveRight className="h-4 w-4" />
              </button>
            </aside>
          </div>

          <div className="homepage-footer__bottom relative z-10 mx-auto mt-20 flex max-w-[96rem] flex-col gap-6 border-t pt-8 md:flex-row md:items-center md:justify-between">
            <p>&copy; {new Date().getFullYear()} Qguard Helix. All rights reserved.</p>

            <div className="homepage-footer__legal">
              <a href="/privacy">Privacy Policy</a>
              <a href="/terms">Terms of Service</a>
              <a href="/refund">Refund Policy</a>
              <a href="/contact">Contact</a>
              <a href="/docs">Security Specification</a>
            </div>

            <div className="homepage-footer__language" aria-label="Language selector">
              <Globe className="h-4 w-4" />
              <span>English</span>
              <ChevronDown className="h-4 w-4" />
            </div>
          </div>
        </footer>

        <RequestDemoModal isOpen={isDemoModalOpen} onClose={() => setIsDemoModalOpen(false)} />
      </div>
    </TooltipProvider>
  );
}

// Custom Cursor or other small details can be added here
