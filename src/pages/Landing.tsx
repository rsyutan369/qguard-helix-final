/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useInView, useReducedMotion } from 'motion/react';
import Navbar2 from "@/components/ui/navbar2";
import { Hero195 } from "@/components/ui/hero-195";
import { capabilities } from "@/components/ui/sticky-scroll-cards-section";
import { QuantumFeaturesMarquee } from "@/components/ui/QuantumFeaturesMarquee";
import { InfiniteSlider } from "@/components/ui/infinite-slider";
import {
  Activity,
  Calendar,
  Shield,
  Check,
  CheckCircle2,
  Cloud,
  Hourglass as HourglassIcon,
  Map,
  KeyRound,
  Lock,
  AlertTriangle,
  FileCheck,
  Users,
  Search,
  Zap,
  Globe,
  Skull,
  Play,
  Pause,
  Plus,
  RefreshCw,
  RefreshCcw,
  X,
  ArrowRight,
  Loader,
  type LucideIcon
} from 'lucide-react';
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
import { ButtonDot, Chars } from './landing-chars';
import { useLandingMotion } from './landing-motion';
import './landing.css';
import { PLAN_PRICING } from '@/lib/billing/plan-pricing';
import { PQC_TRANSITION_SOURCES } from '@/lib/crypto/pqc-transition-sources';

// Asset paths
const ASSETS = {
  hourglass: hourglassImage,
  hourglassVideo: hourGlassVideo
};

const NIST_DEPRECATION_START = new Date(`${PQC_TRANSITION_SOURCES.nist.deprecationStarts}T00:00:00Z`);
const MS_PER_DAY = 24 * 60 * 60 * 1000;
const MS_PER_HOUR = 60 * 60 * 1000;
const MS_PER_MINUTE = 60 * 1000;
const MS_PER_SECOND = 1000;

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
    badge: 'Cryptographic inventory',
    icon: Search
  },
  {
    id: '02',
    num: '02',
    title: 'Assess',
    description: 'Analyze risks and prioritize based on impact.',
    details: 'Flag deprecated hash algorithms, weak cipher suites, and quantum-vulnerable public-key families (RSA, finite-field Diffie-Hellman, ECDH, ECDSA, DSA). Rank assets by data lifetime, business criticality, and Harvest Now, Decrypt Later exposure so the longest-lived secrets are addressed first.',
    badge: 'AI-powered threat modeling',
    icon: Shield
  },
  {
    id: '03',
    num: '03',
    title: 'Plan',
    description: 'Build a migration roadmap using NIST PQC guidance.',
    details: 'Compile sequential project roadmaps matching your risk priorities and applicable NIST guidance. Establish dual-key and hybrid strategy envelopes so infrastructure remains resilient during ongoing migrations.',
    badge: 'NIST guidance reference',
    icon: FileCheck
  },
  {
    id: '04',
    num: '04',
    title: 'Migrate',
    description: 'Execute migration with hybrid and PQC technology.',
    details: 'Introduce ML-KEM (FIPS 203) for key establishment and ML-DSA (FIPS 204) for signatures, using hybrid classical + post-quantum modes where interoperability requires it, with rollback controls at every checkpoint.',
    badge: 'Active hardening',
    icon: RefreshCcw
  },
  {
    id: '05',
    num: '05',
    title: 'Validate',
    description: 'Verify compatibility, performance, and security.',
    details: 'Verify that the larger post-quantum key, ciphertext, and certificate sizes traverse gateways, firewalls, load balancers, and middleboxes, and measure the handshake and fragmentation impact before production cutover.',
    badge: 'Interoperability testing',
    icon: Check
  },
  {
    id: '06',
    num: '06',
    title: 'Monitor',
    description: 'Continuously monitor, optimize, and stay ready.',
    details: 'Continuous monitoring flags reintroduced quantum-vulnerable cryptography, deprecated TLS versions, and unmanaged certificates, and maintains the crypto-agility controls needed to change algorithms again as standards evolve.',
    badge: 'Continuous assurance',
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
    subtitle: "Cryptographic asset identification",
    status: "active",
    statusLabel: "Foundation phase",
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
    subtitle: "Roadmap, testing, and crypto-agility",
    status: "scheduled",
    statusLabel: "Planned target",
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
    subtitle: "Controlled transition to quantum-resistant crypto",
    status: "scheduled",
    statusLabel: "Planned target",
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
    subtitle: "Post-migration assurance and continuous monitoring",
    status: "scheduled",
    statusLabel: "Planned target",
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
    description: "Explore physical entropy sources and the checks required before relying on them for cryptography.",
    icon: Zap,
    image: "/Quantum_qrng.png",
    useCases: [
      "Randomness for cryptographic key generation",
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
    description: "Discover certificates and plan post-quantum signature migration with your certificate authority.",
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
      "Certificate inventory and PQC migration planning",
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
  "NIST NCCoE migration guidance",
  "NIST SP 800-57",
  "NSA CNSA 2.0",
  "CISA Quantum Readiness",
  "IETF TLS Hybrid Key Exchange",
  "PCI DSS 4.0.1",
  "SOC 2 TSC",
  "ISO/IEC 27001"
];

const STANDARDS_ROW_A = TRUSTED_LEADERS.slice(0, 6);
const STANDARDS_ROW_B = TRUSTED_LEADERS.slice(6);

type PricingPlan = {
  name: string;
  description: string;
  priceMonthly: number;
  priceYearly: number;
  badge: string;
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
    priceMonthly: PLAN_PRICING.Starter.monthly,
    priceYearly: PLAN_PRICING.Starter.yearlyPerMonth,
    badge: "Secure desktop",
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
    priceMonthly: PLAN_PRICING.Basic.monthly,
    priceYearly: PLAN_PRICING.Basic.yearlyPerMonth,
    badge: "Readiness & assessment",
    features: [
      "Everything in Starter",
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
    priceMonthly: PLAN_PRICING.Pro.monthly,
    priceYearly: PLAN_PRICING.Pro.yearlyPerMonth,
    badge: "Most popular",
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
    priceMonthly: PLAN_PRICING.Elite.monthly,
    priceYearly: PLAN_PRICING.Elite.yearlyPerMonth,
    badge: "Enterprise agility",
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
      answer: "Q-Day is the point at which a cryptographically relevant quantum computer (CRQC) can break widely-used public-key cryptography such as RSA and elliptic curve. No government or standards body has put a date on it, and estimates remain uncertain. Planning does not depend on the date: the final NIST IR 8547 sets a general transition window, and EO 14412 and OMB M-26-15 set earlier milestones for priority U.S. federal systems."
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
      answer: "The planning problem is real today, because Harvest Now, Decrypt Later does not require the adversary to own a quantum computer yet. No machine has been demonstrated that breaks RSA-2048, and no standards body calls the threat imminent. NIST published FIPS 203, 204 and 205 on 13 August 2024 because migrating an enterprise estate takes years, and NIST IR 8547 deprecates quantum-vulnerable public-key cryptography after 2030 and disallows it under NIST standards and guidance after 2035."
    }
  ],
  migration: [
    {
      question: "What is Post-Quantum Cryptography (PQC)?",
      answer: "PQC refers to cryptographic algorithms designed to resist both classical and quantum attack. NIST finalized three standards on 13 August 2024: ML-KEM (FIPS 203) for key establishment, ML-DSA (FIPS 204) for digital signatures, and SLH-DSA (FIPS 205) for stateless hash-based signatures. SLH-DSA is the standardized form of the SPHINCS+ submission. HQC and FN-DSA were selected for standardization; neither is one of these three finalized standards."
    },
    {
      question: "How does QGuard plan and run a migration?",
      answer: "Discovery scans your endpoints, certificates, repositories and infrastructure for quantum-vulnerable primitives such as RSA, ECDSA and Diffie-Hellman, as well as classically weak uses of SHA-1, and builds a CBOM from what it finds. Migration Planner turns that inventory into a sequenced plan, Migration Sandbox models the change before you make it, and Live Migration Ops runs approved waves with snapshots and rollback. ML-KEM replaces key establishment and ML-DSA or SLH-DSA replaces signatures. How long it takes depends on your estate, your vendors and your protocol support, so the platform measures it rather than promising a figure."
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
      question: "What is a quantum random number generator?",
      answer: "A Quantum Random Number Generator draws entropy from a physical process such as photon arrival times or vacuum fluctuations rather than from a seeded algorithm. Its output still has to be conditioned and health-tested, which is what NIST SP 800-90B validation is for. Hardware QRNG sourcing is a preview capability. A runtime randomness API or a dashboard score does not establish entropy source validation."
    },
    {
      question: "Which post-quantum algorithms can I evaluate?",
      answer: "The Quantum Simulation Range exercises ML-KEM for key establishment and ML-DSA and selected SLH-DSA parameter sets for signatures. These are tests with temporary key material. Use your approved KMS or certificate authority to issue production keys and certificates."
    },
    {
      question: "How is entropy quality measured?",
      answer: "NIST SP 800-90B does not produce a percentage score. It is a validation methodology that estimates the min-entropy of a noise source in bits per sample and requires continuous health tests on that source. An SP 800-90B claim needs evidence for the specific entropy source and its health tests. A vendor quoting a percentage entropy score is giving you a marketing number, not an SP 800-90B result."
    },
    {
      question: "Can I export keys to an HSM or external system?",
      answer: "Export and rotation depend on your provider, its supported formats and the policy for that key. Use your KMS or HSM to create and manage private keys; record inventory and rotation evidence in Qguard Helix."
    },
    {
      question: "How do I integrate key generation into my CI/CD pipeline?",
      answer: "Configure your pipeline to request keys from your approved provider and retain only the provider reference and public material in CI. The Qguard Helix key records API does not issue or rotate production key material."
    }
  ]
};

function padNumber(value: number, size: number) {
  return String(Math.max(0, value)).padStart(size, '0');
}

function getQuantumCountdown(now: Date) {
  if (now >= NIST_DEPRECATION_START) {
    return [
      { label: 'Years', value: '00' },
      { label: 'Days', value: '000' },
      { label: 'Hours', value: '00' },
      { label: 'Minutes', value: '00' },
      { label: 'Seconds', value: '00' }
    ];
  }

  let years = NIST_DEPRECATION_START.getUTCFullYear() - now.getUTCFullYear();
  const yearAnchor = new Date(now);
  yearAnchor.setUTCFullYear(now.getUTCFullYear() + years);

  if (yearAnchor > NIST_DEPRECATION_START) {
    years -= 1;
    yearAnchor.setUTCFullYear(now.getUTCFullYear() + years);
  }

  let remaining = NIST_DEPRECATION_START.getTime() - yearAnchor.getTime();
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

function SectionHead({
  eyebrow,
  title,
  children,
}: {
  eyebrow?: React.ReactNode;
  title: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="lp-head">
      {eyebrow && <p className="lp-eyebrow">{eyebrow}</p>}
      <h2 className="lp-h2" data-letters="scroll" aria-label={title}>
        <Chars text={title} />
      </h2>
      {children}
    </div>
  );
}

function HeroSection() {
  const [now, setNow] = useState(() => new Date());
  const countdownUnits = useMemo(() => getQuantumCountdown(now), [now]);

  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1000);

    return () => window.clearInterval(timer);
  }, []);

  return (
    <section id="hero" className="lp-hero">
      <div className="lp-wrap lp-hero__grid">
        <div>
          <p className="lp-eyebrow">Post-Quantum Threat Advisory: Prepare Before Q-Day</p>
          <h1
            className="lp-hero__title"
            data-letters="load"
            aria-label="The Quantum Clock Is Ticking. Your Security Can't Stand Still."
          >
            <Chars text="The Quantum Clock Is " />
            <span className="lp-hero__mark"><Chars text="Ticking" /></span>
            <Chars text="." />
            <span className="lp-hero__cont"><Chars text="Your Security Can't Stand Still." /></span>
          </h1>

          <div className="lp-hero__body">
            <p className="lp-hero__lead">
              What protects your enterprise today could become tomorrow&apos;s greatest vulnerability.
            </p>
            <p>The quantum threat is approaching, and the time to prepare is now.</p>
            <p>
              Qguard Helix helps you uncover hidden cryptographic risks, identify vulnerable encryption,
              and accelerate your transition to quantum-resistant security.
            </p>
            <p className="lp-hero__lifecycle">
              Discover. Assess. Strategize. Migrate. Validate. Govern.
            </p>
            <p>
              From TLS and VPNs to SSH, certificates, and code signing, see and manage the cryptography you discover
              over your cryptographic infrastructure through one intelligent, unified Post-Quantum Cyber Defense platform.
            </p>
            <p className="lp-hero__pledge">
              Stay ahead of the quantum threat. Protect what matters. Prepare for what&apos;s next.
            </p>
            <p className="lp-hero__signature">
              Qguard Helix — Your Bridge to the Quantum-Safe Future.
            </p>
          </div>

          <div className="lp-hero__actions">
            <a href="/auth" className="lp-btn lp-btn--primary lp-btn--dot">
              Start Migration Strategy
              <ButtonDot />
            </a>
          </div>

          <div className="lp-note">
            <AlertTriangle className="lp-icon" aria-hidden="true" />
            <div>
              <h2>Security Alert</h2>
              <p>
                CISA, the NSA and NIST warn that adversaries can capture encrypted traffic today and decrypt it once a cryptographically relevant quantum computer exists. Data that must stay confidential for years is exposed first.
              </p>
            </div>
          </div>
        </div>

        <div className="lp-instrument lp-dark">
          <div className="lp-instrument__head">
            <h2 className="lp-ref">NIST IR 8547 Transition Timeline</h2>
            <p>
              {PQC_TRANSITION_SOURCES.nist.summary} Earlier deadlines apply to priority U.S. federal systems.
            </p>
          </div>

          <div
            className="lp-count"
            role="timer"
            aria-label="Time remaining until the NIST deprecation window begins"
          >
            {countdownUnits.map((unit) => (
              <div className="lp-count__cell" key={unit.label}>
                <div className="lp-label">{unit.label}</div>
                <div className="lp-count__value">{unit.value}</div>
              </div>
            ))}
          </div>

          <p className="lp-instrument__foot">
            Until NIST’s general deprecation window begins
          </p>

          <video
            src={ASSETS.hourglassVideo}
            aria-label="Quantum hourglass countdown video"
            autoPlay
            muted
            loop
            playsInline
            preload="metadata"
            poster={ASSETS.hourglass}
            className="lp-instrument__video"
          />

          <div className="lp-instrument__metrics">
            {[
              { label: "Threat", value: "CRQC" },
              { label: "Priority", value: "PQC" },
              { label: "Timeline", value: "Now" }
            ].map((metric) => (
              <div key={metric.label}>
                <span className="lp-label">{metric.label}</span>
                <strong>{metric.value}</strong>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

function TrustedLeadersSection() {
  const reduceMotion = useReducedMotion();
  return (
    <section className="lp-standards">
      <div className="lp-wrap lp-standards__grid">
        <h2 data-letters="scroll" aria-label="Standards and guidance for post-quantum migration">
          <span><Chars text="Standards and Guidance for" /></span>
          <Chars text="Post-Quantum Migration" />
        </h2>
        {reduceMotion ? (
          <ul>
            {TRUSTED_LEADERS.map((leader) => (
              <li key={leader}>
                <span className="lp-ref">{leader}</span>
              </li>
            ))}
          </ul>
        ) : (
          <div className="lp-standards__rails" role="list" aria-label="Standards and frameworks">
            {[STANDARDS_ROW_A, STANDARDS_ROW_B].map((row, index) => (
              <InfiniteSlider
                key={index}
                gap={12}
                duration={38}
                durationOnHover={90}
                reverse={index === 1}
                className="lp-standards__rail"
              >
                {row.map((leader) => (
                  <span key={leader} role="listitem" className="lp-standards__chip">
                    <span className="lp-ref">{leader}</span>
                  </span>
                ))}
              </InfiniteSlider>
            ))}
          </div>
        )}
      </div>
      <div className="lp-wrap mt-10" aria-label="Primary post-quantum migration sources">
        <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {Object.values(PQC_TRANSITION_SOURCES).map((source) => (
            <div key={source.label}>
              <dt><a className="lp-ref" href={source.url}>{source.label}</a></dt>
              <dd className="mt-1 text-sm leading-relaxed">{source.summary}</dd>
            </div>
          ))}
        </dl>
        <p className="mt-4 text-sm leading-relaxed">
          Qguard Helix helps teams inventory cryptography, plan upgrades and record verification evidence. Algorithm support and evidence mapping do not confer FIPS 140 module validation or establish agency compliance.
        </p>
      </div>
    </section>
  );
}

function WhyItMattersSection() {
  return (
    <section className="lp-section lp-section--clear">
      <div className="lp-wrap">
        <SectionHead title="Why it Matters" />

        <div className="lp-why">
          <figure className="lp-figure">
            <img src="/HNDL.png" alt="Harvest Now, Decrypt Later" referrerPolicy="no-referrer" />
          </figure>

          <ul className="lp-reasons">
            {[
              { icon: Skull, title: "Harvest now, Decrypt later", text: "CISA, the NSA and NIST warn that an adversary can record encrypted traffic today and store it. They do not need to break it now; they only need to keep it until a Cryptographically Relevant Quantum Computer (CRQC) exists." },
              { icon: HourglassIcon, title: "The Window is Closing", text: "Migrating an enterprise estate takes years. NIST deprecates quantum-vulnerable public-key cryptography after 2030 and disallows it under its standards and guidance after 2035. Start with systems that protect sensitive, long-lived data." },
              { icon: Zap, title: "Start While You Can Phase It", text: "The core standards are already final — FIPS 203, 204 and 205 were published in August 2024. Organizations that wait turn a planned, phased migration into an emergency one, and anything captured in the meantime stays exposed." }
            ].map((item) => (
              <li key={item.title}>
                <item.icon className="lp-icon" aria-hidden="true" />
                <div>
                  <h3>{item.title}</h3>
                  <p>{item.text}</p>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}

function HarvestNowVideo() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const inView = useInView(videoRef);
  const reduceMotion = useReducedMotion();
  const playbackOverride = useRef<boolean | null>(null);
  const [isPlaying, setIsPlaying] = useState(false);

  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;

    if (inView && (playbackOverride.current ?? !reduceMotion)) {
      void video.play().catch(() => {});
    } else {
      video.pause();
    }
  }, [inView, reduceMotion]);

  function togglePlayback() {
    const video = videoRef.current;
    if (!video) return;

    playbackOverride.current = video.paused;
    if (video.paused) {
      void video.play().catch(() => {});
    } else {
      video.pause();
    }
  }

  return (
    <div>
      <div className="lp-stage">
        <video
          id="harvest-now-video"
          ref={videoRef}
          src="/Havest_Now_Final.mp4"
          poster="/harvest-now-poster.webp"
          aria-label="Harvest Now, Decrypt Later. Attackers capture encrypted data today, store it, and aim to decrypt it with a future quantum computer."
          muted
          loop
          playsInline
          preload="none"
          onPlay={() => setIsPlaying(true)}
          onPause={() => setIsPlaying(false)}
          onError={() => setIsPlaying(false)}
        />
      </div>
      <div className="lp-stage__controls">
        <button
          type="button"
          aria-controls="harvest-now-video"
          aria-label={`${isPlaying ? 'Pause' : 'Play'} animation for Harvest Now, Decrypt Later`}
          onClick={togglePlayback}
          className="lp-btn lp-btn--ghost-dark lp-btn--sm"
        >
          {isPlaying ? <Pause aria-hidden="true" /> : <Play aria-hidden="true" />}
          {isPlaying ? 'Pause animation' : 'Play animation'}
        </button>
      </div>
    </div>
  );
}

function HarvestNowSection() {
  return (
    <section className="lp-section lp-section--dark">
      <div className="lp-wrap">
        <SectionHead eyebrow="Long-Lived Data At Risk" title="Harvest Now, Decrypt Later" />
        <HarvestNowVideo />
      </div>
    </section>
  );
}

function ActionSection() {
  return (
    <section id="intelligence" className="lp-section">
      <div className="lp-wrap">
        <SectionHead title="What you can do now" />

        <ul className="lp-actions lp-card">
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
              back: "Plan ML-KEM (FIPS 203) for key establishment and ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures. Test hybrid options where protocols and vendors support them. Coordinate certificate rotation, key exchange modernization and policy enforcement, with snapshots and rollback at every wave. How far automation reaches depends on vendor and protocol support in your estate."
            },
            {
              icon: Users,
              label: "Educate",
              front: "Train your security teams on PQC.",
              back: "Migration playbooks, a PQC readiness checklist, quantum simulations, AI migration and executive advisors, and per-asset remediation guidance mapped to the NIST standards — so engineers, security teams and executives can each see what the findings mean for them."
            }
          ].map((item) => (
            <li key={item.label}>
              <h3 className="lp-actions__label">
                <item.icon className="lp-icon" aria-hidden="true" />
                {item.label}
              </h3>
              <p className="lp-actions__front">{item.front}</p>
              <p className="lp-actions__back">{item.back}</p>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

const NIST_STRATEGY_PHASES = [
  {
    phase: "Prepare",
    sub: "(Now)",
    details: "Establish the foundation for post-quantum readiness across the organization. Identify critical systems, sensitive data, cryptographic dependencies, compliance requirements, and long-term security objectives. Build governance policies, executive awareness, and quantum migration task forces aligned with NIST PQC guidance.",
    actions: ["Create crypto governance framework", "Identify critical business assets", "Define quantum readiness objectives", "Establish PQC migration teams", "Review compliance and regulatory impact"]
  },
  {
    phase: "Assess",
    sub: "(Now-1 Yr)",
    details: "Perform enterprise-wide cryptographic discovery and quantum risk analysis. Detect vulnerable algorithms such as RSA, ECC, DH, and weak PKI implementations across infrastructure, applications, APIs, cloud workloads, and communication systems.",
    actions: ["Inventory cryptographic assets", "Detect PQ-vulnerable algorithms", "Analyze TLS, VPN, SSH, PKI exposure", "Rank systems by risk and urgency", "Assess Harvest Now, Decrypt Later exposure"]
  },
  {
    phase: "Plan",
    sub: "(1-2 Yrs)",
    details: "Design a phased migration roadmap for transitioning to NIST-approved post-quantum cryptography. Define hybrid cryptographic architectures, upgrade timelines, vendor dependencies, interoperability testing, and crypto-agility strategies for long-term resilience.",
    actions: ["Build phased migration roadmap", "Select NIST-approved PQC algorithms", "Define hybrid crypto architectures", "Identify application dependencies", "Develop rollback and testing procedures"]
  },
  {
    phase: "Implement",
    sub: "(2-4 Yrs)",
    details: "Roll out post-quantum cryptography in phases. Use ML-KEM for key establishment and choose ML-DSA or SLH-DSA for signatures where protocols and implementations support them. Validate hybrid configurations before deployment.",
    actions: ["Deploy hybrid PQ-TLS environments", "Rotate vulnerable certificates and keys", "Integrate ML-KEM and ML-DSA", "Upgrade VPN, SSH, and PKI systems", "Enable real-time migration telemetry"]
  },
  {
    phase: "Transition",
    sub: "(4-6 Yrs)",
    details: "Gradually phase out legacy cryptographic systems while validating interoperability, performance, and operational stability. Transition production workloads fully into quantum-resistant environments with continuous monitoring and policy enforcement.",
    actions: ["Decommission legacy cryptography", "Validate interoperability and compatibility", "Enforce PQC security policies", "Monitor migration health and coverage", "Harden enterprise-wide PQ infrastructures"]
  },
  {
    phase: "Optimize",
    sub: "(6+ Yrs)",
    details: "Continuously improve crypto-agility, operational resilience, and future quantum readiness. Monitor evolving NIST standards, emerging threats, cryptographic performance, and infrastructure scalability to maintain long-term protection against future quantum capabilities.",
    actions: ["Continuously monitor PQC posture", "Update algorithms and cryptographic policies", "Optimize performance and scalability", "Maintain crypto-agility frameworks", "Prepare for future NIST PQC revisions"]
  }
];

function NistStrategySection() {
  const [expandedPhase, setExpandedPhase] = useState<number | null>(0);
  const expanded = expandedPhase === null ? null : NIST_STRATEGY_PHASES[expandedPhase];

  return (
    <section id="nist-strategy" className="lp-section lp-band">
      <div className="lp-wrap">
        <SectionHead title="Qguard Helix Migration Workflow">
          <p className="lp-lede">
            Our workflow draws on final NIST IR 8547, NCCoE migration project guidance and the joint CISA, NSA and NIST Quantum-Readiness factsheet.
          </p>
        </SectionHead>

        <div className="lp-timeline">
          {NIST_STRATEGY_PHASES.map((step, i) => (
            <button
              key={step.phase}
              type="button"
              aria-expanded={expandedPhase === i}
              aria-controls="nist-strategy-detail"
              onClick={() => setExpandedPhase(expandedPhase === i ? null : i)}
              className="lp-timeline__step"
            >
              <span className="lp-label">{i + 1}</span>
              <span className="lp-timeline__phase">{step.phase}</span>
              <span className="lp-label">{step.sub}</span>
            </button>
          ))}
        </div>

        <div id="nist-strategy-detail">
          {expanded && (
            <div key={expanded.phase} className="lp-timeline__detail lp-dark">
              <div>
                <h3 className="lp-label">Phase Details</h3>
                <p>{expanded.details}</p>
              </div>
              <div>
                <h3 className="lp-label">Key Actions</h3>
                <ul className="lp-list">
                  {expanded.actions.map((action) => (
                    <li key={action}>{action}</li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function InactionSection() {
  return (
    <section className="lp-section">
      <div className="lp-wrap">
        <SectionHead title="The Impact of Inaction">
          <p className="lp-alert-line">Critical Vulnerability Detected</p>
          <p className="lp-lede">
            Delay does not pause the exposure. Anything protected by RSA or elliptic-curve key exchange and captured today can be opened later, and a phased migration becomes an emergency one.
          </p>
        </SectionHead>

        <div className="lp-impact lp-card">
          {[
            { title: "Data Exposure", val: "RSA / ECC", desc: "Traffic and archives whose confidentiality rests on RSA or elliptic-curve key exchange become readable once a CRQC exists." },
            { title: "Unplanned Cost", val: "Unbudgeted", desc: "Re-encryption, certificate replacement and vendor re-contracting all land at once instead of being phased across budget cycles." },
            { title: "Compliance Risk", val: "2030", desc: "The federal key establishment deadline for high value assets and high impact systems is December 31, 2030, excluding National Security Systems." },
            { title: "Loss of Trust", val: "Signatures", desc: "Code signing, firmware signing and PKI that still rely on RSA or ECDSA stop being defensible to auditors and customers." }
          ].map((risk) => (
            <div key={risk.title}>
              <h3>{risk.title}</h3>
              <strong>{risk.val}</strong>
              <p>{risk.desc}</p>
            </div>
          ))}
        </div>
        <p className="lp-label lp-caption">Impact if migration is deferred</p>
      </div>
    </section>
  );
}

function MigrationProcessSection() {
  const [selectedStepId, setSelectedStepId] = useState<string>('01');
  const selectedStep = MIGRATION_PROCESS_STEPS.find((step) => step.id === selectedStepId) || MIGRATION_PROCESS_STEPS[0];
  const selectedIndex = MIGRATION_PROCESS_STEPS.findIndex((step) => step.id === selectedStep.id);
  const implementationPercent = Math.round(((selectedIndex + 1) / MIGRATION_PROCESS_STEPS.length) * 100);
  const SelectedIcon = selectedStep.icon;

  return (
    <section id="migration-process" className="lp-section lp-band">
      <div className="lp-wrap">
        <SectionHead eyebrow="Strategic Deployment Pipeline" title="Our Post-Quantum Migration Process">
          <p className="lp-lede">
            A modular migration architecture built on the published migration guidance — NIST IR 8547, NIST NCCoE migration guidance and the joint CISA, NSA and NIST Quantum-Readiness factsheet — with rollback controls at every stage.
          </p>
        </SectionHead>

        <div className="lp-process__tabs" role="tablist" aria-label="Post-quantum migration process steps">
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
                className="lp-process__tab"
              >
                <span className="lp-process__tab-top">
                  <span className="lp-label">{step.num}</span>
                  <Icon className="lp-icon" aria-hidden="true" />
                </span>
                <span className="lp-process__tab-title">{step.title}</span>
                <span className="lp-process__tab-copy">{step.description}</span>
              </button>
            );
          })}
        </div>

        <div
          key={selectedStep.id}
          id="migration-process-details"
          role="tabpanel"
          className="lp-process__detail lp-dark"
        >
          <div className="lp-process__main">
            <div className="lp-process__meta">
              <span className="lp-label">Stage {selectedStep.num} Specification Infrastructure</span>
              <span className="lp-tag">{selectedStep.badge}</span>
            </div>
            <h3>
              <span>{selectedStep.num}</span>
              {selectedStep.title} Workflow Integration
            </h3>
            <p>{selectedStep.details}</p>
          </div>

          <div className="lp-process__status" aria-label={`${selectedStep.title} module status`}>
            <SelectedIcon className="lp-icon" aria-hidden="true" />
            <strong>Stage Position</strong>
            <span>Lifecycle Sequence</span>
            <div className="lp-progress">
              <i style={{ transform: `scaleX(${implementationPercent / 100})` }} />
            </div>
            <span className="lp-label">Stage {selectedIndex + 1} of {MIGRATION_PROCESS_STEPS.length}</span>
          </div>
        </div>
      </div>
    </section>
  );
}

function CoreCapabilitiesSection() {
  return (
    <section id="core-capabilities-section" className="lp-section">
      <div className="lp-wrap">
        <SectionHead eyebrow="System Capabilities" title="Core Platform Capabilities">
          <p className="lp-lede">
            The fundamental capabilities of the QGuard Helix platform engineered to discover, manage, and secure cryptographic vulnerabilities at scale.
          </p>
        </SectionHead>

        <ul className="lp-caps">
          {capabilities.map((cap) => (
            <li key={cap.num} id={`core-cap-${cap.num}`}>
              <span className="lp-label">{cap.num}</span>
              <div>
                <h3>{cap.title}</h3>
                <p>{cap.desc}</p>
              </div>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

const SANDBOX_STATUS_LABELS: Record<CryptoKey['quantumStatus'], string> = {
  vulnerable: 'Quantum-vulnerable',
  symmetric: 'Symmetric resilient',
  pqc: 'NIST PQC',
};

function sandboxLogTone(log: string) {
  if (log.startsWith('!')) return 'risk';
  if (log.startsWith('OK')) return 'ok';
  if (log.startsWith('>>')) return 'finding';
  return undefined;
}

function EnterpriseProtectionShowcase() {
  const [selectedKey, setSelectedKey] = useState<CryptoKey>(CRYPTO_SANDBOX_KEYS[0]);
  const [isRunning, setIsRunning] = useState(false);
  const [consoleLogs, setConsoleLogs] = useState<string[]>([]);
  const [assessmentResult, setAssessmentResult] = useState<'idle' | 'risk' | 'resilient'>('idle');

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
    <section id="simulator" className="lp-section">
      <div className="lp-wrap">
        <SectionHead eyebrow="Interactive Cryptographic Playground" title="Quantum Risk Assessment Sandbox">
          <p className="lp-lede">
            Simulate how cryptographic discovery identifies quantum-vulnerable
            RSA/ECC assets, symmetric-key resilience, and NIST-standardized PQC
            migration targets such as ML-KEM, ML-DSA, and SLH-DSA.
          </p>
        </SectionHead>

        <div className="lp-sandbox">
          <div className="lp-sandbox__picker lp-card">
            <div className="lp-sandbox__picker-head">
              <span className="lp-label">Available crypto primitives</span>
              <span className="lp-label">Select to assess</span>
            </div>

            {CRYPTO_SANDBOX_KEYS.map((cryptoKey) => (
              <button
                key={cryptoKey.name}
                type="button"
                disabled={isRunning}
                aria-pressed={selectedKey.name === cryptoKey.name}
                onClick={() => setSelectedKey(cryptoKey)}
                className="lp-prim"
              >
                <span className="lp-prim__name">
                  {cryptoKey.name}
                  <span className={`lp-prim__status lp-prim__status--${cryptoKey.quantumStatus}`}>
                    {SANDBOX_STATUS_LABELS[cryptoKey.quantumStatus]}
                  </span>
                </span>
                <span className="lp-prim__size">{cryptoKey.keySize}</span>
                <span className="lp-prim__type">{cryptoKey.type}</span>
              </button>
            ))}

            <p className="lp-sandbox__advice">
              <strong>Recommended Defense Alignment:</strong>
              Align migration with NIST FIPS 203 ML-KEM for key
              establishment, FIPS 204 ML-DSA for digital signatures, and
              FIPS 205 SLH-DSA where stateless hash-based signatures are
              appropriate.
            </p>
          </div>

          <div className="lp-console lp-dark">
            <div className="lp-console__bar">
              <span>PQC_RISK_ASSESSMENT_CORE</span>
              {!isRunning && <span>Status: Ready</span>}
            </div>

            <dl className="lp-console__fields">
              <div>
                <dt className="lp-label">Algorithm / standard</dt>
                <dd>{selectedKey.structure}</dd>
              </div>
              <div>
                <dt className="lp-label">Quantum attack model</dt>
                <dd>{selectedKey.quantumAttackModel}</dd>
              </div>
              <div>
                <dt className="lp-label">Risk assessment</dt>
                <dd data-tone={selectedKey.quantumStatus === 'vulnerable' ? 'risk' : undefined}>
                  {selectedKey.assessment}
                </dd>
              </div>
            </dl>

            <div className="lp-console__log" aria-live="polite">
              {consoleLogs.map((log, index) => (
                <div key={`${log}-${index}`} data-tone={sandboxLogTone(log)}>
                  {log}
                </div>
              ))}

              {isRunning && (
                <div data-tone="finding">
                  <RefreshCw className="lp-icon lp-spin" aria-hidden="true" style={{ display: 'inline', width: 14, height: 14, marginRight: 8, color: 'inherit' }} />
                  Evaluating quantum-relevant cryptographic exposure...
                </div>
              )}
            </div>

            <div className="lp-console__foot">
              {assessmentResult === 'idle' && (
                <span>
                  * Run assessment to classify the selected primitive
                  against quantum-relevant risk models.
                </span>
              )}

              {assessmentResult === 'risk' && (
                <span className="lp-console__result lp-console__result--risk">
                  <AlertTriangle aria-hidden="true" />
                  Quantum migration required
                </span>
              )}

              {assessmentResult === 'resilient' && (
                <span className="lp-console__result lp-console__result--ok">
                  <CheckCircle2 aria-hidden="true" />
                  Post-quantum risk acceptable
                </span>
              )}

              <button
                type="button"
                disabled={isRunning}
                onClick={runAssessment}
                className="lp-btn lp-btn--light"
              >
                {isRunning ? 'Assessment Running...' : 'Run Quantum Risk Assessment'}
              </button>
            </div>
          </div>
        </div>

        <div className="lp-after">
          <a href="/resources/quantum-simulation" className="lp-link">
            See Quantum Simulations
            <ArrowRight aria-hidden="true" />
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
    <section id="roadmap" className="lp-section lp-band">
      <div className="lp-wrap">
        <SectionHead eyebrow="Example enterprise roadmap" title="2026-2029 Post-Quantum Migration Plan">
          <p className="lp-lede">
            A phased enterprise roadmap for discovering quantum-vulnerable
            cryptography, prioritizing migration, piloting NIST-standardized
            PQC, and maintaining crypto agility. Use applicable federal milestones when scheduling an agency migration.
          </p>
        </SectionHead>

        <div className="lp-roadmap">
          <div>
            <span className="lp-label">Migration phases: 2026 - 2029</span>

            <div className="lp-roadmap__list">
              {ROADMAP_MILESTONES.map((milestone) => (
                <button
                  type="button"
                  key={milestone.id}
                  aria-pressed={milestone.id === selectedId}
                  aria-controls="roadmap-phase-detail"
                  className="lp-phase"
                  onClick={() => setSelectedId(milestone.id)}
                >
                  <span className="lp-phase__year">{milestone.quarter}</span>
                  <span>
                    <span className="lp-phase__title">{milestone.title}</span>
                    <span className="lp-phase__sub">{milestone.subtitle}</span>
                    <span className="lp-label lp-phase__status">{milestone.statusLabel}</span>
                  </span>
                </button>
              ))}
            </div>
          </div>

          <article
            key={selectedId}
            id="roadmap-phase-detail"
            aria-labelledby="roadmap-phase-title"
            className="lp-roadmap__detail lp-dark"
          >
            <div className="lp-console__bar lp-roadmap__detail-top">
              <span className="lp-label">Phase {currentMilestone.id} · Enterprise planning example</span>
              <span className="lp-tag">
                <Calendar aria-hidden="true" strokeWidth={1.5} />
                {currentMilestone.quarter}
              </span>
            </div>

            <div className="lp-roadmap__body">
              <span className="lp-label">Objective focus</span>
              <h3 id="roadmap-phase-title">{currentMilestone.title}</h3>
              <p>{currentMilestone.description}</p>

              <dl className="lp-roadmap__metrics">
                {currentMilestone.metrics.map((metric) => (
                  <div key={metric.name}>
                    <dt className="lp-label">{metric.name}</dt>
                    <dd>{metric.val}</dd>
                  </div>
                ))}
              </dl>

              <span className="lp-label">Key deliverables & controls:</span>
              <ul className="lp-list lp-list--check">
                {currentMilestone.deliverables.map((item) => (
                  <li key={item}>
                    <Check aria-hidden="true" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="lp-roadmap__foot">
              <span className="lp-label">Target: Inventory - Prioritize - Migrate - Validate</span>
              <span className="lp-label">Crypto-agility roadmap online</span>
            </div>
          </article>
        </div>
      </div>
    </section>
  );
}

function QuantumSecurityUseCasesSection() {
  const [activeIndex, setActiveIndex] = useState(2);
  const activeFeature = QUANTUM_USE_CASES[activeIndex];

  return (
    <section id="use-cases" className="lp-section lp-band">
      <div className="lp-wrap">
        <SectionHead
          eyebrow={
            <>
              Applied Quantum Defense
              <span className="lp-tag">Coming Soon</span>
            </>
          }
          title="Quantum Encryption Services Use Cases"
        >
          <p className="lp-lede">
            Applying NIST-standardized post-quantum cryptography to the services enterprises depend on.
          </p>
          <p className="lp-preview">
            Roadmap preview &mdash; these quantum encryption services are planned QGuard Helix capabilities. They are not yet available in the platform.
          </p>
        </SectionHead>

        <div className="lp-usecases">
          <div className="lp-usecases__list">
            {QUANTUM_USE_CASES.map((feature, index) => {
              const Icon = feature.icon;

              return (
                <button
                  key={feature.id}
                  type="button"
                  aria-pressed={activeIndex === index}
                  onClick={() => setActiveIndex(index)}
                  className="lp-usecase"
                >
                  <Icon className="lp-icon" aria-hidden="true" />
                  <span>
                    <strong>{feature.title}</strong>
                    <span>{feature.description}</span>
                  </span>
                </button>
              );
            })}
          </div>

          <article key={activeFeature.id} className="lp-usecases__detail lp-card">
            <img src={activeFeature.image} alt={activeFeature.title} />
            <div className="lp-usecases__intro">
              <span className="lp-tag">Coming Soon</span>
              <h3>{activeFeature.title}</h3>
              <p>{activeFeature.description}</p>
            </div>

            <div className="lp-usecases__cols">
              {[
                { heading: "Real World Use Cases", items: activeFeature.useCases },
                { heading: "Key Features", items: activeFeature.keyFeatures }
              ].map((column) => (
                <div key={column.heading}>
                  <h4>{column.heading}</h4>
                  <ul className="lp-list">
                    {column.items.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </article>
        </div>
      </div>
    </section>
  );
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

  if (!isOpen) {
    return null;
  }

  return (
    <div className="lp-modal">
      <div className="lp-modal__scrim" onClick={handleClose} />

      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="request-demo-modal-title"
        className="lp-modal__dialog"
      >
        <div className="lp-modal__head">
          <div>
            <h3 id="request-demo-modal-title">Request Cryptographic Demo</h3>
            <p className="lp-label">Secure PQC Handshake Link</p>
          </div>
          <button
            type="button"
            onClick={handleClose}
            className="lp-modal__close"
            id="btn-close-modal"
            aria-label="Close request demo modal"
          >
            <X className="lp-icon" aria-hidden="true" />
          </button>
        </div>

        {step !== 'success' && (
          <form onSubmit={handleSubmit} id="demo-request-form" noValidate>
            <fieldset disabled={step === 'sending'} className="lp-form">
              <div aria-hidden="true" className="lp-sr">
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

              <label className="lp-field">
                Your Name
                <input
                  type="text"
                  required
                  autoComplete="name"
                  maxLength={DEMO_FIELD_LIMITS.name}
                  value={formData.name}
                  onChange={(event) => setFormData({ ...formData, name: event.target.value })}
                  placeholder="Enter full name"
                />
              </label>

              <div className="lp-form__row">
                <label className="lp-field">
                  Work Email
                  <input
                    type="email"
                    required
                    autoComplete="email"
                    maxLength={DEMO_FIELD_LIMITS.email}
                    value={formData.email}
                    onChange={(event) => setFormData({ ...formData, email: event.target.value })}
                    placeholder="name@organization.com"
                  />
                </label>
                <label className="lp-field">
                  Organization
                  <input
                    type="text"
                    required
                    autoComplete="organization"
                    maxLength={DEMO_FIELD_LIMITS.organization}
                    value={formData.organization}
                    onChange={(event) => setFormData({ ...formData, organization: event.target.value })}
                    placeholder="Agency / Corp"
                  />
                </label>
              </div>

              <label className="lp-field">
                PQC Migration Status
                <select
                  value={formData.stage}
                  onChange={(event) => setFormData({ ...formData, stage: event.target.value as DemoStage })}
                >
                  {DEMO_STAGES.map((stage) => (
                    <option key={stage.value} value={stage.value}>{stage.label}</option>
                  ))}
                </select>
              </label>

              <label className="lp-field" htmlFor="demo-request-message">
                <span>Message <em>(optional)</em></span>
                <textarea
                  id="demo-request-message"
                  rows={4}
                  maxLength={DEMO_FIELD_LIMITS.message}
                  value={formData.message}
                  onChange={(event) => setFormData({ ...formData, message: event.target.value })}
                  placeholder="What would you like to see? e.g. your environment, timelines, compliance drivers"
                />
              </label>

              <label className="lp-check">
                <input
                  type="checkbox"
                  checked={formData.whitepaper}
                  onChange={(event) => setFormData({ ...formData, whitepaper: event.target.checked })}
                />
                <span>
                  Check to receive: <strong>"Post-Quantum Readiness Playbook (.pdf)"</strong> — a walkthrough of the NIST migration guidance applied to your estate.
                </span>
              </label>

              {sendError && (
                <div role="alert" className="lp-error">
                  <AlertTriangle aria-hidden="true" />
                  <div>
                    <p>{sendError.message}</p>
                    {sendError.inbox && (
                      <a href={demoRequestMailto(sendError.inbox, formData)}>
                        Open an email to {sendError.inbox} with these details
                      </a>
                    )}
                  </div>
                </div>
              )}

              <div className="lp-modal__actions">
                <button
                  type="button"
                  onClick={handleClose}
                  className="lp-btn lp-btn--secondary lp-btn--sm"
                  id="btn-cancel-demo"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="lp-btn lp-btn--primary lp-btn--sm"
                  id="btn-submit-demo-form"
                >
                  {step === 'sending' ? (
                    <>
                      Sending…
                      <Loader className="lp-spin" aria-hidden="true" />
                    </>
                  ) : (
                    <>
                      Request Demo
                      <ArrowRight aria-hidden="true" />
                    </>
                  )}
                </button>
              </div>
            </fieldset>
          </form>
        )}

        {step === 'success' && (
          <div className="lp-success">
            <h4>Demo Request Sent</h4>
            <p>
              Thanks, <strong>{formData.name}</strong>. Your request reached <strong>{deliveredTo}</strong>. We will reply to <strong>{formData.email}</strong> to schedule the session for <strong>{formData.organization}</strong>.
            </p>
            <dl>
              <dt>Contact email:</dt>
              <dd>{formData.email}</dd>
              <dt>PQC migration stage:</dt>
              <dd>{demoStageLabel(formData.stage)}</dd>
              <dt>Readiness guide:</dt>
              <dd>{formData.whitepaper ? 'Requested (.pdf)' : 'Not requested'}</dd>
            </dl>

            <div className="lp-modal__actions">
              <button
                type="button"
                onClick={handleClose}
                className="lp-btn lp-btn--primary lp-btn--sm"
                id="btn-close-demo-success"
              >
                Return to Homepage
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function PricingSection() {
  const [billingPeriod, setBillingPeriod] = useState<"monthly" | "yearly">("yearly");
  const [checkoutPlan, setCheckoutPlan] = useState<string | null>(null);

  const handleSubscribe = (planName: string) => {
    if (checkoutPlan) return;
    setCheckoutPlan(planName);
    // Route through the auth-gated checkout bridge: it requires sign-in, then
    // creates the PayPal subscription and redirects the user to PayPal.
    window.location.href = `/checkout?plan=${encodeURIComponent(planName)}&cycle=${billingPeriod}`;
  };

  return (
    <section id="pricing" className="lp-section">
      <div className="lp-wrap">
        <SectionHead eyebrow="Pricing Scheme" title="Invest in Post-Quantum Transition">
          <p className="lp-lede">
            Transparent plans tailored to your enterprise migration velocity. Build an evidence-backed cryptographic inventory and measurable crypto-agility.
          </p>
        </SectionHead>

        <div className="lp-toggle" role="group" aria-label="Billing period">
          <button
            type="button"
            onClick={() => setBillingPeriod("monthly")}
            aria-pressed={billingPeriod === "monthly"}
          >
            Monthly
          </button>
          <button
            type="button"
            onClick={() => setBillingPeriod("yearly")}
            aria-pressed={billingPeriod === "yearly"}
          >
            Yearly
          </button>
        </div>

        <div className="lp-plans">
          {PRICING_PLANS.map((plan) => {
            const price = billingPeriod === "monthly" ? plan.priceMonthly : plan.priceYearly;
            const annualTotal = plan.priceYearly * 12;

            return (
              <div
                key={plan.name}
                className={`lp-plan lp-card ${plan.popular ? "lp-plan--popular" : ""}`}
                id={`pricing-plan-${plan.name.toLowerCase()}`}
              >
                <div className="lp-plan__top">
                  <span className="lp-label">{plan.badge}</span>
                  {plan.popular && (
                    <span className="lp-label lp-plan__recommended">Recommended for Transition</span>
                  )}
                </div>

                <h3>{plan.name}</h3>
                <p className="lp-plan__desc">{plan.description}</p>

                <div className="lp-plan__price">
                  <strong>${billingPeriod === "yearly" ? annualTotal.toLocaleString("en-US") : price}</strong>
                  <span>{billingPeriod === "yearly" ? "/ year" : "/ month"}</span>

                  {billingPeriod === "yearly" ? (
                    <p>Billed once a year · renews automatically · cancel anytime</p>
                  ) : (
                    <p>Billed monthly · renews automatically · cancel anytime</p>
                  )}
                </div>

                <span className="lp-label lp-plan__included">Capabilities Included:</span>
                <ul className="lp-list lp-list--check">
                  {plan.features.map((feat) => (
                    <li key={feat}>
                      <Check aria-hidden="true" />
                      <span>{feat}</span>
                    </li>
                  ))}
                </ul>

                {plan.learnMoreHref && (
                  <a href={plan.learnMoreHref} className="lp-link">
                    Learn More
                    <ArrowRight aria-hidden="true" />
                  </a>
                )}

                <div className="lp-plan__cta">
                  <button
                    type="button"
                    onClick={() => handleSubscribe(plan.name)}
                    disabled={checkoutPlan !== null}
                    className={`lp-btn lp-btn--block ${plan.popular ? "lp-btn--primary" : "lp-btn--secondary"}`}
                  >
                    {checkoutPlan === plan.name ? "Redirecting to PayPal…" : plan.ctaText}
                  </button>
                  <p>Paid plan · no free trial · access continues until the end of the paid period after cancelling</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
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
    <section id="faq" className="lp-section lp-band">
      <div className="lp-wrap">
        <div className="lp-faq">
          <div>
            <p className="lp-eyebrow">Got Questions?</p>
            <h2 className="lp-h2" data-letters="scroll" aria-label="Frequently Asked Questions">
              <Chars text="Frequently Asked Questions" />
            </h2>

            <div className="lp-faq__cats">
              {FAQ_CATEGORIES.map((category) => (
                <button
                  key={category.key}
                  type="button"
                  aria-pressed={selectedCategory === category.key}
                  onClick={() => handleCategoryChange(category.key)}
                >
                  {category.label}
                </button>
              ))}
            </div>
          </div>

          <div>
            {activeFaqs.map((faq, index) => {
              const isOpen = openIndex === index;

              return (
                <div key={faq.question} className="lp-faq__item">
                  <button
                    type="button"
                    aria-expanded={isOpen}
                    onClick={() => setOpenIndex(isOpen ? null : index)}
                    className="lp-faq__q"
                  >
                    {faq.question}
                    <Plus className="lp-icon" aria-hidden="true" />
                  </button>
                  {isOpen && <p className="lp-faq__a">{faq.answer}</p>}
                </div>
              );
            })}
          </div>
        </div>

        <div className="lp-cta lp-dark">
          <div>
            <h2 className="lp-h2" data-letters="scroll" aria-label="Ready for Quantum Safety?">
              <Chars text="Ready for Quantum Safety?" />
            </h2>
            <p>Create your free account and start your quantum vulnerability scan today.</p>
          </div>
          <div className="lp-cta__actions">
            <a href="/auth" className="lp-btn lp-btn--light lp-btn--dot">
              Create Free Account
              <ButtonDot />
            </a>
            <button type="button" className="lp-btn lp-btn--ghost-dark">
              Learn More
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}

function HomepageFooter({ onRequestDemo }: { onRequestDemo: () => void }) {
  return (
    <footer className="lp-footer">
      <div className="lp-wrap">
        <div className="lp-footer__grid">
          <div>
            <a href="#hero" className="lp-footer__brand">
              <img src="/NEW_LOGO.png" alt="Qguard Helix logo" />
              <span>
                <strong>Qguard Helix</strong>
                <small>Quantum Cyber Defense</small>
              </span>
            </a>

            <p className="lp-footer__about">
              Empowering enterprises to build a quantum-secure future with
              confidence through cryptographic automation, continuous
              vulnerability scanning, and continuous post-quantum readiness monitoring.
            </p>
          </div>

          <nav className="lp-footer__cols" aria-label="Footer navigation">
            {[
              {
                title: "Platform",
                links: [
                  { label: "Overview", href: "#hero" },
                  { label: "Features", href: "/qguard-helix-features" }
                ]
              },
              {
                title: "Solutions",
                links: [
                  { label: "Use Cases", href: "#use-cases" },
                  { label: "Migration Roadmap", href: "#roadmap" }
                ]
              },
              {
                title: "Resources",
                links: [
                  { label: "PQC Checklist", href: "/resources/pqc-checklist" },
                  { label: "Documentation", href: "/docs" }
                ]
              }
            ].map((column) => (
              <div key={column.title}>
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

          <aside className="lp-footer__cta">
            <h3>Ready to become quantum safe?</h3>
            <p>
              Schedule a walkthrough to see cryptographic discovery, quantum
              risk scoring and post-quantum migration running on real data.
            </p>
            <button type="button" onClick={onRequestDemo} className="lp-btn lp-btn--primary lp-btn--dot">
              Request Demo
              <ButtonDot />
            </button>
          </aside>
        </div>

        <div className="lp-footer__bottom">
          <p>&copy; {new Date().getUTCFullYear()} Qguard Helix. All rights reserved.</p>

          <div className="lp-footer__legal">
            <a href="/privacy">Privacy Policy</a>
            <a href="/terms">Terms of Service</a>
            <a href="/refund">Refund Policy</a>
            <a href="/contact">Contact</a>
          </div>
        </div>
      </div>
    </footer>
  );
}

export default function App() {
  const [isDemoModalOpen, setIsDemoModalOpen] = useState(false);
  const openDemoModal = () => setIsDemoModalOpen(true);
  const rootRef = useRef<HTMLDivElement>(null);
  const glowRef = useRef<HTMLCanvasElement>(null);
  useLandingMotion(rootRef, glowRef, isDemoModalOpen);

  return (
    <TooltipProvider>
      <div className="lp" ref={rootRef}>
        <div className="lp-atmo" aria-hidden="true">
          <canvas ref={glowRef} width={96} height={60} />
        </div>

        <Navbar2 onRequestDemo={openDemoModal} />

        <HeroSection />
        <TrustedLeadersSection />
        <WhyItMattersSection />
        <HarvestNowSection />
        <ActionSection />
        <NistStrategySection />
        <InactionSection />
        <MigrationProcessSection />
        <CoreCapabilitiesSection />
        <QuantumFeaturesMarquee />
        <EnterpriseProtectionShowcase />
        <RoadmapSection />
        <Hero195 />
        <QuantumSecurityUseCasesSection />
        <PricingSection />
        <FaqAndCtaSection />

        <HomepageFooter onRequestDemo={openDemoModal} />

        <RequestDemoModal isOpen={isDemoModalOpen} onClose={() => setIsDemoModalOpen(false)} />
      </div>
    </TooltipProvider>
  );
}
