<div align="center">

<img width="1200" height="475" alt="QGuardHelix Banner" src="https://github.com/teslagreat101/QguardHelix_PQC_Migration/blob/main/src/assets/images/QguardHelix_github.png" />

# QGuardHelix — Quantum Cyber Defense Platform

### Enterprise-Grade Post-Quantum Cybersecurity, Threat Detection, PQC Migration & Quantum Readiness

[![Vite](https://img.shields.io/badge/Vite-8-646cff?style=for-the-badge&logo=vite)](https://vite.dev/)
[![React](https://img.shields.io/badge/React-19-61dafb?style=for-the-badge&logo=react)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-3178c6?style=for-the-badge&logo=typescript)](https://www.typescriptlang.org/)
[![Post Quantum](https://img.shields.io/badge/Post--Quantum-Security-gold?style=for-the-badge)](#)
[![Enterprise](https://img.shields.io/badge/Enterprise-Grade-00d084?style=for-the-badge)](#)

</div>

---

# 🛡️ Overview

QGuardHelix is an advanced Quantum Cyber Defense Platform designed to help organizations detect, assess, and migrate vulnerable cryptographic infrastructure before the arrival of Cryptographically Relevant Quantum Computers (CRQC).

The platform delivers:

- Quantum Vulnerability Discovery
- PQC Migration Planning
- Quantum Readiness Scoring
- Real-Time Threat Monitoring
- Secure Quantum Vaulting
- Quantum Random Key Generation (QRNG)
- Enterprise Security Telemetry
- Post-Quantum Cryptography Protection

Built for enterprise environments, QGuardHelix enables organizations to prepare for the post-quantum era before existing encryption becomes obsolete.

---

# ⚡ Core Features

## 🔍 PQC Discovery Scanner
Identify quantum-vulnerable cryptographic assets across your infrastructure.

- RSA / ECC discovery
- Weak TLS detection
- Deprecated algorithm detection
- Certificate inventory analysis
- Quantum risk scoring
- Real-time scan telemetry
- Live SSE/WebSocket updates

---

## 🧬 PQC Migration Wizard
Accelerate migration toward NIST-approved post-quantum cryptography.

Supported migration targets:
- ML-KEM (Kyber)
- ML-DSA (Dilithium)
- Hybrid cryptography
- Quantum-safe TLS planning

Features:
- Migration roadmap generation
- Asset prioritization
- Compliance alignment
- Rollback simulation
- Risk impact visualization

---

## 🔐 Quantum Vault
Secure encrypted storage powered by post-quantum cryptography.

- ML-KEM encryption
- AES-256-GCM protection
- Zero-knowledge architecture
- Secure file encryption
- Protected communications
- Quantum-resistant key storage

---

## ⚛️ Quantum QRNG
Generate high-entropy quantum-safe cryptographic material.

- Quantum random generation
- Secure token creation
- PQC-ready key material
- Entropy validation
- Secure seeding pipelines

---

## 📡 Real-Time Monitoring
Enterprise-grade telemetry and security analytics.

- Live dashboard monitoring
- Attack surface visibility
- Risk scoring updates
- Security event telemetry
- Threat intelligence feeds
- Quantum readiness analytics

---

# 🧠 Technology Stack

## Frontend
- Vite 8 (build & dev server)
- React 19
- TypeScript
- React Router 7 (SPA routing)
- Tailwind CSS v4
- ShadCN UI / Radix UI
- Framer Motion / Motion
- Zustand (state management)
- Three.js & GSAP (visualization)

## Backend
- Node.js
- Express 4 (API server, mounted into Vite in dev via a custom plugin; run standalone in production)
- tsx (TypeScript execution)
- Server-Sent Events (SSE) for real-time streams
- Supabase (Postgres, Auth, Storage) with primary + fallback project failover

## Security & PQC
- ML-KEM (Kyber) & ML-DSA (Dilithium) via [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum)
- AES-256-GCM (Web Crypto API)
- Google Gemini (`@google/genai`) for AI features

## AI / Cloud
- `@google/genai` (Gemini)
- AWS / Azure / GCP SDKs (optional, gated cloud operator patch adapters)

## Cloud Operator Patch Adapters

QGuard Helix includes optional AWS, Azure, and GCP SDK patch adapters for approved connector/operator remediation. They are disabled by default and only run when all safety gates pass:

- `QGUARD_ENABLE_CLOUD_SDK_PATCHES=true` in the operator runtime
- connector metadata `sdkPatchEnabled=true`
- tenant administrator approval
- connector target allowlist match
- least-privilege connector scopes
- explicit operator execute request

Install only the SDK packages required by the providers you operate:

```bash
npm install @aws-sdk/client-elastic-load-balancing-v2 @aws-sdk/client-s3 @aws-sdk/client-kms @aws-sdk/client-rds
npm install @azure/identity @azure/arm-network @azure/arm-storage
npm install @google-cloud/storage @google-cloud/compute
```

The adapters use provider default credential chains such as AWS IAM role/instance profile, Azure DefaultAzureCredential, and GCP Application Default Credentials. Do not paste private cloud keys into QGuard connector records.

---

# 🚀 Local Development

## Prerequisites

- Node.js 20+
- npm / pnpm
- Git

---

## 1. Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/QGuardHelix_PQC_Migration.git
cd QGuardHelix_PQC_Migration
```

---

## 2. Install Dependencies

```bash
npm install
```

---

## 3. Configure Environment Variables

Copy the example file and fill in your values:

```bash
cp .env.example .env
```

Key variables (see `.env.example` for the full list):

```env
# Gemini AI
GEMINI_API_KEY=your_api_key_here

# Supabase (primary project)
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your_anon_key
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key

# Optional fallback Supabase project (used when primary is unavailable
# or when *_USE_FALLBACK=true)
VITE_SUPABASE_FALLBACK_URL=
VITE_SUPABASE_FALLBACK_ANON_KEY=
SUPABASE_FALLBACK_SERVICE_ROLE_KEY=
VITE_SUPABASE_USE_FALLBACK=false
SUPABASE_USE_FALLBACK=false
```

> The frontend and the Express API run together from a single dev server — there is no separate API port.

---

## 4. Run Development Server

```bash
npm run dev
```

The app and its `/api/v1` backend both run on:

```bash
http://localhost:3000
```

For a production-style run (serves the built `dist/` plus the API):

```bash
npm run build
npm start
```

---

# 🛰️ Production Goals

QGuardHelix is designed to evolve into a fully enterprise-ready quantum security ecosystem capable of:

- Quantum vulnerability detection
- Autonomous PQC migration
- Enterprise cryptographic governance
- Real-time threat intelligence
- Quantum-safe communications
- Secure decentralized vaulting
- AI-powered security orchestration

---

# ⚠️ Why Post-Quantum Security Matters

Harvest Now, Decrypt Later attacks are already happening.

Threat actors and state-sponsored groups are actively collecting encrypted traffic today with the intention of decrypting it once large-scale quantum computers become operational.

Organizations that delay migration risk:
- Long-term data exposure
- Certificate compromise
- Historical archive decryption
- Infrastructure obsolescence
- Compliance failure

The transition to PQC takes years — preparation must begin now.

---

# 📌 Status

QGuardHelix is currently under active development.

Focused areas:
- Enterprise UI/UX
- Real-time telemetry
- PQC migration automation
- Threat intelligence
- Quantum-safe infrastructure
- Production-grade scalability

---

# 📄 License

This project is intended for research, educational, and defensive cybersecurity purposes.

---

<div align="center">

### QGuardHelix — Securing the Post-Quantum Future

</div>
