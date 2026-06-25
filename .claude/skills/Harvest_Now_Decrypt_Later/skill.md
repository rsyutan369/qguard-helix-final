# SKILL.md

name: harvest-now-decrypt-later-architect

description:

Enterprise Harvest Now, Decrypt Later (HNDL) specialist responsible for identifying future quantum decryption risks, cryptographic exposure, forward secrecy gaps, long-term confidentiality risks, and post-quantum migration priorities.

The skill ensures QGuard Helix accurately discovers, analyzes, scores, visualizes, and remediates HNDL exposure across cloud, on-premises, SaaS, identities, applications, APIs, certificates, keys, and encrypted data stores.

---

## Core Mission

Answer the following questions:

1. What data can be harvested today?
2. What data remains valuable in 5–25 years?
3. Which cryptographic assets are vulnerable to future CRQC attacks?
4. Which systems lack forward secrecy?
5. What is the estimated future decryptable data volume?
6. Which assets require immediate PQC migration?
7. What is the business impact if harvested today and decrypted later?

---

# Modules

## HNDL Exposure Discovery

Responsibilities:

* Discover cryptographic assets
* Identify legacy cryptography
* Detect vulnerable key exchanges
* Detect non-PFS protocols
* Identify long-term encrypted assets
* Discover archived encrypted data
* Discover encrypted backups
* Discover encrypted databases
* Discover encrypted storage systems

Inventory:

* TLS
* VPN
* SSH
* PKI
* Certificates
* Keys
* Databases
* Archives
* Object Storage
* SaaS Platforms

---

## Harvest Value Engine™

Responsibilities:

* Classify data value
* Determine adversary interest
* Estimate future intelligence value
* Rank high-value targets

Scoring Factors:

* Data sensitivity
* Regulatory impact
* Retention requirements
* Intellectual property value
* Business criticality
* Nation-state interest

Classifications:

* Public
* Internal
* Confidential
* Restricted
* Secret
* Mission Critical

Outputs:

* Harvest Value Score
* Adversary Interest Score
* Confidentiality Duration Score

---

## Data Shelf-Life Analyzer™

Responsibilities:

Determine how long data must remain confidential.

Examples:

* Customer Records
* Trade Secrets
* Source Code
* Financial Data
* Legal Records
* Healthcare Data
* Government Data
* Research Data

Metrics:

* Retention Period
* Confidentiality Duration
* Quantum Risk Window
* Business Impact

Outputs:

* Shelf-Life Score
* Confidentiality Risk Score
* HNDL Priority Score

---

## Cryptographic Exposure Matrix™

Responsibilities:

Inventory and score all cryptographic algorithms.

Evaluate:

* RSA
* ECDSA
* DSA
* Diffie-Hellman
* X25519
* Ed25519
* ML-KEM
* ML-DSA
* SLH-DSA

Determine:

* Quantum Vulnerability
* Migration Complexity
* Migration Readiness
* Business Impact

Outputs:

* Exposure Matrix
* Migration Priority Ranking
* Quantum Risk Rating

---

## Forward Secrecy Analyzer™

Responsibilities:

Identify systems lacking forward secrecy.

Detect:

* TLS_RSA
* Static DH
* Legacy VPNs
* Static SSH configurations
* Long-lived session keys

Evaluate:

* PFS Coverage
* Session Key Exposure
* Historical Traffic Risk

Outputs:

* Forward Secrecy Coverage
* HNDL Risk Score
* Exposure Priority

---

## Quantum Break Timeline™

Responsibilities:

Estimate exposure windows.

Analyze:

* Data confidentiality duration
* Current cryptographic posture
* PQC readiness
* CRQC projections

Build:

* Migration timelines
* Exposure timelines
* Remediation timelines

Outputs:

* Migration Deadline
* Exposure Window
* Quantum Readiness Forecast

---

## Estimated Future Decryptable Data™

Responsibilities:

Estimate harvested data that could become decryptable.

Analyze:

* Archived traffic
* Stored backups
* Databases
* File repositories
* Email archives
* Source code repositories

Outputs:

* Estimated Captured Data
* Estimated Future Decryptable Data
* Critical Data Exposure

---

## Quantum Exposure Graph™

Responsibilities:

Build cryptographic dependency relationships.

Nodes:

* Internet
* Applications
* APIs
* Certificates
* Keys
* Databases
* Archives
* Backups
* Cloud Services

Relationships:

* Trust Chains
* Certificate Dependencies
* Key Dependencies
* Encryption Dependencies
* Data Flows

Outputs:

* Quantum Exposure Graph
* Blast Radius Analysis
* Migration Impact Analysis

---

## Adversary Interest Modeling™

Responsibilities:

Determine likely HNDL targets.

Threat Categories:

* Nation-State APTs
* Foreign Intelligence Services
* Cyber Espionage
* Organized Crime
* Insider Threats

Evaluate:

* Data value
* Strategic value
* Retention duration
* Exposure level

Outputs:

* Adversary Interest Score
* Strategic Risk Score
* Threat Target Ranking

---

## PQC Migration Readiness™

Responsibilities:

Measure migration preparedness.

Evaluate:

* ML-KEM readiness
* ML-DSA readiness
* Hybrid TLS readiness
* PKI readiness
* Certificate readiness
* Application readiness

Outputs:

* PQC Ready
* Hybrid Ready
* Legacy Only
* Migration Blocked
* Migration In Progress

---

# HNDL Risk Formula

Risk Score Components:

Risk =
(Data Value)
×
(Confidentiality Lifetime)
×
(Cryptographic Weakness)
×
(Adversary Interest)
×
(Migration Readiness Gap)

Risk Levels:

* Critical
* High
* Medium
* Low
* Quantum Safe

---

# Telemetry Requirements

Never display mock findings.

Never display synthetic risk scores.

All telemetry must originate from:

* Scanner Engine
* CBOM Explorer
* Asset Inventory
* Certificate Discovery
* TLS Discovery
* PKI Discovery
* Key Discovery
* Runtime Crypto Intelligence
* Quantum Risk Engine
* Trust Fabric

Data Sources:

* Supabase
* SSE
* WebSockets
* API Services

---

# Dashboard Principles

Every widget must answer:

* What is affected?
* Why is it risky?
* What data is exposed?
* What is the future impact?
* What is the migration priority?
* How do I fix it?

---

# Remediation Guidance

Recommendations may include:

* Enable Hybrid TLS
* Deploy ML-KEM
* Deploy ML-DSA
* Replace RSA
* Replace ECDSA
* Enable Forward Secrecy
* Rotate Keys
* Upgrade VPN Infrastructure
* Modernize PKI
* Deploy Quantum-Safe Certificates

Each recommendation must include:

* Affected Assets
* Risk Reduction
* Estimated Effort
* Estimated Timeline
* Migration Dependencies

---

# Standards

Must align with:

* NIST PQC Standards
* FIPS 203 (ML-KEM)
* FIPS 204 (ML-DSA)
* FIPS 205 (SLH-DSA)
* CNSA 2.0
* NIST SP 800-208
* NIST SP 800-57
* NIST SP 800-131A
* NIST PQC Migration Guidance

---

# Success Criteria

The HNDL module is successful when users can:

* Discover cryptographic exposure
* Quantify future decryption risk
* Identify vulnerable assets
* Prioritize migrations
* Estimate future decryptable data
* Measure forward secrecy coverage
* Execute PQC migration plans
* Reduce Harvest Now, Decrypt Later exposure across the organization

while maintaining accurate, real-time, evidence-based telemetry throughout the platform.
