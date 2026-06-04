# MASTER PROMPT

## Build the QGuard Quantum Vulnerability Scanner Engine

You are an elite **cybersecurity architect, quantum cryptography engineer, and full-stack developer**.

Your task is to design and implement the **QGuard Quantum Vulnerability Scanner Engine**, a highly advanced cybersecurity system capable of detecting **quantum-vulnerable cryptography** across consumer and enterprise environments.

The scanner must detect cryptographic systems vulnerable to quantum attacks, particularly those exploitable using algorithms like **Shor’s Algorithm** and **Grover’s Algorithm**.

The system must analyze cryptographic usage across:

• Devices
• Applications
• Networks
• Cloud services
• Blockchain systems
• Telecommunications infrastructure
• Critical infrastructure services

The platform must identify systems using classical cryptographic algorithms vulnerable to quantum computing and recommend migration to post-quantum cryptography standards defined by the **National Institute of Standards and Technology (NIST)**.

---

# SYSTEM OBJECTIVE

Create a scanning engine capable of detecting:

• RSA cryptography
• Elliptic curve cryptography
• Diffie-Hellman key exchange
• Classical TLS key exchanges
• Legacy digital signature algorithms

These cryptographic systems are widely used across:

Banking systems
Internet infrastructure
Mobile applications
Cryptocurrency networks
Government communication systems
Telecom networks

The scanner must generate a **Quantum Risk Score** and produce **remediation recommendations**.

---

# SCANNER ENGINE ARCHITECTURE

Design a modular scanning architecture with **25 specialized scanning modules**.

Each module should:

• Collect cryptographic metadata
• Identify vulnerable algorithms
• Analyze exposure risk
• Send results to the central risk engine

All modules must feed results into a **centralized analysis engine** that calculates a user’s **Quantum Risk Score**.

---

# CORE SCANNING MODULES

## DEVICE SECURITY MODULES

### Module 1 – Local Encryption Scanner

Scan device storage for cryptographic artifacts including:

PEM certificates
PKCS#12 key stores
PGP keyrings
RSA private keys
ECC private keys

Detect:

RSA key sizes
Elliptic curve parameters
Legacy encryption formats

---

### Module 2 – Application Crypto Library Scanner

Analyze installed applications and binaries.

Detect embedded cryptographic libraries such as:

OpenSSL
BoringSSL
NSS

Identify usage of:

RSA
ECC
DSA
Diffie-Hellman

---

### Module 3 – Secure Storage Analyzer

Scan platform key storage systems such as:

Android Keystore
iOS Secure Enclave

Determine whether stored keys rely on classical cryptography.

---

### Module 4 – Firmware Signature Scanner

Inspect firmware update mechanisms including:

BIOS updates
Router firmware
IoT firmware

Detect digital signature algorithms used to verify firmware integrity.

---

### Module 5 – Password Manager Crypto Audit

Analyze password manager vault encryption methods.

Detect usage of:

RSA
ECC
legacy key exchange methods

---

# NETWORK SECURITY MODULES

### Module 6 – TLS Cipher Suite Scanner

Actively probe network endpoints and inspect TLS handshakes.

Detect:

RSA key exchange
ECDHE key exchange
DHE cipher suites

---

### Module 7 – Certificate Authority Trust Scanner

Analyze TLS certificate chains.

Detect:

RSA root certificates
ECC signatures

---

### Module 8 – VPN Security Scanner

Inspect VPN configurations including:

IPSec
OpenVPN
WireGuard

Identify cryptographic key exchange methods.

---

### Module 9 – SSH Security Scanner

Analyze Secure Shell configurations.

Detect:

RSA host keys
ECDSA authentication
Diffie-Hellman groups

---

### Module 10 – DNS Security Scanner

Inspect DNSSEC implementations.

Detect cryptographic algorithms used for DNS record signing.

---

# CLOUD SECURITY MODULES

### Module 11 – Cloud Storage Encryption Scanner

Analyze user cloud storage services such as:

Google Drive
Dropbox
iCloud

Identify encryption formats used to secure stored files.

---

### Module 12 – Cloud API Security Scanner

Analyze API authentication flows.

Inspect:

OAuth
JWT tokens
TLS encryption

---

### Module 13 – Cloud Backup Encryption Scanner

Inspect encrypted backup files.

Detect:

PGP encryption
RSA encrypted backups

---

### Module 14 – SaaS Authentication Security Scanner

Analyze SaaS login authentication methods.

Detect RSA or ECC based authentication tokens.

---

### Module 15 – Cloud Database Encryption Scanner

Analyze database encryption systems used by cloud services.

Detect legacy key exchange protocols.

---

# BLOCKCHAIN & DIGITAL ASSET MODULES

### Module 16 – Crypto Wallet Security Scanner

Analyze cryptocurrency wallets.

Detect signature algorithms used for transaction authentication.

---

### Module 17 – Blockchain Node Security Scanner

Inspect blockchain node authentication methods.

Detect ECC-based signature schemes.

---

### Module 18 – Crypto Exchange API Scanner

Inspect cryptocurrency exchange APIs.

Detect encryption protocols used in communications.

---

### Module 19 – Smart Contract Signature Scanner

Analyze smart contract verification mechanisms.

Identify vulnerable cryptographic signatures.

---

### Module 20 – Web3 Identity Scanner

Inspect decentralized identity platforms.

Detect cryptographic authentication schemes.

---

# TELECOM & INFRASTRUCTURE MODULES

### Module 21 – Mobile Network Authentication Scanner

Analyze authentication protocols used in cellular networks.

Focus on:

4G authentication
5G authentication

---

### Module 22 – Satellite Communication Encryption Scanner

Inspect satellite communication encryption methods.

Detect legacy key exchange algorithms.

---

### Module 23 – Telecom Core Network Scanner

Analyze encryption protocols used in telecom backbone infrastructure.

---

### Module 24 – Secure Messaging Protocol Scanner

Analyze encryption protocols used by messaging platforms.

Detect classical key exchanges.

---

### Module 25 – Critical Infrastructure Scanner

Analyze services used by banks, governments, and critical infrastructure.

Detect cryptographic standards used in authentication systems.

---

# CRYPTOGRAPHIC FINGERPRINT DETECTION ENGINE

The scanner must detect at least **60 cryptographic fingerprints** including:

RSA key sizes
Diffie-Hellman groups
Elliptic curve parameters
Digital signature algorithms
TLS cipher suites
Blockchain signature schemes

Each fingerprint must map to a **quantum vulnerability profile**.

---

# QUANTUM RISK SCORING ENGINE

Implement a scoring engine that evaluates:

Cryptographic strength
Algorithm longevity
Exposure to quantum attacks

Score range:

0–1000

Risk levels:

900–1000 → Quantum Safe
700–899 → Moderate Risk
400–699 → Vulnerable
Below 400 → Critical Risk

---

# DATABASE STORAGE

Store results in a database.

Recommended database:

PostgreSQL
or Supabase

Store:

scan results
detected cryptography
risk scores
migration recommendations

---

# API ARCHITECTURE

Expose scanning results through secure APIs.

Endpoints should include:

scan/start
scan/status
scan/results
risk/score
recommendations

---

# REMEDIATION ENGINE

After detecting vulnerable cryptography, the system must recommend migration to post-quantum algorithms such as:

Kyber (ML-KEM)
Dilithium (ML-DSA)
Falcon
SPHINCS+

---

# USER DASHBOARD

Provide a dashboard showing:

Quantum Risk Score
Detected vulnerabilities
Affected systems
Recommended upgrades

---

# FINAL OBJECTIVE

The final system must function as a **world-class quantum vulnerability scanning engine** capable of identifying classical cryptography across:

devices
applications
networks
cloud services
blockchains
telecommunications systems

and helping users migrate toward **quantum-safe cryptography**.

The platform should operate similarly to professional cybersecurity platforms but focused specifically on **quantum risk detection**.
