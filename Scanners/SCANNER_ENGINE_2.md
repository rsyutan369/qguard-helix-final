# MASTER PROMPT

# Build the Real QGuard Quantum Vulnerability Scanner Engine (Production Architecture)

You are a **world-class cybersecurity architect, distributed systems engineer, and quantum cryptography specialist**.

Your task is to design and implement the **full production architecture** for the **QGuard Quantum Vulnerability Scanner Platform**.

The system must perform **real scanning, real cryptographic detection, and real vulnerability analysis**, not simulated results.

The scanner must detect cryptographic systems vulnerable to quantum attacks such as those exploitable with **Shor's Algorithm** and **Grover's Algorithm**.

The goal is to identify classical cryptographic algorithms and recommend migration to post-quantum cryptography standardized by the **National Institute of Standards and Technology (NIST)**.

---

# CORE SYSTEM REQUIREMENT

Build a **fully functional scanning platform** composed of multiple microservices that perform:

• Device cryptography detection
• Network protocol analysis
• TLS cipher inspection
• Application crypto library analysis
• Blockchain signature detection
• Cloud encryption inspection
• Telecom protocol analysis

The system must generate **real telemetry data** and feed results into a **central analysis engine**.

---

# TECHNOLOGY STACK

Backend:

Python (FastAPI)
Rust for high-performance scanners
Node.js for orchestration services

Scanning Tools:

OpenSSL
zcrypto
zgrab2
scapy
nmap
cryptography Python library

Blockchain analysis:

web3.py
bitcoinlib

Networking:

scapy
asyncio sockets
TLS handshake inspection

Database:

PostgreSQL (or Supabase)

Message Queue:

Redis Streams or Apache Kafka

---

# SYSTEM ARCHITECTURE

Design the platform using the following microservices:

1. **Scan Orchestrator Service**
2. **Network Scanner Engine**
3. **Device Crypto Scanner**
4. **TLS Inspector**
5. **Certificate Analyzer**
6. **Blockchain Signature Analyzer**
7. **Cloud Encryption Scanner**
8. **Telecom Protocol Scanner**
9. **Quantum Risk Scoring Engine**
10. **Report Generator Service**

Each microservice must run independently and communicate through APIs or message queues.

---

# MICROSERVICE IMPLEMENTATION

## Scan Orchestrator

Responsibilities:

Receive scan requests
Dispatch scanning jobs to modules
Track scan progress
Aggregate results

API Endpoints:

POST /scan/start
GET /scan/status
GET /scan/results

---

## Network Scanner Engine

Use:

nmap
zgrab2
scapy

Detect:

Open ports
TLS endpoints
SSH services
VPN endpoints

Extract protocol data for further cryptographic analysis.

---

## TLS Inspector

Perform real TLS handshakes.

Extract:

Cipher suites
Key exchange algorithms
Certificate algorithms

Detect vulnerable cryptographic algorithms such as:

RSA
ECDHE
DHE

---

## Certificate Analyzer

Parse X.509 certificates.

Detect:

RSA key size
Elliptic curve parameters
Signature algorithms

Output certificate fingerprint data.

---

## Device Crypto Scanner

Scan local systems for cryptographic artifacts.

Detect:

PEM keys
PGP keyrings
PKCS#12 keystores
wallet.dat files

Use file signature detection and cryptographic parsing.

---

## Blockchain Signature Analyzer

Analyze cryptocurrency wallets and nodes.

Detect:

ECDSA signatures
secp256k1 curves

Use blockchain libraries to inspect wallet formats.

---

## Cloud Encryption Scanner

Analyze connections to cloud APIs.

Inspect:

OAuth tokens
JWT signatures
TLS encryption layers

Detect classical cryptography usage.

---

## Telecom Protocol Scanner

Analyze telecom protocols including:

5G authentication
satellite communication encryption
secure messaging protocols

Identify classical key exchange algorithms.

---

# CRYPTOGRAPHIC FINGERPRINT DETECTION

Implement detection for at least **60 cryptographic fingerprints**, including:

RSA-1024
RSA-2048
RSA-4096
ECDSA P-256
ECDSA P-384
Diffie-Hellman groups
TLS cipher suites
SHA-based signatures

Each fingerprint must map to a **quantum risk profile**.

---

# QUANTUM RISK SCORING ENGINE

Implement a risk scoring engine.

Inputs:

detected algorithms
key sizes
system exposure

Output:

Quantum Risk Score

Range:

0–1000

Risk categories:

Critical
High
Moderate
Low
Quantum Safe

---

# TELEMETRY SYSTEM

All scanners must emit **real telemetry events**.

Telemetry includes:

detected algorithm
key size
protocol
service location
timestamp

Send telemetry through message queue to the central analysis engine.

---

# DATABASE SCHEMA

Create database tables:

scans
scan_targets
crypto_findings
risk_scores
recommendations

Each scan must persist full results.

---

# REAL-TIME DASHBOARD

Expose results through WebSocket or SSE.

Display:

live scan progress
detected vulnerabilities
quantum risk score

---

# REMEDIATION ENGINE

When vulnerable cryptography is detected, recommend migration to **post-quantum algorithms** such as:

CRYSTALS-Kyber
CRYSTALS-Dilithium
Falcon
SPHINCS+

---

# CONTAINERIZATION

Containerize each microservice using Docker.

Create:

Dockerfiles
docker-compose configuration

Services should include:

scanner-engine
tls-inspector
certificate-analyzer
risk-engine
postgres
redis

---

# SECURITY REQUIREMENTS

All APIs must implement:

authentication
rate limiting
input validation

Sensitive scan results must be encrypted.

---

# FINAL OBJECTIVE

Produce a **production-ready cybersecurity platform** capable of detecting quantum-vulnerable cryptography across:

devices
networks
cloud services
blockchains
telecommunications systems

The platform must generate **real cryptographic detection results**, not simulated or mock data.
