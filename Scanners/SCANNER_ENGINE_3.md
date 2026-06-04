40 Cryptographic Detection Rules for QGuard
TLS & INTERNET PROTOCOL RULES
1. RSA-1024 TLS Certificates

Detect TLS certificates using RSA-1024.

Risk: Already breakable with sufficient computing power.

2. RSA-2048 Certificates on Public Internet

Detect RSA-2048 certificates protecting websites.

Risk: Vulnerable to quantum factorization.

3. Weak Diffie-Hellman Groups

Detect DH groups smaller than 2048 bits.

Risk: Susceptible to classical and quantum attacks.

4. TLS Cipher Suites Using RSA Key Exchange

Detect cipher suites such as:

TLS_RSA_WITH_AES_256_CBC_SHA

Risk: No forward secrecy.

5. TLS Servers Supporting TLS 1.0 / 1.1

Detect outdated protocol versions.

Risk: Deprecated cryptography.

6. SHA-1 Certificate Signatures

Detect certificates signed with SHA-1.

Risk: Collision attacks possible.

7. Self-Signed TLS Certificates

Detect improperly issued certificates.

Risk: MITM potential.

8. TLS Without Forward Secrecy

Detect servers lacking ECDHE/DHE.

Risk: Recorded traffic can be decrypted later.

9. Weak Elliptic Curves

Detect curves like:

secp192r1
secp224r1

Risk: Lower security margin.

10. TLS Using Static Diffie-Hellman

Detect static DH cipher suites.

Risk: Forward secrecy broken.

CERTIFICATE INFRASTRUCTURE RULES
11. Root CA Using RSA-2048

Detect root certificate authorities still using RSA.

Risk: Long-term vulnerability to quantum attacks.

12. Intermediate CA Using Weak Signatures

Detect SHA-1 or outdated algorithms.

13. Expired Certificates Still Accepted

Detect services allowing expired certificates.

14. Short RSA Key Lifetimes

Detect systems rotating keys infrequently.

Risk: Long exposure window.

15. Weak Certificate Chain Length

Detect overly short chains with insufficient validation.

SSH SECURITY RULES
16. SSH Servers Using RSA-1024 Host Keys
17. SSH Servers Allowing Diffie-Hellman Group1
18. SSH Servers Allowing SHA-1 Signatures
19. SSH Using Static Host Keys Without Rotation
20. SSH Servers Allowing Password Authentication Only

Weak crypto protection.

VPN & NETWORK TUNNEL RULES
21. IPSec Using IKEv1
22. IPSec Using Weak DH Groups
23. OpenVPN Using Static Pre-Shared Keys
24. VPN Servers Without Perfect Forward Secrecy
25. WireGuard Misconfigured Key Exchange
APPLICATION CRYPTOGRAPHY RULES
26. Hardcoded RSA Keys in Applications

Detect private keys embedded in binaries.

27. Hardcoded AES Encryption Keys
28. Applications Using MD5 for Signatures
29. JWT Tokens Signed With Weak Algorithms

Example:

HS256 with exposed secret

30. Weak Random Number Generation

Detect predictable entropy sources.

BLOCKCHAIN & DIGITAL ASSET RULES
31. Wallets Using ECDSA (secp256k1)

Used by systems such as Bitcoin and Ethereum.

Risk: Broken by quantum computing.

32. Exposed Public Keys on Blockchain

Quantum attackers could derive private keys.

33. Wallet Backup Files Stored Unencrypted
34. Exchanges Using Weak TLS Configurations
35. Smart Contracts Using Weak Signature Verification
CLOUD & API SECURITY RULES
36. APIs Using RSA Token Signatures
37. OAuth Tokens Without Signature Validation
38. Cloud Storage Encryption Using Legacy RSA
39. JWT Tokens Signed with Weak Curves

Example:

ES256 without key rotation.

40. Cloud Services Without Key Rotation Policies

Long-term cryptographic exposure.

How QGuard Should Use These Rules

Each rule should produce:

Detection event
Severity rating
Quantum vulnerability score
Remediation recommendation

Example output:

Detection: RSA-2048 TLS certificate
Risk Level: High
Quantum Risk Score: 620

Recommendation:
Migrate to hybrid TLS using post-quantum key exchange.

Why These Rules Are Powerful

These detection rules mirror techniques used in:

internet-wide scanners
enterprise vulnerability scanners
cyber defense platforms

They allow QGuard to automatically detect weak cryptography across:

devices
websites
networks
cloud systems
blockchain infrastructure