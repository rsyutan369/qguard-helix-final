# Post-Quantum Cryptography Skill

Purpose:

Implement and validate quantum-safe cryptographic controls.

Approved Algorithms:

Hybrid KEX:

* X25519 + ML-KEM-768

Vault:

* ML-KEM-1024

Signatures:

* Ed25519
* ML-DSA-65

Symmetric Encryption:

* AES-256-GCM

Hashing:

* SHA3-256

KDF:

* HKDF-SHA3-256

Review Areas:

* Key lifecycle
* Entropy generation
* Key storage
* Certificate handling
* TLS configuration

Migration Goals:

* Discover cryptographic assets
* Assess quantum exposure
* Prioritize migration
* Execute migration safely
* Validate cryptographic posture

Disallowed:

* MD5
* SHA1
* RC4
* DES
* 3DES
* Static keys
* Hardcoded secrets

Always verify:

* Forward secrecy
* Key rotation
* Integrity protection
* Cryptographic agility
* Downgrade resistance
