35 Regex Patterns QGuard Should Detect in Source Code
Quantum-Vulnerable Cryptography Detection Rules

Your GitHub scanning engine should apply these regex rules across:

Python

JavaScript / NodeJS

Java

Go

Rust

C/C++

configuration files

1 — RSA Key Generation

Detect RSA implementations.

\bRSA\b
2 — Python RSA Library
from\s+Crypto\.PublicKey\s+import\s+RSA
3 — Python Cryptography RSA
cryptography\.hazmat\.primitives\.asymmetric\.rsa
4 — NodeJS RSA Signatures
createSign\(['"]RSA
5 — OpenSSL RSA Calls
RSA_generate_key
6 — Java RSA KeyPairGenerator
KeyPairGenerator\.getInstance\(["']RSA["']\)
7 — RSA Private Key Blocks
-----BEGIN RSA PRIVATE KEY-----
8 — RSA Public Key Blocks
-----BEGIN PUBLIC KEY-----
9 — PKCS1 RSA
PKCS1
10 — RSA-OAEP
RSA-OAEP
11 — Diffie-Hellman Key Exchange
DiffieHellman
12 — DHE Cipher Usage
DHE_RSA
13 — OpenSSL DH Functions
DH_generate_parameters
14 — Elliptic Curve Crypto
ECDSA
15 — Elliptic Curve Key Generation
EC_KEY_new
16 — Java EC Algorithm
KeyPairGenerator\.getInstance\(["']EC["']\)
17 — NodeJS ECDSA
ecdsa
18 — secp256k1 Curve
secp256k1

This curve is widely used in blockchain wallets such as Bitcoin.

19 — secp256r1 Curve
secp256r1
20 — secp384r1 Curve
secp384r1
21 — SHA-1 Hash
SHA1
22 — Weak Hash MD5
MD5
23 — SHA-1 Signatures
SHA1withRSA
24 — JWT RSA Signatures
RS256
25 — JWT ECDSA Signatures
ES256
26 — Hardcoded Private Key
-----BEGIN PRIVATE KEY-----
27 — PEM Certificates
-----BEGIN CERTIFICATE-----
28 — OpenSSL Key Generation
openssl\s+genrsa
29 — TLS Cipher Suites
TLS_ECDHE_RSA
30 — TLS RSA Cipher
TLS_RSA_WITH
31 — Crypto Library Usage
javax\.crypto
32 — Python PyCrypto
import\s+Crypto
33 — Go Crypto Libraries
crypto\/rsa
34 — Go Elliptic Crypto
crypto\/elliptic
35 — Hardcoded Wallet Private Keys
0x[a-fA-F0-9]{64}

This may indicate blockchain private keys.

Example QGuard GitHub Scan Result

Your scanner might output something like:

Repository: fintech-payment-api

Findings:

RSA key generation detected
Location:
src/security/keys.py

ECDSA secp256k1 detected
Location:
wallet/signature.go

Weak hash MD5 detected
Location:
legacy/hash_util.java

Quantum Risk Level:
HIGH
Recommended Quantum-Safe Alternatives

When QGuard detects vulnerable cryptography, it should recommend migration to post-quantum algorithms standardized by the National Institute of Standards and Technology:

Recommended replacements:

ML-KEM (Kyber)
ML-DSA (Dilithium)
Falcon
SPHINCS+
AES-256-GCM