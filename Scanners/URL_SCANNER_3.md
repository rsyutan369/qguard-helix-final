The 50 Certificate OIDs QGuard Should Detect
Cryptographic Fingerprints for TLS Analysis

Your scanner should parse these from:

TLS certificates

X.509 fields

signatureAlgorithm

publicKeyAlgorithm

extensions

Category 1 — RSA Algorithms (Quantum-Vulnerable)

These are widely used across banking, telecom, and enterprise systems.

1

1.2.840.113549.1.1.1
rsaEncryption

2

1.2.840.113549.1.1.2
md2WithRSAEncryption

3

1.2.840.113549.1.1.3
md4WithRSAEncryption

4

1.2.840.113549.1.1.4
md5WithRSAEncryption

5

1.2.840.113549.1.1.5
sha1WithRSAEncryption

6

1.2.840.113549.1.1.11
sha256WithRSAEncryption

7

1.2.840.113549.1.1.12
sha384WithRSAEncryption

8

1.2.840.113549.1.1.13
sha512WithRSAEncryption

9

1.2.840.113549.1.1.10
RSASSA-PSS

10

1.2.840.113549.1.1.7
RSAES-OAEP

Detection rule:

if OID starts with 1.2.840.113549.1.1
→ RSA detected
→ Quantum vulnerable

These are vulnerable to quantum attacks using Shor's Algorithm.

Category 2 — Elliptic Curve Cryptography (ECC)

ECC is also vulnerable to quantum computing.

11

1.2.840.10045.2.1
ecPublicKey

12

1.2.840.10045.4.1
ecdsa-with-SHA1

13

1.2.840.10045.4.3.2
ecdsa-with-SHA256

14

1.2.840.10045.4.3.3
ecdsa-with-SHA384

15

1.2.840.10045.4.3.4
ecdsa-with-SHA512

16

1.3.132.0.34
secp384r1

17

1.2.840.10045.3.1.7
secp256r1

18

1.3.132.0.35
secp521r1

Detection rule:

if OID contains secp*
→ ECC curve detected
→ Quantum vulnerable
Category 3 — Diffie-Hellman

19

1.2.840.113549.1.3.1
dhKeyAgreement

20

1.2.840.10046.2.1
dhPublicNumber

These are also breakable by quantum computers.

Category 4 — DSA Algorithms

21

1.2.840.10040.4.1
DSA

22

1.2.840.10040.4.3
dsaWithSHA1

23

2.16.840.1.101.3.4.3.2
dsa-with-sha256
Category 5 — Hash Algorithms

Hash functions are generally quantum-weakened (not broken) by Grover's Algorithm.

24

1.3.14.3.2.26
SHA-1

25

2.16.840.1.101.3.4.2.1
SHA-256

26

2.16.840.1.101.3.4.2.2
SHA-384

27

2.16.840.1.101.3.4.2.3
SHA-512
Category 6 — X.509 Certificate Extensions

These help identify certificate capabilities.

28

2.5.29.15
Key Usage

29

2.5.29.19
Basic Constraints

30

2.5.29.37
Extended Key Usage

31

2.5.29.17
Subject Alternative Name
Category 7 — Post-Quantum Cryptography (Important for Detection)

Your scanner should detect PQC implementations.

32

1.3.6.1.4.1.2.267.7.4.4
Dilithium

33

1.3.9999.3.1
Falcon

34

1.3.9999.6.4.1
SPHINCS+

35

1.3.6.1.4.1.2.267.7.4.4
ML-DSA

36

1.3.6.1.4.1.2.267.11.4.4
ML-KEM

These are part of emerging post-quantum standards.

Category 8 — Symmetric Encryption Identifiers

37

2.16.840.1.101.3.4.1.2
AES-128-CBC

38

2.16.840.1.101.3.4.1.22
AES-192-CBC

39

2.16.840.1.101.3.4.1.42
AES-256-CBC

40

2.16.840.1.101.3.4.1.6
AES-128-GCM

41

2.16.840.1.101.3.4.1.46
AES-256-GCM
Category 9 — Legacy Encryption

These should always be flagged.

42

1.2.840.113549.3.7
3DES

43

1.2.840.113549.3.2
RC2

44

1.2.840.113549.3.4
RC4
Category 10 — Certificate Authority Identifiers

45

2.5.29.35
Authority Key Identifier

46

2.5.29.14
Subject Key Identifier

47

1.3.6.1.5.5.7.1.1
Authority Info Access

48

1.3.6.1.5.5.7.48.1
OCSP

49

1.3.6.1.5.5.7.48.2
CA Issuers

50

1.3.6.1.5.5.7.3.1
TLS Web Server Authentication
Example QGuard TLS Analysis Output

Your scanner could display:

Target: example.com

Certificate Signature:
1.2.840.113549.1.1.11
sha256WithRSAEncryption

Public Key Algorithm:
1.2.840.10045.2.1
ecPublicKey

Elliptic Curve:
1.2.840.10045.3.1.7
secp256r1

Quantum Risk Score:
HIGH
Why These OIDs Matter

Parsing these 50 certificate OIDs allows QGuard to:

instantly classify TLS cryptography

detect RSA / ECC systems vulnerable to quantum attacks

identify PQC deployments

produce extremely accurate scan results

This approach is similar to how large-scale internet measurement projects classify cryptography across millions of hosts.

✅ If you'd like, I can also show you something very powerful for your scanner engine:

“The 35 regex patterns your QGuard GitHub scanner should use to automatically detect vulnerable cryptography inside source code.”

Those patterns would allow your scanner to analyze millions of repositories on GitHub and detect quantum-vulnerable crypto implementations automatically.

The 35 regex patterns your QGuard GitHub scanner should use to automatically detect vulnerable cryptography inside source code.”

To make QGuard’s Git repository scanner powerful, it should analyze source code for cryptographic implementations that are vulnerable to quantum attacks.

The best way to do this at scale is by scanning repositories (for example on GitHub) using regex-based pattern detection.

These regex rules allow the scanner to detect:

RSA usage

ECC usage

Diffie-Hellman

weak hashes

hardcoded private keys

vulnerable crypto libraries

Many of these algorithms would be breakable with large-scale quantum computers using Shor's Algorithm.

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
Why These Regex Rules Are Powerful

These 35 regex fingerprints allow QGuard to:

scan millions of repositories automatically

detect quantum-vulnerable cryptography

identify exposed keys

produce automated migration recommendations

This turns QGuard into a Git repository cryptography intelligence engine.

