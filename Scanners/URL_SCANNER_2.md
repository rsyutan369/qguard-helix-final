The 30 TLS Fingerprints QGuard Should Detect
Quantum-Vulnerable Cryptographic Configurations

Your scanner should parse:

TLS handshake

certificate fields

cipher suites

signature algorithms

key exchange mechanisms

Each rule produces a quantum risk classification.

Category 1 — RSA Key Exchange (Critical Quantum Risk)

These cipher suites rely on RSA for key exchange, which becomes completely breakable with large-scale quantum computers.

Fingerprints

1

TLS_RSA_WITH_AES_128_GCM_SHA256

2

TLS_RSA_WITH_AES_256_GCM_SHA384

3

TLS_RSA_WITH_AES_128_CBC_SHA

4

TLS_RSA_WITH_AES_256_CBC_SHA

5

TLS_RSA_WITH_3DES_EDE_CBC_SHA

Detection logic:

if cipher_suite contains "TLS_RSA"
→ flag quantum critical
Category 2 — ECDHE + RSA Hybrid Handshakes

These are extremely common on the internet.

They use:

ECDHE key exchange

RSA certificates

Both become vulnerable to quantum attacks.

Fingerprints

6

TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

7

TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

8

TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256

9

TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA

10

TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA

Detection rule:

if key_exchange == ECDHE
AND certificate_algorithm == RSA
→ quantum high risk
Category 3 — ECDSA Certificates (ECC)

Elliptic curve cryptography is also broken by Shor's algorithm.

Fingerprints

11

TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

12

TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

13

TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

14

TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA

15

TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA

Detection logic:

if certificate_algorithm == ECDSA
→ quantum vulnerable
Category 4 — Weak Certificate Signature Algorithms

These signatures are still seen in older infrastructure.

Fingerprints

16

sha1WithRSAEncryption

17

md5WithRSAEncryption

18

sha256WithRSAEncryption

19

ecdsa-with-SHA256

20

ecdsa-with-SHA384

Detection rule:

parse certificate.signatureAlgorithm
Category 5 — Diffie-Hellman Key Exchange

Diffie-Hellman is also vulnerable to Shor’s algorithm.

Fingerprints

21

TLS_DHE_RSA_WITH_AES_128_GCM_SHA256

22

TLS_DHE_RSA_WITH_AES_256_GCM_SHA384

23

TLS_DHE_RSA_WITH_AES_128_CBC_SHA

24

TLS_DHE_RSA_WITH_AES_256_CBC_SHA

25

TLS_DHE_DSS_WITH_AES_128_CBC_SHA

Detection rule:

if cipher contains "DHE"
→ quantum high risk
Category 6 — Small RSA Key Sizes

Key size analysis is critical.

Fingerprints

26

RSA 1024 certificate

27

RSA 2048 certificate

Detection logic:

if rsa_key_size <= 2048
→ quantum vulnerable
Category 7 — Elliptic Curve Identifiers

TLS servers reveal curve types.

Fingerprints

28

secp256r1

29

secp384r1

30

secp521r1

Detection rule:

if tls_curve == secp*
→ ECC vulnerable to quantum attack
Example Scanner Output

Your QGuard engine might generate something like:

Target: example.com

TLS Version: TLS 1.2
Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
Certificate Algorithm: RSA-2048
Curve: secp256r1

Quantum Risk Score: 92/100
Risk Level: HIGH

Reason:
ECDHE key exchange
RSA certificate
Elliptic curve cryptography
How QGuard Uses These Fingerprints

These fingerprints allow your engine to:

• instantly classify TLS cryptography
• detect quantum-vulnerable configurations
• produce automated remediation advice

For example:

Recommended migration:

Hybrid TLS
ML-KEM + AES-256-GCM
ML-DSA signatures

These post-quantum algorithms are part of the emerging standards from the National Institute of Standards and Technology.