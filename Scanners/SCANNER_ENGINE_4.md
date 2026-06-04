These are 70 cryptographic fingerprints your scanner should recognize to accurately identify vulnerable cryptographic systems across the internet.

These fingerprints include:

TLS identifiers

X.509 certificate OIDs

SSH algorithm IDs

key file headers

blockchain wallet formats

byte signatures

Detecting these allows QGuard to automatically identify classical cryptography vulnerable to quantum attacks such as those enabled by Shor's Algorithm and Grover's Algorithm, while guiding migration toward standards promoted by the National Institute of Standards and Technology.

The 70 Cryptographic Fingerprints QGuard Should Detect
TLS CIPHER SUITE FINGERPRINTS
1

TLS_RSA_WITH_AES_128_CBC_SHA

2

TLS_RSA_WITH_AES_256_CBC_SHA

3

TLS_RSA_WITH_AES_128_GCM_SHA256

4

TLS_RSA_WITH_AES_256_GCM_SHA384

5

TLS_DHE_RSA_WITH_AES_128_CBC_SHA

6

TLS_DHE_RSA_WITH_AES_256_CBC_SHA

7

TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

8

TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

9

TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

10

TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

TLS PROTOCOL VERSION FINGERPRINTS
11

TLS 1.0 handshake identifier

12

TLS 1.1 handshake identifier

13

Legacy SSLv3 support

14

Deprecated renegotiation extension

15

Weak compression extension enabled

CERTIFICATE ALGORITHM OID FINGERPRINTS
16

OID 1.2.840.113549.1.1.1

RSA encryption

17

OID 1.2.840.113549.1.1.5

SHA1WithRSA

18

OID 1.2.840.113549.1.1.11

SHA256WithRSA

19

OID 1.2.840.113549.1.1.13

SHA512WithRSA

20

OID 1.2.840.10045.4.3.2

ECDSA with SHA256

21

OID 1.2.840.10045.4.3.3

ECDSA with SHA384

22

OID 1.2.840.10045.2.1

Elliptic curve public key

23

OID 1.3.132.0.10

secp256k1 curve

24

OID 1.3.132.0.34

secp384r1 curve

25

OID 1.3.132.0.35

secp521r1 curve

SSH ALGORITHM IDENTIFIERS
26

ssh-rsa

27

rsa-sha2-256

28

rsa-sha2-512

29

ssh-dss

30

ecdsa-sha2-nistp256

31

ecdsa-sha2-nistp384

32

ecdsa-sha2-nistp521

33

diffie-hellman-group1-sha1

34

diffie-hellman-group14-sha1

35

curve25519-sha256

KEY FILE HEADER FINGERPRINTS
36

-----BEGIN RSA PRIVATE KEY-----

37

-----BEGIN EC PRIVATE KEY-----

38

-----BEGIN DSA PRIVATE KEY-----

39

-----BEGIN OPENSSH PRIVATE KEY-----

40

-----BEGIN PGP PRIVATE KEY BLOCK-----

CRYPTOGRAPHIC FILE FORMAT FINGERPRINTS
41

PKCS#12 header 0x30 0x82

42

PKCS#8 private key header

43

X.509 certificate DER header

44

PEM encoded certificate

45

Java Keystore JKS file signature

HASH ALGORITHM FINGERPRINTS
46

MD5 digest length (128-bit)

47

SHA1 digest length (160-bit)

48

SHA256 digest length (256-bit)

49

SHA384 digest length (384-bit)

50

SHA512 digest length (512-bit)

BLOCKCHAIN WALLET FINGERPRINTS
51

Bitcoin wallet.dat structure

52

Ethereum keystore JSON format

53

BIP-32 HD wallet key format

54

BIP-39 mnemonic seed structure

55

secp256k1 public key format

Used by:

Bitcoin
Ethereum

DIGITAL SIGNATURE FORMAT FINGERPRINTS
56

ASN.1 DER ECDSA signature structure

57

RSA PKCS#1 v1.5 signature format

58

RSA-PSS signature format

59

DSA signature structure

60

Ed25519 signature format

NETWORK PROTOCOL CRYPTOGRAPHY FINGERPRINTS
61

IKEv1 negotiation identifier

62

IKEv2 Diffie-Hellman groups

63

IPSec ESP encryption identifiers

64

OpenVPN TLS authentication markers

65

WireGuard public key format

CLOUD & API CRYPTOGRAPHY FINGERPRINTS
66

JWT header "alg":"RS256"

67

JWT header "alg":"ES256"

68

OAuth token signature identifiers

69

TLS client certificate authentication

70

API HMAC signature headers

How QGuard Should Use These Fingerprints

Your scanner should:

Detect fingerprint

Map fingerprint to cryptographic algorithm

Evaluate quantum vulnerability

Calculate risk score

Recommend post-quantum migration

Example:

Fingerprint detected:

TLS_RSA_WITH_AES_256_GCM_SHA384

Algorithm:

RSA key exchange

Risk:

High quantum vulnerability

Recommendation:

Migrate to hybrid TLS with PQC key exchange.

Why These Fingerprints Are Extremely Powerful

Detecting these 70 fingerprints allows QGuard to automatically identify vulnerable cryptography across:

web servers

APIs

SSH infrastructure

VPNs

cloud services

blockchain wallets

telecom protocols

This dramatically reduces false positives because detection relies on actual protocol and file signatures, not guesses.