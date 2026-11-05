/* wolfCrypt configuration for the QGuard Messaging crypto boundary.
 *
 * Only compiled with `--features wolfcrypt` (see build.rs). It enables exactly
 * the primitives `crypto::provider` exposes and nothing else: no TLS, no
 * certificates, no file system, no big-integer math.
 *
 * A FIPS 140-3 build does NOT use this file. The validated module must be
 * built with the configuration in its Security Policy and User Guide; point
 * WOLFSSL_LIB_DIR / WOLFSSL_INCLUDE_DIR at that build instead (build.rs).
 */
#ifndef QGUARD_WOLFCRYPT_USER_SETTINGS_H
#define QGUARD_WOLFCRYPT_USER_SETTINGS_H

/* ---- scope ------------------------------------------------------------- */
#define WOLFCRYPT_ONLY
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define NO_ASN
#define NO_CERTS
#define NO_CODING
#define NO_BIG_INT
#define WOLFSSL_IGNORE_FILE_WARN

/* Portable C only. The aarch64 SHA-3 assembly once killed the app with
 * SIGILL on Android CPUs without FEAT_SHA3 (see Cargo.toml, PQClean); the
 * C code runs on every core and tools/verify-android-release.mjs checks the
 * release library for those opcodes. */
#define WOLFSSL_NO_ASM
#define WC_NO_ASYNC_THREADING

/* Large ML-DSA/ML-KEM temporaries on the heap: Tauri runs synchronous
 * commands on the main thread, whose stack is 1 MiB on Windows. */
#define WOLFSSL_SMALL_STACK

/* ---- algorithms QGuard uses --------------------------------------------- */
#define HAVE_AESGCM
#define WOLFSSL_AES_256
#define GCM_TABLE_4BIT
#define WOLFSSL_SHA512
#define WOLFSSL_SHA384
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#define HAVE_HKDF
#define HAVE_PBKDF2
#define HAVE_HASHDRBG
#define HAVE_CURVE25519
#define HAVE_ED25519
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_HAVE_MLDSA
#define WOLFSSL_MLDSA_NO_ASN1

/* ---- not used ----------------------------------------------------------- */
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_SHA
#define NO_DES3
#define NO_PSK
#define NO_OLD_TLS
#define NO_PWDBASED_PKCS12
#define WOLFSSL_NO_ML_KEM_512
#define WOLFSSL_NO_ML_KEM_768
#define WOLFSSL_NO_ML_DSA_44

/* ---- hardening ---------------------------------------------------------- */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT

#endif /* QGUARD_WOLFCRYPT_USER_SETTINGS_H */
