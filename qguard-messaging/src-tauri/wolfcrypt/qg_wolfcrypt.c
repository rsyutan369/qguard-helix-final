/* QGuard Messaging -> wolfCrypt shim (`crypto::provider::wolfcrypt`).
 *
 * A flat C interface over the wolfCrypt API, so the Rust side never depends on
 * the layout of a wolfCrypt struct (Aes, wc_Sha3, MlKemKey, ... are sized by
 * the build configuration). Nothing in here implements cryptography: every
 * function is a sequence of calls into the module, with its objects created
 * and freed inside the call.
 *
 * Return values: 0 on success, a negative wolfCrypt error code on failure,
 * QG_INVALID when a signature or AEAD tag does not verify, and
 * QG_NONCONTRIBUTORY when X25519 produced the all-zero secret.
 */
#ifndef WOLFSSL_USER_SETTINGS
  #error "compile with -DWOLFSSL_USER_SETTINGS (see build.rs)"
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#ifdef HAVE_FIPS
  #include <wolfssl/wolfcrypt/fips_test.h>
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define QG_INVALID         1
#define QG_NONCONTRIBUTORY 2

/* Hash selectors, shared with `provider::wolfcrypt::HashSel`. */
#define QG_HASH_SHA256   1
#define QG_HASH_SHA512   2
#define QG_HASH_SHA3_256 3
#define QG_HASH_SHA3_512 4

#define QG_MLKEM1024_EK 1568
#define QG_MLKEM1024_DK 3168
#define QG_MLKEM1024_CT 1568
#define QG_GCM_NONCE    12
#define QG_GCM_TAG      16

static const byte qg_empty[1] = { 0 };

static int qg_len32(size_t len, word32* out)
{
    if (len > 0xFFFFFFFFu)
        return BUFFER_E;
    *out = (word32)len;
    return 0;
}

static int qg_hash_type(int sel)
{
    switch (sel) {
        case QG_HASH_SHA256:   return WC_SHA256;
        case QG_HASH_SHA512:   return WC_SHA512;
        case QG_HASH_SHA3_256: return WC_SHA3_256;
        case QG_HASH_SHA3_512: return WC_SHA3_512;
        default:               return -1;
    }
}

static void qg_wipe(void* p, size_t n)
{
    volatile byte* v = (volatile byte*)p;
    while (n--)
        *v++ = 0;
}

/* ---- module ---------------------------------------------------------- */

int qg_wc_init(void)
{
    int ret = wolfCrypt_Init();
#ifdef HAVE_FIPS
    if (ret == 0)
        ret = wolfCrypt_GetStatus_fips();
#endif
    return ret;
}

const char* qg_wc_version(void)
{
    return LIBWOLFSSL_VERSION_STRING;
}

/* 0 and the FIPS module version for a FIPS build; -1 otherwise. */
int qg_wc_fips_version(int* major, int* minor, int* patch)
{
#if defined(HAVE_FIPS) && defined(HAVE_FIPS_VERSION)
    *major = HAVE_FIPS_VERSION;
  #ifdef HAVE_FIPS_VERSION_MINOR
    *minor = HAVE_FIPS_VERSION_MINOR;
  #else
    *minor = 0;
  #endif
  #ifdef HAVE_FIPS_VERSION_PATCH
    *patch = HAVE_FIPS_VERSION_PATCH;
  #else
    *patch = 0;
  #endif
    return 0;
#else
    *major = *minor = *patch = 0;
    return -1;
#endif
}

int qg_wc_fips_status(void)
{
#ifdef HAVE_FIPS
    return wolfCrypt_GetStatus_fips();
#else
    return 0;
#endif
}

/* ---- DRBG (Hash_DRBG, SP 800-90A) -------------------------------------- */

int qg_wc_random(uint8_t* out, size_t len)
{
    WC_RNG rng;
    int ret;
    size_t done = 0;

    if (out == NULL && len != 0)
        return BAD_FUNC_ARG;
    ret = wc_InitRng(&rng);
    if (ret != 0)
        return ret;
    while (ret == 0 && done < len) {
        size_t step = len - done;
        if (step > RNG_MAX_BLOCK_LEN)
            step = RNG_MAX_BLOCK_LEN;
        ret = wc_RNG_GenerateBlock(&rng, out + done, (word32)step);
        done += step;
    }
    wc_FreeRng(&rng);
    return ret;
}

/* ---- AES-256-GCM ------------------------------------------------------- */

/* The nonce is generated INSIDE the module (wc_AesGcmSetIV draws it from the
 * module's DRBG) and handed back: FIPS 140-3 IG C.H. The external-IV one-shot
 * encrypt is not an approved service in a FIPS build. */
int qg_wc_aes256gcm_seal(const uint8_t* key, const uint8_t* aad, size_t aad_len,
                         const uint8_t* pt, size_t pt_len, uint8_t* iv_out,
                         uint8_t* ct_out, uint8_t* tag_out)
{
    Aes* aes;
    WC_RNG rng;
    word32 a, p;
    int ret;

    if ((ret = qg_len32(aad_len, &a)) != 0 || (ret = qg_len32(pt_len, &p)) != 0)
        return ret;
    aes = (Aes*)XMALLOC(sizeof(Aes), NULL, DYNAMIC_TYPE_AES);
    if (aes == NULL)
        return MEMORY_E;
    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret == 0)
        ret = wc_AesGcmSetKey(aes, key, 32);
    if (ret == 0) {
        ret = wc_InitRng(&rng);
        if (ret == 0) {
            ret = wc_AesGcmSetIV(aes, QG_GCM_NONCE, NULL, 0, &rng);
            wc_FreeRng(&rng);
        }
    }
    if (ret == 0)
        ret = wc_AesGcmEncrypt_ex(aes, ct_out, p ? pt : qg_empty, p, iv_out,
                                  QG_GCM_NONCE, tag_out, QG_GCM_TAG,
                                  a ? aad : qg_empty, a);
    wc_AesFree(aes);
    XFREE(aes, NULL, DYNAMIC_TYPE_AES);
    return ret;
}

int qg_wc_aes256gcm_open(const uint8_t* key, const uint8_t* iv, const uint8_t* aad,
                         size_t aad_len, const uint8_t* ct, size_t ct_len,
                         const uint8_t* tag, uint8_t* pt_out)
{
    Aes* aes;
    word32 a, c;
    int ret;

    if ((ret = qg_len32(aad_len, &a)) != 0 || (ret = qg_len32(ct_len, &c)) != 0)
        return ret;
    aes = (Aes*)XMALLOC(sizeof(Aes), NULL, DYNAMIC_TYPE_AES);
    if (aes == NULL)
        return MEMORY_E;
    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret == 0)
        ret = wc_AesGcmSetKey(aes, key, 32);
    if (ret == 0)
        ret = wc_AesGcmDecrypt(aes, pt_out, c ? ct : qg_empty, c, iv, QG_GCM_NONCE,
                               tag, QG_GCM_TAG, a ? aad : qg_empty, a);
    if (ret == AES_GCM_AUTH_E) {
        if (c)
            qg_wipe(pt_out, c);
        ret = QG_INVALID;
    }
    wc_AesFree(aes);
    XFREE(aes, NULL, DYNAMIC_TYPE_AES);
    return ret;
}

/* ---- hashes ------------------------------------------------------------ */

int qg_wc_hash(int sel, const uint8_t* data, size_t len, uint8_t* out)
{
    word32 l;
    int ret = qg_len32(len, &l);
    const byte* d = l ? data : qg_empty;

    if (ret != 0)
        return ret;
    switch (sel) {
        case QG_HASH_SHA256:   return wc_Sha256Hash(d, l, out);
        case QG_HASH_SHA512:   return wc_Sha512Hash(d, l, out);
        case QG_HASH_SHA3_256: return wc_Sha3_256Hash(d, l, out);
        case QG_HASH_SHA3_512: return wc_Sha3_512Hash(d, l, out);
        default:               return BAD_FUNC_ARG;
    }
}

void* qg_wc_sha3_256_new(void)
{
    wc_Sha3* h = (wc_Sha3*)XMALLOC(sizeof(wc_Sha3), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (h == NULL)
        return NULL;
    if (wc_InitSha3_256(h, NULL, INVALID_DEVID) != 0) {
        XFREE(h, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    return h;
}

int qg_wc_sha3_256_update(void* h, const uint8_t* data, size_t len)
{
    int ret = 0;
    while (ret == 0 && len > 0) {
        word32 step = len > 0x40000000u ? 0x40000000u : (word32)len;
        ret = wc_Sha3_256_Update((wc_Sha3*)h, data, step);
        data += step;
        len -= step;
    }
    return ret;
}

int qg_wc_sha3_256_final(void* h, uint8_t* out)
{
    return wc_Sha3_256_Final((wc_Sha3*)h, out);
}

void* qg_wc_sha3_256_clone(const void* h)
{
    wc_Sha3* copy = (wc_Sha3*)qg_wc_sha3_256_new();
    if (copy == NULL)
        return NULL;
    if (wc_Sha3_256_Copy((wc_Sha3*)h, copy) != 0) {
        wc_Sha3_256_Free(copy);
        XFREE(copy, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    return copy;
}

void qg_wc_sha3_256_free(void* h)
{
    if (h == NULL)
        return;
    wc_Sha3_256_Free((wc_Sha3*)h);
    XFREE(h, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

/* ---- HMAC / HKDF / PBKDF2 --------------------------------------------- */

int qg_wc_hmac(int sel, const uint8_t* key, size_t key_len, const uint8_t* data,
               size_t len, uint8_t* out)
{
    Hmac* hmac;
    word32 k, l;
    int type = qg_hash_type(sel);
    int ret;

    if (type < 0)
        return BAD_FUNC_ARG;
    if ((ret = qg_len32(key_len, &k)) != 0 || (ret = qg_len32(len, &l)) != 0)
        return ret;
    hmac = (Hmac*)XMALLOC(sizeof(Hmac), NULL, DYNAMIC_TYPE_HMAC);
    if (hmac == NULL)
        return MEMORY_E;
    ret = wc_HmacInit(hmac, NULL, INVALID_DEVID);
    if (ret == 0)
        ret = wc_HmacSetKey(hmac, type, k ? key : qg_empty, k);
    if (ret == 0 && l)
        ret = wc_HmacUpdate(hmac, data, l);
    if (ret == 0)
        ret = wc_HmacFinal(hmac, out);
    wc_HmacFree(hmac);
    XFREE(hmac, NULL, DYNAMIC_TYPE_HMAC);
    return ret;
}

/* RFC 5869. An absent salt is HashLen zero bytes, which is also what an
 * empty HMAC key pads to, so both spellings derive the same key. */
int qg_wc_hkdf(int sel, const uint8_t* ikm, size_t ikm_len, const uint8_t* salt,
               size_t salt_len, const uint8_t* info, size_t info_len, uint8_t* out,
               size_t out_len)
{
    word32 i, s, n, o;
    int type = qg_hash_type(sel);
    int ret;

    if (type < 0)
        return BAD_FUNC_ARG;
    if ((ret = qg_len32(ikm_len, &i)) != 0 || (ret = qg_len32(salt_len, &s)) != 0 ||
        (ret = qg_len32(info_len, &n)) != 0 || (ret = qg_len32(out_len, &o)) != 0)
        return ret;
    return wc_HKDF(type, i ? ikm : qg_empty, i, s ? salt : NULL, s,
                   n ? info : NULL, n, out, o);
}

int qg_wc_pbkdf2(int sel, const uint8_t* pw, size_t pw_len, const uint8_t* salt,
                 size_t salt_len, uint32_t iterations, uint8_t* out, size_t out_len)
{
    int type = qg_hash_type(sel);
    if (type < 0 || pw_len > 0x7FFFFFFF || salt_len > 0x7FFFFFFF ||
        out_len > 0x7FFFFFFF || iterations == 0 || iterations > 0x7FFFFFFF)
        return BAD_FUNC_ARG;
    return wc_PBKDF2(out, pw_len ? pw : qg_empty, (int)pw_len,
                     salt_len ? salt : qg_empty, (int)salt_len, (int)iterations,
                     (int)out_len, type);
}

/* ---- X25519 ------------------------------------------------------------ */

/* QGuard stores X25519 secrets unclamped (x25519-dalek clamps when it uses
 * them); wolfCrypt insists on a clamped scalar. Clamping is idempotent, so
 * both compute with the same scalar. */
static void qg_clamp(byte k[CURVE25519_KEYSIZE])
{
    k[0] &= 248;
    k[CURVE25519_KEYSIZE - 1] &= 127;
    k[CURVE25519_KEYSIZE - 1] |= 64;
}

int qg_wc_x25519_public(const uint8_t* secret, uint8_t* public_out)
{
    byte k[CURVE25519_KEYSIZE];
    int ret;

    XMEMCPY(k, secret, sizeof(k));
    qg_clamp(k);
    ret = wc_curve25519_make_pub(CURVE25519_KEYSIZE, public_out, CURVE25519_KEYSIZE, k);
    qg_wipe(k, sizeof(k));
    return ret;
}

int qg_wc_x25519_shared(const uint8_t* secret, const uint8_t* peer, uint8_t* out)
{
    curve25519_key* priv;
    curve25519_key* pub;
    byte k[CURVE25519_KEYSIZE];
    word32 outLen = CURVE25519_KEYSIZE;
    int ret;
#ifdef WOLFSSL_CURVE25519_BLINDING
    WC_RNG rng;
    int rngReady = 0;
#endif

    priv = (curve25519_key*)XMALLOC(sizeof(curve25519_key), NULL, DYNAMIC_TYPE_CURVE25519);
    pub = (curve25519_key*)XMALLOC(sizeof(curve25519_key), NULL, DYNAMIC_TYPE_CURVE25519);
    if (priv == NULL || pub == NULL) {
        XFREE(priv, NULL, DYNAMIC_TYPE_CURVE25519);
        XFREE(pub, NULL, DYNAMIC_TYPE_CURVE25519);
        return MEMORY_E;
    }
    XMEMCPY(k, secret, sizeof(k));
    qg_clamp(k);
    ret = wc_curve25519_init(priv);
    if (ret == 0)
        ret = wc_curve25519_init(pub);
    if (ret == 0)
        ret = wc_curve25519_import_private_ex(k, CURVE25519_KEYSIZE, priv, EC25519_LITTLE_ENDIAN);
#ifdef WOLFSSL_CURVE25519_BLINDING
    if (ret == 0) {
        ret = wc_InitRng(&rng);
        if (ret == 0) {
            rngReady = 1;
            ret = wc_curve25519_set_rng(priv, &rng);
        }
    }
#endif
    if (ret == 0)
        ret = wc_curve25519_import_public_ex(peer, CURVE25519_KEYSIZE, pub, EC25519_LITTLE_ENDIAN);
    if (ret == 0)
        ret = wc_curve25519_shared_secret_ex(priv, pub, out, &outLen, EC25519_LITTLE_ENDIAN);
    /* wolfCrypt refuses the all-zero result (a low-order peer key). Report it
     * the way x25519-dalek's was_contributory() does, so the caller decides:
     * the bound hybrid combiner refuses it, the legacy one never checked. */
    if (ret == ECC_OUT_OF_RANGE_E) {
        XMEMSET(out, 0, CURVE25519_KEYSIZE);
        ret = QG_NONCONTRIBUTORY;
    }
#ifdef WOLFSSL_CURVE25519_BLINDING
    if (rngReady)
        wc_FreeRng(&rng);
#endif
    qg_wipe(k, sizeof(k));
    wc_curve25519_free(priv);
    wc_curve25519_free(pub);
    XFREE(priv, NULL, DYNAMIC_TYPE_CURVE25519);
    XFREE(pub, NULL, DYNAMIC_TYPE_CURVE25519);
    return ret;
}

/* ---- Ed25519 (RFC 8032; FIPS 186-5 EdDSA) ------------------------------ */

static int qg_ed25519_load(ed25519_key* key, const uint8_t* seed)
{
    byte pub[ED25519_PUB_KEY_SIZE];
    int ret = wc_ed25519_import_private_only(seed, ED25519_KEY_SIZE, key);
    if (ret == 0)
        ret = wc_ed25519_make_public(key, pub, sizeof(pub));
    if (ret == 0)
        ret = wc_ed25519_import_private_key(seed, ED25519_KEY_SIZE, pub, sizeof(pub), key);
    return ret;
}

int qg_wc_ed25519_public(const uint8_t* seed, uint8_t* public_out)
{
    ed25519_key* key = (ed25519_key*)XMALLOC(sizeof(ed25519_key), NULL, DYNAMIC_TYPE_ED25519);
    int ret;

    if (key == NULL)
        return MEMORY_E;
    ret = wc_ed25519_init(key);
    if (ret == 0)
        ret = wc_ed25519_import_private_only(seed, ED25519_KEY_SIZE, key);
    if (ret == 0)
        ret = wc_ed25519_make_public(key, public_out, ED25519_PUB_KEY_SIZE);
    wc_ed25519_free(key);
    XFREE(key, NULL, DYNAMIC_TYPE_ED25519);
    return ret;
}

int qg_wc_ed25519_sign(const uint8_t* seed, const uint8_t* msg, size_t len, uint8_t* sig_out)
{
    ed25519_key* key;
    word32 l, sigLen = ED25519_SIG_SIZE;
    int ret = qg_len32(len, &l);

    if (ret != 0)
        return ret;
    key = (ed25519_key*)XMALLOC(sizeof(ed25519_key), NULL, DYNAMIC_TYPE_ED25519);
    if (key == NULL)
        return MEMORY_E;
    ret = wc_ed25519_init(key);
    if (ret == 0)
        ret = qg_ed25519_load(key, seed);
    if (ret == 0)
        ret = wc_ed25519_sign_msg(l ? msg : qg_empty, l, sig_out, &sigLen, key);
    wc_ed25519_free(key);
    XFREE(key, NULL, DYNAMIC_TYPE_ED25519);
    return ret;
}

int qg_wc_ed25519_verify(const uint8_t* public_key, const uint8_t* msg, size_t len,
                         const uint8_t* sig)
{
    ed25519_key* key;
    word32 l;
    int res = 0;
    int ret = qg_len32(len, &l);

    if (ret != 0)
        return ret;
    key = (ed25519_key*)XMALLOC(sizeof(ed25519_key), NULL, DYNAMIC_TYPE_ED25519);
    if (key == NULL)
        return MEMORY_E;
    ret = wc_ed25519_init(key);
    if (ret == 0)
        ret = wc_ed25519_import_public(public_key, ED25519_PUB_KEY_SIZE, key);
    if (ret == 0) {
        ret = wc_ed25519_verify_msg(sig, ED25519_SIG_SIZE, l ? msg : qg_empty, l, &res, key);
        if (ret == SIG_VERIFY_E || (ret == 0 && res != 1))
            ret = QG_INVALID;
    }
    wc_ed25519_free(key);
    XFREE(key, NULL, DYNAMIC_TYPE_ED25519);
    return ret;
}

/* ---- ML-KEM-1024 (FIPS 203) -------------------------------------------- */

static int qg_mlkem_export(MlKemKey* key, uint8_t* pk_out, uint8_t* sk_out)
{
    int ret = wc_MlKemKey_EncodePublicKey(key, pk_out, QG_MLKEM1024_EK);
    if (ret == 0)
        ret = wc_MlKemKey_EncodePrivateKey(key, sk_out, QG_MLKEM1024_DK);
    return ret;
}

int qg_wc_mlkem1024_keypair(uint8_t* pk_out, uint8_t* sk_out)
{
    MlKemKey* key = wc_MlKemKey_New(WC_ML_KEM_1024, NULL, INVALID_DEVID);
    WC_RNG rng;
    int ret;

    if (key == NULL)
        return MEMORY_E;
    ret = wc_InitRng(&rng);
    if (ret == 0) {
        ret = wc_MlKemKey_MakeKey(key, &rng);
        wc_FreeRng(&rng);
    }
    if (ret == 0)
        ret = qg_mlkem_export(key, pk_out, sk_out);
    wc_MlKemKey_Delete(key, &key);
    return ret;
}

/* FIPS 203 ML-KEM.KeyGen_internal(d, z) from a 64-byte seed d || z. Used by
 * the known-answer tests; production keys come from the DRBG above. */
int qg_wc_mlkem1024_keypair_from_seed(const uint8_t* seed, uint8_t* pk_out, uint8_t* sk_out)
{
    MlKemKey* key = wc_MlKemKey_New(WC_ML_KEM_1024, NULL, INVALID_DEVID);
    int ret;

    if (key == NULL)
        return MEMORY_E;
    ret = wc_MlKemKey_MakeKeyWithRandom(key, seed, WC_ML_KEM_MAKEKEY_RAND_SZ);
    if (ret == 0)
        ret = qg_mlkem_export(key, pk_out, sk_out);
    wc_MlKemKey_Delete(key, &key);
    return ret;
}

int qg_wc_mlkem1024_encapsulate(const uint8_t* pk, uint8_t* ct_out, uint8_t* ss_out)
{
    MlKemKey* key = wc_MlKemKey_New(WC_ML_KEM_1024, NULL, INVALID_DEVID);
    WC_RNG rng;
    int ret;

    if (key == NULL)
        return MEMORY_E;
    ret = wc_MlKemKey_DecodePublicKey(key, pk, QG_MLKEM1024_EK);
    if (ret == 0) {
        ret = wc_InitRng(&rng);
        if (ret == 0) {
            ret = wc_MlKemKey_Encapsulate(key, ct_out, ss_out, &rng);
            wc_FreeRng(&rng);
        }
    }
    wc_MlKemKey_Delete(key, &key);
    return ret;
}

int qg_wc_mlkem1024_decapsulate(const uint8_t* sk, const uint8_t* ct, uint8_t* ss_out)
{
    MlKemKey* key = wc_MlKemKey_New(WC_ML_KEM_1024, NULL, INVALID_DEVID);
    int ret;

    if (key == NULL)
        return MEMORY_E;
    ret = wc_MlKemKey_DecodePrivateKey(key, sk, QG_MLKEM1024_DK);
    if (ret == 0)
        ret = wc_MlKemKey_Decapsulate(key, ss_out, ct, QG_MLKEM1024_CT);
    wc_MlKemKey_Delete(key, &key);
    return ret;
}

/* ---- ML-DSA-65 / ML-DSA-87 (FIPS 204, pure, empty context) ------------- */

static wc_MlDsaKey* qg_mldsa_new(int level, int* ret)
{
    wc_MlDsaKey* key = wc_MlDsaKey_New(NULL, INVALID_DEVID);
    if (key == NULL) {
        *ret = MEMORY_E;
        return NULL;
    }
    *ret = wc_MlDsaKey_SetParams(key, (byte)level);
    return key;
}

static int qg_mldsa_export(wc_MlDsaKey* key, uint8_t* pk_out, size_t pk_len,
                           uint8_t* sk_out, size_t sk_len)
{
    word32 pl = (word32)pk_len, sl = (word32)sk_len;
    int ret = wc_MlDsaKey_ExportPubRaw(key, pk_out, &pl);
    if (ret == 0 && pl != pk_len)
        ret = BUFFER_E;
    if (ret == 0)
        ret = wc_MlDsaKey_ExportPrivRaw(key, sk_out, &sl);
    if (ret == 0 && sl != sk_len)
        ret = BUFFER_E;
    return ret;
}

int qg_wc_mldsa_keypair(int level, uint8_t* pk_out, size_t pk_len, uint8_t* sk_out,
                        size_t sk_len)
{
    WC_RNG rng;
    int ret;
    wc_MlDsaKey* key = qg_mldsa_new(level, &ret);

    if (ret == 0) {
        ret = wc_InitRng(&rng);
        if (ret == 0) {
            ret = wc_MlDsaKey_MakeKey(key, &rng);
            wc_FreeRng(&rng);
        }
    }
    if (ret == 0)
        ret = qg_mldsa_export(key, pk_out, pk_len, sk_out, sk_len);
    if (key != NULL)
        wc_MlDsaKey_Delete(key, &key);
    return ret;
}

/* FIPS 204 ML-DSA.KeyGen_internal(xi) from a 32-byte seed (KAT use). */
int qg_wc_mldsa_keypair_from_seed(int level, const uint8_t* seed, uint8_t* pk_out,
                                  size_t pk_len, uint8_t* sk_out, size_t sk_len)
{
    int ret;
    wc_MlDsaKey* key = qg_mldsa_new(level, &ret);

    if (ret == 0)
        ret = wc_MlDsaKey_MakeKeyFromSeed(key, seed);
    if (ret == 0)
        ret = qg_mldsa_export(key, pk_out, pk_len, sk_out, sk_len);
    if (key != NULL)
        wc_MlDsaKey_Delete(key, &key);
    return ret;
}

int qg_wc_mldsa_sign(int level, const uint8_t* sk, size_t sk_len, const uint8_t* msg,
                     size_t msg_len, uint8_t* sig_out, size_t sig_cap, size_t* sig_len)
{
    WC_RNG rng;
    word32 s, m, sl;
    int ret;
    wc_MlDsaKey* key;

    if ((ret = qg_len32(sk_len, &s)) != 0 || (ret = qg_len32(msg_len, &m)) != 0 ||
        (ret = qg_len32(sig_cap, &sl)) != 0)
        return ret;
    key = qg_mldsa_new(level, &ret);
    if (ret == 0)
        ret = wc_MlDsaKey_ImportPrivRaw(key, sk, s);
    if (ret == 0) {
        ret = wc_InitRng(&rng);
        if (ret == 0) {
            ret = wc_MlDsaKey_SignCtx(key, qg_empty, 0, sig_out, &sl, m ? msg : qg_empty, m, &rng);
            wc_FreeRng(&rng);
        }
    }
    if (ret == 0)
        *sig_len = sl;
    if (key != NULL)
        wc_MlDsaKey_Delete(key, &key);
    return ret;
}

int qg_wc_mldsa_verify(int level, const uint8_t* pk, size_t pk_len, const uint8_t* msg,
                       size_t msg_len, const uint8_t* sig, size_t sig_len)
{
    word32 p, m, s;
    int res = 0;
    int ret;
    wc_MlDsaKey* key;

    if ((ret = qg_len32(pk_len, &p)) != 0 || (ret = qg_len32(msg_len, &m)) != 0 ||
        (ret = qg_len32(sig_len, &s)) != 0)
        return ret;
    key = qg_mldsa_new(level, &ret);
    if (ret == 0)
        ret = wc_MlDsaKey_ImportPubRaw(key, pk, p);
    if (ret == 0) {
        ret = wc_MlDsaKey_VerifyCtx(key, sig, s, qg_empty, 0, m ? msg : qg_empty, m, &res);
        if (ret == SIG_VERIFY_E || (ret == 0 && res != 1))
            ret = QG_INVALID;
    }
    if (key != NULL)
        wc_MlDsaKey_Delete(key, &key);
    return ret;
}
