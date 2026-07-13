//! Platform secure storage for the per-user device storage key (DEK).
//!
//! The DEK is a 32-byte AES-256-GCM key that encrypts the (much larger) device
//! key material file on disk. Only this small key is entrusted to the platform
//! secret store; the key material envelope itself stays in the app data dir.
//!
//! Desktop (Windows/macOS/Linux): OS keychain via the `keyring` crate, storing
//! the DEK base64-encoded under the obfuscated QGuard service name. This is
//! byte-compatible with every previously shipped desktop build.
//!
//! Android: the `keyring` crate has no Android backend. Instead the DEK is
//! wrapped (AES-256-GCM) by a **non-exportable, hardware-backed key generated
//! inside the Android Keystore** (`AndroidKeyStore` provider, TEE/StrongBox
//! where available) reached over JNI. The wrapped blob is stored in the app's
//! private data directory. Because the wrapping key can never leave the
//! Keystore, exfiltrating the blob (or the whole data dir) off-device yields
//! nothing decryptable — matching the security posture of the desktop OS
//! keychain while keeping all cryptographic material handling in native code.

use crate::error::{QGuardError, Result};

/// Loads a previously stored secret for `account`. Returns `Ok(None)` when no
/// secret has been stored yet (first run), `Err` for any real storage failure.
pub fn load_secret(account: &str, data_dir: &std::path::Path) -> Result<Option<Vec<u8>>> {
    platform::load_secret(account, data_dir)
}

/// Persists `secret` for `account`, replacing any previous value.
pub fn store_secret(account: &str, data_dir: &std::path::Path, secret: &[u8]) -> Result<()> {
    platform::store_secret(account, data_dir, secret)
}

/// Removes the stored secret for `account`. Missing entries are not an error.
pub fn delete_secret(account: &str, data_dir: &std::path::Path) -> Result<()> {
    platform::delete_secret(account, data_dir)
}

#[cfg(not(target_os = "android"))]
mod platform {
    use super::*;
    use base64::Engine as _;
    use keyring::Error as KeyringError;

    fn entry(account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(&crate::security::obf::keyring_service(), account)
            .map_err(|e| QGuardError::Storage(format!("open OS keychain entry: {e}")))
    }

    pub fn load_secret(account: &str, _data_dir: &std::path::Path) -> Result<Option<Vec<u8>>> {
        match entry(account)?.get_password() {
            Ok(encoded) => {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(encoded.trim())
                    .map_err(|e| QGuardError::Storage(format!("decode device storage key: {e}")))?;
                Ok(Some(decoded))
            }
            Err(KeyringError::NoEntry) => Ok(None),
            Err(error) => Err(QGuardError::Storage(format!(
                "read device storage key from OS keychain: {error}"
            ))),
        }
    }

    pub fn store_secret(account: &str, _data_dir: &std::path::Path, secret: &[u8]) -> Result<()> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(secret);
        entry(account)?
            .set_password(&encoded)
            .map_err(|e| QGuardError::Storage(format!("write device storage key to OS keychain: {e}")))
    }

    pub fn delete_secret(account: &str, _data_dir: &std::path::Path) -> Result<()> {
        match entry(account)?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(error) => Err(QGuardError::Storage(format!(
                "delete device storage key from OS keychain: {error}"
            ))),
        }
    }
}

#[cfg(target_os = "android")]
mod platform {
    use super::*;
    use base64::Engine as _;
    use jni::objects::{JObject, JValue};
    use jni::JNIEnv;
    use serde::{Deserialize, Serialize};
    use zeroize::Zeroize;

    const KEYSTORE_PROVIDER: &str = "AndroidKeyStore";
    const CIPHER_TRANSFORM: &str = "AES/GCM/NoPadding";
    const GCM_TAG_BITS: i32 = 128;
    // android.security.keystore.KeyProperties: PURPOSE_ENCRYPT | PURPOSE_DECRYPT
    const PURPOSE_ENCRYPT_DECRYPT: i32 = 1 | 2;
    const ENCRYPT_MODE: i32 = 1;
    const DECRYPT_MODE: i32 = 2;

    /// On-disk envelope for the Keystore-wrapped DEK. `iv`/`ct` are base64.
    #[derive(Serialize, Deserialize)]
    struct WrappedSecretFile {
        v: u32,
        alias: String,
        iv: String,
        ct: String,
    }

    fn wrapped_path(account: &str, data_dir: &std::path::Path) -> std::path::PathBuf {
        data_dir.join("keys").join(format!("{account}.dek.androidks"))
    }

    fn key_alias(account: &str) -> String {
        format!("qguard-dek-{account}")
    }

    fn storage_err(context: &str, detail: impl std::fmt::Display) -> QGuardError {
        QGuardError::Storage(format!("Android Keystore {context}: {detail}"))
    }

    /// Runs `f` with a JNIEnv attached to the current thread. Tauri initializes
    /// `ndk-context` with the app's JavaVM before any command can run.
    fn with_env<T>(f: impl FnOnce(&mut JNIEnv) -> Result<T>) -> Result<T> {
        let ctx = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
            .map_err(|e| storage_err("attach JavaVM", e))?;
        let mut env = vm
            .attach_current_thread()
            .map_err(|e| storage_err("attach JNI thread", e))?;
        let result = f(&mut env);
        // A pending Java exception left on the thread aborts the process on the
        // next JNI call — always clear it once it has been converted to Err.
        if result.is_err() && env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
        result
    }

    fn jni_err(env: &mut JNIEnv, context: &str, error: jni::errors::Error) -> QGuardError {
        // Surface the Java exception message when there is one; it names the
        // real failure (KeyPermanentlyInvalidatedException, BadPaddingException…).
        let detail = if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
            format!("{error} (java exception)")
        } else {
            error.to_string()
        };
        storage_err(context, detail)
    }

    /// Loads the AndroidKeyStore and returns it with `load(null)` applied.
    fn open_keystore<'a>(env: &mut JNIEnv<'a>) -> Result<JObject<'a>> {
        let provider = env
            .new_string(KEYSTORE_PROVIDER)
            .map_err(|e| storage_err("alloc provider name", e))?;
        let keystore = env
            .call_static_method(
                "java/security/KeyStore",
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/KeyStore;",
                &[JValue::Object(&provider)],
            )
            .and_then(|v| v.l())
            .map_err(|e| jni_err(env, "KeyStore.getInstance", e))?;
        env.call_method(
            &keystore,
            "load",
            "(Ljava/security/KeyStore$LoadStoreParameter;)V",
            &[JValue::Object(&JObject::null())],
        )
        .map_err(|e| jni_err(env, "KeyStore.load", e))?;
        Ok(keystore)
    }

    /// Fetches the wrapping key for `alias`, generating a fresh non-exportable
    /// AES-256/GCM key inside the Keystore on first use.
    fn get_or_create_wrapping_key<'a>(env: &mut JNIEnv<'a>, alias: &str) -> Result<JObject<'a>> {
        let keystore = open_keystore(env)?;
        let jalias = env
            .new_string(alias)
            .map_err(|e| storage_err("alloc key alias", e))?;

        let exists = env
            .call_method(
                &keystore,
                "containsAlias",
                "(Ljava/lang/String;)Z",
                &[JValue::Object(&jalias)],
            )
            .and_then(|v| v.z())
            .map_err(|e| jni_err(env, "KeyStore.containsAlias", e))?;

        if exists {
            let key = env
                .call_method(
                    &keystore,
                    "getKey",
                    "(Ljava/lang/String;[C)Ljava/security/Key;",
                    &[JValue::Object(&jalias), JValue::Object(&JObject::null())],
                )
                .and_then(|v| v.l())
                .map_err(|e| jni_err(env, "KeyStore.getKey", e))?;
            if !key.is_null() {
                return Ok(key);
            }
        }

        // KeyGenerator.getInstance("AES", "AndroidKeyStore")
        let algo = env
            .new_string("AES")
            .map_err(|e| storage_err("alloc algorithm name", e))?;
        let provider = env
            .new_string(KEYSTORE_PROVIDER)
            .map_err(|e| storage_err("alloc provider name", e))?;
        let generator = env
            .call_static_method(
                "javax/crypto/KeyGenerator",
                "getInstance",
                "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
                &[JValue::Object(&algo), JValue::Object(&provider)],
            )
            .and_then(|v| v.l())
            .map_err(|e| jni_err(env, "KeyGenerator.getInstance", e))?;

        // new KeyGenParameterSpec.Builder(alias, ENCRYPT|DECRYPT)
        //   .setBlockModes("GCM").setEncryptionPaddings("NoPadding").setKeySize(256).build()
        let builder = env
            .new_object(
                "android/security/keystore/KeyGenParameterSpec$Builder",
                "(Ljava/lang/String;I)V",
                &[JValue::Object(&jalias), JValue::Int(PURPOSE_ENCRYPT_DECRYPT)],
            )
            .map_err(|e| jni_err(env, "KeyGenParameterSpec.Builder", e))?;

        let string_class = env
            .find_class("java/lang/String")
            .map_err(|e| jni_err(env, "find String class", e))?;
        let gcm = env
            .new_string("GCM")
            .map_err(|e| storage_err("alloc block mode", e))?;
        let block_modes = env
            .new_object_array(1, &string_class, &gcm)
            .map_err(|e| jni_err(env, "alloc block modes array", e))?;
        let builder = env
            .call_method(
                &builder,
                "setBlockModes",
                "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                &[JValue::Object(&block_modes)],
            )
            .and_then(|v| v.l())
            .map_err(|e| jni_err(env, "setBlockModes", e))?;

        let no_padding = env
            .new_string("NoPadding")
            .map_err(|e| storage_err("alloc padding name", e))?;
        let paddings = env
            .new_object_array(1, &string_class, &no_padding)
            .map_err(|e| jni_err(env, "alloc paddings array", e))?;
        let builder = env
            .call_method(
                &builder,
                "setEncryptionPaddings",
                "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                &[JValue::Object(&paddings)],
            )
            .and_then(|v| v.l())
            .map_err(|e| jni_err(env, "setEncryptionPaddings", e))?;

        let builder = env
            .call_method(
                &builder,
                "setKeySize",
                "(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                &[JValue::Int(256)],
            )
            .and_then(|v| v.l())
            .map_err(|e| jni_err(env, "setKeySize", e))?;

        let spec = env
            .call_method(
                &builder,
                "build",
                "()Landroid/security/keystore/KeyGenParameterSpec;",
                &[],
            )
            .and_then(|v| v.l())
            .map_err(|e| jni_err(env, "KeyGenParameterSpec.build", e))?;

        env.call_method(
            &generator,
            "init",
            "(Ljava/security/spec/AlgorithmParameterSpec;)V",
            &[JValue::Object(&spec)],
        )
        .map_err(|e| jni_err(env, "KeyGenerator.init", e))?;

        env.call_method(&generator, "generateKey", "()Ljavax/crypto/SecretKey;", &[])
            .and_then(|v| v.l())
            .map_err(|e| jni_err(env, "KeyGenerator.generateKey", e))
    }

    fn new_cipher<'a>(env: &mut JNIEnv<'a>) -> Result<JObject<'a>> {
        let transform = env
            .new_string(CIPHER_TRANSFORM)
            .map_err(|e| storage_err("alloc cipher transform", e))?;
        env.call_static_method(
            "javax/crypto/Cipher",
            "getInstance",
            "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
            &[JValue::Object(&transform)],
        )
        .and_then(|v| v.l())
        .map_err(|e| jni_err(env, "Cipher.getInstance", e))
    }

    /// Wraps `secret` with the Keystore key: returns (iv, ciphertext+tag).
    fn keystore_wrap(env: &mut JNIEnv, alias: &str, secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = get_or_create_wrapping_key(env, alias)?;
        let cipher = new_cipher(env)?;
        env.call_method(
            &cipher,
            "init",
            "(ILjava/security/Key;)V",
            &[JValue::Int(ENCRYPT_MODE), JValue::Object(&key)],
        )
        .map_err(|e| jni_err(env, "Cipher.init(encrypt)", e))?;

        let iv_obj = env
            .call_method(&cipher, "getIV", "()[B", &[])
            .and_then(|v| v.l())
            .map_err(|e| jni_err(env, "Cipher.getIV", e))?;
        let iv = env
            .convert_byte_array(jni::objects::JByteArray::from(iv_obj))
            .map_err(|e| jni_err(env, "read IV", e))?;

        let plaintext = env
            .byte_array_from_slice(secret)
            .map_err(|e| jni_err(env, "alloc plaintext array", e))?;
        let ct_obj = env
            .call_method(&cipher, "doFinal", "([B)[B", &[JValue::Object(&plaintext)])
            .and_then(|v| v.l())
            .map_err(|e| jni_err(env, "Cipher.doFinal(encrypt)", e))?;
        let ciphertext = env
            .convert_byte_array(jni::objects::JByteArray::from(ct_obj))
            .map_err(|e| jni_err(env, "read ciphertext", e))?;
        Ok((iv, ciphertext))
    }

    /// Unwraps a previously wrapped DEK.
    fn keystore_unwrap(env: &mut JNIEnv, alias: &str, iv: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        let key = get_or_create_wrapping_key(env, alias)?;
        let cipher = new_cipher(env)?;

        let jiv = env
            .byte_array_from_slice(iv)
            .map_err(|e| jni_err(env, "alloc IV array", e))?;
        let gcm_spec = env
            .new_object(
                "javax/crypto/spec/GCMParameterSpec",
                "(I[B)V",
                &[JValue::Int(GCM_TAG_BITS), JValue::Object(&jiv)],
            )
            .map_err(|e| jni_err(env, "GCMParameterSpec", e))?;

        env.call_method(
            &cipher,
            "init",
            "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
            &[
                JValue::Int(DECRYPT_MODE),
                JValue::Object(&key),
                JValue::Object(&gcm_spec),
            ],
        )
        .map_err(|e| jni_err(env, "Cipher.init(decrypt)", e))?;

        let jct = env
            .byte_array_from_slice(ct)
            .map_err(|e| jni_err(env, "alloc ciphertext array", e))?;
        let pt_obj = env
            .call_method(&cipher, "doFinal", "([B)[B", &[JValue::Object(&jct)])
            .and_then(|v| v.l())
            .map_err(|e| jni_err(env, "Cipher.doFinal(decrypt)", e))?;
        env.convert_byte_array(jni::objects::JByteArray::from(pt_obj))
            .map_err(|e| jni_err(env, "read plaintext", e))
    }

    pub fn load_secret(account: &str, data_dir: &std::path::Path) -> Result<Option<Vec<u8>>> {
        let path = wrapped_path(account, data_dir);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)
            .map_err(|e| storage_err("read wrapped DEK file", e))?;
        let file: WrappedSecretFile = serde_json::from_slice(&bytes)
            .map_err(|e| storage_err("decode wrapped DEK file", e))?;
        let iv = base64::engine::general_purpose::STANDARD
            .decode(&file.iv)
            .map_err(|e| storage_err("decode wrapped DEK iv", e))?;
        let ct = base64::engine::general_purpose::STANDARD
            .decode(&file.ct)
            .map_err(|e| storage_err("decode wrapped DEK ciphertext", e))?;
        let secret = with_env(|env| keystore_unwrap(env, &file.alias, &iv, &ct))?;
        Ok(Some(secret))
    }

    pub fn store_secret(account: &str, data_dir: &std::path::Path, secret: &[u8]) -> Result<()> {
        let alias = key_alias(account);
        let (iv, ct) = with_env(|env| keystore_wrap(env, &alias, secret))?;
        let file = WrappedSecretFile {
            v: 1,
            alias,
            iv: base64::engine::general_purpose::STANDARD.encode(iv),
            ct: base64::engine::general_purpose::STANDARD.encode(ct),
        };
        let mut encoded = serde_json::to_vec(&file)
            .map_err(|e| storage_err("encode wrapped DEK file", e))?;
        let path = wrapped_path(account, data_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| storage_err("create keys directory", e))?;
        }
        let result = std::fs::write(&path, &encoded)
            .map_err(|e| storage_err("write wrapped DEK file", e));
        encoded.zeroize();
        result
    }

    pub fn delete_secret(account: &str, data_dir: &std::path::Path) -> Result<()> {
        let path = wrapped_path(account, data_dir);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| storage_err("delete wrapped DEK file", e))?;
        }
        // Best-effort Keystore cleanup; a dangling alias holds no data.
        let alias = key_alias(account);
        let _ = with_env(|env| -> Result<()> {
            let keystore = open_keystore(env)?;
            let jalias = env
                .new_string(&alias)
                .map_err(|e| storage_err("alloc key alias", e))?;
            env.call_method(
                &keystore,
                "deleteEntry",
                "(Ljava/lang/String;)V",
                &[JValue::Object(&jalias)],
            )
            .map_err(|e| jni_err(env, "KeyStore.deleteEntry", e))?;
            Ok(())
        });
        Ok(())
    }
}
