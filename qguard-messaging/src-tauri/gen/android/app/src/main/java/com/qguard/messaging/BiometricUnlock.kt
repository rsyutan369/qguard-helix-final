package com.qguard.messaging

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Biometric unlock for the app-entry PIN (roadmap 4.2; the PIN spec's seam).
 *
 * The app's session key (SEK) is wrapped by an AES-256-GCM key that lives in
 * the Android Keystore and can only be USED after a strong-biometric prompt
 * succeeds — the prompt authorises the cipher itself (`CryptoObject`), so a
 * hooked "success" callback alone unlocks nothing. Enrolling a new fingerprint
 * or face permanently invalidates the key; the app then falls back to the PIN.
 *
 * Called from Rust over JNI on a background thread (`(Context, String...) ->
 * String`); each call blocks that thread until the prompt finishes. Failures
 * come back in-band as `error:<reason>`.
 */
object BiometricUnlock {
    private const val KEY_ALIAS = "qguard_applock_biometric_v1"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val PROMPT_TIMEOUT_SECONDS = 120L

    @JvmStatic
    fun availability(context: Context): String = runCatching {
        when (BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> "available"
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "none_enrolled"
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE,
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "no_hardware"
            else -> "unavailable"
        }
    }.getOrElse { "error:${it.message ?: it.javaClass.simpleName}" }

    /** Wrap `sekB64` under a fresh biometric-gated key; returns `iv:ciphertext` (Base64). */
    @JvmStatic
    fun enable(context: Context, sekB64: String, title: String): String = runCatching {
        deleteKey()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, createKey())
        val authorised = prompt(context, cipher, title) ?: return "error:cancelled"
        val sek = Base64.decode(sekB64, Base64.NO_WRAP)
        val sealed = authorised.doFinal(sek)
        sek.fill(0)
        encode(authorised.iv) + ":" + encode(sealed)
    }.getOrElse { failure(it) }

    /** Unwrap a blob made by [enable]; returns the SEK in Base64. */
    @JvmStatic
    fun unlock(context: Context, blob: String, title: String): String = runCatching {
        val parts = blob.split(":")
        if (parts.size != 2) return "error:malformed"
        val key = loadKey() ?: return "error:invalidated"
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, Base64.decode(parts[0], Base64.NO_WRAP)))
        val authorised = prompt(context, cipher, title) ?: return "error:cancelled"
        val sek = authorised.doFinal(Base64.decode(parts[1], Base64.NO_WRAP))
        val out = encode(sek)
        sek.fill(0)
        out
    }.getOrElse { failure(it) }

    @JvmStatic
    @Suppress("UNUSED_PARAMETER") // the JNI signature is (Context, String...) -> String
    fun disable(context: Context): String = runCatching {
        deleteKey()
        "ok"
    }.getOrElse { failure(it) }

    private fun failure(error: Throwable): String = when (error) {
        is KeyPermanentlyInvalidatedException -> "error:invalidated"
        else -> "error:${error.message ?: error.javaClass.simpleName}"
    }

    private fun encode(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)

    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun loadKey(): SecretKey? = keyStore().getKey(KEY_ALIAS, null) as? SecretKey

    private fun deleteKey() {
        val store = keyStore()
        if (store.containsAlias(KEY_ALIAS)) store.deleteEntry(KEY_ALIAS)
    }

    private fun createKey(): SecretKey {
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Every use needs a fresh strong-biometric authentication.
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(builder.build())
        return generator.generateKey()
    }

    /**
     * Show the system prompt bound to `cipher` and wait for it. Returns the
     * cipher the prompt authorised, or null when the user cancelled or the
     * prompt failed for good. Runs the prompt on the UI thread.
     */
    private fun prompt(context: Context, cipher: Cipher, title: String): Cipher? {
        val activity = CurrentActivity.resolve(context) as? FragmentActivity
            ?: throw IllegalStateException("the app is not in the foreground")
        val latch = CountDownLatch(1)
        var result: Cipher? = null
        activity.runOnUiThread {
            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(outcome: BiometricPrompt.AuthenticationResult) {
                    result = outcome.cryptoObject?.cipher
                    latch.countDown()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    latch.countDown()
                }
                // onAuthenticationFailed: one unrecognised attempt; the prompt stays up.
            }
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle("QGuard Messaging")
                .setNegativeButtonText("Use PIN")
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .setConfirmationRequired(false)
                .build()
            BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
                .authenticate(info, BiometricPrompt.CryptoObject(cipher))
        }
        if (!latch.await(PROMPT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) return null
        return result
    }
}
