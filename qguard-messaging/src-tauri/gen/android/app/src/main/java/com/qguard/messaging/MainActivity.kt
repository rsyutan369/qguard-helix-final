package com.qguard.messaging

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

class MainActivity : TauriActivity() {

  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    // JNI helpers that launch Activities (vault folder picker, Play Billing)
    // need this instance — Rust only holds the Application context.
    CurrentActivity.set(this)
    PrivacyScreen.apply(this)
    requestCorePermissions()
  }

  override fun onResume() {
    super.onResume()
    CurrentActivity.set(this)
    PrivacyScreen.apply(this)
    PrivacyScreen.onResume(this)
  }

  override fun onPause() {
    // Older Android takes the Recent-apps snapshot after this: cover it first.
    PrivacyScreen.onPause(this)
    super.onPause()
  }

  override fun onDestroy() {
    HelixPermissionPrompt.onDestroyed(this)
    if (isFinishing) {
      HelixSmartConnect.stop(applicationContext)
      HelixLocalHotspot.stop(applicationContext)
    }
    CurrentActivity.clear(this)
    super.onDestroy()
  }

  override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
    super.onRequestPermissionsResult(requestCode, permissions, grantResults)
    HelixPermissionPrompt.onResult(requestCode, grantResults)
    HelixSmartConnect.onPermissionsResult(this, requestCode)
  }

  /**
   * The Quantum Vault's destination-folder picker is a plain
   * `startActivityForResult` (ACTION_OPEN_DOCUMENT_TREE), so its result has to
   * be routed back here. Everything else keeps the default handling.
   */
  @Deprecated("Routing the vault folder picker's Activity result")
  override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    @Suppress("DEPRECATION")
    super.onActivityResult(requestCode, resultCode, data)
    VaultFolderPicker.onActivityResult(this, requestCode, resultCode, data)
  }

  /**
   * Quantum-safe voice/video calls capture media through the WebView (WebRTC
   * getUserMedia). The WebView can only be granted camera/microphone access if
   * the *app* already holds the Android runtime permissions, so they are
   * requested up front together with notification permission (Android 13+).
   * Denial is non-fatal: messaging and the Quantum Vault work without them,
   * and Android re-prompts from the in-call UI on the next call attempt.
   */
  private fun requestCorePermissions() {
    val wanted = mutableListOf(
      Manifest.permission.CAMERA,
      Manifest.permission.RECORD_AUDIO,
    )
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      wanted.add(Manifest.permission.POST_NOTIFICATIONS)
    }
    val missing = wanted.filter {
      ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
    }
    if (missing.isNotEmpty()) {
      ActivityCompat.requestPermissions(this, missing.toTypedArray(), PERMISSION_REQUEST_CODE)
    }
  }

  override fun onStop() {
    super.onStop()
    // Belt-and-suspenders app-entry lock: when the app is backgrounded, ask the
    // web layer to lock immediately (the JS visibilitychange listener is the
    // primary trigger). NOTE: FLAG_SECURE is intentionally NOT set — users must
    // be able to take screenshots. The Recent-apps preview is hidden by
    // PrivacyScreen instead, which leaves screenshots alone.
    runCatching {
      runOnUiThread {
        // Tauri exposes the WebView via the generated activity; evaluate a tiny
        // hook the frontend installs on window. Guard for null during teardown.
        val hook = "window.__qguardAppLock && window.__qguardAppLock()"
        this.javaClass.getMethod("getWebView")?.let { m ->
          val wv = m.invoke(this)
          wv?.javaClass?.getMethod("evaluateJavascript", String::class.java, android.webkit.ValueCallback::class.java)
            ?.invoke(wv, hook, null)
        }
      }
    }
  }

  private companion object {
    const val PERMISSION_REQUEST_CODE = 1001
  }
}
