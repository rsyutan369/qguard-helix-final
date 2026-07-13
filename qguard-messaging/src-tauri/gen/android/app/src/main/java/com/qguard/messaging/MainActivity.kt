package com.qguard.messaging

import android.Manifest
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
    requestCorePermissions()
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

  private companion object {
    const val PERMISSION_REQUEST_CODE = 1001
  }
}
