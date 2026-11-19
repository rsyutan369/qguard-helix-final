package com.qguard.messaging

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.Looper
import java.lang.ref.WeakReference
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Keeps the native command pending while Android owns the permission dialog. */
object HelixPermissionPrompt {
    private const val WAIT_SECONDS = 120L
    private val gate = Any()
    private var pending: Request? = null

    private class Request(activity: Activity, val code: Int) {
        val activity = WeakReference(activity)
        val result = CountDownLatch(1)
        @Volatile var completed = false
    }

    /** Must be called by the JNI blocking worker, never Android's UI thread. */
    fun request(context: Context, permissions: Array<String>, requestCode: Int): Boolean {
        val needed = permissions.distinct().filter {
            context.checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED
        }
        if (needed.isEmpty()) return true
        if (Looper.myLooper() == Looper.getMainLooper()) return false
        val activity = CurrentActivity.resolve(context) ?: return false
        val request = synchronized(gate) {
            if (pending != null) return false
            Request(activity, requestCode).also { pending = it }
        }
        try {
            activity.runOnUiThread {
                val current = synchronized(gate) { pending === request }
                if (!current || activity.isFinishing || activity.isDestroyed) {
                    finish(request, false)
                } else {
                    try {
                        activity.requestPermissions(needed.toTypedArray(), requestCode)
                    } catch (_: Exception) {
                        finish(request, false)
                    }
                }
            }
            if (!request.result.await(WAIT_SECONDS, TimeUnit.SECONDS) || !request.completed) return false
            if (activity.isFinishing || activity.isDestroyed) return false
            return permissions.all {
                context.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            return false
        } catch (_: Exception) {
            return false
        } finally {
            synchronized(gate) {
                if (pending === request) pending = null
            }
        }
    }

    fun onResult(requestCode: Int, grantResults: IntArray) {
        val request = synchronized(gate) { pending?.takeIf { it.code == requestCode } } ?: return
        finish(request, grantResults.isNotEmpty())
    }

    fun onDestroyed(activity: Activity) {
        val request = synchronized(gate) { pending?.takeIf { it.activity.get() === activity } } ?: return
        finish(request, false)
    }

    private fun finish(request: Request, completed: Boolean) {
        synchronized(gate) {
            if (pending !== request || request.result.count == 0L) return
            request.completed = completed
            request.result.countDown()
        }
    }
}
