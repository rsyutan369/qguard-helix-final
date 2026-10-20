package com.qguard.messaging

import android.app.Activity
import android.content.Context
import android.graphics.Color
import android.os.Build
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout

/**
 * Hide the app's content in the Recent-apps switcher, WITHOUT blocking
 * screenshots (roadmap 4.1).
 *
 * `FLAG_SECURE` would do both, and screenshots are allowed by an explicit
 * product decision (PIN spec §11). So:
 *   - Android 13+ (API 33): `setRecentsScreenshotEnabled(false)` — the system
 *     shows a blank card instead of a snapshot; screenshots are unaffected.
 *   - older versions: an opaque cover view is added when the app pauses (the
 *     snapshot is taken after that) and removed when it resumes.
 *
 * On by default; the user can turn it off in Settings. Called from Rust over
 * JNI (see `security/device_privacy.rs`): `(Context, String...) -> String`.
 */
object PrivacyScreen {
    private const val PREFS = "qguard_privacy"
    private const val KEY_MASK_RECENTS = "mask_recents"
    private const val COVER_TAG = "qguard-recents-cover"

    fun isMaskingEnabled(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY_MASK_RECENTS, true)

    @JvmStatic
    fun setRecentsMasking(context: Context, enabled: String): String = runCatching {
        val on = enabled == "true"
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean(KEY_MASK_RECENTS, on).apply()
        CurrentActivity.resolve(context)?.let { activity -> activity.runOnUiThread { apply(activity) } }
        if (on) "true" else "false"
    }.getOrElse { "error:${it.message ?: it.javaClass.simpleName}" }

    @JvmStatic
    fun recentsMaskingStatus(context: Context): String = runCatching {
        val api33 = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
        "{\"enabled\":${isMaskingEnabled(context)},\"method\":\"${if (api33) "system" else "cover"}\"}"
    }.getOrElse { "error:${it.message ?: it.javaClass.simpleName}" }

    /** Apply the current choice to `activity` (Android 13+ path). */
    fun apply(activity: Activity) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            activity.setRecentsScreenshotEnabled(!isMaskingEnabled(activity))
        }
    }

    /** Older Android: cover the content before the system takes its snapshot. */
    fun onPause(activity: Activity) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU || !isMaskingEnabled(activity)) return
        val root = activity.window?.decorView as? ViewGroup ?: return
        if (root.findViewWithTag<View>(COVER_TAG) != null) return
        val cover = FrameLayout(activity).apply {
            tag = COVER_TAG
            setBackgroundColor(Color.parseColor("#0B1020"))
            layoutParams = ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
        }
        root.addView(cover)
    }

    fun onResume(activity: Activity) {
        val root = activity.window?.decorView as? ViewGroup ?: return
        root.findViewWithTag<View>(COVER_TAG)?.let { root.removeView(it) }
    }
}
