package com.qguard.messaging

import android.app.Activity
import android.content.Context
import java.lang.ref.WeakReference

/**
 * The live app Activity, for the helpers Rust calls over JNI.
 *
 * Rust hands every helper the `ndk-context` context. Up to tao 0.34 that was
 * the Activity; since tao 0.37 it is the APPLICATION context. Anything that
 * launches another Activity (the SAF folder picker, the Play Billing purchase
 * flow) needs a real Activity, so `context as? Activity` started failing on
 * every call — "vault folder picker needs the app activity" broke vault
 * encrypt/decrypt and Portable Hybrid Identity creation outright.
 *
 * MainActivity registers itself here instead. The reference is weak so a
 * destroyed Activity is never kept alive, and `resolve` prefers the context
 * it was given when that already is an Activity.
 */
object CurrentActivity {
    @Volatile
    private var ref: WeakReference<Activity>? = null

    fun set(activity: Activity) {
        ref = WeakReference(activity)
    }

    /** Forget `activity` only if it is still the registered one. */
    fun clear(activity: Activity) {
        if (ref?.get() === activity) ref = null
    }

    /** `context` itself when it is an Activity, else the live MainActivity. */
    fun resolve(context: Context): Activity? {
        (context as? Activity)?.let { return it }
        return ref?.get()?.takeUnless { it.isFinishing || it.isDestroyed }
    }
}
