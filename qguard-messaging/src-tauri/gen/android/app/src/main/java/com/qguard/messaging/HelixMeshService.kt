package com.qguard.messaging

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.ServiceCompat

/**
 * Background Qguard Mesh (owner decision 2026-11-09: disaster use).
 *
 * While the user has turned on "Keep Mesh running in the background", a
 * visible foreground service keeps the process (and the Rust Mesh runtime)
 * alive after Qguard locks and leaves the screen, so encrypted Mesh messages
 * and relays from trusted nearby devices keep arriving. It holds a partial
 * wake lock and a Wi-Fi multicast lock only while it runs; turning the setting
 * off, or stopping local networking, stops it.
 *
 * Message alerts are private on the lock screen: the public version never
 * names the sender or carries text, and no alert ever carries message text.
 *
 * Called from Rust over JNI (`offline/background.rs`): `(Context, String...) -> String`,
 * errors in-band as "error:...".
 */
object HelixMeshService {
    internal const val SERVICE_CHANNEL = "qguard_mesh_background"
    private const val ALERT_CHANNEL = "qguard_mesh_messages"
    internal const val SERVICE_NOTIFICATION_ID = 7301
    private const val ALERT_NOTIFICATION_BASE = 7400
    private const val ALERT_SLOTS = 50
    private const val PERMISSION_REQUEST = 7302

    @Volatile internal var title: String = "Qguard Mesh is active"
    @Volatile internal var text: String = "Receiving encrypted messages from trusted nearby devices."

    private fun ensureChannels(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        if (manager.getNotificationChannel(SERVICE_CHANNEL) == null) {
            manager.createNotificationChannel(
                NotificationChannel(SERVICE_CHANNEL, "Background Mesh", NotificationManager.IMPORTANCE_LOW).apply {
                    description = "Shown while Qguard Mesh keeps running in the background."
                    setShowBadge(false)
                    lockscreenVisibility = Notification.VISIBILITY_PUBLIC
                },
            )
        }
        if (manager.getNotificationChannel(ALERT_CHANNEL) == null) {
            manager.createNotificationChannel(
                NotificationChannel(ALERT_CHANNEL, "Mesh messages", NotificationManager.IMPORTANCE_HIGH).apply {
                    description = "New encrypted messages and file offers from trusted nearby devices."
                    lockscreenVisibility = Notification.VISIBILITY_PRIVATE
                },
            )
        }
    }

    internal fun openApp(context: Context): PendingIntent? {
        val launch = context.packageManager.getLaunchIntentForPackage(context.packageName) ?: return null
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        return PendingIntent.getActivity(
            context, 0, launch,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    internal fun serviceNotification(context: Context): Notification {
        ensureChannels(context)
        return NotificationCompat.Builder(context, SERVICE_CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_qguard_mesh)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(openApp(context))
            .build()
    }

    private fun notificationsAllowed(context: Context): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

    /** Start (or update) the background service. Call while Qguard is in front. */
    @JvmStatic
    fun start(context: Context, title: String, text: String): String {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !notificationsAllowed(context)) {
                // Without it the service still runs; only its notice is hidden.
                HelixPermissionPrompt.request(context, arrayOf(Manifest.permission.POST_NOTIFICATIONS), PERMISSION_REQUEST)
            }
            this.title = title.take(80)
            this.text = text.take(240)
            ensureChannels(context)
            val intent = Intent(context, MeshForegroundService::class.java)
            context.startForegroundService(intent)
            "started"
        } catch (error: Exception) {
            "error:Android did not allow background Mesh to start (${error.javaClass.simpleName}). Open Qguard and try again."
        }
    }

    @JvmStatic
    fun stop(context: Context): String {
        return try {
            context.stopService(Intent(context, MeshForegroundService::class.java))
            "stopped"
        } catch (error: Exception) {
            "error:${error.javaClass.simpleName}"
        }
    }

    @JvmStatic
    fun running(context: Context): String = if (MeshForegroundService.active) "true" else "false"

    /**
     * A private alert. `slot` groups repeats (one notice per sender/kind);
     * `title`/`body` may name a trusted device but never carry message text.
     */
    @JvmStatic
    fun notify(context: Context, slot: String, title: String, body: String): String {
        return try {
            if (!notificationsAllowed(context)) return "error:notifications are not allowed"
            ensureChannels(context)
            val public = NotificationCompat.Builder(context, ALERT_CHANNEL)
                .setSmallIcon(R.drawable.ic_stat_qguard_mesh)
                .setContentTitle("Qguard")
                .setContentText("New encrypted activity. Unlock Qguard to view it.")
                .build()
            val notification = NotificationCompat.Builder(context, ALERT_CHANNEL)
                .setSmallIcon(R.drawable.ic_stat_qguard_mesh)
                .setContentTitle(title.take(80))
                .setContentText(body.take(240))
                .setStyle(NotificationCompat.BigTextStyle().bigText(body.take(240)))
                .setCategory(NotificationCompat.CATEGORY_MESSAGE)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
                .setPublicVersion(public)
                .setAutoCancel(true)
                .setContentIntent(openApp(context))
                .build()
            val id = ALERT_NOTIFICATION_BASE + Math.floorMod(slot.hashCode(), ALERT_SLOTS)
            NotificationManagerCompat.from(context).notify(id, notification)
            "shown"
        } catch (error: SecurityException) {
            "error:notifications are not allowed"
        } catch (error: Exception) {
            "error:${error.javaClass.simpleName}"
        }
    }
}

/** The visible service that keeps background Mesh alive. */
class MeshForegroundService : Service() {
    companion object {
        @Volatile var active = false
            private set
    }

    private var wakeLock: PowerManager.WakeLock? = null
    private var multicastLock: WifiManager.MulticastLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = HelixMeshService.serviceNotification(this)
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
        } else {
            0
        }
        try {
            ServiceCompat.startForeground(this, HelixMeshService.SERVICE_NOTIFICATION_ID, notification, type)
        } catch (error: Exception) {
            stopSelf()
            return START_NOT_STICKY
        }
        active = true
        acquireLocks()
        // The Rust runtime decides when Mesh runs; after a process restart it
        // starts again from the app, never by itself.
        return START_NOT_STICKY
    }

    private fun acquireLocks() {
        if (wakeLock == null) {
            val power = getSystemService(PowerManager::class.java)
            wakeLock = power?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Qguard:BackgroundMesh")?.apply {
                setReferenceCounted(false)
                acquire()
            }
        }
        if (multicastLock == null) {
            val wifi = applicationContext.getSystemService(WifiManager::class.java)
            multicastLock = wifi?.createMulticastLock("Qguard:MeshDiscovery")?.apply {
                setReferenceCounted(false)
                acquire()
            }
        }
    }

    override fun onDestroy() {
        active = false
        try { wakeLock?.takeIf { it.isHeld }?.release() } catch (_: Exception) {}
        try { multicastLock?.takeIf { it.isHeld }?.release() } catch (_: Exception) {}
        wakeLock = null
        multicastLock = null
        super.onDestroy()
    }

    override fun onTimeout(startId: Int, fgsType: Int) {
        // Android 15+ time limits do not apply to connectedDevice, but stop
        // cleanly if the system ever asks.
        stopSelf()
    }
}
