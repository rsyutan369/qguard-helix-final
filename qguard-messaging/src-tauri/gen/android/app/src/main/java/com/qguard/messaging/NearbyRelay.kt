package com.qguard.messaging

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.common.GoogleApiAvailability
import com.google.android.gms.nearby.Nearby
import com.google.android.gms.nearby.connection.AdvertisingOptions
import com.google.android.gms.nearby.connection.ConnectionInfo
import com.google.android.gms.nearby.connection.ConnectionLifecycleCallback
import com.google.android.gms.nearby.connection.ConnectionResolution
import com.google.android.gms.nearby.connection.ConnectionsClient
import com.google.android.gms.nearby.connection.DiscoveredEndpointInfo
import com.google.android.gms.nearby.connection.DiscoveryOptions
import com.google.android.gms.nearby.connection.EndpointDiscoveryCallback
import com.google.android.gms.nearby.connection.Payload
import com.google.android.gms.nearby.connection.PayloadCallback
import com.google.android.gms.nearby.connection.PayloadTransferUpdate
import com.google.android.gms.nearby.connection.Strategy
import java.security.SecureRandom
import java.util.Collections
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Nearby delivery (roadmap 9.1; owner decision: Google Play services Nearby
 * Connections). Hands sealed envelope rows to phones in range while the relay
 * is unreachable. The rows are end-to-end sealed for their recipient device, so
 * this link carries ciphertext only; the receiving app screens and verifies a
 * row exactly as if it came from the relay.
 *
 * Privacy: the advertised endpoint name is random per session — no account,
 * device or stable identifier is broadcast. Payloads are capped at one
 * Nearby BYTES payload (32 KiB) and the inbox at [MAX_INBOX] rows.
 *
 * Called from Rust over JNI (`commands/nearby.rs`): `(Context, String...) -> String`,
 * errors in-band as "error:...".
 */
object NearbyRelay {
    private const val SERVICE_ID = "com.qguard.messaging.nearby.v1"
    private const val MAX_PAYLOAD_BYTES = 32 * 1024
    private const val MAX_OUTGOING = 400
    private const val MAX_INBOX = 400

    private val connected: MutableSet<String> = Collections.synchronizedSet(mutableSetOf())
    private val outgoing = ConcurrentLinkedQueue<ByteArray>()
    private val inbox = ConcurrentLinkedQueue<String>()
    @Volatile private var running = false
    private var client: ConnectionsClient? = null
    private var endpointName: String = ""

    private fun requiredPermissions(): Array<String> = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU -> arrayOf(
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.NEARBY_WIFI_DEVICES,
        )
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> arrayOf(
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.ACCESS_FINE_LOCATION,
        )
        else -> arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
    }

    private fun permissionsGranted(context: Context): Boolean =
        requiredPermissions().all { context.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED }

    private fun playServicesAvailable(context: Context): Boolean =
        GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(context) == ConnectionResult.SUCCESS

    private fun randomName(): String {
        val bytes = ByteArray(6)
        SecureRandom().nextBytes(bytes)
        return "qg-" + bytes.joinToString("") { "%02x".format(it) }
    }

    private val payloadCallback = object : PayloadCallback() {
        override fun onPayloadReceived(endpointId: String, payload: Payload) {
            val bytes = payload.asBytes() ?: return
            if (bytes.size > MAX_PAYLOAD_BYTES) return
            while (inbox.size >= MAX_INBOX) inbox.poll()
            inbox.add(String(bytes, Charsets.UTF_8))
        }

        override fun onPayloadTransferUpdate(endpointId: String, update: PayloadTransferUpdate) = Unit
    }

    private val lifecycleCallback = object : ConnectionLifecycleCallback() {
        override fun onConnectionInitiated(endpointId: String, info: ConnectionInfo) {
            // Rows are sealed end to end, so any QGuard phone may carry them.
            client?.acceptConnection(endpointId, payloadCallback)
        }

        override fun onConnectionResult(endpointId: String, resolution: ConnectionResolution) {
            if (resolution.status.isSuccess) {
                connected.add(endpointId)
                outgoing.forEach { client?.sendPayload(endpointId, Payload.fromBytes(it)) }
            }
        }

        override fun onDisconnected(endpointId: String) {
            connected.remove(endpointId)
        }
    }

    private val discoveryCallback = object : EndpointDiscoveryCallback() {
        override fun onEndpointFound(endpointId: String, info: DiscoveredEndpointInfo) {
            if (info.serviceId != SERVICE_ID || connected.contains(endpointId)) return
            client?.requestConnection(endpointName, endpointId, lifecycleCallback)
        }

        override fun onEndpointLost(endpointId: String) {
            connected.remove(endpointId)
        }
    }

    private fun json(available: Boolean, permissions: Boolean): String =
        "{\"available\":$available,\"permissions\":$permissions,\"running\":$running,\"peers\":${connected.size}}"

    @JvmStatic
    fun status(context: Context): String = runCatching {
        json(playServicesAvailable(context), permissionsGranted(context))
    }.getOrElse { "error:${it.message ?: it.javaClass.simpleName}" }

    @JvmStatic
    fun requestPermissions(context: Context): String = runCatching {
        val activity = CurrentActivity.resolve(context) ?: return "error:no activity"
        activity.runOnUiThread { activity.requestPermissions(requiredPermissions(), 4207) }
        "ok"
    }.getOrElse { "error:${it.message ?: it.javaClass.simpleName}" }

    @JvmStatic
    fun start(context: Context): String = runCatching {
        if (!playServicesAvailable(context)) return "error:Google Play services is not available on this phone"
        if (!permissionsGranted(context)) return "error:permissions"
        if (running) return "ok"
        val nearby = Nearby.getConnectionsClient(context.applicationContext)
        client = nearby
        endpointName = randomName()
        nearby.startAdvertising(endpointName, SERVICE_ID, lifecycleCallback, AdvertisingOptions.Builder().setStrategy(Strategy.P2P_CLUSTER).build())
        nearby.startDiscovery(SERVICE_ID, discoveryCallback, DiscoveryOptions.Builder().setStrategy(Strategy.P2P_CLUSTER).build())
        running = true
        "ok"
    }.getOrElse { "error:${it.message ?: it.javaClass.simpleName}" }

    @JvmStatic
    fun stop(context: Context): String = runCatching {
        client?.let {
            it.stopAdvertising()
            it.stopDiscovery()
            it.stopAllEndpoints()
        }
        connected.clear()
        running = false
        "ok"
    }.getOrElse { "error:${it.message ?: it.javaClass.simpleName}" }

    /** Offer one row to every phone connected now, and to any that connects later. */
    @JvmStatic
    fun send(context: Context, row: String): String = runCatching {
        val bytes = row.toByteArray(Charsets.UTF_8)
        if (bytes.size > MAX_PAYLOAD_BYTES) return "error:row too large"
        while (outgoing.size >= MAX_OUTGOING) outgoing.poll()
        outgoing.add(bytes)
        val targets = synchronized(connected) { connected.toList() }
        if (targets.isNotEmpty()) client?.sendPayload(targets, Payload.fromBytes(bytes))
        "ok"
    }.getOrElse { "error:${it.message ?: it.javaClass.simpleName}" }

    /** The relay has the rows now; stop offering them. */
    @JvmStatic
    fun clearOutgoing(context: Context): String = runCatching {
        outgoing.clear()
        "ok"
    }.getOrElse { "error:${it.message ?: it.javaClass.simpleName}" }

    /** Rows received since the last call, as a JSON array of strings. */
    @JvmStatic
    fun takeReceived(context: Context): String = runCatching {
        val items = mutableListOf<String>()
        while (true) items.add(inbox.poll() ?: break)
        org.json.JSONArray(items).toString()
    }.getOrElse { "error:${it.message ?: it.javaClass.simpleName}" }
}
