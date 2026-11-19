package com.qguard.messaging

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.annotation.Keep
import org.json.JSONObject

/** Explicit, local-only Wi-Fi hosting. Credentials never enter BLE discovery. */
@Keep
object HelixLocalHotspot {
    private const val PERMISSION_REQUEST = 7743
    private val main = Handler(Looper.getMainLooper())
    private val lock = Any()
    private var reservation: WifiManager.LocalOnlyHotspotReservation? = null
    private var starting = false
    private var generation = 0L
    private var failure: String? = null

    private fun wifi(context: Context): WifiManager? =
        context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager

    private fun permission(): String = if (Build.VERSION.SDK_INT >= 33) {
        Manifest.permission.NEARBY_WIFI_DEVICES
    } else {
        Manifest.permission.ACCESS_FINE_LOCATION
    }

    private fun hasPermission(context: Context): Boolean =
        context.checkSelfPermission(permission()) == PackageManager.PERMISSION_GRANTED

    @JvmStatic
    fun start(context: Context): String {
        val manager = wifi(context)
        if (manager == null || !context.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI)) {
            return "error:This device does not provide a Wi-Fi adapter."
        }
        if (!hasPermission(context)) {
            if (!HelixPermissionPrompt.request(context, arrayOf(permission()), PERMISSION_REQUEST)) {
                return "error:Nearby Wi-Fi permission was not granted. Allow access in system settings, then retry the temporary hotspot."
            }
        }
        if (Build.VERSION.SDK_INT < 33) {
            val location = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
            if (location?.isLocationEnabled != true) {
                return "error:Turn on device Location for local Wi-Fi hosting on this Android version."
            }
        }
        val requestGeneration: Long
        synchronized(lock) {
            if (reservation != null || starting) return status(context)
            generation += 1
            requestGeneration = generation
            starting = true
            failure = null
        }
        main.post {
            synchronized(lock) {
                if (requestGeneration != generation || !starting) return@post
            }
            try {
                manager.startLocalOnlyHotspot(object : WifiManager.LocalOnlyHotspotCallback() {
                    override fun onStarted(created: WifiManager.LocalOnlyHotspotReservation) {
                        synchronized(lock) {
                            if (requestGeneration != generation) {
                                runCatching { created.close() }
                                return
                            }
                            reservation = created
                            starting = false
                            failure = null
                        }
                    }

                    override fun onStopped() {
                        synchronized(lock) {
                            if (requestGeneration != generation) return
                            reservation = null
                            starting = false
                            failure = "Android stopped the temporary hotspot."
                        }
                    }

                    override fun onFailed(reason: Int) {
                        synchronized(lock) {
                            if (requestGeneration != generation) return
                            reservation = null
                            starting = false
                            failure = when (reason) {
                                ERROR_NO_CHANNEL -> "No Wi-Fi channel is available for a temporary hotspot."
                                ERROR_INCOMPATIBLE_MODE -> "Stop the existing Wi-Fi hotspot or tethering session, then retry."
                                ERROR_TETHERING_DISALLOWED -> "Device policy does not allow a temporary hotspot."
                                else -> "Android could not start a temporary hotspot."
                            }
                        }
                    }
                }, main)
                main.postDelayed({
                    synchronized(lock) {
                        if (requestGeneration == generation && starting) {
                            generation += 1
                            starting = false
                            failure = "Android did not start the temporary hotspot in time. Retry after checking Wi-Fi settings."
                        }
                    }
                }, 30_000)
            } catch (_: SecurityException) {
                setFailure(requestGeneration, "Nearby Wi-Fi permission is required to host this link.")
            } catch (_: IllegalStateException) {
                setFailure(requestGeneration, "A hotspot request is already active. Stop it and retry.")
            } catch (_: Exception) {
                setFailure(requestGeneration, "Android could not start a temporary hotspot.")
            }
        }
        return status(context)
    }

    private fun setFailure(requestGeneration: Long, message: String) {
        synchronized(lock) {
            if (requestGeneration != generation) return
            starting = false
            failure = message
        }
    }

    @JvmStatic
    fun stop(context: Context): String {
        val previous: WifiManager.LocalOnlyHotspotReservation?
        synchronized(lock) {
            generation += 1
            previous = reservation
            reservation = null
            starting = false
            failure = null
        }
        main.post { runCatching { previous?.close() } }
        return status(context)
    }

    @JvmStatic
    fun status(context: Context): String = synchronized(lock) {
        JSONObject()
            .put("available", wifi(context) != null && context.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI))
            .put("active", reservation != null)
            .put("starting", starting)
            .put("error", failure ?: JSONObject.NULL)
            .toString()
    }

    @JvmStatic
    fun details(context: Context): String = synchronized(lock) {
        if (!hasPermission(context)) return "error:Nearby Wi-Fi permission is required."
        val current = reservation ?: return "null"
        val ssid: String?
        val password: String?
        var security = "wpa2"
        if (Build.VERSION.SDK_INT >= 30) {
            ssid = current.softApConfiguration.ssid
            password = current.softApConfiguration.passphrase
            security = when (current.softApConfiguration.securityType) {
                android.net.wifi.SoftApConfiguration.SECURITY_TYPE_WPA3_SAE_TRANSITION -> "wpa3-transition"
                android.net.wifi.SoftApConfiguration.SECURITY_TYPE_WPA3_SAE -> "wpa3"
                else -> "wpa2"
            }
        } else {
            @Suppress("DEPRECATION")
            val config = current.wifiConfiguration
            ssid = config?.SSID?.removeSurrounding("\"")
            password = config?.preSharedKey?.removeSurrounding("\"")
        }
        if (ssid.isNullOrEmpty() || password.isNullOrEmpty()) {
            return "error:Android did not provide secure hotspot credentials."
        }
        JSONObject()
            .put("ssid", ssid)
            .put("password", password)
            .put("security", security)
            .put("addresses", org.json.JSONArray(privateAddresses()))
            .toString()
    }

    /** This device's private IPv4 addresses, the hotspot interface included. */
    private fun privateAddresses(): List<String> {
        val addresses = linkedSetOf<String>()
        runCatching {
            java.net.NetworkInterface.getNetworkInterfaces()?.toList()?.forEach { network ->
                if (network.isUp && !network.isLoopback) {
                    network.inetAddresses.toList().filterIsInstance<java.net.Inet4Address>().forEach { address ->
                        if (address.isSiteLocalAddress && addresses.size < 8) {
                            address.hostAddress?.let { addresses.add(it) }
                        }
                    }
                }
            }
        }
        return addresses.toList()
    }
}
