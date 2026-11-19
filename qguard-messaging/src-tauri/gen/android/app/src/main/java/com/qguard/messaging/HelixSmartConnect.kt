package com.qguard.messaging

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.UUID
import java.util.ArrayDeque
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Foreground, opt-in BLE discovery. Public hints never authorize a session. */
@androidx.annotation.Keep
object HelixSmartConnect {
    private val SERVICE_UUID = UUID.fromString("8d0d6ad1-9596-473a-bff8-6f431bb720af")
    private val METADATA_UUID = UUID.fromString("8d0d6ad1-9596-473a-bff8-6f431bb720b0")
    private val WRITE_UUID = UUID.fromString("8d0d6ad1-9596-473a-bff8-6f431bb720b1")
    private val READ_UUID = UUID.fromString("8d0d6ad1-9596-473a-bff8-6f431bb720b2")
    private val DEVICE_HINT_UUID = UUID.fromString("8d0d6ad1-9596-473a-bff8-6f431bb720b3")
    private const val PERMISSION_REQUEST = 7142
    private const val MAX_METADATA_BYTES = 512
    private const val MAX_PEERS = 128
    private const val MAX_CONNECTIONS = 3
    private const val PEER_TTL_MS = 20_000L
    private const val RETRY_MS = 8_000L
    private const val CONNECT_TIMEOUT_MS = 6_000L
    // A data link also negotiates the MTU before it opens.
    private const val LINK_OPEN_TIMEOUT_MS = 12_000L
    private const val MTU_WAIT_MS = 2_500L
    private const val KNOWN_PEER_REFRESH_MS = 45_000L
    // ATT's default packet (MTU 23) and the largest attribute value ATT allows.
    // The connecting device measures the link and declares its size in OPEN:
    // 15-byte payloads need over a thousand round trips for one post-quantum
    // handshake, full-size packets a few dozen.
    private const val MIN_PACKET_BYTES = 20
    private const val MAX_PACKET_BYTES = 512
    private const val ATT_ATTEMPTS = 3
    private const val MAX_LINKS = 4
    private const val MAX_LINK_BYTES = 64 * 1024
    private const val LINK_TIMEOUT_MS = 120_000L
    private const val LINK_ACK_TIMEOUT_MS = 30_000L

    private val gate = Any()
    private val handler = Handler(Looper.getMainLooper())
    private var appContext: Context? = null
    private var adapter: BluetoothAdapter? = null
    private var server: BluetoothGattServer? = null
    private var wanted = false
    private var scanning = false
    private var advertising = false
    private var generation = 0L
    private var metadata: JSONObject? = null
    private var lastError: String? = null
    private var activeAdvertiseCallback: AdvertiseCallback? = null
    private var activeAdvertisingSetCallback: android.bluetooth.le.AdvertisingSetCallback? = null
    private var activeAdvertisingSet: android.bluetooth.le.AdvertisingSet? = null
    private var lastAdvertiseAttempt = 0L
    private var activeScanCallback: ScanCallback? = null
    private data class Peer(val address: String, val metadata: String, var seenAt: Long, var rssi: Int, val readAt: Long)
    private data class ReadSnapshot(val bytes: ByteArray, val createdAt: Long, val characteristic: UUID)
    private val peers = linkedMapOf<String, Peer>()
    private val attempted = linkedMapOf<String, Long>()
    private val connections = mutableMapOf<String, BluetoothGatt?>()
    private val readSnapshots = mutableMapOf<String, ReadSnapshot>()
    private val mtus = mutableMapOf<String, Int>()
    private class ServerLink(val id: String, val address: String, val packetBytes: Int) {
        val incoming = ArrayDeque<ByteArray>()
        val outgoing = ArrayDeque<ByteArray>()
        val acknowledgments = mutableMapOf<Long, CountDownLatch>()
        var incomingBytes = 0
        var outgoingBytes = 0
        var nextReceive = 0L
        var nextSend = 0L
        var lastReceived: ByteArray? = null
        var lastRemoteAck = -1L
        var closed = false
        /** The size self-test has not been acknowledged yet (version 3 links). */
        var probePending = false
        var activeAt = android.os.SystemClock.elapsedRealtime()
    }
    private val serverLinks = mutableMapOf<String, ServerLink>()
    private val clientLinks = mutableMapOf<String, ClientLink>()
    private val incomingLinks = ArrayDeque<String>()

    private fun sequence(packet: ByteArray): Long = ((packet[1].toLong() and 255) shl 24) or
        ((packet[2].toLong() and 255) shl 16) or ((packet[3].toLong() and 255) shl 8) or (packet[4].toLong() and 255)

    /** The packet size an OPEN asks for: version 1 is fixed at 20 bytes, version 2 declares it. */
    private fun openSize(packet: ByteArray): Int? = when {
        packet.contentEquals(byteArrayOf(1, 1)) -> MIN_PACKET_BYTES
        packet.size == 4 && packet[0].toInt() == 1 && packet[1].toInt() in 2..3 ->
            (((packet[2].toInt() and 255) shl 8) or (packet[3].toInt() and 255)).takeIf { it in MIN_PACKET_BYTES..MAX_PACKET_BYTES }
        else -> null
    }

    /** Version 3 OPEN: the declared size plus a size self-test on the first read. */
    private fun openPacket(packetBytes: Int): ByteArray {
        val size = packetBytes.coerceIn(MIN_PACKET_BYTES, MAX_PACKET_BYTES)
        return byteArrayOf(1, 3, (size shr 8).toByte(), (size and 255).toByte())
    }

    // The size self-test. A read longer than the radio link really carries is
    // cut short without any error, which silently drops stream bytes. So the
    // first read on a version 3 link returns a packet of exactly the agreed
    // size; the connecting device compares what arrived and, when it is
    // shorter, reopens the link at the size that did arrive.
    private fun probePacket(packetBytes: Int): ByteArray {
        val packet = ByteArray(packetBytes) { 0xA5.toByte() }
        packet[0] = 5
        packet[1] = (packetBytes shr 8).toByte()
        packet[2] = (packetBytes and 255).toByte()
        return packet
    }

    private fun validPacket(packet: ByteArray): Boolean = when (packet.firstOrNull()?.toInt()) {
        0, 4, 6 -> packet.size == 1
        1 -> openSize(packet) != null
        2 -> packet.size in 6..MAX_PACKET_BYTES
        3 -> packet.size == 5
        5 -> packet.size in 3..MAX_PACKET_BYTES
        else -> false
    }

    private fun serverWrite(address: String, packet: ByteArray): Boolean {
        if (!validPacket(packet)) return false
        if (packet[0].toInt() == 1) {
            val size = openSize(packet) ?: return false
            serverLinks.entries.removeAll { it.value.closed }
            incomingLinks.removeAll { !serverLinks.containsKey(it) }
            serverLinks.values.find { it.address == address }?.let { current ->
                return current.packetBytes == size && current.nextReceive == 0L && current.nextSend == 0L && current.incoming.isEmpty() && current.outgoing.isEmpty()
            }
            if (serverLinks.size + clientLinks.size >= MAX_LINKS) return false
            if (incomingLinks.size >= MAX_LINKS) return false
            val link = ServerLink("s-" + UUID.randomUUID().toString(), address, size)
            link.probePending = packet[1].toInt() == 3
            serverLinks[link.id] = link
            incomingLinks.add(link.id)
            return true
        }
        val link = serverLinks.values.find { it.address == address } ?: return false
        link.activeAt = android.os.SystemClock.elapsedRealtime()
        return when (packet[0].toInt()) {
            2 -> {
                val seq = sequence(packet)
                if (link.closed || packet.size > link.packetBytes) false
                else if (seq + 1 == link.nextReceive && link.lastReceived?.contentEquals(packet) == true) true
                else if (seq != link.nextReceive || link.incomingBytes + packet.size > MAX_LINK_BYTES) false
                else {
                    link.nextReceive += 1
                    link.lastReceived = packet.copyOf()
                    link.incoming.add(packet.copyOf())
                    link.incomingBytes += packet.size
                    true
                }
            }
            3 -> {
                val seq = sequence(packet)
                val first = link.outgoing.peekFirst()
                if (seq == link.lastRemoteAck) true
                else if (first != null && sequence(first) == seq) {
                    link.outgoingBytes -= link.outgoing.removeFirst().size
                    link.lastRemoteAck = seq
                    link.acknowledgments.remove(seq)?.countDown()
                    true
                } else false
            }
            4 -> { closeServerLink(link); true }
            // Only a packet for a link (never an OPEN, a size test or an idle marker) reaches here.
            // The write half of the size self-test: only a whole packet of the agreed size passes.
            5 -> packet.size == link.packetBytes
            6 -> { link.probePending = false; true }
            else -> false
        }
    }

    private fun closeServerLink(link: ServerLink) {
        link.closed = true
        link.acknowledgments.values.forEach { it.countDown() }
        link.acknowledgments.clear()
    }

    private fun serverRead(address: String): ByteArray {
        val link = serverLinks.values.find { it.address == address } ?: return byteArrayOf(4)
        link.activeAt = android.os.SystemClock.elapsedRealtime()
        return when {
            link.closed -> byteArrayOf(4)
            link.probePending -> probePacket(link.packetBytes)
            link.outgoing.isNotEmpty() -> link.outgoing.first.copyOf()
            else -> byteArrayOf(0)
        }
    }

    private class ClientLink(val id: String, val address: String, val context: Context, val device: android.bluetooth.BluetoothDevice) {
        private val ready = CountDownLatch(1)
        private val operationGate = Any()
        @Volatile private var operation: CountDownLatch? = null
        @Volatile private var result: ByteArray? = null
        @Volatile private var succeeded = false
        @Volatile private var closed = false
        @Volatile private var opened = false
        @Volatile private var gatt: BluetoothGatt? = null
        private var ingress: BluetoothGattCharacteristic? = null
        private var egress: BluetoothGattCharacteristic? = null
        @Volatile var activeAt = android.os.SystemClock.elapsedRealtime()
        @Volatile private var mtu = 23
        /** Packet size this link agreed in OPEN, from the negotiated ATT MTU. */
        @Volatile var packetBytes = MIN_PACKET_BYTES
            private set
        private val discovering = java.util.concurrent.atomic.AtomicBoolean(false)

        private fun complete(ok: Boolean, bytes: ByteArray? = null) {
            succeeded = ok
            result = bytes?.copyOf()
            operation?.countDown()
        }

        /** Runs once, after the MTU exchange finishes or is given up on. */
        private fun discover(link: BluetoothGatt) {
            if (closed || !discovering.compareAndSet(false, true)) return
            if (!runCatching { link.discoverServices() }.getOrDefault(false)) close()
        }

        private val callback = object : BluetoothGattCallback() {
            override fun onConnectionStateChange(link: BluetoothGatt, status: Int, state: Int) {
                if (status != BluetoothGatt.GATT_SUCCESS || state == BluetoothProfile.STATE_DISCONNECTED) { close(); return }
                if (state != BluetoothProfile.STATE_CONNECTED) return
                // A short connection interval and a large MTU carry the
                // post-quantum handshake in seconds instead of minutes.
                runCatching { link.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_HIGH) }
                val requested = runCatching { link.requestMtu(517) }.getOrDefault(false)
                if (!requested) discover(link)
                // Some stacks never answer the MTU request; continue at the default size.
                else handler.postDelayed({ discover(link) }, MTU_WAIT_MS)
            }

            override fun onMtuChanged(link: BluetoothGatt, value: Int, status: Int) {
                if (status == BluetoothGatt.GATT_SUCCESS && !discovering.get()) mtu = value.coerceIn(23, 517)
                discover(link)
            }

            override fun onServicesDiscovered(link: BluetoothGatt, status: Int) {
                if (status != BluetoothGatt.GATT_SUCCESS || closed) { close(); return }
                val service = link.getService(SERVICE_UUID)
                ingress = service?.getCharacteristic(WRITE_UUID)
                egress = service?.getCharacteristic(READ_UUID)
                val write = ingress
                packetBytes = (mtu - 3).coerceIn(MIN_PACKET_BYTES, MAX_PACKET_BYTES)
                if (write == null || egress == null || !runCatching { writeRaw(link, write, openPacket(packetBytes)) }.getOrDefault(false)) close()
            }

            override fun onCharacteristicWrite(link: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
                if (!opened) {
                    opened = status == BluetoothGatt.GATT_SUCCESS
                    ready.countDown()
                    if (!opened) close()
                } else complete(status == BluetoothGatt.GATT_SUCCESS)
            }

            @Deprecated("Android API 32 and earlier callback")
            override fun onCharacteristicRead(link: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
                if (Build.VERSION.SDK_INT < 33) complete(status == BluetoothGatt.GATT_SUCCESS, characteristic.value)
            }

            override fun onCharacteristicRead(link: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray, status: Int) {
                complete(status == BluetoothGatt.GATT_SUCCESS, value)
            }
        }

        private fun writeRaw(link: BluetoothGatt, characteristic: BluetoothGattCharacteristic, packet: ByteArray): Boolean {
            return if (Build.VERSION.SDK_INT >= 33) {
                link.writeCharacteristic(characteristic, packet, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT) == android.bluetooth.BluetoothStatusCodes.SUCCESS
            } else {
                characteristic.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                characteristic.value = packet
                link.writeCharacteristic(characteristic)
            }
        }

        fun open(): Boolean {
            gatt = device.connectGatt(context, false, callback, android.bluetooth.BluetoothDevice.TRANSPORT_LE)
            if (!ready.await(LINK_OPEN_TIMEOUT_MS, TimeUnit.MILLISECONDS) || !opened || closed) { close(); return false }
            // Size self-test: the first read must arrive at the full agreed
            // size. When the link delivers it cut short, reopen at the size
            // that did arrive, so no data packet is silently truncated later.
            for (round in 0 until 8) {
                val asked = packetBytes
                val first = read() ?: return false
                if (first.size == 1 && first[0].toInt() == 0) return true // the peer sent no self-test
                val declared = if (first.size >= 3 && first[0].toInt() == 5) ((first[1].toInt() and 255) shl 8) or (first[2].toInt() and 255) else -1
                if (declared != asked) { close(); return false }
                if (first.size == asked) {
                    // The write half: a full-size packet must be accepted whole.
                    if (write(probePacket(asked), closeOnFailure = false)) return write(byteArrayOf(6))
                    if (closed) return false
                    val next = intArrayOf(244, 128, 64, MIN_PACKET_BYTES).firstOrNull { it < asked }
                    if (next == null || !write(byteArrayOf(4))) { close(); return false }
                    packetBytes = next
                    if (!write(openPacket(next))) return false
                    continue
                }
                // A read carries MTU - 1 bytes and a write MTU - 3: two fewer.
                val smaller = (first.size - 2).coerceAtLeast(MIN_PACKET_BYTES)
                if (smaller >= asked || !write(byteArrayOf(4))) { close(); return false }
                packetBytes = smaller
                if (!write(openPacket(smaller))) return false
            }
            close()
            return false
        }

        // Reads and writes are idempotent in this protocol (a repeated packet
        // is recognised by its sequence), so a transient radio error or a busy
        // stack is retried before the link is given up.
        fun write(packet: ByteArray, closeOnFailure: Boolean = true): Boolean = synchronized(operationGate) {
            if (closed || !validPacket(packet) || packet.size > packetBytes) return@synchronized false
            var ok = false
            for (attempt in 0 until ATT_ATTEMPTS) {
                val link = gatt ?: break
                val target = ingress ?: break
                if (closed) break
                if (attempt > 0) runCatching { Thread.sleep(150) }
                val done = CountDownLatch(1)
                operation = done
                succeeded = false
                result = null
                ok = runCatching { writeRaw(link, target, packet) && done.await(CONNECT_TIMEOUT_MS, TimeUnit.MILLISECONDS) && succeeded }.getOrDefault(false)
                operation = null
                if (ok) break
            }
            activeAt = android.os.SystemClock.elapsedRealtime()
            if (!ok && closeOnFailure) close()
            ok
        }

        fun read(): ByteArray? = synchronized(operationGate) {
            var bytes: ByteArray? = null
            for (attempt in 0 until ATT_ATTEMPTS) {
                val link = gatt ?: break
                val target = egress ?: break
                if (closed) break
                if (attempt > 0) runCatching { Thread.sleep(150) }
                val done = CountDownLatch(1)
                operation = done
                succeeded = false
                result = null
                val ok = runCatching { link.readCharacteristic(target) && done.await(CONNECT_TIMEOUT_MS, TimeUnit.MILLISECONDS) && succeeded }.getOrDefault(false)
                val value = result?.copyOf()
                operation = null
                if (ok && value != null && validPacket(value) && value.size <= packetBytes) { bytes = value; break }
            }
            activeAt = android.os.SystemClock.elapsedRealtime()
            if (bytes == null) close()
            bytes
        }

        fun close() {
            closed = true
            opened = false
            ready.countDown()
            operation?.countDown()
            val link = gatt
            gatt = null
            runCatching { link?.disconnect() }
            runCatching { link?.close() }
        }
    }

    private fun permissions(): Array<String> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.BLUETOOTH_CONNECT)
    } else {
        arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
    }

    private fun permissionsGranted(context: Context): Boolean = permissions().all {
        context.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED
    }

    private fun manager(context: Context): BluetoothManager? = context.getSystemService(BluetoothManager::class.java)

    private fun available(context: Context): Boolean =
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE) && manager(context)?.adapter != null

    private fun includeDeviceHints(result: JSONObject, source: JSONObject): JSONObject {
        // These fields are display hints. Rust applies the shared label policy.
        (source.opt("label") as? String)?.takeIf { it.toByteArray(Charsets.UTF_8).size in 1..100 }
            ?.let { result.put("label", it) }
        when (val platform = source.opt("platform")) {
            "android", "windows", "macos", "linux" -> result.put("platform", platform)
        }
        // Opt-in picture fingerprint (16 hex digits); the picture itself is
        // fetched over an authenticated session, never from this hint.
        (source.opt("picture") as? String)?.takeIf { it.matches(Regex("[0-9a-f]{16}")) }
            ?.let { result.put("picture", it) }
        return result
    }

    private fun metadataWithAddresses(withHints: Boolean): ByteArray {
        val source = metadata ?: return ByteArray(0)
        val addresses = linkedSetOf<String>()
        runCatching {
            NetworkInterface.getNetworkInterfaces()?.toList()?.forEach { network ->
                val name = network.name.lowercase()
                val localInterface = name.contains("wlan") || name.startsWith("wifi") || name.startsWith("ap") ||
                    name.startsWith("p2p") || name.startsWith("eth") || name.startsWith("en")
                if (network.isUp && !network.isLoopback && localInterface) {
                    network.inetAddresses.toList().filterIsInstance<Inet4Address>().forEach { address ->
                        if (!address.isLoopbackAddress && (address.isSiteLocalAddress || address.isLinkLocalAddress)) {
                            address.hostAddress?.let { if (addresses.size < 8) addresses.add(it) }
                        }
                    }
                }
            }
        }
        val result = JSONObject()
            .put("version", 1)
            .put("fingerprint", source.getString("fingerprint"))
            .put("port", source.getInt("port"))
            .put("addresses", JSONArray(addresses.toList()))
            .put("bleMesh", true)
        val legacy = result.toString().toByteArray(Charsets.UTF_8)
        return if (withHints) includeDeviceHints(result, source).toString().toByteArray(Charsets.UTF_8)
            .takeIf { it.size <= MAX_METADATA_BYTES } ?: legacy else legacy
    }

    private fun remoteMetadata(value: ByteArray, withHints: Boolean): String? {
        if (value.size > MAX_METADATA_BYTES) return null
        val hint = JSONObject(value.toString(Charsets.UTF_8))
        val fingerprint = hint.optString("fingerprint")
        val port = hint.optInt("port")
        if (hint.optInt("version") != 1 || !fingerprint.matches(Regex("[0-9a-f]{64}")) || port !in 1..65535 || fingerprint == metadata?.optString("fingerprint")) return null
        val source = hint.optJSONArray("addresses") ?: return null
        if (source.length() > 8) return null
        val addresses = linkedSetOf<String>()
        for (index in 0 until source.length()) {
            val candidate = source.optString(index)
            val pieces = candidate.split('.')
            if (pieces.size != 4) continue
            val octets = pieces.mapNotNull { it.toIntOrNull()?.takeIf { byte -> byte in 0..255 } }
            if (octets.size == 4 && (octets[0] == 10 || (octets[0] == 172 && octets[1] in 16..31) ||
                    (octets[0] == 192 && octets[1] == 168) || (octets[0] == 169 && octets[1] == 254))) {
                addresses.add(octets.joinToString("."))
            }
        }
        val result = JSONObject().put("version", 1).put("fingerprint", fingerprint).put("port", port)
            .put("addresses", JSONArray(addresses.toList())).put("bleMesh", hint.optBoolean("bleMesh", false))
        if (withHints) includeDeviceHints(result, hint)
        return result.toString()
    }

    private fun advertiseCallback(token: Long) = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
            synchronized(gate) { if (wanted && generation == token) advertising = true }
        }

        override fun onStartFailure(errorCode: Int) {
            synchronized(gate) {
                if (generation != token) return
                advertising = false
                if (wanted) lastError = "Bluetooth advertising failed ($errorCode). Discovery can continue when scanning is available."
            }
        }
    }

    // Many phones stop a connectable advertisement as soon as one device
    // connects (a hint read is enough) and never resume it. An advertising
    // set reports that, and the same set is switched back on, so the phone
    // stays discoverable with the same address.
    private fun advertisingSetCallback(token: Long) = object : android.bluetooth.le.AdvertisingSetCallback() {
        override fun onAdvertisingSetStarted(set: android.bluetooth.le.AdvertisingSet?, txPower: Int, status: Int) {
            val fallback = synchronized(gate) {
                if (!wanted || generation != token) return
                if (status == ADVERTISE_SUCCESS && set != null) {
                    activeAdvertisingSet = set
                    advertising = true
                    false
                } else {
                    activeAdvertisingSetCallback = null
                    true
                }
            }
            // This radio has no advertising sets: use the original call.
            if (fallback) synchronized(gate) { runCatching { advertiseLegacy(token) } }
        }

        override fun onAdvertisingEnabled(set: android.bluetooth.le.AdvertisingSet?, enable: Boolean, status: Int) {
            synchronized(gate) {
                if (!wanted || generation != token) return
                advertising = enable && status == ADVERTISE_SUCCESS
                if (!enable) runCatching { set?.enableAdvertising(true, 0, 0) }
            }
        }

        override fun onAdvertisingSetStopped(set: android.bluetooth.le.AdvertisingSet?) {
            synchronized(gate) { if (generation == token) { advertising = false; activeAdvertisingSet = null } }
        }
    }

    private fun advertiseData(): AdvertiseData = AdvertiseData.Builder().addServiceUuid(ParcelUuid(SERVICE_UUID))
        .setIncludeDeviceName(false).setIncludeTxPowerLevel(false).build()

    private fun advertiseLegacy(token: Long) {
        val advertiser = adapter?.bluetoothLeAdvertiser ?: return
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(true)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .build()
        val callback = advertiseCallback(token)
        activeAdvertiseCallback = callback
        advertiser.startAdvertising(settings, advertiseData(), callback)
    }

    private fun advertise(token: Long) {
        val radio = adapter ?: return
        val advertiser = radio.bluetoothLeAdvertiser
        if (advertiser == null) {
            lastError = "This Bluetooth adapter can scan but cannot advertise a nearby service."
            return
        }
        lastAdvertiseAttempt = android.os.SystemClock.elapsedRealtime()
        val parameters = android.bluetooth.le.AdvertisingSetParameters.Builder()
            .setLegacyMode(true)
            .setConnectable(true)
            .setScannable(true)
            .setInterval(android.bluetooth.le.AdvertisingSetParameters.INTERVAL_LOW)
            .setTxPowerLevel(android.bluetooth.le.AdvertisingSetParameters.TX_POWER_MEDIUM)
            .build()
        val callback = advertisingSetCallback(token)
        activeAdvertisingSetCallback = callback
        val started = runCatching { advertiser.startAdvertisingSet(parameters, advertiseData(), null, null, null, callback) }.isSuccess
        if (!started) {
            activeAdvertisingSetCallback = null
            advertiseLegacy(token)
        }
    }

    /** Called with the gate held: stop whichever advertisement is running. */
    private fun stopAdvertisingLocked() {
        val advertiser = adapter?.bluetoothLeAdvertiser
        activeAdvertisingSetCallback?.let { callback -> runCatching { advertiser?.stopAdvertisingSet(callback) } }
        activeAdvertiseCallback?.let { callback -> runCatching { advertiser?.stopAdvertising(callback) } }
        activeAdvertisingSetCallback = null
        activeAdvertisingSet = null
        activeAdvertiseCallback = null
        advertising = false
    }

    /**
     * Called with the gate held, after a device connects or disconnects and
     * on every status poll: switch a stopped advertisement back on.
     */
    private fun keepAdvertisingLocked(token: Long) {
        if (!wanted || generation != token || server == null) return
        val set = activeAdvertisingSet
        if (set != null) {
            // Re-enabling a running set is harmless and keeps its address.
            runCatching { set.enableAdvertising(true, 0, 0) }
            return
        }
        // Nothing is advertising (it failed, or the radio dropped it): retry, but not in a tight loop.
        val now = android.os.SystemClock.elapsedRealtime()
        if (!advertising && activeAdvertisingSetCallback == null && now - lastAdvertiseAttempt > 10_000) {
            stopAdvertisingLocked()
            runCatching { advertise(token) }
        }
    }

    private fun serverCallback(token: Long) = object : BluetoothGattServerCallback() {
        override fun onServiceAdded(status: Int, service: BluetoothGattService) {
            synchronized(gate) {
                if (!wanted || generation != token || service.uuid != SERVICE_UUID) return
                if (status == BluetoothGatt.GATT_SUCCESS) runCatching { advertise(token) }.onFailure {
                    lastError = "Bluetooth advertising could not start. Check Bluetooth access in system settings."
                } else lastError = "The Bluetooth discovery service could not be registered ($status)."
            }
        }

        override fun onMtuChanged(device: android.bluetooth.BluetoothDevice, mtu: Int) {
            val address = runCatching { device.address }.getOrNull() ?: return
            synchronized(gate) { if (generation == token && (mtus.size < 16 || mtus.containsKey(address))) mtus[address] = mtu.coerceIn(23, 517) }
        }

        override fun onConnectionStateChange(device: android.bluetooth.BluetoothDevice, status: Int, newState: Int) {
            val address = runCatching { device.address }.getOrNull() ?: return
            // A connection is exactly when phones drop their advertisement.
            synchronized(gate) { keepAdvertisingLocked(token) }
            if (newState == BluetoothProfile.STATE_DISCONNECTED) synchronized(gate) {
                if (generation != token) return
                mtus.remove(address)
                readSnapshots.remove(address)
                serverLinks.entries.removeAll {
                    if (it.value.address == address) { closeServerLink(it.value); true } else false
                }
            }
        }

        override fun onCharacteristicWriteRequest(device: android.bluetooth.BluetoothDevice, requestId: Int, characteristic: BluetoothGattCharacteristic, preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray) {
            val address = runCatching { device.address }.getOrNull() ?: return
            runCatching { synchronized(gate) {
                if (generation != token) return
                val accepted = wanted && characteristic.uuid == WRITE_UUID && !preparedWrite && responseNeeded && offset == 0 && serverWrite(address, value)
                if (responseNeeded) server?.sendResponse(device, requestId, if (accepted) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_FAILURE, offset, null)
            } }.onFailure { synchronized(gate) { lastError = "Bluetooth stream access changed. Retry after checking system Bluetooth permissions." } }
        }

        override fun onCharacteristicReadRequest(device: android.bluetooth.BluetoothDevice, requestId: Int, offset: Int, characteristic: BluetoothGattCharacteristic) {
            val address = runCatching { device.address }.getOrNull() ?: return
            runCatching { synchronized(gate) {
                val gatt = server ?: return
                if (generation != token) return
                if (wanted && characteristic.uuid == READ_UUID && offset == 0) {
                    gatt.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, serverRead(address))
                    return
                }
                val withHints = characteristic.uuid == DEVICE_HINT_UUID
                if (!wanted || (!withHints && characteristic.uuid != METADATA_UUID)) {
                    gatt.sendResponse(device, requestId, BluetoothGatt.GATT_READ_NOT_PERMITTED, offset, null)
                    return
                }
                val now = android.os.SystemClock.elapsedRealtime()
                readSnapshots.entries.removeAll { now - it.value.createdAt > CONNECT_TIMEOUT_MS }
                val snapshot = if (offset == 0) {
                    if (readSnapshots.size >= 16 && !readSnapshots.containsKey(address)) {
                        gatt.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null)
                        return
                    }
                    ReadSnapshot(metadataWithAddresses(withHints), now, characteristic.uuid).also { readSnapshots[address] = it }
                } else readSnapshots[address]?.takeIf { it.characteristic == characteristic.uuid }
                if (snapshot == null || offset < 0 || offset > snapshot.bytes.size || snapshot.bytes.size > MAX_METADATA_BYTES) {
                    gatt.sendResponse(device, requestId, BluetoothGatt.GATT_INVALID_OFFSET, offset, null)
                    return
                }
                val until = minOf(snapshot.bytes.size, offset + (mtus[address] ?: 23) - 1)
                gatt.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, snapshot.bytes.copyOfRange(offset, until))
            } }.onFailure { synchronized(gate) { lastError = "Bluetooth stream access changed. Retry after checking system Bluetooth permissions." } }
        }
    }

    private fun scanCallback(token: Long) = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) = observe(result, token)
        override fun onBatchScanResults(results: MutableList<ScanResult>) { results.forEach { observe(it, token) } }
        override fun onScanFailed(errorCode: Int) {
            synchronized(gate) {
                if (generation != token) return
                scanning = false
                peers.clear()
                if (wanted) lastError = "Bluetooth scanning failed ($errorCode). Retry discovery after checking system Bluetooth access."
            }
        }
    }

    private fun observe(result: ScanResult, scanToken: Long) {
        synchronized(gate) {
            if (!wanted || !scanning || generation != scanToken) return
            val context = appContext ?: return
            if (!permissionsGranted(context)) return
            val address = runCatching { result.device.address }.getOrNull() ?: return
            val now = android.os.SystemClock.elapsedRealtime()
            // Keep a device listed while it is in range, including during a
            // link to it: the list must not drop the peer being paired.
            val known = peers[address]?.also { it.seenAt = now; it.rssi = result.rssi }
            // Hint reads share the radio with data links. Never start one
            // while a stream is open, and re-read a known peer only rarely.
            if (clientLinks.isNotEmpty() || serverLinks.values.any { !it.closed }) return
            if (known != null && now - known.readAt < KNOWN_PEER_REFRESH_MS) return
            if (connections.containsKey(address) || connections.size >= MAX_CONNECTIONS || now - (attempted[address] ?: 0) < RETRY_MS) return
            attempted.entries.removeAll { now - it.value > PEER_TTL_MS }
            if (attempted.size >= MAX_PEERS && !attempted.containsKey(address)) return
            attempted[address] = now
            connections[address] = null
            val token = generation
            val callback = object : BluetoothGattCallback() {
                private fun finish(gatt: BluetoothGatt) {
                    synchronized(gate) {
                        if (connections[address] === gatt || connections[address] == null) connections.remove(address)
                    }
                    runCatching { gatt.disconnect() }
                    runCatching { gatt.close() }
                }

                override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
                    synchronized(gate) {
                        if (!wanted || generation != token || status != BluetoothGatt.GATT_SUCCESS || newState == BluetoothProfile.STATE_DISCONNECTED) {
                            finish(gatt)
                        } else if (newState == BluetoothProfile.STATE_CONNECTED && !runCatching { gatt.discoverServices() }.getOrDefault(false)) finish(gatt)
                    }
                }

                override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
                    synchronized(gate) {
                        if (!wanted || generation != token || status != BluetoothGatt.GATT_SUCCESS) { finish(gatt); return }
                        if (!readDiscovery(gatt, DEVICE_HINT_UUID) && !readDiscovery(gatt, METADATA_UUID)) finish(gatt)
                    }
                }

                private fun readDiscovery(gatt: BluetoothGatt, uuid: UUID): Boolean = runCatching {
                    val characteristic = gatt.getService(SERVICE_UUID)?.getCharacteristic(uuid) ?: return@runCatching false
                    gatt.readCharacteristic(characteristic)
                }.getOrDefault(false)

                private fun received(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray, status: Int) {
                    synchronized(gate) {
                        if (wanted && scanning && generation == token) {
                            val withHints = characteristic.uuid == DEVICE_HINT_UUID
                            val text = if (status == BluetoothGatt.GATT_SUCCESS && (withHints || characteristic.uuid == METADATA_UUID)) {
                                runCatching { remoteMetadata(value, withHints) }.getOrNull()
                            } else null
                            if (text != null && (peers.size < MAX_PEERS || peers.containsKey(address))) {
                                val readAt = android.os.SystemClock.elapsedRealtime()
                                peers[address] = Peer(address, text, readAt, peers[address]?.rssi ?: result.rssi, readAt)
                            }
                            if (text == null && withHints && readDiscovery(gatt, METADATA_UUID)) return
                        }
                    }
                    finish(gatt)
                }

                @Deprecated("Android API 32 and earlier callback")
                override fun onCharacteristicRead(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
                    if (Build.VERSION.SDK_INT < 33) received(gatt, characteristic, characteristic.value ?: ByteArray(0), status)
                }

                override fun onCharacteristicRead(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray, status: Int) = received(gatt, characteristic, value, status)
            }
            val gatt = runCatching { result.device.connectGatt(context, false, callback, android.bluetooth.BluetoothDevice.TRANSPORT_LE) }.getOrNull()
            if (gatt == null) connections.remove(address) else {
                connections[address] = gatt
                handler.postDelayed({ synchronized(gate) {
                    if (generation == token && connections[address] === gatt) {
                        connections.remove(address)
                        runCatching { gatt.disconnect() }
                        runCatching { gatt.close() }
                    }
                } }, CONNECT_TIMEOUT_MS)
            }
        }
    }

    @JvmStatic
    fun start(context: Context, metadataJson: String): String = synchronized(gate) {
        try {
            val parsed = JSONObject(metadataJson)
            if (metadataJson.toByteArray().size > MAX_METADATA_BYTES || parsed.optInt("version") != 1 ||
                !parsed.optString("fingerprint").matches(Regex("[0-9a-f]{64}")) || parsed.optInt("port") !in 1..65535) return@synchronized "error:Invalid Bluetooth discovery metadata."
            stopLocked()
            appContext = context.applicationContext
            metadata = parsed
            wanted = true
            if (!available(context)) { lastError = "Bluetooth Low Energy is unavailable on this device."; return@synchronized status(context) }
            if (!permissionsGranted(context)) { lastError = "Allow Nearby devices access to start Bluetooth discovery."; return@synchronized status(context) }
            val radio = manager(context)?.adapter ?: return@synchronized "error:Bluetooth adapter unavailable."
            adapter = radio
            if (!radio.isEnabled) { lastError = "Turn on Bluetooth in system settings, then retry discovery."; return@synchronized status(context) }
            val service = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
            service.addCharacteristic(BluetoothGattCharacteristic(METADATA_UUID, BluetoothGattCharacteristic.PROPERTY_READ, BluetoothGattCharacteristic.PERMISSION_READ))
            service.addCharacteristic(BluetoothGattCharacteristic(DEVICE_HINT_UUID, BluetoothGattCharacteristic.PROPERTY_READ, BluetoothGattCharacteristic.PERMISSION_READ))
            service.addCharacteristic(BluetoothGattCharacteristic(WRITE_UUID, BluetoothGattCharacteristic.PROPERTY_WRITE, BluetoothGattCharacteristic.PERMISSION_WRITE))
            service.addCharacteristic(BluetoothGattCharacteristic(READ_UUID, BluetoothGattCharacteristic.PROPERTY_READ, BluetoothGattCharacteristic.PERMISSION_READ))
            val token = generation
            server = manager(context)?.openGattServer(context.applicationContext, serverCallback(token))
            if (server?.addService(service) != true) lastError = "Bluetooth advertising service could not start. Scanning remains available."
            val scanner = radio.bluetoothLeScanner
            if (scanner != null) {
                val callback = scanCallback(token)
                activeScanCallback = callback
                scanner.startScan(listOf(ScanFilter.Builder().setServiceUuid(ParcelUuid(SERVICE_UUID)).build()), ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(), callback)
                scanning = true
            } else lastError = "Bluetooth scanning is unavailable."
            status(context)
        } catch (_: SecurityException) {
            lastError = "Bluetooth access was revoked. Allow Nearby devices access, then retry discovery."
            status(context)
        } catch (_: Exception) {
            lastError = "Bluetooth discovery could not start. Check Bluetooth in system settings and retry."
            status(context)
        }
    }

    @JvmStatic
    fun status(context: Context): String = synchronized(gate) {
        val now = android.os.SystemClock.elapsedRealtime()
        val permitted = permissionsGranted(context)
        val enabled = permitted && runCatching { manager(context)?.adapter?.isEnabled == true }.getOrDefault(false)
        if (!enabled && (scanning || advertising)) {
            stopLocked()
            lastError = if (permitted) "Turn on Bluetooth in system settings, then retry discovery."
                else "Allow Nearby devices access to start Bluetooth discovery."
        }
        if (enabled) keepAdvertisingLocked(generation)
        val scannerActive = enabled && scanning
        val advertiserActive = enabled && advertising
        peers.entries.removeAll { entry ->
            !scannerActive || (now - entry.value.seenAt > PEER_TTL_MS && clientLinks.values.none { it.address == entry.key })
        }
        serverLinks.entries.removeAll {
            if (now - it.value.activeAt > LINK_TIMEOUT_MS) { closeServerLink(it.value); true } else false
        }
        clientLinks.entries.removeAll { (_, link) ->
            if (now - link.activeAt > LINK_TIMEOUT_MS) { link.close(); true } else false
        }
        val list = JSONArray()
        peers.values.forEach { peer ->
            // A peer kept only by its open link still counts as present.
            val age = (now - peer.seenAt).coerceIn(0, PEER_TTL_MS - 2_000)
            val entry = JSONObject().put("address", peer.address).put("metadata", peer.metadata)
                .put("lastSeen", (System.currentTimeMillis() - age) / 1000)
            if (peer.rssi in -127..20) entry.put("rssi", peer.rssi)
            list.put(entry)
        }
        JSONObject().put("available", available(context)).put("permissionGranted", permitted)
            .put("running", scannerActive || advertiserActive)
            .put("scanning", scannerActive).put("advertising", advertiserActive)
            .put("error", lastError ?: JSONObject.NULL)
            .put("peers", list).toString()
    }

    private fun stopLocked() {
        generation += 1
        wanted = false
        activeScanCallback?.let { callback -> runCatching { adapter?.bluetoothLeScanner?.stopScan(callback) } }
        stopAdvertisingLocked()
        activeScanCallback = null
        scanning = false
        advertising = false
        connections.values.filterNotNull().forEach { runCatching { it.disconnect(); it.close() } }
        connections.clear()
        clientLinks.values.forEach { it.close() }
        clientLinks.clear()
        serverLinks.values.forEach(::closeServerLink)
        serverLinks.clear()
        incomingLinks.clear()
        runCatching { server?.close() }
        server = null
        peers.clear()
        attempted.clear()
        readSnapshots.clear()
        mtus.clear()
        lastError = null
    }

    @JvmStatic
    fun stop(context: Context): String = synchronized(gate) {
        stopLocked()
        metadata = null
        "ok"
    }

    @JvmStatic
    fun requestPermissions(context: Context): String {
        return if (runCatching { HelixPermissionPrompt.request(context, permissions(), PERMISSION_REQUEST) }.getOrDefault(false)) "ok"
        else "error:Nearby devices permission was not granted. Allow Bluetooth access in system settings, then retry discovery."
    }

    fun onPermissionsResult(context: Context, requestCode: Int) {
        if (requestCode != PERMISSION_REQUEST) return
        val pending = synchronized(gate) { if (wanted) metadata?.toString() else null }
        if (pending != null && permissionsGranted(context)) start(context, pending)
    }

    /** Returns "<link id>#<packet bytes>" or an in-band error. */
    @JvmStatic
    fun openLink(context: Context, address: String): String {
        // The first LE connection attempt often fails (GATT status 133) while
        // the peer is between advertising events. One retry covers that.
        var failure = "error:The nearby Bluetooth device did not establish a stream."
        for (attempt in 0 until 2) {
            if (attempt > 0) runCatching { Thread.sleep(500) }
            val link = synchronized(gate) {
                if (!wanted || !permissionsGranted(context)) return "error:Start Bluetooth discovery and grant Nearby devices access before connecting."
                if (serverLinks.size + clientLinks.size >= MAX_LINKS) return "error:The Bluetooth connection queue is full."
                if (!BluetoothAdapter.checkBluetoothAddress(address)) return "error:Invalid Bluetooth address."
                val device = runCatching { adapter?.getRemoteDevice(address) }.getOrNull() ?: return "error:Bluetooth adapter unavailable."
                ClientLink("c-" + UUID.randomUUID().toString(), address, context.applicationContext, device).also { clientLinks[it.id] = it }
            }
            try {
                if (link.open()) return link.id + "#" + link.packetBytes
                synchronized(gate) { clientLinks.remove(link.id) }
            } catch (_: Exception) {
                link.close()
                synchronized(gate) { clientLinks.remove(link.id) }
                failure = "error:The nearby Bluetooth connection could not start."
            }
        }
        return failure
    }

    @JvmStatic
    fun takeIncoming(context: Context): String = synchronized(gate) {
        val incoming = JSONArray()
        while (incomingLinks.isNotEmpty()) {
            val id = incomingLinks.removeFirst()
            serverLinks[id]?.takeUnless { it.closed }?.let {
                incoming.put(JSONObject().put("id", it.id).put("address", it.address).put("packet", it.packetBytes))
            }
        }
        incoming.toString()
    }

    @JvmStatic
    fun linkWrite(context: Context, id: String, encoded: String): String {
        // Base64 of one full-size packet.
        if (encoded.length > 4 * ((MAX_PACKET_BYTES + 2) / 3)) return "error:Bluetooth packet exceeds its bound."
        val packet = runCatching { Base64.decode(encoded, Base64.NO_WRAP) }.getOrNull() ?: return "error:Invalid Bluetooth packet."
        if (!validPacket(packet)) return "error:Invalid Bluetooth packet framing."
        val client = synchronized(gate) { clientLinks[id] }
        if (client != null) return if (client.write(packet)) "ok" else "error:The Bluetooth stream write failed."
        var pendingAck: CountDownLatch? = null
        val queued = synchronized(gate) {
            val link = serverLinks[id] ?: return@synchronized "error:The Bluetooth stream has closed."
            link.activeAt = android.os.SystemClock.elapsedRealtime()
            when (packet[0].toInt()) {
                2 -> {
                    if (link.closed || sequence(packet) != link.nextSend) "error:Unexpected Bluetooth packet sequence."
                    else if (packet.size > link.packetBytes) "error:Bluetooth packet exceeds the link size."
                    else if (link.outgoingBytes + packet.size > MAX_LINK_BYTES) "error:Bluetooth stream backpressure."
                    else {
                        link.outgoing.add(packet.copyOf())
                        link.outgoingBytes += packet.size
                        link.nextSend += 1
                        pendingAck = CountDownLatch(1).also { link.acknowledgments[sequence(packet)] = it }
                        "ok"
                    }
                }
                3 -> if (sequence(packet) < link.nextReceive) "ok" else "error:Unexpected Bluetooth acknowledgment."
                4 -> { closeServerLink(link); "ok" }
                else -> "error:Unexpected Bluetooth packet."
            }
        }
        if (queued != "ok") return queued
        val acknowledgment = pendingAck ?: return queued
        val completed = runCatching { acknowledgment.await(LINK_ACK_TIMEOUT_MS, TimeUnit.MILLISECONDS) }.getOrDefault(false)
        return synchronized(gate) {
            val link = serverLinks[id]
            if (completed && link != null && !link.closed && link.lastRemoteAck >= sequence(packet)) "ok"
            else {
                if (link != null) closeServerLink(link)
                "error:The Bluetooth peer did not acknowledge the packet."
            }
        }
    }

    @JvmStatic
    fun linkRead(context: Context, id: String): String {
        val client = synchronized(gate) { clientLinks[id] }
        if (client != null) {
            val packet = client.read() ?: return "error:The Bluetooth stream read failed."
            return Base64.encodeToString(packet, Base64.NO_WRAP)
        }
        return synchronized(gate) {
            val link = serverLinks[id] ?: return@synchronized "error:The Bluetooth stream has closed."
            link.activeAt = android.os.SystemClock.elapsedRealtime()
            val packet = if (link.closed) byteArrayOf(4) else link.incoming.pollFirst()?.also { link.incomingBytes -= it.size } ?: byteArrayOf(0)
            Base64.encodeToString(packet, Base64.NO_WRAP)
        }
    }

    @JvmStatic
    fun linkClose(context: Context, id: String): String {
        val client = synchronized(gate) {
            serverLinks.remove(id)?.let(::closeServerLink)
            incomingLinks.remove(id)
            clientLinks.remove(id)
        }
        client?.close()
        return "ok"
    }
}
