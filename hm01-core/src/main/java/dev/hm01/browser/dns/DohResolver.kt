package dev.hm01.browser.dns

import dev.hm01.browser.config.BrowserPolicyConfig
import dev.hm01.browser.config.DefaultBaselineLists
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.Locale
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Pluggable transport for executing RFC 8484 DNS-over-HTTPS queries.
 */
fun interface DohTransport {
    @Throws(IOException::class)
    fun query(endpointUrl: String, dnsQueryPacket: ByteArray, timeoutMs: Int): ByteArray
}

/**
 * CleanBrowsing RFC 8484 DNS-over-HTTPS (DoH) client.
 *
 * Verifies every hostname against CleanBrowsing's DoH endpoint (default `FAMILY_FILTER`)
 * using binary DNS wireformat (`application/dns-message`) and pinned IP bootstrap
 * (`185.228.168.168` / `185.228.169.168`) so initial lookups never depend on untrusted local DNS.
 */
open class DohResolver(
    private val configProvider: () -> BrowserPolicyConfig = { BrowserPolicyConfig() },
    val cache: DohDecisionCache = SharedCacheHolder.INSTANCE,
    private val transport: DohTransport = HttpsPinnedDohTransport(),
    private val timeoutMs: Int = DEFAULT_TIMEOUT_MS
) {

    object SharedCacheHolder {
        val INSTANCE = DohDecisionCache()
    }

    /**
     * Evaluates [rawHost] against the configured CleanBrowsing DoH endpoint, using the shared
     * LRU+TTL cache and coalescing concurrent in-flight requests for the same hostname.
     */
    open fun resolve(rawHost: String): DohVerdict {
        val host = rawHost.trim().trimEnd('.').lowercase(Locale.ROOT)
        if (host.isEmpty()) return DohVerdict.BLOCK

        // Explicit CleanBrowsing test domain check in case offline/unit-tested without network
        cache.get(host)?.let { return it }

        var shouldCache = true
        return cache.getOrCompute(
            hostname = host,
            timeoutMs = (timeoutMs * 2L).coerceAtLeast(3_000L),
            cacheResult = { shouldCache }
        ) { targetHost ->
            val config = configProvider()
            val endpointUrl = config.dohPreset.resolveEndpointUrl(config.customDohUrl)
            try {
                val queryBytes = buildDnsAQueryPacket(targetHost)
                val responseBytes = transport.query(endpointUrl, queryBytes, timeoutMs)
                parseDnsResponseVerdict(responseBytes)
            } catch (e: Exception) {
                shouldCache = false
                if (DefaultBaselineLists.isDedicatedTrustedIdpOrPaymentOrCaptchaHost(targetHost)) {
                    // Fail open for Trusted IdP hosts so sign-ins don't break on captive portals
                    DohVerdict.ALLOW
                } else if (config.failClosedOnDnsError) {
                    DohVerdict.BLOCK
                } else {
                    DohVerdict.ALLOW
                }
            }
        }
    }

    companion object {
        const val DEFAULT_TIMEOUT_MS: Int = 1_500
        const val CLEANBROWSING_DOH_HOST: String = "doh.cleanbrowsing.org"

        val CLEANBROWSING_BOOTSTRAP_IPS: List<ByteArray> = listOf(
            byteArrayOf(185.toByte(), 228.toByte(), 168.toByte(), 168.toByte()),
            byteArrayOf(185.toByte(), 228.toByte(), 169.toByte(), 168.toByte())
        )

        private const val DNS_TYPE_A = 1
        private const val DNS_TYPE_CNAME = 5
        private const val DNS_TYPE_SOA = 6
        private const val DNS_CLASS_IN = 1

        private const val RCODE_NOERROR = 0
        private const val RCODE_NXDOMAIN = 3

        /**
         * Builds an RFC 1035 binary DNS query packet for `QTYPE = A (1)`, `QCLASS = IN (1)`.
         */
        @JvmStatic
        fun buildDnsAQueryPacket(hostname: String): ByteArray {
            val cleanHost = hostname.trim().trimEnd('.').lowercase(Locale.ROOT)
            val baos = ByteArrayOutputStream(64)
            val out = DataOutputStream(baos)

            // 12-byte DNS Header
            out.writeShort(0x0000) // ID = 0 (RFC 8484 Section 4.1 recommends ID = 0 for DoH caching)
            out.writeShort(0x0100) // Flags: QR=0, Opcode=0, RD=1 (Recursion Desired)
            out.writeShort(1)      // QDCOUNT = 1
            out.writeShort(0)      // ANCOUNT = 0
            out.writeShort(0)      // NSCOUNT = 0
            out.writeShort(0)      // ARCOUNT = 0

            // Question Section: QNAME
            val labels = cleanHost.split('.')
            for (label in labels) {
                val bytes = label.toByteArray(StandardCharsets.US_ASCII)
                require(bytes.isNotEmpty() && bytes.size <= 63) {
                    "Invalid DNS label in hostname: $hostname"
                }
                out.writeByte(bytes.size)
                out.write(bytes)
            }
            out.writeByte(0) // Root terminator

            out.writeShort(DNS_TYPE_A)   // QTYPE = A (1)
            out.writeShort(DNS_CLASS_IN) // QCLASS = IN (1)
            out.flush()
            return baos.toByteArray()
        }

        /**
         * Encodes a binary DNS query packet using RFC 8484 Base64url (unpadded).
         */
        @JvmStatic
        fun encodeBase64UrlUnpadded(packet: ByteArray): String {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(packet)
        }

        /**
         * Parses an RFC 1035 binary DNS response packet and evaluates CleanBrowsing's verdict:
         * - `BLOCK`: `RCODE == 3` (`NXDOMAIN`), empty answer with sinkhole SOA (`cleanbrowsing.rpz`),
         *   or any A record pointing to CleanBrowsing block/sinkhole IPs (`185.228.168.0/24`,
         *   `185.228.169.0/24`, `0.0.0.0`, `127.0.0.1`).
         * - `ALLOW`: `RCODE == 0` (`NOERROR`) with at least one valid public IP record that is not
         *   a sinkhole IP.
         */
        @JvmStatic
        fun parseDnsResponseVerdict(packet: ByteArray): DohVerdict {
            if (packet.size < 12) return DohVerdict.BLOCK

            val flags = readUInt16(packet, 2)
            val rcode = flags and 0x0F
            if (rcode == RCODE_NXDOMAIN) {
                return DohVerdict.BLOCK
            }
            if (rcode != RCODE_NOERROR) {
                return DohVerdict.BLOCK
            }

            val qdCount = readUInt16(packet, 4)
            val anCount = readUInt16(packet, 6)
            val nsCount = readUInt16(packet, 8)

            var offset = 12
            // Skip Question section
            for (i in 0 until qdCount) {
                offset = skipDnsName(packet, offset)
                if (offset < 0 || offset + 4 > packet.size) return DohVerdict.BLOCK
                offset += 4 // QTYPE + QCLASS
            }

            var validPublicARecords = 0
            var hasCnameRecord = false

            // Parse Answer RRs
            for (i in 0 until anCount) {
                offset = skipDnsName(packet, offset)
                if (offset < 0 || offset + 10 > packet.size) return DohVerdict.BLOCK
                val rrType = readUInt16(packet, offset)
                val rdLength = readUInt16(packet, offset + 8)
                offset += 10
                if (offset + rdLength > packet.size) return DohVerdict.BLOCK

                if (rrType == DNS_TYPE_A && rdLength == 4) {
                    val b0 = packet[offset].toInt() and 0xFF
                    val b1 = packet[offset + 1].toInt() and 0xFF
                    val b2 = packet[offset + 2].toInt() and 0xFF
                    val b3 = packet[offset + 3].toInt() and 0xFF

                    if (isSinkholeOrBlockIp(b0, b1, b2, b3)) {
                        return DohVerdict.BLOCK
                    }
                    validPublicARecords++
                } else if (rrType == DNS_TYPE_CNAME) {
                    hasCnameRecord = true
                    val cnameTarget = decodeDnsName(packet, offset).lowercase(Locale.ROOT)
                    if (cnameTarget.contains("cleanbrowsing.rpz") ||
                        cnameTarget.contains("block.cleanbrowsing")
                    ) {
                        return DohVerdict.BLOCK
                    }
                }

                offset += rdLength
            }

            // Parse Authority RRs (check for cleanbrowsing.rpz sinkhole SOA)
            for (i in 0 until nsCount) {
                val ownerName = decodeDnsName(packet, offset).lowercase(Locale.ROOT)
                offset = skipDnsName(packet, offset)
                if (offset < 0 || offset + 10 > packet.size) break
                val rrType = readUInt16(packet, offset)
                val rdLength = readUInt16(packet, offset + 8)
                offset += 10
                if (offset + rdLength > packet.size) break

                if (ownerName.contains("cleanbrowsing.rpz")) {
                    return DohVerdict.BLOCK
                }
                if (rrType == DNS_TYPE_SOA) {
                    val mname = decodeDnsName(packet, offset).lowercase(Locale.ROOT)
                    val afterMname = skipDnsName(packet, offset)
                    val rname = if (afterMname in 0 until (offset + rdLength)) {
                        decodeDnsName(packet, afterMname).lowercase(Locale.ROOT)
                    } else {
                        ""
                    }
                    if (mname.contains("cleanbrowsing.rpz") || rname.contains("cleanbrowsing.rpz")) {
                        return DohVerdict.BLOCK
                    }
                }
                offset += rdLength
            }

            return if (validPublicARecords > 0 || hasCnameRecord) {
                DohVerdict.ALLOW
            } else {
                // RCODE == 0 with 0 valid A records and no CNAME
                DohVerdict.BLOCK
            }
        }

        /**
         * Checks whether an IPv4 address (`b0.b1.b2.b3`) is a known CleanBrowsing block/sinkhole IP:
         * - `185.228.168.0/24`
         * - `185.228.169.0/24`
         * - `0.0.0.0`
         * - `127.0.0.1` (or `127.0.0.0/8`)
         */
        @JvmStatic
        fun isSinkholeOrBlockIp(b0: Int, b1: Int, b2: Int, b3: Int): Boolean {
            if (b0 == 0 && b1 == 0 && b2 == 0 && b3 == 0) return true
            if (b0 == 127) return true
            if (b0 == 185 && b1 == 228 && (b2 == 168 || b2 == 169)) return true
            return false
        }

        private fun readUInt16(bytes: ByteArray, offset: Int): Int {
            return ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
        }

        private fun skipDnsName(packet: ByteArray, startOffset: Int): Int {
            var offset = startOffset
            var steps = 0
            while (offset < packet.size && steps++ < 128) {
                val len = packet[offset].toInt() and 0xFF
                if (len == 0) {
                    return offset + 1
                }
                if ((len and 0xC0) == 0xC0) {
                    // 2-byte compression pointer terminates the name in-place
                    return if (offset + 2 <= packet.size) offset + 2 else -1
                }
                offset += 1 + len
            }
            return -1
        }

        private fun decodeDnsName(packet: ByteArray, startOffset: Int): String {
            val sb = StringBuilder()
            var offset = startOffset
            var jumps = 0
            while (offset in packet.indices && jumps < 32) {
                val len = packet[offset].toInt() and 0xFF
                if (len == 0) break
                if ((len and 0xC0) == 0xC0) {
                    if (offset + 1 >= packet.size) break
                    val pointer = ((len and 0x3F) shl 8) or (packet[offset + 1].toInt() and 0xFF)
                    offset = pointer
                    jumps++
                    continue
                }
                offset++
                if (offset + len > packet.size) break
                if (sb.isNotEmpty()) sb.append('.')
                sb.append(String(packet, offset, len, StandardCharsets.US_ASCII))
                offset += len
            }
            return sb.toString()
        }
    }
}

/**
 * Default RFC 8484 HTTPS transport with pinned IP bootstrap (`185.228.168.168` / `185.228.169.168`)
 * for `doh.cleanbrowsing.org`.
 */
class HttpsPinnedDohTransport : DohTransport {

    private val pinnedSocketFactory = CleanBrowsingPinnedSslSocketFactory(
        SSLSocketFactory.getDefault() as SSLSocketFactory
    )

    override fun query(endpointUrl: String, dnsQueryPacket: ByteArray, timeoutMs: Int): ByteArray {
        val encodedDns = DohResolver.encodeBase64UrlUnpadded(dnsQueryPacket)
        val separator = if (endpointUrl.contains('?')) '&' else '?'
        val fullUrl = URL("$endpointUrl${separator}dns=$encodedDns")

        val connection = (fullUrl.openConnection() as HttpsURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            useCaches = false
            instanceFollowRedirects = false
            setRequestProperty("Accept", "application/dns-message")
            if (fullUrl.host.equals(DohResolver.CLEANBROWSING_DOH_HOST, ignoreCase = true)) {
                sslSocketFactory = pinnedSocketFactory
            }
        }

        try {
            val status = connection.responseCode
            if (status != 200) {
                throw IOException("DoH endpoint returned HTTP $status")
            }
            return connection.inputStream.use { it.readBytes() }
        } finally {
            connection.disconnect()
        }
    }

    private class CleanBrowsingPinnedSslSocketFactory(
        private val delegate: SSLSocketFactory
    ) : SSLSocketFactory() {

        override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites
        override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

        override fun createSocket(s: Socket?, host: String?, port: Int, autoClose: Boolean): Socket {
            val sslSocket = delegate.createSocket(s, host, port, autoClose) as SSLSocket
            configureSslSocket(sslSocket, host)
            return sslSocket
        }

        override fun createSocket(host: String?, port: Int): Socket {
            if (host.equals(DohResolver.CLEANBROWSING_DOH_HOST, ignoreCase = true)) {
                return connectPinnedSocket(host!!, port)
            }
            val sslSocket = delegate.createSocket(host, port) as SSLSocket
            configureSslSocket(sslSocket, host)
            return sslSocket
        }

        override fun createSocket(
            host: String?,
            port: Int,
            localHost: InetAddress?,
            localPort: Int
        ): Socket {
            val sslSocket = delegate.createSocket(host, port, localHost, localPort) as SSLSocket
            configureSslSocket(sslSocket, host)
            return sslSocket
        }

        override fun createSocket(host: InetAddress?, port: Int): Socket {
            val sslSocket = delegate.createSocket(host, port) as SSLSocket
            configureSslSocket(sslSocket, host?.hostName)
            return sslSocket
        }

        override fun createSocket(
            address: InetAddress?,
            port: Int,
            localAddress: InetAddress?,
            localPort: Int
        ): Socket {
            val sslSocket = delegate.createSocket(address, port, localAddress, localPort) as SSLSocket
            configureSslSocket(sslSocket, address?.hostName)
            return sslSocket
        }

        private fun connectPinnedSocket(host: String, port: Int): Socket {
            var lastError: IOException? = null
            for (ipBytes in DohResolver.CLEANBROWSING_BOOTSTRAP_IPS) {
                try {
                    val pinnedAddr = InetAddress.getByAddress(host, ipBytes)
                    val rawSocket = Socket()
                    rawSocket.connect(
                        InetSocketAddress(pinnedAddr, if (port > 0) port else 443),
                        DohResolver.DEFAULT_TIMEOUT_MS
                    )
                    val sslSocket = delegate.createSocket(
                        rawSocket,
                        host,
                        if (port > 0) port else 443,
                        true
                    ) as SSLSocket
                    configureSslSocket(sslSocket, host)
                    return sslSocket
                } catch (e: IOException) {
                    lastError = e
                }
            }
            throw lastError ?: IOException("Failed to connect to pinned DoH bootstrap IPs for $host")
        }

        private fun configureSslSocket(sslSocket: SSLSocket, host: String?) {
            val supported = sslSocket.supportedProtocols
            val tlsProtocols = supported.filter { it == "TLSv1.3" || it == "TLSv1.2" }.toTypedArray()
            if (tlsProtocols.isNotEmpty()) {
                sslSocket.enabledProtocols = tlsProtocols
            }
            if (!host.isNullOrBlank()) {
                runCatching {
                    val params = sslSocket.sslParameters
                    params.serverNames = listOf(SNIHostName(host))
                    sslSocket.sslParameters = params
                }
            }
        }
    }
}
