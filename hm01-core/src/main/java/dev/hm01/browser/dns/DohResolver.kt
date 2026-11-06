package dev.hm01.browser.dns

import dev.hm01.browser.config.BrowserPolicyConfig
import dev.hm01.browser.config.DefaultBaselineLists
import dev.hm01.browser.config.DnsMode
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.IDN
import java.net.URL
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.Locale
import javax.net.ssl.HttpsURLConnection

/**
 * Pluggable transport for executing RFC 8484 DNS-over-HTTPS queries.
 */
fun interface DohTransport {
    @Throws(IOException::class)
    fun query(endpointUrl: String, dnsQueryPacket: ByteArray, timeoutMs: Int): ByteArray
}

/**
 * Standard RFC 8484 DNS-over-HTTPS (DoH) client (`application/dns-message`).
 *
 * Works with any RFC 8484 DoH provider selected by the user or configured by the developer
 * (e.g., AdGuard Family, CleanBrowsing Adult/Family, Cloudflare Family, Mullvad Family,
 * OpenDNS FamilyShield, NextDNS, or a custom DoH server URL).
 */
open class DohResolver(
    private val configProvider: () -> BrowserPolicyConfig = { BrowserPolicyConfig() },
    val cache: DohDecisionCache = SharedCacheHolder.INSTANCE,
    private val transport: DohTransport = StandardRfc8484DohTransport(),
    private val timeoutMs: Int = DEFAULT_TIMEOUT_MS
) {

    object SharedCacheHolder {
        val INSTANCE = DohDecisionCache()
    }

    /**
     * Evaluates [rawHost] against the active DoH endpoint, using the shared LRU+TTL cache
     * (scoped by `endpointUrl|host`) and coalescing concurrent in-flight requests.
     */
    open fun resolve(rawHost: String): DohVerdict {
        val host = normalizeDnsHostname(rawHost) ?: return DohVerdict.BLOCK

        val config = configProvider()
        if (config.dnsMode == DnsMode.DISABLED) {
            return DohVerdict.ALLOW
        }

        val endpointUrl = config.resolveActiveDohEndpointUrl()
        if (endpointUrl.isBlank()) {
            // If USER_DEFINED mode has no selected DNS server yet, fail closed without caching
            return if (config.dnsMode == DnsMode.USER_DEFINED) {
                DohVerdict.BLOCK
            } else {
                DohVerdict.ALLOW
            }
        }

        if (!BrowserPolicyConfig.isValidDohEndpointUrl(endpointUrl)) {
            return if (config.failClosedOnDnsError) DohVerdict.BLOCK else DohVerdict.ALLOW
        }

        val cacheKey = "${endpointUrl.trim().lowercase(Locale.ROOT)}|$host"
        cache.get(cacheKey)?.let { return it }

        var shouldCache = true
        var resolvedTtlMs = cache.defaultTtlMs

        return try {
            cache.getOrCompute(
                hostname = cacheKey,
                timeoutMs = (timeoutMs * 2L).coerceAtLeast(3_000L),
                cacheResult = { shouldCache },
                ttlMsProvider = { resolvedTtlMs }
            ) {
                try {
                    val queryBytes = buildDnsAQueryPacket(host)
                    val responseBytes = transport.query(endpointUrl, queryBytes, timeoutMs)
                    val parsed = parseDnsResponseVerdictWithTtl(responseBytes, cache.defaultTtlMs)
                    if (parsed.ttlMs <= 0L) {
                        shouldCache = false
                    } else {
                        resolvedTtlMs = parsed.ttlMs
                    }
                    parsed.verdict
                } catch (e: Exception) {
                    shouldCache = false
                    fallbackVerdictOnError(host, config)
                }
            }
        } catch (e: Exception) {
            fallbackVerdictOnError(host, config)
        }
    }

    private fun fallbackVerdictOnError(host: String, config: BrowserPolicyConfig): DohVerdict {
        return if (DefaultBaselineLists.isDedicatedTrustedIdpOrPaymentOrCaptchaHost(host, config)) {
            // Fail open for Trusted IdP hosts so sign-ins don't break on transient DNS hiccups
            DohVerdict.ALLOW
        } else if (config.failClosedOnDnsError) {
            DohVerdict.BLOCK
        } else {
            DohVerdict.ALLOW
        }
    }

    data class ParsedDnsVerdict(
        val verdict: DohVerdict,
        val ttlMs: Long
    )

    companion object {
        const val DEFAULT_TIMEOUT_MS: Int = 2_000
        const val MAX_DNS_MESSAGE_BYTES: Int = 65_535

        private const val DNS_TYPE_A = 1
        private const val DNS_TYPE_CNAME = 5
        private const val DNS_TYPE_SOA = 6
        private const val DNS_TYPE_AAAA = 28
        private const val DNS_TYPE_OPT = 41
        private const val DNS_CLASS_IN = 1
        private const val EDNS_OPT_PADDING = 12

        private const val RCODE_NOERROR = 0
        private const val RCODE_NXDOMAIN = 3

        private val UNICODE_DOTS_REGEX = Regex("[\\u3002\\uFF0E\\uFF61]")
        private val DNS_LABEL_REGEX = Regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

        @JvmStatic
        internal fun normalizeDnsHostname(rawHost: String): String? {
            val dotNormalized = rawHost
                .replace(UNICODE_DOTS_REGEX, ".")
                .trim()
                .trimEnd('.')
                .lowercase(Locale.ROOT)
            if (dotNormalized.isEmpty() || dotNormalized.startsWith(".") || dotNormalized.contains("..")) {
                return null
            }
            val ascii = try {
                IDN.toASCII(dotNormalized, IDN.USE_STD3_ASCII_RULES)
                    .trim()
                    .trimEnd('.')
                    .lowercase(Locale.ROOT)
            } catch (e: Exception) {
                return null
            }
            if (ascii.isEmpty() || ascii.length > 253) return null
            val labels = ascii.split('.')
            if (labels.any { !DNS_LABEL_REGEX.matches(it) }) return null
            return ascii
        }

        /**
         * Builds an RFC 1035 binary DNS query packet for `QTYPE = A (1)`, `QCLASS = IN (1)`.
         */
        @JvmStatic
        fun buildDnsAQueryPacket(hostname: String): ByteArray {
            val cleanHost = normalizeDnsHostname(hostname)
                ?: throw IllegalArgumentException("Invalid DNS hostname: $hostname")
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
         * Appends an RFC 7830 / RFC 8467 EDNS(0) Padding `OPT` pseudo-record (Type 41, Option 12)
         * so the total DNS wire message size is padded to a multiple of [blockSize] (128 bytes by default),
         * preventing TLS record-size traffic analysis.
         */
        @JvmStatic
        @JvmOverloads
        fun padDnsQueryPacketWithEdns0(queryPacket: ByteArray, blockSize: Int = 128): ByteArray {
            if (queryPacket.size < 12 || blockSize <= 0) return queryPacket
            val arCount = readUInt16(queryPacket, 10)
            if (arCount != 0) return queryPacket

            // Base OPT record without padding option payload is 11 bytes (1 root + 2 type + 2 udpSize + 4 ttl + 2 rdlen)
            // Plus 4 bytes for EDNS Option header (2 optionCode + 2 optionLength) = 15 bytes minimum overhead
            val baseWithOptHeaderLen = queryPacket.size + 15
            val remainder = baseWithOptHeaderLen % blockSize
            val padBytesLen = if (remainder == 0) 0 else (blockSize - remainder)
            val rdLength = 4 + padBytesLen

            val padded = ByteArrayOutputStream(baseWithOptHeaderLen + padBytesLen)
            val out = DataOutputStream(padded)

            // Copy first 10 bytes of header, then write ARCOUNT = 1
            out.write(queryPacket, 0, 10)
            out.writeShort(1) // ARCOUNT = 1
            // Copy remainder of original packet
            out.write(queryPacket, 12, queryPacket.size - 12)

            // Write EDNS(0) OPT RR (RFC 6891 + RFC 7830)
            out.writeByte(0)                   // NAME = root (0)
            out.writeShort(DNS_TYPE_OPT)       // TYPE = OPT (41)
            out.writeShort(4096)               // CLASS = UDP payload size (4096)
            out.writeInt(0)                    // TTL = Extended RCODE & Flags (0)
            out.writeShort(rdLength)           // RDLENGTH
            out.writeShort(EDNS_OPT_PADDING)   // OPTION-CODE = 12 (Padding)
            out.writeShort(padBytesLen)        // OPTION-LENGTH
            if (padBytesLen > 0) {
                out.write(ByteArray(padBytesLen)) // Zero-filled padding per RFC 7830 Section 3
            }
            out.flush()
            return padded.toByteArray()
        }

        /**
         * Encodes a binary DNS query packet using RFC 8484 Base64url (unpadded).
         */
        @JvmStatic
        fun encodeBase64UrlUnpadded(packet: ByteArray): String {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(packet)
        }

        /**
         * Parses an RFC 1035 binary DNS response packet and evaluates the filter verdict across
         * standard DoH providers (AdGuard, CleanBrowsing, Cloudflare, Mullvad, OpenDNS, NextDNS, etc.):
         * - `BLOCK`: `RCODE != 0` (`NXDOMAIN` / `REFUSED`), empty answer with RPZ/block SOA,
         *   CNAME-only response with zero resolved public IPs, or any `A`/`AAAA` record pointing to a
         *   sinkhole, private (RFC 1918), loopback, link-local, CGNAT, or reserved IP.
         * - `ALLOW`: `RCODE == 0` (`NOERROR`) with at least one valid global unicast `A` or `AAAA` record.
         */
        @JvmStatic
        fun parseDnsResponseVerdict(packet: ByteArray): DohVerdict {
            return parseDnsResponseVerdictWithTtl(packet, DohDecisionCache.DEFAULT_TTL_MS).verdict
        }

        @JvmStatic
        fun parseDnsResponseVerdictWithTtl(
            packet: ByteArray,
            maxTtlMs: Long = DohDecisionCache.DEFAULT_TTL_MS
        ): ParsedDnsVerdict {
            if (packet.size < 12 || packet.size > MAX_DNS_MESSAGE_BYTES) {
                return ParsedDnsVerdict(DohVerdict.BLOCK, maxTtlMs)
            }

            val flags = readUInt16(packet, 2)
            // Must be a DNS response (QR == 1) with no truncation (TC == 0)
            if ((flags and 0x8000) == 0) {
                return ParsedDnsVerdict(DohVerdict.BLOCK, maxTtlMs)
            }
            val rcode = flags and 0x0F
            if (rcode == RCODE_NXDOMAIN || rcode != RCODE_NOERROR) {
                return ParsedDnsVerdict(DohVerdict.BLOCK, maxTtlMs)
            }

            val qdCount = readUInt16(packet, 4)
            val anCount = readUInt16(packet, 6)
            val nsCount = readUInt16(packet, 8)

            var offset = 12
            // Skip Question section
            for (i in 0 until qdCount) {
                offset = skipDnsName(packet, offset)
                if (offset < 0 || offset + 4 > packet.size) {
                    return ParsedDnsVerdict(DohVerdict.BLOCK, maxTtlMs)
                }
                offset += 4 // QTYPE + QCLASS
            }

            var validPublicIpRecords = 0
            var minAnswerTtlSeconds: Long? = null

            // Parse Answer RRs
            for (i in 0 until anCount) {
                offset = skipDnsName(packet, offset)
                if (offset < 0 || offset + 10 > packet.size) {
                    return ParsedDnsVerdict(DohVerdict.BLOCK, maxTtlMs)
                }
                val rrType = readUInt16(packet, offset)
                val rrTtlSeconds = readUInt32(packet, offset + 4)
                val rdLength = readUInt16(packet, offset + 8)
                offset += 10
                if (offset + rdLength > packet.size) {
                    return ParsedDnsVerdict(DohVerdict.BLOCK, maxTtlMs)
                }

                if (rrType == DNS_TYPE_A && rdLength == 4) {
                    val b0 = packet[offset].toInt() and 0xFF
                    val b1 = packet[offset + 1].toInt() and 0xFF
                    val b2 = packet[offset + 2].toInt() and 0xFF
                    val b3 = packet[offset + 3].toInt() and 0xFF

                    if (isSinkholeOrBlockIp(b0, b1, b2, b3)) {
                        return ParsedDnsVerdict(DohVerdict.BLOCK, maxTtlMs)
                    }
                    validPublicIpRecords++
                    minAnswerTtlSeconds = if (minAnswerTtlSeconds == null) {
                        rrTtlSeconds
                    } else {
                        minOf(minAnswerTtlSeconds, rrTtlSeconds)
                    }
                } else if (rrType == DNS_TYPE_AAAA && rdLength == 16) {
                    if (isSinkholeOrBlockIpv6(packet, offset)) {
                        return ParsedDnsVerdict(DohVerdict.BLOCK, maxTtlMs)
                    }
                    validPublicIpRecords++
                    minAnswerTtlSeconds = if (minAnswerTtlSeconds == null) {
                        rrTtlSeconds
                    } else {
                        minOf(minAnswerTtlSeconds, rrTtlSeconds)
                    }
                } else if (rrType == DNS_TYPE_CNAME) {
                    val cnameTarget = decodeDnsName(packet, offset).lowercase(Locale.ROOT)
                    if (cnameTarget.contains("cleanbrowsing.rpz") ||
                        cnameTarget.contains("block.cleanbrowsing") ||
                        cnameTarget.contains("block.opendns") ||
                        cnameTarget.contains("blocked.")
                    ) {
                        return ParsedDnsVerdict(DohVerdict.BLOCK, maxTtlMs)
                    }
                }

                offset += rdLength
            }

            // Parse Authority RRs (check for RPZ sinkhole SOA)
            for (i in 0 until nsCount) {
                val ownerName = decodeDnsName(packet, offset).lowercase(Locale.ROOT)
                offset = skipDnsName(packet, offset)
                if (offset < 0 || offset + 10 > packet.size) break
                val rrType = readUInt16(packet, offset)
                val rdLength = readUInt16(packet, offset + 8)
                offset += 10
                if (offset + rdLength > packet.size) break

                if (ownerName.contains("cleanbrowsing.rpz") || ownerName.contains(".rpz")) {
                    return ParsedDnsVerdict(DohVerdict.BLOCK, maxTtlMs)
                }
                if (rrType == DNS_TYPE_SOA) {
                    val mname = decodeDnsName(packet, offset).lowercase(Locale.ROOT)
                    val afterMname = skipDnsName(packet, offset)
                    val rname = if (afterMname in 0 until (offset + rdLength)) {
                        decodeDnsName(packet, afterMname).lowercase(Locale.ROOT)
                    } else {
                        ""
                    }
                    if (mname.contains("cleanbrowsing.rpz") ||
                        rname.contains("cleanbrowsing.rpz") ||
                        mname.contains(".rpz.")
                    ) {
                        return ParsedDnsVerdict(DohVerdict.BLOCK, maxTtlMs)
                    }
                }
                offset += rdLength
            }

            // Require at least one valid global unicast IP (bare CNAMEs without resolved A/AAAA are rejected)
            if (validPublicIpRecords <= 0) {
                return ParsedDnsVerdict(DohVerdict.BLOCK, maxTtlMs)
            }

            val computedTtlMs = if (minAnswerTtlSeconds != null) {
                (minAnswerTtlSeconds * 1000L).coerceAtMost(maxTtlMs)
            } else {
                maxTtlMs
            }

            return ParsedDnsVerdict(DohVerdict.ALLOW, computedTtlMs)
        }

        /**
         * Checks whether an IPv4 address (`b0.b1.b2.b3`) is a DNS filter sinkhole IP OR a non-global
         * unicast / private / reserved address:
         * - `0.0.0.0/8` (Cloudflare/Mullvad/AdGuard/NextDNS `0.0.0.0` sinkhole & current-network block)
         * - `10.0.0.0/8` (RFC 1918 private network)
         * - `100.64.0.0/10` (RFC 6598 Shared Address Space / CGNAT)
         * - `127.0.0.0/8` (Loopback sinkhole)
         * - `169.254.0.0/16` (Link-local / cloud metadata)
         * - `172.16.0.0/12` (RFC 1918 private network)
         * - `192.0.0.0/24` & `192.0.2.0/24` (IETF Protocol Assignments & TEST-NET-1)
         * - `192.168.0.0/16` (RFC 1918 private network)
         * - `198.18.0.0/15` & `198.51.100.0/24` (Benchmarking & TEST-NET-2)
         * - `203.0.113.0/24` (TEST-NET-3)
         * - `224.0.0.0/4` & `240.0.0.0/4` (Multicast & Reserved/Broadcast)
         * - `185.228.168.0/24` & `185.228.169.0/24` (CleanBrowsing Family & Adult)
         * - `94.140.14.33`..`94.140.14.36` (AdGuard Family block page IPs)
         * - `146.112.61.0/24` (OpenDNS FamilyShield block page IPs)
         */
        @JvmStatic
        fun isSinkholeOrBlockIp(b0: Int, b1: Int, b2: Int, b3: Int): Boolean {
            // 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8
            if (b0 == 0 || b0 == 10 || b0 == 127) return true
            // 100.64.0.0/10 (CGNAT)
            if (b0 == 100 && (b1 and 0xC0) == 64) return true
            // 169.254.0.0/16 (Link-local / metadata)
            if (b0 == 169 && b1 == 254) return true
            // 172.16.0.0/12 (RFC 1918)
            if (b0 == 172 && b1 in 16..31) return true
            // 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16
            if (b0 == 192 && b1 == 0 && (b2 == 0 || b2 == 2)) return true
            if (b0 == 192 && b1 == 168) return true
            // 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24
            if (b0 == 198 && (b1 == 18 || b1 == 19)) return true
            if (b0 == 198 && b1 == 51 && b2 == 100) return true
            if (b0 == 203 && b1 == 0 && b2 == 113) return true
            // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved / Broadcast)
            if (b0 >= 224) return true

            // Known DoH family filter sinkhole ranges
            if (b0 == 185 && b1 == 228 && (b2 == 168 || b2 == 169)) return true
            if (b0 == 94 && b1 == 140 && b2 == 14 && b3 in 33..36) return true
            if (b0 == 146 && b1 == 112 && b2 == 61) return true
            return false
        }

        /**
         * Checks whether a 16-byte IPv6 address at [offset] in [packet] is a sinkhole or non-global
         * unicast address (`::`, `::1`, IPv4-mapped `::ffff:0:0/96`, `fc00::/7`, `fe80::/10`, `ff00::/8`,
         * `2001:db8::/32`, or known CleanBrowsing/AdGuard IPv6 block ranges).
         */
        @JvmStatic
        fun isSinkholeOrBlockIpv6(packet: ByteArray, offset: Int): Boolean {
            if (offset < 0 || offset + 16 > packet.size) return true
            val b0 = packet[offset].toInt() and 0xFF
            val b1 = packet[offset + 1].toInt() and 0xFF

            // Check all-zeros (::) or loopback (::1)
            var allZeroPrefix10 = true
            for (i in 0 until 10) {
                if ((packet[offset + i].toInt() and 0xFF) != 0) {
                    allZeroPrefix10 = false
                    break
                }
            }
            if (allZeroPrefix10) {
                val b10 = packet[offset + 10].toInt() and 0xFF
                val b11 = packet[offset + 11].toInt() and 0xFF
                val b12 = packet[offset + 12].toInt() and 0xFF
                val b13 = packet[offset + 13].toInt() and 0xFF
                val b14 = packet[offset + 14].toInt() and 0xFF
                val b15 = packet[offset + 15].toInt() and 0xFF
                // Unspecified (::) or Loopback (::1) or IPv4-compatible
                if (b10 == 0 && b11 == 0 && b12 == 0 && b13 == 0 && b14 == 0 && (b15 == 0 || b15 == 1)) {
                    return true
                }
                // IPv4-mapped IPv6 (::ffff:a.b.c.d)
                if (b10 == 0xFF && b11 == 0xFF) {
                    return isSinkholeOrBlockIp(b12, b13, b14, b15)
                }
            }

            // Unique Local (fc00::/7 -> 0xFC or 0xFD)
            if ((b0 and 0xFE) == 0xFC) return true
            // Link-Local (fe80::/10)
            if (b0 == 0xFE && (b1 and 0xC0) == 0x80) return true
            // Multicast (ff00::/8)
            if (b0 == 0xFF) return true
            // Documentation (2001:db8::/32)
            val b2 = packet[offset + 2].toInt() and 0xFF
            val b3 = packet[offset + 3].toInt() and 0xFF
            if (b0 == 0x20 && b1 == 0x01 && b2 == 0x0D && b3 == 0xB8) return true

            // CleanBrowsing IPv6 sinkhole prefix (2a0d:2a00:1::/48, 2a0d:2a00:2::/48)
            val b4 = packet[offset + 4].toInt() and 0xFF
            val b5 = packet[offset + 5].toInt() and 0xFF
            if (b0 == 0x2A && b1 == 0x0D && b2 == 0x2A && b3 == 0x00 && b4 == 0x00 && (b5 == 0x01 || b5 == 0x02)) {
                return true
            }

            return false
        }

        private fun readUInt16(bytes: ByteArray, offset: Int): Int {
            return ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
        }

        private fun readUInt32(bytes: ByteArray, offset: Int): Long {
            val b0 = (bytes[offset].toLong() and 0xFF) shl 24
            val b1 = (bytes[offset + 1].toLong() and 0xFF) shl 16
            val b2 = (bytes[offset + 2].toLong() and 0xFF) shl 8
            val b3 = bytes[offset + 3].toLong() and 0xFF
            return b0 or b1 or b2 or b3
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
 * Standard RFC 8484 HTTPS transport (`POST` with `Content-Type: application/dns-message`,
 * RFC 7830 / RFC 8467 EDNS(0) 128-byte block padding, and a strict 65,535-byte response limit).
 */
class StandardRfc8484DohTransport : DohTransport {

    override fun query(endpointUrl: String, dnsQueryPacket: ByteArray, timeoutMs: Int): ByteArray {
        require(BrowserPolicyConfig.isValidDohEndpointUrl(endpointUrl)) {
            "DoH endpoint must be a valid https:// hostname URL"
        }
        val paddedQuery = DohResolver.padDnsQueryPacketWithEdns0(dnsQueryPacket)
        val fullUrl = URL(endpointUrl.trim())

        val connection = (fullUrl.openConnection() as? HttpsURLConnection)
            ?: throw IOException("DoH endpoint did not open an HttpsURLConnection")

        connection.apply {
            requestMethod = "POST"
            doOutput = true
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            useCaches = false
            instanceFollowRedirects = false
            setRequestProperty("Content-Type", "application/dns-message")
            setRequestProperty("Accept", "application/dns-message")
            setFixedLengthStreamingMode(paddedQuery.size)
        }

        try {
            connection.outputStream.use { out ->
                out.write(paddedQuery)
                out.flush()
            }

            val status = connection.responseCode
            if (status != 200) {
                throw IOException("DoH endpoint returned HTTP $status")
            }

            val contentType = connection.contentType?.lowercase(Locale.ROOT).orEmpty()
            if (contentType.isNotEmpty() && !contentType.startsWith("application/dns-message")) {
                throw IOException("Unexpected DoH Content-Type: $contentType")
            }

            return readBoundedBytes(connection.inputStream, DohResolver.MAX_DNS_MESSAGE_BYTES)
        } finally {
            connection.disconnect()
        }
    }

    private fun readBoundedBytes(input: InputStream, maxBytes: Int): ByteArray {
        input.use { stream ->
            val buffer = ByteArrayOutputStream(512)
            val chunk = ByteArray(4096)
            var total = 0
            while (true) {
                val read = stream.read(chunk)
                if (read < 0) break
                total += read
                if (total > maxBytes) {
                    throw IOException("DoH response exceeded maximum size of $maxBytes bytes")
                }
                buffer.write(chunk, 0, read)
            }
            return buffer.toByteArray()
        }
    }
}
