package dev.hm01.browser.filter

import java.net.IDN
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Locale

/**
 * Strict, WHATWG/RFC 3986-aligned URL parser and canonicalizer for `HM01`.
 *
 * Eliminates parser differentials between `java.net.URI` and Chromium's `GURL` / WHATWG parser:
 * - Rejects userinfo (`user:pass@host`) and backslashes (`\`) before query/fragment.
 * - Converts Unicode IDNs and fullwidth dot separators (`\u3002`, `\uFF0E`, `\uFF61`) to ASCII Punycode.
 * - Resolves dot segments (`/./`, `/../`), collapses duplicate slashes (`//`), strips path matrix
 *   parameters (`;param=1`), and decodes percent-encoded path characters before policy matching.
 * - Never falls back to naive string splitting when a URL is malformed.
 */
data class CanonicalUrl(
    val scheme: String,
    val host: String,
    val port: Int?,
    val rawPath: String,
    val normalizedPath: String,
    val rawQuery: String?,
    val normalizedPathWithQuery: String,
    val canonicalUrlString: String,
    val isIpLiteral: Boolean
) {
    companion object {
        private val SCHEME_REGEX = Regex("^[a-z][a-z0-9+.-]*$")
        private val UNICODE_DOTS_REGEX = Regex("[\\u3002\\uFF0E\\uFF61]")
        private val MULTI_SLASH_REGEX = Regex("/{2,}")
        private val DNS_LABEL_REGEX = Regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

        /**
         * Extracts and validates the lowercase URI scheme, or returns `""` if invalid/missing.
         */
        @JvmStatic
        fun extractScheme(rawUrl: String): String {
            val trimmed = rawUrl.trim()
            if (trimmed.isEmpty() || containsControlChars(trimmed)) return ""
            val colonIndex = trimmed.indexOf(':')
            if (colonIndex <= 0) return ""
            val scheme = trimmed.substring(0, colonIndex).lowercase(Locale.ROOT)
            return if (SCHEME_REGEX.matches(scheme)) scheme else ""
        }

        /**
         * Strictly parses and canonicalizes an `http://` or `https://` URL.
         * Returns `null` if the URL is malformed, ambiguous, or contains disallowed components (such as userinfo).
         */
        @JvmStatic
        fun parseHttpOrHttps(rawUrl: String): CanonicalUrl? {
            val trimmed = rawUrl.trim()
            if (trimmed.isEmpty() || containsControlChars(trimmed)) return null

            val scheme = extractScheme(trimmed)
            if (scheme != "https" && scheme != "http") return null

            val afterColon = trimmed.substring(scheme.length + 1)
            if (!afterColon.startsWith("//")) return null
            val afterSlashes = afterColon.substring(2)
            if (afterSlashes.isEmpty()) return null

            // Locate start of path, query, or fragment
            val pathStartIdx = indexOfFirstDelimiter(afterSlashes, charArrayOf('/', '?', '#'))
            val authority = if (pathStartIdx >= 0) {
                afterSlashes.substring(0, pathStartIdx)
            } else {
                afterSlashes
            }
            val remainder = if (pathStartIdx >= 0) {
                afterSlashes.substring(pathStartIdx)
            } else {
                ""
            }

            // Reject backslashes anywhere in authority or path (WHATWG treats '\' as '/', whereas RFC 3986 does not)
            val preQueryEnd = indexOfFirstDelimiter(afterSlashes, charArrayOf('?', '#'))
            val authorityAndPath = if (preQueryEnd >= 0) afterSlashes.substring(0, preQueryEnd) else afterSlashes
            if (authorityAndPath.contains('\\')) {
                return null
            }

            if (authority.isEmpty() || authority.any { it.isWhitespace() }) {
                return null
            }

            // Strictly reject userinfo (username:password@host) in raw or percent-encoded form
            if (authority.contains('@') || authority.lowercase(Locale.ROOT).contains("%40")) {
                return null
            }

            // Separate host and optional port
            val rawHostPart: String
            val portPart: String
            if (authority.startsWith("[")) {
                val closeBracket = authority.indexOf(']')
                if (closeBracket < 0) return null
                rawHostPart = authority.substring(0, closeBracket + 1)
                portPart = authority.substring(closeBracket + 1)
            } else {
                val firstColon = authority.indexOf(':')
                if (firstColon >= 0) {
                    // Multiple colons without brackets is an invalid unbracketed IPv6 literal
                    if (authority.indexOf(':', firstColon + 1) >= 0) return null
                    rawHostPart = authority.substring(0, firstColon)
                    portPart = authority.substring(firstColon)
                } else {
                    rawHostPart = authority
                    portPart = ""
                }
            }

            val parsedPort: Int? = if (portPart.isEmpty() || portPart == ":") {
                null
            } else if (portPart.startsWith(":")) {
                val portNum = portPart.substring(1).toIntOrNull() ?: return null
                if (portNum !in 1..65535) return null
                portNum
            } else {
                return null
            }

            // Reject percent-encoding in hostname
            if (rawHostPart.contains('%')) return null

            // Normalize Unicode fullwidth dots to ASCII '.'
            val dotNormalizedHost = rawHostPart
                .replace(UNICODE_DOTS_REGEX, ".")
                .trim()
                .trimEnd('.')
                .lowercase(Locale.ROOT)

            if (dotNormalizedHost.isEmpty() || dotNormalizedHost.startsWith(".") || dotNormalizedHost.contains("..")) {
                return null
            }

            // Check if raw/dot-normalized host is already an IP literal
            if (DomainExtractor.isIpLiteral(dotNormalizedHost)) {
                val (rawPath, normalizedPath, rawQuery, rawFragment) = parseAndNormalizeRemainder(remainder) ?: return null
                val pathWithQuery = if (!rawQuery.isNullOrEmpty()) "$normalizedPath?$rawQuery" else normalizedPath
                val canonicalUrl = buildCanonicalUrl(scheme, dotNormalizedHost, parsedPort, rawPath, rawQuery, rawFragment)
                return CanonicalUrl(
                    scheme = scheme,
                    host = dotNormalizedHost,
                    port = parsedPort,
                    rawPath = rawPath,
                    normalizedPath = normalizedPath,
                    rawQuery = rawQuery,
                    normalizedPathWithQuery = pathWithQuery,
                    canonicalUrlString = canonicalUrl,
                    isIpLiteral = true
                )
            }

            // Convert Internationalized Domain Names (IDN) to ASCII Punycode
            val asciiHost = try {
                IDN.toASCII(dotNormalizedHost, IDN.USE_STD3_ASCII_RULES)
                    .trim()
                    .trimEnd('.')
                    .lowercase(Locale.ROOT)
            } catch (e: Exception) {
                return null
            }

            if (asciiHost.isEmpty() || asciiHost.startsWith(".") || asciiHost.contains("..")) {
                return null
            }

            // Re-check IP literal after IDN conversion (e.g. fullwidth digits)
            val isIp = DomainExtractor.isIpLiteral(asciiHost)
            if (!isIp) {
                val labels = asciiHost.split('.')
                if (labels.any { label -> !DNS_LABEL_REGEX.matches(label) }) {
                    return null
                }
            }

            val (rawPath, normalizedPath, rawQuery, rawFragment) = parseAndNormalizeRemainder(remainder) ?: return null
            val pathWithQuery = if (!rawQuery.isNullOrEmpty()) "$normalizedPath?$rawQuery" else normalizedPath
            val canonicalUrl = buildCanonicalUrl(scheme, asciiHost, parsedPort, rawPath, rawQuery, rawFragment)

            return CanonicalUrl(
                scheme = scheme,
                host = asciiHost,
                port = parsedPort,
                rawPath = rawPath,
                normalizedPath = normalizedPath,
                rawQuery = rawQuery,
                normalizedPathWithQuery = pathWithQuery,
                canonicalUrlString = canonicalUrl,
                isIpLiteral = isIp
            )
        }

        /**
         * Normalizes a raw URL path for policy evaluation (percent-decoding, matrix-parameter stripping,
         * duplicate-slash collapsing, and RFC 3986 dot-segment resolution).
         */
        @JvmStatic
        fun normalizePathForPolicy(rawPathInput: String?): String? {
            val initial = if (rawPathInput.isNullOrEmpty()) "/" else rawPathInput
            // Reject null-byte injection in path
            if (initial.lowercase(Locale.ROOT).contains("%00")) return null

            // Decode up to 2 passes so double-encoded characters (%2572 -> %72 -> r) cannot evade path checks
            var decoded = initial
            repeat(2) {
                val next = percentDecodePathSafely(decoded) ?: return null
                decoded = next
            }

            if (containsControlChars(decoded)) return null

            // Replace backslashes, strip matrix params (;param=val) per segment, and resolve '.' / '..'
            val cleanSlashes = decoded.replace('\\', '/')
            return resolveDotSegmentsAndCollapseSlashes(cleanSlashes, stripMatrixParams = true)
        }

        private data class ParsedRemainder(
            val canonicalRawPath: String,
            val normalizedPath: String,
            val rawQuery: String?,
            val rawFragment: String?
        )

        private fun parseAndNormalizeRemainder(remainder: String): ParsedRemainder? {
            val hashIdx = remainder.indexOf('#')
            val beforeFragment = if (hashIdx >= 0) remainder.substring(0, hashIdx) else remainder
            val rawFragment = if (hashIdx >= 0) remainder.substring(hashIdx + 1) else null

            val queryIdx = beforeFragment.indexOf('?')
            val rawPathPart = if (queryIdx >= 0) beforeFragment.substring(0, queryIdx) else beforeFragment
            val rawQuery = if (queryIdx >= 0) beforeFragment.substring(queryIdx + 1) else null

            val effectiveRawPath = if (rawPathPart.isEmpty()) "/" else rawPathPart
            if (!effectiveRawPath.startsWith("/")) return null

            val normalizedPath = normalizePathForPolicy(effectiveRawPath) ?: return null
            val canonicalRawPath = resolveDotSegmentsAndCollapseSlashes(effectiveRawPath, stripMatrixParams = false)

            return ParsedRemainder(
                canonicalRawPath = canonicalRawPath,
                normalizedPath = normalizedPath,
                rawQuery = rawQuery,
                rawFragment = rawFragment
            )
        }

        private fun resolveDotSegmentsAndCollapseSlashes(path: String, stripMatrixParams: Boolean): String {
            val collapsed = path.replace(MULTI_SLASH_REGEX, "/")
            val endsWithSlash = collapsed.endsWith("/")
            val rawSegments = collapsed.split('/')
            val stack = ArrayDeque<String>()
            var endedWithDotSegment = false

            for (rawSeg in rawSegments) {
                if (rawSeg.isEmpty()) continue
                val seg = if (stripMatrixParams) rawSeg.substringBefore(';') else rawSeg
                if (seg.isEmpty() || seg == ".") {
                    endedWithDotSegment = true
                    continue
                }
                if (seg == "..") {
                    if (stack.isNotEmpty()) {
                        stack.removeLast()
                    }
                    endedWithDotSegment = true
                    continue
                }
                endedWithDotSegment = false
                stack.addLast(seg)
            }

            if (stack.isEmpty()) return "/"
            val joined = "/" + stack.joinToString("/")
            return if ((endsWithSlash || endedWithDotSegment) && !joined.endsWith("/")) {
                "$joined/"
            } else {
                joined
            }
        }

        private fun percentDecodePathSafely(input: String): String? {
            if (!input.contains('%')) return input
            val sb = StringBuilder(input.length)
            var i = 0
            while (i < input.length) {
                val ch = input[i]
                if (ch == '%') {
                    if (i + 2 >= input.length) return null
                    val hex = input.substring(i + 1, i + 3)
                    val byteVal = hex.toIntOrNull(16) ?: return null
                    if (byteVal == 0) return null
                    // Collect contiguous percent-encoded UTF-8 bytes
                    val bytes = ByteArrayOutputStreamLite()
                    bytes.write(byteVal)
                    i += 3
                    while (i + 2 < input.length && input[i] == '%') {
                        val nextHex = input.substring(i + 1, i + 3)
                        val nextByte = nextHex.toIntOrNull(16) ?: return null
                        if (nextByte == 0) return null
                        bytes.write(nextByte)
                        i += 3
                    }
                    sb.append(String(bytes.toByteArray(), StandardCharsets.UTF_8))
                } else {
                    sb.append(ch)
                    i++
                }
            }
            return sb.toString()
        }

        private class ByteArrayOutputStreamLite {
            private var buf = ByteArray(16)
            private var count = 0
            fun write(b: Int) {
                if (count == buf.size) {
                    buf = buf.copyOf(buf.size * 2)
                }
                buf[count++] = b.toByte()
            }
            fun toByteArray(): ByteArray = buf.copyOf(count)
        }

        private fun buildCanonicalUrl(
            scheme: String,
            host: String,
            port: Int?,
            path: String,
            query: String?,
            fragment: String?
        ): String {
            val sb = StringBuilder()
            sb.append(scheme).append("://").append(host)
            if (port != null && !isDefaultPort(scheme, port)) {
                sb.append(':').append(port)
            }
            sb.append(if (path.startsWith("/")) path else "/$path")
            if (query != null) {
                sb.append('?').append(query)
            }
            if (fragment != null) {
                sb.append('#').append(fragment)
            }
            return sb.toString()
        }

        private fun isDefaultPort(scheme: String, port: Int): Boolean {
            return (scheme == "https" && port == 443) || (scheme == "http" && port == 80)
        }

        private fun indexOfFirstDelimiter(input: String, delimiters: CharArray): Int {
            for (i in input.indices) {
                if (input[i] in delimiters) return i
            }
            return -1
        }

        private fun containsControlChars(s: String): Boolean {
            for (ch in s) {
                if (ch.code <= 0x1F || ch.code == 0x7F) return true
            }
            return false
        }
    }
}
