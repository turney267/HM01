package dev.hm01.browser.filter

import java.util.Locale

/**
 * Extracts the registrable domain (`eTLD+1`) or isolated multi-tenant cloud hostname,
 * and detects raw IP-literal hosts (IPv4, IPv6, octal, hex, integer/dword).
 */
object DomainExtractor {

    /**
     * Multi-tenant cloud hosting suffixes where each tenant subdomain must be isolated as a
     * distinct external domain (`tenant-a.vercel.app != tenant-b.vercel.app`).
     */
    val MULTI_TENANT_CLOUD_SUFFIXES: Set<String> = setOf(
        "a.run.app",
        "run.app",
        "web.app",
        "firebaseapp.com",
        "github.io",
        "gitlab.io",
        "vercel.app",
        "netlify.app",
        "pages.dev",
        "workers.dev",
        "onrender.com",
        "fly.dev",
        "herokuapp.com",
        "supabase.co",
        "substack.com"
    )

    /**
     * Known multi-part country-code second-level domains (ccSLDs).
     */
    val MULTI_PART_CC_TLDS: Set<String> = setOf(
        // Australia
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
        // United Kingdom
        "co.uk", "org.uk", "me.uk", "gov.uk", "ac.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
        // New Zealand
        "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz", "school.nz", "geek.nz", "kiwi.nz",
        // Japan
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ed.jp", "gr.jp", "lg.jp",
        // Singapore
        "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg", "per.sg",
        // Hong Kong & Taiwan
        "com.hk", "edu.hk", "gov.hk", "net.hk", "org.hk",
        "com.tw", "edu.tw", "gov.tw", "net.tw", "org.tw",
        // South Korea
        "co.kr", "ne.kr", "or.kr", "re.kr", "pe.kr", "go.kr", "ac.kr",
        // India
        "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "ac.in", "edu.in", "res.in", "gov.in", "mil.in",
        // South Africa
        "co.za", "org.za", "net.za", "gov.za", "edu.za", "ac.za",
        // Americas
        "com.br", "net.br", "org.br", "gov.br", "edu.br",
        "com.mx", "org.mx", "net.mx", "gob.mx", "edu.mx",
        "com.ar", "org.ar", "net.ar", "gob.ar", "edu.ar",
        "com.co", "org.co", "net.co", "gov.co", "edu.co",
        // Southeast Asia & Middle East
        "com.my", "net.my", "org.my", "gov.my", "edu.my",
        "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
        "co.id", "or.id", "ac.id", "go.id", "web.id",
        "co.th", "or.th", "ac.th", "go.th", "in.th",
        "co.il", "org.il", "net.il", "ac.il", "gov.il",
        "com.tr", "org.tr", "net.tr", "gov.tr", "edu.tr"
    )

    private val IPV4_STANDARD_REGEX = Regex("^\\d{1,3}(?:\\.\\d{1,3}){3}$")
    private val HEX_LABEL_REGEX = Regex("^0x[0-9a-f]+$", RegexOption.IGNORE_CASE)
    private val OCTAL_OR_NUMERIC_LABEL_REGEX = Regex("^[0-9]+$")

    /**
     * Returns the effective registrable domain (`eTLD+1`) or isolated multi-tenant subdomain for [rawHost].
     *
     * Examples:
     * - `www.kmart.com.au` -> `kmart.com.au`
     * - `shop.ikea.com` -> `ikea.com`
     * - `my-school-event.vercel.app` -> `my-school-event.vercel.app`
     * - `api.my-school-event.vercel.app` -> `my-school-event.vercel.app`
     * - `other-site.vercel.app` -> `other-site.vercel.app`
     */
    @JvmStatic
    fun extractEffectiveDomain(rawHost: String): String {
        val host = normalizeHost(rawHost)
        if (host.isEmpty()) return ""

        // 1. Check multi-tenant cloud suffixes (longest suffix match first, e.g. a.run.app before run.app)
        val matchedTenantSuffix = MULTI_TENANT_CLOUD_SUFFIXES
            .sortedByDescending { it.length }
            .firstOrNull { suffix ->
                host == suffix || host.endsWith(".$suffix")
            }

        if (matchedTenantSuffix != null) {
            if (host == matchedTenantSuffix) return host
            val prefix = host.removeSuffix(".$matchedTenantSuffix")
            val tenantLabel = prefix.substringAfterLast('.')
            return "$tenantLabel.$matchedTenantSuffix"
        }

        val labels = host.split('.')
        if (labels.size <= 2) return host

        // 2. Check multi-part ccTLDs (e.g. com.au, co.uk, govt.nz)
        val lastTwo = "${labels[labels.size - 2]}.${labels[labels.size - 1]}"
        if (lastTwo in MULTI_PART_CC_TLDS) {
            return if (labels.size >= 3) {
                "${labels[labels.size - 3]}.$lastTwo"
            } else {
                host
            }
        }

        // 3. Standard eTLD+1 (last 2 labels)
        return lastTwo
    }

    /**
     * Returns `true` if [hostA] and [hostB] resolve to the same registrable or multi-tenant domain.
     */
    @JvmStatic
    fun isSameEffectiveDomain(hostA: String, hostB: String): Boolean {
        val domainA = extractEffectiveDomain(hostA)
        val domainB = extractEffectiveDomain(hostB)
        return domainA.isNotEmpty() && domainA == domainB
    }

    /**
     * Detects whether [rawHost] is a raw IP literal:
     * - Standard IPv4 (`1.2.3.4`)
     * - Bracketed or raw IPv6 (`[::1]`, `[2001:db8::1]`, `fe80::1`)
     * - Dotted or single-integer hex IP (`0x7f.0.0.1`, `0x7f000001`)
     * - Dotted octal IP (`0177.0.0.1`)
     * - Raw integer/dword IP (`2130706433`)
     */
    @JvmStatic
    fun isIpLiteral(rawHost: String): Boolean {
        val trimmed = rawHost.trim().trimEnd('.')
        if (trimmed.isEmpty()) return false

        // Bracketed IPv6 or colon-separated IPv6
        if (trimmed.startsWith("[") || trimmed.endsWith("]") || trimmed.contains(':')) {
            return true
        }

        // Standard IPv4
        if (IPV4_STANDARD_REGEX.matches(trimmed)) {
            return true
        }

        // Single-label numeric or hex IP (e.g. 2130706433 or 0x7f000001)
        val labels = trimmed.split('.')
        if (labels.all { label ->
                OCTAL_OR_NUMERIC_LABEL_REGEX.matches(label) || HEX_LABEL_REGEX.matches(label)
            }
        ) {
            return true
        }

        return false
    }

    internal fun normalizeHost(rawHost: String): String {
        return rawHost.trim().trimEnd('.').lowercase(Locale.ROOT)
    }
}
