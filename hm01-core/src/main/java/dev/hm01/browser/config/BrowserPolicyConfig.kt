package dev.hm01.browser.config

/**
 * Supported DNS-over-HTTPS (DoH) filter presets (RFC 8484).
 *
 * Includes both `CLEANBROWSING_*` and `*_FILTER` enum constants for seamless compatibility
 * with programmatic callers and Android Managed Configuration string keys.
 */
enum class DohPreset(val defaultEndpointUrl: String) {
    CLEANBROWSING_FAMILY("https://doh.cleanbrowsing.org/doh/family-filter/"),
    CLEANBROWSING_ADULT("https://doh.cleanbrowsing.org/doh/adult-filter/"),
    CLEANBROWSING_SECURITY("https://doh.cleanbrowsing.org/doh/security-filter/"),
    FAMILY_FILTER("https://doh.cleanbrowsing.org/doh/family-filter/"),
    ADULT_FILTER("https://doh.cleanbrowsing.org/doh/adult-filter/"),
    SECURITY_FILTER("https://doh.cleanbrowsing.org/doh/security-filter/"),
    CUSTOM("");

    fun resolveEndpointUrl(customDohUrl: String? = null): String {
        if (this == CUSTOM) {
            return customDohUrl?.takeIf { it.isNotBlank() }
                ?: CLEANBROWSING_FAMILY.defaultEndpointUrl
        }
        return customDohUrl?.takeIf { it.isNotBlank() } ?: defaultEndpointUrl
    }

    companion object {
        fun fromString(value: String?): DohPreset {
            if (value.isNullOrBlank()) return CLEANBROWSING_FAMILY
            val normalized = value.trim().uppercase().replace('-', '_')
            return entries.firstOrNull { it.name == normalized }
                ?: when (normalized) {
                    "FAMILY" -> CLEANBROWSING_FAMILY
                    "ADULT" -> CLEANBROWSING_ADULT
                    "SECURITY" -> CLEANBROWSING_SECURITY
                    else -> CLEANBROWSING_FAMILY
                }
        }
    }
}

/**
 * Target descriptor for handing off custom OAuth/app callback URI schemes (e.g. `juubundpc://`, `myapp://oauth`).
 */
data class CustomSchemeTarget(
    val scheme: String,
    val targetPackage: String? = null,
    val action: String = "android.intent.action.VIEW"
)

/**
 * Immutable policy configuration for `HM01` Intent & Custom Tabs Browser.
 */
data class BrowserPolicyConfig(
    val brandTitle: String = "HM01",
    val dohPreset: DohPreset = DohPreset.CLEANBROWSING_FAMILY,
    val customDohUrl: String? = null,
    val failClosedOnDnsError: Boolean = false,
    val blockedDomains: Set<String> = emptySet(),
    val blockedHostKeywords: Set<String> = emptySet(),
    val blockedPathRegexes: List<String> = emptyList(),
    val allowedDomainsOverride: Set<String> = emptySet(),
    val customCallbackSchemes: Map<String, CustomSchemeTarget> = emptyMap(),
    val maxExternalDomainHops: Int = 1,
    val maxTotalNavigationHops: Int = 45,
    val sessionTimeoutMs: Long = 10 * 60 * 1000L, // 10 minutes
    val blockVideoAndAudio: Boolean = true,
    val capImageDimensions: Boolean = false,
    val blockSearchEngines: Boolean = true,
    val upgradeInitialHttpToHttps: Boolean = true,
    val allowDownloads: Boolean = false
) {
    /**
     * Compiled regex list cached per immutable config instance.
     */
    val compiledBlockedPathRegexes: List<Regex> by lazy {
        blockedPathRegexes.mapNotNull { pattern ->
            runCatching { Regex(pattern, RegexOption.IGNORE_CASE) }.getOrNull()
        }
    }
}
