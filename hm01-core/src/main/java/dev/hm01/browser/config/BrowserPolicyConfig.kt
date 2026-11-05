package dev.hm01.browser.config

import java.util.Locale

/**
 * DNS resolution mode for `HM01`.
 */
enum class DnsMode {
    /**
     * Requires the developer to provide [BrowserPolicyConfig.userDnsOptions] and requires the user
     * to select a DNS provider (or enter a custom DoH URL) before web links are permitted.
     */
    USER_DEFINED,

    /**
     * Uses a single developer-configured DoH endpoint via [BrowserPolicyConfig.dohPreset] or
     * [BrowserPolicyConfig.customDohUrl].
     */
    DEVELOPER_FIXED,

    /**
     * Disables `HM01`'s RFC 8484 DoH check and relies on the OS network stack.
     */
    DISABLED
}

/**
 * A selectable DNS-over-HTTPS (DoH) provider option supplied by the host developer when
 * [BrowserPolicyConfig.dnsMode] is [DnsMode.USER_DEFINED].
 */
data class DnsProviderOption(
    val id: String,
    val displayName: String,
    val dohEndpointUrl: String
)

/**
 * Built-in DoH endpoint enum for backwards-compatible programmatic or Managed Configuration callers.
 */
enum class DohPreset(val defaultEndpointUrl: String) {
    NONE(""),
    ADGUARD_FAMILY("https://family.adguard-dns.com/dns-query"),
    CLEANBROWSING_ADULT("https://doh.cleanbrowsing.org/doh/adult-filter/"),
    CLEANBROWSING_FAMILY("https://doh.cleanbrowsing.org/doh/family-filter/"),
    CLEANBROWSING_SECURITY("https://doh.cleanbrowsing.org/doh/security-filter/"),
    CLOUDFLARE_FAMILY("https://family.cloudflare-dns.com/dns-query"),
    MULLVAD_FAMILY("https://family.dns.mullvad.net/dns-query"),
    OPENDNS_FAMILYSHIELD("https://doh.familyshield.opendns.com/dns-query"),
    FAMILY_FILTER("https://doh.cleanbrowsing.org/doh/family-filter/"),
    ADULT_FILTER("https://doh.cleanbrowsing.org/doh/adult-filter/"),
    SECURITY_FILTER("https://doh.cleanbrowsing.org/doh/security-filter/"),
    CUSTOM("");

    fun resolveEndpointUrl(customDohUrl: String? = null): String {
        if (this == NONE) {
            return customDohUrl?.trim().orEmpty()
        }
        if (this == CUSTOM) {
            return customDohUrl?.trim().orEmpty()
        }
        return customDohUrl?.takeIf { it.isNotBlank() }?.trim() ?: defaultEndpointUrl
    }

    companion object {
        fun fromString(value: String?): DohPreset {
            if (value.isNullOrBlank()) return NONE
            val normalized = value.trim().uppercase(Locale.ROOT).replace('-', '_')
            return entries.firstOrNull { it.name == normalized }
                ?: when (normalized) {
                    "FAMILY" -> CLEANBROWSING_FAMILY
                    "ADULT" -> CLEANBROWSING_ADULT
                    "SECURITY" -> CLEANBROWSING_SECURITY
                    else -> CUSTOM
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
 * Path-scoped rule for a multi-purpose platform domain: allows navigation to authentication/OAuth
 * paths on [domain] while blocking general browsing paths on that same domain.
 *
 * @property domain Exact domain (`"github.com"`), wildcard suffix (`"*.firebaseapp.com"`), or regex (`"^.*\\.google\\..*$"`).
 * @property allowedPathPrefixes Path prefixes (case-insensitive) permitted on this domain (e.g. `listOf("/login")`).
 * @property allowedPathRegexes Optional regex patterns permitted on this domain.
 * @property allowIfInitialLandingHost If `true`, allows full access when the exact tenant host was the initial URL opened.
 */
data class PathScopedPlatformRule(
    val domain: String,
    val allowedPathPrefixes: List<String> = emptyList(),
    val allowedPathRegexes: List<String> = emptyList(),
    val allowIfInitialLandingHost: Boolean = false
) {
    val compiledAllowedPathRegexes: List<Regex> by lazy {
        allowedPathRegexes.mapNotNull { pattern ->
            runCatching { Regex(pattern, RegexOption.IGNORE_CASE) }.getOrNull()
        }
    }
}

/**
 * Immutable policy configuration for `HM01` Intent & Custom Tabs Browser.
 *
 * Out of the box, `HM01` ships with **empty** blocklists (plus a single illustrative example for
 * [pathScopedPlatformRules] and [blockedMediaExtensions]) so host developers have full control
 * over what their app blocks.
 */
data class BrowserPolicyConfig(
    val brandTitle: String = "HM01",
    val dnsMode: DnsMode = DnsMode.DEVELOPER_FIXED,
    val userDnsOptions: List<DnsProviderOption> = emptyList(),
    val selectedDnsEndpointUrl: String? = null,
    val dohPreset: DohPreset = DohPreset.NONE,
    val customDohUrl: String? = null,
    val failClosedOnDnsError: Boolean = false,
    val blockedDomains: Set<String> = emptySet(),
    val blockedTlds: Set<String> = emptySet(),
    val blockedHostKeywords: Set<String> = emptySet(),
    val blockedPathRegexes: List<String> = emptyList(),
    val searchEngineDomains: Set<String> = emptySet(),
    val pathScopedPlatformRules: List<PathScopedPlatformRule> = DEFAULT_EXAMPLE_PATH_SCOPED_RULES,
    val trustedIdpAndPaymentHosts: Set<String> = DefaultBaselineLists.EXACT_DEDICATED_IDP_PAYMENT_CAPTCHA_HOSTS,
    val trustedIdpAndPaymentSuffixes: Set<String> = DefaultBaselineLists.SUFFIX_DEDICATED_IDP_PAYMENT_CAPTCHA_HOSTS,
    val urlShortenerDomains: Set<String> = DefaultBaselineLists.KNOWN_URL_SHORTENERS,
    val allowedDomainsOverride: Set<String> = emptySet(),
    val customCallbackSchemes: Map<String, CustomSchemeTarget> = emptyMap(),
    /**
     * Maximum number of external domain hops allowed outside the initial landing domain ("Link Leash").
     * Defaults to `1`. Set to `null` (or call [withoutLinkLeash]) to disable the Link Leash completely.
     */
    val maxExternalDomainHops: Int? = 1,
    val maxTotalNavigationHops: Int = 45,
    val sessionTimeoutMs: Long = 10 * 60 * 1000L, // 10 minutes
    val blockVideoAndAudio: Boolean = true,
    /**
     * Media file extensions blocked when [blockVideoAndAudio] is `true`.
     * Defaults to a single example format (`setOf(".mp4")`) until customized by the developer.
     */
    val blockedMediaExtensions: Set<String> = DEFAULT_EXAMPLE_MEDIA_EXTENSIONS,
    val blockedMediaMimePrefixes: Set<String> = emptySet(),
    val blockedSecFetchDests: Set<String> = emptySet(),
    val blockByteRangeMediaRequests: Boolean = false,
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

    /**
     * Returns a copy of this configuration with the 1-hop Link Leash disabled (`maxExternalDomainHops = null`).
     */
    fun withoutLinkLeash(): BrowserPolicyConfig = copy(maxExternalDomainHops = null)

    /**
     * Returns a copy of this configuration with the Link Leash set to [maxExternalHops] external domain hops.
     */
    fun withLinkLeash(maxExternalHops: Int): BrowserPolicyConfig =
        copy(maxExternalDomainHops = maxExternalHops.coerceAtLeast(0))

    /**
     * Resolves the active DoH endpoint URL based on [dnsMode], [selectedDnsEndpointUrl],
     * [BrowserPolicyProvider.getUserSelectedDnsUrl], [dohPreset], and [customDohUrl].
     */
    fun resolveActiveDohEndpointUrl(): String {
        return when (dnsMode) {
            DnsMode.DISABLED -> ""
            DnsMode.USER_DEFINED -> {
                selectedDnsEndpointUrl?.takeIf { it.isNotBlank() }?.trim()
                    ?: BrowserPolicyProvider.getUserSelectedDnsUrl().orEmpty().trim()
            }
            DnsMode.DEVELOPER_FIXED -> {
                selectedDnsEndpointUrl?.takeIf { it.isNotBlank() }?.trim()
                    ?: dohPreset.resolveEndpointUrl(customDohUrl)
            }
        }
    }

    companion object {
        /**
         * Single illustrative example of a path-scoped platform rule (`github.com` login/2FA allowed,
         * repository surfing blocked). Developers can replace or clear this list in [BrowserPolicyConfig].
         */
        val DEFAULT_EXAMPLE_PATH_SCOPED_RULES: List<PathScopedPlatformRule> = listOf(
            PathScopedPlatformRule(
                domain = "github.com",
                allowedPathPrefixes = listOf("/login", "/sessions", "/settings/two_factor")
            )
        )

        /**
         * Single illustrative example of a blocked media extension (`.mp4`).
         * Developers can replace or clear this set in [BrowserPolicyConfig].
         */
        val DEFAULT_EXAMPLE_MEDIA_EXTENSIONS: Set<String> = setOf(".mp4")
    }
}
