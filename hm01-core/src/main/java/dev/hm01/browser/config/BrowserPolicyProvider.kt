package dev.hm01.browser.config

import android.content.Context
import android.content.RestrictionsManager
import android.os.Bundle
import dev.hm01.browser.dns.DohResolver

/**
 * Singleton policy provider and DI hook for `HM01`.
 *
 * Supports:
 * 1. Programmatic configuration via [configure] (for host apps like Juubun consuming `:hm01-core`).
 * 2. Android Enterprise Managed Configurations via [RestrictionsManager] (for standalone APK deployments).
 */
object BrowserPolicyProvider {

    @Volatile
    private var programmaticConfig: BrowserPolicyConfig? = null

    @Volatile
    private var customDohResolver: DohResolver? = null

    /**
     * Programmatically sets the active [BrowserPolicyConfig].
     */
    @JvmStatic
    fun configure(config: BrowserPolicyConfig) {
        programmaticConfig = config
    }

    /**
     * Optional DI hook to override the [DohResolver] instance (e.g., for testing or custom network stacks).
     */
    @JvmStatic
    fun setDohResolver(resolver: DohResolver?) {
        customDohResolver = resolver
    }

    /**
     * Returns the configured [DohResolver], or creates one backed by the active policy config.
     */
    @JvmStatic
    fun getDohResolver(context: Context? = null): DohResolver {
        return customDohResolver ?: DohResolver(
            configProvider = { getConfig(context) }
        )
    }

    /**
     * Resets programmatic overrides back to default baseline configuration.
     */
    @JvmStatic
    fun reset() {
        programmaticConfig = null
        customDohResolver = null
    }

    /**
     * Resolves the active [BrowserPolicyConfig].
     *
     * Priority:
     * 1. Programmatically injected config via [configure].
     * 2. Android Enterprise [RestrictionsManager] application restrictions if [context] is provided.
     * 3. Default [BrowserPolicyConfig].
     */
    @JvmStatic
    fun getConfig(context: Context? = null): BrowserPolicyConfig {
        programmaticConfig?.let { return it }

        if (context != null) {
            val restrictions = runCatching {
                val manager = context.getSystemService(Context.RESTRICTIONS_SERVICE) as? RestrictionsManager
                manager?.applicationRestrictions
            }.getOrNull()

            if (restrictions != null && !restrictions.isEmpty) {
                return parseRestrictionsBundle(restrictions)
            }
        }

        return BrowserPolicyConfig()
    }

    /**
     * Parses an Android Enterprise Managed Configurations [Bundle] into a [BrowserPolicyConfig].
     */
    @JvmStatic
    fun parseRestrictionsBundle(bundle: Bundle, base: BrowserPolicyConfig = BrowserPolicyConfig()): BrowserPolicyConfig {
        val brandTitle = bundle.getString("brand_title")?.takeIf { it.isNotBlank() } ?: base.brandTitle
        val dohPreset = bundle.getString("doh_preset")?.let { DohPreset.fromString(it) } ?: base.dohPreset
        val customDohUrl = bundle.getString("custom_doh_url")?.takeIf { it.isNotBlank() } ?: base.customDohUrl
        val failClosed = if (bundle.containsKey("fail_closed_on_dns_error")) {
            bundle.getBoolean("fail_closed_on_dns_error", base.failClosedOnDnsError)
        } else {
            base.failClosedOnDnsError
        }

        val blockedDomains = extractStringSet(bundle, "blocked_domains") ?: base.blockedDomains
        val blockedKeywords = extractStringSet(bundle, "blocked_keywords") ?: base.blockedHostKeywords
        val blockedPathRegexes = extractStringList(bundle, "blocked_path_regexes") ?: base.blockedPathRegexes
        val allowedDomainsOverride = extractStringSet(bundle, "allowed_domains_override") ?: base.allowedDomainsOverride

        val maxExternalHops = if (bundle.containsKey("max_external_domain_hops")) {
            bundle.getInt("max_external_domain_hops", base.maxExternalDomainHops).coerceAtLeast(0)
        } else {
            base.maxExternalDomainHops
        }

        val maxTotalHops = if (bundle.containsKey("max_total_navigation_hops")) {
            bundle.getInt("max_total_navigation_hops", base.maxTotalNavigationHops).coerceAtLeast(1)
        } else {
            base.maxTotalNavigationHops
        }

        val sessionTimeoutMs = if (bundle.containsKey("session_timeout_seconds")) {
            val seconds = bundle.getInt("session_timeout_seconds", (base.sessionTimeoutMs / 1000L).toInt())
            (seconds.coerceAtLeast(10) * 1000L)
        } else {
            base.sessionTimeoutMs
        }

        val blockVideoAudio = if (bundle.containsKey("block_video_audio")) {
            bundle.getBoolean("block_video_audio", base.blockVideoAndAudio)
        } else {
            base.blockVideoAndAudio
        }

        val capImages = if (bundle.containsKey("cap_image_dimensions")) {
            bundle.getBoolean("cap_image_dimensions", base.capImageDimensions)
        } else {
            base.capImageDimensions
        }

        val blockSearch = if (bundle.containsKey("block_search_engines")) {
            bundle.getBoolean("block_search_engines", base.blockSearchEngines)
        } else {
            base.blockSearchEngines
        }

        return base.copy(
            brandTitle = brandTitle,
            dohPreset = dohPreset,
            customDohUrl = customDohUrl,
            failClosedOnDnsError = failClosed,
            blockedDomains = blockedDomains,
            blockedHostKeywords = blockedKeywords,
            blockedPathRegexes = blockedPathRegexes,
            allowedDomainsOverride = allowedDomainsOverride,
            maxExternalDomainHops = maxExternalHops,
            maxTotalNavigationHops = maxTotalHops,
            sessionTimeoutMs = sessionTimeoutMs,
            blockVideoAndAudio = blockVideoAudio,
            capImageDimensions = capImages,
            blockSearchEngines = blockSearch
        )
    }

    private fun extractStringList(bundle: Bundle, key: String): List<String>? {
        if (!bundle.containsKey(key)) return null
        val arrayValue = bundle.getStringArray(key)
        if (arrayValue != null) {
            return arrayValue
                .flatMap { it.split(',', '\n', ';') }
                .map { it.trim() }
                .filter { it.isNotEmpty() }
        }
        val stringValue = bundle.getString(key)
        if (stringValue != null) {
            return stringValue
                .split(',', '\n', ';')
                .map { it.trim() }
                .filter { it.isNotEmpty() }
        }
        return emptyList()
    }

    private fun extractStringSet(bundle: Bundle, key: String): Set<String>? {
        return extractStringList(bundle, key)?.map { it.lowercase() }?.toSet()
    }
}
