package dev.hm03.browser.config

import android.app.Activity
import android.content.Context
import android.content.RestrictionsManager
import android.os.Bundle
import dev.hm03.browser.dns.DohResolver
import java.util.Locale

/**
 * Callback interface allowing a host application (such as Juubun) to present its own native
 * DNS selection popup the first time the user opens a link when [DnsMode.USER_DEFINED] is active
 * and no DNS provider has been chosen yet.
 */
fun interface DnsSelectionPromptHandler {
    fun onPromptDnsSelection(
        activity: Activity,
        onDnsSelected: () -> Unit,
        onCancelled: () -> Unit
    )
}

/**
 * Singleton policy provider and DI hook for `HM03`.
 *
 * Supports:
 * 1. Programmatic configuration via [configure] (for host apps like Juubun consuming `:hm03-core`).
 * 2. User-defined DNS selection persistence via [setUserSelectedDns] / [getUserSelectedDnsUrl].
 * 3. Android Enterprise Managed Configurations via [RestrictionsManager].
 */
object BrowserPolicyProvider {

    private const val PREFS_NAME = "hm03_browser_prefs"
    private const val KEY_SELECTED_DNS_ID = "selected_dns_id"
    private const val KEY_SELECTED_DNS_URL = "selected_dns_url"

    @Volatile
    private var programmaticConfig: BrowserPolicyConfig? = null

    @Volatile
    private var customDohResolver: DohResolver? = null

    @Volatile
    private var userSelectedDnsId: String? = null

    @Volatile
    private var userSelectedDnsUrl: String? = null

    @Volatile
    private var dnsSelectionPromptHandler: DnsSelectionPromptHandler? = null

    @Volatile
    private var cachedRestrictionsSignature: Int? = null

    @Volatile
    private var cachedRestrictionsConfig: BrowserPolicyConfig? = null

    /**
     * Registers a host-provided [DnsSelectionPromptHandler] to display a first-time DNS selection
     * popup when [DnsMode.USER_DEFINED] has no selected DNS server yet.
     */
    @JvmStatic
    fun setDnsSelectionPromptHandler(handler: DnsSelectionPromptHandler?) {
        dnsSelectionPromptHandler = handler
    }

    /**
     * Returns the registered [DnsSelectionPromptHandler], if any.
     */
    @JvmStatic
    fun getDnsSelectionPromptHandler(): DnsSelectionPromptHandler? = dnsSelectionPromptHandler

    /**
     * Programmatically sets the active [BrowserPolicyConfig].
     *
     * @throws IllegalArgumentException if [BrowserPolicyConfig.dnsMode] is [DnsMode.USER_DEFINED]
     * and [BrowserPolicyConfig.userDnsOptions] is empty, or if any configured DoH URL is not a valid `https://` URL.
     */
    @JvmStatic
    fun configure(config: BrowserPolicyConfig) {
        if (config.dnsMode == DnsMode.USER_DEFINED) {
            require(config.userDnsOptions.isNotEmpty()) {
                "DnsMode.USER_DEFINED requires a non-empty userDnsOptions list to be provided by the developer."
            }
        }
        for (option in config.userDnsOptions) {
            require(BrowserPolicyConfig.isValidDohEndpointUrl(option.dohEndpointUrl)) {
                "Invalid DoH endpoint URL in userDnsOptions (${option.id}): must be a valid https:// hostname URL."
            }
        }
        if (!config.customDohUrl.isNullOrBlank()) {
            require(BrowserPolicyConfig.isValidDohEndpointUrl(config.customDohUrl)) {
                "Invalid customDohUrl: must be a valid https:// hostname URL."
            }
        }
        if (!config.selectedDnsEndpointUrl.isNullOrBlank()) {
            require(BrowserPolicyConfig.isValidDohEndpointUrl(config.selectedDnsEndpointUrl)) {
                "Invalid selectedDnsEndpointUrl: must be a valid https:// hostname URL."
            }
        }

        programmaticConfig = config
        if (!config.selectedDnsEndpointUrl.isNullOrBlank()) {
            userSelectedDnsUrl = config.selectedDnsEndpointUrl.trim()
        }
        DohResolver.SharedCacheHolder.INSTANCE.clear()
    }

    /**
     * Loads any persisted user-selected DNS choice from SharedPreferences into memory.
     */
    @JvmStatic
    fun loadUserDnsSelection(context: Context) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val savedId = prefs.getString(KEY_SELECTED_DNS_ID, null)?.takeIf { it.isNotBlank() }
        val savedUrl = prefs.getString(KEY_SELECTED_DNS_URL, null)?.takeIf {
            BrowserPolicyConfig.isValidDohEndpointUrl(it)
        }
        userSelectedDnsId = if (savedUrl != null) savedId else null
        userSelectedDnsUrl = savedUrl
    }

    /**
     * Updates and persists the user's selected DNS provider or custom DoH endpoint URL,
     * and clears the DoH decision cache so the new DNS filter takes effect immediately.
     *
     * @throws IllegalArgumentException if [dohEndpointUrl] is non-null and not a valid `https://` URL,
     * or if [BrowserPolicyConfig.allowCustomUserDohUrl] is `false` and the URL is not in [BrowserPolicyConfig.userDnsOptions].
     */
    @JvmStatic
    fun setUserSelectedDns(
        context: Context? = null,
        optionId: String?,
        dohEndpointUrl: String?
    ) {
        val cleanId = optionId?.trim()?.takeIf { it.isNotEmpty() }
        val cleanUrl = dohEndpointUrl?.trim()?.takeIf { it.isNotEmpty() }

        if (cleanUrl != null) {
            require(BrowserPolicyConfig.isValidDohEndpointUrl(cleanUrl)) {
                "DoH endpoint URL must be a valid https:// hostname URL."
            }
            val currentConfig = programmaticConfig
            if (currentConfig != null && !currentConfig.allowCustomUserDohUrl && currentConfig.userDnsOptions.isNotEmpty()) {
                val matchesOption = currentConfig.userDnsOptions.any { option ->
                    option.dohEndpointUrl.trim().equals(cleanUrl, ignoreCase = true)
                }
                require(matchesOption) {
                    "Custom DoH URLs are disabled by policy; selected URL must match one of the configured userDnsOptions."
                }
            }
        }

        userSelectedDnsId = cleanId
        userSelectedDnsUrl = cleanUrl

        if (context != null) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putString(KEY_SELECTED_DNS_ID, cleanId)
                .putString(KEY_SELECTED_DNS_URL, cleanUrl)
                .apply()
        }

        DohResolver.SharedCacheHolder.INSTANCE.clear()
    }

    /**
     * Returns the ID of the DNS provider currently selected by the user, or `null` if none is selected.
     */
    @JvmStatic
    fun getUserSelectedDnsId(context: Context? = null): String? {
        if (userSelectedDnsId == null && context != null) {
            loadUserDnsSelection(context)
        }
        return userSelectedDnsId
    }

    /**
     * Returns the DoH endpoint URL currently selected by the user, or `null` if none is selected.
     */
    @JvmStatic
    fun getUserSelectedDnsUrl(context: Context? = null): String? {
        if (userSelectedDnsUrl == null && context != null) {
            loadUserDnsSelection(context)
        }
        return userSelectedDnsUrl
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
        userSelectedDnsId = null
        userSelectedDnsUrl = null
        dnsSelectionPromptHandler = null
        cachedRestrictionsSignature = null
        cachedRestrictionsConfig = null
        DohResolver.SharedCacheHolder.INSTANCE.clear()
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
        if (context != null && userSelectedDnsUrl == null) {
            loadUserDnsSelection(context)
        }

        val baseConfig = programmaticConfig?.let { config ->
            val activeUserUrl = userSelectedDnsUrl
            if (config.dnsMode == DnsMode.USER_DEFINED && !activeUserUrl.isNullOrBlank()) {
                val allowedUrl = if (!config.allowCustomUserDohUrl && config.userDnsOptions.isNotEmpty()) {
                    activeUserUrl.takeIf { candidate ->
                        config.userDnsOptions.any { it.dohEndpointUrl.trim().equals(candidate, ignoreCase = true) }
                    }
                } else {
                    activeUserUrl
                }
                if (!allowedUrl.isNullOrBlank() && BrowserPolicyConfig.isValidDohEndpointUrl(allowedUrl)) {
                    config.copy(selectedDnsEndpointUrl = allowedUrl)
                } else {
                    config
                }
            } else {
                config
            }
        }

        if (context != null) {
            val restrictions = runCatching {
                val manager = context.getSystemService(Context.RESTRICTIONS_SERVICE) as? RestrictionsManager
                manager?.applicationRestrictions
            }.getOrNull()

            if (restrictions != null && !restrictions.isEmpty) {
                val parsed = parseRestrictionsBundle(restrictions, base = baseConfig ?: BrowserPolicyConfig())
                cachedRestrictionsConfig = parsed
                return parsed
            }
        }

        return baseConfig ?: BrowserPolicyConfig()
    }

    /**
     * Parses an Android Enterprise Managed Configurations [Bundle] into a [BrowserPolicyConfig].
     */
    @JvmStatic
    fun parseRestrictionsBundle(bundle: Bundle, base: BrowserPolicyConfig = BrowserPolicyConfig()): BrowserPolicyConfig {
        val brandTitle = bundle.getString("brand_title")?.takeIf { it.isNotBlank() } ?: base.brandTitle
        val rawCustomDohUrl = bundle.getString("custom_doh_url")?.trim()?.takeIf { it.isNotBlank() }
        val hasValidManagedDoh = rawCustomDohUrl != null && BrowserPolicyConfig.isValidDohEndpointUrl(rawCustomDohUrl)
        val customDohUrl = if (hasValidManagedDoh) {
            rawCustomDohUrl!!
        } else {
            base.customDohUrl
        }
        val dnsMode = if (hasValidManagedDoh) {
            DnsMode.DEVELOPER_FIXED
        } else {
            base.dnsMode
        }
        val selectedDnsEndpointUrl = if (hasValidManagedDoh) {
            rawCustomDohUrl
        } else {
            base.selectedDnsEndpointUrl
        }

        val failClosed = if (bundle.containsKey("fail_closed_on_dns_error")) {
            bundle.getBoolean("fail_closed_on_dns_error", base.failClosedOnDnsError)
        } else {
            base.failClosedOnDnsError
        }

        val allowCustomUserDohUrl = if (bundle.containsKey("allow_custom_user_doh_url")) {
            bundle.getBoolean("allow_custom_user_doh_url", base.allowCustomUserDohUrl)
        } else {
            base.allowCustomUserDohUrl
        }

        val blockedDomains = extractStringSet(bundle, "blocked_domains") ?: base.blockedDomains
        val blockedKeywords = extractStringSet(bundle, "blocked_keywords") ?: base.blockedHostKeywords
        val blockedPathRegexes = extractRegexStringList(bundle, "blocked_path_regexes") ?: base.blockedPathRegexes
        val allowedDomainsOverride = extractStringSet(bundle, "allowed_domains_override") ?: base.allowedDomainsOverride

        val allowUnregisteredCustomSchemes = if (bundle.containsKey("allow_unregistered_custom_schemes")) {
            bundle.getBoolean("allow_unregistered_custom_schemes", base.allowUnregisteredCustomSchemes)
        } else {
            base.allowUnregisteredCustomSchemes
        }

        val allowThirdPartyIframes = if (bundle.containsKey("allow_third_party_iframes")) {
            bundle.getBoolean("allow_third_party_iframes", base.allowThirdPartyIframes)
        } else {
            base.allowThirdPartyIframes
        }

        val stripWebViewUa = if (bundle.containsKey("strip_webview_user_agent_token")) {
            bundle.getBoolean("strip_webview_user_agent_token", base.stripWebViewUserAgentToken)
        } else {
            base.stripWebViewUserAgentToken
        }

        val maxExternalHops = if (bundle.containsKey("max_external_domain_hops")) {
            val rawHops = bundle.getInt("max_external_domain_hops", base.maxExternalDomainHops ?: 1)
            if (rawHops < 0) null else rawHops
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
            dnsMode = dnsMode,
            customDohUrl = customDohUrl,
            selectedDnsEndpointUrl = selectedDnsEndpointUrl,
            failClosedOnDnsError = failClosed,
            allowCustomUserDohUrl = allowCustomUserDohUrl,
            blockedDomains = blockedDomains,
            blockedHostKeywords = blockedKeywords,
            blockedPathRegexes = blockedPathRegexes,
            allowedDomainsOverride = allowedDomainsOverride,
            allowUnregisteredCustomSchemes = allowUnregisteredCustomSchemes,
            allowThirdPartyIframes = allowThirdPartyIframes,
            stripWebViewUserAgentToken = stripWebViewUa,
            maxExternalDomainHops = maxExternalHops,
            maxTotalNavigationHops = maxTotalHops,
            sessionTimeoutMs = sessionTimeoutMs,
            blockVideoAndAudio = blockVideoAudio,
            capImageDimensions = capImages,
            blockSearchEngines = blockSearch
        )
    }

    /**
     * Splits a delimiter-separated list while preserving commas inside regex quantifiers `{m,n}`
     * and character classes `[...]`, as well as escaped delimiters `\,`.
     */
    @JvmStatic
    internal fun splitConfigListPreservingQuantifiers(raw: String): List<String> {
        if (raw.isEmpty()) return emptyList()
        val result = mutableListOf<String>()
        val current = StringBuilder()
        var braceDepth = 0
        var bracketDepth = 0
        var escaped = false

        for (ch in raw) {
            if (escaped) {
                current.append(ch)
                escaped = false
                continue
            }
            when (ch) {
                '\\' -> {
                    current.append(ch)
                    escaped = true
                }
                '[' -> {
                    bracketDepth++
                    current.append(ch)
                }
                ']' -> {
                    if (bracketDepth > 0) bracketDepth--
                    current.append(ch)
                }
                '{' -> {
                    if (bracketDepth == 0) braceDepth++
                    current.append(ch)
                }
                '}' -> {
                    if (bracketDepth == 0 && braceDepth > 0) braceDepth--
                    current.append(ch)
                }
                '\n', ';' -> {
                    if (bracketDepth == 0 && braceDepth == 0) {
                        val token = current.toString().trim()
                        if (token.isNotEmpty()) result.add(token)
                        current.setLength(0)
                    } else {
                        current.append(ch)
                    }
                }
                ',' -> {
                    if (bracketDepth == 0 && braceDepth == 0) {
                        val token = current.toString().trim()
                        if (token.isNotEmpty()) result.add(token)
                        current.setLength(0)
                    } else {
                        current.append(ch)
                    }
                }
                else -> current.append(ch)
            }
        }
        val tail = current.toString().trim()
        if (tail.isNotEmpty()) {
            result.add(tail)
        }
        return result
    }

    private fun extractRegexStringList(bundle: Bundle, key: String): List<String>? {
        if (!bundle.containsKey(key)) return null
        val arrayValue = bundle.getStringArray(key)
        if (arrayValue != null) {
            return arrayValue
                .flatMap { splitConfigListPreservingQuantifiers(it) }
                .filter { it.isNotEmpty() }
        }
        val stringValue = bundle.getString(key)
        if (stringValue != null) {
            return splitConfigListPreservingQuantifiers(stringValue)
        }
        return emptyList()
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
        return extractStringList(bundle, key)?.map { it.lowercase(Locale.ROOT) }?.toSet()
    }

    @Suppress("DEPRECATION")
    private fun computeBundleSignature(bundle: Bundle): Int {
        var result = 1
        for (key in bundle.keySet().sorted()) {
            result = 31 * result + key.hashCode()
            val value = bundle.get(key)
            val valHash = when (value) {
                is Array<*> -> value.contentDeepHashCode()
                else -> value?.hashCode() ?: 0
            }
            result = 31 * result + valHash
        }
        return result
    }
}
