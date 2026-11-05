package dev.hm01.browser.filter

import dev.hm01.browser.config.BrowserPolicyConfig
import dev.hm01.browser.config.DefaultBaselineLists
import dev.hm01.browser.config.DnsMode
import dev.hm01.browser.dns.DohResolver
import dev.hm01.browser.dns.DohVerdict
import java.net.URI
import java.util.Locale

/**
 * Reason why a URL navigation or sub-resource request was blocked by [UrlPolicyEvaluator].
 */
enum class BlockReason(val title: String, val userMessage: String) {
    INSECURE_OR_INVALID_SCHEME(
        "Unsupported or Insecure Link",
        "Only secure HTTPS web links are permitted in HM01."
    ),
    IP_LITERAL_NOT_ALLOWED(
        "Direct IP Address Blocked",
        "Direct numeric IP addresses are blocked to enforce hostname safety checks."
    ),
    NON_OAUTH_PLATFORM_PATH(
        "Platform Feature Restricted",
        "Only sign-in and authentication pages are permitted on this platform."
    ),
    SEARCH_ENGINE_OR_PROXY(
        "Search & Web Surfing Disabled",
        "General search engines, web proxies, and archive mirrors are disabled in HM01."
    ),
    ADULT_BASELINE_BLOCK(
        "Restricted Content Blocked",
        "This website is blocked by your active TLD safety policy."
    ),
    HOST_BLOCKLIST_DOMAIN(
        "Blocked Website",
        "This website is restricted by your active focus or device policy."
    ),
    HOST_BLOCKLIST_KEYWORD(
        "Blocked Topic or Keyword",
        "This website matches a restricted keyword in your active policy."
    ),
    HOST_BLOCKLIST_PATH(
        "Blocked Page Section",
        "This section or feed is restricted by your active focus policy."
    ),
    MAX_TOTAL_HOPS_EXCEEDED(
        "Session Navigation Limit Reached",
        "You have reached the maximum number of page loads for a single link session."
    ),
    LINK_LEASH_HOP_LIMIT_EXCEEDED(
        "External Link Limit Reached",
        "HM01 stays focused on the link you opened and prevents multi-site web surfing."
    ),
    DNS_NOT_SELECTED(
        "DNS Filter Not Selected",
        "Please select a DNS filter in Settings before opening web links."
    ),
    DOH_FAMILY_FILTER_BLOCK(
        "Blocked by DNS Safety Filter",
        "This domain was blocked by your selected DNS safety filter."
    ),
    MEDIA_STREAM_BLOCKED(
        "Video & Audio Disabled",
        "Video and audio streaming are disabled in HM01."
    )
}

/**
 * Decision returned by [UrlPolicyEvaluator].
 */
sealed class PolicyDecision {
    data class Allow(
        val url: String,
        val host: String,
        val effectiveDomain: String,
        val isTrustedIdpOrScopedOAuth: Boolean = false
    ) : PolicyDecision()

    data class UpgradeToHttps(
        val httpsUrl: String
    ) : PolicyDecision()

    data class HandOffToNativeApp(
        val url: String,
        val scheme: String,
        val targetPackage: String? = null
    ) : PolicyDecision()

    data class Block(
        val reason: BlockReason,
        val url: String,
        val host: String,
        val detail: String = reason.userMessage
    ) : PolicyDecision()
}

/**
 * Evaluates main-frame navigations (`shouldOverrideUrlLoading`) and sub-resource requests
 * (`shouldInterceptRequest`) through the 6-step HM01 policy pipeline:
 *
 * 1. Scheme, IP-Literal & Native App Handoff
 * 2. Scoped OAuth & Trusted Identity Provider Allowlist (driven by [BrowserPolicyConfig.pathScopedPlatformRules])
 * 3. Search Engine & Proxy Blocker (driven by [BrowserPolicyConfig.searchEngineDomains])
 * 4. Pluggable Blocklist (driven by [BrowserPolicyConfig.blockedDomains], [BrowserPolicyConfig.blockedHostKeywords], [BrowserPolicyConfig.blockedPathRegexes])
 * 5. "Link Leash" (External Domain Hop Policy, optional via [BrowserPolicyConfig.maxExternalDomainHops])
 * 6. User-Selected or Developer-Configured DNS-over-HTTPS Check
 */
class UrlPolicyEvaluator(
    private val configProvider: () -> BrowserPolicyConfig = { BrowserPolicyConfig() },
    private val dohResolver: DohResolver = DohResolver(configProvider = configProvider),
    private val nativeAppHandlerDetector: ((String) -> Boolean)? = null
) {

    private val stateLock = Any()

    @Volatile
    var initialLandingHost: String? = null
        private set

    @Volatile
    var landingEffectiveDomain: String? = null
        private set

    @Volatile
    var currentExternalDomain: String? = null
        private set

    @Volatile
    var externalDomainHops: Int = 0
        private set

    @Volatile
    var totalNavigationHops: Int = 0
        private set

    @Volatile
    private var inRedirectResolutionGrace: Boolean = true

    /**
     * Resets session state for a new link launch.
     */
    fun resetSession() {
        synchronized(stateLock) {
            initialLandingHost = null
            landingEffectiveDomain = null
            currentExternalDomain = null
            externalDomainHops = 0
            totalNavigationHops = 0
            inRedirectResolutionGrace = true
        }
    }

    /**
     * Marks that the landing page has finished its initial redirect chain.
     */
    fun markRedirectGraceComplete() {
        synchronized(stateLock) {
            if (landingEffectiveDomain != null) {
                inRedirectResolutionGrace = false
            }
        }
    }

    /**
     * Evaluates a main-frame navigation request (`Intent` launch or `shouldOverrideUrlLoading`).
     */
    fun evaluateMainFrameNavigation(
        rawUrl: String,
        isInitialLaunch: Boolean = false,
        isServerRedirect: Boolean = false
    ): PolicyDecision {
        val config = configProvider()
        val trimmedUrl = rawUrl.trim()
        if (trimmedUrl.isEmpty()) {
            return PolicyDecision.Block(BlockReason.INSECURE_OR_INVALID_SCHEME, rawUrl, "")
        }

        val scheme = extractScheme(trimmedUrl)

        // =========================================================================
        // STEP 1: Scheme, IP-Literal & Native App Handoff
        // =========================================================================
        if (scheme != "https") {
            if (scheme == "http") {
                if (isInitialLaunch && config.upgradeInitialHttpToHttps) {
                    val upgraded = "https://" + trimmedUrl.substringAfter("://")
                    return PolicyDecision.UpgradeToHttps(upgraded)
                }
                return PolicyDecision.Block(
                    reason = BlockReason.INSECURE_OR_INVALID_SCHEME,
                    url = trimmedUrl,
                    host = extractFallbackHost(trimmedUrl)
                )
            }

            if (isAllowedCustomCallbackScheme(scheme, config)) {
                val targetPkg = config.customCallbackSchemes[scheme]?.targetPackage
                return PolicyDecision.HandOffToNativeApp(
                    url = trimmedUrl,
                    scheme = scheme,
                    targetPackage = targetPkg
                )
            }

            return PolicyDecision.Block(
                reason = BlockReason.INSECURE_OR_INVALID_SCHEME,
                url = trimmedUrl,
                host = ""
            )
        }

        val parsedUri = runCatching { URI(trimmedUrl) }.getOrNull()
        val rawHost = parsedUri?.host ?: extractFallbackHost(trimmedUrl)
        val host = rawHost.trim().trimEnd('.').lowercase(Locale.ROOT)
        if (host.isEmpty()) {
            return PolicyDecision.Block(BlockReason.INSECURE_OR_INVALID_SCHEME, trimmedUrl, "")
        }

        val rawPath = parsedUri?.rawPath?.takeIf { it.isNotEmpty() } ?: extractFallbackPath(trimmedUrl)
        val rawQuery = parsedUri?.rawQuery
        val pathWithQuery = if (!rawQuery.isNullOrEmpty()) "$rawPath?$rawQuery" else rawPath

        if (DomainExtractor.isIpLiteral(host)) {
            return PolicyDecision.Block(BlockReason.IP_LITERAL_NOT_ALLOWED, trimmedUrl, host)
        }

        if (!isInitialLaunch && nativeAppHandlerDetector?.invoke(trimmedUrl) == true) {
            return PolicyDecision.HandOffToNativeApp(url = trimmedUrl, scheme = "https")
        }

        val effectiveDomain = DomainExtractor.extractEffectiveDomain(host)
        val isExplicitlyAllowedOverride = isDomainInSet(host, effectiveDomain, config.allowedDomainsOverride)

        // =========================================================================
        // STEP 2: Scoped OAuth & Trusted Identity Provider Allowlist
        // =========================================================================
        val predictedInitialHost = synchronized(stateLock) {
            initialLandingHost
                ?: if (!DefaultBaselineLists.isKnownUrlShortener(host, config.urlShortenerDomains)) host else null
        }

        val scopedPlatformResult = DefaultBaselineLists.evaluatePathScopedPlatform(
            rawHost = host,
            rawPath = rawPath,
            initialLandingHost = predictedInitialHost,
            rules = config.pathScopedPlatformRules
        )
        if (scopedPlatformResult == DefaultBaselineLists.ScopedPlatformResult.BLOCKED_NON_OAUTH_PATH &&
            !isExplicitlyAllowedOverride
        ) {
            return PolicyDecision.Block(BlockReason.NON_OAUTH_PLATFORM_PATH, trimmedUrl, host)
        }

        val isTrustedIdpOrScopedOAuth =
            scopedPlatformResult == DefaultBaselineLists.ScopedPlatformResult.ALLOWED_SCOPED_OAUTH ||
                DefaultBaselineLists.isDedicatedTrustedIdpOrPaymentOrCaptchaHost(host, config)

        // =========================================================================
        // STEP 3: Search Engine & Proxy Blocker (Developer-Configured)
        // =========================================================================
        if (config.blockSearchEngines && !isExplicitlyAllowedOverride) {
            if (DefaultBaselineLists.isSearchEngineOrProxy(host, rawPath, config.searchEngineDomains)) {
                return PolicyDecision.Block(BlockReason.SEARCH_ENGINE_OR_PROXY, trimmedUrl, host)
            }
        }

        // =========================================================================
        // STEP 4: Pluggable Blocklist (Developer-Configured)
        // =========================================================================
        if (!isExplicitlyAllowedOverride) {
            val blocklistDecision = evaluateBlocklists(trimmedUrl, host, effectiveDomain, pathWithQuery, config)
            if (blocklistDecision != null) {
                return blocklistDecision
            }
        }

        // =========================================================================
        // STEP 5: "Link Leash" (External Domain Hop Policy)
        // =========================================================================
        synchronized(stateLock) {
            if (totalNavigationHops + 1 > config.maxTotalNavigationHops) {
                return PolicyDecision.Block(BlockReason.MAX_TOTAL_HOPS_EXCEEDED, trimmedUrl, host)
            }

            if (!isTrustedIdpOrScopedOAuth) {
                val isShortener = DefaultBaselineLists.isKnownUrlShortener(host, config.urlShortenerDomains)
                val maxHops = config.maxExternalDomainHops

                if (landingEffectiveDomain == null) {
                    if (!isShortener) {
                        landingEffectiveDomain = effectiveDomain
                        initialLandingHost = host
                        if (!isServerRedirect && !isInitialLaunch) {
                            inRedirectResolutionGrace = false
                        }
                    }
                } else if (inRedirectResolutionGrace && isServerRedirect && !isShortener && externalDomainHops == 0) {
                    landingEffectiveDomain = effectiveDomain
                    initialLandingHost = host
                } else {
                    val currentLanding = landingEffectiveDomain!!
                    if (effectiveDomain != currentLanding) {
                        inRedirectResolutionGrace = false
                        if (effectiveDomain == currentExternalDomain) {
                            // Browsing within the already-entered allowed external domain
                        } else {
                            val nextExternalHops = externalDomainHops + 1
                            if (maxHops != null && nextExternalHops > maxHops) {
                                return PolicyDecision.Block(
                                    reason = BlockReason.LINK_LEASH_HOP_LIMIT_EXCEEDED,
                                    url = trimmedUrl,
                                    host = host
                                )
                            }
                            externalDomainHops = nextExternalHops
                            currentExternalDomain = effectiveDomain
                        }
                    }
                }
            }

            totalNavigationHops++
        }

        // =========================================================================
        // STEP 6: DNS-over-HTTPS Safety Check
        // =========================================================================
        if (!isExplicitlyAllowedOverride && config.dnsMode != DnsMode.DISABLED) {
            val activeDohUrl = config.resolveActiveDohEndpointUrl()
            if (config.dnsMode == DnsMode.USER_DEFINED && activeDohUrl.isBlank()) {
                return PolicyDecision.Block(BlockReason.DNS_NOT_SELECTED, trimmedUrl, host)
            }
            if (activeDohUrl.isNotBlank()) {
                val dohVerdict = dohResolver.resolve(host)
                if (dohVerdict == DohVerdict.BLOCK) {
                    return PolicyDecision.Block(BlockReason.DOH_FAMILY_FILTER_BLOCK, trimmedUrl, host)
                }
            }
        }

        return PolicyDecision.Allow(
            url = trimmedUrl,
            host = host,
            effectiveDomain = effectiveDomain,
            isTrustedIdpOrScopedOAuth = isTrustedIdpOrScopedOAuth
        )
    }

    /**
     * Evaluates a background sub-resource request (`shouldInterceptRequest`).
     */
    fun evaluateSubResourceRequest(
        rawUrl: String,
        requestHeaders: Map<String, String> = emptyMap()
    ): PolicyDecision {
        val config = configProvider()
        val trimmedUrl = rawUrl.trim()
        if (trimmedUrl.isEmpty()) {
            return PolicyDecision.Block(BlockReason.INSECURE_OR_INVALID_SCHEME, rawUrl, "")
        }

        val scheme = extractScheme(trimmedUrl)
        if (scheme != "https") {
            return PolicyDecision.Block(
                reason = BlockReason.INSECURE_OR_INVALID_SCHEME,
                url = trimmedUrl,
                host = extractFallbackHost(trimmedUrl)
            )
        }

        val parsedUri = runCatching { URI(trimmedUrl) }.getOrNull()
        val rawHost = parsedUri?.host ?: extractFallbackHost(trimmedUrl)
        val host = rawHost.trim().trimEnd('.').lowercase(Locale.ROOT)
        if (host.isEmpty()) {
            return PolicyDecision.Block(BlockReason.INSECURE_OR_INVALID_SCHEME, trimmedUrl, "")
        }

        if (DomainExtractor.isIpLiteral(host)) {
            return PolicyDecision.Block(BlockReason.IP_LITERAL_NOT_ALLOWED, trimmedUrl, host)
        }

        val rawPath = parsedUri?.rawPath?.takeIf { it.isNotEmpty() } ?: extractFallbackPath(trimmedUrl)
        val rawQuery = parsedUri?.rawQuery
        val pathWithQuery = if (!rawQuery.isNullOrEmpty()) "$rawPath?$rawQuery" else rawPath
        val effectiveDomain = DomainExtractor.extractEffectiveDomain(host)

        // Media stream lockdown check
        if (MediaStreamBlocker.shouldBlockMediaRequest(trimmedUrl, requestHeaders, config)) {
            return PolicyDecision.Block(BlockReason.MEDIA_STREAM_BLOCKED, trimmedUrl, host)
        }

        val isExplicitlyAllowedOverride = isDomainInSet(host, effectiveDomain, config.allowedDomainsOverride)

        // Search engine / proxy check
        if (config.blockSearchEngines && !isExplicitlyAllowedOverride) {
            if (DefaultBaselineLists.isSearchEngineOrProxy(host, rawPath, config.searchEngineDomains)) {
                return PolicyDecision.Block(BlockReason.SEARCH_ENGINE_OR_PROXY, trimmedUrl, host)
            }
        }

        // Pluggable blocklists
        if (!isExplicitlyAllowedOverride) {
            val blocklistDecision = evaluateBlocklists(trimmedUrl, host, effectiveDomain, pathWithQuery, config)
            if (blocklistDecision != null) {
                return blocklistDecision
            }
        }

        // DoH check
        if (!isExplicitlyAllowedOverride && config.dnsMode != DnsMode.DISABLED) {
            val activeDohUrl = config.resolveActiveDohEndpointUrl()
            if (config.dnsMode == DnsMode.USER_DEFINED && activeDohUrl.isBlank()) {
                return PolicyDecision.Block(BlockReason.DNS_NOT_SELECTED, trimmedUrl, host)
            }
            if (activeDohUrl.isNotBlank()) {
                val dohVerdict = dohResolver.resolve(host)
                if (dohVerdict == DohVerdict.BLOCK) {
                    return PolicyDecision.Block(BlockReason.DOH_FAMILY_FILTER_BLOCK, trimmedUrl, host)
                }
            }
        }

        return PolicyDecision.Allow(
            url = trimmedUrl,
            host = host,
            effectiveDomain = effectiveDomain
        )
    }

    private fun evaluateBlocklists(
        url: String,
        host: String,
        effectiveDomain: String,
        pathWithQuery: String,
        config: BrowserPolicyConfig
    ): PolicyDecision.Block? {
        // 1. Developer-Injected Blocked TLDs (e.g. ".xxx", ".porn")
        if (config.blockedTlds.any { rawTld ->
                val tld = rawTld.trim().lowercase(Locale.ROOT).let {
                    if (it.startsWith(".")) it else ".$it"
                }
                tld.length > 1 && host.endsWith(tld)
            }
        ) {
            return PolicyDecision.Block(BlockReason.ADULT_BASELINE_BLOCK, url, host)
        }

        // 2. Developer-Injected Blocked Domains (exact domain + subdomain suffix match)
        if (isDomainInSet(host, effectiveDomain, config.blockedDomains)) {
            return PolicyDecision.Block(BlockReason.HOST_BLOCKLIST_DOMAIN, url, host)
        }

        // 3. Developer-Injected Blocked Host Keywords
        if (config.blockedHostKeywords.any { keyword ->
                val cleanKeyword = keyword.trim().lowercase(Locale.ROOT)
                cleanKeyword.isNotEmpty() && host.contains(cleanKeyword)
            }
        ) {
            return PolicyDecision.Block(BlockReason.HOST_BLOCKLIST_KEYWORD, url, host)
        }

        // 4. Developer-Injected Blocked Path Regexes
        if (config.compiledBlockedPathRegexes.any { regex ->
                regex.containsMatchIn(pathWithQuery)
            }
        ) {
            return PolicyDecision.Block(BlockReason.HOST_BLOCKLIST_PATH, url, host)
        }

        return null
    }

    private fun isDomainInSet(host: String, effectiveDomain: String, domainSet: Set<String>): Boolean {
        if (domainSet.isEmpty()) return false
        return domainSet.any { rawEntry ->
            val entry = rawEntry.trim().trimStart('.').trimEnd('.').lowercase(Locale.ROOT)
            entry.isNotEmpty() && (
                host == entry ||
                    effectiveDomain == entry ||
                    host.endsWith(".$entry")
                )
        }
    }

    private fun isAllowedCustomCallbackScheme(scheme: String, config: BrowserPolicyConfig): Boolean {
        val disallowedSchemes = setOf(
            "http", "https", "file", "javascript", "data", "content", "blob", "about", "intent", "market", "tel", "sms", "mailto"
        )
        if (scheme in disallowedSchemes) return false
        if (config.customCallbackSchemes.containsKey(scheme)) return false.not()
        return scheme.matches(Regex("^[a-z][a-z0-9+.-]*$"))
    }

    private fun extractScheme(url: String): String {
        val colonIndex = url.indexOf(':')
        if (colonIndex <= 0) return ""
        return url.substring(0, colonIndex).trim().lowercase(Locale.ROOT)
    }

    private fun extractFallbackHost(url: String): String {
        val afterScheme = url.substringAfter("://", "")
        return afterScheme
            .substringBefore('/')
            .substringBefore('?')
            .substringBefore('#')
            .substringBefore(':')
    }

    private fun extractFallbackPath(url: String): String {
        val afterScheme = url.substringAfter("://", "")
        val slashIndex = afterScheme.indexOf('/')
        if (slashIndex < 0) return "/"
        return afterScheme.substring(slashIndex).substringBefore('?').substringBefore('#')
    }
}
