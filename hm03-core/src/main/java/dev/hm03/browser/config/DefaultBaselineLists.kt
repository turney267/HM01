package dev.hm03.browser.config

import dev.hm03.browser.filter.CanonicalUrl
import dev.hm03.browser.filter.DomainExtractor
import java.util.Locale

/**
 * Minimal baseline helpers for `HM03`:
 * - Dedicated OAuth Identity Providers (IdPs), Payment Gateways & Captcha Hosts
 * - Path-scoped platform evaluator driven by [BrowserPolicyConfig.pathScopedPlatformRules]
 * - URL shortener redirect grace helper driven by [BrowserPolicyConfig.urlShortenerDomains]
 *
 * Note: `HM03` does not hardcode website blocklists by default; host apps inject their own
 * domain, keyword, path, search-engine, and media lists via [BrowserPolicyConfig].
 */
object DefaultBaselineLists {

    val EXACT_DEDICATED_IDP_PAYMENT_CAPTCHA_HOSTS: Set<String> = setOf(
        // Google dedicated OAuth / identity hosts
        "gds.google.com",
        "oauthaccountmanager.googleapis.com",
        // Apple, Microsoft, Yahoo
        "appleid.apple.com",
        "idmsa.apple.com",
        "login.microsoftonline.com",
        "login.live.com",
        "login.yahoo.com",
        // Payment & Checkout
        "checkout.stripe.com",
        "hooks.stripe.com",
        "js.stripe.com",
        "www.paypal.com",
        "paypal.com",
        // Government SSO
        "mygovid.gov.au",
        "my.gov.au",
        "signin.account.gov.uk",
        "login.gov",
        "id.me",
        "api.id.me",
        // Captcha Providers
        "challenges.cloudflare.com"
    )

    val SUFFIX_DEDICATED_IDP_PAYMENT_CAPTCHA_HOSTS: Set<String> = setOf(
        ".auth0.com",
        ".okta.com",
        ".oktapreview.com",
        ".b2clogin.com",
        ".amazoncognito.com",
        ".clerk.accounts.dev",
        ".duosecurity.com",
        ".plaid.com",
        ".my.gov.au",
        ".singpass.gov.sg",
        ".realme.govt.nz",
        ".recaptcha.net",
        ".hcaptcha.com",
        ".arkoselabs.com",
        ".funcaptcha.com"
    )

    val CAPTCHA_HOST_SUFFIXES: Set<String> = setOf(
        "challenges.cloudflare.com",
        ".recaptcha.net",
        "recaptcha.net",
        ".hcaptcha.com",
        "hcaptcha.com",
        ".arkoselabs.com",
        "arkoselabs.com",
        ".funcaptcha.com",
        "funcaptcha.com"
    )

    val KNOWN_URL_SHORTENERS: Set<String> = setOf(
        "bit.ly",
        "bitly.com",
        "tinyurl.com",
        "t.co",
        "lnkd.in",
        "ow.ly",
        "buff.ly",
        "is.gd",
        "rb.gy",
        "cutt.ly",
        "shorturl.at",
        "tiny.cc",
        "rebrand.ly",
        "bl.ink",
        "snip.ly",
        "ift.tt",
        "dlvr.it",
        "fb.me",
        "amzn.to",
        "amzn.asia",
        "a.co",
        "g.co",
        "goo.gl"
    )

    private val GOOGLE_DOMAIN_REGEX = Regex(
        "^(?:www\\.|accounts\\.|m\\.)?google\\.(?:com|co|org|net|[a-z]{2})(?:\\.[a-z]{2})?$",
        RegexOption.IGNORE_CASE
    )
    private val ACCOUNTS_GOOGLE_REGEX = Regex(
        "^accounts\\.google\\.(?:com|co|org|net|[a-z]{2})(?:\\.[a-z]{2})?$",
        RegexOption.IGNORE_CASE
    )

    /**
     * Checks whether [rawHost] is a dedicated Trusted Identity Provider, Payment Gateway, or Captcha host.
     */
    fun isDedicatedTrustedIdpOrPaymentOrCaptchaHost(
        rawHost: String,
        config: BrowserPolicyConfig? = null
    ): Boolean {
        val host = normalizeHost(rawHost)
        if (host.isEmpty()) return false
        val exactSet = config?.trustedIdpAndPaymentHosts ?: EXACT_DEDICATED_IDP_PAYMENT_CAPTCHA_HOSTS
        val suffixSet = config?.trustedIdpAndPaymentSuffixes ?: SUFFIX_DEDICATED_IDP_PAYMENT_CAPTCHA_HOSTS
        if (host in exactSet) return true
        if (ACCOUNTS_GOOGLE_REGEX.matches(host)) return true
        return suffixSet.any { suffix ->
            host.endsWith(suffix) && host.length > suffix.length
        }
    }

    /**
     * Checks whether [rawHost] (and optional [rawPath]) is a known Captcha challenge host
     * where byte-range audio/challenge requests are permitted.
     */
    fun isCaptchaHost(rawHost: String, rawPath: String? = null): Boolean {
        val host = normalizeHost(rawHost)
        if (host.isEmpty()) return false
        if (CAPTCHA_HOST_SUFFIXES.any { suffix ->
                if (suffix.startsWith(".")) host.endsWith(suffix) && host.length > suffix.length
                else host == suffix
            }
        ) {
            return true
        }
        val path = (CanonicalUrl.normalizePathForPolicy(rawPath) ?: "").lowercase(Locale.ROOT)
        if (isGoogleMultiPurposeHost(host) && (path == "/recaptcha" || path.startsWith("/recaptcha/"))) {
            return true
        }
        return false
    }

    /**
     * Result of evaluating a path-scoped platform rule.
     */
    enum class ScopedPlatformResult {
        NOT_APPLICABLE,
        ALLOWED_SCOPED_OAUTH,
        BLOCKED_NON_OAUTH_PATH
    }

    /**
     * Evaluates [rawHost] and [rawPath] against the configured [rules] (`BrowserPolicyConfig.pathScopedPlatformRules`).
     */
    fun evaluatePathScopedPlatform(
        rawHost: String,
        rawPath: String?,
        initialLandingHost: String? = null,
        rules: List<PathScopedPlatformRule> = BrowserPolicyConfig.DEFAULT_EXAMPLE_PATH_SCOPED_RULES
    ): ScopedPlatformResult {
        val host = normalizeHost(rawHost)
        if (host.isEmpty() || rules.isEmpty()) return ScopedPlatformResult.NOT_APPLICABLE
        val normalizedPath = CanonicalUrl.normalizePathForPolicy(rawPath)?.lowercase(Locale.ROOT)

        for (rule in rules) {
            if (!matchesRuleDomain(host, rule.domain)) continue

            // If the path failed canonicalization (e.g. null byte or malformed percent-encoding), fail closed
            if (normalizedPath == null) {
                return ScopedPlatformResult.BLOCKED_NON_OAUTH_PATH
            }

            val matchesPrefix = rule.allowedPathPrefixes.any { prefix ->
                val cleanPrefix = prefix.trim().lowercase(Locale.ROOT)
                cleanPrefix.isNotEmpty() && normalizedPath.startsWith(cleanPrefix)
            }
            val matchesRegex = rule.compiledAllowedPathRegexes.any { regex ->
                regex.matches(normalizedPath)
            }

            if (matchesPrefix || matchesRegex) {
                return ScopedPlatformResult.ALLOWED_SCOPED_OAUTH
            }

            if (rule.allowIfInitialLandingHost) {
                val normalizedInitial = initialLandingHost?.let { normalizeHost(it) }
                if (normalizedInitial != null && normalizedInitial == host) {
                    return ScopedPlatformResult.NOT_APPLICABLE
                }
            }

            return ScopedPlatformResult.BLOCKED_NON_OAUTH_PATH
        }

        return ScopedPlatformResult.NOT_APPLICABLE
    }

    private fun matchesRuleDomain(host: String, patternRaw: String): Boolean {
        val pattern = patternRaw.trim().lowercase(Locale.ROOT)
        if (pattern.isEmpty()) return false
        if (pattern == "google.*") {
            return isGoogleMultiPurposeHost(host)
        }
        if (pattern.startsWith("*.")) {
            val suffix = pattern.removePrefix("*") // e.g. ".firebaseapp.com"
            return host.endsWith(suffix) && host.length > suffix.length
        }
        return host == pattern || host == "www.$pattern" || host.endsWith(".$pattern")
    }

    /**
     * Checks whether [rawHost] and [rawPath] match any developer-configured search engine or proxy domain.
     */
    fun isSearchEngineOrProxy(
        rawHost: String,
        rawPath: String? = null,
        searchDomains: Set<String> = emptySet()
    ): Boolean {
        val host = normalizeHost(rawHost)
        if (host.isEmpty()) return false
        val path = (CanonicalUrl.normalizePathForPolicy(rawPath) ?: rawPath ?: "/").lowercase(Locale.ROOT)

        // If google.* or search engine domains are configured, check Google search paths
        if (searchDomains.isNotEmpty() &&
            isGoogleAnyHost(host) &&
            (path.startsWith("/search") || path.startsWith("/url") || path.startsWith("/webhp"))
        ) {
            return true
        }

        if (searchDomains.any { rawDomain ->
                val domain = normalizeHost(rawDomain)
                domain.isNotEmpty() && (host == domain || host.endsWith(".$domain"))
            }
        ) {
            return true
        }

        return false
    }

    /**
     * Checks whether [rawHost] is a URL shortener in [shortenerDomains] that should receive redirect resolution grace.
     */
    fun isKnownUrlShortener(
        rawHost: String,
        shortenerDomains: Set<String> = KNOWN_URL_SHORTENERS
    ): Boolean {
        val host = normalizeHost(rawHost)
        if (host.isEmpty()) return false
        return shortenerDomains.any { shortener ->
            val clean = normalizeHost(shortener)
            clean.isNotEmpty() && (host == clean || host.endsWith(".$clean"))
        }
    }

    fun isGoogleMultiPurposeHost(rawHost: String): Boolean {
        val host = normalizeHost(rawHost)
        return GOOGLE_DOMAIN_REGEX.matches(host)
    }

    private fun isGoogleAnyHost(host: String): Boolean {
        return GOOGLE_DOMAIN_REGEX.matches(host) ||
            host.contains(".google.") ||
            host.startsWith("google.")
    }

    internal fun normalizeHost(rawHost: String): String {
        return DomainExtractor.normalizeHost(rawHost)
    }
}
