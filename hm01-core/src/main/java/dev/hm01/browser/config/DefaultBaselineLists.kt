package dev.hm01.browser.config

import java.util.Locale

/**
 * Built-in baseline rules for `HM01`:
 * - Dedicated OAuth Identity Providers (IdPs), Payment Gateways & Captcha Hosts
 * - Path-scoped multi-purpose platforms (`google.*`, `facebook.com`, `github.com`, `*.firebaseapp.com`, `*.web.app`)
 * - Anti-Escape-Hatch search engine, translator, and archive mirror blockers
 * - Built-in Adult/NSFW TLDs and hostname keywords
 * - Known URL shorteners for Link Leash redirect resolution grace
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

    val GOOGLE_ALLOWED_OAUTH_PATH_PREFIXES: List<String> = listOf(
        "/o/oauth",
        "/signin",
        "/v3/signin",
        "/accounts/",
        "/servicelogin",
        "/checkcookie",
        "/mergesession",
        "/recaptcha"
    )

    val FACEBOOK_ALLOWED_OAUTH_PATH_REGEXES: List<Regex> = listOf(
        Regex("^/login.*", RegexOption.IGNORE_CASE),
        Regex("^/dialog/oauth.*", RegexOption.IGNORE_CASE),
        Regex("^/v[0-9.]+/dialog/oauth.*", RegexOption.IGNORE_CASE)
    )

    val GITHUB_ALLOWED_OAUTH_PATH_PREFIXES: List<String> = listOf(
        "/login",
        "/sessions",
        "/settings/two_factor"
    )

    val SEARCH_ENGINE_AND_PROXY_DOMAINS: Set<String> = setOf(
        "bing.com",
        "duckduckgo.com",
        "search.yahoo.com",
        "search.brave.com",
        "startpage.com",
        "kagi.com",
        "ecosia.org",
        "qwant.com",
        "baidu.com",
        "translate.google.com",
        "translate.goog",
        "archive.org",
        "web.archive.org",
        "archive.is",
        "archive.ph",
        "archive.today",
        "12ft.io"
    )

    val ADULT_TLDS: Set<String> = setOf(
        ".xxx",
        ".porn",
        ".sex",
        ".adult",
        ".cam",
        ".tube",
        ".webcam",
        ".sexy"
    )

    val ADULT_HOSTNAME_KEYWORDS: Set<String> = setOf(
        "porn",
        "xxx",
        "rule34",
        "hentai",
        "onlyfans",
        "fansly",
        "chaturbate",
        "redgifs",
        "xvideos",
        "xnxx",
        "pornhub",
        "xhamster",
        "youporn",
        "spankbang",
        "brazzers",
        "stripchat",
        "livejasmin",
        "myfreecams",
        "nsfw",
        "erome"
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
    private val YANDEX_DOMAIN_REGEX = Regex(
        "^(?:.*\\.)?yandex\\.(?:com|ru|ua|by|kz|uz|com\\.tr|[a-z]{2,3})$",
        RegexOption.IGNORE_CASE
    )
    private val SEARX_DOMAIN_REGEX = Regex(
        "^(?:.*\\.)?searx(?:ng)?\\.[a-z.]+$",
        RegexOption.IGNORE_CASE
    )

    /**
     * Checks whether [rawHost] is a dedicated Trusted Identity Provider, Payment Gateway, or Captcha host.
     */
    fun isDedicatedTrustedIdpOrPaymentOrCaptchaHost(rawHost: String): Boolean {
        val host = normalizeHost(rawHost)
        if (host.isEmpty()) return false
        if (host in EXACT_DEDICATED_IDP_PAYMENT_CAPTCHA_HOSTS) return true
        if (ACCOUNTS_GOOGLE_REGEX.matches(host)) return true
        return SUFFIX_DEDICATED_IDP_PAYMENT_CAPTCHA_HOSTS.any { suffix ->
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
        val path = (rawPath ?: "").lowercase(Locale.ROOT)
        if (isGoogleMultiPurposeHost(host) && path.startsWith("/recaptcha")) {
            return true
        }
        return false
    }

    /**
     * Result of evaluating a multi-purpose platform (`google.*`, `facebook.com`, `github.com`,
     * `*.firebaseapp.com`, `*.web.app`).
     */
    enum class ScopedPlatformResult {
        NOT_APPLICABLE,
        ALLOWED_SCOPED_OAUTH,
        BLOCKED_NON_OAUTH_PATH
    }

    /**
     * Evaluates path-scoped multi-purpose platforms:
     * - `google.*`: Only `/o/oauth...`, `/signin...`, `/v3/signin...`, `/accounts/...`, `/servicelogin...`,
     *   `/checkcookie...`, `/mergesession...`, `/recaptcha...`
     * - `facebook.com`: Only `/login...`, `/dialog/oauth...`, `/v.../dialog/oauth...`
     * - `github.com`: Only `/login...`, `/sessions...`, `/settings/two_factor...`
     * - `*.firebaseapp.com` / `*.web.app`: Only `/__/auth/...` (unless that exact tenant host is the
     *   initial link opened by the user)
     */
    fun evaluatePathScopedPlatform(
        rawHost: String,
        rawPath: String?,
        initialLandingHost: String? = null
    ): ScopedPlatformResult {
        val host = normalizeHost(rawHost)
        val path = (rawPath?.takeIf { it.isNotEmpty() } ?: "/").lowercase(Locale.ROOT)

        // 1. Google multi-purpose domains (excluding dedicated hosts like gds.google.com / translate.google.com)
        if (isGoogleMultiPurposeHost(host)) {
            val isAllowedPath = GOOGLE_ALLOWED_OAUTH_PATH_PREFIXES.any { prefix ->
                path.startsWith(prefix)
            }
            return if (isAllowedPath) {
                ScopedPlatformResult.ALLOWED_SCOPED_OAUTH
            } else {
                ScopedPlatformResult.BLOCKED_NON_OAUTH_PATH
            }
        }

        // 2. Facebook (facebook.com, www.facebook.com, m.facebook.com, web.facebook.com)
        if (host == "facebook.com" || host.endsWith(".facebook.com")) {
            val isAllowedPath = FACEBOOK_ALLOWED_OAUTH_PATH_REGEXES.any { regex ->
                regex.matches(path)
            }
            return if (isAllowedPath) {
                ScopedPlatformResult.ALLOWED_SCOPED_OAUTH
            } else {
                ScopedPlatformResult.BLOCKED_NON_OAUTH_PATH
            }
        }

        // 3. GitHub (github.com, www.github.com)
        if (host == "github.com" || host == "www.github.com") {
            val isAllowedPath = GITHUB_ALLOWED_OAUTH_PATH_PREFIXES.any { prefix ->
                path.startsWith(prefix)
            }
            return if (isAllowedPath) {
                ScopedPlatformResult.ALLOWED_SCOPED_OAUTH
            } else {
                ScopedPlatformResult.BLOCKED_NON_OAUTH_PATH
            }
        }

        // 4. Firebase Hosting (*.firebaseapp.com / *.web.app)
        if ((host.endsWith(".firebaseapp.com") && host.length > ".firebaseapp.com".length) ||
            (host.endsWith(".web.app") && host.length > ".web.app".length)
        ) {
            if (path.startsWith("/__/auth/")) {
                return ScopedPlatformResult.ALLOWED_SCOPED_OAUTH
            }
            val normalizedInitial = initialLandingHost?.let { normalizeHost(it) }
            return if (normalizedInitial != null && normalizedInitial == host) {
                // Exact tenant host was the initial link opened by the user
                ScopedPlatformResult.NOT_APPLICABLE
            } else {
                ScopedPlatformResult.BLOCKED_NON_OAUTH_PATH
            }
        }

        return ScopedPlatformResult.NOT_APPLICABLE
    }

    /**
     * Checks whether [rawHost] and [rawPath] match a blocked search engine, web translator, or web archive mirror.
     */
    fun isSearchEngineOrProxy(rawHost: String, rawPath: String? = null): Boolean {
        val host = normalizeHost(rawHost)
        if (host.isEmpty()) return false
        val path = (rawPath ?: "/").lowercase(Locale.ROOT)

        // Google search paths on any google.* domain
        if (isGoogleAnyHost(host) && (path.startsWith("/search") || path.startsWith("/url") || path.startsWith("/webhp"))) {
            return true
        }

        // Exact or subdomain match against SEARCH_ENGINE_AND_PROXY_DOMAINS
        if (SEARCH_ENGINE_AND_PROXY_DOMAINS.any { domain ->
                host == domain || host.endsWith(".$domain")
            }
        ) {
            return true
        }

        // Yandex and Searx wildcard TLD families
        if (YANDEX_DOMAIN_REGEX.matches(host) || SEARX_DOMAIN_REGEX.matches(host)) {
            return true
        }

        return false
    }

    /**
     * Checks whether [rawHost] matches the HM01 built-in Adult/NSFW TLD or hostname keyword list.
     */
    fun isBaselineAdultHost(rawHost: String): Boolean {
        val host = normalizeHost(rawHost)
        if (host.isEmpty()) return false

        if (ADULT_TLDS.any { tld -> host.endsWith(tld) }) {
            return true
        }

        return ADULT_HOSTNAME_KEYWORDS.any { keyword ->
            host.contains(keyword)
        }
    }

    /**
     * Checks whether [rawHost] is a known URL shortener that should receive redirect resolution grace.
     */
    fun isKnownUrlShortener(rawHost: String): Boolean {
        val host = normalizeHost(rawHost)
        if (host.isEmpty()) return false
        return KNOWN_URL_SHORTENERS.any { shortener ->
            host == shortener || host.endsWith(".$shortener")
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
        return rawHost.trim().trimEnd('.').lowercase(Locale.ROOT)
    }
}
