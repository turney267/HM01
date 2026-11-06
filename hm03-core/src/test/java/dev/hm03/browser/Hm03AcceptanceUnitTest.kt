package dev.hm03.browser

import dev.hm03.browser.config.BrowserPolicyConfig
import dev.hm03.browser.config.BrowserPolicyProvider
import dev.hm03.browser.config.CustomSchemeTarget
import dev.hm03.browser.config.DnsMode
import dev.hm03.browser.config.DnsProviderOption
import dev.hm03.browser.config.PathScopedPlatformRule
import dev.hm03.browser.dns.DohDecisionCache
import dev.hm03.browser.dns.DohResolver
import dev.hm03.browser.dns.DohVerdict
import dev.hm03.browser.filter.BlockReason
import dev.hm03.browser.filter.CanonicalUrl
import dev.hm03.browser.filter.DomainExtractor
import dev.hm03.browser.filter.MediaStreamBlocker
import dev.hm03.browser.filter.PolicyDecision
import dev.hm03.browser.filter.UrlPolicyEvaluator
import dev.hm03.browser.ui.BlockedPageRenderer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Comprehensive unit tests verifying all 7 acceptance test scenarios in `HM03_Spec.md`
 * plus security regression tests for findings `HM03-01` through `HM03-15`.
 */
class Hm03AcceptanceUnitTest {

    // =========================================================================
    // Scenario 1: CleanBrowsing Family Filter DoH Enforcement & Coalesced Cache
    // =========================================================================

    @Test
    fun scenario1_cleanBrowsingDohWireformatAndCaching() {
        val cache = DohDecisionCache(maxEntries = 100, defaultTtlMs = 60_000L)
        val networkCalls = AtomicInteger(0)

        val fakeResolver = DohResolver(
            configProvider = { BrowserPolicyConfig(customDohUrl = "https://dns.example.com/dns-query") },
            cache = cache,
            transport = { _, queryPacket, _ ->
                networkCalls.incrementAndGet()
                val qname = extractQueryName(queryPacket)
                when {
                    qname == "adult-filter-test.cleanbrowsing.org" -> {
                        // Return CleanBrowsing sinkhole IP 185.228.168.10
                        buildMockDnsAResponse(qname, rcode = 0, ip = intArrayOf(185, 228, 168, 10))
                    }
                    qname.contains("nxdomain") -> {
                        // Return RCODE == 3 (NXDOMAIN)
                        buildMockDnsAResponse(qname, rcode = 3, ip = null)
                    }
                    else -> {
                        // Return valid public IP 104.18.20.30
                        buildMockDnsAResponse(qname, rcode = 0, ip = intArrayOf(104, 18, 20, 30))
                    }
                }
            }
        )

        // 1. Blocked adult/CleanBrowsing test domain -> BLOCK
        assertEquals(DohVerdict.BLOCK, fakeResolver.resolve("adult-filter-test.cleanbrowsing.org"))
        assertEquals(1, networkCalls.get())

        // 2. Legitimate retail domain -> ALLOW and cached
        assertEquals(DohVerdict.ALLOW, fakeResolver.resolve("kmart.com.au"))
        assertEquals(2, networkCalls.get())

        // Second lookup for kmart.com.au hits the LRU+TTL cache without a network request
        assertEquals(DohVerdict.ALLOW, fakeResolver.resolve("kmart.com.au"))
        assertEquals(2, networkCalls.get())

        // 3. NXDOMAIN -> BLOCK
        assertEquals(DohVerdict.BLOCK, fakeResolver.resolve("bad-nxdomain.example.com"))
        assertEquals(3, networkCalls.get())
    }

    @Test
    fun scenario1_coalescedInFlightDohLookups() {
        val cache = DohDecisionCache()
        val lookupCounter = AtomicInteger(0)
        val startGate = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(15)

        try {
            val futures = (1..15).map {
                executor.submit<DohVerdict> {
                    startGate.await(2, TimeUnit.SECONDS)
                    cache.getOrCompute("cdn.shopify.com") {
                        lookupCounter.incrementAndGet()
                        Thread.sleep(80)
                        DohVerdict.ALLOW
                    }
                }
            }

            startGate.countDown()
            val verdicts = futures.map { it.get(5, TimeUnit.SECONDS) }

            assertTrue(verdicts.all { it == DohVerdict.ALLOW })
            assertEquals(
                "15 simultaneous requests for cdn.shopify.com must coalesce into 1 DoH request",
                1,
                lookupCounter.get()
            )
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun scenario1_cleanBrowsingSoaSinkholeDetection() {
        val packet = buildMockDnsSoaSinkholeResponse(
            qname = "blocked-site.example",
            soaMname = "cleanbrowsing.rpz.noc.org"
        )
        assertEquals(DohVerdict.BLOCK, DohResolver.parseDnsResponseVerdict(packet))
    }

    @Test
    fun scenario1_userDefinedDnsModeRequiresSelection() {
        BrowserPolicyProvider.reset()
        val options = listOf(
            DnsProviderOption("example_dns", "Example DNS", "https://dns.example.com/dns-query")
        )
        BrowserPolicyProvider.configure(
            BrowserPolicyConfig(
                dnsMode = DnsMode.USER_DEFINED,
                userDnsOptions = options
            )
        )

        val evaluator = UrlPolicyEvaluator(
            configProvider = { BrowserPolicyProvider.getConfig() },
            dohResolver = createAllowAllDohResolver()
        )

        // Before the user selects a DNS provider, navigation must be blocked with DNS_NOT_SELECTED
        val unselectedDecision = evaluator.evaluateMainFrameNavigation(
            "https://ikea.com",
            isInitialLaunch = true
        )
        assertTrue(unselectedDecision is PolicyDecision.Block)
        assertEquals(BlockReason.DNS_NOT_SELECTED, (unselectedDecision as PolicyDecision.Block).reason)

        // Once the user selects a DNS option, navigation is allowed
        BrowserPolicyProvider.setUserSelectedDns(
            context = null,
            optionId = "example_dns",
            dohEndpointUrl = "https://dns.example.com/dns-query"
        )
        evaluator.resetSession()
        val selectedDecision = evaluator.evaluateMainFrameNavigation(
            "https://ikea.com",
            isInitialLaunch = true
        )
        assertTrue(selectedDecision is PolicyDecision.Allow)
        BrowserPolicyProvider.reset()
    }

    // =========================================================================
    // Scenario 2: Spouse Gift Link Flow (Shortener Redirect, Same-Domain, 1 Hop, Video Block)
    // =========================================================================

    @Test
    fun scenario2_spouseGiftLinkFlowWithShortenerAndMediaLockdown() {
        val config = BrowserPolicyConfig(
            maxExternalDomainHops = 1,
            blockVideoAndAudio = true,
            blockedMediaExtensions = setOf(".mp4"),
            blockedSecFetchDests = setOf("video", "audio")
        )
        val evaluator = UrlPolicyEvaluator(
            configProvider = { config },
            dohResolver = createAllowAllDohResolver()
        )

        // 1. User taps a shortened gift link (https://bit.ly/spouse-gift)
        val shortenerDecision = evaluator.evaluateMainFrameNavigation(
            rawUrl = "https://bit.ly/spouse-gift",
            isInitialLaunch = true
        )
        assertTrue(shortenerDecision is PolicyDecision.Allow)
        assertNull("Shortener should not lock in as landing domain", evaluator.landingEffectiveDomain)

        // 2. Shortener redirects to https://www.kmart.com.au/product/coffee-maker
        val landingDecision = evaluator.evaluateMainFrameNavigation(
            rawUrl = "https://www.kmart.com.au/product/coffee-maker",
            isInitialLaunch = false,
            isServerRedirect = true
        )
        assertTrue(landingDecision is PolicyDecision.Allow)
        assertEquals("kmart.com.au", evaluator.landingEffectiveDomain)
        assertEquals(0, evaluator.externalDomainHops)
        evaluator.markRedirectGraceComplete()

        // 3. Product images from Kmart or CDN load normally
        val imageDecision = evaluator.evaluateSubResourceRequest(
            rawUrl = "https://cdn.kmart.com.au/images/coffee-maker.webp",
            requestHeaders = mapOf("Accept" to "image/webp,image/apng,image/*,*/*;q=0.8")
        )
        assertTrue(imageDecision is PolicyDecision.Allow)

        // 4. Clicking another product on the same store domain (kmart.com.au) works at 0 external hops
        val secondProductDecision = evaluator.evaluateMainFrameNavigation(
            rawUrl = "https://shop.kmart.com.au/product/mug-set"
        )
        assertTrue(secondProductDecision is PolicyDecision.Allow)
        assertEquals(0, evaluator.externalDomainHops)

        // 5. Embedded <video> / .mp4 / video/* headers on the product page are blocked
        val mp4SubDecision = evaluator.evaluateSubResourceRequest(
            rawUrl = "https://cdn.kmart.com.au/videos/promo.mp4"
        )
        assertTrue(mp4SubDecision is PolicyDecision.Block)
        assertEquals(
            BlockReason.MEDIA_STREAM_BLOCKED,
            (mp4SubDecision as PolicyDecision.Block).reason
        )

        val videoHeaderDecision = evaluator.evaluateSubResourceRequest(
            rawUrl = "https://cdn.kmart.com.au/stream/12345",
            requestHeaders = mapOf("Sec-Fetch-Dest" to "video")
        )
        assertTrue(videoHeaderDecision is PolicyDecision.Block)

        // 6. Outbound manufacturer/reference link (1st external domain hop) is allowed
        val hop1Decision = evaluator.evaluateMainFrameNavigation(
            rawUrl = "https://www.breville.com.au/specs/barista"
        )
        assertTrue(hop1Decision is PolicyDecision.Allow)
        assertEquals(1, evaluator.externalDomainHops)

        // 7. Clicking to a 2nd distinct external domain is blocked by the Link Leash
        val hop2Decision = evaluator.evaluateMainFrameNavigation(
            rawUrl = "https://www.coffee-forums.org/threads/123"
        )
        assertTrue(hop2Decision is PolicyDecision.Block)
        assertEquals(
            BlockReason.LINK_LEASH_HOP_LIMIT_EXCEEDED,
            (hop2Decision as PolicyDecision.Block).reason
        )
    }

    // =========================================================================
    // Scenario 3: Search Engine & Proxy Escape Prevention
    // =========================================================================

    @Test
    fun scenario3_searchEngineEscapePrevention() {
        val config = BrowserPolicyConfig(
            searchEngineDomains = setOf(
                "bing.com",
                "duckduckgo.com",
                "search.brave.com",
                "kagi.com",
                "translate.google.com",
                "translate.goog",
                "web.archive.org",
                "12ft.io"
            ),
            pathScopedPlatformRules = listOf(
                PathScopedPlatformRule(
                    domain = "google.*",
                    allowedPathPrefixes = listOf("/o/oauth", "/signin", "/v3/signin")
                )
            )
        )
        val evaluator = UrlPolicyEvaluator(
            configProvider = { config },
            dohResolver = createAllowAllDohResolver()
        )

        // Open legitimate page first
        assertTrue(
            evaluator.evaluateMainFrameNavigation(
                "https://www.ikea.com/au/en/p/billy-bookcase/",
                isInitialLaunch = true
            ) is PolicyDecision.Allow
        )
        evaluator.markRedirectGraceComplete()

        val escapeUrls = listOf(
            "https://www.google.com/search?q=news",
            "https://www.google.com.au/search?q=reddit",
            "https://duckduckgo.com/?q=test",
            "https://www.bing.com/search?q=weather",
            "https://search.brave.com/search?q=test",
            "https://kagi.com/search?q=test",
            "https://translate.google.com/?sl=auto&tl=en",
            "https://example-com.translate.goog/",
            "https://web.archive.org/web/2025/https://news.com",
            "https://12ft.io/https://news.com"
        )

        for (escapeUrl in escapeUrls) {
            val decision = evaluator.evaluateMainFrameNavigation(escapeUrl)
            assertTrue("Expected $escapeUrl to be blocked", decision is PolicyDecision.Block)
            val reason = (decision as PolicyDecision.Block).reason
            assertTrue(
                "Unexpected block reason $reason for $escapeUrl",
                reason == BlockReason.SEARCH_ENGINE_OR_PROXY ||
                    reason == BlockReason.NON_OAUTH_PLATFORM_PATH
            )
        }
    }

    // =========================================================================
    // Scenario 4: OAuth & Passkey / 2FA Sign-In Flow
    // =========================================================================

    @Test
    fun scenario4_oauthAndPasskeySignInFlowAndUserAgentSanitization() {
        // Verify default BrowserPolicyConfig contains only the single example github.com rule
        val defaultConfig = BrowserPolicyConfig()
        assertEquals(1, defaultConfig.pathScopedPlatformRules.size)
        assertEquals("github.com", defaultConfig.pathScopedPlatformRules.first().domain)
        assertEquals(setOf(".mp4"), defaultConfig.blockedMediaExtensions)
        assertTrue(defaultConfig.blockedDomains.isEmpty())
        assertTrue(defaultConfig.failClosedOnDnsError)
        assertFalse(defaultConfig.allowUnregisteredCustomSchemes)
        assertFalse(defaultConfig.allowThirdPartyIframes)

        val evaluator = UrlPolicyEvaluator(
            configProvider = {
                BrowserPolicyConfig(
                    pathScopedPlatformRules = listOf(
                        PathScopedPlatformRule(
                            domain = "github.com",
                            allowedPathPrefixes = listOf("/login", "/sessions", "/settings/two_factor")
                        ),
                        PathScopedPlatformRule(
                            domain = "google.*",
                            allowedPathPrefixes = listOf("/o/oauth", "/signin", "/v3/signin", "/accounts/")
                        ),
                        PathScopedPlatformRule(
                            domain = "facebook.com",
                            allowedPathRegexes = listOf("^/login.*", "^/dialog/oauth.*", "^/v[0-9.]+/dialog/oauth.*")
                        )
                    ),
                    customCallbackSchemes = mapOf(
                        "exampleapp" to CustomSchemeTarget("exampleapp", "com.example.app")
                    )
                )
            },
            dohResolver = createAllowAllDohResolver()
        )

        // 1. Google OAuth sign-in paths & regional accounts.google.<ccTLD> cookie/session endpoints are allowed
        val googleOAuth = evaluator.evaluateMainFrameNavigation(
            "https://accounts.google.com/o/oauth2/v2/auth?client_id=123&redirect_uri=exampleapp://oauth",
            isInitialLaunch = true
        )
        assertTrue(googleOAuth is PolicyDecision.Allow)
        assertTrue((googleOAuth as PolicyDecision.Allow).isTrustedIdpOrScopedOAuth)

        val longToken = "A".repeat(2600)
        for (regionalAuthUrl in listOf(
            "https://accounts.google.com.au/accounts/SetSID?ssdc=1&sidt=$longToken",
            "https://accounts.google.com.au/CookieMismatch?continue=$longToken",
            "https://accounts.google.com.au/InteractiveLogin",
            "https://accounts.google.com/_/signin/challenge",
            "https://accounts.youtube.com/accounts/SetSID?ssdc=1&sidt=$longToken",
            "https://accounts.youtube.com/accounts/CheckConnection?pmpo=https://accounts.google.com"
        )) {
            val regionalDecision = evaluator.evaluateMainFrameNavigation(regionalAuthUrl)
            assertTrue("Expected $regionalAuthUrl to be allowed", regionalDecision is PolicyDecision.Allow)
            assertTrue((regionalDecision as PolicyDecision.Allow).isTrustedIdpOrScopedOAuth)
        }

        // 2. Facebook OAuth dialog is allowed
        val fbOAuth = evaluator.evaluateMainFrameNavigation(
            "https://www.facebook.com/v18.0/dialog/oauth?client_id=abc"
        )
        assertTrue(fbOAuth is PolicyDecision.Allow)

        // 3. Facebook feed / home is strictly blocked
        val fbFeed = evaluator.evaluateMainFrameNavigation(
            "https://www.facebook.com/watch"
        )
        assertTrue(fbFeed is PolicyDecision.Block)
        assertEquals(BlockReason.NON_OAUTH_PLATFORM_PATH, (fbFeed as PolicyDecision.Block).reason)

        // 4. GitHub login & 2FA allowed, GitHub repo exploration blocked
        assertTrue(
            evaluator.evaluateMainFrameNavigation("https://github.com/login/oauth/authorize")
                is PolicyDecision.Allow
        )
        assertTrue(
            evaluator.evaluateMainFrameNavigation("https://github.com/settings/two_factor")
                is PolicyDecision.Allow
        )
        val ghExplore = evaluator.evaluateMainFrameNavigation("https://github.com/trending")
        assertTrue(ghExplore is PolicyDecision.Block)
        assertEquals(BlockReason.NON_OAUTH_PLATFORM_PATH, (ghExplore as PolicyDecision.Block).reason)

        // 5. Custom callback scheme handoff (exampleapp://oauth?code=xyz)
        val callbackDecision = evaluator.evaluateMainFrameNavigation(
            "exampleapp://oauth?code=xyz123"
        )
        assertTrue(callbackDecision is PolicyDecision.HandOffToNativeApp)
        assertEquals(
            "com.example.app",
            (callbackDecision as PolicyDecision.HandOffToNativeApp).targetPackage
        )

        // 6. User-Agent sanitization strips "; wv" and "Version/4.0"
        val rawWebViewUa =
            "Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/UQ1A.240205.004; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/122.0.6261.64 Mobile Safari/537.36"
        val sanitizedUa = MinimalCustomTabsService.sanitizeCustomTabUserAgent(rawWebViewUa)
        assertFalse("Sanitized UA must not contain '; wv'", sanitizedUa.contains("; wv"))
        assertFalse("Sanitized UA must not contain 'Version/4.0'", sanitizedUa.contains("Version/4.0"))
        assertTrue(sanitizedUa.contains("Chrome/122.0.6261.64"))
    }

    // =========================================================================
    // Scenario 5: Attention-Hog Blocklist Injection (Host App Integration)
    // =========================================================================

    @Test
    fun scenario5_attentionHogBlocklistInjection() {
        val hostConfig = BrowserPolicyConfig(
            brandTitle = "Safe Link Viewer",
            blockedDomains = setOf("substack.com", "reddit.com", "news.ycombinator.com"),
            blockedHostKeywords = setOf(" tabloid ", "gossip"),
            blockedPathRegexes = listOf("^/reels(/|$)", "^/shorts(/|$)", "^/r/")
        )

        val evaluator = UrlPolicyEvaluator(
            configProvider = { hostConfig },
            dohResolver = createAllowAllDohResolver()
        )

        // 1. Direct intent launch to substack.com or subdomain newsletter.substack.com is blocked
        val substackDirect = evaluator.evaluateMainFrameNavigation(
            "https://newsletter.substack.com/p/weekly-digest",
            isInitialLaunch = true
        )
        assertTrue(substackDirect is PolicyDecision.Block)
        assertEquals(BlockReason.HOST_BLOCKLIST_DOMAIN, (substackDirect as PolicyDecision.Block).reason)

        // 2. Open allowed retail site, then click in-page link to reddit.com or news.ycombinator.com -> blocked
        evaluator.resetSession()
        assertTrue(
            evaluator.evaluateMainFrameNavigation(
                "https://www.kmart.com.au/product/1",
                isInitialLaunch = true
            ) is PolicyDecision.Allow
        )
        evaluator.markRedirectGraceComplete()

        val redditLink = evaluator.evaluateMainFrameNavigation("https://old.reddit.com/r/android")
        assertTrue(redditLink is PolicyDecision.Block)
        assertEquals(BlockReason.HOST_BLOCKLIST_DOMAIN, (redditLink as PolicyDecision.Block).reason)

        val hnLink = evaluator.evaluateMainFrameNavigation("https://news.ycombinator.com/item?id=1")
        assertTrue(hnLink is PolicyDecision.Block)
        assertEquals(BlockReason.HOST_BLOCKLIST_DOMAIN, (hnLink as PolicyDecision.Block).reason)

        // 3. Blocked keyword match
        val gossipLink = evaluator.evaluateMainFrameNavigation("https://dailygossip.com.au/story")
        assertTrue(gossipLink is PolicyDecision.Block)
        assertEquals(BlockReason.HOST_BLOCKLIST_KEYWORD, (gossipLink as PolicyDecision.Block).reason)

        // 4. Blocked path regex match (/shorts or /reels)
        val shortsLink = evaluator.evaluateMainFrameNavigation("https://www.kmart.com.au/shorts/123")
        assertTrue(shortsLink is PolicyDecision.Block)
        assertEquals(BlockReason.HOST_BLOCKLIST_PATH, (shortsLink as PolicyDecision.Block).reason)
    }

    // =========================================================================
    // Scenario 6: Multi-Tenant Cloud Isolation & IP-Literal Blocking
    // =========================================================================

    @Test
    fun scenario6_multiTenantCloudIsolationAndCcTlds() {
        assertEquals(
            "my-school-event.vercel.app",
            DomainExtractor.extractEffectiveDomain("my-school-event.vercel.app")
        )
        assertEquals(
            "my-school-event.vercel.app",
            DomainExtractor.extractEffectiveDomain("api.my-school-event.vercel.app")
        )
        assertEquals(
            "other-site.vercel.app",
            DomainExtractor.extractEffectiveDomain("other-site.vercel.app")
        )
        assertEquals(
            "kmart.com.au",
            DomainExtractor.extractEffectiveDomain("www.kmart.com.au")
        )
        assertEquals(
            "bbc.co.uk",
            DomainExtractor.extractEffectiveDomain("news.bbc.co.uk")
        )

        val evaluator = UrlPolicyEvaluator(
            configProvider = { BrowserPolicyConfig(maxExternalDomainHops = 1) },
            dohResolver = createAllowAllDohResolver()
        )

        // 1. Open https://my-school-event.vercel.app
        val initial = evaluator.evaluateMainFrameNavigation(
            "https://my-school-event.vercel.app/schedule",
            isInitialLaunch = true
        )
        assertTrue(initial is PolicyDecision.Allow)
        evaluator.markRedirectGraceComplete()
        assertEquals("my-school-event.vercel.app", evaluator.landingEffectiveDomain)
        assertEquals(0, evaluator.externalDomainHops)

        // 2. Navigating within my-school-event.vercel.app stays at 0 external hops
        val sameTenant = evaluator.evaluateMainFrameNavigation(
            "https://my-school-event.vercel.app/tickets"
        )
        assertTrue(sameTenant is PolicyDecision.Allow)
        assertEquals(0, evaluator.externalDomainHops)

        // 3. Navigating to https://other-site.vercel.app counts as external domain hop #1
        val otherTenant = evaluator.evaluateMainFrameNavigation(
            "https://other-site.vercel.app/"
        )
        assertTrue(otherTenant is PolicyDecision.Allow)
        assertEquals(1, evaluator.externalDomainHops)

        // 4. Navigating to a third tenant https://third-site.vercel.app is blocked (hop #2 > 1)
        val thirdTenant = evaluator.evaluateMainFrameNavigation(
            "https://third-site.vercel.app/"
        )
        assertTrue(thirdTenant is PolicyDecision.Block)
        assertEquals(
            BlockReason.LINK_LEASH_HOP_LIMIT_EXCEEDED,
            (thirdTenant as PolicyDecision.Block).reason
        )

        // 5. Raw IP literals (IPv4, IPv6, hex, octal, dword) are blocked
        assertTrue(DomainExtractor.isIpLiteral("1.2.3.4"))
        assertTrue(DomainExtractor.isIpLiteral("[2606:4700:4700::1111]"))
        assertTrue(DomainExtractor.isIpLiteral("0x7f.0.0.1"))
        assertTrue(DomainExtractor.isIpLiteral("0177.0.0.1"))
        assertTrue(DomainExtractor.isIpLiteral("2130706433"))
        assertFalse(DomainExtractor.isIpLiteral("kmart.com.au"))

        val ipDecision = evaluator.evaluateMainFrameNavigation("https://1.1.1.1/dns-query")
        assertTrue(ipDecision is PolicyDecision.Block)
        assertEquals(BlockReason.IP_LITERAL_NOT_ALLOWED, (ipDecision as PolicyDecision.Block).reason)
    }

    // =========================================================================
    // Scenario 7: Ephemeral Cleanup & Blocked Screen XSS Safety
    // =========================================================================

    @Test
    fun scenario7_ephemeralCleanupAndBlockedPageRendering() {
        val blockDecision = PolicyDecision.Block(
            reason = BlockReason.HOST_BLOCKLIST_DOMAIN,
            url = "https://evil.example.com/<script>alert(1)</script>",
            host = "evil.example.com\"><script>alert(1)</script>"
        )
        val html = BlockedPageRenderer.buildBlockedHtml(
            blockDecision,
            BrowserPolicyConfig(brandTitle = "Safe Link Viewer")
        )
        assertTrue(html.contains("Safe Link Viewer Policy"))
        assertTrue(html.contains("Blocked Website"))
        assertFalse("Blocked HTML must escape script tags", html.contains("<script>"))
        assertTrue(html.contains("&lt;script&gt;"))

        val jsLockdown = MediaStreamBlocker.buildLockdownJavascript(
            BrowserPolicyConfig(blockVideoAndAudio = true, capImageDimensions = false)
        )
        assertTrue(jsLockdown.contains("HTMLMediaElement.prototype.play"))
        assertTrue(jsLockdown.contains("window.MediaSource"))
        assertTrue(jsLockdown.contains("window.RTCPeerConnection"))

        // Verify wipeEphemeralWebData executes safely without throwing when invoked headless in JVM tests
        // in both ephemeral (default) and persistent-cookies modes.
        IntentBrowserActivity.wipeEphemeralWebData(context = null, webView = null)
        IntentBrowserActivity.wipeEphemeralWebData(
            context = null,
            webView = null,
            persistCookiesAndStorage = true
        )

        val defaultConfig = BrowserPolicyConfig()
        assertFalse(defaultConfig.persistCookiesAndStorage)
        val persistentConfig = defaultConfig.withPersistentCookiesAndStorage()
        assertTrue(persistentConfig.persistCookiesAndStorage)
        assertFalse(persistentConfig.withPersistentCookiesAndStorage(false).persistCookiesAndStorage)
    }

    // =========================================================================
    // Security Regression Suite (HM03-01 through HM03-15)
    // =========================================================================

    @Test
    fun securityRegression_hm03_01_urlParserDifferentialAndIdnCanonicalization() {
        val config = BrowserPolicyConfig(
            blockedDomains = setOf("reddit.com", "evil.example")
        )
        val evaluator = UrlPolicyEvaluator(
            configProvider = { config },
            dohResolver = createAllowAllDohResolver()
        )

        // 1. Userinfo (@) authority confusion with WHATWG fallback triggers must be strictly rejected
        val userinfoAttacks = listOf(
            "https://accounts.google.com:443@evil.example/?q=|",
            "https://kmart.com.au:443@reddit.com/r/all?x={1}",
            "https://github.com@evil.example/login",
            "https://user%40evil.example@kmart.com.au/",
            "https://kmart.com.au\\@evil.example/path",
            "https://kmart.com.au\\evil.example/path"
        )
        for (attackUrl in userinfoAttacks) {
            val decision = evaluator.evaluateMainFrameNavigation(attackUrl, isInitialLaunch = true)
            assertTrue("Expected $attackUrl to be blocked", decision is PolicyDecision.Block)
            assertEquals(
                BlockReason.INSECURE_OR_INVALID_SCHEME,
                (decision as PolicyDecision.Block).reason
            )
        }

        // 2. Fullwidth dot separator (\u3002, \uFF0E, \uFF61) must normalize to '.' and match blocklists
        val fullwidthReddit = evaluator.evaluateMainFrameNavigation(
            "https://www\u3002reddit\uFF0Ecom/r/android",
            isInitialLaunch = true
        )
        assertTrue(fullwidthReddit is PolicyDecision.Block)
        assertEquals(BlockReason.HOST_BLOCKLIST_DOMAIN, (fullwidthReddit as PolicyDecision.Block).reason)

        // 3. Unicode IDN converts to ASCII Punycode in canonical URL
        val idnParsed = CanonicalUrl.parseHttpOrHttps("https://münchen.de/rathaus")
        assertNotNull(idnParsed)
        assertEquals("xn--mnchen-3ya.de", idnParsed!!.host)
        assertEquals("https://xn--mnchen-3ya.de/rathaus", idnParsed.canonicalUrlString)

        // 4. Legitimate URLs containing WHATWG query characters ('|', '{', '}') still work cleanly
        val validPipeQuery = evaluator.evaluateMainFrameNavigation(
            "https://www.kmart.com.au/search?facets=color|blue",
            isInitialLaunch = true
        )
        assertTrue(validPipeQuery is PolicyDecision.Allow)
    }

    @Test
    fun securityRegression_hm03_02_mainFrameHttpPostInterception() {
        val config = BrowserPolicyConfig(
            blockedDomains = setOf("reddit.com"),
            maxExternalDomainHops = 1
        )
        val evaluator = UrlPolicyEvaluator(
            configProvider = { config },
            dohResolver = createAllowAllDohResolver()
        )

        // Establish initial landing domain (kmart.com.au)
        assertTrue(
            evaluator.evaluateMainFrameNavigation(
                "https://www.kmart.com.au/login",
                isInitialLaunch = true
            ) is PolicyDecision.Allow
        )
        evaluator.markRedirectGraceComplete()

        // 1. Same-domain POST form submission is allowed
        val sameDomainPost = evaluator.evaluateMainFrameInterceptRequest(
            rawUrl = "https://www.kmart.com.au/auth/submit",
            method = "POST"
        )
        assertTrue(sameDomainPost is PolicyDecision.Allow)

        // 2. POST navigation to a blocked domain is blocked
        val blockedDomainPost = evaluator.evaluateMainFrameInterceptRequest(
            rawUrl = "https://www.reddit.com/login",
            method = "POST"
        )
        assertTrue(blockedDomainPost is PolicyDecision.Block)
        assertEquals(BlockReason.HOST_BLOCKLIST_DOMAIN, (blockedDomainPost as PolicyDecision.Block).reason)

        // 3. POST navigation to 1st external domain counts as hop #1, and 2nd external POST is blocked by Link Leash
        val hop1Post = evaluator.evaluateMainFrameInterceptRequest(
            rawUrl = "https://www.breville.com.au/register",
            method = "POST"
        )
        assertTrue(hop1Post is PolicyDecision.Allow)
        assertEquals(1, evaluator.externalDomainHops)

        val hop2Post = evaluator.evaluateMainFrameInterceptRequest(
            rawUrl = "https://www.other-external-site.org/form",
            method = "POST"
        )
        assertTrue(hop2Post is PolicyDecision.Block)
        assertEquals(
            BlockReason.LINK_LEASH_HOP_LIMIT_EXCEEDED,
            (hop2Post as PolicyDecision.Block).reason
        )
    }

    @Test
    fun securityRegression_hm03_03_customSchemeDefaultDenyAndPackagePinning() {
        val config = BrowserPolicyConfig(
            customCallbackSchemes = mapOf(
                "exampleapp" to CustomSchemeTarget(
                    scheme = "exampleapp",
                    targetPackage = "com.example.app",
                    action = "android.intent.action.VIEW"
                )
            ),
            allowUnregisteredCustomSchemes = false
        )
        val evaluator = UrlPolicyEvaluator(
            configProvider = { config },
            dohResolver = createAllowAllDohResolver()
        )

        // 1. Registered custom callback scheme is allowed and carries targetPackage
        val registered = evaluator.evaluateMainFrameNavigation("exampleapp://oauth?code=secret")
        assertTrue(registered is PolicyDecision.HandOffToNativeApp)
        assertEquals("com.example.app", (registered as PolicyDecision.HandOffToNativeApp).targetPackage)

        // 2. Unregistered custom schemes and secondary browser schemes are blocked by default (Option 1A)
        for (unregisteredUrl in listOf(
            "googlechrome://navigate?url=https://reddit.com",
            "firefox://open-url?url=https://reddit.com",
            "vnd.youtube://watch?v=123",
            "unregisteredapp://oauth?code=123",
            "smsto:123456",
            "geo:0,0?q=test"
        )) {
            val decision = evaluator.evaluateMainFrameNavigation(unregisteredUrl)
            assertTrue("Expected $unregisteredUrl to be blocked", decision is PolicyDecision.Block)
            assertEquals(
                BlockReason.INSECURE_OR_INVALID_SCHEME,
                (decision as PolicyDecision.Block).reason
            )
        }
    }

    @Test
    fun securityRegression_hm03_04_subFrameIframeIsolationAndPathRules() {
        val config = BrowserPolicyConfig(
            allowThirdPartyIframes = false
        )
        val evaluator = UrlPolicyEvaluator(
            configProvider = { config },
            dohResolver = createAllowAllDohResolver()
        )

        assertTrue(
            evaluator.evaluateMainFrameNavigation(
                "https://www.kmart.com.au/checkout",
                isInitialLaunch = true
            ) is PolicyDecision.Allow
        )
        evaluator.markRedirectGraceComplete()

        // 1. Same-domain iframe is allowed
        val sameDomainIframe = evaluator.evaluateSubResourceRequest(
            rawUrl = "https://pay.kmart.com.au/widget",
            requestHeaders = mapOf("Sec-Fetch-Dest" to "iframe")
        )
        assertTrue(sameDomainIframe is PolicyDecision.Allow)

        // 2. Trusted IdP / Payment / Captcha iframes (Stripe, Cloudflare Turnstile) are allowed
        val stripeIframe = evaluator.evaluateSubResourceRequest(
            rawUrl = "https://js.stripe.com/v3/elements-inner-card.html",
            requestHeaders = mapOf("Sec-Fetch-Dest" to "iframe")
        )
        assertTrue(stripeIframe is PolicyDecision.Allow)

        val captchaIframe = evaluator.evaluateSubResourceRequest(
            rawUrl = "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/turnstile",
            isSubFrameNavigation = true
        )
        assertTrue(captchaIframe is PolicyDecision.Allow)

        // 3. Restricted path-scoped platform in an iframe is blocked with NON_OAUTH_PLATFORM_PATH
        val githubRepoIframe = evaluator.evaluateSubResourceRequest(
            rawUrl = "https://github.com/trending",
            isSubFrameNavigation = true
        )
        assertTrue(githubRepoIframe is PolicyDecision.Block)
        assertEquals(
            BlockReason.NON_OAUTH_PLATFORM_PATH,
            (githubRepoIframe as PolicyDecision.Block).reason
        )

        // 4. Arbitrary third-party surfing iframe is blocked with THIRD_PARTY_IFRAME_BLOCKED (Option 4A)
        val thirdPartyIframe = evaluator.evaluateSubResourceRequest(
            rawUrl = "https://untrusted-portal.org/surf",
            requestHeaders = mapOf("Sec-Fetch-Dest" to "iframe")
        )
        assertTrue(thirdPartyIframe is PolicyDecision.Block)
        assertEquals(
            BlockReason.THIRD_PARTY_IFRAME_BLOCKED,
            (thirdPartyIframe as PolicyDecision.Block).reason
        )
    }

    @Test
    fun securityRegression_hm03_07_09_dohPrivateIpBlockingBareCnameTtlAndEdnsPadding() {
        // 1. Private RFC 1918, Link-Local, CGNAT, and Multicast IPs are rejected as sinkhole/non-public
        assertTrue(DohResolver.isSinkholeOrBlockIp(10, 0, 0, 1))
        assertTrue(DohResolver.isSinkholeOrBlockIp(172, 16, 0, 1))
        assertTrue(DohResolver.isSinkholeOrBlockIp(172, 31, 255, 255))
        assertTrue(DohResolver.isSinkholeOrBlockIp(192, 168, 1, 1))
        assertTrue(DohResolver.isSinkholeOrBlockIp(169, 254, 169, 254))
        assertTrue(DohResolver.isSinkholeOrBlockIp(100, 64, 0, 1))
        assertTrue(DohResolver.isSinkholeOrBlockIp(0, 1, 2, 3))
        assertTrue(DohResolver.isSinkholeOrBlockIp(224, 0, 0, 1))
        assertFalse(DohResolver.isSinkholeOrBlockIp(93, 184, 216, 34))

        val privateIpPacket = buildMockDnsAResponse("rebind.example", rcode = 0, ip = intArrayOf(192, 168, 1, 1))
        assertEquals(DohVerdict.BLOCK, DohResolver.parseDnsResponseVerdict(privateIpPacket))

        // 2. Bare CNAME response with zero resolved A/AAAA records is blocked
        val bareCnamePacket = buildMockDnsCnameOnlyResponse("alias.example", "target.example")
        assertEquals(DohVerdict.BLOCK, DohResolver.parseDnsResponseVerdict(bareCnamePacket))

        // 3. EDNS(0) padding pads query packets to a multiple of 128 bytes
        val rawQuery = DohResolver.buildDnsAQueryPacket("kmart.com.au")
        val paddedQuery = DohResolver.padDnsQueryPacketWithEdns0(rawQuery, blockSize = 128)
        assertEquals(0, paddedQuery.size % 128)
        assertEquals("kmart.com.au", extractQueryName(paddedQuery))

        // 4. DoH endpoint validation rejects cleartext http:// and IP literals
        assertTrue(BrowserPolicyConfig.isValidDohEndpointUrl("https://family.cloudflare-dns.com/dns-query"))
        assertFalse(BrowserPolicyConfig.isValidDohEndpointUrl("http://family.cloudflare-dns.com/dns-query"))
        assertFalse(BrowserPolicyConfig.isValidDohEndpointUrl("https://1.1.1.1/dns-query"))
        assertFalse(BrowserPolicyConfig.isValidDohEndpointUrl("https://localhost/dns-query"))
    }

    @Test
    fun securityRegression_hm03_08_11_12_pathNormalizationRegexQuantifiersAndExpandedPsl() {
        val config = BrowserPolicyConfig(
            blockedPathRegexes = BrowserPolicyProvider.splitConfigListPreservingQuantifiers(
                "^/(reels?|shorts|stories)(/|$), ^/api/v[0-9]{1,2}/feed"
            ),
            blockedMediaExtensions = setOf(".mp4"),
            blockedMediaMimePrefixes = setOf("video/", "audio/")
        )
        val evaluator = UrlPolicyEvaluator(
            configProvider = { config },
            dohResolver = createAllowAllDohResolver()
        )

        // 1. Path traversal /login/../trending on path-scoped github.com is normalized to /trending and blocked
        val traversalAttack = evaluator.evaluateMainFrameNavigation(
            "https://github.com/login/../trending",
            isInitialLaunch = true
        )
        assertTrue(traversalAttack is PolicyDecision.Block)
        assertEquals(BlockReason.NON_OAUTH_PLATFORM_PATH, (traversalAttack as PolicyDecision.Block).reason)

        // 2. Percent-encoded (%72eels), double-encoded (%2572eels), and double-slash (//reels) paths match blockedPathRegexes
        for (evasionUrl in listOf(
            "https://www.kmart.com.au/%72eels/123",
            "https://www.kmart.com.au/%2572eels/123",
            "https://www.kmart.com.au//shorts/123",
            "https://www.kmart.com.au/api/v12/feed"
        )) {
            val decision = evaluator.evaluateMainFrameNavigation(evasionUrl, isInitialLaunch = true)
            assertTrue("Expected $evasionUrl to be blocked", decision is PolicyDecision.Block)
            assertEquals(BlockReason.HOST_BLOCKLIST_PATH, (decision as PolicyDecision.Block).reason)
        }

        // 3. Matrix parameter & percent-encoded .mp4 extension and composite Accept header are blocked by MediaStreamBlocker
        assertTrue(
            MediaStreamBlocker.shouldBlockMediaRequest(
                url = "https://cdn.example.com/clip.%6dp4;jsessionid=123",
                config = config
            )
        )
        assertTrue(
            MediaStreamBlocker.shouldBlockMediaRequest(
                url = "https://cdn.example.com/stream",
                requestHeaders = mapOf("Accept" to "image/webp, video/mp4;q=0.9"),
                config = config
            )
        )

        // 4. Expanded PSL multi-tenant cloud domains and ccSLDs isolate properly
        assertEquals("blog-a.wordpress.com", DomainExtractor.extractEffectiveDomain("blog-a.wordpress.com"))
        assertEquals("blog-b.wordpress.com", DomainExtractor.extractEffectiveDomain("blog-b.wordpress.com"))
        assertEquals("d111.cloudfront.net", DomainExtractor.extractEffectiveDomain("d111.cloudfront.net"))
        assertEquals("shop.com.vn", DomainExtractor.extractEffectiveDomain("www.shop.com.vn"))
        assertEquals("school.k12.ca.us", DomainExtractor.extractEffectiveDomain("portal.school.k12.ca.us"))
    }

    // =========================================================================
    // Test Helpers
    // =========================================================================

    private fun createAllowAllDohResolver(): DohResolver {
        return DohResolver(
            configProvider = { BrowserPolicyConfig() },
            cache = DohDecisionCache(),
            transport = { _, queryPacket, _ ->
                val qname = extractQueryName(queryPacket)
                buildMockDnsAResponse(qname, rcode = 0, ip = intArrayOf(93, 184, 216, 34))
            }
        )
    }

    private fun extractQueryName(queryPacket: ByteArray): String {
        val sb = StringBuilder()
        var offset = 12
        while (offset < queryPacket.size) {
            val len = queryPacket[offset].toInt() and 0xFF
            if (len == 0) break
            offset++
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(queryPacket, offset, len, StandardCharsets.US_ASCII))
            offset += len
        }
        return sb.toString()
    }

    private fun buildMockDnsAResponse(qname: String, rcode: Int, ip: IntArray?): ByteArray {
        val baos = ByteArrayOutputStream()
        val out = DataOutputStream(baos)

        val anCount = if (ip != null) 1 else 0
        out.writeShort(0x0000) // ID
        out.writeShort(0x8180 or (rcode and 0x0F)) // QR=1, RD=1, RA=1, RCODE
        out.writeShort(1) // QDCOUNT
        out.writeShort(anCount) // ANCOUNT
        out.writeShort(0) // NSCOUNT
        out.writeShort(0) // ARCOUNT

        writeDnsName(out, qname)
        out.writeShort(1) // QTYPE = A
        out.writeShort(1) // QCLASS = IN

        if (ip != null) {
            out.writeShort(0xC00C) // Pointer to QNAME at offset 12
            out.writeShort(1) // TYPE = A
            out.writeShort(1) // CLASS = IN
            out.writeInt(300) // TTL = 300s
            out.writeShort(4) // RDLENGTH = 4
            for (octet in ip) {
                out.writeByte(octet)
            }
        }
        out.flush()
        return baos.toByteArray()
    }

    private fun buildMockDnsCnameOnlyResponse(qname: String, cnameTarget: String): ByteArray {
        val baos = ByteArrayOutputStream()
        val out = DataOutputStream(baos)

        out.writeShort(0x0000)
        out.writeShort(0x8180) // NOERROR
        out.writeShort(1) // QDCOUNT = 1
        out.writeShort(1) // ANCOUNT = 1 (CNAME only, no A/AAAA)
        out.writeShort(0) // NSCOUNT = 0
        out.writeShort(0) // ARCOUNT = 0

        writeDnsName(out, qname)
        out.writeShort(1) // QTYPE = A
        out.writeShort(1) // QCLASS = IN

        out.writeShort(0xC00C) // Pointer to QNAME
        out.writeShort(5) // TYPE = CNAME
        out.writeShort(1) // CLASS = IN
        out.writeInt(300) // TTL = 300s

        val rdataBytes = ByteArrayOutputStream()
        writeDnsName(DataOutputStream(rdataBytes), cnameTarget)
        val rdata = rdataBytes.toByteArray()
        out.writeShort(rdata.size)
        out.write(rdata)
        out.flush()
        return baos.toByteArray()
    }

    private fun buildMockDnsSoaSinkholeResponse(qname: String, soaMname: String): ByteArray {
        val baos = ByteArrayOutputStream()
        val out = DataOutputStream(baos)

        out.writeShort(0x0000)
        out.writeShort(0x8180) // NOERROR
        out.writeShort(1) // QDCOUNT = 1
        out.writeShort(0) // ANCOUNT = 0
        out.writeShort(1) // NSCOUNT = 1
        out.writeShort(0) // ARCOUNT = 0

        writeDnsName(out, qname)
        out.writeShort(1) // QTYPE = A
        out.writeShort(1) // QCLASS = IN

        // Authority RR (SOA)
        writeDnsName(out, "cleanbrowsing.rpz")
        out.writeShort(6) // TYPE = SOA
        out.writeShort(1) // CLASS = IN
        out.writeInt(60)  // TTL

        val rdataBytes = ByteArrayOutputStream()
        val rdataOut = DataOutputStream(rdataBytes)
        writeDnsName(rdataOut, soaMname)
        writeDnsName(rdataOut, "admin.cleanbrowsing.rpz")
        rdataOut.writeInt(1)
        rdataOut.writeInt(3600)
        rdataOut.writeInt(600)
        rdataOut.writeInt(86400)
        rdataOut.writeInt(60)
        rdataOut.flush()
        val rdata = rdataBytes.toByteArray()

        out.writeShort(rdata.size)
        out.write(rdata)
        out.flush()
        return baos.toByteArray()
    }

    private fun writeDnsName(out: DataOutputStream, domain: String) {
        for (label in domain.trimEnd('.').split('.')) {
            val bytes = label.toByteArray(StandardCharsets.US_ASCII)
            out.writeByte(bytes.size)
            out.write(bytes)
        }
        out.writeByte(0)
    }
}
