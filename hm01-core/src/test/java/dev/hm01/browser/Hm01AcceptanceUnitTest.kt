package dev.hm01.browser

import dev.hm01.browser.config.BrowserPolicyConfig
import dev.hm01.browser.config.CustomSchemeTarget
import dev.hm01.browser.config.DohPreset
import dev.hm01.browser.dns.DohDecisionCache
import dev.hm01.browser.dns.DohResolver
import dev.hm01.browser.dns.DohVerdict
import dev.hm01.browser.filter.BlockReason
import dev.hm01.browser.filter.DomainExtractor
import dev.hm01.browser.filter.MediaStreamBlocker
import dev.hm01.browser.filter.PolicyDecision
import dev.hm01.browser.filter.UrlPolicyEvaluator
import dev.hm01.browser.ui.BlockedPageRenderer
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
 * Comprehensive unit tests verifying all 7 acceptance test scenarios in `HM01_Spec.md`.
 */
class Hm01AcceptanceUnitTest {

    // =========================================================================
    // Scenario 1: CleanBrowsing Family Filter DoH Enforcement & Coalesced Cache
    // =========================================================================

    @Test
    fun scenario1_cleanBrowsingDohWireformatAndCaching() {
        val cache = DohDecisionCache(maxEntries = 100, defaultTtlMs = 60_000L)
        val networkCalls = AtomicInteger(0)

        val fakeResolver = DohResolver(
            configProvider = { BrowserPolicyConfig(dohPreset = DohPreset.CLEANBROWSING_FAMILY) },
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
    fun scenario1_liveCleanBrowsingFamilyFilterDohEndpoint() {
        val liveCache = DohDecisionCache()
        val liveResolver = DohResolver(
            configProvider = {
                BrowserPolicyConfig(
                    dohPreset = DohPreset.CLEANBROWSING_FAMILY,
                    failClosedOnDnsError = true
                )
            },
            cache = liveCache
        )

        val blockedVerdict = liveResolver.resolve("adult-filter-test.cleanbrowsing.org")
        assertEquals(
            "CleanBrowsing test domain must resolve to BLOCK over live RFC 8484 DoH",
            DohVerdict.BLOCK,
            blockedVerdict
        )

        val allowedVerdict = liveResolver.resolve("ikea.com")
        assertEquals(
            "Legitimate retail domain must resolve to ALLOW over live RFC 8484 DoH",
            DohVerdict.ALLOW,
            allowedVerdict
        )
        assertEquals(
            "Allowed domain verdict must be cached in DohDecisionCache",
            DohVerdict.ALLOW,
            liveCache.get("ikea.com")
        )
    }

    // =========================================================================
    // Scenario 2: Spouse Gift Link Flow (Shortener Redirect, Same-Domain, 1 Hop, Video Block)
    // =========================================================================

    @Test
    fun scenario2_spouseGiftLinkFlowWithShortenerAndMediaLockdown() {
        val config = BrowserPolicyConfig(maxExternalDomainHops = 1, blockVideoAndAudio = true)
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
        val evaluator = UrlPolicyEvaluator(
            configProvider = { BrowserPolicyConfig() },
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
        val evaluator = UrlPolicyEvaluator(
            configProvider = {
                BrowserPolicyConfig(
                    customCallbackSchemes = mapOf(
                        "juubunparent" to CustomSchemeTarget("juubunparent", "com.juubun.app")
                    )
                )
            },
            dohResolver = createAllowAllDohResolver()
        )

        // 1. Google OAuth sign-in paths are allowed
        val googleOAuth = evaluator.evaluateMainFrameNavigation(
            "https://accounts.google.com/o/oauth2/v2/auth?client_id=123&redirect_uri=juubunparent://oauth",
            isInitialLaunch = true
        )
        assertTrue(googleOAuth is PolicyDecision.Allow)
        assertTrue((googleOAuth as PolicyDecision.Allow).isTrustedIdpOrScopedOAuth)

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

        // 5. Custom callback scheme handoff (juubunparent://oauth?code=xyz)
        val callbackDecision = evaluator.evaluateMainFrameNavigation(
            "juubunparent://oauth?code=xyz123"
        )
        assertTrue(callbackDecision is PolicyDecision.HandOffToNativeApp)
        assertEquals(
            "com.juubun.app",
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
    // Scenario 5: Attention-Hog Blocklist Injection (Juubun Integration)
    // =========================================================================

    @Test
    fun scenario5_attentionHogBlocklistInjection() {
        val juubunConfig = BrowserPolicyConfig(
            brandTitle = "Juubun Safe Link",
            blockedDomains = setOf("substack.com", "reddit.com", "news.ycombinator.com"),
            blockedHostKeywords = setOf(" tabloid ", "gossip"),
            blockedPathRegexes = listOf("^/reels(/|$)", "^/shorts(/|$)", "^/r/")
        )

        val evaluator = UrlPolicyEvaluator(
            configProvider = { juubunConfig },
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
            BrowserPolicyConfig(brandTitle = "Juubun Safe Link")
        )
        assertTrue(html.contains("Juubun Safe Link Policy"))
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
        IntentBrowserActivity.wipeEphemeralWebData(context = null, webView = null)
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
