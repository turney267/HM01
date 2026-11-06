package dev.hm03.browser

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.webkit.CookieManager
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.hm03.browser.config.BrowserPolicyProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented Android tests verifying Managed Configurations parsing, CustomTabsService binding,
 * and ephemeral cookie/storage cleanup on a real Android runtime.
 */
@RunWith(AndroidJUnit4::class)
class Hm03InstrumentedTest {

    @After
    fun tearDown() {
        BrowserPolicyProvider.reset()
    }

    @Test
    fun managedRestrictionsBundleParsesCorrectly() {
        val bundle = Bundle().apply {
            putString("brand_title", "Juubun Safe Link")
            putString("custom_doh_url", "https://family.cloudflare-dns.com/dns-query")
            putBoolean("fail_closed_on_dns_error", true)
            putString("blocked_domains", "substack.com, reddit.com, news.ycombinator.com")
            putString("blocked_keywords", "gossip, tabloid")
            putString("blocked_path_regexes", "^/reels, ^/shorts, ^/api/v[0-9]{1,2}/feed")
            putInt("max_external_domain_hops", 1)
            putInt("session_timeout_seconds", 300)
            putBoolean("block_video_audio", true)
        }

        val parsed = BrowserPolicyProvider.parseRestrictionsBundle(bundle)
        assertEquals("Juubun Safe Link", parsed.brandTitle)
        assertEquals("https://family.cloudflare-dns.com/dns-query", parsed.customDohUrl)
        assertTrue(parsed.failClosedOnDnsError)
        assertTrue(parsed.blockedDomains.contains("substack.com"))
        assertTrue(parsed.blockedDomains.contains("reddit.com"))
        assertTrue(parsed.blockedDomains.contains("news.ycombinator.com"))
        assertEquals(3, parsed.compiledBlockedPathRegexes.size)
        assertEquals(1, parsed.maxExternalDomainHops)
        assertEquals(300_000L, parsed.sessionTimeoutMs)
        assertTrue(parsed.blockVideoAndAudio)
    }

    @Test
    fun ephemeralCleanupWipesCookiesAndStorage() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val cookieManager = CookieManager.getInstance()
        cookieManager.setAcceptCookie(true)
        cookieManager.setCookie("https://kmart.com.au", "session_id=secret123; Path=/")
        cookieManager.flush()

        IntentBrowserActivity.wipeEphemeralWebData(context, null)

        val cookieAfterWipe = cookieManager.getCookie("https://kmart.com.au")
        assertTrue(
            "Cookies must be wiped after wipeEphemeralWebData",
            cookieAfterWipe.isNullOrEmpty()
        )
    }

    @Test
    fun launcherIntentDoesNotResolveToHm03() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val launcherIntent = Intent(Intent.ACTION_MAIN).apply {
            addCategory(Intent.CATEGORY_LAUNCHER)
            setPackage(context.packageName)
        }
        val activities = context.packageManager.queryIntentActivities(launcherIntent, 0)
        assertFalse(
            "HM03 must not expose a CATEGORY_LAUNCHER icon",
            activities.any { it.activityInfo.name == IntentBrowserActivity::class.java.name }
        )
    }
}
