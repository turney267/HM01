package dev.hm03.browser

import android.net.Uri
import android.os.Bundle
import androidx.browser.customtabs.CustomTabsService
import androidx.browser.customtabs.CustomTabsSessionToken

/**
 * Lightweight [CustomTabsService] implementation so OAuth/OIDC SDKs (AppAuth, Auth0, Slack,
 * banking, and government sign-in flows) recognize `HM03` as a compliant Custom Tabs provider.
 */
class MinimalCustomTabsService : CustomTabsService() {

    override fun warmup(flags: Long): Boolean {
        return true
    }

    override fun newSession(sessionToken: CustomTabsSessionToken): Boolean {
        return true
    }

    override fun mayLaunchUrl(
        sessionToken: CustomTabsSessionToken,
        url: Uri?,
        extras: Bundle?,
        otherLikelyBundles: MutableList<Bundle>?
    ): Boolean {
        // Lightweight no-op: HM03 never pre-fetches speculative background pages
        return true
    }

    override fun extraCommand(commandName: String, args: Bundle?): Bundle? {
        return null
    }

    override fun updateVisuals(sessionToken: CustomTabsSessionToken, bundle: Bundle?): Boolean {
        return true
    }

    override fun requestPostMessageChannel(
        sessionToken: CustomTabsSessionToken,
        postMessageOrigin: Uri
    ): Boolean {
        return false
    }

    override fun postMessage(
        sessionToken: CustomTabsSessionToken,
        message: String,
        extras: Bundle?
    ): Int {
        return RESULT_FAILURE_DISALLOWED
    }

    override fun validateRelationship(
        sessionToken: CustomTabsSessionToken,
        relation: Int,
        origin: Uri,
        extras: Bundle?
    ): Boolean {
        return false
    }

    override fun receiveFile(
        sessionToken: CustomTabsSessionToken,
        uri: Uri,
        purpose: Int,
        extras: Bundle?
    ): Boolean {
        return false
    }

    companion object {
        private val WV_TOKEN_REGEX = Regex(";\\s*wv(?=\\)|;)", RegexOption.IGNORE_CASE)
        private val VERSION_TOKEN_REGEX = Regex("\\s*Version/\\d+\\.\\d+", RegexOption.IGNORE_CASE)

        /**
         * Strips `; wv` and `Version/4.0` tokens from a WebView User-Agent string so strict
         * OAuth/OIDC identity providers (like Google OAuth) treat `HM03` as a compliant Custom Tab.
         */
        @JvmStatic
        fun sanitizeCustomTabUserAgent(rawUserAgent: String?): String {
            if (rawUserAgent.isNullOrBlank()) return ""
            return rawUserAgent
                .replace(WV_TOKEN_REGEX, "")
                .replace(VERSION_TOKEN_REGEX, "")
                .replace(Regex("\\s{2,}"), " ")
                .trim()
        }
    }
}
