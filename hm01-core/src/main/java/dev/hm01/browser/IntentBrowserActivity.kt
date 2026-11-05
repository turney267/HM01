package dev.hm01.browser

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.ClipDrawable
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.LayerDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.TextUtils
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.webkit.CookieManager
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebStorage
import android.webkit.WebView
import android.webkit.WebViewClient
import android.webkit.WebViewDatabase
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import dev.hm01.browser.config.BrowserPolicyConfig
import dev.hm01.browser.config.BrowserPolicyProvider
import dev.hm01.browser.config.DnsMode
import dev.hm01.browser.filter.MediaStreamBlocker
import dev.hm01.browser.filter.PolicyDecision
import dev.hm01.browser.filter.UrlPolicyEvaluator
import dev.hm01.browser.ui.BlockedPageRenderer

/**
 * Captive, no-URL-bar, ephemeral Intent & Custom Tabs Browser Activity (`HM01`).
 *
 * Wakes up only on external `ACTION_VIEW` links or in-app OAuth Custom Tab intents, enforces
 * the 6-step `UrlPolicyEvaluator` + `MediaStreamBlocker` + `DohResolver` pipeline, and wipes all
 * cookies, storage, cache, and history when closed or timed out.
 */
class IntentBrowserActivity : Activity() {

    private lateinit var activeConfig: BrowserPolicyConfig
    private lateinit var policyEvaluator: UrlPolicyEvaluator

    private var webView: WebView? = null
    private lateinit var hostnameView: TextView
    private lateinit var lockIconView: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var webContainer: FrameLayout

    private val mainHandler = Handler(Looper.getMainLooper())
    private val sessionTimeoutRunnable = Runnable {
        closeAndWipeSession()
    }

    private var isSessionWiped = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        activeConfig = BrowserPolicyProvider.getConfig(applicationContext)
        val dohResolver = BrowserPolicyProvider.getDohResolver(applicationContext)

        policyEvaluator = UrlPolicyEvaluator(
            configProvider = { activeConfig },
            dohResolver = dohResolver,
            nativeAppHandlerDetector = { targetUrl ->
                hasNonBrowserNativeAppHandler(this, targetUrl)
            }
        )

        setContentView(buildMinimalBrowserLayout())
        scheduleSessionTimeout()

        handleLaunchIntent(intent)
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        setIntent(intent)
        policyEvaluator.resetSession()
        scheduleSessionTimeout()
        handleLaunchIntent(intent)
    }

    private fun handleLaunchIntent(launchIntent: Intent?) {
        val rawUrl = launchIntent?.dataString?.trim()
        if (rawUrl.isNullOrEmpty()) {
            closeAndWipeSession()
            return
        }

        activeConfig = BrowserPolicyProvider.getConfig(applicationContext)
        if (activeConfig.dnsMode == DnsMode.USER_DEFINED &&
            activeConfig.resolveActiveDohEndpointUrl().isBlank()
        ) {
            val promptHandler = BrowserPolicyProvider.getDnsSelectionPromptHandler()
            if (promptHandler != null) {
                promptHandler.onPromptDnsSelection(
                    activity = this,
                    onDnsSelected = {
                        activeConfig = BrowserPolicyProvider.getConfig(applicationContext)
                        policyEvaluator.resetSession()
                        scheduleSessionTimeout()
                        evaluateAndOpenInitialUrl(rawUrl)
                    },
                    onCancelled = {
                        closeAndWipeSession()
                    }
                )
                return
            }
        }

        evaluateAndOpenInitialUrl(rawUrl)
    }

    private fun evaluateAndOpenInitialUrl(rawUrl: String) {
        val initialDecision = policyEvaluator.evaluateMainFrameNavigation(
            rawUrl = rawUrl,
            isInitialLaunch = true,
            isServerRedirect = false
        )

        when (initialDecision) {
            is PolicyDecision.UpgradeToHttps -> {
                val upgradedDecision = policyEvaluator.evaluateMainFrameNavigation(
                    rawUrl = initialDecision.httpsUrl,
                    isInitialLaunch = true,
                    isServerRedirect = false
                )
                applyMainFrameDecision(upgradedDecision, loadIntoWebViewOnAllow = true)
            }
            else -> {
                applyMainFrameDecision(initialDecision, loadIntoWebViewOnAllow = true)
            }
        }
    }

    private fun applyMainFrameDecision(
        decision: PolicyDecision,
        loadIntoWebViewOnAllow: Boolean
    ): Boolean {
        return when (decision) {
            is PolicyDecision.Allow -> {
                updateVerifiedHostHeader(decision.host, isBlocked = false)
                if (loadIntoWebViewOnAllow) {
                    webView?.loadUrl(decision.url)
                }
                false // Allow WebView navigation when called from shouldOverrideUrlLoading
            }
            is PolicyDecision.UpgradeToHttps -> {
                webView?.loadUrl(decision.httpsUrl)
                true
            }
            is PolicyDecision.HandOffToNativeApp -> {
                launchSanitizedExternalIntent(decision.url, decision.targetPackage)
                closeAndWipeSession()
                true
            }
            is PolicyDecision.Block -> {
                renderBlockedScreen(decision)
                true
            }
        }
    }

    private fun renderBlockedScreen(decision: PolicyDecision.Block) {
        updateVerifiedHostHeader(
            host = decision.host.ifBlank { activeConfig.brandTitle },
            isBlocked = true
        )
        val html = BlockedPageRenderer.buildBlockedHtml(decision, activeConfig)
        webView?.stopLoading()
        webView?.loadDataWithBaseURL(
            "about:blank",
            html,
            "text/html",
            "UTF-8",
            null
        )
    }

    private fun updateVerifiedHostHeader(host: String, isBlocked: Boolean) {
        runOnUiThread {
            if (isBlocked) {
                lockIconView.text = "\u26A0" // Warning sign
                lockIconView.setTextColor(Color.parseColor("#DC2626"))
                hostnameView.text = host.ifBlank { activeConfig.brandTitle }
            } else {
                lockIconView.text = "\uD83D\uDD12" // Lock icon
                lockIconView.setTextColor(Color.parseColor("#16A34A"))
                hostnameView.text = host
            }
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun createConfiguredWebView(): WebView {
        val wv = WebView(this)
        val settings = wv.settings

        settings.javaScriptEnabled = true
        settings.domStorageEnabled = true
        @Suppress("DEPRECATION")
        settings.databaseEnabled = false
        settings.allowFileAccess = false
        settings.allowContentAccess = false
        settings.setGeolocationEnabled(false)
        @Suppress("DEPRECATION")
        settings.saveFormData = false
        // Support popup windows (e.g., Google 2-Step Verification & OAuth popups) by intercepting
        // them in WebChromeClient.onCreateWindow and routing their URLs through the policy evaluator
        // into the single main WebView.
        settings.setSupportMultipleWindows(true)
        settings.javaScriptCanOpenWindowsAutomatically = true
        settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
        settings.mediaPlaybackRequiresUserGesture = true
        settings.builtInZoomControls = true
        settings.displayZoomControls = false
        settings.useWideViewPort = true
        settings.loadWithOverviewMode = true
        settings.cacheMode = WebSettings.LOAD_NO_CACHE

        // Strip "; wv" and "Version/4.0" so Google OAuth & strict OIDC providers treat HM01 as a compliant Custom Tab
        settings.userAgentString = MinimalCustomTabsService.sanitizeCustomTabUserAgent(
            settings.userAgentString
        )

        if (!activeConfig.allowDownloads) {
            wv.setDownloadListener { _, _, _, _, _ ->
                // Downloads disabled by default
            }
        }

        val cookieManager = CookieManager.getInstance()
        cookieManager.setAcceptCookie(true)
        // Cross-domain OAuth / 2SV challenges (e.g. accounts.google.com <-> myaccount.google.com)
        // require cookies during the ephemeral session; all cookies are wiped on close/timeout.
        cookieManager.setAcceptThirdPartyCookies(wv, true)

        wv.webChromeClient = object : WebChromeClient() {
            override fun onProgressChanged(view: WebView?, newProgress: Int) {
                if (newProgress in 1..99) {
                    progressBar.visibility = View.VISIBLE
                    progressBar.progress = newProgress
                } else {
                    progressBar.progress = 100
                    progressBar.visibility = View.INVISIBLE
                }
            }

            override fun onShowCustomView(view: View?, callback: CustomViewCallback?) {
                // Never allow fullscreen video custom views
                callback?.onCustomViewHidden()
            }

            override fun onCreateWindow(
                view: WebView?,
                isDialog: Boolean,
                isUserGesture: Boolean,
                resultMsg: android.os.Message?
            ): Boolean {
                val transport = resultMsg?.obj as? WebView.WebViewTransport ?: return false
                val popupWebView = WebView(this@IntentBrowserActivity)
                popupWebView.webViewClient = object : WebViewClient() {
                    override fun shouldOverrideUrlLoading(
                        popupView: WebView?,
                        request: WebResourceRequest?
                    ): Boolean {
                        val targetUrl = request?.url?.toString()
                        popupView?.destroy()
                        if (!targetUrl.isNullOrBlank()) {
                            val decision = policyEvaluator.evaluateMainFrameNavigation(
                                rawUrl = targetUrl,
                                isInitialLaunch = false,
                                isServerRedirect = false
                            )
                            applyMainFrameDecision(decision, loadIntoWebViewOnAllow = true)
                        }
                        return true
                    }
                }
                transport.webView = popupWebView
                resultMsg.sendToTarget()
                return true
            }
        }

        wv.webViewClient = object : WebViewClient() {

            override fun shouldOverrideUrlLoading(
                view: WebView?,
                request: WebResourceRequest?
            ): Boolean {
                val targetUrl = request?.url?.toString() ?: return true
                if (targetUrl == "about:blank") return false

                if (!request.isForMainFrame) {
                    val subDecision = policyEvaluator.evaluateSubResourceRequest(
                        rawUrl = targetUrl,
                        requestHeaders = request.requestHeaders ?: emptyMap()
                    )
                    return subDecision is PolicyDecision.Block
                }

                val isRedirect = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    request.isRedirect
                } else {
                    false
                }

                val decision = policyEvaluator.evaluateMainFrameNavigation(
                    rawUrl = targetUrl,
                    isInitialLaunch = false,
                    isServerRedirect = isRedirect
                )
                return applyMainFrameDecision(decision, loadIntoWebViewOnAllow = false)
            }

            override fun shouldInterceptRequest(
                view: WebView?,
                request: WebResourceRequest?
            ): WebResourceResponse? {
                val req = request ?: return null
                val targetUrl = req.url?.toString() ?: return BlockedPageRenderer.createEmptyBlockedSubResourceResponse()
                if (targetUrl == "about:blank") return null

                val headers = req.requestHeaders ?: emptyMap()

                if (req.isForMainFrame) {
                    // Enforce media stream check even on main-frame direct links to .mp4 / video files
                    if (MediaStreamBlocker.shouldBlockMediaRequest(targetUrl, headers, activeConfig)) {
                        val blockDecision = PolicyDecision.Block(
                            reason = dev.hm01.browser.filter.BlockReason.MEDIA_STREAM_BLOCKED,
                            url = targetUrl,
                            host = req.url?.host ?: ""
                        )
                        return BlockedPageRenderer.createBlockedHtmlResponse(blockDecision, activeConfig)
                    }
                    return null
                }

                val subDecision = policyEvaluator.evaluateSubResourceRequest(
                    rawUrl = targetUrl,
                    requestHeaders = headers
                )
                return when (subDecision) {
                    is PolicyDecision.Allow -> null
                    else -> BlockedPageRenderer.createEmptyBlockedSubResourceResponse()
                }
            }

            override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
                super.onPageStarted(view, url, favicon)
                if (url != null && url != "about:blank") {
                    val host = runCatching { Uri.parse(url).host }.getOrNull().orEmpty()
                    if (host.isNotBlank()) {
                        updateVerifiedHostHeader(host, isBlocked = false)
                    }
                }
                injectMediaLockdownScript(view)
            }

            override fun onPageCommitVisible(view: WebView?, url: String?) {
                super.onPageCommitVisible(view, url)
                injectMediaLockdownScript(view)
            }

            override fun onPageFinished(view: WebView?, url: String?) {
                super.onPageFinished(view, url)
                injectMediaLockdownScript(view)
                if (url != null && url != "about:blank") {
                    policyEvaluator.markRedirectGraceComplete()
                }
            }
        }

        return wv
    }

    private fun injectMediaLockdownScript(view: WebView?) {
        val targetView = view ?: return
        val script = MediaStreamBlocker.buildLockdownJavascript(activeConfig)
        targetView.evaluateJavascript(script, null)
    }

    private fun buildMinimalBrowserLayout(): View {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
            setBackgroundColor(Color.parseColor("#FFFFFF"))
        }

        // Header Bar: Back (<), Lock Icon + Verified Hostname, Refresh (↻), Close (✕)
        val headerBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dpToPx(52)
            )
            setPadding(dpToPx(8), 0, dpToPx(8), 0)
            setBackgroundColor(Color.parseColor("#F8FAFC"))
        }

        val backButton = createHeaderButton(
            symbol = "<",
            contentDesc = "Navigate Back",
            viewId = ID_BUTTON_BACK
        ) {
            navigateBackOrClose()
        }

        val hostContainer = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
            ).apply {
                marginStart = dpToPx(8)
                marginEnd = dpToPx(8)
            }
        }

        lockIconView = TextView(this).apply {
            id = ID_LOCK_ICON
            text = "\uD83D\uDD12"
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            setPadding(0, 0, dpToPx(6), 0)
        }

        hostnameView = TextView(this).apply {
            id = ID_HOSTNAME_TEXT
            text = activeConfig.brandTitle
            setTextColor(Color.parseColor("#0F172A"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
            typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
            maxLines = 1
            ellipsize = TextUtils.TruncateAt.END
        }

        hostContainer.addView(lockIconView)
        hostContainer.addView(hostnameView)

        val refreshButton = createHeaderButton(
            symbol = "\u21BB",
            contentDesc = "Refresh Page",
            viewId = ID_BUTTON_REFRESH
        ) {
            webView?.reload()
        }

        val closeButton = createHeaderButton(
            symbol = "\u2715",
            contentDesc = "Close and Wipe Session",
            viewId = ID_BUTTON_CLOSE
        ) {
            closeAndWipeSession()
        }

        headerBar.addView(backButton)
        headerBar.addView(hostContainer)
        headerBar.addView(refreshButton)
        headerBar.addView(closeButton)

        // 4dp Slim Horizontal Progress Bar underneath the header
        progressBar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            id = ID_PROGRESS_BAR
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dpToPx(4)
            )
            max = 100
            progress = 0
            visibility = View.INVISIBLE

            val bg = ColorDrawable(Color.parseColor("#E2E8F0"))
            val fg = ClipDrawable(
                ColorDrawable(Color.parseColor("#2563EB")),
                Gravity.START,
                ClipDrawable.HORIZONTAL
            )
            progressDrawable = LayerDrawable(arrayOf(bg, fg)).apply {
                setId(0, android.R.id.background)
                setId(1, android.R.id.progress)
            }
        }

        webContainer = FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
        }

        val configuredWebView = createConfiguredWebView()
        webView = configuredWebView
        webContainer.addView(
            configuredWebView,
            FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        )

        root.addView(headerBar)
        root.addView(progressBar)
        root.addView(webContainer)

        return root
    }

    private fun createHeaderButton(
        symbol: String,
        contentDesc: String,
        viewId: Int,
        onClick: () -> Unit
    ): TextView {
        return TextView(this).apply {
            id = viewId
            text = symbol
            contentDescription = contentDesc
            gravity = Gravity.CENTER
            setTextColor(Color.parseColor("#1E293B"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 18f)
            typeface = Typeface.DEFAULT_BOLD
            layoutParams = LinearLayout.LayoutParams(dpToPx(40), dpToPx(40))
            isClickable = true
            isFocusable = true
            setOnClickListener { onClick() }
        }
    }

    private fun navigateBackOrClose() {
        val wv = webView
        if (wv != null && wv.canGoBack()) {
            wv.goBack()
        } else {
            closeAndWipeSession()
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        navigateBackOrClose()
    }

    private fun scheduleSessionTimeout() {
        mainHandler.removeCallbacks(sessionTimeoutRunnable)
        val timeoutMs = activeConfig.sessionTimeoutMs
        if (timeoutMs > 0L) {
            mainHandler.postDelayed(sessionTimeoutRunnable, timeoutMs)
        }
    }

    private fun launchSanitizedExternalIntent(url: String, targetPackage: String?) {
        runCatching {
            val handoffIntent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply {
                addCategory(Intent.CATEGORY_BROWSABLE)
                component = null
                selector = null
                if (!targetPackage.isNullOrBlank()) {
                    setPackage(targetPackage)
                }
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivity(handoffIntent)
        }.onFailure {
            if (!targetPackage.isNullOrBlank()) {
                runCatching {
                    val fallbackIntent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply {
                        addCategory(Intent.CATEGORY_BROWSABLE)
                        component = null
                        selector = null
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                    startActivity(fallbackIntent)
                }
            }
        }
    }

    /**
     * Immediately destroys the session, wipes all cookies, WebStorage, cache, and history,
     * and finishes the activity.
     */
    fun closeAndWipeSession() {
        mainHandler.removeCallbacks(sessionTimeoutRunnable)
        if (!isSessionWiped) {
            isSessionWiped = true
            val currentWv = webView
            webView = null
            if (currentWv != null) {
                webContainer.removeView(currentWv)
            }
            wipeEphemeralWebData(applicationContext, currentWv)
        }
        if (!isFinishing) {
            finishAndRemoveTask()
        }
    }

    override fun onDestroy() {
        mainHandler.removeCallbacks(sessionTimeoutRunnable)
        if (!isSessionWiped) {
            isSessionWiped = true
            val currentWv = webView
            webView = null
            if (currentWv != null) {
                webContainer.removeView(currentWv)
            }
            wipeEphemeralWebData(applicationContext, currentWv)
        }
        super.onDestroy()
    }

    private fun dpToPx(dp: Int): Int {
        return TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            dp.toFloat(),
            resources.displayMetrics
        ).toInt()
    }

    companion object {
        const val ID_BUTTON_BACK = 0x7F0B0001
        const val ID_LOCK_ICON = 0x7F0B0002
        const val ID_HOSTNAME_TEXT = 0x7F0B0003
        const val ID_BUTTON_REFRESH = 0x7F0B0004
        const val ID_BUTTON_CLOSE = 0x7F0B0005
        const val ID_PROGRESS_BAR = 0x7F0B0006

        /**
         * Wipes all cookies, WebStorage, HTTP auth credentials, cache, form data, and history.
         */
        @JvmStatic
        fun wipeEphemeralWebData(context: Context?, webView: WebView?) {
            runCatching {
                val cookieManager = CookieManager.getInstance()
                cookieManager.removeAllCookies(null)
                cookieManager.flush()
            }
            runCatching {
                WebStorage.getInstance().deleteAllData()
            }
            if (context != null) {
                runCatching {
                    WebViewDatabase.getInstance(context).clearHttpAuthUsernamePassword()
                }
            }
            if (webView != null) {
                runCatching {
                    webView.stopLoading()
                    webView.clearCache(true)
                    webView.clearFormData()
                    webView.clearHistory()
                    webView.clearSslPreferences()
                    webView.loadUrl("about:blank")
                    webView.removeAllViews()
                    webView.destroy()
                }
            }
        }

        /**
         * Checks whether a non-browser native application is installed that handles [httpsUrl].
         */
        @JvmStatic
        fun hasNonBrowserNativeAppHandler(context: Context, httpsUrl: String): Boolean {
            return runCatching {
                val pm = context.packageManager
                val probeIntent = Intent(Intent.ACTION_VIEW, Uri.parse("https://example.invalid")).apply {
                    addCategory(Intent.CATEGORY_BROWSABLE)
                }
                val browserPackages = queryResolvedPackageNames(pm, probeIntent)

                val targetIntent = Intent(Intent.ACTION_VIEW, Uri.parse(httpsUrl)).apply {
                    addCategory(Intent.CATEGORY_BROWSABLE)
                }
                val targetPackages = queryResolvedPackageNames(pm, targetIntent)

                targetPackages.any { pkg ->
                    pkg != context.packageName && pkg !in browserPackages
                }
            }.getOrDefault(false)
        }

        private fun queryResolvedPackageNames(pm: PackageManager, intent: Intent): Set<String> {
            val resolveInfos = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.queryIntentActivities(
                    intent,
                    PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_DEFAULT_ONLY.toLong())
                )
            } else {
                @Suppress("DEPRECATION")
                pm.queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY)
            }
            return resolveInfos.mapNotNull { it.activityInfo?.packageName }.toSet()
        }
    }
}
