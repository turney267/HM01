package dev.hm03.browser

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
import android.net.http.SslError
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.text.TextUtils
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.webkit.CookieManager
import android.webkit.SslErrorHandler
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
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
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import dev.hm03.browser.config.BrowserPolicyConfig
import dev.hm03.browser.config.BrowserPolicyProvider
import dev.hm03.browser.config.DnsMode
import dev.hm03.browser.filter.BlockReason
import dev.hm03.browser.filter.CanonicalUrl
import dev.hm03.browser.filter.MediaStreamBlocker
import dev.hm03.browser.filter.PolicyDecision
import dev.hm03.browser.filter.UrlPolicyEvaluator
import dev.hm03.browser.ui.BlockedPageRenderer

/**
 * Captive, no-URL-bar, ephemeral Intent & Custom Tabs Browser Activity (`HM03`).
 *
 * Wakes up only on external `ACTION_VIEW` links or in-app OAuth Custom Tab intents, enforces
 * the 6-step `UrlPolicyEvaluator` + `MediaStreamBlocker` + `DohResolver` pipeline, and wipes all
 * cookies, storage, cache, and history when closed or timed out.
 */
class IntentBrowserActivity : Activity() {

    private lateinit var activeConfig: BrowserPolicyConfig
    private lateinit var policyEvaluator: UrlPolicyEvaluator

    private var webView: WebView? = null
    private val activePopupWebViews = mutableSetOf<WebView>()
    private lateinit var hostnameView: TextView
    private lateinit var lockIconView: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var webContainer: FrameLayout

    private val mainHandler = Handler(Looper.getMainLooper())
    private val sessionTimeoutRunnable = Runnable {
        closeAndWipeSession()
    }

    private var sessionStartElapsedRealtimeMs: Long = 0L
    private var committedHost: String? = null
    private var isBlockedScreenVisible: Boolean = false
    private var isSessionWiped: Boolean = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val initialRawUrl = intent?.dataString?.trim()
        if (initialRawUrl.isNullOrEmpty()) {
            isSessionWiped = true
            finishAndRemoveTask()
            return
        }

        activeConfig = BrowserPolicyProvider.getConfig(applicationContext)
        if (!activeConfig.persistCookiesAndStorage) {
            // Defensively wipe any leftover disk state from a prior OS-killed session before starting
            wipeSessionStorageOnly(applicationContext)
        } else {
            flushPersistentCookies()
        }
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
        val rawUrl = intent?.dataString?.trim()
        // Ignore empty/malformed external intents so other apps cannot remotely wipe an active session
        if (rawUrl.isNullOrEmpty()) {
            return
        }

        setIntent(intent)
        resetSessionAndWebView()
        scheduleSessionTimeout()
        handleLaunchIntent(intent)
    }

    override fun onStart() {
        super.onStart()
        checkElapsedSessionTimeout()
    }

    override fun onResume() {
        super.onResume()
        checkElapsedSessionTimeout()
    }

    private fun checkElapsedSessionTimeout() {
        if (!::activeConfig.isInitialized || isSessionWiped) return
        val timeoutMs = activeConfig.sessionTimeoutMs
        if (timeoutMs <= 0L || sessionStartElapsedRealtimeMs <= 0L) return

        val elapsedMs = SystemClock.elapsedRealtime() - sessionStartElapsedRealtimeMs
        if (elapsedMs >= timeoutMs) {
            closeAndWipeSession()
        } else {
            mainHandler.removeCallbacks(sessionTimeoutRunnable)
            mainHandler.postDelayed(sessionTimeoutRunnable, timeoutMs - elapsedMs)
        }
    }

    private fun resetSessionAndWebView() {
        destroyAllPopupWebViews()
        val oldWv = webView
        webView = null
        if (oldWv != null && ::webContainer.isInitialized) {
            webContainer.removeView(oldWv)
        }
        activeConfig = BrowserPolicyProvider.getConfig(applicationContext)
        wipeEphemeralWebData(applicationContext, oldWv, activeConfig.persistCookiesAndStorage)
        committedHost = null
        isBlockedScreenVisible = false
        isSessionWiped = false
        policyEvaluator.resetSession()

        if (::webContainer.isInitialized) {
            val freshWv = createConfiguredWebView()
            webView = freshWv
            webContainer.addView(
                freshWv,
                FrameLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.MATCH_PARENT
                )
            )
            updateProvisionalLoadingHeader()
        }
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
                isBlockedScreenVisible = false
                // Do not display a verified green lock for the new host until the navigation commits
                updateProvisionalLoadingHeader()
                if (loadIntoWebViewOnAllow) {
                    webView?.loadUrl(decision.url)
                }
                false // Allow WebView navigation when called from shouldOverrideUrlLoading
            }
            is PolicyDecision.UpgradeToHttps -> {
                isBlockedScreenVisible = false
                updateProvisionalLoadingHeader()
                webView?.loadUrl(decision.httpsUrl)
                true
            }
            is PolicyDecision.HandOffToNativeApp -> {
                if (::activeConfig.isInitialized && activeConfig.persistCookiesAndStorage) {
                    flushPersistentCookies()
                }
                launchSanitizedExternalIntent(
                    url = decision.url,
                    targetPackage = decision.targetPackage,
                    action = decision.action
                )
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
        isBlockedScreenVisible = true
        committedHost = null
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

    /**
     * Updates the header during provisional navigation without spoofing a verified green lock (`🔒`)
     * for an uncommitted destination. If a page is already committed and visible on screen, its
     * hostname remains displayed until the new document commits.
     */
    private fun updateProvisionalLoadingHeader() {
        runOnUiThread {
            if (!::lockIconView.isInitialized || !::hostnameView.isInitialized) return@runOnUiThread
            val currentCommitted = committedHost
            if (!currentCommitted.isNullOrBlank() && !isBlockedScreenVisible) {
                lockIconView.text = "\uD83D\uDD12"
                lockIconView.setTextColor(Color.parseColor("#16A34A"))
                hostnameView.text = currentCommitted
            } else if (!isBlockedScreenVisible) {
                lockIconView.text = "\u2026" // Neutral ellipsis while connecting
                lockIconView.setTextColor(Color.parseColor("#64748B"))
                hostnameView.text = activeConfig.brandTitle
            }
        }
    }

    private fun syncCommittedHostHeader(view: WebView?, callbackUrl: String?) {
        if (isBlockedScreenVisible) return
        val candidateUrl = view?.url?.takeIf { it.isNotBlank() } ?: callbackUrl ?: return
        if (candidateUrl == "about:blank") return

        val parsed = CanonicalUrl.parseHttpOrHttps(candidateUrl)
        if (parsed != null && parsed.scheme == "https" && parsed.host.isNotBlank()) {
            committedHost = parsed.host
            updateVerifiedHostHeader(host = parsed.host, isBlocked = false)
        }
    }

    private fun updateVerifiedHostHeader(host: String, isBlocked: Boolean) {
        runOnUiThread {
            if (!::lockIconView.isInitialized || !::hostnameView.isInitialized) return@runOnUiThread
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

    @SuppressLint("SetJavaScriptEnabled", "RequiresFeature")
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
        // Support user-initiated popup windows (e.g., Google 2-Step Verification & OAuth popups) by
        // intercepting them in WebChromeClient.onCreateWindow and routing their URLs through the
        // policy evaluator into the single main WebView.
        settings.setSupportMultipleWindows(true)
        settings.javaScriptCanOpenWindowsAutomatically = false
        settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
        settings.mediaPlaybackRequiresUserGesture = true
        settings.builtInZoomControls = true
        settings.displayZoomControls = false
        settings.useWideViewPort = true
        settings.loadWithOverviewMode = true
        settings.cacheMode = WebSettings.LOAD_NO_CACHE

        if (activeConfig.stripWebViewUserAgentToken) {
            settings.userAgentString = MinimalCustomTabsService.sanitizeCustomTabUserAgent(
                settings.userAgentString
            )
        }

        if (!activeConfig.allowDownloads) {
            wv.setDownloadListener { _, _, _, _, _ ->
                // Downloads disabled by default
            }
        }

        val cookieManager = CookieManager.getInstance()
        cookieManager.setAcceptCookie(true)
        // Cross-domain OAuth / 2SV challenges (e.g. accounts.google.com <-> myaccount.google.com)
        // require cookies during the ephemeral session; all cookies are wiped on close/timeout/new-intent.
        cookieManager.setAcceptThirdPartyCookies(wv, true)

        // Inject media/MSE/WebRTC/CSS lockdown at document start across ALL frames (including iframes)
        runCatching {
            if (WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)) {
                WebViewCompat.addDocumentStartJavaScript(
                    wv,
                    MediaStreamBlocker.buildLockdownJavascript(activeConfig),
                    setOf("*")
                )
            }
        }

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
                // Reject background/automated popups not triggered by an explicit user gesture
                if (!isUserGesture) return false
                val transport = resultMsg?.obj as? WebView.WebViewTransport ?: return false

                val popupWebView = WebView(this@IntentBrowserActivity).apply {
                    settings.javaScriptEnabled = false
                    settings.allowFileAccess = false
                    settings.allowContentAccess = false
                    settings.setGeolocationEnabled(false)
                    settings.domStorageEnabled = false
                    settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
                }
                activePopupWebViews.add(popupWebView)

                val timeoutCleanup = Runnable {
                    destroyPopupWebView(popupWebView)
                }
                mainHandler.postDelayed(timeoutCleanup, POPUP_CAPTURE_TIMEOUT_MS)

                popupWebView.webViewClient = object : WebViewClient() {
                    private var handled = false

                    private fun handlePopupTargetUrl(targetUrl: String?) {
                        if (handled) return
                        handled = true
                        mainHandler.removeCallbacks(timeoutCleanup)
                        destroyPopupWebView(popupWebView)
                        if (!targetUrl.isNullOrBlank() && targetUrl != "about:blank") {
                            val decision = policyEvaluator.evaluateMainFrameNavigation(
                                rawUrl = targetUrl,
                                isInitialLaunch = false,
                                isServerRedirect = false
                            )
                            applyMainFrameDecision(decision, loadIntoWebViewOnAllow = true)
                        }
                    }

                    override fun shouldOverrideUrlLoading(
                        popupView: WebView?,
                        request: WebResourceRequest?
                    ): Boolean {
                        handlePopupTargetUrl(request?.url?.toString())
                        return true
                    }

                    override fun shouldInterceptRequest(
                        popupView: WebView?,
                        request: WebResourceRequest?
                    ): WebResourceResponse? {
                        val targetUrl = request?.url?.toString()
                        if (!targetUrl.isNullOrBlank() && targetUrl != "about:blank") {
                            mainHandler.post { handlePopupTargetUrl(targetUrl) }
                        }
                        return BlockedPageRenderer.createEmptyBlockedSubResourceResponse()
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
                        requestHeaders = request.requestHeaders ?: emptyMap(),
                        isSubFrameNavigation = true
                    )
                    return subDecision !is PolicyDecision.Allow
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
                    val isRedirect = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        req.isRedirect
                    } else {
                        false
                    }
                    val mainInterceptDecision = policyEvaluator.evaluateMainFrameInterceptRequest(
                        rawUrl = targetUrl,
                        method = req.method ?: "GET",
                        requestHeaders = headers,
                        isServerRedirect = isRedirect
                    )
                    return when (mainInterceptDecision) {
                        is PolicyDecision.Allow -> null
                        is PolicyDecision.Block -> {
                            isBlockedScreenVisible = true
                            committedHost = null
                            updateVerifiedHostHeader(
                                host = mainInterceptDecision.host.ifBlank { activeConfig.brandTitle },
                                isBlocked = true
                            )
                            BlockedPageRenderer.createBlockedHtmlResponse(mainInterceptDecision, activeConfig)
                        }
                        is PolicyDecision.HandOffToNativeApp,
                        is PolicyDecision.UpgradeToHttps -> {
                            mainHandler.post {
                                applyMainFrameDecision(mainInterceptDecision, loadIntoWebViewOnAllow = true)
                            }
                            BlockedPageRenderer.createEmptyBlockedSubResourceResponse()
                        }
                    }
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
                    updateProvisionalLoadingHeader()
                }
                injectMediaLockdownScript(view)
            }

            override fun onPageCommitVisible(view: WebView?, url: String?) {
                super.onPageCommitVisible(view, url)
                syncCommittedHostHeader(view, url)
                injectMediaLockdownScript(view)
            }

            override fun doUpdateVisitedHistory(view: WebView?, url: String?, isReload: Boolean) {
                super.doUpdateVisitedHistory(view, url, isReload)
                syncCommittedHostHeader(view, url)
            }

            override fun onPageFinished(view: WebView?, url: String?) {
                super.onPageFinished(view, url)
                syncCommittedHostHeader(view, url)
                injectMediaLockdownScript(view)
                if (activeConfig.persistCookiesAndStorage) {
                    flushPersistentCookies()
                }
                if (url != null && url != "about:blank") {
                    policyEvaluator.markRedirectGraceComplete()
                }
            }

            override fun onReceivedSslError(
                view: WebView?,
                handler: SslErrorHandler?,
                error: SslError?
            ) {
                handler?.cancel()
                val failingUrl = error?.url.orEmpty()
                val failingHost = CanonicalUrl.parseHttpOrHttps(failingUrl)?.host.orEmpty()
                renderBlockedScreen(
                    PolicyDecision.Block(
                        reason = BlockReason.INSECURE_OR_INVALID_SCHEME,
                        url = failingUrl,
                        host = failingHost
                    )
                )
            }

            override fun onReceivedError(
                view: WebView?,
                request: WebResourceRequest?,
                error: WebResourceError?
            ) {
                super.onReceivedError(view, request, error)
                if (request?.isForMainFrame == true) {
                    syncCommittedHostHeader(view, view?.url)
                }
            }
        }

        return wv
    }

    private fun destroyPopupWebView(popupView: WebView?) {
        if (popupView == null) return
        activePopupWebViews.remove(popupView)
        runCatching {
            popupView.stopLoading()
            popupView.destroy()
        }
    }

    private fun destroyAllPopupWebViews() {
        val snapshot = activePopupWebViews.toList()
        activePopupWebViews.clear()
        for (popup in snapshot) {
            runCatching {
                popup.stopLoading()
                popup.destroy()
            }
        }
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
            text = "\u2026"
            setTextColor(Color.parseColor("#64748B"))
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
        sessionStartElapsedRealtimeMs = SystemClock.elapsedRealtime()
        val timeoutMs = activeConfig.sessionTimeoutMs
        if (timeoutMs > 0L) {
            mainHandler.postDelayed(sessionTimeoutRunnable, timeoutMs)
        }
    }

    /**
     * Launches an external native application or custom OAuth callback scheme.
     *
     * When [targetPackage] is configured, retries without `CATEGORY_BROWSABLE` **only within that
     * same [targetPackage]** and never falls back to an unpinned broadcast (preventing OAuth
     * authorization code interception by scheme-squatting apps).
     */
    private fun launchSanitizedExternalIntent(
        url: String,
        targetPackage: String?,
        action: String = Intent.ACTION_VIEW
    ) {
        val resolvedAction = action.trim().takeIf { it.isNotEmpty() } ?: Intent.ACTION_VIEW
        val cleanTargetPackage = targetPackage?.trim()?.takeIf { it.isNotEmpty() }

        runCatching {
            val handoffIntent = buildSanitizedHandoffIntent(
                url = url,
                action = resolvedAction,
                targetPackage = cleanTargetPackage,
                requireBrowsable = true
            )
            startActivity(handoffIntent)
        }.onFailure {
            // Option 2A: If a specific targetPackage is configured and its callback Activity declared
            // CATEGORY_DEFAULT without CATEGORY_BROWSABLE, retry still pinned to targetPackage.
            // Never drop targetPackage!
            if (cleanTargetPackage != null) {
                runCatching {
                    val pinnedFallbackIntent = buildSanitizedHandoffIntent(
                        url = url,
                        action = resolvedAction,
                        targetPackage = cleanTargetPackage,
                        requireBrowsable = false
                    )
                    startActivity(pinnedFallbackIntent)
                }
            }
        }
    }

    /**
     * Immediately destroys the session, wipes cache/history (and cookies/storage unless
     * [BrowserPolicyConfig.persistCookiesAndStorage] is enabled), and finishes the activity.
     */
    fun closeAndWipeSession() {
        mainHandler.removeCallbacks(sessionTimeoutRunnable)
        destroyAllPopupWebViews()
        if (!isSessionWiped) {
            isSessionWiped = true
            val currentWv = webView
            webView = null
            if (currentWv != null && ::webContainer.isInitialized) {
                webContainer.removeView(currentWv)
            }
            val persistCookies = ::activeConfig.isInitialized && activeConfig.persistCookiesAndStorage
            wipeEphemeralWebData(applicationContext, currentWv, persistCookies)
        }
        if (!isFinishing) {
            finishAndRemoveTask()
        }
    }

    override fun onDestroy() {
        mainHandler.removeCallbacks(sessionTimeoutRunnable)
        destroyAllPopupWebViews()
        if (!isSessionWiped) {
            isSessionWiped = true
            val currentWv = webView
            webView = null
            if (currentWv != null && ::webContainer.isInitialized) {
                webContainer.removeView(currentWv)
            }
            val persistCookies = ::activeConfig.isInitialized && activeConfig.persistCookiesAndStorage
            wipeEphemeralWebData(applicationContext, currentWv, persistCookies)
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

        private const val POPUP_CAPTURE_TIMEOUT_MS = 3_000L

        @JvmStatic
        internal fun buildSanitizedHandoffIntent(
            url: String,
            action: String = Intent.ACTION_VIEW,
            targetPackage: String? = null,
            requireBrowsable: Boolean = true
        ): Intent {
            val resolvedAction = action.trim().takeIf { it.isNotEmpty() } ?: Intent.ACTION_VIEW
            return Intent(resolvedAction, Uri.parse(url)).apply {
                if (requireBrowsable) {
                    addCategory(Intent.CATEGORY_BROWSABLE)
                } else {
                    addCategory(Intent.CATEGORY_DEFAULT)
                }
                component = null
                selector = null
                if (!targetPackage.isNullOrBlank()) {
                    setPackage(targetPackage.trim())
                }
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
        }

        @JvmStatic
        internal fun wipeSessionStorageOnly(context: Context?) {
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
        }

        @JvmStatic
        internal fun flushPersistentCookies() {
            runCatching {
                CookieManager.getInstance().flush()
            }
        }

        /**
         * Wipes ephemeral WebView state (cache, form data, history, SSL preferences, and WebView instance).
         * When [persistCookiesAndStorage] is `false` (default), also wipes all cookies, `WebStorage`,
         * and HTTP auth credentials. When `true`, preserves cookies and `WebStorage` and flushes cookies to disk.
         */
        @JvmStatic
        @JvmOverloads
        fun wipeEphemeralWebData(
            context: Context?,
            webView: WebView?,
            persistCookiesAndStorage: Boolean = false
        ) {
            if (persistCookiesAndStorage) {
                flushPersistentCookies()
            } else {
                wipeSessionStorageOnly(context)
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
