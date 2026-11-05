package dev.hm01.browser.filter

import dev.hm01.browser.config.BrowserPolicyConfig
import dev.hm01.browser.config.DefaultBaselineLists
import java.net.URI
import java.util.Locale

/**
 * Enforces video, audio, and media streaming lockdown at both the network interception layer
 * and the DOM/JavaScript layer.
 */
object MediaStreamBlocker {

    val BLOCKED_MEDIA_EXTENSIONS: Set<String> = setOf(
        ".mp4",
        ".webm",
        ".m3u8",
        ".mpd",
        ".ts",
        ".m4s",
        ".mov",
        ".avi",
        ".mkv",
        ".flv",
        ".gifv",
        ".mp3",
        ".m4a",
        ".ogg",
        ".wav"
    )

    val BLOCKED_SEC_FETCH_DESTS: Set<String> = setOf(
        "video",
        "audio",
        "object",
        "embed"
    )

    /**
     * Evaluates whether a network request should be blocked as a video/audio/media stream.
     *
     * @param url Full request URL string.
     * @param requestHeaders Case-insensitive or raw HTTP request headers map.
     * @param config Active [BrowserPolicyConfig].
     * @return `true` if the request is a blocked media stream and should be intercepted with a 403/empty response.
     */
    @JvmStatic
    fun shouldBlockMediaRequest(
        url: String,
        requestHeaders: Map<String, String> = emptyMap(),
        config: BrowserPolicyConfig = BrowserPolicyConfig()
    ): Boolean {
        if (!config.blockVideoAndAudio) return false

        val parsed = runCatching { URI(url) }.getOrNull()
        val host = parsed?.host ?: extractFallbackHost(url)
        val path = (parsed?.rawPath ?: extractFallbackPath(url)).lowercase(Locale.ROOT)

        // 1. Check media file extensions on the URL path
        if (hasBlockedMediaExtension(path)) {
            return true
        }

        // Normalize header lookup
        var acceptHeader: String? = null
        var secFetchDest: String? = null
        var rangeHeader: String? = null

        for ((rawKey, rawValue) in requestHeaders) {
            when (rawKey.trim().lowercase(Locale.ROOT)) {
                "accept" -> acceptHeader = rawValue.trim().lowercase(Locale.ROOT)
                "sec-fetch-dest" -> secFetchDest = rawValue.trim().lowercase(Locale.ROOT)
                "range" -> rangeHeader = rawValue.trim().lowercase(Locale.ROOT)
            }
        }

        // 2. Check Sec-Fetch-Dest header (video | audio | object | embed)
        if (secFetchDest != null && secFetchDest in BLOCKED_SEC_FETCH_DESTS) {
            return true
        }

        // 3. Check Accept header for video/* or audio/* media requests
        if (acceptHeader != null) {
            val isDocumentOrImageAccept = acceptHeader.startsWith("text/html") ||
                acceptHeader.startsWith("image/")
            if (!isDocumentOrImageAccept &&
                (acceptHeader.contains("video/") || acceptHeader.contains("audio/"))
            ) {
                return true
            }
        }

        // 4. Check byte-range media streaming (Range: bytes=...) except on known Captcha challenge hosts
        if (rangeHeader != null && rangeHeader.startsWith("bytes=")) {
            if (!DefaultBaselineLists.isCaptchaHost(host, path)) {
                return true
            }
        }

        return false
    }

    /**
     * Checks whether [rawPath] ends with any blocked video or audio file extension.
     */
    @JvmStatic
    fun hasBlockedMediaExtension(rawPath: String): Boolean {
        val cleanPath = rawPath
            .substringBefore('?')
            .substringBefore('#')
            .trim()
            .lowercase(Locale.ROOT)
        if (cleanPath.isEmpty()) return false
        return BLOCKED_MEDIA_EXTENSIONS.any { ext ->
            cleanPath.endsWith(ext)
        }
    }

    /**
     * Builds the DOM/JavaScript lockdown script injected on `onPageStarted`, `onPageCommitVisible`,
     * and `onPageFinished`.
     *
     * - Overrides `HTMLMediaElement.prototype.play` to immediately pause and reject
     * - Deletes `window.MediaSource`, `window.ManagedMediaSource`, `window.RTCPeerConnection`,
     *   and `window.webkitRTCPeerConnection`
     * - Disables `Element.prototype.requestFullscreen`
     * - Injects CSS hiding `video, audio, object, embed`
     * - Optionally caps image dimensions when [BrowserPolicyConfig.capImageDimensions] is `true`
     */
    @JvmStatic
    fun buildLockdownJavascript(config: BrowserPolicyConfig = BrowserPolicyConfig()): String {
        if (!config.blockVideoAndAudio && !config.capImageDimensions) {
            return "(function(){})();"
        }

        val mediaCss = if (config.blockVideoAndAudio) {
            "video, audio, object, embed { display: none !important; visibility: hidden !important; width: 0 !important; height: 0 !important; opacity: 0 !important; pointer-events: none !important; }"
        } else {
            ""
        }

        val imageCapCss = if (config.capImageDimensions) {
            " img, svg, picture, canvas { max-width: 240px !important; max-height: 240px !important; object-fit: contain !important; }"
        } else {
            ""
        }

        val combinedCss = (mediaCss + imageCapCss).trim()

        return """
            (function() {
                try {
                    if (${config.blockVideoAndAudio}) {
                        if (typeof HTMLMediaElement !== 'undefined' && HTMLMediaElement.prototype) {
                            HTMLMediaElement.prototype.play = function() {
                                try { this.pause(); this.removeAttribute('src'); this.load(); } catch (e) {}
                                return Promise.reject(new DOMException('Media playback is disabled by HM01 policy.', 'NotAllowedError'));
                            };
                        }
                        try { delete window.MediaSource; window.MediaSource = undefined; } catch (e) {}
                        try { delete window.ManagedMediaSource; window.ManagedMediaSource = undefined; } catch (e) {}
                        try { delete window.RTCPeerConnection; window.RTCPeerConnection = undefined; } catch (e) {}
                        try { delete window.webkitRTCPeerConnection; window.webkitRTCPeerConnection = undefined; } catch (e) {}
                        if (typeof Element !== 'undefined' && Element.prototype) {
                            Element.prototype.requestFullscreen = function() {
                                return Promise.reject(new DOMException('Fullscreen is disabled by HM01 policy.', 'NotAllowedError'));
                            };
                            Element.prototype.webkitRequestFullscreen = Element.prototype.requestFullscreen;
                        }
                    }
                    var styleId = '__hm01_media_lockdown_style__';
                    if (!document.getElementById(styleId)) {
                        var style = document.createElement('style');
                        style.id = styleId;
                        style.type = 'text/css';
                        style.appendChild(document.createTextNode('$combinedCss'));
                        var target = document.head || document.documentElement;
                        if (target) {
                            target.appendChild(style);
                        }
                    }
                    if (${config.blockVideoAndAudio} && document.querySelectorAll) {
                        var mediaNodes = document.querySelectorAll('video, audio');
                        for (var i = 0; i < mediaNodes.length; i++) {
                            try {
                                mediaNodes[i].pause();
                                mediaNodes[i].removeAttribute('src');
                                mediaNodes[i].load();
                            } catch (e) {}
                        }
                    }
                } catch (err) {}
            })();
        """.trimIndent()
    }

    private fun extractFallbackHost(url: String): String {
        val afterScheme = url.substringAfter("://", "")
        return afterScheme.substringBefore('/').substringBefore(':').substringBefore('?')
    }

    private fun extractFallbackPath(url: String): String {
        val afterScheme = url.substringAfter("://", "")
        val slashIndex = afterScheme.indexOf('/')
        if (slashIndex < 0) return "/"
        return afterScheme.substring(slashIndex).substringBefore('?').substringBefore('#')
    }
}
