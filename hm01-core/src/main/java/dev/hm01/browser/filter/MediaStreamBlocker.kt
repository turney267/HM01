package dev.hm01.browser.filter

import dev.hm01.browser.config.BrowserPolicyConfig
import dev.hm01.browser.config.DefaultBaselineLists
import java.util.Locale

/**
 * Enforces video, audio, and media streaming lockdown at both the network interception layer
 * and the DOM/JavaScript layer based on the developer's [BrowserPolicyConfig].
 *
 * Out of the box, [BrowserPolicyConfig.blockedMediaExtensions] contains only a single example
 * format (`setOf(".mp4")`) and header/MIME/byte-range sets are empty until populated by the developer.
 */
object MediaStreamBlocker {

    val DEFAULT_EXAMPLE_MEDIA_EXTENSIONS: Set<String> =
        BrowserPolicyConfig.DEFAULT_EXAMPLE_MEDIA_EXTENSIONS

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

        val parsed = CanonicalUrl.parseHttpOrHttps(url) ?: return true
        val host = parsed.host
        val path = parsed.normalizedPath.lowercase(Locale.ROOT)

        // 1. Check media file extensions on the normalized URL path configured in BrowserPolicyConfig
        if (hasBlockedMediaExtension(path, config.blockedMediaExtensions)) {
            return true
        }

        if (requestHeaders.isEmpty()) return false

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

        // 2. Check Sec-Fetch-Dest header against configured blockedSecFetchDests
        if (secFetchDest != null && config.blockedSecFetchDests.isNotEmpty()) {
            if (config.blockedSecFetchDests.any { it.equals(secFetchDest, ignoreCase = true) }) {
                return true
            }
        }

        // 3. Check Accept header media ranges against configured blockedMediaMimePrefixes (e.g. "video/", "audio/")
        if (acceptHeader != null && config.blockedMediaMimePrefixes.isNotEmpty()) {
            val mediaRanges = acceptHeader
                .split(',')
                .map { it.substringBefore(';').trim() }
                .filter { it.isNotEmpty() }

            val hasBlockedMimeRange = mediaRanges.any { mediaType ->
                config.blockedMediaMimePrefixes.any { prefix ->
                    val cleanPrefix = prefix.trim().lowercase(Locale.ROOT)
                    cleanPrefix.isNotEmpty() && mediaType.startsWith(cleanPrefix)
                }
            }
            if (hasBlockedMimeRange) {
                return true
            }
        }

        // 4. Check byte-range media streaming (Range: bytes=...) when enabled
        if (config.blockByteRangeMediaRequests &&
            rangeHeader != null &&
            rangeHeader.startsWith("bytes=")
        ) {
            if (!DefaultBaselineLists.isCaptchaHost(host, path)) {
                return true
            }
        }

        return false
    }

    /**
     * Checks whether [rawPath] ends with any blocked file extension in [extensions]
     * after canonicalizing percent-encoding, dot-segments, and matrix parameters.
     */
    @JvmStatic
    @JvmOverloads
    fun hasBlockedMediaExtension(
        rawPath: String,
        extensions: Set<String> = DEFAULT_EXAMPLE_MEDIA_EXTENSIONS
    ): Boolean {
        if (extensions.isEmpty()) return false
        val pathOnly = rawPath
            .substringBefore('?')
            .substringBefore('#')
            .trim()
        if (pathOnly.isEmpty()) return false

        val normalized = (CanonicalUrl.normalizePathForPolicy(pathOnly) ?: return true)
            .trimEnd('/')
            .lowercase(Locale.ROOT)
        if (normalized.isEmpty()) return false

        return extensions.any { rawExt ->
            val ext = rawExt.trim().lowercase(Locale.ROOT).let {
                if (it.startsWith(".")) it else ".$it"
            }
            ext.length > 1 && normalized.endsWith(ext)
        }
    }

    /**
     * Builds the DOM/JavaScript lockdown script injected at document start (across all frames via
     * `WebViewCompat.addDocumentStartJavaScript`) and on `onPageStarted`, `onPageCommitVisible`,
     * and `onPageFinished`.
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
                    if (typeof document !== 'undefined' && !document.getElementById(styleId)) {
                        var style = document.createElement('style');
                        style.id = styleId;
                        style.type = 'text/css';
                        style.appendChild(document.createTextNode('$combinedCss'));
                        var target = document.head || document.documentElement;
                        if (target) {
                            target.appendChild(style);
                        }
                    }
                    if (${config.blockVideoAndAudio} && typeof document !== 'undefined' && document.querySelectorAll) {
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
}
