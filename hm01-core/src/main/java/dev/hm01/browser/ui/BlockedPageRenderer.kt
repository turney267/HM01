package dev.hm01.browser.ui

import android.webkit.WebResourceResponse
import dev.hm01.browser.config.BrowserPolicyConfig
import dev.hm01.browser.filter.PolicyDecision
import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets

/**
 * Renders a clean, minimal, distraction-free HTML block screen and [WebResourceResponse]
 * for blocked navigations and sub-resources.
 */
object BlockedPageRenderer {

    /**
     * Generates a self-contained, link-free HTML page describing why the navigation was blocked.
     */
    @JvmStatic
    fun buildBlockedHtml(
        decision: PolicyDecision.Block,
        config: BrowserPolicyConfig = BrowserPolicyConfig()
    ): String {
        val brand = escapeHtml(config.brandTitle)
        val title = escapeHtml(decision.reason.title)
        val message = escapeHtml(decision.detail)
        val hostBadge = if (decision.host.isNotBlank()) {
            """<div class="host">${escapeHtml(decision.host)}</div>"""
        } else {
            ""
        }

        return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
                <title>$title — $brand</title>
                <style>
                    :root {
                        color-scheme: light dark;
                    }
                    * {
                        box-sizing: border-box;
                        margin: 0;
                        padding: 0;
                    }
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                        background-color: #f8fafc;
                        color: #0f172a;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        min-height: 85vh;
                        padding: 24px;
                        text-align: center;
                    }
                    @media (prefers-color-scheme: dark) {
                        body {
                            background-color: #0f172a;
                            color: #f1f5f9;
                        }
                        .card {
                            background-color: #1e293b !important;
                            border-color: #334155 !important;
                        }
                        .host {
                            background-color: #0f172a !important;
                            color: #94a3b8 !important;
                        }
                        .msg {
                            color: #cbd5e1 !important;
                        }
                    }
                    .card {
                        max-width: 420px;
                        width: 100%;
                        background-color: #ffffff;
                        border: 1px solid #e2e8f0;
                        border-radius: 16px;
                        padding: 32px 24px;
                        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.04);
                    }
                    .badge {
                        display: inline-block;
                        font-size: 11px;
                        font-weight: 700;
                        letter-spacing: 0.08em;
                        text-transform: uppercase;
                        color: #64748b;
                        margin-bottom: 12px;
                    }
                    h1 {
                        font-size: 20px;
                        font-weight: 600;
                        margin-bottom: 12px;
                        line-height: 1.3;
                    }
                    .msg {
                        font-size: 15px;
                        line-height: 1.5;
                        color: #475569;
                        margin-bottom: 18px;
                    }
                    .host {
                        display: inline-block;
                        font-family: monospace;
                        font-size: 13px;
                        background-color: #f1f5f9;
                        color: #475569;
                        padding: 6px 12px;
                        border-radius: 8px;
                        word-break: break-all;
                    }
                </style>
            </head>
            <body>
                <div class="card">
                    <div class="badge">$brand Policy</div>
                    <h1>$title</h1>
                    <p class="msg">$message</p>
                    $hostBadge
                </div>
            </body>
            </html>
        """.trimIndent()
    }

    /**
     * Creates an empty `403 Forbidden` [WebResourceResponse] for blocked background sub-resources.
     */
    @JvmStatic
    fun createEmptyBlockedSubResourceResponse(): WebResourceResponse {
        return WebResourceResponse(
            "text/plain",
            "UTF-8",
            403,
            "Blocked by HM01 Policy",
            mapOf("Cache-Control" to "no-store"),
            ByteArrayInputStream(ByteArray(0))
        )
    }

    /**
     * Creates an HTML `403 Forbidden` [WebResourceResponse] for blocked main-frame requests.
     */
    @JvmStatic
    fun createBlockedHtmlResponse(
        decision: PolicyDecision.Block,
        config: BrowserPolicyConfig = BrowserPolicyConfig()
    ): WebResourceResponse {
        val htmlBytes = buildBlockedHtml(decision, config).toByteArray(StandardCharsets.UTF_8)
        return WebResourceResponse(
            "text/html",
            "UTF-8",
            403,
            "Blocked by HM01 Policy",
            mapOf("Cache-Control" to "no-store"),
            ByteArrayInputStream(htmlBytes)
        )
    }

    internal fun escapeHtml(input: String): String {
        val sb = StringBuilder(input.length)
        for (ch in input) {
            when (ch) {
                '&' -> sb.append("&amp;")
                '<' -> sb.append("&lt;")
                '>' -> sb.append("&gt;")
                '"' -> sb.append("&quot;")
                '\'' -> sb.append("&#39;")
                else -> sb.append(ch)
            }
        }
        return sb.toString()
    }
}
