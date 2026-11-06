# HM01 — Headless Intent & Auth Browser for Android

**`HM01`** is an open-source, unopinionated, **Intent-Only ("Link-In, Look, Close") Browser and Custom Tabs Provider** for Android.

It solves a critical problem for digital-minimalism setups, parental control DPCs, and enterprise/kiosk devices: **how to remove full web browsers (like Chrome) without breaking everyday life.** When someone texts you a link to a birthday gift idea, a restaurant menu, or a package tracking page—or when an app launches an OAuth/SSO/2FA sign-in flow—`HM01` opens the link cleanly while giving the host developer complete control over DNS filtering, domain/path rules, external hop limits, and media lockdown.

---

## Core Design Principles

1. **No Address Bar, No Search Bar, No Launcher Icon:** Users cannot open `HM01` on their own or type a URL. It wakes up only when invoked by an external `https://` link (`ACTION_VIEW`) or an in-app OAuth Custom Tab request.
2. **No Tabs, No Bookmarks, No Persistent History:** When the window is closed, times out, or receives a new intent, all cookies, `WebStorage`, HTTP auth credentials, cache, and history are immediately wiped.
3. **Unopinionated Engine — Developer & User in Control:** Out of the box, `HM01` ships with **empty** website blocklists (plus a single illustrative example for path-scoped rules and media extensions) and **zero** hardcoded third-party DNS providers. Every policy decision outside the chosen DNS server is configured by the host application.
4. **Configurable RFC 8484 DNS-over-HTTPS (DoH):** Supports developer-fixed DoH endpoints (`DnsMode.DEVELOPER_FIXED`), user-selectable DoH provider lists with optional custom DoH input (`DnsMode.USER_DEFINED`), or disabled DoH (`DnsMode.DISABLED`), using EDNS(0)-padded HTTPS `POST` requests and failing closed on DNS errors by default.
5. **1-Hop "Link Leash" (Easily Modified or Removed):** By default, users can browse within the website they opened and take at most `1` external domain hop (`maxExternalDomainHops = 1`). Developers can change the hop limit (`withLinkLeash(n)`) or remove it completely (`withoutLinkLeash()` / `maxExternalDomainHops = null`).
6. **Configurable Media Lockdown & Path-Scoped OAuth:** Developers can supply custom lists of blocked media extensions/MIME types and path-scoped platform rules (allowing `/login` or `/oauth` on a platform while blocking its social feed), enforced across main-frame `GET`/`POST` navigations and all `<iframe>` sub-frames.

---

## Project Structure

- **`:hm01-core`** — Reusable Android Library (`.aar`) containing `IntentBrowserActivity`, `MinimalCustomTabsService`, `DohResolver`, `UrlPolicyEvaluator`, `CanonicalUrl`, `MediaStreamBlocker`, and `BrowserPolicyProvider`.
- **`:app`** — Thin wrapper producing a standalone open-source APK with Android Enterprise Managed Configurations (`res/xml/app_restrictions.xml`).

---

## Embedding `:hm01-core` in a Host App

### Option A: Link via Gradle Composite Build (`settings.gradle.kts`)

```kotlin
includeBuild("../HM01") {
    dependencySubstitution {
        substitute(module("com.github.turney267:hm01-core")).using(project(":hm01-core"))
    }
}
```

### Option B: Consume via JitPack (`settings.gradle.kts`)

```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven("https://jitpack.io")
    }
}
```

### Add Dependency (`app/build.gradle.kts`)

Pin an immutable release tag or commit SHA:

```kotlin
dependencies {
    implementation("com.github.turney267.HM01:hm01-core:v1.0.0")
}
```

### Configure Policy at Runtime

```kotlin
import dev.hm01.browser.config.BrowserPolicyConfig
import dev.hm01.browser.config.BrowserPolicyProvider
import dev.hm01.browser.config.CustomSchemeTarget
import dev.hm01.browser.config.DnsMode
import dev.hm01.browser.config.DnsProviderOption
import dev.hm01.browser.config.PathScopedPlatformRule

val dnsOptions = listOf(
    DnsProviderOption("adguard_family", "AdGuard Family", "https://family.adguard-dns.com/dns-query"),
    DnsProviderOption("cloudflare_family", "Cloudflare Family", "https://family.cloudflare-dns.com/dns-query")
)

BrowserPolicyProvider.configure(
    BrowserPolicyConfig(
        brandTitle = "Safe Link Viewer",
        dnsMode = DnsMode.USER_DEFINED,
        userDnsOptions = dnsOptions,
        failClosedOnDnsError = true,
        allowCustomUserDohUrl = true,
        blockedDomains = setOf("reddit.com", "substack.com", "news.ycombinator.com"),
        blockedHostKeywords = setOf("gossip", "tabloid"),
        blockedPathRegexes = listOf("^/(reels?|shorts|stories)(/|$)"),
        pathScopedPlatformRules = listOf(
            // Default example included in HM01: allow GitHub login/2FA, block repo browsing
            PathScopedPlatformRule(
                domain = "github.com",
                allowedPathPrefixes = listOf("/login", "/sessions", "/settings/two_factor")
            )
        ),
        customCallbackSchemes = mapOf(
            "myapp" to CustomSchemeTarget(scheme = "myapp", targetPackage = "com.example.myapp")
        ),
        allowUnregisteredCustomSchemes = false,
        allowThirdPartyIframes = false,
        stripWebViewUserAgentToken = true,
        maxExternalDomainHops = 1, // Call .withoutLinkLeash() or set to null to disable
        sessionTimeoutMs = 10 * 60 * 1000L,
        blockVideoAndAudio = true,
        blockedMediaExtensions = setOf(".mp4", ".webm", ".m3u8", ".mp3"),
        blockedMediaMimePrefixes = setOf("video/", "audio/")
    )
)

// Persist the user's selected DNS provider or custom DoH endpoint URL:
BrowserPolicyProvider.setUserSelectedDns(
    context = applicationContext,
    optionId = "cloudflare_family",
    dohEndpointUrl = "https://family.cloudflare-dns.com/dns-query"
)
```

### Optional: Restricting `:hm01-core` to Internal In-App Links Only

By default, `:hm01-core` exports `IntentBrowserActivity` and `MinimalCustomTabsService` so DPC and browser-replacement apps work out of the box. If a host app only wants to use `IntentBrowserActivity` internally without registering as a system-wide browser or Custom Tabs provider, add the following override to the host app's `AndroidManifest.xml`:

```xml
<application xmlns:tools="http://schemas.android.com/tools">
    <activity android:name="dev.hm01.browser.IntentBrowserActivity" android:exported="false">
        <intent-filter tools:node="removeAll" />
    </activity>
    <service android:name="dev.hm01.browser.MinimalCustomTabsService" tools:node="remove" />
</application>
```

---

## Managing the Standalone APK (MDM / Device Owner DPC)

When deployed as a standalone APK (`:app`), `HM01` reads Android Enterprise Managed Configurations via `RestrictionsManager`:

| Restriction Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `brand_title` | `string` | `"HM01"` | Header title displayed on policy block screens |
| `custom_doh_url` | `string` | `""` | RFC 8484 HTTPS DNS-over-HTTPS endpoint URL |
| `fail_closed_on_dns_error` | `bool` | `true` | Block non-IdP domains if the DoH endpoint is unreachable |
| `allow_custom_user_doh_url` | `bool` | `true` | Allow custom HTTPS DoH URLs outside `userDnsOptions` |
| `blocked_domains` | `string` | `""` | Comma-separated domains to block (exact + subdomain suffix match) |
| `blocked_keywords` | `string` | `""` | Comma-separated hostname keywords to block |
| `blocked_path_regexes` | `string` | `""` | Comma- or newline-separated URL path regexes to block (preserves `{m,n}` quantifiers) |
| `allowed_domains_override` | `string` | `""` | Comma-separated domains explicitly permitted |
| `allow_unregistered_custom_schemes` | `bool` | `false` | Permit custom URI schemes not explicitly declared in `customCallbackSchemes` |
| `allow_third_party_iframes` | `bool` | `false` | Permit cross-domain iframes beyond the active domain and trusted IdP/Payment/Captcha hosts |
| `strip_webview_user_agent_token` | `bool` | `true` | Strip `; wv` and `Version/X.Y` tokens for Custom Tabs OAuth compatibility |
| `max_external_domain_hops` | `integer` | `1` | Maximum external domain hops allowed (`-1` to disable Link Leash) |
| `max_total_navigation_hops` | `integer` | `45` | Maximum total main-frame navigations per session |
| `session_timeout_seconds` | `integer` | `600` | Auto-close and wipe timeout in seconds |
| `block_video_audio` | `bool` | `true` | Block configured video/audio streams, MSE, WebRTC, and HTML5 media |
| `cap_image_dimensions` | `bool` | `false` | Cap rendered images to `240x240px` |
| `block_search_engines` | `bool` | `true` | Block developer-configured search engine and proxy domains |

---

## Building & Running Tests

```bash
./gradlew testDebugUnitTest compileDebugAndroidTestKotlin assembleDebug assembleRelease
```

---

## Acknowledgments

Designed and specified by [@turney267](https://github.com/turney267); implemented and verified in pair-programming collaboration with Google Antigravity (Gemini).

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
