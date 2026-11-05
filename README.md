# HM01 — Headless Intent & Auth Browser for Android

**`HM01`** is an open-source, distraction-free, **Intent-Only ("Link-In, Look, Close") Browser and Custom Tabs Provider** for Android.

It solves a critical problem for digital-minimalism setups, parental control DPCs, and enterprise/kiosk devices: **how to remove full web browsers (like Chrome) without breaking everyday life.** When someone texts you a link to a birthday gift idea, a restaurant menu, a package tracking page, or when an app launches an OAuth/SSO sign-in flow, `HM01` opens the link cleanly—while making mindless web surfing, video streaming, adult content, and rabbit-hole doomscrolling impossible.

---

## Core Design Principles

1. **No Address Bar, No Search Bar, No Launcher Icon:** Users cannot open `HM01` on their own or type a URL. It only wakes up when invoked by an external `https://` link (`ACTION_VIEW`) or an in-app OAuth Custom Tab request.
2. **No Tabs, No Bookmarks, No Persistent History:** When the window is closed (or times out), cookies, `WebStorage`, cache, and history are wiped.
3. **Forced CleanBrowsing Family Filter DNS-over-HTTPS (DoH):** Every hostname is verified against CleanBrowsing's `FAMILY_FILTER` DoH endpoint (`RFC 8484` wireformat with pinned IP bootstrap) before the `WebView` connects, blocking adult sites, proxies/VPN bypasses, and malware at the application layer regardless of OS network settings.
4. **Anti-Escape-Hatch ("Link Leash"):** Users can view the link they tapped and navigate within that website (or complete OAuth/payment flows), with a maximum of `1` external domain hop after initial redirect resolution, and cannot use footer links to jump to Google Search, Bing, DuckDuckGo, or social feeds.
5. **Video & Audio Stream Lockdown:** Blocks video and audio streams at both the network interception layer (`.mp4`, `.m3u8`, `Accept: video/*`, `Sec-Fetch-Dest: video|audio`, byte-range streams) and DOM/JS layer (`HTMLMediaElement.prototype.play`, `MediaSource`, `RTCPeerConnection`).
6. **Pluggable Blocklist Architecture:** `HM01` remains neutral and multipurpose for the broader developer community, while a host app (such as a digital-wellbeing launcher, parental control DPC, or kiosk manager) can inject its own custom domain, keyword, and URL-path regex blocklists programmatically or via Android Enterprise Managed Configurations (`RestrictionsManager`).

---

## Project Structure

- **`:hm01-core`** — Reusable Android Library (`.aar`) containing `IntentBrowserActivity`, `MinimalCustomTabsService`, `DohResolver`, `UrlPolicyEvaluator`, `MediaStreamBlocker`, and `BrowserPolicyProvider`.
- **`:app`** — Thin wrapper producing a standalone open-source APK with Android Enterprise Managed Configurations (`res/xml/app_restrictions.xml`).

---

## Embedding `:hm01-core` in a Host App

### Option A: Link via Gradle Composite Build (`settings.gradle.kts`)

```kotlin
includeBuild("../HM01") {
    dependencySubstitution {
        substitute(module("dev.hm01:hm01-core")).using(project(":hm01-core"))
    }
}
```

### Option B: Consume via JitPack (`settings.gradle.kts`)

```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}
```

### Add Dependency (`app/build.gradle.kts`)

```kotlin
dependencies {
    implementation("dev.hm01:hm01-core:1.0.0") // Or com.github.turney267:HM01:main-SNAPSHOT via JitPack
}
```

### Configure Policy at Runtime

```kotlin
import dev.hm01.browser.config.BrowserPolicyConfig
import dev.hm01.browser.config.BrowserPolicyProvider
import dev.hm01.browser.config.CustomSchemeTarget
import dev.hm01.browser.config.DohPreset

BrowserPolicyProvider.configure(
    BrowserPolicyConfig(
        brandTitle = "Safe Link Viewer",
        dohPreset = DohPreset.CLEANBROWSING_FAMILY,
        blockedDomains = setOf("reddit.com", "substack.com", "news.ycombinator.com"),
        blockedHostKeywords = setOf("gossip", "tabloid"),
        blockedPathRegexes = listOf("^/reels", "^/shorts", "^/trending"),
        customCallbackSchemes = mapOf(
            "myapp" to CustomSchemeTarget(scheme = "myapp", targetPackage = "com.example.myapp")
        ),
        maxExternalDomainHops = 1,
        sessionTimeoutMs = 10 * 60 * 1000L,
        blockVideoAndAudio = true,
        capImageDimensions = false
    )
)
```

---

## Managing the Standalone APK (MDM / Device Owner DPC)

When deployed as a standalone APK (`:app`), `HM01` automatically reads Android Enterprise Managed Configurations via `RestrictionsManager`:

| Restriction Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `brand_title` | `string` | `"HM01"` | Header title displayed on policy block screens |
| `doh_preset` | `choice` | `"CLEANBROWSING_FAMILY"` | `CLEANBROWSING_FAMILY`, `CLEANBROWSING_ADULT`, `CLEANBROWSING_SECURITY`, or `CUSTOM` |
| `custom_doh_url` | `string` | `""` | Custom RFC 8484 DoH endpoint URL when `doh_preset` is `CUSTOM` |
| `fail_closed_on_dns_error` | `bool` | `false` | Block non-IdP domains if the DoH endpoint is unreachable |
| `blocked_domains` | `string` | `""` | Comma-separated domains to block (exact + subdomain suffix match) |
| `blocked_keywords` | `string` | `""` | Comma-separated hostname keywords to block |
| `blocked_path_regexes` | `string` | `""` | Comma-separated URL path regexes to block (e.g. `^/reels, ^/shorts`) |
| `allowed_domains_override` | `string` | `""` | Comma-separated domains explicitly permitted |
| `max_external_domain_hops` | `integer` | `1` | Maximum external domain hops allowed from the landing domain |
| `max_total_navigation_hops` | `integer` | `45` | Maximum total main-frame navigations per session |
| `session_timeout_seconds` | `integer` | `600` | Auto-close and wipe timeout in seconds |
| `block_video_audio` | `bool` | `true` | Block video/audio streams, MSE, WebRTC, and HTML5 media playback |
| `cap_image_dimensions` | `bool` | `false` | Cap rendered images to `240x240px` |
| `block_search_engines` | `bool` | `true` | Block general search engines, web translators, and archive mirrors |

---

## Building & Running Tests

```bash
./gradlew testDebugUnitTest assembleDebug assembleRelease
```

---

## Acknowledgments

Designed and specified by [@turney267](https://github.com/turney267); implemented and verified in pair-programming collaboration with Google Antigravity (Gemini).

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
