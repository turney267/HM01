# Technical Specification: `HM01` — Headless Intent & Auth Browser

## 1. Executive Summary & Product Vision

**`HM01`** is an open-source, distraction-free, **Intent-Only ("Link-In, Look, Close") Browser and Custom Tabs Provider** for Android.

It solves a critical problem for digital-minimalism setups, parental control DPCs, and enterprise/kiosk devices: **how to remove full web browsers (like Chrome) without breaking everyday life.** When someone texts you a link to a birthday gift idea, a restaurant menu, a package tracking page, or when an app launches an OAuth/SSO sign-in flow, `HM01` opens the link cleanly—while making mindless web surfing, video streaming, adult content, and rabbit-hole doomscrolling impossible.

### Core Design Principles
1. **No Address Bar, No Search Bar, No Launcher Icon:** Users cannot open `HM01` on their own or type a URL. It only wakes up when invoked by an external `https://` link (`ACTION_VIEW`) or an in-app OAuth Custom Tab request.
2. **No Tabs, No Bookmarks, No Persistent History:** When the window is closed (or times out), cookies, `WebStorage`, cache, and history are wiped.
3. **Forced CleanBrowsing Family Filter DNS-over-HTTPS (DoH):** Every hostname is verified against CleanBrowsing's `FAMILY_FILTER` DoH endpoint before the `WebView` is permitted to connect, blocking porn, adult sites, proxies/VPN bypasses, and malware at the application layer regardless of OS network settings.
4. **Anti-Escape-Hatch ("Link Leash"):** Users can view the link they tapped and navigate within that website (or complete OAuth/payment flows), with a maximum of `1` external domain hop after initial redirect resolution, and cannot use footer links to jump to Google Search, Bing, YouTube, or social feeds.
5. **Pluggable Blocklist Architecture:** `HM01` remains neutral and multipurpose for the broader developer community, while a host app (like **Juubun**) can inject its own opinionated "Attention-Hog Blocklist" (news sites, Substack, Reddit, forums, AI chat portals, etc.) via a programmatic config API or Android Managed Configurations (`RestrictionsManager`).

---

## 2. Repository & Gradle Architecture (Option 2: Standalone Repo + `includeBuild`)

The `HM01` repository compiles both a **reusable Android Library (`.aar`)** (consumed directly by host apps via Gradle `includeBuild` or JitPack) and a **standalone open-source APK** for GitHub Releases.

```text
HM01/
├── settings.gradle.kts          # rootProject.name = "HM01"
├── build.gradle.kts
├── hm01-core/                   # com.android.library (Published to JitPack / consumed via includeBuild)
│   ├── build.gradle.kts
│   └── src/main/
│       ├── AndroidManifest.xml
│       └── java/dev/hm01/browser/
│           ├── IntentBrowserActivity.kt       # Captive no-URL-bar WebView Activity
│           ├── MinimalCustomTabsService.kt    # androidx.browser.customtabs.CustomTabsService
│           ├── config/
│           │   ├── BrowserPolicyConfig.kt     # Immutable policy configuration data class
│           │   ├── BrowserPolicyProvider.kt   # Singleton/DI hook + RestrictionsManager reader
│           │   └── DefaultBaselineLists.kt    # Built-in search engine, adult & OAuth IdP rules
│           ├── dns/
│           │   ├── DohResolver.kt             # CleanBrowsing RFC 8484 DNS-over-HTTPS client
│           │   └── DohDecisionCache.kt        # Thread-safe LRU + TTL hostname verdict cache
│           ├── filter/
│           │   ├── UrlPolicyEvaluator.kt      # Evaluates DoH, blocklists, OAuth paths & Link Leash
│           │   ├── DomainExtractor.kt         # eTLD+1 & multi-tenant cloud suffix isolator
│           │   └── MediaStreamBlocker.kt      # Blocks video/audio headers, extensions & MSE/WebRTC
│           └── ui/
│               └── BlockedPageRenderer.kt     # Clean minimal HTML/native block screen
└── app/                         # com.android.application (Thin wrapper for standalone APK releases)
    ├── build.gradle.kts
    └── src/main/
        ├── AndroidManifest.xml
        └── res/xml/
            └── app_restrictions.xml           # Android Enterprise Managed Configurations schema
```

### Target SDK & Dependencies
* **Language:** Kotlin (JVM Target 17)
* **`minSdk`:** 26 (Android 8.0)
* **`compileSdk` / `targetSdk`:** 35
* **Dependencies:** Zero heavy third-party frameworks. Only `androidx.browser:browser:1.8.0` (for `CustomTabsService` compatibility) and Android SDK built-ins (`org.json`, `javax.net.ssl.HttpsURLConnection`, `android.webkit.*`).

---

## 3. Detailed Component Specifications

### 3.1. UI & UX (`IntentBrowserActivity.kt`)
* **Header Bar:**
  * Displays a lock icon + the current **verified hostname** (`uri.host`) so the user always knows what site they are on (anti-phishing).
  * **Back Button** (`<`): Navigates back within the current session history (`webView.goBack()`), or closes the activity if at the root page.
  * **Refresh Button** (`↻`): Reloads the current page.
  * **Close Button** (`✕`): Immediately destroys the session, wipes all cookies/storage/cache, and finishes the activity.
  * **Horizontal Progress Bar:** 4dp slim progress indicator underneath the header.
* **Strictly Omitted UI:**
  * No editable URL bar or search input.
  * No "Open in Chrome" or external browser menu item.
  * No tabs switcher, bookmarks, or history screen.
  * Downloads disabled by default (configurable via policy).

---

### 3.2. CleanBrowsing DNS-over-HTTPS Engine (`DohResolver.kt`)

Because Android's `WebView` resolves DNS inside Chromium's native C++ network stack, forcing CleanBrowsing DNS at the application level works by performing a fast, cached **DoH Hostname Gate** before any navigation or sub-resource request is allowed to proceed.

#### Supported CleanBrowsing DoH Presets
1. **`FAMILY_FILTER` (Default):** `https://doh.cleanbrowsing.org/doh/family-filter/`
   * Blocks porn, adult content, proxies/VPNs, malware, and enforces SafeSearch/mixed-content blocks.
2. **`ADULT_FILTER`:** `https://doh.cleanbrowsing.org/doh/adult-filter/`
   * Blocks porn, adult content, and malware while allowing mixed-content domains.
3. **`SECURITY_FILTER`:** `https://doh.cleanbrowsing.org/doh/security-filter/`
4. **`CUSTOM`:** Any RFC 8484 DoH URL provided by `BrowserPolicyConfig`.

#### Resolution Protocol & Caching
* **Wireformat (RFC 8484):** Sends an `application/dns-message` (GET `?dns=<base64url>` or POST binary DNS A-record query) over HTTPS (`TLS 1.2+`) to the CleanBrowsing DoH endpoint using a pinned IP bootstrap for `doh.cleanbrowsing.org` (`185.228.168.168` / `185.228.169.168`) so initial DoH lookups don't depend on untrusted local DNS.
* **Verdict Evaluation:**
  * `ALLOW`: Response `RCODE == 0` (NOERROR) with at least one valid public IP record that is **not** a CleanBrowsing block/sinkhole IP.
  * `BLOCK`: Response `RCODE == 3` (`NXDOMAIN`), empty answer with sinkhole SOA (`cleanbrowsing.rpz`), or an A record pointing to known CleanBrowsing block page IPs (`185.228.168.0/24`, `185.228.169.0/24`, `0.0.0.0`, `127.0.0.1`).
* **Performance & Caching (`DohDecisionCache`):**
  * Concurrent in-memory LRU cache (max 2,000 hostnames, TTL 30 minutes).
  * Main-frame navigation (`shouldOverrideUrlLoading`) and background sub-resource interception (`shouldInterceptRequest`) share the cache.
  * **Coalesced In-Flight Lookups:** If a page requests 15 assets from `cdn.shopify.com` simultaneously, only 1 DoH request is sent; the other 14 threads await the same `CompletableFuture`.
  * **Timeout & Fail Behavior:** 1,500ms connect/read timeout. Configurable `failClosedOnDnsError: Boolean` (defaults to `false` for Trusted IdP hosts so sign-ins don't break on captive portals).

---

### 3.3. Layered URL & Navigation Policy (`UrlPolicyEvaluator.kt`)

Every URL (`shouldOverrideUrlLoading` and `shouldInterceptRequest`) passes through a 6-step pipeline in strict order:

1. **Scheme, IP-Literal & Native App Handoff:**
   * **HTTPS-Only:** Cleartext `http://` is rejected on sub-resources and either rejected or optionally auto-upgraded to `https://` on initial intent launch (`upgradeInitialHttpToHttps = true`). `file://`, `javascript://`, `content://`, and `data://` navigations are blocked.
   * **IP-Literal Blocking:** Raw IPv4 (`1.2.3.4`), IPv6 (`[...]`), octal, and hex IP hosts are rejected so users cannot bypass DNS/hostname filters.
   * **Native App Handoff:** If an installed non-browser native app handles the `https://` App Link (or custom OAuth callback scheme like `myapp://oauth`), hand off via a sanitized `CATEGORY_BROWSABLE` intent (`component = null`, `selector = null`) and close `HM01`.
2. **Scoped OAuth & Trusted Identity Provider Allowlist:**
   * **Trusted Dedicated IdPs, Payment & Captcha Hosts:**
     * `accounts.google.*`, `gds.google.com`, `oauthaccountmanager.googleapis.com`
     * `appleid.apple.com`, `idmsa.apple.com`, `login.microsoftonline.com`, `login.live.com`, `login.yahoo.com`
     * `*.auth0.com`, `*.okta.com`, `*.b2clogin.com`, `*.amazoncognito.com`, `*.clerk.accounts.dev`, `*.duosecurity.com`
     * Payment/Checkout: `checkout.stripe.com`, `hooks.stripe.com`, `js.stripe.com`, `www.paypal.com`, `*.plaid.com`
     * Government SSO: `*.my.gov.au`, `mygovid.gov.au`, `signin.account.gov.uk`, `login.gov`, `id.me`, `*.singpass.gov.sg`, `*.realme.govt.nz`
     * Captcha Providers: `challenges.cloudflare.com`, `*.recaptcha.net`, `*.hcaptcha.com`, `*.arkoselabs.com`, `*.funcaptcha.com`
   * **Path-Scoped Multi-Purpose Platforms:**
     * `google.*`: Only `/o/oauth*`, `/signin*`, `/v3/signin*`, `/accounts/*`, `/servicelogin*`, `/checkcookie*`, `/mergesession*`, `/recaptcha*`. All other Google paths (`/search`, `/maps`, `/news`, `/travel`, etc.) are blocked.
     * `facebook.com`: Only `/login*`, `/dialog/oauth*`, `/v*/dialog/oauth*`.
     * `github.com`: Only `/login*`, `/sessions*`, `/settings/two_factor*`.
     * `*.firebaseapp.com` / `*.web.app`: Only `/__/auth/*` (unless that exact tenant host is the initial link opened by the user).
3. **Anti-Escape-Hatch (Search Engine & Proxy Blocker):**
   * Built-in block on general web search engines, web proxies, and archive mirrors:
     * `google.*/search`, `bing.com`, `duckduckgo.com`, `search.yahoo.com`, `search.brave.com`, `startpage.com`, `kagi.com`, `ecosia.org`, `qwant.com`, `yandex.*`, `baidu.com`, `searx.*`
     * `translate.google.com`, `translate.goog`, `archive.org`, `web.archive.org`, `archive.is`, `archive.ph`, `12ft.io`
4. **Pluggable Blocklist (`HM01` Baseline + Host App Injection):**
   * **`HM01` Open-Source Baseline (Built-in):**
     * Adult TLDs (`.xxx`, `.porn`, `.sex`, `.adult`, `.cam`, `.tube`, `.webcam`, `.sexy`)
     * Adult/NSFW hostname keywords (`porn`, `xxx`, `rule34`, `hentai`, `onlyfans`, `fansly`, `chaturbate`, `redgifs`, etc.)
   * **Host-Injected Blocklist (Provided by Juubun at runtime):**
     * `blockedDomains: Set<String>` (exact domain + subdomain suffix match)
     * `blockedHostKeywords: Set<String>`
     * `blockedPathRegexes: List<Regex>` (e.g., `/reels`, `/shorts`, `/watch`, `/feeds`, `/r/`, `/trending`)
5. **"Link Leash" (External Domain Hop Policy):**
   * **Redirect Resolution Grace:** Initial HTTP `301`/`302`/`307`/`308` or immediate JS redirects from known URL shorteners (`bit.ly`, `tinyurl.com`, `t.co`, `lnkd.in`, email tracking links) resolve to the **Landing Registrable Domain** (`kmart.com.au`).
   * **Same-Domain Browsing:** Once on `kmart.com.au`, the user can freely click links within `*.kmart.com.au` and load third-party CDNs/payment gateways (`stripe.com`, `paypal.com`).
   * **External Domain Hop Limit (`maxExternalDomainHops = 1`):** Allows up to `1` external domain hop from the landing domain so outbound product/reference links work, while preventing multi-site rabbit holes.
   * **Multi-Tenant Cloud Isolation (`DomainExtractor.kt`):** Shared hosting suffixes (`run.app`, `web.app`, `firebaseapp.com`, `github.io`, `gitlab.io`, `vercel.app`, `netlify.app`, `pages.dev`, `workers.dev`, `onrender.com`, `fly.dev`, `herokuapp.com`, `supabase.co`, `substack.com`) are isolated to the **full tenant subdomain** (`tenant-a.vercel.app` != `tenant-b.vercel.app`) and correctly handle multi-part ccTLDs (`com.au`, `co.uk`, `co.nz`, `co.jp`, etc.).
6. **CleanBrowsing Family Filter DoH Check:**
   * Verifies the hostname via `DohResolver`.

---

### 3.4. Video, Audio & Media Stream Lockdown (`MediaStreamBlocker.kt`)
Even on an allowed website (like a store or utility page), `HM01` must never become a video player:
1. **Network-Level Interception (`shouldInterceptRequest`):**
   * Blocks media file extensions: `.mp4`, `.webm`, `.m3u8`, `.mpd`, `.ts`, `.m4s`, `.mov`, `.avi`, `.mkv`, `.flv`, `.gifv`, `.mp3`, `.m4a`, `.ogg`, `.wav`.
   * Blocks requests with `Accept: video/*`, `Accept: audio/*`, or `Sec-Fetch-Dest: video|audio|object|embed`.
   * Blocks byte-range media streaming (`Range: bytes=...`) except on known Captcha challenge hosts.
2. **DOM/JS Injection (`onPageStarted` / `onPageCommitVisible` / `onPageFinished`):**
   * Overrides `HTMLMediaElement.prototype.play` to immediately reject and pause.
   * Deletes `window.MediaSource`, `window.ManagedMediaSource`, `window.RTCPeerConnection`, and `window.webkitRTCPeerConnection`.
   * Disables `Element.prototype.requestFullscreen`.
   * Injects CSS hiding `video, audio, object, embed`.
   * **Configurable Image Policy (`capImageDimensions: Boolean = false`):**
     * Defaults to `false` so product photos, maps, and diagrams render normally on allowed pages, while remaining available for ultra-strict modes.

---

### 3.5. Custom Tabs Service (`MinimalCustomTabsService.kt`)
Many modern Android apps (Slack, banking apps, government apps, Auth0/AppAuth SDKs) check `PackageManager` for a browser that binds to `android.support.customtabs.action.CustomTabsService`.
* `MinimalCustomTabsService` extends `androidx.browser.customtabs.CustomTabsService` and implements `warmup()`, `newSession()`, and `mayLaunchUrl()` as lightweight no-ops returning success (`true`).
* When an app launches a Custom Tab intent (`EXTRA_SESSION`), `IntentBrowserActivity` handles it transparently with the exact same UI and policy engine.
* Strips `; wv` and `Version/4.0` from `WebSettings.userAgentString` so Google OAuth and strict OIDC providers treat `HM01` as a compliant Custom Tab rather than an embedded third-party WebView.

---

## 4. Configuration API & Juubun Integration

### 4.1. `BrowserPolicyConfig` Data Class (`hm01-core`)

```kotlin
package dev.hm01.browser.config

data class BrowserPolicyConfig(
    val brandTitle: String = "HM01",
    val dohPreset: DohPreset = DohPreset.CLEANBROWSING_FAMILY,
    val customDohUrl: String? = null,
    val failClosedOnDnsError: Boolean = false,
    val blockedDomains: Set<String> = emptySet(),
    val blockedHostKeywords: Set<String> = emptySet(),
    val blockedPathRegexes: List<String> = emptyList(),
    val allowedDomainsOverride: Set<String> = emptySet(),
    val customCallbackSchemes: Map<String, CustomSchemeTarget> = emptyMap(),
    val maxExternalDomainHops: Int = 1,
    val maxTotalNavigationHops: Int = 45,
    val sessionTimeoutMs: Long = 10 * 60 * 1000L, // 10 minutes
    val blockVideoAndAudio: Boolean = true,
    val capImageDimensions: Boolean = false,
    val blockSearchEngines: Boolean = true
)
```

### 4.2. Dual Configuration Support (Programmatic + Android Managed Configurations)
`BrowserPolicyProvider` resolves the active `BrowserPolicyConfig` in two ways:
1. **Programmatic Injection (Used when embedded in Juubun via `:hm01-core`):**
   Juubun calls `BrowserPolicyProvider.configure(...)` in its startup/enforcement path.
2. **Android Enterprise `RestrictionsManager` (Used when installed as a standalone `HM01` APK):**
   Reads `RestrictionsManager.getApplicationRestrictions()` keys (`doh_preset`, `blocked_domains`, `blocked_keywords`, `max_external_domain_hops`, `session_timeout_seconds`, `block_video_audio`), allowing any MDM or Device Owner DPC to manage the standalone APK remotely.

---

## 5. How Juubun Connects to `HM01` (Option 2 Setup)

### Step 1: Link in Juubun's `settings.gradle.kts`
Assuming `HM01` is located at `C:\Users\samtu\Desktop\Projects\HM01` (`../HM01`):

```kotlin
// In Zendroid/settings.gradle.kts
includeBuild("../HM01") {
    dependencySubstitution {
        substitute(module("com.github.juubun:hm01-core")).using(project(":hm01-core"))
    }
}
```

### Step 2: Add Dependency in Juubun's `app/build.gradle.kts`
```kotlin
dependencies {
    implementation("com.github.juubun:hm01-core:1.0.0")
}
```

### Step 3: Inject Juubun's Attention-Hog Blocklist
Inside Juubun, pass your private blocklist (Substack, news sites, social feeds, Reddit, forums, AI portals, etc.) and custom callback schemes (`juubundpc://`, `juubunparent://`) into `BrowserPolicyProvider`:

```kotlin
BrowserPolicyProvider.configure(
    BrowserPolicyConfig(
        brandTitle = "Juubun Safe Link",
        dohPreset = DohPreset.CLEANBROWSING_FAMILY,
        blockedDomains = JuubunBlocklist.ATTENTION_HOG_DOMAINS, // News, Substack, Reddit, Social, etc.
        blockedHostKeywords = JuubunBlocklist.BLOCKED_KEYWORDS,
        blockedPathRegexes = JuubunBlocklist.BLOCKED_PATH_PATTERNS,
        maxExternalDomainHops = 1,
        sessionTimeoutMs = 10 * 60 * 1000L,
        blockVideoAndAudio = true,
        capImageDimensions = false
    )
)
```

---

## 6. Verification & Acceptance Test Plan for `HM01`

When building `HM01` in the new project, verify these 7 test scenarios via unit + instrumented tests:
1. **CleanBrowsing Family Filter DoH Enforcement:**
   * Querying a known adult domain or CleanBrowsing test domain (`adult-filter-test.cleanbrowsing.org`) via `DohResolver` returns `BLOCK` and prevents `WebView` connection.
   * Querying a legitimate retail domain (`kmart.com.au` or `ikea.com`) returns `ALLOW` and caches the result.
2. **Spouse Gift Link Flow:**
   * Launching an `ACTION_VIEW` intent to a retail product link (or via a `bit.ly` redirect) loads the product page with intact product images, allows clicking another product on the same store domain, and blocks embedded `<video>` tags.
3. **Search Engine Escape Prevention:**
   * Navigating from an allowed page to `https://www.google.com/search?q=news` or `https://duckduckgo.com` is immediately blocked.
4. **OAuth & Passkey / 2FA Sign-In Flow:**
   * Launching `https://accounts.google.com/o/oauth2/v2/auth?...` or `https://www.facebook.com/v18.0/dialog/oauth?...` succeeds even though `google.com` search and `facebook.com` feed are blocked.
5. **Attention-Hog Blocklist Injection:**
   * Injecting `substack.com`, `reddit.com`, and `news.ycombinator.com` via `BrowserPolicyConfig.blockedDomains` blocks both direct intent launches and in-page links to those domains.
6. **Multi-Tenant Cloud Isolation:**
   * Opening `https://my-school-event.vercel.app` allows navigating within `my-school-event.vercel.app` but counts `https://other-site.vercel.app` as an external domain hop.
7. **Ephemeral Cleanup:**
   * Closing the activity or hitting session timeout wipes `CookieManager`, `WebStorage`, cache, and form data.
