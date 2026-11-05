# Technical Specification: `HM01` — Headless Intent & Auth Browser

## 1. Executive Summary & Product Vision

**`HM01`** is an open-source, unopinionated, **Intent-Only ("Link-In, Look, Close") Browser and Custom Tabs Provider** for Android.

It solves a critical problem for digital-minimalism setups, parental control DPCs, and enterprise/kiosk devices: **how to remove full web browsers (like Chrome) without breaking everyday life.** When someone texts you a link to a birthday gift idea, a restaurant menu, or a package tracking page—or when an app launches an OAuth/SSO/2FA sign-in flow—`HM01` opens the link cleanly while giving the host developer complete control over DNS filtering, domain/keyword/path blocklists, external domain hop limits, and media lockdown.

### Core Design Principles
1. **No Address Bar, No Search Bar, No Launcher Icon:** Users cannot open `HM01` on their own or type a URL. It wakes up only when invoked by an external `https://` link (`ACTION_VIEW`) or an in-app OAuth Custom Tab request.
2. **No Tabs, No Bookmarks, No Persistent History:** When the window is closed (or times out), cookies, `WebStorage`, HTTP auth credentials, cache, and history are wiped.
3. **Unopinionated Engine (Mechanism vs. Policy):** Out of the box, `HM01` ships with **empty** website blocklists (plus a single illustrative example for `pathScopedPlatformRules` and `blockedMediaExtensions`) and **zero** hardcoded DNS provider endpoints. All blocking outside of the selected DNS server is configured by the host app.
4. **Configurable RFC 8484 DNS-over-HTTPS (DoH):** Supports `DnsMode.USER_DEFINED` (requiring the developer to provide a list of `DnsProviderOption` entries for user selection or custom DoH input), `DnsMode.DEVELOPER_FIXED` (single developer-specified DoH URL), and `DnsMode.DISABLED`.
5. **1-Hop "Link Leash" (Easily Modified or Removed):** Users can view the link they tapped and navigate within that website, with a default limit of `1` external domain hop (`maxExternalDomainHops = 1`). Developers can easily adjust the limit (`withLinkLeash(n)`) or remove it completely (`withoutLinkLeash()` / `maxExternalDomainHops = null`).

---

## 2. Repository & Gradle Architecture

The `HM01` repository compiles both a **reusable Android Library (`.aar`)** (`:hm01-core`, consumed via Gradle `includeBuild` or JitPack) and a **standalone open-source APK** (`:app`).

```text
HM01/
├── settings.gradle.kts          # rootProject.name = "HM01"
├── build.gradle.kts
├── hm01-core/                   # com.android.library (Published to JitPack / consumed via includeBuild)
│   ├── build.gradle.kts
│   └── src/main/
│       ├── AndroidManifest.xml
│       └── java/dev/hm01/browser/
│           ├── IntentBrowserActivity.kt       # Captive no-URL-bar WebView Activity + OAuth popup redirector
│           ├── MinimalCustomTabsService.kt    # androidx.browser.customtabs.CustomTabsService
│           ├── config/
│           │   ├── BrowserPolicyConfig.kt     # Immutable policy configuration data class
│           │   ├── BrowserPolicyProvider.kt   # Singleton/DI hook, user DNS persistence & RestrictionsManager
│           │   └── DefaultBaselineLists.kt    # OAuth IdP helpers, URL shorteners & path-scoped evaluator
│           ├── dns/
│           │   ├── DohResolver.kt             # Standard RFC 8484 DNS-over-HTTPS client
│           │   └── DohDecisionCache.kt        # Thread-safe LRU + TTL cache with background worker pool
│           ├── filter/
│           │   ├── UrlPolicyEvaluator.kt      # Evaluates DoH, blocklists, OAuth paths & Link Leash
│           │   ├── DomainExtractor.kt         # eTLD+1 & multi-tenant cloud suffix isolator
│           │   └── MediaStreamBlocker.kt      # Blocks configured media extensions/MIME types & MSE/WebRTC
│           └── ui/
│               └── BlockedPageRenderer.kt     # Clean minimal HTML/native block screen
└── app/                         # com.android.application (Thin wrapper for standalone APK releases)
    ├── build.gradle.kts
    └── src/main/
        ├── AndroidManifest.xml
        └── res/xml/
            └── app_restrictions.xml           # Android Enterprise Managed Configurations schema
```

---

## 3. Detailed Component Specifications

### 3.1. UI & UX (`IntentBrowserActivity.kt`)
* **Header Bar:**
  * Displays a lock icon + the current **verified hostname** (`uri.host`) so the user always knows what site they are on.
  * **Back Button** (`<`): Navigates back within the current session history (`webView.goBack()`), or closes the activity if at the root page.
  * **Refresh Button** (`↻`): Reloads the current page.
  * **Close Button** (`✕`): Immediately destroys the session, wipes all cookies/storage/cache, and finishes the activity.
* **OAuth & 2-Step Verification Popup Support:**
  * Intercepts `window.open` / `target="_blank"` popups via `WebChromeClient.onCreateWindow`, evaluates the popup destination URL through `UrlPolicyEvaluator`, and routes allowed OAuth/2SV challenges directly into the single main `WebView`.

### 3.2. Standard RFC 8484 DNS-over-HTTPS Engine (`DohResolver.kt` & `DohDecisionCache.kt`)
* **DNS Modes (`DnsMode`):**
  * `DnsMode.USER_DEFINED`: Requires the host developer to supply `userDnsOptions: List<DnsProviderOption>`. Until the user selects an option (or enters a custom DoH URL) via `BrowserPolicyProvider.setUserSelectedDns(...)`, `UrlPolicyEvaluator` blocks navigation with `BlockReason.DNS_NOT_SELECTED`.
  * `DnsMode.DEVELOPER_FIXED`: Uses `customDohUrl` / `selectedDnsEndpointUrl` configured by the developer.
  * `DnsMode.DISABLED`: Skips the application-layer DoH check.
* **Wireformat & Sinkhole Detection:**
  * Sends standard RFC 8484 `application/dns-message` queries on a dedicated background worker pool (`hm01-doh-worker`) so main-thread Android UI calls never trigger `NetworkOnMainThreadException`.
  * Coalesces concurrent in-flight requests for the same hostname via `CompletableFuture` and caches verdicts in an LRU+TTL cache (2,000 entries, 30-minute TTL).
  * Recognizes `NXDOMAIN`, `REFUSED`, RPZ SOA/CNAME records, and standard filter sinkhole IPs (`0.0.0.0`, `127.0.0.0/8`, `185.228.168.0/24`, `185.228.169.0/24`, `94.140.14.33..36`, `146.112.61.0/24`).

### 3.3. 6-Step URL & Navigation Policy Pipeline (`UrlPolicyEvaluator.kt`)
1. **Scheme, IP-Literal & Native App Handoff:** Enforces HTTPS-only (auto-upgrading initial `http://` intents when `upgradeInitialHttpToHttps = true`), blocks raw IPv4/IPv6/hex/octal literals, and hands off custom OAuth callback schemes (`juubundpc://`, `myapp://oauth`) or installed native App Links.
2. **Scoped OAuth & Trusted Identity Provider Allowlist:** Evaluates `BrowserPolicyConfig.pathScopedPlatformRules` (shipping with a single default example for `github.com` allowing `/login`, `/sessions`, `/settings/two_factor`).
3. **Developer-Configured Search Engine & Proxy Blocker:** Evaluates `BrowserPolicyConfig.searchEngineDomains` (empty by default).
4. **Developer-Configured Blocklists:** Evaluates `blockedTlds`, `blockedDomains`, `blockedHostKeywords`, and `blockedPathRegexes` (all empty by default).
5. **"Link Leash" (External Domain Hop Policy):** Allows unlimited navigation within the landing registrable domain (`eTLD+1`), with redirect grace for `urlShortenerDomains` (`bit.ly`, `amzn.to`, `a.co`, `amzn.asia`, etc.) and configurable `maxExternalDomainHops: Int? = 1` (`null` disables the Link Leash).
6. **DNS-over-HTTPS Safety Check:** Verifies the hostname against the user-selected or developer-configured DoH endpoint.
