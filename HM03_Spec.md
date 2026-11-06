# Technical Specification: `HM03` — Headless Intent & Auth Browser

## 1. Executive Summary & Product Vision

**`HM03`** is an open-source, unopinionated, **Intent-Only ("Link-In, Look, Close") Browser and Custom Tabs Provider** for Android.

It solves a critical problem for digital-minimalism setups, parental control DPCs, and enterprise/kiosk devices: **how to remove full web browsers (like Chrome) without breaking everyday life.** When someone texts you a link to a birthday gift idea, a restaurant menu, or a package tracking page—or when an app launches an OAuth/SSO/2FA sign-in flow—`HM03` opens the link cleanly while giving the host developer complete control over DNS filtering, domain/keyword/path blocklists, external domain hop limits, and media lockdown.

### Core Design Principles
1. **No Address Bar, No Search Bar, No Launcher Icon:** Users cannot open `HM03` on their own or type a URL. It wakes up only when invoked by an external `https://` link (`ACTION_VIEW`) or an in-app OAuth Custom Tab request.
2. **No Tabs, No Bookmarks, No Persistent History:** When the window is closed, times out, or starts a new session, cookies, `WebStorage`, HTTP auth credentials, cache, and history are wiped.
3. **Unopinionated Engine (Mechanism vs. Policy):** Out of the box, `HM03` ships with **empty** website blocklists (plus a single illustrative example for `pathScopedPlatformRules` and `blockedMediaExtensions`) and **zero** hardcoded DNS provider endpoints. All blocking outside of the selected DNS server is configured by the host app.
4. **Configurable RFC 8484 DNS-over-HTTPS (DoH):** Supports `DnsMode.USER_DEFINED` (requiring the developer to provide a list of `DnsProviderOption` entries for user selection or custom DoH input), `DnsMode.DEVELOPER_FIXED` (single developer-specified DoH URL), and `DnsMode.DISABLED`, with EDNS(0) 128-byte block padding and fail-closed default behavior.
5. **1-Hop "Link Leash" (Easily Modified or Removed):** Users can view the link they tapped and navigate within that website, with a default limit of `1` external domain hop (`maxExternalDomainHops = 1`). Developers can easily adjust the limit (`withLinkLeash(n)`) or remove it completely (`withoutLinkLeash()` / `maxExternalDomainHops = null`).

---

## 2. Repository & Gradle Architecture

The `HM03` repository compiles both a **reusable Android Library (`.aar`)** (`:hm03-core`, consumed via Gradle `includeBuild` or JitPack) and a **standalone open-source APK** (`:app`).

```text
HM03/
├── settings.gradle.kts          # rootProject.name = "HM03"
├── build.gradle.kts
├── hm03-core/                   # com.android.library (Published to JitPack / consumed via includeBuild)
│   ├── build.gradle.kts
│   └── src/main/
│       ├── AndroidManifest.xml
│       └── java/dev/hm03/browser/
│           ├── IntentBrowserActivity.kt       # Captive no-URL-bar WebView Activity + OAuth popup redirector
│           ├── MinimalCustomTabsService.kt    # androidx.browser.customtabs.CustomTabsService
│           ├── config/
│           │   ├── BrowserPolicyConfig.kt     # Immutable policy configuration data class
│           │   ├── BrowserPolicyProvider.kt   # Singleton/DI hook, user DNS persistence & RestrictionsManager
│           │   └── DefaultBaselineLists.kt    # OAuth IdP helpers, URL shorteners & path-scoped evaluator
│           ├── dns/
│           │   ├── DohResolver.kt             # Standard RFC 8484 DNS-over-HTTPS client (POST + EDNS0 padding)
│           │   └── DohDecisionCache.kt        # Thread-safe LRU + TTL cache with bounded worker pool
│           ├── filter/
│           │   ├── CanonicalUrl.kt            # Strict WHATWG/RFC 3986 URL & IDN canonicalizer
│           │   ├── UrlPolicyEvaluator.kt      # Evaluates DoH, blocklists, OAuth paths, iframes & Link Leash
│           │   ├── DomainExtractor.kt         # eTLD+1 & PSL multi-tenant cloud suffix isolator
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
  * Displays a lock icon (`🔒`) + the **committed verified hostname** (`view.url` host) only after TLS handshake and document commit (`onPageCommitVisible` / `onPageFinished`), preventing provisional navigation spoofing.
  * **Back Button** (`<`): Navigates back within the current session history (`webView.goBack()`), or closes the activity if at the root page.
  * **Refresh Button** (`↻`): Reloads the current page.
  * **Close Button** (`✕`): Immediately destroys the session, wipes all cookies/storage/cache, and finishes the activity.
* **User-Initiated OAuth & 2-Step Verification Popup Support:**
  * Intercepts user-initiated `window.open` / `target="_blank"` popups (`isUserGesture == true`) via `WebChromeClient.onCreateWindow` using a hardened, non-JS temporary `WebView` with automatic lifecycle cleanup, evaluates the popup destination URL through `UrlPolicyEvaluator`, and routes allowed OAuth/2SV challenges directly into the single main `WebView`.

### 3.2. Standard RFC 8484 DNS-over-HTTPS Engine (`DohResolver.kt` & `DohDecisionCache.kt`)
* **DNS Modes (`DnsMode`):**
  * `DnsMode.USER_DEFINED`: Requires the host developer to supply `userDnsOptions: List<DnsProviderOption>`. Until the user selects an option (or enters a validated `https://` custom DoH URL when `allowCustomUserDohUrl = true`) via `BrowserPolicyProvider.setUserSelectedDns(...)`, `UrlPolicyEvaluator` blocks navigation with `BlockReason.DNS_NOT_SELECTED`.
  * `DnsMode.DEVELOPER_FIXED`: Uses `customDohUrl` / `selectedDnsEndpointUrl` configured by the developer.
  * `DnsMode.DISABLED`: Skips the application-layer DoH check.
* **Wireformat & Sinkhole/Private-IP Detection:**
  * Sends standard RFC 8484 `application/dns-message` `POST` queries padded to 128-byte blocks via RFC 7830 / RFC 8467 EDNS(0) on a bounded background worker pool (`hm03-doh-worker`).
  * Coalesces concurrent in-flight requests for the same `(endpointUrl, hostname)` key via `CompletableFuture` and caches verdicts in an LRU+TTL cache (2,000 entries, capped by DNS record TTL up to 30 minutes).
  * Recognizes `NXDOMAIN`, `REFUSED`, RPZ SOA/CNAME records, bare CNAME-only responses, non-global-unicast / RFC 1918 / link-local / CGNAT / loopback IPv4 & IPv6 addresses, and standard filter sinkhole IPs (`0.0.0.0/8`, `127.0.0.0/8`, `185.228.168.0/24`, `185.228.169.0/24`, `94.140.14.33..36`, `146.112.61.0/24`).

### 3.3. 6-Step URL & Navigation Policy Pipeline (`UrlPolicyEvaluator.kt` & `CanonicalUrl.kt`)
1. **Scheme, Canonicalization, IP-Literal & Native App Handoff:** Strictly canonicalizes URLs (rejecting userinfo `@`, backslashes `\`, and malformed syntax; converting IDNs and fullwidth dots to ASCII Punycode; resolving `/./` and `/../` dot segments and percent-encoded paths), enforces HTTPS-only, blocks raw IPv4/IPv6/hex/octal literals, and hands off registered custom OAuth callback schemes (`CustomSchemeTarget` pinned to `targetPackage`) or installed native App Links.
2. **Scoped OAuth & Trusted Identity Provider Allowlist:** Evaluates `BrowserPolicyConfig.pathScopedPlatformRules` across both main-frame (`GET`/`POST`) and sub-frame (`<iframe>`) navigations.
3. **Developer-Configured Search Engine & Proxy Blocker:** Evaluates `BrowserPolicyConfig.searchEngineDomains` (empty by default).
4. **Developer-Configured Blocklists & Sub-Frame Isolation:** Evaluates `blockedTlds`, `blockedDomains`, `blockedHostKeywords`, and `blockedPathRegexes`, and restricts cross-domain `<iframe>` sub-frames to the active domain and trusted IdP/Payment/Captcha hosts unless `allowThirdPartyIframes = true`.
5. **"Link Leash" (External Domain Hop Policy):** Allows unlimited navigation within the landing registrable domain (`eTLD+1` / PSL multi-tenant cloud domain), with redirect grace for `urlShortenerDomains` and configurable `maxExternalDomainHops: Int? = 1` (`null` disables the Link Leash).
6. **DNS-over-HTTPS Safety Check:** Verifies the hostname against the user-selected or developer-configured DoH endpoint.
