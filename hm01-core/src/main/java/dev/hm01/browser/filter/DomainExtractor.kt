package dev.hm01.browser.filter

import java.util.Locale

/**
 * Extracts the registrable domain (`eTLD+1`) or isolated multi-tenant cloud hostname,
 * and detects raw IP-literal hosts (IPv4, IPv6, octal, hex, integer/dword).
 */
object DomainExtractor {

    private val UNICODE_DOTS_REGEX = Regex("[\\u3002\\uFF0E\\uFF61]")

    /**
     * Multi-tenant cloud, CDN, PaaS, and content-hosting suffixes (aligned with the Mozilla Public Suffix
     * List `PRIVATE` section) where each tenant subdomain must be isolated as a distinct external domain
     * (`tenant-a.vercel.app != tenant-b.vercel.app`, `blog-a.wordpress.com != blog-b.wordpress.com`).
     */
    val MULTI_TENANT_CLOUD_SUFFIXES: Set<String> = setOf(
        // Google Cloud / Firebase / App Engine
        "a.run.app",
        "run.app",
        "web.app",
        "firebaseapp.com",
        "appspot.com",
        "cloudfunctions.net",
        // AWS / CloudFront / S3 / Amplify / Elastic Beanstalk
        "cloudfront.net",
        "s3.amazonaws.com",
        "elasticbeanstalk.com",
        "amplifyapp.com",
        // Microsoft Azure
        "azurewebsites.net",
        "azurestaticapps.net",
        "cloudapp.azure.com",
        "blob.core.windows.net",
        // Cloudflare
        "pages.dev",
        "workers.dev",
        "trycloudflare.com",
        "r2.dev",
        // Modern PaaS / Serverless / Jamstack
        "vercel.app",
        "now.sh",
        "netlify.app",
        "netlify.com",
        "onrender.com",
        "fly.dev",
        "herokuapp.com",
        "herokussl.com",
        "railway.app",
        "up.railway.app",
        "replit.app",
        "replit.dev",
        "repl.co",
        "glitch.me",
        "deno.dev",
        "surge.sh",
        "koyeb.app",
        "adaptable.app",
        "cleverapps.io",
        "ondigitalocean.app",
        "digitaloceanspaces.com",
        "supabase.co",
        // Code Hosting Pages
        "github.io",
        "githubusercontent.com",
        "gitlab.io",
        "bitbucket.io",
        "codeberg.page",
        "sourceforge.io",
        // Multi-Tenant Publishing, Blogs, Docs & Storefronts
        "substack.com",
        "wordpress.com",
        "blogspot.com",
        "medium.com",
        "ghost.io",
        "tumblr.com",
        "webflow.io",
        "wixsite.com",
        "squarespace.com",
        "myshopify.com",
        "carrd.co",
        "notion.site",
        "gitbook.io",
        "readthedocs.io",
        "itch.io",
        "pantheonsite.io",
        // Tunneling & Ephemeral Proxies
        "ngrok.io",
        "ngrok-free.app",
        " ngrok.app",
        "loca.lt",
        "tailscale.net",
        "ts.net"
    ).map { it.trim() }.toSet()

    /**
     * Known multi-part country-code second-level domains (ccSLDs) and regional public suffixes.
     */
    val MULTI_PART_CC_TLDS: Set<String> = setOf(
        // Australia
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
        "act.edu.au", "nsw.edu.au", "nt.edu.au", "qld.edu.au", "sa.edu.au", "tas.edu.au", "vic.edu.au", "wa.edu.au",
        "act.gov.au", "nsw.gov.au", "nt.gov.au", "qld.gov.au", "sa.gov.au", "tas.gov.au", "vic.gov.au", "wa.gov.au",
        // United Kingdom
        "co.uk", "org.uk", "me.uk", "gov.uk", "ac.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "nhs.uk", "police.uk",
        // New Zealand
        "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz", "school.nz", "geek.nz", "kiwi.nz", "maori.nz", "iwi.nz",
        // Japan
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ed.jp", "gr.jp", "lg.jp", "ad.jp",
        // Singapore
        "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg", "per.sg",
        // Hong Kong, Taiwan & China
        "com.hk", "edu.hk", "gov.hk", "net.hk", "org.hk", "idv.hk",
        "com.tw", "edu.tw", "gov.tw", "net.tw", "org.tw", "idv.tw", "game.tw", "ebiz.tw", "club.tw",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
        // South Korea
        "co.kr", "ne.kr", "or.kr", "re.kr", "pe.kr", "go.kr", "ac.kr", "hs.kr", "ms.kr", "es.kr", "sc.kr", "kg.kr",
        // India, Pakistan, Bangladesh, Sri Lanka & Nepal
        "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "ac.in", "edu.in", "res.in", "gov.in", "mil.in", "nic.in",
        "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk", "fam.pk", "biz.pk", "web.pk",
        "com.bd", "edu.bd", "gov.bd", "net.bd", "org.bd", "ac.bd",
        "com.lk", "org.lk", "edu.lk", "gov.lk", "net.lk", "ac.lk",
        "com.np", "org.np", "edu.np", "gov.np", "net.np", "mil.np",
        // Southeast Asia (Malaysia, Philippines, Indonesia, Thailand, Vietnam)
        "com.my", "net.my", "org.my", "gov.my", "edu.my", "mil.my", "name.my",
        "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph", "mil.ph", "ngo.ph",
        "co.id", "or.id", "ac.id", "go.id", "web.id", "sch.id", "mil.id", "my.id", "biz.id",
        "co.th", "or.th", "ac.th", "go.th", "in.th", "mi.th", "net.th",
        "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn", "int.vn", "ac.vn", "biz.vn", "info.vn", "name.vn", "pro.vn", "health.vn",
        // Middle East (Israel, Turkey, UAE, Saudi Arabia, Qatar, Kuwait, Lebanon, Jordan)
        "co.il", "org.il", "net.il", "ac.il", "gov.il", "k12.il", "muni.il", "idf.il",
        "com.tr", "org.tr", "net.tr", "gov.tr", "edu.tr", "bel.tr", "pol.tr", "mil.tr", "k12.tr", "av.tr", "dr.tr", "gen.tr", "info.tr", "bbs.tr", "name.tr", "tel.tr", "tv.tr", "web.tr",
        "co.ae", "net.ae", "org.ae", "gov.ae", "ac.ae", "sch.ae", "mil.ae",
        "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa", "pub.sa", "med.sa", "sch.sa",
        "com.qa", "net.qa", "org.qa", "gov.qa", "edu.qa", "mil.qa",
        "com.kw", "net.kw", "org.kw", "gov.kw", "edu.kw",
        "com.lb", "net.lb", "org.lb", "gov.lb", "edu.lb",
        "com.jo", "net.jo", "org.jo", "gov.jo", "edu.jo", "mil.jo",
        // Africa (South Africa, Nigeria, Egypt, Kenya, Tanzania, Ghana, Uganda, Morocco)
        "co.za", "org.za", "net.za", "gov.za", "edu.za", "ac.za", "law.za", "mil.za", "nom.za", "school.za", "web.za",
        "com.ng", "org.ng", "gov.ng", "edu.ng", "net.ng", "sch.ng", "mil.ng", "mobi.ng", "name.ng",
        "com.eg", "edu.eg", "gov.eg", "org.eg", "net.eg", "sci.eg", "eun.eg", "mil.eg",
        "co.ke", "or.ke", "go.ke", "ac.ke", "sc.ke", "me.ke", "mobi.ke", "info.ke", "ne.ke",
        "co.tz", "or.tz", "go.tz", "ac.tz", "sc.tz", "ne.tz", "mil.tz", "hotel.tz", "mobi.tz", "tv.tz", "info.tz", "me.tz",
        "com.gh", "edu.gh", "gov.gh", "org.gh", "mil.gh",
        "co.ug", "or.ug", "go.ug", "ac.ug", "sc.ug", "ne.ug", "com.ug", "org.ug",
        "co.ma", "net.ma", "org.ma", "gov.ma", "ac.ma", "press.ma",
        // Europe (Ukraine, Poland, Russia, Greece, Cyprus, Malta, Spain, Portugal, Austria)
        "com.ua", "org.ua", "net.ua", "gov.ua", "edu.ua", "in.ua", "kyiv.ua", "kiev.ua", "lviv.ua", "kharkiv.ua", "odesa.ua",
        "com.pl", "net.pl", "org.pl", "edu.pl", "gov.pl", "info.pl", "biz.pl", "waw.pl",
        "com.ru", "net.ru", "org.ru", "pp.ru", "ac.ru", "edu.ru", "gov.ru",
        "com.gr", "edu.gr", "net.gr", "org.gr", "gov.gr",
        "com.cy", "net.cy", "org.cy", "gov.cy", "ac.cy", "pro.cy",
        "com.mt", "org.mt", "net.mt", "edu.mt", "gov.mt",
        "com.es", "nom.es", "org.es", "gob.es", "edu.es",
        "com.pt", "edu.pt", "gov.pt", "org.pt", "net.pt", "publ.pt",
        "co.at", "or.at", "gv.at", "ac.at",
        // Americas (Brazil, Mexico, Argentina, Colombia, Peru, Venezuela, Ecuador, Uruguay, Costa Rica, Canada, US)
        "com.br", "net.br", "org.br", "gov.br", "edu.br", "mil.br", "art.br", "blog.br", "eco.br", "emp.br", "ind.br", "inf.br", "jus.br", "leg.br", "med.br", "psi.br", "rec.br", "srv.br", "tmp.br", "tur.br", "tv.br", "vet.br", "vlog.br", "wiki.br",
        "com.mx", "org.mx", "net.mx", "gob.mx", "edu.mx",
        "com.ar", "org.ar", "net.ar", "gob.ar", "gov.ar", "edu.ar", "int.ar", "mil.ar", "musica.ar", "tur.ar",
        "com.co", "org.co", "net.co", "gov.co", "edu.co", "mil.co", "nom.co",
        "com.pe", "org.pe", "net.pe", "gob.pe", "edu.pe", "mil.pe", "nom.pe",
        "com.ve", "org.ve", "net.ve", "gob.ve", "gov.ve", "edu.ve", "mil.ve", "info.ve", "co.ve", "web.ve",
        "com.ec", "org.ec", "net.ec", "gob.ec", "gov.ec", "edu.ec", "mil.ec", "fin.ec", "med.ec", "pro.ec", "info.ec",
        "com.uy", "org.uy", "net.uy", "gub.uy", "edu.uy", "mil.uy",
        "co.cr", "or.cr", "go.cr", "ac.cr", "ed.cr", "fi.cr", "sa.cr",
        "ab.ca", "bc.ca", "mb.ca", "nb.ca", "nf.ca", "nl.ca", "ns.ca", "nt.ca", "nu.ca", "on.ca", "pe.ca", "qc.ca", "sk.ca", "yk.ca",
        "k12.ca.us", "k12.ny.us", "k12.tx.us", "k12.fl.us", "k12.il.us", "k12.pa.us", "k12.oh.us", "k12.wa.us", "k12.ma.us", "k12.va.us", "k12.nc.us", "k12.ga.us", "k12.mi.us", "k12.nj.us", "k12.az.us", "k12.co.us"
    )

    private val SORTED_MULTI_TENANT_SUFFIXES: List<String> =
        MULTI_TENANT_CLOUD_SUFFIXES.sortedByDescending { it.length }

    private val SORTED_CC_TLDS: List<String> =
        MULTI_PART_CC_TLDS.sortedByDescending { it.length }

    private val IPV4_STANDARD_REGEX = Regex("^\\d{1,3}(?:\\.\\d{1,3}){3}$")
    private val HEX_LABEL_REGEX = Regex("^0x[0-9a-f]+$", RegexOption.IGNORE_CASE)
    private val OCTAL_OR_NUMERIC_LABEL_REGEX = Regex("^[0-9]+$")

    /**
     * Returns the effective registrable domain (`eTLD+1`) or isolated multi-tenant subdomain for [rawHost].
     *
     * Examples:
     * - `www.kmart.com.au` -> `kmart.com.au`
     * - `shop.ikea.com` -> `ikea.com`
     * - `my-school-event.vercel.app` -> `my-school-event.vercel.app`
     * - `api.my-school-event.vercel.app` -> `my-school-event.vercel.app`
     * - `other-site.vercel.app` -> `other-site.vercel.app`
     * - `blog-a.wordpress.com` -> `blog-a.wordpress.com`
     */
    @JvmStatic
    fun extractEffectiveDomain(rawHost: String): String {
        val host = normalizeHost(rawHost)
        if (host.isEmpty()) return ""

        // 1. Check multi-tenant cloud suffixes (longest suffix match first, e.g. a.run.app before run.app)
        val matchedTenantSuffix = SORTED_MULTI_TENANT_SUFFIXES.firstOrNull { suffix ->
            host == suffix || host.endsWith(".$suffix")
        }

        if (matchedTenantSuffix != null) {
            if (host == matchedTenantSuffix) return host
            val prefix = host.removeSuffix(".$matchedTenantSuffix")
            val tenantLabel = prefix.substringAfterLast('.')
            return "$tenantLabel.$matchedTenantSuffix"
        }

        val labels = host.split('.')
        if (labels.size <= 2) return host

        // 2. Check multi-part ccTLDs (supports both 2-part like com.au/com.vn and 3-part like k12.ca.us/nsw.edu.au)
        val matchedCcTld = SORTED_CC_TLDS.firstOrNull { ccTld ->
            host == ccTld || host.endsWith(".$ccTld")
        }
        if (matchedCcTld != null) {
            if (host == matchedCcTld) return host
            val prefix = host.removeSuffix(".$matchedCcTld")
            val registrableLabel = prefix.substringAfterLast('.')
            return "$registrableLabel.$matchedCcTld"
        }

        // 3. Standard eTLD+1 (last 2 labels)
        return "${labels[labels.size - 2]}.${labels[labels.size - 1]}"
    }

    /**
     * Returns `true` if [hostA] and [hostB] resolve to the same registrable or multi-tenant domain.
     */
    @JvmStatic
    fun isSameEffectiveDomain(hostA: String, hostB: String): Boolean {
        val domainA = extractEffectiveDomain(hostA)
        val domainB = extractEffectiveDomain(hostB)
        return domainA.isNotEmpty() && domainA == domainB
    }

    /**
     * Detects whether [rawHost] is a raw IP literal:
     * - Standard IPv4 (`1.2.3.4`)
     * - Bracketed or raw IPv6 (`[::1]`, `[2001:db8::1]`, `fe80::1`)
     * - Dotted or single-integer hex IP (`0x7f.0.0.1`, `0x7f000001`)
     * - Dotted octal IP (`0177.0.0.1`)
     * - Raw integer/dword IP (`2130706433`)
     */
    @JvmStatic
    fun isIpLiteral(rawHost: String): Boolean {
        val trimmed = rawHost
            .replace(UNICODE_DOTS_REGEX, ".")
            .trim()
            .trimEnd('.')
        if (trimmed.isEmpty()) return false

        // Bracketed IPv6 or colon-separated IPv6
        if (trimmed.startsWith("[") || trimmed.endsWith("]") || trimmed.contains(':')) {
            return true
        }

        // Standard IPv4
        if (IPV4_STANDARD_REGEX.matches(trimmed)) {
            return true
        }

        // Single-label or multi-label numeric/octal/hex IP (e.g. 2130706433 or 0x7f000001 or 127.1)
        val labels = trimmed.split('.')
        if (labels.all { label ->
                OCTAL_OR_NUMERIC_LABEL_REGEX.matches(label) || HEX_LABEL_REGEX.matches(label)
            }
        ) {
            return true
        }

        return false
    }

    internal fun normalizeHost(rawHost: String): String {
        return rawHost
            .replace(UNICODE_DOTS_REGEX, ".")
            .trim()
            .trimEnd('.')
            .lowercase(Locale.ROOT)
    }
}
