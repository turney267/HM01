package dev.hm01.browser.dns

import java.util.Locale
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Verdict returned by CleanBrowsing DNS-over-HTTPS evaluation.
 */
enum class DohVerdict {
    ALLOW,
    BLOCK
}

/**
 * Thread-safe LRU + TTL cache for DNS-over-HTTPS hostname verdicts, with coalesced in-flight lookups.
 *
 * - Default max capacity: 2,000 hostnames
 * - Default TTL: 30 minutes
 * - Coalesces concurrent requests for the same hostname via [CompletableFuture] so simultaneous
 *   sub-resource loads for the same CDN host only trigger a single network lookup.
 */
class DohDecisionCache(
    private val maxEntries: Int = DEFAULT_MAX_ENTRIES,
    private val defaultTtlMs: Long = DEFAULT_TTL_MS,
    private val clockMs: () -> Long = { System.currentTimeMillis() }
) {
    private data class CacheEntry(
        val verdict: DohVerdict,
        val expiresAtMs: Long
    )

    private val lock = Any()
    private val lruMap = object : LinkedHashMap<String, CacheEntry>(128, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, CacheEntry>?): Boolean {
            return size > maxEntries
        }
    }

    private val inFlight = ConcurrentHashMap<String, CompletableFuture<DohVerdict>>()

    /**
     * Returns the cached [DohVerdict] for [hostname] if present and not expired, or `null`.
     */
    fun get(hostname: String): DohVerdict? {
        val key = normalizeHost(hostname)
        if (key.isEmpty()) return null
        val now = clockMs()
        synchronized(lock) {
            val entry = lruMap[key] ?: return null
            if (now >= entry.expiresAtMs) {
                lruMap.remove(key)
                return null
            }
            return entry.verdict
        }
    }

    /**
     * Stores [verdict] for [hostname] in the LRU cache with the specified [ttlMs].
     */
    fun put(hostname: String, verdict: DohVerdict, ttlMs: Long = defaultTtlMs) {
        val key = normalizeHost(hostname)
        if (key.isEmpty() || ttlMs <= 0L) return
        val expiresAt = clockMs() + ttlMs
        synchronized(lock) {
            lruMap[key] = CacheEntry(verdict = verdict, expiresAtMs = expiresAt)
        }
    }

    /**
     * Returns the cached verdict for [hostname], or executes [lookup] once across all concurrent callers
     * for the same hostname while coalescing in-flight lookups.
     */
    fun getOrCompute(
        hostname: String,
        timeoutMs: Long = 3_000L,
        cacheResult: (DohVerdict) -> Boolean = { true },
        lookup: (String) -> DohVerdict
    ): DohVerdict {
        val key = normalizeHost(hostname)
        get(key)?.let { return it }

        val ourFuture = CompletableFuture<DohVerdict>()
        val existingFuture = inFlight.putIfAbsent(key, ourFuture)
        if (existingFuture != null) {
            return try {
                existingFuture.get(timeoutMs, TimeUnit.MILLISECONDS)
            } catch (e: Exception) {
                lookup(key)
            }
        }

        return try {
            // Double-check cache in case another thread just finished before putIfAbsent
            val cached = get(key)
            if (cached != null) {
                ourFuture.complete(cached)
                return cached
            }
            // Always execute network lookup on the background DoH executor so calls from
            // Android's Main UI thread never throw android.os.NetworkOnMainThreadException.
            val lookupFuture = CompletableFuture.supplyAsync({ lookup(key) }, DOH_NETWORK_EXECUTOR)
            val verdict = lookupFuture.get(timeoutMs, TimeUnit.MILLISECONDS)
            if (cacheResult(verdict)) {
                put(key, verdict)
            }
            ourFuture.complete(verdict)
            verdict
        } catch (t: Throwable) {
            ourFuture.completeExceptionally(t)
            throw t
        } finally {
            inFlight.remove(key, ourFuture)
        }
    }

    /**
     * Clears all cached verdicts and in-flight entries.
     */
    fun clear() {
        synchronized(lock) {
            lruMap.clear()
        }
        inFlight.clear()
    }

    /**
     * Current number of cached entries.
     */
    fun size(): Int {
        synchronized(lock) {
            return lruMap.size
        }
    }

    /**
     * Number of currently active in-flight lookups (useful for testing).
     */
    fun inFlightCount(): Int = inFlight.size

    private fun normalizeHost(rawHost: String): String {
        return rawHost.trim().trimEnd('.').lowercase(Locale.ROOT)
    }

    companion object {
        const val DEFAULT_MAX_ENTRIES: Int = 2_000
        const val DEFAULT_TTL_MS: Long = 30L * 60L * 1000L // 30 minutes
        private val DOH_NETWORK_EXECUTOR = Executors.newCachedThreadPool { runnable ->
            Thread(runnable, "hm01-doh-worker").apply { isDaemon = true }
        }
    }
}
