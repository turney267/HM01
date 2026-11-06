package dev.hm03.browser.dns

import java.util.Locale
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Verdict returned by DNS-over-HTTPS evaluation.
 */
enum class DohVerdict {
    ALLOW,
    BLOCK
}

/**
 * Thread-safe LRU + TTL cache for DNS-over-HTTPS hostname verdicts, with coalesced in-flight lookups
 * and a bounded background worker pool.
 *
 * - Default max capacity: 2,000 entries
 * - Default max TTL: 30 minutes
 * - Coalesces concurrent requests for the same key via [CompletableFuture] so simultaneous
 *   sub-resource loads for the same CDN host only trigger a single network lookup.
 */
class DohDecisionCache(
    private val maxEntries: Int = DEFAULT_MAX_ENTRIES,
    val defaultTtlMs: Long = DEFAULT_TTL_MS,
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
        val key = normalizeKey(hostname)
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
        val key = normalizeKey(hostname)
        if (key.isEmpty() || ttlMs <= 0L) return
        val cappedTtlMs = ttlMs.coerceAtMost(defaultTtlMs)
        val expiresAt = clockMs() + cappedTtlMs
        synchronized(lock) {
            lruMap[key] = CacheEntry(verdict = verdict, expiresAtMs = expiresAt)
        }
    }

    /**
     * Returns the cached verdict for [hostname], or executes [lookup] once across all concurrent callers
     * for the same key while coalescing in-flight lookups on the bounded background worker pool.
     */
    fun getOrCompute(
        hostname: String,
        timeoutMs: Long = 3_000L,
        cacheResult: (DohVerdict) -> Boolean = { true },
        ttlMsProvider: (DohVerdict) -> Long = { defaultTtlMs },
        lookup: (String) -> DohVerdict
    ): DohVerdict {
        val key = normalizeKey(hostname)
        get(key)?.let { return it }

        val ourFuture = CompletableFuture<DohVerdict>()
        val existingFuture = inFlight.putIfAbsent(key, ourFuture)
        if (existingFuture != null) {
            return try {
                existingFuture.get(timeoutMs, TimeUnit.MILLISECONDS)
            } catch (e: Exception) {
                // Never run network lookup directly on the calling (potentially Main UI) thread
                CompletableFuture.supplyAsync({ lookup(key) }, DOH_NETWORK_EXECUTOR)
                    .get(timeoutMs, TimeUnit.MILLISECONDS)
            }
        }

        return try {
            // Double-check cache in case another thread just finished before putIfAbsent
            val cached = get(key)
            if (cached != null) {
                ourFuture.complete(cached)
                return cached
            }
            // Always execute network lookup on the bounded background DoH executor so calls from
            // Android's Main UI thread never throw android.os.NetworkOnMainThreadException.
            val lookupFuture = CompletableFuture.supplyAsync({ lookup(key) }, DOH_NETWORK_EXECUTOR)
            val verdict = lookupFuture.get(timeoutMs, TimeUnit.MILLISECONDS)
            val resolvedTtlMs = ttlMsProvider(verdict)
            if (cacheResult(verdict) && resolvedTtlMs > 0L) {
                put(key, verdict, resolvedTtlMs)
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

    private fun normalizeKey(rawKey: String): String {
        return rawKey.trim().trimEnd('.').lowercase(Locale.ROOT)
    }

    companion object {
        const val DEFAULT_MAX_ENTRIES: Int = 2_000
        const val DEFAULT_TTL_MS: Long = 30L * 60L * 1000L // 30 minutes
        private const val CORE_POOL_THREADS = 4
        private const val MAX_POOL_THREADS = 16
        private const val MAX_QUEUE_CAPACITY = 256

        private val workerCounter = AtomicInteger(1)

        internal val DOH_NETWORK_EXECUTOR = ThreadPoolExecutor(
            CORE_POOL_THREADS,
            MAX_POOL_THREADS,
            30L,
            TimeUnit.SECONDS,
            LinkedBlockingQueue(MAX_QUEUE_CAPACITY),
            ThreadFactory { runnable ->
                Thread(runnable, "hm03-doh-worker-${workerCounter.getAndIncrement()}").apply {
                    isDaemon = true
                }
            },
            ThreadPoolExecutor.AbortPolicy()
        ).apply {
            allowCoreThreadTimeOut(true)
        }
    }
}
