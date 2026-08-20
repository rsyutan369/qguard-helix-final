/**
 * Per-tenant single-flight cache for the expensive dashboard builders.
 *
 * WHY THIS EXISTS
 * ---------------
 * `buildSnapshot`, `buildPortfolio` and `buildGovernanceModel` each fan out
 * 12-54 Supabase queries, and every one of them was cached with the same shape:
 *
 *     const cached = cache.get(userId)
 *     if (cached && Date.now() - cached.at < TTL) return cached.promise
 *     const promise = compute(token, userId)
 *     cache.set(userId, { at: Date.now(), promise })
 *
 * `at` was stamped when the build STARTED. So whenever a build took longer than
 * its own TTL (15s), the next SSE poll — they run every 8-30s — saw an expired
 * entry and launched a SECOND build while the first was still in flight. That
 * duplicate re-issued the same 12-54 queries, which made the window slower
 * still, which expired the entry again, which spawned a third. A single slow
 * period compounded into the connection storm that produced hundreds of
 * `UND_ERR_CONNECT_TIMEOUT` failures.
 *
 * Two changes break that loop:
 *
 *  1. An IN-FLIGHT computation is shared regardless of age. There is never more
 *     than one build per tenant per builder.
 *  2. The TTL is measured from COMPLETION, not from start, so a build that takes
 *     longer than the TTL is not already stale the instant it lands.
 *
 * `force` still starts a genuinely fresh build: it is used right after a
 * mutation, where reusing a build that began BEFORE the write would serve
 * pre-write data. Those call sites are rare and user-initiated, so the extra
 * work is both bounded and correct.
 *
 * Failures are never cached — the next caller retries.
 */

interface Entry<T> {
  /** Stamped at completion, so the TTL measures RESULT age. */
  at: number
  pending: boolean
  promise: Promise<T>
}

export interface SingleFlightCache<T> {
  /** Shared in-flight build, else a fresh one. `force` always rebuilds. */
  get(key: string, compute: () => Promise<T>, force?: boolean): Promise<T>
  /** Drops a tenant's entry so the next read reflects a just-made write. */
  delete(key: string): void
  readonly size: number
}

export function createSingleFlightCache<T>(ttlMs: number, maxEntries = 500): SingleFlightCache<T> {
  const entries = new Map<string, Entry<T>>()

  return {
    get(key, compute, force = false) {
      const cached = entries.get(key)
      if (!force && cached && (cached.pending || Date.now() - cached.at < ttlMs)) {
        return cached.promise
      }

      const entry: Entry<T> = { at: Date.now(), pending: true, promise: compute() }
      entries.set(key, entry)
      entry.promise.then(
        () => {
          entry.pending = false
          entry.at = Date.now()
        },
        () => {
          entry.pending = false
          // Only evict our own entry — a `force` rebuild may have replaced it.
          if (entries.get(key) === entry) entries.delete(key)
        },
      )

      if (entries.size > maxEntries) {
        const now = Date.now()
        for (const [k, v] of entries) {
          if (!v.pending && now - v.at > ttlMs) entries.delete(k)
        }
      }

      return entry.promise
    },

    delete(key) {
      entries.delete(key)
    },

    get size() {
      return entries.size
    },
  }
}
