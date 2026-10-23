/**
 * Reads that stay correct when a conversation has hundreds or thousands of
 * members (migration 047: large groups and channels start at 1,000 people).
 *
 * Two limits of the REST relay bite at that size, both silently:
 *   * a select returns at most `max-rows` rows (1,000 on Supabase), so a query
 *     for "every member row I can see" quietly loses the rest — including this
 *     account's own rows in other conversations, which then vanish from the list;
 *   * `.in(column, ids)` travels in the URL, and a thousand UUIDs (~37 KB) is
 *     past what the gateway accepts.
 *
 * `selectAllPages` reads page by page until a short page; `selectInChunks`
 * splits the id list. Both stop at the first error and return it, so a caller
 * never mistakes a failed read for an empty one.
 */

import { chunk } from "@/lib/channels";

/** Ids per `.in()` filter: ~5.5 KB of UUIDs, well inside any gateway's URL limit. */
export const IN_FILTER_CHUNK = 150;
/** Rows per page; at or below the relay's max-rows, so a full page means "maybe more". */
export const PAGE_SIZE = 1000;
/** A ceiling so a runaway read cannot loop forever (100 pages). */
export const MAX_PAGED_ROWS = 100_000;

interface QueryResult<T> {
  data: T[] | null;
  error: unknown;
}

export async function selectAllPages<T>(
  page: (from: number, to: number) => PromiseLike<QueryResult<T>>,
  pageSize = PAGE_SIZE,
  maxRows = MAX_PAGED_ROWS,
): Promise<QueryResult<T>> {
  const rows: T[] = [];
  for (let from = 0; from < maxRows; from += pageSize) {
    const { data, error } = await page(from, from + pageSize - 1);
    if (error) return { data: null, error };
    const batch = data ?? [];
    rows.push(...batch);
    if (batch.length < pageSize) break;
  }
  return { data: rows, error: null };
}

export async function selectInChunks<T>(
  ids: readonly string[],
  query: (ids: string[]) => PromiseLike<QueryResult<T>>,
  size = IN_FILTER_CHUNK,
): Promise<QueryResult<T>> {
  const unique = Array.from(new Set(ids.filter(Boolean)));
  if (unique.length === 0) return { data: [], error: null };
  const results = await Promise.all(chunk(unique, size).map((part) => query(part)));
  const failed = results.find((result) => result.error);
  if (failed) return { data: null, error: failed.error };
  return { data: results.flatMap((result) => result.data ?? []), error: null };
}
