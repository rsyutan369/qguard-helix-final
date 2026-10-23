import { describe, expect, it, vi } from "vitest";
import { IN_FILTER_CHUNK, selectAllPages, selectInChunks } from "./query-batching";

describe("selectAllPages", () => {
  it("reads past the relay's row cap until a short page", async () => {
    const rows = Array.from({ length: 2500 }, (_, index) => ({ index }));
    const page = vi.fn(async (from: number, to: number) => ({ data: rows.slice(from, to + 1), error: null }));
    const result = await selectAllPages(page, 1000);
    expect(result.error).toBeNull();
    expect(result.data).toHaveLength(2500);
    expect(page.mock.calls).toEqual([[0, 999], [1000, 1999], [2000, 2999]]);
  });

  it("asks once more after an exactly full page, then stops", async () => {
    const rows = Array.from({ length: 1000 }, (_, index) => ({ index }));
    const page = vi.fn(async (from: number, to: number) => ({ data: rows.slice(from, to + 1), error: null }));
    expect((await selectAllPages(page, 1000)).data).toHaveLength(1000);
    expect(page).toHaveBeenCalledTimes(2);
  });

  it("returns the error, never a partial list that looks complete", async () => {
    const page = vi.fn(async (from: number) => (from === 0
      ? { data: Array.from({ length: 1000 }, () => ({})), error: null }
      : { data: null, error: new Error("timeout") }));
    const result = await selectAllPages(page, 1000);
    expect(result.data).toBeNull();
    expect(result.error).toBeInstanceOf(Error);
  });

  it("stops at the ceiling", async () => {
    const page = vi.fn(async () => ({ data: Array.from({ length: 10 }, () => ({})), error: null }));
    expect((await selectAllPages(page, 10, 30)).data).toHaveLength(30);
  });
});

describe("selectInChunks", () => {
  it("splits a long id list so no URL carries a thousand ids", async () => {
    const ids = Array.from({ length: 1000 }, (_, index) => `id-${index}`);
    const query = vi.fn(async (part: string[]) => ({ data: part.map((id) => ({ id })), error: null }));
    const result = await selectInChunks(ids, query);
    expect(result.data).toHaveLength(1000);
    expect(query).toHaveBeenCalledTimes(Math.ceil(1000 / IN_FILTER_CHUNK));
    expect(Math.max(...query.mock.calls.map(([part]) => part.length))).toBeLessThanOrEqual(IN_FILTER_CHUNK);
  });

  it("de-duplicates, skips empty ids, and makes no request for nothing", async () => {
    const query = vi.fn(async (part: string[]) => ({ data: part, error: null }));
    expect((await selectInChunks(["a", "a", "", "b"], query)).data).toEqual(["a", "b"]);
    query.mockClear();
    expect(await selectInChunks([], query)).toEqual({ data: [], error: null });
    expect(query).not.toHaveBeenCalled();
  });

  it("fails as a whole when any chunk fails", async () => {
    const ids = Array.from({ length: 400 }, (_, index) => `id-${index}`);
    const query = vi.fn(async (part: string[]) => (part.includes("id-399") ? { data: null, error: new Error("denied") } : { data: part, error: null }));
    const result = await selectInChunks(ids, query);
    expect(result.data).toBeNull();
    expect(result.error).toBeInstanceOf(Error);
  });
});
