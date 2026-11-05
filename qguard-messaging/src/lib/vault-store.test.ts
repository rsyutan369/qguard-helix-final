import { describe, expect, it } from "vitest";
import {
  breadcrumb,
  byId,
  canPreview,
  describeStoreError,
  folderTotals,
  formatBytes,
  inTrash,
  liveEntries,
  matchesFilter,
  moveTargets,
  sortEntries,
  type StoreEntry,
} from "./vault-store";

let counter = 0;
function entry(partial: Partial<StoreEntry> & Pick<StoreEntry, "name">): StoreEntry {
  counter += 1;
  return {
    id: partial.id ?? `id-${counter}`,
    kind: "file",
    parentId: null,
    createdAt: "2026-11-01T00:00:00Z",
    updatedAt: "2026-11-01T00:00:00Z",
    trashedAt: null,
    favorite: false,
    sizeBytes: 10,
    storedBytes: 200,
    contentType: "text/plain",
    category: "document",
    typeCheck: "match",
    plaintextSha3: "",
    containerVersion: 5,
    pinBound: true,
    totalChunks: 1,
    recoveryProtected: false,
    integrity: "unverified",
    lastVerifiedAt: null,
    hasThumbnail: false,
    ...partial,
  };
}

function tree() {
  const trip = entry({ id: "trip", name: "Trip", kind: "folder", sizeBytes: 0 });
  const day = entry({ id: "day", name: "Day 1", kind: "folder", parentId: "trip", sizeBytes: 0 });
  const photo = entry({ id: "photo", name: "beach.jpg", parentId: "day", category: "image", contentType: "image/jpeg", sizeBytes: 300 });
  const notes = entry({ id: "notes", name: "notes.txt", parentId: "trip", sizeBytes: 40 });
  const loose = entry({ id: "loose", name: "Loose.pdf", contentType: "application/pdf", sizeBytes: 5 });
  return [trip, day, photo, notes, loose];
}

describe("vault storage tree helpers", () => {
  it("cascades the trash from a folder to everything inside it", () => {
    const entries = tree().map((e) => (e.id === "trip" ? { ...e, trashedAt: "2026-11-02T00:00:00Z" } : e));
    const index = byId(entries);
    expect(inTrash(index, "photo")).toBe(true);
    expect(inTrash(index, "loose")).toBe(false);
    expect(liveEntries(entries).map((e) => e.id)).toEqual(["loose"]);
  });

  it("builds breadcrumbs from the top level down", () => {
    const index = byId(tree());
    expect(breadcrumb(index, "day").map((e) => e.name)).toEqual(["Trip", "Day 1"]);
    expect(breadcrumb(index, null)).toEqual([]);
  });

  it("never offers a folder as a move target into itself or below it", () => {
    const targets = moveTargets(tree(), new Set(["trip"])).map((e) => e.id);
    expect(targets).toEqual([]);
    expect(moveTargets(tree(), new Set(["photo"])).map((e) => e.id)).toEqual(["trip", "day"]);
  });

  it("totals only live files below a folder", () => {
    expect(folderTotals(tree(), "trip")).toEqual({ files: 2, bytes: 340 });
    const trashedPhoto = tree().map((e) => (e.id === "photo" ? { ...e, trashedAt: "x" } : e));
    expect(folderTotals(trashedPhoto, "trip")).toEqual({ files: 1, bytes: 40 });
  });

  it("sorts folders first, then by the chosen key", () => {
    const sorted = sortEntries(tree(), "size", "desc").map((e) => e.id);
    expect(sorted.slice(0, 2).sort()).toEqual(["day", "trip"]);
    expect(sorted.slice(2)).toEqual(["photo", "notes", "loose"]);
    expect(sortEntries(tree(), "name", "asc").slice(2).map((e) => e.name)).toEqual(["beach.jpg", "Loose.pdf", "notes.txt"]);
  });

  it("filters by name, category and favourite", () => {
    const [, , photo, notes] = tree();
    expect(matchesFilter(photo, { query: "BEACH" })).toBe(true);
    expect(matchesFilter(notes, { query: "beach" })).toBe(false);
    expect(matchesFilter(photo, { categories: ["image", "video"] })).toBe(true);
    expect(matchesFilter(notes, { categories: ["image"] })).toBe(false);
    expect(matchesFilter(notes, { favoritesOnly: true })).toBe(false);
  });

  it("previews only types and sizes the core will decrypt into memory", () => {
    const [, , photo, , pdf] = tree();
    expect(canPreview(photo, 1000)).toBe(true);
    expect(canPreview(photo, 100)).toBe(false);
    expect(canPreview(pdf, 1000)).toBe(false);
  });

  it("formats sizes and explains core errors without the error prefix", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(5 * 1024 * 1024 * 1024)).toBe("5.0 GB");
    expect(describeStoreError("invalid input: a name is required")).toBe("a name is required");
    expect(describeStoreError(new Error("trust error: VAULT_STORE_FOREIGN_INDEX: sealed"))).toMatch(/previous vault key/);
    expect(describeStoreError("crypto error: AEAD authentication failed")).toMatch(/Integrity check failed/);
  });
});
