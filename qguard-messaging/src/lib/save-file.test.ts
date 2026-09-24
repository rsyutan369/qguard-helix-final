import { describe, expect, it } from "vitest";
import { SAVE_CHUNK_BYTES, saveToAndroidDownloads, type SaveInvoker } from "@/lib/save-file";

interface Call {
  command: string;
  args: Record<string, unknown> | undefined;
}

function recordingInvoker(overrides: Partial<Record<string, (args: Record<string, unknown> | undefined) => unknown>> = {}) {
  const calls: Call[] = [];
  const invoker: SaveInvoker = async <T,>(command: string, args?: Record<string, unknown>) => {
    calls.push({ command, args });
    const override = overrides[command];
    if (override) return override(args) as T;
    if (command === "downloads_save_begin") return "handle-1" as T;
    if (command === "downloads_save_commit") {
      return { name: "report.pdf", location: "Download/QGuard/report.pdf", bytes: 3 } as T;
    }
    return undefined as T;
  };
  return { calls, invoker };
}

function decodeChunks(calls: Call[]): Uint8Array {
  const parts = calls
    .filter((call) => call.command === "downloads_save_chunk")
    .map((call) => new Uint8Array(Buffer.from(String(call.args?.chunkB64), "base64")));
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

describe("saveToAndroidDownloads", () => {
  it("streams the bytes through begin -> chunk -> commit and reports where they went", async () => {
    const { calls, invoker } = recordingInvoker();
    const blob = new Blob([new Uint8Array([1, 2, 3])], { type: "application/pdf" });

    const saved = await saveToAndroidDownloads("report.pdf", blob, invoker);

    expect(calls.map((call) => call.command)).toEqual([
      "downloads_save_begin",
      "downloads_save_chunk",
      "downloads_save_commit",
    ]);
    expect(calls[0].args).toEqual({ fileName: "report.pdf", mimeType: "application/pdf" });
    expect(calls[1].args?.handle).toBe("handle-1");
    expect(Array.from(decodeChunks(calls))).toEqual([1, 2, 3]);
    expect(saved).toEqual({ name: "report.pdf", location: "Download/QGuard/report.pdf", confirmed: true });
  });

  it("splits large files into bounded chunks and reassembles them exactly", async () => {
    const { calls, invoker } = recordingInvoker();
    const size = SAVE_CHUNK_BYTES * 2 + 17;
    const source = new Uint8Array(size).map((_value, index) => index % 251);

    await saveToAndroidDownloads("big.bin", new Blob([source]), invoker);

    const chunkCalls = calls.filter((call) => call.command === "downloads_save_chunk");
    expect(chunkCalls).toHaveLength(3);
    // Byte-exact reassembly (Buffer.compare: an element-wise toEqual over a
    // megabyte is needlessly slow).
    expect(Buffer.compare(Buffer.from(decodeChunks(calls)), Buffer.from(source))).toBe(0);
  });

  it("still creates (and commits) an empty file", async () => {
    const { calls, invoker } = recordingInvoker();
    await saveToAndroidDownloads("empty.txt", new Blob([]), invoker);
    expect(calls.map((call) => call.command)).toEqual(["downloads_save_begin", "downloads_save_commit"]);
  });

  it("falls back to a generic type when the blob has none", async () => {
    const { calls, invoker } = recordingInvoker();
    await saveToAndroidDownloads("notes", new Blob(["x"]), invoker);
    expect(calls[0].args?.mimeType).toBe("application/octet-stream");
  });

  it("aborts the partial file and rethrows when a chunk fails", async () => {
    const { calls, invoker } = recordingInvoker({
      downloads_save_chunk: () => {
        throw new Error("storage error: write to Downloads: No space left on device");
      },
    });

    await expect(saveToAndroidDownloads("report.pdf", new Blob(["abc"]), invoker)).rejects.toThrow("No space left");
    expect(calls.map((call) => call.command)).toEqual([
      "downloads_save_begin",
      "downloads_save_chunk",
      "downloads_save_abort",
    ]);
    expect(calls[2].args).toEqual({ handle: "handle-1" });
  });

  it("does not try to abort when the file could not even be created", async () => {
    const { calls, invoker } = recordingInvoker({
      downloads_save_begin: () => {
        throw new Error("Supabase session required");
      },
    });
    await expect(saveToAndroidDownloads("a.txt", new Blob(["a"]), invoker)).rejects.toThrow("session required");
    expect(calls.map((call) => call.command)).toEqual(["downloads_save_begin"]);
  });
});
