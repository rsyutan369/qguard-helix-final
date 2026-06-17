# Lessons — Q-Shrink Vault Engine

## L1 — Web Streams: read before you write, settle both sides on error
**Failure pattern:** `CompressionStream`/`DecompressionStream` via `new Response(stream.readable).arrayBuffer()` produced intermittently truncated output (`Z_BUF_ERROR: unexpected end of file`), and a *deliberately* corrupt decompress (tamper test) crashed the **next** test with an uncaught `TypeError` from Node's webstreams adapter.
**Root cause:** (a) writing without an active reader / without awaiting risks truncated collection and backpressure deadlock; (b) when a transform errors, `new Response(readable)` can leave a dangling, unhandled stream `error` event that surfaces on a later tick.
**Prevention rule:** pump transform streams manually — get both reader and writer, run read+write concurrently, and on error `cancel()` the reader, `abort()` the writer, and `Promise.allSettled` both halves before rethrowing a clean error. Never use `new Response(readable)` for data that may be corrupt. (`src/lib/vault/q-shrink/codec.ts`)

## L2 — Test assertions must match the algorithm's real behavior
**Failure pattern:** a cross-file dedup assertion failed because the "shared" content was repetitive *text* whose 69-byte period doesn't align to 8 KB chunk boundaries — it compresses ~99% but doesn't dedup.
**Prevention rule:** to exercise block-level dedup, share a large **random** blob (stable, alignable content-defined boundaries). Compression and deduplication are different wins; test them with inputs that isolate each.

## L3 — Compress before encrypt; never inflate
**Rule:** high-entropy ciphertext is incompressible, so optimization must precede encryption. Entropy-gate + a post-compression guard + a container-vs-original guard guarantee the sealed object is never larger than the input (`applied:false` seals raw bytes). Each file compresses in isolation (no CRIME/BREACH shared-context oracle).

## L4 — A self-describing magic must be unforgeable by the payload it describes
**Failure pattern:** restore detected containers purely by the `QSHRN1` magic, while the no-inflation path sealed *raw* bytes with `applied:false`. A real user file whose plaintext happened to begin with the 7 magic bytes (`51 53 48 52 4E 31 01`) was therefore mis-detected as a container on download and `restorePackage` tried to `JSON.parse` random bytes → threw → **permanent data loss for a correctly-sealed file**. Attacker-craftable (just upload a file starting with those bytes; a re-uploaded vault container literally does).
**Root cause:** the two halves of the contract disagreed — optimize could emit a passthrough that collides with the very sentinel restore treats as authoritative. The `applied` flag that was *supposed* to disambiguate lived in mutable, unauthenticated server metadata, so restore (correctly, for zero-knowledge) ignored it — leaving magic-only detection with a false-positive hole.
**Prevention rule:** when a format is detected by an in-band sentinel, the *producer* must guarantee no non-format payload can start with that sentinel. Here: `optimizeFile` now wraps any raw input that begins with the magic instead of passing it through (`!beneficial && !isQShrinkPackage(data)` gates passthrough), so the magic is truly authoritative and the decision stays inside the GCM-authenticated bytes — never trusting mutable metadata. Regression covered in `roundtrip-test.ts` → `[magic-collision safety]`.
