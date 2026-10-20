# Private On-Device AI — Threat Model and Design

**Date:** 2026-10-19 (updated 2026-10-20) · **Roadmap:** Phase 8 · **Status:** owner chose cloud models with the user's own key — built (§7); the on-device design (§1–§6) remains the offline fallback

---

## 1. Starting point (verified)

The app has no AI, summarisation or translation code: no model runtime in `Cargo.toml`, no ML dependency in the Android Gradle build, and nothing in `src/`. Decrypted messages exist only in memory (`chat-plaintext-cache.ts`) and are wiped on lock, logout and owner change.

## 2. 8.1 Threat model

An assistant feature has to **read plaintext**. It must leave every guarantee the app gives today intact.

| # | Threat | Requirement |
| --- | --- | --- |
| T1 | Plaintext leaves the device (a cloud API, telemetry, crash reports) | Inference runs locally only. The AI module has no network access: no `fetch`, and no Tauri HTTP capability is granted to it. A test fails the build if the AI module imports anything network-capable. Off by default, per device. |
| T2 | AI output outlives the messages it came from | Output is held in memory only, next to the plaintext caches, and is wiped with them (`clearChatPlaintextCaches`). It is never written to disk, the relay or backups. **Disappearing, read-once and view-once messages are excluded from model input**, and a summary is dropped when any message it used expires. |
| T3 | Prompt injection: an incoming message tells the model to do something | The model has **no tools and no actions**. Output is display-only text, clearly labelled "AI-generated · on this device", and is never sent, never used to auto-reply, and never fed back as an instruction. Smart replies are suggestions the user must tap and then send. |
| T4 | A tampered model file (supply chain) | Model files are pinned by SHA3-256 in the signed app release. If they are downloaded, the source is the project's own release host, verified before loading, with no "load any file" option. |
| T5 | A shoulder-surfer or someone with device access reads summaries | Summaries are hidden behind the same workspace lock, and the privacy screen (roadmap 4.x) covers them. |
| T6 | The user forgets AI is on | A per-conversation indicator shows when AI is enabled, and an opt-out per conversation. Turning AI off wipes its output immediately. |
| T7 | Contacts don't expect their messages to be processed | Processing is local and invisible to them, the same exposure as the user reading the message. Documented in `security-limitations.md`. There is no "contact consent" signal, because it could not be enforced on the reader's device anyway. |

## 3. 8.2 Features and backends

| Feature | Android | Desktop (Windows/macOS/Linux) | Notes |
| --- | --- | --- | --- |
| **Translation** | Bergamot (Mozilla Firefox Translations): about 15–40 MB per language pair, MPL-2.0, CPU via WASM in the WebView | Same WASM build | **Recommended first:** small, permissive licence, works on every platform including Android WebView, and needs no GPU. |
| **Summary / "catch me up"** | ML Kit GenAI Summarization (Gemini Nano via AICore), only on supported devices (recent Pixel and some Samsung). Elsewhere the feature is unavailable rather than falling back to the cloud. | llama.cpp through a Rust binding running a 1–3B instruction model (for example Qwen2.5-1.5B-Instruct, Apache-2.0, about 1 GB at Q4) | Desktop needs a model download decision (§5). Building llama.cpp adds a native C++ build. |
| **Smart replies** | ML Kit GenAI / Gemini Nano | Same local model as summaries | Suggestions only (T3). |

Every backend reports *available / downloadable / unavailable* from real detection. Nothing pretends to work.

## 4. 8.3 Rules the implementation must follow

1. AI output is never written into the plaintext cache, or anywhere else persistent, unless the user explicitly saves it (for example "copy").
2. Model input excludes messages that are disappearing, read-once, view-once, expired, locked (`available_at` in the future) or failed to decrypt.
3. A summary records the ids of the messages it used, and is dropped when any of them expires or is deleted.
4. The module has no network capability (T1), enforced by a test.
5. Everything is opt-in per device, off by default, with a per-conversation opt-out (T6).

## 5. Owner decisions needed

1. **Which feature first?** Translation (Bergamot) is the recommendation: smallest and on every platform.
2. **Desktop model:** which model and licence (Qwen2.5 is Apache-2.0; Gemma has its own terms; Llama has its own licence), and how to distribute it: bundled (+1 GB installer) or downloaded on demand from the release host with SHA3-256 pinning (T4).
3. **Android:** accept that summaries only exist on AICore-capable devices?
4. Is "catch me up" on a group (Phase 7) in scope? It reads many senders' messages at once.

## 6. Acceptance (when built)

- Unit tests: input filtering excludes disappearing, read-once and view-once messages; output is wiped on lock; no network import (a static test).
- On-device tests on one AICore device and one non-AICore device.
- Desktop: run with networking blocked and confirm the feature still works and makes no connection attempts.

---

## 7. Owner decision of 2026-10-20: cloud models (built)

The owner chose **cloud models with the user's own API key**:

- **First:** Anthropic Claude Sonnet 5.5 (`claude-sonnet-5-5`).
- **Then:** OpenAI. The model id is entered by the user, because this project cannot verify the name "GPT 6 Astra".
- **Download method:** there is nothing to download for a cloud model. The on-device design above (§3, §5) stays the fallback for a future offline mode; if it is built, it should use an on-demand download from the release host, pinned by SHA3-256 (T4).

This **reverses T1**: what the assistant reads leaves the device. Built so that it happens only knowingly.

| | |
| --- | --- |
| Off by default | Enabled per device in Settings → AI assistant, which states plainly that the messages it reads are sent to the provider and leave end-to-end encryption. |
| Per conversation | The first use in a conversation asks for permission, which is kept per device. It can be withdrawn there, and turning the assistant off withdraws every permission. The other people in the conversation are **not** notified (stated in the prompt). |
| Only on request | Nothing runs in the background. Each of *Catch me up*, *Suggest replies* and *Translate* is one button press and one request. |
| What is sent | Only decrypted, currently visible, ordinary messages (`selectAssistantInput`): never disappearing, read-once, view-once, scheduled or undecrypted ones. Attachments are never sent, only an "[attachment]" marker. At most the last 60 messages, each capped at 2,000 characters. |
| Prompt injection | Messages go inside `<conversation>` as JSON with `<` and `>` escaped, so a message cannot close the block. A test caught that plain `JSON.stringify` allowed it. The system prompt marks the content as untrusted. The model has no tools, and output is display text only; suggested replies go to the composer and are never sent automatically. |
| Output | Memory only, labelled "AI-generated by <provider> — may be wrong", and wiped with the decrypted-message caches (lock, logout, owner change). |
| API key | The user's own, stored encrypted in the core (`commands/assistant.rs`, the same sealed store as recovery documents, erased by panic wipe). The UI sees only the last 4 characters. The full key leaves the core only for the request it authorises. |
| Network | The CSP admits exactly `https://api.anthropic.com` and `https://api.openai.com`. Requests run from the app's web layer (`credentials: "omit"`; Anthropic requires its direct-browser-access header). The Rust core has no HTTP client on Android, and adding one would mean an unverified native build. |

**Verified:** 16 unit tests (filtering, prompt framing and escaping, both providers' request and response shapes, error mapping, timeout, consent, memory wipe) and 5 Rust tests (key storage encrypted on disk, last-four hint only, clear, refusal of malformed keys, per-account isolation).

**Not verified:** a call to either live API. No key is available in this environment.
