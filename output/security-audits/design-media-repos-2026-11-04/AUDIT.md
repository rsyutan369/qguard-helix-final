# ComfyUI, Reanimate, and Remotion: security review and skill integration

Review date: 2026-11-04, Asia/Manila.

## Decisions

No evidence of deliberately malicious behavior was identified in the reviewed scope. This is not an assurance that the complete applications or their dependencies are threat-free. A confirmed file-write escape blocks Reanimate installation. The other additions are scoped skills, not application installations.

| Repository | Pinned revision | Decision |
| --- | --- | --- |
| Comfy-Org/ComfyUI | `56f179f6c50dad0c4c860ae4da427415c8e86415` | Added a locally authored, documentation-only `comfyui-workflows` skill. ComfyUI has no upstream `SKILL.md` in this snapshot. No application, model, manager, custom node, or GPU dependency installed. |
| NiazMorshed2007/reanimate | `3f7a55a2986a84ca2173e86ee9127eefe31d046d` | Not installed: confirmed traversal and overwrite in its GL trace serializer. |
| remotion-dev/remotion | `2f06c4e3166a94607c5c56d68169f3754a0ecc72` | Installed the reviewed, self-contained `remotion-best-practices` Codex skill. No Remotion application/runtime dependencies, browser binaries, or cloud resources installed. |

The original `Comfy-Org/Comfy` address returned 404 from both GitHub and its public API. The user supplied and authorized the corrected ComfyUI address during this review.

## Scope and method

All source was pinned before review. Archive entries were checked for containment, symlinks were identified, and extracted bytes were checked against Git blob hashes from the pinned source trees. Repository code was not executed during download or extraction.

| Source | Inspection coverage |
| --- | --- |
| ComfyUI | All 1,332 regular archive files inventoried/hashed; all 1,029 Python files parsed without importing them during static inspection. Manual review concentrated on startup, model loading, custom nodes, API/origin/file handling, optional cloud/agent paths, and security regressions. |
| Reanimate | All 378 regular archive files inventoried/hashed. Reviewed the complete skill entrypoint, bootstrap, helper scripts, browser trace/asset handling, output writes/cleanup, dependency locks, and selected site/vendor setup. No browser or FFmpeg installed. |
| Remotion | Full tree contains 14,502 files. Reviewed a sparse checkout of 1,516 files covering bundled skills, renderer, CLI, Studio server/protocol, project scaffolding, CI, and scripts. Parsed 994 JavaScript/TypeScript files with no syntax diagnostics. Verified all 127 files in the selected skill. This was a focused audit, not a line-by-line review of every monorepo package. |

Public dependency versions were queried against npm's bulk advisory service, with advisory ranges evaluated against exact locked versions. ComfyUI's seven exact direct pins were queried through OSV. This did not install application packages or run upstream package lifecycle scripts. The only new verification dependency was PyYAML 6.0.3 in an isolated audit-only directory for the existing Codex skill validator; system Python and application dependencies were unchanged.

Archive SHA-256 values:

- ComfyUI: `b9ae37f3de256f5e3834c61477f520d1a1d49f872f7f4f0cb1bab6487bd9d673`.
- Reanimate: `d1b5d625eb4ac9feb5501dd82735df50c72578d2d15b28a791be563ef4f50c8d`.
- Remotion used a commit-pinned sparse Git checkout; all 1,516 checked-out files matched the source tree's blob hashes, allowing for checkout line endings.

## Reanimate findings

### HIGH — Webpage-controlled trace fields escape the capture directory and overwrite files

`capture.ts:535` obtains the trace by evaluating the mutable page global `window.__mcgl.export()`. At line 604, the result goes into `writeGlArtifacts()` without a host-side schema or path-containment check. The page can replace that export or change the trace object; in-page initialization does not make the exported values trusted.

In `gl.ts`, raw program/module/texture IDs, dump fields, and scene indices are used in host filesystem paths. Sanitizing a display label does not sanitize those IDs. Particularly clear sinks are the module filename at lines 78–79 and the scene filename at line 100. They use `writeFileSync`, which can overwrite existing files.

Evidence: [page export](https://github.com/NiazMorshed2007/reanimate/blob/3f7a55a2986a84ca2173e86ee9127eefe31d046d/skills/reanimate/scripts/capture.ts#L535), [serializer call](https://github.com/NiazMorshed2007/reanimate/blob/3f7a55a2986a84ca2173e86ee9127eefe31d046d/skills/reanimate/scripts/capture.ts#L604), [module path](https://github.com/NiazMorshed2007/reanimate/blob/3f7a55a2986a84ca2173e86ee9127eefe31d046d/skills/reanimate/scripts/gl.ts#L78), [scene path](https://github.com/NiazMorshed2007/reanimate/blob/3f7a55a2986a84ca2173e86ee9127eefe31d046d/skills/reanimate/scripts/gl.ts#L100).

A harmless reproduction called the original, unmodified serializer with synthetic page-controlled trace data. All filesystem access was restricted using Node's permission model, with writes allowed only in an audit-owned reproduction directory. It successfully:

1. Wrote a `.wgsl` marker outside the chosen `capture/` directory.
2. Overwrote an existing, audit-owned `package.json` sentinel outside `capture/` with chosen JSON.
3. Completed processing without an exception.

Evidence is saved in `reanimate-path-repro/result.json`; the reproduction is `reanimate-path-repro.mjs`. This is a confirmed serializer vulnerability with a statically traced webpage-to-host path. A remote malicious page, full Chromium capture, or code execution through a poisoned project was not exercised. It does not prove the repository is intentionally malicious, and no existing user project file was targeted.

Installation decision: **withheld**. A safe upstream fix needs host-generated filenames or strict ID/index/type validation, containment checks against resolved output paths, link/junction handling, appropriate overwrite rules, and regression tests exercising hostile exported page data. The issue was not sent to maintainers because the user did not authorize external messages.

### WARNING — Output reuse deletes files and setup downloads executable dependencies

`frames.ts:38` removes every `.png` in the selected output directory. Capture/GL helpers also clear named frame, asset, and trace directories. Accidentally selecting an existing asset directory can lose files. The workflow intends dedicated per-capture folders, but the helpers do not establish ownership before cleaning them.

`setup.sh` runs `bun install` and may download Chromium. FFmpeg is a binary dependency; package integrity does not by itself establish the provenance or safety of all downloaded executables. Its helper assumes a Unix-style `ffmpeg` path and the setup is Bash-based; Windows is explicitly untested upstream. None of these bootstrap commands ran here.

### INFO — Dependency advisories do not detect the confirmed source-code flaw

The script lockfile contains 24 exact package-version entries; none matched npm advisories during this review. The optional site's lockfile contains 494 entries and matched one moderate `minimatch` advisory covering locked versions 3.1.5 and 10.2.6. Neither result changes the confirmed source-level file-write finding.

## ComfyUI findings

### WARNING — Local trusted-user application, not an authenticated multi-tenant service

The server defaults to loopback. Its [security policy](https://github.com/Comfy-Org/ComfyUI/blob/56f179f6c50dad0c4c860ae4da427415c8e86415/SECURITY.md) explicitly assumes people able to reach the instance are trusted. `--listen` without a value exposes network interfaces, and enabling permissive CORS broadens browser access. User profile IDs/headers do not establish tenant authentication or isolation.

Do not expose this runtime as a Qguard service or connect it to sensitive shared workflows without a separate authentication, authorization, network, and job-isolation design. The installed skill preserves loopback use and does not launch a server or change network configuration.

### WARNING — Custom nodes, managers, agents, and model/runtime dependencies are separate trust decisions

Custom-node startup/import hooks run Python code on the host. Optional manager and agent packages extend that execution surface; paid partner/cloud nodes can intentionally transmit inputs and use credentials. These are visible application features, not evidence of covert exfiltration. A workflow does not sandbox the code behind its selected node classes.

The main model loader in `comfy/utils.py:225` uses `torch.load(..., weights_only=True)` for non-safetensors inputs and uses safetensors handling for those artifacts. This is a positive safeguard, not a guarantee that arbitrary model files, old dependency versions, or third-party nodes are safe.

Seven exact direct pins across the main, manager, and agent requirement files returned no OSV advisories. **Twenty-nine requirements remain unpinned or range-constrained**, and transitive/runtime versions were not resolved. There is no reproducible complete dependency environment to certify from these declarations alone. An actual installation needs its own platform-specific resolution and advisory review.

No built-in Codex skill was present. The new `comfyui-workflows` is original guidance grounded in the inspected source, not a repackaged executable application or a claim that GPU inference is available.

### Verification of existing protections

Focused tests of the original `folder_paths` module passed **21 assertions** covering legitimate paths, traversal and sibling-prefix rejection, annotated input/output/temp paths, executable content-type detection, and SVG image-versus-document context handling. No server, PyTorch, custom node, or inference ran. The symlink case was skipped because Windows denied link creation (WinError 1314); it is not counted as a passing check.

The skill's API guidance was checked against the pinned `server.py` and WebSocket example, including prompt acceptance versus completion, job-scoped history, and safe output retrieval. [Official route reference](https://docs.comfy.org/development/comfyui-server/comms_routes).

## Remotion findings

### WARNING — Known vulnerabilities across the full monorepo dependency lock

The bulk advisory scan checked **4,165 exact package-version pairs** and found **380 advisory-range/version matches affecting 88 distinct package names**. By highest reported severity per package name: **7 critical, 46 high, 25 moderate, 10 low**.

Examples include affected `happy-dom`, `form-data`, `tar`, `shell-quote`, `maplibre-gl`, and `tinypool` versions. Full package/version/title/URL details are in `remotion-monorepo-dependency-audit.json`.

These counts cover the entire monorepo lockfile, including development/test/example/optional dependencies. They do not show that all affected packages are reachable in a specific renderer deployment, or that the installed documentation skill depends on them. No application dependency graph was installed or approved.

### WARNING — Rendering executes code with reduced browser isolation

`packages/renderer/src/open-browser.ts:241` includes `--no-sandbox`, along with other rendering-oriented browser flags. Disabling web security is also available as an option. This makes trusted composition code, controlled media inputs, and isolation of untrusted rendering important. Studio also provides privileged local editing and package-management capabilities; it should not be treated as a public untrusted-user service.

The maintainer documents browser-visible environment values, the danger of exposing AWS credentials to the frontend, and the need to protect expensive rendering endpoints. Those concerns are reflected in the installed skill. [Security guidance](https://www.remotion.dev/docs/security).

### INFO — Skill and runtime are independently installable; license conditions remain

The selected source directory is `packages/codex-plugin/skills/remotion-best-practices`. It contains a router plus embedded references, samples, metadata, and local geodata helpers. No hidden lifecycle hook or covert collection mechanism was identified in this skill scope. Map/voiceover/cloud examples can intentionally contact providers if later invoked; their credentials, costs, and destinations need to match the current task's authorization.

Remotion's application license has commercial-use conditions. The upstream `LICENSE.md` is retained with the skill. Installing guidance does not determine licensing eligibility for a future application or video service. [Upstream license](https://github.com/remotion-dev/remotion/blob/2f06c4e3166a94607c5c56d68169f3754a0ecc72/LICENSE.md).

## Installed artifacts and adaptations

- `C:\Users\ruel3\.codex\skills\remotion-best-practices`: 127 upstream files were checked against the reviewed source before adaptation. Added the upstream license and provenance record, producing 129 installed files. Only the main `SKILL.md` was adapted: compatible metadata, useful discovery text, Windows/Codex behavior, installed-version API checking, explicit runtime/dependency scope, secret handling, and current-task authorization boundaries. Upstream examples/helpers remain unchanged.
- `C:\Users\ruel3\.codex\skills\comfyui-workflows`: 3 files, comprising the locally authored skill, API reference, and provenance record. No upstream application code is bundled.
- `reanimate`: not installed. Existing UI/UX and motion skills were preserved.

Both installed skills are discoverable normally and should be available on the next user turn. ComfyUI and Remotion application runtimes are still separate setup tasks; skill installation does not make generation/rendering available by itself.

## Verification results

| Check | Result |
| --- | --- |
| Reanimate serializer reproduction | Confirmed out-of-capture write and existing JSON sentinel overwrite; no later processing error |
| ComfyUI source parsing | 1,029 Python files parsed; no parse errors |
| ComfyUI focused security checks | 21 passed; symlink case skipped due Windows privilege restriction |
| Remotion sparse checkout integrity | 1,516 files matched pinned Git blobs |
| Remotion source syntax | 994 JS/TS files parsed; no syntax diagnostics |
| Selected Remotion skill integrity | All 127 original files verified before adaptation |
| Trusted Codex skill validator | Both installed skills passed |
| Local skill references | 104 Remotion links and 1 ComfyUI link resolved, with no missing or escaping targets |
| Final installed manifest | All 132 installed files matched recorded hashes |
| Installed Remotion Cesium helper | Produced a finite 297-point camera path from its bundled sample, with writes confined to audit output |
| Installed MapTiler helper | Usage path passed without installing its optional Turf dependency; full geodata processing was not exercised |
| Reanimate installation status | Absent from global skills |

The dedicated helper/reproduction runs used Node permissions to restrict filesystem access and disallow ungranted process/network capabilities. Those are verification controls, not permanent runtime sandboxes installed with the skills.

## Evidence and limitations

This folder retains pinned metadata/tree inventories, two source archives, a sparse Remotion checkout, source hashes, dependency audit JSON, the harmless Reanimate reproduction, ComfyUI check results, installed manifests, validation results, and reproduction/installation scripts. `dependency-audits.log`, `skill-verification.json`, `comfy-security-check/results.json`, and `reanimate-path-repro/result.json` are the compact result records.

No full application build, GPU inference, live ComfyUI job, full Remotion video render, Reanimate browser capture, third-party custom-node audit, native-binary decompilation, antivirus detonation, maintainer-account review, or historical-commit audit was performed. npm/OSV findings are time-specific and limited to their databases. A clean advisory lookup does not establish package safety or even package availability. The review does not approve future releases or automatic skill/runtime updates.

Qguard application code, tenant/security controls, cryptography, telemetry, dependencies, and deployment configuration were not changed. Verification targeted the reviewed source surfaces and delivered skills, so a Qguard application build was not applicable to these changes.
