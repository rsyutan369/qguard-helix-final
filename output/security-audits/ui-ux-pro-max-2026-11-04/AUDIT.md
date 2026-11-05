# UI/UX Pro Max security review and installation

Reviewed on 2026-11-04 (Asia/Manila).

## Decision

No evidence of malware, credential theft, covert telemetry, or backdoor behavior was found in the reviewed core UI/UX skill. The full repository is not free of security concerns: its optional gallery has vulnerable dependencies, its optional Claude stack requests broad permissions, and the CLI contains unsafe legacy shell handling and overly broad uninstall behavior.

Installed only the core skill, pinned to the reviewed commit. This decision does not approve running the repository's CLI, optional stack, gallery, or six sibling skills. Those components were excluded from installation. Source review cannot establish that a project is completely safe or that future updates will be safe.

## Source and review scope

- Repository: [nextlevelbuilder/ui-ux-pro-max-skill](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill).
- Exact revision: [dd9a1b4cf9f67ca2e326f646d93e101b2778db30](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill/tree/dd9a1b4cf9f67ca2e326f646d93e101b2778db30).
- Downloaded archive SHA-256: `a2a9aac80824235c72bde1f917058ddea44087a5ba803e65b679febd76c8c058`.
- Inventoried and hashed 704 regular files; parsed all 111 Python files with Python's AST parser without importing them during inspection.
- Reviewed core runtime imports, sensitive operations, CLI installation/update/uninstall paths, package lifecycle scripts, dependency locks, CI/release configuration, agent instructions, optional network-capable tools, and example/gallery network and injection patterns. Manual inspection concentrated on executable/security-sensitive paths; documentation and data received targeted scans rather than line-by-line semantic review.
- One archive symlink, `gallery/data/styles.csv`, points to the repository's own canonical styles data. It was recorded and skipped during audit extraction. No symlinks were required by the installed core skill.
- Compared core skill data/scripts against canonical `src/ui-ux-pro-max` copies: no differences.
- Queried npm's advisory service using `npm audit --ignore-scripts --package-lock-only --json`. No npm packages were installed and no upstream npm lifecycle scripts ran.

## Findings

### CRITICAL — Optional gallery depends on vulnerable Next.js

The gallery lockfile selects Next.js **14.2.35**. The advisory scan reports eight vulnerable package entries: **1 critical, 5 high, 2 moderate**. Counts represent affected package entries, not eight distinct advisories or eight proven exploit paths.

| Package | Locked version | Highest reported severity |
| --- | --- | --- |
| next | 14.2.35 | Critical |
| browserslist | 4.28.1 | High |
| nanoid | 3.3.11 | High |
| picomatch | 2.3.1 | High |
| postcss | 8.5.6 | High |
| source-map-js | 1.2.1 | High |
| baseline-browser-mapping | 2.9.19 | Moderate |
| postcss-selector-parser | 6.1.2 | Moderate |

One directly relevant advisory is CVE-2026-75604 / GHSA-p293-qw3h-jr36: the maintainer describes remote code execution affecting certain Windows-hosted Next.js servers in a range that includes 14.2.35. Exploitability depends on application features, routing, and deployment conditions; the gallery was not deployed or exploited during this audit. [Maintainer advisory](https://github.com/vercel/next.js/security/advisories/GHSA-p293-qw3h-jr36).

Evidence: [gallery dependency lock](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill/blob/dd9a1b4cf9f67ca2e326f646d93e101b2778db30/gallery/package-lock.json) and the saved `gallery-npm-audit.json`.

Action: exclude the gallery. Before any future deployment, update its framework and affected dependency graph to versions satisfying all then-current advisories and rerun tests/audit. The example patch version in one advisory does not establish that every other advisory is resolved.

### WARNING — Optional Claude stack grants broad tool and filesystem access

`stack/.claude/settings.json:3` enables all project MCP servers. Line 9 allows reading `//home/**`, and surrounding entries permit browser-related MCP tools and Playwright commands. `stack/.mcp.json` launches three npm-delivered MCP servers through `npx -y` with `@latest` versions. The setup script also installs packages and Chromium.

These are explicit setup choices, not evidence of covert malware. However, using that stack expands an agent's read/tool access and introduces moving third-party executable dependencies. This is unnecessary for the local design search skill.

Evidence: [permission settings](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill/blob/dd9a1b4cf9f67ca2e326f646d93e101b2778db30/stack/.claude/settings.json#L3), [MCP configuration](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill/blob/dd9a1b4cf9f67ca2e326f646d93e101b2778db30/stack/.mcp.json), and [setup script](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill/blob/dd9a1b4cf9f67ca2e326f646d93e101b2778db30/stack/scripts/setup.sh).

Action: exclude the stack, permission configuration, and MCP servers. A future installation should separately scope permissions and pin/review each external tool.

### WARNING — Legacy CLI helpers interpolate filesystem paths into shell commands

`cli/src/utils/extract.ts:17,19,76,78` builds PowerShell/unzip/xcopy/cp command strings using path interpolation. A specially crafted path can break quoting or be interpreted by a shell. The helper does not perform its own complete archive-entry validation either; extraction behavior depends on the external extraction tool.

This is a conditional code-level risk, not a demonstrated remote exploit. The current public CLI entry point does not expose a `--legacy` option, although the internal initializer retains a legacy branch. Default template installation uses a different path. No malicious extraction or shell payload was executed.

Evidence: [extraction helpers](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill/blob/dd9a1b4cf9f67ca2e326f646d93e101b2778db30/cli/src/utils/extract.ts#L12), [initializer](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill/blob/dd9a1b4cf9f67ca2e326f646d93e101b2778db30/cli/src/commands/init.ts), and [CLI entry point](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill/blob/dd9a1b4cf9f67ca2e326f646d93e101b2778db30/cli/src/index.ts).

Action: bypass the upstream CLI. If maintaining it, remove shell construction, use argument-vector process APIs or native filesystem/archive libraries, validate entry containment and links, and remove unused legacy paths.

### WARNING — CLI expands installation scope and uninstalls by folder name

Normal CLI installation copies six sibling skills in addition to the core orchestrator. Some extras can read `.env` files, use image-provider API keys, call external image services, or install UI packages when explicitly invoked. Those capabilities are documented functionality, but substantially exceed the core offline search capability.

The uninstaller constructs a list of core and sibling skill names and recursively removes matching directories without verifying installation ownership. An existing independent skill with a matching name can be skipped during installation and still be removed during uninstall. This was identified through control-flow review, not by deleting user data.

Evidence: [sibling copying](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill/blob/dd9a1b4cf9f67ca2e326f646d93e101b2778db30/cli/src/utils/template.ts#L303), [uninstaller](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill/blob/dd9a1b4cf9f67ca2e326f646d93e101b2778db30/cli/src/commands/uninstall.ts#L29), and [optional image provider tool](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill/blob/dd9a1b4cf9f67ca2e326f646d93e101b2778db30/.claude/skills/design/scripts/logo/generate.py#L51).

Action: install only the requested core skill using Codex's trusted installer. An upstream fix should record file ownership and avoid removing pre-existing skills owned by other installations.

### INFO — Core persistence assumes a trusted destination directory

Project/page names are slugged into safe path segments, writes are atomic, and existing files are preserved unless force is requested. However, the implementation does not explicitly reject symlink/junction ancestors under a selected output directory. It is a local CLI, not a filesystem security boundary. Use a trusted project destination and review existing junctions/symlinks before persistence in an untrusted checkout. No junction escape was exercised.

Evidence: [core persistence implementation](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill/blob/dd9a1b4cf9f67ca2e326f646d93e101b2778db30/src/ui-ux-pro-max/scripts/design_system.py#L986).

### INFO — Release and example dependencies remain supply-chain inputs

CI uses version-tagged actions and unpinned release tooling; example HTML loads external CDN scripts/fonts. The CLI updater can install a newer global npm package when explicitly invoked. These observations are supply-chain exposure, not proof of compromise. None of these paths were installed or activated. Reviewing this commit does not approve future npm releases, repository changes, or third-party CDN responses.

## Core skill behavior and verification

The installed search runtime imports Python standard-library modules and its reviewed sibling modules. It reads bundled CSV/JSON design guidance. No network/client library, shell runner, dynamic code evaluation, credential-file loader, or unrelated persistence mechanism was identified in the core runtime. The only environment read identified in core runtime logic is terminal color capability (`COLORTERM`). Optional `--persist` writes design-system Markdown to the caller-selected project destination.

The instructions tell the agent that search results are recommendations, forbid using private project data in queries/output, and require accurate handling of empty results. Instruction/data scans did not reveal a malicious redirection payload in the installed scope. This is evidence for the reviewed snapshot, not a proof against all possible prompt injection or misuse.

| Verification | Result |
| --- | --- |
| Upstream core Python suite | 177 tests passed |
| Data validator | Passed: 12 domain files, 22 stack files, reasoning CSV |
| CLI lockfile advisory scan | 0 known vulnerable package entries reported |
| Gallery lockfile advisory scan | 8 affected package entries; excluded |
| Installed file comparison before adaptation | All 74 upstream files matched reviewed hashes |
| Installed search tests | React, HTML/Tailwind, Android Jetpack Compose, Flutter, React Native, SwiftUI, UX passed |
| Installed design-system generation | Passed |
| Existing master preservation | Passed; second persistence left master unchanged |
| Page-name traversal handling | Passed; `../../safe-page` became a safe page filename |
| Network/process-denied installed verification | Passed; no attempted socket or subprocess operations observed |
| Actual installed PowerShell command | Passed; Android search returned a matching result |
| Final installed manifest | All 76 installed files matched hashes |

The network/process denial guard applied to the dedicated installed smoke verification process. The 177 upstream tests ran separately after source review; some tests launch Python subprocesses for CLI/offline fixture tests. The guard is a test control, not a permanently installed runtime sandbox.

## Installation delivered

Installed global skill: `C:\Users\ruel3\.codex\skills\ui-ux-pro-max`.

Source path: `.claude/skills/ui-ux-pro-max` at the exact commit above. Codex's existing skill-installer helper performed a commit-pinned direct download; the upstream npm CLI was not used.

All Python scripts and design data remain byte-for-byte upstream versions. Local changes are confined to `SKILL.md`: replace Claude plugin-root placeholders with installed absolute paths, use PowerShell syntax and the existing Codex bundled Python runtime, and record provenance plus the precedence of user/repository security and accuracy requirements. The upstream MIT license and `AUDIT-ORIGIN.json` were added. No operating-system Python installation was required.

Coverage includes web design, design systems, accessibility, Android Jetpack Compose, iOS SwiftUI, React Native, Flutter, and other supported UI stacks. Skill discovery should make it available on the next user turn.

Qguard application source, authentication, tenant controls, telemetry, cryptography, dependencies, and deployment configuration were not changed by this task. Application build/TypeScript tests were therefore not applicable; verification targeted the installed skill and audit artifacts.

## Evidence and limitations

The audit folder contains `source.zip`, `commit.txt`, `archive-symlinks.json`, `static-inventory.json`, both npm audit JSON files, `upstream-tests.log`, `data-validation.log`, `installed-manifest.json`, and `verification-output/results.json`. The audit/verification scripts are included to make the review reproducible; the finalization script intentionally refuses a second installation adaptation because its precondition is a pristine upstream file set.

This review did not inspect every historical commit, establish maintainer-account security, decompile third-party packages/fonts, perform antivirus detonation, validate npm tarball/source equivalence, deploy the optional gallery, or prove absence of unknown vulnerabilities. The optional stack's unpinned dependencies were not installed or independently resolved/audited. Future updates need a fresh review; no automatic updater was installed.
