# Qguard Helix Lightweight Agent Installer — Architecture & Execution Plan

Spec: `Qguard_Wiki/Agent_Installer`. Reuse-first (spec §37): no parallel systems.

## Reused (unchanged contracts)
- `scanner_agents` / `scanner_agent_policies` / `agent_heartbeats` / `scanner_evidence` /
  `scanner_alerts` — existing tenant-scoped tables (no migration required).
- `/api/v1/agent-scanner/*` — enroll, list, rotate, revoke, delete, policy, heartbeat,
  telemetry, evidence, runtime-events, remediation jobs, `agent-scanner-sync` SSE.
- `processEvidenceBatch()` — canonical evidence -> assets / crypto_inventory /
  pqc_scan_results / crypto_exposures / scanner_alerts materialiser.
- `tools/qguard-agent/agent.ts` — the real collector (TLS, SSH, PKI, packages, configs,
  native runtime) and remediation/migration executor.
- `MANDATORY_PQC_STACK` — mandatory cryptographic target.

## New
1. `src/lib/agent-installer/agent-release.ts` — isomorphic release + platform matrix,
   agent roles/capability model, install phases, canonical event names.
2. `src/lib/agent-installer/installer-templates.ts` — pure generators for real,
   runnable installers (bash / PowerShell / docker-compose / k8s / cloud-init /
   portable PowerShell). Each embeds tenant+agent identity, API URL, policy scope and
   the expected SHA-256 of the runtime bundle.
3. `tools/build-agent-release.mjs` — esbuild single-file CJS bundle of the agent +
   `manifest.json` (version, sha256, bytes, releasedAt). npm script `agent:release`.
4. `src/api-server/agent-installer.ts` — `/api/v1/agent-installer` (Pro+):
   releases, package generation, runtime download (agent-authed, checksum headers),
   installation phase events, jobs/commands, scan/upgrade/disable/enable, health,
   telemetry, findings, scans, activity, `agent.*` SSE event stream.
5. Command queue on `scanner_agents.metadata.commandQueue` (bounded) — delivered through
   the agent's existing `/agent/policy` poll; acked via `/agent/command-ack`.
   Zero-migration, tenant-scoped by row ownership.
6. Certificate materialisation: TLS certificate evidence -> `certificates` table so the
   Certificate/PKI dashboards see agent-discovered PKI.
7. Agent runtime: install-phase reporting, command execution, host health telemetry
   (cpu/mem/disk/uptime/queue), version from the shared release module.
8. `/downloads` — Agent Center page + `useAgentInstaller` hook.
9. Scanner `?tab=agents` Installer button wired to the real generator.

## Data integrity rules enforced
- Never render Unknown as Quantum Safe; never render Pending as Completed.
- Unscanned asset => "Not Yet Assessed", never "0 vulnerabilities".
- Connection state derives from real heartbeat recency; SSE "Connected" only when the
  EventSource is actually open.

---

# Execution record — COMPLETE

All items implemented and verified. Docs: `docs/AGENT_INSTALLER.md`.

## Delivered
- `src/lib/agent-installer/agent-release.ts` — roles, platforms, install phases, event names, command model, accuracy vocabulary.
- `src/lib/agent-installer/installer-templates.ts` — six real artifact generators.
- `tools/build-agent-release.mjs` + `npm run agent:release` (chained from `prebuild`) — 107.6 KB zero-dependency bundle + manifest + checksum.
- `src/api-server/agent-installer.ts` — 16 endpoints incl. `agent.*` SSE with Last-Event-ID replay.
- `src/api-server/agent-event-bus.ts` — shared ring buffer (no import cycle between the two routers).
- `agent-scanner.ts` — command delivery on the policy poll, `/agent/commands/:id/ack`, `/agent/scan-progress`, connection/heartbeat events, `persistCertificateEvidence()`.
- `tools/qguard-agent/agent.ts` — config-file support, host health telemetry, 9-stage scan progress, command execution, `status`/`version` modes, resilient watch loop.
- `src/hooks/use-agent-installer.ts` — REST + supervised SSE (exponential backoff, dedup, honest `streamState`).
- `/downloads` Agent Center — summary cards, published-runtime panel, platform matrix, 7-step wizard, agents table, detail drawer.
- Scanner `?tab=agents` Installer button now generates and downloads the real artifact (fabricated `get.qguardhelix.com` commands removed).
- `subscription-guard.ts` — `/api/v1/agent-installer` gated Pro+.

## Verification
- `npm run agent:test` — **103/103** (real agent binary executed; evidence → certificates/CBOM/assets/PQC results; commands; SSE; isolation; revocation).
- `npm run agent:test:artifacts` — **13/13** (bash -n, PowerShell parser, YAML load, backslash-path survival).
- `npx tsc --noEmit` — no errors in any new/modified file.
- `npm run build` — succeeds.
- Browser walkthrough as owner: wizard created an agent, issued a one-time token, generated a Linux installer; browser-computed digest matched the server digest.

## Deliberate design decisions
- **No migration required.** Command queue lives in `scanner_agents.metadata` (bounded); install phases/progress reuse `agent_heartbeats`. Reuse over parallel systems (spec §37).
- **`/package` refuses to mint a token silently.** The plaintext is unrecoverable, so it returns 409 and requires an explicit rotation rather than invalidating deployed agents behind the operator's back.
- **Windows uses a SYSTEM startup task, not a true SCM service** — a plain Node process cannot answer the Service Control Manager and no wrapper binary is shipped. Labelled accurately everywhere in the UI.
- **`upgrade` never self-replaces the binary**; it is acknowledged and applied by re-running the verified installer (spec §22).

## Not covered
- Live execution on real Linux/macOS/Docker/Kubernetes hosts. Artifacts are syntax-validated and the runtime was executed on Windows; the systemd/winget/k8s paths are unexercised on their target OSes.
- Signed releases use SHA-256/SHA3-256 digests, not code-signing certificates (no signing identity is configured in this repo).

---

# Security follow-up (access control & tenant isolation)

Driven by the question "is /downloads gated, and can tenants cross over?".
Answered with `tools/agent-installer-tests/verify-tenant-isolation.mjs`
(`npm run agent:test:isolation`) — **67/67**, using an entitled **Pro** attacker
against an **Elite** victim so a 403 cannot mask a missing ownership check.

## Verified
- Anonymous: 401 on every Agent Center + agent-scanner path; forged bearer 401.
- Starter and Basic: 403 from the API; the page renders an honest upgrade panel.
- Signed-out browser: redirected to `/login?redirect=/downloads`.
- Cross-tenant read (health/activity/findings/scans/jobs): 404.
- Cross-tenant command (scan/upgrade/enable/disable): 404.
- Cross-tenant installer generation, **even while holding the victim's agent token**: 404.
- Agent credentials: victim id + attacker token 401; agent token unusable as a user session.
- Listings, evidence, certificates, assets and the SSE stream: no crossover
  (and the victim DOES receive their own events, so the result is not vacuous).

## Fixed (all pre-existing in agent-scanner; none leaked data, all lied about outcomes)
1. `POST /agents/:id/revoke` returned 200 for any id — a false success on a
   security control. Now 404s on a non-owned/absent id and errors if no row changed.
2. `DELETE /agents/:id` did the same and wrote an audit row for a deletion that
   never happened. Now 404s; audits only real deletions.
3. `POST /agents/:id/token/rotate` REPLACED `metadata`, wiping the agent's role,
   environment, asset binding and queued commands. Now merges.

## Added (assets & profile in-sync)
- `metadata.assetId` is now server-resolved at enrollment: looked up under the
  caller's `user_id`, 404 if not theirs, and `assetName`/`assetType` written from
  the row rather than the client payload (previously spread in verbatim).
- `GET /api/v1/agent-installer/assets` — tenant-scoped picker source with per-asset
  agent coverage and the caller's own tenant id.
- Wizard asset field is now a picker over the tenant's real assets, not free text.
- `/downloads` gained a "Your asset coverage" panel: assets, covered-by-an-agent,
  agents-not-bound-to-an-asset, and a per-asset agent list.
- `useAgentCollector` summary split "Awaiting install" from "Offline" so the
  scanner tab and the Agent Center no longer disagree about the same rows.

## Note
Isolation rests on explicit `.eq('user_id', …)` predicates, not on RLS: the API
server falls back to the service client when a request-scoped client cannot be
built. Any new agent query must carry that predicate.
