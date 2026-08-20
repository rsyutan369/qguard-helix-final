# Qguard Helix Lightweight Agent — Installer & Deployment Control Plane

Spec: `Qguard_Wiki/Agent_Installer`. Surfaces: `/downloads` (Agent Center) and
`/dashboard/scanner?tab=agents` (Agent Collector Console).

---

## 1. What the agent actually is

A **single-file, dependency-free CommonJS bundle** (~108 KB) that runs on any
Node 18+ host. It is built from `tools/qguard-agent/agent.ts` plus its collector
modules and the shared mandatory PQC stack:

```bash
npm run agent:release
```

Output → `tools/qguard-agent/dist/`:

| File | Purpose |
| --- | --- |
| `qguard-agent.cjs` | the runtime the customer executes |
| `manifest.json` | version, byte size, SHA-256, SHA3-256, build time, source modules |
| `qguard-agent.cjs.sha256` | checksum file for out-of-band verification |

The builder **fails the build** if any `node_modules` input ends up in the graph —
the agent must stay Node-core-only, because it runs on customer infrastructure.

`prebuild` is chained to `agent:release`, so `npm run build` always publishes a
fresh, digest-matched runtime. The directory is gitignored.

---

## 2. Roles and platforms

Defined once in `src/lib/agent-installer/agent-release.ts` and consumed by the
API server, both frontends and the agent itself.

**Roles** — `collector`, `scanner` (read-only) · `patcher`, `operator` (may
change configuration, and only when the operator explicitly authorises it in the
wizard; the role alone is not sufficient).

**Platforms** — `linux` (systemd), `windows` (SYSTEM startup task), `docker`
(compose), `kubernetes` (Namespace + ServiceAccount + Secret + ConfigMap +
Deployment), `powershell` (portable, no install), `cloud-init`.

---

## 3. The installation chain

```
Agent Center  →  POST /api/v1/agent-installer/package
                     │  embeds tenant, agent id, enrollment token, scope,
                     │  and the SHA-256 of the published runtime
                     ▼
              generated installer (downloaded in-browser, never via a URL
              that carries the token)
                     │
                     ▼  operator runs it on the target host
              GET /api/v1/agent-installer/runtime
                     │  authenticated with x-qguard-agent-id / -token
                     ▼
              sha256 verified against the embedded digest
                     │  mismatch ⇒ refuses to install
                     ▼
              config written 0600 (root) / SYSTEM+Administrators only
                     ▼
              service registered → agent starts → heartbeat → evidence
```

Each step posts a phase to `POST /api/v1/agent-installer/installation-event`, so
the Verify step in the wizard reflects what actually happened on the host.

**No `curl | sh` bootstrap.** Download, verify, then execute — per spec §7.

---

## 4. API surface

Everything under `/api/v1/agent-installer` (Pro+, enforced in
`subscription-guard.ts`). Agent-credentialed sub-paths authenticate with the
agent's own token, not a session.

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/releases` | user | published runtime + platform/role catalog |
| GET | `/releases/:platform` | user | one platform + quick command |
| POST | `/package` | user | generate a tenant-bound installer artifact |
| GET | `/runtime` | **agent** | download the verified runtime bundle |
| POST | `/installation-event` | **agent** | report an install phase |
| GET | `/self` | **agent** | agent's own connection/version view |
| GET | `/summary` | user | all agents + deployment summary + release |
| POST | `/agents/:id/scan` | user | queue a scan |
| POST | `/agents/:id/upgrade` | user | queue an upgrade to the published build |
| POST | `/agents/:id/enable` \| `/disable` | user | queue enable/disable |
| GET | `/agents/:id/jobs` | user | queued commands + execution history |
| GET | `/agents/:id/health` | user | heartbeat-derived health + host telemetry |
| GET | `/agents/:id/activity` | user | ordered activity timeline |
| GET | `/agents/:id/findings` | user | evidence + alerts produced by this agent |
| GET | `/agents/:id/scans` | user | scan history reconstructed from heartbeats |
| GET | `/events/stream` | user | `agent.*` SSE with Last-Event-ID replay |

Agent identity, enrollment, token rotation/revocation, policy, heartbeat,
telemetry, evidence upload and remediation remain owned by
`/api/v1/agent-scanner` — this router composes them rather than duplicating them
(spec §37).

---

## 5. Persistence — no new tables

Deliberately reuses the existing tenant-scoped schema:

| Concern | Storage |
| --- | --- |
| agent identity, capabilities, policy | `scanner_agents` |
| policy detail | `scanner_agent_policies` |
| heartbeats, install phases, scan progress, activity | `agent_heartbeats` |
| evidence | `scanner_evidence` |
| alerts | `scanner_alerts` |
| **command queue + history** | `scanner_agents.metadata.commandQueue` / `.commandHistory` (bounded: 25 queued, 50 history) |
| releases | the on-disk manifest, re-verified against the artifact on read |
| audit | `audit_logs`, `security_events` |

The command queue hangs off the agent's own row, so tenant isolation is
structural — an agent can only ever read the queue attached to its own record.
**No migration is required to run this feature.**

---

## 6. Command channel

The agent's existing policy poll doubles as the command channel — one round
trip, no extra endpoint:

```
GET  /api/v1/agent-scanner/agent/policy      → { policy, commands[] }   (marks delivered)
POST /api/v1/agent-scanner/agent/commands/:id/ack  → running | completed | failed
POST /api/v1/agent-scanner/agent/scan-progress     → live stage + percent
```

Duplicate commands of the same type are de-duplicated rather than queued twice,
and a queued `scan` suppresses that cycle's scheduled scan so evidence is never
uploaded twice.

`upgrade` is acknowledged but **never self-replaces the binary** — the platform's
installer/service manager applies it after verifying the signed digest (spec §22:
no arbitrary binaries pushed to agents).

---

## 7. Dashboard materialisation

Agent evidence flows through the canonical `processEvidenceBatch()` into
`assets`, `crypto_inventory`, `pqc_scan_results`, `crypto_exposures` and
`scanner_alerts`.

Added in this work: **`persistCertificateEvidence()`** materialises observed
X.509 certificates into the `certificates` table (subject, SAN-bearing subject
string, issuer, serial, validity, key type/size, fingerprint, chain metadata), so
the Certificate and PKI dashboards see agent-discovered PKI. Rows are keyed on
`(user_id, serial_number)` so a rescan updates rather than duplicates.

Quantum posture uses the platform's single classifier
(`analyzeCryptoObservation` in `src/lib/crypto/suite-anatomy.ts`) — no rival
model. `is_quantum_safe` is written **only** when the algorithm is determined;
an unclassifiable algorithm stays `NULL` rather than being coerced to `true`
(which would fabricate safety) or `false` (which would fabricate a vulnerability).

---

## 8. Accuracy rules enforced in code

| Rule | Where |
| --- | --- |
| Never-checked-in agent reads **"Awaiting install"**, never Offline/healthy | `connectionStateFor()` |
| An agent with no evidence returns `scanned: false` → UI renders **Not Yet Assessed**, never "0 findings" | `/agents/:id/findings`, `NotAssessed` |
| No host telemetry ⇒ `null`, not zeros ("0% memory" ≠ "no data") | `/agents/:id/health` |
| SSE shows **Live** only while the EventSource is actually open | `streamState` in `use-agent-installer.ts` |
| A queued command reports honest delivery ("agent is not currently connected") | `enqueueCommand()` |
| Manifest digest is re-verified against the artifact before any installer embeds it | `loadRelease()` |

---

## 9. Security posture

- Enrollment token is stored **only** as a SHA-256 hash. It cannot be recovered,
  so `/package` requires the caller to still hold the live token — otherwise it
  returns `409` and asks the operator to rotate. It never silently mints a
  credential that would invalidate deployed agents.
- The token never appears in a URL, a log line or an audit record.
- Runtime download requires agent credentials; anonymous, wrong-token and
  revoked-agent requests all return `401`.
- Generated config files are `0600` root (POSIX) or SYSTEM + Administrators with
  inheritance stripped (Windows).
- Installer scripts embed only machine-generated identity values verbatim;
  operator-supplied scope (paths, targets, names) is sanitised of shell/YAML
  metacharacters, with backslashes preserved and re-escaped per format.

---

## 9b. Access control — verified, not assumed

`/downloads` and every Agent Center endpoint are gated on independent layers:

| Layer | Where | Behaviour |
| --- | --- | --- |
| Authentication | route guard + `requireUserAuth` | signed-out browser redirects to `/login?redirect=/downloads`; every API path returns 401 |
| Entitlement | `subscription-guard.ts` (server) + page gate (client) | Starter/Basic get 403 from the API and an honest upgrade panel in the UI; Pro+ passes |
| Ownership | `loadTenantAgent()` on every `/agents/:id/*` route | another tenant's agent id returns **404**, never data |
| Agent identity | `requireAgentAuth` | agent id + token must match the same row; an agent token cannot be used as a user session |

Tenant isolation is enforced by explicit `user_id` predicates on every query. The
API server may fall back to the service client when a request-scoped client cannot
be built, so it never relies on RLS alone.

**Asset binding is server-resolved.** `metadata.assetId` was previously spread in
verbatim from the request, so an agent could be bound to another tenant's asset
UUID. That never granted access to the other tenant's data — every read filters on
`user_id` — but it would plant a foreign asset reference in the caller's own
inventory, reports and migration scope. Enrollment now looks the asset up under the
caller's `user_id`, returns 404 if it is not theirs, and writes `assetName` /
`assetType` from the row rather than from the client payload.
`GET /api/v1/agent-installer/assets` backs the wizard's picker and returns only the
caller's own assets, with the agents already covering each one.

### Three ownership-reporting bugs fixed in agent-scanner

Found by the isolation suite. All three predate this feature; none of them leaked
data across tenants, but all three reported outcomes that had not happened:

1. `POST /agents/:id/revoke` returned **200 for any id**. The tenant filter meant no
   row changed, so there was no crossover — but an operator revoking a compromised
   collector was told it worked when it had not. For a security control that is a
   real failure. Now verifies ownership, 404s otherwise, and errors if the write
   changes nothing.
2. `DELETE /agents/:id` did the same, and wrote an `audit_logs` row claiming a
   deletion that never happened. Now 404s, and audits only real deletions.
3. `POST /agents/:id/token/rotate` **replaced** the whole `metadata` JSONB with
   `{rotatedAt, rotatedBy}`, wiping the agent's role, environment, asset binding and
   queued commands — rotating a token turned a Migration Operator back into an
   unassigned collector. Now merges.
## 10. Testing

```bash
npm run agent:test            # 103 assertions — full lifecycle against a live server
npm run agent:test:artifacts  #  13 assertions — bash -n / PowerShell parser / YAML load
npm run agent:test:isolation  #  67 assertions — auth, entitlement, cross-tenant attack
```

`agent:test` creates a real agent, generates all six installers, downloads the
runtime with agent credentials, **executes the published bundle**, and asserts on
evidence, certificates, CBOM rows, assets, PQC results, health telemetry,
activity, the command queue, SSE events, tenant isolation and revocation. Both
require the dev server on `localhost:3000`.

`agent:test:isolation` runs a real cross-tenant attack: an entitled **Pro** tenant
(so a 403 cannot mask a missing ownership check) attempts to read, command,
revoke, delete and generate installers for an **Elite** tenant's agent, bind to
their assets, and observe their event stream. It also asserts the victim DOES
receive their own events, so a passing result cannot be vacuous.
