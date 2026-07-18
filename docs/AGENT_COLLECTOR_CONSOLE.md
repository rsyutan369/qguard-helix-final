# Agent Collector Console — Enterprise UX Redesign

Implements `Qguard_Wiki/Agents_Refactor_Improvements`: the Agent Collector
Scanner (`/dashboard/scanner?tab=agents`) redesigned into a modern enterprise
SaaS experience (Falcon / Defender XDR / Wiz / Prisma-class) with progressive
disclosure — **a security engineer can create, install, verify and scan a
collector in under five minutes without docs** — while preserving **every**
backend capability.

## What changed

- **Replaced** ~63 KB of inline JSX (the old 8-step workflow that exposed API
  endpoints, TLS/JSON/RBAC/certs/scopes on the create form) in
  `ScannerDashboard.tsx` with a single `<AgentCollectorConsole />` and removed
  the now-dead install-command/workflow-step constants.
- **UX only** — zero backend changes. Every `/api/v1/agent-scanner/*` route,
  RBAC gate, SSE stream, audit write, connector integration, cryptographic
  enforcement, snapshot/rollback and approval workflow is untouched.

## Architecture

| Piece | Path |
| --- | --- |
| Data layer | `src/hooks/use-agent-collector.ts` — wraps the existing REST + `agent-scanner-sync` SSE; exposes create/rotate/revoke/delete/updatePolicy/createConnector/createOperatorAction/setOperatorStatus/ack/resolve + evidence-derived summary + health/status helpers |
| Console | `src/components/agent-collector/AgentCollectorConsole.tsx` |

## Information architecture (the four questions + progressive disclosure)

- **Sub-nav:** Overview · Collectors · Scans · Operations · Settings · Help.
- **Overview** — 6 dashboard summary cards (Registered / Online / Offline /
  Assets Discovered / Quantum Risks / Pending Remediation) + Last Heartbeat +
  Recent Scan Evidence, then the **4-step Quick Start wizard**:
  1. **Create Collector** — simplified form: Name, Environment (Windows/Linux/
     Docker/Kubernetes/VM/Cloud Connector), Description (optional), Tags,
     Allowed Targets. Nothing else. Completed/Running/Waiting step badges.
  2. **Install Collector** — one-time enrollment token (copy + rotate + "shown
     once" warning, hashing hidden) and install **tabs** (Linux, Windows,
     Docker, Kubernetes, Helm, PowerShell, Cloud-Init) each with copy +
     installer download.
  3. **Verify Connection** — status, hostname, version, environment, heartbeat,
     connection quality, last seen, health score; "Waiting for first
     heartbeat…" with auto-refresh via SSE.
  4. **Run First Scan** — Start Scan + jump to discovered assets.
- **Collectors** — simplified table (Collector · Environment · Status ·
  Version · Last Seen · Assets · Health · Actions). Internal IDs / tenant /
  telemetry / connector UUIDs hidden — they live in the details drawer.
- **Collector Details Drawer** — Overview, Agent Health (score + heartbeat/
  version/interval), Start Scan (scan-type chips), Quantum Findings, Recent
  Telemetry; sticky action bar: Rotate Token / Revoke / Delete. ESC-close,
  focus-managed, keyboard-navigable.
- **Scans** — findings summary (Assets Scanned / Evidence / Quantum
  Vulnerabilities / Pending Remediation), the 9 scan types, recent findings
  with ack/resolve.
- **Operations Center** — remediation stats, Cloud Connections, remediation
  actions, and a collapsible **Advanced Settings** panel (RBAC, Snapshots,
  Rollback, Connector Credentials, Cloud SDK, JSON, Dry Run, Approval Gates,
  Evidence Upload, Operator Permissions, Cloud APIs) — hidden by default.
- **Settings → Security Standards** — the mandatory PQC stack (ML-KEM / ML-DSA
  / SLH-DSA / AES-256-GCM / HKDF-SHA3 / hybrid TLS), moved off the collector
  page per the guide.
- **Help → How Collectors Work** — deployment architecture diagram + FAQ
  (where they run, what they can/can't scan, cloud connections, security
  model / least privilege).

## Enterprise UX + a11y

Glassmorphism panels, soft shadows, rounded cards, generous whitespace, status
dots/badges, skeleton loaders, sticky drawer action bar, responsive grids,
dark/light via the app theme. WCAG-minded: `aria-current` nav, `role="dialog"`
+ `aria-modal` drawer with focus management and ESC, visible
`focus-visible` outlines, semantic `<details>`/`<summary>` FAQ, status conveyed
by text + icon (not color alone).

## Language changes (per guide)

Register→**Create Collector**, Run Authorized Scan→**Start Scan**, Connector
Access→**Cloud Connections**, Operator Patch Workflow→**Automated
Remediation** (Operations Center), Mandatory Quantum Stack→**Security
Standards**, Local Collector Clarification→**How Collectors Work**.

## Settings tab — `AgentSettingsConsole` (aligned redesign)

`?tab=settings` was redesigned to complement the collector console.
`src/components/agent-collector/AgentSettingsConsole.tsx` replaces the old
gold-themed inline settings block and shares the **same `useAgentCollector`
hook** — identical REST + `agent-scanner-sync` SSE, so collector state, live
sync and lifecycle actions stay consistent across both tabs.

- **Collector Policy editor**: Policy Enabled, Heartbeat Interval (30–60s),
  Alert Threshold, a 16-option **Scan Scope** toggle grid (TLS/certs/PKI/SSH/
  VPN/libraries/configs/packages/k8s/cloud/KMS/HSM/DB/web/API/runtime),
  Authorized Targets + Paths; **Apply to selected or all active collectors**
  via `PUT /agents/{id}/policy`.
- **Selected Collector** panel (details + rotate/revoke/delete + one-time
  token) and **Live Sync & Alerts** (SSE status, last sync, connectors, open
  alerts, acknowledge/sync).
- **Security Standards** (mandatory PQC stack) and collapsible **Tenant API
  References** (advanced).
- Gated: renders for Pro+/owner (matching the `agent-scanner` tier); Basic
  users see a clean upgrade notice instead of 403 errors.
- **Redundant-SSE fix**: ScannerDashboard no longer loads collector state or
  opens its own `agent-scanner/stream` connection — both consoles own that via
  the hook, so there is exactly one collector SSE connection per tab.

## Verification (2026-07-17)

- `tsc --noEmit` clean; `vite build` clean.
- Authenticated headless-Chrome (owner) render confirmed: Overview (cards +
  4-step wizard + simplified form), sub-nav switching, Help (architecture
  diagram + FAQ accordion).
- Backend smoke test — all 10 `/api/v1/agent-scanner/*` endpoints 200,
  including the full enroll → rotate → revoke → delete lifecycle with
  one-time token. No API changes.
