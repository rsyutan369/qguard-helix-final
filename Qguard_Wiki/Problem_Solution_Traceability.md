# Problem → Solution Traceability

How each problem in `Problems_To_Solve_1..6` is solved by QGuard Helix modules,
which backend serves it, and where the data comes from. Verified 2026-07-10
(platform-wide wiring audit + build). Companion execution log: `tasks/todo.md`.

Legend: every backend listed queries **tenant-scoped Supabase tables** (RLS,
`user_id`-filtered) — no fabricated metrics; empty tables produce empty states
with setup guidance, not synthetic numbers.

---

## Problem 1 — "The challenge is understanding everything connected to it"
Trust estate is larger than the crypto estate; hidden trust hierarchies stall
migrations; Visibility → Ownership → Dependencies → Risk.

| Capability | Module (page) | Backend | Key data sources |
|---|---|---|---|
| Trust-state discovery workflow (Visibility→Ownership→Dependencies→Risk→Migration Gate scores, findings, gate decision) | `/dashboard/trust-state-discovery` | `api-server/trust-state-discovery.ts` | assets, asset_relationships, certificates, crypto_inventory, runtime_crypto_events, scanner_evidence/alerts, vendor_assessments, migration_jobs, trust_state_findings (16 tables) |
| Hidden-trust detection (runtime certificate fingerprints not in inventory → blocker; self-signed/unknown-issuer paths; undocumented middleware trust) | same | same | runtime_crypto_events × certificates fingerprint diff |
| Certificate-replacement blast radius | `/dashboard/ecosystem-dependency-map`, trust graph on trust-state-discovery | `api-server/ecosystem-supply-chain.ts` | asset_relationships + certificates + vendors |

## Problem 2 — Trust inventory vs crypto inventory; the Migration Gate
| Capability | Module | Backend |
|---|---|---|
| The 5-checkpoint gate itself (discover → own → map → risk → validate rollback) with ready/review/blocked state and per-checkpoint scores | `/dashboard/trust-state-discovery` workflow strip + gate card | `trust-state-discovery.ts` (`workflow`, `gate`) |
| Gate ↔ migration enforcement (active migration jobs overlapping blocked trust paths are flagged `migrationConflicts` and pause-recommended) | same + `/dashboard/live_migration_ops` | `trust-state-discovery.ts` + `migration.ts` |
| Rollback/recovery validation before proceeding | Migration Sandbox (simulate + rollback semantics), Migration Planner 9-stage workflow | `sandbox.ts`, `migration-planner.ts` |
| Trust chain reconstruction | `/dashboard/trust-chain-analyzer` | `ecosystem-supply-chain.ts` (mode `trust-chain`) |
| Vendor/supplier readiness as a dependency class | `/dashboard/vendor-pqc-readiness` | `ecosystem-supply-chain.ts` (vendor_assessments) |

## Problem 3 — Trust as a runtime cost (PKI performance observability)
| Capability | Module | Backend |
|---|---|---|
| **Trust Path Cost panel (ADDED 2026-07-10)**: handshake round-trip profile (TLS version → 1-RTT/2-RTT/legacy), key-exchange compute class (ECDHE / DHE / RSA-kex / hybrid ML-KEM), costliest observed trust paths (relative 0-100 index incl. failure/retry cost), hybrid ML-KEM-768 bytes-on-wire outlook (FIPS 203 sizes × observed TLS 1.3 handshake volume) | `/dashboard/tls-telemetry` → "Trust Path Cost" | `tls-telemetry.ts` (`trustPathCost`) — deterministic protocol arithmetic over observed connections; **no fabricated latency** |
| Handshake success/failure rates, version & cipher distribution, per-server/client volumes | `/dashboard/tls-telemetry`, `/dashboard/protocol-analytics` | `tls-telemetry.ts`, `crypto-operations-dashboard.ts` |
| PKI hierarchy & certificate lifecycle visibility | `/dashboard/pki-visibility`, `/dashboard/certificate-telemetry` | `pki-visibility.ts`, `observability-dashboard.ts` |

## Problem 4 — Deep discovery beyond network scans; Shor vs Grover
| Capability | Module | Backend |
|---|---|---|
| Static/SAST-style detection (source patterns, hardcoded suites), runtime events, connector/cloud discovery — beyond point-in-time network scans | `/dashboard/scanner_dashboard`, `/dashboard/shadow-crypto`, `/dashboard/crypto-exposure`, `/dashboard/runtime-crypto-intel` | `scanner.ts`, `agent-scanner.ts` + web-scanner/scanner_2 libs (detection-rules, cipher-suite-analyzer, crypto-patterns, oid-database) |
| Shadow IT / ephemeral workload crypto (shadow_crypto flags on runtime events) | `/dashboard/shadow-crypto` | scanner intelligence + runtime_crypto_events |
| **Quantum Threat Model decomposition (ADDED 2026-07-10)**: Shor-exposed public-key findings (RSA/ECC/DH — sets migration priority) vs Grover symmetric-margin findings (AES-128 → key-size planning) vs legacy hash vs PQC-protected, each with counts, affected assets, 7-day trend, and roadmap guidance | `/dashboard/quantum-risk-scoring` → "Quantum Threat Model" | `quantum-risk-scoring.ts` (`threatModel`, `threatClassFor`) |

## Problem 5 — Do you know where your encryption keys live?
| Capability | Module | Backend |
|---|---|---|
| Centralized key inventory, lifecycle, governance, rotation, PQC readiness, risk analysis | `/dashboard/qkms/*` (7 mode-driven pages) | `qkms-dashboard.ts` — qkms_keys, qkms_rotation_jobs, qkms_policies, qkms_audit_events, generated_keys, certificates |
| Hard-coded key / exposed-secret detection | scanner findings → crypto_exposures | scanner pipeline |
| Expired/unmanaged certificate detection | trust-state-discovery findings, PKI visibility, QKMS readiness | respective routers |
| Hybrid key infrastructure readiness | QKMS PQC Readiness + Hybrid Crypto Compatibility Lab | `qkms-dashboard.ts`, `ecosystem-supply-chain.ts` (mode `hybrid-lab`) |

## Problem 6 — The five roadmap questions / crypto agility
| Roadmap question | Module |
|---|---|
| 1. Where is cryptography used? | PQC Scanner, Assets & CBOM, CBOM Explorer, Shadow Crypto, Crypto Exposure |
| 2. Which assets are most critical? | Quantum Risk Scoring (asset scores, distribution), QR Assessment Engine |
| 3. What depends on what? | Ecosystem Dependency Map, Trust Chain Analyzer, trust-state graph |
| 4. Can infrastructure support new standards? | Hybrid Crypto Compatibility Lab, Vendor PQC Readiness, TLS Telemetry hybrid outlook |
| 5. Execute and reverse safely? | Migration Planner (9-stage), Migration Sandbox (simulate/rollback), Live Migration Ops, Migration Timeline/Phases |
| Crypto agility as ongoing capability | `/dashboard/crypto-agility` (`/api/v1/dashboard/crypto-agility`), Crypto Agility Engine, drift detection |

---

## Runtime verification (2026-07-10, live dev server + real tenant data)
`tools/threat-model-cost-check.ts` (20 checks, all passing) verified both new
capabilities end-to-end against the running API with an authenticated tenant:
- **Empty tenant**: both snapshots return honest zero-state blocks with setup
  guidance — no fabricated numbers.
- **Populated tenant** (real web-scan of the repo's smoke-test target
  `tls-v1-2.badssl.com` persisted 42 findings + certificate): threat model
  classified 34 Shor-exposed findings (urgency `migrate`, "Shor sets the
  priority" guidance), 1 Grover-class (`plan`), 52 PQC-protected; trust-path
  cost profiled all 44 observed connections (RTT + key-exchange classes summing
  exactly to totalConnections), ranked the legacy badssl path at cost index 100,
  and the hybrid ML-KEM-768 outlook arithmetic verified.
- **Tier RBAC confirmed live**: the Starter-tier test account receives 403 on
  both dashboard APIs (subscription gateway working); Elite tier gets 200.
  Both SPA routes serve HTTP 200.

## Platform integrity notes (this audit)
- All ~70 dashboard pages are wired to real backends via three patterns: direct
  fetch pages, mode-driven shared dashboards (`_components/*Dashboard.tsx`), and
  hooks (`src/hooks/use-*.ts`). No orphan APIs, no fabricated fallbacks found.
- Removed dead empty directory `src/app/dashboard/runtime-discovery` (2026-07-10).
- Gaps closed 2026-07-10: Shor/Grover threat model (P4) and Trust Path Cost (P3),
  both derived exclusively from real tenant telemetry.
- Known boundary: trust-path cost uses protocol-fact derivation because agents do
  not yet capture handshake timings; if a future agent version reports
  `handshake_ms`, extend `trustPathCost` with measured percentiles.
