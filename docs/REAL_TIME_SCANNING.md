# Real Time Scanning — QGuard Helix Scanning Workflow

Route: `/dashboard/scanner/real-time` (Discovery › PQC Scanner › Real Time Scanning)
Guideline: `Qguard_Wiki/Live_Scanning`

A live, interactive dependency canvas drawn **only** from what the existing scanner
engines observe. You start an authorized scan, and nodes then appear one by one
across six lanes: assets and endpoints, CAs and trust anchors, certificates,
algorithms, relying systems and vendors, and findings. Wires light up as each
relationship is verified.

```
executeWebScan (unchanged engines) ──observer taps──▶ TargetObserver (observation processor)
        │ findings / module events                         │ nodes · edges · evidence · findings
        ▼                                                  ▼
  normalizeWebResult → persistResult           append-only event log (seq 1..n)
  (assets, CBOM, exposures, certs…)            ├─ SSE publisher (replay after=N, heartbeat)
                                               ├─ flushed to pqc_scan_sessions.metadata.liveScan
                                               └─ browser: same reducer → React Flow canvas
```

## What was reused, extended, and new

| | Item | Notes |
|---|---|---|
| Reused | `executeWebScan` and all its engines (edge intelligence, TLS analyzer, certificate parser, key-exchange analyzer, cipher-suite analyzer, detection rules, risk scoring, PQC recommendations) | Called exactly as the PQC Scanner calls it |
| Reused | `normalizeTarget`, `createSession`, `updateSession`, `persistResult`, `normalizeWebResult`, `buildSummary` (exported from `api-server/scanner.ts`) | Live scans persist into the same shared tables, so Assets, CBOM, Exposure and Reports see them |
| Reused | `verifyPublicHost` / safe DNS (SSRF guard), `classify` (crypto knowledge base), `openAuthenticatedEventStream`, `@xyflow/react`, `html-to-image` | |
| Extended | `executeWebScan(…, observer?)` | Optional `onEdge` / `onTls` taps so the canvas draws certificates the moment they are parsed. Purely observational, so existing callers are unaffected |
| Extended | `walkCertificateChain` | Chain entries now carry `fingerprint256`, `serialNumber`, `validFrom`, and `signatureVerifiedByNext` (`checkIssued` + signature `verify`). Also fixes chain signature algorithms that always read `unknown` |
| New | `src/lib/live-scan/{types,policy,graph-reducer,observations}.ts` | Pure contract, central severity policy, idempotent reducer, observation processor |
| New | `src/api-server/live-scan.ts` → `/api/v1/scanner/live` | Background runner, event log, SSE, controls, export |
| New | `src/hooks/use-live-scan.ts`, `src/app/dashboard/real_time_scanning/*` | Page, canvas, inspector, styles |
| New | `tools/live-scan-check.ts`, `tools/live-scan-live-check.ts` | Tests |

## API (all require `Authorization: Bearer`; BASIC tier via the `/api/v1/scanner` gate)

| Method | Path | |
|---|---|---|
| POST | `/runs` | `{ name, targets[], authorized: true, concurrency 1–4, targetTimeoutSec 20–90, expiringWithinDays }` → 202 |
| GET | `/runs` | History: runs in memory plus stored live sessions |
| GET | `/runs/:id` | Snapshot: run metadata, full event log, summary, `lastSeq` (`:id` = run id or session id) |
| GET | `/runs/:id/stream?after=N` | SSE: replays events after N, then streams live; `Last-Event-ID` is honoured; `heartbeat` every 15 s; `end` is sent after the terminal record is persisted |
| POST | `/runs/:id/pause` · `/resume` · `/cancel` | Controls worker scheduling. In-flight targets finish first; this is honest and stated in the UI |
| POST | `/runs/:id/rescan` | `{ target }`, which must already be in the run's authorized scope |
| GET | `/runs/:id/findings`, `/runs/:id/entities/:entityId`, `/runs/:id/export?format=json\|csv` | |

## Accuracy rules enforced

- **Issuer links** are `validated` only when the signature verified under the issuer's key, `failed` when the check failed, and `inferred` (dashed) when the link rests on the issuer name alone.
- **`CHAIN_VALIDATED_TO` / `TRUSTED_BY_STORE`** exist only when trust-store path validation passed. A self-signed certificate never becomes a trusted root.
- **CDN/edge vendors** inferred from response headers are drawn as inferred edges. The "vendor migration dependency" finding never claims a vendor lacks PQC support.
- **Hybrid ML-KEM** is taken from the named-group *measurement*. If probing did not settle, the result is `PQC_READINESS_UNKNOWN` (status Unknown), never a negative claim.
- Public key, signature and key-establishment algorithms are separate nodes. AES/symmetric primitives are never quantum-migration exposure.
- Every finding has at least one evidence record, and each record carries a SHA-256 content hash. Measured passes (`SAFE`) are evidence, not findings.
- Failed or unreachable targets count as **Unknown / incomplete**, never as safe.
- Finding *groups* on the canvas are presentation only. Counts always read the records.
- There is no demo or simulated mode: with no run, the page shows an empty canvas and the way to start one.

## Operations

- **Persistence:** each live run is a `pqc_scan_sessions` row (`metadata.scannerMode = 'live-real-time-workflow'`) holding the event log (capped at 8,000 events, with `truncated` flagged), plus the normal per-target CBOM, asset and exposure rows. Deleting it from scan history removes everything.
- **No new migration or environment variables.** The feature reuses the existing Supabase tables and API server env.
- **Worker model:** in-process, owned by the API server. If the process restarts mid-scan, the stored run reopens as *Failed — Interrupted* with a rescan hint; it is not resumed automatically.
- **Limits:** 25 targets per run, 2 concurrent runs per user, 1–4 parallel targets, 20–90 s probe budget per target. Private, loopback and internal names are refused (deploy a collector agent for those).
- **Throughput here:** about 35–40 s per target at concurrency 2, dominated by engine probing plus ~600 ms Supabase round-trips.

## Not implemented (by design or deferred)

- Internal-network scanning from this page (that is the Agents Collector's job), passive CT discovery, and tenant-specific trust stores (validation uses the runtime's bundled roots, which the UI states).
- A dedicated `scan_events` table or ELK.js layout. The session row holds the log, and a deterministic lane layout with incremental placement is used instead.
- Saved per-user graph layouts (positions persist only for the session) and SVG export (JSON, PNG and CSV are available).

## Verification

```bash
npx tsx tools/live-scan-check.ts --network      # 43 pure + 19 real-engine fixture checks
npx tsx tools/live-scan-live-check.ts           # 34 live API/SSE/persistence/isolation checks
npx tsx tools/dashboard-contrast-check.ts       # light/dark integrity
```
