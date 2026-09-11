# Quantum Simulation Range — Rebuild Plan

Target: `/resources/quantum-simulation`

## Problem with the current page

| # | Defect | Evidence |
|---|--------|----------|
| 1 | **Every number is invented.** `DEC_STATS_MAP` hardcodes "14.7 TB decrypted / ~4 Hours factor time" per scenario with no model behind it. | `SimulationCanvas.tsx:33-115` |
| 2 | **No real cryptography anywhere.** The "Shor core" is a CSS animation; the terminal prints a fake period `r = 2650381045982183907817024831` for RSA-2048 that is not a period of anything. | `commandsData.ts:38` |
| 3 | **Teaches the wrong lesson about symmetric crypto.** Telemetry says Grover "reduces symmetric key strength"; `DEC_STATS_MAP` lists `AES/RSA` as *broken*. AES-256 is not broken by a quantum computer. | `page.tsx:225`, `SimulationCanvas.tsx:70` |
| 4 | **No NIST grounding.** FIPS 203/204 are name-dropped in log strings; no parameter sets, no transition dates, no citations. | `page.tsx:243-246` |
| 5 | **Theme is split.** `.qs-page` is a *light* gradient; the components inside are `bg-slate-950` / `bg-white/70`. | `index.css:3812`, `MetricsPanel.tsx:28` |
| 6 | **No 3D / WebGL.** 2D SVG bezier fibers + a 2D particle canvas. The repo already ships R3F, drei, postprocessing and a Performance Manager that this page never uses. | `SimulationCanvas.tsx:10-31` |
| 7 | State is 5 uncoordinated `setInterval` effects; dead components (`MetricsPanel`, `MissionPanel`) are never imported. | `page.tsx:167-250` |

## Principle

A simulation page is allowed to simulate — but every number must come from a
**named model or a real computation**, and be labelled as such. Three tiers,
shown to the user as badges:

- **MEASURED** — computed live in the browser right now (real ML-KEM keygen, real timings).
- **MODEL** — output of a published resource-estimation model, with citation.
- **PUBLISHED** — a standards fact (FIPS parameter set, IANA code point, transition date).

Nothing else is displayed as a number.

## Build

### Engine — `src/lib/quantum-sim/` (pure TS, no React)

| Module | Contents |
|---|---|
| `nist-standards.ts` | FIPS 203/204/205 parameter sets + real byte sizes, HQC, NIST IR 8547 milestones, CNSA 2.0 timeline, IANA TLS named groups. |
| `classical-crypto.ts` | RSA/ECC/DH/AES/SHA registry: classical bits, quantum attack, verdict, PQC replacement. |
| `resource-estimator.ts` | Surface-code CRQC estimator. Gidney–Ekerå 2021 (RSA), Gidney 2025 (RSA), Roetteler et al. 2017 (ECC). Anchored + calibrated. |
| `shor.ts` | **Real state-vector quantum simulator.** H, controlled modular exponentiation, inverse QFT, measurement, continued fractions, gcd → real factors. |
| `grover.ts` | Exact amplitude-amplification model + MAXDEPTH reality check. |
| `mosca.ts` | Mosca's inequality X + Y > Z. |
| `tls-evidence.ts` | Byte-accurate TLS 1.3 ClientHello/ServerHello builder with real IANA code points and real ML-KEM key shares. |
| `pqc-live.ts` | Real in-browser ML-KEM / ML-DSA / SLH-DSA ops + measured benchmark. |
| `attack-chain.ts` | The 6 stages described by *mechanism*, bound to the engines above. |

### UI — `src/app/resources/quantum-simulation/`

Single dark enterprise console. Sections:

1. Hero — WebGL quantum core, live countdown to the published 2030/2035 milestones.
2. **Simulation Range** — scenario × 6-stage chain, 3D attack lattice (R3F), evidence panel per stage.
3. **Shor Laboratory** — run the real simulator, watch the interference pattern, factor a real number.
4. **Resource Estimator** — what a CRQC would actually cost for your key sizes.
5. **Mosca Calculator** — am I already too late?
6. **Algorithm Explorer** — classical vs PQC, live benchmark.
7. **Standards & Timeline** — the real NIST/NSA dates with citations.

### Verification

- `tools/quantum-sim-check.ts` — offline check: FIPS sizes match `@noble/post-quantum` `lengths`, Shor factors correctly across a matrix of (N, a), resource model reproduces its published anchors, no undeclared magic numbers.
- `npm run lint` (tsc --noEmit).
- Browser: render, console clean, interactions work.
