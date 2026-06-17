# Q-Shrink Vault Engine — TODO / status

## Done
- [x] Core engine: chunker (FastCDC), codec (CompressionStream), entropy, manifest+Merkle, `QSHRN1` container, public API.
- [x] No-inflation guard + backward-compatible restore (legacy files pass through).
- [x] Wire into vault crypto path: upload, re-seal, decrypt, share.
- [x] Persist + sign `envelope_meta.qshrink` summary.
- [x] Dashboard panel + interactive analyzer (real data, reversibility proof, folder-dedup demo).
- [x] Round-trip test (30 checks) — reversibility, integrity, no-inflation, tamper rejection, magic-collision safety.
- [x] `tsc --noEmit` clean; `vite build` clean.
- [x] Design doc + architecture/lessons records.
- [x] Adversarial multi-agent review + fixes.
- [x] **Validation fix (L4):** magic-collision data-loss bug — `optimizeFile` now wraps raw inputs that begin with the `QSHRN1` magic so restore detection (magic-authoritative) can never mis-parse a real user file. Probes retired into the permanent suite.

## Verification strategy
- Type: `npm run lint`. Reversibility: `npx tsx tools/q-shrink/roundtrip-test.ts`. Build: `npx vite build`.

## Rollback plan
- Engine is additive. To disable: revert the `optimizeForVault`/`restoreFromVault` call sites in `page.tsx` and remove the panel import. Already-sealed Q-Shrink objects still restore (format + flag are self-describing).

## Future (not in scope now)
- [ ] Multi-file/folder upload UI with live cross-file dedup.
- [ ] WASM Zstandard/Brotli backend (codec ids 3/4 reserved).
- [ ] Optional bucketed padding for high-assurance length-hiding mode.
- [ ] `QSHRN2` 64-bit sections for multi-GiB streaming.
