# Q-Shrink Vault Engine — Architecture (execution record)

## Components
- **Engine** `src/lib/vault/q-shrink/` — chunk → dedup → compress → manifest+Merkle → `QSHRN1` container. Pure, dependency-free (native `CompressionStream`).
- **Integration** `src/app/dashboard/vault/page.tsx` — `optimizeForVault()` before `encryptFileLocal`; `restoreFromVault()` after `decryptFileLocal` (upload, re-seal, decrypt, share).
- **UI** `src/components/quantum-vault/QShrinkEnginePanel.tsx` — real aggregate posture from `envelope_meta.qshrink` + in-browser analyzer with reversibility proof.
- **Test** `tools/q-shrink/roundtrip-test.ts` — reversibility/integrity/no-inflation (27 checks).

## Data flow
Plaintext → optimize (client) → `QSHRN1` package → `encryptFileLocal` (X25519+ML-KEM-1024+AES-256-GCM) → Supabase storage. Restore is the exact inverse, guarded by per-file SHA3-256 + chunk Merkle root.

## Trust boundaries
All optimization + encryption client-side. Server stores ciphertext + non-secret `qshrink` summary only. Zero-knowledge preserved; no cross-tenant state added.

## Failure points & handling
- Optimization error → seal raw bytes (`applied:false`), never blocks upload.
- `>4 GiB` input → `QSHRINK_TOO_LARGE` → raw fallback.
- Corruption/tamper → GCM tag, then `QSHRINK_INTEGRITY_FAILED` / `QSHRINK_MERKLE_INTEGRITY_FAILED`.
- Legacy (pre-Q-Shrink) files → magic/flag detection returns bytes unchanged.

## Scaling
Whole-blob single-stream compression (no per-chunk overhead); entropy-gated to skip incompressible data. Codec-tagged format reserves Zstandard/Brotli (ids 3/4).
