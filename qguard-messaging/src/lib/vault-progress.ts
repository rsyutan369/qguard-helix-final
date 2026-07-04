// Pure types + formatters for the Vault Crypto Terminal live progress panel.
// Every value originates from real VaultProgress events emitted by the Rust
// vault streamer (src-tauri/src/vault_stream.rs) — these helpers only format,
// never fabricate.

export interface VaultProgress {
  op: "encrypt" | "decrypt" | "rewrap" | "verify";
  phase: string;
  message: string;
  processedBytes: number;
  totalBytes: number;
  chunkIndex: number;
  totalChunks: number;
  level: "info" | "success";
}

const PHASE_LABELS: Record<string, string> = {
  init: "Initializing",
  fek: "File key · AES-256-GCM",
  vmk_wrap: "VMK seal · X25519 + ML-KEM-1024",
  recovery_wrap: "Recovery wrap · ML-KEM-1024",
  sign: "Signing · ML-DSA-87",
  header: "Header written",
  chunk: "Streaming · AES-256-GCM",
  verify: "Verifying signature · ML-DSA-87",
  decapsulate: "VMK recover · ML-KEM-1024",
  unwrap_fek: "Unwrapping file key",
  finalize: "Finalizing",
  done: "Complete",
};

export function phaseLabel(phase: string): string {
  return PHASE_LABELS[phase] ?? phase;
}

export function opLabel(op: string): string {
  if (op === "encrypt") return "Encrypting";
  if (op === "decrypt") return "Decrypting";
  if (op === "rewrap") return "Re-protecting";
  if (op === "verify") return "Verifying";
  return op;
}

// Stage-weighted overall progress. A small file is a single chunk, so a pure
// bytes-based bar would jump 0 -> 100 instantly. Weighting each REAL crypto
// phase lets the bar climb across the steps that actually executed (key gen,
// VMK seal, signing, streaming, finalize) — honest, not fabricated. The chunk
// stage fills proportionally to real processed bytes.
const PHASE_RANGE: Record<string, [number, number]> = {
  init: [0, 5],
  verify: [0, 8], // decrypt: header signature verified
  fek: [5, 14],
  decapsulate: [8, 18], // decrypt: VMK recovered
  vmk_wrap: [14, 24],
  unwrap_fek: [18, 26], // decrypt: per-file key unwrapped
  recovery_wrap: [24, 30],
  sign: [30, 38],
  header: [38, 42],
  chunk: [42, 98],
  finalize: [98, 99],
  done: [100, 100],
};

export function overallPercent(p: VaultProgress): number {
  if (p.phase === "done") return 100;
  const [a, b] = PHASE_RANGE[p.phase] ?? [0, 100];
  if (p.phase === "chunk" && p.totalBytes > 0) {
    const frac = Math.max(0, Math.min(1, p.processedBytes / p.totalBytes));
    return Math.round(a + (b - a) * frac);
  }
  return Math.round((a + b) / 2);
}

export function formatThroughput(bytes: number, elapsedMs: number): string {
  if (elapsedMs <= 0 || bytes <= 0) return "— MB/s";
  const mbps = bytes / (1024 * 1024) / (elapsedMs / 1000);
  // Whole numbers render without a trailing ".0"; small rates keep one decimal.
  const rounded = mbps >= 10 ? Math.round(mbps) : Math.round(mbps * 10) / 10;
  return `${rounded} MB/s`;
}

export function formatEta(processed: number, total: number, elapsedMs: number): string {
  if (elapsedMs <= 0 || processed <= 0 || total <= 0 || processed >= total) return "ETA —";
  const rate = processed / (elapsedMs / 1000); // bytes per second
  const remaining = (total - processed) / rate; // seconds
  if (!Number.isFinite(remaining)) return "ETA —";
  if (remaining >= 60) return `ETA ${Math.round(remaining / 60)}m`;
  return `ETA ${Math.max(1, Math.round(remaining))}s`;
}
