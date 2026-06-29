// Pure types + formatters for the Vault Crypto Terminal live progress panel.
// Every value originates from real VaultProgress events emitted by the Rust
// vault streamer (src-tauri/src/vault_stream.rs) — these helpers only format,
// never fabricate.

export interface VaultProgress {
  op: "encrypt" | "decrypt" | "rewrap";
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
  return op;
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
