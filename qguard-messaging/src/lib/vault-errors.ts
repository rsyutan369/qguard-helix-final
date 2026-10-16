// Interpreting why the Quantum Vault refused to open a container.
//
// The Rust core (src-tauri/src/vault_stream.rs) authenticates every container
// as THIS vault's own before it writes a single byte. Two of its refusals are
// not "the file is broken" and need their own handling in the UI, so each
// carries a stable marker. Keep the two constants in sync with
// `FOREIGN_VAULT_MARKER` / `UNRECOGNIZED_SIGNER_MARKER` in vault_stream.rs.

/** Sealed under a different vault key (pre-reset, another device, or not ours). */
export const FOREIGN_VAULT_MARKER = "FOREIGN_VAULT_KEY";
/** A legacy v1/v2 container whose signer this device does not recognise. */
export const UNRECOGNIZED_SIGNER_MARKER = "UNRECOGNIZED_VAULT_SIGNER";

export type VaultOpenFailure = "foreign_vault" | "unrecognized_signer" | "other";

export function vaultErrorText(error: unknown): string {
  if (!error) return "Unknown error";
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  if (typeof error === "object") {
    const record = error as Record<string, unknown>;
    const message = record.message ?? record.error;
    if (typeof message === "string") return message;
    try {
      return JSON.stringify(record);
    } catch {
      return "Unexpected error";
    }
  }
  return String(error);
}

export function classifyVaultOpenError(error: unknown): VaultOpenFailure {
  const message = vaultErrorText(error);
  if (message.includes(UNRECOGNIZED_SIGNER_MARKER)) return "unrecognized_signer";
  if (message.includes(FOREIGN_VAULT_MARKER)) return "foreign_vault";
  return "other";
}

/**
 * The message to show the user: the backend's own explanation with the machine
 * marker and the error-category prefix removed. Nothing is invented here — a
 * message without a marker is returned unchanged.
 */
export function describeVaultOpenError(error: unknown): string {
  const message = vaultErrorText(error);
  for (const marker of [FOREIGN_VAULT_MARKER, UNRECOGNIZED_SIGNER_MARKER]) {
    const at = message.indexOf(`${marker}:`);
    if (at >= 0) return message.slice(at + marker.length + 1).trim();
  }
  return message;
}

/** Thrown when the user declines to open a container from an unrecognised signer. */
export class VaultConsentDeclinedError extends Error {
  constructor() {
    super("Not opened: this older vault file is signed by a key this device does not recognise, and you chose not to trust it.");
    this.name = "VaultConsentDeclinedError";
  }
}

/**
 * Run an owner-side vault operation (decrypt / verify / re-protect), asking for
 * the user's consent — and only then retrying — when the container is a legacy
 * v1/v2 file whose signer this device does not recognise.
 *
 * The first attempt is ALWAYS made without consent, so the override can never
 * be the default path. Consent is asked once per operation and is not
 * remembered: it applies to this file, this time. Every other failure
 * (including a foreign vault key, which is not overridable) propagates as is.
 */
export async function withLegacySignerConsent<T>(
  run: (allowUnverifiedLegacy: boolean) => Promise<T>,
  askConsent: () => Promise<boolean>,
): Promise<T> {
  try {
    return await run(false);
  } catch (error) {
    if (classifyVaultOpenError(error) !== "unrecognized_signer") throw error;
    const consented = await askConsent();
    if (!consented) throw new VaultConsentDeclinedError();
    return run(true);
  }
}
