/**
 * Lets something outside Quantum Vault (the "someone sent you a file" notice)
 * open a particular vault section. The vault may not be mounted yet — it sits
 * behind its own lock — so the request is kept until the vault takes it, and
 * a vault that is already open hears it at once through an event.
 */
export type VaultSectionRequest = "shared";

const EVENT = "qguard:vault-section";
let pendingRequest: VaultSectionRequest | null = null;

export function requestVaultSection(section: VaultSectionRequest): void {
  pendingRequest = section;
  window.dispatchEvent(new CustomEvent<VaultSectionRequest>(EVENT, { detail: section }));
}

/** The section asked for since the vault last looked, once. */
export function takeRequestedVaultSection(): VaultSectionRequest | null {
  const section = pendingRequest;
  pendingRequest = null;
  return section;
}

/** Hear requests while the vault is mounted; returns the unsubscribe. */
export function onVaultSectionRequest(listener: (section: VaultSectionRequest) => void): () => void {
  const handler = () => {
    const section = takeRequestedVaultSection();
    if (section) listener(section);
  };
  window.addEventListener(EVENT, handler);
  return () => window.removeEventListener(EVENT, handler);
}
