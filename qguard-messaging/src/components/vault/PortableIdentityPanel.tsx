import {
  AlertTriangle,
  BadgeCheck,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ClipboardPaste,
  Copy,
  Download,
  FileSearch,
  FolderOpen,
  KeyRound,
  Loader2,
  LockKeyhole,
  Send,
  ShieldCheck,
  Trash2,
  Upload,
  UserPlus,
  UnlockKeyhole,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { open as openDialog } from "@/lib/tauri-dialog";
import { isAndroidRuntime, isTauriRuntime, safeInvoke } from "@/lib/tauri";

// ---------------------------------------------------------------------------
// Portable Hybrid Identity — the sharing half of the Quantum Vault.
//
// A `.qvault` is normally sealed to the device that made it, which is exactly
// what you want for your own files and exactly what you cannot use to send one
// to somebody else. A portable identity is a person-scoped keypair set the
// container can be sealed to instead:
//
//   • .qgkey       private bundle, passphrase-protected, stays with its owner
//   • .qgpub.json  public bundle, handed to whoever wants to send you something
//
// Crypto is unchanged from the rest of the vault: the per-file key (AES-256-GCM)
// is wrapped for each recipient with X25519 + ML-KEM-1024 through HKDF-SHA3-256,
// and the container header is signed Ed25519 + ML-DSA-87. Critically, a
// recipient wrap seals the PER-FILE key, never the Vault Master Key — a person
// you share one file with gains access to that file and nothing else.
// ---------------------------------------------------------------------------

const IS_ANDROID = isAndroidRuntime();
/** Matches the Rust-side minimum in `crypto::portable_identity`. */
const MIN_PASSPHRASE_LEN = 12;
/** Idle timeout before the unlocked identity is dropped from memory. */
const IDLE_LOCK_MS = 5 * 60_000;

export interface IdentitySummary {
  fingerprint: string;
  short_fingerprint: string;
  label: string | null;
  kem_algorithm: string;
  signature_algorithm: string;
  can_attest: boolean;
  bundle_path: string | null;
  unlocked: boolean;
}

export interface RecipientSummary {
  fingerprint: string;
  short_fingerprint: string;
  label: string | null;
  kem_algorithm: string;
  signature_algorithm: string;
  bundle: string;
}

export interface SealedRecipient {
  fingerprint: string;
  label: string;
  algorithm: string;
}

export interface VerifiedSender {
  fingerprint: string;
  label: string;
  signature_algorithm: string;
}

export interface SealedInspection {
  file_id: string;
  kind: "file" | "folder";
  name: string;
  content_type: string;
  original_size: number;
  total_chunks: number;
  sealed_for: SealedRecipient[];
  verified_sender: VerifiedSender | null;
}

/**
 * Mirrors the Rust `VaultLocalStreamSummary` exactly — including `suite`, which
 * the page's registry stores. Keeping the full shape here (rather than a subset
 * plus a cast at the call site) is what lets the compiler catch a drift between
 * what a seal returns and what the Explorer records.
 */
export interface VaultStreamSummary {
  file_id: string;
  kind: "file" | "folder";
  name: string;
  content_type: string;
  original_size: number;
  total_chunks: number;
  source_path: string;
  output_path: string;
  suite: Record<string, string>;
}

type Busy =
  | "generate"
  | "import"
  | "export-public"
  | "add-recipient"
  | "seal-file"
  | "seal-folder"
  | "inspect"
  | "open-file"
  | "open-folder"
  | null;

interface Notice {
  tone: "ok" | "error" | "info";
  message: string;
}

interface FolderChoice {
  path: string;
  label: string;
}

export interface PortableIdentityPanelProps {
  userId: string;
  /** Append a line to the shared Vault Crypto Terminal. */
  appendLog: (level: "info" | "success" | "error", message: string) => void;
  /** Record an entry in the shared vault activity feed. */
  pushActivity: (entry: {
    source: "encrypt" | "decrypt";
    title: string;
    detail: string;
    status: "success" | "failed" | "info";
  }) => void;
  /** Run a vault stream command with the page's live progress terminal. */
  runVaultStream: (command: string, args: Record<string, unknown>) => Promise<VaultStreamSummary>;
  /** Ask the user for a destination folder (desktop dialog / Android SAF). */
  chooseDestinationFolder: (title: string) => Promise<FolderChoice | null>;
  /** Resolve a chosen folder + file name into a concrete output target. */
  prepareDestination: (folder: string, fileName: string) => Promise<string>;
  /** Display name for a picked source (handles Android content URIs). */
  resolveSourceName: (sourcePath: string) => Promise<string>;
  /** True while another vault operation owns the progress terminal. */
  vaultBusy: boolean;
  /** Called after a seal/open so the page can refresh its registry view. */
  onContainerWritten?: (summary: VaultStreamSummary, kind: "sealed" | "opened") => void;
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function describeError(error: unknown): string {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  if (error && typeof error === "object" && "message" in error) {
    return String((error as { message: unknown }).message);
  }
  return "Unexpected error";
}

function basename(value: string): string {
  return value.split(/[\\/]/).filter(Boolean).pop() ?? value;
}

/** Local-only strength read-out. Length dominates for an offline bundle. */
function passphraseStrength(value: string): { score: 0 | 1 | 2 | 3; label: string; tone: string } {
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((r) => r.test(value)).length;
  if (value.length < MIN_PASSPHRASE_LEN) {
    return { score: 0, label: `Too short — ${MIN_PASSPHRASE_LEN} characters minimum`, tone: "text-rose-600" };
  }
  if (value.length >= 20 && classes >= 2) return { score: 3, label: "Strong", tone: "text-emerald-600" };
  if (value.length >= 16 || classes >= 3) return { score: 2, label: "Good", tone: "text-cyan-700" };
  return { score: 1, label: "Acceptable — longer is better", tone: "text-amber-600" };
}

export default function PortableIdentityPanel({
  userId,
  appendLog,
  pushActivity,
  runVaultStream,
  chooseDestinationFolder,
  prepareDestination,
  resolveSourceName,
  vaultBusy,
  onContainerWritten,
}: PortableIdentityPanelProps) {
  const recipientsKey = useMemo(() => `qguard.vault.recipients.v1:${userId}`, [userId]);
  const expandedKey = useMemo(() => `qguard.vault.identity-panel.expanded:${userId}`, [userId]);

  // Collapsed by default: sharing is an occasional task, and the vault page
  // already carries three always-open panels. The choice is remembered per user.
  const [expanded, setExpanded] = useState(false);
  const [identity, setIdentity] = useState<IdentitySummary | null>(null);
  const [busy, setBusy] = useState<Busy>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [label, setLabel] = useState("");
  const [attest, setAttest] = useState(true);

  // Address book of public recipient bundles. Public key material only — no
  // secrets — so it is safe in device-local storage.
  const [recipients, setRecipients] = useState<RecipientSummary[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [recipientDraft, setRecipientDraft] = useState("");
  const [recipientDrawerOpen, setRecipientDrawerOpen] = useState(false);

  const [inspection, setInspection] = useState<SealedInspection | null>(null);

  // Passphrase modal.
  const [modal, setModal] = useState<
    | { mode: "create"; title: string; description: string; onSubmit: (passphrase: string) => Promise<void> }
    | { mode: "unlock"; title: string; description: string; onSubmit: (passphrase: string) => Promise<void> }
    | null
  >(null);
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [modalError, setModalError] = useState<string | null>(null);
  const passphraseRef = useRef<HTMLInputElement>(null);

  const strength = passphraseStrength(passphrase);
  const locked = identity === null;
  const anyBusy = busy !== null || vaultBusy;
  const bodyId = "portable-identity-panel-body";

  useEffect(() => {
    try {
      setExpanded(window.localStorage.getItem(expandedKey) === "true");
    } catch {
      setExpanded(false);
    }
  }, [expandedKey]);

  const toggleExpanded = useCallback(() => {
    setExpanded((open) => {
      const next = !open;
      try {
        window.localStorage.setItem(expandedKey, String(next));
      } catch {
        // Remembering the choice is a convenience; never block the toggle on it.
      }
      return next;
    });
  }, [expandedKey]);

  // ── Identity session ──────────────────────────────────────────────────────

  const refreshIdentity = useCallback(async () => {
    if (!isTauriRuntime()) return;
    try {
      const current = await safeInvoke<IdentitySummary | null>("vault_identity_status", undefined, null);
      setIdentity(current);
    } catch {
      setIdentity(null);
    }
  }, []);

  useEffect(() => {
    void refreshIdentity();
  }, [refreshIdentity]);

  const lockIdentity = useCallback(
    async (reason: "manual" | "idle") => {
      if (!isTauriRuntime()) return;
      try {
        await safeInvoke("vault_identity_lock");
      } catch {
        // A failed lock still clears the UI; the Rust side drops it on
        // workspace lock and sign-out regardless.
      }
      setIdentity(null);
      setNotice({
        tone: "info",
        message:
          reason === "idle"
            ? "Identity auto-locked after 5 minutes idle. Unlock it again to open or seal shared containers."
            : "Identity locked — its key material has been dropped from memory.",
      });
    },
    [],
  );

  // Auto-lock on idle. Share key material should not sit unlocked while the
  // user is away from the machine; every vault action resets the timer.
  useEffect(() => {
    if (!identity) return undefined;
    let timer = window.setTimeout(() => void lockIdentity("idle"), IDLE_LOCK_MS);
    const reset = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => void lockIdentity("idle"), IDLE_LOCK_MS);
    };
    const events: (keyof WindowEventMap)[] = ["mousedown", "keydown", "wheel", "touchstart"];
    events.forEach((event) => window.addEventListener(event, reset, { passive: true }));
    return () => {
      window.clearTimeout(timer);
      events.forEach((event) => window.removeEventListener(event, reset));
    };
  }, [identity, lockIdentity]);

  // ── Recipient address book ────────────────────────────────────────────────

  useEffect(() => {
    try {
      const saved = window.localStorage.getItem(recipientsKey);
      setRecipients(saved ? (JSON.parse(saved) as RecipientSummary[]) : []);
    } catch {
      setRecipients([]);
    }
    setSelected([]);
  }, [recipientsKey]);

  const persistRecipients = useCallback(
    (next: RecipientSummary[]) => {
      setRecipients(next);
      try {
        window.localStorage.setItem(recipientsKey, JSON.stringify(next));
      } catch {
        // Storage full or unavailable — the in-memory list still works for
        // this session, so this must not break the seal flow.
      }
    },
    [recipientsKey],
  );

  const addRecipient = useCallback(
    (recipient: RecipientSummary) => {
      const existing = recipients.findIndex((r) => r.fingerprint === recipient.fingerprint);
      const next = existing >= 0 ? recipients.map((r, i) => (i === existing ? recipient : r)) : [...recipients, recipient];
      persistRecipients(next);
      setSelected((prev) => (prev.includes(recipient.fingerprint) ? prev : [...prev, recipient.fingerprint]));
      setNotice({
        tone: "ok",
        message:
          existing >= 0
            ? `Updated recipient ${recipient.label || recipient.short_fingerprint}.`
            : `Added recipient ${recipient.label || recipient.short_fingerprint}. Confirm the fingerprint with them over a channel you trust before sending anything sensitive.`,
      });
    },
    [persistRecipients, recipients],
  );

  async function run(action: Busy, task: () => Promise<void>) {
    if (anyBusy) {
      setNotice({ tone: "error", message: "Another vault operation is still running. Let it finish first." });
      return;
    }
    setBusy(action);
    setNotice(null);
    try {
      await task();
    } catch (error) {
      const message = describeError(error);
      setNotice({ tone: "error", message });
      appendLog("error", `Portable identity: ${message}`);
    } finally {
      setBusy(null);
    }
  }

  // ── Generate / import / export ────────────────────────────────────────────

  function openModal(next: NonNullable<typeof modal>) {
    setPassphrase("");
    setConfirmPassphrase("");
    setModalError(null);
    setModal(next);
    window.setTimeout(() => passphraseRef.current?.focus(), 30);
  }

  function startGenerate() {
    openModal({
      mode: "create",
      title: "Protect your new identity",
      description:
        `This passphrase encrypts the private .qgkey bundle on disk (Argon2id → HKDF-SHA3-256 → AES-256-GCM). ` +
        `Minimum ${MIN_PASSPHRASE_LEN} characters. There is no recovery — if you lose it, containers sealed to this identity can no longer be opened.`,
      onSubmit: async (secret) => {
        setModal(null);
        await run("generate", async () => {
          const trimmed = label.trim();
          const stem = trimmed ? trimmed.replace(/[^a-z0-9-_]+/gi, "_") : "identity";
          // Same output path as every other vault artefact: pick a folder, let
          // the Rust side create the (de-duplicated) file. That is what makes
          // this work identically on desktop and through Android's SAF.
          const folder = await chooseDestinationFolder("Choose where to save your private .qgkey bundle");
          if (!folder) {
            setNotice({ tone: "info", message: "Identity not created — no location chosen for the .qgkey bundle." });
            return;
          }
          const dest = await prepareDestination(folder.path, `qguard-${stem}.qgkey`);
          appendLog("info", "Generating portable hybrid identity · X25519 + ML-KEM-1024 / Ed25519 + ML-DSA-87");
          const summary = await safeInvoke<IdentitySummary>("vault_identity_generate", {
            label: trimmed || null,
            passphrase: secret,
            destPath: dest,
          });
          setIdentity(summary);
          appendLog("success", `Identity ${summary.short_fingerprint} created and unlocked · bundle saved to ${basename(dest)}`);
          setNotice({
            tone: "ok",
            message: `Identity created and unlocked. Your private bundle is at ${dest} — back it up somewhere safe and never share it. Export the public recipient JSON to let others seal files to you.`,
          });
        });
      },
    });
  }

  function startImport() {
    void (async () => {
      const source = await openDialog({
        multiple: false,
        directory: false,
        title: "Select your .qgkey identity bundle",
        filters: [{ name: "QGuard Identity", extensions: ["qgkey", "json"] }],
      });
      if (typeof source !== "string") return;
      openModal({
        mode: "unlock",
        title: `Unlock ${basename(source)}`,
        description: "Enter the passphrase you chose when this identity bundle was created.",
        onSubmit: async (secret) => {
          setModal(null);
          await run("import", async () => {
            const summary = await safeInvoke<IdentitySummary>("vault_identity_import", {
              sourcePath: source,
              passphrase: secret,
            });
            setIdentity(summary);
            appendLog("success", `Identity ${summary.short_fingerprint} unlocked from ${basename(source)}`);
            setNotice({
              tone: "ok",
              message: `Identity ${summary.short_fingerprint} unlocked. It auto-locks after 5 minutes idle, when the vault locks, and on sign-out.`,
            });
          });
        },
      });
    })();
  }

  function exportPublicBundle() {
    void run("export-public", async () => {
      if (!identity) return;
      const stem = (identity.label || "identity").replace(/[^a-z0-9-_]+/gi, "_");
      const folder = await chooseDestinationFolder("Choose where to save your public recipient bundle");
      if (!folder) {
        setNotice({ tone: "info", message: "Export cancelled — no location chosen." });
        return;
      }
      const dest = await prepareDestination(
        folder.path,
        `qguard-${stem}-${identity.fingerprint.slice(0, 8)}.qgpub.json`,
      );
      const written = await safeInvoke<string>("vault_identity_export_public", { destPath: dest });
      appendLog("success", `Public recipient bundle exported to ${basename(written)}`);
      setNotice({
        tone: "ok",
        message: `Public bundle saved to ${written}. Send this file to anyone who needs to seal a container to you — it contains public keys only.`,
      });
    });
  }

  // ── Recipients ────────────────────────────────────────────────────────────

  function addRecipientFromDraft() {
    void run("add-recipient", async () => {
      const recipient = await safeInvoke<RecipientSummary>("vault_parse_recipient", {
        bundle: recipientDraft,
      });
      addRecipient(recipient);
      setRecipientDraft("");
      setRecipientDrawerOpen(false);
    });
  }

  function addRecipientFromFile() {
    void run("add-recipient", async () => {
      const source = await openDialog({
        multiple: false,
        directory: false,
        title: "Select a recipient's public bundle (.qgpub.json)",
        filters: [{ name: "QGuard Public Recipient", extensions: ["json", "qgpub"] }],
      });
      if (typeof source !== "string") return;
      const recipient = await safeInvoke<RecipientSummary>("vault_load_recipient_file", {
        sourcePath: source,
      });
      addRecipient(recipient);
      setRecipientDrawerOpen(false);
    });
  }

  function removeRecipient(fingerprint: string) {
    persistRecipients(recipients.filter((r) => r.fingerprint !== fingerprint));
    setSelected((prev) => prev.filter((f) => f !== fingerprint));
  }

  function toggleRecipient(fingerprint: string) {
    setSelected((prev) =>
      prev.includes(fingerprint) ? prev.filter((f) => f !== fingerprint) : [...prev, fingerprint],
    );
  }

  const selectedBundles = useMemo(
    () => recipients.filter((r) => selected.includes(r.fingerprint)).map((r) => r.bundle),
    [recipients, selected],
  );

  // ── Seal ──────────────────────────────────────────────────────────────────

  function sealFile() {
    void run("seal-file", async () => {
      if (selectedBundles.length === 0) {
        setNotice({ tone: "error", message: "Select at least one recipient before sealing." });
        return;
      }
      const source = await openDialog({ multiple: false, directory: false, title: "Step 1 of 2 — select a file to seal" });
      if (typeof source !== "string") return;
      const sourceName = await resolveSourceName(source);
      const folder = await chooseDestinationFolder("Step 2 of 2 — choose where to save the sealed container");
      if (!folder) {
        setNotice({ tone: "info", message: "Sealing cancelled — no destination folder chosen." });
        return;
      }
      const dest = await prepareDestination(folder.path, `${sourceName}.qvault`);
      const names = recipients
        .filter((r) => selected.includes(r.fingerprint))
        .map((r) => r.label || r.short_fingerprint)
        .join(", ");
      appendLog("info", `Sealing ${sourceName} for ${names} · per-file key wrapped with X25519 + ML-KEM-1024`);
      const summary = await runVaultStream("vault_seal_path", {
        sourcePath: source,
        destPath: dest,
        recipients: selectedBundles,
        attest: attest && (identity?.can_attest ?? false),
      });
      const line = `Sealed ${summary.name} (${formatBytes(summary.original_size)}) for ${selectedBundles.length} recipient${selectedBundles.length === 1 ? "" : "s"} → ${folder.label}`;
      appendLog("success", line);
      pushActivity({ source: "encrypt", title: "File sealed for recipients", detail: line, status: "success" });
      onContainerWritten?.(summary, "sealed");
      setNotice({
        tone: "ok",
        message: `${line}. Send the .qvault to ${names} however you like — it is useless to anyone else, including whoever carries it.`,
      });
    });
  }

  function sealFolder() {
    void run("seal-folder", async () => {
      if (IS_ANDROID) {
        setNotice({
          tone: "error",
          message: "Sealing a whole folder is desktop-only: Android cannot walk a directory tree through the Storage Access Framework. Seal individual files instead.",
        });
        return;
      }
      if (selectedBundles.length === 0) {
        setNotice({ tone: "error", message: "Select at least one recipient before sealing." });
        return;
      }
      const source = await openDialog({ multiple: false, directory: true, title: "Step 1 of 2 — select a folder to seal" });
      if (typeof source !== "string") return;
      const folder = await chooseDestinationFolder("Step 2 of 2 — choose where to save the sealed archive");
      if (!folder) {
        setNotice({ tone: "info", message: "Sealing cancelled — no destination folder chosen." });
        return;
      }
      const dest = await prepareDestination(folder.path, `${basename(source)}.qguard-folder.qvault`);
      appendLog("info", `Archiving and sealing folder ${basename(source)} for ${selectedBundles.length} recipient(s)`);
      const summary = await runVaultStream("vault_seal_folder_path", {
        sourceDir: source,
        destPath: dest,
        recipients: selectedBundles,
        attest: attest && (identity?.can_attest ?? false),
      });
      const line = `Sealed folder ${summary.name} (${formatBytes(summary.original_size)}) for ${selectedBundles.length} recipient${selectedBundles.length === 1 ? "" : "s"} → ${folder.label}`;
      appendLog("success", line);
      pushActivity({ source: "encrypt", title: "Folder sealed for recipients", detail: line, status: "success" });
      onContainerWritten?.(summary, "sealed");
      setNotice({ tone: "ok", message: line });
    });
  }

  // ── Inspect / open ────────────────────────────────────────────────────────

  function inspectSealed() {
    void run("inspect", async () => {
      const source = await openDialog({
        multiple: false,
        directory: false,
        title: "Select a sealed .qvault container to inspect",
        filters: [{ name: "QGuard Vault", extensions: ["qvault"] }],
      });
      if (typeof source !== "string") return;
      const result = await safeInvoke<SealedInspection>("vault_inspect_sealed", { sourcePath: source });
      setInspection(result);
      appendLog(
        "info",
        `Inspected ${result.name} · sealed for ${result.sealed_for.length} identity/identities${result.verified_sender ? ` · attested by identity ${result.verified_sender.fingerprint.slice(0, 16)}` : " · no sender attestation"}`,
      );
      if (result.sealed_for.length === 0) {
        setNotice({
          tone: "info",
          message: `${result.name} is an owner-only container, not a shared one. Open it from the Decrypt workspace above.`,
        });
      }
    });
  }

  function openSealedFile() {
    void run("open-file", async () => {
      const source = await openDialog({
        multiple: false,
        directory: false,
        title: "Step 1 of 2 — select the sealed .qvault you received",
        filters: [{ name: "QGuard Vault", extensions: ["qvault"] }],
      });
      if (typeof source !== "string") return;
      const sourceName = await resolveSourceName(source);
      const folder = await chooseDestinationFolder("Step 2 of 2 — choose where to restore the file");
      if (!folder) {
        setNotice({ tone: "info", message: "Cancelled — no destination folder chosen." });
        return;
      }
      const dest = await prepareDestination(folder.path, sourceName.replace(/\.qvault$/i, "") || "restored-file");
      appendLog("info", `Opening sealed container ${sourceName} with identity ${identity?.short_fingerprint ?? ""}`);
      const summary = await runVaultStream("vault_open_sealed_path", { sourcePath: source, destPath: dest });
      const line = `Opened ${summary.name} (${formatBytes(summary.original_size)}) → ${folder.label}`;
      appendLog("success", line);
      pushActivity({ source: "decrypt", title: "Sealed container opened", detail: line, status: "success" });
      onContainerWritten?.(summary, "opened");
      setNotice({ tone: "ok", message: line });
    });
  }

  function openSealedFolder() {
    void run("open-folder", async () => {
      if (IS_ANDROID) {
        setNotice({
          tone: "error",
          message: "Restoring a whole folder is desktop-only: Android cannot write a directory tree through the Storage Access Framework.",
        });
        return;
      }
      const source = await openDialog({
        multiple: false,
        directory: false,
        title: "Step 1 of 2 — select the sealed folder archive",
        filters: [{ name: "QGuard Vault", extensions: ["qvault"] }],
      });
      if (typeof source !== "string") return;
      const dest = await openDialog({ multiple: false, directory: true, title: "Step 2 of 2 — choose where to restore the folder" });
      if (typeof dest !== "string") {
        setNotice({ tone: "info", message: "Cancelled — no destination folder chosen." });
        return;
      }
      const summary = await runVaultStream("vault_open_sealed_folder_path", { sourcePath: source, destDir: dest });
      const line = `Restored sealed folder ${summary.name} (${formatBytes(summary.original_size)}) → ${dest}`;
      appendLog("success", line);
      pushActivity({ source: "decrypt", title: "Sealed folder restored", detail: line, status: "success" });
      onContainerWritten?.(summary, "opened");
      setNotice({ tone: "ok", message: line });
    });
  }

  function copyFingerprint() {
    if (!identity) return;
    navigator.clipboard
      .writeText(identity.fingerprint)
      .then(() => setNotice({ tone: "ok", message: "Fingerprint copied. Read it out to your recipient over a channel you both trust." }))
      .catch(() => setNotice({ tone: "error", message: "Could not copy automatically — select the fingerprint and copy it manually." }));
  }

  function submitModal() {
    if (!modal) return;
    if (passphrase.length < MIN_PASSPHRASE_LEN) {
      setModalError(`Passphrase must be at least ${MIN_PASSPHRASE_LEN} characters.`);
      return;
    }
    if (modal.mode === "create" && passphrase !== confirmPassphrase) {
      setModalError("The two passphrases do not match.");
      return;
    }
    const secret = passphrase;
    setPassphrase("");
    setConfirmPassphrase("");
    setModalError(null);
    void modal.onSubmit(secret);
  }

  // ── Render ────────────────────────────────────────────────────────────────

  // One line of real state for the collapsed header, so the panel can be shut
  // without hiding whether an identity is unlocked or who is ready to receive.
  const collapsedSummary = identity
    ? [
        identity.label || "Unlabelled identity",
        identity.short_fingerprint,
        `${recipients.length} recipient${recipients.length === 1 ? "" : "s"}`,
        selected.length > 0 ? `${selected.length} selected` : null,
      ]
        .filter(Boolean)
        .join(" · ")
    : recipients.length > 0
      ? `Locked · ${recipients.length} recipient${recipients.length === 1 ? "" : "s"} saved · unlock a .qgkey to seal or open shared files`
      : "Share encrypted files with other people — generate or import a .qgkey to start";

  return (
    <section className="shell-card">
      {/* Header doubles as the expand/collapse control. */}
      <button
        type="button"
        onClick={toggleExpanded}
        aria-expanded={expanded}
        aria-controls={bodyId}
        className="flex w-full items-center gap-3 rounded-lg p-5 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/60"
      >
        <span className="shrink-0 text-ink-400">
          {expanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
        </span>
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-cyan-500 to-violet-600 text-white shadow-tight">
          <KeyRound size={17} />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block text-base font-bold text-ink-950">Portable Hybrid Identity (.qgkey)</span>
          {expanded ? (
            <span className="mt-0.5 block text-sm text-ink-600">
              Seal vault files and folders to another person instead of to this device — so you can share
              quantum-encrypted data over any channel. Export your public recipient bundle when someone needs to send you
              something.
            </span>
          ) : (
            <span className="mt-0.5 block truncate text-sm text-ink-600" title={collapsedSummary}>
              {collapsedSummary}
            </span>
          )}
        </span>
        <span
          className={`status-pill shrink-0 ${locked ? "bg-ink-100 text-ink-600" : "bg-emerald-50 text-emerald-600"}`}
          title={locked ? "No identity is unlocked in this session" : "Identity key material is held in memory"}
        >
          {locked ? <LockKeyhole size={12} /> : <UnlockKeyhole size={12} />}
          {locked ? "Locked" : "Unlocked"}
        </span>
      </button>

      {expanded && (
      <div id={bodyId} className="px-5 pb-5">

      {/* Identity controls */}
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          disabled={anyBusy || !!modal}
          onClick={startGenerate}
          className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-bold text-white hover:bg-cyan-700 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {busy === "generate" ? <Loader2 className="animate-spin" size={16} /> : <UserPlus size={16} />}
          Generate new identity
        </button>
        <button
          type="button"
          disabled={anyBusy || !!modal}
          onClick={startImport}
          className="flex items-center gap-2 rounded-lg border border-cyan-200 bg-white px-4 py-2 text-sm font-bold text-cyan-700 hover:bg-cyan-50 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {busy === "import" ? <Loader2 className="animate-spin" size={16} /> : <Upload size={16} />}
          Import .qgkey
        </button>
        {identity && (
          <>
            <button
              type="button"
              disabled={anyBusy}
              onClick={exportPublicBundle}
              title="Save the public JSON that senders add as a recipient"
              className="flex items-center gap-2 rounded-lg border border-violet-200 bg-white px-4 py-2 text-sm font-bold text-violet-700 hover:bg-violet-50 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {busy === "export-public" ? <Loader2 className="animate-spin" size={16} /> : <Download size={16} />}
              Export public recipient bundle
            </button>
            <button
              type="button"
              onClick={() => void lockIdentity("manual")}
              title="Drop this identity's key material from memory"
              className="flex items-center gap-2 rounded-lg border border-line bg-white px-4 py-2 text-sm font-semibold text-ink-600 hover:text-ink-950"
            >
              <LockKeyhole size={16} /> Lock now
            </button>
          </>
        )}
      </div>

      {!identity && (
        <div className="mt-3">
          <label htmlFor="qgkey-label" className="text-xs font-semibold text-ink-600">
            Optional label for the new identity
          </label>
          <input
            id="qgkey-label"
            type="text"
            value={label}
            onChange={(event) => setLabel(event.target.value)}
            placeholder='e.g. "Alice — laptop"'
            className="mt-1 w-full max-w-md rounded-lg border border-line bg-canvas px-3 py-2 text-sm text-ink-950 focus:border-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-400/40"
          />
          <p className="mt-1 text-xs text-ink-400">
            Shown to people you share with. It is display text only — the fingerprint is what actually identifies you.
          </p>
        </div>
      )}

      {/* Unlocked identity summary */}
      {identity && (
        <div className="mt-4 rounded-lg border border-emerald-100 bg-emerald-50/70 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-sm font-bold text-emerald-800">
              <UnlockKeyhole size={15} /> Identity unlocked
              {identity.label && <span className="font-medium text-emerald-700">· {identity.label}</span>}
            </div>
            <button
              type="button"
              onClick={copyFingerprint}
              className="flex items-center gap-1.5 rounded-md border border-emerald-200 bg-white px-2.5 py-1 font-mono text-xs font-semibold text-emerald-700 hover:bg-emerald-50"
              title="Copy the full fingerprint"
            >
              <Copy size={12} /> {identity.short_fingerprint}
            </button>
          </div>
          <div className="mt-2 grid gap-2 sm:grid-cols-3">
            <div className="rounded-md border border-emerald-100 bg-white px-3 py-2">
              <div className="text-[11px] font-semibold text-ink-400">Key encapsulation</div>
              <div className="font-mono text-xs font-bold text-ink-950">X25519 + {identity.kem_algorithm}</div>
            </div>
            <div className="rounded-md border border-emerald-100 bg-white px-3 py-2">
              <div className="text-[11px] font-semibold text-ink-400">Attestation signature</div>
              <div className="font-mono text-xs font-bold text-ink-950">Ed25519 + {identity.signature_algorithm}</div>
            </div>
            <div className="rounded-md border border-emerald-100 bg-white px-3 py-2">
              <div className="text-[11px] font-semibold text-ink-400">Key wrapping</div>
              <div className="font-mono text-xs font-bold text-ink-950">HKDF-SHA3-256 · AES-256-GCM</div>
            </div>
          </div>
          <p className="mt-2 text-xs text-emerald-800/80">
            Auto-locks after 5 minutes idle, when the vault workspace locks, and on sign-out. Share only the public
            recipient bundle — your private .qgkey never leaves this device.
          </p>
          {!identity.can_attest && (
            <p className="mt-2 flex items-start gap-1.5 text-xs font-semibold text-amber-700">
              <AlertTriangle size={13} className="mt-0.5 shrink-0" />
              This identity signs with {identity.signature_algorithm}, so it can receive sealed containers but cannot add a
              sender attestation. Generate an identity here for {"ML-DSA-87"} attestation.
            </p>
          )}
        </div>
      )}

      {/* Recipients */}
      <div className="mt-5 rounded-lg border border-line bg-canvas p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-sm font-bold text-ink-950">Recipients</div>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              disabled={anyBusy}
              onClick={addRecipientFromFile}
              className="flex items-center gap-2 rounded-lg border border-cyan-200 bg-white px-3 py-1.5 text-xs font-bold text-cyan-700 hover:bg-cyan-50 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <FolderOpen size={14} /> Load .qgpub.json
            </button>
            <button
              type="button"
              disabled={anyBusy}
              onClick={() => setRecipientDrawerOpen((open) => !open)}
              className="flex items-center gap-2 rounded-lg border border-line bg-white px-3 py-1.5 text-xs font-bold text-ink-600 hover:text-ink-950 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <ClipboardPaste size={14} /> Paste bundle
            </button>
          </div>
        </div>
        <p className="mt-1 text-xs text-ink-600">
          A recipient is someone&apos;s public identity bundle. Sealing wraps this file&apos;s key to each one you tick —
          they get that file and nothing else from your vault.
        </p>

        {recipientDrawerOpen && (
          <div className="mt-3">
            <textarea
              value={recipientDraft}
              onChange={(event) => setRecipientDraft(event.target.value)}
              rows={5}
              spellCheck={false}
              placeholder='Paste the contents of a .qgpub.json file, e.g. {"type":"qguard-public-recipient","publics":{...}}'
              className="w-full rounded-lg border border-line bg-white px-3 py-2 font-mono text-xs text-ink-950 focus:border-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-400/40"
            />
            <div className="mt-2 flex gap-2">
              <button
                type="button"
                disabled={anyBusy || !recipientDraft.trim()}
                onClick={addRecipientFromDraft}
                className="flex items-center gap-2 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-bold text-white hover:bg-cyan-700 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {busy === "add-recipient" ? <Loader2 className="animate-spin" size={14} /> : <UserPlus size={14} />}
                Add recipient
              </button>
              <button
                type="button"
                onClick={() => {
                  setRecipientDraft("");
                  setRecipientDrawerOpen(false);
                }}
                className="rounded-lg border border-line bg-white px-3 py-1.5 text-xs font-semibold text-ink-600 hover:text-ink-950"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {recipients.length === 0 ? (
          <div className="mt-3 rounded-lg border border-dashed border-line bg-white px-4 py-6 text-center">
            <UserPlus className="mx-auto text-ink-400" size={26} />
            <div className="mt-2 text-sm font-semibold text-ink-950">No recipients yet</div>
            <div className="mt-1 text-xs text-ink-600">
              Ask the person you want to share with to open QGuard → Quantum Vault → Portable Hybrid Identity, generate an
              identity, and send you their public recipient bundle.
            </div>
          </div>
        ) : (
          <ul className="mt-3 space-y-2">
            {recipients.map((recipient) => {
              const checked = selected.includes(recipient.fingerprint);
              return (
                <li
                  key={recipient.fingerprint}
                  className={`flex flex-wrap items-center gap-3 rounded-lg border px-3 py-2 transition ${
                    checked ? "border-cyan-300 bg-cyan-50/60" : "border-line bg-white"
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => toggleRecipient(recipient.fingerprint)}
                    aria-label={`Seal to ${recipient.label || recipient.short_fingerprint}`}
                    className="h-4 w-4 shrink-0 accent-cyan-600"
                  />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-bold text-ink-950">
                      {recipient.label || "Unlabelled identity"}
                    </div>
                    <div className="font-mono text-[11px] text-ink-600">
                      {recipient.short_fingerprint} · X25519 + {recipient.kem_algorithm} · {recipient.signature_algorithm}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => removeRecipient(recipient.fingerprint)}
                    className="icon-button"
                    title="Remove this recipient"
                  >
                    <Trash2 size={15} />
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {/* Seal */}
      <div className="mt-4 rounded-lg border border-line bg-white p-4">
        <div className="flex items-center gap-2 text-sm font-bold text-ink-950">
          <Send size={15} className="text-cyan-600" /> Seal for recipients
        </div>
        <p className="mt-1 text-xs text-ink-600">
          Produces a normal <span className="font-mono">.qvault</span> container that only the ticked recipients can open —
          plus you, on this device. Send it by email, chat, USB stick, anything.
        </p>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={anyBusy || selected.length === 0}
            onClick={sealFile}
            className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-bold text-white hover:bg-cyan-700 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {busy === "seal-file" ? <Loader2 className="animate-spin" size={16} /> : <LockKeyhole size={16} />}
            Seal file
          </button>
          {!IS_ANDROID && (
            <button
              type="button"
              disabled={anyBusy || selected.length === 0}
              onClick={sealFolder}
              className="flex items-center gap-2 rounded-lg border border-cyan-200 bg-white px-4 py-2 text-sm font-bold text-cyan-700 hover:bg-cyan-50 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {busy === "seal-folder" ? <Loader2 className="animate-spin" size={16} /> : <FolderOpen size={16} />}
              Seal folder
            </button>
          )}
          <label
            className={`flex items-center gap-2 text-xs font-semibold ${identity?.can_attest ? "text-ink-600" : "text-ink-400"}`}
            title={
              identity?.can_attest
                ? "Sign the container with your identity so the recipient can check it came from your fingerprint"
                : "Unlock an ML-DSA-87 identity generated in this app to sign as the sender"
            }
          >
            <input
              type="checkbox"
              checked={attest && (identity?.can_attest ?? false)}
              disabled={!identity?.can_attest}
              onChange={(event) => setAttest(event.target.checked)}
              className="h-4 w-4 accent-violet-600"
            />
            Sign as sender (ML-DSA-87 attestation)
          </label>
        </div>
        {selected.length === 0 && recipients.length > 0 && (
          <div className="mt-2 text-xs font-semibold text-amber-700">Tick at least one recipient above to enable sealing.</div>
        )}
      </div>

      {/* Receive */}
      <div className="mt-4 rounded-lg border border-line bg-white p-4">
        <div className="flex items-center gap-2 text-sm font-bold text-ink-950">
          <ShieldCheck size={15} className="text-violet-600" /> Open something sent to you
        </div>
        <p className="mt-1 text-xs text-ink-600">
          Unlock your identity first, then open the <span className="font-mono">.qvault</span> you were sent. Inspect it
          beforehand to see who it is addressed to and, when the sender signed it, who it came from.
        </p>
        <div className="mt-3 flex flex-wrap gap-2">
          <button
            type="button"
            disabled={anyBusy}
            onClick={inspectSealed}
            className="flex items-center gap-2 rounded-lg border border-line bg-white px-4 py-2 text-sm font-bold text-ink-600 hover:text-ink-950 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {busy === "inspect" ? <Loader2 className="animate-spin" size={16} /> : <FileSearch size={16} />}
            Inspect container
          </button>
          <button
            type="button"
            disabled={anyBusy || locked}
            onClick={openSealedFile}
            title={locked ? "Unlock your identity first" : undefined}
            className="flex items-center gap-2 rounded-lg bg-violet-600 px-4 py-2 text-sm font-bold text-white hover:bg-violet-700 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {busy === "open-file" ? <Loader2 className="animate-spin" size={16} /> : <UnlockKeyhole size={16} />}
            Open sealed file
          </button>
          {!IS_ANDROID && (
            <button
              type="button"
              disabled={anyBusy || locked}
              onClick={openSealedFolder}
              title={locked ? "Unlock your identity first" : undefined}
              className="flex items-center gap-2 rounded-lg border border-violet-200 bg-white px-4 py-2 text-sm font-bold text-violet-700 hover:bg-violet-50 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {busy === "open-folder" ? <Loader2 className="animate-spin" size={16} /> : <FolderOpen size={16} />}
              Open sealed folder
            </button>
          )}
        </div>

        {inspection && (
          <div className="mt-3 rounded-lg border border-line bg-canvas p-3">
            <div className="flex items-center justify-between gap-2">
              <div className="truncate text-sm font-bold text-ink-950">{inspection.name}</div>
              <button type="button" onClick={() => setInspection(null)} className="icon-button" title="Dismiss">
                <X size={15} />
              </button>
            </div>
            <div className="mt-1 text-xs text-ink-600">
              {inspection.kind === "folder" ? "Folder archive" : "File"} · {formatBytes(inspection.original_size)} ·{" "}
              {inspection.total_chunks} chunk{inspection.total_chunks === 1 ? "" : "s"} · header intact
            </div>
            {inspection.verified_sender ? (
              (() => {
                // A valid attestation proves the container was sealed by the
                // holder of THIS identity. Whose identity it is only becomes
                // known by matching the fingerprint to one the user has already
                // vetted — a label is whatever the sender typed. So "known
                // contact" is decided by fingerprint alone, never by name.
                const attested = inspection.verified_sender;
                const known = recipients.find(
                  (saved) => saved.fingerprint.toLowerCase() === attested.fingerprint.toLowerCase(),
                );
                return (
                  <div
                    className={`mt-2 flex items-start gap-1.5 rounded-md border px-2.5 py-2 text-xs font-semibold ${
                      known ? "border-emerald-100 bg-emerald-50 text-emerald-700" : "border-amber-200 bg-amber-50 text-amber-800"
                    }`}
                  >
                    {known ? <BadgeCheck size={14} className="mt-px shrink-0" /> : <AlertTriangle size={14} className="mt-px shrink-0" />}
                    <span>
                      {known
                        ? `Sealed by your saved contact ${known.label || known.short_fingerprint}`
                        : `Sealed by an identity that is not in your saved contacts${attested.label ? ` (it calls itself "${attested.label}")` : ""}`}
                      <span className="ml-1 font-mono font-normal">{attested.fingerprint.slice(0, 32)}…</span>
                      <span className="ml-1 font-normal">
                        {known
                          ? `(${attested.signature_algorithm} signature valid; the fingerprint matches the one you saved).`
                          : `(${attested.signature_algorithm} signature valid, but anyone can create an identity and name it anything). Compare this fingerprint with the one the sender gave you directly before trusting the contents.`}
                      </span>
                    </span>
                  </div>
                );
              })()
            ) : (
              <div className="mt-2 flex items-start gap-1.5 rounded-md border border-line bg-white px-2.5 py-2 text-xs text-ink-600">
                <AlertTriangle size={14} className="mt-px shrink-0 text-amber-600" />
                <span>
                  No sender attestation. The container&apos;s integrity is proven, but nothing in it identifies who created
                  it — treat its origin as unverified.
                </span>
              </div>
            )}
            {inspection.sealed_for.length > 0 && (
              <div className="mt-2">
                <div className="text-[11px] font-semibold text-ink-400">Sealed for</div>
                <ul className="mt-1 space-y-1">
                  {inspection.sealed_for.map((entry) => {
                    const mine = identity?.fingerprint === entry.fingerprint;
                    return (
                      <li key={entry.fingerprint} className="flex flex-wrap items-center gap-2 font-mono text-[11px] text-ink-600">
                        {mine ? (
                          <span className="status-pill bg-emerald-50 text-emerald-600">
                            <CheckCircle2 size={11} /> you
                          </span>
                        ) : null}
                        <span>{entry.fingerprint.slice(0, 24)}…</span>
                        {entry.label && <span className="font-sans font-semibold text-ink-950">{entry.label}</span>}
                        <span className="text-ink-400">{entry.algorithm}</span>
                      </li>
                    );
                  })}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>

      {notice && (
        <div
          className={`mt-4 rounded-lg border px-3 py-2 text-sm ${
            notice.tone === "ok"
              ? "border-emerald-100 bg-emerald-50 text-emerald-700"
              : notice.tone === "error"
                ? "border-rose-100 bg-rose-50 text-rose-700"
                : "border-line bg-canvas text-ink-600"
          }`}
          role="status"
        >
          {notice.message}
        </div>
      )}

      </div>
      )}

      {/* Kept outside the collapsible body: an open passphrase modal must not be
          torn down (losing what the user typed) if the panel is collapsed. */}
      {modal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/50 p-4 backdrop-blur-sm"
          onClick={() => setModal(null)}
        >
          <div
            className="w-full max-w-md rounded-xl border border-white/30 bg-white p-5 shadow-soft"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-base font-bold text-ink-950">
                <KeyRound size={18} className="text-cyan-600" /> {modal.title}
              </div>
              <button type="button" onClick={() => setModal(null)} className="icon-button" title="Close">
                <X size={18} />
              </button>
            </div>
            <p className="mt-2 text-sm text-ink-600">{modal.description}</p>

            <form
              className="mt-4 space-y-3"
              onSubmit={(event) => {
                event.preventDefault();
                submitModal();
              }}
            >
              <div>
                <label htmlFor="qgkey-passphrase" className="text-xs font-semibold text-ink-600">
                  Passphrase
                </label>
                <input
                  id="qgkey-passphrase"
                  ref={passphraseRef}
                  type="password"
                  autoComplete={modal.mode === "create" ? "new-password" : "current-password"}
                  value={passphrase}
                  onChange={(event) => setPassphrase(event.target.value)}
                  className="mt-1 w-full rounded-lg border border-line bg-canvas px-3 py-2 text-sm text-ink-950 focus:border-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-400/40"
                />
                {modal.mode === "create" && passphrase.length > 0 && (
                  <div className={`mt-1 text-xs font-semibold ${strength.tone}`}>{strength.label}</div>
                )}
              </div>
              {modal.mode === "create" && (
                <div>
                  <label htmlFor="qgkey-passphrase-confirm" className="text-xs font-semibold text-ink-600">
                    Confirm passphrase
                  </label>
                  <input
                    id="qgkey-passphrase-confirm"
                    type="password"
                    autoComplete="new-password"
                    value={confirmPassphrase}
                    onChange={(event) => setConfirmPassphrase(event.target.value)}
                    className="mt-1 w-full rounded-lg border border-line bg-canvas px-3 py-2 text-sm text-ink-950 focus:border-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-400/40"
                  />
                </div>
              )}
              {modalError && <div className="text-xs font-semibold text-rose-600">{modalError}</div>}
              <div className="flex justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => setModal(null)}
                  className="rounded-lg border border-line bg-white px-4 py-2 text-sm font-semibold text-ink-600 hover:text-ink-950"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-bold text-white hover:bg-cyan-700"
                >
                  {modal.mode === "create" ? "Create identity" : "Unlock"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </section>
  );
}
