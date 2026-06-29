import {
  Activity,
  CircleHelp,
  Gauge,
  KeyRound,
  LayoutDashboard,
  LockKeyhole,
  MessageSquare,
  MonitorSmartphone,
  QrCode,
  Settings,
  type LucideIcon,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { DashboardData, MessagingModule, Page } from "@/lib/types";

/**
 * First-run guided product tour for QGuard Messaging.
 *
 * The tour is intentionally lightweight: it spotlights the real product
 * modules and hands users off to the existing pages (Vault, Keys, Devices,
 * Settings) instead of re-implementing security wizards. Progress is persisted
 * per-user so the welcome experience appears once, can be resumed, and can be
 * replayed on demand from the Help menu.
 */

export type OnboardingPhase = "hidden" | "welcome" | "touring" | "complete";

export type TourAccent = "violet" | "cyan" | "emerald" | "amber";

export interface TourStep {
  id: string;
  /** `data-tour` attribute of the element to spotlight. */
  anchor: string;
  /** App page to navigate to when this step becomes active. */
  page?: Page;
  eyebrow: string;
  title: string;
  body: string;
  icon: LucideIcon;
  accent: TourAccent;
}

export interface ChecklistItem {
  id: string;
  label: string;
  hint: string;
  done: boolean;
  page: Page;
}

interface ModuleCopy {
  eyebrow: string;
  title: string;
  body: string;
  icon: LucideIcon;
  accent: TourAccent;
}

const ESTIMATED_MINUTES = "3 min";

const MODULE_COPY: Partial<Record<Page, ModuleCopy>> = {
  dashboard: {
    eyebrow: "Your command center",
    title: "See your security posture at a glance",
    body: "The dashboard summarizes your quantum-safe score, trusted devices, live activity, and anything that needs attention — your starting point every day.",
    icon: LayoutDashboard,
    accent: "violet",
  },
  chat: {
    eyebrow: "Quantum-safe messaging",
    title: "Message with hybrid encryption",
    body: "Every conversation, voice note, file, and call is protected with hybrid X25519 + ML-KEM encryption. The lock indicator confirms quantum-safe protection in real time.",
    icon: MessageSquare,
    accent: "cyan",
  },
  vault: {
    eyebrow: "Encrypted Quantum Vault",
    title: "Protect files — and create your Recovery Key",
    body: "The Quantum Vault encrypts files locally with post-quantum cryptography. Generate your Recovery Key here so you can restore encrypted data on a new trusted device.",
    icon: LockKeyhole,
    accent: "emerald",
  },
  keys: {
    eyebrow: "Your cryptographic identity",
    title: "Manage identity keys and prekeys",
    body: "Review your identity keys, signed prekeys, and rotation history across ML-DSA signatures and ML-KEM key establishment. This is the root of your secure identity.",
    icon: KeyRound,
    accent: "violet",
  },
  devices: {
    eyebrow: "Device trust",
    title: "Approve and govern trusted devices",
    body: "Register this device, approve new ones by QR, and revoke anything you no longer recognize. Trusted devices are how your encrypted data follows you safely.",
    icon: MonitorSmartphone,
    accent: "cyan",
  },
  verification: {
    eyebrow: "Verify your contacts",
    title: "Confirm there is no eavesdropper",
    body: "Compare safety numbers and fingerprints — in person or by QR — to verify you are talking to the right person and no one is intercepting the conversation.",
    icon: QrCode,
    accent: "amber",
  },
  quantum: {
    eyebrow: "Quantum readiness",
    title: "Track your post-quantum protection",
    body: "Monitor PQC status, Harvest-Now-Decrypt-Later protection, and key-rotation history so your communications stay safe against future quantum attacks.",
    icon: Gauge,
    accent: "emerald",
  },
  audit: {
    eyebrow: "Tamper-evident history",
    title: "Review your security audit trail",
    body: "Every security-relevant action is recorded in a local, tamper-evident event chain you can review and export for compliance.",
    icon: Activity,
    accent: "violet",
  },
  settings: {
    eyebrow: "Make it yours",
    title: "Tune security modes and alerts",
    body: "Choose security modes, enable multi-factor authentication, and set alerts and retention to match how your organization works.",
    icon: Settings,
    accent: "amber",
  },
};

/**
 * Build the spotlight steps from the modules actually enabled for this user,
 * preserving sidebar order, then close with the always-present Help anchor.
 */
export function buildTourSteps(modules: MessagingModule[]): TourStep[] {
  const moduleSteps = modules
    .filter((module) => module.route !== "admin")
    .map((module): TourStep | null => {
      const copy = MODULE_COPY[module.route];
      if (!copy) return null;
      return {
        id: `module-${module.route}`,
        anchor: `nav-${module.route}`,
        page: module.route,
        eyebrow: copy.eyebrow,
        title: copy.title,
        body: copy.body,
        icon: copy.icon,
        accent: copy.accent,
      };
    })
    .filter((step): step is TourStep => step !== null);

  const helpStep: TourStep = {
    id: "help",
    anchor: "help",
    eyebrow: "You're in control",
    title: "Help is always one click away",
    body: "Open the Help menu anytime for security guidance — and replay this product tour whenever you want a refresher.",
    icon: CircleHelp,
    accent: "cyan",
  };

  return [...moduleSteps, helpStep];
}

function hasName(value: string | null | undefined): boolean {
  return typeof value === "string" && value.trim().length > 0;
}

/**
 * Evidence-based readiness checklist. Each item reflects real account state so
 * the completion screen tells the truth and points to what still needs doing.
 */
export function buildChecklist(data: DashboardData, userId: string): ChecklistItem[] {
  const myDevices = data.devices.filter((device) => device.user_id === userId);
  const trustedDevice = myDevices.some(
    (device) => device.trust_state === "ThisDevice" || device.trust_state === "Trusted",
  );
  const identityReady =
    data.keyInventory.identity_device_count > 0 && data.keyInventory.active_signed_prekeys > 0;
  const encryptionActive =
    /active|enabled|protected|ready/i.test(data.snapshot.e2ee_status) ||
    data.snapshot.quantum_safe_score > 0;
  // The Quantum Vault is local-only, so there are no cloud vault files to count.
  // Treat the vault as set up once the user has configured a recovery key on this
  // device (the vault page sets this flag on recovery setup/enable).
  const vaultReady = (() => {
    try {
      return window.localStorage.getItem("qguard.vault.recovery.configured") === "true";
    } catch {
      return false;
    }
  })();
  const messagingStarted = data.conversations.length > 0 || data.contacts.length > 0;

  return [
    {
      id: "profile",
      label: "Profile completed",
      hint: "Add your name so contacts can recognize you.",
      done: hasName(data.profile?.name),
      page: "settings",
    },
    {
      id: "device",
      label: "Device trusted",
      hint: "Register this device in the Device Trust Center.",
      done: trustedDevice,
      page: "devices",
    },
    {
      id: "keys",
      label: "Identity keys ready",
      hint: "Publish your identity and signed prekeys.",
      done: identityReady,
      page: "keys",
    },
    {
      id: "encryption",
      label: "Quantum-safe encryption active",
      hint: "Establish a hybrid PQC session to protect messages.",
      done: encryptionActive,
      page: "quantum",
    },
    {
      id: "vault",
      label: "Quantum Vault initialized",
      hint: "Encrypt your first file and store a Recovery Key.",
      done: vaultReady,
      page: "vault",
    },
    {
      id: "messaging",
      label: "Secure messaging started",
      hint: "Add a contact or start your first conversation.",
      done: messagingStarted,
      page: "chat",
    },
  ];
}

export const TOUR_ESTIMATED_TIME = ESTIMATED_MINUTES;

// --- Persistence -----------------------------------------------------------

type StoredStatus = "pending" | "active" | "completed" | "skipped";

interface OnboardingRecord {
  status: StoredStatus;
  lastStep: number;
  updatedAt: string;
}

const STORAGE_PREFIX = "qguard.onboarding.v1:";

function storageKey(userId: string): string {
  return `${STORAGE_PREFIX}${userId}`;
}

function readRecord(userId: string): OnboardingRecord | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(storageKey(userId));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<OnboardingRecord>;
    if (!parsed || typeof parsed.status !== "string") return null;
    return {
      status: parsed.status as StoredStatus,
      lastStep: Number.isFinite(parsed.lastStep) ? Number(parsed.lastStep) : 0,
      updatedAt: typeof parsed.updatedAt === "string" ? parsed.updatedAt : new Date().toISOString(),
    };
  } catch {
    return null;
  }
}

function writeRecord(userId: string, record: OnboardingRecord): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(storageKey(userId), JSON.stringify(record));
  } catch {
    // Persistence is best-effort; the tour still works in-memory this session.
  }
}

function clamp(value: number, min: number, max: number): number {
  if (max < min) return min;
  return Math.min(Math.max(value, min), max);
}

export interface OnboardingController {
  phase: OnboardingPhase;
  stepIndex: number;
  stepCount: number;
  start: () => void;
  next: () => void;
  back: () => void;
  goToStep: (index: number) => void;
  skip: () => void;
  resumeLater: () => void;
  complete: () => void;
  replay: () => void;
}

/**
 * Drives onboarding phase + persisted progress for the signed-in user.
 * `ready` gates auto-display until dashboard data has loaded, and `stepCount`
 * keeps navigation in bounds as the enabled module set resolves.
 */
export function useOnboarding(
  userId: string | null,
  stepCount: number,
  ready: boolean,
): OnboardingController {
  const [phase, setPhase] = useState<OnboardingPhase>("hidden");
  const [stepIndex, setStepIndex] = useState(0);

  // Decide the initial phase for a user once their data is ready.
  useEffect(() => {
    if (!userId || !ready) return;
    const record = readRecord(userId);
    if (!record || record.status === "pending") {
      setPhase("welcome");
      setStepIndex(0);
      return;
    }
    if (record.status === "active") {
      setPhase("touring");
      setStepIndex(clamp(record.lastStep, 0, Math.max(0, stepCount - 1)));
      return;
    }
    setPhase("hidden");
    // `stepCount` intentionally excluded: a resumed/auto tour should be decided
    // from the persisted record, not re-triggered when the module set resolves.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId, ready]);

  const persist = useCallback(
    (status: StoredStatus, lastStep: number) => {
      if (!userId) return;
      writeRecord(userId, { status, lastStep, updatedAt: new Date().toISOString() });
    },
    [userId],
  );

  const start = useCallback(() => {
    setStepIndex(0);
    setPhase("touring");
    persist("active", 0);
  }, [persist]);

  const next = useCallback(() => {
    setStepIndex((current) => {
      const lastIndex = Math.max(0, stepCount - 1);
      if (current >= lastIndex) {
        setPhase("complete");
        persist("active", current);
        return current;
      }
      const nextIndex = current + 1;
      persist("active", nextIndex);
      return nextIndex;
    });
  }, [persist, stepCount]);

  const back = useCallback(() => {
    setStepIndex((current) => {
      const previous = Math.max(0, current - 1);
      persist("active", previous);
      return previous;
    });
  }, [persist]);

  const goToStep = useCallback(
    (index: number) => {
      const target = clamp(index, 0, Math.max(0, stepCount - 1));
      setStepIndex(target);
      setPhase("touring");
      persist("active", target);
    },
    [persist, stepCount],
  );

  const skip = useCallback(() => {
    setPhase("hidden");
    persist("skipped", stepIndex);
  }, [persist, stepIndex]);

  const resumeLater = useCallback(() => {
    setPhase("hidden");
    persist("active", stepIndex);
  }, [persist, stepIndex]);

  const complete = useCallback(() => {
    setPhase("hidden");
    persist("completed", Math.max(0, stepCount - 1));
  }, [persist, stepCount]);

  const replay = useCallback(() => {
    setStepIndex(0);
    setPhase("welcome");
    persist("pending", 0);
  }, [persist]);

  return useMemo(
    () => ({
      phase,
      stepIndex: clamp(stepIndex, 0, Math.max(0, stepCount - 1)),
      stepCount,
      start,
      next,
      back,
      goToStep,
      skip,
      resumeLater,
      complete,
      replay,
    }),
    [phase, stepIndex, stepCount, start, next, back, goToStep, skip, resumeLater, complete, replay],
  );
}
