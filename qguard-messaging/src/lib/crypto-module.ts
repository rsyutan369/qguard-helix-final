import { isTauriRuntime, safeInvoke } from "@/lib/tauri";

/** What the core's cryptographic module reports about itself (`commands::crypto_module`). */
export interface CryptoModuleStatus {
  module: {
    backend: "rustcrypto" | "wolfcrypt" | string;
    name: string;
    version: string;
    fipsModuleVersion: string | null;
    fipsStatus: number | null;
  };
  /** A FIPS build of the module, operational, whose version maps to a CMVP certificate. */
  fipsValidatedModule: boolean;
  certificate: {
    number: number;
    module: string;
    moduleVersion: string;
    standard: string;
    validatedOn: string;
    sunset: string;
    url: string;
    covers: string[];
    testedPlatforms: string[];
  } | null;
  approvedMode: boolean;
  approvedModeSource: "build" | "environment" | "setting";
  selfTest: {
    passed: boolean;
    backend: string;
    ranAt: string;
    durationMs: number;
    results: { name: string; passed: boolean; detail?: string }[];
  };
  algorithms: {
    id: string;
    name: string;
    standard: string;
    usedFor: string;
    approved: boolean;
    validated: boolean;
    note: string | null;
  }[];
  outsideBoundary: string[];
  credentials: {
    id: string;
    label: string;
    kdf: string;
    approvedKdf: boolean;
    meetsApprovedMode: boolean;
    note: string | null;
  }[];
  pbkdf2: { prf: string; iterations: number; saltBits: number; vaultPasswordMinChars: number };
}

export async function fetchCryptoModuleStatus(): Promise<CryptoModuleStatus | null> {
  if (!isTauriRuntime()) return null;
  return safeInvoke<CryptoModuleStatus | null>("crypto_module_status", undefined, null);
}

export async function setApprovedMode(enabled: boolean): Promise<CryptoModuleStatus> {
  return safeInvoke<CryptoModuleStatus>("crypto_set_approved_mode", { enabled });
}
