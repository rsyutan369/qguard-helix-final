import { verifyRuntimeAssetIntegrity, type RuntimeAssetIntegrity } from "@/lib/runtime-integrity";
import { supabaseUrl } from "@/lib/supabase";
import { safeInvoke } from "@/lib/tauri";
import { measureTransport, mergeTransportEvidence } from "@/lib/transport-evidence";
import type { SecurityHardeningCheck, SecurityHardeningStatus } from "@/lib/types";

const hardeningCacheTtlMs = 60_000;
let cachedHardeningStatus: { loadedAt: number; status: SecurityHardeningStatus } | null = null;
let hardeningStatusPromise: Promise<SecurityHardeningStatus> | null = null;

export function fallbackHardeningStatus(): SecurityHardeningStatus {
  const releaseBuild = import.meta.env.PROD;
  const checks: SecurityHardeningCheck[] = [
    { id: "anti_debugger_protection", label: "Anti-Debugger Protection", status: "warning", active: false, detail: "Desktop runtime status is unavailable in this context" },
    { id: "anti_tampering_detection", label: "Anti-Tampering Detection", status: "warning", active: false, detail: "Desktop runtime status is unavailable in this context" },
    { id: "binary_integrity_verification", label: "Binary Integrity Verification", status: "warning", active: false, detail: "Desktop binary measurement is unavailable in this context" },
    { id: "signed_build_verification", label: "Signed Build Verification", status: "warning", active: false, detail: "Release signing marker is not configured" },
    { id: "runtime_integrity_hash_checks", label: "Integrity Hash Checks", status: "warning", active: false, detail: "Desktop SHA3-256 runtime hash check is unavailable in this context" },
    { id: "secure_memory_zeroize", label: "Secure Memory (zeroize)", status: "active", active: true, detail: "Key cleanup paths are compiled into the desktop backend" },
    { id: "tamper_evident_audit_chain", label: "Tamper-Evident Audit Chain", status: "warning", active: false, detail: "Desktop audit chain status is unavailable in this context" },
    { id: "post_quantum_protection", label: "Post-Quantum Protection (FIPS 203/204)", status: "active", active: true, detail: "Hybrid PQC suite is configured" },
    { id: "rate_limiting", label: "Rate Limiting", status: "active", active: true, detail: "Profile action rate-limit RPC is configured" },
    { id: "code_obfuscation", label: "Code Obfuscation", status: releaseBuild ? "active" : "warning", active: releaseBuild, detail: releaseBuild ? "Production web bundle is minified and sourcemaps are disabled" : "Development build keeps readable symbols" },
    { id: "control_flow_flattening", label: "Control-Flow Flattening", status: "warning", active: false, detail: "Dedicated control-flow flattening marker is not configured" },
    { id: "string_encryption", label: "String Encryption", status: "warning", active: false, detail: "Dedicated string encryption marker is not configured" },
    { id: "tls_transport_policy", label: "Transport Policy (TLS 1.3 + hybrid PQ)", status: "warning", active: false, detail: "Desktop transport policy is unavailable in this context" },
  ];

  return {
    checks,
    debugger_detected: false,
    binary_sha3: null,
    binary_path: null,
    expected_binary_sha3: null,
    build_profile: releaseBuild ? "release" : "debug",
    debug_assertions: !releaseBuild,
    plaintext_logging_disabled: true,
    aead_required: true,
    nonce_uniqueness_checked: true,
    replay_protection_enabled: true,
    strict_cors_required_for_relay: true,
    secure_headers_documented: true,
    dependency_scanning_documented: true,
    anti_debugger_protection: false,
    anti_tampering_detection: false,
    binary_integrity_verification: false,
    secure_memory_zeroize: true,
    tamper_evident_audit_chain: false,
    post_quantum_protection: true,
    rate_limiting: true,
    code_obfuscation: releaseBuild,
    control_flow_flattening: false,
    string_encryption: false,
    signed_build_verification: false,
    integrity_hash_checks: false,
    // Reported, not assumed: outside the desktop shell there is no way to know
    // what the network stack was configured with, and claiming "strict" here
    // would be a posture the app never actually set.
    tls_policy: {
      mode: "compat",
      minimum_version: "unknown",
      post_quantum_key_agreement: false,
      enforced_by_app: false,
      detail: "Desktop transport policy is unavailable in this context",
    },
  };
}

export function runtimeAssetIntegrityCheck(result: RuntimeAssetIntegrity | null): SecurityHardeningCheck {
  if (!result) {
    return {
      id: "web_asset_integrity",
      label: "Web Asset Integrity",
      status: "warning",
      active: false,
      detail: "Runtime web asset hash check is pending",
    };
  }

  return {
    id: "web_asset_integrity",
    label: "Web Asset Integrity",
    status: result.status,
    active: result.verified,
    detail: result.detail,
  };
}

export function mergeRuntimeAssetIntegrity(
  hardening: SecurityHardeningStatus,
  assetIntegrity: RuntimeAssetIntegrity | null,
): SecurityHardeningStatus {
  const runtimeCheck = runtimeAssetIntegrityCheck(assetIntegrity);
  const checks = [
    ...hardening.checks.filter((check) => check.id !== runtimeCheck.id),
    runtimeCheck,
  ];

  return {
    ...hardening,
    checks,
    integrity_hash_checks: hardening.integrity_hash_checks || Boolean(assetIntegrity?.verified),
  };
}

export async function loadSecurityHardeningStatus(): Promise<SecurityHardeningStatus> {
  const now = Date.now();
  if (cachedHardeningStatus && now - cachedHardeningStatus.loadedAt < hardeningCacheTtlMs) {
    return cachedHardeningStatus.status;
  }
  if (hardeningStatusPromise) return hardeningStatusPromise;

  hardeningStatusPromise = Promise.all([
    safeInvoke<SecurityHardeningStatus>("security_hardening_status", {}, fallbackHardeningStatus()),
    verifyRuntimeAssetIntegrity(),
    // What the backend connection actually negotiated, measured through the
    // WebView's own TLS stack. See transport-evidence.ts.
    measureTransport(supabaseUrl),
  ])
    .then(([hardening, assetIntegrity, transport]) => {
      const status = mergeTransportEvidence(mergeRuntimeAssetIntegrity(hardening, assetIntegrity), transport);
      cachedHardeningStatus = { loadedAt: Date.now(), status };
      return status;
    })
    .finally(() => {
      hardeningStatusPromise = null;
    });

  return hardeningStatusPromise;
}
