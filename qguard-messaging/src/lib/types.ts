export type Page =
  | "dashboard"
  | "chat"
  | "vault"
  | "keys"
  | "devices"
  | "verification"
  | "audit"
  | "quantum"
  | "admin"
  | "subscription"
  | "settings";

export interface DashboardSnapshot {
  e2ee_status: string;
  pqc_status: string;
  active_sessions: number;
  vault_storage: string;
  device_count: number;
  quantum_safe_score: number;
  hndl_status: string;
}

export interface Profile {
  id: string;
  email: string;
  name: string | null;
  username: string | null;
  avatar_storage_path: string | null;
  avatar_updated_at: string | null;
  tier: string;
  q_score: number | null;
  vault_storage_used: number | null;
  max_vault_storage: number | null;
}

export interface MessagingModule {
  module_id: Page;
  label: string;
  icon: string;
  route: Page;
  enabled: boolean;
  sort_order: number;
}

export interface KeyInventory {
  identity_device_count: number;
  active_signed_prekeys: number;
  available_one_time_prekeys: number;
  next_signed_prekey_expiry: string | null;
  rotation_events: number;
  algorithms: string[];
}

export interface ConversationSummary {
  id: string;
  conversation_type: string;
  title: string;
  last_activity: string;
  unread_count: number;
  updated_at: string;
  member_user_ids: string[];
  archived_at: string | null;
  hidden_at: string | null;
  deleted_at: string | null;
}

export interface ContactSummary {
  id: string;
  contact_user_id: string;
  alias: string | null;
  display_name: string;
  username: string;
  trust_state: "added" | "blocked" | "removed";
  created_at: string;
  updated_at: string;
}

export interface UserSearchResult {
  user_id: string;
  display_name: string;
  username: string;
}

export interface VaultFileSummary {
  id: string;
  storage_path: string;
  display_name_hint?: string | null;
  size_bytes: number;
  content_type: string;
  suite: Record<string, unknown>;
  created_at: string;
  revoked_at: string | null;
}

export interface SecurityEvent {
  id: string;
  device_id?: string | null;
  event_type: string;
  severity: "info" | "warning" | "critical";
  encrypted_details?: Record<string, unknown> | null;
  event_hash: string;
  previous_hash: string | null;
  created_at: string;
}

export interface OrgMemberSummary {
  org_id: string;
  user_id: string;
  role: string;
  created_at: string;
}

export interface TelemetryEvent {
  id: string;
  stage: string;
  detail: string;
  progress: number;
  created_at: string;
}

export interface DualSignature {
  ed25519: number[];
  ml_dsa_65: number[];
}

export interface SignedPrekeySummary {
  prekey_id: string;
  x25519_public: number[];
  mlkem_public: number[];
  signature: DualSignature;
  fingerprint: string;
  expires_at?: string;
}

export interface TrustedDevice {
  device_id: string;
  user_id: string;
  label: string;
  fingerprint: string;
  trust_state: "ThisDevice" | "Trusted" | "PendingQrApproval" | "Revoked" | "Suspicious";
  pqc_status: string;
  suite: Record<string, unknown>;
  last_seen_at: string;
  created_at: string;
  revoked_at: string | null;
  approved_by_device_id: string | null;
  x25519_identity_public: number[];
  mlkem_identity_public: number[];
  ed25519_identity_public: number[];
  mldsa_identity_public: number[];
  identity_signature: DualSignature | null;
  signed_prekey: SignedPrekeySummary | null;
}

export interface QuantumSecurityReport {
  hybrid_session_status: string;
  pqc_algorithm: string;
  forward_secrecy: string;
  hndl_protection: string;
  quantum_safe_score: number;
  key_rotation_history: string[];
  warnings: string[];
}

export interface SecurityHardeningCheck {
  id: string;
  label: string;
  status: "active" | "warning" | "failed";
  active: boolean;
  detail: string;
}

export interface SecurityHardeningStatus {
  checks: SecurityHardeningCheck[];
  debugger_detected: boolean;
  binary_sha3: string | null;
  binary_path: string | null;
  expected_binary_sha3: string | null;
  build_profile: string;
  debug_assertions: boolean;
  plaintext_logging_disabled: boolean;
  aead_required: boolean;
  nonce_uniqueness_checked: boolean;
  replay_protection_enabled: boolean;
  strict_cors_required_for_relay: boolean;
  secure_headers_documented: boolean;
  dependency_scanning_documented: boolean;
  anti_debugger_protection: boolean;
  anti_tampering_detection: boolean;
  binary_integrity_verification: boolean;
  secure_memory_zeroize: boolean;
  tamper_evident_audit_chain: boolean;
  post_quantum_protection: boolean;
  rate_limiting: boolean;
  code_obfuscation: boolean;
  control_flow_flattening: boolean;
  string_encryption: boolean;
  signed_build_verification: boolean;
  integrity_hash_checks: boolean;
}

export interface DashboardData {
  profile: Profile | null;
  modules: MessagingModule[];
  devices: TrustedDevice[];
  contacts: ContactSummary[];
  conversations: ConversationSummary[];
  vaultFiles: VaultFileSummary[];
  securityEvents: SecurityEvent[];
  orgMembers: OrgMemberSummary[];
  keyInventory: KeyInventory;
  telemetry: TelemetryEvent[];
  hardening: SecurityHardeningStatus;
  snapshot: DashboardSnapshot;
  report: QuantumSecurityReport;
}
