-- Upgrade future QGuard Messaging device and Quantum Vault metadata defaults to ML-KEM-1024.
-- Existing rows are not relabeled because their stored public keys/packages may have been
-- generated under the earlier ML-KEM-768 suite.

ALTER TABLE IF EXISTS public.messaging_devices
  ALTER COLUMN suite SET DEFAULT '{"classical_kex":"X25519","pq_kem":"ML-KEM-1024","kdf":"HKDF-SHA3-256","symmetric":"AES-256-GCM","classical_signature":"Ed25519","pq_signature":"ML-DSA-65"}'::jsonb;

ALTER TABLE IF EXISTS public.messaging_device_link_requests
  ALTER COLUMN requested_suite SET DEFAULT '{"classical_kex":"X25519","pq_kem":"ML-KEM-1024","kdf":"HKDF-SHA3-256","symmetric":"AES-256-GCM","classical_signature":"Ed25519","pq_signature":"ML-DSA-65"}'::jsonb;

ALTER TABLE IF EXISTS public.qguard_vault_operations
  ALTER COLUMN algorithm SET DEFAULT 'ML-KEM-1024 + X25519 + HKDF-SHA3-256 + AES-256-GCM + ML-DSA-65 + Ed25519';
