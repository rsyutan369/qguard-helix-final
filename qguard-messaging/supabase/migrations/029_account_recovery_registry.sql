-- Account-level vault recovery registry (Unify_Syncronization).
--
-- The Quantum Vault recovery key used to be DEVICE-local: every device could
-- generate its own key, a fresh device had no way to tell whether a typed key
-- was really the account's key (only the checksum was validated), and
-- "reset vault with recovery key" failed on any device that did not create
-- the key. This registry makes the recovery key ACCOUNT-based — one recovery
-- key per QGuard account, valid on every trusted device — per the unified
-- multi-device design:
--
--   * Stores ONLY the one-way verifier of the recovery root
--     (HKDF-SHA3-256-derived, then hashed; computed on-device in Rust) plus
--     mode metadata. The recovery key itself never leaves the device, and
--     vault CONTENTS stay device-local and are never synchronized.
--   * Any signed-in device validates a typed recovery key against the account
--     verifier before enabling it locally or resetting its vault lock, and
--     the Vault UI steers additional devices to "enable the existing key"
--     instead of generating a second, conflicting key.
--
-- Threat note: the verifier is a non-invertible commitment; possessing it
-- does not help recover files. A malicious backend could only lie about the
-- verifier, which either rejects a correct key (denial of service) or skips
-- the typo check — it can never decrypt vault contents or mint a valid key.

CREATE TABLE IF NOT EXISTS public.messaging_account_recovery (
  user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  mode TEXT NOT NULL CHECK (mode IN ('personal', 'enterprise', 'hybrid')),
  verifier TEXT NOT NULL,
  recipient_key_id TEXT,
  configured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.messaging_account_recovery ENABLE ROW LEVEL SECURITY;

-- Owner-only in every direction: the verifier is not secret-bearing, but no
-- other account has any reason to read or write it.
DROP POLICY IF EXISTS "account recovery owner select" ON public.messaging_account_recovery;
CREATE POLICY "account recovery owner select" ON public.messaging_account_recovery
  FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "account recovery owner insert" ON public.messaging_account_recovery;
CREATE POLICY "account recovery owner insert" ON public.messaging_account_recovery
  FOR INSERT WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "account recovery owner update" ON public.messaging_account_recovery;
CREATE POLICY "account recovery owner update" ON public.messaging_account_recovery
  FOR UPDATE USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "account recovery owner delete" ON public.messaging_account_recovery;
CREATE POLICY "account recovery owner delete" ON public.messaging_account_recovery
  FOR DELETE USING (auth.uid() = user_id);

-- Realtime: other signed-in devices see recovery status changes instantly
-- (e.g. Desktop configures the key, Android's vault status flips to
-- "account recovery key active" without a manual refresh).
DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_account_recovery;
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;
