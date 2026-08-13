-- ============================================================
-- QGuard Helix — PQAuth Identity Discovery schema
-- ============================================================
--
-- Adds the structured identity inventory the PQAuth Identity Migration Engine
-- needs. Before this, no identity table existed: PQAuth built its "identity
-- inventory" by regex-matching the text of generic crypto rows, which
-- classified a TLS test domain as an identity asset and reported an identity
-- provider the tenant did not have.
--
-- Everything here is DISCOVERED EVIDENCE, keyed by the protocol's own primary
-- key (the OIDC `issuer` / SAML `entityID`), so a re-scan updates a provider
-- rather than duplicating it.
--
-- Metadata only. Never token contents, never private key material — a JWKS
-- publishes public keys by design, and only public parameters are stored.
--
-- Apply with:  psql "$DATABASE_URL" -f supabase/pqauth-identity-schema.sql
-- Idempotent: safe to re-run.
-- ============================================================

-- ------------------------------------------------------------
-- 1. IDENTITY PROVIDERS
--    One row per discovered issuer (OIDC / OAuth 2.0 AS / SAML IdP).
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS identity_providers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    -- The asset the provider was discovered from, when it maps to one.
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,

    -- The protocol's own identity. OIDC `issuer`, SAML `entityID`.
    issuer TEXT NOT NULL,
    protocol VARCHAR(16) NOT NULL DEFAULT 'oidc',   -- oidc | oauth2 | saml2
    display_name VARCHAR(255),
    -- Named ONLY when the issuer host proves the vendor. NULL is the honest
    -- default; the audit found a vendor invented from a keyword match.
    vendor VARCHAR(120),
    host VARCHAR(255),

    -- Advertised capability. "Supported" is not "in use" — the distinction is
    -- preserved because a provider that CAN do ML-DSA is not one that DOES.
    signing_algorithms_supported TEXT[] DEFAULT '{}',
    key_encryption_algorithms_supported TEXT[] DEFAULT '{}',
    content_encryption_algorithms_supported TEXT[] DEFAULT '{}',
    grant_types_supported TEXT[] DEFAULT '{}',
    response_types_supported TEXT[] DEFAULT '{}',
    scopes_supported TEXT[] DEFAULT '{}',

    jwks_uri TEXT,
    endpoints JSONB DEFAULT '[]',

    -- Worst posture across the signing primitives ACTUALLY observed in the
    -- JWKS, falling back to advertised support only when no JWKS was read.
    quantum_class VARCHAR(16) NOT NULL DEFAULT 'unknown', -- safe|hybrid|vulnerable|unknown

    -- Provenance: the exact URL the record was read from.
    source_url TEXT,
    discovery_method VARCHAR(40),
    http_status INTEGER,

    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

ALTER TABLE identity_providers ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS identity_providers_user_isolation ON identity_providers;
CREATE POLICY identity_providers_user_isolation ON identity_providers
    FOR ALL
    USING (user_id = auth.uid())
    WITH CHECK (user_id = auth.uid());

CREATE INDEX IF NOT EXISTS idx_identity_providers_user ON identity_providers(user_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_identity_providers_asset ON identity_providers(asset_id);
CREATE INDEX IF NOT EXISTS idx_identity_providers_class ON identity_providers(user_id, quantum_class);
-- Re-scanning the same issuer UPDATES it. Without this the inventory would
-- grow by one duplicate provider per scan.
CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_providers_user_issuer
    ON identity_providers(user_id, issuer);

-- ------------------------------------------------------------
-- 2. IDENTITY SIGNING KEYS
--    Public JWKS keys. These are what actually sign tokens.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS identity_signing_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,

    key_id VARCHAR(255) NOT NULL,           -- JWKS `kid`
    key_type VARCHAR(16) NOT NULL,          -- RSA | EC | OKP | oct
    -- NULL when the JWKS did not state one. Never invented.
    algorithm VARCHAR(64),
    key_use VARCHAR(16) NOT NULL DEFAULT 'unspecified', -- signature|encryption|unspecified
    key_size INTEGER,
    curve VARCHAR(32),

    -- Classification of THIS key's primitive.
    quantum_class VARCHAR(16) NOT NULL DEFAULT 'unknown',
    -- signature | key-encapsulation | symmetric | hash | unknown.
    -- Kept explicit so a signature key can never be given an ML-KEM target.
    crypto_purpose VARCHAR(24) NOT NULL DEFAULT 'unknown',
    pqc_target VARCHAR(120),
    standard VARCHAR(40),
    rationale TEXT,

    source_url TEXT,
    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

ALTER TABLE identity_signing_keys ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS identity_signing_keys_user_isolation ON identity_signing_keys;
CREATE POLICY identity_signing_keys_user_isolation ON identity_signing_keys
    FOR ALL
    USING (user_id = auth.uid())
    WITH CHECK (user_id = auth.uid());

CREATE INDEX IF NOT EXISTS idx_identity_signing_keys_user ON identity_signing_keys(user_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_identity_signing_keys_provider ON identity_signing_keys(provider_id);
CREATE INDEX IF NOT EXISTS idx_identity_signing_keys_class ON identity_signing_keys(user_id, quantum_class);
-- A kid is unique within its provider, not globally: two providers may both
-- publish "sig-1" and they are different keys.
CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_signing_keys_provider_kid
    ON identity_signing_keys(provider_id, key_id);

-- ------------------------------------------------------------
-- 3. IDENTITY TRUST RELATIONSHIPS
--    Who trusts whom, and for what. Powers the Trust Fabric graph.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS identity_trust_relationships (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,

    -- Either end may be a provider or an asset; exactly one column per end is
    -- populated. Kept as separate nullable FKs rather than a polymorphic id so
    -- the database enforces referential integrity.
    source_provider_id UUID REFERENCES identity_providers(id) ON DELETE CASCADE,
    source_asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,
    target_provider_id UUID REFERENCES identity_providers(id) ON DELETE CASCADE,
    target_asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,

    -- ISSUES_TOKEN | VALIDATES_TOKEN | SIGNS | TRUSTS | FEDERATES_WITH |
    -- AUTHENTICATES | AUTHORIZES | USES_KEY | ROUTES_TO | DEPENDS_ON
    relationship_type VARCHAR(40) NOT NULL,
    protocol VARCHAR(16),

    -- How the relationship was established. A relationship with no evidence is
    -- not written at all.
    evidence TEXT,
    source_url TEXT,
    confidence VARCHAR(16) NOT NULL DEFAULT 'observed', -- observed | declared | inferred

    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT identity_trust_source_present
        CHECK (source_provider_id IS NOT NULL OR source_asset_id IS NOT NULL),
    CONSTRAINT identity_trust_target_present
        CHECK (target_provider_id IS NOT NULL OR target_asset_id IS NOT NULL)
);

ALTER TABLE identity_trust_relationships ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS identity_trust_relationships_user_isolation ON identity_trust_relationships;
CREATE POLICY identity_trust_relationships_user_isolation ON identity_trust_relationships
    FOR ALL
    USING (user_id = auth.uid())
    WITH CHECK (user_id = auth.uid());

CREATE INDEX IF NOT EXISTS idx_identity_trust_user ON identity_trust_relationships(user_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_identity_trust_source_provider ON identity_trust_relationships(source_provider_id);
CREATE INDEX IF NOT EXISTS idx_identity_trust_target_provider ON identity_trust_relationships(target_provider_id);
CREATE INDEX IF NOT EXISTS idx_identity_trust_source_asset ON identity_trust_relationships(source_asset_id);
CREATE INDEX IF NOT EXISTS idx_identity_trust_target_asset ON identity_trust_relationships(target_asset_id);

-- ------------------------------------------------------------
-- 4. IDENTITY DISCOVERY PROBES
--    Every probe that RAN, including the ones that found nothing.
--
--    This table is what lets the UI distinguish "no identity infrastructure
--    exists here" from "we never looked" — the difference between proof of
--    absence and absence of evidence. Without it, an empty inventory is
--    ambiguous and the page cannot honestly say which it is.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS identity_discovery_probes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,
    scan_session_id UUID,

    probe_url TEXT NOT NULL,
    method VARCHAR(40) NOT NULL,   -- oidc-discovery | oauth-as-metadata | jwks | saml-metadata
    http_status INTEGER,
    -- found | not-found | unparseable | error
    outcome VARCHAR(24) NOT NULL,
    detail TEXT,

    observed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

ALTER TABLE identity_discovery_probes ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS identity_discovery_probes_user_isolation ON identity_discovery_probes;
CREATE POLICY identity_discovery_probes_user_isolation ON identity_discovery_probes
    FOR ALL
    USING (user_id = auth.uid())
    WITH CHECK (user_id = auth.uid());

CREATE INDEX IF NOT EXISTS idx_identity_probes_user ON identity_discovery_probes(user_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_identity_probes_asset ON identity_discovery_probes(asset_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_identity_probes_session ON identity_discovery_probes(scan_session_id);

-- ------------------------------------------------------------
-- 5. REALTIME
--    PQAuth subscribes to these tables so a scan updates the UI live.
--    Wrapped because adding a table twice raises.
-- ------------------------------------------------------------
DO $$
BEGIN
    BEGIN ALTER PUBLICATION supabase_realtime ADD TABLE identity_providers; EXCEPTION WHEN duplicate_object THEN NULL; END;
    BEGIN ALTER PUBLICATION supabase_realtime ADD TABLE identity_signing_keys; EXCEPTION WHEN duplicate_object THEN NULL; END;
    BEGIN ALTER PUBLICATION supabase_realtime ADD TABLE identity_trust_relationships; EXCEPTION WHEN duplicate_object THEN NULL; END;
    BEGIN ALTER PUBLICATION supabase_realtime ADD TABLE identity_discovery_probes; EXCEPTION WHEN duplicate_object THEN NULL; END;
EXCEPTION WHEN undefined_object THEN
    RAISE NOTICE 'supabase_realtime publication not present; skipping realtime registration';
END $$;
