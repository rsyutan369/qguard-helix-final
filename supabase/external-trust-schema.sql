-- ============================================================
-- QGuard Helix — External Trust & Ecosystem Suite
-- ============================================================
-- Adds the two entities the External Trust suite needs that the platform
-- does not already model:
--
--   1. vendor_evidence_requests   — the vendor evidence request workflow
--                                   (Requested → Vendor Responded → Evidence
--                                   Received → Under Review → Accepted/Rejected)
--   2. hybrid_crypto_experiments  — Hybrid Crypto Lab experiment records
--
-- Everything else the suite renders is derived from tables that already exist
-- (assets, certificates, crypto_inventory, asset_relationships, connector_accounts,
-- vendor_assessments, runtime_crypto_events, scanner_evidence, trust_state_findings).
--
-- The API degrades gracefully when this file has NOT been applied: the evidence
-- workflow and experiment history read as empty with an explicit
-- "backend capability not provisioned" state rather than fabricating rows.
--
-- Apply with:  psql "$DATABASE_URL" -f supabase/external-trust-schema.sql
--          or: paste into the Supabase SQL editor.
-- Safe to re-run (idempotent).
-- ============================================================

-- ============================================================
-- 1. VENDOR EVIDENCE REQUESTS
-- ============================================================
CREATE TABLE IF NOT EXISTS vendor_evidence_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    -- Vendor identity is stored by name + stable slug because vendors are
    -- derived from evidence (catalog attribution, connectors, certificate
    -- issuers) and do not all have a vendor_assessments row.
    vendor_id VARCHAR(160) NOT NULL,
    vendor_name VARCHAR(255) NOT NULL,
    vendor_assessment_id UUID REFERENCES vendor_assessments(id) ON DELETE SET NULL,

    -- pqc-roadmap, algorithm-support-matrix, tls-pqc-statement, certificate-roadmap,
    -- key-management-roadmap, crypto-architecture, migration-timeline,
    -- product-version-support, security-compliance-docs
    request_type VARCHAR(80) NOT NULL,

    -- requested, vendor-responded, evidence-received, under-review, accepted, rejected
    stage VARCHAR(40) NOT NULL DEFAULT 'requested',

    owner VARCHAR(255),
    reviewer VARCHAR(255),
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    due_at TIMESTAMP WITH TIME ZONE,
    responded_at TIMESTAMP WITH TIME ZONE,
    reviewed_at TIMESTAMP WITH TIME ZONE,

    response_summary TEXT,
    -- Reference/URI to the supplied artefact. Never store credentials or secrets.
    evidence_ref TEXT,
    notes TEXT,
    metadata JSONB DEFAULT '{}',

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT vendor_evidence_requests_stage_check CHECK (
        stage IN ('requested', 'vendor-responded', 'evidence-received', 'under-review', 'accepted', 'rejected')
    )
);

ALTER TABLE vendor_evidence_requests ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS vendor_evidence_requests_user_isolation ON vendor_evidence_requests;
CREATE POLICY vendor_evidence_requests_user_isolation ON vendor_evidence_requests
    FOR ALL
    USING (user_id = auth.uid())
    WITH CHECK (user_id = auth.uid());

CREATE INDEX IF NOT EXISTS idx_ver_user ON vendor_evidence_requests(user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_ver_vendor ON vendor_evidence_requests(user_id, vendor_id);
CREATE INDEX IF NOT EXISTS idx_ver_stage ON vendor_evidence_requests(user_id, stage);
CREATE INDEX IF NOT EXISTS idx_ver_due ON vendor_evidence_requests(user_id, due_at)
    WHERE stage NOT IN ('accepted', 'rejected');

-- ============================================================
-- 2. HYBRID CRYPTO LAB EXPERIMENTS
-- ============================================================
CREATE TABLE IF NOT EXISTS hybrid_crypto_experiments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,

    target_label VARCHAR(255) NOT NULL,
    target_host VARCHAR(255),
    target_port INTEGER DEFAULT 443,
    environment VARCHAR(80),
    vendor_id VARCHAR(160),

    -- simulation      = evidence projection, no connection is made
    -- controlled-test = live READ-ONLY handshake probe against a public host
    -- No mode of this table ever mutates a production system.
    execution_mode VARCHAR(40) NOT NULL DEFAULT 'simulation',

    -- passed, passed-with-warnings, conditional, failed, not-evaluated
    outcome VARCHAR(40) NOT NULL DEFAULT 'not-evaluated',
    risk VARCHAR(20) DEFAULT 'unknown',
    duration_ms INTEGER DEFAULT 0,

    -- Full experiment specification: target, current + proposed configuration.
    payload JSONB NOT NULL DEFAULT '{}',
    -- Per-dimension checks, findings and the derivation basis.
    result JSONB NOT NULL DEFAULT '{}',

    -- Set when the operator explicitly generates an evidence record.
    evidence_id UUID REFERENCES compliance_evidence(id) ON DELETE SET NULL,

    created_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT hybrid_crypto_experiments_mode_check CHECK (
        execution_mode IN ('simulation', 'controlled-test')
    ),
    CONSTRAINT hybrid_crypto_experiments_outcome_check CHECK (
        outcome IN ('passed', 'passed-with-warnings', 'conditional', 'failed', 'not-evaluated')
    )
);

ALTER TABLE hybrid_crypto_experiments ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS hybrid_crypto_experiments_user_isolation ON hybrid_crypto_experiments;
CREATE POLICY hybrid_crypto_experiments_user_isolation ON hybrid_crypto_experiments
    FOR ALL
    USING (user_id = auth.uid())
    WITH CHECK (user_id = auth.uid());

CREATE INDEX IF NOT EXISTS idx_hce_user ON hybrid_crypto_experiments(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_hce_asset ON hybrid_crypto_experiments(asset_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_hce_outcome ON hybrid_crypto_experiments(user_id, outcome);
CREATE INDEX IF NOT EXISTS idx_hce_vendor ON hybrid_crypto_experiments(user_id, vendor_id);

-- ============================================================
-- 3. REALTIME
-- ============================================================
-- Wrapped so re-running the file cannot fail on an already-published table.
DO $$
BEGIN
    BEGIN
        ALTER PUBLICATION supabase_realtime ADD TABLE vendor_evidence_requests;
    EXCEPTION WHEN duplicate_object THEN NULL;
    END;
    BEGIN
        ALTER PUBLICATION supabase_realtime ADD TABLE hybrid_crypto_experiments;
    EXCEPTION WHEN duplicate_object THEN NULL;
    END;
END $$;
