-- R&MA Stage 10B — trusted identity to internal account binding.
-- This migration is a CI/lab contract, not a production auth implementation.
-- The API gateway MUST verify JWT signature, issuer, audience, expiry and claims
-- before invoking resolve_rma_account(). Never accept issuer/subject from an
-- untrusted request body, and never trust client-supplied account_id.
--
-- The gateway role is intentionally unable to read or modify the binding table.
-- Only a separately controlled provisioning/admin path may manage bindings.

CREATE TABLE IF NOT EXISTS rma_identity_bindings (
    issuer text NOT NULL CHECK (length(trim(issuer)) > 0),
    subject text NOT NULL CHECK (length(trim(subject)) > 0),
    account_id text NOT NULL REFERENCES rma_accounts(account_id),
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (issuer, subject)
);

CREATE INDEX IF NOT EXISTS rma_identity_bindings_account_idx
    ON rma_identity_bindings(account_id);

DO $$
BEGIN
    CREATE ROLE rma_auth_gateway NOLOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
    CREATE ROLE rma_untrusted_client NOLOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
    CREATE ROLE rma_identity_admin NOLOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE OR REPLACE FUNCTION resolve_rma_account(
    p_issuer text,
    p_subject text
)
RETURNS text
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_account_id text;
BEGIN
    IF length(trim(coalesce(p_issuer, ''))) = 0
       OR length(trim(coalesce(p_subject, ''))) = 0 THEN
        RAISE EXCEPTION 'verified identity is required'
            USING ERRCODE = '28000';
    END IF;

    SELECT b.account_id
      INTO v_account_id
      FROM public.rma_identity_bindings b
      JOIN public.rma_accounts a ON a.account_id = b.account_id
     WHERE b.issuer = p_issuer
       AND b.subject = p_subject
       AND b.status = 'active'
       AND a.status = 'active';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity has no active account binding'
            USING ERRCODE = '28000';
    END IF;

    RETURN v_account_id;
END;
$$;

REVOKE ALL ON TABLE rma_identity_bindings FROM PUBLIC;
REVOKE ALL ON FUNCTION resolve_rma_account(text, text) FROM PUBLIC;
REVOKE ALL ON TABLE rma_identity_bindings FROM rma_auth_gateway;
REVOKE ALL ON TABLE rma_identity_bindings FROM rma_untrusted_client;
REVOKE ALL ON FUNCTION resolve_rma_account(text, text) FROM rma_untrusted_client;

GRANT EXECUTE ON FUNCTION resolve_rma_account(text, text) TO rma_auth_gateway;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE rma_identity_bindings TO rma_identity_admin;

-- Production hardening checklist:
-- 1. Bind rma_identity_admin to a separate, audited provisioning process.
-- 2. Grant rma_auth_gateway only to the trusted backend workload identity.
-- 3. The backend must verify JWT signature + iss + aud + exp + nbf before calling.
-- 4. Never expose this SQL function to a browser/mobile client or PostgREST role.
-- 5. A compromised gateway can still call this function with fabricated identity
--    arguments; use a separately verified identity boundary and short-lived,
--    non-forgeable service credentials. This SQL layer is defense in depth only.
-- 6. Production deployment requires review of role ownership, schema privileges,
--    connection credentials, and actual auth-provider integration.
