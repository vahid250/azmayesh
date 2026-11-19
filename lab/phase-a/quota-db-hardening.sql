-- R&MA Stage 10C: database ownership, least privilege, and tenant-scoped quota API.
-- Lab migration only. Production rollout requires a reviewed migration identity and
-- verified JWT claims at the trusted API gateway. The custom GUC below is NOT identity.
DO $$ BEGIN CREATE ROLE rma_data_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE rma_quota_service NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE rma_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

REVOKE rma_data_owner FROM rma_auth_gateway, rma_untrusted_client, rma_quota_service, rma_identity_admin;
REVOKE rma_migrator FROM rma_auth_gateway, rma_untrusted_client, rma_quota_service, rma_identity_admin;
REVOKE rma_identity_admin FROM rma_auth_gateway, rma_untrusted_client, rma_quota_service;

GRANT USAGE, CREATE ON SCHEMA public TO rma_data_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM rma_auth_gateway, rma_untrusted_client, rma_quota_service;
GRANT USAGE ON SCHEMA public TO rma_auth_gateway, rma_quota_service;

ALTER TABLE rma_accounts OWNER TO rma_data_owner;
ALTER TABLE quota_plans OWNER TO rma_data_owner;
ALTER TABLE account_subscriptions OWNER TO rma_data_owner;
ALTER TABLE account_audit_events OWNER TO rma_data_owner;
ALTER TABLE quota_periods OWNER TO rma_data_owner;
ALTER TABLE quota_events OWNER TO rma_data_owner;
ALTER TABLE rma_identity_bindings OWNER TO rma_data_owner;

ALTER FUNCTION create_rma_account(text,text) OWNER TO rma_data_owner;
ALTER FUNCTION set_rma_account_status(text,text,text,text) OWNER TO rma_data_owner;
ALTER FUNCTION create_account_subscription(uuid,text,text,timestamptz,timestamptz) OWNER TO rma_data_owner;
ALTER FUNCTION ensure_current_quota_period(text,timestamptz) OWNER TO rma_data_owner;
ALTER FUNCTION record_quota_usage(uuid,text,text,bigint) OWNER TO rma_data_owner;
ALTER FUNCTION record_account_quota_usage(uuid,text,bigint,timestamptz) OWNER TO rma_data_owner;
ALTER FUNCTION resolve_rma_account(text,text) OWNER TO rma_data_owner;
REVOKE CREATE ON SCHEMA public FROM rma_data_owner;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM rma_auth_gateway, rma_untrusted_client, rma_quota_service;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM rma_auth_gateway, rma_untrusted_client, rma_quota_service;
REVOKE EXECUTE ON FUNCTION create_rma_account(text,text) FROM rma_auth_gateway, rma_untrusted_client, rma_quota_service;
REVOKE EXECUTE ON FUNCTION set_rma_account_status(text,text,text,text) FROM rma_auth_gateway, rma_untrusted_client, rma_quota_service;
REVOKE EXECUTE ON FUNCTION create_account_subscription(uuid,text,text,timestamptz,timestamptz) FROM rma_auth_gateway, rma_untrusted_client, rma_quota_service;
REVOKE EXECUTE ON FUNCTION ensure_current_quota_period(text,timestamptz) FROM rma_auth_gateway, rma_untrusted_client, rma_quota_service;
REVOKE EXECUTE ON FUNCTION record_quota_usage(uuid,text,text,bigint) FROM rma_auth_gateway, rma_untrusted_client, rma_quota_service;
REVOKE EXECUTE ON FUNCTION record_account_quota_usage(uuid,text,bigint,timestamptz) FROM rma_auth_gateway, rma_untrusted_client, rma_quota_service;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE rma_identity_bindings TO rma_identity_admin;
GRANT USAGE ON SCHEMA public TO rma_identity_admin;
GRANT EXECUTE ON FUNCTION resolve_rma_account(text,text) TO rma_auth_gateway;

-- Tenant RLS is defense in depth. Runtime roles have no direct table grants.
ALTER TABLE account_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE account_subscriptions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rma_subscription_tenant_scope ON account_subscriptions;
CREATE POLICY rma_subscription_tenant_scope ON account_subscriptions
 USING (account_id = nullif(current_setting('rma.account_id', true), ''))
 WITH CHECK (account_id = nullif(current_setting('rma.account_id', true), ''));

ALTER TABLE quota_periods ENABLE ROW LEVEL SECURITY;
ALTER TABLE quota_periods FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rma_quota_period_tenant_scope ON quota_periods;
CREATE POLICY rma_quota_period_tenant_scope ON quota_periods
 USING (account_id = nullif(current_setting('rma.account_id', true), ''))
 WITH CHECK (account_id = nullif(current_setting('rma.account_id', true), ''));

ALTER TABLE quota_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE quota_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rma_quota_event_tenant_scope ON quota_events;
CREATE POLICY rma_quota_event_tenant_scope ON quota_events
 USING (account_id = nullif(current_setting('rma.account_id', true), ''))
 WITH CHECK (account_id = nullif(current_setting('rma.account_id', true), ''));

ALTER TABLE account_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE account_audit_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rma_audit_tenant_scope ON account_audit_events;
CREATE POLICY rma_audit_tenant_scope ON account_audit_events
 USING (account_id = nullif(current_setting('rma.account_id', true), ''))
 WITH CHECK (account_id = nullif(current_setting('rma.account_id', true), ''));

CREATE OR REPLACE FUNCTION record_rma_quota_usage_for_identity(
 p_issuer text, p_subject text, p_event_id uuid, p_bytes bigint,
 p_now timestamptz DEFAULT clock_timestamp()
)
RETURNS TABLE(accepted boolean, duplicate boolean, used_bytes bigint, quota_bytes bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = on
AS $$
DECLARE v_account_id text;
BEGIN
 v_account_id := public.resolve_rma_account(p_issuer, p_subject);
 PERFORM set_config('rma.account_id', v_account_id, true);
 RETURN QUERY SELECT x.accepted, x.duplicate, x.used_bytes, x.quota_bytes
   FROM public.record_account_quota_usage(p_event_id, v_account_id, p_bytes, p_now) x;
END;
$$;
ALTER FUNCTION record_rma_quota_usage_for_identity(text,text,uuid,bigint,timestamptz) OWNER TO rma_data_owner;
REVOKE ALL ON FUNCTION record_rma_quota_usage_for_identity(text,text,uuid,bigint,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION record_rma_quota_usage_for_identity(text,text,uuid,bigint,timestamptz) TO rma_quota_service;
