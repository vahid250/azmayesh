-- R&MA Phase A / Stage 9
-- Account state, subscription entitlements, and monthly quota-period provisioning.
-- Identity authentication is intentionally delegated to a future trusted auth layer.
-- Never pass an unverified client-supplied account_id to these functions in production.

CREATE TABLE IF NOT EXISTS rma_accounts (
    account_id text PRIMARY KEY,
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'closed')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS quota_plans (
    plan_code text PRIMARY KEY,
    quota_bytes bigint NOT NULL CHECK (quota_bytes > 0),
    period_kind text NOT NULL DEFAULT 'calendar_month'
        CHECK (period_kind = 'calendar_month'),
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS account_subscriptions (
    subscription_id uuid PRIMARY KEY,
    account_id text NOT NULL REFERENCES rma_accounts(account_id),
    plan_code text NOT NULL REFERENCES quota_plans(plan_code),
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'cancelled')),
    starts_at timestamptz NOT NULL,
    ends_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (ends_at > starts_at)
);

CREATE INDEX IF NOT EXISTS account_subscriptions_lookup_idx
    ON account_subscriptions(account_id, starts_at DESC, ends_at)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS account_audit_events (
    audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id text NOT NULL REFERENCES rma_accounts(account_id),
    actor_id text NOT NULL,
    action text NOT NULL CHECK (action IN ('account_created', 'suspended', 'resumed', 'closed')),
    reason text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION create_rma_account(p_account_id text, p_actor_id text)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    IF length(trim(coalesce(p_account_id, ''))) = 0
       OR length(trim(coalesce(p_actor_id, ''))) = 0 THEN
        RAISE EXCEPTION 'account_id and actor_id are required';
    END IF;
    INSERT INTO rma_accounts(account_id) VALUES (p_account_id);
    INSERT INTO account_audit_events(account_id, actor_id, action, reason)
    VALUES (p_account_id, p_actor_id, 'account_created', 'account provisioned');
END;
$$;

CREATE OR REPLACE FUNCTION set_rma_account_status(
    p_account_id text,
    p_new_status text,
    p_actor_id text,
    p_reason text
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v_old_status text;
    v_action text;
BEGIN
    IF p_new_status NOT IN ('active', 'suspended', 'closed') THEN
        RAISE EXCEPTION 'invalid account status';
    END IF;
    IF length(trim(coalesce(p_actor_id, ''))) = 0
       OR length(trim(coalesce(p_reason, ''))) = 0 THEN
        RAISE EXCEPTION 'actor_id and reason are required';
    END IF;

    SELECT status INTO v_old_status
      FROM rma_accounts WHERE account_id = p_account_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'account not found';
    END IF;
    IF v_old_status = p_new_status THEN
        RETURN;
    END IF;
    IF v_old_status = 'closed' THEN
        RAISE EXCEPTION 'closed accounts cannot be reactivated';
    END IF;
    IF v_old_status = 'active' AND p_new_status = 'closed' THEN
        v_action := 'closed';
    ELSIF p_new_status = 'suspended' THEN
        v_action := 'suspended';
    ELSIF v_old_status = 'suspended' AND p_new_status = 'active' THEN
        v_action := 'resumed';
    ELSE
        RAISE EXCEPTION 'unsupported account status transition';
    END IF;

    UPDATE rma_accounts
       SET status = p_new_status, updated_at = clock_timestamp()
     WHERE account_id = p_account_id;
    INSERT INTO account_audit_events(account_id, actor_id, action, reason)
    VALUES (p_account_id, p_actor_id, v_action, p_reason);
END;
$$;

CREATE OR REPLACE FUNCTION create_account_subscription(
    p_subscription_id uuid,
    p_account_id text,
    p_plan_code text,
    p_starts_at timestamptz,
    p_ends_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    IF p_ends_at <= p_starts_at THEN
        RAISE EXCEPTION 'subscription end must be after start';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rma_accounts WHERE account_id = p_account_id) THEN
        RAISE EXCEPTION 'account not found';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM quota_plans WHERE plan_code = p_plan_code AND active) THEN
        RAISE EXCEPTION 'plan not found or inactive';
    END IF;
    INSERT INTO account_subscriptions(subscription_id, account_id, plan_code, starts_at, ends_at)
    VALUES (p_subscription_id, p_account_id, p_plan_code, p_starts_at, p_ends_at);
END;
$$;

CREATE OR REPLACE FUNCTION ensure_current_quota_period(
    p_account_id text,
    p_now timestamptz DEFAULT clock_timestamp()
)
RETURNS TABLE(period_key text, quota_bytes bigint, used_bytes bigint)
LANGUAGE plpgsql
AS $$
DECLARE
    v_account_status text;
    v_plan_code text;
    v_quota bigint;
    v_period_key text;
BEGIN
    SELECT a.status INTO v_account_status
      FROM rma_accounts a
     WHERE a.account_id = p_account_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'account not found';
    END IF;
    IF v_account_status <> 'active' THEN
        RAISE EXCEPTION 'account is not active';
    END IF;

    SELECT s.plan_code, p.quota_bytes
      INTO v_plan_code, v_quota
      FROM account_subscriptions s
      JOIN quota_plans p ON p.plan_code = s.plan_code AND p.active
     WHERE s.account_id = p_account_id
       AND s.status = 'active'
       AND s.starts_at <= p_now
       AND s.ends_at > p_now
     ORDER BY s.starts_at DESC, s.created_at DESC
     LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no active subscription entitlement';
    END IF;

    v_period_key := to_char(p_now AT TIME ZONE 'UTC', 'YYYY-MM');
    INSERT INTO quota_periods(account_id, period_key, quota_bytes)
    VALUES (p_account_id, v_period_key, v_quota)
    ON CONFLICT ON CONSTRAINT quota_periods_pkey DO NOTHING;

    RETURN QUERY
    SELECT qp.period_key, qp.quota_bytes, qp.used_bytes
      FROM quota_periods qp
     WHERE qp.account_id = p_account_id
       AND qp.period_key = v_period_key;
END;
$$;

CREATE OR REPLACE FUNCTION record_account_quota_usage(
    p_event_id uuid,
    p_account_id text,
    p_bytes bigint,
    p_now timestamptz DEFAULT clock_timestamp()
)
RETURNS TABLE(accepted boolean, duplicate boolean, used_bytes bigint, quota_bytes bigint)
LANGUAGE plpgsql
AS $$
DECLARE
    v_period_key text;
BEGIN
    SELECT x.period_key INTO v_period_key
      FROM ensure_current_quota_period(p_account_id, p_now) x;
    RETURN QUERY
    SELECT r.accepted, r.duplicate, r.used_bytes, r.quota_bytes
      FROM record_quota_usage(p_event_id, p_account_id, v_period_key, p_bytes) r;
END;
$$;

-- NOTE: production deployment must revoke direct table/function access from client roles
-- and grant only narrowly scoped API-role execution after trusted identity verification.
