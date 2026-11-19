-- R&MA Phase A / Stage 8
-- Durable, idempotent quota accounting. PostgreSQL is the source of truth.
CREATE TABLE IF NOT EXISTS quota_periods (
    account_id   text   NOT NULL,
    period_key   text   NOT NULL,
    quota_bytes  bigint NOT NULL CHECK (quota_bytes >= 0),
    used_bytes   bigint NOT NULL DEFAULT 0 CHECK (used_bytes >= 0 AND used_bytes <= quota_bytes),
    updated_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (account_id, period_key)
);

CREATE TABLE IF NOT EXISTS quota_events (
    event_id     uuid PRIMARY KEY,
    account_id   text NOT NULL,
    period_key   text NOT NULL,
    bytes        bigint NOT NULL CHECK (bytes > 0),
    status       text NOT NULL CHECK (status IN ('pending', 'accepted', 'denied')),
    created_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (account_id, period_key)
        REFERENCES quota_periods (account_id, period_key)
);

CREATE INDEX IF NOT EXISTS quota_events_account_period_idx
    ON quota_events (account_id, period_key, created_at);

CREATE OR REPLACE FUNCTION record_quota_usage(
    p_event_id uuid,
    p_account_id text,
    p_period_key text,
    p_bytes bigint
)
RETURNS TABLE (
    accepted boolean,
    duplicate boolean,
    used_bytes bigint,
    quota_bytes bigint
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_inserted integer;
    v_existing quota_events%ROWTYPE;
    v_used bigint;
    v_quota bigint;
BEGIN
    IF p_bytes IS NULL OR p_bytes <= 0 THEN
        RAISE EXCEPTION 'bytes must be a positive integer';
    END IF;

    INSERT INTO quota_events(event_id, account_id, period_key, bytes, status)
    VALUES (p_event_id, p_account_id, p_period_key, p_bytes, 'pending')
    ON CONFLICT (event_id) DO NOTHING;

    GET DIAGNOSTICS v_inserted = ROW_COUNT;

    IF v_inserted = 0 THEN
        SELECT * INTO v_existing FROM quota_events WHERE event_id = p_event_id;
        IF v_existing.account_id <> p_account_id
           OR v_existing.period_key <> p_period_key
           OR v_existing.bytes <> p_bytes THEN
            RAISE EXCEPTION 'idempotency key reused with different request data';
        END IF;
        SELECT qp.used_bytes, qp.quota_bytes
          INTO v_used, v_quota
          FROM quota_periods qp
         WHERE qp.account_id = p_account_id AND qp.period_key = p_period_key;
        RETURN QUERY SELECT (v_existing.status = 'accepted'), true, v_used, v_quota;
        RETURN;
    END IF;

    UPDATE quota_periods qp
       SET used_bytes = qp.used_bytes + p_bytes,
           updated_at = clock_timestamp()
     WHERE qp.account_id = p_account_id
       AND qp.period_key = p_period_key
       AND qp.used_bytes <= qp.quota_bytes - p_bytes
    RETURNING qp.used_bytes, qp.quota_bytes INTO v_used, v_quota;

    IF NOT FOUND THEN
        SELECT qp.used_bytes, qp.quota_bytes
          INTO v_used, v_quota
          FROM quota_periods qp
         WHERE qp.account_id = p_account_id AND qp.period_key = p_period_key;
        UPDATE quota_events SET status = 'denied' WHERE event_id = p_event_id;
        RETURN QUERY SELECT false, false, v_used, v_quota;
        RETURN;
    END IF;

    UPDATE quota_events SET status = 'accepted' WHERE event_id = p_event_id;
    RETURN QUERY SELECT true, false, v_used, v_quota;
END;
$$;
