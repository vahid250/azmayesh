#!/usr/bin/env python3
"""Stage 9: account lifecycle, subscription entitlement, and quota-period tests."""
from __future__ import annotations

import os
import uuid

import psycopg

DSN = os.environ["DATABASE_URL"]


def connect():
    return psycopg.connect(DSN, connect_timeout=5)


def one(conn, sql, params=()):
    return conn.execute(sql, params).fetchone()


def check(actual, expected, label):
    if actual != expected:
        raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")
    print(f"PASS: {label}: {actual!r}")


def expect_error(fn, label):
    try:
        fn()
    except psycopg.Error as exc:
        print(f"PASS: {label}: {exc.__class__.__name__}")
    else:
        raise AssertionError(f"{label}: expected database rejection")


def main():
    with connect() as conn:
        for filename in ("quota-ledger.sql", "quota-account-lifecycle.sql"):
            path = os.path.join(os.path.dirname(__file__), filename)
            conn.execute(open(path, encoding="utf-8").read(), prepare=False)
        conn.execute(
            "INSERT INTO quota_plans(plan_code, quota_bytes) VALUES "
            "('stage9-basic',10000),('stage9-plus',20000) "
            "ON CONFLICT(plan_code) DO UPDATE SET quota_bytes=EXCLUDED.quota_bytes, active=true"
        )
        conn.execute(
            "INSERT INTO rma_accounts(account_id,status) VALUES "
            "('stage9-user','active'),('stage9-expired','active') "
            "ON CONFLICT(account_id) DO UPDATE SET status='active'"
        )
        conn.execute(
            "DELETE FROM quota_events WHERE account_id IN ('stage9-user','stage9-expired')"
        )
        conn.execute(
            "DELETE FROM quota_periods WHERE account_id IN ('stage9-user','stage9-expired')"
        )
        conn.execute(
            "DELETE FROM account_subscriptions WHERE account_id IN ('stage9-user','stage9-expired')"
        )
        conn.execute(
            "DELETE FROM account_audit_events WHERE account_id IN ('stage9-user','stage9-expired')"
        )
        conn.execute(
            "INSERT INTO account_subscriptions(subscription_id,account_id,plan_code,starts_at,ends_at) "
            "VALUES (%s,'stage9-user','stage9-basic','2026-11-01T00:00:00Z','2026-12-01T00:00:00Z'),"
            "(%s,'stage9-user','stage9-plus','2026-12-01T00:00:00Z','2027-01-01T00:00:00Z'),"
            "(%s,'stage9-expired','stage9-basic','2026-10-01T00:00:00Z','2026-11-01T00:00:00Z')",
            (uuid.uuid4(), uuid.uuid4(), uuid.uuid4()),
        )

    print("[Q-24] Account provisioning and auditable lifecycle transitions")
    with connect() as conn:
        conn.execute("SELECT create_rma_account('stage9-created','system-test')")
        conn.execute(
            "SELECT set_rma_account_status('stage9-created','suspended','admin-test','test suspension')"
        )
        status = one(conn, "SELECT status FROM rma_accounts WHERE account_id='stage9-created'")[0]
        check(status, "suspended", "account suspension state")
        action = one(
            conn,
            "SELECT action FROM account_audit_events WHERE account_id='stage9-created' "
            "ORDER BY audit_id DESC LIMIT 1",
        )[0]
        check(action, "suspended", "suspension audit event")
        conn.execute(
            "SELECT set_rma_account_status('stage9-created','active','admin-test','test restoration')"
        )
        status = one(conn, "SELECT status FROM rma_accounts WHERE account_id='stage9-created'")[0]
        check(status, "active", "account restoration state")

    print("[Q-25] Entitlement creates correct monthly quota period")
    with connect() as conn:
        row = one(
            conn,
            "SELECT period_key, quota_bytes, used_bytes FROM ensure_current_quota_period"
            "('stage9-user','2026-11-19T12:00:00Z')",
        )
        check(row, ("2026-11", 10000, 0), "basic plan November entitlement")

    print("[Q-26] Monthly usage is preserved; repeated provisioning never resets usage")
    event = uuid.uuid4()
    with connect() as conn:
        used = one(
            conn,
            "SELECT accepted,duplicate,used_bytes,quota_bytes FROM record_account_quota_usage"
            "(%s,'stage9-user',3000,'2026-11-19T13:00:00Z')",
            (event,),
        )
        check(used, (True, False, 3000, 10000), "usage recorded under current entitlement")
        again = one(
            conn,
            "SELECT period_key,quota_bytes,used_bytes FROM ensure_current_quota_period"
            "('stage9-user','2026-11-20T12:00:00Z')",
        )
        check(again, ("2026-11", 10000, 3000), "re-provision does not reset monthly usage")

    print("[Q-27] Plan change applies at next period, not retroactively")
    with connect() as conn:
        next_period = one(
            conn,
            "SELECT period_key,quota_bytes,used_bytes FROM ensure_current_quota_period"
            "('stage9-user','2026-12-02T12:00:00Z')",
        )
        check(next_period, ("2026-12", 20000, 0), "next month receives upgraded plan quota")
        previous = one(
            conn,
            "SELECT quota_bytes,used_bytes FROM quota_periods "
            "WHERE account_id='stage9-user' AND period_key='2026-11'",
        )
        check(previous, (10000, 3000), "prior month remains unchanged")

    print("[Q-28] Suspended, unknown, and expired accounts cannot obtain quota")
    with connect() as conn:
        conn.execute(
            "SELECT set_rma_account_status('stage9-user','suspended','admin-test','policy test')"
        )
    expect_error(
        lambda: _period("stage9-user", "2026-12-10T00:00:00Z"),
        "suspended account is denied",
    )
    expect_error(
        lambda: _period("missing-user", "2026-12-10T00:00:00Z"),
        "unknown account is denied",
    )
    expect_error(
        lambda: _period("stage9-expired", "2026-11-19T12:00:00Z"),
        "expired subscription is denied",
    )

    print("[Q-29] Closed accounts cannot be reopened")
    with connect() as conn:
        conn.execute(
            "SELECT set_rma_account_status('stage9-created','closed','admin-test','closure test')"
        )
    expect_error(
        lambda: _set_status("stage9-created", "active"),
        "closed account cannot be reactivated",
    )

    print("Stage 9 account lifecycle and entitlement tests Q24-Q29 passed.")
    print("This validates lifecycle logic in disposable CI PostgreSQL; production auth and payment verification remain separate.")


def _period(account, when):
    with connect() as conn:
        return one(
            conn,
            "SELECT * FROM ensure_current_quota_period(%s,%s)",
            (account, when),
        )


def _set_status(account, status):
    with connect() as conn:
        conn.execute(
            "SELECT set_rma_account_status(%s,%s,'admin-test','negative transition test')",
            (account, status),
        )


if __name__ == "__main__":
    main()
