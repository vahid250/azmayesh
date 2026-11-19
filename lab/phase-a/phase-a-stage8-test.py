#!/usr/bin/env python3
"""Stage 8: durable PostgreSQL quota ledger integration and failure tests."""
from __future__ import annotations

import concurrent.futures
import os
import subprocess
import sys
import time
import uuid

import psycopg

DSN = os.environ["DATABASE_URL"]
CONTAINER_ID = os.environ["POSTGRES_SERVICE_ID"]


def connect():
    return psycopg.connect(DSN, connect_timeout=3)


def scalar(conn, sql, params=()):
    return conn.execute(sql, params).fetchone()


def assert_eq(actual, expected, label):
    if actual != expected:
        raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")
    print(f"PASS: {label}: {actual!r}")


def record(event_id, account, period, amount):
    with connect() as conn:
        return scalar(
            conn,
            "SELECT accepted, duplicate, used_bytes, quota_bytes "
            "FROM record_quota_usage(%s, %s, %s, %s)",
            (event_id, account, period, amount),
        )


def wait_database():
    for _ in range(40):
        try:
            with connect() as conn:
                scalar(conn, "SELECT 1")
            return
        except Exception:
            time.sleep(1)
    raise RuntimeError("PostgreSQL did not become ready after restart")


def main():
    migration_path = os.path.join(os.path.dirname(__file__), "quota-ledger.sql")
    with connect() as conn:
        conn.execute(open(migration_path, encoding="utf-8").read(), prepare=False)
        conn.execute(
            "INSERT INTO quota_periods(account_id, period_key, quota_bytes) "
            "VALUES ('stage8-main','2026-11',100000), "
            "('stage8-restart','2026-11',50000), "
            "('stage8-failclosed','2026-11',50000) "
            "ON CONFLICT (account_id, period_key) DO UPDATE "
            "SET quota_bytes=EXCLUDED.quota_bytes, used_bytes=0"
        )
        conn.execute(
            "DELETE FROM quota_events WHERE account_id IN "
            "('stage8-main','stage8-restart','stage8-failclosed')"
        )

    print("[Q-19] Initial ledger write and event idempotency")
    event = uuid.uuid4()
    first = record(event, "stage8-main", "2026-11", 12000)
    assert_eq(first, (True, False, 12000, 100000), "first usage event accepted")
    replay = record(event, "stage8-main", "2026-11", 12000)
    assert_eq(replay, (True, True, 12000, 100000), "replayed event is idempotent")
    with connect() as conn:
        used = scalar(conn, "SELECT used_bytes FROM quota_periods WHERE account_id='stage8-main'")[0]
    assert_eq(used, 12000, "duplicate event charged exactly once")

    print("[Q-20] Reusing an idempotency key with different data is rejected")
    try:
        record(event, "stage8-main", "2026-11", 13000)
    except psycopg.Error:
        print("PASS: mismatched replay rejected")
    else:
        raise AssertionError("mismatched idempotency-key reuse was accepted")

    print("[Q-21] Concurrent requests cannot overspend the account quota")
    events = [uuid.uuid4() for _ in range(20)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(
            lambda e: record(e, "stage8-main", "2026-11", 5000), events
        ))
    accepted = sum(1 for row in results if row[0])
    denied = sum(1 for row in results if not row[0])
    with connect() as conn:
        used, cap = scalar(
            conn,
            "SELECT used_bytes, quota_bytes FROM quota_periods "
            "WHERE account_id='stage8-main' AND period_key='2026-11'"
        )
    assert_eq((accepted, denied, used, cap), (17, 3, 97000, 100000),
              "20 concurrent requests preserve exact remaining quota")
    # 12,000 from Q19 + 17*5,000 = 97,000; three requests denied.

    print("[Q-22] Database container restart preserves committed usage")
    record(uuid.uuid4(), "stage8-restart", "2026-11", 23000)
    subprocess.run(["docker", "restart", CONTAINER_ID], check=True, capture_output=True)
    wait_database()
    with connect() as conn:
        used = scalar(
            conn,
            "SELECT used_bytes FROM quota_periods "
            "WHERE account_id='stage8-restart' AND period_key='2026-11'"
        )[0]
    assert_eq(used, 23000, "usage survives PostgreSQL process/container restart")

    print("[Q-23] Database outage fails closed; no success is fabricated")
    subprocess.run(["docker", "stop", CONTAINER_ID], check=True, capture_output=True)
    try:
        record(uuid.uuid4(), "stage8-failclosed", "2026-11", 1000)
    except Exception:
        print("PASS: unavailable ledger causes request failure (fail closed)")
    else:
        raise AssertionError("usage call unexpectedly succeeded while database was stopped")
    finally:
        subprocess.run(["docker", "start", CONTAINER_ID], check=True, capture_output=True)
    wait_database()
    with connect() as conn:
        used = scalar(
            conn,
            "SELECT used_bytes FROM quota_periods "
            "WHERE account_id='stage8-failclosed' AND period_key='2026-11'"
        )[0]
    assert_eq(used, 0, "database outage did not create unrecorded usage")

    print("Stage 8 durable quota ledger tests Q19-Q23 passed.")
    print("This validates PostgreSQL ledger behavior in CI; it is not production VPN acceptance.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise
