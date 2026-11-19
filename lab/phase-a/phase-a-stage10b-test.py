#!/usr/bin/env python3
"""Stage 10B: identity binding and least-privilege contract tests.

These tests use disposable PostgreSQL and simulated backend roles. They do NOT
verify real JWT signatures or prove that a production API gateway is trusted.
"""
from __future__ import annotations

import os
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


def expect_db_error(fn, label):
    try:
        fn()
    except psycopg.Error as exc:
        print(f"PASS: {label}: rejected ({exc.sqlstate})")
    else:
        raise AssertionError(f"{label}: expected database rejection")


def main():
    root = connect()
    with root:
        for filename in ("quota-ledger.sql", "quota-account-lifecycle.sql",
                         "quota-identity-binding.sql"):
            path = os.path.join(os.path.dirname(__file__), filename)
            root.execute(open(path, encoding="utf-8").read(), prepare=False)

        root.execute(
            "INSERT INTO rma_accounts(account_id,status) VALUES "
            "('stage10b-account-a','active'),('stage10b-account-b','active'),"
            "('stage10b-suspended','suspended') "
            "ON CONFLICT(account_id) DO UPDATE SET status=EXCLUDED.status"
        )
        root.execute(
            "INSERT INTO rma_identity_bindings(issuer,subject,account_id,status) VALUES "
            "('https://issuer.example','subject-a','stage10b-account-a','active'),"
            "('https://issuer.example','subject-b','stage10b-account-b','active'),"
            "('https://issuer.example','subject-revoked','stage10b-account-a','revoked'),"
            "('https://issuer.example','subject-suspended','stage10b-suspended','active') "
            "ON CONFLICT(issuer,subject) DO UPDATE SET "
            "account_id=EXCLUDED.account_id,status=EXCLUDED.status"
        )

    print("[Q-30] Verified issuer+subject resolves to the mapped internal account")
    with connect() as conn:
        conn.execute("SET ROLE rma_auth_gateway")
        account = one(conn,
            "SELECT resolve_rma_account(%s,%s)",
            ("https://issuer.example", "subject-a"))[0]
        check(account, "stage10b-account-a", "identity A resolves to account A")

    print("[Q-31] Client-provided account_id is not part of the resolver contract")
    with connect() as conn:
        args = one(conn, """
            SELECT pg_get_function_arguments(
                'public.resolve_rma_account(text,text)'::regprocedure
            )
        """)[0]
        check(args, "p_issuer text, p_subject text",
              "resolver accepts only issuer and subject, not account_id")

    print("[Q-32] Unknown, revoked, and suspended identities fail closed")
    for issuer, subject, label in [
        ("https://issuer.example", "missing-subject", "unknown identity denied"),
        ("https://issuer.example", "subject-revoked", "revoked identity denied"),
        ("https://issuer.example", "subject-suspended", "suspended account denied"),
        ("https://wrong-issuer.example", "subject-a", "wrong issuer denied"),
    ]:
        def attempt(i=issuer, s=subject):
            with connect() as conn:
                conn.execute("SET ROLE rma_auth_gateway")
                one(conn, "SELECT resolve_rma_account(%s,%s)", (i, s))
        expect_db_error(attempt, label)

    print("[Q-33] Gateway cannot read or modify identity bindings directly")
    def direct_read():
        with connect() as conn:
            conn.execute("SET ROLE rma_auth_gateway")
            one(conn, "SELECT account_id FROM rma_identity_bindings LIMIT 1")
    expect_db_error(direct_read, "gateway direct table read denied")

    def direct_write():
        with connect() as conn:
            conn.execute("SET ROLE rma_auth_gateway")
            conn.execute(
                "UPDATE rma_identity_bindings SET account_id='stage10b-account-b' "
                "WHERE subject='subject-a'"
            )
    expect_db_error(direct_write, "gateway direct table write denied")

    print("[Q-34] Untrusted client role cannot invoke the identity resolver")
    def client_resolve():
        with connect() as conn:
            conn.execute("SET ROLE rma_untrusted_client")
            one(conn, "SELECT resolve_rma_account(%s,%s)",
                ("https://issuer.example", "subject-a"))
    expect_db_error(client_resolve, "untrusted client execution denied")

    print("[Q-35] Duplicate issuer+subject cannot be rebound ambiguously")
    def duplicate_binding():
        with connect() as conn:
            conn.execute(
                "INSERT INTO rma_identity_bindings(issuer,subject,account_id) "
                "VALUES ('https://issuer.example','subject-a','stage10b-account-b')"
            )
    expect_db_error(duplicate_binding, "duplicate identity binding rejected")

    print("Stage 10B identity-binding and least-privilege tests Q30-Q35 passed.")
    print("JWT verification and production gateway trust remain unimplemented and unverified.")


if __name__ == "__main__":
    main()
