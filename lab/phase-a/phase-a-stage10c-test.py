#!/usr/bin/env python3
"""Stage 10C: database ownership, privilege separation, and tenant isolation tests."""
from __future__ import annotations
import os, uuid
import psycopg
DSN = os.environ["DATABASE_URL"]

def connect():
    return psycopg.connect(DSN, connect_timeout=5)

def scalar(c, q, p=()):
    return c.execute(q, p).fetchone()[0]

def check(v, expected, label):
    if v != expected:
        raise AssertionError(f"{label}: expected {expected!r}, got {v!r}")
    print(f"PASS: {label}")

def denied(fn, label):
    try: fn()
    except psycopg.Error as e: print(f"PASS: {label}: denied ({e.sqlstate})")
    else: raise AssertionError(f"{label}: expected denial")

def main():
    with connect() as root:
        for name in ("quota-ledger.sql","quota-account-lifecycle.sql",
                     "quota-identity-binding.sql","quota-db-hardening.sql"):
            path=os.path.join(os.path.dirname(__file__),name)
            root.execute(open(path,encoding="utf-8").read(),prepare=False)
        root.execute("""INSERT INTO rma_accounts(account_id,status) VALUES
          ('stage10c-a','active'),('stage10c-b','active')
          ON CONFLICT(account_id) DO UPDATE SET status=EXCLUDED.status""")
        root.execute("""INSERT INTO quota_plans(plan_code,quota_bytes,period_kind,active)
          VALUES ('stage10c-plan',100000,'calendar_month',true)
          ON CONFLICT(plan_code) DO UPDATE SET quota_bytes=EXCLUDED.quota_bytes,active=true""")
        root.execute("""INSERT INTO account_subscriptions
          (subscription_id,account_id,plan_code,status,starts_at,ends_at) VALUES
          ('c1000000-0000-4000-8000-000000000001','stage10c-a','stage10c-plan','active',now()-interval '1 day',now()+interval '30 days'),
          ('c1000000-0000-4000-8000-000000000002','stage10c-b','stage10c-plan','active',now()-interval '1 day',now()+interval '30 days')
          ON CONFLICT(subscription_id) DO NOTHING""")
        root.execute("""INSERT INTO rma_identity_bindings(issuer,subject,account_id,status) VALUES
          ('https://issuer.example','stage10c-sub-a','stage10c-a','active'),
          ('https://issuer.example','stage10c-sub-b','stage10c-b','active')
          ON CONFLICT(issuer,subject) DO UPDATE SET account_id=EXCLUDED.account_id,status='active'""")

    print("[Q36] Dedicated owner is NOLOGIN, non-superuser, and cannot bypass RLS")
    with connect() as c:
        check(scalar(c,"SELECT (NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole) FROM pg_roles WHERE rolname='rma_data_owner'"),True,"owner role attributes")
        check(scalar(c,"""SELECT count(*) FROM pg_class WHERE relname IN
          ('rma_accounts','quota_periods','quota_events','account_subscriptions','rma_identity_bindings')
          AND pg_get_userbyid(relowner)='rma_data_owner'"""),5,"core tables transferred to dedicated owner")

    print("[Q37] No runtime role inherits owner, migrator, or identity-admin rights")
    with connect() as c:
        check(scalar(c,"""SELECT count(*) FROM pg_auth_members m
          JOIN pg_roles g ON g.oid=m.roleid JOIN pg_roles u ON u.oid=m.member
          WHERE g.rolname IN ('rma_data_owner','rma_migrator','rma_identity_admin')
          AND u.rolname IN ('rma_auth_gateway','rma_untrusted_client','rma_quota_service')"""),0,"privileged memberships absent")

    print("[Q38] Runtime roles cannot directly read account data")
    for role in ("rma_auth_gateway","rma_untrusted_client","rma_quota_service"):
        def read(role=role):
            with connect() as c:
                c.execute(f"SET ROLE {role}")
                scalar(c,"SELECT count(*) FROM rma_accounts")
        denied(read,f"{role} direct table read denied")

    print("[Q39] Raw account_id quota functions are not callable by runtime roles")
    for role in ("rma_auth_gateway","rma_untrusted_client","rma_quota_service"):
        def raw(role=role):
            with connect() as c:
                c.execute(f"SET ROLE {role}")
                c.execute("SELECT * FROM record_account_quota_usage(%s,%s,%s,%s)",
                          (str(uuid.uuid4()),"stage10c-b",10,"2026-11-19T12:00:00Z"))
        denied(raw,f"{role} raw account-id function denied")

    print("[Q40] Identity-scoped quota wrapper accepts the authenticated subject path")
    with connect() as c:
        c.execute("SET ROLE rma_quota_service")
        ok=scalar(c,"""SELECT accepted FROM record_rma_quota_usage_for_identity(%s,%s,%s,10,now())""",
                  ("https://issuer.example","stage10c-sub-a",str(uuid.uuid4())))
        check(ok,True,"identity A quota event accepted")

    print("[Q41] Forced RLS restricts tenant rows and fails closed without context")
    with connect() as c:
        c.execute("SET ROLE rma_data_owner")
        c.execute("SELECT set_config('rma.account_id','stage10c-a',false)")
        a=scalar(c,"SELECT count(*) FROM quota_periods WHERE account_id='stage10c-a'")
        b=scalar(c,"SELECT count(*) FROM quota_periods WHERE account_id='stage10c-b'")
        check(a>=1 and b==0,True,"tenant A context cannot see tenant B quota rows")
        c.execute("SELECT set_config('rma.account_id','',false)")
        check(scalar(c,"SELECT count(*) FROM quota_periods"),0,"missing tenant context returns no rows")

    print("[Q42] Runtime cannot create schema objects or assume the owner role")
    def create():
        with connect() as c:
            c.execute("SET ROLE rma_quota_service")
            c.execute("CREATE TABLE public.stage10c_escalation_probe(id int)")
    denied(create,"runtime CREATE denied")
    def assume():
        with connect() as c:
            c.execute("SET SESSION AUTHORIZATION rma_quota_service")
            c.execute("SET ROLE rma_data_owner")
    denied(assume,"SET ROLE escalation denied")

    print("[Q43] SECURITY DEFINER functions pin a safe search_path with pg_temp last")
    with connect() as c:
        for signature in (
            "resolve_rma_account(text,text)",
            "record_rma_quota_usage_for_identity(text,text,uuid,bigint,timestamp with time zone)"
        ):
            cfg=scalar(c,"""SELECT proconfig FROM pg_proc
              WHERE oid=%s::regprocedure""",(signature,))
            check(any(x == "search_path=pg_catalog, public, pg_temp" for x in (cfg or [])),
                  True,f"{signature} safe search_path")

    print("[Q44] Temporary-object shadowing cannot alter quota identity processing")
    with connect() as c:
        c.execute("SET ROLE rma_quota_service")
        c.execute("CREATE TEMP TABLE rma_accounts(account_id text, status text, updated_at timestamptz)")
        c.execute("INSERT INTO rma_accounts VALUES ('stage10c-a','suspended',now())")
        accepted=scalar(c,"""SELECT accepted FROM public.record_rma_quota_usage_for_identity(
          %s,%s,%s,7,now())""",
          ("https://issuer.example","stage10c-sub-a",str(uuid.uuid4())))
        check(accepted,True,"temporary shadow table did not override trusted account table")

    print("[Q45] Revoked identity bindings fail closed")
    with connect() as c:
        c.execute("""INSERT INTO rma_identity_bindings(issuer,subject,account_id,status)
          VALUES ('https://issuer.example','stage10c-sub-revoked','stage10c-a','revoked')
          ON CONFLICT(issuer,subject) DO UPDATE SET status='revoked'""")
    def revoked_identity():
        with connect() as c:
            c.execute("SET ROLE rma_quota_service")
            c.execute("""SELECT * FROM public.record_rma_quota_usage_for_identity(
              %s,%s,%s,5,now())""",
              ("https://issuer.example","stage10c-sub-revoked",str(uuid.uuid4()))).fetchall()
    denied(revoked_identity,"revoked identity quota call denied")

    print("[Q46] Invalid quota byte counts are rejected")
    for bad_bytes in (0,-1):
        def invalid_bytes(bad_bytes=bad_bytes):
            with connect() as c:
                c.execute("SET ROLE rma_quota_service")
                c.execute("""SELECT * FROM public.record_rma_quota_usage_for_identity(
                  %s,%s,%s,%s,now())""",
                  ("https://issuer.example","stage10c-sub-a",str(uuid.uuid4()),bad_bytes)).fetchall()
        denied(invalid_bytes,f"non-positive byte count {bad_bytes} denied")

    print("[Q47] Cross-tenant idempotency-key reuse is rejected without charging tenant B")
    shared_event=str(uuid.uuid4())
    with connect() as c:
        c.execute("SET ROLE rma_quota_service")
        a_result=c.execute("""SELECT accepted FROM public.record_rma_quota_usage_for_identity(
          %s,%s,%s,11,now())""",
          ("https://issuer.example","stage10c-sub-a",shared_event)).fetchone()[0]
        check(a_result,True,"tenant A initial idempotent event accepted")
    with connect() as c:
        c.execute("SET ROLE rma_quota_service")
        before=scalar(c,"""SELECT used_bytes FROM public.quota_periods
          WHERE account_id='stage10c-b' AND period_key=to_char(now() AT TIME ZONE 'UTC','YYYY-MM')""")
    def cross_tenant_replay():
        with connect() as c:
            c.execute("SET ROLE rma_quota_service")
            c.execute("""SELECT * FROM public.record_rma_quota_usage_for_identity(
              %s,%s,%s,11,now())""",
              ("https://issuer.example","stage10c-sub-b",shared_event)).fetchall()
    denied(cross_tenant_replay,"cross-tenant idempotency replay denied")
    with connect() as c:
        after=scalar(c,"""SELECT used_bytes FROM public.quota_periods
          WHERE account_id='stage10c-b' AND period_key=to_char(now() AT TIME ZONE 'UTC','YYYY-MM')""")
        check(after,before,"tenant B quota unchanged after cross-tenant replay")

    print("[Q48] Runtime function grants and forced-RLS coverage remain narrow")
    with connect() as c:
        check(scalar(c,"SELECT has_function_privilege('rma_quota_service','record_rma_quota_usage_for_identity(text,text,uuid,bigint,timestamptz)','EXECUTE')"),True,"quota service can call identity-scoped wrapper")
        check(scalar(c,"SELECT has_function_privilege('rma_untrusted_client','record_rma_quota_usage_for_identity(text,text,uuid,bigint,timestamptz)','EXECUTE')"),False,"untrusted client cannot call quota wrapper")
        check(scalar(c,"SELECT has_function_privilege('rma_auth_gateway','record_rma_quota_usage_for_identity(text,text,uuid,bigint,timestamptz)','EXECUTE')"),False,"auth gateway cannot call quota wrapper directly")
        check(scalar(c,"""SELECT count(*) FROM pg_class
          WHERE relname IN ('account_subscriptions','quota_periods','quota_events','account_audit_events')
            AND relrowsecurity AND relforcerowsecurity"""),4,"all tenant tables have enabled and forced RLS")

    print("Stage 10C database hardening tests Q36-Q48 passed.")
    print("RLS is defense in depth; verified JWT validation remains an API responsibility.")

if __name__=="__main__": main()
