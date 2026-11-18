import os
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import Base, engine, get_db
from app.models import Entitlement, Order, OrderTermsAcceptance, Plan, UserSession, WireGuardClient, WireGuardClientOwner
from app.security import authenticate_session_token, decrypt_secret, issue_user_session, require_authenticated_request, revoke_user_session, verify_telegram_init_data
from app.billing import active_entitlement_for_user, record_verified_usage
from app.metering import METERING_PATH, METERING_REGISTRY_PATH, METERING_PEER_ACK_PATH, verify_metering_signature, verify_signed_internal_request
from app.wireguard import (
    _validate_real_server,
    get_wireguard_peer_status,
    issue_wireguard_config,
    revoke_wireguard_peer,
)
from app.telegram_bot import router as telegram_router
from app import models  # noqa: F401 - register ORM metadata
from app.models import PaymentAsset
from app.market_mappings import load_enabled_market_specs, fetch_payment_asset_observations
from app.quote_engine import build_locked_quote


app = FastAPI(title="R&MA Backend Lab", version="0.5.0")
CURRENT_TERMS_VERSION = "0.2"
TERMS_DOCUMENT_PATH = "https://github.com/vahid250/azmayesh/blob/rebuild/rma-hardening-from-dashboard/docs/USER_TERMS_FA.md"
PRIVACY_DOCUMENT_PATH = "https://github.com/vahid250/azmayesh/blob/rebuild/rma-hardening-from-dashboard/docs/PRIVACY_POLICY_FA.md"
app.include_router(telegram_router)


@app.middleware("http")
async def protect_api_responses(request: Request, call_next):
    """Prevent sensitive API payloads from being cached or framed."""
    response = await call_next(request)
    if request.url.path.startswith(("/api/", "/telegram/")):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


# SQLite is used only for local development and lightweight tests. A Worker
# must use the explicitly configured Hyperdrive binding; never create an
# ephemeral SQLite database in the Worker filesystem.
if (
    os.environ.get("RMA_CLOUDFLARE_WORKER") != "1"
    and engine.dialect.name == "sqlite"
):
    Base.metadata.create_all(bind=engine)


class SessionExchangeRequest(BaseModel):
    init_data: str = Field(min_length=1, max_length=16384)
    exchange_key: str = Field(min_length=43, max_length=43)


class WireGuardRequest(BaseModel):
    client_name: str = Field(default="R&MA Client", min_length=1, max_length=64)


def authenticate_request(
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> dict:
    if authorization:
        scheme, _, credential = authorization.partition(" ")
        if scheme.lower() != "bearer" or not credential or " " in credential:
            raise HTTPException(status_code=401, detail="A valid Bearer session is required")
        return authenticate_session_token(db, credential)
    # The lab API key remains available only in explicit development/test mode.
    return require_authenticated_request(x_api_key=x_api_key, x_telegram_init_data=None)


@app.post("/api/v1/auth/session")
def exchange_telegram_session(request: SessionExchangeRequest, db: Session = Depends(get_db)):
    verified = verify_telegram_init_data(request.init_data)
    return issue_user_session(db, str(verified["user"]["id"]), request.init_data, request.exchange_key)


@app.post("/api/v1/auth/logout")
def logout_session(
    authorization: str | None = Header(default=None, alias="Authorization"),
    db: Session = Depends(get_db),
):
    if not authorization:
        raise HTTPException(status_code=401, detail="Bearer session is required")
    scheme, _, credential = authorization.partition(" ")
    if scheme.lower() != "bearer" or not credential or " " in credential:
        raise HTTPException(status_code=401, detail="A valid Bearer session is required")
    authenticate_session_token(db, credential)
    revoke_user_session(db, credential)
    return {"revoked": True}


def service_is_paused() -> bool:
    return get_settings().service_mode.strip().lower() == "paused"


def ensure_new_activations_enabled() -> None:
    if service_is_paused():
        raise HTTPException(
            status_code=503,
            detail=get_settings().service_pause_message,
        )


@app.get("/api/v1/public/service-status")
def public_service_status():
    """Public, non-sensitive notice used by the Mini App before authentication."""
    config = get_settings()
    paused = service_is_paused()
    days = config.trial_duration_days if config.trial_duration_days in (20, 30) else 30
    return {
        "mode": "paused" if paused else "prelaunch",
        "headline": "توقف موقت برای پایش کیفیت" if paused else "R&MA در مرحله آماده‌سازی",
        "message": config.service_pause_message if paused else (
            "هنوز دوره آزمایشی آغاز نشده و ثبت سفارش، دریافت وجه و فعال‌سازی اتصال جدید غیرفعال است. "
            f"دوره آزمایشی برنامه‌ریزی‌شده {days} روزه است؛ زمان شروع پس از آزمون سرور واقعی و اعلام رسمی مشخص می‌شود."
        ),
        "trial_duration_days": days,
        "trial_start_at": config.trial_start_at or None,
        "referral_reward_bytes": max(0, config.referral_reward_bytes),
        "accepting_new_activations": False,
        "existing_connections_policy": "preserved",
    }


class OrderRequest(BaseModel):
    plan_code: str = Field(min_length=1, max_length=40)
    payment_method: str = Field(default="crypto", pattern="^(crypto|rial)$")
    terms_version: str | None = Field(default=None, min_length=1, max_length=32)


class UsageReportRequest(BaseModel):
    client_id: int = Field(gt=0)
    bytes_used: int = Field(gt=0, le=10**12)


class HostRegistryRequest(BaseModel):
    interface: str = Field(min_length=1, max_length=15)


class PeerStatusAckRequest(BaseModel):
    client_id: int = Field(gt=0)
    public_key: str = Field(min_length=1, max_length=128)
    state: str = Field(pattern="^(peer_registered|revoked|suspended)$")


def order_payload(order: Order) -> dict:
    return {
        "id": order.id,
        "plan_code": order.plan_code,
        "payment_method": order.payment_method,
        "amount_minor": order.amount_minor,
        "currency": order.currency,
        "quota_bytes": order.quota_bytes,
        "max_devices": order.max_devices,
        "duration_days": order.duration_days,
        "status": order.status,
        "created_at": order.created_at,
        "paid_at": order.paid_at,
    }


def owner_id_from_auth(auth: dict) -> str:
    if auth.get("auth_method") == "lab_api_key":
        return "lab-local"
    user = auth.get("user") or {}
    telegram_id = user.get("id")
    if not isinstance(telegram_id, (int, str)) or not str(telegram_id).isdigit():
        raise HTTPException(status_code=401, detail="Telegram user identity is missing from initData")
    return str(telegram_id)


def get_client_or_404(db: Session, client_id: int, owner_id: str) -> WireGuardClient:
    row = db.get(WireGuardClient, client_id)
    if row is None:
        raise HTTPException(status_code=404, detail="WireGuard client not found")
    owner = db.get(WireGuardClientOwner, client_id)
    if owner is None or owner.telegram_user_id != owner_id:
        raise HTTPException(status_code=404, detail="WireGuard client not found")
    return row


@app.get("/api/v1/diagnostics/database")
def database_diagnostic(
    auth: dict = Depends(authenticate_request),
    db: Session = Depends(get_db),
):
    """Run an authenticated, read-only database connectivity probe."""
    try:
        probe_result = db.execute(text("SELECT 1")).scalar_one()
    except Exception:
        # Do not expose connection strings, credentials, hostnames, or driver
        # internals through a public API response.
        raise HTTPException(
            status_code=503,
            detail="Database connectivity check failed",
        ) from None

    if probe_result != 1:
        raise HTTPException(status_code=503, detail="Database connectivity check failed")

    return {
        "status": "ok",
        "database": "reachable",
        "probe": "SELECT 1",
        "read_only": True,
    }




@app.post(METERING_PATH)
async def ingest_trusted_usage(
    request: Request,
    x_rma_timestamp: str = Header(..., alias="X-RMA-Timestamp"),
    x_rma_event_id: str = Header(..., alias="X-RMA-Event-Id"),
    x_rma_signature: str = Header(..., alias="X-RMA-Signature"),
    db: Session = Depends(get_db),
):
    raw_body = await request.body()
    if len(raw_body) > 4096:
        raise HTTPException(status_code=413, detail="Metering report is too large")
    verify_metering_signature(
        secret=get_settings().metering_shared_secret,
        timestamp=x_rma_timestamp,
        event_id=x_rma_event_id,
        signature=x_rma_signature,
        body=raw_body,
    )
    try:
        report = UsageReportRequest.model_validate_json(raw_body)
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid metering report payload") from None

    owner = db.get(WireGuardClientOwner, report.client_id)
    if owner is None or owner.entitlement_id is None:
        raise HTTPException(status_code=404, detail="Metered WireGuard client not found")
    entitlement = record_verified_usage(
        db,
        entitlement_id=owner.entitlement_id,
        source="wireguard-meter",
        source_event_id=x_rma_event_id,
        bytes_used=report.bytes_used,
    )
    return {
        "accepted": True,
        "client_id": report.client_id,
        "entitlement_id": entitlement.id,
        "consumed_bytes": entitlement.consumed_bytes,
        "remaining_bytes": max(0, entitlement.quota_bytes - entitlement.consumed_bytes),
    }


@app.post(METERING_REGISTRY_PATH)
async def get_trusted_wireguard_registry(
    request: Request,
    x_rma_timestamp: str = Header(..., alias="X-RMA-Timestamp"),
    x_rma_event_id: str = Header(..., alias="X-RMA-Event-Id"),
    x_rma_signature: str = Header(..., alias="X-RMA-Signature"),
    db: Session = Depends(get_db),
):
    """Return authorized peers and required removals to the trusted VPN host agent."""
    raw_body = await request.body()
    if len(raw_body) > 4096:
        raise HTTPException(status_code=413, detail="Registry request is too large")
    verify_signed_internal_request(
        secret=get_settings().metering_shared_secret,
        method="POST",
        path=METERING_REGISTRY_PATH,
        timestamp=x_rma_timestamp,
        event_id=x_rma_event_id,
        signature=x_rma_signature,
        body=raw_body,
    )
    try:
        payload = HostRegistryRequest.model_validate_json(raw_body)
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid host registry request") from None
    if payload.interface != get_settings().wg_interface:
        raise HTTPException(status_code=409, detail="Requested WireGuard interface does not match this backend")

    now = datetime.now(timezone.utc)
    rows = db.execute(
        select(WireGuardClient, Entitlement)
        .join(WireGuardClientOwner, WireGuardClientOwner.client_id == WireGuardClient.id)
        .outerjoin(Entitlement, Entitlement.id == WireGuardClientOwner.entitlement_id)
        .where(WireGuardClient.state.in_([
            "pending_peer_registration", "peer_registered", "revocation_pending"
        ]))
        .order_by(WireGuardClient.id.asc())
        .limit(2001)
    ).all()
    if len(rows) > 2000:
        raise HTTPException(status_code=503, detail="WireGuard registry exceeds the supported safe batch size")

    active_peers, remove_peers = [], []
    for client, entitlement in rows:
        expires_at = entitlement.expires_at if entitlement is not None else None
        if expires_at is not None and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        entitled = (
            entitlement is not None
            and entitlement.status == "active"
            and expires_at is not None
            and expires_at > now
            and entitlement.consumed_bytes < entitlement.quota_bytes
        )
        if client.state in ("pending_peer_registration", "peer_registered") and entitled:
            active_peers.append({
                "client_id": client.id,
                "public_key": client.public_key,
                "allowed_ips": client.client_ip,
                "state": client.state,
            })
        else:
            remove_state = "revoked" if client.state in ("revocation_pending", "revoked") else "suspended"
            remove_peers.append({
                "client_id": client.id,
                "public_key": client.public_key,
                "state": remove_state,
            })
    return {
        "interface": payload.interface,
        "generated_at": now,
        "peers": active_peers,
        "remove_peers": remove_peers,
    }


@app.post(METERING_PEER_ACK_PATH)
async def acknowledge_host_peer_state(
    request: Request,
    x_rma_timestamp: str = Header(..., alias="X-RMA-Timestamp"),
    x_rma_event_id: str = Header(..., alias="X-RMA-Event-Id"),
    x_rma_signature: str = Header(..., alias="X-RMA-Signature"),
    db: Session = Depends(get_db),
):
    raw_body = await request.body()
    if len(raw_body) > 4096:
        raise HTTPException(status_code=413, detail="Peer status report is too large")
    verify_signed_internal_request(
        secret=get_settings().metering_shared_secret,
        method="POST",
        path=METERING_PEER_ACK_PATH,
        timestamp=x_rma_timestamp,
        event_id=x_rma_event_id,
        signature=x_rma_signature,
        body=raw_body,
    )
    try:
        report = PeerStatusAckRequest.model_validate_json(raw_body)
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid peer status report") from None

    row = db.get(WireGuardClient, report.client_id)
    if row is None or row.public_key != report.public_key:
        raise HTTPException(status_code=404, detail="WireGuard peer not found")
    if report.state == "peer_registered":
        if row.state == "peer_registered":
            return {"accepted": True, "client_id": row.id, "state": row.state}
        if row.state != "pending_peer_registration":
            raise HTTPException(status_code=409, detail="Peer is no longer awaiting registration")
        owner = db.get(WireGuardClientOwner, row.id)
        entitlement = db.get(Entitlement, owner.entitlement_id) if owner and owner.entitlement_id else None
        expires_at = entitlement.expires_at if entitlement is not None else None
        if expires_at is not None and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if (
            entitlement is None or entitlement.status != "active"
            or expires_at is None or expires_at <= datetime.now(timezone.utc)
            or entitlement.consumed_bytes >= entitlement.quota_bytes
        ):
            raise HTTPException(status_code=409, detail="Peer entitlement is no longer active")
    elif report.state == "revoked":
        if row.state == "revoked":
            return {"accepted": True, "client_id": row.id, "state": row.state}
        if row.state != "revocation_pending":
            raise HTTPException(status_code=409, detail="Peer is not awaiting revocation")
    elif report.state == "suspended":
        if row.state == "suspended":
            return {"accepted": True, "client_id": row.id, "state": row.state}
        owner = db.get(WireGuardClientOwner, row.id)
        entitlement = db.get(Entitlement, owner.entitlement_id) if owner and owner.entitlement_id else None
        expires_at = entitlement.expires_at if entitlement is not None else None
        if expires_at is not None and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if entitlement is not None and entitlement.status == "active" and expires_at and expires_at > datetime.now(timezone.utc) and entitlement.consumed_bytes < entitlement.quota_bytes:
            raise HTTPException(status_code=409, detail="Peer entitlement remains active")
    row.state = report.state
    db.commit()
    return {"accepted": True, "client_id": row.id, "state": row.state}

@app.get("/api/v1/plans")
def list_active_plans(db: Session = Depends(get_db)):
    plans = db.execute(
        select(Plan).where(Plan.is_active.is_(True)).order_by(Plan.amount_minor.asc(), Plan.code.asc())
    ).scalars().all()
    return [
        {
            "code": plan.code,
            "title": plan.title,
            "amount_minor": plan.amount_minor,
            "currency": plan.currency,
            "quota_bytes": plan.quota_bytes,
            "max_devices": plan.max_devices,
            "duration_days": plan.duration_days,
        }
        for plan in plans
    ]


@app.get("/api/v1/public/payment-rate")
async def public_payment_rate(
    currency: str,
    network: str,
    db: Session = Depends(get_db),
):
    """Return a live, validated display rate and the independent quote benchmark.

    This endpoint is informational only: it creates no invoice, deposit address,
    payment intent, or order. Client-supplied rates are never accepted.
    """
    payment_currency = currency.strip().upper()
    payment_network = network.strip().upper()
    if (
        not payment_currency
        or len(payment_currency) > 12
        or not payment_network
        or len(payment_network) > 32
    ):
        raise HTTPException(status_code=422, detail="Payment asset selection is invalid")

    asset = db.execute(
        select(PaymentAsset).where(
            PaymentAsset.currency == payment_currency,
            PaymentAsset.network == payment_network,
            PaymentAsset.is_enabled.is_(True),
        )
    ).scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=404, detail="Payment asset or network is not available")

    try:
        mappings = load_enabled_market_specs(
            db,
            payment_asset_id=asset.id,
            payment_currency=asset.currency,
        )
        now = datetime.now(timezone.utc)
        observations = await fetch_payment_asset_observations(
            payment_currency=asset.currency,
            mappings=mappings,
            now=now,
        )
        quote = build_locked_quote(
            price_usd_minor=100,
            payment_decimals=asset.decimals,
            observations=observations,
            now=now,
            admin_margin_bps=0,
        )
    except (ValueError, ArithmeticError):
        raise HTTPException(
            status_code=503,
            detail="A validated market rate is temporarily unavailable",
        ) from None
    except Exception:
        # Network and provider failures must not leak internal details.
        raise HTTPException(
            status_code=503,
            detail="A validated market rate is temporarily unavailable",
        ) from None

    best_row = next(
        row for row in quote.source_snapshot if row["best_display_rate"]
    )
    return {
        "currency": asset.currency,
        "network": asset.network,
        "display_rate": {
            "meaning": "USD value of one payment-asset unit",
            "usd_per_unit": best_row["usd_per_payment_unit"],
            "source": best_row["source"],
            "observed_at": best_row["observed_at"],
        },
        "quote_benchmark": {
            "meaning": "USD value of one payment-asset unit at the accepted two-source mean",
            "usd_per_unit": format(Decimal(1) / quote.units_per_usd, "f"),
            "selected_sources": list(quote.selected_sources),
            "spread_bps": quote.rate_spread_bps,
        },
        "source_snapshot": quote.source_snapshot,
        "fetched_at": now,
        "informational_only": True,
        "invoice_rate_locked": False,
    }


@app.get("/api/v1/public/terms")
def public_terms_metadata():
    """Expose the single canonical draft version; this is not a legal approval."""
    return {
        "version": CURRENT_TERMS_VERSION,
        "status": "draft_testing_only",
        "document_path": TERMS_DOCUMENT_PATH,
        "privacy_document_path": PRIVACY_DOCUMENT_PATH,
        "acceptance_enabled": True,
        "legal_effect": "not_final_terms_or_a_payment_authorization",
    }


@app.post("/api/v1/orders")
def create_user_order(
    request: OrderRequest,
    auth: dict = Depends(authenticate_request),
):
    ensure_new_activations_enabled()
    if request.terms_version != CURRENT_TERMS_VERSION:
        raise HTTPException(status_code=409, detail="شرایط استفاده تغییر کرده است؛ نسخه جدید را مطالعه و تأیید کنید.")
    # Fail closed until a real payment provider, settlement verification,
    # refund path, and production readiness checks have been implemented.
    # No database session is opened and no pending order is created in prelaunch.
    raise HTTPException(
        status_code=503,
        detail="ثبت سفارش و پرداخت هنوز فعال نیست؛ هیچ سفارش یا وجهی دریافت نمی‌شود.",
    )


@app.get("/api/v1/orders")
def list_user_orders(
    auth: dict = Depends(authenticate_request),
    db: Session = Depends(get_db),
):
    rows = db.execute(
        select(Order)
        .where(Order.telegram_user_id == owner_id_from_auth(auth))
        .order_by(Order.id.desc())
        .limit(100)
    ).scalars().all()
    return [order_payload(order) for order in rows]


@app.get("/api/v1/entitlements")
def list_user_entitlements(
    auth: dict = Depends(authenticate_request),
    db: Session = Depends(get_db),
):
    rows = db.execute(
        select(Entitlement)
        .where(Entitlement.telegram_user_id == owner_id_from_auth(auth))
        .order_by(Entitlement.expires_at.desc(), Entitlement.id.desc())
        .limit(100)
    ).scalars().all()
    now = datetime.now(timezone.utc)
    payload = []
    for item in rows:
        expires_at = item.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        payload.append({
            "id": item.id,
            "quota_bytes": item.quota_bytes,
            "consumed_bytes": item.consumed_bytes,
            "remaining_bytes": max(0, item.quota_bytes - item.consumed_bytes),
            "max_devices": item.max_devices,
            "expires_at": expires_at,
            "status": "expired" if expires_at <= now and item.status == "active" else item.status,
        })
    return payload


@app.get("/health")
def health():
    provisioning_ready = False
    provisioning_reason = "mock_mode_enabled" if get_settings().mock_mode else None

    if not get_settings().mock_mode:
        try:
            # Validate config parameters only; peer commands run on the remote host agent.
            _validate_real_server()
            provisioning_ready = True
        except HTTPException as exc:
            provisioning_reason = exc.detail

    return {
        "status": "ok",
        "environment": get_settings().app_env,
        "mock_mode": get_settings().mock_mode,
        "real_provisioning_configured": provisioning_ready,
        "provisioning_reason": provisioning_reason,
        "host_agent_control_plane_configured": len(get_settings().metering_shared_secret) >= 32,
        "host_agent_online": "not_verified",
        "connectivity_verified": False,
    }


@app.post("/api/v1/wireguard/configs")
def create_wireguard_config(
    request: WireGuardRequest,
    auth: dict = Depends(authenticate_request),
    db: Session = Depends(get_db),
):
    ensure_new_activations_enabled()
    # Billing and entitlement ledgers now exist, but production issuance remains
    # fail-closed until a real payment adapter, traffic meter, and server rollout
    # have been independently verified.
    if get_settings().app_env == "production":
        raise HTTPException(
            status_code=503,
            detail=(
                "Configuration issuance remains disabled in production until "
                "a verified payment adapter, trusted traffic metering, and real VPN server rollout are complete."
            ),
        )
    owner_id = owner_id_from_auth(auth)
    entitlement = active_entitlement_for_user(db, owner_id)
    active_devices = db.execute(
        select(func.count(WireGuardClientOwner.client_id))
        .join(WireGuardClient, WireGuardClient.id == WireGuardClientOwner.client_id)
        .where(
            WireGuardClientOwner.entitlement_id == entitlement.id,
            WireGuardClient.state.in_(["pending_peer_registration", "peer_registered"]),
        )
    ).scalar_one()
    if active_devices >= entitlement.max_devices:
        raise HTTPException(status_code=403, detail="The active entitlement has reached its device limit")
    return issue_wireguard_config(
        db,
        request.client_name,
        owner_id,
        entitlement_id=entitlement.id,
    )


@app.get("/api/v1/wireguard/configs")
def list_wireguard_configs(
    auth: dict = Depends(authenticate_request),
    db: Session = Depends(get_db),
):
    owner_id = owner_id_from_auth(auth)
    rows = db.execute(
        select(WireGuardClient)
        .join(WireGuardClientOwner, WireGuardClientOwner.client_id == WireGuardClient.id)
        .where(WireGuardClientOwner.telegram_user_id == owner_id)
        .order_by(WireGuardClient.id.desc())
    ).scalars().all()
    return [
        {
            "id": row.id,
            "client_name": row.client_name,
            "client_ip": row.client_ip,
            "public_key": row.public_key,
            "state": row.state,
            "created_at": row.created_at,
        }
        for row in rows
    ]


@app.get("/api/v1/wireguard/configs/{client_id}/config")
def get_wireguard_config(
    client_id: int,
    auth: dict = Depends(authenticate_request),
    db: Session = Depends(get_db),
):
    row = get_client_or_404(db, client_id, owner_id_from_auth(auth))
    if row.state in ("revoked", "revocation_pending", "suspended"):
        raise HTTPException(status_code=410, detail="This WireGuard client is no longer active")
    return {
        "id": row.id,
        "client_name": row.client_name,
        "config": decrypt_secret(row.config_encrypted),
        "state": row.state,
        "connectivity_verified": False,
    }


@app.get("/api/v1/wireguard/configs/{client_id}/status")
def wireguard_status(
    client_id: int,
    auth: dict = Depends(authenticate_request),
    db: Session = Depends(get_db),
):
    return get_wireguard_peer_status(get_client_or_404(db, client_id, owner_id_from_auth(auth)))


@app.post("/api/v1/wireguard/configs/{client_id}/revoke")
def revoke_wireguard_config(
    client_id: int,
    auth: dict = Depends(authenticate_request),
    db: Session = Depends(get_db),
):
    return revoke_wireguard_peer(db, get_client_or_404(db, client_id, owner_id_from_auth(auth)))
