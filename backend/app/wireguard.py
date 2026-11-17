import base64
import ipaddress
import re
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import WireGuardClient, WireGuardClientOwner
from app.security import encrypt_secret


def generate_keypair() -> tuple[str, str]:
    private = x25519.X25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(private_bytes).decode(), base64.b64encode(public_bytes).decode()


def _next_client_ip(db: Session) -> str:
    try:
        network = ipaddress.ip_network(get_settings().wg_subnet, strict=True)
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="WG_SUBNET is invalid") from exc
    if network.version != 4 or network.num_addresses < 4:
        raise HTTPException(status_code=503, detail="WG_SUBNET must be a usable IPv4 subnet")
    used = {row[0] for row in db.execute(select(WireGuardClient.client_ip)).all()}
    # Reserve network address, server address and broadcast address.
    for address in network.hosts():
        candidate = f"{address}/32"
        if candidate in used:
            continue
        if address == network.network_address + 1:
            continue
        return candidate
    raise HTTPException(status_code=409, detail="No free client IP addresses remain")


def _validate_client_config_settings() -> tuple[str, int]:
    """Validate values interpolated into the downloadable WireGuard config."""
    dns_value = get_settings().wg_dns
    if (
        not isinstance(dns_value, str)
        or not dns_value
        or len(dns_value) > 255
        or any(ord(char) < 32 or ord(char) == 127 for char in dns_value)
    ):
        raise HTTPException(status_code=503, detail="WG_DNS is invalid")

    dns_servers = [item.strip() for item in dns_value.split(",")]
    if not dns_servers or any(not item for item in dns_servers):
        raise HTTPException(status_code=503, detail="WG_DNS is invalid")
    try:
        normalized_dns = ", ".join(str(ipaddress.ip_address(item)) for item in dns_servers)
    except ValueError:
        raise HTTPException(status_code=503, detail="WG_DNS must contain only valid IP addresses") from None

    mtu = get_settings().wg_mtu
    if isinstance(mtu, bool) or not isinstance(mtu, int) or not 1280 <= mtu <= 9000:
        raise HTTPException(status_code=503, detail="WG_MTU must be an integer between 1280 and 9000")
    return normalized_dns, mtu


def _validate_real_server() -> None:
    """Validate the literal endpoint and public key embedded in a client config."""
    if get_settings().mock_mode:
        return

    raw_endpoint = get_settings().wg_server_endpoint
    raw_public_key = get_settings().wg_server_public_key
    if not raw_endpoint or not raw_public_key:
        raise HTTPException(status_code=503, detail="WireGuard server endpoint/public key are not configured")

    try:
        # Reject control characters and whitespace before parsing. urlsplit()
        # normalizes some of them, which is unsafe when the raw value is later
        # interpolated into the downloadable config.
        if (
            len(raw_endpoint) > 300
            or any(ord(char) <= 32 or ord(char) == 127 for char in raw_endpoint)
        ):
            raise ValueError("invalid endpoint characters")

        endpoint = urlsplit("//" + raw_endpoint)
        host = endpoint.hostname
        port = endpoint.port
        if (
            not host
            or port is None
            or not 1 <= port <= 65535
            or endpoint.netloc != raw_endpoint
            or endpoint.username is not None
            or endpoint.password is not None
            or endpoint.path
            or endpoint.query
            or endpoint.fragment
            or "%" in host
        ):
            raise ValueError("invalid endpoint structure")

        try:
            ipaddress.ip_address(host)
        except ValueError:
            label = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
            if len(host) > 253 or not re.fullmatch(label + r"(?:\\." + label + r")*", host):
                raise ValueError("invalid endpoint hostname")

        decoded_key = base64.b64decode(raw_public_key, validate=True)
        if len(decoded_key) != 32 or base64.b64encode(decoded_key).decode("ascii") != raw_public_key:
            raise ValueError("invalid public key")
    except (ValueError, TypeError, UnicodeError):
        raise HTTPException(status_code=503, detail="WireGuard server endpoint or public key is invalid") from None


def issue_wireguard_config(db: Session, client_name: str, owner_id: str, entitlement_id: int | None = None) -> dict:
    dns_servers, mtu = _validate_client_config_settings()
    _validate_real_server()
    clean_name = " ".join(client_name.strip().split())[:64]
    if not clean_name:
        raise HTTPException(status_code=422, detail="client_name cannot be empty")

    # Unique constraints are the final protection against concurrent IP allocation.
    for attempt in range(5):
        client_ip = _next_client_ip(db)
        private_key, public_key = generate_keypair()
        if get_settings().mock_mode:
            server_public_key = "MOCK_ONLY_NO_REAL_SERVER_KEY"
            endpoint = "mock.invalid:51820"
        else:
            server_public_key = get_settings().wg_server_public_key
            endpoint = get_settings().wg_server_endpoint

        config = (
            "[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"Address = {client_ip}\n"
            f"DNS = {dns_servers}\n"
            f"MTU = {mtu}\n\n"
            "[Peer]\n"
            f"PublicKey = {server_public_key}\n"
            f"Endpoint = {endpoint}\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            "PersistentKeepalive = 25\n"
        )
        row = WireGuardClient(
            client_name=clean_name,
            client_ip=client_ip,
            public_key=public_key,
            private_key_encrypted=encrypt_secret(private_key),
            config_encrypted=encrypt_secret(config),
            state="generated_mock" if get_settings().mock_mode else "pending_peer_registration",
        )
        db.add(row)
        try:
            db.flush()
            db.add(WireGuardClientOwner(client_id=row.id, telegram_user_id=owner_id, entitlement_id=entitlement_id))
            db.commit()
            db.refresh(row)
            break
        except IntegrityError:
            db.rollback()
            if attempt == 4:
                raise HTTPException(status_code=409, detail="Could not allocate a unique client IP")

    return {
        "id": row.id,
        "client_name": row.client_name,
        "protocol": "wireguard",
        "client_ip": row.client_ip,
        "public_key": row.public_key,
        "config": config,
        "state": row.state,
        "connectivity_verified": False,
        "notice": (
            "TEST CONFIG ONLY: no real server peer or internet route is configured"
            if get_settings().mock_mode else
            "Peer registration is pending. The trusted VPN host agent must register this peer before the tunnel can connect."
        ),
    }


def revoke_wireguard_peer(db: Session, row: WireGuardClient) -> dict:
    if row.state in ("revoked", "revocation_pending"):
        return {
            "id": row.id,
            "state": row.state,
            "revoked": row.state == "revoked",
            "pending": row.state == "revocation_pending",
        }
    if get_settings().mock_mode:
        row.state = "revoked"
        db.commit()
        return {"id": row.id, "state": row.state, "revoked": True, "pending": False}
    row.state = "revocation_pending"
    db.commit()
    return {"id": row.id, "state": row.state, "revoked": False, "pending": True}

def get_wireguard_peer_status(row: WireGuardClient) -> dict:
    if get_settings().mock_mode:
        return {
            "id": row.id,
            "state": row.state,
            "handshake_seen": False,
            "latest_handshake_epoch": None,
            "rx_bytes": 0,
            "tx_bytes": 0,
            "connectivity_verified": False,
            "notice": "Mock mode has no live WireGuard server; no handshake or traffic can be measured.",
        }
    return {
        "id": row.id,
        "state": row.state,
        "handshake_seen": False,
        "latest_handshake_epoch": None,
        "rx_bytes": None,
        "tx_bytes": None,
        "connectivity_verified": False,
        "notice": "Peer lifecycle state is managed by the trusted VPN host agent; live handshake telemetry is not yet exposed by the API.",
    }
