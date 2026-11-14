import base64
import ipaddress
import shutil
import subprocess
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.config import settings
from app.models import WireGuardClient
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
        network = ipaddress.ip_network(settings.wg_subnet, strict=True)
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


def _validate_real_server() -> None:
    if settings.mock_mode:
        return
    if not settings.wg_server_endpoint or not settings.wg_server_public_key:
        raise HTTPException(status_code=503, detail="Real WireGuard endpoint/public key are not configured")
    if not shutil.which("wg"):
        raise HTTPException(status_code=503, detail="wireguard-tools (wg) is not installed")
    try:
        subprocess.run(["wg", "show", settings.wg_interface], check=True, capture_output=True, text=True, timeout=8)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        raise HTTPException(status_code=503, detail="Configured WireGuard interface is not available") from exc


def issue_wireguard_config(db: Session, client_name: str) -> dict:
    _validate_real_server()
    clean_name = " ".join(client_name.strip().split())[:64]
    if not clean_name:
        raise HTTPException(status_code=422, detail="client_name cannot be empty")

    # Unique constraints are the final protection against concurrent IP allocation.
    for attempt in range(5):
        client_ip = _next_client_ip(db)
        private_key, public_key = generate_keypair()
        if settings.mock_mode:
            server_public_key = "MOCK_ONLY_NO_REAL_SERVER_KEY"
            endpoint = "mock.invalid:51820"
        else:
            server_public_key = settings.wg_server_public_key
            endpoint = settings.wg_server_endpoint

        config = (
            "[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"Address = {client_ip}\n"
            f"DNS = {settings.wg_dns}\n"
            f"MTU = {settings.wg_mtu}\n\n"
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
            state="generated_mock" if settings.mock_mode else "pending_peer_registration",
        )
        db.add(row)
        try:
            db.commit()
            db.refresh(row)
            break
        except IntegrityError:
            db.rollback()
            if attempt == 4:
                raise HTTPException(status_code=409, detail="Could not allocate a unique client IP")

    if not settings.mock_mode:
        try:
            subprocess.run(
                ["wg", "set", settings.wg_interface, "peer", public_key, "allowed-ips", client_ip],
                check=True, capture_output=True, text=True, timeout=10,
            )
            row.state = "peer_registered"
            db.commit()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            try:
                subprocess.run(
                    ["wg", "set", settings.wg_interface, "peer", public_key, "remove"],
                    check=False, capture_output=True, text=True, timeout=5,
                )
            except Exception:
                pass
            db.delete(row)
            db.commit()
            raise HTTPException(status_code=502, detail="WireGuard peer registration failed; no config was issued") from exc

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
            if settings.mock_mode else
            "Peer registered. Handshake and internet traffic still require client-side verification."
        ),
    }



def revoke_wireguard_peer(db: Session, row: WireGuardClient) -> dict:
    if row.state == "revoked":
        return {"id": row.id, "state": "revoked", "revoked": True}
    if not settings.mock_mode:
        _validate_real_server()
        try:
            subprocess.run(
                ["wg", "set", settings.wg_interface, "peer", row.public_key, "remove"],
                check=True, capture_output=True, text=True, timeout=10,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            raise HTTPException(status_code=502, detail="WireGuard peer removal failed; record remains unchanged") from exc
    row.state = "revoked"
    db.commit()
    return {"id": row.id, "state": row.state, "revoked": True}


def get_wireguard_peer_status(row: WireGuardClient) -> dict:
    if settings.mock_mode:
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
    _validate_real_server()
    try:
        result = subprocess.run(
            ["wg", "show", settings.wg_interface, "dump"],
            check=True, capture_output=True, text=True, timeout=8,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        raise HTTPException(status_code=502, detail="Could not read WireGuard peer status") from exc

    peer = None
    for line in result.stdout.splitlines()[1:]:
        fields = line.split("\t")
        if len(fields) >= 8 and fields[0] == row.public_key:
            peer = fields
            break
    if peer is None:
        return {
            "id": row.id,
            "state": row.state,
            "handshake_seen": False,
            "latest_handshake_epoch": None,
            "rx_bytes": 0,
            "tx_bytes": 0,
            "connectivity_verified": False,
            "notice": "Peer is not present in the live WireGuard interface.",
        }
    try:
        handshake = int(peer[4])
        rx_bytes = int(peer[5])
        tx_bytes = int(peer[6])
    except (ValueError, IndexError) as exc:
        raise HTTPException(status_code=502, detail="WireGuard returned an unreadable peer status") from exc
    return {
        "id": row.id,
        "state": row.state,
        "handshake_seen": handshake > 0,
        "latest_handshake_epoch": handshake or None,
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
        "connectivity_verified": False,
        "notice": "Handshake and byte counters are server observations only; DNS and HTTPS must still be tested on the client.",
    }
