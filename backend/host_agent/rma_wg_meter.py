#!/usr/bin/env python3
"""Trusted WireGuard host agent: peer reconciliation, byte metering, quota enforcement."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

METERING_PATH = "/api/v1/internal/metering/usage"
REGISTRY_PATH = "/api/v1/internal/metering/peers"
PEER_ACK_PATH = "/api/v1/internal/metering/peer-status"
LOG = logging.getLogger("rma-wg-meter")


@dataclass(frozen=True)
class Peer:
    client_id: int
    public_key: str
    allowed_ips: str = ""
    state: str = "peer_registered"


@dataclass(frozen=True)
class Counters:
    rx_bytes: int
    tx_bytes: int

    @property
    def total(self) -> int:
        return self.rx_bytes + self.tx_bytes


@dataclass(frozen=True)
class PendingEvent:
    event_id: str
    client_id: int
    public_key: str
    bytes_used: int
    body: bytes
    created_at: float
    failure_status: int | None = None


def parse_wg_dump(output: str) -> dict[str, Counters]:
    """Parse wg show IFACE dump; the first line describes the interface."""
    peers = {}
    lines = output.splitlines()
    if not lines:
        raise ValueError("WireGuard dump is empty")
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) < 8:
            raise ValueError("WireGuard dump contains a malformed peer row")
        key = fields[0]
        if not key or key == "(none)":
            continue
        try:
            rx, tx = int(fields[5]), int(fields[6])
        except (TypeError, ValueError):
            raise ValueError("WireGuard returned invalid byte counters") from None
        if rx < 0 or tx < 0:
            raise ValueError("WireGuard returned negative byte counters")
        peers[key] = Counters(rx, tx)
    return peers


def _validate_wireguard_public_key(value: str) -> str:
    """Accept only canonical base64-encoded 32-byte WireGuard public keys."""
    if not isinstance(value, str) or len(value) != 44:
        raise ValueError("trusted registry contains an invalid WireGuard public key")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise ValueError("trusted registry contains an invalid WireGuard public key") from None
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("trusted registry contains an invalid WireGuard public key")
    return value


def _validate_peer_allowed_ips(value: str) -> str:
    """A customer peer may own exactly one IPv4 host address, never a route."""
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("trusted registry contains invalid allowed_ips")
    try:
        interface = ipaddress.ip_interface(value)
    except ValueError:
        raise ValueError("trusted registry contains invalid allowed_ips") from None
    address = interface.ip
    if (
        interface.version != 4
        or interface.network.prefixlen != 32
        or str(interface) != value
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
    ):
        raise ValueError("trusted registry allowed_ips must be one canonical IPv4 /32 host")
    return str(interface)


def sign_request(secret: str, timestamp: str, event_id: str, body: bytes,
                 path: str = METERING_PATH, method: str = "POST") -> str:
    if len(secret) < 32:
        raise ValueError("shared secret must contain at least 32 characters")
    digest = hashlib.sha256(body).hexdigest()
    canonical = "\n".join([method.upper(), path, timestamp, event_id, digest])
    return hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def load_peers(path: str) -> dict[str, Peer]:
    """Legacy offline/test registry parser; production uses the signed API registry."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    items = raw.get("peers") if isinstance(raw, dict) else None
    if not isinstance(items, list):
        raise ValueError("peer registry must contain a peers array")
    result = {}
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("peer registry entries must be objects")
        client_id, key = item.get("client_id"), item.get("public_key")
        allowed_ips = item.get("allowed_ips", "")
        if type(client_id) is not int or client_id <= 0:
            raise ValueError("client_id must be a positive integer")
        if not isinstance(key, str) or not key.strip() or len(key) > 128:
            raise ValueError("public_key is invalid")
        if not isinstance(allowed_ips, str) or len(allowed_ips) > 128:
            raise ValueError("allowed_ips is invalid")
        if key in result:
            raise ValueError("duplicate public_key in peer registry")
        result[key] = Peer(client_id, key, allowed_ips)
    return result


class MeteringStore:
    """Durable byte baselines, managed peer inventory, and retry-safe outbox."""

    def __init__(self, path: str):
        self.db = sqlite3.connect(path, timeout=10)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS peer_counters(
            public_key TEXT PRIMARY KEY, total_bytes INTEGER NOT NULL CHECK(total_bytes>=0),
            disabled INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS pending_events(
            public_key TEXT PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, client_id INTEGER NOT NULL,
            bytes_used INTEGER NOT NULL CHECK(bytes_used>0), body BLOB NOT NULL,
            created_at REAL NOT NULL DEFAULT 0, failure_status INTEGER);
          CREATE TABLE IF NOT EXISTS agent_state(key TEXT PRIMARY KEY, value REAL NOT NULL);
          CREATE TABLE IF NOT EXISTS managed_peers(
            public_key TEXT PRIMARY KEY, client_id INTEGER NOT NULL, allowed_ips TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS revoked_peer_sources(
            address TEXT PRIMARY KEY, recorded_at REAL NOT NULL);
        """)
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(pending_events)")}
        if "created_at" not in columns:
            self.db.execute("ALTER TABLE pending_events ADD COLUMN created_at REAL NOT NULL DEFAULT 0")
        if "failure_status" not in columns:
            self.db.execute("ALTER TABLE pending_events ADD COLUMN failure_status INTEGER")
        self.db.commit()

    def disabled(self, key):
        row = self.db.execute("SELECT disabled FROM peer_counters WHERE public_key=?", (key,)).fetchone()
        return bool(row and row[0])

    def pending(self, key):
        row = self.db.execute(
            "SELECT event_id,client_id,bytes_used,body,created_at,failure_status FROM pending_events WHERE public_key=?",
            (key,),
        ).fetchone()
        return PendingEvent(row[0], row[1], key, row[2], bytes(row[3]), row[4], row[5]) if row else None

    def pending_all(self):
        rows = self.db.execute(
            """SELECT event_id,client_id,public_key,bytes_used,body,created_at,failure_status
               FROM pending_events WHERE failure_status IS NULL ORDER BY created_at"""
        ).fetchall()
        return [PendingEvent(row[0], row[1], row[2], row[3], bytes(row[4]), row[5], row[6]) for row in rows]

    def prepare_delta(self, peer, current_total):
        if current_total < 0:
            raise ValueError("counter total cannot be negative")
        with self.db:
            row = self.db.execute(
                "SELECT total_bytes,disabled FROM peer_counters WHERE public_key=?",
                (peer.public_key,),
            ).fetchone()
            if row and row[1]:
                return None
            previous = row[0] if row else 0
            delta = current_total - previous if current_total >= previous else current_total
            self.db.execute(
                """INSERT INTO peer_counters(public_key,total_bytes,disabled) VALUES(?,?,0)
                   ON CONFLICT(public_key) DO UPDATE SET total_bytes=excluded.total_bytes""",
                (peer.public_key, current_total),
            )
            if delta <= 0:
                return None
            event_id = "wg-" + uuid.uuid4().hex
            body = json.dumps(
                {"client_id": peer.client_id, "bytes_used": delta},
                separators=(",", ":"), sort_keys=True,
            ).encode()
            self.db.execute(
                """INSERT INTO pending_events
                   (public_key,event_id,client_id,bytes_used,body,created_at)
                   VALUES(?,?,?,?,?,?)""",
                (peer.public_key, event_id, peer.client_id, delta, body, time.time()),
            )
        return self.pending(peer.public_key)

    def acknowledge(self, key, event_id):
        with self.db:
            self.db.execute(
                "DELETE FROM pending_events WHERE public_key=? AND event_id=?",
                (key, event_id),
            )

    def mark_disabled(self, key):
        with self.db:
            self.db.execute(
                """INSERT INTO peer_counters(public_key,total_bytes,disabled) VALUES(?,0,1)
                   ON CONFLICT(public_key) DO UPDATE SET disabled=1""",
                (key,),
            )
    
    def mark_permanent_failure(self, key, event_id, status):
        with self.db:
            self.db.execute(
                "UPDATE pending_events SET failure_status=? WHERE public_key=? AND event_id=?",
                (status, key, event_id),
            )


    def discard_pending(self, key):
        with self.db:
            self.db.execute("DELETE FROM pending_events WHERE public_key=?", (key,))

    def enable(self, key):
        with self.db:
            self.db.execute(
                """INSERT INTO peer_counters(public_key,total_bytes,disabled) VALUES(?,0,0)
                   ON CONFLICT(public_key) DO UPDATE SET disabled=0""",
                (key,),
            )

    def replace_registry(self, peers: dict[str, Peer]) -> list[str]:
        old = {row[0] for row in self.db.execute("SELECT public_key FROM managed_peers")}
        new = set(peers)
        with self.db:
            self.db.executemany(
                """INSERT INTO managed_peers(public_key,client_id,allowed_ips) VALUES(?,?,?)
                   ON CONFLICT(public_key) DO UPDATE SET
                   client_id=excluded.client_id, allowed_ips=excluded.allowed_ips""",
                [(p.public_key, p.client_id, p.allowed_ips) for p in peers.values()],
            )
        return sorted(old - new)

    def unmanage(self, key):
        with self.db:
            self.db.execute("DELETE FROM managed_peers WHERE public_key=?", (key,))

    def current_peers(self) -> dict[str, Peer]:
        rows = self.db.execute(
            "SELECT public_key,client_id,allowed_ips FROM managed_peers"
        ).fetchall()
        return {key: Peer(client_id, key, allowed_ips) for key, client_id, allowed_ips in rows}

    def managed_peer(self, key):
        row = self.db.execute(
            "SELECT client_id,allowed_ips FROM managed_peers WHERE public_key=?", (key,)
        ).fetchone()
        return Peer(row[0], key, row[1]) if row else None

    def remember_revoked_source(self, allowed_ips):
        interface = _validate_peer_allowed_ips(allowed_ips)
        address = str(ipaddress.ip_interface(interface).ip)
        with self.db:
            self.db.execute(
                "INSERT OR IGNORE INTO revoked_peer_sources(address,recorded_at) VALUES(?,?)",
                (address, time.time()),
            )

    def forget_revoked_source(self, allowed_ips):
        interface = _validate_peer_allowed_ips(allowed_ips)
        address = str(ipaddress.ip_interface(interface).ip)
        with self.db:
            self.db.execute("DELETE FROM revoked_peer_sources WHERE address=?", (address,))

    def revoked_sources(self):
        return [row[0] for row in self.db.execute(
            "SELECT address FROM revoked_peer_sources ORDER BY address"
        ).fetchall()]

    def has_revoked_source(self, allowed_ips):
        interface = _validate_peer_allowed_ips(allowed_ips)
        address = str(ipaddress.ip_interface(interface).ip)
        return self.db.execute(
            "SELECT 1 FROM revoked_peer_sources WHERE address=?", (address,)
        ).fetchone() is not None

    def note_failure(self, name: str, now: float) -> float:
        key = f"{name}_fail_since"
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO agent_state(key,value) VALUES(?,?)", (key, now))
        return self.db.execute("SELECT value FROM agent_state WHERE key=?", (key,)).fetchone()[0]

    def clear_failure(self, name: str):
        with self.db:
            self.db.execute("DELETE FROM agent_state WHERE key=?", (f"{name}_fail_since",))

    def close(self):
        self.db.close()


class WireGuardMeter:
    def __init__(self, *, api_base_url, secret, interface, peers, store,
                 command: Callable = subprocess.run, post: Callable | None = None,
                 registry_fetcher: Callable | None = None, max_outage_seconds: int = 120):
        parsed = urlsplit(api_base_url)
        if (
            parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment
            or parsed.username or parsed.password or parsed.path not in ("", "/")
        ):
            raise ValueError("API base URL must be an HTTPS origin without credentials, path, query, or fragment")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface):
            raise ValueError("invalid WireGuard interface name")
        if len(secret) < 32:
            raise ValueError("shared secret must contain at least 32 characters")
        if max_outage_seconds < 1:
            raise ValueError("max outage window must be positive")
        self.api_base_url = api_base_url.rstrip("/")
        self.api_url = self.api_base_url + METERING_PATH
        self.registry_url = self.api_base_url + REGISTRY_PATH
        self.secret, self.interface, self.peers, self.store = secret, interface, peers, store
        self.command = command
        self.post = post or self._https_post
        self.registry_fetcher = registry_fetcher if registry_fetcher is not None else (
            self._https_registry_fetch if not peers else None
        )
        self.max_outage_seconds = max_outage_seconds

    @staticmethod
    def _signed_headers(secret, path, body, event_id=None):
        timestamp = str(int(time.time()))
        event_id = event_id or (("registry-" if path == REGISTRY_PATH else "wg-") + uuid.uuid4().hex)
        signature = sign_request(secret, timestamp, event_id, body, path=path)
        return {
            "Content-Type": "application/json",
            "X-RMA-Timestamp": timestamp,
            "X-RMA-Event-Id": event_id,
            "X-RMA-Signature": signature,
        }

    @staticmethod
    def _https_post(url, headers, body):
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=8) as response:
                return response.status
        except urllib.error.HTTPError as exc:
            return exc.code

    def _https_registry_fetch(self, url, headers, body):
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=8) as response:
            if response.status != 200:
                raise RuntimeError(f"registry endpoint returned HTTP {response.status}")
            payload = json.loads(response.read(1024 * 1024))
        return payload

    def _wg(self, *args):
        return self.command(["wg", *args], check=True, capture_output=True, text=True, timeout=8)

    def sample(self):
        return parse_wg_dump(self._wg("show", self.interface, "dump").stdout)

    def _verify_revocation_guards(self):
        # Both local traffic and forwarded traffic must be filtered before
        # ordinary filter-priority established-flow accepts.
        for hook in ("input", "forward"):
            result = self.command(
                ["nft", "-a", "list", "chain", "inet", "rma_guard", hook],
                check=False, capture_output=True, text=True, timeout=8,
            )
            if result.returncode != 0:
                raise RuntimeError(f"required nftables {hook} revocation chain is unavailable")
            output = result.stdout
            priority_marker = f"hook {hook} priority "
            priority = None
            if priority_marker in output:
                try:
                    priority = int(output.split(priority_marker, 1)[1].split(";", 1)[0].split()[0])
                except (ValueError, IndexError):
                    priority = None
            guard = (
                f'iifname "{self.interface}" ip saddr @revoked_peer_sources' in output
                and " drop" in output
            )
            if priority is None or priority > -10 or not guard:
                raise RuntimeError(f"nftables {hook} revocation guard is missing or not early enough")

    def _nft_element_present(self, address):
        address = str(ipaddress.ip_address(address))
        if ipaddress.ip_address(address).version != 4:
            raise ValueError("revocation firewall supports IPv4 peer addresses only")
        result = self.command(
            ["nft", "get", "element", "inet", "rma_guard", "revoked_peer_sources", "{", address, "}"],
            check=False, capture_output=True, text=True, timeout=8,
        )
        return result.returncode == 0

    def _revoke_peer_source(self, allowed_ips):
        self._verify_revocation_guards()
        interface = _validate_peer_allowed_ips(allowed_ips)
        address = str(ipaddress.ip_interface(interface).ip)
        # Persist intent before touching the volatile nftables set. A crash or
        # firewall reload can therefore be repaired on the next agent start.
        self.store.remember_revoked_source(interface)
        if self._nft_element_present(address):
            return
        try:
            self.command(
                ["nft", "add", "element", "inet", "rma_guard", "revoked_peer_sources", "{", address, "}"],
                check=True, capture_output=True, text=True, timeout=8,
            )
        except subprocess.CalledProcessError:
            # A concurrent reconciler may have inserted the same element.
            if not self._nft_element_present(address):
                raise

    def restore_revoked_sources(self):
        """Rehydrate the volatile firewall set from the durable local revocation ledger."""
        self._verify_revocation_guards()
        for address in self.store.revoked_sources():
            if self._nft_element_present(address):
                continue
            try:
                self.command(
                    ["nft", "add", "element", "inet", "rma_guard", "revoked_peer_sources", "{", address, "}"],
                    check=True, capture_output=True, text=True, timeout=8,
                )
            except subprocess.CalledProcessError:
                # Treat an already-present element as success; propagate all
                # other failures so reconciliation remains fail-closed.
                if not self._nft_element_present(address):
                    raise

    def _unrevoke_peer_source(self, allowed_ips):
        self._verify_revocation_guards()
        interface = _validate_peer_allowed_ips(allowed_ips)
        address = str(ipaddress.ip_interface(interface).ip)
        if self._nft_element_present(address):
            self.command(
                ["nft", "delete", "element", "inet", "rma_guard", "revoked_peer_sources", "{", address, "}"],
                check=True, capture_output=True, text=True, timeout=8,
            )
        self.store.forget_revoked_source(interface)

    def _remove_peer(self, key, peer=None, *, require_firewall=False):
        peer = peer or self.store.managed_peer(key) or self.peers.get(key)
        if peer is not None and peer.allowed_ips:
            # Prefer the network-layer guard. If nftables is unavailable, still
            # remove the WireGuard key to stop new authenticated tunnel traffic;
            # do not ACK until a later reconciliation installs the source guard.
            try:
                self._revoke_peer_source(peer.allowed_ips)
            except Exception:
                try:
                    self._wg("set", self.interface, "peer", key, "remove")
                    self.store.mark_disabled(key)
                    self.store.unmanage(key)
                except Exception as remove_exc:
                    LOG.critical("firewall guard and WireGuard fallback both failed for %s (%s)",
                                 key[:10], type(remove_exc).__name__)
                raise
        elif require_firewall:
            raise ValueError("revocation requires a validated peer IPv4 /32 address")
        self._wg("set", self.interface, "peer", key, "remove")
        self.store.mark_disabled(key)
        self.store.unmanage(key)
        LOG.warning("managed peer suspended: %s", key[:10])

    def _register_peer(self, peer):
        key = _validate_wireguard_public_key(peer.public_key)
        allowed_ips = _validate_peer_allowed_ips(peer.allowed_ips)
        # Install WireGuard first; keep the source guard until registration succeeds.
        self._wg("set", self.interface, "peer", key, "allowed-ips", allowed_ips)
        self._unrevoke_peer_source(allowed_ips)
        self.store.enable(peer.public_key)
        LOG.info("managed peer reconciled: client_id=%s", peer.client_id)

    def _fetch_registry(self):
        body = json.dumps({"interface": self.interface}, separators=(",", ":"), sort_keys=True).encode()
        headers = self._signed_headers(self.secret, REGISTRY_PATH, body)
        payload = self.registry_fetcher(self.registry_url, headers, body)
        if not isinstance(payload, dict) or payload.get("interface") != self.interface:
            raise ValueError("trusted registry response has the wrong interface")
        items, removals = payload.get("peers"), payload.get("remove_peers")
        if not isinstance(items, list) or not isinstance(removals, list) or len(items) + len(removals) > 2000:
            raise ValueError("trusted registry response has invalid peer lists")
        peers, remove_peers = {}, {}
        assigned_ips = set()
        for item in items:
            if not isinstance(item, dict):
                raise ValueError("trusted registry contains an invalid peer")
            client_id, key, allowed_ips = item.get("client_id"), item.get("public_key"), item.get("allowed_ips")
            state = item.get("state", "peer_registered")
            if type(client_id) is not int or client_id <= 0:
                raise ValueError("trusted registry client_id is invalid")
            key = _validate_wireguard_public_key(key)
            allowed_ips = _validate_peer_allowed_ips(allowed_ips)
            if state not in ("pending_peer_registration", "peer_registered"):
                raise ValueError("trusted registry peer state is invalid")
            if key in peers:
                raise ValueError("trusted registry contains duplicate public keys")
            if allowed_ips in assigned_ips:
                raise ValueError("trusted registry contains duplicate peer IP addresses")
            assigned_ips.add(allowed_ips)
            peers[key] = Peer(client_id, key, allowed_ips, state)
        for item in removals:
            if not isinstance(item, dict):
                raise ValueError("trusted removal registry contains an invalid peer")
            client_id, key = item.get("client_id"), item.get("public_key")
            allowed_ips, state = item.get("allowed_ips"), item.get("state")
            if type(client_id) is not int or client_id <= 0:
                raise ValueError("trusted removal registry peer identity is invalid")
            key = _validate_wireguard_public_key(key)
            allowed_ips = _validate_peer_allowed_ips(allowed_ips)
            if state not in ("revoked", "suspended") or key in remove_peers or key in peers:
                raise ValueError("trusted removal registry peer state is invalid")
            if allowed_ips in assigned_ips:
                raise ValueError("trusted registry contains duplicate peer IP addresses")
            assigned_ips.add(allowed_ips)
            remove_peers[key] = Peer(client_id, key, allowed_ips, state)
        return peers, remove_peers

    def _ack_peer_status(self, peer, state):
        body = json.dumps(
            {"client_id": peer.client_id, "public_key": peer.public_key, "state": state},
            separators=(",", ":"), sort_keys=True,
        ).encode()
        headers = self._signed_headers(self.secret, PEER_ACK_PATH, body)
        status = self.post(self.api_base_url + PEER_ACK_PATH, headers, body)
        if not 200 <= status < 300:
            LOG.error("backend did not acknowledge peer %s state=%s (HTTP %s)", peer.client_id, state, status)
            return False
        return True

    def _flush_pending(self, peer):
        pending = self.store.pending(peer.public_key)
        if pending is None:
            return True
        if pending.failure_status is not None:
            self._remove_peer_for_usage_failure(peer.public_key, peer.client_id, pending.failure_status)
            return False
        try:
            status = self._send(pending)
        except Exception as exc:
            if time.time() - pending.created_at >= self.max_outage_seconds:
                self._remove_peer_for_usage_failure(peer.public_key, peer.client_id, "network outage")
            else:
                LOG.warning("pending usage remains queued for client %s (%s)", peer.client_id, type(exc).__name__)
            return False
        if 200 <= status < 300:
            self.store.acknowledge(peer.public_key, pending.event_id)
            return True
        self._handle_usage_response(pending, status)
        return False

    def sync_registry(self):
        if self.registry_fetcher is None:
            return self.peers
        active, removals = self._fetch_registry()
        # Restore durable revocations before any authorized peer can be
        # reconciled or re-enabled. If the firewall contract is broken, still
        # attempt immediate WireGuard-key removal for backend-revoked peers;
        # never ACK them until the source guard can be restored.
        try:
            self.restore_revoked_sources()
        except Exception as guard_exc:
            for key, peer in removals.items():
                try:
                    self._remove_peer(key, peer, require_firewall=True)
                except Exception as remove_exc:
                    LOG.critical(
                        "revoked peer fallback removal failed for client %s (%s)",
                        peer.client_id, type(remove_exc).__name__,
                    )
            # Do not proceed with any active-peer reconciliation in this cycle.
            # Fallback key removals above are still attempted, but no revocation
            # ACK is possible until the firewall contract is repaired.
            self.peers = {}
            LOG.critical("revocation firewall unavailable; peer activation paused (%s)",
                         type(guard_exc).__name__)
            return {}
        previously_managed = self.store.current_peers()
        stale_keys = self.store.replace_registry(active)
        removal_map = dict(removals)
        for key in stale_keys:
            if key not in removal_map:
                old_peer = previously_managed.get(key)
                if old_peer is not None:
                    removal_map[key] = Peer(old_peer.client_id, key, old_peer.allowed_ips, "suspended")
        for key, peer in removal_map.items():
            try:
                self._flush_pending(peer)
                if not self.store.disabled(key):
                    self._remove_peer(key, peer, require_firewall=True)
                else:
                    # Reassert the source guard on every reconciliation before ACK.
                    self._revoke_peer_source(peer.allowed_ips)
                    self.store.unmanage(key)
                self._ack_peer_status(peer, peer.state)
            except Exception as exc:
                LOG.critical("managed peer removal/ack failed for client %s (%s)", peer.client_id, type(exc).__name__)
        for key, peer in active.items():
            # Never re-enable a peer while an older usage interval is unacknowledged.
            if not self._flush_pending(peer):
                continue
            # An IP may have been revoked before a crash and subsequently
            # authorized again. Install/update the WG peer first, then remove
            # its persistent source guard in the same safe order.
            if self.store.has_revoked_source(peer.allowed_ips):
                self._register_peer(peer)
            else:
                self.store.enable(key)
        self.peers = active
        return active

    def _send(self, event):
        headers = self._signed_headers(self.secret, METERING_PATH, event.body, event.event_id)
        return self.post(self.api_url, headers, event.body)

    def _remove_peer_for_usage_failure(self, key, client_id, reason):
        if self.store.disabled(key):
            return
        try:
            self._remove_peer(key)
        except Exception as exc:
            LOG.critical(
                "peer removal failed after usage delivery problem for client %s (%s: %s); operator action required",
                client_id,
                reason,
                type(exc).__name__,
            )

    def _handle_usage_response(self, event, status):
        permanent_statuses = {400, 401, 403, 404, 409, 410, 422}
        if status in permanent_statuses:
            self.store.mark_permanent_failure(event.public_key, event.event_id, status)
            LOG.critical(
                "usage event for client %s was permanently rejected with HTTP %s; event retained for operator review",
                event.client_id,
                status,
            )
            self._remove_peer_for_usage_failure(event.public_key, event.client_id, f"HTTP {status}")
            return
        if time.time() - event.created_at >= self.max_outage_seconds:
            LOG.critical(
                "usage event for client %s remains unaccepted after the outage window (HTTP %s); event retained",
                event.client_id,
                status,
            )
            self._remove_peer_for_usage_failure(event.public_key, event.client_id, f"HTTP {status}")
        else:
            LOG.warning(
                "usage API returned HTTP %s for client %s; event retained for bounded retry",
                status,
                event.client_id,
            )

    def run_once(self):
        registry_ok = False
        try:
            self.sync_registry()
            self.store.clear_failure("registry")
            registry_ok = True
        except Exception as exc:
            now = time.time()
            failed_since = self.store.note_failure("registry", now)
            self.peers = self.store.current_peers()
            if now - failed_since >= self.max_outage_seconds:
                for key in list(self.peers):
                    if self.store.disabled(key):
                        continue
                    try:
                        self._remove_peer(key)
                    except Exception as remove_exc:
                        LOG.critical("registry outage and peer removal failed for %s (%s)", key[:10], type(remove_exc).__name__)
            else:
                LOG.error("trusted peer registry unavailable; bounded fail-closed timer started (%s)", type(exc).__name__)

        # Retry all durable outbox events, including events for peers already
        # removed during an outage or revocation. Never silently lose usage.
        for pending_event in self.store.pending_all():
            try:
                status = self._send(pending_event)
            except Exception as exc:
                if time.time() - pending_event.created_at >= self.max_outage_seconds and not self.store.disabled(pending_event.public_key):
                    try:
                        self._remove_peer(pending_event.public_key)
                    except Exception as remove_exc:
                        LOG.critical("outbox outage and peer removal failed for %s (%s)", pending_event.public_key[:10], type(remove_exc).__name__)
                else:
                    LOG.warning("usage outbox retry remains pending for client %s (%s)", pending_event.client_id, type(exc).__name__)
                continue
            if 200 <= status < 300:
                self.store.acknowledge(pending_event.public_key, pending_event.event_id)
            else:
                self._handle_usage_response(pending_event, status)

        try:
            counters = self.sample()
            self.store.clear_failure("sample")
        except Exception as exc:
            now = time.time()
            failed_since = self.store.note_failure("sample", now)
            if now - failed_since >= self.max_outage_seconds:
                for key in self.peers:
                    if self.store.disabled(key):
                        continue
                    try:
                        self._remove_peer(key)
                    except Exception as remove_exc:
                        LOG.critical("WireGuard sampling outage and peer removal failed for %s (%s)", key[:10], type(remove_exc).__name__)
            else:
                LOG.error("WireGuard sampling failed; bounded fail-closed timer started (%s)", type(exc).__name__)
            return

        for key, peer in list(self.peers.items()):
            if self.store.disabled(key):
                continue
            current = counters.get(key)
            if current is None and registry_ok:
                try:
                    self._register_peer(peer)
                    counters = self.sample()
                    current = counters.get(key)
                except Exception as exc:
                    LOG.critical("authorized peer registration failed for client %s (%s)", peer.client_id, type(exc).__name__)
                    continue
            if current is None:
                continue
            if peer.state == "pending_peer_registration":
                if not self._ack_peer_status(peer, "peer_registered"):
                    continue
            pending = self.store.pending(key)
            if pending is not None and pending.failure_status is not None:
                self._remove_peer_for_usage_failure(key, peer.client_id, pending.failure_status)
                continue
            if pending is None:
                pending = self.store.prepare_delta(peer, current.total)
            if pending is None:
                continue
            try:
                status = self._send(pending)
            except Exception as exc:
                if time.time() - pending.created_at >= self.max_outage_seconds:
                    try:
                        self._remove_peer(key)
                    except Exception as remove_exc:
                        LOG.critical("metering outage and peer removal failed for %s (%s)", key[:10], type(remove_exc).__name__)
                else:
                    LOG.error("usage delivery failed; event retained for bounded retry (%s)", type(exc).__name__)
                continue
            if 200 <= status < 300:
                self.store.acknowledge(key, pending.event_id)
            else:
                self._handle_usage_response(pending, status)


def build_from_env():
    api = os.environ.get("RMA_API_BASE_URL", "")
    secret = os.environ.get("RMA_METERING_SHARED_SECRET", "")
    interface = os.environ.get("RMA_WG_INTERFACE", "wg0")
    state_path = os.environ.get("RMA_METERING_STATE_DB", "/var/lib/rma-meter/usage.sqlite3")
    interval = int(os.environ.get("RMA_POLL_INTERVAL_SECONDS", "15"))
    max_outage = int(os.environ.get("RMA_METERING_MAX_OUTAGE_SECONDS", "120"))
    if interval < 5 or interval > 300:
        raise ValueError("poll interval must be between 5 and 300 seconds")
    Path(state_path).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(Path(state_path).parent, 0o700)
    store = MeteringStore(state_path)
    os.chmod(state_path, 0o600)
    meter = WireGuardMeter(
        api_base_url=api, secret=secret, interface=interface, peers={},
        store=store, max_outage_seconds=max_outage,
    )
    return meter, store, interval


def main():
    parser = argparse.ArgumentParser(description="R&MA trusted WireGuard metering agent")
    parser.add_argument("--once", action="store_true", help="run one live reconciliation/metering cycle")
    parser.add_argument("--check", action="store_true", help="read-only API and WireGuard preflight; makes no changes")
    args = parser.parse_args()
    logging.basicConfig(
        level=os.environ.get("RMA_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    meter, store, interval = build_from_env()
    try:
        if args.check:
            peers, removals = meter._fetch_registry()
            observed = meter.sample()
            missing = sum(1 for key in peers if key not in observed)
            result = {
                "api_registry_authenticated": True,
                "wireguard_interface_readable": True,
                "interface": meter.interface,
                "authorized_peer_count": len(peers),
                "authorized_peers_missing_from_interface": missing,
                "pending_removal_count": len(removals),
                "observed_interface_peer_count": len(observed),
                "no_peer_changes": True,
                "no_usage_submission": True,
            }
            print(json.dumps(result, sort_keys=True))
            return 0 if missing == 0 and not removals else 2
        while True:
            try:
                meter.run_once()
            except Exception as exc:
                LOG.error("metering cycle failed (%s)", type(exc).__name__)
            if args.once:
                return 0
            time.sleep(interval)
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
