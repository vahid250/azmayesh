#!/usr/bin/env python3
"""Trusted WireGuard host agent: peer reconciliation, byte metering, quota enforcement."""
from __future__ import annotations

import argparse
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
            created_at REAL NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS agent_state(key TEXT PRIMARY KEY, value REAL NOT NULL);
          CREATE TABLE IF NOT EXISTS managed_peers(
            public_key TEXT PRIMARY KEY, client_id INTEGER NOT NULL, allowed_ips TEXT NOT NULL);
        """)
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(pending_events)")}
        if "created_at" not in columns:
            self.db.execute("ALTER TABLE pending_events ADD COLUMN created_at REAL NOT NULL DEFAULT 0")
        self.db.commit()

    def disabled(self, key):
        row = self.db.execute("SELECT disabled FROM peer_counters WHERE public_key=?", (key,)).fetchone()
        return bool(row and row[0])

    def pending(self, key):
        row = self.db.execute(
            "SELECT event_id,client_id,bytes_used,body,created_at FROM pending_events WHERE public_key=?",
            (key,),
        ).fetchone()
        return PendingEvent(row[0], row[1], key, row[2], bytes(row[3]), row[4]) if row else None

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
        if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
            raise ValueError("API base URL must use HTTPS")
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

    def _remove_peer(self, key):
        self._wg("set", self.interface, "peer", key, "remove")
        self.store.mark_disabled(key)
        self.store.unmanage(key)
        LOG.warning("managed peer suspended: %s", key[:10])

    def _register_peer(self, peer):
        if not peer.allowed_ips:
            raise ValueError("trusted registry peer is missing allowed_ips")
        try:
            ipaddress.ip_interface(peer.allowed_ips)
        except ValueError:
            raise ValueError("trusted registry contains invalid allowed_ips") from None
        self._wg("set", self.interface, "peer", peer.public_key, "allowed-ips", peer.allowed_ips)
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
        for item in items:
            if not isinstance(item, dict):
                raise ValueError("trusted registry contains an invalid peer")
            client_id, key, allowed_ips = item.get("client_id"), item.get("public_key"), item.get("allowed_ips")
            state = item.get("state", "peer_registered")
            if type(client_id) is not int or client_id <= 0:
                raise ValueError("trusted registry client_id is invalid")
            if not isinstance(key, str) or not key.strip() or len(key) > 128:
                raise ValueError("trusted registry public_key is invalid")
            if not isinstance(allowed_ips, str) or len(allowed_ips) > 128:
                raise ValueError("trusted registry allowed_ips is invalid")
            if state not in ("pending_peer_registration", "peer_registered"):
                raise ValueError("trusted registry peer state is invalid")
            try:
                ipaddress.ip_interface(allowed_ips)
            except ValueError:
                raise ValueError("trusted registry allowed_ips is invalid") from None
            if key in peers:
                raise ValueError("trusted registry contains duplicate public keys")
            peers[key] = Peer(client_id, key, allowed_ips, state)
        for item in removals:
            if not isinstance(item, dict):
                raise ValueError("trusted removal registry contains an invalid peer")
            client_id, key, state = item.get("client_id"), item.get("public_key"), item.get("state")
            if type(client_id) is not int or client_id <= 0 or not isinstance(key, str) or not key.strip() or len(key) > 128:
                raise ValueError("trusted removal registry peer identity is invalid")
            if state not in ("revoked", "suspended") or key in remove_peers or key in peers:
                raise ValueError("trusted removal registry peer state is invalid")
            remove_peers[key] = Peer(client_id, key, "", state)
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

    def sync_registry(self):
        if self.registry_fetcher is None:
            return self.peers
        active, removals = self._fetch_registry()
        previously_managed = self.store.current_peers()
        stale_keys = self.store.replace_registry(active)
        removal_map = dict(removals)
        for key in stale_keys:
            if key not in removal_map:
                old_peer = previously_managed.get(key)
                if old_peer is not None:
                    removal_map[key] = Peer(old_peer.client_id, key, "", "suspended")
        for key, peer in removal_map.items():
            try:
                if not self.store.disabled(key):
                    self._remove_peer(key)
                else:
                    self.store.unmanage(key)
                self._ack_peer_status(peer, peer.state)
            except Exception as exc:
                LOG.critical("managed peer removal/ack failed for client %s (%s)", peer.client_id, type(exc).__name__)
        for key in active:
            self.store.enable(key)
        self.peers = active
        return active

    def _send(self, event):
        headers = self._signed_headers(self.secret, METERING_PATH, event.body, event.event_id)
        return self.post(self.api_url, headers, event.body)

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
            elif status in (401, 403, 404, 410):
                try:
                    self._remove_peer(key)
                except Exception as exc:
                    LOG.critical("peer enforcement failed for %s (%s); operator action required", key[:10], type(exc).__name__)
            elif status == 409:
                LOG.warning("backend rejected usage for client %s; awaiting authoritative registry removal", peer.client_id)
            elif time.time() - pending.created_at >= self.max_outage_seconds:
                try:
                    self._remove_peer(key)
                except Exception as exc:
                    LOG.critical("metering outage and peer removal failed for %s (%s)", key[:10], type(exc).__name__)
            else:
                LOG.error("metering API returned HTTP %s; event retained for bounded retry", status)


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
    meter = WireGuardMeter(
        api_base_url=api, secret=secret, interface=interface, peers={},
        store=store, max_outage_seconds=max_outage,
    )
    return meter, store, interval


def main():
    parser = argparse.ArgumentParser(description="R&MA trusted WireGuard metering agent")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(
        level=os.environ.get("RMA_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    meter, store, interval = build_from_env()
    try:
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
