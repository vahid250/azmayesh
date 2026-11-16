#!/usr/bin/env python3
"""Trusted host-side WireGuard byte metering and quota enforcement."""
from __future__ import annotations
import argparse, hashlib, hmac, json, logging, os, re, sqlite3, subprocess, time, urllib.error, urllib.request, uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

METERING_PATH = "/api/v1/internal/metering/usage"
LOG = logging.getLogger("rma-wg-meter")

@dataclass(frozen=True)
class Peer:
    client_id: int
    public_key: str

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
    """Parse wg show IFACE dump output; skip the interface header row."""
    peers = {}
    for line in output.splitlines()[1:]:
        fields = line.split("\t")
        if len(fields) < 8:
            continue
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

def sign_request(secret: str, timestamp: str, event_id: str, body: bytes) -> str:
    if len(secret) < 32:
        raise ValueError("shared secret must contain at least 32 characters")
    digest = hashlib.sha256(body).hexdigest()
    canonical = "\n".join(["POST", METERING_PATH, timestamp, event_id, digest])
    return hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()

def load_peers(path: str) -> dict[str, Peer]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    items = raw.get("peers") if isinstance(raw, dict) else None
    if not isinstance(items, list):
        raise ValueError("peer registry must contain a peers array")
    result = {}
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("peer registry entries must be objects")
        client_id, key = item.get("client_id"), item.get("public_key")
        if type(client_id) is not int or client_id <= 0:
            raise ValueError("client_id must be a positive integer")
        if not isinstance(key, str) or not key.strip() or len(key) > 128:
            raise ValueError("public_key is invalid")
        if key in result:
            raise ValueError("duplicate public_key in peer registry")
        result[key] = Peer(client_id, key)
    return result

class MeteringStore:
    """Durable counters and retry-safe outbox."""
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
        """)
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(pending_events)")}
        if "created_at" not in columns:
            self.db.execute("ALTER TABLE pending_events ADD COLUMN created_at REAL NOT NULL DEFAULT 0")
        self.db.commit()

    def disabled(self, key):
        row = self.db.execute("SELECT disabled FROM peer_counters WHERE public_key=?", (key,)).fetchone()
        return bool(row and row[0])

    def pending(self, key):
        row = self.db.execute("SELECT event_id,client_id,bytes_used,body,created_at FROM pending_events WHERE public_key=?", (key,)).fetchone()
        return PendingEvent(row[0], row[1], key, row[2], bytes(row[3]), row[4]) if row else None

    def prepare_delta(self, peer, current_total):
        if current_total < 0:
            raise ValueError("counter total cannot be negative")
        with self.db:
            row = self.db.execute("SELECT total_bytes,disabled FROM peer_counters WHERE public_key=?", (peer.public_key,)).fetchone()
            if row and row[1]:
                return None
            previous = row[0] if row else 0
            # If the interface counters reset, count the new post-reset value.
            delta = current_total - previous if current_total >= previous else current_total
            self.db.execute("""INSERT INTO peer_counters(public_key,total_bytes,disabled) VALUES(?,?,0)
              ON CONFLICT(public_key) DO UPDATE SET total_bytes=excluded.total_bytes""", (peer.public_key,current_total))
            if delta <= 0:
                return None
            event_id = "wg-" + uuid.uuid4().hex
            body = json.dumps({"client_id":peer.client_id,"bytes_used":delta},separators=(",",":"),sort_keys=True).encode()
            self.db.execute("INSERT INTO pending_events(public_key,event_id,client_id,bytes_used,body,created_at) VALUES(?,?,?,?,?,?)",(peer.public_key,event_id,peer.client_id,delta,body,time.time()))
        return self.pending(peer.public_key)

    def acknowledge(self, key, event_id):
        with self.db:
            self.db.execute("DELETE FROM pending_events WHERE public_key=? AND event_id=?",(key,event_id))

    def mark_disabled(self, key):
        with self.db:
            self.db.execute("""INSERT INTO peer_counters(public_key,total_bytes,disabled) VALUES(?,0,1)
              ON CONFLICT(public_key) DO UPDATE SET disabled=1""",(key,))
            self.db.execute("DELETE FROM pending_events WHERE public_key=?",(key,))

    def close(self):
        self.db.close()

class WireGuardMeter:
    def __init__(self, *, api_base_url, secret, interface, peers, store,
                 command: Callable = subprocess.run, post: Callable | None = None, max_outage_seconds: int = 120):
        parsed = urlsplit(api_base_url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
            raise ValueError("API base URL must use HTTPS")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface):
            raise ValueError("invalid WireGuard interface name")
        if len(secret) < 32:
            raise ValueError("shared secret must contain at least 32 characters")
        self.api_url = api_base_url.rstrip("/") + METERING_PATH
        self.secret, self.interface, self.peers, self.store = secret, interface, peers, store
        if max_outage_seconds < 1:
            raise ValueError("max outage window must be positive")
        self.command, self.post = command, post or self._https_post
        self.max_outage_seconds = max_outage_seconds

    @staticmethod
    def _https_post(url, headers, body):
        req = urllib.request.Request(url,data=body,headers=headers,method="POST")
        try:
            with urllib.request.urlopen(req,timeout=8) as response:
                return response.status
        except urllib.error.HTTPError as exc:
            return exc.code

    def _wg(self, *args):
        return self.command(["wg",*args],check=True,capture_output=True,text=True,timeout=8)

    def sample(self):
        return parse_wg_dump(self._wg("show",self.interface,"dump").stdout)

    def _remove_peer(self,key):
        self._wg("set",self.interface,"peer",key,"remove")
        self.store.mark_disabled(key)
        LOG.warning("peer suspended after quota/entitlement rejection: %s",key[:10])

    def _send(self,event):
        timestamp = str(int(time.time()))
        signature = sign_request(self.secret,timestamp,event.event_id,event.body)
        headers = {"Content-Type":"application/json","X-RMA-Timestamp":timestamp,
                   "X-RMA-Event-Id":event.event_id,"X-RMA-Signature":signature}
        return self.post(self.api_url,headers,event.body)

    def run_once(self):
        counters = self.sample()
        for key,peer in self.peers.items():
            if self.store.disabled(key):
                continue
            pending = self.store.pending(key)
            if pending is None:
                current = counters.get(key)
                if current is None:
                    continue
                pending = self.store.prepare_delta(peer,current.total)
            if pending is None:
                continue
            try:
                status = self._send(pending)
            except Exception as exc:
                if time.time() - pending.created_at >= self.max_outage_seconds:
                    try:
                        self._remove_peer(key)
                    except Exception as remove_exc:
                        LOG.critical("metering outage and peer removal failed for %s (%s)",key[:10],type(remove_exc).__name__)
                else:
                    LOG.error("delivery failed; event retained for bounded retry (%s)",type(exc).__name__)
                continue
            if 200 <= status < 300:
                self.store.acknowledge(key,pending.event_id)
            elif status in (401,403,404,409,410,413,422):
                # Unknown client, expired/inactive entitlement, or exhausted quota.
                try:
                    self._remove_peer(key)
                except Exception as exc:
                    LOG.critical("peer enforcement failed for %s (%s); operator action required",key[:10],type(exc).__name__)
            elif time.time() - pending.created_at >= self.max_outage_seconds:
                try:
                    self._remove_peer(key)
                except Exception as exc:
                    LOG.critical("metering outage and peer removal failed for %s (%s)",key[:10],type(exc).__name__)
            else:
                LOG.error("metering API returned HTTP %s; event retained for bounded retry",status)

def build_from_env():
    api = os.environ.get("RMA_API_BASE_URL","")
    secret = os.environ.get("RMA_METERING_SHARED_SECRET","")
    interface = os.environ.get("RMA_WG_INTERFACE","wg0")
    peers_path = os.environ.get("RMA_WG_PEERS_FILE","/etc/rma/peers.json")
    state_path = os.environ.get("RMA_METERING_STATE_DB","/var/lib/rma-meter/usage.sqlite3")
    interval = int(os.environ.get("RMA_POLL_INTERVAL_SECONDS","15"))
    max_outage = int(os.environ.get("RMA_METERING_MAX_OUTAGE_SECONDS","120"))
    if interval < 5 or interval > 300:
        raise ValueError("poll interval must be between 5 and 300 seconds")
    Path(state_path).parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    os.chmod(Path(state_path).parent,0o700)
    store = MeteringStore(state_path)
    meter = WireGuardMeter(api_base_url=api,secret=secret,interface=interface,
                           peers=load_peers(peers_path),store=store,max_outage_seconds=max_outage)
    return meter,store,interval

def main():
    parser = argparse.ArgumentParser(description="R&MA trusted WireGuard metering agent")
    parser.add_argument("--once",action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=os.environ.get("RMA_LOG_LEVEL","INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    meter,store,interval = build_from_env()
    try:
        while True:
            try:
                meter.run_once()
            except Exception as exc:
                LOG.error("metering cycle failed (%s)",type(exc).__name__)
            if args.once:
                return 0
            time.sleep(interval)
    finally:
        store.close()

if __name__ == "__main__":
    raise SystemExit(main())
