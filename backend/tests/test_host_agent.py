import base64
import hashlib
import hmac
import subprocess
import os
import sys

import pytest

from host_agent.rma_wg_meter import (
    METERING_PATH, Counters, MeteringStore, Peer, WireGuardMeter,
    parse_wg_dump, sign_request, _acquire_process_lock,
)

SECRET = "agent-test-secret-that-is-longer-than-thirty-two-characters"
PUB = base64.b64encode(b"p" * 32).decode("ascii")


def dump(rx, tx):
    header = "\t".join(["private", "public", "port", "fwmark"])
    peer = "\t".join([PUB, "(none)", "198.51.100.1:51820", "10.0.0.2/32", "0", str(rx), str(tx), "25"])
    return header + "\n" + peer + "\n"


class FakeWG:
    def __init__(self, rx=0, tx=0):
        self.rx, self.tx = rx, tx
        self.calls = []
        self.fail_show = False
        self.hide_peer = False
        self.revoked_ips = set()
        self.fail_nft_add = False
        self.fail_guard = False
        self.fail_wg_remove = False
        self.fail_wg_register = False

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        if args[:4] == ["nft", "-a", "list", "chain"]:
            if self.fail_guard:
                return subprocess.CompletedProcess(args, 1, "", "missing guard")
            hook = args[-1]
            output = (
                f'chain {hook} {{ type filter hook {hook} priority -10; policy accept; '
                'iifname "wg0" ip saddr @revoked_peer_sources counter drop }'
            )
            return subprocess.CompletedProcess(args, 0, output, "")
        if args[:3] == ["nft", "get", "element"]:
            return subprocess.CompletedProcess(args, 0 if args[-2] in self.revoked_ips else 1, "", "")
        if args[:3] == ["nft", "add", "element"]:
            if self.fail_nft_add:
                raise subprocess.CalledProcessError(1, args, stderr="simulated nft failure")
            self.revoked_ips.add(args[-2])
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[:3] == ["nft", "delete", "element"]:
            self.revoked_ips.discard(args[-2])
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[1:3] == ["show", "wg0"]:
            if self.fail_show:
                raise subprocess.CalledProcessError(1, args, stderr="simulated wg dump failure")
            output = "\t".join(["private", "public", "51820", "off"]) + "\n" if self.hide_peer else dump(self.rx, self.tx)
            return subprocess.CompletedProcess(args, 0, output, "")
        if args[1:3] == ["set", "wg0"] and "remove" in args and self.fail_wg_remove:
            raise subprocess.CalledProcessError(1, args, stderr="simulated WireGuard removal failure")
        if args[1:3] == ["set", "wg0"] and "allowed-ips" in args and self.fail_wg_register:
            raise subprocess.CalledProcessError(1, args, stderr="simulated WG peer registration failure")
        if args[1:3] == ["set", "wg0"] and "allowed-ips" in args:
            self.hide_peer = False
        return subprocess.CompletedProcess(args, 0, "", "")


def test_parse_wg_dump_and_signature_matches_backend_canonical_format():
    parsed = parse_wg_dump(dump(123, 456))
    assert parsed[PUB] == Counters(123, 456)
    body = b'{"client_id":7,"bytes_used":99}'
    timestamp, event_id = "1790000000", "wg-test-event"
    expected = hmac.new(
        SECRET.encode(),
        "\n".join(["POST", METERING_PATH, timestamp, event_id, hashlib.sha256(body).hexdigest()]).encode(),
        hashlib.sha256,
    ).hexdigest()
    assert sign_request(SECRET, timestamp, event_id, body) == expected


def test_pending_event_retries_same_id_and_body_then_accounts_new_delta(tmp_path):
    store = MeteringStore(str(tmp_path / "state.sqlite3"))
    wg = FakeWG(60, 40)
    replies = [503, 200, 200, 200]
    sent = []

    def post(url, headers, body):
        sent.append((headers["X-RMA-Event-Id"], body))
        return replies.pop(0)

    meter = WireGuardMeter(
        api_base_url="https://api.example.test",
        secret=SECRET, interface="wg0", peers={PUB: Peer(7, PUB)},
        store=store, command=wg, post=post,
    )
    meter.run_once()
    assert len(sent) == 1
    pending = store.pending(PUB)
    assert pending is not None and pending.bytes_used == 100

    wg.rx, wg.tx = 120, 80
    meter.run_once()
    assert sent[1] == sent[0]
    assert store.pending(PUB) is None
    # The 100 bytes transferred while the first report was pending are
    # emitted as a new event after the original event is acknowledged.
    assert b'"bytes_used":100' in sent[2][1]

    wg.rx, wg.tx = 150, 100
    meter.run_once()
    assert len(sent) == 4
    assert b'"bytes_used":50' in sent[3][1]
    store.close()


def test_quota_exhaustion_is_reconciled_by_registry_then_removes_peer(tmp_path):
    from host_agent.rma_wg_meter import METERING_PATH

    store = MeteringStore(str(tmp_path / "state.sqlite3"))
    wg = FakeWG(20, 10)
    responses = [
        {"interface": "wg0", "peers": [{
            "client_id": 7, "public_key": PUB, "allowed_ips": "10.0.0.2/32", "state": "peer_registered"
        }], "remove_peers": []},
        {"interface": "wg0", "peers": [], "remove_peers": [{
            "client_id": 7, "public_key": PUB, "allowed_ips": "10.0.0.2/32", "state": "suspended"
        }]},
    ]

    def registry_fetcher(url, headers, body):
        return responses.pop(0)

    def post(url, headers, body):
        return 200

    meter = WireGuardMeter(
        api_base_url="https://api.example.test",
        secret=SECRET, interface="wg0", peers={},
        store=store, command=wg, post=post, registry_fetcher=registry_fetcher,
    )
    meter.run_once()
    assert not store.disabled(PUB)
    assert not any(call[1:] == ["set", "wg0", "peer", PUB, "remove"] for call in wg.calls)

    meter.run_once()
    assert any(call[1:] == ["set", "wg0", "peer", PUB, "remove"] for call in wg.calls)
    assert store.disabled(PUB)
    assert store.pending(PUB) is None
    store.close()

def test_counter_reset_counts_new_value_and_does_not_create_negative_delta(tmp_path):
    store = MeteringStore(str(tmp_path / "state.sqlite3"))
    peer = Peer(7, PUB)
    first = store.prepare_delta(peer, 1000)
    assert first.bytes_used == 1000
    store.acknowledge(PUB, first.event_id)
    reset = store.prepare_delta(peer, 25)
    assert reset.bytes_used == 25
    store.close()


def test_network_failure_keeps_pending_event_for_retry(tmp_path):
    store = MeteringStore(str(tmp_path / "state.sqlite3"))
    wg = FakeWG(5, 5)

    def fail(*_):
        raise OSError("offline")

    meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET,
        interface="wg0", peers={PUB: Peer(7, PUB)}, store=store,
        command=wg, post=fail,
    )
    meter.run_once()
    assert store.pending(PUB) is not None
    store.close()


def test_extended_metering_outage_removes_peer_after_grace_period(tmp_path):
    store = MeteringStore(str(tmp_path / "state.sqlite3"))
    wg = FakeWG(15, 5)

    def fail(*_):
        raise OSError("backend unavailable")

    meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET,
        interface="wg0", peers={PUB: Peer(7, PUB)}, store=store,
        command=wg, post=fail, max_outage_seconds=1,
    )
    meter.run_once()
    assert store.pending(PUB) is not None
    store.db.execute("UPDATE pending_events SET created_at=0 WHERE public_key=?", (PUB,))
    store.db.commit()
    meter.run_once()
    assert store.disabled(PUB)
    assert store.pending(PUB) is not None
    assert any(call[1:] == ["set", "wg0", "peer", PUB, "remove"] for call in wg.calls)
    store.close()


def test_extended_wireguard_sampling_failure_removes_managed_peers(tmp_path):
    store = MeteringStore(str(tmp_path / "state.sqlite3"))
    wg = FakeWG(0, 0)
    wg.fail_show = True
    meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET,
        interface="wg0", peers={PUB: Peer(7, PUB)}, store=store,
        command=wg, post=lambda *_: 200, max_outage_seconds=1,
    )
    meter.run_once()
    assert not store.disabled(PUB)
    store.db.execute("UPDATE agent_state SET value=0 WHERE key='sample_fail_since'")
    store.db.commit()
    meter.run_once()
    assert store.disabled(PUB)
    assert any(call[1:] == ["set", "wg0", "peer", PUB, "remove"] for call in wg.calls)
    store.close()


def test_signed_registry_adds_authorized_peer_and_removes_stale_peer(tmp_path):
    from host_agent.rma_wg_meter import REGISTRY_PATH

    store = MeteringStore(str(tmp_path / "state.sqlite3"))
    wg = FakeWG(10, 5)
    responses = [
        {"interface": "wg0", "peers": [{
            "client_id": 7, "public_key": PUB, "allowed_ips": "10.0.0.2/32", "state": "peer_registered"
        }], "remove_peers": []},
        {"interface": "wg0", "peers": [], "remove_peers": [{
            "client_id": 7, "public_key": PUB, "allowed_ips": "10.0.0.2/32", "state": "suspended"
        }]},
    ]
    registry_requests = []
    sent_usage = []

    def registry_fetcher(url, headers, body):
        registry_requests.append((url, headers, body))
        return responses.pop(0)

    def post(url, headers, body):
        sent_usage.append((url, headers, body))
        return 200

    meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET,
        interface="wg0", peers={}, store=store, command=wg, post=post,
        registry_fetcher=registry_fetcher,
    )
    meter.run_once()
    assert len(registry_requests) == 1
    url, headers, body = registry_requests[0]
    assert url.endswith(REGISTRY_PATH)
    assert body == b'{"interface":"wg0"}'
    expected = sign_request(
        SECRET, headers["X-RMA-Timestamp"], headers["X-RMA-Event-Id"],
        body, path=REGISTRY_PATH,
    )
    assert headers["X-RMA-Signature"] == expected
    assert store.current_peers()[PUB].client_id == 7
    assert len(sent_usage) == 1

    meter.run_once()
    assert store.current_peers() == {}
    assert store.disabled(PUB)
    assert any(call[1:] == ["set", "wg0", "peer", PUB, "remove"] for call in wg.calls)
    store.close()


def test_pending_peer_is_acknowledged_only_after_host_observes_or_registers_it(tmp_path):
    from host_agent.rma_wg_meter import PEER_ACK_PATH

    store = MeteringStore(str(tmp_path / "state.sqlite3"))
    wg = FakeWG(0, 0)
    wg.hide_peer = True
    registry = {
        "interface": "wg0",
        "peers": [{
            "client_id": 7,
            "public_key": PUB,
            "allowed_ips": "10.0.0.2/32",
            "state": "pending_peer_registration",
        }],
        "remove_peers": [],
    }
    calls = []

    def registry_fetcher(url, headers, body):
        return registry

    def post(url, headers, body):
        calls.append((url, headers, body))
        return 200

    meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET,
        interface="wg0", peers={}, store=store, command=wg,
        post=post, registry_fetcher=registry_fetcher,
    )
    meter.run_once()
    acknowledgements = [call for call in calls if call[0].endswith(PEER_ACK_PATH)]
    assert len(acknowledgements) == 1
    assert b'"state":"peer_registered"' in acknowledgements[0][2]
    assert any(call[1:] == ["set", "wg0", "peer", PUB, "allowed-ips", "10.0.0.2/32"] for call in wg.calls)
    store.close()



@pytest.mark.parametrize(
    "bad_key",
    ["not-a-wireguard-key", "AA==", "A" * 44],
)
def test_signed_registry_rejects_malformed_wireguard_public_keys(tmp_path, bad_key):
    store = MeteringStore(str(tmp_path / "state.sqlite3"))
    payload = {
        "interface": "wg0",
        "peers": [{
            "client_id": 7,
            "public_key": bad_key,
            "allowed_ips": "10.0.0.2/32",
            "state": "peer_registered",
        }],
        "remove_peers": [],
    }
    meter = WireGuardMeter(
        api_base_url="https://api.example.test",
        secret=SECRET,
        interface="wg0",
        peers={},
        store=store,
        command=FakeWG(),
        registry_fetcher=lambda *_: payload,
    )
    try:
        with pytest.raises(ValueError, match="public key"):
            meter._fetch_registry()
    finally:
        store.close()


@pytest.mark.parametrize(
    "allowed_ips",
    ["0.0.0.0/0", "10.0.0.0/24", "2001:db8::2/128", "127.0.0.1/32", "10.0.0.2/31"],
)
def test_signed_registry_rejects_routes_that_are_not_single_customer_ipv4_hosts(tmp_path, allowed_ips):
    store = MeteringStore(str(tmp_path / "state.sqlite3"))
    payload = {
        "interface": "wg0",
        "peers": [{
            "client_id": 7,
            "public_key": PUB,
            "allowed_ips": allowed_ips,
            "state": "peer_registered",
        }],
        "remove_peers": [],
    }
    meter = WireGuardMeter(
        api_base_url="https://api.example.test",
        secret=SECRET,
        interface="wg0",
        peers={},
        store=store,
        command=FakeWG(),
        registry_fetcher=lambda *_: payload,
    )
    try:
        with pytest.raises(ValueError, match="allowed_ips"):
            meter._fetch_registry()
    finally:
        store.close()


def test_signed_registry_rejects_duplicate_peer_ip_assignments(tmp_path):
    store = MeteringStore(str(tmp_path / "state.sqlite3"))
    payload = {
        "interface": "wg0",
        "peers": [
            {"client_id": 7, "public_key": PUB, "allowed_ips": "10.0.0.2/32", "state": "peer_registered"},
            {"client_id": 8, "public_key": base64.b64encode(b"q" * 32).decode("ascii"), "allowed_ips": "10.0.0.2/32", "state": "peer_registered"},
        ],
        "remove_peers": [],
    }
    meter = WireGuardMeter(
        api_base_url="https://api.example.test",
        secret=SECRET,
        interface="wg0",
        peers={},
        store=store,
        command=FakeWG(),
        registry_fetcher=lambda *_: payload,
    )
    try:
        with pytest.raises(ValueError, match="duplicate peer IP"):
            meter._fetch_registry()
    finally:
        store.close()



def test_permanent_usage_rejection_quarantines_peer_and_preserves_event(tmp_path):
    store = MeteringStore(str(tmp_path / "state.sqlite3"))
    wg = FakeWG(60, 40)
    sent = []

    def post(url, headers, body):
        sent.append((url, headers, body))
        return 409

    meter = WireGuardMeter(
        api_base_url="https://api.example.test",
        secret=SECRET,
        interface="wg0",
        peers={PUB: Peer(7, PUB)},
        store=store,
        command=wg,
        post=post,
    )
    try:
        meter.run_once()
        pending = store.pending(PUB)
        assert pending is not None
        assert pending.failure_status == 409
        assert pending.bytes_used == 100
        assert store.pending_all() == []
        assert store.disabled(PUB)
        assert any(call[1:] == ["set", "wg0", "peer", PUB, "remove"] for call in wg.calls)

        meter.run_once()
        assert len(sent) == 1
        assert store.pending(PUB) is not None
    finally:
        store.close()


def test_transient_http_failure_removes_peer_after_grace_and_keeps_event(tmp_path):
    store = MeteringStore(str(tmp_path / "state.sqlite3"))
    wg = FakeWG(20, 10)
    sent = []

    def post(url, headers, body):
        sent.append((url, headers, body))
        return 503

    meter = WireGuardMeter(
        api_base_url="https://api.example.test",
        secret=SECRET,
        interface="wg0",
        peers={PUB: Peer(7, PUB)},
        store=store,
        command=wg,
        post=post,
        max_outage_seconds=1,
    )
    try:
        meter.run_once()
        pending = store.pending(PUB)
        assert pending is not None
        assert pending.failure_status is None
        assert not store.disabled(PUB)

        store.db.execute("UPDATE pending_events SET created_at=0 WHERE public_key=?", (PUB,))
        store.db.commit()
        meter.run_once()

        assert store.pending(PUB) is not None
        assert store.disabled(PUB)
        assert any(call[1:] == ["set", "wg0", "peer", PUB, "remove"] for call in wg.calls)
    finally:
        store.close()

 
def test_revocation_blocks_peer_source_before_wireguard_removal_and_ack(tmp_path):
    store = MeteringStore(str(tmp_path / "state.sqlite3"))
    wg = FakeWG(10, 5)
    acks = []
    registry = {"interface":"wg0","peers":[],"remove_peers":[{
        "client_id":7,"public_key":PUB,"allowed_ips":"10.0.0.2/32","state":"revoked"
    }]}
    meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET, interface="wg0",
        peers={}, store=store, command=wg,
        post=lambda url, headers, body: acks.append(body) or 200,
        registry_fetcher=lambda *_: registry,
    )
    meter.sync_registry()
    add_index = next(i for i,c in enumerate(wg.calls) if c[:3] == ["nft","add","element"])
    remove_index = next(i for i,c in enumerate(wg.calls) if c[1:3] == ["set","wg0"] and "remove" in c)
    assert add_index < remove_index
    assert "10.0.0.2" in wg.revoked_ips
    assert acks and b'"state":"revoked"' in acks[0]
    store.close()


def test_revocation_firewall_failure_falls_back_to_wireguard_removal_without_ack(tmp_path):
    store = MeteringStore(str(tmp_path / "state.sqlite3"))
    wg = FakeWG(10, 5)
    wg.fail_nft_add = True
    acks = []
    registry = {"interface":"wg0","peers":[],"remove_peers":[{
        "client_id":7,"public_key":PUB,"allowed_ips":"10.0.0.2/32","state":"revoked"
    }]}
    meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET, interface="wg0",
        peers={}, store=store, command=wg,
        post=lambda *args: acks.append(args) or 200,
        registry_fetcher=lambda *_: registry,
    )
    meter.sync_registry()
    assert any(c[1:3] == ["set","wg0"] and "remove" in c for c in wg.calls)
    assert not acks
    assert store.disabled(PUB)
    assert "10.0.0.2" not in wg.revoked_ips

    # Once the operator restores the nftables contract, reconciliation
    # installs the guard and only then acknowledges the pending revocation.
    wg.fail_guard = False
    wg.fail_nft_add = False
    meter.sync_registry()
    assert "10.0.0.2" in wg.revoked_ips
    assert acks and b'"state":"revoked"' in acks[0][2]
    store.close()


def test_concurrent_registry_reconciliation_is_serialized(tmp_path):
    import threading
    import time

    store = MeteringStore(str(tmp_path / "state.sqlite3"))
    wg = FakeWG()
    active_calls = 0
    peak_calls = 0
    state_lock = threading.Lock()

    def fetch_registry(*_):
        nonlocal active_calls, peak_calls
        with state_lock:
            active_calls += 1
            peak_calls = max(peak_calls, active_calls)
        time.sleep(0.03)
        with state_lock:
            active_calls -= 1
        return {"interface":"wg0","peers":[],"remove_peers":[]}

    meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET, interface="wg0",
        peers={}, store=store, command=wg, post=lambda *_: 200,
        registry_fetcher=fetch_registry,
    )
    threads = [threading.Thread(target=meter.sync_registry) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)
    assert all(not thread.is_alive() for thread in threads)
    assert peak_calls == 1, "registry sync must not run concurrently within one agent process"
    store.close()


def test_revocation_ledger_rehydrates_nft_set_after_agent_and_firewall_restart(tmp_path):
    db_path = str(tmp_path / "state.sqlite3")
    wg = FakeWG(10, 5)
    revoked = {"interface":"wg0","peers":[],"remove_peers":[{
        "client_id":7,"public_key":PUB,"allowed_ips":"10.0.0.2/32","state":"revoked"
    }]}
    store = MeteringStore(db_path)
    meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET, interface="wg0",
        peers={}, store=store, command=wg, post=lambda *_: 200,
        registry_fetcher=lambda *_: revoked,
    )
    meter.sync_registry()
    assert store.revoked_sources() == ["10.0.0.2"]
    assert "10.0.0.2" in wg.revoked_ips
    store.close()

    # Simulate both processes restarting: SQLite survives, nftables' dynamic
    # set is empty after its persistent ruleset is reloaded.
    wg.revoked_ips.clear()
    wg.calls.clear()
    restarted_store = MeteringStore(db_path)
    restarted = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET, interface="wg0",
        peers={}, store=restarted_store, command=wg, post=lambda *_: 200,
        registry_fetcher=lambda *_: {"interface":"wg0","peers":[],"remove_peers":[]},
    )
    restarted.sync_registry()
    assert "10.0.0.2" in wg.revoked_ips
    assert restarted_store.revoked_sources() == ["10.0.0.2"]
    add_index = next(i for i, call in enumerate(wg.calls) if call[:3] == ["nft", "add", "element"])
    guard_indices = [i for i, call in enumerate(wg.calls) if call[:4] == ["nft", "-a", "list", "chain"]]
    assert len(guard_indices) == 2 and max(guard_indices) < add_index
    restarted_store.close()


def test_reauthorization_registration_failure_keeps_revocation_guard(tmp_path):
    store = MeteringStore(str(tmp_path / "reauth-fail.sqlite3"))
    wg = FakeWG()
    wg.revoked_ips.add("10.0.0.2")
    wg.fail_wg_register = True
    store.remember_revoked_source("10.0.0.2/32")
    meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET, interface="wg0",
        peers={}, store=store, command=wg, post=lambda *_: 200,
        registry_fetcher=lambda *_: {"interface": "wg0", "peers": [{
            "client_id": 7, "public_key": PUB, "allowed_ips": "10.0.0.2/32", "state": "peer_registered"
        }], "remove_peers": []},
    )
    meter.sync_registry()
    assert "10.0.0.2" in wg.revoked_ips
    assert store.has_revoked_source("10.0.0.2/32")
    assert not any(call[:3] == ["nft", "delete", "element"] for call in wg.calls)
    store.close()


def test_reauthorization_after_restart_restores_peer_before_clearing_durable_guard(tmp_path):
    db_path = str(tmp_path / "state.sqlite3")
    wg = FakeWG(0, 0)
    store = MeteringStore(db_path)
    store.remember_revoked_source("10.0.0.2/32")
    wg.revoked_ips.clear()
    meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET, interface="wg0",
        peers={}, store=store, command=wg, post=lambda *_: 200,
        registry_fetcher=lambda *_: {"interface":"wg0","peers":[{
            "client_id":7,"public_key":PUB,"allowed_ips":"10.0.0.2/32","state":"peer_registered"
        }],"remove_peers":[]},
    )
    meter.sync_registry()
    set_index = next(i for i, call in enumerate(wg.calls)
                     if call[1:3] == ["set", "wg0"] and "allowed-ips" in call)
    delete_index = next(i for i, call in enumerate(wg.calls)
                        if call[:3] == ["nft", "delete", "element"])
    assert set_index < delete_index
    assert "10.0.0.2" not in wg.revoked_ips
    assert store.revoked_sources() == []
    store.close()


def test_reauthorization_removes_source_guard_only_after_wireguard_update(tmp_path):
    store = MeteringStore(str(tmp_path / "state.sqlite3"))
    wg = FakeWG(0, 0)
    wg.revoked_ips.add("10.0.0.2")
    peer = Peer(7, PUB, "10.0.0.2/32", "pending_peer_registration")
    meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET, interface="wg0",
        peers={}, store=store, command=wg, post=lambda *_: 200,
    )
    meter._register_peer(peer)
    set_index = next(i for i,c in enumerate(wg.calls) if c[1:3] == ["set","wg0"] and "allowed-ips" in c)
    delete_index = next(i for i,c in enumerate(wg.calls) if c[:3] == ["nft","delete","element"])
    assert set_index < delete_index
    assert "10.0.0.2" not in wg.revoked_ips
    store.close()


def test_revocation_guard_must_be_present_before_any_peer_removal_or_ack(tmp_path):
    store = MeteringStore(str(tmp_path / "state.sqlite3"))
    wg = FakeWG(10, 5)
    wg.fail_guard = True
    acks = []
    registry = {"interface":"wg0","peers":[],"remove_peers":[{
        "client_id":7,"public_key":PUB,"allowed_ips":"10.0.0.2/32","state":"revoked"
    }]}
    meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET, interface="wg0",
        peers={}, store=store, command=wg,
        post=lambda *args: acks.append(args) or 200,
        registry_fetcher=lambda *_: registry,
    )
    meter.sync_registry()
    # Missing firewall guard triggers WireGuard removal as a fallback,
    # but backend state must remain pending and unacknowledged.
    assert any(c[1:3] == ["set","wg0"] and "remove" in c for c in wg.calls)
    assert store.disabled(PUB)
    assert not acks
    store.close()


def test_stale_registry_peer_keeps_previous_ip_for_firewall_revocation(tmp_path):
    store = MeteringStore(str(tmp_path / "state.sqlite3"))
    wg = FakeWG(10, 5)
    responses = [
        {"interface":"wg0","peers":[{
            "client_id":7,"public_key":PUB,"allowed_ips":"10.0.0.2/32","state":"peer_registered"
        }],"remove_peers":[]},
        {"interface":"wg0","peers":[],"remove_peers":[]},
    ]
    meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET, interface="wg0",
        peers={}, store=store, command=wg, post=lambda *_: 200,
        registry_fetcher=lambda *_: responses.pop(0),
    )
    meter.sync_registry()
    meter.sync_registry()
    assert "10.0.0.2" in wg.revoked_ips
    assert store.disabled(PUB)
    store.close()

def test_concurrent_revoke_then_reauthorize_keeps_guard_until_peer_install(tmp_path):
    import threading

    store = MeteringStore(str(tmp_path / "race-state.sqlite3"))
    wg = FakeWG()
    revoke_payload = {"interface":"wg0","peers":[],"remove_peers":[{
        "client_id":7,"public_key":PUB,"allowed_ips":"10.0.0.2/32","state":"revoked"
    }]}
    authorize_payload = {"interface":"wg0","peers":[{
        "client_id":7,"public_key":PUB,"allowed_ips":"10.0.0.2/32","state":"peer_registered"
    }],"remove_peers":[]}
    first_fetch_entered = threading.Event()
    release_first_fetch = threading.Event()
    second_call_started = threading.Event()
    fetch_count = 0
    fetch_lock = threading.Lock()

    def fetch_registry(*_):
        nonlocal fetch_count
        with fetch_lock:
            fetch_count += 1
            current = fetch_count
        if current == 1:
            first_fetch_entered.set()
            assert release_first_fetch.wait(timeout=2)
            return revoke_payload
        return authorize_payload

    meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET, interface="wg0",
        peers={}, store=store, command=wg, post=lambda *_: 200,
        registry_fetcher=fetch_registry,
    )
    errors = []

    def run_sync():
        try:
            meter.sync_registry()
        except Exception as exc:
            errors.append(exc)

    first = threading.Thread(target=run_sync)
    second = threading.Thread(target=lambda: (second_call_started.set(), run_sync()))
    first.start()
    assert first_fetch_entered.wait(timeout=2)
    second.start()
    assert second_call_started.wait(timeout=2)
    release_first_fetch.set()
    first.join(timeout=3)
    second.join(timeout=3)

    assert not first.is_alive() and not second.is_alive()
    assert not errors
    assert fetch_count == 2
    assert "10.0.0.2" not in wg.revoked_ips
    assert store.revoked_sources() == []
    # The source guard is removed only after WireGuard has been configured
    # for the re-authorized peer; the serialized syncs cannot interleave.
    install_index = next(
        i for i, call in enumerate(wg.calls)
        if call[:4] == ["wg", "set", "wg0", "peer"] and "allowed-ips" in call
    )
    unlock_index = next(
        i for i, call in enumerate(wg.calls)
        if call[:3] == ["nft", "delete", "element"]
    )
    assert install_index < unlock_index
    store.close()


def test_host_agent_instance_lock_blocks_other_process_and_releases_on_close(tmp_path):
    lock_path = str(tmp_path / "agent.lock")
    fd = _acquire_process_lock(lock_path)
    try:
        child_code = (
            "from host_agent.rma_wg_meter import _acquire_process_lock\n"
            "import sys\n"
            "try:\n    _acquire_process_lock(sys.argv[1])\n"
            "except RuntimeError:\n    sys.exit(23)\n"
            "sys.exit(0)\n"
        )
        child_env = os.environ.copy()
        child_env["PYTHONPATH"] = os.pathsep.join(
            filter(None, [os.getcwd(), child_env.get("PYTHONPATH", "")])
        )
        result = subprocess.run(
            [sys.executable, "-c", child_code, lock_path],
            env=child_env, capture_output=True, text=True, timeout=5,
        )
        assert result.returncode == 23, result.stderr
    finally:
        os.close(fd)
    # Lock is released when the owning file descriptor closes; a new instance
    # can acquire it after the prior process exits.
    new_fd = _acquire_process_lock(lock_path)
    os.close(new_fd)


def test_registry_rejects_ip_reuse_between_active_and_revoked_peers(tmp_path):
    other_pub = base64.b64encode(b"q" * 32).decode("ascii")
    store = MeteringStore(str(tmp_path / "state.sqlite3"))
    payload = {
        "interface": "wg0",
        "peers": [{"client_id": 8, "public_key": other_pub,
                   "allowed_ips": "10.0.0.2/32", "state": "peer_registered"}],
        "remove_peers": [{"client_id": 7, "public_key": PUB,
                          "allowed_ips": "10.0.0.2/32", "state": "revoked"}],
    }
    meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET, interface="wg0",
        peers={}, store=store, command=FakeWG(), post=lambda *_: 200,
        registry_fetcher=lambda *_: payload,
    )
    with pytest.raises(ValueError, match="duplicate peer IP"):
        meter._fetch_registry()
    store.close()


def test_crash_window_after_durable_ledger_before_nft_recovered_on_restart(tmp_path):
    db_path = str(tmp_path / "crash-window.sqlite3")
    registry = {"interface": "wg0", "peers": [], "remove_peers": [{
        "client_id": 7, "public_key": PUB, "allowed_ips": "10.0.0.2/32", "state": "revoked"
    }]}
    first_store = MeteringStore(db_path)
    first_wg = FakeWG()
    first_wg.fail_nft_add = True
    first_acks = []
    first_meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET, interface="wg0",
        peers={}, store=first_store, command=first_wg,
        post=lambda *args: first_acks.append(args) or 200,
        registry_fetcher=lambda *_: registry,
    )

    # nft insertion fails after the ledger transaction committed. Agent fallback
    # removes the WG peer but must not ACK while the firewall source guard is absent.
    first_meter.sync_registry()
    assert first_store.revoked_sources() == ["10.0.0.2"]
    assert first_store.disabled(PUB)
    assert not first_acks
    first_store.close()

    # Simulate abrupt process exit plus firewall ruleset reload: SQLite persists,
    # but nftables' dynamic set is empty. A new process must restore the guard
    # before it acknowledges the removal.
    restarted_store = MeteringStore(db_path)
    restarted_wg = FakeWG()
    restarted_acks = []
    sequence = []
    def ack(*args):
        sequence.append("ack")
        restarted_acks.append(args)
        return 200
    original_command = restarted_wg.__call__
    def ordered_command(args, **kwargs):
        if args[:3] == ["nft", "add", "element"]:
            sequence.append("guard")
        if args[1:3] == ["set", "wg0"] and "remove" in args:
            sequence.append("wg_remove")
        return original_command(args, **kwargs)
    restarted_meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET, interface="wg0",
        peers={}, store=restarted_store, command=ordered_command,
        post=ack, registry_fetcher=lambda *_: registry,
    )
    restarted_meter.sync_registry()
    assert "10.0.0.2" in restarted_wg.revoked_ips
    assert restarted_store.revoked_sources() == ["10.0.0.2"]
    assert restarted_acks and b'"state":"revoked"' in restarted_acks[0][2]
    assert sequence.index("guard") < sequence.index("ack")
    restarted_store.close()


def test_full_revoke_restart_reconcile_reauthorize_sequence(tmp_path):
    db_path = str(tmp_path / "full-lifecycle.sqlite3")
    wg = FakeWG()
    revoke_registry = {"interface": "wg0", "peers": [], "remove_peers": [{
        "client_id": 7, "public_key": PUB, "allowed_ips": "10.0.0.2/32", "state": "revoked"
    }]}
    revoke_store = MeteringStore(db_path)
    revoke_acks = []
    revoke_meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET, interface="wg0",
        peers={}, store=revoke_store, command=wg,
        post=lambda *args: revoke_acks.append(args) or 200,
        registry_fetcher=lambda *_: revoke_registry,
    )
    revoke_meter.sync_registry()
    assert "10.0.0.2" in wg.revoked_ips
    assert revoke_store.has_revoked_source("10.0.0.2/32")
    assert revoke_acks and b'"state":"revoked"' in revoke_acks[0][2]
    revoke_store.close()

    reauth_store = MeteringStore(db_path)
    reauth_acks = []
    active_registry = {"interface": "wg0", "peers": [{
        "client_id": 7, "public_key": PUB, "allowed_ips": "10.0.0.2/32", "state": "peer_registered"
    }], "remove_peers": []}
    reauth_meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET, interface="wg0",
        peers={}, store=reauth_store, command=wg,
        post=lambda *args: reauth_acks.append(args) or 200,
        registry_fetcher=lambda *_: active_registry,
    )
    reauth_meter.sync_registry()
    wg_register = next(i for i, call in enumerate(wg.calls)
                       if call[1:3] == ["set", "wg0"] and "allowed-ips" in call)
    guard_delete = next(i for i, call in enumerate(wg.calls)
                       if call[:3] == ["nft", "delete", "element"])
    assert wg_register < guard_delete
    assert "10.0.0.2" not in wg.revoked_ips
    assert reauth_store.revoked_sources() == []
    assert reauth_store.managed_peer(PUB) is not None
    reauth_store.close()


def test_ack_failure_keeps_revocation_guard_and_retries_after_restart(tmp_path):
    db_path = str(tmp_path / "ack-retry.sqlite3")
    registry = {"interface": "wg0", "peers": [], "remove_peers": [{
        "client_id": 7, "public_key": PUB, "allowed_ips": "10.0.0.2/32", "state": "revoked"
    }]}
    wg = FakeWG()
    first_store = MeteringStore(db_path)
    first_ack_calls = []
    first_meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET, interface="wg0",
        peers={}, store=first_store, command=wg,
        post=lambda *args: first_ack_calls.append(args) or 503,
        registry_fetcher=lambda *_: registry,
    )
    first_meter.sync_registry()
    assert "10.0.0.2" in wg.revoked_ips
    assert first_store.has_revoked_source("10.0.0.2/32")
    assert first_store.disabled(PUB)
    assert len(first_ack_calls) == 1
    first_store.close()

    restarted_store = MeteringStore(db_path)
    successful_acks = []
    restarted_meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET, interface="wg0",
        peers={}, store=restarted_store, command=wg,
        post=lambda *args: successful_acks.append(args) or 204,
        registry_fetcher=lambda *_: registry,
    )
    restarted_meter.sync_registry()
    assert "10.0.0.2" in wg.revoked_ips
    assert restarted_store.has_revoked_source("10.0.0.2/32")
    assert successful_acks and b'"state":"revoked"' in successful_acks[0][2]
    restarted_store.close()


def test_crash_after_firewall_guard_before_wireguard_remove_retries_without_ack(tmp_path):
    db_path = str(tmp_path / "guard-before-remove.sqlite3")
    registry = {"interface": "wg0", "peers": [], "remove_peers": [{
        "client_id": 7, "public_key": PUB, "allowed_ips": "10.0.0.2/32", "state": "revoked"
    }]}
    store = MeteringStore(db_path)
    wg = FakeWG()
    wg.fail_wg_remove = True
    first_acks = []
    first_meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET, interface="wg0",
        peers={}, store=store, command=wg,
        post=lambda *args: first_acks.append(args) or 200,
        registry_fetcher=lambda *_: registry,
    )
    first_meter.sync_registry()
    assert "10.0.0.2" in wg.revoked_ips
    assert store.has_revoked_source("10.0.0.2/32")
    assert not first_acks
    store.close()

    wg.fail_wg_remove = False
    restarted_store = MeteringStore(db_path)
    restarted_acks = []
    restarted_meter = WireGuardMeter(
        api_base_url="https://api.example.test", secret=SECRET, interface="wg0",
        peers={}, store=restarted_store, command=wg,
        post=lambda *args: restarted_acks.append(args) or 200,
        registry_fetcher=lambda *_: registry,
    )
    restarted_meter.sync_registry()
    assert "10.0.0.2" in wg.revoked_ips
    assert restarted_store.disabled(PUB)
    assert restarted_acks and b'"state":"revoked"' in restarted_acks[0][2]
    restarted_store.close()
