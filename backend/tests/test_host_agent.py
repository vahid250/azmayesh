import base64
import hashlib
import hmac
import subprocess

import pytest

from host_agent.rma_wg_meter import (
    METERING_PATH, Counters, MeteringStore, Peer, WireGuardMeter,
    parse_wg_dump, sign_request,
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

    def __call__(self, args, **kwargs):
        self.calls.append(args)
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
            "client_id": 7, "public_key": PUB, "state": "suspended"
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


def test_revocation_firewall_failure_does_not_remove_peer_or_ack(tmp_path):
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
    assert not any(c[1:3] == ["set","wg0"] and "remove" in c for c in wg.calls)
    assert not acks
    assert not store.disabled(PUB)
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
