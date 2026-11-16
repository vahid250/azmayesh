import hashlib
import hmac
import subprocess

from host_agent.rma_wg_meter import (
    METERING_PATH, Counters, MeteringStore, Peer, WireGuardMeter,
    parse_wg_dump, sign_request,
)

SECRET = "agent-test-secret-that-is-longer-than-thirty-two-characters"
PUB = "test-wireguard-public-key"


def dump(rx, tx):
    header = "\t".join(["private", "public", "port", "fwmark"])
    peer = "\t".join([PUB, "(none)", "198.51.100.1:51820", "10.0.0.2/32", "0", str(rx), str(tx), "25"])
    return header + "\n" + peer + "\n"


class FakeWG:
    def __init__(self, rx=0, tx=0):
        self.rx, self.tx = rx, tx
        self.calls = []
        self.fail_show = False

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        if args[1:3] == ["show", "wg0"]:
            if self.fail_show:
                raise subprocess.CalledProcessError(1, args, stderr="simulated wg dump failure")
            return subprocess.CompletedProcess(args, 0, dump(self.rx, self.tx), "")
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
    replies = [503, 200, 200]
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

    wg.rx, wg.tx = 150, 100
    meter.run_once()
    assert len(sent) == 3
    assert b'"bytes_used":150' in sent[2][1]
    store.close()


def test_quota_rejection_removes_peer_and_marks_it_disabled(tmp_path):
    store = MeteringStore(str(tmp_path / "state.sqlite3"))
    wg = FakeWG(20, 10)
    meter = WireGuardMeter(
        api_base_url="https://api.example.test",
        secret=SECRET, interface="wg0", peers={PUB: Peer(7, PUB)},
        store=store, command=wg, post=lambda *_: 409,
    )
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
    assert store.pending(PUB) is None
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
