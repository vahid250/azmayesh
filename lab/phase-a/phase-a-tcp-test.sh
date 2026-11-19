#!/usr/bin/env bash
set -Eeuo pipefail

readonly GW="rma-lab-gw"
readonly A="rma-lab-a"
readonly SINK="rma-lab-sink"
readonly DATA_PORT=44003
readonly PROBE_PORT=44004
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TCP="$ROOT/tcp.py"

die() { echo "FAIL: $*" >&2; exit 1; }
for x in ip nft python3; do command -v "$x" >/dev/null 2>&1 || die "missing tool: $x"; done
for ns in "$GW" "$A" "$SINK"; do
  ip netns list | awk '{print $1}' | grep -Fxq "$ns" || die "namespace missing: $ns"
done
[[ -f "$TCP" ]] || die "tcp.py not found"

TMP="$(mktemp -d)"
SERVER_PID=""
PROBE_PID=""
cleanup() {
  [[ -z "$SERVER_PID" ]] || kill "$SERVER_PID" 2>/dev/null || true
  [[ -z "$PROBE_PID" ]] || kill "$PROBE_PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

echo "[Q-07] TCP bulk transfer: attempt 1 MiB through the shared quota"
ip netns exec "$GW" nft reset quota inet rma_lab shared_ab >/dev/null
ip netns exec "$SINK" python3 "$TCP" serve --port "$DATA_PORT" --duration 6 --output "$TMP/tcp.json" --ready-file "$TMP/data-ready" &
SERVER_PID=$!
for _ in $(seq 1 50); do
  [[ -f "$TMP/data-ready" ]] && break
  kill -0 "$SERVER_PID" 2>/dev/null || die "TCP data server exited before ready"
  sleep 0.1
done
[[ -f "$TMP/data-ready" ]] || die "TCP data server readiness timeout"

ip netns exec "$A" python3 "$TCP" send --port "$DATA_PORT" --total-bytes 1048576 --duration 2 --timeout 0.3
QUOTA_OUTPUT="$(ip netns exec "$GW" nft list quota inet rma_lab shared_ab)"
printf '%s\n' "$QUOTA_OUTPUT"
grep -q 'used 64 kbytes' <<<"$QUOTA_OUTPUT" || die "TCP traffic did not exhaust the 64-kbyte quota"

echo "[Q-08] New TCP connection after quota exhaustion must be blocked"
ip netns exec "$SINK" python3 "$TCP" serve --port "$PROBE_PORT" --duration 3 --output "$TMP/probe.json" --ready-file "$TMP/probe-ready" &
PROBE_PID=$!
for _ in $(seq 1 50); do
  [[ -f "$TMP/probe-ready" ]] && break
  kill -0 "$PROBE_PID" 2>/dev/null || die "TCP probe server exited before ready"
  sleep 0.1
done
[[ -f "$TMP/probe-ready" ]] || die "TCP probe server readiness timeout"
ip netns exec "$A" python3 "$TCP" probe --port "$PROBE_PORT" --timeout 1.5

wait "$SERVER_PID"
SERVER_PID=""
wait "$PROBE_PID"
PROBE_PID=""
cat "$TMP/tcp.json"
cat "$TMP/probe.json"

python3 - "$TMP/tcp.json" "$TMP/probe.json" <<'CHECK'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    bulk = json.load(f)
with open(sys.argv[2], encoding="utf-8") as f:
    probe = json.load(f)
received = bulk.get("received_bytes", 0)
if received <= 0:
    raise SystemExit("FAIL: TCP sink received no application data")
if received >= 1048576:
    raise SystemExit(f"FAIL: all requested TCP data arrived ({received} bytes); quota did not constrain the stream")
if probe.get("connections", 0) != 0:
    raise SystemExit(f"FAIL: post-quota TCP probe reached the listener ({probe['connections']} connections)")
print(f"PASS: TCP delivered {received}/1048576 application bytes before quota exhaustion; post-quota connection was not accepted.")
CHECK

echo "Phase-A TCP tests passed. This is a bounded IPv4/TCP lab test, not production acceptance."
