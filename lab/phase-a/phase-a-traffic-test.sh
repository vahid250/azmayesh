#!/usr/bin/env bash
set -Eeuo pipefail

readonly GW="rma-lab-gw"
readonly A="rma-lab-a"
readonly B="rma-lab-b"
readonly C="rma-lab-c"
readonly SINK="rma-lab-sink"
readonly PORT=44000
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PY="$ROOT/traffic.py"

die() { echo "FAIL: $*" >&2; exit 1; }
need_ns() {
  for ns in "$GW" "$A" "$B" "$C" "$SINK"; do
    ip netns list | awk '{print $1}' | grep -Fxq "$ns" || die "namespace missing: $ns (run phase-a-lab.sh up first)"
  done
}
need_tools() {
  for x in ip nft python3; do command -v "$x" >/dev/null 2>&1 || die "missing tool: $x"; done
}
start_sink() {
  local output="$1"
  ip netns exec "$SINK" python3 "$PY" serve --port "$PORT" --duration 2.0 --output "$output" &
  SINK_PID=$!
  sleep 0.20
}
wait_sink() {
  local pid="$1"
  wait "$pid" || die "UDP sink process failed"
}
quota_reset() {
  ip netns exec "$GW" nft reset quota inet rma_lab "$1" >/dev/null
}
show_quota() {
  ip netns exec "$GW" nft list quota inet rma_lab "$1"
}
need_tools
need_ns
[[ -f "$PY" ]] || die "traffic.py not found"
TMP="$(mktemp -d)"
SINK_PID=""
cleanup() {
  if [[ -n "$SINK_PID" ]]; then kill "$SINK_PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT

echo "[Q-01] Shared quota: A then B, 30 UDP datagrams each (1200-byte payloads)"
quota_reset shared_ab
start_sink "$TMP/shared.json"
SINK_PID=$!
ip netns exec "$A" python3 "$PY" send --port "$PORT" --count 30
ip netns exec "$B" python3 "$PY" send --port "$PORT" --count 30
wait_sink "$SINK_PID"
SINK_PID=""

echo "Shared quota object after A+B traffic:"
show_quota shared_ab
echo "Independent sink receive counts:"
cat "$TMP/shared.json"
python3 - "$TMP/shared.json" <<'CHECK'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)
a = data.get("10.10.1.2", {}).get("packets", 0)
b = data.get("10.10.2.2", {}).get("packets", 0)
if a < 25:
    raise SystemExit(f"FAIL: A delivered only {a}/30 packets; baseline path not healthy")
if not (1 <= b < 30):
    raise SystemExit(f"FAIL: B delivered {b}/30 packets; shared quota behavior not demonstrated")
print(f"PASS: A delivered {a}/30; B delivered {b}/30. Shared cap constrained the second device.")
CHECK

echo "[Q-02] Independent quota: C should retain its own full allowance"
quota_reset isolated_c
start_sink "$TMP/c.json"
SINK_PID=$!
ip netns exec "$C" python3 "$PY" send --port "$PORT" --count 30
wait_sink "$SINK_PID"
SINK_PID=""
show_quota isolated_c
cat "$TMP/c.json"
python3 - "$TMP/c.json" <<'CHECK'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)
c = data.get("10.10.3.2", {}).get("packets", 0)
if c != 30:
    raise SystemExit(f"FAIL: C delivered {c}/30 packets; independent quota/path unexpected")
print("PASS: C delivered all 30 packets under its independent quota.")
CHECK

echo "Phase-A UDP smoke tests passed. This is not yet packet-boundary, TCP, IPv6, reboot, or production acceptance."
