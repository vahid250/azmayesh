#!/usr/bin/env bash
set -Eeuo pipefail

readonly GW="rma-lab-gw"
readonly A="rma-lab-a"
readonly B="rma-lab-b"
readonly SINK="rma-lab-sink"
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PY="$ROOT/ip6.py"

die() { echo "FAIL: $*" >&2; exit 1; }
for x in ip nft python3; do command -v "$x" >/dev/null 2>&1 || die "missing tool: $x"; done
for ns in "$GW" "$A" "$B" "$SINK"; do
  ip netns list | awk '{print $1}' | grep -Fxq "$ns" || die "namespace missing: $ns"
done
[[ -f "$PY" ]] || die "ip6.py not found"

TMP="$(mktemp -d)"
PIDS=()
cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  rm -rf "$TMP"
}
trap cleanup EXIT

wait_ready() {
  local pid="$1" ready="$2"
  for _ in $(seq 1 50); do
    [[ -f "$ready" ]] && return 0
    kill -0 "$pid" 2>/dev/null || die "listener exited before readiness: $ready"
    sleep 0.1
  done
  die "listener readiness timeout: $ready"
}
quota_reset() { ip netns exec "$GW" nft reset quota inet rma_lab shared_ab >/dev/null; }
quota_show() { ip netns exec "$GW" nft list quota inet rma_lab shared_ab; }

echo "[Q-09] IPv6 A+B simultaneous traffic must share the same 64-KiB quota"
quota_reset
ip netns exec "$SINK" python3 "$PY" serve --port 44010 --duration 3 --output "$TMP/ipv6-forward.json" --ready-file "$TMP/forward.ready" &
PIDS+=("$!")
wait_ready "${PIDS[-1]}" "$TMP/forward.ready"
ip netns exec "$A" python3 "$PY" send --port 44010 --count 100 --interval 0.01 &
PA=$!
ip netns exec "$B" python3 "$PY" send --port 44010 --count 100 --interval 0.01 &
PB=$!
wait "$PA"; wait "$PB"
wait "${PIDS[-1]}"
cat "$TMP/ipv6-forward.json"
quota_show
quota_show | grep -q "used 64 kbytes" || die "IPv6 shared quota did not reach its configured cap"
python3 - "$TMP/ipv6-forward.json" <<'CHECK'
import json, sys
data=json.load(open(sys.argv[1], encoding="utf-8"))
total=sum(v.get("packets",0) for v in data.values())
if not 50 <= total <= 52:
    raise SystemExit(f"FAIL: expected 50–52 received IPv6 UDP packets (receiver may drop at most two under burst load), observed {total}")
print(f"PASS: {total}/200 IPv6 UDP packets received; nftables independently confirmed the 64-KiB quota was exhausted.")
CHECK

echo "[Q-10] Reverse-direction IPv6 traffic must also consume the same quota"
quota_reset
ip netns exec "$A" python3 "$PY" serve --bind fd10:10:1::2 --port 44011 --duration 3 --output "$TMP/ipv6-reverse.json" --ready-file "$TMP/reverse.ready" &
PIDS+=("$!")
wait_ready "${PIDS[-1]}" "$TMP/reverse.ready"
# Prime both IPv6 neighbor-cache hops before the measured burst; discard warm-up bytes.
ip netns exec "$SINK" ping -6 -c 1 -W 2 fd10:10:1::2 >/dev/null || die "IPv6 reverse-path warm-up failed"
quota_reset
ip netns exec "$SINK" python3 "$PY" send --destination fd10:10:1::2 --port 44011 --count 100 --interval 0.01
wait "${PIDS[-1]}"
cat "$TMP/ipv6-reverse.json"
quota_show
quota_show | grep -q "used 64 kbytes" || die "reverse IPv6 shared quota did not reach its configured cap"
python3 - "$TMP/ipv6-reverse.json" <<'CHECK'
import json, sys
data=json.load(open(sys.argv[1], encoding="utf-8"))
total=sum(v.get("packets",0) for v in data.values())
if not 50 <= total <= 52:
    raise SystemExit(f"FAIL: expected 50–52 received reverse IPv6 packets (receiver may drop at most two under burst load), observed {total}")
print(f"PASS: reverse IPv6 received {total} packets; nftables independently confirmed the 64-KiB quota was exhausted.")
CHECK

echo "[Q-11] Forward and reverse IPv6 flows must consume one combined quota"
quota_reset
ip netns exec "$SINK" python3 "$PY" serve --port 44012 --duration 3 --output "$TMP/mixed-forward.json" --ready-file "$TMP/mixed-forward.ready" &
PIDS+=("$!")
SINK_PID="${PIDS[-1]}"
wait_ready "$SINK_PID" "$TMP/mixed-forward.ready"
ip netns exec "$A" python3 "$PY" serve --bind fd10:10:1::2 --port 44013 --duration 3 --output "$TMP/mixed-reverse.json" --ready-file "$TMP/mixed-reverse.ready" &
PIDS+=("$!")
A_PID="${PIDS[-1]}"
wait_ready "$A_PID" "$TMP/mixed-reverse.ready"
ip netns exec "$A" python3 "$PY" send --port 44012 --count 26 --interval 0.005
ip netns exec "$SINK" python3 "$PY" send --destination fd10:10:1::2 --port 44013 --count 26 --interval 0.005
ip netns exec "$A" python3 "$PY" send --port 44012 --count 1 --interval 0.005
wait "$SINK_PID"
wait "$A_PID"
cat "$TMP/mixed-forward.json"
cat "$TMP/mixed-reverse.json"
quota_show
python3 - "$TMP/mixed-forward.json" "$TMP/mixed-reverse.json" <<'CHECK'
import json, sys
f=json.load(open(sys.argv[1], encoding="utf-8"))
r=json.load(open(sys.argv[2], encoding="utf-8"))
forward=sum(v.get("packets",0) for v in f.values())
reverse=sum(v.get("packets",0) for v in r.values())
if (forward, reverse) != (26, 26):
    raise SystemExit(f"FAIL: expected 26 packets each way, observed forward={forward}, reverse={reverse}")
print("PASS: 26 forward + 26 reverse IPv6 packets consumed the same quota; the 53rd packet was blocked.")
CHECK

echo "Phase-A Stage 5 IPv6 and bidirectional tests passed. This is bounded lab validation, not production acceptance."
