#!/usr/bin/env bash
set -Eeuo pipefail

readonly GW="rma-lab-gw"
readonly A="rma-lab-a"
readonly SINK="rma-lab-sink"
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly UDP4="$ROOT/traffic.py"
readonly UDP6="$ROOT/ip6.py"

die() { echo "FAIL: $*" >&2; exit 1; }
for x in ip nft python3; do command -v "$x" >/dev/null 2>&1 || die "missing tool: $x"; done
for ns in "$GW" "$A" "$SINK"; do
  ip netns list | awk '{print $1}' | grep -Fxq "$ns" || die "namespace missing: $ns"
done
[[ -f "$UDP4" && -f "$UDP6" ]] || die "UDP endpoint script missing"

TMP="$(mktemp -d)"
PIDS=()
cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
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
reset_shared() { ip netns exec "$GW" nft reset quota inet rma_lab shared_ab >/dev/null; }
quota_shared() { ip netns exec "$GW" nft list quota inet rma_lab shared_ab; }

echo "[Q-12] One exact 64-KiB quota shared across mixed IPv4 and IPv6 packets"
reset_shared
ip netns exec "$SINK" python3 "$UDP4" serve --port 44020 --duration 4 --output "$TMP/mixed-v4.json" --ready-file "$TMP/mixed-v4.ready" &
PIDS+=("$!"); V4_PID="${PIDS[-1]}"
ip netns exec "$SINK" python3 "$UDP6" serve --port 44021 --duration 4 --output "$TMP/mixed-v6.json" --ready-file "$TMP/mixed-v6.ready" &
PIDS+=("$!"); V6_PID="${PIDS[-1]}"
wait_ready "$V4_PID" "$TMP/mixed-v4.ready"
wait_ready "$V6_PID" "$TMP/mixed-v6.ready"

# IPv4 packet overhead is 28 bytes; IPv6 packet overhead is 48 bytes.
# 26*(1200+28) + 26*(1200+48) + (1112+48) = 65536.
ip netns exec "$A" python3 "$UDP4" send --port 44020 --count 26 --payload-size 1200 --interval 0.001
ip netns exec "$A" python3 "$UDP6" send --port 44021 --count 26 --payload-size 1200 --interval 0.001
ip netns exec "$A" python3 "$UDP6" send --port 44021 --count 1 --payload-size 1112 --interval 0
QUOTA_AT_BOUNDARY="$(quota_shared)"
printf '%s\n' "$QUOTA_AT_BOUNDARY"
grep -q 'used 64 kbytes' <<<"$QUOTA_AT_BOUNDARY" || die "mixed IPv4/IPv6 traffic did not reach the exact 64-KiB quota"

# A packet in either family must now be denied.
ip netns exec "$A" python3 "$UDP4" send --port 44020 --count 1 --payload-size 1200 --interval 0
wait "$V4_PID"; wait "$V6_PID"
cat "$TMP/mixed-v4.json"
cat "$TMP/mixed-v6.json"
python3 - "$TMP/mixed-v4.json" "$TMP/mixed-v6.json" <<'CHECK'
import json, sys
v4=json.load(open(sys.argv[1], encoding="utf-8"))
v6=json.load(open(sys.argv[2], encoding="utf-8"))
p4=sum(x.get("packets",0) for x in v4.values())
p6=sum(x.get("packets",0) for x in v6.values())
b4=sum(x.get("payload_bytes",0) for x in v4.values())
b6=sum(x.get("payload_bytes",0) for x in v6.values())
if (p4,p6,b4,b6)!=(26,27,31200,32312):
    raise SystemExit(f"FAIL: unexpected mixed-family delivery: IPv4={p4}/{b4}, IPv6={p6}/{b6}")
print("PASS: exact mixed-family boundary reached; the next IPv4 packet was blocked.")
CHECK

echo "[Q-13] Spoofed/unauthorized source addresses must not bypass metered rules"
reset_shared
ip -n "$A" addr add 10.10.1.6/32 dev a0
ip -6 -n "$A" addr add fd10:10:1::99/128 dev a0
ip netns exec "$SINK" python3 "$UDP4" serve --port 44022 --duration 3 --output "$TMP/spoof-v4.json" --ready-file "$TMP/spoof-v4.ready" &
PIDS+=("$!"); SV4_PID="${PIDS[-1]}"
ip netns exec "$SINK" python3 "$UDP6" serve --port 44023 --duration 3 --output "$TMP/spoof-v6.json" --ready-file "$TMP/spoof-v6.ready" &
PIDS+=("$!"); SV6_PID="${PIDS[-1]}"
wait_ready "$SV4_PID" "$TMP/spoof-v4.ready"
wait_ready "$SV6_PID" "$TMP/spoof-v6.ready"
ip netns exec "$A" python3 "$UDP4" send --source 10.10.1.6 --port 44022 --count 10 --interval 0.001
ip netns exec "$A" python3 "$UDP6" send --source fd10:10:1::99 --port 44023 --count 10 --interval 0.001
wait "$SV4_PID"; wait "$SV6_PID"
python3 - "$TMP/spoof-v4.json" "$TMP/spoof-v6.json" <<'CHECK'
import json, sys
for path in sys.argv[1:]:
    data=json.load(open(path, encoding="utf-8"))
    if sum(v.get("packets",0) for v in data.values()) != 0:
        raise SystemExit(f"FAIL: unauthorized source reached sink: {path}")
print("PASS: neither unauthorized IPv4 nor IPv6 source reached the sink.")
CHECK
QUOTA_AFTER_SPOOF="$(quota_shared)"
printf '%s\n' "$QUOTA_AFTER_SPOOF"
grep -Eq 'used 0 bytes|used 0 kbytes' <<<"$QUOTA_AFTER_SPOOF" || die "unauthorized packets unexpectedly consumed or altered the shared quota"

echo "[Q-14] Firewall rule-order audit: default drop and every accept must be quota-metered"
RULES="$(ip netns exec "$GW" nft list chain inet rma_lab forward)"
printf '%s\n' "$RULES"
grep -q 'policy drop' <<<"$RULES" || die "forward chain is not default-drop"
awk '/ accept/ { if ($0 !~ /quota name/) exit 1; n++ } END { if (n != 12) exit 1 }' <<<"$RULES" || die "expected exactly 12 quota-metered accept rules; found an unmetered or missing accept"
echo "PASS: forward chain is default-drop and all 12 accept rules are quota-metered."

echo "[Q-15] Fail-closed behavior: traffic must not pass while client interface is down"
reset_shared
ip netns exec "$SINK" python3 "$UDP4" serve --port 44024 --duration 2 --output "$TMP/link-down.json" --ready-file "$TMP/link-down.ready" &
PIDS+=("$!"); LINK_PID="${PIDS[-1]}"
wait_ready "$LINK_PID" "$TMP/link-down.ready"
ip -n "$A" link set a0 down
ip netns exec "$A" python3 "$UDP4" send --port 44024 --count 5 --interval 0.01
ip -n "$A" link set a0 up
wait "$LINK_PID"
python3 - "$TMP/link-down.json" <<'CHECK'
import json, sys
data=json.load(open(sys.argv[1], encoding="utf-8"))
if sum(v.get("packets",0) for v in data.values()) != 0:
    raise SystemExit("FAIL: traffic reached sink while the client interface was down")
print("PASS: no packets reached the sink while the client link was down.")
CHECK
QUOTA_AFTER_LINK="$(quota_shared)"
printf '%s\n' "$QUOTA_AFTER_LINK"
grep -Eq 'used 0 bytes|used 0 kbytes' <<<"$QUOTA_AFTER_LINK" || die "quota changed while the client link was down"

echo "Phase-A Stage 6 mixed-family, bypass-resistance, firewall-order, and fail-closed tests passed."
echo "This is bounded disposable-lab validation, not production acceptance or a security certification."
