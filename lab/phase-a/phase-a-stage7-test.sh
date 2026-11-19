#!/usr/bin/env bash
set -Eeuo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LAB="$ROOT/phase-a-lab.sh"
readonly UDP4="$ROOT/traffic.py"
readonly GW="rma-lab-gw"
readonly A="rma-lab-a"
readonly B="rma-lab-b"
readonly C="rma-lab-c"
readonly SINK="rma-lab-sink"

die() { echo "FAIL: $*" >&2; exit 1; }
for x in ip nft python3; do command -v "$x" >/dev/null 2>&1 || die "missing tool: $x"; done
for ns in "$GW" "$A" "$B" "$C" "$SINK"; do
  ip netns list | awk '{print $1}' | grep -Fxq "$ns" || die "namespace missing: $ns"
done
[[ -f "$LAB" && -f "$UDP4" ]] || die "required Phase-A files missing"

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
  for _ in $(seq 1 60); do
    [[ -f "$ready" ]] && return 0
    kill -0 "$pid" 2>/dev/null || die "listener exited before readiness: $ready"
    sleep 0.1
  done
  die "listener readiness timeout: $ready"
}
reset_quotas() {
  ip netns exec "$GW" nft reset quota inet rma_lab shared_ab >/dev/null
  ip netns exec "$GW" nft reset quota inet rma_lab isolated_c >/dev/null
}
quota_shared() { ip netns exec "$GW" nft list quota inet rma_lab shared_ab; }
quota_c() { ip netns exec "$GW" nft list quota inet rma_lab isolated_c; }

echo "[Q-16] Three simultaneous virtual users: A+B share a cap; C remains independent"
# Restore client links and routes after the preceding fail-closed test.
ip -n "$A" link set a0 up
ip -n "$A" route replace default via 10.10.1.1 dev a0
ip -n "$B" link set b0 up
ip -n "$B" route replace default via 10.10.2.1 dev b0
ip -n "$C" link set c0 up
ip -n "$C" route replace default via 10.10.3.1 dev c0
reset_quotas
ip netns exec "$SINK" python3 "$UDP4" serve --port 44030 --duration 5 --output "$TMP/multi-user.json" --ready-file "$TMP/multi-user.ready" &
SERVER_PID=$!; PIDS+=("$SERVER_PID")
wait_ready "$SERVER_PID" "$TMP/multi-user.ready"
ip netns exec "$A" python3 "$UDP4" send --port 44030 --count 26 --interval 0.001 &
PA=$!; PIDS+=("$PA")
ip netns exec "$B" python3 "$UDP4" send --port 44030 --count 26 --interval 0.001 &
PB=$!; PIDS+=("$PB")
ip netns exec "$C" python3 "$UDP4" send --port 44030 --count 30 --interval 0.001 &
PC=$!; PIDS+=("$PC")
wait "$PA"; wait "$PB"; wait "$PC"
ip netns exec "$A" python3 "$UDP4" send --port 44030 --count 1 --payload-size 1200 --interval 0
ip netns exec "$B" python3 "$UDP4" send --port 44030 --count 1 --payload-size 424 --interval 0
wait "$SERVER_PID"
PIDS=()
cat "$TMP/multi-user.json"
python3 - "$TMP/multi-user.json" <<'CHECK'
import json, sys
d=json.load(open(sys.argv[1], encoding="utf-8"))
expected={
 "10.10.1.2": (27, 32400),
 "10.10.2.2": (27, 31624),
 "10.10.3.2": (30, 36000),
}
for addr, want in expected.items():
    got=(d.get(addr,{}).get("packets",0), d.get(addr,{}).get("payload_bytes",0))
    if got != want:
        raise SystemExit(f"FAIL: {addr}: expected {want}, got {got}")
print("PASS: A+B delivered exactly 54 packets/64024 payload bytes at their shared 64-KiB wire quota; C independently delivered 30/30.")
CHECK
grep -q 'used 64 kbytes' <<<"$(quota_shared)" || die "shared A+B quota did not reach 64 KiB"
C_QUOTA="$(quota_c)"
printf '%s\n' "$C_QUOTA"
grep -Eq 'used 36840 bytes|used 36 kbytes' <<<"$C_QUOTA" || die "C independent quota did not record its 30 packets (expected 36840 bytes)"
echo "PASS: concurrent users did not leak quota usage across account groups."

echo "[Q-17] Repeated sustained quota cycles (6 rounds)"
for round in $(seq 1 6); do
  echo "Soak round $round/6"
  reset_quotas
  ip netns exec "$SINK" python3 "$UDP4" serve --port 44031 --duration 3 --output "$TMP/soak-$round.json" --ready-file "$TMP/soak-$round.ready" &
  SOAK_PID=$!; PIDS+=("$SOAK_PID")
  wait_ready "$SOAK_PID" "$TMP/soak-$round.ready"
  ip netns exec "$A" python3 "$UDP4" send --port 44031 --count 26 --interval 0.001 &
  S_A=$!; PIDS+=("$S_A")
  ip netns exec "$B" python3 "$UDP4" send --port 44031 --count 26 --interval 0.001 &
  S_B=$!; PIDS+=("$S_B")
  wait "$S_A"; wait "$S_B"
  ip netns exec "$A" python3 "$UDP4" send --port 44031 --count 1 --payload-size 1200 --interval 0
  ip netns exec "$B" python3 "$UDP4" send --port 44031 --count 1 --payload-size 424 --interval 0
  wait "$SOAK_PID"
  PIDS=()
  python3 - "$TMP/soak-$round.json" <<'CHECK'
import json, sys
d=json.load(open(sys.argv[1], encoding="utf-8"))
packets=sum(v.get("packets",0) for v in d.values())
payload=sum(v.get("payload_bytes",0) for v in d.values())
if (packets,payload)!=(54,64024):
    raise SystemExit(f"FAIL: soak round expected 54 packets/64024 bytes, got {packets}/{payload}")
CHECK
  grep -q 'used 64 kbytes' <<<"$(quota_shared)" || die "round $round did not stop at the configured quota"
  echo "PASS: round $round reached the exact quota boundary without excess delivery."
done
echo "PASS: six consecutive load/reset cycles completed (approximately 18 seconds of listener soak)."

echo "[Q-18] Recovery after complete lab teardown and topology rebuild"
bash "$LAB" down
bash "$LAB" up
for ns in "$GW" "$A" "$B" "$C" "$SINK"; do
  ip netns list | awk '{print $1}' | grep -Fxq "$ns" || die "namespace missing after rebuild: $ns"
done
grep -q 'until 64 kbytes' <<<"$(ip netns exec "$GW" nft list quota inet rma_lab shared_ab)" || die "shared quota policy not recreated"
grep -q 'policy drop' <<<"$(ip netns exec "$GW" nft list chain inet rma_lab forward)" || die "default-drop policy not restored after rebuild"
ip netns exec "$SINK" python3 "$UDP4" serve --port 44032 --duration 2 --output "$TMP/recovery.json" --ready-file "$TMP/recovery.ready" &
REC_PID=$!; PIDS+=("$REC_PID")
wait_ready "$REC_PID" "$TMP/recovery.ready"
ip netns exec "$A" python3 "$UDP4" send --port 44032 --count 3 --interval 0.01
wait "$REC_PID"
PIDS=()
python3 - "$TMP/recovery.json" <<'CHECK'
import json, sys
d=json.load(open(sys.argv[1], encoding="utf-8"))
got=d.get("10.10.1.2",{}).get("packets",0)
if got != 3:
    raise SystemExit(f"FAIL: post-rebuild traffic recovery expected 3 packets, got {got}")
print("PASS: all namespaces and firewall policy rebuilt; client traffic resumed after lab restart.")
CHECK

echo "Phase-A Stage 7 multi-user isolation, sustained-load, and rebuild-recovery tests passed."
echo "Restart here means isolated lab teardown/recreation, not a physical host reboot."
echo "This is bounded disposable-lab validation, not production acceptance or a durability certification."
