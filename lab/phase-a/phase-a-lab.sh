#!/usr/bin/env bash
set -Eeuo pipefail

# Disposable Phase-A lab. All interfaces live in Linux network namespaces.
# This script never edits the host firewall, default routes, or production files.
readonly GW="rma-lab-gw"
readonly A="rma-lab-a"
readonly B="rma-lab-b"
readonly C="rma-lab-c"
readonly SINK="rma-lab-sink"
readonly TABLE="rma_lab"

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Run with sudo/root." >&2
    exit 1
  fi
}
need_tools() {
  local missing=()
  for x in ip nft sysctl ping; do command -v "$x" >/dev/null 2>&1 || missing+=("$x"); done
  if (("${#missing[@]}")); then
    printf 'Missing required tools: %s\n' "${missing[*]}" >&2
    exit 1
  fi
}
exists_ns() { ip netns list | awk '{print $1}' | grep -Fxq "$1"; }
assert_clean_names() {
  for ns in "$GW" "$A" "$B" "$C" "$SINK"; do
    if exists_ns "$ns"; then
      echo "Refusing: namespace $ns already exists; inspect it manually before proceeding." >&2
      exit 1
    fi
  done
}
cleanup_partial() {
  for ns in "$A" "$B" "$C" "$SINK" "$GW"; do
    if exists_ns "$ns"; then ip netns del "$ns" || true; fi
  done
}
link_pair() {
  local client="$1" cdev="$2" gwdev="$3" caddr="$4" gwaddr="$5"
  ip link add "$cdev" type veth peer name "$gwdev"
  ip link set "$cdev" netns "$client"
  ip link set "$gwdev" netns "$GW"
  ip -n "$client" link set lo up
  ip -n "$client" addr add "$caddr" dev "$cdev"
  ip -n "$client" link set "$cdev" up
  ip -n "$client" route add default via "${gwaddr%/*}"
  ip -n "$GW" addr add "$gwaddr" dev "$gwdev"
  ip -n "$GW" link set "$gwdev" up
}

up() {
  need_root; need_tools; assert_clean_names
  trap 'cleanup_partial' ERR
  for ns in "$GW" "$A" "$B" "$C" "$SINK"; do ip netns add "$ns"; done
  ip -n "$GW" link set lo up
  ip -n "$SINK" link set lo up

  link_pair "$A" a0 ga0 10.10.1.2/30 10.10.1.1/30
  link_pair "$B" b0 gb0 10.10.2.2/30 10.10.2.1/30
  link_pair "$C" c0 gc0 10.10.3.2/30 10.10.3.1/30

  ip link add gs0 type veth peer name s0
  ip link set gs0 netns "$GW"
  ip link set s0 netns "$SINK"
  ip -n "$GW" addr add 10.10.4.1/30 dev gs0
  ip -n "$GW" link set gs0 up
  ip -n "$SINK" addr add 10.10.4.2/30 dev s0
  ip -n "$SINK" link set s0 up
  ip -n "$SINK" route add 10.10.1.0/30 via 10.10.4.1
  ip -n "$SINK" route add 10.10.2.0/30 via 10.10.4.1
  ip -n "$SINK" route add 10.10.3.0/30 via 10.10.4.1

  ip netns exec "$GW" sysctl -q -w net.ipv4.ip_forward=1
  ip netns exec "$GW" nft -f - <<'NFT'
table inet rma_lab {
  # One aggregate quota for A+B; C has an independent quota.
  quota shared_ab { until 1 mbytes; }
  quota isolated_c { until 1 mbytes; }

  chain forward {
    type filter hook forward priority filter; policy drop;

    # A and B share exactly one quota in both directions.
    ip saddr 10.10.1.2 ip daddr 10.10.4.2 quota name "shared_ab" counter accept
    ip saddr 10.10.2.2 ip daddr 10.10.4.2 quota name "shared_ab" counter accept
    ip saddr 10.10.4.2 ip daddr 10.10.1.2 quota name "shared_ab" counter accept
    ip saddr 10.10.4.2 ip daddr 10.10.2.2 quota name "shared_ab" counter accept

    # C must not consume or inherit A+B quota.
    ip saddr 10.10.3.2 ip daddr 10.10.4.2 quota name "isolated_c" counter accept
    ip saddr 10.10.4.2 ip daddr 10.10.3.2 quota name "isolated_c" counter accept
  }
}
NFT
  trap - ERR
  echo "Phase-A topology created. No host firewall or production interface was modified."
  echo "Namespaces: $A, $B (shared quota), $C (independent quota), $GW, $SINK"
  echo "Inspect: sudo ip netns exec $GW nft list ruleset"
}

down() {
  need_root
  cleanup_partial
  echo "Removed only the named Phase-A lab namespaces."
}

status() {
  need_root
  for ns in "$GW" "$A" "$B" "$C" "$SINK"; do
    if exists_ns "$ns"; then echo "present: $ns"; else echo "absent:  $ns"; fi
  done
  if exists_ns "$GW"; then ip netns exec "$GW" nft list table inet "$TABLE" || true; fi
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *)
    echo "Usage: sudo $0 {up|status|down}" >&2
    exit 2
    ;;
esac
