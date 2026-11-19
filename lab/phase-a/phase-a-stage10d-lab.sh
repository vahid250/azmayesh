#!/usr/bin/env bash
set -Eeuo pipefail
# Disposable Stage 10D network: all zone interfaces are in named namespaces.
# Only the router namespace owns nftables forwarding policy; host firewall is untouched.
readonly ROUTER="rma10d-router"
readonly TABLE="rma10d"
declare -A IDX=( [edge]=1 [api]=2 [control]=3 [admin]=4 [monitor]=5 [vpn]=6 [db]=7 [ci]=8 [rogue]=9 [vpn_peer]=10 )
zones=(edge api control admin monitor vpn db ci rogue vpn_peer)
exists_ns(){ ip netns list | awk '{print $1}' | grep -Fxq "$1"; }
cleanup(){ for z in "${zones[@]}"; do exists_ns "rma10d-$z" && ip netns del "rma10d-$z" || true; done; exists_ns "$ROUTER" && ip netns del "$ROUTER" || true; }
need_root(){ [[ $EUID -eq 0 ]] || { echo "Run with sudo/root" >&2; exit 1; }; }
up(){
 need_root
 for n in "$ROUTER" "${zones[@]/#/rma10d-}"; do exists_ns "$n" && { echo "Refusing existing namespace: $n" >&2; exit 1; }; done
 ip netns add "$ROUTER"; ip -n "$ROUTER" link set lo up
 for z in "${zones[@]}"; do
   ns="rma10d-$z"; i="${IDX[$z]}"; net="10.20.$i"
   ip netns add "$ns"; ip -n "$ns" link set lo up
   ip link add "z${i}c" type veth peer name "z${i}r"
   ip link set "z${i}c" netns "$ns"; ip link set "z${i}r" netns "$ROUTER"
   ip -n "$ns" addr add "$net.2/30" dev "z${i}c"; ip -n "$ns" link set "z${i}c" up
   ip -n "$ns" route add default via "$net.1"
   ip -n "$ROUTER" addr add "$net.1/30" dev "z${i}r"; ip -n "$ROUTER" link set "z${i}r" up
 done
 ip netns exec "$ROUTER" sysctl -q -w net.ipv4.ip_forward=1
 ip netns exec "$ROUTER" nft -f - <<'NFT'
table inet rma10d {
 chain forward {
  type filter hook forward priority filter; policy drop;
  ct state established,related accept
  # Edge -> user API only
  ip saddr 10.20.1.2 ip daddr 10.20.2.2 tcp dport 8080 ct state new counter accept
  # User API -> approved control-plane API only
  ip saddr 10.20.2.2 ip daddr 10.20.3.2 tcp dport 8443 ct state new counter accept
  # Control plane -> database and registered VPN-node management only
  ip saddr 10.20.3.2 ip daddr 10.20.7.2 tcp dport 5432 ct state new counter accept
  ip saddr 10.20.3.2 ip daddr 10.20.6.2 tcp dport 9445 ct state new counter accept
  # Admin -> dedicated admin API and approved control-plane management
  ip saddr 10.20.4.2 ip daddr 10.20.3.2 tcp dport 9443 ct state new counter accept
  ip saddr 10.20.4.2 ip daddr 10.20.3.2 tcp dport 9444 ct state new counter accept
  # Monitoring -> read-only health endpoints only
  ip saddr 10.20.5.2 ip daddr 10.20.2.2 tcp dport 9100 ct state new counter accept
  ip saddr 10.20.5.2 ip daddr 10.20.3.2 tcp dport 9100 ct state new counter accept
 }
}
NFT
 echo "PASS: Stage 10D disposable zone topology created; router forward policy is default drop."
}
down(){ need_root; cleanup; echo "Removed only Stage 10D namespaces."; }
status(){ need_root; for n in "$ROUTER" "${zones[@]/#/rma10d-}"; do exists_ns "$n" && echo "present $n" || echo "absent $n"; done; }
case "${1:-}" in up) up;; down) down;; status) status;; *) echo "Usage: $0 {up|status|down}" >&2; exit 2;; esac
