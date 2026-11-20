#!/usr/bin/env bash
set -Eeuo pipefail
# Disposable Stage 10D network: all zone interfaces are in named namespaces.
# Keep this topology covered by hardening, route, IPv6, and stateful-revocation CI.
# Only the router namespace owns nftables forwarding policy; host firewall is untouched.
readonly ROUTER="rma10d-router"
readonly EGRESS="rma10d-egress"
declare -A IDX=( [edge]=1 [api]=2 [control]=3 [admin]=4 [monitor]=5 [vpn]=6 [db]=7 [ci]=8 [rogue]=9 [vpn_peer]=10 )
zones=(edge api control admin monitor vpn db ci rogue vpn_peer)
exists_ns(){ ip netns list | awk '{print $1}' | grep -Fxq "$1"; }
cleanup(){ for z in "${zones[@]}"; do exists_ns "rma10d-$z" && ip netns del "rma10d-$z" || true; done; exists_ns "$EGRESS" && ip netns del "$EGRESS" || true; exists_ns "$ROUTER" && ip netns del "$ROUTER" || true; }
need_root(){ [[ $EUID -eq 0 ]] || { echo "Run with sudo/root" >&2; exit 1; }; }
up(){
 need_root
 for n in "$ROUTER" "$EGRESS" "${zones[@]/#/rma10d-}"; do exists_ns "$n" && { echo "Refusing existing namespace: $n" >&2; exit 1; }; done
 ip netns add "$ROUTER"; ip netns exec "$ROUTER" sysctl -q -w net.ipv6.conf.all.disable_ipv6=0; ip netns exec "$ROUTER" sysctl -q -w net.ipv6.conf.default.disable_ipv6=0; ip -n "$ROUTER" link set lo up
 for z in "${zones[@]}"; do
   ns="rma10d-$z"; i="${IDX[$z]}"; net="10.20.$i"
   ip netns add "$ns"; ip netns exec "$ns" sysctl -q -w net.ipv6.conf.all.disable_ipv6=0; ip netns exec "$ns" sysctl -q -w net.ipv6.conf.default.disable_ipv6=0; ip -n "$ns" link set lo up
   ip link add "z${i}c" type veth peer name "z${i}r"
   ip link set "z${i}c" netns "$ns"; ip link set "z${i}r" netns "$ROUTER"
   ip -n "$ns" addr add "$net.2/30" dev "z${i}c"; ip -n "$ns" -6 addr add "fd10:10:${i}::2/64" dev "z${i}c" nodad; ip -n "$ns" link set "z${i}c" up
   ip -n "$ns" route add default via "$net.1"
   ip -n "$ns" -6 route add default via "fd10:10:${i}::1" dev "z${i}c"
   ip -n "$ROUTER" addr add "$net.1/30" dev "z${i}r"; ip -n "$ROUTER" -6 addr add "fd10:10:${i}::1/64" dev "z${i}r" nodad; ip -n "$ROUTER" link set "z${i}r" up
 done
 # Isolated egress transit: packets reach a disposable external namespace, never host/global network.
 ip netns add "$EGRESS"; ip -n "$EGRESS" link set lo up
 ip link add "rma10d-out" type veth peer name "rma10d-in"
 ip link set "rma10d-out" netns "$ROUTER"; ip link set "rma10d-in" netns "$EGRESS"
 ip -n "$ROUTER" addr add 198.18.0.1/30 dev "rma10d-out"; ip -n "$ROUTER" link set "rma10d-out" up
 ip -n "$EGRESS" addr add 198.18.0.2/30 dev "rma10d-in"; ip -n "$EGRESS" link set "rma10d-in" up
 ip -n "$ROUTER" route add default via 198.18.0.2
 ip -n "$EGRESS" route add 10.20.0.0/16 via 198.18.0.1
 ip netns exec "$ROUTER" sysctl -q -w net.ipv4.ip_forward=1
 ip netns exec "$ROUTER" sysctl -q -w net.ipv6.conf.all.forwarding=1
 ip netns exec "$ROUTER" nft -f - <<'NFT'
table inet rma10d {
 # Dynamic exact-flow revocation list; control plane may add/remove tuple elements.
 set revoked_tcp_flows {
  type ipv4_addr . ipv4_addr . inet_service
 }
 set revoked_peer_sources {
  type ipv4_addr
 }
 chain forward {
  type filter hook forward priority filter; policy drop;
  # Validate source identity and deny IPv6 before established-flow fast path.
  # Per-zone IPv4 source anti-spoofing: each ingress interface accepts only its assigned source.
  iifname "z1r" ip saddr != 10.20.1.2 counter drop
  iifname "z2r" ip saddr != 10.20.2.2 counter drop
  iifname "z3r" ip saddr != 10.20.3.2 counter drop
  iifname "z4r" ip saddr != 10.20.4.2 counter drop
  iifname "z5r" ip saddr != 10.20.5.2 counter drop
  iifname "z6r" ip saddr != 10.20.6.2 counter drop
  iifname "z7r" ip saddr != 10.20.7.2 counter drop
  iifname "z8r" ip saddr != 10.20.8.2 counter drop
  iifname "z9r" ip saddr != 10.20.9.2 counter drop
  iifname "z10r" ip saddr != 10.20.10.2 counter drop
  # IPv6 forwarding is explicitly denied on every zone ingress.
  iifname "z1r" meta nfproto ipv6 counter drop
  iifname "z2r" meta nfproto ipv6 counter drop
  iifname "z3r" meta nfproto ipv6 counter drop
  iifname "z4r" meta nfproto ipv6 counter drop
  iifname "z5r" meta nfproto ipv6 counter drop
  iifname "z6r" meta nfproto ipv6 counter drop
  iifname "z7r" meta nfproto ipv6 counter drop
  iifname "z8r" meta nfproto ipv6 counter drop
  iifname "z9r" meta nfproto ipv6 counter drop
  iifname "z10r" meta nfproto ipv6 counter drop
  # Peer-source revocation guard blocks all traffic from a revoked tunnel address.
  iifname "z1r" ip saddr @revoked_peer_sources counter drop comment "stage10d-peer-source-revocation"
  # Exact-flow revocation remains available for narrowly scoped policy cases.
  ip saddr . ip daddr . tcp dport @revoked_tcp_flows counter drop comment "stage10d-revocation-set"
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
  # Explicit egress-deny counters: outside the lab subnet is blocked per source zone.
  ip saddr 10.20.1.2 ip daddr != 10.20.0.0/16 counter drop
  ip saddr 10.20.2.2 ip daddr != 10.20.0.0/16 counter drop
  ip saddr 10.20.3.2 ip daddr != 10.20.0.0/16 counter drop
  ip saddr 10.20.4.2 ip daddr != 10.20.0.0/16 counter drop
  ip saddr 10.20.5.2 ip daddr != 10.20.0.0/16 counter drop
  ip saddr 10.20.6.2 ip daddr != 10.20.0.0/16 counter drop
  ip saddr 10.20.7.2 ip daddr != 10.20.0.0/16 counter drop
  ip saddr 10.20.8.2 ip daddr != 10.20.0.0/16 counter drop
  ip saddr 10.20.9.2 ip daddr != 10.20.0.0/16 counter drop
  ip saddr 10.20.10.2 ip daddr != 10.20.0.0/16 counter drop
  # Explicit deny-path counters for the Route Matrix negative cases.
  ip saddr 10.20.1.2 ip daddr 10.20.3.2 tcp dport 8443 counter drop
  ip saddr 10.20.2.2 ip daddr 10.20.7.2 tcp dport 5432 counter drop
  ip saddr 10.20.2.2 ip daddr 10.20.4.2 tcp dport 9443 counter drop
  ip saddr 10.20.5.2 ip daddr 10.20.3.2 tcp dport 8443 counter drop
  ip saddr 10.20.6.2 ip daddr 10.20.7.2 tcp dport 5432 counter drop
  ip saddr 10.20.6.2 ip daddr 10.20.8.2 tcp dport 8080 counter drop
  ip saddr 10.20.4.2 ip daddr 10.20.7.2 tcp dport 5432 counter drop
  ip saddr 10.20.9.2 ip daddr 10.20.2.2 tcp dport 8080 counter drop
  ip saddr 10.20.10.2 ip daddr 10.20.3.2 tcp dport 8443 counter drop
  # Additional negative-route audit cases; counters prove the matching drop rule.
  ip saddr 10.20.1.2 ip daddr 10.20.7.2 tcp dport 5432 counter drop
  ip saddr 10.20.1.2 ip daddr 10.20.3.2 tcp dport 9443 counter drop
  ip saddr 10.20.2.2 ip daddr 10.20.3.2 tcp dport 9444 counter drop
  ip saddr 10.20.2.2 ip daddr 10.20.6.2 tcp dport 9445 counter drop
  ip saddr 10.20.5.2 ip daddr 10.20.3.2 tcp dport 9200 counter drop
  ip saddr 10.20.4.2 ip daddr 10.20.2.2 tcp dport 8080 counter drop
  ip saddr 10.20.4.2 ip daddr 10.20.3.2 tcp dport 8443 counter drop
  ip saddr 10.20.4.2 ip daddr 10.20.6.2 tcp dport 9445 counter drop
  ip saddr 10.20.4.2 ip daddr 10.20.8.2 tcp dport 9000 counter drop
  # Monitoring -> read-only health endpoints only
  ip saddr 10.20.5.2 ip daddr 10.20.2.2 tcp dport 9100 ct state new counter accept
  ip saddr 10.20.5.2 ip daddr 10.20.3.2 tcp dport 9100 ct state new counter accept
 }
}
NFT
 echo "PASS: Stage 10D disposable zone topology created; router forward policy is default drop."
}
down(){ need_root; cleanup; echo "Removed only Stage 10D namespaces."; }
status(){ need_root; for n in "$ROUTER" "$EGRESS" "${zones[@]/#/rma10d-}"; do exists_ns "$n" && echo "present $n" || echo "absent $n"; done; }
case "${1:-}" in up) up;; down) down;; status) status;; *) echo "Usage: $0 {up|status|down}" >&2; exit 2;; esac
