# R&MA Phase A — disposable namespace lab

This folder contains a Linux-only, isolated smoke-test topology.

## Files

- `phase-a-lab.sh`: creates/removes the five named network namespaces and their veth links.
- `traffic.py`: standard-library UDP sink and sender; no external Python packages.
- `phase-a-traffic-test.sh`: runs a shared-quota test for A+B and an independent-quota test for C.

## Safety

Run only in a disposable Linux VM. The scripts create no public egress route and do not edit the host firewall or production network. The setup script refuses namespace-name collisions. Cleanup removes only the lab namespaces.

## Run

```bash
sudo ./phase-a-lab.sh up
sudo ./phase-a-lab.sh status
sudo ./phase-a-traffic-test.sh
sudo ./phase-a-lab.sh down
```

The initial quota is 64 kbytes. A and B each attempt 30 UDP datagrams with 1200-byte payloads. A should fit within the cap; B should be constrained by the same named quota. C is tested against a separately reset quota and should deliver all 30 packets.

The test deliberately uses broad packet-count acceptance bounds to detect shared-vs-independent behavior, not to certify exact quota byte accounting. UDP sink payload bytes are not the same accounting layer as nftables skb bytes. Exact boundary, packet overhead, bidirectional accounting, concurrency, TCP, MTU, and overshoot remain separate tests.

A passing local smoke test is not a production approval.
