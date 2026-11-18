# R&MA Integrated VPN — Phase A disposable Linux lab

## Purpose

Build a local, isolated network-namespace topology before any provider-hosted VM is considered. Device A and B share one nftables named quota; Device C has a separate quota. All forwarding is restricted to the lab sink and the dedicated namespace firewall chain.

## Safety boundary

- Requires root because Linux network namespaces and nftables are kernel features.
- The script refuses to run if any of its fixed namespace names already exist.
- It creates only veth links inside the named namespaces. It does not edit the host firewall, host routes, production services, cloud resources, Neon, or application data.
- No default route to the public internet is created.
- Flowtable and hardware offload are not configured.
- Use a disposable Linux VM where possible. Do not run on a production VPN host.
- Cleanup is explicit: `sudo ./phase-a-lab.sh down`. It deletes only the five exact namespace names owned by this lab; inspect them first if a name collision was reported.

## Requirements

Linux kernel with network namespace/veth support; `iproute2`, `nftables`, `iputils-ping`, and root privileges. Record `uname -r`, `nft --version`, and `ip -Version` with every test run.

## Start and inspect

```bash
sudo ./phase-a-lab.sh up
sudo ./phase-a-lab.sh status
sudo ip netns exec rma-lab-gw nft list ruleset
```

Topology:
- A: `10.10.1.2/30`
- B: `10.10.2.2/30`
- C: `10.10.3.2/30`
- Gateway-to-sink: `10.10.4.1/30` → `10.10.4.2/30`

A and B reference the same `shared_ab` quota object in both directions. C references `isolated_c`. The forward chain has a drop policy and contains no generic established/related accept rule that could bypass quota accounting.

## Phase-A execution sequence

1. **G0 preflight:** create the topology in a disposable VM; save kernel/tool versions and namespace/link/route snapshots.
2. **Baseline:** verify A, B, and C can reach only the sink before adding quota traffic generators. Confirm no public egress exists.
3. **Q-01/Q-02:** generate traffic from A and B, separately and concurrently; verify both consume the same named quota.
4. **Q-03:** generate traffic from C; verify only `isolated_c` changes.
5. **Q-04/Q-05:** repeat with TCP and UDP, both directions, varied MTU and concurrent flows. Record nftables quota/counters and independent sender/receiver byte counts.
6. **Boundary:** use small quotas and packet-size sweeps to measure the packet that crosses the threshold and any in-flight packets. Do not infer a billable-byte definition from nftables counters alone.
7. **Recovery:** destroy and recreate the disposable namespaces; test quota reset semantics. Reboot/restore tests belong to a disposable VM snapshot, not the host.
8. **Evidence:** store a redacted run record with commit, UTC time, kernel/nft versions, topology, commands, quota output, counters, packet capture, and pass/fail rationale.

The script's 1 MiB quotas are smoke-test defaults, not product policy or an approved overshoot limit. Do not interpret setup success as a passing quota test. Actual acceptance requires repeatable traffic tests and independently reconciled counters.

## Commands

```bash
sudo ./phase-a-lab.sh up
sudo ./phase-a-lab.sh status
sudo ./phase-a-lab.sh down
```

The initial scaffold deliberately does not start a traffic generator or claim a passing result. The next implementation step is an automated traffic/counter test harness, followed by execution inside the disposable VM.
