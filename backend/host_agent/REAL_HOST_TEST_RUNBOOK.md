# R&MA real-host lab test runbook

This runbook is for an isolated staging test only. It does not authorize a production launch, real payment collection, or customer rollout.

## 1. Required topology

- R&MA API and database may run on Cloudflare/another backend host.
- The actual WireGuard interface runs on a separate Linux VPN server.
- The trusted host agent runs only on that VPN server and is the only R&MA component that needs WireGuard network-administration capability.
- The API and VPN host share one operator-managed HMAC secret, delivered through their secret stores. Never send it in chat, commit it, or put it in a client configuration. Keep the VPN host clock synchronized with NTP/chrony; signatures older than five minutes are rejected.
- The API setting WG_INTERFACE and agent setting RMA_WG_INTERFACE must match exactly. The backend does not need CAP_NET_ADMIN; only the isolated host agent receives it.

## 2. Staging API configuration

Use a separate staging deployment and staging database. Required settings:

- APP_ENV=staging
- MOCK_MODE=false
- WG_SERVER_ENDPOINT=public-vpn-hostname-or-ip:51820
- WG_SERVER_PUBLIC_KEY=the actual 32-byte server public key, base64 encoded
- WG_INTERFACE=wg0 (or the actual interface)
- WG_SUBNET=the actual client subnet, e.g. 10.66.66.0/24
- ENCRYPTION_KEY=a separately generated Fernet key
- METERING_SHARED_SECRET=the same random secret configured on the VPN host (at least 32 characters)
- API_KEY=a staging-only API key if using the lab-local identity

Apply database migrations before issuing any test config. Do not reuse production credentials or production database.

## 3. VPN host preflight

On the VPN host, verify the interface is already configured and running, and confirm the firewall allows the WireGuard UDP port and the host has the required IP forwarding/NAT rules for the intended exit traffic:

    sudo wg show wg0
    sudo wg show wg0 dump

Install Python 3 and wireguard-tools. Copy the host_agent directory to /opt/rma/host_agent. Create the dedicated account and state directory:

    sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin rma-meter
    sudo install -d -o rma-meter -g rma-meter -m 0700 /var/lib/rma-meter
    sudo install -d -m 0700 /etc/rma

Create /etc/rma/metering.env with mode 0600. Populate it from metering.env.example using the same secret as the API. Do not put the secret in shell history or source control.

Install both systemd units at /etc/systemd/system/rma-wg-meter.service and /etc/systemd/system/rma-wg-meter-check.service. Review the interface dependency in both units if the interface is not wg0. Both units grant CAP_NET_ADMIN to the dedicated account only; do not run the agent as root. CAP_NET_ADMIN is scoped to the process's network namespace, not one interface. For production, isolate the VPN interface and agent in a dedicated network namespace/container.

## 4. Read-only preflight

Before enabling the service, run:

    sudo systemctl daemon-reload
    sudo systemctl start rma-wg-meter-check
    sudo journalctl -u rma-wg-meter-check -n 30 --no-pager

Expected output is JSON with:
- api_registry_authenticated=true
- wireguard_interface_readable=true
- authorized_peers_missing_from_interface=0
- pending_removal_count=0
- no_peer_changes=true
- no_usage_submission=true

The check command does not add or remove peers and does not submit usage. It may initialize the local SQLite state file. The one-shot preflight unit uses the same protected environment file and limited network capability as the long-running service.

If the API cannot be reached, the signature is rejected, the interface differs, or WireGuard counters cannot be read, stop here and correct the configuration.

## 5. Create one staging-only entitlement

On a trusted operator machine with access to the staging database, set APP_ENV=staging, MOCK_MODE=false, DATABASE_URL and RMA_ALLOW_TEST_ENTITLEMENTS=1. Run the helper from the backend directory:

    python scripts/create_lab_entitlement.py --telegram-user-id lab-local --quota-bytes 10485760 --duration-hours 2 --max-devices 1 --confirm-lab-only

This writes an explicitly zero-value TEST settlement and entitlement to staging only. It does not contact a payment provider and must never be run against production. Use the staging API key for the lab-local identity.

## 6. Start the host agent and issue one test config

Start the agent:

    sudo systemctl daemon-reload
    sudo systemctl enable --now rma-wg-meter
    sudo systemctl status rma-wg-meter
    sudo journalctl -u rma-wg-meter -f

Call POST /api/v1/wireguard/configs using the staging API key and body {"client_name":"rma-host-lab-phone"}. The API returns a config in pending_peer_registration state. The host agent should add the peer and acknowledge peer_registered within one polling interval. Confirm the state in the API before importing the config into a single test device.

Never publish the config, private key, API key, or shared secret.

## 7. Real traffic and quota test

1. Import the config into one test phone/device.
2. Connect and verify a handshake on the VPN host using wg show wg0.
3. Transfer a known small test payload through the tunnel.
4. Confirm RX+TX counters rise on the VPN host and the entitlement consumed_bytes rises in the staging database/API after the reporting interval.
5. Transfer enough data to exceed the remaining test quota. The backend should mark the entitlement exhausted; the next registry refresh should remove the peer and acknowledge suspended.
6. Revoke the peer through the API and verify the host agent removes it and the API state becomes revoked.
7. Confirm the device can no longer establish a handshake after removal.

## 8. Limits and stop conditions

- The agent polls counters; this is interval metering, not kernel-level byte-perfect shaping. Small additional traffic can pass between sampling and peer removal.
- The full measured final interval is recorded for audit, while entitlement consumption is capped at the purchased quota. A small amount of traffic may pass between the final sample and peer removal, but it is not debited beyond the quota.
- If peer removal fails, the agent logs a critical error. Do not proceed with customer traffic.
- The API currently does not expose live handshake telemetry from the host agent; verify handshake directly on the VPN host during this lab.
- Do not test failure modes by blocking the only remote management path on a production server.
- A successful lab test does not enable production issuance. Payment verification, legal/payment route, monitoring, backup/recovery, capacity, abuse handling, and a controlled production rollout remain separate gates.


## 9. Required nftables peer-revocation guard

Before starting the agent, provision the dedicated set and early drop rules in the host firewall (example for `wg0`; adapt only after reviewing the complete host ruleset):

    table inet rma_guard {
        set revoked_peer_sources {
            type ipv4_addr
        }
        chain input {
            type filter hook input priority -10; policy accept;
            iifname "wg0" ip saddr @revoked_peer_sources counter drop
        }
        chain forward {
            type filter hook forward priority -10; policy accept;
            iifname "wg0" ip saddr @revoked_peer_sources counter drop
        }
    }

Load this policy through the host's persistent nftables configuration and verify both guards appear before established-flow accept rules. Do not flush or replace an existing host firewall. The agent only mutates elements in the pre-existing set; it never creates tables, chains, sets, or policy rules. If the set is absent or nftables rejects an update, the agent must not acknowledge revocation.

The systemd agent unit is ordered after `nftables.service` so the persistent firewall policy is loaded first. The agent also stores revoked IPv4 sources in its protected SQLite state database (`/var/lib/rma-meter/usage.sqlite3`) before changing the volatile nftables set. On every authenticated registry reconciliation it validates both guard chains and rehydrates missing set elements from this durable ledger before enabling any authorized peer. Preserve this database across agent upgrades/restarts and include it in the protected host backup; never copy it to an untrusted machine.

### Restart and recovery test (staging only)

1. Revoke the lab peer and verify its IP appears in both the agent's durable revocation ledger and `nft list set inet rma_guard revoked_peer_sources`.
2. Stop the agent, reload the host's persistent nftables ruleset in the isolated staging environment (which recreates the dynamic set empty), then start the agent.
3. Within one registry polling cycle, verify the revoked IP is restored to the nftables set and the revoked WireGuard public key remains absent. Verify no peer-status ACK is sent until both firewall and WireGuard states are confirmed.
4. Restart the agent a second time without reloading nftables; confirm reconciliation is idempotent and does not fail on an already-present set element.
5. Test reauthorization for the same IP: confirm the WireGuard peer is installed first, then the nftables source element and durable ledger entry are removed.
6. Repeat with either guard chain missing. The agent must withhold the revocation ACK and attempt WireGuard-key removal as a fallback. Restore the firewall contract and confirm the next reconciliation repairs the source set and only then acknowledges the backend state.

Do not perform a full firewall flush on a host that carries management or production traffic. Use a disposable staging namespace/VM and retain an out-of-band recovery path.
