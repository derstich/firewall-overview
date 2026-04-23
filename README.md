# firewall-overview

Displays a clear, color-coded overview of all ingress and egress firewall rules — including NAT/DNAT routing and ipset/nft-set IP group expansion.

Automatically detects whether the system uses **iptables** (legacy or nft frontend) or **pure nftables** and picks the best parser.

## Features

- **Auto-detection**: prefers `iptables-save` when active rules exist (gives full port detail for iptables-nft systems); falls back to `nft -j list ruleset` for pure nftables
- **Three-step ingress model**: RAW PREROUTING → NAT PREROUTING (DNAT) → INPUT filter
- **DNAT-aware summary**: ports forwarded to Docker/containers are shown separately and excluded from ALLOW/DROP counts
- **Recursive chain resolution**: follows Illumio VEN (`ILO-FILTER-*`) and custom chains to determine the final action
- **IP group expansion**: resolves ipset groups (`--match-set`) and native nft sets (`@SETNAME`) — IPs are listed directly below the rule
- **inet family support**: handles native nftables VEN deployments using the `inet` family (e.g. CentOS/RHEL with Illumio VEN)
- **Color-coded terminal output** + plain-text file output (ANSI stripped)

## Requirements

- Python 3.6+
- `sudo` access to run `iptables-save` and/or `nft`
- `ipset` (optional — for IP group expansion on iptables systems)

## Usage

```bash
# Auto-detect backend (recommended)
python3 firewall_overview.py

# Force iptables engine
python3 firewall_overview.py --backend iptables

# Force nft engine
python3 firewall_overview.py --backend nft

# Write output to a specific file
python3 firewall_overview.py -o /tmp/my-server.txt
```

The detected backend is shown in the header:
```
Firewall Overview  –  hostname.example.com  [iptables / iptables-nft – auto-detected]
Firewall Overview  –  hostname.example.com  [nftables – auto-detected]
```

## Output structure

```
Firewall Overview  –  hostname.example.com  [iptables / iptables-nft – auto-detected]

Default Policies (*filter):
  INPUT       : ACCEPT
  FORWARD     : DROP
  OUTPUT      : ACCEPT

INGRESS  –  INPUT chain
  -- Step 1 - RAW PREROUTING (before DNAT) --
  NAT  any  172.17.0.2  any  ! via docker0  DROP
       -> Direct access to Docker container blocked

  -- Step 2 - NAT PREROUTING (DNAT - before INPUT filter!) --
  NAT  tcp  <server>  8081  ! via docker0  ->DNAT
       -> Forwarded to 172.17.0.2:80  -  traffic continues via FORWARD (bypasses INPUT)

  -- Step 3 - INPUT filter (ILO-FILTER-INPUT) --
  1    any   any  any  22,80  NEW      ALLOW
  ...
  6    tcp   172.17.0.1[docker0]  any  22:23  NEW  ALLOW
             172.24.50.112
             172.24.50.161
             172.24.50.164
  ...
  8    any   any  any  any    DEFAULT  DROP
       -> All connections not explicitly covered above

EGRESS  –  OUTPUT chain
  ...

SUMMARY:
  + INGRESS ALLOW:  22 (SSH) [tcp], 80 (HTTP) [tcp], ...
  - INGRESS DROP:   ...
  > NAT/DNAT:       8081 (HTTP-alt) -> 172.17.0.2:80
                    (DNAT ports bypass INPUT filter - traffic routed via FORWARD to container)
  + EGRESS ALLOW:   53 (DNS) [tcp], ...

  Output written to: firewall-overview-hostname.example.com.txt
```

## Tested on

- Ubuntu 22.04 with Illumio VEN (`ILO-FILTER-*` chains, iptables-nft frontend)
- CentOS / RHEL with Illumio VEN (`inet ILO-FILTER-X` table, native nftables)
- Docker host with DNAT port forwarding
- Systems using ipset groups and native nft sets for IP whitelists
