# iptables-overview

A Python script that reads `iptables-save` output and displays a clear, color-coded overview of all ingress and egress firewall rules — including NAT/DNAT routing.

## Features

- **Three-step ingress model**: RAW PREROUTING → NAT PREROUTING (DNAT) → INPUT filter
- **DNAT-aware summary**: ports forwarded to Docker/containers are shown separately and excluded from ALLOW/DROP counts
- **Recursive chain resolution**: follows Illumio VEN (`ILO-FILTER-*`) and custom chains to determine the final action
- **Color-coded terminal output** + plain-text file output (ANSI stripped)
- **Generic**: works on any Linux host — auto-detects hostname, chains, and DNAT targets

## Requirements

- Python 3.6+
- `sudo` access to run `iptables-save`

## Usage

```bash
# Run with default output file (iptables-overview-<hostname>.txt)
sudo python3 iptables_overview.py

# Specify output file
sudo python3 iptables_overview.py -o /tmp/my-server.txt
```

## Output Structure

```
INGRESS – INPUT chain
  -- Step 1 – RAW PREROUTING (before DNAT) --
  NAT  ...  DROP     ← direct container IP access blocked

  -- Step 2 – NAT PREROUTING (DNAT – before INPUT filter!) --
  NAT  tcp  <server>  8081  ->DNAT  ← forwarded to 172.17.0.2:80 via FORWARD

  -- Step 3 – INPUT filter (ILO-FILTER-INPUT) --
  1    any   ...  22,80   NEW   ALLOW
  2    ...         8081   NEW   DROP  ← Illumio enforcement (only affects non-DNAT traffic)
  ...
  8    any   ...   any    DEFAULT  DROP

EGRESS – OUTPUT chain
  ...

SUMMARY:
  + INGRESS ALLOW:  22 (SSH), 80 (HTTP), ...
  - INGRESS DROP:   ...
  > NAT/DNAT:       8081 -> 172.17.0.2:80, 8082 -> 172.17.0.3:80
                    (DNAT ports bypass INPUT filter - traffic routed via FORWARD to container)
```

## Tested On

- Ubuntu 22.04 with Illumio VEN (`ILO-FILTER-*` chains)
- Docker host with DNAT port forwarding
