# iptables-overview

Reads `iptables-save` output and displays a clear, color-coded overview of all ingress and egress firewall rules — including NAT/DNAT routing. Available as both a **Python** and a **Bash** script.

## Features

- **Three-step ingress model**: RAW PREROUTING → NAT PREROUTING (DNAT) → INPUT filter
- **DNAT-aware summary**: ports forwarded to Docker/containers are shown separately and excluded from ALLOW/DROP counts
- **Recursive chain resolution**: follows Illumio VEN (`ILO-FILTER-*`) and custom chains to determine the final action
- **Color-coded terminal output** + plain-text file output (ANSI stripped)
- **Generic**: works on any Linux host — auto-detects hostname, chains, and DNAT targets

---

## Python version (`iptables_overview.py`)

### Requirements

- Python 3.6+
- `sudo` access to run `iptables-save`

### Usage

```bash
# Run with default output file (iptables-overview-<hostname>.txt)
python3 iptables_overview.py

# Specify output file
python3 iptables_overview.py -o /tmp/my-server.txt
```

---

## Bash version (`iptables_overview.sh`)

### Requirements

- Bash 4+
- `sudo` access to run `iptables-save`
- `grep` with PCRE support (`grep -P`) — available by default on Ubuntu/RHEL

### Usage

```bash
# Run with default output file (iptables-overview-<hostname>.txt)
bash iptables_overview.sh

# Specify output file
bash iptables_overview.sh -o /tmp/my-server.txt
```

---

## Output structure

Both versions produce identical output:

```
iptables Firewall Overview  -  hostname.example.com

Default Policies (*filter):
  INPUT       : ACCEPT
  FORWARD     : DROP
  OUTPUT      : ACCEPT

INGRESS  -  INPUT chain
  -- Step 1 - RAW PREROUTING (before DNAT) --
  NAT  any  172.17.0.2  any  ! via docker0  DROP
       -> Direct access to Docker container blocked

  -- Step 2 - NAT PREROUTING (DNAT - before INPUT filter!) --
  NAT  tcp  <server>  8081  ! via docker0  ->DNAT
       -> Forwarded to 172.17.0.2:80  -  traffic continues via FORWARD (bypasses INPUT)

  -- Step 3 - INPUT filter (ILO-FILTER-INPUT) --
  1    any   any  any  22,80  NEW      ALLOW
  2    any   any  any  8081   NEW      DROP
       -> Illumio enforcement - applies only to traffic NOT redirected via DNAT
  ...
  8    any   any  any  any    DEFAULT  DROP
       -> All connections not explicitly covered above

EGRESS  -  OUTPUT chain
  ...

SUMMARY:
  + INGRESS ALLOW:  22 (SSH) [tcp], 80 (HTTP) [tcp], ...
  - INGRESS DROP:   ...
  > NAT/DNAT:       8081 (HTTP-alt) -> 172.17.0.2:80, 8082 -> 172.17.0.3:80
                    (DNAT ports bypass INPUT filter - traffic routed via FORWARD to container)
  + EGRESS ALLOW:   53 (DNS) [tcp], ...

  Output written to: iptables-overview-hostname.example.com.txt
```

---

## Tested on

- Ubuntu 22.04 with Illumio VEN (`ILO-FILTER-*` chains)
- Docker host with DNAT port forwarding
