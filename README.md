# iptables-overview

Displays a clear, color-coded overview of all ingress and egress firewall rules — including NAT/DNAT routing.

**Recommended: use `firewall_overview.py`** — it auto-detects whether the system uses iptables or nftables and picks the best parser automatically. Individual scripts are also available if you want to force a specific backend.

## Features

- **Three-step ingress model**: RAW PREROUTING → NAT PREROUTING (DNAT) → INPUT filter
- **DNAT-aware summary**: ports forwarded to Docker/containers are shown separately and excluded from ALLOW/DROP counts
- **Recursive chain resolution**: follows Illumio VEN (`ILO-FILTER-*`) and custom chains to determine the final action
- **Color-coded terminal output** + plain-text file output (ANSI stripped)
- **Generic**: works on any Linux host — auto-detects hostname, chains, and DNAT targets

---

## Auto-detecting version (`firewall_overview.py`) — recommended

Automatically selects the best parser:
1. Uses `iptables-save` when iptables has active rules (covers both `iptables-legacy` and `iptables-nft` — gives full port detail via multiport/ctstate)
2. Falls back to `nft -j list ruleset` for pure nftables systems

### Requirements

- Python 3.6+
- `sudo` access to run `iptables-save` and/or `nft`

### Usage

```bash
# Auto-detect backend (default)
python3 firewall_overview.py

# Force iptables engine
python3 firewall_overview.py --backend iptables

# Force nft engine
python3 firewall_overview.py --backend nft

# Specify output file
python3 firewall_overview.py -o /tmp/my-server.txt
```

The detected backend is shown in the header, e.g.:
```
Firewall Overview  –  hostname.example.com  [iptables / iptables-nft – auto-detected]
```

---

## Python version (`iptables_overview.py`)

Reads `iptables-save` output directly. Best for systems using the iptables frontend (including `iptables-nft`).

### Requirements

- Python 3.6+
- `sudo` access to run `iptables-save`

### Usage

```bash
python3 iptables_overview.py
python3 iptables_overview.py -o /tmp/my-server.txt
```

---

## Bash version (`iptables_overview.sh`)

Identical output to the Python version, implemented in Bash.

### Requirements

- Bash 4+
- `sudo` access to run `iptables-save`
- `grep` with PCRE support (`grep -P`) — available by default on Ubuntu/RHEL

### Usage

```bash
bash iptables_overview.sh
bash iptables_overview.sh -o /tmp/my-server.txt
```

---

## nft-native Python version (`nft_overview.py`)

Reads rules directly via `sudo nft -j list ruleset` (JSON). Best for pure nftables systems.

> **Note for iptables-nft systems**: Port matching via `xt multiport` extensions is opaque in the nft JSON — ports appear as `(multiport)`. DNAT destinations are supplemented via `iptables-save -t nat`. For full per-port details on iptables-nft systems, use `firewall_overview.py` (auto) or `--backend iptables`.

### Requirements

- Python 3.6+
- `sudo` access to run `nft` and `iptables-save`

### Usage

```bash
python3 nft_overview.py
python3 nft_overview.py -o /tmp/my-server.txt
```

---

## Output structure

`iptables_overview.py` and `iptables_overview.sh` produce identical output:

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

`nft_overview.py` produces the same structure but reads from the nftables JSON backend.

---

## Tested on

- Ubuntu 22.04 with Illumio VEN (`ILO-FILTER-*` chains)
- Docker host with DNAT port forwarding
- Systems using `iptables-nft` (iptables frontend over nftables backend)
