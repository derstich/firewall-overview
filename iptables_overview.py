#!/usr/bin/env python3
"""
iptables-overview.py  –  Generic ingress/egress firewall rule overview incl. NAT/DNAT
Processing order: RAW PREROUTING -> CONNTRACK -> NAT PREROUTING (DNAT) -> INPUT / FORWARD
"""

import subprocess, re, sys, socket, argparse, io
from collections import defaultdict

R="\033[0m"; B="\033[1m"; RED="\033[31m"; GRN="\033[32m"
YEL="\033[33m"; CYN="\033[36m"; MGT="\033[35m"; GRY="\033[90m"

def strip_ansi(s):
    return re.sub(r"\x1b\[[0-9;]*m", "", s)

class Tee:
    """Write to both stdout (with color) and a file (plain text, no ANSI)."""
    def __init__(self, filepath):
        self.terminal = sys.stdout
        self.file = open(filepath, "w", encoding="utf-8")
    def write(self, msg):
        self.terminal.write(msg)
        self.file.write(strip_ansi(msg))
    def flush(self):
        self.terminal.flush()
        self.file.flush()
    def close(self):
        self.file.close()

def iptables_save():
    r = subprocess.run(["sudo","iptables-save"], capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"Error: {r.stderr}")
    return r.stdout

# ── Parser ────────────────────────────────────────────────────────────────────
def parse(raw):
    chains = defaultdict(list); policies = {}
    current_table = None
    all_chains = defaultdict(list)
    for line in raw.splitlines():
        s = line.strip()
        if s.startswith("*"):
            current_table = s[1:]; continue
        if s.startswith(":"):
            m = re.match(r":(\S+)\s+(ACCEPT|DROP|REJECT)", s)
            if m: policies[m.group(1)] = m.group(2)
        elif s.startswith("-A "):
            m = re.match(r"-A (\S+)\s+(.*)", s)
            if m:
                all_chains[(current_table, m.group(1))].append(m.group(2))
                if current_table == "filter":
                    chains[m.group(1)].append(m.group(2))
    return chains, policies, all_chains

# ── Action resolution ─────────────────────────────────────────────────────────
def chain_final_action(name, chains, seen=None):
    if seen is None: seen = set()
    if name in seen: return "ALLOW"
    seen.add(name)
    for rule in chains.get(name, []):
        if re.search(r"-j\s+(DROP|REJECT)\b", rule): return "DROP"
        m = re.search(r"-[jg]\s+(ILO-FILTER-ACTION-\S+)", rule)
        if m:
            if chain_final_action(m.group(1), chains, seen.copy()) == "DROP":
                return "DROP"
    return "ALLOW"

# ── Port names ────────────────────────────────────────────────────────────────
PORT_NAMES = {
    "22":"SSH","80":"HTTP","443":"HTTPS","53":"DNS",
    "67":"DHCP-srv","68":"DHCP-cli","8080":"HTTP-alt","8081":"HTTP-alt",
    "8443":"PCE-UI","8444":"PCE-Cluster","3306":"MySQL",
    "3389":"RDP","23":"Telnet","33434:33523":"Traceroute",
}

def port_label(p):
    if not p: return "any"
    for k,v in PORT_NAMES.items():
        if p == k: return f"{p} ({v})"
    return p

# ── Rule parser ───────────────────────────────────────────────────────────────
def parse_rule(raw_rule, chains):
    def g(pat, default=""):
        m = re.search(pat, raw_rule); return m.group(1) if m else default
    proto  = g(r"\b-p\s+(\S+)",  "any")
    src    = g(r"\b-s\s+(\S+)",  "any")
    dst    = g(r"\b-d\s+(\S+)",  "any")
    dport  = g(r"--dports?\s+(\S+)")
    sport  = g(r"--sports?\s+(\S+)")
    state  = g(r"--ctstate\s+(\S+)")
    iface  = g(r"\b-[io]\s+(\S+)")
    target = g(r"(?:^|\s)-[jg]\s+(\S+)")

    if   re.search(r"\b(DROP|REJECT)\b", target):  action = "DROP"
    elif target in ("ACCEPT","RETURN"):             action = "ALLOW"
    elif target.startswith("ILO-FILTER-ACTION-"):   action = chain_final_action(target, chains)
    elif target.startswith("ILO-FILTER-"):          action = None
    elif target == "":                              action = None
    else:                                           action = "ALLOW"

    return dict(proto=proto, src=src, dst=dst, dport=dport, sport=sport,
                state=state, iface=iface, action=action, note="")

SKIP = [
    r"--ctstate\s+(RELATED,ESTABLISHED|UNTRACKED)",
    r"-[io]\s+lo\b",
    r"ILO-FILTER-NS-LOG",
]

# ── Helper rows ───────────────────────────────────────────────────────────────
def static_row(state, action, note="", proto="any", src="any", dst="any",
               dport="", sport="", iface=""):
    return dict(proto=proto, src=src, dst=dst, dport=dport, sport=sport,
                state=state, iface=iface, action=action, note=note, row_type="rule")

def separator(label):
    return dict(row_type="separator", label=label)

def nat_row(proto, src, dst, dport, state, action, note):
    return dict(proto=proto, src=src, dst=dst, dport=dport, sport="",
                state=state, iface="", action=action, note=note, row_type="nat")

# ── NAT: RAW PREROUTING ───────────────────────────────────────────────────────
def collect_raw_rows(all_chains):
    rows = []
    for rule in all_chains.get(("raw", "PREROUTING"), []):
        m_t = re.search(r"(?:^|\s)-j\s+(\S+)", rule)
        if not m_t: continue
        target = m_t.group(1)
        if target not in ("DROP","REJECT","ACCEPT","RETURN"): continue

        proto  = re.search(r"\b-p\s+(\S+)", rule)
        src    = re.search(r"\b-s\s+(\S+)", rule)
        dst    = re.search(r"\b-d\s+(\S+)", rule)
        dport  = re.search(r"--dports?\s+(\S+)", rule)
        m_ni   = re.search(r"!\s*-i\s+(\S+)", rule)

        cond    = f"! via {m_ni.group(1)}" if m_ni else "any"
        action  = "DROP" if target in ("DROP","REJECT") else "ALLOW"
        dst_val = dst.group(1) if dst else "any"
        note    = ""
        if dst and re.match(r"172\.", dst_val):
            note = "Direct access to Docker container blocked"

        rows.append(nat_row(
            proto.group(1) if proto else "any",
            src.group(1)   if src   else "any",
            dst_val,
            dport.group(1) if dport else "any",
            cond, action, note
        ))
    return rows

# ── NAT: DNAT – recursive chain traversal ────────────────────────────────────
def collect_dnat_chain(all_chains, table, chain_name, seen=None):
    if seen is None: seen = set()
    if chain_name in seen: return []
    seen.add(chain_name)
    rows = []
    for rule in all_chains.get((table, chain_name), []):
        m_t = re.search(r"(?:^|\s)-j\s+(\S+)", rule)
        if not m_t: continue
        target = m_t.group(1)

        if target == "DNAT":
            proto   = re.search(r"\b-p\s+(\S+)", rule)
            dport   = re.search(r"--dports?\s+(\S+)", rule)
            to_dst  = re.search(r"--to-destination\s+(\S+)", rule)
            m_ni    = re.search(r"!\s*-i\s+(\S+)", rule)
            state_m = re.search(r"--ctstate\s+(\S+)", rule)

            conds = []
            if m_ni:    conds.append(f"! via {m_ni.group(1)}")
            if state_m: conds.append(f"->  {state_m.group(1)} conn")
            cond = "  ".join(conds) if conds else "any"

            dp = dport.group(1)  if dport  else ""
            to = to_dst.group(1) if to_dst else "?"
            pr = proto.group(1)  if proto  else "any"

            rows.append(nat_row(pr, "any", "<server>", dp, cond, "->DNAT",
                                f"Forwarded to {to}  -  traffic continues via FORWARD (bypasses INPUT)"))

        elif target == "MASQUERADE":
            proto = re.search(r"\b-p\s+(\S+)", rule)
            src   = re.search(r"\b-s\s+(\S+)", rule)
            rows.append(nat_row(
                proto.group(1) if proto else "any",
                src.group(1)   if src   else "any",
                "any", "", "POSTROUTING", "MASQ",
                "Source NAT for outbound traffic"
            ))

        elif (table, target) in all_chains:
            rows.extend(collect_dnat_chain(all_chains, table, target, seen))

    return rows

# ── Resolve effective chain ───────────────────────────────────────────────────
def get_effective_chain(filter_chains, base_chain):
    """Follow the first -j/-g jump from the base chain to the actual rule chain."""
    for rule in filter_chains.get(base_chain, []):
        m = re.search(r"-[jg]\s+(\S+)", rule)
        if m:
            target = m.group(1)
            if target in filter_chains:
                return target
    return base_chain

# ── Collect rules ─────────────────────────────────────────────────────────────
def collect_ingress(filter_chains, all_chains, policies):
    rows = []

    raw_rows = collect_raw_rows(all_chains)
    rows.append(separator("Step 1 - RAW PREROUTING (before DNAT)"))
    rows.extend(raw_rows)

    dnat_rows = collect_dnat_chain(all_chains, "nat", "PREROUTING")
    rows.append(separator("Step 2 - NAT PREROUTING (DNAT - before INPUT filter!)"))
    rows.extend(dnat_rows)

    dnat_ports = {r["dport"] for r in dnat_rows if r.get("dport")}

    input_chain = get_effective_chain(filter_chains, "INPUT")
    rows.append(separator(f"Step 3 - INPUT filter ({input_chain})"))
    rows.append(static_row("lo interface",        "ALLOW"))
    rows.append(static_row("RELATED,ESTABLISHED", "ALLOW"))

    added_default = False
    for raw_rule in filter_chains.get(input_chain, []):
        if any(re.search(p, raw_rule) for p in SKIP): continue
        m_t = re.search(r"-[jg]\s+(\S+)", raw_rule)
        if m_t:
            t = m_t.group(1)
            if t.endswith("-ENFORCE") or (t not in filter_chains and t not in
                    ("DROP","REJECT","ACCEPT","RETURN","MASQUERADE","DNAT","SNAT","LOG")):
                action = chain_final_action(t, filter_chains) if t in filter_chains else policies.get("INPUT", "ACCEPT")
                rows.append(static_row("DEFAULT (no match above)", action,
                                       "All connections not explicitly covered above"))
                added_default = True
                continue
        r = parse_rule(raw_rule, filter_chains)
        if r["action"] is not None:
            if r["action"] == "DROP" and r.get("dport") in dnat_ports:
                r["note"] = ("Illumio enforcement - applies only to traffic "
                             "NOT redirected via DNAT")
            r["row_type"] = "rule"
            rows.append(r)

    if not added_default:
        action = policies.get("INPUT", "ACCEPT")
        rows.append(static_row("DEFAULT (no match above)", action,
                               "All connections not explicitly covered above"))
    return rows

def collect_egress(filter_chains, policies):
    rows = []
    output_chain = get_effective_chain(filter_chains, "OUTPUT")
    rows.append(separator(f"Step - OUTPUT filter ({output_chain})"))
    rows.append(static_row("lo interface",        "ALLOW"))
    rows.append(static_row("RELATED,ESTABLISHED", "ALLOW"))

    added_default = False
    for raw_rule in filter_chains.get(output_chain, []):
        if any(re.search(p, raw_rule) for p in SKIP): continue
        m_t = re.search(r"-[jg]\s+(\S+)", raw_rule)
        if m_t:
            t = m_t.group(1)
            if t.endswith("-ENFORCE") or (t not in filter_chains and t not in
                    ("DROP","REJECT","ACCEPT","RETURN","MASQUERADE","DNAT","SNAT","LOG")):
                action = chain_final_action(t, filter_chains) if t in filter_chains else policies.get("OUTPUT", "ACCEPT")
                rows.append(static_row("DEFAULT (no match above)", action,
                                       "No explicit DROP for outbound traffic"))
                added_default = True
                continue
        r = parse_rule(raw_rule, filter_chains)
        if r["action"] is not None:
            r["row_type"] = "rule"
            rows.append(r)

    if not added_default:
        action = policies.get("OUTPUT", "ACCEPT")
        rows.append(static_row("DEFAULT (no match above)", action,
                               "No explicit DROP for outbound traffic"))
    return rows

# ── Formatting ────────────────────────────────────────────────────────────────
W = [4, 6, 14, 20, 26, 30, 8]
TOTAL_W = sum(W) + 2*(len(W)-1)

def hdr():
    cols = ["#","Proto","Src","Dst-IP","Port / Service","State / Condition","Action"]
    return (B + "  ".join(f"{c:<{w}}" for c,w in zip(cols,W)) + R
            + "\n" + "-"*TOTAL_W)

def fmt_action(action):
    if action == "ALLOW":   return f"{B}{GRN}ALLOW {R}"
    if action == "DROP":    return f"{B}{RED}DROP  {R}"
    if action == "->DNAT":  return f"{B}{MGT}->DNAT{R}"
    if action == "MASQ":    return f"{B}{MGT}MASQ  {R}"
    return f"{GRY}{str(action):<6}{R}"

def fmt_row(n, r, row_type="rule"):
    dp    = port_label(r["dport"]) if r["dport"] else ""
    sp    = f"src:{r['sport']}"    if r.get("sport") else ""
    port  = ", ".join(x for x in [dp,sp] if x) or "any"
    state = r.get("state") or "any"
    src   = r["src"]
    dst   = r["dst"]
    if r.get("iface"): src = src + f"[{r['iface']}]"

    num_col = f"{GRY}NAT{R}" if row_type == "nat" else str(n)
    vals = [num_col, r["proto"], src, dst, port, state]

    line = ""
    for v, w in zip(vals, W):
        visible = re.sub(r"\x1b\[[0-9;]*m", "", v)
        padding = max(0, w - len(visible))
        line += v + " "*padding + "  "
    line += fmt_action(r["action"])

    if r.get("note"):
        note_color = MGT if row_type == "nat" else GRY
        line += f"\n      {note_color}-> {r['note']}{R}"
    return line

def print_section(title, color, rows, direction):
    sep = color + "="*TOTAL_W + R
    print(f"\n{B}{color}{sep}{R}")
    print(f"{B}{color}  {direction}  -  {title}{R}")
    print(f"{B}{color}{sep}{R}")
    print(hdr())
    seq = 0
    for r in rows:
        rt = r.get("row_type","rule")
        if rt == "separator":
            print(f"\n  {B}{GRY}-- {r['label']} --{R}")
            continue
        if rt == "nat":
            print(fmt_row("NAT", r, "nat"))
        else:
            seq += 1
            print(fmt_row(seq, r, "rule"))
    print("-"*TOTAL_W)

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="iptables firewall overview")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="write plain-text output to FILE "
                             "(default: iptables-overview-<hostname>.txt)")
    args = parser.parse_args()

    hostname = socket.getfqdn()
    outfile = args.output if args.output else f"iptables-overview-{hostname}.txt"

    tee = Tee(outfile)
    sys.stdout = tee

    bar = "="*TOTAL_W
    print(f"\n{B}{bar}{R}")
    print(f"{B}  iptables Firewall Overview  -  {hostname}{R}")
    print(f"{B}{bar}{R}")

    raw = iptables_save()
    filter_chains, policies, all_chains = parse(raw)

    print(f"\n{B}Default Policies (*filter):{R}")
    for ch in ("INPUT","FORWARD","OUTPUT"):
        p = policies.get(ch,"ACCEPT")
        c = GRN if p=="ACCEPT" else RED
        print(f"  {ch:<12}: {B}{c}{p}{R}")

    ingress = collect_ingress(filter_chains, all_chains, policies)
    egress  = collect_egress(filter_chains, policies)

    print_section("INPUT chain", CYN, ingress, "INGRESS")
    print_section("OUTPUT chain", YEL, egress,  "EGRESS")

    i_dnat     = [r for r in ingress if r.get("action")=="->DNAT"]
    dnat_ports = {r["dport"] for r in i_dnat if r.get("dport")}

    def has_dnat_port(dport_str):
        """True if any individual port in a multiport string is DNAT'd."""
        return any(p in dnat_ports for p in dport_str.split(","))

    # Exclude rules where any port is DNAT'd: those bypass INPUT via FORWARD
    i_allow = [r for r in ingress if r.get("action")=="ALLOW" and r.get("dport")
               and not has_dnat_port(r["dport"])]
    i_drop  = [r for r in ingress if r.get("action")=="DROP"  and r.get("dport")
               and not has_dnat_port(r["dport"])]
    e_allow = [r for r in egress  if r.get("action")=="ALLOW" and r.get("dport")]
    e_drop  = [r for r in egress  if r.get("action")=="DROP"  and r.get("dport")]

    print(f"\n{B}SUMMARY:{R}")
    print(f"  {GRN}+ INGRESS ALLOW:{R}  "
          + ", ".join(f"{port_label(r['dport'])} [{r['proto']}]" for r in i_allow)
          + ",  RELATED/ESTABLISHED")
    if i_drop:
        print(f"  {RED}- INGRESS DROP: {R}  "
              + ", ".join(f"{port_label(r['dport'])} [{r['proto']}]" for r in i_drop))
    if i_dnat:
        print(f"  {MGT}> NAT/DNAT:    {R}  "
              + ", ".join(
                  f"{port_label(r['dport'])} -> {r.get('note','').split('to ')[-1].split(' ')[0]}"
                  for r in i_dnat))
        print(f"  {GRY}               (DNAT ports bypass INPUT filter - traffic routed via FORWARD to container){R}")
    print(f"  {YEL}+ EGRESS ALLOW: {R}  "
          + ", ".join(f"{port_label(r['dport'])} [{r['proto']}]" for r in e_allow)
          + ",  RELATED/ESTABLISHED,  DEFAULT ALLOW")
    if e_drop:
        print(f"  {RED}- EGRESS DROP:  {R}  "
              + ", ".join(f"{port_label(r['dport'])} [{r['proto']}]" for r in e_drop))
    tee.close()
    sys.stdout = tee.terminal
    print(f"\n  Output written to: {outfile}\n")

if __name__ == "__main__":
    main()
