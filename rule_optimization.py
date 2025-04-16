# rule_optimization.py
import pandas as pd
from ip_utils import group_ips_into_networks, ports_to_services
from typing import Dict, Any, List

def aggregate_single_rule(logs_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Since the entire log belongs to a single rule, 
    we gather all distinct source IPs, 
    all distinct destination IPs, 
    and all distinct destination ports,
    then produce one recommended CIDR set for sources/destinations 
    and one set of services for ports.
    """
    # Unique sets of IPs and ports
    src_ips = logs_df["source.ip"].unique()
    dst_ips = logs_df["destination.ip"].unique()
    ports = logs_df["destination.port"].unique()
    
    # Convert the arrays to Python lists (if not already)
    src_list = list(src_ips)
    dst_list = list(dst_ips)
    port_list = [int(p) for p in ports]
    
    # Group IP addresses into CIDRs
    src_cidrs = group_ips_into_networks(src_list)
    dst_cidrs = group_ips_into_networks(dst_list)
    
    # Convert port numbers to service names or custom-ports
    services = ports_to_services(port_list)
    
    # Create a dictionary summarizing the single rule's "optimized" addresses/ports
    # No new rule name or anything is created—just a single aggregator
    optimized_rule = {
        "source_address": ", ".join(src_cidrs) if src_cidrs else "any",
        "destination_address": ", ".join(dst_cidrs) if dst_cidrs else "any",
        "service": ", ".join(services) if services else "any",
        "log_count": len(logs_df)
    }
    
    return optimized_rule

###############################################################################
# 1)  Helpers
###############################################################################

def _build_ip_to_cidr_map(all_ips: List[str]) -> Dict[str, str]:
    """
    Runs group_ips_into_networks(all_ips) **once** and produces
    a dict: raw_ip -> aggregated_cidr it belongs to.
    """
    cidr_list = group_ips_into_networks(all_ips)
    ip_to_cidr = {}
    import ipaddress

    for cidr in cidr_list:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            net = None

        # assign every IP that falls inside that net
        for ip in all_ips:
            if ip in ip_to_cidr:             # already mapped
                continue
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if net and ip_obj in net:
                ip_to_cidr[ip] = cidr

    # safety: any IP not mapped (invalid / IPv6 / etc.) => /32 of itself
    for ip in all_ips:
        ip_to_cidr.setdefault(ip, f"{ip}/32")

    return ip_to_cidr


###############################################################################
# 2)  Rule generator  (CIDR‑pair  →  rule)
###############################################################################

def generate_cidr_pair_rules(logs_df: pd.DataFrame) -> List[Dict]:
    """
    Step‑A: group *all* source IPs -> CIDRs, dest IPs -> CIDRs.
    Step‑B: group the dataframe on (src‑CIDR , dst‑CIDR).
    Step‑C: collapse **all ports** that appear in that pair to services list.
    Returns a list[dict]  (one dict per rule).
    """

    # ------------------------------------------------------------------  A
    src_map = _build_ip_to_cidr_map(logs_df["source.ip"].unique().tolist())
    dst_map = _build_ip_to_cidr_map(logs_df["destination.ip"].unique().tolist())

    # add two new columns with the CIDR labels
    logs_df = logs_df.copy()
    logs_df["src_cidr"] = logs_df["source.ip"].map(src_map)
    logs_df["dst_cidr"] = logs_df["destination.ip"].map(dst_map)

    # ------------------------------------------------------------------  B
    grouped = logs_df.groupby(["src_cidr", "dst_cidr"])

    rules = []
    rule_idx = 0
    for (src_cidr, dst_cidr), sub in grouped:

        # ------------------------------------------------------------------  C
        port_set = sorted({int(p) for p in sub["destination.port"].unique()})
        service_list = ports_to_services(port_set)
        services_str = ", ".join(service_list)

        rules.append(
            {
                "rule_name": f"cidr_pair_rule_{rule_idx}",
                "source_address": src_cidr,
                "destination_address": dst_cidr,
                "service": services_str or "any",
                "log_count": len(sub),
            }
        )
        rule_idx += 1

    return rules


###############################################################################
# 3)  Hard‑cap to ≤ 7  (same logic you already plugged earlier)
###############################################################################

MAX_RULES = 7
TOP_RULES = MAX_RULES - 1   # keep 6 busiest, merge the tail

def cap_rules_to_seven(rules: List[Dict]) -> List[Dict]:
    """
    Keep TOP_RULES largest by log_count, merge the rest into one catch‑all.
    """
    if len(rules) <= MAX_RULES:
        return rules

    rules.sort(key=lambda r: r["log_count"], reverse=True)
    top, tail = rules[:TOP_RULES], rules[TOP_RULES:]

    # merge tail ---------------------------------------------------------
    all_src, all_dst, all_ports, log_sum = [], [], set(), 0
    for r in tail:
        all_src  += [cidr.strip() for cidr in r["source_address"].split(",")]
        all_dst  += [cidr.strip() for cidr in r["destination_address"].split(",")]
        for s in r["service"].split(","):
            all_ports.add(s.strip())
        log_sum += r["log_count"]

    merged_src = group_ips_into_networks(all_src)
    merged_dst = group_ips_into_networks(all_dst)

    # rebuild services list
    numeric_ports = []
    named_services = []
    for svc in all_ports:
        if svc.startswith("custom-ports-"):
            numeric_ports += [int(p) for p in svc.split("-")[2:]]
        else:
            named_services.append(svc)
    if numeric_ports:
        named_services += ports_to_services(numeric_ports)

    catch_all = {
        "rule_name": "catch_all_tail",
        "source_address": ", ".join(merged_src) or "any",
        "destination_address": ", ".join(merged_dst) or "any",
        "service": ", ".join(sorted(set(named_services))) or "any",
        "log_count": log_sum,
    }

    return top + [catch_all]
