# rule_optimization.py
import pandas as pd
from ip_utils import group_ips_into_networks, ports_to_services
from typing import Dict, Any

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
