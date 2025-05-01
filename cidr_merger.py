import ipaddress
from typing import List, Dict, Tuple
import pandas as pd
import numpy as np

def merge_overlapping_cidrs(cidr_list: List[str]) -> List[str]:
    """
    Merge CIDRs that are overlapping or adjacent to create more efficient rules.
    Returns a list of optimized CIDR blocks.
    """
    if not cidr_list:
        return []
    
    networks = []
    for cidr in cidr_list:
        try:
            networks.append(ipaddress.ip_network(cidr.strip(), strict=False))
        except ValueError:
            print(f"Warning: Invalid CIDR {cidr}, skipping.")
    
    if not networks:
        return []
    
    networks.sort(key=lambda x: (x.network_address, x.prefixlen))
    
    merged = []
    current = networks[0]
    
    for network in networks[1:]:
        current_broadcast = current.broadcast_address
        next_first = network.network_address
        
        if int(next_first) <= int(current_broadcast) + 1:
            try:
                combined = ipaddress.ip_network(
                    f"{current.network_address}/{min(current.prefixlen, network.prefixlen)}", 
                    strict=False
                )
                
                if (combined.num_addresses <= (current.num_addresses + network.num_addresses) * 1.5):
                    current = combined
                    continue
            except ValueError:
                pass
        
        merged.append(current)
        current = network
    
    merged.append(current)
    
    return [str(net) for net in merged]

def calculate_cidr_efficiency(original_cidrs: List[str], merged_cidrs: List[str]) -> Dict[str, float]:
    """
    Calculate the efficiency of CIDR merging by comparing
    address space coverage, rule count reduction, and overall efficiency.
    """
    if not original_cidrs or not merged_cidrs:
        return {
            "address_space_ratio": 1.0,
            "rule_reduction_ratio": 1.0,
            "overall_efficiency": 1.0
        }
    
    original_addr_count = sum(ipaddress.ip_network(cidr.strip(), strict=False).num_addresses 
                             for cidr in original_cidrs)
    merged_addr_count = sum(ipaddress.ip_network(cidr.strip(), strict=False).num_addresses 
                          for cidr in merged_cidrs)
    
    address_space_ratio = original_addr_count / merged_addr_count if merged_addr_count > 0 else 1.0
    rule_reduction_ratio = len(original_cidrs) / len(merged_cidrs) if len(merged_cidrs) > 0 else 1.0
    
    overall_efficiency = (0.7 * address_space_ratio) + (0.3 * rule_reduction_ratio)
    
    return {
        "address_space_ratio": round(address_space_ratio, 4),
        "rule_reduction_ratio": round(rule_reduction_ratio, 4),
        "overall_efficiency": round(overall_efficiency, 4)
    }

def optimize_cidrs_by_usage(
    logs_df: pd.DataFrame, 
    cidr_list: List[str], 
    ip_column: str, 
    min_efficiency: float = 0.7
) -> Tuple[List[str], Dict]:
    """
    Optimize CIDRs based on actual usage patterns in the logs.
    Returns optimized CIDRs and efficiency metrics.
    """
    if cidr_list is None or len(cidr_list) <= 1:
        return cidr_list, {}
    
    ip_counts = logs_df[ip_column].value_counts().to_dict()
    
    ip_to_cidr = {}
    for cidr in cidr_list:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
        for ip_str in ip_counts:
            try:
                ip = ipaddress.ip_address(ip_str)
                if ip in net:
                    ip_to_cidr[ip_str] = cidr
            except ValueError:
                continue
    
    cidr_usage = {}
    for ip, cidr in ip_to_cidr.items():
        cidr_usage.setdefault(cidr, 0)
        cidr_usage[cidr] += ip_counts.get(ip, 0)
    
    sorted_cidrs = sorted(cidr_usage.items(), key=lambda x: x[1], reverse=True)
    
    result_cidrs = [sorted_cidrs[0][0]] if sorted_cidrs else []
    
    for cidr, _ in sorted_cidrs[1:]:
        best_merge = None
        best_efficiency = 0
        
        for i, existing in enumerate(result_cidrs):
            test_merge = merge_overlapping_cidrs([existing, cidr])
            
            if len(test_merge) < 2:  # Successfully merged
                efficiency = calculate_cidr_efficiency([existing, cidr], test_merge)
                if efficiency["overall_efficiency"] > best_efficiency:
                    best_merge = (i, test_merge[0])
                    best_efficiency = efficiency["overall_efficiency"]
        
        if best_merge and best_efficiency >= min_efficiency:
            i, merged_cidr = best_merge
            result_cidrs[i] = merged_cidr
        else:
            result_cidrs.append(cidr)
    
    efficiency_metrics = calculate_cidr_efficiency(cidr_list, result_cidrs)
    
    return result_cidrs, efficiency_metrics

def merge_cidrs(cidr_list: List[str]) -> List[str]:
    """
    Merge a list of CIDRs into optimized network ranges.
    
    Args:
        cidr_list: List of CIDR strings
        
    Returns:
        List of optimized CIDR strings
    """
    return merge_overlapping_cidrs(cidr_list)
