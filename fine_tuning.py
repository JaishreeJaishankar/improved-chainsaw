import pandas as pd
import numpy as np
from typing import Dict, Any, List, Set, Tuple
import ipaddress
from collections import defaultdict
from ip_utils import group_ips_into_networks, ports_to_services

def fine_tune_single_rule(logs_df: pd.DataFrame, single_rule: Dict[str, Any], 
                         max_src_cidrs: int = 5, max_dst_cidrs: int = 5) -> Dict[str, Any]:
    """
    Apply fine-tuning to a single optimized rule to further reduce the permission boundary.
    
    This function analyzes traffic patterns to identify more specific CIDR blocks that
    still cover the necessary traffic while minimizing unnecessary permissions.
    
    Args:
        logs_df: DataFrame with source.ip, destination.ip, and destination.port columns
        single_rule: The single optimized rule to fine-tune
        max_src_cidrs: Maximum number of source CIDRs to include (default: 5)
        max_dst_cidrs: Maximum number of destination CIDRs to include (default: 5)
        
    Returns:
        Fine-tuned rule dictionary
    """
    src_cidrs = [cidr.strip() for cidr in single_rule["source_address"].split(",")]
    dst_cidrs = [cidr.strip() for cidr in single_rule["destination_address"].split(",")]
    
    src_ip_counts = logs_df["source.ip"].value_counts()
    dst_ip_counts = logs_df["destination.ip"].value_counts()
    
    unique_src_ips = logs_df["source.ip"].unique().tolist()
    unique_dst_ips = logs_df["destination.ip"].unique().tolist()
    
    fine_tuned_src_cidrs = fine_tune_cidrs(unique_src_ips, src_ip_counts, max_cidrs=max_src_cidrs)
    
    fine_tuned_dst_cidrs = fine_tune_cidrs(unique_dst_ips, dst_ip_counts, max_cidrs=max_dst_cidrs)
    
    fine_tuned_rule = {
        "source_address": ", ".join(fine_tuned_src_cidrs) if fine_tuned_src_cidrs else "any",
        "destination_address": ", ".join(fine_tuned_dst_cidrs) if fine_tuned_dst_cidrs else "any",
        "service": single_rule["service"],  # Keep the same services
        "log_count": single_rule["log_count"]
    }
    
    return fine_tuned_rule

def fine_tune_cidrs(ips: List[str], ip_counts: pd.Series, max_cidrs: int = 5) -> List[str]:
    """
    Fine-tune CIDRs based on IP frequency and subnet patterns.
    
    Args:
        ips: List of IP addresses
        ip_counts: Series with IP counts
        max_cidrs: Maximum number of CIDRs to return
        
    Returns:
        List of optimized CIDRs
    """
    if not ips:
        return []
    
    subnet_groups = defaultdict(list)
    for ip in ips:
        try:
            ip_obj = ipaddress.ip_address(ip)
            for mask in [24, 23, 22, 21, 20, 19, 18, 17, 16]:
                network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                subnet_groups[str(network)].append(ip)
        except (ValueError, TypeError):
            continue
    
    subnet_metrics = []
    for subnet, subnet_ips in subnet_groups.items():
        traffic_coverage = sum(ip_counts.get(ip, 0) for ip in subnet_ips)
        
        try:
            subnet_obj = ipaddress.ip_network(subnet)
            subnet_size = subnet_obj.num_addresses
            efficiency = traffic_coverage / subnet_size
        except (ValueError, ZeroDivisionError):
            efficiency = 0
        
        subnet_metrics.append({
            'subnet': subnet,
            'coverage': traffic_coverage,
            'efficiency': efficiency,
            'size': len(subnet_ips)
        })
    
    subnet_metrics.sort(key=lambda x: x['efficiency'], reverse=True)
    
    selected_subnets = []
    covered_ips = set()
    
    for subnet_info in subnet_metrics:
        subnet = subnet_info['subnet']
        subnet_ips = set(subnet_groups[subnet])
        
        new_ips = subnet_ips - covered_ips
        if new_ips:
            selected_subnets.append(subnet)
            covered_ips.update(new_ips)
            
            if len(selected_subnets) >= max_cidrs:
                break
    
    uncovered_ips = [ip for ip in ips if ip not in covered_ips]
    if uncovered_ips and len(selected_subnets) < max_cidrs:
        additional_cidrs = group_ips_into_networks(uncovered_ips)
        selected_subnets.extend(additional_cidrs[:max_cidrs - len(selected_subnets)])
    
    return selected_subnets

def analyze_rule_improvement(original_rule: Dict[str, Any], fine_tuned_rule: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze the improvement achieved by fine-tuning.
    
    Args:
        original_rule: The original single optimized rule
        fine_tuned_rule: The fine-tuned rule
        
    Returns:
        Dictionary with improvement metrics
    """
    original_src_cidrs = original_rule["source_address"].split(", ")
    fine_tuned_src_cidrs = fine_tuned_rule["source_address"].split(", ")
    
    original_dst_cidrs = original_rule["destination_address"].split(", ")
    fine_tuned_dst_cidrs = fine_tuned_rule["destination_address"].split(", ")
    
    original_src_size = calculate_address_space(original_src_cidrs)
    fine_tuned_src_size = calculate_address_space(fine_tuned_src_cidrs)
    
    original_dst_size = calculate_address_space(original_dst_cidrs)
    fine_tuned_dst_size = calculate_address_space(fine_tuned_dst_cidrs)
    
    src_reduction = 0
    if original_src_size > 0:
        src_reduction = ((original_src_size - fine_tuned_src_size) / original_src_size) * 100
    
    dst_reduction = 0
    if original_dst_size > 0:
        dst_reduction = ((original_dst_size - fine_tuned_dst_size) / original_dst_size) * 100
    
    return {
        "original_src_cidrs": len(original_src_cidrs),
        "fine_tuned_src_cidrs": len(fine_tuned_src_cidrs),
        "original_dst_cidrs": len(original_dst_cidrs),
        "fine_tuned_dst_cidrs": len(fine_tuned_dst_cidrs),
        "src_address_space_reduction": f"{src_reduction:.2f}%",
        "dst_address_space_reduction": f"{dst_reduction:.2f}%",
        "overall_reduction": f"{((src_reduction + dst_reduction) / 2):.2f}%"
    }

def calculate_address_space(cidrs: List[str]) -> int:
    """
    Calculate the total address space covered by a list of CIDRs.
    
    Args:
        cidrs: List of CIDR strings
        
    Returns:
        Total number of IP addresses covered
    """
    if "any" in cidrs:
        return 2**32  # Maximum IPv4 address space
    
    total_addresses = 0
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr.strip(), strict=False)
            total_addresses += network.num_addresses
        except ValueError:
            continue
    
    return total_addresses
