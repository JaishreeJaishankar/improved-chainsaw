import pandas as pd
import numpy as np
from typing import Dict, Any, List, Set, Tuple
from ip_utils import group_ips_into_networks, ports_to_services
from collections import defaultdict
import time

def generate_relationship_based_rules(logs_df: pd.DataFrame, max_rules: int = 15) -> List[Dict]:
    """
    Generate firewall rules based on actual source-destination-port relationships.
    This ensures that if certain source IPs only access certain destination IPs,
    they won't be grouped with other source IPs in the same rule.
    
    Args:
        logs_df: DataFrame with source.ip, destination.ip, and destination.port columns
        max_rules: Maximum number of rules to generate (default: 15)
        
    Returns:
        List of rule dictionaries
    """
    start_time = time.time()
    
    df = logs_df.copy()
    
    src_to_dest_map = defaultdict(set)
    
    for _, row in df.iterrows():
        src_ip = row['source.ip']
        dst_ip = row['destination.ip']
        dst_port = row['destination.port']
        src_to_dest_map[src_ip].add((dst_ip, dst_port))
    
    similarity_groups = group_by_destination_similarity(src_to_dest_map)
    
    rules = []
    rule_idx = 0
    
    for group in similarity_groups:
        src_ips = list(group)
        
        dest_ports_map = defaultdict(set)
        for src_ip in src_ips:
            for dst_ip, dst_port in src_to_dest_map[src_ip]:
                dest_ports_map[dst_ip].add(dst_port)
        
        dest_groups = group_destinations_by_ports(dest_ports_map)
        
        for dest_group in dest_groups:
            dest_ips = list(dest_group.keys())
            ports = sorted(list(set().union(*dest_group.values())))
            
            if not ports:
                continue
                
            clean_src_ips = [ip for ip in src_ips if not ip.endswith('/32')]
            clean_dst_ips = [ip for ip in dest_ips if not ip.endswith('/32')]
            
            src_cidrs = group_ips_into_networks(clean_src_ips)
            dst_cidrs = group_ips_into_networks(clean_dst_ips)
            
            port_ints = [int(p) for p in ports]
            services = ports_to_services(port_ints)
            
            rule_logs = df[
                df['source.ip'].isin(src_ips) & 
                df['destination.ip'].isin(dest_ips) & 
                df['destination.port'].isin(ports)
            ]
            
            rules.append({
                "rule_name": f"relationship_rule_{rule_idx}",
                "source_address": ", ".join(src_cidrs) if src_cidrs else "any",
                "destination_address": ", ".join(dst_cidrs) if dst_cidrs else "any",
                "service": ", ".join(services) if services else "any",
                "log_count": len(rule_logs)
            })
            
            rule_idx += 1
    
    if len(rules) > max_rules:
        rules = cap_rules(rules, max_rules)
    
    end_time = time.time()
    print(f"Rule generation completed in {end_time - start_time:.2f} seconds")
    
    return rules

def group_by_destination_similarity(src_to_dest_map: Dict[str, Set[Tuple[str, str]]], 
                                   similarity_threshold: float = 0.7) -> List[Set[str]]:
    """
    Group source IPs that have similar destination patterns.
    
    Args:
        src_to_dest_map: Mapping of source IPs to sets of (destination IP, port) tuples
        similarity_threshold: Jaccard similarity threshold for grouping (default: 0.7)
        
    Returns:
        List of sets of source IPs that should be grouped together
    """
    src_ips = list(src_to_dest_map.keys())
    
    groups = []
    assigned = set()
    
    for src_ip in src_ips:
        if src_ip in assigned:
            continue
            
        current_group = {src_ip}
        assigned.add(src_ip)
        
        for other_ip in src_ips:
            if other_ip in assigned or other_ip == src_ip:
                continue
                
            set1 = src_to_dest_map[src_ip]
            set2 = src_to_dest_map[other_ip]
            
            if not set1 or not set2:
                continue
                
            intersection = len(set1.intersection(set2))
            union = len(set1.union(set2))
            
            similarity = intersection / union if union > 0 else 0
            
            if similarity >= similarity_threshold:
                current_group.add(other_ip)
                assigned.add(other_ip)
        
        groups.append(current_group)
    
    return groups

def group_destinations_by_ports(dest_ports_map: Dict[str, Set[str]]) -> List[Dict[str, Set[str]]]:
    """
    Group destination IPs that have the same or similar port sets.
    
    Args:
        dest_ports_map: Mapping of destination IPs to sets of ports
        
    Returns:
        List of dictionaries mapping destination IPs to port sets
    """
    dest_ips = list(dest_ports_map.keys())
    
    groups = []
    assigned = set()
    
    for dest_ip in dest_ips:
        if dest_ip in assigned:
            continue
            
        current_group = {dest_ip: dest_ports_map[dest_ip]}
        assigned.add(dest_ip)
        
        for other_ip in dest_ips:
            if other_ip in assigned or other_ip == dest_ip:
                continue
                
            if dest_ports_map[other_ip] == dest_ports_map[dest_ip]:
                current_group[other_ip] = dest_ports_map[other_ip]
                assigned.add(other_ip)
        
        groups.append(current_group)
    
    return groups

def cap_rules(rules: List[Dict], max_rules: int) -> List[Dict]:
    """
    Cap the number of rules by keeping the most frequent ones and merging the rest.
    
    Args:
        rules: List of rule dictionaries
        max_rules: Maximum number of rules to keep
        
    Returns:
        Capped list of rule dictionaries
    """
    if len(rules) <= max_rules:
        return rules
    
    rules.sort(key=lambda r: r["log_count"], reverse=True)
    
    top_rules = rules[:max_rules-1]
    tail_rules = rules[max_rules-1:]
    
    all_src, all_dst, all_ports, log_sum = [], [], set(), 0
    for r in tail_rules:
        all_src += [cidr.strip() for cidr in r["source_address"].split(",")]
        all_dst += [cidr.strip() for cidr in r["destination_address"].split(",")]
        for s in r["service"].split(","):
            all_ports.add(s.strip())
        log_sum += r["log_count"]
    
    clean_src = [ip for ip in all_src if not ip.endswith('/32') and not '/32/32' in ip]
    clean_dst = [ip for ip in all_dst if not ip.endswith('/32') and not '/32/32' in ip]
    
    merged_src = group_ips_into_networks(clean_src)
    merged_dst = group_ips_into_networks(clean_dst)
    
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
        "source_address": ", ".join(merged_src) if merged_src else "any",
        "destination_address": ", ".join(merged_dst) if merged_dst else "any",
        "service": ", ".join(sorted(set(named_services))) if named_services else "any",
        "log_count": log_sum
    }
    
    return top_rules + [catch_all]
