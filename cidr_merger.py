import ipaddress
from typing import List, Dict, Any, Tuple, Set
import pandas as pd
from collections import defaultdict

def analyze_cidrs(cidrs: List[str]) -> Dict[str, Any]:
    """
    Analyze a list of CIDRs to identify potential merging opportunities.
    
    Args:
        cidrs: List of CIDR strings
        
    Returns:
        Dictionary with analysis results
    """
    if not cidrs or cidrs == ["any"]:
        return {"message": "No CIDRs to analyze or 'any' specified"}
    
    networks = []
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr.strip(), strict=False)
            networks.append({
                "cidr": str(network),
                "network": network,
                "size": network.num_addresses,
                "first_ip": str(network.network_address),
                "last_ip": str(network.broadcast_address)
            })
        except ValueError as e:
            return {"error": f"Invalid CIDR: {cidr} - {str(e)}"}
    
    networks.sort(key=lambda x: x["size"])
    
    overlaps = []
    for i, net1 in enumerate(networks):
        for j, net2 in enumerate(networks):
            if i != j:
                if net1["network"].overlaps(net2["network"]):
                    overlaps.append({
                        "cidr1": net1["cidr"],
                        "cidr2": net2["cidr"],
                        "relationship": "overlaps"
                    })
    
    mergeable = []
    for i, net1 in enumerate(networks):
        for j, net2 in enumerate(networks):
            if i != j:
                if (net1["network"].broadcast_address + 1 == net2["network"].network_address or
                    net2["network"].broadcast_address + 1 == net1["network"].network_address):
                    
                    combined_ips = list(net1["network"].hosts()) + list(net2["network"].hosts())
                    try:
                        combined_network = ipaddress.ip_network(
                            ipaddress.ip_network(
                                f"{min(combined_ips)}/{max(net1['network'].prefixlen, net2['network'].prefixlen)}", 
                                strict=False
                            ).supernet(new_prefix=min(net1['network'].prefixlen, net2['network'].prefixlen) - 1),
                            strict=False
                        )
                        
                        mergeable.append({
                            "cidr1": net1["cidr"],
                            "cidr2": net2["cidr"],
                            "merged_cidr": str(combined_network),
                            "original_size": net1["size"] + net2["size"],
                            "merged_size": combined_network.num_addresses,
                            "efficiency": (net1["size"] + net2["size"]) / combined_network.num_addresses
                        })
                    except (ValueError, TypeError):
                        pass
    
    mergeable.sort(key=lambda x: x["efficiency"], reverse=True)
    
    return {
        "networks": networks,
        "overlaps": overlaps,
        "mergeable": mergeable
    }

def suggest_cidr_merges(cidrs: List[str], min_efficiency: float = 0.5) -> List[Dict[str, Any]]:
    """
    Suggest CIDR merges based on efficiency threshold.
    
    Args:
        cidrs: List of CIDR strings
        min_efficiency: Minimum efficiency threshold for merging (default: 0.5)
        
    Returns:
        List of suggested merges
    """
    analysis = analyze_cidrs(cidrs)
    
    if "error" in analysis or "message" in analysis:
        return []
    
    suggestions = [merge for merge in analysis["mergeable"] if merge["efficiency"] >= min_efficiency]
    
    return suggestions

def merge_cidrs(cidrs: List[str], merges_to_apply: List[Dict[str, Any]]) -> List[str]:
    """
    Apply specified merges to a list of CIDRs.
    
    Args:
        cidrs: List of CIDR strings
        merges_to_apply: List of merge dictionaries to apply
        
    Returns:
        Updated list of CIDRs
    """
    if not cidrs or cidrs == ["any"] or not merges_to_apply:
        return cidrs
    
    result_cidrs = cidrs.copy()
    
    for merge in merges_to_apply:
        if "cidr1" in merge and "cidr2" in merge and "merged_cidr" in merge:
            if merge["cidr1"] in result_cidrs:
                result_cidrs.remove(merge["cidr1"])
            if merge["cidr2"] in result_cidrs:
                result_cidrs.remove(merge["cidr2"])
            
            if merge["merged_cidr"] not in result_cidrs:
                result_cidrs.append(merge["merged_cidr"])
    
    return result_cidrs

def interactive_cidr_merge(rule: Dict[str, Any]) -> Dict[str, Any]:
    """
    Interactive CIDR merging for a firewall rule.
    
    Args:
        rule: Firewall rule dictionary
        
    Returns:
        Updated rule with merged CIDRs
    """
    print("\nInteractive CIDR Merger")
    print("======================")
    
    src_cidrs = [cidr.strip() for cidr in rule["source_address"].split(",")]
    dst_cidrs = [cidr.strip() for cidr in rule["destination_address"].split(",")]
    
    print("\nAnalyzing Source CIDRs...")
    src_analysis = analyze_cidrs(src_cidrs)
    
    if "error" in src_analysis:
        print(f"Error analyzing source CIDRs: {src_analysis['error']}")
    elif "message" in src_analysis:
        print(f"Source CIDRs: {src_analysis['message']}")
    else:
        print(f"Found {len(src_analysis['networks'])} source networks")
        print(f"Found {len(src_analysis['overlaps'])} overlapping source networks")
        print(f"Found {len(src_analysis['mergeable'])} potentially mergeable source networks")
        
        if src_analysis['mergeable']:
            print("\nSuggested Source CIDR Merges:")
            for i, merge in enumerate(src_analysis['mergeable']):
                print(f"{i+1}. Merge {merge['cidr1']} and {merge['cidr2']} into {merge['merged_cidr']}")
                print(f"   Efficiency: {merge['efficiency']:.2f} (Original: {merge['original_size']} IPs, Merged: {merge['merged_size']} IPs)")
            
            print("\nEnter the numbers of the source CIDR merges to apply (comma-separated), or 'all' for all, or 'none' to skip:")
            merge_input = input().strip().lower()
            
            merges_to_apply = []
            if merge_input == 'all':
                merges_to_apply = src_analysis['mergeable']
            elif merge_input != 'none':
                try:
                    merge_indices = [int(idx.strip()) - 1 for idx in merge_input.split(',')]
                    merges_to_apply = [src_analysis['mergeable'][idx] for idx in merge_indices if 0 <= idx < len(src_analysis['mergeable'])]
                except (ValueError, IndexError):
                    print("Invalid input, no merges will be applied to source CIDRs")
            
            if merges_to_apply:
                src_cidrs = merge_cidrs(src_cidrs, merges_to_apply)
                print(f"\nUpdated Source CIDRs: {', '.join(src_cidrs)}")
    
    print("\nAnalyzing Destination CIDRs...")
    dst_analysis = analyze_cidrs(dst_cidrs)
    
    if "error" in dst_analysis:
        print(f"Error analyzing destination CIDRs: {dst_analysis['error']}")
    elif "message" in dst_analysis:
        print(f"Destination CIDRs: {dst_analysis['message']}")
    else:
        print(f"Found {len(dst_analysis['networks'])} destination networks")
        print(f"Found {len(dst_analysis['overlaps'])} overlapping destination networks")
        print(f"Found {len(dst_analysis['mergeable'])} potentially mergeable destination networks")
        
        if dst_analysis['mergeable']:
            print("\nSuggested Destination CIDR Merges:")
            for i, merge in enumerate(dst_analysis['mergeable']):
                print(f"{i+1}. Merge {merge['cidr1']} and {merge['cidr2']} into {merge['merged_cidr']}")
                print(f"   Efficiency: {merge['efficiency']:.2f} (Original: {merge['original_size']} IPs, Merged: {merge['merged_size']} IPs)")
            
            print("\nEnter the numbers of the destination CIDR merges to apply (comma-separated), or 'all' for all, or 'none' to skip:")
            merge_input = input().strip().lower()
            
            merges_to_apply = []
            if merge_input == 'all':
                merges_to_apply = dst_analysis['mergeable']
            elif merge_input != 'none':
                try:
                    merge_indices = [int(idx.strip()) - 1 for idx in merge_input.split(',')]
                    merges_to_apply = [dst_analysis['mergeable'][idx] for idx in merge_indices if 0 <= idx < len(dst_analysis['mergeable'])]
                except (ValueError, IndexError):
                    print("Invalid input, no merges will be applied to destination CIDRs")
            
            if merges_to_apply:
                dst_cidrs = merge_cidrs(dst_cidrs, merges_to_apply)
                print(f"\nUpdated Destination CIDRs: {', '.join(dst_cidrs)}")
    
    updated_rule = rule.copy()
    updated_rule["source_address"] = ", ".join(src_cidrs)
    updated_rule["destination_address"] = ", ".join(dst_cidrs)
    
    return updated_rule

def merge_rule_cidrs(rule: Dict[str, Any], min_efficiency: float = 0.7) -> Dict[str, Any]:
    """
    Automatically merge CIDRs in a firewall rule based on efficiency threshold.
    
    Args:
        rule: Firewall rule dictionary
        min_efficiency: Minimum efficiency threshold for merging (default: 0.7)
        
    Returns:
        Updated rule with merged CIDRs
    """
    src_cidrs = [cidr.strip() for cidr in rule["source_address"].split(",")]
    dst_cidrs = [cidr.strip() for cidr in rule["destination_address"].split(",")]
    
    src_suggestions = suggest_cidr_merges(src_cidrs, min_efficiency)
    dst_suggestions = suggest_cidr_merges(dst_cidrs, min_efficiency)
    
    if src_suggestions:
        src_cidrs = merge_cidrs(src_cidrs, src_suggestions)
    
    if dst_suggestions:
        dst_cidrs = merge_cidrs(dst_cidrs, dst_suggestions)
    
    updated_rule = rule.copy()
    updated_rule["source_address"] = ", ".join(src_cidrs)
    updated_rule["destination_address"] = ", ".join(dst_cidrs)
    
    updated_rule["merge_info"] = {
        "src_merges_applied": len(src_suggestions),
        "dst_merges_applied": len(dst_suggestions),
        "src_merges": src_suggestions,
        "dst_merges": dst_suggestions
    }
    
    return updated_rule
