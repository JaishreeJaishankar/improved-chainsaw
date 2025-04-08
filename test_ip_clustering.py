import ipaddress
import pandas as pd
from collections import defaultdict
from typing import List

def _group_ips_into_networks(ip_list) -> List[str]:
    """Group a list of IP addresses into precise network CIDR notations."""
    if isinstance(ip_list, pd.Series):
        if ip_list.empty:
            return []
        ip_list = ip_list.tolist()
    elif len(ip_list) == 0:
        return []
    
    try:
        ip_objects = [ipaddress.ip_address(ip) for ip in ip_list]
        
        ipv4_objects = [ip for ip in ip_objects if isinstance(ip, ipaddress.IPv4Address)]
        
        if not ipv4_objects:
            return [f"{ip}/32" for ip in ip_list]
        
        ipv4_objects.sort()
        
        networks = []
        current_ips = []
        
        for ip in ipv4_objects:
            if not current_ips:
                current_ips.append(ip)
                continue
            
            if int(ip) - int(current_ips[-1]) <= 256:  # Within 256 addresses
                current_ips.append(ip)
            else:
                networks.extend(_find_optimal_subnets(current_ips))
                current_ips = [ip]
        
        if current_ips:
            networks.extend(_find_optimal_subnets(current_ips))
        
        return networks
    except Exception as e:
        print(f"Error grouping IPs: {e}")
        return [f"{ip}/32" for ip in ip_list]

def _find_optimal_subnets(ip_list) -> List[str]:
    """Find the optimal subnets for a list of IP addresses."""
    if len(ip_list) == 1:
        return [f"{ip_list[0]}/32"]
    
    ip_ints = [int(ip) for ip in ip_list]
    min_ip = min(ip_ints)
    max_ip = max(ip_ints)
    
    for prefix_len in range(31, 15, -1):
        try:
            network = ipaddress.IPv4Network(f"{ipaddress.IPv4Address(min_ip)}/{prefix_len}", strict=False)
            
            if all(ipaddress.IPv4Address(ip_int) in network for ip_int in ip_ints):
                return [str(network)]
        except ValueError:
            continue
    
    if len(ip_list) > 2:
        mid = len(ip_list) // 2
        return (
            _find_optimal_subnets(ip_list[:mid]) + 
            _find_optimal_subnets(ip_list[mid:])
        )
    else:
        return [f"{ip}/32" for ip in ip_list]

def test_ip_clustering():
    """Test the IP clustering algorithm with sample IP addresses."""
    ips1 = [
        "192.168.1.1",
        "192.168.1.2",
        "192.168.1.10",
        "192.168.1.20",
        "192.168.1.30"
    ]
    networks1 = _group_ips_into_networks(ips1)
    print(f"Test case 1 - Similar IPs in same subnet:")
    print(f"Input: {ips1}")
    print(f"Output: {networks1}")
    print()
    
    ips2 = [
        "192.168.1.1",
        "192.168.2.1",
        "10.0.0.1",
        "172.16.0.1"
    ]
    networks2 = _group_ips_into_networks(ips2)
    print(f"Test case 2 - Different subnets:")
    print(f"Input: {ips2}")
    print(f"Output: {networks2}")
    print()
    
    ips3 = [
        "192.168.1.1",
        "192.168.1.100",
        "192.168.2.1",
        "192.168.2.100",
        "192.168.3.1"
    ]
    networks3 = _group_ips_into_networks(ips3)
    print(f"Test case 3 - IPs that would be /16 in old algorithm:")
    print(f"Input: {ips3}")
    print(f"Output: {networks3}")
    print()
    
    ips4 = [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
        "10.0.1.1",  # Gap
        "10.0.1.2",
        "10.0.1.3"
    ]
    networks4 = _group_ips_into_networks(ips4)
    print(f"Test case 4 - IPs with gaps:")
    print(f"Input: {ips4}")
    print(f"Output: {networks4}")
    print()
    
    ips5 = []
    networks5 = _group_ips_into_networks(ips5)
    print(f"Test case 5a - Empty list:")
    print(f"Input: {ips5}")
    print(f"Output: {networks5}")
    
    ips6 = ["192.168.1.1"]
    networks6 = _group_ips_into_networks(ips6)
    print(f"Test case 5b - Single IP:")
    print(f"Input: {ips6}")
    print(f"Output: {networks6}")

if __name__ == "__main__":
    test_ip_clustering()
