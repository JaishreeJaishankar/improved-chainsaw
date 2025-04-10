# ip_utils.py
import ipaddress
from typing import List

def group_ips_into_networks(ip_list: List[str]) -> List[str]:
    """
    Convert a list of IP addresses into aggregated CIDRs 
    (if addresses are within 256 increments).
    """
    if not ip_list:
        return []
    
    ip_objs = []
    for ip in ip_list:
        try:
            ip_objs.append(ipaddress.ip_address(ip))
        except ValueError:
            print(f"Warning: invalid IP address {ip}, skipping.")
    
    ipv4_objs = [x for x in ip_objs if isinstance(x, ipaddress.IPv4Address)]
    
    if not ipv4_objs:
        return [f"{ip}/32" for ip in ip_list]
    
    ipv4_objs.sort()
    networks = []
    current = [ipv4_objs[0]]
    
    def _find_optimal_subnets(block: List[ipaddress.IPv4Address]) -> List[str]:
        if len(block) == 1:
            return [f"{block[0]}/32"]
        ip_ints = [int(x) for x in block]
        min_ip = min(ip_ints)
        for prefix_len in range(31, 15, -1):
            try:
                net = ipaddress.IPv4Network(f"{ipaddress.IPv4Address(min_ip)}/{prefix_len}", strict=False)
                if all(ipaddress.IPv4Address(val) in net for val in ip_ints):
                    return [str(net)]
            except ValueError:
                continue
        
        if len(block) > 2:
            mid = len(block) // 2
            return _find_optimal_subnets(block[:mid]) + _find_optimal_subnets(block[mid:])
        else:
            return [f"{ip}/32" for ip in block]
    
    for i in range(1, len(ipv4_objs)):
        if (int(ipv4_objs[i]) - int(ipv4_objs[i-1])) <= 256:
            current.append(ipv4_objs[i])
        else:
            networks.extend(_find_optimal_subnets(current))
            current = [ipv4_objs[i]]
    
    if current:
        networks.extend(_find_optimal_subnets(current))
    
    return networks

def ports_to_services(port_list: List[int]) -> List[str]:
    """
    Maps known ports to service names, lumps the rest into custom-ports.
    """
    port_to_service = {
        80: 'http',
        443: 'https',
        22: 'ssh',
        3389: 'rdp',
        21: 'ftp',
        25: 'smtp',
        53: 'dns',
        123: 'ntp',
        161: 'snmp',
        3306: 'mysql',
        1433: 'mssql'
    }
    services = []
    unknown = []
    for p in port_list:
        if p in port_to_service:
            services.append(port_to_service[p])
        else:
            unknown.append(str(p))
    if unknown:
        services.append("custom-ports-" + "-".join(unknown))
    return services
