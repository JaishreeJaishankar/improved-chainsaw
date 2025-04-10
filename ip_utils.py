# ip_utils.py
import ipaddress
from typing import List

def group_ips_into_networks(ip_list) -> List[str]:
    # Convert to list if necessary
    if hasattr(ip_list, 'empty') and ip_list.empty:
        return []
    ip_list = list(ip_list)
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
    if len(ip_list) == 1:
        return [f"{ip_list[0]}/32"]
    ip_ints = [int(ip) for ip in ip_list]
    min_ip = min(ip_ints)
    for prefix_len in range(31, 15, -1):
        try:
            network = ipaddress.IPv4Network(f"{ipaddress.IPv4Address(min_ip)}/{prefix_len}", strict=False)
            if all(ipaddress.IPv4Address(ip_int) in network for ip_int in ip_ints):
                return [str(network)]
        except ValueError:
            continue
    if len(ip_list) > 2:
        mid = len(ip_list) // 2
        return _find_optimal_subnets(ip_list[:mid]) + _find_optimal_subnets(ip_list[mid:])
    else:
        return [f"{ip}/32" for ip in ip_list]

def ports_to_services(port_list: List[int]) -> List[str]:
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
    unknown_ports = []
    for port in port_list:
        if port in port_to_service:
            services.append(port_to_service[port])
        else:
            unknown_ports.append(str(port))
    if unknown_ports:
        services.append(f"custom-ports-{'-'.join(unknown_ports)}")
    return services
