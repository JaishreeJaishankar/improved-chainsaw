import csv
import random
import ipaddress
import datetime
import os
from typing import List, Dict, Any

SOURCE_IPS = [f"192.168.{random.randint(1, 5)}.{random.randint(1, 254)}" for _ in range(20)]
INTERNAL_DEST_IPS = [f"10.0.0.{random.randint(1, 254)}" for _ in range(10)]
EXTERNAL_DEST_IPS = [
    "172.217.160.78",  # Google
    "142.250.190.46",  # Google
    "13.107.42.14",    # Microsoft
    "104.244.42.65",   # Twitter
    "31.13.72.36",     # Facebook
    "151.101.1.69",    # Reddit
    "199.232.69.194",  # GitHub
    "52.94.236.248",   # Amazon
    "23.185.0.2",      # LinkedIn
    "151.101.193.69",  # Cloudflare
]
COLLECTORS = ["fw-collector-01", "fw-collector-02", "fw-collector-03"]
COMMON_PORTS = {
    "http": 80,
    "https": 443,
    "ssh": 22,
    "rdp": 3389,
    "ftp": 21,
    "smtp": 25,
    "dns": 53,
    "telnet": 23,
    "mysql": 3306,
    "mssql": 1433,
    "ntp": 123,
    "snmp": 161
}
ZONES = ["internal", "external", "dmz", "database", "application"]

RULES = [
    {
        "rule_name": "allow-web-https",
        "hits": 0,
        "priority": 1,
        "description": "Allow HTTPS traffic to external websites",
        "recommended_action": "None",
        "source_zone": "internal",
        "source_address": "192.168.0.0/16",
        "destination_zone": "external",
        "destination_address": "any",
        "application": "web-browsing",
        "service": "https",
        "url_category": "any",
        "action": "allow",
        "profile_group": "default",
        "options": "log-start, log-end",
        "modified_date": "2025-03-15",
        "created_date": "2024-10-01",
        "risky_permissive": "permissive",
        "ingress_egress": "egress"
    },
    {
        "rule_name": "allow-web-http",
        "hits": 0,
        "priority": 2,
        "description": "Allow HTTP traffic to external websites",
        "recommended_action": "Consider restricting to HTTPS only",
        "source_zone": "internal",
        "source_address": "192.168.0.0/16",
        "destination_zone": "external",
        "destination_address": "any",
        "application": "web-browsing",
        "service": "http",
        "url_category": "any",
        "action": "allow",
        "profile_group": "default",
        "options": "log-start, log-end",
        "modified_date": "2025-03-15",
        "created_date": "2024-10-01",
        "risky_permissive": "permissive",
        "ingress_egress": "egress"
    },
    {
        "rule_name": "allow-ssh",
        "hits": 0,
        "priority": 3,
        "description": "Allow SSH access to internal servers",
        "recommended_action": "Restrict to specific source IPs",
        "source_zone": "internal",
        "source_address": "192.168.0.0/16",
        "destination_zone": "dmz",
        "destination_address": "10.0.0.0/24",
        "application": "ssh",
        "service": "ssh",
        "url_category": "any",
        "action": "allow",
        "profile_group": "default",
        "options": "log-start, log-end",
        "modified_date": "2025-02-20",
        "created_date": "2024-10-01",
        "risky_permissive": "risky",
        "ingress_egress": "ingress"
    },
    {
        "rule_name": "allow-rdp",
        "hits": 0,
        "priority": 4,
        "description": "Allow RDP access to internal servers",
        "recommended_action": "Restrict to specific source IPs",
        "source_zone": "internal",
        "source_address": "192.168.0.0/16",
        "destination_zone": "dmz",
        "destination_address": "10.0.0.0/24",
        "application": "rdp",
        "service": "rdp",
        "url_category": "any",
        "action": "allow",
        "profile_group": "default",
        "options": "log-start, log-end",
        "modified_date": "2025-02-20",
        "created_date": "2024-10-01",
        "risky_permissive": "risky",
        "ingress_egress": "ingress"
    },
    {
        "rule_name": "allow-dns",
        "hits": 0,
        "priority": 5,
        "description": "Allow DNS queries",
        "recommended_action": "Restrict to specific DNS servers",
        "source_zone": "internal",
        "source_address": "192.168.0.0/16",
        "destination_zone": "external",
        "destination_address": "8.8.8.8, 8.8.4.4",
        "application": "dns",
        "service": "dns",
        "url_category": "any",
        "action": "allow",
        "profile_group": "default",
        "options": "log-start, log-end",
        "modified_date": "2025-01-10",
        "created_date": "2024-10-01",
        "risky_permissive": "permissive",
        "ingress_egress": "egress"
    },
    {
        "rule_name": "allow-database-access",
        "hits": 0,
        "priority": 6,
        "description": "Allow application servers to access database servers",
        "recommended_action": "Restrict to specific application servers",
        "source_zone": "application",
        "source_address": "192.168.2.0/24",
        "destination_zone": "database",
        "destination_address": "10.0.1.0/24",
        "application": "mysql, mssql",
        "service": "mysql, mssql",
        "url_category": "any",
        "action": "allow",
        "profile_group": "default",
        "options": "log-start, log-end",
        "modified_date": "2025-03-01",
        "created_date": "2024-11-15",
        "risky_permissive": "permissive",
        "ingress_egress": "ingress"
    },
    {
        "rule_name": "allow-any-any",
        "hits": 0,
        "priority": 100,
        "description": "Allow any traffic (catch-all rule)",
        "recommended_action": "Remove or restrict this rule",
        "source_zone": "any",
        "source_address": "any",
        "destination_zone": "any",
        "destination_address": "any",
        "application": "any",
        "service": "any",
        "url_category": "any",
        "action": "allow",
        "profile_group": "default",
        "options": "log-start, log-end",
        "modified_date": "2025-01-01",
        "created_date": "2024-10-01",
        "risky_permissive": "risky",
        "ingress_egress": "both"
    }
]

def generate_timestamp(start_date: datetime.datetime, end_date: datetime.datetime) -> str:
    """Generate a random timestamp between start_date and end_date."""
    time_diff = end_date - start_date
    random_seconds = random.randint(0, int(time_diff.total_seconds()))
    random_date = start_date + datetime.timedelta(seconds=random_seconds)
    return random_date.strftime("%Y-%m-%dT%H:%M:%SZ")

def generate_log_entry(rules: List[Dict[str, Any]], timestamp: str = None) -> Dict[str, Any]:
    """Generate a single log entry."""
    rule = random.choice(rules)
    rule_name = rule["rule_name"]
    
    if not timestamp:
        end_date = datetime.datetime.now()
        start_date = end_date - datetime.timedelta(days=7)
        timestamp = generate_timestamp(start_date, end_date)
    
    if rule["source_zone"] == "internal" and rule["destination_zone"] == "external":
        source_ip = random.choice(SOURCE_IPS)
        destination_ip = random.choice(EXTERNAL_DEST_IPS)
        ingress_zone = "internal"
        egress_zone = "external"
    elif rule["source_zone"] == "internal" and rule["destination_zone"] == "dmz":
        source_ip = random.choice(SOURCE_IPS)
        destination_ip = random.choice(INTERNAL_DEST_IPS)
        ingress_zone = "internal"
        egress_zone = "dmz"
    elif rule["source_zone"] == "application" and rule["destination_zone"] == "database":
        source_ip = f"192.168.2.{random.randint(1, 254)}"
        destination_ip = f"10.0.1.{random.randint(1, 254)}"
        ingress_zone = "application"
        egress_zone = "database"
    else:
        source_ip = random.choice(SOURCE_IPS)
        destination_ip = random.choice(INTERNAL_DEST_IPS + EXTERNAL_DEST_IPS)
        ingress_zone = random.choice(ZONES)
        egress_zone = random.choice([z for z in ZONES if z != ingress_zone])
    
    if rule["service"] == "any":
        port = random.choice(list(COMMON_PORTS.values()))
    elif rule["service"] == "http":
        port = COMMON_PORTS["http"]
    elif rule["service"] == "https":
        port = COMMON_PORTS["https"]
    elif rule["service"] == "ssh":
        port = COMMON_PORTS["ssh"]
    elif rule["service"] == "rdp":
        port = COMMON_PORTS["rdp"]
    elif rule["service"] == "dns":
        port = COMMON_PORTS["dns"]
    elif "mysql" in rule["service"]:
        port = COMMON_PORTS["mysql"]
    elif "mssql" in rule["service"]:
        port = COMMON_PORTS["mssql"]
    else:
        port = random.choice(list(COMMON_PORTS.values()))
    
    log_entry = {
        "timestamp": timestamp,
        "source.ip": source_ip,
        "host.collector": random.choice(COLLECTORS),
        "destination.port": port,
        "destination.ip": destination_ip,
        "observer.egress.zone": egress_zone,
        "observer.ingress.zone": ingress_zone,
        "rule.name": rule_name
    }
    
    return log_entry

def generate_log_file(num_entries: int = 10000, output_file: str = "firewall_logs.csv") -> None:
    """Generate a log file with the specified number of entries."""
    end_date = datetime.datetime.now()
    start_date = end_date - datetime.timedelta(days=7)
    
    timestamps = []
    for _ in range(num_entries):
        timestamps.append(generate_timestamp(start_date, end_date))
    
    timestamps.sort()
    
    log_entries = []
    for timestamp in timestamps:
        log_entry = generate_log_entry(RULES, timestamp)
        log_entries.append(log_entry)
        
        for rule in RULES:
            if rule["rule_name"] == log_entry["rule.name"]:
                rule["hits"] += 1
    
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ["timestamp", "source.ip", "host.collector", "destination.port", 
                     "destination.ip", "observer.egress.zone", "observer.ingress.zone", "rule.name"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for entry in log_entries:
            writer.writerow(entry)
    
    print(f"Generated {num_entries} log entries in {output_file}")
    
    rule_file = "firewall_rules.csv"
    with open(rule_file, 'w', newline='') as csvfile:
        fieldnames = list(RULES[0].keys())
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for rule in RULES:
            writer.writerow(rule)
    
    print(f"Generated rule information in {rule_file}")

if __name__ == "__main__":
    generate_log_file()
