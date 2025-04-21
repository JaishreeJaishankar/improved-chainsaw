import pandas as pd
from enhanced_rule_optimization import generate_relationship_based_rules

data = [
    {"source.ip": "192.168.1.1", "destination.ip": "10.0.0.1", "destination.port": "80"},
    {"source.ip": "192.168.1.1", "destination.ip": "10.0.0.2", "destination.port": "443"},
    {"source.ip": "192.168.1.2", "destination.ip": "10.0.0.1", "destination.port": "80"},
    {"source.ip": "192.168.1.2", "destination.ip": "10.0.0.2", "destination.port": "443"},
    
    {"source.ip": "192.168.2.1", "destination.ip": "10.0.1.1", "destination.port": "22"},
    {"source.ip": "192.168.2.1", "destination.ip": "10.0.1.2", "destination.port": "3306"},
    {"source.ip": "192.168.2.2", "destination.ip": "10.0.1.1", "destination.port": "22"},
    {"source.ip": "192.168.2.2", "destination.ip": "10.0.1.2", "destination.port": "3306"},
    
    {"source.ip": "192.168.3.1", "destination.ip": "10.0.2.1", "destination.port": "8080"},
    {"source.ip": "192.168.3.2", "destination.ip": "10.0.3.1", "destination.port": "5432"}
]

df = pd.DataFrame(data)

print("Test Dataset:")
print(df)
print("\nGenerating relationship-based rules...")

rules = generate_relationship_based_rules(df, max_rules=5)

print("\nGenerated Rules:")
for i, rule in enumerate(rules):
    print(f"\nRule {i+1}:")
    print(f"  Rule Name: {rule['rule_name']}")
    print(f"  Source CIDRs: {rule['source_address']}")
    print(f"  Destination CIDRs: {rule['destination_address']}")
    print(f"  Service(s): {rule['service']}")
    print(f"  Log Count: {rule['log_count']}")

print("\nVerifying source-destination mappings:")
for rule in rules:
    src_cidrs = rule['source_address'].split(', ')
    dst_cidrs = rule['destination_address'].split(', ')
    
    print(f"\nRule: {rule['rule_name']}")
    print(f"  Source CIDRs: {src_cidrs}")
    print(f"  Destination CIDRs: {dst_cidrs}")
    
    for src_cidr in src_cidrs:
        if src_cidr == "any":
            continue
        
        src_prefix = src_cidr.split('/')[0]
        
        matching_src_ips = [row['source.ip'] for _, row in df.iterrows() 
                           if row['source.ip'].startswith(src_prefix)]
        
        accessed_dst_ips = set()
        for _, row in df.iterrows():
            if row['source.ip'] in matching_src_ips:
                accessed_dst_ips.add(row['destination.ip'])
        
        for dst_cidr in dst_cidrs:
            if dst_cidr == "any":
                continue
            
            dst_prefix = dst_cidr.split('/')[0]
            
            rule_dst_ips = [dst_ip for dst_ip in accessed_dst_ips 
                           if dst_ip.startswith(dst_prefix)]
            
            if not rule_dst_ips:
                print(f"  WARNING: Source CIDR {src_cidr} does not access any IPs in destination CIDR {dst_cidr}")
