# traffic_analysis.py
from typing import Dict, Any
import pandas as pd

def analyze_traffic_patterns(logs_df: pd.DataFrame) -> Dict[str, Any]:
    patterns = {}
    logs_df['hour'] = logs_df['timestamp'].dt.hour
    patterns['hourly_traffic'] = logs_df.groupby('hour').size().to_dict()
    
    logs_df['day_of_week'] = logs_df['timestamp'].dt.day_name()
    patterns['daily_traffic'] = logs_df.groupby('day_of_week').size().to_dict()
    
    patterns['zone_traffic'] = logs_df.groupby('observer.ingress.zone').size().to_dict()
    patterns['top_source_ips'] = logs_df['source.ip'].value_counts().head(10).to_dict()
    patterns['top_destination_ips'] = logs_df['destination.ip'].value_counts().head(10).to_dict()
    patterns['top_destination_ports'] = logs_df['destination.port'].value_counts().head(10).to_dict()
    
    logs_df['source_dest_pair'] = logs_df['source.ip'] + ' -> ' + logs_df['destination.ip']
    patterns['top_source_dest_pairs'] = logs_df['source_dest_pair'].value_counts().head(10).to_dict()
    return patterns

def identify_anomalies(logs_df: pd.DataFrame) -> Dict[str, Any]:
    anomalies = {}
    common_ports = {80, 443, 22, 3389, 21, 25, 53, 123, 161, 3306, 1433}
    unusual_ports = logs_df[~logs_df['destination.port'].isin(common_ports)]
    if not unusual_ports.empty:
        anomalies['unusual_ports'] = unusual_ports['destination.port'].value_counts().head(10).to_dict()
    
    pair_counts = logs_df.groupby(['source.ip', 'destination.ip']).size().reset_index(name='count')
    low_occurrence_pairs = pair_counts[pair_counts['count'] < 5]
    if not low_occurrence_pairs.empty:
        anomalies['low_occurrence_pairs'] = low_occurrence_pairs.head(10).to_dict('records')
    
    business_hours = (8, 18)
    after_hours_traffic = logs_df[(logs_df['hour'] < business_hours[0]) | 
                                  (logs_df['hour'] >= business_hours[1])]
    if not after_hours_traffic.empty:
        anomalies['after_hours_traffic'] = {
            'count': len(after_hours_traffic),
            'percentage': len(after_hours_traffic) / len(logs_df) * 100,
            'sample': after_hours_traffic.head(5).to_dict('records')
        }
    return anomalies

def analyze_log_based_patterns(logs_df: pd.DataFrame, ip_grouping_fn, ports_to_services_fn) -> Dict[str, Any]:
    patterns = {}
    rule_names = logs_df['rule.name'].unique()
    rule_patterns = {}
    for rule_name in rule_names:
        rule_logs = logs_df[logs_df['rule.name'] == rule_name]
        source_ips = rule_logs['source.ip'].unique()
        dest_ips = rule_logs['destination.ip'].unique()
        dest_ports = rule_logs['destination.port'].unique()
        source_networks = ip_grouping_fn(source_ips)
        dest_networks = ip_grouping_fn(dest_ips)
        service_names = ports_to_services_fn(dest_ports)
        
        rule_patterns[rule_name] = {
            'source_networks': source_networks,
            'destination_networks': dest_networks,
            'services': service_names,
            'log_count': len(rule_logs),
            'source_ips': source_ips.tolist(),
            'destination_ips': dest_ips.tolist(),
            'destination_ports': dest_ports.tolist()
        }
    patterns['rule_patterns'] = rule_patterns
    return patterns
