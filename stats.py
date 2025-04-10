# stats.py
from typing import Dict, Any
import pandas as pd

def get_basic_stats(logs_df: pd.DataFrame, rules_df: pd.DataFrame = None) -> Dict[str, Any]:
    stats = {}
    stats['total_log_entries'] = len(logs_df)
    stats['date_range'] = {
        'start': logs_df['timestamp'].min().strftime('%Y-%m-%d %H:%M:%S'),
        'end': logs_df['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S')
    }
    stats['unique_source_ips'] = logs_df['source.ip'].nunique()
    stats['unique_destination_ips'] = logs_df['destination.ip'].nunique()
    stats['unique_destination_ports'] = logs_df['destination.port'].nunique()
    
    if rules_df is not None:
        stats['total_rules'] = len(rules_df)
        stats['rules_by_action'] = rules_df['action'].value_counts().to_dict()
        stats['risky_rules'] = len(rules_df[rules_df['risky_permissive'] == 'risky'])
        stats['permissive_rules'] = len(rules_df[rules_df['risky_permissive'] == 'permissive'])
        rule_usage = logs_df['rule.name'].value_counts().to_dict()
        stats['rule_usage'] = rule_usage
        all_rule_names = set(rules_df['rule_name'])
        used_rule_names = set(rule_usage.keys())
        stats['unused_rules'] = list(all_rule_names - used_rule_names)
    else:
        rule_usage = logs_df['rule.name'].value_counts().to_dict()
        stats['rule_usage'] = rule_usage
        stats['total_rules'] = len(rule_usage)
        stats['unused_rules'] = []
    
    return stats
