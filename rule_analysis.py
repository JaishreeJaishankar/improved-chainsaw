# rule_analysis.py
from typing import Dict, Any
import pandas as pd

def analyze_rule_usage(logs_df: pd.DataFrame, rules_df: pd.DataFrame) -> Dict[str, Any]:
    rule_usage = logs_df['rule.name'].value_counts().reset_index()
    rule_usage.columns = ['rule_name', 'log_count']
    rule_analysis_df = pd.merge(rules_df, rule_usage, on='rule_name', how='left')
    rule_analysis_df['log_count'] = rule_analysis_df['log_count'].fillna(0)
    
    analysis = {}
    unused_rules = rule_analysis_df[rule_analysis_df['log_count'] == 0]
    if not unused_rules.empty:
        analysis['unused_rules'] = unused_rules[['rule_name', 'description', 'priority']].to_dict('records')
    
    permissive_rules = rule_analysis_df[
        (rule_analysis_df['risky_permissive'] == 'permissive') &
        (rule_analysis_df['log_count'] > 0)
    ]
    if not permissive_rules.empty:
        analysis['permissive_rules'] = permissive_rules[
            ['rule_name', 'description', 'source_address', 'destination_address', 'service', 'log_count']
        ].to_dict('records')
    
    # Compute rule patterns from logs for additional analysis.
    rule_patterns = {}
    for rule_name in rule_analysis_df['rule_name']:
        rule_logs = logs_df[logs_df['rule.name'] == rule_name]
        if not rule_logs.empty:
            source_ips = rule_logs['source.ip'].unique()
            dest_ips = rule_logs['destination.ip'].unique()
            dest_ports = rule_logs['destination.port'].unique()
            rule_patterns[rule_name] = {
                'unique_source_ips': len(source_ips),
                'unique_destination_ips': len(dest_ips),
                'unique_destination_ports': len(dest_ports),
                'source_ips': source_ips.tolist(),
                'destination_ips': dest_ips.tolist(),
                'destination_ports': dest_ports.tolist()
            }
    analysis['rule_patterns'] = rule_patterns
    return analysis

def generate_optimized_rules(logs_df, rules_df, ip_grouping_fn, ports_to_services_fn) -> Dict[str, Any]:
    optimized_rules = {}
    
    if rules_df is None:
        # Fall back to log-based optimization if no rule file provided.
        from traffic_analysis import analyze_log_based_patterns
        log_patterns = analyze_log_based_patterns(logs_df, ip_grouping_fn, ports_to_services_fn)
        for rule_name, pattern in log_patterns['rule_patterns'].items():
            optimized_rule = {
                'rule_name': rule_name,
                'source_address': ', '.join(pattern['source_networks']) if pattern['source_networks'] else 'any',
                'destination_address': ', '.join(pattern['destination_networks']) if pattern['destination_networks'] else 'any',
                'service': ', '.join(pattern['services']) if pattern['services'] else 'any',
                'log_count': pattern['log_count']
            }
            recommendations = [
                f"Optimize source address to {optimized_rule['source_address']}",
                f"Optimize destination address to {optimized_rule['destination_address']}",
                f"Optimize service to {optimized_rule['service']}"
            ]
            optimized_rules[rule_name] = {
                'optimized_rule': optimized_rule,
                'recommendation': '; '.join(recommendations)
            }
        return optimized_rules

    # When a rule file is provided:
    rule_analysis_results = analyze_rule_usage(logs_df, rules_df)
    for _, rule in rules_df.iterrows():
        rule_name = rule['rule_name']
        if rule_name not in rule_analysis_results.get('rule_patterns', {}):
            optimized_rules[rule_name] = {
                'original_rule': rule.to_dict(),
                'recommendation': 'Consider removing this unused rule',
                'optimized_rule': None
            }
            continue
        
        pattern = rule_analysis_results['rule_patterns'][rule_name]
        optimized_rule = rule.to_dict()
        recommendations = []
        
        if rule['source_address'] == 'any' and len(pattern['source_ips']) > 0:
            src_networks = ip_grouping_fn(pattern['source_ips'])
            if src_networks:
                optimized_rule['source_address'] = ', '.join(src_networks)
                recommendations.append(f"Restrict source address to {optimized_rule['source_address']}")
        
        if rule['destination_address'] == 'any' and len(pattern['destination_ips']) > 0:
            dst_networks = ip_grouping_fn(pattern['destination_ips'])
            if dst_networks:
                optimized_rule['destination_address'] = ', '.join(dst_networks)
                recommendations.append(f"Restrict destination address to {optimized_rule['destination_address']}")
        
        if rule['service'] == 'any' and len(pattern['destination_ports']) > 0:
            services = ports_to_services_fn(pattern['destination_ports'])
            if services:
                optimized_rule['service'] = ', '.join(services)
                recommendations.append(f"Restrict service to {optimized_rule['service']}")
        
        if rule['risky_permissive'] == 'risky':
            recommendations.append("This rule is marked as risky and should be reviewed")
        
        optimized_rules[rule_name] = {
            'original_rule': rule.to_dict(),
            'recommendation': '; '.join(recommendations) if recommendations else 'No optimization needed',
            'optimized_rule': optimized_rule if recommendations else None
        }
    return optimized_rules
