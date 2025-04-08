import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import ipaddress
import datetime
import os
import json
from collections import Counter, defaultdict
from typing import List, Dict, Any, Tuple, Set
import argparse
from pathlib import Path
import matplotlib.dates as mdates
import networkx as nx
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

class FirewallAnalyzer:
    """
    A class to analyze firewall logs and provide recommendations for rule optimization.
    """
    
    def __init__(self, log_file: str, rule_file: str = None):
        """Initialize the FirewallAnalyzer with log file and optional rule file."""
        self.log_file = log_file
        self.rule_file = rule_file
        self.logs_df = None
        self.rules_df = None
        self.load_data()
        
    def load_data(self) -> None:
        """Load log data from CSV file and optional rule data for validation."""
        print(f"Loading log data from {self.log_file}...")
        self.logs_df = pd.read_csv(self.log_file)
        
        self.logs_df['timestamp'] = pd.to_datetime(self.logs_df['timestamp'])
        
        if self.rule_file:
            print(f"Loading rule data from {self.rule_file} (for validation only)...")
            self.rules_df = pd.read_csv(self.rule_file)
            print(f"Loaded {len(self.logs_df)} log entries and {len(self.rules_df)} rules.")
        else:
            print(f"Loaded {len(self.logs_df)} log entries. No rule file provided.")
    
    def get_basic_stats(self) -> Dict[str, Any]:
        """Get basic statistics about the logs and rules."""
        stats = {}
        
        stats['total_log_entries'] = len(self.logs_df)
        stats['date_range'] = {
            'start': self.logs_df['timestamp'].min().strftime('%Y-%m-%d %H:%M:%S'),
            'end': self.logs_df['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S')
        }
        stats['unique_source_ips'] = self.logs_df['source.ip'].nunique()
        stats['unique_destination_ips'] = self.logs_df['destination.ip'].nunique()
        stats['unique_destination_ports'] = self.logs_df['destination.port'].nunique()
        
        if self.rules_df is not None:
            stats['total_rules'] = len(self.rules_df)
            stats['rules_by_action'] = self.rules_df['action'].value_counts().to_dict()
            stats['risky_rules'] = len(self.rules_df[self.rules_df['risky_permissive'] == 'risky'])
            stats['permissive_rules'] = len(self.rules_df[self.rules_df['risky_permissive'] == 'permissive'])
            
            rule_usage = self.logs_df['rule.name'].value_counts().to_dict()
            stats['rule_usage'] = rule_usage
            
            all_rule_names = set(self.rules_df['rule_name'])
            used_rule_names = set(rule_usage.keys())
            unused_rule_names = all_rule_names - used_rule_names
            stats['unused_rules'] = list(unused_rule_names)
        else:
            rule_usage = self.logs_df['rule.name'].value_counts().to_dict()
            stats['rule_usage'] = rule_usage
            stats['total_rules'] = len(rule_usage)
            stats['unused_rules'] = []
        
        return stats
        
    def analyze_traffic_patterns(self) -> Dict[str, Any]:
        """Analyze traffic patterns in the logs."""
        patterns = {}
        
        self.logs_df['hour'] = self.logs_df['timestamp'].dt.hour
        hourly_traffic = self.logs_df.groupby('hour').size()
        patterns['hourly_traffic'] = hourly_traffic.to_dict()
        
        self.logs_df['day_of_week'] = self.logs_df['timestamp'].dt.day_name()
        daily_traffic = self.logs_df.groupby('day_of_week').size()
        patterns['daily_traffic'] = daily_traffic.to_dict()
        
        zone_traffic = self.logs_df.groupby('observer.ingress.zone').size()
        patterns['zone_traffic'] = zone_traffic.to_dict()
        
        top_sources = self.logs_df['source.ip'].value_counts().head(10).to_dict()
        patterns['top_source_ips'] = top_sources
        
        top_destinations = self.logs_df['destination.ip'].value_counts().head(10).to_dict()
        patterns['top_destination_ips'] = top_destinations
        
        top_ports = self.logs_df['destination.port'].value_counts().head(10).to_dict()
        patterns['top_destination_ports'] = top_ports
        
        self.logs_df['source_dest_pair'] = self.logs_df['source.ip'] + ' -> ' + self.logs_df['destination.ip']
        top_pairs = self.logs_df['source_dest_pair'].value_counts().head(10).to_dict()
        patterns['top_source_dest_pairs'] = top_pairs
        
        return patterns
        
    def identify_anomalies(self) -> Dict[str, Any]:
        """Identify potential anomalies in the traffic patterns."""
        anomalies = {}
        
        common_ports = {80, 443, 22, 3389, 21, 25, 53, 123, 161, 3306, 1433}
        unusual_ports = self.logs_df[~self.logs_df['destination.port'].isin(common_ports)]
        if len(unusual_ports) > 0:
            anomalies['unusual_ports'] = unusual_ports['destination.port'].value_counts().head(10).to_dict()
        
        pair_counts = self.logs_df.groupby(['source.ip', 'destination.ip']).size().reset_index(name='count')
        
        low_occurrence_pairs = pair_counts[pair_counts['count'] < 5]
        if len(low_occurrence_pairs) > 0:
            anomalies['low_occurrence_pairs'] = low_occurrence_pairs.head(10).to_dict('records')
        
        business_hours = (8, 18)
        after_hours_traffic = self.logs_df[(self.logs_df['hour'] < business_hours[0]) | 
                                          (self.logs_df['hour'] >= business_hours[1])]
        if len(after_hours_traffic) > 0:
            anomalies['after_hours_traffic'] = {
                'count': len(after_hours_traffic),
                'percentage': len(after_hours_traffic) / len(self.logs_df) * 100,
                'sample': after_hours_traffic.head(5).to_dict('records')
            }
        
        return anomalies
        
    def analyze_log_based_patterns(self) -> Dict[str, Any]:
        """Analyze log patterns focusing on source.ip, destination.port, and destination.ip."""
        patterns = {}
        
        rule_names = self.logs_df['rule.name'].unique()
        
        rule_patterns = {}
        for rule_name in rule_names:
            rule_logs = self.logs_df[self.logs_df['rule.name'] == rule_name]
            
            source_ips = rule_logs['source.ip'].unique()
            dest_ips = rule_logs['destination.ip'].unique()
            dest_ports = rule_logs['destination.port'].unique()
            
            source_networks = self._group_ips_into_networks(source_ips)
            dest_networks = self._group_ips_into_networks(dest_ips)
            service_names = self._ports_to_services(dest_ports)
            
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
        
    def analyze_rule_usage(self) -> Dict[str, Any]:
        """Analyze rule usage and identify optimization opportunities."""
        if self.rules_df is None:
            return self.analyze_log_based_patterns()
            
        rule_analysis = {}
        
        rule_usage = self.logs_df['rule.name'].value_counts().reset_index()
        rule_usage.columns = ['rule_name', 'log_count']
        
        rule_analysis_df = pd.merge(self.rules_df, rule_usage, on='rule_name', how='left')
        rule_analysis_df['log_count'] = rule_analysis_df['log_count'].fillna(0)
        
        unused_rules = rule_analysis_df[rule_analysis_df['log_count'] == 0]
        if len(unused_rules) > 0:
            rule_analysis['unused_rules'] = unused_rules[['rule_name', 'description', 'priority']].to_dict('records')
        
        permissive_rules = rule_analysis_df[
            (rule_analysis_df['risky_permissive'] == 'permissive') & 
            (rule_analysis_df['log_count'] > 0)
        ]
        if len(permissive_rules) > 0:
            rule_analysis['permissive_rules'] = permissive_rules[
                ['rule_name', 'description', 'source_address', 'destination_address', 'service', 'log_count']
            ].to_dict('records')
        
        any_rules = rule_analysis_df[
            (rule_analysis_df['source_address'] == 'any') | 
            (rule_analysis_df['destination_address'] == 'any') |
            (rule_analysis_df['service'] == 'any') |
            (rule_analysis_df['application'] == 'any')
        ]
        if len(any_rules) > 0:
            rule_analysis['any_rules'] = any_rules[
                ['rule_name', 'description', 'source_address', 'destination_address', 
                 'service', 'application', 'log_count']
            ].to_dict('records')
        
        rule_patterns = {}
        for rule_name in rule_analysis_df['rule_name']:
            rule_logs = self.logs_df[self.logs_df['rule.name'] == rule_name]
            if len(rule_logs) > 0:
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
        
        rule_analysis['rule_patterns'] = rule_patterns
        
        return rule_analysis
        
    def _group_ips_into_networks(self, ip_list) -> List[str]:
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
                    networks.extend(self._find_optimal_subnets(current_ips))
                    current_ips = [ip]
            
            if current_ips:
                networks.extend(self._find_optimal_subnets(current_ips))
            
            return networks
        except Exception as e:
            print(f"Error grouping IPs: {e}")
            return [f"{ip}/32" for ip in ip_list]
    
    def _find_optimal_subnets(self, ip_list) -> List[str]:
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
                self._find_optimal_subnets(ip_list[:mid]) + 
                self._find_optimal_subnets(ip_list[mid:])
            )
        else:
            return [f"{ip}/32" for ip in ip_list]
    
    def _ports_to_services(self, port_list: List[int]) -> List[str]:
        """Convert a list of ports to service names."""
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
        
    def generate_log_based_optimized_rules(self) -> Dict[str, Any]:
        """Generate optimized rule recommendations based solely on log analysis."""
        optimized_rules = {}
        
        log_patterns = self.analyze_log_based_patterns()
        
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
        
    def generate_optimized_rules(self) -> Dict[str, Any]:
        """Generate optimized rule recommendations based on analysis."""
        if self.rules_df is None:
            return self.generate_log_based_optimized_rules()
            
        optimized_rules = {}
        
        rule_analysis = self.analyze_rule_usage()
        
        for _, rule in self.rules_df.iterrows():
            rule_name = rule['rule_name']
            
            if rule_name not in rule_analysis.get('rule_patterns', {}):
                optimized_rules[rule_name] = {
                    'original_rule': rule.to_dict(),
                    'recommendation': 'Consider removing this unused rule',
                    'optimized_rule': None
                }
                continue
            
            pattern = rule_analysis['rule_patterns'][rule_name]
            
            optimized_rule = rule.to_dict()
            recommendations = []
            
            if rule['source_address'] == 'any' and len(pattern['source_ips']) > 0:
                source_networks = self._group_ips_into_networks(pattern['source_ips'])
                if source_networks:
                    optimized_rule['source_address'] = ', '.join(source_networks)
                    recommendations.append(f"Restrict source address to {optimized_rule['source_address']}")
            
            if rule['destination_address'] == 'any' and len(pattern['destination_ips']) > 0:
                dest_networks = self._group_ips_into_networks(pattern['destination_ips'])
                if dest_networks:
                    optimized_rule['destination_address'] = ', '.join(dest_networks)
                    recommendations.append(f"Restrict destination address to {optimized_rule['destination_address']}")
            
            if rule['service'] == 'any' and len(pattern['destination_ports']) > 0:
                services = self._ports_to_services(pattern['destination_ports'])
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
        
    def visualize_traffic(self, output_dir: str = 'visualizations') -> Dict[str, str]:
        """Generate visualizations of traffic patterns."""
        os.makedirs(output_dir, exist_ok=True)
        
        visualization_files = {}
        
        plt.figure(figsize=(12, 6))
        traffic_by_day = self.logs_df.groupby(self.logs_df['timestamp'].dt.date).size()
        traffic_by_day.plot(kind='line', marker='o')
        plt.title('Firewall Traffic Over Time')
        plt.xlabel('Date')
        plt.ylabel('Number of Log Entries')
        plt.grid(True)
        plt.tight_layout()
        time_plot_file = os.path.join(output_dir, 'traffic_over_time.png')
        plt.savefig(time_plot_file)
        visualization_files['traffic_over_time'] = time_plot_file
        plt.close()
        
        plt.figure(figsize=(12, 6))
        if 'hour' not in self.logs_df.columns:
            self.logs_df['hour'] = self.logs_df['timestamp'].dt.hour
        hourly_traffic = self.logs_df.groupby('hour').size()
        hourly_traffic.plot(kind='bar')
        plt.title('Firewall Traffic by Hour of Day')
        plt.xlabel('Hour of Day')
        plt.ylabel('Number of Log Entries')
        plt.xticks(range(24))
        plt.grid(True, axis='y')
        plt.tight_layout()
        hourly_plot_file = os.path.join(output_dir, 'traffic_by_hour.png')
        plt.savefig(hourly_plot_file)
        visualization_files['traffic_by_hour'] = hourly_plot_file
        plt.close()
        
        plt.figure(figsize=(14, 8))
        rule_traffic = self.logs_df['rule.name'].value_counts()
        rule_traffic.plot(kind='bar')
        plt.title('Firewall Traffic by Rule')
        plt.xlabel('Rule Name')
        plt.ylabel('Number of Log Entries')
        plt.xticks(rotation=45, ha='right')
        plt.grid(True, axis='y')
        plt.tight_layout()
        rule_plot_file = os.path.join(output_dir, 'traffic_by_rule.png')
        plt.savefig(rule_plot_file)
        visualization_files['traffic_by_rule'] = rule_plot_file
        plt.close()
        
        plt.figure(figsize=(10, 6))
        if 'day_of_week' not in self.logs_df.columns:
            self.logs_df['day_of_week'] = self.logs_df['timestamp'].dt.day_name()
        
        zone_traffic = self.logs_df['observer.ingress.zone'].value_counts()
        zone_traffic.plot(kind='pie', autopct='%1.1f%%')
        plt.title('Firewall Traffic by Source Zone')
        plt.ylabel('')
        plt.tight_layout()
        zone_plot_file = os.path.join(output_dir, 'traffic_by_zone.png')
        plt.savefig(zone_plot_file)
        visualization_files['traffic_by_zone'] = zone_plot_file
        plt.close()
        
        plt.figure(figsize=(12, 12))
        G = nx.DiGraph()
        
        source_dest_counts = self.logs_df.groupby(['source.ip', 'destination.ip']).size().reset_index(name='count')
        source_dest_counts = source_dest_counts.sort_values('count', ascending=False).head(30)
        
        for _, row in source_dest_counts.iterrows():
            source = row['source.ip']
            dest = row['destination.ip']
            count = row['count']
            
            G.add_node(source, type='source')
            G.add_node(dest, type='destination')
            G.add_edge(source, dest, weight=count)
        
        node_colors = []
        for node in G.nodes():
            if G.nodes[node].get('type') == 'source':
                node_colors.append('skyblue')
            else:
                node_colors.append('lightgreen')
        
        edge_widths = [G[u][v]['weight'] / 10 for u, v in G.edges()]
        
        pos = nx.spring_layout(G, seed=42)
        nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=300, alpha=0.8)
        nx.draw_networkx_edges(G, pos, width=edge_widths, alpha=0.5, edge_color='gray', arrows=True, arrowsize=15)
        nx.draw_networkx_labels(G, pos, font_size=8)
        
        plt.title('Network Traffic Graph (Top Source-Destination Pairs)')
        plt.axis('off')
        plt.tight_layout()
        network_plot_file = os.path.join(output_dir, 'network_graph.png')
        plt.savefig(network_plot_file)
        visualization_files['network_graph'] = network_plot_file
        plt.close()
        
        return visualization_files
        
    def generate_report(self, output_file: str = 'firewall_analysis_report.json') -> None:
        """Generate a comprehensive report of the analysis."""
        report = {}
        
        report['basic_stats'] = self.get_basic_stats()
        
        report['traffic_patterns'] = self.analyze_traffic_patterns()
        
        report['anomalies'] = self.identify_anomalies()
        
        if self.rules_df is None:
            report['log_analysis'] = self.analyze_log_based_patterns()
        else:
            report['rule_analysis'] = self.analyze_rule_usage()
        
        report['optimized_rules'] = self.generate_optimized_rules()
        
        class CustomJSONEncoder(json.JSONEncoder):
            def default(self, obj):
                if isinstance(obj, pd.Timestamp):
                    return obj.strftime('%Y-%m-%d %H:%M:%S')
                elif isinstance(obj, np.integer):
                    return int(obj)
                elif isinstance(obj, np.floating):
                    return float(obj)
                elif isinstance(obj, np.ndarray):
                    return obj.tolist()
                return super().default(obj)
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=4, cls=CustomJSONEncoder)
        
        print(f"Report generated and saved to {output_file}")
        
        return report
        
    def generate_html_report(self, output_file: str = 'firewall_analysis_report.html') -> None:
        """Generate an HTML report with visualizations."""
        visualization_files = self.visualize_traffic()
        
        report = self.generate_report()
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Firewall Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2, h3 {{ color: #333; }}
                .section {{ margin-bottom: 30px; }}
                .visualization {{ margin: 20px 0; text-align: center; }}
                .visualization img {{ max-width: 100%; border: 1px solid #ddd; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
                .recommendation {{ background-color: #fffacd; padding: 10px; border-left: 4px solid #ffd700; }}
                .warning {{ background-color: #ffebee; padding: 10px; border-left: 4px solid #f44336; }}
            </style>
        </head>
        <body>
            <h1>Firewall Analysis Report</h1>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <p>This report analyzes firewall logs and rules to identify optimization opportunities and security improvements.</p>
                <ul>
                    <li>Total log entries analyzed: {report['basic_stats']['total_log_entries']}</li>
                    <li>Date range: {report['basic_stats']['date_range']['start']} to {report['basic_stats']['date_range']['end']}</li>
                    <li>Total rules: {report['basic_stats']['total_rules']}</li>
                    {f"<li>Risky rules: {report['basic_stats']['risky_rules']}</li>" if 'risky_rules' in report['basic_stats'] else ""}
                    {f"<li>Permissive rules: {report['basic_stats']['permissive_rules']}</li>" if 'permissive_rules' in report['basic_stats'] else ""}
                </ul>
            </div>
            
            <div class="section">
                <h2>Traffic Visualizations</h2>
                
                <div class="visualization">
                    <h3>Traffic Over Time</h3>
                    <img src="{visualization_files['traffic_over_time']}" alt="Traffic Over Time">
                </div>
                
                <div class="visualization">
                    <h3>Traffic by Hour of Day</h3>
                    <img src="{visualization_files['traffic_by_hour']}" alt="Traffic by Hour">
                </div>
                
                <div class="visualization">
                    <h3>Traffic by Rule</h3>
                    <img src="{visualization_files['traffic_by_rule']}" alt="Traffic by Rule">
                </div>
                
                <div class="visualization">
                    <h3>Traffic by Source Zone</h3>
                    <img src="{visualization_files['traffic_by_zone']}" alt="Traffic by Zone">
                </div>
                
                <div class="visualization">
                    <h3>Network Traffic Graph</h3>
                    <img src="{visualization_files['network_graph']}" alt="Network Graph">
                </div>
            </div>
            
            <div class="section">
                <h2>Top Traffic Patterns</h2>
                
                <h3>Top Source IPs</h3>
                <table>
                    <tr>
                        <th>Source IP</th>
                        <th>Count</th>
                    </tr>
        """
        
        for ip, count in report['traffic_patterns']['top_source_ips'].items():
            html_content += f"""
                    <tr>
                        <td>{ip}</td>
                        <td>{count}</td>
                    </tr>
            """
        
        html_content += """
                </table>
                
                <h3>Top Destination IPs</h3>
                <table>
                    <tr>
                        <th>Destination IP</th>
                        <th>Count</th>
                    </tr>
        """
        
        for ip, count in report['traffic_patterns']['top_destination_ips'].items():
            html_content += f"""
                    <tr>
                        <td>{ip}</td>
                        <td>{count}</td>
                    </tr>
            """
        
        html_content += """
                </table>
                
                <h3>Top Destination Ports</h3>
                <table>
                    <tr>
                        <th>Port</th>
                        <th>Count</th>
                    </tr>
        """
        
        for port, count in report['traffic_patterns']['top_destination_ports'].items():
            html_content += f"""
                    <tr>
                        <td>{port}</td>
                        <td>{count}</td>
                    </tr>
            """
        
        html_content += """
                </table>
            </div>
            
            <div class="section">
                <h2>Anomalies and Unusual Patterns</h2>
        """
        
        if 'unusual_ports' in report['anomalies']:
            html_content += """
                <h3>Unusual Ports</h3>
                <table>
                    <tr>
                        <th>Port</th>
                        <th>Count</th>
                    </tr>
            """
            
            for port, count in report['anomalies']['unusual_ports'].items():
                html_content += f"""
                        <tr>
                            <td>{port}</td>
                            <td>{count}</td>
                        </tr>
                """
            
            html_content += """
                </table>
            """
        
        if 'after_hours_traffic' in report['anomalies']:
            html_content += f"""
                <h3>After Hours Traffic</h3>
                <div class="warning">
                    <p>Detected {report['anomalies']['after_hours_traffic']['count']} log entries ({report['anomalies']['after_hours_traffic']['percentage']:.2f}%) outside normal business hours (8 AM - 6 PM).</p>
                </div>
            """
        
        html_content += """
            </div>
            
            <div class="section">
                <h2>Rule Optimization Recommendations</h2>
                <table>
                    <tr>
                        <th>Rule Name</th>
                        <th>Current Configuration</th>
                        <th>Recommendation</th>
                        <th>Optimized Configuration</th>
                    </tr>
        """
        
        for rule_name, rule_info in report['optimized_rules'].items():
            recommendation = rule_info['recommendation']
            optimized_rule = rule_info['optimized_rule']
            
            if 'original_rule' in rule_info:
                original_rule = rule_info['original_rule']
                current_config = f"""
                    <strong>Source:</strong> {original_rule['source_address']}<br>
                    <strong>Destination:</strong> {original_rule['destination_address']}<br>
                    <strong>Service:</strong> {original_rule['service']}<br>
                    <strong>Application:</strong> {original_rule.get('application', 'any')}
                """
            else:
                current_config = "<em>No rule definition available - using log-based analysis</em>"
            
            if optimized_rule:
                optimized_config = f"""
                    <strong>Source:</strong> {optimized_rule['source_address']}<br>
                    <strong>Destination:</strong> {optimized_rule['destination_address']}<br>
                    <strong>Service:</strong> {optimized_rule['service']}<br>
                    <strong>Application:</strong> {optimized_rule.get('application', 'any')}
                """
            else:
                optimized_config = "N/A"
            
            html_content += f"""
                    <tr>
                        <td>{rule_name}</td>
                        <td>{current_config}</td>
                        <td class="recommendation">{recommendation}</td>
                        <td>{optimized_config}</td>
                    </tr>
            """
        
        html_content += """
                </table>
            </div>
            
            <div class="section">
                <h2>Conclusion</h2>
                <p>This analysis has identified several opportunities to optimize your firewall rules and improve security:</p>
                <ul>
                    <li>Consider removing unused rules to simplify management and reduce potential attack surface</li>
                    <li>Restrict overly permissive rules by limiting source/destination addresses and services</li>
                    <li>Review rules marked as risky for potential security improvements</li>
                    <li>Monitor unusual traffic patterns and anomalies for potential security incidents</li>
                </ul>
            </div>
            
            <footer>
                <p>Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </footer>
        </body>
        </html>
        """
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        print(f"HTML report generated and saved to {output_file}")
