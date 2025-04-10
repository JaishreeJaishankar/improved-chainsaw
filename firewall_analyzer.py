# firewall_analyzer.py
import os, json, datetime
import numpy as np
import pandas as pd
from data_loader import load_logs, load_rules
from stats import get_basic_stats
from traffic_analysis import analyze_traffic_patterns, identify_anomalies, analyze_log_based_patterns
from rule_analysis import analyze_rule_usage, generate_optimized_rules
from ip_utils import group_ips_into_networks, ports_to_services
from visualization import visualize_traffic
from report_generator import generate_report, generate_html_report

class FirewallAnalyzer:
    """
    A class to analyze firewall logs and provide recommendations for rule optimization.
    """
    def __init__(self, log_file: str, rule_file: str = None):
        self.log_file = log_file
        self.rule_file = rule_file
        self.logs_df = None
        self.rules_df = None
        self.load_data()
        
    def load_data(self) -> None:
        self.logs_df = load_logs(self.log_file)
        if self.rule_file:
            self.rules_df = load_rules(self.rule_file)
            print(f"Loaded {len(self.logs_df)} log entries and {len(self.rules_df)} rules.")
        else:
            print(f"Loaded {len(self.logs_df)} log entries. No rule file provided.")
    
    def get_basic_stats(self) -> dict:
        return get_basic_stats(self.logs_df, self.rules_df)
        
    def analyze_traffic_patterns(self) -> dict:
        return analyze_traffic_patterns(self.logs_df)
        
    def identify_anomalies(self) -> dict:
        return identify_anomalies(self.logs_df)
        
    def analyze_log_based_patterns(self) -> dict:
        return analyze_log_based_patterns(self.logs_df, group_ips_into_networks, ports_to_services)
        
    def analyze_rule_usage(self) -> dict:
        if self.rules_df is None:
            return self.analyze_log_based_patterns()
        return analyze_rule_usage(self.logs_df, self.rules_df)
        
    def generate_optimized_rules(self) -> dict:
        return generate_optimized_rules(self.logs_df, self.rules_df, group_ips_into_networks, ports_to_services)
        
    def visualize_traffic(self, output_dir: str = 'visualizations') -> dict:
        return visualize_traffic(self.logs_df, output_dir)
        
    def generate_report(self, output_file: str = 'firewall_analysis_report.json') -> dict:
        report = {}
        report['basic_stats'] = self.get_basic_stats()
        report['traffic_patterns'] = self.analyze_traffic_patterns()
        report['anomalies'] = self.identify_anomalies()
        if self.rules_df is None:
            report['log_analysis'] = self.analyze_log_based_patterns()
        else:
            report['rule_analysis'] = self.analyze_rule_usage()
        report['optimized_rules'] = self.generate_optimized_rules()
        
        # Use the report_generator module to output the JSON file
        generate_report(report['basic_stats'],
                        report['traffic_patterns'],
                        report['anomalies'],
                        report.get('rule_analysis', report.get('log_analysis')),
                        report['optimized_rules'],
                        output_file)
        return report
        
    def generate_html_report(self, output_file: str = 'firewall_analysis_report.html') -> None:
        vis_files = self.visualize_traffic()
        report = self.generate_report()
        generate_html_report(report, vis_files, output_file)
