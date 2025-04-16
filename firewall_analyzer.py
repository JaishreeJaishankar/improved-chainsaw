# firewall_analyzer.py
from data_loader import load_logs
from stats import get_basic_stats
from traffic_analysis import analyze_traffic_patterns, identify_anomalies
from rule_optimization import aggregate_single_rule, generate_cidr_pair_rules, cap_rules_to_seven

from visualization import visualize_traffic
from report_generator import generate_json_report, generate_html_report

class FirewallAnalyzer:
    """
    Coordinates analyzing logs with only 3 columns for a single rule,
    returning stats, anomalies, visualizations, and 
    one aggregated set of source/dest addresses + ports.
    """
    def __init__(self, log_file: str):
        self.log_file = log_file
        self.logs_df = None
        self.load_data()
    
    def load_data(self):
        self.logs_df = load_logs(self.log_file)
    
    def get_basic_stats(self):
        return get_basic_stats(self.logs_df)
    
    def analyze_traffic_patterns(self):
        return analyze_traffic_patterns(self.logs_df)
    
    def identify_anomalies(self):
        return identify_anomalies(self.logs_df)
    
    def optimize_single_rule(self):
        """
        Gathers and aggregates all IPs/ports from the entire logs_df
        into one set of source/destination addresses and services.
        """
        return aggregate_single_rule(self.logs_df)
    
    def visualize_traffic(self, output_dir="visualizations"):
        return visualize_traffic(self.logs_df, output_dir)
    
    def generate_report(self, json_file="firewall_analysis_report.json"):
        """
        Produces a JSON with stats, traffic patterns, anomalies,
        and the single aggregator for source/dest/ports.
        """
        stats = self.get_basic_stats()
        patterns = self.analyze_traffic_patterns()
        anomalies = self.identify_anomalies()
        single_rule_opt = self.optimize_single_rule()
        
        # Return a dictionary
        from report_generator import generate_json_report
        report_dict = generate_json_report(
            stats, patterns, anomalies, single_rule_opt, json_file
        )
        return report_dict
    
    def generate_lean_rule_set(self) -> list:
        """
        Returns a list of 'lean' rules, one per (destination port, adjacency group of destination IPs).
        Each rule also aggregates source IP addresses for that group.
        """
        raw_rules  = generate_cidr_pair_rules(self.logs_df) 
        capped     = cap_rules_to_seven(raw_rules)
        return capped
    
    def generate_html_report(self, html_file="firewall_analysis_report.html"):
        """
        Produces an HTML report referencing the bar charts and single aggregator.
        """
        # Generate the visualization
        vis_files = self.visualize_traffic()
        lean_rules = self.generate_lean_rule_set()
        # Generate JSON-based dictionary in memory
        data = self.generate_report()
        from report_generator import generate_html_report
        generate_html_report(data, vis_files, lean_rules, html_file)
