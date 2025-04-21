# firewall_analyzer.py
from data_loader import load_logs
from stats import get_basic_stats
from traffic_analysis import analyze_traffic_patterns, identify_anomalies
from rule_optimization import aggregate_single_rule, generate_cidr_pair_rules, cap_rules_to_seven
from enhanced_rule_optimization import generate_relationship_based_rules
from ml_rule_optimization import MLRuleOptimizer
from fine_tuning import fine_tune_single_rule, analyze_rule_improvement
from cidr_merger import merge_rule_cidrs, interactive_cidr_merge

from visualization import visualize_traffic
from report_generator import generate_json_report, generate_html_report
import os

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
    
    def optimize_single_rule(self, fine_tune=False, max_src_cidrs=5, max_dst_cidrs=5, 
                           merge_cidrs=False, min_efficiency=0.7, interactive=False):
        """
        Gathers and aggregates all IPs/ports from the entire logs_df
        into one set of source/destination addresses and services.
        
        Args:
            fine_tune: Whether to apply fine-tuning to the single rule (default: False)
            max_src_cidrs: Maximum number of source CIDRs for fine-tuning (default: 5)
            max_dst_cidrs: Maximum number of destination CIDRs for fine-tuning (default: 5)
            merge_cidrs: Whether to merge CIDRs after optimization (default: False)
            min_efficiency: Minimum efficiency threshold for CIDR merging (default: 0.7)
            interactive: Whether to use interactive CIDR merging (default: False)
            
        Returns:
            Dictionary with the optimized rule
        """
        single_rule = aggregate_single_rule(self.logs_df)
        
        if fine_tune:
            fine_tuned_rule = fine_tune_single_rule(
                self.logs_df, 
                single_rule, 
                max_src_cidrs=max_src_cidrs, 
                max_dst_cidrs=max_dst_cidrs
            )
            
            # Analyze improvement
            improvement = analyze_rule_improvement(single_rule, fine_tuned_rule)
            fine_tuned_rule["improvement"] = improvement
            
            rule_to_use = fine_tuned_rule
        else:
            rule_to_use = single_rule
        
        # Apply CIDR merging if requested
        if merge_cidrs:
            if interactive:
                merged_rule = interactive_cidr_merge(rule_to_use)
            else:
                merged_rule = merge_rule_cidrs(rule_to_use, min_efficiency)
            
            return merged_rule
        
        return rule_to_use
    
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
    
    def generate_relationship_based_rule_set(self, max_rules=15):
        """
        Returns a list of rules based on actual source-destination-port relationships.
        This ensures that if certain source IPs only access certain destination IPs,
        they won't be grouped with other source IPs in the same rule.
        
        Args:
            max_rules: Maximum number of rules to generate (default: 15)
            
        Returns:
            List of rule dictionaries
        """
        return generate_relationship_based_rules(self.logs_df, max_rules)
        
    def generate_ml_rules(self, output_dir="ml_output", max_rules=15, visualize=True):
        """
        Generate firewall rules using machine learning techniques.
        Evaluates multiple ML approaches and compares their performance.
        
        Args:
            output_dir: Directory to save ML visualizations and results
            max_rules: Maximum number of rules to generate per technique
            visualize: Whether to generate visualizations
            
        Returns:
            Dictionary with rule sets from different ML techniques and performance metrics
        """
        print("Generating ML-based firewall rules...")
        
        ml_optimizer = MLRuleOptimizer(self.logs_df)
        
        ml_optimizer.preprocess_data()
        
        ml_optimizer.evaluate_kmeans_clustering()
        ml_optimizer.evaluate_dbscan_clustering()
        ml_optimizer.evaluate_isolation_forest()
        
        # Generate rules using different techniques
        kmeans_rules = ml_optimizer.generate_rules_from_kmeans(max_rules=max_rules)
        dbscan_rules = ml_optimizer.generate_rules_from_dbscan(max_rules=max_rules)
        ensemble_rules = ml_optimizer.generate_ensemble_rules(max_rules=max_rules)
        
        performance_metrics = ml_optimizer.compare_performance()
        
        # Generate visualizations if requested
        if visualize:
            ml_optimizer.visualize_results(output_dir=output_dir)
        
        # Return all rule sets and performance metrics
        return {
            "kmeans_rules": kmeans_rules,
            "dbscan_rules": dbscan_rules,
            "ensemble_rules": ensemble_rules,
            "performance_metrics": performance_metrics
        }
    
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
