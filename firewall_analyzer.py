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
    
    def optimize_single_rule(self, merge_cidrs=False):
        """
        Gathers and aggregates all IPs/ports from the entire logs_df
        into one set of source/destination addresses and services.
        
        Args:
            merge_cidrs: Whether to apply CIDR merging to optimize rules (default: False)
            
        Returns:
            Dictionary with the optimized rule
        """
        rule = aggregate_single_rule(self.logs_df)
        
        if merge_cidrs:
            try:
                from cidr_merger import merge_overlapping_cidrs, optimize_cidrs_by_usage, calculate_cidr_efficiency
                
                original_src_cidrs = rule['source_address'].split(', ') if rule['source_address'] != 'any' else []
                merged_src_cidrs = merge_overlapping_cidrs(original_src_cidrs)
                optimized_src_cidrs, src_metrics = optimize_cidrs_by_usage(
                    self.logs_df, merged_src_cidrs, 'source.ip'
                )
                
                original_dst_cidrs = rule['destination_address'].split(', ') if rule['destination_address'] != 'any' else []
                merged_dst_cidrs = merge_overlapping_cidrs(original_dst_cidrs)
                optimized_dst_cidrs, dst_metrics = optimize_cidrs_by_usage(
                    self.logs_df, merged_dst_cidrs, 'destination.ip'
                )
                
                rule['source_address'] = optimized_src_cidrs
                rule['destination_address'] = optimized_dst_cidrs
                
                rule['cidr_optimization'] = {
                    'source': src_metrics,
                    'destination': dst_metrics,
                    'original_src_count': len(original_src_cidrs),
                    'optimized_src_count': len(optimized_src_cidrs),
                    'original_dst_count': len(original_dst_cidrs),
                    'optimized_dst_count': len(optimized_dst_cidrs)
                }
                
                print(f"CIDR optimization: Source CIDRs reduced from {len(original_src_cidrs)} to {len(optimized_src_cidrs)}")
                print(f"CIDR optimization: Destination CIDRs reduced from {len(original_dst_cidrs)} to {len(optimized_dst_cidrs)}")
            except ImportError:
                print("Warning: CIDR merger module not available. Skipping CIDR optimization.")
        
        return rule
    
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
    
    def generate_ml_rules(self, output_dir="visualizations"):
        """
        Generate rules using machine learning clustering techniques.
        
        Args:
            output_dir: Directory to save visualizations
            
        Returns:
            Dictionary with ML-based rules and performance metrics
        """
        try:
            from ml_rule_optimization import MLRuleOptimizer
            from ml_performance_metrics import compare_ml_techniques, visualize_ml_performance
            
            print("Generating ML-based rules...")
            
            ml_optimizer = MLRuleOptimizer(self.logs_df)
            
            try:
                ml_optimizer.enhanced_preprocess_data()
                print("Using enhanced IP preprocessing...")
            except AttributeError:
                ml_optimizer.preprocess_data()
                print("Using standard IP preprocessing...")
            
            ml_optimizer.evaluate_kmeans_clustering(n_iter=5)
            ml_optimizer.evaluate_dbscan_clustering(n_iter=5)
            ml_optimizer.evaluate_hdbscan_clustering(n_iter=5)
            
            # Generate rules from clustering results
            kmeans_rules = ml_optimizer.generate_rules_from_kmeans()
            dbscan_rules = ml_optimizer.generate_rules_from_dbscan()
            hdbscan_rules = ml_optimizer.generate_rules_from_hdbscan()
            ensemble_rules = ml_optimizer.generate_ensemble_rules()
            
            # Generate visualizations
            kmeans_vis = ml_optimizer.visualize_clustering_results("kmeans", output_dir)
            dbscan_vis = ml_optimizer.visualize_clustering_results("dbscan", output_dir)
            hdbscan_vis = ml_optimizer.visualize_hdbscan_results(output_dir)
            
            # Generate Louvain community detection rules
            louvain_rules = []
            louvain_vis = {}
            louvain_metrics = {}
            
            try:
                from louvain_community_detection import LouvainCommunityDetector
                
                print("Generating Louvain community detection rules...")
                
                louvain_detector = LouvainCommunityDetector(self.logs_df)
                louvain_detector.build_network_graph()
                communities, modularity = louvain_detector.detect_communities()
                louvain_rules = louvain_detector.generate_rules()
                louvain_vis = louvain_detector.visualize_communities(output_dir)
                
                louvain_metrics = {
                    "algorithm": "louvain",
                    "runtime": louvain_detector.runtime,
                    "modularity": modularity,
                    "rule_count": len(louvain_rules),
                    "log_coverage": sum(rule["log_count"] for rule in louvain_rules),
                    "coverage": sum(rule["log_count"] for rule in louvain_rules) / len(self.logs_df) if louvain_rules else 0,
                    "avg_logs_per_rule": sum(rule["log_count"] for rule in louvain_rules) / len(louvain_rules) if louvain_rules else 0,
                    "community_count": len(communities)
                }
            except ImportError as e:
                print(f"Warning: Louvain community detection not available. Skipping Louvain rule generation. Error: {e}")
            
            automated_rules = []
            automated_metrics = {}
            
            try:
                from ml_result_automation import apply_ml_result_automation
                
                print("Applying ML result automation...")
                
                algorithm_rules = {
                    "kmeans": kmeans_rules,
                    "dbscan": dbscan_rules,
                    "hdbscan": hdbscan_rules,
                    "louvain": louvain_rules
                }
                
                automation_result = apply_ml_result_automation(self.logs_df, algorithm_rules)
                automated_rules = automation_result.get("rules", [])
                
                automated_metrics = {
                    "algorithm": "automated",
                    "runtime": sum(r.get("runtime", 0) for r in [
                        ml_optimizer.results.get("kmeans", {}),
                        ml_optimizer.results.get("dbscan", {}),
                        ml_optimizer.results.get("hdbscan", {})
                    ]) + (louvain_detector.runtime if 'louvain_detector' in locals() else 0),
                    "rule_count": len(automated_rules),
                    "log_coverage": sum(rule["log_count"] for rule in automated_rules),
                    "coverage": sum(rule["log_count"] for rule in automated_rules) / len(self.logs_df) if automated_rules else 0,
                    "avg_logs_per_rule": sum(rule["log_count"] for rule in automated_rules) / len(automated_rules) if automated_rules else 0
                }
                
                print(f"ML result automation generated {len(automated_rules)} optimized rules")
            except ImportError as e:
                print(f"Warning: ML result automation not available. Skipping automation. Error: {e}")
            
            metrics = []
            
            if "kmeans" in ml_optimizer.results:
                kmeans_metrics = {
                    "algorithm": "kmeans",
                    "runtime": ml_optimizer.results["kmeans"]["runtime"],
                    "silhouette": ml_optimizer.results["kmeans"]["score"],
                    "rule_count": len(kmeans_rules),
                    "log_coverage": sum(rule["log_count"] for rule in kmeans_rules),
                    "coverage": sum(rule["log_count"] for rule in kmeans_rules) / len(self.logs_df) if kmeans_rules else 0,
                    "avg_logs_per_rule": sum(rule["log_count"] for rule in kmeans_rules) / len(kmeans_rules) if kmeans_rules else 0,
                    "cluster_count": len(set(ml_optimizer.results["kmeans"]["clusters"])) - (1 if -1 in ml_optimizer.results["kmeans"]["clusters"] else 0)
                }
                metrics.append(kmeans_metrics)
            
            if "dbscan" in ml_optimizer.results:
                dbscan_metrics = {
                    "algorithm": "dbscan",
                    "runtime": ml_optimizer.results["dbscan"]["runtime"],
                    "silhouette": ml_optimizer.results["dbscan"]["score"],
                    "rule_count": len(dbscan_rules),
                    "log_coverage": sum(rule["log_count"] for rule in dbscan_rules),
                    "coverage": sum(rule["log_count"] for rule in dbscan_rules) / len(self.logs_df) if dbscan_rules else 0,
                    "avg_logs_per_rule": sum(rule["log_count"] for rule in dbscan_rules) / len(dbscan_rules) if dbscan_rules else 0,
                    "cluster_count": len(set(ml_optimizer.results["dbscan"]["clusters"])) - (1 if -1 in ml_optimizer.results["dbscan"]["clusters"] else 0)
                }
                metrics.append(dbscan_metrics)
            
            if "hdbscan" in ml_optimizer.results:
                hdbscan_metrics = {
                    "algorithm": "hdbscan",
                    "runtime": ml_optimizer.results["hdbscan"]["runtime"],
                    "silhouette": ml_optimizer.results["hdbscan"]["score"],
                    "rule_count": len(hdbscan_rules),
                    "log_coverage": sum(rule["log_count"] for rule in hdbscan_rules),
                    "coverage": sum(rule["log_count"] for rule in hdbscan_rules) / len(self.logs_df) if hdbscan_rules else 0,
                    "avg_logs_per_rule": sum(rule["log_count"] for rule in hdbscan_rules) / len(hdbscan_rules) if hdbscan_rules else 0,
                    "cluster_count": len(set(ml_optimizer.results["hdbscan"]["clusters"])) - (1 if -1 in ml_optimizer.results["hdbscan"]["clusters"] else 0)
                }
                metrics.append(hdbscan_metrics)
            
            if louvain_metrics:
                metrics.append(louvain_metrics)
            
            if automated_metrics:
                metrics.append(automated_metrics)
            
            comparison = compare_ml_techniques(metrics)
            
            # Generate performance visualizations
            performance_vis = visualize_ml_performance(metrics, output_dir)
            
            # Prepare ML rules dictionary
            ml_rules = {
                "kmeans": kmeans_rules,
                "dbscan": dbscan_rules,
                "hdbscan": hdbscan_rules,
                "louvain": louvain_rules,
                "ensemble": ensemble_rules,
                "automated": automated_rules,
                "performance_metrics": {
                    "kmeans": kmeans_metrics if "kmeans" in ml_optimizer.results else {},
                    "dbscan": dbscan_metrics if "dbscan" in ml_optimizer.results else {},
                    "hdbscan": hdbscan_metrics if "hdbscan" in ml_optimizer.results else {},
                    "louvain": louvain_metrics if louvain_metrics else {},
                    "automated": automated_metrics if automated_metrics else {},
                    "comparison": comparison
                },
                "visualizations": {
                    "kmeans": kmeans_vis.get("clustering") if kmeans_vis else None,
                    "dbscan": dbscan_vis.get("clustering") if dbscan_vis else None,
                    "hdbscan": hdbscan_vis.get("clustering") if hdbscan_vis else None,
                    "louvain": louvain_vis.get("communities") if louvain_vis else None,
                    "louvain_heatmap": louvain_vis.get("heatmap") if louvain_vis else None,
                    "performance": performance_vis
                }
            }
            
            return ml_rules
        except ImportError as e:
            print(f"Warning: ML rule optimization modules not available. Skipping ML rule generation. Error: {e}")
            return None
    
    def generate_html_report(self, html_file="firewall_analysis_report.html"):
        """
        Produces an HTML report referencing the bar charts and single aggregator.
        Also includes ML-based rules if available.
        """
        # Generate the visualization
        vis_files = self.visualize_traffic()
        lean_rules = self.generate_lean_rule_set()
        # Generate JSON-based dictionary in memory
        data = self.generate_report()
        
        # Generate ML-based rules
        ml_rules = self.generate_ml_rules()
        
        from report_generator import generate_html_report
        generate_html_report(data, vis_files, lean_rules, html_file, ml_rules=ml_rules)
