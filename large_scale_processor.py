
import os
import time
import pandas as pd
import numpy as np
import psutil
from typing import Dict, List, Any, Tuple
import random
from data_loader import load_logs
from ip_utils import group_ips_into_networks, ports_to_services
from cidr_merger import merge_overlapping_cidrs, optimize_cidrs_by_usage
from ml_rule_optimization import MLRuleOptimizer
from ml_performance_metrics import compare_ml_techniques, visualize_ml_performance
from report_generator import generate_large_scale_html_report

class LargeScaleProcessor:
    """
    Memory-efficient processor for large firewall log datasets.
    Processes logs in batches to minimize memory usage.
    """
    
    def __init__(
        self,
        log_file: str,
        output_dir: str = "output",
        batch_size: int = 5000,
        sample_size: int = 2000,
        max_rules: int = 10,
        skip_ml: bool = False
    ):
        self.log_file = log_file
        self.output_dir = output_dir
        self.batch_size = batch_size
        self.sample_size = sample_size
        self.max_rules = max_rules
        self.skip_ml = skip_ml
        
        self.stats = {
            "total_logs": 0,
            "unique_source_ips": set(),
            "unique_destination_ips": set(),
            "unique_destination_ports": set(),
            "processing_time": 0,
            "peak_memory": 0
        }
        
        self.results = {
            "single_rule": None,
            "ml_rules": {},
            "ml_metrics": [],
            "ml_comparison": {},
            "visualizations": {}
        }
        
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, "visualizations"), exist_ok=True)
    
    def process(self) -> int:
        """
        Process the logs in batches to minimize memory usage.
        Returns the total number of logs processed.
        """
        print(f"Processing {self.log_file} in batches of {self.batch_size}...")
        
        total_logs = 0
        source_ip_counts = {}
        dest_ip_counts = {}
        port_counts = {}
        
        start_time = time.time()
        batch_num = 0
        
        with open(self.log_file, 'r') as f:
            total_lines = sum(1 for _ in f)
        
        for batch_df in pd.read_csv(self.log_file, chunksize=self.batch_size):
            batch_num += 1
            batch_size = len(batch_df)
            total_logs += batch_size
            
            current_memory = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
            if current_memory > self.stats["peak_memory"]:
                self.stats["peak_memory"] = current_memory
            
            for ip in batch_df["source.ip"].unique():
                self.stats["unique_source_ips"].add(ip)
                source_ip_counts[ip] = source_ip_counts.get(ip, 0) + batch_df[batch_df["source.ip"] == ip].shape[0]
            
            for ip in batch_df["destination.ip"].unique():
                self.stats["unique_destination_ips"].add(ip)
                dest_ip_counts[ip] = dest_ip_counts.get(ip, 0) + batch_df[batch_df["destination.ip"] == ip].shape[0]
            
            for port in batch_df["destination.port"].unique():
                self.stats["unique_destination_ports"].add(port)
                port_counts[port] = port_counts.get(port, 0) + batch_df[batch_df["destination.port"] == port].shape[0]
            
            progress = (batch_num * self.batch_size / total_lines) * 100
            print(f"Batch {batch_num}: Processed {batch_size} logs ({progress:.1f}% complete)")
            
            del batch_df
        
        self.stats["total_logs"] = total_logs
        self.stats["processing_time"] = time.time() - start_time
        
        print("Generating single optimized rule...")
        self._generate_single_rule(source_ip_counts, dest_ip_counts, port_counts)
        
        if not self.skip_ml:
            print("Generating ML-based rules (using sampling for efficiency)...")
            self._generate_ml_rules()
        
        return total_logs
    
    def _generate_single_rule(self, source_ip_counts, dest_ip_counts, port_counts):
        """
        Generate a single optimized rule from the processed logs.
        """
        src_ips = list(source_ip_counts.keys())
        dst_ips = list(dest_ip_counts.keys())
        ports = [int(p) for p in port_counts.keys()]
        
        src_cidrs = group_ips_into_networks(src_ips)
        dst_cidrs = group_ips_into_networks(dst_ips)
        
        services = ports_to_services(ports)
        
        merged_src_cidrs = merge_overlapping_cidrs(src_cidrs)
        merged_dst_cidrs = merge_overlapping_cidrs(dst_cidrs)
        
        self.results["single_rule"] = {
            "source_address": ", ".join(merged_src_cidrs) if merged_src_cidrs else "any",
            "destination_address": ", ".join(merged_dst_cidrs) if merged_dst_cidrs else "any",
            "service": ", ".join(services) if services else "any",
            "log_count": self.stats["total_logs"]
        }
        
        rule_file = os.path.join(self.output_dir, "single_optimized_rule.json")
        pd.DataFrame([self.results["single_rule"]]).to_json(rule_file, orient="records", indent=2)
        print(f"Single optimized rule saved to {rule_file}")
    
    def _generate_ml_rules(self):
        """
        Generate ML-based rules using sampling for efficiency.
        """
        print(f"Sampling {self.sample_size} logs for ML processing...")
        sample_df = pd.read_csv(self.log_file, nrows=self.sample_size)
        
        ml_optimizer = MLRuleOptimizer(sample_df, max_rules=self.max_rules)
        
        print("Generating KMeans rules...")
        kmeans_rules, kmeans_metrics = ml_optimizer.generate_kmeans_rules()
        self.results["ml_rules"]["kmeans"] = kmeans_rules
        self.results["ml_metrics"].append(kmeans_metrics)
        
        print("Generating DBSCAN rules...")
        dbscan_rules, dbscan_metrics = ml_optimizer.generate_dbscan_rules()
        self.results["ml_rules"]["dbscan"] = dbscan_rules
        self.results["ml_metrics"].append(dbscan_metrics)
        
        print("Generating HDBSCAN rules...")
        hdbscan_rules, hdbscan_metrics = ml_optimizer.generate_hdbscan_rules()
        self.results["ml_rules"]["hdbscan"] = hdbscan_rules
        self.results["ml_metrics"].append(hdbscan_metrics)
        
        self.results["ml_comparison"] = compare_ml_techniques(self.results["ml_metrics"])
        
        vis_dir = os.path.join(self.output_dir, "visualizations")
        self.results["visualizations"] = visualize_ml_performance(
            self.results["ml_metrics"], vis_dir
        )
        
        for algo, rules in self.results["ml_rules"].items():
            rule_file = os.path.join(self.output_dir, f"{algo}_rules.json")
            pd.DataFrame(rules).to_json(rule_file, orient="records", indent=2)
            print(f"{algo.upper()} rules saved to {rule_file}")
    
    def generate_html_report(self):
        """
        Generate an HTML report with the results.
        """
        print("Generating HTML report...")
        report_file = os.path.join(self.output_dir, "large_scale_analysis_report.html")
        
        generate_large_scale_html_report(
            report_file,
            self.stats,
            self.results,
            self.log_file
        )
        
        print(f"HTML report saved to {report_file}")
