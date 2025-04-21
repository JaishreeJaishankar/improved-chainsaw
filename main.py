# main.py

import argparse
import os
from firewall_analyzer import FirewallAnalyzer

def main():
    parser = argparse.ArgumentParser(description="Analyze a single-rule log (3 columns) and produce optimized CIDRs")
    parser.add_argument("--log-file", required=True, help="Path to CSV: source.ip, destination.ip, destination.port")
    parser.add_argument("--output-dir", default="output", help="Output directory")
    parser.add_argument("--html-report", action="store_true", help="Generate HTML report")
    parser.add_argument("--ml-rules", action="store_true", help="Generate rules using machine learning techniques")
    parser.add_argument("--max-rules", type=int, default=15, help="Maximum number of rules to generate per technique")
    parser.add_argument("--fine-tune", action="store_true", help="Apply fine-tuning to the single optimized rule")
    parser.add_argument("--max-src-cidrs", type=int, default=5, help="Maximum number of source CIDRs for fine-tuning")
    parser.add_argument("--max-dst-cidrs", type=int, default=5, help="Maximum number of destination CIDRs for fine-tuning")
    parser.add_argument("--merge-cidrs", action="store_true", help="Merge CIDRs after optimization")
    parser.add_argument("--min-efficiency", type=float, default=0.7, help="Minimum efficiency threshold for CIDR merging")
    parser.add_argument("--interactive", action="store_true", help="Use interactive CIDR merging")
    args = parser.parse_args()
    
    os.makedirs(args.output_dir, exist_ok=True)
    
    analyzer = FirewallAnalyzer(args.log_file)
    
    print("Generating visualizations...")
    vis_dir = os.path.join(args.output_dir, "visualizations")
    analyzer.visualize_traffic(vis_dir)
    
    print("Generating JSON report...")
    json_report_path = os.path.join(args.output_dir, "firewall_analysis_report.json")
    analyzer.generate_report(json_report_path)
    
    if args.html_report:
        print("Generating HTML report...")
        html_report_path = os.path.join(args.output_dir, "firewall_analysis_report.html")
        analyzer.generate_html_report(html_report_path)
    
    # Quick console summary
    stats = analyzer.get_basic_stats()
    print(f"\nAnalysis Complete! Processed {stats['total_log_entries']} logs from {args.log_file}.")
    print(f"Unique source IPs: {stats['unique_source_ips']}")
    print(f"Unique destination IPs: {stats['unique_destination_ips']}")
    print(f"Unique destination ports: {stats['unique_destination_ports']}")
    
    anomalies = analyzer.identify_anomalies()
    if "unusual_ports" in anomalies:
        print(f"Found unusual ports: {list(anomalies['unusual_ports'].keys())[:5]} ...")
    if "low_occurrence_pairs" in anomalies:
        print(f"Found {len(anomalies['low_occurrence_pairs'])} low-occurrence pairs.")
    
    single_rule_opt = analyzer.optimize_single_rule(
        fine_tune=args.fine_tune,
        max_src_cidrs=args.max_src_cidrs,
        max_dst_cidrs=args.max_dst_cidrs
    )
    
    print("\nSingle Optimized Rule:")
    print(f"  Source CIDRs: {single_rule_opt['source_address']}")
    print(f"  Destination CIDRs: {single_rule_opt['destination_address']}")
    print(f"  Service(s): {single_rule_opt['service']}")
    print(f"  Log Count: {single_rule_opt['log_count']}")
    
    if args.fine_tune and 'improvement' in single_rule_opt:
        improvement = single_rule_opt['improvement']
        print("\nFine-Tuning Improvement:")
        print(f"  Original Source CIDRs: {improvement['original_src_cidrs']}")
        print(f"  Fine-Tuned Source CIDRs: {improvement['fine_tuned_src_cidrs']}")
        print(f"  Source Address Space Reduction: {improvement['src_address_space_reduction']}")
        print(f"  Original Destination CIDRs: {improvement['original_dst_cidrs']}")
        print(f"  Fine-Tuned Destination CIDRs: {improvement['fine_tuned_dst_cidrs']}")
        print(f"  Destination Address Space Reduction: {improvement['dst_address_space_reduction']}")
        print(f"  Overall Address Space Reduction: {improvement['overall_reduction']}")
    
    if args.merge_cidrs and 'merge_info' in single_rule_opt:
        merge_info = single_rule_opt['merge_info']
        print("\nCIDR Merging Results:")
        print(f"  Source CIDR Merges Applied: {merge_info['src_merges_applied']}")
        print(f"  Destination CIDR Merges Applied: {merge_info['dst_merges_applied']}")
        
        if merge_info['src_merges']:
            print("\n  Source CIDR Merges:")
            for i, merge in enumerate(merge_info['src_merges']):
                print(f"    {i+1}. Merged {merge['cidr1']} and {merge['cidr2']} into {merge['merged_cidr']}")
                print(f"       Efficiency: {merge['efficiency']:.2f}")
        
        if merge_info['dst_merges']:
            print("\n  Destination CIDR Merges:")
            for i, merge in enumerate(merge_info['dst_merges']):
                print(f"    {i+1}. Merged {merge['cidr1']} and {merge['cidr2']} into {merge['merged_cidr']}")
                print(f"       Efficiency: {merge['efficiency']:.2f}")
    
    print("\nRelationship-Based Rules (Respecting Source-Destination-Port Combinations):")
    relationship_rules = analyzer.generate_relationship_based_rule_set()
    for i, rule in enumerate(relationship_rules):
        print(f"\nRule {i+1}:")
        print(f"  Rule Name: {rule['rule_name']}")
        print(f"  Source CIDRs: {rule['source_address']}")
        print(f"  Destination CIDRs: {rule['destination_address']}")
        print(f"  Service(s): {rule['service']}")
        print(f"  Log Count: {rule['log_count']}")
    
    if args.ml_rules:
        print("\nGenerating ML-based firewall rules...")
        ml_output_dir = os.path.join(args.output_dir, "ml_output")
        ml_results = analyzer.generate_ml_rules(output_dir=ml_output_dir, max_rules=args.max_rules)
        
        print("\nK-means Clustering Rules:")
        for i, rule in enumerate(ml_results["kmeans_rules"]):
            print(f"\nK-means Rule {i+1}:")
            print(f"  Rule Name: {rule['rule_name']}")
            print(f"  Source CIDRs: {rule['source_address']}")
            print(f"  Destination CIDRs: {rule['destination_address']}")
            print(f"  Service(s): {rule['service']}")
            print(f"  Log Count: {rule['log_count']}")
        
        print("\nDBSCAN Clustering Rules:")
        for i, rule in enumerate(ml_results["dbscan_rules"]):
            print(f"\nDBSCAN Rule {i+1}:")
            print(f"  Rule Name: {rule['rule_name']}")
            print(f"  Source CIDRs: {rule['source_address']}")
            print(f"  Destination CIDRs: {rule['destination_address']}")
            print(f"  Service(s): {rule['service']}")
            print(f"  Log Count: {rule['log_count']}")
        
        print("\nEnsemble ML Rules (Combined Approach):")
        for i, rule in enumerate(ml_results["ensemble_rules"]):
            print(f"\nEnsemble Rule {i+1}:")
            print(f"  Rule Name: {rule['rule_name']}")
            print(f"  Source CIDRs: {rule['source_address']}")
            print(f"  Destination CIDRs: {rule['destination_address']}")
            print(f"  Service(s): {rule['service']}")
            print(f"  Log Count: {rule['log_count']}")
        
        print(f"\nML visualizations saved to: {ml_output_dir}")
    
    if args.html_report:
        print(f"\nHTML report at: {html_report_path}")
    else:
        print(f"\nJSON report at: {json_report_path}")

if __name__ == "__main__":
    main()
