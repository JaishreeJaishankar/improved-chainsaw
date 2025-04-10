# main.py

import argparse
import os
from firewall_analyzer import FirewallAnalyzer

def main():
    parser = argparse.ArgumentParser(description="Analyze a single-rule log (3 columns) and produce optimized CIDRs")
    parser.add_argument("--log-file", required=True, help="Path to CSV: source.ip, destination.ip, destination.port")
    parser.add_argument("--output-dir", default="output", help="Output directory")
    parser.add_argument("--html-report", action="store_true", help="Generate HTML report")
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
    
    single_rule_opt = analyzer.optimize_single_rule()
    print("\nOptimized Single Rule (Aggregated):")
    print(f"  Source CIDRs: {single_rule_opt['source_address']}")
    print(f"  Destination CIDRs: {single_rule_opt['destination_address']}")
    print(f"  Service(s): {single_rule_opt['service']}")
    print(f"  Log Count: {single_rule_opt['log_count']}")
    
    if args.html_report:
        print(f"\nHTML report at: {html_report_path}")
    else:
        print(f"\nJSON report at: {json_report_path}")

if __name__ == "__main__":
    main()
