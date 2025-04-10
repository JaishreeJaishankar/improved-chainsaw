# main.py
"""
Firewall Log Analyzer and Rule Optimizer

This script analyzes firewall logs and rule definitions to identify optimization
opportunities and reduce permission boundaries.
"""

import argparse
import os
from firewall_analyzer import FirewallAnalyzer

def main():
    parser = argparse.ArgumentParser(description='Analyze firewall logs and optimize rules')
    parser.add_argument('--generate-sample', action='store_true', help='Generate sample data for demonstration')
    parser.add_argument('--log-file', type=str, default='firewall_logs.csv', help='Path to the firewall log file (CSV)')
    parser.add_argument('--rule-file', type=str, default=None, help='Path to the firewall rule file (CSV) - optional, used only for validation')
    parser.add_argument('--output-dir', type=str, default='output', help='Directory to store output files')
    parser.add_argument('--html-report', action='store_true', help='Generate HTML report with visualizations')
    
    args = parser.parse_args()
    os.makedirs(args.output_dir, exist_ok=True)
    
    if args.generate_sample:
        print("Generating sample data...")
        from generate_sample_data import generate_log_file
        generate_log_file()
    
    analyzer = FirewallAnalyzer(args.log_file, args.rule_file)
    
    print("Generating visualizations...")
    visualization_dir = os.path.join(args.output_dir, 'visualizations')
    analyzer.visualize_traffic(visualization_dir)
    
    print("Generating analysis report...")
    report_file = os.path.join(args.output_dir, 'firewall_analysis_report.json')
    analyzer.generate_report(report_file)
    
    if args.html_report:
        print("Generating HTML report...")
        html_report_file = os.path.join(args.output_dir, 'firewall_analysis_report.html')
        analyzer.generate_html_report(html_report_file)
    
    print(f"\nAnalysis complete! Results saved to {args.output_dir}")
    stats = analyzer.get_basic_stats()
    print(f"- Analyzed {stats['total_log_entries']} log entries")
    if 'total_rules' in stats:
        print(f"- Found {stats['total_rules']} rules in logs")
        if 'unused_rules' in stats and stats['unused_rules']:
            print(f"- Found {len(stats['unused_rules'])} unused rules that could be removed")
    optimized_rules = analyzer.generate_optimized_rules()
    rules_with_recommendations = sum(1 for rule_info in optimized_rules.values() if rule_info.get('recommendation', '') != 'No optimization needed')
    print(f"- Identified {rules_with_recommendations} rules that could be optimized")
    anomalies = analyzer.identify_anomalies()
    if 'unusual_ports' in anomalies:
        print(f"- Detected {len(anomalies['unusual_ports'])} unusual ports in the traffic")
    if 'after_hours_traffic' in anomalies:
        print(f"- Found {anomalies['after_hours_traffic']['percentage']:.1f}% of traffic outside business hours")
    
    print("\nRecommendations:")
    print("1. Optimize firewall rules by limiting source/destination addresses based on actual traffic")
    print("2. Restrict services to specific ports based on observed usage")
    print("3. Monitor unusual traffic patterns for potential security incidents")
    if analyzer.rules_df is not None:
        print("4. Review and remove unused rules to simplify management")
    
    if args.html_report:
        print(f"\nFor detailed analysis, open the HTML report at: {html_report_file}")
    else:
        print(f"\nFor detailed analysis, check the JSON report at: {report_file}")
        print("Run with --html-report to generate a visual HTML report")

if __name__ == "__main__":
    main()
