# report_generator.py
import json
import datetime
import numpy as np
import pandas as pd
from typing import Dict, Any

def generate_report(basic_stats: Dict[str, Any],
                    traffic_patterns: Dict[str, Any],
                    anomalies: Dict[str, Any],
                    rule_analysis: Dict[str, Any],
                    optimized_rules: Dict[str, Any],
                    output_file: str = 'firewall_analysis_report.json') -> Dict[str, Any]:
    report = {}
    report['basic_stats'] = basic_stats
    report['traffic_patterns'] = traffic_patterns
    report['anomalies'] = anomalies
    report['rule_analysis'] = rule_analysis
    report['optimized_rules'] = optimized_rules

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

def generate_html_report(report: Dict[str, Any], visualization_files: Dict[str, str],
                         output_file: str = 'firewall_analysis_report.html') -> None:
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
    html_content += f"""
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
