# report_generator.py
import json
import datetime
import numpy as np
import pandas as pd
from typing import Dict, Any

def generate_json_report(basic_stats: Dict[str, Any],
                         traffic_patterns: Dict[str, Any],
                         anomalies: Dict[str, Any],
                         optimized_rule: Dict[str, Any],
                         output_file: str) -> Dict[str, Any]:
    """
    Save a JSON with stats, patterns, anomalies, 
    and the single 'optimized rule' aggregator.
    """
    report = {
        "basic_stats": basic_stats,
        "traffic_patterns": traffic_patterns,
        "anomalies": anomalies,
        "optimized_single_rule": optimized_rule
    }
    
    class CustomEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, pd.Timestamp):
                return obj.strftime("%Y-%m-%d %H:%M:%S")
            elif isinstance(obj, np.integer):
                return int(obj)
            elif isinstance(obj, np.floating):
                return float(obj)
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
            return super().default(obj)
    
    with open(output_file, "w") as f:
        json.dump(report, f, indent=4, cls=CustomEncoder)
    
    print(f"JSON report generated at {output_file}")
    return report

def generate_html_report(report: Dict[str, Any],
                         visualization_files: Dict[str, str],
                         output_file: str) -> None:
    """
    Creates an HTML file that displays basic stats, traffic patterns, anomalies,
    and a summary of the single aggregated rule. Also references the chart images.
    """
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Firewall Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #333; }}
        .section {{ margin-bottom: 30px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; }}
        th {{ background-color: #f2f2f2; }}
        .visualization img {{ max-width: 100%; border: 1px solid #ddd; }}
        .recommendation {{ background-color: #fffacd; padding: 10px; border-left: 4px solid #ffd700; }}
    </style>
</head>
<body>
    <h1>Firewall Analysis Report</h1>
    <div class="section">
        <h2>Basic Statistics</h2>
        <ul>
            <li>Total log entries: {report['basic_stats']['total_log_entries']}</li>
            <li>Unique source IPs: {report['basic_stats']['unique_source_ips']}</li>
            <li>Unique destination IPs: {report['basic_stats']['unique_destination_ips']}</li>
            <li>Unique destination ports: {report['basic_stats']['unique_destination_ports']}</li>
        </ul>
    </div>

    <div class="section">
        <h2>Traffic Visualizations</h2>
        <div class="visualization">
            <h3>Top Source IPs</h3>
            <img src="{visualization_files['top_source_ips']}" alt="Top Source IPs">
        </div>
        <div class="visualization">
            <h3>Top Destination IPs</h3>
            <img src="{visualization_files['top_destination_ips']}" alt="Top Destination IPs">
        </div>
        <div class="visualization">
            <h3>Top Destination Ports</h3>
            <img src="{visualization_files['top_destination_ports']}" alt="Top Destination Ports">
        </div>
        <div class="visualization">
            <h3>Network Graph</h3>
            <img src="{visualization_files['network_graph']}" alt="Network Graph">
        </div>
    </div>
    
    <div class="section">
        <h2>Traffic Patterns</h2>
        <h3>Top Source IPs</h3>
        <table>
            <tr><th>Source IP</th><th>Count</th></tr>
    """
    for ip, cnt in report["traffic_patterns"]["top_source_ips"].items():
        html += f"<tr><td>{ip}</td><td>{cnt}</td></tr>"
    
    html += """
        </table>
        <h3>Top Destination IPs</h3>
        <table>
            <tr><th>Destination IP</th><th>Count</th></tr>
    """
    for ip, cnt in report["traffic_patterns"]["top_destination_ips"].items():
        html += f"<tr><td>{ip}</td><td>{cnt}</td></tr>"
    
    html += """
        </table>
        <h3>Top Destination Ports</h3>
        <table>
            <tr><th>Port</th><th>Count</th></tr>
    """
    for port, cnt in report["traffic_patterns"]["top_destination_ports"].items():
        html += f"<tr><td>{port}</td><td>{cnt}</td></tr>"
    
    html += """
        </table>
    </div>
    
    <div class="section">
        <h2>Anomalies</h2>
    """
    anomalies = report["anomalies"]
    if "unusual_ports" in anomalies:
        html += "<h3>Unusual Ports</h3><ul>"
        for p, c in anomalies["unusual_ports"].items():
            html += f"<li>Port {p}: {c} occurrences</li>"
        html += "</ul>"
    if "low_occurrence_pairs" in anomalies:
        html += """<h3>Low-Occurrence Source-Destination Pairs</h3>
        <table>
            <tr><th>Source IP</th><th>Destination IP</th><th>Count</th></tr>
        """
        for row in anomalies["low_occurrence_pairs"]:
            html += f"<tr><td>{row['source.ip']}</td><td>{row['destination.ip']}</td><td>{row['count']}</td></tr>"
        html += "</table>"
    html += "</div>"
    
    # Show the single aggregated "optimized rule"
    rule = report["optimized_single_rule"]
    html += f"""
    <div class="section">
        <h2>Optimized Single Rule</h2>
        <p>This entire log belongs to one rule, 
           so we've aggregated all source addresses, 
           destination addresses, and ports into a single CIDR-based recommendation.</p>
        <table>
            <tr><th>Source CIDRs</th><td>{rule['source_address']}</td></tr>
            <tr><th>Destination CIDRs</th><td>{rule['destination_address']}</td></tr>
            <tr><th>Services</th><td>{rule['service']}</td></tr>
            <tr><th>Log Count</th><td>{rule['log_count']}</td></tr>
        </table>
    </div>

    <footer>
        <p>Generated on {now}</p>
    </footer>
</body>
</html>
"""
    
    with open(output_file, "w") as f:
        f.write(html)
    print(f"HTML report generated at {output_file}")
