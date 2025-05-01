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
                         lean_rules: list,
                         output_file: str,
                         ml_rules: Dict[str, Any] = None) -> None:
    import os  # Required for checking if HTML files exist
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
"""
    
    html += """
    <div class="section">
      <h2>Lean Optimized Rules</h2>
      <table>
        <tr>
          <th>Rule Name</th>
          <th>Source CIDRs</th>
          <th>Destination CIDR</th>
          <th>Service</th>
          <th>Log Count</th>
        </tr>
    """
    for rule_info in lean_rules:
        html += f"""
        <tr>
          <td>{rule_info['rule_name']}</td>
          <td>{rule_info['source_address']}</td>
          <td>{rule_info['destination_address']}</td>
          <td>{rule_info['service']}</td>
          <td>{rule_info['log_count']}</td>
        </tr>
        """
    html += "</table></div>"
    
    if ml_rules:
        html += """
        <div class="section">
          <h2>Machine Learning Optimized Rules</h2>
          <p>Rules generated using various machine learning clustering techniques.</p>
        """
        
        if 'visualizations' in ml_rules:
            html += """
            <div class="visualization-container">
              <h3>Clustering Visualizations</h3>
              <div class="visualization-grid">
            """
            
            for technique, viz_path in ml_rules['visualizations'].items():
                if isinstance(viz_path, dict) and 'html' in viz_path:
                    html += f"""
                    <div class="visualization">
                      <h4>{technique.upper()} Clustering</h4>
                      <div class="viz-tabs">
                        <button class="viz-tab active" onclick="showViz(event, '{technique}-static')">Static</button>
                        <button class="viz-tab" onclick="showViz(event, '{technique}-interactive')">Interactive</button>
                      </div>
                      <div id="{technique}-static" class="viz-content active">
                        <img src="{viz_path['png']}" alt="{technique} Clustering">
                      </div>
                      <div id="{technique}-interactive" class="viz-content">
                        <iframe src="{viz_path['html']}" width="100%" height="500px" frameborder="0"></iframe>
                      </div>
                    </div>
                    """
                elif viz_path and isinstance(viz_path, str):
                    html_path = viz_path.replace('.png', '.html')
                    if os.path.exists(html_path):
                        html += f"""
                        <div class="visualization">
                          <h4>{technique.upper()} Clustering</h4>
                          <div class="viz-tabs">
                            <button class="viz-tab active" onclick="showViz(event, '{technique}-static')">Static</button>
                            <button class="viz-tab" onclick="showViz(event, '{technique}-interactive')">Interactive</button>
                          </div>
                          <div id="{technique}-static" class="viz-content active">
                            <img src="{viz_path}" alt="{technique} Clustering">
                          </div>
                          <div id="{technique}-interactive" class="viz-content">
                            <iframe src="{html_path}" width="100%" height="500px" frameborder="0"></iframe>
                          </div>
                        </div>
                        """
                    else:
                        html += f"""
                        <div class="visualization">
                          <h4>{technique.upper()} Clustering</h4>
                          <img src="{viz_path}" alt="{technique} Clustering">
                        </div>
                        """
            
            html += """
              </div>
            </div>
            """
        
        if 'kmeans' in ml_rules:
            html += """
            <h3>K-means Clustering Rules</h3>
            <table>
              <tr>
                <th>Rule Name</th>
                <th>Source CIDRs</th>
                <th>Destination CIDR</th>
                <th>Service</th>
                <th>Log Count</th>
              </tr>
            """
            
            for rule_info in ml_rules['kmeans']:
                html += f"""
                <tr>
                  <td>{rule_info.get('rule_name', f"Cluster {rule_info.get('cluster', 'Unknown')}")}</td>
                  <td>{rule_info['source_address']}</td>
                  <td>{rule_info['destination_address']}</td>
                  <td>{rule_info['service']}</td>
                  <td>{rule_info['log_count']}</td>
                </tr>
                """
            
            html += "</table>"
        
        if 'dbscan' in ml_rules:
            html += """
            <h3>DBSCAN Clustering Rules</h3>
            <table>
              <tr>
                <th>Rule Name</th>
                <th>Source CIDRs</th>
                <th>Destination CIDR</th>
                <th>Service</th>
                <th>Log Count</th>
              </tr>
            """
            
            for rule_info in ml_rules['dbscan']:
                html += f"""
                <tr>
                  <td>{rule_info.get('rule_name', f"Cluster {rule_info.get('cluster', 'Unknown')}")}</td>
                  <td>{rule_info['source_address']}</td>
                  <td>{rule_info['destination_address']}</td>
                  <td>{rule_info['service']}</td>
                  <td>{rule_info['log_count']}</td>
                </tr>
                """
            
            html += "</table>"
        
        if 'hdbscan' in ml_rules:
            html += """
            <h3>HDBSCAN Clustering Rules</h3>
            <table>
              <tr>
                <th>Rule Name</th>
                <th>Source CIDRs</th>
                <th>Destination CIDR</th>
                <th>Service</th>
                <th>Log Count</th>
              </tr>
            """
            
            for rule_info in ml_rules['hdbscan']:
                html += f"""
                <tr>
                  <td>{rule_info.get('rule_name', f"Cluster {rule_info.get('cluster', 'Unknown')}")}</td>
                  <td>{rule_info['source_address']}</td>
                  <td>{rule_info['destination_address']}</td>
                  <td>{rule_info['service']}</td>
                  <td>{rule_info['log_count']}</td>
                </tr>
                """
            
            html += "</table>"
        
        if 'ensemble' in ml_rules:
            html += """
            <h3>Ensemble Rules (Combined Approach)</h3>
            <table>
              <tr>
                <th>Rule Name</th>
                <th>Source CIDRs</th>
                <th>Destination CIDR</th>
                <th>Service</th>
                <th>Log Count</th>
              </tr>
            """
            
            for rule_info in ml_rules['ensemble']:
                html += f"""
                <tr>
                  <td>{rule_info.get('rule_name', f"Cluster {rule_info.get('cluster', 'Unknown')}")}</td>
                  <td>{rule_info['source_address']}</td>
                  <td>{rule_info['destination_address']}</td>
                  <td>{rule_info['service']}</td>
                  <td>{rule_info['log_count']}</td>
                </tr>
                """
            
            html += "</table>"
        
        if 'louvain' in ml_rules:
            html += """
            <h3>Louvain Community Detection Rules</h3>
            <table>
              <tr>
                <th>Rule Name</th>
                <th>Source CIDRs</th>
                <th>Destination CIDR</th>
                <th>Service</th>
                <th>Log Count</th>
              </tr>
            """
            
            for rule_info in ml_rules['louvain']:
                html += f"""
                <tr>
                  <td>{rule_info.get('rule_name', f"Community {rule_info.get('community', 'Unknown')}")}</td>
                  <td>{rule_info['source_address']}</td>
                  <td>{rule_info['destination_address']}</td>
                  <td>{rule_info['service']}</td>
                  <td>{rule_info['log_count']}</td>
                </tr>
                """
            
            html += "</table>"
        
        if 'automated' in ml_rules:
            html += """
            <h3>Automated Optimized Rules</h3>
            <p>These rules are automatically generated by combining and optimizing results from multiple ML algorithms.</p>
            <table>
              <tr>
                <th>Rule Name</th>
                <th>Source CIDRs</th>
                <th>Destination CIDR</th>
                <th>Service</th>
                <th>Log Count</th>
                <th>Original Algorithm</th>
              </tr>
            """
            
            for i, rule_info in enumerate(ml_rules['automated']):
                html += f"""
                <tr>
                  <td>Optimized Rule {i+1}</td>
                  <td>{rule_info['source_address']}</td>
                  <td>{rule_info['destination_address']}</td>
                  <td>{rule_info['service']}</td>
                  <td>{rule_info['log_count']}</td>
                  <td>{rule_info.get('original_algorithm', 'N/A')}</td>
                </tr>
                """
            
            html += "</table>"
        
        if 'performance_metrics' in ml_rules:
            html += """
            <h3>Performance Metrics</h3>
            <table>
              <tr>
                <th>Metric</th>
                <th>K-means</th>
                <th>DBSCAN</th>
                <th>HDBSCAN</th>
                <th>Louvain</th>
                <th>Automated</th>
              </tr>
            """
            
            metrics = ml_rules['performance_metrics']
            metric_rows = [
                {"name": "Runtime (seconds)", "key": "runtime_seconds", "format": "{:.2f}"},
                {"name": "Rule Count", "key": "rule_count", "format": "{}"},
                {"name": "Log Coverage", "key": "log_coverage", "format": "{}"},
                {"name": "Coverage Percentage", "key": "coverage_percentage", "format": "{:.2f}%"},
                {"name": "Avg Logs per Rule", "key": "avg_logs_per_rule", "format": "{:.2f}"},
                {"name": "Silhouette Score", "key": "silhouette_score", "format": "{:.3f}"},
                {"name": "Calinski-Harabasz Score", "key": "calinski_harabasz_score", "format": "{:.2f}"},
                {"name": "Davies-Bouldin Score", "key": "davies_bouldin_score", "format": "{:.3f}"},
                {"name": "Cluster Count", "key": "cluster_count", "format": "{}"},
                {"name": "Min Cluster Size", "key": "min_cluster_size", "format": "{}"},
                {"name": "Max Cluster Size", "key": "max_cluster_size", "format": "{}"}
            ]
            
            for row in metric_rows:
                html += f"""
                <tr>
                  <td>{row["name"]}</td>
                """
                
                for model in ["kmeans", "dbscan", "hdbscan", "louvain", "automated"]:
                    if model in metrics and row["key"] in metrics[model]:
                        value = metrics[model][row["key"]]
                        formatted_value = row["format"].format(value) if value is not None else "N/A"
                        html += f"<td>{formatted_value}</td>"
                    else:
                        html += "<td>N/A</td>"
                
                html += "</tr>"
            
            html += """
            </table>
            
            <h4>Comparison Summary</h4>
            <div class="comparison-summary">
            """
            
            if 'comparison' in metrics:
                comparison = metrics['comparison']
                for metric, data in comparison.items():
                    if metric != "models_compared" and data.get("algorithm") is not None:
                        try:
                            value_str = f"Value: {data.get('value', 0):.2f}" if "value" in data else ""
                            html += f"""
                            <div class="metric-card">
                              <div class="metric-name">Best {metric.replace('_', ' ').title()}</div>
                              <div class="metric-value">{data["algorithm"].upper()}</div>
                              <div class="metric-detail">{value_str}</div>
                            </div>
                            """
                        except Exception as e:
                            print(f"Error rendering metric card for {metric}: {str(e)}")
            
            html += """
            </div>
            """
        
        html += """
        <style>
          .visualization-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-top: 20px;
          }
          .visualization {
            border: 1px solid #ddd;
            padding: 10px;
            border-radius: 5px;
          }
          .visualization img {
            max-width: 100%;
            height: auto;
          }
          .viz-tabs {
            overflow: hidden;
            border: 1px solid #ccc;
            background-color: #f1f1f1;
            border-radius: 5px 5px 0 0;
          }
          .viz-tab {
            background-color: inherit;
            float: left;
            border: none;
            outline: none;
            cursor: pointer;
            padding: 10px 16px;
            transition: 0.3s;
          }
          .viz-tab:hover {
            background-color: #ddd;
          }
          .viz-tab.active {
            background-color: #ccc;
          }
          .viz-content {
            display: none;
            padding: 6px 12px;
            border: 1px solid #ccc;
            border-top: none;
            border-radius: 0 0 5px 5px;
          }
          .viz-content.active {
            display: block;
          }
          .comparison-summary {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin-top: 15px;
          }
          .metric-card {
            background-color: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 10px;
            width: 200px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          }
          .metric-name {
            font-weight: bold;
            margin-bottom: 5px;
          }
          .metric-value {
            font-size: 1.2em;
            color: #007bff;
            margin-bottom: 5px;
          }
          .metric-detail {
            font-size: 0.9em;
            color: #666;
          }
        </style>
        <script>
          function showViz(evt, vizId) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("viz-content");
            for (i = 0; i < tabcontent.length; i++) {
              tabcontent[i].style.display = "none";
            }
            tablinks = document.getElementsByClassName("viz-tab");
            for (i = 0; i < tablinks.length; i++) {
              tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            document.getElementById(vizId).style.display = "block";
            evt.currentTarget.className += " active";
          }
        </script>
        </div>
        """
    
    html += f"""
    <footer>
        <p>Generated on {now}</p>
    </footer>
</body>
</html>
    """
    
    with open(output_file, "w") as f:
        f.write(html)
    print(f"HTML report generated at {output_file}")
