# visualization.py
import os
import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd
from typing import Dict

def visualize_traffic(logs_df: pd.DataFrame, output_dir: str = 'visualizations') -> Dict[str, str]:
    os.makedirs(output_dir, exist_ok=True)
    visualization_files = {}
    
    plt.figure(figsize=(12, 6))
    traffic_by_day = logs_df.groupby(logs_df['timestamp'].dt.date).size()
    traffic_by_day.plot(kind='line', marker='o')
    plt.title('Firewall Traffic Over Time')
    plt.xlabel('Date')
    plt.ylabel('Number of Log Entries')
    plt.grid(True)
    plt.tight_layout()
    time_plot_file = os.path.join(output_dir, 'traffic_over_time.png')
    plt.savefig(time_plot_file)
    visualization_files['traffic_over_time'] = time_plot_file
    plt.close()
    
    plt.figure(figsize=(12, 6))
    if 'hour' not in logs_df.columns:
        logs_df['hour'] = logs_df['timestamp'].dt.hour
    hourly_traffic = logs_df.groupby('hour').size()
    hourly_traffic.plot(kind='bar')
    plt.title('Firewall Traffic by Hour of Day')
    plt.xlabel('Hour of Day')
    plt.ylabel('Number of Log Entries')
    plt.xticks(range(24))
    plt.grid(True, axis='y')
    plt.tight_layout()
    hourly_plot_file = os.path.join(output_dir, 'traffic_by_hour.png')
    plt.savefig(hourly_plot_file)
    visualization_files['traffic_by_hour'] = hourly_plot_file
    plt.close()
    
    plt.figure(figsize=(14, 8))
    rule_traffic = logs_df['rule.name'].value_counts()
    rule_traffic.plot(kind='bar')
    plt.title('Firewall Traffic by Rule')
    plt.xlabel('Rule Name')
    plt.ylabel('Number of Log Entries')
    plt.xticks(rotation=45, ha='right')
    plt.grid(True, axis='y')
    plt.tight_layout()
    rule_plot_file = os.path.join(output_dir, 'traffic_by_rule.png')
    plt.savefig(rule_plot_file)
    visualization_files['traffic_by_rule'] = rule_plot_file
    plt.close()
    
    plt.figure(figsize=(10, 6))
    if 'day_of_week' not in logs_df.columns:
        logs_df['day_of_week'] = logs_df['timestamp'].dt.day_name()
    zone_traffic = logs_df['observer.ingress.zone'].value_counts()
    zone_traffic.plot(kind='pie', autopct='%1.1f%%')
    plt.title('Firewall Traffic by Source Zone')
    plt.ylabel('')
    plt.tight_layout()
    zone_plot_file = os.path.join(output_dir, 'traffic_by_zone.png')
    plt.savefig(zone_plot_file)
    visualization_files['traffic_by_zone'] = zone_plot_file
    plt.close()
    
    plt.figure(figsize=(12, 12))
    G = nx.DiGraph()
    source_dest_counts = logs_df.groupby(['source.ip', 'destination.ip']).size().reset_index(name='count')
    source_dest_counts = source_dest_counts.sort_values('count', ascending=False).head(30)
    
    for _, row in source_dest_counts.iterrows():
        source = row['source.ip']
        dest = row['destination.ip']
        count = row['count']
        G.add_node(source, type='source')
        G.add_node(dest, type='destination')
        G.add_edge(source, dest, weight=count)
        
    node_colors = ['skyblue' if G.nodes[node].get('type') == 'source' else 'lightgreen' for node in G.nodes()]
    edge_widths = [G[u][v]['weight'] / 10 for u,v in G.edges()]
    pos = nx.spring_layout(G, seed=42)
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=300, alpha=0.8)
    nx.draw_networkx_edges(G, pos, width=edge_widths, alpha=0.5, edge_color='gray', arrows=True, arrowsize=15)
    nx.draw_networkx_labels(G, pos, font_size=8)
    plt.title('Network Traffic Graph (Top Source-Destination Pairs)')
    plt.axis('off')
    plt.tight_layout()
    network_plot_file = os.path.join(output_dir, 'network_graph.png')
    plt.savefig(network_plot_file)
    visualization_files['network_graph'] = network_plot_file
    plt.close()
    
    return visualization_files
