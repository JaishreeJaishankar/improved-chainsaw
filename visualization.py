# visualization.py
import os
import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd
from typing import Dict

def visualize_traffic(logs_df: pd.DataFrame, output_dir: str = "visualizations") -> Dict[str, str]:
    """
    Generates:
      - Bar chart of top source IPs
      - Bar chart of top destination IPs
      - Bar chart of top destination ports
      - Network graph of top 30 source-dest pairs
    """
    os.makedirs(output_dir, exist_ok=True)
    files = {}
    
    # 1) Top Source IPs
    plt.figure(figsize=(8, 5))
    top_src = logs_df["source.ip"].value_counts().head(10)
    top_src.plot(kind="bar")
    plt.title("Top Source IPs")
    plt.xlabel("Source IP")
    plt.ylabel("Count")
    plt.tight_layout()
    src_file = os.path.join(output_dir, "top_source_ips.png")
    plt.savefig(src_file)
    plt.close()
    files["top_source_ips"] = src_file
    
    # 2) Top Destination IPs
    plt.figure(figsize=(8, 5))
    top_dst = logs_df["destination.ip"].value_counts().head(10)
    top_dst.plot(kind="bar")
    plt.title("Top Destination IPs")
    plt.xlabel("Destination IP")
    plt.ylabel("Count")
    plt.tight_layout()
    dst_file = os.path.join(output_dir, "top_destination_ips.png")
    plt.savefig(dst_file)
    plt.close()
    files["top_destination_ips"] = dst_file
    
    # 3) Top Destination Ports
    plt.figure(figsize=(8, 5))
    top_ports = logs_df["destination.port"].value_counts().head(10)
    top_ports.plot(kind="bar")
    plt.title("Top Destination Ports")
    plt.xlabel("Port")
    plt.ylabel("Count")
    plt.tight_layout()
    ports_file = os.path.join(output_dir, "top_destination_ports.png")
    plt.savefig(ports_file)
    plt.close()
    files["top_destination_ports"] = ports_file
    
    # 4) Network Graph
    pair_df = logs_df.groupby(["source.ip", "destination.ip"]).size().reset_index(name="count")
    pair_df = pair_df.sort_values("count", ascending=False).head(30)
    
    G = nx.DiGraph()
    for _, row in pair_df.iterrows():
        src = row["source.ip"]
        dst = row["destination.ip"]
        cnt = row["count"]
        G.add_node(src, type='source')
        G.add_node(dst, type='destination')
        G.add_edge(src, dst, weight=cnt)
    
    plt.figure(figsize=(10, 6))
    node_colors = []
    for node in G.nodes():
        node_colors.append("skyblue" if G.nodes[node].get("type") == "source" else "lightgreen")
    
    edge_widths = [G[u][v]["weight"] / 10 for u, v in G.edges()]
    pos = nx.spring_layout(G, seed=42)
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=400)
    nx.draw_networkx_edges(G, pos, width=edge_widths, alpha=0.5, arrows=True, arrowsize=15)
    nx.draw_networkx_labels(G, pos, font_size=8)
    plt.title("Top Source-Destination Pairs")
    plt.axis("off")
    plt.tight_layout()
    
    net_file = os.path.join(output_dir, "network_graph.png")
    plt.savefig(net_file)
    plt.close()
    files["network_graph"] = net_file
    
    return files
