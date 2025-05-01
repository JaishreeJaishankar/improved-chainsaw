# visualization.py
import os
import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from typing import Dict, List, Any

def visualize_traffic(logs_df: pd.DataFrame, output_dir: str = "visualizations") -> Dict[str, str]:
    """
    Generates enhanced visualizations for firewall traffic analysis:
    
    Static visualizations (PNG):
    - Enhanced bar chart of top source IPs using Seaborn
    - Enhanced bar chart of top destination IPs using Seaborn
    - Enhanced bar chart of top destination ports using Seaborn
    - Enhanced network graph of source-destination pairs using NetworkX
    
    Interactive visualizations (HTML):
    - Interactive bar chart of top source IPs using Plotly
    - Interactive bar chart of top destination IPs using Plotly
    - Interactive bar chart of top destination ports using Plotly
    - Interactive network graph using Plotly
    
    Args:
        logs_df: DataFrame with firewall logs
        output_dir: Directory to save visualizations
        
    Returns:
        Dictionary with paths to all visualization files
    """
    os.makedirs(output_dir, exist_ok=True)
    files = {}
    
    sns.set(style="whitegrid")
    
    # 1) Top Source IPs - Static with Seaborn
    plt.figure(figsize=(12, 6))
    top_src = logs_df["source.ip"].value_counts().head(10).reset_index()
    top_src.columns = ["IP", "Count"]
    
    ax = sns.barplot(x="Count", y="IP", data=top_src, hue="IP", palette="viridis", legend=False)
    ax.set_title("Top 10 Source IPs", fontsize=14, fontweight="bold")
    ax.set_xlabel("Connection Count", fontsize=12)
    ax.set_ylabel("Source IP Address", fontsize=12)
    
    for i, v in enumerate(top_src["Count"]):
        ax.text(v + 0.1, i, str(v), color='black', va='center')
    
    plt.tight_layout()
    src_file = os.path.join(output_dir, "top_source_ips.png")
    plt.savefig(src_file, dpi=300)
    plt.close()
    files["top_source_ips"] = src_file
    
    fig_src = px.bar(
        top_src,
        x="Count",
        y="IP",
        orientation="h",
        title="<b>Top 10 Source IP Addresses</b>",
        labels={"Count": "Connection Count", "IP": "Source IP Address"},
        color="Count",
        color_continuous_scale="Viridis",
        text="Count"
    )
    
    fig_src.update_layout(
        font=dict(size=12),
        hoverlabel=dict(bgcolor="white", font_size=12),
        xaxis_title="Connection Count",
        yaxis_title="Source IP Address",
        height=600,
        margin=dict(l=50, r=50, t=80, b=50)
    )
    
    fig_src.update_traces(textposition="outside")
    
    src_html = os.path.join(output_dir, "top_source_ips_interactive.html")
    fig_src.write_html(src_html, include_plotlyjs="cdn")
    files["top_source_ips_interactive"] = src_html
    
    # 2) Top Destination IPs - Static with Seaborn
    plt.figure(figsize=(12, 6))
    top_dst = logs_df["destination.ip"].value_counts().head(10).reset_index()
    top_dst.columns = ["IP", "Count"]
    
    ax = sns.barplot(x="Count", y="IP", data=top_dst, hue="IP", palette="magma", legend=False)
    ax.set_title("Top 10 Destination IPs", fontsize=14, fontweight="bold")
    ax.set_xlabel("Connection Count", fontsize=12)
    ax.set_ylabel("Destination IP Address", fontsize=12)
    
    for i, v in enumerate(top_dst["Count"]):
        ax.text(v + 0.1, i, str(v), color='black', va='center')
    
    plt.tight_layout()
    dst_file = os.path.join(output_dir, "top_destination_ips.png")
    plt.savefig(dst_file, dpi=300)
    plt.close()
    files["top_destination_ips"] = dst_file
    
    fig_dst = px.bar(
        top_dst,
        x="Count",
        y="IP",
        orientation="h",
        title="<b>Top 10 Destination IP Addresses</b>",
        labels={"Count": "Connection Count", "IP": "Destination IP Address"},
        color="Count",
        color_continuous_scale="Magma",
        text="Count"
    )
    
    fig_dst.update_layout(
        font=dict(size=12),
        hoverlabel=dict(bgcolor="white", font_size=12),
        xaxis_title="Connection Count",
        yaxis_title="Destination IP Address",
        height=600,
        margin=dict(l=50, r=50, t=80, b=50)
    )
    
    fig_dst.update_traces(textposition="outside")
    
    dst_html = os.path.join(output_dir, "top_destination_ips_interactive.html")
    fig_dst.write_html(dst_html, include_plotlyjs="cdn")
    files["top_destination_ips_interactive"] = dst_html
    
    # 3) Top Destination Ports - Static with Seaborn
    plt.figure(figsize=(12, 6))
    top_ports = logs_df["destination.port"].value_counts().head(10).reset_index()
    top_ports.columns = ["Port", "Count"]
    
    top_ports["Port"] = top_ports["Port"].astype(str)
    
    ax = sns.barplot(x="Count", y="Port", data=top_ports, hue="Port", palette="crest", legend=False)
    ax.set_title("Top 10 Destination Ports", fontsize=14, fontweight="bold")
    ax.set_xlabel("Connection Count", fontsize=12)
    ax.set_ylabel("Destination Port", fontsize=12)
    
    for i, v in enumerate(top_ports["Count"]):
        ax.text(v + 0.1, i, str(v), color='black', va='center')
    
    plt.tight_layout()
    ports_file = os.path.join(output_dir, "top_destination_ports.png")
    plt.savefig(ports_file, dpi=300)
    plt.close()
    files["top_destination_ports"] = ports_file
    
    fig_ports = px.bar(
        top_ports,
        x="Count",
        y="Port",
        orientation="h",
        title="<b>Top 10 Destination Ports</b>",
        labels={"Count": "Connection Count", "Port": "Destination Port"},
        color="Count",
        color_continuous_scale="Blues",
        text="Count"
    )
    
    fig_ports.update_layout(
        font=dict(size=12),
        hoverlabel=dict(bgcolor="white", font_size=12),
        xaxis_title="Connection Count",
        yaxis_title="Destination Port",
        height=600,
        margin=dict(l=50, r=50, t=80, b=50)
    )
    
    fig_ports.update_traces(textposition="outside")
    
    ports_html = os.path.join(output_dir, "top_destination_ports_interactive.html")
    fig_ports.write_html(ports_html, include_plotlyjs="cdn")
    files["top_destination_ports_interactive"] = ports_html
    
    # 4) Network Graph - Enhanced static version with NetworkX
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
    
    plt.figure(figsize=(14, 10))
    
    pos = nx.spring_layout(G, k=0.3, iterations=50, seed=42)
    
    source_nodes = [node for node in G.nodes() if G.nodes[node].get("type") == "source"]
    dest_nodes = [node for node in G.nodes() if G.nodes[node].get("type") == "destination"]
    
    source_sizes = [300 + (G.degree(node) * 30) for node in source_nodes]
    dest_sizes = [300 + (G.degree(node) * 30) for node in dest_nodes]
    
    nx.draw_networkx_nodes(
        G, pos, 
        nodelist=source_nodes, 
        node_color="royalblue", 
        node_size=source_sizes,
        alpha=0.8,
        edgecolors="black",
        linewidths=1
    )
    
    nx.draw_networkx_nodes(
        G, pos, 
        nodelist=dest_nodes, 
        node_color="tomato", 
        node_size=dest_sizes,
        alpha=0.8,
        edgecolors="black",
        linewidths=1
    )
    
    edge_weights = [G[u][v]["weight"] for u, v in G.edges()]
    max_weight = max(edge_weights) if edge_weights else 1
    
    edge_widths = [1 + (G[u][v]["weight"] / max_weight * 5) for u, v in G.edges()]
    
    nx.draw_networkx_edges(
        G, pos, 
        width=edge_widths, 
        alpha=0.7, 
        arrows=True, 
        arrowsize=15,
        edge_color="gray",
        connectionstyle="arc3,rad=0.1"  # Curved edges for better visibility
    )
    
    nx.draw_networkx_labels(
        G, pos, 
        font_size=8, 
        font_family="sans-serif",
        font_weight="bold",
        bbox=dict(facecolor="white", alpha=0.7, edgecolor="none", pad=3)
    )
    
    source_patch = plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='royalblue', markersize=10, label='Source IP')
    dest_patch = plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='tomato', markersize=10, label='Destination IP')
    plt.legend(handles=[source_patch, dest_patch], loc='upper right')
    
    plt.title("Network Traffic Graph - Top 30 Source-Destination Pairs", fontsize=16, fontweight="bold")
    plt.axis("off")
    plt.tight_layout()
    
    net_file = os.path.join(output_dir, "network_graph.png")
    plt.savefig(net_file, dpi=300, bbox_inches="tight")
    plt.close()
    files["network_graph"] = net_file
    
    edge_traces = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        weight = G[edge[0]][edge[1]]["weight"]
        width = 1 + (weight / max_weight * 5)
        
        edge_trace = go.Scatter(
            x=[x0, x1, None],
            y=[y0, y1, None],
            line=dict(width=width, color='rgba(150,150,150,0.7)'),
            hoverinfo='text',
            text=f"{edge[0]} → {edge[1]}<br>Count: {weight}",
            mode='lines'
        )
        edge_traces.append(edge_trace)
    
    node_trace_source = go.Scatter(
        x=[pos[node][0] for node in source_nodes],
        y=[pos[node][1] for node in source_nodes],
        text=[f"Source: {node}<br>Connections: {G.degree(node)}" for node in source_nodes],
        mode='markers+text',
        hoverinfo='text',
        marker=dict(
            showscale=False,
            color='rgba(65, 105, 225, 0.8)',
            size=[10 + (G.degree(node) * 2) for node in source_nodes],
            line=dict(width=2, color='rgb(50, 50, 50)')
        ),
        textposition="top center",
        textfont=dict(size=10)
    )
    
    node_trace_dest = go.Scatter(
        x=[pos[node][0] for node in dest_nodes],
        y=[pos[node][1] for node in dest_nodes],
        text=[f"Destination: {node}<br>Connections: {G.degree(node)}" for node in dest_nodes],
        mode='markers+text',
        hoverinfo='text',
        marker=dict(
            showscale=False,
            color='rgba(255, 99, 71, 0.8)',
            size=[10 + (G.degree(node) * 2) for node in dest_nodes],
            line=dict(width=2, color='rgb(50, 50, 50)')
        ),
        textposition="bottom center",
        textfont=dict(size=10)
    )
    
    fig_network = go.Figure(
        data=edge_traces + [node_trace_source, node_trace_dest],
        layout=go.Layout(
            title=dict(
                text="Interactive Network Traffic Graph - Top 30 Source-Destination Pairs",
                font=dict(size=16)
            ),
            showlegend=False,
            hovermode='closest',
            margin=dict(b=20, l=5, r=5, t=40),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=800,
            width=1000,
            plot_bgcolor='rgba(248,248,248,1)'
        )
    )
    
    fig_network.add_trace(go.Scatter(
        x=[None],
        y=[None],
        mode='markers',
        marker=dict(size=15, color='rgba(65, 105, 225, 0.8)'),
        showlegend=True,
        name='Source IP'
    ))
    
    fig_network.add_trace(go.Scatter(
        x=[None],
        y=[None],
        mode='markers',
        marker=dict(size=15, color='rgba(255, 99, 71, 0.8)'),
        showlegend=True,
        name='Destination IP'
    ))
    
    fig_network.update_layout(
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        )
    )
    
    net_html = os.path.join(output_dir, "network_graph_interactive.html")
    fig_network.write_html(net_html, include_plotlyjs="cdn")
    files["network_graph_interactive"] = net_html
    
    dashboard = make_subplots(
        rows=2, cols=2,
        subplot_titles=(
            "Top Source IPs", 
            "Top Destination IPs",
            "Top Destination Ports", 
            "Source-Destination Connections"
        ),
        specs=[
            [{"type": "bar"}, {"type": "bar"}],
            [{"type": "bar"}, {"type": "scatter"}]
        ],
        vertical_spacing=0.1,
        horizontal_spacing=0.05
    )
    
    # Add top source IPs
    for trace in fig_src.data:
        dashboard.add_trace(trace, row=1, col=1)
    
    # Add top destination IPs
    for trace in fig_dst.data:
        dashboard.add_trace(trace, row=1, col=2)
    
    for trace in fig_ports.data:
        dashboard.add_trace(trace, row=2, col=1)
    
    simplified_edges = []
    for i, (src, dst) in enumerate(list(G.edges())[:10]):  # Only top 10 edges for clarity
        x0, y0 = pos[src]
        x1, y1 = pos[dst]
        weight = G[src][dst]["weight"]
        
        edge_trace = go.Scatter(
            x=[x0, x1, None],
            y=[y0, y1, None],
            line=dict(width=1 + (weight / max_weight * 3), color='rgba(150,150,150,0.7)'),
            hoverinfo='text',
            text=f"{src} → {dst}<br>Count: {weight}",
            mode='lines',
            showlegend=False
        )
        simplified_edges.append(edge_trace)
    
    for edge_trace in simplified_edges:
        dashboard.add_trace(edge_trace, row=2, col=2)
    
    dashboard.add_trace(
        go.Scatter(
            x=[pos[node][0] for node in source_nodes[:5]],  # Only top 5 nodes
            y=[pos[node][1] for node in source_nodes[:5]],
            text=[node for node in source_nodes[:5]],
            mode='markers',
            marker=dict(color='blue', size=10),
            name='Source',
            showlegend=True
        ),
        row=2, col=2
    )
    
    dashboard.add_trace(
        go.Scatter(
            x=[pos[node][0] for node in dest_nodes[:5]],  # Only top 5 nodes
            y=[pos[node][1] for node in dest_nodes[:5]],
            text=[node for node in dest_nodes[:5]],
            mode='markers',
            marker=dict(color='red', size=10),
            name='Destination',
            showlegend=True
        ),
        row=2, col=2
    )
    
    dashboard.update_layout(
        title="Firewall Traffic Analysis Dashboard",
        height=1000,
        width=1200,
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        )
    )
    
    dashboard.update_xaxes(title_text="Count", row=1, col=1)
    dashboard.update_yaxes(title_text="Source IP", row=1, col=1)
    
    dashboard.update_xaxes(title_text="Count", row=1, col=2)
    dashboard.update_yaxes(title_text="Destination IP", row=1, col=2)
    
    dashboard.update_xaxes(title_text="Count", row=2, col=1)
    dashboard.update_yaxes(title_text="Port", row=2, col=1)
    
    dashboard.update_xaxes(showticklabels=False, row=2, col=2)
    dashboard.update_yaxes(showticklabels=False, row=2, col=2)
    
    dashboard_html = os.path.join(output_dir, "traffic_dashboard.html")
    dashboard.write_html(dashboard_html, include_plotlyjs="cdn")
    files["traffic_dashboard"] = dashboard_html
    
    return files
