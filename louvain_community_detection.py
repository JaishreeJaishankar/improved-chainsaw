import networkx as nx
import pandas as pd
import numpy as np
import time
from typing import Dict, List, Any, Tuple
from ip_utils import group_ips_into_networks, ports_to_services

class LouvainCommunityDetector:
    """
    Implements Louvain community detection algorithm for firewall rule optimization.
    Uses NetworkX to build a graph of IP communications and detect communities.
    Ensures 100% log coverage in the generated rules.
    """
    def __init__(self, logs_df: pd.DataFrame):
        """
        Initialize with logs DataFrame containing source.ip, destination.ip, destination.port.
        
        Args:
            logs_df: DataFrame with firewall logs
        """
        self.logs_df = logs_df
        self.G = None
        self.communities = None
        self.runtime = 0
        self.modularity = 0
        self.ip_to_community = {}
        
    def build_network_graph(self):
        """
        Build a network graph from the logs DataFrame.
        Nodes are IP addresses and edges represent communication between IPs.
        Edge weights are the number of log entries between the IPs.
        """
        print("Building network graph for Louvain community detection...")
        
        self.G = nx.DiGraph()
        
        source_ips = set(self.logs_df['source.ip'].unique())
        dest_ips = set(self.logs_df['destination.ip'].unique())
        all_ips = source_ips.union(dest_ips)
        
        self.G.add_nodes_from(all_ips)
        
        edge_weights = {}
        
        grouped = self.logs_df.groupby(['source.ip', 'destination.ip']).size().reset_index(name='weight')
        
        for _, row in grouped.iterrows():
            src = row['source.ip']
            dst = row['destination.ip']
            weight = row['weight']
            
            self.G.add_edge(src, dst, weight=weight)
        
        print(f"Network graph built with {self.G.number_of_nodes()} nodes and {self.G.number_of_edges()} edges.")
        
    def detect_communities(self):
        """
        Apply the Louvain community detection algorithm to the network graph.
        Returns the communities and modularity score.
        """
        if self.G is None:
            self.build_network_graph()
            
        print("Detecting communities using Louvain algorithm...")
        
        start_time = time.time()
        
        communities = nx.community.louvain_communities(self.G, weight='weight', resolution=1.0)
        
        partition = {}
        for i, community in enumerate(communities):
            for node in community:
                partition[node] = i
                self.ip_to_community[node] = i
        
        self.modularity = nx.community.modularity(self.G, communities, weight='weight')
        self.communities = communities
        
        self.runtime = time.time() - start_time
        
        print(f"Detected {len(communities)} communities with modularity {self.modularity:.4f} in {self.runtime:.2f} seconds.")
        
        return communities, self.modularity
        
    def generate_rules(self) -> List[Dict[str, Any]]:
        """
        Generate firewall rules based on the detected communities.
        Ensures 100% log coverage by creating rules for each community and a catch-all rule if needed.
        
        Returns:
            List of rule dictionaries with 100% log coverage
        """
        if self.communities is None:
            self.detect_communities()
            
        rules = []
        covered_logs = set()
        
        for i, community in enumerate(self.communities):
            source_ips_in_community = [ip for ip in community if ip in set(self.logs_df['source.ip'].unique())]
            dest_ips_in_community = [ip for ip in community if ip in set(self.logs_df['destination.ip'].unique())]
            
            if not source_ips_in_community and not dest_ips_in_community:
                continue
            
            if source_ips_in_community and not dest_ips_in_community:
                dest_ips_in_community = list(self.logs_df['destination.ip'].unique())
                
            if dest_ips_in_community and not source_ips_in_community:
                source_ips_in_community = list(self.logs_df['source.ip'].unique())
            
            community_logs = self.logs_df[
                self.logs_df['source.ip'].isin(source_ips_in_community) & 
                self.logs_df['destination.ip'].isin(dest_ips_in_community)
            ]
            
            if len(community_logs) == 0:
                continue
            
            for idx in community_logs.index:
                covered_logs.add(idx)
            
            ports = community_logs['destination.port'].unique()
            
            source_cidrs = group_ips_into_networks(source_ips_in_community)
            dest_cidrs = group_ips_into_networks(dest_ips_in_community)
            services = ports_to_services(ports)
            
            rule = {
                'source_address': source_cidrs,
                'destination_address': dest_cidrs,
                'service': services,
                'log_count': len(community_logs),
                'community': i,
                'algorithm': 'louvain'
            }
            
            rules.append(rule)
        
        uncovered_logs = self.logs_df.loc[~self.logs_df.index.isin(covered_logs)]
        
        if len(uncovered_logs) > 0:
            uncovered_src_ips = uncovered_logs['source.ip'].unique()
            uncovered_dst_ips = uncovered_logs['destination.ip'].unique()
            ports = uncovered_logs['destination.port'].unique()
            
            source_cidrs = group_ips_into_networks(list(uncovered_src_ips))
            dest_cidrs = group_ips_into_networks(list(uncovered_dst_ips))
            services = ports_to_services(ports)
            
            rule = {
                'source_address': source_cidrs,
                'destination_address': dest_cidrs,
                'service': services,
                'log_count': len(uncovered_logs),
                'community': -999,  # Special marker for catch-all
                'algorithm': 'louvain_catchall'
            }
            
            rules.append(rule)
        
        rules.sort(key=lambda x: x['log_count'], reverse=True)
        
        total_logs_covered = sum(rule['log_count'] for rule in rules)
        coverage_percentage = (total_logs_covered / len(self.logs_df)) * 100
        
        print(f"Louvain rules cover {coverage_percentage:.2f}% of logs ({total_logs_covered}/{len(self.logs_df)})")
        
        return rules
        
    def visualize_communities(self, output_dir: str) -> Dict[str, str]:
        """
        Generate visualizations for the detected communities.
        
        Args:
            output_dir: Directory to save visualizations
            
        Returns:
            Dictionary with paths to visualization files
        """
        import os
        import matplotlib.pyplot as plt
        
        if self.communities is None:
            self.detect_communities()
            
        os.makedirs(output_dir, exist_ok=True)
        
        pos = nx.spring_layout(self.G, seed=42)
        
        plt.figure(figsize=(12, 10))
        
        for i, community in enumerate(self.communities):
            nx.draw_networkx_nodes(
                self.G, 
                pos, 
                nodelist=community,
                node_color=f"C{i}",
                node_size=50,
                alpha=0.8,
                label=f"Community {i}"
            )
        
        edge_weights = [self.G[u][v]['weight'] for u, v in self.G.edges()]
        max_weight = max(edge_weights) if edge_weights else 1
        
        nx.draw_networkx_edges(
            self.G, 
            pos, 
            width=[0.1 + 0.9 * (w / max_weight) for w in edge_weights],
            alpha=0.3,
            arrows=True,
            arrowsize=5
        )
        
        plt.title(f"Louvain Communities (Modularity: {self.modularity:.4f})")
        plt.legend(scatterpoints=1, frameon=False, labelspacing=1)
        plt.axis('off')
        
        community_file = os.path.join(output_dir, "louvain_communities.png")
        plt.savefig(community_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        community_matrix = np.zeros((len(self.communities), len(self.communities)))
        
        for u, v, data in self.G.edges(data=True):
            if u in self.ip_to_community and v in self.ip_to_community:
                u_comm = self.ip_to_community[u]
                v_comm = self.ip_to_community[v]
                community_matrix[u_comm, v_comm] += data['weight']
        
        plt.figure(figsize=(10, 8))
        sns_heatmap = None
        
        try:
            import seaborn as sns
            sns_heatmap = sns.heatmap(
                community_matrix, 
                annot=False, 
                cmap="YlGnBu", 
                xticklabels=[f"C{i}" for i in range(len(self.communities))],
                yticklabels=[f"C{i}" for i in range(len(self.communities))]
            )
        except ImportError:
            plt.imshow(community_matrix, cmap="YlGnBu")
            plt.colorbar()
            
        plt.title("Community Interaction Heatmap")
        plt.xlabel("Destination Community")
        plt.ylabel("Source Community")
        
        heatmap_file = os.path.join(output_dir, "louvain_community_heatmap.png")
        plt.savefig(heatmap_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        return {
            "communities": community_file,
            "heatmap": heatmap_file
        }
