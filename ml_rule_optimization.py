import pandas as pd
import numpy as np
from typing import Dict, Any, List, Set, Tuple, Optional
from collections import defaultdict
import time
from sklearn.cluster import KMeans, DBSCAN
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score, calinski_harabasz_score
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
import os
from ip_utils import group_ips_into_networks, ports_to_services

class MLRuleOptimizer:
    """
    A class that implements various machine learning techniques for firewall rule optimization.
    Evaluates and compares different approaches to find the most effective rule generation strategy.
    """
    
    def __init__(self, logs_df: pd.DataFrame):
        """
        Initialize the ML Rule Optimizer with firewall logs.
        
        Args:
            logs_df: DataFrame with source.ip, destination.ip, and destination.port columns
        """
        self.logs_df = logs_df
        self.ip_features = None
        self.port_features = None
        self.models = {}
        self.results = {}
        self.performance_metrics = {}
        
    def preprocess_data(self):
        """
        Preprocess the data for machine learning algorithms.
        - Convert IP addresses to numerical features
        - Normalize port numbers
        - Create feature matrices
        """
        print("Preprocessing data for ML analysis...")
        
        src_ips = self.logs_df['source.ip'].unique()
        self.src_ip_to_idx = {ip: i for i, ip in enumerate(src_ips)}
        
        dst_ips = self.logs_df['destination.ip'].unique()
        self.dst_ip_to_idx = {ip: i for i, ip in enumerate(dst_ips)}
        
        ports = self.logs_df['destination.port'].unique()
        self.port_to_idx = {port: i for i, port in enumerate(ports)}
        
        ip_pairs_data = []
        for (src_ip, dst_ip), group in self.logs_df.groupby(['source.ip', 'destination.ip']):
            count = len(group)
            ip_pairs_data.append((src_ip, dst_ip, count))
        
        self.ip_pairs = pd.DataFrame(ip_pairs_data, columns=['source.ip', 'destination.ip', 'count'])
        
        src_ip_features = np.array([list(map(int, ip.split('.'))) for ip in self.ip_pairs['source.ip']])
        dst_ip_features = np.array([list(map(int, ip.split('.'))) for ip in self.ip_pairs['destination.ip']])
        count_features = np.array(self.ip_pairs['count']).reshape(-1, 1)
        
        self.ip_features = np.hstack([src_ip_features, dst_ip_features, count_features])
        
        port_pairs_data = []
        for (dst_ip, dst_port), group in self.logs_df.groupby(['destination.ip', 'destination.port']):
            count = len(group)
            port_pairs_data.append((dst_ip, dst_port, count))
        
        self.port_pairs = pd.DataFrame(port_pairs_data, columns=['destination.ip', 'destination.port', 'count'])
        
        port_features = np.array([int(port) for port in self.port_pairs['destination.port']]).reshape(-1, 1)
        dst_ip_features = np.array([list(map(int, ip.split('.'))) for ip in self.port_pairs['destination.ip']])
        count_features = np.array(self.port_pairs['count']).reshape(-1, 1)
        
        self.port_features = np.hstack([dst_ip_features, port_features, count_features])
        
        self.scaler_ip = StandardScaler()
        self.ip_features_scaled = self.scaler_ip.fit_transform(self.ip_features)
        
        self.scaler_port = StandardScaler()
        self.port_features_scaled = self.scaler_port.fit_transform(self.port_features)
        
        ip_pair_count = 0 if self.ip_features is None else len(self.ip_features)
        port_pair_count = 0 if self.port_features is None else len(self.port_features)
        print(f"Preprocessed {ip_pair_count} IP pairs and {port_pair_count} port pairs")
        
    def evaluate_kmeans_clustering(self, max_clusters=15):
        """
        Evaluate K-means clustering for grouping similar traffic patterns.
        
        Args:
            max_clusters: Maximum number of clusters to evaluate
            
        Returns:
            Best K-means model and optimal number of clusters
        """
        print("Evaluating K-means clustering...")
        start_time = time.time()
        
        silhouette_scores = []
        calinski_scores = []
        kmeans_models = {}
        
        if self.ip_features is None or len(self.ip_features) == 0:
            print("No IP features available for clustering.")
            return None, None
            
        max_possible_clusters = min(max_clusters + 1, len(self.ip_features))
        cluster_range = list(range(2, max_possible_clusters))
        
        for n_clusters in cluster_range:
            kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
            ip_clusters = kmeans.fit_predict(self.ip_features_scaled)
            
            if len(set(ip_clusters)) > 1:  # Ensure we have at least 2 clusters
                silhouette = silhouette_score(self.ip_features_scaled, ip_clusters)
                calinski = calinski_harabasz_score(self.ip_features_scaled, ip_clusters)
                
                silhouette_scores.append(silhouette)
                calinski_scores.append(calinski)
                kmeans_models[n_clusters] = kmeans
                
                print(f"  K-means with {n_clusters} clusters: Silhouette={silhouette:.4f}, Calinski-Harabasz={calinski:.4f}")
        
        if silhouette_scores:
            optimal_idx = np.argmax(silhouette_scores)
            optimal_n_clusters = cluster_range[optimal_idx]
            best_kmeans = kmeans_models[optimal_n_clusters]
            
            print(f"Optimal number of clusters for K-means: {optimal_n_clusters}")
            
            self.models['kmeans'] = best_kmeans
            self.results['kmeans'] = {
                'optimal_clusters': optimal_n_clusters,
                'silhouette_scores': silhouette_scores,
                'calinski_scores': calinski_scores,
                'clusters': best_kmeans.predict(self.ip_features_scaled),
                'runtime': time.time() - start_time
            }
            
            return best_kmeans, optimal_n_clusters
        else:
            print("Could not determine optimal clusters for K-means")
            return None, None
            
    def evaluate_dbscan_clustering(self, eps_values=None, min_samples_values=None):
        """
        Evaluate DBSCAN clustering for identifying traffic pattern groups.
        
        Args:
            eps_values: List of eps values to try
            min_samples_values: List of min_samples values to try
            
        Returns:
            Best DBSCAN model and parameters
        """
        print("Evaluating DBSCAN clustering...")
        start_time = time.time()
        
        if eps_values is None:
            eps_values = [0.5, 1.0, 1.5, 2.0, 2.5, 3.0]
        
        if min_samples_values is None:
            min_samples_values = [3, 5, 10, 15, 20]
        
        best_silhouette = -1
        best_dbscan = None
        best_params = None
        silhouette_scores = []
        
        for eps in eps_values:
            for min_samples in min_samples_values:
                dbscan = DBSCAN(eps=eps, min_samples=min_samples)
                ip_clusters = dbscan.fit_predict(self.ip_features_scaled)
                
                unique_clusters = set(ip_clusters)
                if len(unique_clusters) > 1 and -1 not in unique_clusters:
                    silhouette = silhouette_score(self.ip_features_scaled, ip_clusters)
                    
                    print(f"  DBSCAN with eps={eps}, min_samples={min_samples}: Silhouette={silhouette:.4f}, Clusters={len(unique_clusters)}")
                    silhouette_scores.append((eps, min_samples, silhouette, len(unique_clusters)))
                    
                    if silhouette > best_silhouette:
                        best_silhouette = silhouette
                        best_dbscan = dbscan
                        best_params = (eps, min_samples)
        
        if best_dbscan is not None and best_params is not None:
            eps_val, min_samples_val = best_params
            print(f"Best DBSCAN parameters: eps={eps_val}, min_samples={min_samples_val}")
            
            self.models['dbscan'] = best_dbscan
            self.results['dbscan'] = {
                'best_params': best_params,
                'silhouette_scores': silhouette_scores,
                'clusters': best_dbscan.fit_predict(self.ip_features_scaled),
                'runtime': time.time() - start_time
            }
            
            return best_dbscan, best_params
        else:
            print("Could not find suitable DBSCAN parameters")
            return None, None
            
    def evaluate_isolation_forest(self, contamination=0.05):
        """
        Evaluate Isolation Forest for anomaly detection in traffic patterns.
        
        Args:
            contamination: Expected proportion of anomalies in the dataset
            
        Returns:
            Trained Isolation Forest model
        """
        print("Evaluating Isolation Forest for anomaly detection...")
        start_time = time.time()
        
        isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42
        )
        
        isolation_forest.fit(self.ip_features_scaled)
        
        predictions = isolation_forest.predict(self.ip_features_scaled)
        anomaly_scores = isolation_forest.decision_function(self.ip_features_scaled)
        
        anomaly_count = np.sum(predictions == -1)
        anomaly_indices = np.where(predictions == -1)[0]
        
        ip_pair_count = 0 if self.ip_features is None else len(self.ip_features)
        print(f"Isolation Forest detected {anomaly_count} anomalies out of {ip_pair_count} IP pairs")
        
        self.models['isolation_forest'] = isolation_forest
        self.results['isolation_forest'] = {
            'predictions': predictions,
            'anomaly_scores': anomaly_scores,
            'anomaly_indices': anomaly_indices,
            'anomaly_count': anomaly_count,
            'runtime': time.time() - start_time
        }
        
        return isolation_forest
    
    def evaluate_random_forest(self, test_size=0.3):
        """
        Evaluate Random Forest for classifying traffic patterns.
        This is useful for predicting which destination IPs a source IP is likely to access.
        
        Args:
            test_size: Proportion of data to use for testing
            
        Returns:
            Trained Random Forest model
        """
        print("Evaluating Random Forest for traffic pattern classification...")
        start_time = time.time()
        
        X = np.array([list(map(int, ip.split('.'))) for ip in self.logs_df['source.ip']])
        y = np.array([self.dst_ip_to_idx[ip] for ip in self.logs_df['destination.ip']])
        
        from sklearn.model_selection import train_test_split
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42)
        
        rf = RandomForestClassifier(n_estimators=100, random_state=42)
        rf.fit(X_train, y_train)
        
        train_accuracy = rf.score(X_train, y_train)
        test_accuracy = rf.score(X_test, y_test)
        
        print(f"Random Forest - Train accuracy: {train_accuracy:.4f}, Test accuracy: {test_accuracy:.4f}")
        
        self.models['random_forest'] = rf
        self.results['random_forest'] = {
            'train_accuracy': train_accuracy,
            'test_accuracy': test_accuracy,
            'feature_importances': rf.feature_importances_,
            'runtime': time.time() - start_time
        }
        
        return rf
    
    def generate_rules_from_kmeans(self, max_rules=15):
        """
        Generate firewall rules based on K-means clustering results.
        
        Args:
            max_rules: Maximum number of rules to generate
            
        Returns:
            List of rule dictionaries
        """
        print("Generating rules from K-means clustering...")
        
        if 'kmeans' not in self.models:
            print("K-means model not found. Run evaluate_kmeans_clustering first.")
            return []
        
        kmeans = self.models['kmeans']
        clusters = kmeans.predict(self.ip_features_scaled)
        
        self.ip_pairs['cluster'] = clusters
        
        rules = []
        
        for cluster_id in self.ip_pairs['cluster'].unique():
            cluster_df = self.ip_pairs[self.ip_pairs['cluster'] == cluster_id]
            
            src_ips = cluster_df['source.ip'].unique().tolist()
            dst_ips = cluster_df['destination.ip'].unique().tolist()
            
            src_mask = self.logs_df['source.ip'].isin(src_ips)
            dst_mask = self.logs_df['destination.ip'].isin(dst_ips)
            
            matching_logs = self.logs_df[src_mask & dst_mask]
            ports = matching_logs['destination.port'].unique().tolist()
            
            if isinstance(src_ips, str):
                src_ip_list = [src_ips]
            elif isinstance(src_ips, list):
                src_ip_list = src_ips
            else:
                src_ip_list = src_ips.tolist()
                
            if isinstance(dst_ips, str):
                dst_ip_list = [dst_ips]
            elif isinstance(dst_ips, list):
                dst_ip_list = dst_ips
            else:
                dst_ip_list = dst_ips.tolist()
            
            src_cidrs = group_ips_into_networks([str(ip) for ip in src_ip_list])
            dst_cidrs = group_ips_into_networks([str(ip) for ip in dst_ip_list])
            
            port_ints = [int(p) for p in ports]
            services = ports_to_services(port_ints)
            
            rule = {
                "rule_name": f"kmeans_cluster_{cluster_id}",
                "source_address": ", ".join(src_cidrs) if src_cidrs else "any",
                "destination_address": ", ".join(dst_cidrs) if dst_cidrs else "any",
                "service": ", ".join(services) if services else "any",
                "log_count": len(cluster_df)
            }
            
            rules.append(rule)
        
        if len(rules) > max_rules:
            rules.sort(key=lambda r: r["log_count"], reverse=True)
            rules = rules[:max_rules]
        
        return rules
    
    def generate_rules_from_dbscan(self, max_rules=15):
        """
        Generate firewall rules based on DBSCAN clustering results.
        
        Args:
            max_rules: Maximum number of rules to generate
            
        Returns:
            List of rule dictionaries
        """
        print("Generating rules from DBSCAN clustering...")
        
        if 'dbscan' not in self.models:
            print("DBSCAN model not found. Run evaluate_dbscan_clustering first.")
            return []
        
        clusters = self.results['dbscan']['clusters']
        
        self.ip_pairs['dbscan_cluster'] = clusters
        
        rules = []
        
        for cluster_id in np.unique(clusters):
            if cluster_id == -1:  # Process noise points separately
                continue
                
            cluster_df = self.ip_pairs[self.ip_pairs['dbscan_cluster'] == cluster_id]
            
            src_ips = cluster_df['source.ip'].unique().tolist()
            dst_ips = cluster_df['destination.ip'].unique().tolist()
            
            src_mask = self.logs_df['source.ip'].isin(src_ips)
            dst_mask = self.logs_df['destination.ip'].isin(dst_ips)
            
            matching_logs = self.logs_df[src_mask & dst_mask]
            ports = matching_logs['destination.port'].unique().tolist()
            
            if isinstance(src_ips, str):
                src_ip_list = [src_ips]
            elif isinstance(src_ips, list):
                src_ip_list = src_ips
            else:
                src_ip_list = src_ips.tolist()
                
            if isinstance(dst_ips, str):
                dst_ip_list = [dst_ips]
            elif isinstance(dst_ips, list):
                dst_ip_list = dst_ips
            else:
                dst_ip_list = dst_ips.tolist()
            
            src_cidrs = group_ips_into_networks([str(ip) for ip in src_ip_list])
            dst_cidrs = group_ips_into_networks([str(ip) for ip in dst_ip_list])
            
            port_ints = [int(p) for p in ports]
            services = ports_to_services(port_ints)
            
            rule = {
                "rule_name": f"dbscan_cluster_{cluster_id}",
                "source_address": ", ".join(src_cidrs) if src_cidrs else "any",
                "destination_address": ", ".join(dst_cidrs) if dst_cidrs else "any",
                "service": ", ".join(services) if services else "any",
                "log_count": len(cluster_df)
            }
            
            rules.append(rule)
        
        # Process noise points
        noise_df = self.ip_pairs[self.ip_pairs['dbscan_cluster'] == -1]
        if len(noise_df) > 0:
            src_ips = noise_df['source.ip'].unique().tolist()
            dst_ips = noise_df['destination.ip'].unique().tolist()
            
            src_mask = self.logs_df['source.ip'].isin(src_ips)
            dst_mask = self.logs_df['destination.ip'].isin(dst_ips)
            
            matching_logs = self.logs_df[src_mask & dst_mask]
            ports = matching_logs['destination.port'].unique().tolist()
            
            if isinstance(src_ips, str):
                src_ip_list = [src_ips]
            elif isinstance(src_ips, list):
                src_ip_list = src_ips
            else:
                src_ip_list = src_ips.tolist()
                
            if isinstance(dst_ips, str):
                dst_ip_list = [dst_ips]
            elif isinstance(dst_ips, list):
                dst_ip_list = dst_ips
            else:
                dst_ip_list = dst_ips.tolist()
            
            src_cidrs = group_ips_into_networks([str(ip) for ip in src_ip_list])
            dst_cidrs = group_ips_into_networks([str(ip) for ip in dst_ip_list])
            
            port_ints = [int(p) for p in ports]
            services = ports_to_services(port_ints)
            
            rule = {
                "rule_name": "dbscan_noise",
                "source_address": ", ".join(src_cidrs) if src_cidrs else "any",
                "destination_address": ", ".join(dst_cidrs) if dst_cidrs else "any",
                "service": ", ".join(services) if services else "any",
                "log_count": len(noise_df)
            }
            
            rules.append(rule)
        
        if len(rules) > max_rules:
            rules.sort(key=lambda r: r["log_count"], reverse=True)
            rules = rules[:max_rules]
        
        return rules
        
    def generate_ensemble_rules(self, max_rules=15, weight_kmeans=0.4, weight_dbscan=0.4, weight_isolation=0.2):
        """
        Generate firewall rules using an ensemble of multiple ML techniques.
        
        Args:
            max_rules: Maximum number of rules to generate
            weight_kmeans: Weight for K-means clustering results
            weight_dbscan: Weight for DBSCAN clustering results
            weight_isolation: Weight for Isolation Forest anomaly detection
            
        Returns:
            List of rule dictionaries
        """
        print("Generating ensemble rules from multiple ML techniques...")
        
        required_models = ['kmeans', 'dbscan', 'isolation_forest']
        missing_models = [model for model in required_models if model not in self.models]
        
        if missing_models:
            print(f"Missing models: {', '.join(missing_models)}. Run the corresponding evaluation methods first.")
            return []
        
        kmeans_rules = self.generate_rules_from_kmeans(max_rules=max_rules*2)
        dbscan_rules = self.generate_rules_from_dbscan(max_rules=max_rules*2)
        
        anomaly_indices = self.results['isolation_forest']['anomaly_indices']
        anomaly_pairs = [
            (self.ip_pairs.iloc[i]['source.ip'], self.ip_pairs.iloc[i]['destination.ip'])
            for i in anomaly_indices
        ]
        
        anomaly_rules = []
        if anomaly_pairs:
            src_ips = list(set([pair[0] for pair in anomaly_pairs]))
            dst_ips = list(set([pair[1] for pair in anomaly_pairs]))
            
            ports = set()
            for src_ip in src_ips:
                for dst_ip in dst_ips:
                    matching_logs = self.logs_df[
                        (self.logs_df['source.ip'] == src_ip) & 
                        (self.logs_df['destination.ip'] == dst_ip)
                    ]
                    ports.update(matching_logs['destination.port'].tolist())
            
            if isinstance(src_ips, str):
                src_ip_list = [src_ips]
            elif isinstance(src_ips, list):
                src_ip_list = src_ips
            else:
                src_ip_list = src_ips.tolist()
                
            if isinstance(dst_ips, str):
                dst_ip_list = [dst_ips]
            elif isinstance(dst_ips, list):
                dst_ip_list = dst_ips
            else:
                dst_ip_list = dst_ips.tolist()
            
            src_cidrs = group_ips_into_networks([str(ip) for ip in src_ip_list])
            dst_cidrs = group_ips_into_networks([str(ip) for ip in dst_ip_list])
            
            port_ints = [int(p) for p in ports]
            services = ports_to_services(port_ints)
            
            rule = {
                "rule_name": "anomaly_traffic",
                "source_address": ", ".join(src_cidrs) if src_cidrs else "any",
                "destination_address": ", ".join(dst_cidrs) if dst_cidrs else "any",
                "service": ", ".join(services) if services else "any",
                "log_count": len(anomaly_pairs),
                "is_anomaly": True
            }
            
            anomaly_rules.append(rule)
        
        all_rules = []
        
        for rule in kmeans_rules:
            rule['ensemble_score'] = rule['log_count'] * weight_kmeans
            rule['techniques'] = ['kmeans']
            all_rules.append(rule)
        
        for dbscan_rule in dbscan_rules:
            merged = False
            
            for i, existing_rule in enumerate(all_rules):
                overlap = self._calculate_address_overlap(
                    existing_rule['source_address'], 
                    existing_rule['destination_address'],
                    dbscan_rule['source_address'], 
                    dbscan_rule['destination_address']
                )
                
                if overlap > 0.7:  # If there's significant overlap
                    all_rules[i]['ensemble_score'] += dbscan_rule['log_count'] * weight_dbscan
                    if 'dbscan' not in all_rules[i]['techniques']:
                        all_rules[i]['techniques'].append('dbscan')
                    merged = True
                    break
            
            if not merged:
                dbscan_rule['ensemble_score'] = dbscan_rule['log_count'] * weight_dbscan
                dbscan_rule['techniques'] = ['dbscan']
                all_rules.append(dbscan_rule)
        
        for anomaly_rule in anomaly_rules:
            anomaly_rule['ensemble_score'] = anomaly_rule['log_count'] * weight_isolation * 2  # Higher weight for anomalies
            anomaly_rule['techniques'] = ['isolation_forest']
            all_rules.append(anomaly_rule)
        
        all_rules.sort(key=lambda r: r['ensemble_score'], reverse=True)
        
        top_rules = all_rules[:max_rules]
        
        for rule in top_rules:
            rule['rule_name'] = f"ensemble_{','.join(rule['techniques'])}"
            if 'ensemble_score' in rule:
                del rule['ensemble_score']
            if 'techniques' in rule:
                del rule['techniques']
        
        return top_rules
    
    def _calculate_address_overlap(self, src_cidrs1, dst_cidrs1, src_cidrs2, dst_cidrs2):
        """
        Calculate the overlap between two sets of source and destination CIDRs.
        
        Args:
            src_cidrs1: First set of source CIDRs as a comma-separated string
            dst_cidrs1: First set of destination CIDRs as a comma-separated string
            src_cidrs2: Second set of source CIDRs as a comma-separated string
            dst_cidrs2: Second set of destination CIDRs as a comma-separated string
            
        Returns:
            Overlap score between 0 and 1
        """
        src1 = set(cidr.strip() for cidr in src_cidrs1.split(','))
        dst1 = set(cidr.strip() for cidr in dst_cidrs1.split(','))
        src2 = set(cidr.strip() for cidr in src_cidrs2.split(','))
        dst2 = set(cidr.strip() for cidr in dst_cidrs2.split(','))
        
        if 'any' in src1:
            src1 = set()
        if 'any' in dst1:
            dst1 = set()
        if 'any' in src2:
            src2 = set()
        if 'any' in dst2:
            dst2 = set()
        
        if src1 or src2:
            src_intersection = len(src1.intersection(src2))
            src_union = len(src1.union(src2))
            src_similarity = src_intersection / src_union if src_union > 0 else 0
        else:
            src_similarity = 1.0  # Both are 'any'
        
        if dst1 or dst2:
            dst_intersection = len(dst1.intersection(dst2))
            dst_union = len(dst1.union(dst2))
            dst_similarity = dst_intersection / dst_union if dst_union > 0 else 0
        else:
            dst_similarity = 1.0  # Both are 'any'
        
        return (src_similarity + dst_similarity) / 2
    
    def visualize_results(self, output_dir='output'):
        """
        Create visualizations of the ML results.
        
        Args:
            output_dir: Directory to save visualizations
        """
        print("Creating visualizations of ML results...")
        
        os.makedirs(output_dir, exist_ok=True)
        
        if 'kmeans' in self.models and self.ip_features is not None:
            pca = PCA(n_components=2)
            ip_features_2d = pca.fit_transform(self.ip_features_scaled)
            
            clusters = self.models['kmeans'].predict(self.ip_features_scaled)
            
            plt.figure(figsize=(10, 8))
            scatter = plt.scatter(ip_features_2d[:, 0], ip_features_2d[:, 1], c=clusters, cmap='viridis', alpha=0.7)
            plt.colorbar(scatter, label='Cluster')
            plt.title('K-means Clustering of IP Pairs')
            plt.xlabel('PCA Component 1')
            plt.ylabel('PCA Component 2')
            plt.savefig(f"{output_dir}/kmeans_clusters.png")
            plt.close()
            
            if 'silhouette_scores' in self.results['kmeans']:
                plt.figure(figsize=(10, 6))
                n_clusters = range(2, 2 + len(self.results['kmeans']['silhouette_scores']))
                plt.plot(n_clusters, self.results['kmeans']['silhouette_scores'], 'o-', color='blue')
                plt.title('K-means Clustering: Silhouette Score vs. Number of Clusters')
                plt.xlabel('Number of Clusters')
                plt.ylabel('Silhouette Score')
                plt.grid(True)
                plt.savefig(f"{output_dir}/kmeans_silhouette.png")
                plt.close()
        
        if 'dbscan' in self.models and self.ip_features is not None:
            pca = PCA(n_components=2)
            ip_features_2d = pca.fit_transform(self.ip_features_scaled)
            
            clusters = self.results['dbscan']['clusters']
            
            plt.figure(figsize=(10, 8))
            scatter = plt.scatter(ip_features_2d[:, 0], ip_features_2d[:, 1], c=clusters, cmap='viridis', alpha=0.7)
            plt.colorbar(scatter, label='Cluster')
            plt.title('DBSCAN Clustering of IP Pairs')
            plt.xlabel('PCA Component 1')
            plt.ylabel('PCA Component 2')
            plt.savefig(f"{output_dir}/dbscan_clusters.png")
            plt.close()
        
        if 'isolation_forest' in self.models and self.ip_features is not None:
            pca = PCA(n_components=2)
            ip_features_2d = pca.fit_transform(self.ip_features_scaled)
            
            predictions = self.results['isolation_forest']['predictions']
            
            plt.figure(figsize=(10, 8))
            normal_mask = predictions == 1
            anomaly_mask = predictions == -1
            
            plt.scatter(ip_features_2d[normal_mask, 0], ip_features_2d[normal_mask, 1], 
                       c='blue', label='Normal', alpha=0.5)
            plt.scatter(ip_features_2d[anomaly_mask, 0], ip_features_2d[anomaly_mask, 1], 
                       c='red', label='Anomaly', alpha=0.7)
            
            plt.title('Isolation Forest: Anomaly Detection')
            plt.xlabel('PCA Component 1')
            plt.ylabel('PCA Component 2')
            plt.legend()
            plt.savefig(f"{output_dir}/isolation_forest_anomalies.png")
            plt.close()
    
    def compare_performance(self, rule_sets=None):
        """
        Compare the performance of different rule generation techniques.
        
        Args:
            rule_sets: Dictionary mapping technique names to rule sets
            
        Returns:
            Dictionary of performance metrics
        """
        print("Comparing performance of different rule generation techniques...")
        
        if rule_sets is None:
            rule_sets = {}
            
            if 'kmeans' in self.models:
                rule_sets['kmeans'] = self.generate_rules_from_kmeans()
            
            if 'dbscan' in self.models:
                rule_sets['dbscan'] = self.generate_rules_from_dbscan()
            
            if all(model in self.models for model in ['kmeans', 'dbscan', 'isolation_forest']):
                rule_sets['ensemble'] = self.generate_ensemble_rules()
        
        metrics = {}
        
        for technique, rules in rule_sets.items():
            total_logs = len(self.logs_df)
            covered_logs = sum(rule['log_count'] for rule in rules)
            coverage = covered_logs / total_logs if total_logs > 0 else 0
            
            avg_src_cidrs = np.mean([len(rule['source_address'].split(',')) if rule['source_address'] != 'any' else 1 for rule in rules])
            avg_dst_cidrs = np.mean([len(rule['destination_address'].split(',')) if rule['destination_address'] != 'any' else 1 for rule in rules])
            avg_services = np.mean([len(rule['service'].split(',')) if rule['service'] != 'any' else 1 for rule in rules])
            
            complexity = (avg_src_cidrs + avg_dst_cidrs + avg_services) / 3
            
            rule_count = len(rules)
            
            efficiency = coverage / rule_count if rule_count > 0 else 0
            
            metrics[technique] = {
                'coverage': coverage,
                'complexity': complexity,
                'rule_count': rule_count,
                'efficiency': efficiency,
                'runtime': self.results.get(technique, {}).get('runtime', 0)
            }
        
        self.performance_metrics = metrics
        
        print("\nPerformance Comparison:")
        print(f"{'Technique':<15} {'Coverage':<10} {'Complexity':<12} {'Rule Count':<12} {'Efficiency':<12} {'Runtime (s)':<12}")
        print("-" * 70)
        
        for technique, metric in metrics.items():
            print(f"{technique:<15} {metric['coverage']:.4f}     {metric['complexity']:.4f}       {metric['rule_count']:<12} {metric['efficiency']:.4f}     {metric['runtime']:.4f}")
        
        return metrics
