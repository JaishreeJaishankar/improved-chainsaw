import numpy as np
import pandas as pd
import time
import ipaddress
from typing import Dict, List, Any, Tuple
from sklearn.cluster import KMeans, DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score, davies_bouldin_score
from sklearn.model_selection import ParameterGrid
import warnings

warnings.filterwarnings("ignore", category=UserWarning, message=".*n_init.*")
warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*empty cluster.*")

try:
    import hdbscan
    HDBSCAN_AVAILABLE = True
except ImportError:
    HDBSCAN_AVAILABLE = False
    print("Warning: HDBSCAN not available. Install with 'pip install hdbscan' to use HDBSCAN clustering.")

class MLRuleOptimizer:
    """
    Optimizes firewall rules using machine learning clustering techniques.
    Includes hyperparameter tuning for KMeans, DBSCAN, and HDBSCAN.
    """
    def __init__(self, logs_df: pd.DataFrame):
        """
        Initialize with logs DataFrame containing source.ip, destination.ip, destination.port.
        
        Args:
            logs_df: DataFrame with firewall logs
        """
        self.logs_df = logs_df
        self.ip_features = None
        self.ip_features_scaled = None
        self.source_ips = None
        self.dest_ips = None
        self.dest_ports = None
        self.results = {}
        
    def preprocess_data(self):
        """
        Convert IP addresses to numerical features for clustering.
        """
        print("Preprocessing data for ML clustering...")
        
        self.source_ips = self.logs_df['source.ip'].unique()
        self.dest_ips = self.logs_df['destination.ip'].unique()
        self.dest_ports = self.logs_df['destination.port'].unique()
        
        ip_features = []
        ip_mapping = {}
        
        for ip in np.concatenate([self.source_ips, self.dest_ips]):
            if ip in ip_mapping:
                continue
                
            try:
                ip_obj = ipaddress.ip_address(ip)
                ip_int = int(ip_obj)
                ip_bytes = ip_obj.packed
                
                features = [
                    ip_int,  # Full IP as integer
                    ip_bytes[0],  # First octet
                    ip_bytes[1],  # Second octet
                    ip_bytes[2],  # Third octet
                    ip_bytes[3],  # Fourth octet
                    (ip_bytes[0] << 8) + ip_bytes[1],  # First two octets combined
                    (ip_bytes[2] << 8) + ip_bytes[3]   # Last two octets combined
                ]
                
                ip_mapping[ip] = features
                ip_features.append(features)
            except ValueError:
                print(f"Warning: Invalid IP address {ip}, skipping.")
        
        if not ip_features:
            raise ValueError("No valid IP addresses found for clustering.")
        
        self.ip_features = np.array(ip_features)
        
        scaler = StandardScaler()
        self.ip_features_scaled = scaler.fit_transform(self.ip_features)
        
        print(f"Preprocessed {len(self.ip_features)} unique IP addresses for clustering.")
        
    def enhanced_preprocess_data(self):
        """
        Apply enhanced preprocessing techniques for IP addresses.
        """
        print("Applying enhanced IP preprocessing...")
        
        self.preprocess_data()
        
        from ml_result_automation import MLResultOptimizer
        optimizer = MLResultOptimizer(self.logs_df)
        enhanced_features, feature_names, all_ips = optimizer.advanced_ip_preprocessing()
        
        ip_to_index = {ip: i for i, ip in enumerate(all_ips)}
        enhanced_ip_features = np.zeros((len(self.ip_features), enhanced_features.shape[1]))
        
        all_source_dest_ips = np.concatenate([self.source_ips, self.dest_ips])
        for i, ip in enumerate(all_source_dest_ips):
            if ip in ip_to_index:
                enhanced_ip_features[i] = enhanced_features[ip_to_index[ip]]
        
        self.ip_features = np.hstack([self.ip_features, enhanced_ip_features])
        
        scaler = StandardScaler()
        self.ip_features_scaled = scaler.fit_transform(self.ip_features)
        
        print(f"Enhanced preprocessing complete. Feature matrix shape: {self.ip_features.shape}")
        
    def evaluate_kmeans_clustering(self, n_iter: int = 10):
        """
        Evaluate KMeans clustering with hyperparameter tuning.
        
        Args:
            n_iter: Number of iterations for randomized parameter search
        """
        print("Evaluating KMeans clustering with hyperparameter tuning...")
        
        param_grid = {
            'n_clusters': list(range(3, min(20, len(self.ip_features) // 5))),
            'init': ['k-means++', 'random'],
            'n_init': [10, 'auto'],
            'random_state': [42]
        }
        
        all_params = list(ParameterGrid(param_grid))
        np.random.seed(42)
        selected_params = np.random.choice(all_params, min(n_iter, len(all_params)), replace=False)
        
        best_score = -1
        best_model = None
        best_params = {}
        best_labels = None
        total_time = 0
        
        for params in selected_params:
            start_time = time.time()
            kmeans = KMeans(**params)
            labels = kmeans.fit_predict(self.ip_features_scaled)
            elapsed = time.time() - start_time
            total_time += elapsed
            
            unique_labels = set(labels)
            if len(unique_labels) <= 1 or (len(unique_labels) == 2 and -1 in unique_labels):
                continue
            
            try:
                score = silhouette_score(self.ip_features_scaled, labels)
                
                if score > best_score:
                    best_score = score
                    best_model = kmeans
                    best_params = params
                    best_labels = labels
                    
                print(f"KMeans {params}: silhouette={score:.4f}, time={elapsed:.2f}s")
            except:
                pass
        
        self.results["kmeans"] = {
            "model": best_model,
            "clusters": best_labels,
            "params": best_params,
            "score": best_score,
            "runtime": total_time
        }
        
        print(f"Best KMeans model: {best_params}")
        print(f"Best silhouette score: {best_score:.4f}")
        
    def evaluate_dbscan_clustering(self, n_iter: int = 10):
        """
        Evaluate DBSCAN clustering with hyperparameter tuning.
        
        Args:
            n_iter: Number of iterations for randomized parameter search
        """
        print("Evaluating DBSCAN clustering with hyperparameter tuning...")
        
        param_grid = {
            'eps': np.linspace(0.1, 2.0, 20),
            'min_samples': list(range(2, 15)),
            'metric': ['euclidean', 'manhattan']
        }
        
        all_params = list(ParameterGrid(param_grid))
        np.random.seed(42)
        selected_params = np.random.choice(all_params, min(n_iter, len(all_params)), replace=False)
        
        best_score = -1
        best_model = None
        best_params = {}
        best_labels = None
        total_time = 0
        
        for params in selected_params:
            start_time = time.time()
            dbscan = DBSCAN(**params)
            labels = dbscan.fit_predict(self.ip_features_scaled)
            elapsed = time.time() - start_time
            total_time += elapsed
            
            if np.all(labels == -1):
                continue
            
            try:
                mask = labels != -1
                if np.sum(mask) > 1:
                    score = silhouette_score(self.ip_features_scaled[mask], labels[mask])
                    
                    if score > best_score:
                        best_score = score
                        best_model = dbscan
                        best_params = params
                        best_labels = labels
                        
                    print(f"DBSCAN {params}: silhouette={score:.4f}, time={elapsed:.2f}s")
            except:
                pass
        
        self.results["dbscan"] = {
            "model": best_model,
            "clusters": best_labels,
            "params": best_params,
            "score": best_score,
            "runtime": total_time
        }
        
        print(f"Best DBSCAN model: {best_params}")
        print(f"Best silhouette score: {best_score:.4f}")
        
    def evaluate_hdbscan_clustering(self, n_iter: int = 10):
        """
        Evaluate HDBSCAN clustering with hyperparameter tuning.
        
        Args:
            n_iter: Number of iterations for randomized parameter search
        """
        if not HDBSCAN_AVAILABLE:
            print("HDBSCAN not available. Skipping HDBSCAN evaluation.")
            return
            
        print("Evaluating HDBSCAN clustering with hyperparameter tuning...")
        
        param_grid = {
            'min_cluster_size': list(range(2, 15)),
            'min_samples': list(range(1, 10)),
            'cluster_selection_method': ['eom', 'leaf'],
            'metric': ['euclidean', 'manhattan']
        }
        
        all_params = list(ParameterGrid(param_grid))
        np.random.seed(42)
        selected_params = np.random.choice(all_params, min(n_iter, len(all_params)), replace=False)
        
        best_score = -1
        best_model = None
        best_params = {}
        best_labels = None
        total_time = 0
        
        for params in selected_params:
            start_time = time.time()
            hdb = hdbscan.HDBSCAN(**params)
            labels = hdb.fit_predict(self.ip_features_scaled)
            elapsed = time.time() - start_time
            total_time += elapsed
            
            if np.all(labels == -1):
                continue
            
            try:
                mask = labels != -1
                if np.sum(mask) > 1:
                    score = silhouette_score(self.ip_features_scaled[mask], labels[mask])
                    
                    if score > best_score:
                        best_score = score
                        best_model = hdb
                        best_params = params
                        best_labels = labels
                        
                    print(f"HDBSCAN {params}: silhouette={score:.4f}, time={elapsed:.2f}s")
            except:
                pass
        
        self.results["hdbscan"] = {
            "model": best_model,
            "clusters": best_labels,
            "params": best_params,
            "score": best_score,
            "runtime": total_time
        }
        
        print(f"Best HDBSCAN model: {best_params}")
        print(f"Best silhouette score: {best_score:.4f}")
        
    def _generate_rules_from_clusters(self, labels, algorithm_name: str) -> List[Dict[str, Any]]:
        """
        Generate firewall rules from clustering results.
        
        Args:
            labels: Cluster labels
            algorithm_name: Name of the clustering algorithm
            
        Returns:
            List of rule dictionaries with 100% log coverage
        """
        if labels is None:
            return []
            
        ip_to_cluster = {}
        all_ips = np.concatenate([self.source_ips, self.dest_ips])
        
        for i, ip in enumerate(all_ips):
            if i < len(labels):
                ip_to_cluster[ip] = labels[i]
        
        cluster_ips = {}
        noise_ips = []
        
        for ip, cluster in ip_to_cluster.items():
            if cluster == -1:  # Collect noise points separately
                noise_ips.append(ip)
                continue
                
            if cluster not in cluster_ips:
                cluster_ips[cluster] = []
                
            cluster_ips[cluster].append(ip)
        
        rules = []
        covered_logs = set()
        
        for cluster, ips in cluster_ips.items():
            source_ips_in_cluster = [ip for ip in ips if ip in self.source_ips]
            dest_ips_in_cluster = [ip for ip in ips if ip in self.dest_ips]
            
            if not source_ips_in_cluster and not dest_ips_in_cluster:
                continue
            
            if source_ips_in_cluster and not dest_ips_in_cluster:
                dest_ips_in_cluster = list(self.dest_ips)
                
            if dest_ips_in_cluster and not source_ips_in_cluster:
                source_ips_in_cluster = list(self.source_ips)
            
            cluster_logs = self.logs_df[
                self.logs_df['source.ip'].isin(source_ips_in_cluster) & 
                self.logs_df['destination.ip'].isin(dest_ips_in_cluster)
            ]
            
            if len(cluster_logs) == 0:
                continue
            
            for idx in cluster_logs.index:
                covered_logs.add(idx)
            
            ports = cluster_logs['destination.port'].unique()
            
            from ip_utils import group_ips_into_networks, ports_to_services
            
            source_cidrs = group_ips_into_networks(source_ips_in_cluster)
            dest_cidrs = group_ips_into_networks(dest_ips_in_cluster)
            services = ports_to_services(ports)
            
            rule = {
                'source_address': source_cidrs,
                'destination_address': dest_cidrs,
                'service': services,
                'log_count': len(cluster_logs),
                'cluster': int(cluster),
                'algorithm': algorithm_name
            }
            
            rules.append(rule)
        
        if noise_ips:
            noise_source_ips = [ip for ip in noise_ips if ip in self.source_ips]
            noise_dest_ips = [ip for ip in noise_ips if ip in self.dest_ips]
            
            if noise_source_ips or noise_dest_ips:
                if noise_source_ips and not noise_dest_ips:
                    noise_dest_ips = list(self.dest_ips)
                    
                if noise_dest_ips and not noise_source_ips:
                    noise_source_ips = list(self.source_ips)
                
                noise_logs = self.logs_df[
                    self.logs_df['source.ip'].isin(noise_source_ips) & 
                    self.logs_df['destination.ip'].isin(noise_dest_ips)
                ]
                
                if len(noise_logs) > 0:
                    for idx in noise_logs.index:
                        covered_logs.add(idx)
                    
                    ports = noise_logs['destination.port'].unique()
                    
                    from ip_utils import group_ips_into_networks, ports_to_services
                    
                    source_cidrs = group_ips_into_networks(noise_source_ips)
                    dest_cidrs = group_ips_into_networks(noise_dest_ips)
                    services = ports_to_services(ports)
                    
                    rule = {
                        'source_address': source_cidrs,
                        'destination_address': dest_cidrs,
                        'service': services,
                        'log_count': len(noise_logs),
                        'cluster': -1,  # Noise cluster
                        'algorithm': f"{algorithm_name}_noise"
                    }
                    
                    rules.append(rule)
        
        uncovered_logs = self.logs_df.loc[~self.logs_df.index.isin(covered_logs)]
        
        if len(uncovered_logs) > 0:
            uncovered_src_ips = uncovered_logs['source.ip'].unique()
            uncovered_dst_ips = uncovered_logs['destination.ip'].unique()
            ports = uncovered_logs['destination.port'].unique()
            
            from ip_utils import group_ips_into_networks, ports_to_services
            
            source_cidrs = group_ips_into_networks(list(uncovered_src_ips))
            dest_cidrs = group_ips_into_networks(list(uncovered_dst_ips))
            services = ports_to_services(ports)
            
            rule = {
                'source_address': source_cidrs,
                'destination_address': dest_cidrs,
                'service': services,
                'log_count': len(uncovered_logs),
                'cluster': -999,  # Special marker for catch-all
                'algorithm': f"{algorithm_name}_catchall"
            }
            
            rules.append(rule)
        
        rules.sort(key=lambda x: x['log_count'], reverse=True)
        
        total_logs_covered = sum(rule['log_count'] for rule in rules)
        coverage_percentage = (total_logs_covered / len(self.logs_df)) * 100
        
        print(f"{algorithm_name} rules cover {coverage_percentage:.2f}% of logs ({total_logs_covered}/{len(self.logs_df)})")
        
        return rules
        
    def generate_rules_from_kmeans(self) -> List[Dict[str, Any]]:
        """
        Generate firewall rules from KMeans clustering results.
        
        Returns:
            List of rule dictionaries
        """
        if "kmeans" not in self.results or self.results["kmeans"]["clusters"] is None:
            return []
            
        return self._generate_rules_from_clusters(
            self.results["kmeans"]["clusters"],
            "kmeans"
        )
        
    def generate_rules_from_dbscan(self) -> List[Dict[str, Any]]:
        """
        Generate firewall rules from DBSCAN clustering results.
        
        Returns:
            List of rule dictionaries
        """
        if "dbscan" not in self.results or self.results["dbscan"]["clusters"] is None:
            return []
            
        return self._generate_rules_from_clusters(
            self.results["dbscan"]["clusters"],
            "dbscan"
        )
        
    def generate_rules_from_hdbscan(self) -> List[Dict[str, Any]]:
        """
        Generate firewall rules from HDBSCAN clustering results.
        
        Returns:
            List of rule dictionaries
        """
        if not HDBSCAN_AVAILABLE or "hdbscan" not in self.results or self.results["hdbscan"]["clusters"] is None:
            return []
            
        return self._generate_rules_from_clusters(
            self.results["hdbscan"]["clusters"],
            "hdbscan"
        )
        
    def generate_ensemble_rules(self) -> List[Dict[str, Any]]:
        """
        Generate ensemble rules by combining results from multiple clustering algorithms.
        Ensures 100% log coverage by including all rules from each algorithm.
        
        Returns:
            List of rule dictionaries with 100% log coverage
        """
        all_rules = []
        
        kmeans_rules = self.generate_rules_from_kmeans()
        if kmeans_rules:
            all_rules.extend(kmeans_rules)
            
        dbscan_rules = self.generate_rules_from_dbscan()
        if dbscan_rules:
            all_rules.extend(dbscan_rules)
            
        hdbscan_rules = self.generate_rules_from_hdbscan()
        if hdbscan_rules:
            all_rules.extend(hdbscan_rules)
            
        if not all_rules:
            from ip_utils import group_ips_into_networks, ports_to_services
            
            source_cidrs = group_ips_into_networks(list(self.source_ips))
            dest_cidrs = group_ips_into_networks(list(self.dest_ips))
            ports = self.logs_df['destination.port'].unique()
            services = ports_to_services(ports)
            
            rule = {
                'source_address': source_cidrs,
                'destination_address': dest_cidrs,
                'service': services,
                'log_count': len(self.logs_df),
                'cluster': 0,
                'algorithm': "ensemble_fallback",
                'ensemble': True
            }
            
            return [rule]
            
        all_rules.sort(key=lambda x: x['log_count'], reverse=True)
        
        for rule in all_rules:
            rule['ensemble'] = True
        
        total_logs_covered = sum(rule['log_count'] for rule in all_rules)
        coverage_percentage = (total_logs_covered / len(self.logs_df)) * 100
        
        print(f"Ensemble rules cover {coverage_percentage:.2f}% of logs ({total_logs_covered}/{len(self.logs_df)})")
        
        return all_rules
        
    def visualize_clustering_results(self, algorithm: str, output_dir: str) -> Dict[str, str]:
        """
        Generate visualizations for clustering results.
        
        Args:
            algorithm: Algorithm name ('kmeans' or 'dbscan')
            output_dir: Directory to save visualizations
            
        Returns:
            Dictionary with visualization file paths
        """
        import os
        import matplotlib.pyplot as plt
        from sklearn.decomposition import PCA
        
        if algorithm not in self.results or self.results[algorithm]["clusters"] is None:
            return {}
            
        os.makedirs(output_dir, exist_ok=True)
        
        pca = PCA(n_components=2)
        reduced_features = pca.fit_transform(self.ip_features_scaled)
        
        labels = self.results[algorithm]["clusters"]
        
        plt.figure(figsize=(10, 8))
        
        unique_labels = set(labels)
        colors = plt.cm.rainbow(np.linspace(0, 1, len(unique_labels)))
        
        for label, color in zip(unique_labels, colors):
            if label == -1:
                color = [0, 0, 0, 1]
                
            mask = labels == label
            plt.scatter(
                reduced_features[mask, 0],
                reduced_features[mask, 1],
                c=[color],
                label=f"Cluster {label}" if label != -1 else "Noise"
            )
            
        plt.title(f"{algorithm.upper()} Clustering Results")
        plt.xlabel("PCA Component 1")
        plt.ylabel("PCA Component 2")
        plt.legend()
        plt.grid(True, linestyle='--', alpha=0.7)
        
        vis_file = os.path.join(output_dir, f"{algorithm}_clustering.png")
        plt.savefig(vis_file)
        plt.close()
        
        return {
            "clustering": vis_file
        }
        
    def visualize_hdbscan_results(self, output_dir: str) -> Dict[str, str]:
        """
        Generate visualizations for HDBSCAN clustering results.
        
        Args:
            output_dir: Directory to save visualizations
            
        Returns:
            Dictionary with visualization file paths
        """
        if not HDBSCAN_AVAILABLE or "hdbscan" not in self.results or self.results["hdbscan"]["clusters"] is None:
            return {}
            
        return self.visualize_clustering_results("hdbscan", output_dir)
