"""
Automated fine-tuning and optimization of ML-generated firewall rules.
This module provides functionality to:
1. Automatically fine-tune ML algorithm results
2. Combine rules from different algorithms intelligently
3. Apply advanced preprocessing techniques for IP data
"""

import pandas as pd
import numpy as np
import ipaddress
from typing import Dict, List, Any, Tuple, Set
from ip_utils import group_ips_into_networks, ports_to_services
from cidr_merger import merge_cidrs


class MLResultOptimizer:
    """
    Automatically optimizes and fine-tunes ML-generated firewall rules.
    Provides methods to combine rules from different algorithms and
    apply advanced preprocessing techniques.
    """
    
    def __init__(self, logs_df: pd.DataFrame):
        """
        Initialize with logs DataFrame containing source.ip, destination.ip, destination.port.
        
        Args:
            logs_df: DataFrame with firewall logs
        """
        self.logs_df = logs_df
        self.source_ips = set(logs_df['source.ip'].unique())
        self.dest_ips = set(logs_df['destination.ip'].unique())
        self.ports = set(logs_df['destination.port'].unique())
        
    def combine_ml_rules(self, ml_rules: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """
        Intelligently combine rules from different ML algorithms.
        
        Args:
            ml_rules: Dictionary mapping algorithm names to lists of rule dictionaries
            
        Returns:
            List of optimized rule dictionaries
        """
        print("Combining ML rules from different algorithms...")
        
        all_rules = []
        for algorithm, rules in ml_rules.items():
            for rule in rules:
                rule['original_algorithm'] = algorithm
                all_rules.append(rule)
        
        all_rules.sort(key=lambda x: x['log_count'], reverse=True)
        
        covered_logs = set()
        optimized_rules = []
        
        for rule in all_rules:
            source_cidrs = rule['source_address']
            dest_cidrs = rule['destination_address']
            services = rule['service']
            
            source_ips = self._expand_cidrs_to_ips(source_cidrs)
            dest_ips = self._expand_cidrs_to_ips(dest_cidrs)
            
            rule_logs = self.logs_df[
                self.logs_df['source.ip'].isin(source_ips) & 
                self.logs_df['destination.ip'].isin(dest_ips)
            ]
            
            new_logs = set(rule_logs.index) - covered_logs
            
            if new_logs:
                new_rule_logs = self.logs_df.loc[list(new_logs)]
                
                new_source_ips = set(new_rule_logs['source.ip'].unique())
                new_dest_ips = set(new_rule_logs['destination.ip'].unique())
                new_ports = set(new_rule_logs['destination.port'].unique())
                
                new_source_cidrs = group_ips_into_networks(list(new_source_ips))
                new_dest_cidrs = group_ips_into_networks(list(new_dest_ips))
                new_services = ports_to_services(list(new_ports))
                
                optimized_rule = {
                    'source_address': new_source_cidrs,
                    'destination_address': new_dest_cidrs,
                    'service': new_services,
                    'log_count': len(new_logs),
                    'original_algorithm': rule['original_algorithm'],
                    'algorithm': 'optimized'
                }
                
                optimized_rules.append(optimized_rule)
                covered_logs.update(new_logs)
        
        if len(covered_logs) < len(self.logs_df):
            uncovered_logs = self.logs_df.loc[~self.logs_df.index.isin(covered_logs)]
            
            uncovered_src_ips = uncovered_logs['source.ip'].unique()
            uncovered_dst_ips = uncovered_logs['destination.ip'].unique()
            uncovered_ports = uncovered_logs['destination.port'].unique()
            
            uncovered_source_cidrs = group_ips_into_networks(list(uncovered_src_ips))
            uncovered_dest_cidrs = group_ips_into_networks(list(uncovered_dst_ips))
            uncovered_services = ports_to_services(list(uncovered_ports))
            
            catchall_rule = {
                'source_address': uncovered_source_cidrs,
                'destination_address': uncovered_dest_cidrs,
                'service': uncovered_services,
                'log_count': len(uncovered_logs),
                'original_algorithm': 'catchall',
                'algorithm': 'optimized_catchall'
            }
            
            optimized_rules.append(catchall_rule)
        
        optimized_rules = self.apply_cidr_merging(optimized_rules)
        
        print(f"Combined {len(all_rules)} rules into {len(optimized_rules)} optimized rules")
        
        return optimized_rules
    
    def apply_cidr_merging(self, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Apply CIDR merging to optimize rules further.
        
        Args:
            rules: List of rule dictionaries
            
        Returns:
            List of optimized rule dictionaries with merged CIDRs
        """
        for rule in rules:
            if len(rule['source_address']) > 1:
                rule['source_address'] = merge_cidrs(rule['source_address'])
            
            if len(rule['destination_address']) > 1:
                rule['destination_address'] = merge_cidrs(rule['destination_address'])
        
        return rules
    
    def _expand_cidrs_to_ips(self, cidrs: List[str]) -> Set[str]:
        """
        Expand CIDR notation to individual IP addresses.
        
        Args:
            cidrs: List of CIDR strings
            
        Returns:
            Set of individual IP addresses
        """
        ips = set()
        
        for cidr in cidrs:
            try:
                if cidr.endswith('/32'):
                    ips.add(cidr.split('/')[0])
                    continue
                
                network = ipaddress.ip_network(cidr, strict=False)
                
                if network.num_addresses <= 256:
                    for ip in network:
                        ips.add(str(ip))
                else:
                    for ip in self.source_ips.union(self.dest_ips):
                        try:
                            if ipaddress.ip_address(ip) in network:
                                ips.add(ip)
                        except ValueError:
                            continue
            except ValueError:
                continue
        
        return ips
    
    def advanced_ip_preprocessing(self) -> Tuple[np.ndarray, List[str]]:
        """
        Apply advanced preprocessing techniques for IP addresses.
        
        Returns:
            Tuple of (feature matrix, feature names)
        """
        print("Applying advanced IP preprocessing...")
        
        all_ips = list(self.source_ips.union(self.dest_ips))
        
        features = []
        feature_names = []
        
        network_classes = []
        for ip in all_ips:
            try:
                first_octet = int(ip.split('.')[0])
                if first_octet < 128:
                    network_classes.append('A')
                elif first_octet < 192:
                    network_classes.append('B')
                elif first_octet < 224:
                    network_classes.append('C')
                else:
                    network_classes.append('D_or_E')
            except:
                network_classes.append('Unknown')
        
        from sklearn.preprocessing import OneHotEncoder
        encoder = OneHotEncoder(sparse_output=False)
        network_class_features = encoder.fit_transform(np.array(network_classes).reshape(-1, 1))
        
        features.append(network_class_features)
        feature_names.extend([f'network_class_{c}' for c in encoder.categories_[0]])
        
        subnet_features = []
        for ip in all_ips:
            try:
                octets = ip.split('.')
                subnet_features.append([
                    int(octets[0]),
                    int(octets[1]),
                    int(octets[2])
                ])
            except:
                subnet_features.append([0, 0, 0])
        
        subnet_features = np.array(subnet_features)
        
        from sklearn.preprocessing import MinMaxScaler
        scaler = MinMaxScaler()
        subnet_features = scaler.fit_transform(subnet_features)
        
        features.append(subnet_features)
        feature_names.extend(['first_octet', 'second_octet', 'third_octet'])
        
        private_ip_features = []
        for ip in all_ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                private_ip_features.append(1 if ip_obj.is_private else 0)
            except:
                private_ip_features.append(0)
        
        private_ip_features = np.array(private_ip_features).reshape(-1, 1)
        
        features.append(private_ip_features)
        feature_names.append('is_private')
        
        ip_to_index = {ip: i for i, ip in enumerate(all_ips)}
        
        source_counts = self.logs_df['source.ip'].value_counts()
        source_freq = np.zeros(len(all_ips))
        
        for ip, count in source_counts.items():
            if ip in ip_to_index:
                source_freq[ip_to_index[ip]] = count
        
        source_freq = source_freq / source_freq.max() if source_freq.max() > 0 else source_freq
        source_freq = source_freq.reshape(-1, 1)
        
        features.append(source_freq)
        feature_names.append('source_frequency')
        
        dest_counts = self.logs_df['destination.ip'].value_counts()
        dest_freq = np.zeros(len(all_ips))
        
        for ip, count in dest_counts.items():
            if ip in ip_to_index:
                dest_freq[ip_to_index[ip]] = count
        
        dest_freq = dest_freq / dest_freq.max() if dest_freq.max() > 0 else dest_freq
        dest_freq = dest_freq.reshape(-1, 1)
        
        features.append(dest_freq)
        feature_names.append('destination_frequency')
        
        combined_features = np.hstack(features)
        
        print(f"Generated {combined_features.shape[1]} features for {len(all_ips)} unique IPs")
        
        return combined_features, feature_names, all_ips
    
    def generate_optimized_rules(self, ml_rules: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Generate optimized rules using advanced techniques.
        
        Args:
            ml_rules: Dictionary mapping algorithm names to lists of rule dictionaries
            
        Returns:
            Dictionary with optimized rules and metadata
        """
        optimized_rules = self.combine_ml_rules(ml_rules)
        
        total_logs = len(self.logs_df)
        covered_logs = sum(rule['log_count'] for rule in optimized_rules)
        coverage_percentage = (covered_logs / total_logs) * 100
        
        print(f"Optimized rules cover {coverage_percentage:.2f}% of logs ({covered_logs}/{total_logs})")
        
        return {
            'rules': optimized_rules,
            'coverage': coverage_percentage,
            'rule_count': len(optimized_rules),
            'algorithm': 'ml_result_automation'
        }


def apply_ml_result_automation(logs_df: pd.DataFrame, ml_rules: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """
    Apply ML result automation to optimize firewall rules.
    
    Args:
        logs_df: DataFrame with firewall logs
        ml_rules: Dictionary mapping algorithm names to lists of rule dictionaries
        
    Returns:
        Dictionary with optimized rules and metadata
    """
    optimizer = MLResultOptimizer(logs_df)
    return optimizer.generate_optimized_rules(ml_rules)
