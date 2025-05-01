import numpy as np
import pandas as pd
import time
from typing import Dict, List, Any, Tuple
from sklearn.metrics import silhouette_score, davies_bouldin_score, calinski_harabasz_score
import matplotlib.pyplot as plt
import seaborn as sns
import os

def calculate_ml_performance_metrics(
    algorithm: str,
    clusters,
    features,
    runtime: float,
    rule_count: int,
    covered_logs: int,
    total_logs: int
) -> Dict[str, Any]:
    """
    Calculate performance metrics for ML clustering algorithms.
    
    Args:
        algorithm: Algorithm name
        clusters: Cluster labels
        features: Feature matrix
        runtime: Algorithm runtime in seconds
        rule_count: Number of rules generated
        covered_logs: Number of logs covered by the rules
        total_logs: Total number of logs
        
    Returns:
        Dictionary with performance metrics
    """
    metrics = {
        "algorithm": algorithm,
        "runtime": round(runtime, 2),
        "rule_count": rule_count,
        "coverage": round(covered_logs / total_logs, 4) if total_logs > 0 else 0
    }
    
    try:
        mask = clusters != -1
        if np.sum(mask) > 1:
            metrics["silhouette"] = round(silhouette_score(features[mask], clusters[mask]), 4)
            
            try:
                metrics["davies_bouldin"] = round(davies_bouldin_score(features[mask], clusters[mask]), 4)
            except:
                metrics["davies_bouldin"] = None
            
            try:
                metrics["calinski_harabasz"] = round(calinski_harabasz_score(features[mask], clusters[mask]), 4)
            except:
                metrics["calinski_harabasz"] = None
            
            unique_clusters = np.unique(clusters[mask])
            metrics["cluster_count"] = len(unique_clusters)
            
            cluster_sizes = [np.sum(clusters == c) for c in unique_clusters]
            metrics["min_cluster_size"] = min(cluster_sizes)
            metrics["max_cluster_size"] = max(cluster_sizes)
            metrics["avg_cluster_size"] = round(np.mean(cluster_sizes), 2)
    except Exception as e:
        print(f"Error calculating metrics for {algorithm}: {str(e)}")
        metrics["silhouette"] = None
        metrics["davies_bouldin"] = None
        metrics["calinski_harabasz"] = None
        metrics["cluster_count"] = 0
        metrics["min_cluster_size"] = 0
        metrics["max_cluster_size"] = 0
        metrics["avg_cluster_size"] = 0
    
    return metrics

def compare_ml_techniques(metrics_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compare different ML techniques based on their performance metrics.
    
    Args:
        metrics_list: List of metrics dictionaries from different algorithms
        
    Returns:
        Dictionary with comparison results
    """
    if not metrics_list:
        return {}
    
    comparison = {
        "best_silhouette": {"algorithm": None, "value": -1},
        "best_davies_bouldin": {"algorithm": None, "value": float('inf')},
        "best_calinski_harabasz": {"algorithm": None, "value": -1},
        "fastest": {"algorithm": None, "value": float('inf')},
        "best_coverage": {"algorithm": None, "value": -1},
        "most_efficient": {"algorithm": None, "value": -1}
    }
    
    for metrics in metrics_list:
        algorithm = metrics["algorithm"]
        
        if metrics.get("silhouette") is not None and metrics["silhouette"] > comparison["best_silhouette"]["value"]:
            comparison["best_silhouette"]["algorithm"] = algorithm
            comparison["best_silhouette"]["value"] = metrics["silhouette"]
        
        if metrics.get("davies_bouldin") is not None and metrics["davies_bouldin"] < comparison["best_davies_bouldin"]["value"]:
            comparison["best_davies_bouldin"]["algorithm"] = algorithm
            comparison["best_davies_bouldin"]["value"] = metrics["davies_bouldin"]
        
        if metrics.get("calinski_harabasz") is not None and metrics["calinski_harabasz"] > comparison["best_calinski_harabasz"]["value"]:
            comparison["best_calinski_harabasz"]["algorithm"] = algorithm
            comparison["best_calinski_harabasz"]["value"] = metrics["calinski_harabasz"]
        
        if metrics["runtime"] < comparison["fastest"]["value"]:
            comparison["fastest"]["algorithm"] = algorithm
            comparison["fastest"]["value"] = metrics["runtime"]
        
        if metrics["coverage"] > comparison["best_coverage"]["value"]:
            comparison["best_coverage"]["algorithm"] = algorithm
            comparison["best_coverage"]["value"] = metrics["coverage"]
        
        efficiency = metrics["coverage"] / (metrics["runtime"] + 0.1)  # Add small constant to avoid division by zero
        if efficiency > comparison["most_efficient"]["value"]:
            comparison["most_efficient"]["algorithm"] = algorithm
            comparison["most_efficient"]["value"] = round(efficiency, 4)
    
    algorithm_scores = {}
    for metrics in metrics_list:
        algorithm = metrics["algorithm"]
        score = 0
        
        if metrics.get("silhouette") is not None and comparison["best_silhouette"]["value"] > 0:
            score += 0.3 * (metrics["silhouette"] / comparison["best_silhouette"]["value"])
        
        if metrics.get("davies_bouldin") is not None and metrics["davies_bouldin"] > 0:
            score += 0.2 * (comparison["best_davies_bouldin"]["value"] / metrics["davies_bouldin"])
        
        if comparison["best_coverage"]["value"] > 0:
            score += 0.3 * (metrics["coverage"] / comparison["best_coverage"]["value"])
        
        if metrics["runtime"] > 0:
            score += 0.2 * (comparison["fastest"]["value"] / metrics["runtime"])
        
        algorithm_scores[algorithm] = round(score, 4)
    
    if algorithm_scores:
        best_algorithm = max(algorithm_scores.items(), key=lambda x: x[1])
        comparison["best_overall"] = {
            "algorithm": best_algorithm[0],
            "score": best_algorithm[1],
            "all_scores": algorithm_scores
        }
    
    return comparison

def visualize_ml_performance(metrics_list: List[Dict[str, Any]], output_dir: str) -> Dict[str, str]:
    """
    Generate visualizations comparing ML algorithm performance.
    
    Args:
        metrics_list: List of metrics dictionaries from different algorithms
        output_dir: Directory to save visualizations
        
    Returns:
        Dictionary with paths to visualization files
    """
    if not metrics_list:
        return {}
    
    os.makedirs(output_dir, exist_ok=True)
    visualization_files = {}
    
    algorithms = [m["algorithm"] for m in metrics_list]
    runtimes = [m["runtime"] for m in metrics_list]
    coverages = [m["coverage"] for m in metrics_list]
    silhouettes = [m.get("silhouette", 0) for m in metrics_list]
    davies_bouldin = [m.get("davies_bouldin", 0) for m in metrics_list]
    
    df = pd.DataFrame({
        "Algorithm": algorithms,
        "Runtime (s)": runtimes,
        "Coverage": coverages,
        "Silhouette Score": silhouettes,
        "Davies-Bouldin Score": davies_bouldin
    })
    
    plt.figure(figsize=(10, 6))
    sns.barplot(x="Algorithm", y="Runtime (s)", data=df, hue="Algorithm", palette="viridis", legend=False)
    plt.title("Algorithm Runtime Comparison")
    plt.ylabel("Runtime (seconds)")
    plt.xticks(rotation=45)
    plt.tight_layout()
    runtime_file = os.path.join(output_dir, "algorithm_runtime_comparison.png")
    plt.savefig(runtime_file)
    plt.close()
    visualization_files["runtime_comparison"] = runtime_file
    
    plt.figure(figsize=(10, 6))
    sns.barplot(x="Algorithm", y="Coverage", data=df, hue="Algorithm", palette="magma", legend=False)
    plt.title("Algorithm Coverage Comparison")
    plt.ylabel("Coverage Ratio")
    plt.xticks(rotation=45)
    plt.tight_layout()
    coverage_file = os.path.join(output_dir, "algorithm_coverage_comparison.png")
    plt.savefig(coverage_file)
    plt.close()
    visualization_files["coverage_comparison"] = coverage_file
    
    plt.figure(figsize=(10, 6))
    sns.barplot(x="Algorithm", y="Silhouette Score", data=df, hue="Algorithm", palette="crest", legend=False)
    plt.title("Algorithm Silhouette Score Comparison")
    plt.ylabel("Silhouette Score")
    plt.xticks(rotation=45)
    plt.tight_layout()
    silhouette_file = os.path.join(output_dir, "algorithm_silhouette_comparison.png")
    plt.savefig(silhouette_file)
    plt.close()
    visualization_files["silhouette_comparison"] = silhouette_file
    
    plt.figure(figsize=(12, 8))
    
    metrics_df = df.copy()
    metrics_to_normalize = ["Runtime (s)", "Coverage", "Silhouette Score", "Davies-Bouldin Score"]
    
    for metric in metrics_to_normalize:
        if metric == "Runtime (s)" or metric == "Davies-Bouldin Score":
            max_val = metrics_df[metric].max()
            if max_val > 0:
                metrics_df[metric] = 1 - (metrics_df[metric] / max_val)
        else:
            max_val = metrics_df[metric].max()
            if max_val > 0:
                metrics_df[metric] = metrics_df[metric] / max_val
    
    from matplotlib.path import Path
    from matplotlib.spines import Spine
    from matplotlib.transforms import Affine2D
    
    categories = ["Runtime", "Coverage", "Silhouette", "Davies-Bouldin"]
    N = len(categories)
    
    angles = [n / float(N) * 2 * np.pi for n in range(N)]
    angles += angles[:1]  # Close the loop
    
    ax = plt.subplot(111, polar=True)
    
    plt.xticks(angles[:-1], categories)
    
    for i, algorithm in enumerate(algorithms):
        values = [
            metrics_df.loc[i, "Runtime (s)"],
            metrics_df.loc[i, "Coverage"],
            metrics_df.loc[i, "Silhouette Score"],
            metrics_df.loc[i, "Davies-Bouldin Score"]
        ]
        values += values[:1]  # Close the loop
        
        ax.plot(angles, values, linewidth=2, linestyle='solid', label=algorithm)
        ax.fill(angles, values, alpha=0.1)
    
    plt.legend(loc='upper right', bbox_to_anchor=(0.1, 0.1))
    plt.title("Algorithm Performance Comparison")
    
    radar_file = os.path.join(output_dir, "algorithm_radar_comparison.png")
    plt.savefig(radar_file)
    plt.close()
    visualization_files["radar_comparison"] = radar_file
    
    return visualization_files
