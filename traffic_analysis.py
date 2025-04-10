# traffic_analysis.py
from typing import Dict, Any
import pandas as pd

def analyze_traffic_patterns(logs_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Identifies top source IPs, top destination IPs, 
    and top destination ports. Also tracks top source->dest pairs.
    """
    patterns = {}
    patterns["top_source_ips"] = logs_df["source.ip"].value_counts().head(10).to_dict()
    patterns["top_destination_ips"] = logs_df["destination.ip"].value_counts().head(10).to_dict()
    patterns["top_destination_ports"] = logs_df["destination.port"].value_counts().head(10).to_dict()
    
    logs_df["src_dst_pair"] = logs_df["source.ip"] + " -> " + logs_df["destination.ip"]
    patterns["top_source_dest_pairs"] = logs_df["src_dst_pair"].value_counts().head(10).to_dict()
    return patterns

def identify_anomalies(logs_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Detects potential anomalies:
      - Unusual ports (not in a known set)
      - Low-occurrence source-destination pairs (count < 5)
    """
    anomalies = {}
    
    common_ports = {80, 443, 22, 3389, 21, 25, 53, 123, 161, 3306, 1433}
    unusual_df = logs_df[~logs_df["destination.port"].isin(common_ports)]
    if not unusual_df.empty:
        anomalies["unusual_ports"] = unusual_df["destination.port"].value_counts().head(10).to_dict()
    
    pair_counts = logs_df.groupby(["source.ip", "destination.ip"]).size().reset_index(name="count")
    low_occ = pair_counts[pair_counts["count"] < 5]
    if not low_occ.empty:
        anomalies["low_occurrence_pairs"] = low_occ.head(10).to_dict("records")
    
    return anomalies
