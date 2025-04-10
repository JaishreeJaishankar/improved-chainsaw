# stats.py
from typing import Dict, Any
import pandas as pd

def get_basic_stats(logs_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Returns basic statistics for logs containing:
    source.ip, destination.ip, destination.port
    """
    stats = {}
    stats["total_log_entries"] = len(logs_df)
    stats["unique_source_ips"] = logs_df["source.ip"].nunique()
    stats["unique_destination_ips"] = logs_df["destination.ip"].nunique()
    stats["unique_destination_ports"] = logs_df["destination.port"].nunique()
    return stats
