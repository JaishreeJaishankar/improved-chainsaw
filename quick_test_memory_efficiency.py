
import argparse
import os
import time
import psutil
import pandas as pd
import numpy as np
import random
import ipaddress
from typing import List, Dict, Any

def generate_sample_data(num_logs: int, output_file: str):
    """
    Generate sample log data for testing memory efficiency.
    """
    print(f"Generating {num_logs} sample log entries...")
    
    src_networks = [
        f"192.168.{random.randint(1, 10)}.0/24" for _ in range(5)
    ] + [
        f"10.{random.randint(1, 10)}.{random.randint(1, 10)}.0/24" for _ in range(5)
    ]
    
    dst_networks = [
        f"172.{random.randint(16, 31)}.{random.randint(1, 10)}.0/24" for _ in range(5)
    ] + [
        f"203.0.{random.randint(1, 10)}.0/24" for _ in range(5)
    ]
    
    common_ports = [80, 443, 22, 25, 53, 3389, 8080, 8443]
    
    src_ips = []
    for network in src_networks:
        net = ipaddress.ip_network(network)
        hosts = list(net.hosts())
        src_ips.extend([str(random.choice(hosts)) for _ in range(num_logs // 10)])
    
    dst_ips = []
    for network in dst_networks:
        net = ipaddress.ip_network(network)
        hosts = list(net.hosts())
        dst_ips.extend([str(random.choice(hosts)) for _ in range(num_logs // 10)])
    
    logs = []
    for _ in range(num_logs):
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(dst_ips)
        dst_port = random.choice(common_ports)
        logs.append({
            "source.ip": src_ip,
            "destination.ip": dst_ip,
            "destination.port": dst_port
        })
    
    df = pd.DataFrame(logs)
    df.to_csv(output_file, index=False)
    print(f"Sample data saved to {output_file}")
    return df

def test_memory_efficiency(logs_df: pd.DataFrame, batch_size: int = 1000):
    """
    Test memory efficiency by processing logs in batches.
    """
    print(f"Testing memory efficiency with {len(logs_df)} logs...")
    
    start_time = time.time()
    start_memory = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
    
    print(f"Initial memory usage: {start_memory:.2f} MB")
    
    total_logs = 0
    peak_memory = start_memory
    
    for i in range(0, len(logs_df), batch_size):
        batch_df = logs_df.iloc[i:i+batch_size]
        batch_size = len(batch_df)
        total_logs += batch_size
        
        _ = batch_df["source.ip"].nunique()
        _ = batch_df["destination.ip"].nunique()
        _ = batch_df["destination.port"].nunique()
        
        current_memory = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
        if current_memory > peak_memory:
            peak_memory = current_memory
        
        progress = (i + batch_size) / len(logs_df) * 100
        print(f"Batch {i//batch_size + 1}: Processed {batch_size} logs ({progress:.1f}% complete)")
        print(f"Current memory usage: {current_memory:.2f} MB")
        
        del batch_df
    
    end_time = time.time()
    end_memory = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
    
    print(f"\nTest Complete! Processed {total_logs} logs.")
    print(f"Processing time: {end_time - start_time:.2f} seconds")
    print(f"Peak memory usage: {peak_memory:.2f} MB")
    print(f"Final memory usage: {end_memory:.2f} MB")
    print(f"Memory increase: {end_memory - start_memory:.2f} MB")
    
    return {
        "total_logs": total_logs,
        "processing_time": end_time - start_time,
        "peak_memory": peak_memory,
        "memory_increase": end_memory - start_memory
    }

def main():
    parser = argparse.ArgumentParser(description="Quick test for memory efficiency")
    parser.add_argument("--generate", action="store_true", help="Generate sample data")
    parser.add_argument("--num-logs", type=int, default=5000, help="Number of logs to generate")
    parser.add_argument("--log-file", default="sample_logs.csv", help="Log file to use")
    parser.add_argument("--batch-size", type=int, default=1000, help="Batch size for processing")
    parser.add_argument("--html-report", action="store_true", help="Generate HTML report")
    args = parser.parse_args()
    
    if args.generate:
        logs_df = generate_sample_data(args.num_logs, args.log_file)
    else:
        print(f"Loading logs from {args.log_file}...")
        logs_df = pd.read_csv(args.log_file)
    
    results = test_memory_efficiency(logs_df, args.batch_size)
    
    if args.html_report:
        try:
            from report_generator import generate_memory_test_report
            report_file = "memory_test_report.html"
            generate_memory_test_report(report_file, results, args.log_file)
            print(f"HTML report saved to {report_file}")
        except ImportError:
            print("Warning: report_generator module not available. Skipping HTML report generation.")

if __name__ == "__main__":
    main()
