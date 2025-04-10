#!/usr/bin/env python3

import pandas as pd

def extract_minimal_fields(input_file: str, output_file: str):
    """
    Reads a CSV firewall log with fields:
        timestamp, source.ip, host.collector, destination.port, destination.ip,
        observer.egress.zone, observer.ingress.zone, rule.name
    and outputs a CSV containing only:
        source.ip, destination.ip, destination.port.
    """
    # Load the original log file
    df = pd.read_csv(input_file)
    
    # Filter only the columns we need
    required_columns = ["source.ip", "destination.ip", "destination.port"]
    df_filtered = df[required_columns]
    
    # Write the filtered data to a new CSV
    df_filtered.to_csv(output_file, index=False)
    print(f"Saved minimal CSV with columns {required_columns} to {output_file}")

if __name__ == "__main__":
    # Example usage
    extract_minimal_fields("firewall_logs.csv", "firewall_logs_min.csv")
