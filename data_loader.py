# data_loader.py
import pandas as pd

def load_logs(log_file: str) -> pd.DataFrame:
    print(f"Loading log data from {log_file}...")
    df = pd.read_csv(log_file)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    print(f"Loaded {len(df)} log entries.")
    return df

def load_rules(rule_file: str) -> pd.DataFrame:
    print(f"Loading rule data from {rule_file} (for validation only)...")
    df = pd.read_csv(rule_file)
    print(f"Loaded {len(df)} rules.")
    return df
