# data_loader.py
import pandas as pd

def load_logs(log_file: str) -> pd.DataFrame:
    """
    Load a CSV with exactly these columns:
      - source.ip
      - destination.ip
      - destination.port
    """
    print(f"Loading log data from {log_file}...")
    df = pd.read_csv(log_file)
    
    required_cols = {"source.ip", "destination.ip", "destination.port"}
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(f"Missing columns in {log_file}: {missing}")
    
    print(f"Loaded {len(df)} entries from {log_file}.")
    return df
