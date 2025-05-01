
import argparse
import os
import time
import psutil
from data_loader import load_logs
from large_scale_processor import LargeScaleProcessor

def main():
    parser = argparse.ArgumentParser(description="Memory-efficient firewall log analyzer for large datasets")
    parser.add_argument("--log-file", required=True, help="Path to CSV: source.ip, destination.ip, destination.port")
    parser.add_argument("--output-dir", default="output", help="Output directory")
    parser.add_argument("--html-report", action="store_true", help="Generate HTML report")
    parser.add_argument("--batch-size", type=int, default=5000, help="Number of logs to process in each batch")
    parser.add_argument("--sample-size", type=int, default=2000, help="Sample size for ML algorithms")
    parser.add_argument("--max-rules", type=int, default=10, help="Maximum number of rules to generate")
    parser.add_argument("--skip-ml", action="store_true", help="Skip ML rule generation for faster processing")
    args = parser.parse_args()
    
    os.makedirs(args.output_dir, exist_ok=True)
    
    start_time = time.time()
    start_memory = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
    
    print(f"Starting large-scale analysis of {args.log_file}")
    print(f"Initial memory usage: {start_memory:.2f} MB")
    
    processor = LargeScaleProcessor(
        log_file=args.log_file,
        output_dir=args.output_dir,
        batch_size=args.batch_size,
        sample_size=args.sample_size,
        max_rules=args.max_rules,
        skip_ml=args.skip_ml
    )
    
    total_logs = processor.process()
    
    if args.html_report:
        processor.generate_html_report()
    
    end_time = time.time()
    end_memory = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
    
    print(f"\nAnalysis Complete! Processed {total_logs} logs from {args.log_file}.")
    print(f"Processing time: {end_time - start_time:.2f} seconds")
    print(f"Peak memory usage: {processor.peak_memory:.2f} MB")
    print(f"Final memory usage: {end_memory:.2f} MB")
    print(f"Memory increase: {end_memory - start_memory:.2f} MB")
    print(f"Output saved to {args.output_dir}")

if __name__ == "__main__":
    main()
