import pandas as pd
from firewall_analyzer import FirewallAnalyzer
from fine_tuning import fine_tune_single_rule, analyze_rule_improvement
import os

def test_fine_tuning():
    """
    Test the fine-tuning layer for single optimized rule.
    """
    data = [
        {"source.ip": "192.168.1.1", "destination.ip": "10.0.0.1", "destination.port": "80"},
        {"source.ip": "192.168.1.2", "destination.ip": "10.0.0.2", "destination.port": "443"},
        {"source.ip": "192.168.1.3", "destination.ip": "10.0.0.3", "destination.port": "22"},
        {"source.ip": "192.168.1.4", "destination.ip": "10.0.0.4", "destination.port": "3306"},
        {"source.ip": "192.168.1.5", "destination.ip": "10.0.0.5", "destination.port": "8080"},
        
        {"source.ip": "192.168.2.1", "destination.ip": "10.0.1.1", "destination.port": "80"},
        {"source.ip": "192.168.2.2", "destination.ip": "10.0.1.2", "destination.port": "443"},
        {"source.ip": "192.168.2.3", "destination.ip": "10.0.1.3", "destination.port": "22"},
        
        {"source.ip": "192.168.3.1", "destination.ip": "10.0.2.1", "destination.port": "80"},
        {"source.ip": "192.168.3.2", "destination.ip": "10.0.2.2", "destination.port": "443"},
    ]
    
    test_csv = "test_logs.csv"
    pd.DataFrame(data).to_csv(test_csv, index=False)
    
    try:
        print("Testing fine-tuning through FirewallAnalyzer...")
        analyzer = FirewallAnalyzer(test_csv)
        
        regular_rule = analyzer.optimize_single_rule(fine_tune=False)
        print("\nRegular Single Rule:")
        print(f"  Source CIDRs: {regular_rule['source_address']}")
        print(f"  Destination CIDRs: {regular_rule['destination_address']}")
        print(f"  Service(s): {regular_rule['service']}")
        
        fine_tuned_rule = analyzer.optimize_single_rule(fine_tune=True, max_src_cidrs=3, max_dst_cidrs=3)
        print("\nFine-Tuned Rule:")
        print(f"  Source CIDRs: {fine_tuned_rule['source_address']}")
        print(f"  Destination CIDRs: {fine_tuned_rule['destination_address']}")
        print(f"  Service(s): {fine_tuned_rule['service']}")
        
        if 'improvement' in fine_tuned_rule:
            improvement = fine_tuned_rule['improvement']
            print("\nImprovement Metrics:")
            print(f"  Source Address Space Reduction: {improvement['src_address_space_reduction']}")
            print(f"  Destination Address Space Reduction: {improvement['dst_address_space_reduction']}")
            print(f"  Overall Address Space Reduction: {improvement['overall_reduction']}")
        
        print("\nTesting fine_tune_single_rule function directly...")
        logs_df = pd.read_csv(test_csv)
        
        from rule_optimization import aggregate_single_rule
        single_rule = aggregate_single_rule(logs_df)
        
        fine_tuned = fine_tune_single_rule(logs_df, single_rule, max_src_cidrs=2, max_dst_cidrs=2)
        
        print("\nDirect Fine-Tuned Rule:")
        print(f"  Source CIDRs: {fine_tuned['source_address']}")
        print(f"  Destination CIDRs: {fine_tuned['destination_address']}")
        print(f"  Service(s): {fine_tuned['service']}")
        
        improvement = analyze_rule_improvement(single_rule, fine_tuned)
        print("\nDirect Improvement Metrics:")
        print(f"  Source Address Space Reduction: {improvement['src_address_space_reduction']}")
        print(f"  Destination Address Space Reduction: {improvement['dst_address_space_reduction']}")
        print(f"  Overall Address Space Reduction: {improvement['overall_reduction']}")
        
        print("\nFine-tuning test completed successfully!")
        
    finally:
        if os.path.exists(test_csv):
            os.remove(test_csv)

if __name__ == "__main__":
    test_fine_tuning()
