import pandas as pd
from firewall_analyzer import FirewallAnalyzer
from cidr_merger import analyze_cidrs, suggest_cidr_merges, merge_cidrs, merge_rule_cidrs
import os

def test_cidr_merger():
    """
    Test the CIDR merging functionality.
    """
    data = [
        {"source.ip": "192.168.1.1", "destination.ip": "10.0.0.1", "destination.port": "80"},
        {"source.ip": "192.168.1.2", "destination.ip": "10.0.0.2", "destination.port": "443"},
        {"source.ip": "192.168.1.3", "destination.ip": "10.0.0.3", "destination.port": "22"},
        {"source.ip": "192.168.1.4", "destination.ip": "10.0.0.4", "destination.port": "3306"},
        
        {"source.ip": "192.168.2.1", "destination.ip": "10.0.1.1", "destination.port": "80"},
        {"source.ip": "192.168.2.2", "destination.ip": "10.0.1.2", "destination.port": "443"},
        {"source.ip": "192.168.2.3", "destination.ip": "10.0.1.3", "destination.port": "22"},
        {"source.ip": "192.168.2.4", "destination.ip": "10.0.1.4", "destination.port": "3306"},
        
        {"source.ip": "192.168.3.1", "destination.ip": "10.0.2.1", "destination.port": "80"},
        {"source.ip": "192.168.3.2", "destination.ip": "10.0.2.2", "destination.port": "443"},
    ]
    
    test_csv = "test_logs.csv"
    pd.DataFrame(data).to_csv(test_csv, index=False)
    
    try:
        print("Testing CIDR analysis and merging functions...")
        
        test_cidrs = ["192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24"]
        
        print("\nAnalyzing CIDRs:", ", ".join(test_cidrs))
        analysis = analyze_cidrs(test_cidrs)
        
        if "error" in analysis or "message" in analysis:
            print(f"Analysis result: {analysis.get('error', analysis.get('message'))}")
        else:
            print(f"Found {len(analysis['networks'])} networks")
            print(f"Found {len(analysis['overlaps'])} overlapping networks")
            print(f"Found {len(analysis['mergeable'])} potentially mergeable networks")
            
            if analysis['mergeable']:
                print("\nMergeable CIDRs:")
                for i, merge in enumerate(analysis['mergeable']):
                    print(f"{i+1}. {merge['cidr1']} + {merge['cidr2']} -> {merge['merged_cidr']} (Efficiency: {merge['efficiency']:.2f})")
                
                suggestions = suggest_cidr_merges(test_cidrs, min_efficiency=0.5)
                print(f"\nFound {len(suggestions)} merge suggestions with efficiency >= 0.5")
                
                merged_cidrs = merge_cidrs(test_cidrs, suggestions)
                print(f"\nMerged CIDRs: {', '.join(merged_cidrs)}")
        
        print("\nTesting CIDR merging through FirewallAnalyzer...")
        analyzer = FirewallAnalyzer(test_csv)
        
        regular_rule = analyzer.optimize_single_rule()
        print("\nRegular Single Rule:")
        print(f"  Source CIDRs: {regular_rule['source_address']}")
        print(f"  Destination CIDRs: {regular_rule['destination_address']}")
        
        merged_rule = analyzer.optimize_single_rule(merge_cidrs=True, min_efficiency=0.5)
        print("\nRule with CIDR Merging:")
        print(f"  Source CIDRs: {merged_rule['source_address']}")
        print(f"  Destination CIDRs: {merged_rule['destination_address']}")
        
        if 'merge_info' in merged_rule:
            merge_info = merged_rule['merge_info']
            print("\nMerge Info:")
            print(f"  Source CIDR Merges Applied: {merge_info['src_merges_applied']}")
            print(f"  Destination CIDR Merges Applied: {merge_info['dst_merges_applied']}")
        
        fine_tuned_merged_rule = analyzer.optimize_single_rule(
            fine_tune=True, 
            max_src_cidrs=3, 
            max_dst_cidrs=3,
            merge_cidrs=True, 
            min_efficiency=0.5
        )
        
        print("\nRule with Fine-Tuning and CIDR Merging:")
        print(f"  Source CIDRs: {fine_tuned_merged_rule['source_address']}")
        print(f"  Destination CIDRs: {fine_tuned_merged_rule['destination_address']}")
        
        if 'improvement' in fine_tuned_merged_rule:
            improvement = fine_tuned_merged_rule['improvement']
            print("\nImprovement Metrics:")
            print(f"  Source Address Space Reduction: {improvement['src_address_space_reduction']}")
            print(f"  Destination Address Space Reduction: {improvement['dst_address_space_reduction']}")
        
        if 'merge_info' in fine_tuned_merged_rule:
            merge_info = fine_tuned_merged_rule['merge_info']
            print("\nMerge Info:")
            print(f"  Source CIDR Merges Applied: {merge_info['src_merges_applied']}")
            print(f"  Destination CIDR Merges Applied: {merge_info['dst_merges_applied']}")
        
        print("\nCIDR merging test completed successfully!")
        
    finally:
        if os.path.exists(test_csv):
            os.remove(test_csv)

if __name__ == "__main__":
    test_cidr_merger()
