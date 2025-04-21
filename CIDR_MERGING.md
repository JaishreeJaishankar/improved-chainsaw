# CIDR Merging Functionality

This document explains the CIDR merging functionality implemented for optimizing firewall rules.

## Overview

The CIDR merging functionality allows users to review and merge CIDRs (Classless Inter-Domain Routing) after generating firewall rules. This helps in further optimizing the rules by reducing the number of CIDR blocks while maintaining the same IP address coverage.

## Features

1. **CIDR Analysis**: Analyzes a list of CIDRs to identify potential merging opportunities
2. **Automatic Merging**: Automatically merges CIDRs based on an efficiency threshold
3. **Interactive Merging**: Allows users to interactively select which CIDRs to merge
4. **Efficiency Calculation**: Calculates the efficiency of each potential merge to help users make informed decisions

## Usage

### Command-Line Arguments

The following command-line arguments have been added to `main.py`:

```
--merge-cidrs         Enable CIDR merging after optimization
--min-efficiency      Minimum efficiency threshold for CIDR merging (default: 0.7)
--interactive         Use interactive CIDR merging
```

### Example Usage

```bash
# Automatic CIDR merging with default efficiency threshold (0.7)
python main.py --log-file firewall_logs_min.csv --output-dir output --merge-cidrs

# Automatic CIDR merging with custom efficiency threshold
python main.py --log-file firewall_logs_min.csv --output-dir output --merge-cidrs --min-efficiency 0.5

# Interactive CIDR merging
python main.py --log-file firewall_logs_min.csv --output-dir output --merge-cidrs --interactive
```

### Interactive Mode

In interactive mode, the system will:

1. Analyze the source and destination CIDRs
2. Display potential merges with their efficiency metrics
3. Prompt the user to select which merges to apply
4. Apply the selected merges and display the updated rule

Example interactive session:

```
Analyzing Source CIDRs...
Found 3 source networks
Found 0 overlapping source networks
Found 2 potentially mergeable source networks

Suggested Source CIDR Merges:
1. Merge 192.168.1.0/24 and 192.168.2.0/24 into 192.168.0.0/23
   Efficiency: 1.00 (Original: 512 IPs, Merged: 512 IPs)

Enter the numbers of the source CIDR merges to apply (comma-separated), or 'all' for all, or 'none' to skip:
1

Updated Source CIDRs: 192.168.0.0/23, 192.168.3.0/24
```

## Technical Details

### Efficiency Calculation

The efficiency of a CIDR merge is calculated as:

```
efficiency = (original_size / merged_size)
```

Where:
- `original_size` is the total number of IP addresses in the original CIDRs
- `merged_size` is the number of IP addresses in the merged CIDR

An efficiency of 1.0 means the merge is perfect (no additional IP addresses are included). Lower values indicate that the merged CIDR includes IP addresses that weren't in the original CIDRs.

### Merging Algorithm

The CIDR merging algorithm:

1. Identifies adjacent networks that can be merged
2. Calculates the efficiency of each potential merge
3. Sorts potential merges by efficiency (highest first)
4. Applies merges based on the efficiency threshold or user selection

## Integration with Other Features

The CIDR merging functionality can be combined with other optimization features:

```bash
# Combine with fine-tuning
python main.py --log-file firewall_logs_min.csv --output-dir output --fine-tune --merge-cidrs

# Combine with ML-based rules
python main.py --log-file firewall_logs_min.csv --output-dir output --ml-rules --merge-cidrs
```

## API Reference

### Key Functions

- `analyze_cidrs(cidrs)`: Analyzes a list of CIDRs to identify potential merging opportunities
- `suggest_cidr_merges(cidrs, min_efficiency)`: Suggests CIDR merges based on efficiency threshold
- `merge_cidrs(cidrs, merges_to_apply)`: Applies specified merges to a list of CIDRs
- `interactive_cidr_merge(rule)`: Interactive CIDR merging for a firewall rule
- `merge_rule_cidrs(rule, min_efficiency)`: Automatically merges CIDRs in a firewall rule

### FirewallAnalyzer Integration

The `optimize_single_rule` method in the `FirewallAnalyzer` class has been updated to support CIDR merging:

```python
def optimize_single_rule(self, fine_tune=False, max_src_cidrs=5, max_dst_cidrs=5, 
                       merge_cidrs=False, min_efficiency=0.7, interactive=False):
    # ... existing code ...
    
    # Apply CIDR merging if requested
    if merge_cidrs:
        if interactive:
            merged_rule = interactive_cidr_merge(rule_to_use)
        else:
            merged_rule = merge_rule_cidrs(rule_to_use, min_efficiency)
        
        return merged_rule
    
    return rule_to_use
```
