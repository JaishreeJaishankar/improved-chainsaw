# Fine-Tuning Layer for Firewall Rules

This document explains the fine-tuning layer implemented for optimizing single firewall rules.

## Overview

The fine-tuning layer provides an additional optimization step for single aggregated firewall rules. It analyzes traffic patterns to identify more specific CIDR blocks that still cover the necessary traffic while minimizing unnecessary permissions, effectively reducing the permission boundary.

## Features

1. **Traffic Pattern Analysis**: Analyzes source and destination IP frequency and subnet patterns
2. **Subnet Efficiency Calculation**: Determines the most efficient subnets to include in rules
3. **Configurable CIDR Limits**: Allows users to specify maximum number of source and destination CIDRs
4. **Improvement Metrics**: Provides detailed metrics on address space reduction

## Usage

### Command-Line Arguments

The following command-line arguments have been added to `main.py`:

```
--fine-tune          Apply fine-tuning to the single optimized rule
--max-src-cidrs      Maximum number of source CIDRs for fine-tuning (default: 5)
--max-dst-cidrs      Maximum number of destination CIDRs for fine-tuning (default: 5)
```

### Example Usage

```bash
# Basic fine-tuning with default parameters
python main.py --log-file firewall_logs_min.csv --output-dir output --fine-tune

# Fine-tuning with custom CIDR limits
python main.py --log-file firewall_logs_min.csv --output-dir output --fine-tune --max-src-cidrs 3 --max-dst-cidrs 3
```

## Technical Details

### Fine-Tuning Algorithm

The fine-tuning algorithm works as follows:

1. **Group IPs by Subnet**: Analyzes IP addresses to identify common subnet patterns
2. **Calculate Traffic Coverage**: Determines how much traffic each subnet covers
3. **Calculate Subnet Efficiency**: Computes efficiency as traffic coverage divided by subnet size
4. **Select Optimal Subnets**: Chooses the most efficient subnets up to the specified limits
5. **Handle Uncovered IPs**: Ensures all original IPs are covered by adding additional CIDRs if needed

### Efficiency Calculation

The efficiency of a subnet is calculated as:

```
efficiency = traffic_coverage / subnet_size
```

Where:
- `traffic_coverage` is the sum of traffic counts for IPs in the subnet
- `subnet_size` is the number of IP addresses in the subnet

Higher efficiency values indicate subnets that cover more actual traffic with fewer unused IP addresses.

### Improvement Metrics

The fine-tuning layer provides the following improvement metrics:

- **Original Source/Destination CIDRs**: Number of CIDRs in the original rule
- **Fine-Tuned Source/Destination CIDRs**: Number of CIDRs in the fine-tuned rule
- **Source Address Space Reduction**: Percentage reduction in source address space
- **Destination Address Space Reduction**: Percentage reduction in destination address space
- **Overall Reduction**: Average of source and destination address space reductions

## Integration with Other Features

The fine-tuning layer can be combined with other optimization features:

```bash
# Combine with CIDR merging
python main.py --log-file firewall_logs_min.csv --output-dir output --fine-tune --merge-cidrs

# Combine with ML-based rules
python main.py --log-file firewall_logs_min.csv --output-dir output --fine-tune --ml-rules
```

## API Reference

### Key Functions

- `fine_tune_single_rule(logs_df, single_rule, max_src_cidrs, max_dst_cidrs)`: Applies fine-tuning to a single optimized rule
- `fine_tune_cidrs(ips, ip_counts, max_cidrs)`: Fine-tunes a list of CIDRs based on IP frequency
- `analyze_rule_improvement(original_rule, fine_tuned_rule)`: Calculates improvement metrics

### FirewallAnalyzer Integration

The `optimize_single_rule` method in the `FirewallAnalyzer` class has been updated to support fine-tuning:

```python
def optimize_single_rule(self, fine_tune=False, max_src_cidrs=5, max_dst_cidrs=5, 
                       merge_cidrs=False, min_efficiency=0.7, interactive=False):
    # ... existing code ...
    
    if fine_tune:
        fine_tuned_rule = fine_tune_single_rule(
            self.logs_df, 
            single_rule, 
            max_src_cidrs=max_src_cidrs, 
            max_dst_cidrs=max_dst_cidrs
        )
        
        # Analyze improvement
        improvement = analyze_rule_improvement(single_rule, fine_tuned_rule)
        fine_tuned_rule["improvement"] = improvement
        
        rule_to_use = fine_tuned_rule
    else:
        rule_to_use = single_rule
    
    # ... rest of the method ...
```

## Example Results

Here's an example of the improvement achieved by fine-tuning:

**Original Rule:**
```
Source CIDRs: 192.168.0.0/22
Destination CIDRs: 10.0.0.0/22
Service(s): http, https, ssh, mysql, custom-ports-8080
```

**Fine-Tuned Rule:**
```
Source CIDRs: 192.168.1.0/24, 192.168.2.0/24, 192.168.3.0/24
Destination CIDRs: 10.0.0.0/24, 10.0.1.0/24, 10.0.2.0/24
Service(s): http, https, ssh, mysql, custom-ports-8080
```

**Improvement Metrics:**
```
Source Address Space Reduction: 50.00%
Destination Address Space Reduction: 25.00%
Overall Address Space Reduction: 37.50%
```

This example shows how fine-tuning can significantly reduce the address space covered by the rule while still permitting all necessary traffic.
