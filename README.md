# Firewall Rule Analyzer and Optimizer

A Python tool for analyzing Palo Alto Networks firewall logs and optimizing rule permissions.

## Overview

This tool helps security teams fine-tune firewall rules by analyzing traffic patterns, identifying anomalies, and providing recommendations to reduce permission boundaries. It processes firewall logs and rule definitions to generate comprehensive reports and visualizations.

## Features

- **Traffic Pattern Analysis**: Identifies patterns by time, source/destination, and zones
- **Anomaly Detection**: Flags unusual ports, low-occurrence connections, and after-hours traffic
- **Rule Optimization**: Recommends specific changes to reduce permission boundaries
- **IP Network Grouping**: Intelligently groups IPs into CIDR notations for cleaner rules
- **Service Mapping**: Maps ports to service names for better readability
- **Visualization**: Creates interactive charts and graphs of traffic patterns
- **Reporting**: Generates comprehensive HTML and JSON reports with actionable recommendations
- **Relationship-Based Rules**: Creates rules that respect source-destination relationships
- **Machine Learning Optimization**: Uses ML techniques to generate optimized rule sets
- **Fine-Tuning Layer**: Further optimizes single rules to reduce permission boundaries
- **CIDR Merging**: Interactive and automatic merging of CIDRs for cleaner rule sets

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/firewall-analyzer.git
cd firewall-analyzer

# Install required packages
pip install pandas numpy matplotlib seaborn networkx scikit-learn
```

## Usage

### Generate Sample Data and Run Analysis

```bash
python main.py --generate-sample --html-report
```

### Analyze Existing Log and Rule Files

```bash
python main.py --log-file your_logs.csv --rule-file your_rules.csv --html-report
```

### Command Line Arguments

- `--generate-sample`: Generate sample data for demonstration
- `--log-file`: Path to the firewall log file (CSV)
- `--rule-file`: Path to the firewall rule file (CSV)
- `--output-dir`: Directory to store output files
- `--html-report`: Generate HTML report with visualizations
- `--ml-rules`: Generate rules using machine learning techniques
- `--max-rules`: Maximum number of rules to generate (default: 15)
- `--fine-tune`: Apply fine-tuning to the single optimized rule
- `--max-src-cidrs`: Maximum number of source CIDRs for fine-tuning (default: 5)
- `--max-dst-cidrs`: Maximum number of destination CIDRs for fine-tuning (default: 5)
- `--merge-cidrs`: Enable CIDR merging for optimized rules
- `--min-efficiency`: Minimum efficiency threshold for CIDR merging (default: 0.7)
- `--interactive`: Enable interactive mode for CIDR merging

## Input File Formats

### Log File Format (CSV)

```
timestamp,source.ip,host.collector,destination.port,destination.ip,observer.egress.zone,observer.ingress.zone,rule.name
2025-04-07T10:01:15Z,192.168.1.10,fw-collector-01,443,172.217.160.78,external,internal,allow-web-https
```

### Rule File Format (CSV)

```
rule_name,hits,priority,description,recommended_action,source_zone,source_address,destination_zone,destination_address,application,service,url_category,action,profile_group,options,modified_date,created_date,risky_permissive,ingress_egress
allow-web-https,1250,1,Allow HTTPS traffic,None,internal,any,external,any,web-browsing,tcp/443,any,allow,default,None,2025-04-01,2025-01-01,permissive,ingress
```

## Output

The tool generates:

1. **Visualizations**: Charts and graphs showing traffic patterns
2. **JSON Report**: Detailed analysis in machine-readable format
3. **HTML Report**: Interactive report with visualizations and recommendations
4. **Optimized Rules**: Several types of optimized firewall rules:
   - Single optimized rule with aggregated IPs and services
   - Lean rule set with more granular control
   - Relationship-based rules that respect source-destination relationships
   - ML-based rules using various clustering techniques
   - Fine-tuned rules with reduced permission boundaries
   - CIDR-merged rules for cleaner configurations

## Project Structure

- `main.py`: Entry point for the application
- `firewall_analyzer.py`: Core analysis engine
- `generate_sample_data.py`: Utility to generate sample data
- `rule_optimization.py`: Basic rule optimization algorithms
- `enhanced_rule_optimization.py`: Relationship-based rule generation
- `ml_rule_optimization.py`: Machine learning based rule optimization
- `fine_tuning.py`: Fine-tuning layer for single optimized rules
- `cidr_merger.py`: CIDR merging functionality
- `CIDR_MERGING.md`: Detailed documentation for CIDR merging feature

## License

MIT

## Author

Your Name
