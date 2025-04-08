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

## Project Structure

- `main.py`: Entry point for the application
- `firewall_analyzer.py`: Core analysis engine
- `generate_sample_data.py`: Utility to generate sample data

## License

MIT

## Author

Your Name
