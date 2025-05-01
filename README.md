# Firewall Rule Analyzer and Optimizer

A Python tool for analyzing firewall logs and optimizing rule permissions with advanced machine learning techniques.

## Overview

This tool helps security teams fine-tune firewall rules by analyzing traffic patterns, identifying anomalies, and providing recommendations to reduce permission boundaries. It processes firewall logs and rule definitions to generate comprehensive reports and visualizations, with a focus on optimizing rules while maintaining security.

## Features

- **Traffic Pattern Analysis**: Identifies patterns by time, source/destination, and zones
- **Anomaly Detection**: Flags unusual ports, low-occurrence connections, and after-hours traffic
- **Rule Optimization**: Recommends specific changes to reduce permission boundaries
- **IP Network Grouping**: Intelligently groups IPs into CIDR notations for cleaner rules
- **Service Mapping**: Maps ports to service names for better readability
- **Enhanced Visualizations**: Creates both static and interactive charts using Seaborn and Plotly
- **Comprehensive Reporting**: Generates detailed HTML reports with actionable recommendations
- **Relationship-Based Rules**: Creates rules that respect source-destination relationships
- **Machine Learning Optimization**: Uses ML techniques with hyperparameter tuning to generate optimized rule sets
- **CIDR Merging**: Intelligent merging of CIDRs for cleaner rule sets
- **Memory-Efficient Processing**: Handles large datasets (1M+ logs) efficiently with batch processing

## Installation

```bash
# Clone the repository
git clone https://github.com/JaishreeJaishankar/improved-chainsaw.git
cd improved-chainsaw

# Install required packages
pip install -r requirements.txt
```

## Usage

### Basic Analysis

```bash
python main.py --log-file your_logs.csv --output-dir output --html-report
```

### Analysis with CIDR Merging

```bash
python main.py --log-file your_logs.csv --output-dir output --html-report --merge-cidrs
```

### Large-Scale Analysis (Memory-Efficient)

```bash
python main_large_scale.py --log-file large_logs.csv --output-dir output --batch-size 10000 --html-report
```

### Quick Test for Memory Efficiency

```bash
python quick_test_memory_efficiency.py --generate --num-logs 5000 --html-report
```

### Command Line Arguments

#### Main Script
- `--log-file`: Path to the firewall log file (CSV)
- `--output-dir`: Directory to store output files (default: "output")
- `--html-report`: Generate HTML report with visualizations
- `--merge-cidrs`: Apply CIDR merging to optimize rules

#### Large-Scale Processing
- `--batch-size`: Number of logs to process in each batch (default: 5000)
- `--sample-size`: Sample size for ML algorithms (default: 2000)
- `--max-rules`: Maximum number of rules to generate (default: 10)
- `--skip-ml`: Skip ML rule generation for faster processing

## Input File Format

### Log File Format (CSV)

The tool expects a CSV file with at least these three columns:
```
source.ip,destination.ip,destination.port
192.168.1.10,172.217.160.78,443
```

## Output

The tool generates:

1. **Enhanced Visualizations**:
   - Static charts using Seaborn (PNG format)
   - Interactive charts using Plotly (HTML format)
   - Network traffic graphs showing source-destination relationships
   - Comprehensive dashboard with all visualizations

2. **Optimized Rules**:
   - Single optimized rule with aggregated IPs and services
   - CIDR-merged rules for cleaner configurations
   - ML-based rules using various clustering techniques:
     - KMeans clustering with hyperparameter tuning
     - DBSCAN clustering with hyperparameter tuning
     - HDBSCAN clustering with hyperparameter tuning
     - Ensemble rules combining multiple techniques

3. **Performance Metrics**:
   - Clustering quality metrics (silhouette score, Davies-Bouldin index)
   - Algorithm runtime comparisons
   - Memory usage statistics for large-scale processing

4. **HTML Report**: Interactive report with all visualizations and recommendations

## Project Structure

- `main.py`: Entry point for standard analysis
- `main_large_scale.py`: Entry point for memory-efficient large-scale analysis
- `firewall_analyzer.py`: Core analysis engine
- `ip_utils.py`: IP address utilities and basic rule generation
- `cidr_merger.py`: CIDR merging functionality
- `ml_rule_optimization.py`: Machine learning based rule optimization with hyperparameter tuning
- `ml_performance_metrics.py`: Performance metrics for ML algorithms
- `visualization.py`: Enhanced visualization with Seaborn and Plotly
- `report_generator.py`: HTML report generation
- `large_scale_processor.py`: Memory-efficient processing for large datasets
- `quick_test_memory_efficiency.py`: Quick testing utility for memory efficiency

## Memory Efficiency

The tool is designed to handle large datasets (1M+ logs) efficiently on systems with limited memory (32GB RAM):

- **Batch Processing**: Processes logs in configurable batches to control memory usage
- **Sampling**: Uses statistical sampling for ML algorithms to reduce memory requirements
- **Memory Monitoring**: Tracks memory usage during processing
- **Optimized Data Structures**: Uses efficient data structures to minimize memory footprint

## License

MIT

## Author

Jaishree Jaishankar
