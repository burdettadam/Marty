#!/usr/bin/env python3
"""
Performance Threshold Validation Script.

This script validates performance test results against predefined thresholds
for CI/CD pipeline integration.
"""

import argparse
import csv
import json
import logging
import statistics
import sys
from pathlib import Path
from typing import Dict, List, Any

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Performance thresholds by service
PERFORMANCE_THRESHOLDS = {
    "pkd_service": {
        "max_avg_response_time": 500,  # ms
        "max_p95_response_time": 1000,  # ms
        "min_success_rate": 95.0,  # %
        "min_throughput": 50,  # req/s
    },
    "trust-svc": {
        "max_avg_response_time": 300,
        "max_p95_response_time": 800,
        "min_success_rate": 98.0,
        "min_throughput": 100,
    },
    "csca-service": {
        "max_avg_response_time": 400,
        "max_p95_response_time": 1000,
        "min_success_rate": 95.0,
        "min_throughput": 80,
    },
    "passport-engine": {
        "max_avg_response_time": 2000,  # Document processing is slower
        "max_p95_response_time": 5000,
        "min_success_rate": 90.0,
        "min_throughput": 10,
    },
    "mdl-engine": {
        "max_avg_response_time": 1500,
        "max_p95_response_time": 4000,
        "min_success_rate": 92.0,
        "min_throughput": 15,
    },
    "inspection-system": {
        "max_avg_response_time": 1000,
        "max_p95_response_time": 3000,
        "min_success_rate": 95.0,
        "min_throughput": 30,
    },
    "ui_app": {
        "max_avg_response_time": 200,
        "max_p95_response_time": 500,
        "min_success_rate": 99.0,
        "min_throughput": 200,
    },
    "default": {
        "max_avg_response_time": 1000,
        "max_p95_response_time": 3000,
        "min_success_rate": 90.0,
        "min_throughput": 20,
    }
}


def load_performance_results(results_file: Path) -> List[Dict[str, Any]]:
    """Load performance test results from CSV file."""
    results = []
    
    try:
        with open(results_file, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # Convert numeric fields
                try:
                    row['response_time'] = float(row['response_time'])
                    row['status_code'] = int(row['status_code'])
                    row['success'] = row['success'].lower() == 'true'
                    if 'response_size' in row:
                        row['response_size'] = int(row.get('response_size', 0))
                except (ValueError, KeyError) as e:
                    logger.warning(f"Error parsing row: {e}")
                    continue
                
                results.append(row)
                
    except FileNotFoundError:
        logger.error(f"Results file not found: {results_file}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error loading results: {e}")
        sys.exit(1)
    
    return results


def calculate_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate performance metrics from test results."""
    if not results:
        return {}
    
    response_times = [r['response_time'] * 1000 for r in results]  # Convert to ms
    successful_requests = [r for r in results if r['success']]
    
    total_requests = len(results)
    successful_count = len(successful_requests)
    success_rate = (successful_count / total_requests * 100) if total_requests > 0 else 0
    
    # Calculate response time statistics
    avg_response_time = statistics.mean(response_times) if response_times else 0
    p50_response_time = statistics.median(response_times) if response_times else 0
    p95_response_time = (
        statistics.quantiles(response_times, n=20)[18] if len(response_times) > 20 else
        max(response_times) if response_times else 0
    )
    p99_response_time = (
        statistics.quantiles(response_times, n=100)[98] if len(response_times) > 100 else
        max(response_times) if response_times else 0
    )
    
    # Calculate throughput (requests per second)
    if results:
        # Estimate test duration from first and last timestamp
        first_time = min(r.get('timestamp', '') for r in results if r.get('timestamp'))
        last_time = max(r.get('timestamp', '') for r in results if r.get('timestamp'))
        
        # If timestamps are available, use them; otherwise estimate
        if first_time and last_time:
            try:
                from datetime import datetime
                first_dt = datetime.fromisoformat(first_time.replace('Z', '+00:00'))
                last_dt = datetime.fromisoformat(last_time.replace('Z', '+00:00'))
                duration = (last_dt - first_dt).total_seconds()
                throughput = total_requests / duration if duration > 0 else 0
            except:
                throughput = 0
        else:
            throughput = 0
    else:
        throughput = 0
    
    return {
        "total_requests": total_requests,
        "successful_requests": successful_count,
        "success_rate": success_rate,
        "avg_response_time": avg_response_time,
        "p50_response_time": p50_response_time,
        "p95_response_time": p95_response_time,
        "p99_response_time": p99_response_time,
        "throughput": throughput,
        "min_response_time": min(response_times) if response_times else 0,
        "max_response_time": max(response_times) if response_times else 0,
    }


def validate_thresholds(metrics: Dict[str, Any], service: str) -> List[str]:
    """Validate metrics against service thresholds."""
    thresholds = PERFORMANCE_THRESHOLDS.get(service, PERFORMANCE_THRESHOLDS["default"])
    violations = []
    
    # Check average response time
    if metrics["avg_response_time"] > thresholds["max_avg_response_time"]:
        violations.append(
            f"Average response time {metrics['avg_response_time']:.1f}ms "
            f"exceeds threshold {thresholds['max_avg_response_time']}ms"
        )
    
    # Check 95th percentile response time
    if metrics["p95_response_time"] > thresholds["max_p95_response_time"]:
        violations.append(
            f"95th percentile response time {metrics['p95_response_time']:.1f}ms "
            f"exceeds threshold {thresholds['max_p95_response_time']}ms"
        )
    
    # Check success rate
    if metrics["success_rate"] < thresholds["min_success_rate"]:
        violations.append(
            f"Success rate {metrics['success_rate']:.1f}% "
            f"below threshold {thresholds['min_success_rate']}%"
        )
    
    # Check throughput (only if we have a reasonable estimate)
    if metrics["throughput"] > 0 and metrics["throughput"] < thresholds["min_throughput"]:
        violations.append(
            f"Throughput {metrics['throughput']:.1f} req/s "
            f"below threshold {thresholds['min_throughput']} req/s"
        )
    
    return violations


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Validate performance test results")
    parser.add_argument("--results-file", required=True, help="Path to results CSV file")
    parser.add_argument("--service", required=True, help="Service name")
    parser.add_argument("--output-json", help="Output JSON file for metrics")
    
    args = parser.parse_args()
    
    results_file = Path(args.results_file)
    
    logger.info(f"Loading performance results from {results_file}")
    results = load_performance_results(results_file)
    
    if not results:
        logger.error("No valid results found")
        sys.exit(1)
    
    logger.info(f"Calculating metrics for {len(results)} test results")
    metrics = calculate_metrics(results)
    
    logger.info("Performance Metrics:")
    logger.info(f"  Total Requests: {metrics['total_requests']}")
    logger.info(f"  Success Rate: {metrics['success_rate']:.1f}%")
    logger.info(f"  Avg Response Time: {metrics['avg_response_time']:.1f}ms")
    logger.info(f"  95th Percentile: {metrics['p95_response_time']:.1f}ms")
    logger.info(f"  Throughput: {metrics['throughput']:.1f} req/s")
    
    # Validate against thresholds
    violations = validate_thresholds(metrics, args.service)
    
    if violations:
        logger.error("Performance threshold violations:")
        for violation in violations:
            logger.error(f"  ❌ {violation}")
        
        # Save metrics even if thresholds are violated
        if args.output_json:
            with open(args.output_json, 'w') as f:
                json.dump(metrics, f, indent=2)
        
        sys.exit(1)
    else:
        logger.info("✅ All performance thresholds passed")
        
        # Save metrics
        if args.output_json:
            with open(args.output_json, 'w') as f:
                json.dump(metrics, f, indent=2)
        
        sys.exit(0)


if __name__ == "__main__":
    main()