"""
Performance Monitoring Integration for Marty Platform

Integrates performance test metrics with existing Prometheus/Grafana monitoring stack.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)

# Grafana dashboard configuration for performance testing
PERFORMANCE_DASHBOARD = {
    "dashboard": {
        "id": None,
        "title": "Marty Platform - Performance Testing",
        "tags": ["marty", "performance", "testing"],
        "timezone": "utc",
        "panels": [
            {
                "id": 1,
                "title": "Request Rate",
                "type": "stat",
                "targets": [
                    {
                        "expr": "rate(perf_test_requests_total[5m])",
                        "legendFormat": "{{endpoint}} - {{method}}"
                    }
                ],
                "fieldConfig": {
                    "defaults": {
                        "unit": "reqps",
                        "min": 0
                    }
                },
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
            },
            {
                "id": 2,
                "title": "Response Time Distribution",
                "type": "heatmap",
                "targets": [
                    {
                        "expr": "rate(perf_test_request_duration_seconds_bucket[5m])",
                        "legendFormat": "{{le}}"
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
            },
            {
                "id": 3,
                "title": "Error Rate",
                "type": "stat",
                "targets": [
                    {
                        "expr": "rate(perf_test_errors_total[5m])",
                        "legendFormat": "{{error_type}}"
                    }
                ],
                "fieldConfig": {
                    "defaults": {
                        "unit": "percent",
                        "max": 100,
                        "thresholds": {
                            "steps": [
                                {"color": "green", "value": 0},
                                {"color": "yellow", "value": 1},
                                {"color": "red", "value": 5}
                            ]
                        }
                    }
                },
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8}
            },
            {
                "id": 4,
                "title": "Response Time Percentiles",
                "type": "graph",
                "targets": [
                    {
                        "expr": "histogram_quantile(0.50, rate(perf_test_request_duration_seconds_bucket[5m]))",
                        "legendFormat": "50th percentile"
                    },
                    {
                        "expr": "histogram_quantile(0.95, rate(perf_test_request_duration_seconds_bucket[5m]))",
                        "legendFormat": "95th percentile"
                    },
                    {
                        "expr": "histogram_quantile(0.99, rate(perf_test_request_duration_seconds_bucket[5m]))",
                        "legendFormat": "99th percentile"
                    }
                ],
                "yAxes": [
                    {"unit": "s", "min": 0},
                    {"show": False}
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8}
            },
            {
                "id": 5,
                "title": "Request Status Codes",
                "type": "piechart",
                "targets": [
                    {
                        "expr": "sum by (status) (rate(perf_test_requests_total[5m]))",
                        "legendFormat": "HTTP {{status}}"
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16}
            },
            {
                "id": 6,
                "title": "Request Volume by Endpoint",
                "type": "bargauge",
                "targets": [
                    {
                        "expr": "sum by (endpoint) (rate(perf_test_requests_total[5m]))",
                        "legendFormat": "{{endpoint}}"
                    }
                ],
                "fieldConfig": {
                    "defaults": {
                        "unit": "reqps",
                        "min": 0
                    }
                },
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16}
            }
        ],
        "time": {
            "from": "now-1h",
            "to": "now"
        },
        "refresh": "5s"
    }
}

# Prometheus alerting rules for performance testing
PERFORMANCE_ALERTS = {
    "groups": [
        {
            "name": "performance_testing",
            "rules": [
                {
                    "alert": "HighErrorRate",
                    "expr": "rate(perf_test_errors_total[5m]) > 0.05",
                    "for": "2m",
                    "labels": {
                        "severity": "warning",
                        "service": "{{ $labels.endpoint }}"
                    },
                    "annotations": {
                        "summary": "High error rate during performance testing",
                        "description": "Error rate for {{ $labels.endpoint }} is {{ $value | humanizePercentage }} over the last 5 minutes."
                    }
                },
                {
                    "alert": "HighResponseTime",
                    "expr": "histogram_quantile(0.95, rate(perf_test_request_duration_seconds_bucket[5m])) > 2",
                    "for": "2m",
                    "labels": {
                        "severity": "warning",
                        "service": "{{ $labels.endpoint }}"
                    },
                    "annotations": {
                        "summary": "High response time during performance testing",
                        "description": "95th percentile response time for {{ $labels.endpoint }} is {{ $value }}s over the last 5 minutes."
                    }
                },
                {
                    "alert": "LowThroughput",
                    "expr": "rate(perf_test_requests_total[5m]) < 1",
                    "for": "5m",
                    "labels": {
                        "severity": "critical",
                        "service": "{{ $labels.endpoint }}"
                    },
                    "annotations": {
                        "summary": "Low throughput during performance testing",
                        "description": "Request rate for {{ $labels.endpoint }} is {{ $value }} req/s over the last 5 minutes."
                    }
                }
            ]
        }
    ]
}

def setup_performance_monitoring(monitoring_dir: Path = Path("monitoring")):
    """Set up performance monitoring configuration files."""
    
    # Create Grafana dashboard
    grafana_dir = monitoring_dir / "grafana" / "dashboards"
    grafana_dir.mkdir(parents=True, exist_ok=True)
    
    dashboard_file = grafana_dir / "performance-testing.json"
    with dashboard_file.open("w") as f:
        json.dump(PERFORMANCE_DASHBOARD, f, indent=2)
    
    logger.info(f"Created Grafana dashboard: {dashboard_file}")
    
    # Create Prometheus alerts
    prometheus_dir = monitoring_dir / "prometheus" / "rules"
    prometheus_dir.mkdir(parents=True, exist_ok=True)
    
    alerts_file = prometheus_dir / "performance-alerts.yml"
    with alerts_file.open("w") as f:
        # Convert to YAML format
        import yaml
        yaml.dump(PERFORMANCE_ALERTS, f, default_flow_style=False)
    
    logger.info(f"Created Prometheus alerts: {alerts_file}")
    
    return dashboard_file, alerts_file

def generate_performance_summary(results_dir: Path) -> Dict:
    """Generate a performance summary from test results."""
    
    summary = {
        "test_runs": [],
        "services_tested": set(),
        "total_requests": 0,
        "overall_success_rate": 0,
        "average_response_time": 0
    }
    
    # Scan for test result files
    for metrics_file in results_dir.rglob("metrics.json"):
        try:
            with metrics_file.open() as f:
                metrics = json.load(f)
            
            summary["test_runs"].append({
                "test_name": metrics.get("test_name", "unknown"),
                "timestamp": metrics.get("timestamp", "unknown"),
                "service": metrics.get("test_name", "").split("_")[-1] if "_" in metrics.get("test_name", "") else "unknown",
                "total_requests": metrics.get("total_requests", 0),
                "success_rate": (metrics.get("successful_requests", 0) / metrics.get("total_requests", 1)) * 100,
                "average_response_time": metrics.get("average_response_time", 0),
                "p95_response_time": metrics.get("p95_response_time", 0),
                "requests_per_second": metrics.get("requests_per_second", 0),
                "error_rate": metrics.get("error_rate", 0)
            })
            
            # Extract service name
            service_name = metrics.get("test_name", "").split("_")[-1] if "_" in metrics.get("test_name", "") else "unknown"
            summary["services_tested"].add(service_name)
            summary["total_requests"] += metrics.get("total_requests", 0)
            
        except Exception as e:
            logger.warning(f"Failed to process {metrics_file}: {e}")
    
    # Calculate overall metrics
    if summary["test_runs"]:
        total_successful = sum(run["total_requests"] * run["success_rate"] / 100 for run in summary["test_runs"])
        summary["overall_success_rate"] = (total_successful / summary["total_requests"]) * 100 if summary["total_requests"] > 0 else 0
        summary["average_response_time"] = sum(run["average_response_time"] for run in summary["test_runs"]) / len(summary["test_runs"])
    
    summary["services_tested"] = list(summary["services_tested"])
    
    return summary

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Performance Monitoring Setup")
    parser.add_argument("--setup", action="store_true", help="Set up monitoring configuration")
    parser.add_argument("--summary", type=str, help="Generate summary from results directory")
    
    args = parser.parse_args()
    
    if args.setup:
        dashboard_file, alerts_file = setup_performance_monitoring()
        print(f"✅ Performance monitoring configured:")
        print(f"   📊 Dashboard: {dashboard_file}")
        print(f"   🚨 Alerts: {alerts_file}")
    
    if args.summary:
        summary = generate_performance_summary(Path(args.summary))
        print(f"📈 Performance Summary:")
        print(f"   Services tested: {', '.join(summary['services_tested'])}")
        print(f"   Total test runs: {len(summary['test_runs'])}")
        print(f"   Total requests: {summary['total_requests']:,}")
        print(f"   Overall success rate: {summary['overall_success_rate']:.1f}%")
        print(f"   Average response time: {summary['average_response_time']:.3f}s")