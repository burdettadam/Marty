"""
Grafana Dashboard Configuration for Marty Microservices Observability.

This dashboard configuration provides comprehensive monitoring for the Marty
microservices platform using the unified observability framework.
"""

import json
from typing import Dict, List, Any


def create_marty_observability_dashboard() -> Dict[str, Any]:
    """
    Create a comprehensive Grafana dashboard for Marty microservices observability.
    
    This dashboard leverages the standardized metrics from the unified observability
    framework to provide insights into service health, performance, and business metrics.
    """
    
    dashboard = {
        "dashboard": {
            "id": None,
            "title": "Marty Microservices - Unified Observability",
            "tags": ["marty", "microservices", "observability"],
            "timezone": "UTC",
            "refresh": "30s",
            "time": {
                "from": "now-1h",
                "to": "now"
            },
            "templating": {
                "list": [
                    {
                        "name": "service",
                        "type": "query",
                        "query": "label_values(marty_service_requests_total, service_name)",
                        "refresh": "time",
                        "includeAll": True,
                        "allValue": ".*",
                        "multi": True
                    },
                    {
                        "name": "environment", 
                        "type": "query",
                        "query": "label_values(marty_service_requests_total, environment)",
                        "refresh": "time",
                        "includeAll": False,
                        "multi": False
                    }
                ]
            },
            "panels": []
        }
    }
    
    # Add service health overview panels
    dashboard["dashboard"]["panels"].extend(_create_service_health_panels())
    
    # Add performance monitoring panels  
    dashboard["dashboard"]["panels"].extend(_create_performance_panels())
    
    # Add business metrics panels
    dashboard["dashboard"]["panels"].extend(_create_business_metrics_panels())
    
    # Add distributed tracing panels
    dashboard["dashboard"]["panels"].extend(_create_tracing_panels())
    
    # Add infrastructure monitoring panels
    dashboard["dashboard"]["panels"].extend(_create_infrastructure_panels())
    
    return dashboard


def _create_service_health_panels() -> List[Dict[str, Any]]:
    """Create service health monitoring panels."""
    return [
        {
            "id": 1,
            "title": "Service Health Status",
            "type": "stat",
            "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
            "targets": [
                {
                    "expr": "marty_service_health_status{service=~\"$service\", environment=\"$environment\"}",
                    "legendFormat": "{{service_name}} - {{check_name}}"
                }
            ],
            "fieldConfig": {
                "defaults": {
                    "color": {"mode": "thresholds"},
                    "thresholds": {
                        "steps": [
                            {"color": "red", "value": 0},
                            {"color": "yellow", "value": 0.5}, 
                            {"color": "green", "value": 1}
                        ]
                    },
                    "mappings": [
                        {"options": {"0": {"text": "Unhealthy"}}, "type": "value"},
                        {"options": {"0.5": {"text": "Degraded"}}, "type": "value"},
                        {"options": {"1": {"text": "Healthy"}}, "type": "value"}
                    ]
                }
            }
        },
        {
            "id": 2,
            "title": "Service Uptime",
            "type": "stat", 
            "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
            "targets": [
                {
                    "expr": "marty_service_uptime_seconds{service=~\"$service\", environment=\"$environment\"}",
                    "legendFormat": "{{service_name}}"
                }
            ],
            "fieldConfig": {
                "defaults": {
                    "unit": "s",
                    "color": {"mode": "continuous-GrYlRd"}
                }
            }
        },
        {
            "id": 3,
            "title": "Service Error Rate",
            "type": "graph",
            "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8},
            "targets": [
                {
                    "expr": "rate(marty_service_requests_total{service=~\"$service\", environment=\"$environment\", status_code!~\"2..\"}[5m])",
                    "legendFormat": "{{service_name}} - Error Rate"
                }
            ],
            "yAxes": [
                {"label": "Errors/sec", "min": 0},
                {"show": False}
            ],
            "alert": {
                "conditions": [
                    {
                        "query": {"queryType": "", "refId": "A"},
                        "reducer": {"params": [], "type": "last"},
                        "evaluator": {"params": [0.05], "type": "gt"}
                    }
                ],
                "executionErrorState": "alerting",
                "for": "5m",
                "frequency": "10s",
                "handler": 1,
                "name": "Service Error Rate Alert",
                "noDataState": "no_data"
            }
        }
    ]


def _create_performance_panels() -> List[Dict[str, Any]]:
    """Create performance monitoring panels.""" 
    return [
        {
            "id": 4,
            "title": "Request Latency (P95)",
            "type": "graph",
            "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16},
            "targets": [
                {
                    "expr": "histogram_quantile(0.95, rate(marty_service_request_duration_seconds_bucket{service=~\"$service\", environment=\"$environment\"}[5m]))",
                    "legendFormat": "{{service_name}} - P95"
                },
                {
                    "expr": "histogram_quantile(0.50, rate(marty_service_request_duration_seconds_bucket{service=~\"$service\", environment=\"$environment\"}[5m]))",
                    "legendFormat": "{{service_name}} - P50"
                }
            ],
            "yAxes": [
                {"label": "Response Time", "unit": "s", "min": 0},
                {"show": False}
            ]
        },
        {
            "id": 5,
            "title": "Request Rate",
            "type": "graph", 
            "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16},
            "targets": [
                {
                    "expr": "rate(marty_service_requests_total{service=~\"$service\", environment=\"$environment\"}[5m])",
                    "legendFormat": "{{service_name}}"
                }
            ],
            "yAxes": [
                {"label": "Requests/sec", "min": 0},
                {"show": False}
            ]
        },
        {
            "id": 6,
            "title": "gRPC Method Performance", 
            "type": "table",
            "gridPos": {"h": 8, "w": 24, "x": 0, "y": 24},
            "targets": [
                {
                    "expr": "topk(10, rate(marty_grpc_requests_total{service=~\"$service\", environment=\"$environment\"}[5m]))",
                    "format": "table",
                    "instant": True
                }
            ],
            "transformations": [
                {
                    "id": "organize",
                    "options": {
                        "excludeByName": {"Time": True},
                        "renameByName": {
                            "service_name": "Service",
                            "grpc_method": "Method", 
                            "Value": "Requests/sec"
                        }
                    }
                }
            ]
        }
    ]


def _create_business_metrics_panels() -> List[Dict[str, Any]]:
    """Create business-specific metrics panels."""
    return [
        {
            "id": 7,
            "title": "Certificate Validation Operations",
            "type": "graph",
            "gridPos": {"h": 8, "w": 12, "x": 0, "y": 32},
            "targets": [
                {
                    "expr": "rate(marty_certificate_validations_total{environment=\"$environment\"}[5m])",
                    "legendFormat": "{{result}} - {{certificate_type}}"
                }
            ],
            "yAxes": [
                {"label": "Validations/sec", "min": 0},
                {"show": False}
            ]
        },
        {
            "id": 8,
            "title": "Document Signing Operations", 
            "type": "graph",
            "gridPos": {"h": 8, "w": 12, "x": 12, "y": 32},
            "targets": [
                {
                    "expr": "rate(marty_document_operations_total{operation=\"sign\", environment=\"$environment\"}[5m])",
                    "legendFormat": "{{document_type}} - {{algorithm}}"
                }
            ],
            "yAxes": [
                {"label": "Signings/sec", "min": 0},
                {"show": False}
            ]
        },
        {
            "id": 9,
            "title": "PKD Synchronization Status",
            "type": "stat",
            "gridPos": {"h": 4, "w": 8, "x": 0, "y": 40},
            "targets": [
                {
                    "expr": "marty_pkd_sync_operations_total{result=\"success\", environment=\"$environment\"}",
                    "legendFormat": "Successful Syncs"
                }
            ],
            "fieldConfig": {
                "defaults": {
                    "color": {"mode": "thresholds"},
                    "thresholds": {
                        "steps": [
                            {"color": "red", "value": 0},
                            {"color": "green", "value": 1}
                        ]
                    }
                }
            }
        },
        {
            "id": 10,
            "title": "SD-JWT Operations",
            "type": "graph",
            "gridPos": {"h": 8, "w": 16, "x": 8, "y": 40},
            "targets": [
                {
                    "expr": "rate(marty_sdjwt_operations_total{environment=\"$environment\"}[5m])",
                    "legendFormat": "{{operation}} - {{issuer}}"
                }
            ],
            "yAxes": [
                {"label": "Operations/sec", "min": 0},
                {"show": False}
            ]
        }
    ]


def _create_tracing_panels() -> List[Dict[str, Any]]:
    """Create distributed tracing panels."""
    return [
        {
            "id": 11,
            "title": "Trace Latency Distribution",
            "type": "heatmap",
            "gridPos": {"h": 8, "w": 24, "x": 0, "y": 48},
            "targets": [
                {
                    "expr": "rate(marty_trace_duration_seconds_bucket{service=~\"$service\", environment=\"$environment\"}[5m])",
                    "format": "heatmap",
                    "legendFormat": "{{le}}"
                }
            ],
            "heatmap": {
                "xAxis": {"show": True},
                "yAxis": {"show": True, "logBase": 1, "unit": "s"},
                "colorMode": "spectrum"
            }
        },
        {
            "id": 12,
            "title": "Service Dependencies",
            "type": "node-graph",
            "gridPos": {"h": 8, "w": 24, "x": 0, "y": 56},
            "targets": [
                {
                    "expr": "marty_service_requests_total{service=~\"$service\", environment=\"$environment\"}",
                    "format": "table"
                }
            ]
        }
    ]


def _create_infrastructure_panels() -> List[Dict[str, Any]]:
    """Create infrastructure monitoring panels."""
    return [
        {
            "id": 13,
            "title": "Memory Usage",
            "type": "graph", 
            "gridPos": {"h": 8, "w": 12, "x": 0, "y": 64},
            "targets": [
                {
                    "expr": "marty_service_memory_usage_bytes{service=~\"$service\", environment=\"$environment\"}",
                    "legendFormat": "{{service_name}}"
                }
            ],
            "yAxes": [
                {"label": "Memory", "unit": "bytes", "min": 0},
                {"show": False}
            ]
        },
        {
            "id": 14,
            "title": "CPU Usage",
            "type": "graph",
            "gridPos": {"h": 8, "w": 12, "x": 12, "y": 64},
            "targets": [
                {
                    "expr": "rate(marty_service_cpu_usage_seconds_total{service=~\"$service\", environment=\"$environment\"}[5m])",
                    "legendFormat": "{{service_name}}"
                }
            ],
            "yAxes": [
                {"label": "CPU %", "unit": "percent", "min": 0, "max": 1},
                {"show": False}
            ]
        },
        {
            "id": 15,
            "title": "Database Connection Pool",
            "type": "graph",
            "gridPos": {"h": 8, "w": 24, "x": 0, "y": 72},
            "targets": [
                {
                    "expr": "marty_database_connections_active{service=~\"$service\", environment=\"$environment\"}",
                    "legendFormat": "{{service_name}} - Active"
                },
                {
                    "expr": "marty_database_connections_idle{service=~\"$service\", environment=\"$environment\"}",
                    "legendFormat": "{{service_name}} - Idle"
                }
            ],
            "yAxes": [
                {"label": "Connections", "min": 0},
                {"show": False}
            ]
        }
    ]


def create_alerting_rules() -> Dict[str, Any]:
    """
    Create Prometheus alerting rules for Marty microservices.
    
    These rules leverage the unified observability metrics to detect
    service health issues and performance degradation.
    """
    
    return {
        "groups": [
            {
                "name": "marty.microservices.alerts",
                "rules": [
                    {
                        "alert": "MartyServiceDown",
                        "expr": "marty_service_health_status == 0",
                        "for": "1m",
                        "labels": {
                            "severity": "critical",
                            "service": "{{ $labels.service_name }}"
                        },
                        "annotations": {
                            "summary": "Marty service {{ $labels.service_name }} is down",
                            "description": "Service {{ $labels.service_name }} health check {{ $labels.check_name }} has been failing for more than 1 minute."
                        }
                    },
                    {
                        "alert": "MartyHighErrorRate",
                        "expr": "rate(marty_service_requests_total{status_code!~\"2..\"}[5m]) > 0.05",
                        "for": "5m",
                        "labels": {
                            "severity": "warning",
                            "service": "{{ $labels.service_name }}"
                        },
                        "annotations": {
                            "summary": "High error rate in {{ $labels.service_name }}",
                            "description": "Service {{ $labels.service_name }} has error rate above 5% for more than 5 minutes."
                        }
                    },
                    {
                        "alert": "MartyHighLatency",
                        "expr": "histogram_quantile(0.95, rate(marty_service_request_duration_seconds_bucket[5m])) > 1.0",
                        "for": "10m", 
                        "labels": {
                            "severity": "warning",
                            "service": "{{ $labels.service_name }}"
                        },
                        "annotations": {
                            "summary": "High latency in {{ $labels.service_name }}",
                            "description": "Service {{ $labels.service_name }} P95 latency is above 1 second for more than 10 minutes."
                        }
                    },
                    {
                        "alert": "MartyCertificateValidationFailures", 
                        "expr": "rate(marty_certificate_validations_total{result=\"error\"}[5m]) > 0.01",
                        "for": "5m",
                        "labels": {
                            "severity": "warning",
                            "team": "security"
                        },
                        "annotations": {
                            "summary": "High certificate validation failure rate",
                            "description": "Certificate validation error rate is above 1% for more than 5 minutes."
                        }
                    },
                    {
                        "alert": "MartyPKDSyncFailure",
                        "expr": "increase(marty_pkd_sync_operations_total{result=\"error\"}[1h]) > 0",
                        "for": "0m",
                        "labels": {
                            "severity": "critical",
                            "team": "platform"
                        },
                        "annotations": {
                            "summary": "PKD synchronization failed",
                            "description": "PKD sync operation has failed. Trust anchor data may be stale."
                        }
                    }
                ]
            }
        ]
    }


def export_dashboard_config(output_path: str = "monitoring/grafana_dashboard.json"):
    """Export the dashboard configuration to a JSON file."""
    dashboard = create_marty_observability_dashboard()
    
    with open(output_path, 'w') as f:
        json.dump(dashboard, f, indent=2)
    
    print(f"Dashboard configuration exported to {output_path}")


def export_alerting_rules(output_path: str = "monitoring/prometheus_alerts.yml"):
    """Export the alerting rules to a YAML file."""
    import yaml
    
    rules = create_alerting_rules()
    
    with open(output_path, 'w') as f:
        yaml.dump(rules, f, indent=2)
    
    print(f"Alerting rules exported to {output_path}")


if __name__ == "__main__":
    export_dashboard_config()
    export_alerting_rules()