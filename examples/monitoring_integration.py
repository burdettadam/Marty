#!/usr/bin/env python3
"""
Example integration of the Marty monitoring infrastructure with a gRPC service.

This script demonstrates how to integrate comprehensive monitoring, health checks,
and alerting into a Marty microservice.
"""

import logging
import signal
import sys
import time
from concurrent import futures

import grpc

# Import our monitoring infrastructure
from marty_common.monitoring import (
    AlertSeverity,
    create_metrics_interceptor,
    create_service_monitor,
    monitor_operation,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)


class MonitoredService:
    """Example service with comprehensive monitoring."""

    def __init__(self, service_name: str, port: int) -> None:
        self.service_name = service_name
        self.port = port
        self.server = None

        # Create service monitor
        self.monitor = create_service_monitor(
            service_name=service_name,
            service_version="1.0.0",
            port=port,
            environment="production"
        )

        # Setup monitoring components
        self._setup_monitoring()

    def _setup_monitoring(self) -> None:
        """Configure monitoring components."""

        # Add custom health checks
        self.monitor.health_monitor.add_health_check(
            name="grpc_server_health",
            description="Check if gRPC server is running",
            check_function=self._check_grpc_server,
            critical=True
        )

        self.monitor.health_monitor.add_health_check(
            name="database_connection",
            description="Check database connectivity (mock)",
            check_function=self._check_database,
            critical=True
        )

        # Add custom alerts
        self.monitor.alert_manager.add_alert(
            name="high_request_rate",
            description="Request rate is unusually high",
            severity=AlertSeverity.WARNING,
            condition=self._check_high_request_rate
        )

        self.monitor.alert_manager.add_alert(
            name="service_degraded",
            description="Service is in degraded state",
            severity=AlertSeverity.ERROR,
            condition=self._check_service_degraded
        )

        # Add alert callback
        self.monitor.alert_manager.add_alert_callback(self._handle_alert)

    def _check_grpc_server(self) -> bool:
        """Check if gRPC server is running."""
        return self.server is not None

    def _check_database(self) -> bool:
        """Mock database connectivity check."""
        # In real implementation, this would check actual database connectivity
        return True

    def _check_high_request_rate(self, metrics) -> bool:
        """Check for high request rate."""
        request_metric = self.monitor.metrics_collector.get_latest_metric("grpc.requests.total")
        # Simple threshold check - in production would be more sophisticated
        return request_metric and request_metric.value > 100

    def _check_service_degraded(self, metrics) -> bool:
        """Check if service is degraded."""
        health_status = self.monitor.health_monitor.current_status
        from marty_common.monitoring import HealthStatus
        return health_status == HealthStatus.DEGRADED

    def _handle_alert(self, alert) -> None:
        """Handle triggered alerts."""
        logger.warning(f"ALERT TRIGGERED: {alert.name} - {alert.description} "
                      f"(Severity: {alert.severity.value})")

        # In production, this would send notifications via email, Slack, etc.
        if alert.severity == AlertSeverity.CRITICAL:
            logger.critical(f"CRITICAL ALERT: {alert.name} - Immediate action required!")

    def start_service(self) -> None:
        """Start the monitored service."""
        logger.info(f"Starting {self.service_name} on port {self.port}")

        # Create gRPC server with monitoring interceptor
        metrics_interceptor = create_metrics_interceptor(self.monitor)
        self.server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=10),
            interceptors=[metrics_interceptor]
        )

        # Add service implementation here (would be actual proto service)
        # server.add_YourServiceServicer_to_server(YourServiceImpl(), self.server)

        # Start server
        listen_addr = f"[::]:{self.port}"
        self.server.add_insecure_port(listen_addr)
        self.server.start()

        # Start monitoring
        self.monitor.start_monitoring()

        logger.info(f"Service started on {listen_addr}")
        logger.info("Monitoring enabled - health checks, metrics, and alerts active")

        # Simulate some service activity
        self._simulate_activity()

    def _simulate_activity(self) -> None:
        """Simulate service activity for demonstration."""
        logger.info("Simulating service activity...")

        # Simulate some requests
        for i in range(20):
            with monitor_operation(self.monitor.metrics_collector, "simulate_request"):
                # Simulate request processing
                time.sleep(0.1)

                # Record some custom metrics
                self.monitor.metrics_collector.increment_counter(
                    "custom.requests.processed",
                    {"endpoint": "test", "status": "success"}
                )

                if i % 5 == 0:
                    self.monitor.metrics_collector.set_gauge(
                        "custom.active_connections",
                        i + 1
                    )

        logger.info("Activity simulation complete")

    def stop_service(self) -> None:
        """Stop the monitored service."""
        logger.info(f"Stopping {self.service_name}")

        # Stop monitoring first
        self.monitor.stop_monitoring()

        # Stop gRPC server
        if self.server:
            self.server.stop(grace=5)
            self.server = None

        logger.info("Service stopped")

    def get_status(self):
        """Get comprehensive service status."""
        return self.monitor.get_monitoring_status()


def signal_handler(signum, frame) -> None:
    """Handle shutdown signals."""
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    sys.exit(0)


def main() -> None:
    """Main function demonstrating monitored service."""

    # Setup signal handling
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Create and start monitored service
    service = MonitoredService("example-service", 50051)

    try:
        service.start_service()

        # Let it run and demonstrate monitoring
        logger.info("Service running... Press Ctrl+C to stop")

        # Show status periodically
        for _i in range(10):
            time.sleep(5)

            status = service.get_status()
            logger.info(f"Service Status: {status['health']['status']}")
            logger.info(f"Active Alerts: {len(status['active_alerts'])}")

            # Show some metrics
            cpu_metric = service.monitor.metrics_collector.get_latest_metric("system.cpu.percent")
            if cpu_metric:
                logger.info(f"CPU Usage: {cpu_metric.value:.1f}%")

        logger.info("Demonstration complete")

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception:
        logger.exception("Service error")
    finally:
        service.stop_service()


if __name__ == "__main__":
    main()
