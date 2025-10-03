#!/usr/bin/env python3
"""
Performance Testing Framework for Marty Platform

Comprehensive performance testing suite including load testing, stress testing,
benchmark tests, and performance monitoring integration.
"""

import asyncio
import csv
import json
import logging
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
import requests
from prometheus_client import Counter, Histogram, start_http_server

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Prometheus metrics
REQUEST_COUNT = Counter('perf_test_requests_total', 'Total requests made', ['endpoint', 'method', 'status'])
REQUEST_DURATION = Histogram('perf_test_request_duration_seconds', 'Request duration', ['endpoint', 'method'])
ERROR_COUNT = Counter('perf_test_errors_total', 'Total errors', ['endpoint', 'error_type'])

@dataclass
class TestResult:
    """Container for test execution results."""
    endpoint: str
    method: str
    status_code: int
    response_time: float
    success: bool
    error_message: Optional[str] = None
    response_size: Optional[int] = None
    timestamp: Optional[datetime] = None

@dataclass
class PerformanceMetrics:
    """Container for aggregated performance metrics."""
    total_requests: int
    successful_requests: int
    failed_requests: int
    average_response_time: float
    median_response_time: float
    p95_response_time: float
    p99_response_time: float
    min_response_time: float
    max_response_time: float
    requests_per_second: float
    error_rate: float
    total_duration: float

class PerformanceTestFramework:
    """Main performance testing framework."""
    
    def __init__(self, base_url: str = "http://localhost", output_dir: str = "reports/performance"):
        self.base_url = base_url
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Test configurations for different Marty services
        self.service_configs = {
            "pkd_service": {
                "port": 8088,
                "endpoints": [
                    {"path": "/", "method": "GET"},
                    {"path": "/docs", "method": "GET"},
                    {"path": "/v1/masterlist", "method": "GET"},
                    {"path": "/v1/dsclist", "method": "GET"},
                    {"path": "/v1/crl", "method": "GET"},
                ],
                "auth_header": {"X-API-Key": "test_api_key"}
            },
            "document_processing": {
                "port": 8080,
                "endpoints": [
                    {"path": "/", "method": "GET"},
                    {"path": "/api/health", "method": "GET"},
                    {"path": "/api/ping", "method": "GET"},
                    {"path": "/docs", "method": "GET"},
                ],
                "auth_header": {"X-API-Key": "test_api_key"}
            },
            "ui_app": {
                "port": 8000,
                "endpoints": [
                    {"path": "/", "method": "GET"},
                    {"path": "/health", "method": "GET"},
                    {"path": "/docs", "method": "GET"},
                ],
                "auth_header": {}
            }
        }
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(limit=100)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def make_request(self, url: str, method: str = "GET", headers: Dict[str, str] = None, 
                          data: Any = None) -> TestResult:
        """Make a single HTTP request and record metrics."""
        headers = headers or {}
        start_time = time.time()
        
        try:
            if not self.session:
                raise RuntimeError("Session not initialized - use async context manager")
            
            async with self.session.request(method, url, headers=headers, json=data) as response:
                response_time = time.time() - start_time
                response_size = len(await response.read()) if response.content else 0
                
                # Record Prometheus metrics
                REQUEST_COUNT.labels(endpoint=url, method=method, status=response.status).inc()
                REQUEST_DURATION.labels(endpoint=url, method=method).observe(response_time)
                
                return TestResult(
                    endpoint=url,
                    method=method,
                    status_code=response.status,
                    response_time=response_time,
                    success=200 <= response.status < 400,
                    response_size=response_size,
                    timestamp=datetime.now(timezone.utc)
                )
        
        except Exception as e:
            response_time = time.time() - start_time
            error_msg = str(e)
            
            # Record error metrics
            ERROR_COUNT.labels(endpoint=url, error_type=type(e).__name__).inc()
            
            return TestResult(
                endpoint=url,
                method=method,
                status_code=0,
                response_time=response_time,
                success=False,
                error_message=error_msg,
                timestamp=datetime.now(timezone.utc)
            )
    
    async def load_test(self, service_name: str, concurrent_users: int = 10, 
                       duration_seconds: int = 60, requests_per_second: Optional[int] = None) -> List[TestResult]:
        """
        Perform load testing on a service.
        
        Args:
            service_name: Name of the service to test
            concurrent_users: Number of concurrent virtual users
            duration_seconds: Test duration in seconds
            requests_per_second: Optional RPS limit
            
        Returns:
            List of test results
        """
        logger.info(f"Starting load test for {service_name}: {concurrent_users} users, {duration_seconds}s")
        
        service_config = self.service_configs.get(service_name)
        if not service_config:
            raise ValueError(f"Unknown service: {service_name}")
        
        base_service_url = f"{self.base_url}:{service_config['port']}"
        endpoints = service_config['endpoints']
        auth_headers = service_config['auth_header']
        
        results = []
        end_time = time.time() + duration_seconds
        
        # Calculate delay between requests if RPS is specified
        request_delay = 1.0 / requests_per_second if requests_per_second else 0
        
        async def user_session(user_id: int) -> List[TestResult]:
            """Simulate a single user session."""
            user_results = []
            request_count = 0
            
            while time.time() < end_time:
                for endpoint_config in endpoints:
                    if time.time() >= end_time:
                        break
                    
                    url = f"{base_service_url}{endpoint_config['path']}"
                    method = endpoint_config['method']
                    
                    result = await self.make_request(url, method, auth_headers)
                    user_results.append(result)
                    request_count += 1
                    
                    # Apply rate limiting if specified
                    if request_delay > 0:
                        await asyncio.sleep(request_delay)
                    
                    # Small delay between requests within a user session
                    await asyncio.sleep(0.1)
            
            logger.debug(f"User {user_id} completed {request_count} requests")
            return user_results
        
        # Run concurrent user sessions
        tasks = [user_session(i) for i in range(concurrent_users)]
        user_results = await asyncio.gather(*tasks)
        
        # Flatten results
        for user_result in user_results:
            results.extend(user_result)
        
        logger.info(f"Load test completed: {len(results)} total requests")
        return results
    
    async def stress_test(self, service_name: str, max_users: int = 100, 
                         ramp_up_time: int = 300) -> List[TestResult]:
        """
        Perform stress testing by gradually increasing load.
        
        Args:
            service_name: Name of the service to test
            max_users: Maximum number of concurrent users
            ramp_up_time: Time to ramp up to max users (seconds)
            
        Returns:
            List of test results
        """
        logger.info(f"Starting stress test for {service_name}: ramping up to {max_users} users over {ramp_up_time}s")
        
        results = []
        step_duration = ramp_up_time // 10  # 10 steps
        users_per_step = max_users // 10
        
        for step in range(10):
            current_users = (step + 1) * users_per_step
            logger.info(f"Stress test step {step + 1}/10: {current_users} concurrent users")
            
            step_results = await self.load_test(
                service_name=service_name,
                concurrent_users=current_users,
                duration_seconds=step_duration
            )
            results.extend(step_results)
        
        logger.info(f"Stress test completed: {len(results)} total requests")
        return results
    
    def calculate_metrics(self, results: List[TestResult]) -> PerformanceMetrics:
        """Calculate aggregated performance metrics from test results."""
        if not results:
            raise ValueError("No results to calculate metrics from")
        
        successful_results = [r for r in results if r.success]
        failed_results = [r for r in results if not r.success]
        response_times = [r.response_time for r in results]
        
        total_duration = max(r.timestamp for r in results) - min(r.timestamp for r in results)
        total_duration_seconds = total_duration.total_seconds() if total_duration else 1
        
        return PerformanceMetrics(
            total_requests=len(results),
            successful_requests=len(successful_results),
            failed_requests=len(failed_results),
            average_response_time=statistics.mean(response_times),
            median_response_time=statistics.median(response_times),
            p95_response_time=self._percentile(response_times, 95),
            p99_response_time=self._percentile(response_times, 99),
            min_response_time=min(response_times),
            max_response_time=max(response_times),
            requests_per_second=len(results) / total_duration_seconds,
            error_rate=(len(failed_results) / len(results)) * 100,
            total_duration=total_duration_seconds
        )
    
    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calculate the specified percentile of a dataset."""
        sorted_data = sorted(data)
        index = int((percentile / 100) * len(sorted_data))
        return sorted_data[min(index, len(sorted_data) - 1)]
    
    def save_results(self, results: List[TestResult], test_name: str, 
                    metrics: PerformanceMetrics) -> Path:
        """Save test results and metrics to files."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        test_dir = self.output_dir / f"{test_name}_{timestamp}"
        test_dir.mkdir(exist_ok=True)
        
        # Save raw results as CSV
        csv_path = test_dir / "results.csv"
        with csv_path.open("w", newline="") as csvfile:
            fieldnames = ["timestamp", "endpoint", "method", "status_code", 
                         "response_time", "success", "error_message", "response_size"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                writer.writerow({
                    "timestamp": result.timestamp.isoformat() if result.timestamp else "",
                    "endpoint": result.endpoint,
                    "method": result.method,
                    "status_code": result.status_code,
                    "response_time": result.response_time,
                    "success": result.success,
                    "error_message": result.error_message or "",
                    "response_size": result.response_size or 0
                })
        
        # Save metrics as JSON
        metrics_path = test_dir / "metrics.json"
        with metrics_path.open("w") as f:
            json.dump({
                "test_name": test_name,
                "timestamp": timestamp,
                "total_requests": metrics.total_requests,
                "successful_requests": metrics.successful_requests,
                "failed_requests": metrics.failed_requests,
                "average_response_time": metrics.average_response_time,
                "median_response_time": metrics.median_response_time,
                "p95_response_time": metrics.p95_response_time,
                "p99_response_time": metrics.p99_response_time,
                "min_response_time": metrics.min_response_time,
                "max_response_time": metrics.max_response_time,
                "requests_per_second": metrics.requests_per_second,
                "error_rate": metrics.error_rate,
                "total_duration": metrics.total_duration
            }, f, indent=2)
        
        # Generate HTML report
        html_path = test_dir / "report.html"
        self._generate_html_report(metrics, html_path, test_name)
        
        logger.info(f"Results saved to {test_dir}")
        return test_dir
    
    def _generate_html_report(self, metrics: PerformanceMetrics, output_path: Path, test_name: str):
        """Generate an HTML performance report."""
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Performance Test Report - {test_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .metric {{ margin: 10px 0; }}
        .metric-label {{ font-weight: bold; }}
        .success {{ color: green; }}
        .warning {{ color: orange; }}
        .error {{ color: red; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>Performance Test Report</h1>
    <h2>{test_name}</h2>
    
    <table>
        <tr><th>Metric</th><th>Value</th><th>Status</th></tr>
        <tr>
            <td>Total Requests</td>
            <td>{metrics.total_requests:,}</td>
            <td class="success">✓</td>
        </tr>
        <tr>
            <td>Successful Requests</td>
            <td>{metrics.successful_requests:,}</td>
            <td class="{'success' if metrics.error_rate < 1 else 'warning' if metrics.error_rate < 5 else 'error'}">
                {metrics.successful_requests / metrics.total_requests * 100:.1f}%
            </td>
        </tr>
        <tr>
            <td>Failed Requests</td>
            <td>{metrics.failed_requests:,}</td>
            <td class="{'success' if metrics.error_rate < 1 else 'warning' if metrics.error_rate < 5 else 'error'}">
                {metrics.error_rate:.1f}%
            </td>
        </tr>
        <tr>
            <td>Average Response Time</td>
            <td>{metrics.average_response_time:.3f}s</td>
            <td class="{'success' if metrics.average_response_time < 1 else 'warning' if metrics.average_response_time < 3 else 'error'}">
                {'✓' if metrics.average_response_time < 1 else '⚠️' if metrics.average_response_time < 3 else '❌'}
            </td>
        </tr>
        <tr>
            <td>Median Response Time</td>
            <td>{metrics.median_response_time:.3f}s</td>
            <td>-</td>
        </tr>
        <tr>
            <td>95th Percentile</td>
            <td>{metrics.p95_response_time:.3f}s</td>
            <td class="{'success' if metrics.p95_response_time < 2 else 'warning' if metrics.p95_response_time < 5 else 'error'}">
                {'✓' if metrics.p95_response_time < 2 else '⚠️' if metrics.p95_response_time < 5 else '❌'}
            </td>
        </tr>
        <tr>
            <td>99th Percentile</td>
            <td>{metrics.p99_response_time:.3f}s</td>
            <td>-</td>
        </tr>
        <tr>
            <td>Requests per Second</td>
            <td>{metrics.requests_per_second:.1f}</td>
            <td class="{'success' if metrics.requests_per_second > 10 else 'warning' if metrics.requests_per_second > 1 else 'error'}">
                {'✓' if metrics.requests_per_second > 10 else '⚠️' if metrics.requests_per_second > 1 else '❌'}
            </td>
        </tr>
        <tr>
            <td>Test Duration</td>
            <td>{metrics.total_duration:.1f}s</td>
            <td>-</td>
        </tr>
    </table>
    
    <h3>Performance Thresholds</h3>
    <ul>
        <li><strong>Error Rate:</strong> &lt; 1% ✓ | &lt; 5% ⚠️ | ≥ 5% ❌</li>
        <li><strong>Average Response Time:</strong> &lt; 1s ✓ | &lt; 3s ⚠️ | ≥ 3s ❌</li>
        <li><strong>95th Percentile:</strong> &lt; 2s ✓ | &lt; 5s ⚠️ | ≥ 5s ❌</li>
        <li><strong>Throughput:</strong> &gt; 10 RPS ✓ | &gt; 1 RPS ⚠️ | ≤ 1 RPS ❌</li>
    </ul>
    
    <p><small>Generated at {datetime.now().isoformat()}</small></p>
</body>
</html>"""
        
        with output_path.open("w") as f:
            f.write(html_content)

# CLI interface functions
async def run_load_test(service_name: str, concurrent_users: int = 10, 
                       duration: int = 60, rps: Optional[int] = None):
    """Run a load test on a specific service."""
    async with PerformanceTestFramework() as framework:
        results = await framework.load_test(service_name, concurrent_users, duration, rps)
        metrics = framework.calculate_metrics(results)
        
        test_name = f"load_test_{service_name}"
        output_dir = framework.save_results(results, test_name, metrics)
        
        print(f"\n📊 Load Test Results for {service_name}")
        print(f"{'='*50}")
        print(f"Total Requests: {metrics.total_requests:,}")
        print(f"Success Rate: {metrics.successful_requests/metrics.total_requests*100:.1f}%")
        print(f"Error Rate: {metrics.error_rate:.1f}%")
        print(f"Average Response Time: {metrics.average_response_time:.3f}s")
        print(f"95th Percentile: {metrics.p95_response_time:.3f}s")
        print(f"Requests/Second: {metrics.requests_per_second:.1f}")
        print(f"\n📁 Results saved to: {output_dir}")

async def run_stress_test(service_name: str, max_users: int = 100, ramp_up_time: int = 300):
    """Run a stress test on a specific service."""
    async with PerformanceTestFramework() as framework:
        results = await framework.stress_test(service_name, max_users, ramp_up_time)
        metrics = framework.calculate_metrics(results)
        
        test_name = f"stress_test_{service_name}"
        output_dir = framework.save_results(results, test_name, metrics)
        
        print(f"\n🔥 Stress Test Results for {service_name}")
        print(f"{'='*50}")
        print(f"Total Requests: {metrics.total_requests:,}")
        print(f"Success Rate: {metrics.successful_requests/metrics.total_requests*100:.1f}%")
        print(f"Error Rate: {metrics.error_rate:.1f}%")
        print(f"Average Response Time: {metrics.average_response_time:.3f}s")
        print(f"95th Percentile: {metrics.p95_response_time:.3f}s")
        print(f"Requests/Second: {metrics.requests_per_second:.1f}")
        print(f"\n📁 Results saved to: {output_dir}")

def start_metrics_server(port: int = 9090):
    """Start Prometheus metrics server."""
    start_http_server(port)
    logger.info(f"Prometheus metrics server started on port {port}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Marty Platform Performance Testing Framework")
    parser.add_argument("test_type", choices=["load", "stress"], help="Type of test to run")
    parser.add_argument("service", choices=["pkd_service", "document_processing", "ui_app"], 
                       help="Service to test")
    parser.add_argument("--users", type=int, default=10, help="Number of concurrent users")
    parser.add_argument("--duration", type=int, default=60, help="Test duration in seconds")
    parser.add_argument("--rps", type=int, help="Requests per second limit")
    parser.add_argument("--max-users", type=int, default=100, help="Maximum users for stress test")
    parser.add_argument("--ramp-up", type=int, default=300, help="Ramp-up time for stress test")
    parser.add_argument("--metrics-port", type=int, default=9090, help="Prometheus metrics port")
    
    args = parser.parse_args()
    
    # Start metrics server
    start_metrics_server(args.metrics_port)
    
    # Run the appropriate test
    if args.test_type == "load":
        asyncio.run(run_load_test(args.service, args.users, args.duration, args.rps))
    elif args.test_type == "stress":
        asyncio.run(run_stress_test(args.service, args.max_users, args.ramp_up))