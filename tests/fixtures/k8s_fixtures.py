"""
Kubernetes-specific test fixtures for Marty test suite.

This module provides fixtures for managing Kubernetes services during testing,
including service discovery, health checks, and cleanup operations.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Generator

import httpx
import pytest

from tests.k8s_test_orchestrator import KubernetesTestOrchestrator, TestMode

logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def k8s_cluster():
    """Ensure Kind cluster exists for testing."""
    project_root = Path(__file__).parent.parent.parent
    orchestrator = KubernetesTestOrchestrator(
        project_root=project_root,
        namespace="marty-test-fixtures",
    )
    
    # Ensure cluster exists
    orchestrator.ensure_cluster()
    yield orchestrator.cluster_name
    
    # Cleanup is optional - cluster can be reused


@pytest.fixture(scope="function")
def k8s_namespace(k8s_cluster):
    """Create and clean up a test namespace."""
    import uuid
    from tests.k8s_test_orchestrator import KubernetesTestOrchestrator
    
    namespace = f"test-{uuid.uuid4().hex[:8]}"
    project_root = Path(__file__).parent.parent.parent
    orchestrator = KubernetesTestOrchestrator(
        project_root=project_root,
        namespace=namespace,
    )
    
    # Create namespace
    try:
        orchestrator._run_kubectl(["create", "namespace", namespace])
        yield namespace
    finally:
        # Cleanup namespace
        orchestrator._run_kubectl(["delete", "namespace", namespace], check=False)


@pytest.fixture
def k8s_service_health_checker():
    """Fixture for checking service health."""
    
    async def check_service_health(url: str, timeout: float = 60.0) -> bool:
        """Check if a service is healthy."""
        start = time.time()
        async with httpx.AsyncClient(timeout=5.0) as client:
            while time.time() - start < timeout:
                try:
                    resp = await client.get(f"{url}/health")
                    if resp.status_code == 200:
                        health_data = resp.json()
                        if health_data.get("status") in ["ok", "healthy", "up"]:
                            return True
                except (httpx.HTTPError, Exception) as e:
                    logger.debug(f"Health check failed: {e}")
                
                await asyncio.sleep(2)
        
        return False
    
    return check_service_health


@pytest.fixture
def k8s_port_forwarder():
    """Fixture for managing port forwards."""
    import subprocess
    
    port_forwards = []
    
    def create_port_forward(service_name: str, namespace: str, local_port: int, remote_port: int) -> subprocess.Popen:
        """Create a port forward to a Kubernetes service."""
        cmd = [
            "kubectl", "port-forward",
            f"service/{service_name}",
            f"{local_port}:{remote_port}",
            "-n", namespace
        ]
        
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        
        port_forwards.append(proc)
        
        # Give port forward time to establish
        time.sleep(3)
        
        return proc
    
    yield create_port_forward
    
    # Cleanup all port forwards
    for proc in port_forwards:
        proc.terminate()
        proc.wait()


@pytest.fixture
def k8s_service_deployer(k8s_namespace):
    """Fixture for deploying services to Kubernetes."""
    import subprocess
    from pathlib import Path
    
    deployed_services = []
    project_root = Path(__file__).parent.parent.parent
    
    def deploy_service(service_name: str, chart_path: str | None = None, values: dict | None = None) -> bool:
        """Deploy a service using Helm."""
        if chart_path is None:
            chart_path = f"./helm/charts/{service_name}"
        
        helm_cmd = [
            "helm", "upgrade", "--install",
            service_name,
            chart_path,
            "--namespace", k8s_namespace,
            "--wait",
            "--timeout", "120s"
        ]
        
        # Add custom values if provided
        if values:
            import tempfile
            import yaml
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                yaml.dump(values, f)
                helm_cmd.extend(["-f", f.name])
        
        try:
            result = subprocess.run(
                helm_cmd,
                capture_output=True,
                text=True,
                check=True,
                cwd=project_root,
            )
            
            deployed_services.append(service_name)
            logger.info(f"Successfully deployed {service_name}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to deploy {service_name}: {e}")
            logger.error(f"stdout: {e.stdout}")
            logger.error(f"stderr: {e.stderr}")
            return False
    
    yield deploy_service
    
    # Cleanup deployed services
    for service_name in deployed_services:
        try:
            subprocess.run(
                ["helm", "uninstall", service_name, "-n", k8s_namespace],
                capture_output=True,
                check=False,
            )
        except Exception as e:
            logger.warning(f"Failed to cleanup {service_name}: {e}")


@pytest.fixture
def k8s_grpc_client():
    """Fixture for creating gRPC clients to Kubernetes services."""
    import grpc
    
    channels = []
    
    def create_grpc_channel(host: str, port: int, secure: bool = False) -> grpc.Channel:
        """Create a gRPC channel."""
        address = f"{host}:{port}"
        
        if secure:
            channel = grpc.secure_channel(address, grpc.ssl_channel_credentials())
        else:
            channel = grpc.insecure_channel(address)
        
        channels.append(channel)
        return channel
    
    yield create_grpc_channel
    
    # Cleanup channels
    for channel in channels:
        channel.close()


@pytest.fixture
def k8s_service_discovery():
    """Fixture for service discovery in Kubernetes."""
    import subprocess
    import json
    
    def get_service_endpoints(service_name: str, namespace: str) -> list[dict]:
        """Get service endpoints."""
        try:
            result = subprocess.run(
                ["kubectl", "get", "endpoints", service_name, "-n", namespace, "-o", "json"],
                capture_output=True,
                text=True,
                check=True,
            )
            
            endpoints_data = json.loads(result.stdout)
            endpoints = []
            
            for subset in endpoints_data.get("subsets", []):
                for address in subset.get("addresses", []):
                    for port in subset.get("ports", []):
                        endpoints.append({
                            "ip": address["ip"],
                            "port": port["port"],
                            "protocol": port.get("protocol", "TCP"),
                        })
            
            return endpoints
            
        except subprocess.CalledProcessError:
            return []
    
    def get_service_url(service_name: str, namespace: str, port: int | None = None) -> str:
        """Get service URL for cluster-internal access."""
        if port:
            return f"http://{service_name}.{namespace}.svc.cluster.local:{port}"
        else:
            # Get the first port from service definition
            try:
                result = subprocess.run(
                    ["kubectl", "get", "service", service_name, "-n", namespace, "-o", "json"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                
                service_data = json.loads(result.stdout)
                ports = service_data.get("spec", {}).get("ports", [])
                if ports:
                    service_port = ports[0]["port"]
                    return f"http://{service_name}.{namespace}.svc.cluster.local:{service_port}"
                
            except subprocess.CalledProcessError:
                pass
        
        return f"http://{service_name}.{namespace}.svc.cluster.local"
    
    return {
        "get_endpoints": get_service_endpoints,
        "get_url": get_service_url,
    }


@pytest.fixture
def k8s_wait_for_deployment():
    """Fixture for waiting for deployments to be ready."""
    import subprocess
    
    def wait_for_deployment(deployment_name: str, namespace: str, timeout: int = 300) -> bool:
        """Wait for a deployment to be ready."""
        try:
            result = subprocess.run(
                [
                    "kubectl", "wait", "--for=condition=available",
                    f"deployment/{deployment_name}",
                    "-n", namespace,
                    f"--timeout={timeout}s"
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            
            return "condition met" in result.stdout
            
        except subprocess.CalledProcessError:
            return False
    
    return wait_for_deployment


@pytest.fixture
def k8s_logs_collector():
    """Fixture for collecting logs from Kubernetes pods."""
    import subprocess
    
    def get_pod_logs(pod_selector: str, namespace: str, container: str | None = None) -> str:
        """Get logs from pods matching selector."""
        cmd = ["kubectl", "logs", "-l", pod_selector, "-n", namespace]
        
        if container:
            cmd.extend(["-c", container])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
            )
            
            return result.stdout
            
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to get logs: {e}")
            return ""
    
    def get_deployment_logs(deployment_name: str, namespace: str) -> str:
        """Get logs from all pods in a deployment."""
        return get_pod_logs(f"app={deployment_name}", namespace)
    
    return {
        "get_pod_logs": get_pod_logs,
        "get_deployment_logs": get_deployment_logs,
    }


@pytest.fixture
def k8s_resource_monitor():
    """Fixture for monitoring Kubernetes resource usage."""
    import subprocess
    import json
    
    def get_resource_usage(namespace: str) -> dict:
        """Get resource usage for namespace."""
        try:
            # Get pod resource usage
            result = subprocess.run(
                ["kubectl", "top", "pods", "-n", namespace, "--no-headers"],
                capture_output=True,
                text=True,
                check=True,
            )
            
            pod_usage = {}
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split()
                    if len(parts) >= 3:
                        pod_name = parts[0]
                        cpu = parts[1]
                        memory = parts[2]
                        pod_usage[pod_name] = {"cpu": cpu, "memory": memory}
            
            return {"pods": pod_usage}
            
        except subprocess.CalledProcessError:
            return {"pods": {}}
    
    return get_resource_usage


# Convenience fixture that combines multiple K8s fixtures
@pytest.fixture
def k8s_test_suite(
    k8s_namespace,
    k8s_service_deployer,
    k8s_port_forwarder,
    k8s_service_health_checker,
    k8s_grpc_client,
    k8s_service_discovery,
    k8s_wait_for_deployment,
):
    """Combined fixture providing all K8s testing utilities."""
    return {
        "namespace": k8s_namespace,
        "deploy_service": k8s_service_deployer,
        "port_forward": k8s_port_forwarder,
        "check_health": k8s_service_health_checker,
        "grpc_client": k8s_grpc_client,
        "discovery": k8s_service_discovery,
        "wait_for_deployment": k8s_wait_for_deployment,
    }