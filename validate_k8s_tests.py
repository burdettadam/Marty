#!/usr/bin/env python3
"""
Simple validation test for Kubernetes test fixtures.
This test validates that the K8s infrastructure is working without requiring
full service deployment or protocol buffer compilation.
"""

import asyncio
import logging
import subprocess
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_kubectl_connectivity():
    """Test that we can connect to kubectl."""
    try:
        result = subprocess.run(
            ["kubectl", "cluster-info"],
            capture_output=True,
            text=True,
            check=True,
        )
        logger.info("✅ kubectl connectivity test passed")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ kubectl connectivity test failed: {e}")
        return False


def test_namespace_operations():
    """Test that we can create and delete namespaces."""
    test_namespace = "k8s-test-validation"
    
    try:
        # Create namespace
        subprocess.run(
            ["kubectl", "create", "namespace", test_namespace],
            check=True,
            capture_output=True,
        )
        logger.info(f"✅ Created test namespace: {test_namespace}")
        
        # List namespaces to verify it exists
        result = subprocess.run(
            ["kubectl", "get", "namespaces", test_namespace],
            check=True,
            capture_output=True,
            text=True,
        )
        logger.info("✅ Namespace listing test passed")
        
        # Delete namespace
        subprocess.run(
            ["kubectl", "delete", "namespace", test_namespace],
            check=True,
            capture_output=True,
        )
        logger.info(f"✅ Deleted test namespace: {test_namespace}")
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Namespace operations test failed: {e}")
        return False


def test_k8s_orchestrator_import():
    """Test that our K8s orchestrator can be imported."""
    try:
        from tests.k8s_test_orchestrator import KubernetesTestOrchestrator, TestMode
        
        # Create orchestrator instance
        orchestrator = KubernetesTestOrchestrator(
            project_root=project_root,
            namespace="test-import",
        )
        
        logger.info("✅ K8s orchestrator import test passed")
        logger.info(f"✅ Cluster name: {orchestrator.cluster_name}")
        logger.info(f"✅ Namespace: {orchestrator.namespace}")
        logger.info(f"✅ Services configured: {len(orchestrator.services)}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ K8s orchestrator import test failed: {e}")
        return False


def test_k8s_fixtures_import():
    """Test that our K8s fixtures can be imported."""
    try:
        from tests.fixtures.k8s_fixtures import k8s_cluster
        
        logger.info("✅ K8s fixtures import test passed")
        return True
        
    except Exception as e:
        logger.error(f"❌ K8s fixtures import test failed: {e}")
        return False


async def test_simple_service_deployment():
    """Test deploying a simple nginx service."""
    test_namespace = "k8s-service-test"
    
    try:
        # Create namespace
        subprocess.run(
            ["kubectl", "create", "namespace", test_namespace],
            check=True,
            capture_output=True,
        )
        
        # Deploy simple nginx pod
        subprocess.run([
            "kubectl", "run", "nginx-test",
            "--image=nginx:alpine",
            "--port=80",
            f"--namespace={test_namespace}"
        ], check=True, capture_output=True)
        
        # Wait for pod to be ready
        subprocess.run([
            "kubectl", "wait", "--for=condition=ready",
            "pod/nginx-test",
            f"--namespace={test_namespace}",
            "--timeout=60s"
        ], check=True, capture_output=True)
        
        # Expose as service
        subprocess.run([
            "kubectl", "expose", "pod", "nginx-test",
            "--port=80",
            "--target-port=80",
            f"--namespace={test_namespace}"
        ], check=True, capture_output=True)
        
        logger.info("✅ Simple service deployment test passed")
        
        # Cleanup
        subprocess.run(
            ["kubectl", "delete", "namespace", test_namespace],
            check=True,
            capture_output=True,
        )
        
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Simple service deployment test failed: {e}")
        # Cleanup on failure
        subprocess.run(
            ["kubectl", "delete", "namespace", test_namespace],
            capture_output=True,
        )
        return False


def main():
    """Run validation tests."""
    logger.info("🚀 Starting Kubernetes test validation...")
    
    tests = [
        ("kubectl connectivity", test_kubectl_connectivity),
        ("namespace operations", test_namespace_operations),
        ("K8s orchestrator import", test_k8s_orchestrator_import),
        ("K8s fixtures import", test_k8s_fixtures_import),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        logger.info(f"🧪 Running test: {test_name}")
        try:
            if asyncio.iscoroutinefunction(test_func):
                result = asyncio.run(test_func())
            else:
                result = test_func()
            results.append((test_name, result))
        except Exception as e:
            logger.error(f"❌ Test {test_name} failed with exception: {e}")
            results.append((test_name, False))
    
    # Run async test separately
    logger.info("🧪 Running test: simple service deployment")
    try:
        result = asyncio.run(test_simple_service_deployment())
        results.append(("simple service deployment", result))
    except Exception as e:
        logger.error(f"❌ Test simple service deployment failed with exception: {e}")
        results.append(("simple service deployment", False))
    
    # Summary
    logger.info("\n📊 Test Results Summary:")
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        logger.info(f"  {status}: {test_name}")
        if result:
            passed += 1
    
    logger.info(f"\n🎯 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        logger.info("🎉 All Kubernetes validation tests passed!")
        return 0
    else:
        logger.error("💥 Some Kubernetes validation tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())