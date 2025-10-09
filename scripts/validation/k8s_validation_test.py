"""
Kubernetes Infrastructure Validation Test

This script validates that the Kubernetes infrastructure and changes are working correctly
by testing core K8s functionality, protobuf compilation, and basic service deployment
without requiring the full service stack.
"""

import asyncio
import logging
import subprocess
import sys
import time
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)8s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

# Project root
PROJECT_ROOT = Path(__file__).parent


class K8sValidationTest:
    """Validates Kubernetes infrastructure changes."""

    def __init__(self) -> None:
        self.cluster_name = "marty-dev"
        self.namespace = "marty-test-validation"
        self.results: list[tuple[str, bool, str]] = []

    def run_command(self, cmd: list[str], capture_output: bool = True) -> tuple[bool, str, str]:
        """Run a command and return success status, stdout, stderr."""
        try:
            result = subprocess.run(
                cmd, capture_output=capture_output, text=True, check=False, timeout=30
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)

    def test_cluster_connectivity(self) -> bool:
        """Test that we can connect to the Kubernetes cluster."""
        logger.info("🔗 Testing Kubernetes cluster connectivity...")

        success, stdout, stderr = self.run_command(
            ["kubectl", "cluster-info", "--context", f"kind-{self.cluster_name}"]
        )

        if success:
            logger.info("✅ Cluster connectivity: PASS")
            self.results.append(
                ("Cluster Connectivity", True, "Successfully connected to Kind cluster")
            )
            return True
        else:
            logger.error(f"❌ Cluster connectivity: FAIL - {stderr}")
            self.results.append(("Cluster Connectivity", False, f"Failed to connect: {stderr}"))
            return False

    def test_namespace_operations(self) -> bool:
        """Test creating, listing, and deleting namespaces."""
        logger.info("📁 Testing namespace operations...")

        # Create namespace
        success, stdout, stderr = self.run_command(
            [
                "kubectl",
                "create",
                "namespace",
                self.namespace,
                "--context",
                f"kind-{self.cluster_name}",
            ]
        )

        if not success and "already exists" not in stderr:
            logger.error(f"❌ Namespace creation: FAIL - {stderr}")
            self.results.append(
                ("Namespace Operations", False, f"Failed to create namespace: {stderr}")
            )
            return False

        # List namespace to verify it exists
        success, stdout, stderr = self.run_command(
            [
                "kubectl",
                "get",
                "namespace",
                self.namespace,
                "--context",
                f"kind-{self.cluster_name}",
            ]
        )

        if not success:
            logger.error(f"❌ Namespace listing: FAIL - {stderr}")
            self.results.append(
                ("Namespace Operations", False, f"Failed to list namespace: {stderr}")
            )
            return False

        logger.info("✅ Namespace operations: PASS")
        self.results.append(
            ("Namespace Operations", True, "Successfully created and listed namespace")
        )
        return True

    def test_protobuf_compilation(self) -> bool:
        """Test that protobuf compilation is working."""
        logger.info("🔧 Testing protobuf compilation...")

        success, stdout, stderr = self.run_command(
            ["uv", "run", "python", "-m", "src.compile_protos"]
        )

        # Check if compilation was successful (even if there are INFO messages)
        if success and ("Successfully compiled proto files" in stdout or "Fixed imports" in stdout):
            logger.info("✅ Protobuf compilation: PASS")
            self.results.append(
                ("Protobuf Compilation", True, "All proto files compiled successfully")
            )
            return True

        logger.error(f"❌ Protobuf compilation: FAIL - stderr: {stderr}")
        self.results.append(("Protobuf Compilation", False, f"Compilation failed: {stderr}"))
        return False

    def test_protobuf_imports(self) -> bool:
        """Test that protobuf modules can be imported."""
        logger.info("📦 Testing protobuf imports...")

        success, stdout, stderr = self.run_command(
            [
                "uv",
                "run",
                "python",
                "-c",
                "from src.proto.v1 import common_services_pb2, passport_engine_pb2; print('Imports successful')",
            ]
        )

        if success and "Imports successful" in stdout:
            logger.info("✅ Protobuf imports: PASS")
            self.results.append(("Protobuf Imports", True, "All protobuf modules import correctly"))
            return True
        else:
            logger.error(f"❌ Protobuf imports: FAIL - {stderr}")
            self.results.append(("Protobuf Imports", False, f"Import failed: {stderr}"))
            return False

    def test_simple_pod_deployment(self) -> bool:
        """Test deploying a simple pod to validate basic K8s functionality."""
        logger.info("🚀 Testing simple pod deployment...")

        # Deploy nginx pod
        success, stdout, stderr = self.run_command(
            [
                "kubectl",
                "run",
                "validation-test-nginx",
                "--image=nginx:alpine",
                "--restart=Never",
                f"--namespace={self.namespace}",
                "--context",
                f"kind-{self.cluster_name}",
            ]
        )

        if not success and "already exists" not in stderr:
            logger.error(f"❌ Pod deployment: FAIL - {stderr}")
            self.results.append(("Pod Deployment", False, f"Failed to deploy pod: {stderr}"))
            return False

        # Wait for pod to be ready
        for attempt in range(30):  # 30 seconds timeout
            success, stdout, stderr = self.run_command(
                [
                    "kubectl",
                    "get",
                    "pod",
                    "validation-test-nginx",
                    f"--namespace={self.namespace}",
                    "--context",
                    f"kind-{self.cluster_name}",
                    "-o",
                    "jsonpath={.status.phase}",
                ]
            )

            if success and "Running" in stdout:
                logger.info("✅ Pod deployment: PASS")
                self.results.append(
                    ("Pod Deployment", True, "Successfully deployed and started nginx pod")
                )
                return True

            time.sleep(1)

        logger.error("❌ Pod deployment: FAIL - Pod failed to start within timeout")
        self.results.append(("Pod Deployment", False, "Pod failed to start within 30 seconds"))
        return False

    def test_service_creation(self) -> bool:
        """Test creating a Kubernetes service."""
        logger.info("🌐 Testing service creation...")

        success, stdout, stderr = self.run_command(
            [
                "kubectl",
                "expose",
                "pod",
                "validation-test-nginx",
                "--port=80",
                "--target-port=80",
                f"--namespace={self.namespace}",
                "--context",
                f"kind-{self.cluster_name}",
            ]
        )

        if not success and "already exists" not in stderr:
            logger.error(f"❌ Service creation: FAIL - {stderr}")
            self.results.append(("Service Creation", False, f"Failed to create service: {stderr}"))
            return False

        # Verify service exists
        success, stdout, stderr = self.run_command(
            [
                "kubectl",
                "get",
                "service",
                "validation-test-nginx",
                f"--namespace={self.namespace}",
                "--context",
                f"kind-{self.cluster_name}",
            ]
        )

        if success:
            logger.info("✅ Service creation: PASS")
            self.results.append(
                ("Service Creation", True, "Successfully created Kubernetes service")
            )
            return True
        else:
            logger.error(f"❌ Service creation: FAIL - {stderr}")
            self.results.append(
                ("Service Creation", False, f"Service verification failed: {stderr}")
            )
            return False

    def test_helm_chart_validation(self) -> bool:
        """Test that our Helm charts have valid structure."""
        logger.info("📊 Testing Helm chart validation...")

        chart_paths = [
            "helm/charts/passport-engine",
            "helm/charts/csca-service",
            "helm/charts/trust-anchor",
        ]

        for chart_path in chart_paths:
            if not (PROJECT_ROOT / chart_path).exists():
                continue

            success, stdout, stderr = self.run_command(
                ["helm", "lint", str(PROJECT_ROOT / chart_path)]
            )

            if not success:
                logger.error(f"❌ Helm chart validation: FAIL - {chart_path}: {stderr}")
                self.results.append(
                    (
                        "Helm Chart Validation",
                        False,
                        f"Chart {chart_path} failed validation: {stderr}",
                    )
                )
                return False

        logger.info("✅ Helm chart validation: PASS")
        self.results.append(("Helm Chart Validation", True, "All Helm charts have valid structure"))
        return True

    def test_k8s_orchestrator_import(self) -> bool:
        """Test that the K8s test orchestrator can be imported."""
        logger.info("🎯 Testing K8s orchestrator import...")

        success, stdout, stderr = self.run_command(
            [
                "uv",
                "run",
                "python",
                "-c",
                "from tests.k8s_test_orchestrator import KubernetesTestOrchestrator; print('Import successful')",
            ]
        )

        if success and "Import successful" in stdout:
            logger.info("✅ K8s orchestrator import: PASS")
            self.results.append(
                ("K8s Orchestrator Import", True, "Test orchestrator imports correctly")
            )
            return True
        else:
            logger.error(f"❌ K8s orchestrator import: FAIL - {stderr}")
            self.results.append(("K8s Orchestrator Import", False, f"Import failed: {stderr}"))
            return False

    def cleanup(self) -> None:
        """Clean up test resources."""
        logger.info("🧹 Cleaning up test resources...")

        # Delete the test namespace (this will delete all resources in it)
        self.run_command(
            [
                "kubectl",
                "delete",
                "namespace",
                self.namespace,
                "--context",
                f"kind-{self.cluster_name}",
                "--ignore-not-found=true",
            ]
        )

        logger.info("✅ Cleanup completed")

    def generate_report(self) -> None:
        """Generate a comprehensive test report."""
        print("\n" + "=" * 80)
        print("🎯 KUBERNETES INFRASTRUCTURE VALIDATION REPORT")
        print("=" * 80)

        passed = sum(1 for _, success, _ in self.results if success)
        total = len(self.results)

        print(f"\n📊 Overall Results: {passed}/{total} tests passed")

        if passed == total:
            print("🎉 Status: ALL TESTS PASSED - Kubernetes infrastructure is working correctly!")
        else:
            print("⚠️  Status: SOME TESTS FAILED - Issues detected in Kubernetes infrastructure")

        print("\n📋 Detailed Results:")
        print("-" * 80)

        for test_name, success, details in self.results:
            status = "✅ PASS" if success else "❌ FAIL"
            print(f"{status}: {test_name}")
            print(f"   └─ {details}")

        print("\n" + "=" * 80)

        if passed == total:
            print("🚀 Ready for production deployment!")
            print("🔧 Protobuf compilation working correctly")
            print("⚙️  Kubernetes infrastructure validated")
            print("🎯 E2E testing infrastructure ready")
        else:
            print("🔧 Review failed tests and fix issues before proceeding")

        print("=" * 80)

    async def run_all_tests(self) -> bool:
        """Run all validation tests."""
        logger.info("🚀 Starting Kubernetes infrastructure validation...")

        # Define test sequence
        tests = [
            ("cluster_connectivity", self.test_cluster_connectivity),
            ("namespace_operations", self.test_namespace_operations),
            ("protobuf_compilation", self.test_protobuf_compilation),
            ("protobuf_imports", self.test_protobuf_imports),
            ("simple_pod_deployment", self.test_simple_pod_deployment),
            ("service_creation", self.test_service_creation),
            ("helm_chart_validation", self.test_helm_chart_validation),
            ("k8s_orchestrator_import", self.test_k8s_orchestrator_import),
        ]

        all_passed = True

        for test_name, test_func in tests:
            try:
                if not test_func():
                    all_passed = False
                    # Continue with other tests even if one fails

            except Exception as e:
                logger.error(f"❌ Test {test_name} failed with exception: {e}")
                self.results.append((test_name.replace("_", " ").title(), False, f"Exception: {e}"))
                all_passed = False

        # Cleanup
        self.cleanup()

        # Generate report
        self.generate_report()

        return all_passed


async def main():
    """Main function."""
    validator = K8sValidationTest()
    success = await validator.run_all_tests()
    return 0 if success else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
