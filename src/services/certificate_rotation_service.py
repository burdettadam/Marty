#!/usr/bin/env python3
"""
Certificate Rotation Service

This service automates the rotation of certificates based on configured security policies.
It works with the Certificate Lifecycle Monitor to identify certificates needing renewal
and automatically processes them according to the defined rotation policy.
"""

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

import grpc

from src.proto import csca_service_pb2, csca_service_pb2_grpc
from src.services.certificate_lifecycle_monitor import CertificateLifecycleMonitor


class CertificateRotationService:
    """
    Service for automatic rotation of certificates based on security policies.

    This class provides functionality to:
    1. Identify certificates approaching expiration date
    2. Automatically renew certificates based on policy
    3. Schedule future renewals
    4. Maintain an overlap period between old and new certificates
    """

    def __init__(
        self,
        csca_endpoint: Optional[str] = None,
        config_file: Optional[str] = None,
        history_file: Optional[str] = None,
        lifecycle_monitor: CertificateLifecycleMonitor = None,
    ) -> None:
        """
        Initialize the Certificate Rotation Service.

        Args:
            csca_endpoint: gRPC endpoint for the CSCA service
            config_file: Path to the rotation configuration file
            history_file: Path to the rotation history file
            lifecycle_monitor: An existing CertificateLifecycleMonitor instance to share
        """
        self.logger = logging.getLogger(__name__)

        # Default configuration
        self.config = {
            "rotation_policy": {
                "standard_cert_validity_days": 1095,  # 3 years
                "root_ca_validity_days": 3650,  # 10 years
                "key_algorithm": "RSA",
                "key_size": 2048,
                "auto_renew_days_before": 90,  # Auto-renew 90 days before expiry
                "overlap_period_days": 30,  # 30-day overlap between old and new certs
            },
            "check_interval": 24,  # Hours between checks
            "rotation_history_file": os.path.join("data", "csca", "rotation_history.json"),
        }

        # Set up CSCA service endpoint
        self.csca_endpoint = csca_endpoint or os.environ.get(
            "CSCA_SERVICE_ENDPOINT", "localhost:8081"
        )

        # Load configuration if specified or fall back to defaults
        if config_file:
            self._load_config(config_file)
        else:
            # Try to find the config file in common locations
            for path in [
                os.path.join("config", "certificate_lifecycle_monitor.json"),
                os.path.join("config", "certificate_rotation.json"),
            ]:
                if os.path.exists(path):
                    self._load_config(path)
                    break

        # Set up rotation history tracking
        self.history_file = history_file or self.config.get("rotation_history_file")
        self.rotation_history = self._load_rotation_history()

        # Set up or reuse the lifecycle monitor
        if lifecycle_monitor:
            self.lifecycle_monitor = lifecycle_monitor
        else:
            self.lifecycle_monitor = CertificateLifecycleMonitor(
                csca_endpoint=self.csca_endpoint, config_file=config_file
            )

        # Internal state
        self.running = False
        self.rotation_thread = None

    def _load_config(self, config_file: str) -> None:
        """
        Load configuration from a JSON file.

        Args:
            config_file: Path to the configuration file
        """
        try:
            if os.path.exists(config_file):
                with open(config_file) as f:
                    loaded_config = json.load(f)

                    # Make sure rotation policy exists
                    if "rotation_policy" in loaded_config:
                        self.config.update(loaded_config)
                    elif "rotation_policy" not in self.config:
                        # Create a default rotation policy if none exists
                        self.config["rotation_policy"] = {
                            "standard_cert_validity_days": 1095,
                            "root_ca_validity_days": 3650,
                            "key_algorithm": "RSA",
                            "key_size": 2048,
                            "auto_renew_days_before": 90,
                            "overlap_period_days": 30,
                        }

                    self.logger.info(f"Loaded configuration from {config_file}")
            else:
                self.logger.warning(f"Configuration file {config_file} not found, using defaults")
        except Exception as e:
            self.logger.exception(f"Error loading configuration: {e}")

    def _load_rotation_history(self) -> dict[str, Any]:
        """
        Load rotation history from the history file.

        Returns:
            Dictionary mapping certificate IDs to rotation details
        """
        history = {}
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file) as f:
                    history = json.load(f)
                    self.logger.info(f"Loaded rotation history from {self.history_file}")
        except Exception as e:
            self.logger.exception(f"Error loading rotation history: {e}")

        return history

    def _save_rotation_history(self) -> None:
        """Save the current rotation history to the history file."""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.history_file), exist_ok=True)

            with open(self.history_file, "w") as f:
                json.dump(self.rotation_history, f, indent=2)
                self.logger.debug(f"Saved rotation history to {self.history_file}")
        except Exception as e:
            self.logger.exception(f"Error saving rotation history: {e}")

    def record_rotation(self, old_cert_id: str, new_cert_id: str) -> None:
        """
        Record that a certificate has been rotated.

        Args:
            old_cert_id: ID of the certificate that was replaced
            new_cert_id: ID of the new certificate
        """
        now = datetime.now(timezone.utc).isoformat()

        rotation_record = {
            "old_certificate_id": old_cert_id,
            "new_certificate_id": new_cert_id,
            "rotation_date": now,
        }

        # Store in history by old cert ID
        self.rotation_history[old_cert_id] = rotation_record

        # Also add a reference by new cert ID for chain tracking
        self.rotation_history[f"predecessor_{new_cert_id}"] = old_cert_id

        self._save_rotation_history()
        self.logger.info(f"Recorded rotation: {old_cert_id} -> {new_cert_id}")

    def find_certificates_for_rotation(self) -> list[dict[str, Any]]:
        """
        Find certificates that should be rotated based on policy.

        Returns:
            List of dictionaries with details about certificates needing rotation
        """
        try:
            # Use the existing lifecycle monitor to find expiring certificates
            policy = self.config.get("rotation_policy", {})
            auto_renew_days = policy.get("auto_renew_days_before", 90)

            with grpc.insecure_channel(self.csca_endpoint) as channel:
                stub = csca_service_pb2_grpc.CscaServiceStub(channel)

                # Request expiring certificates
                expiry_request = csca_service_pb2.CheckExpiringCertificatesRequest(
                    days_threshold=auto_renew_days
                )

                expiry_response = stub.CheckExpiringCertificates(expiry_request)

                # Filter out certificates that have already been rotated
                certificates_for_rotation = []

                for cert in expiry_response.certificates:
                    # Skip if already rotated
                    if cert.certificate_id in self.rotation_history:
                        continue

                    # Get detailed certificate information
                    status_request = csca_service_pb2.CertificateStatusRequest(
                        certificate_id=cert.certificate_id
                    )
                    status_response = stub.GetCertificateStatus(status_request)

                    # Add to the list if not already rotated
                    certificates_for_rotation.append(
                        {
                            "certificate_id": cert.certificate_id,
                            "subject": cert.subject,
                            "issuer": cert.issuer,
                            "expires": cert.not_after,
                            "is_ca": "CA:TRUE"
                            in status_response.extensions.get("basicConstraints", ""),
                            "key_usage": status_response.extensions.get("keyUsage", ""),
                        }
                    )

                return certificates_for_rotation

        except Exception as e:
            self.logger.exception(f"Error finding certificates for rotation: {e}")
            return []

    def rotate_certificate(self, cert_info: dict[str, Any]) -> Optional[str]:
        """
        Rotate a single certificate based on its information.

        Args:
            cert_info: Dictionary with certificate information

        Returns:
            The new certificate ID if rotation was successful, None otherwise
        """
        try:
            policy = self.config.get("rotation_policy", {})

            # Determine validity period based on certificate type
            if cert_info.get("is_ca", False):
                validity_days = policy.get("root_ca_validity_days", 3650)
            else:
                validity_days = policy.get("standard_cert_validity_days", 1095)

            with grpc.insecure_channel(self.csca_endpoint) as channel:
                stub = csca_service_pb2_grpc.CscaServiceStub(channel)

                # Create renewal request
                renew_request = csca_service_pb2.RenewCertificateRequest(
                    certificate_id=cert_info["certificate_id"],
                    validity_days=validity_days,
                    reuse_key=False,  # Always generate new keys for security
                )

                self.logger.info(
                    f"Initiating rotation for certificate {cert_info['certificate_id']}"
                )

                # Request renewal
                renew_response = stub.RenewCertificate(renew_request)

                if renew_response.status == "ISSUED":
                    # Record the rotation
                    self.record_rotation(cert_info["certificate_id"], renew_response.certificate_id)

                    # Notify about the successful rotation
                    self.logger.info(
                        f"Successfully rotated certificate {cert_info['certificate_id']} "
                        f"to new certificate {renew_response.certificate_id}"
                    )

                    return renew_response.certificate_id
                self.logger.error(
                    f"Failed to rotate certificate {cert_info['certificate_id']}: "
                    f"{renew_response.error_message}"
                )
                return None

        except Exception as e:
            self.logger.exception(f"Error during certificate rotation: {e}")
            return None

    def perform_certificate_rotation(self) -> dict[str, Any]:
        """
        Perform certificate rotation for all certificates needing renewal.

        Returns:
            Dictionary with rotation results
        """
        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "certificates_rotated": [],
            "certificates_failed": [],
        }

        # Find certificates that need rotation
        certificates_for_rotation = self.find_certificates_for_rotation()

        for cert_info in certificates_for_rotation:
            # Rotate the certificate
            new_cert_id = self.rotate_certificate(cert_info)

            if new_cert_id:
                results["certificates_rotated"].append(
                    {
                        "old_cert_id": cert_info["certificate_id"],
                        "new_cert_id": new_cert_id,
                        "subject": cert_info["subject"],
                    }
                )
            else:
                results["certificates_failed"].append(
                    {"certificate_id": cert_info["certificate_id"], "subject": cert_info["subject"]}
                )

        return results

    def rotation_loop(self) -> None:
        """
        Main rotation loop that runs at configured intervals.
        """
        self.logger.info("Certificate Rotation Service started")

        while self.running:
            try:
                results = self.perform_certificate_rotation()

                # Log the rotation results
                rotated_count = len(results["certificates_rotated"])
                failed_count = len(results["certificates_failed"])

                if rotated_count > 0:
                    self.logger.info(f"Rotated {rotated_count} certificates")
                    for entry in results["certificates_rotated"]:
                        self.logger.info(
                            f"  - {entry['subject']} ({entry['old_cert_id']} -> {entry['new_cert_id']})"
                        )

                if failed_count > 0:
                    self.logger.warning(f"Failed to rotate {failed_count} certificates")
                    for entry in results["certificates_failed"]:
                        self.logger.warning(f"  - {entry['subject']} ({entry['certificate_id']})")

                if rotated_count == 0 and failed_count == 0:
                    self.logger.info("No certificates need rotation at this time")

            except Exception as e:
                self.logger.exception(f"Error in rotation loop: {e}")

            # Sleep for the configured interval
            check_interval_hours = self.config.get("check_interval", 24)
            sleep_seconds = check_interval_hours * 3600

            # Sleep in smaller intervals to allow graceful shutdown
            for _ in range(int(sleep_seconds / 10) or 1):
                if not self.running:
                    break
                time.sleep(min(10, sleep_seconds))

    def start(self) -> None:
        """Start the rotation service."""
        if not self.running:
            self.running = True
            self.rotation_thread = threading.Thread(target=self.rotation_loop)
            self.rotation_thread.daemon = True
            self.rotation_thread.start()
            self.logger.info("Certificate Rotation Service started")

    def stop(self) -> None:
        """Stop the rotation service."""
        self.running = False
        if self.rotation_thread and self.rotation_thread.is_alive():
            self.rotation_thread.join(30)  # Wait up to 30 seconds for the thread to finish
            self.logger.info("Certificate Rotation Service stopped")

    def rotate_now(self) -> dict[str, Any]:
        """
        Immediately perform certificate rotation and return results.

        Returns:
            Dictionary with rotation results
        """
        return self.perform_certificate_rotation()


# Command line interface for manual testing
if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    if len(sys.argv) > 1 and sys.argv[1] == "daemon":
        # Run as a daemon
        service = CertificateRotationService()
        service.start()

        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            service.stop()
            print("Service stopped")
    else:
        # Run a single rotation check
        service = CertificateRotationService()
        results = service.rotate_now()

        print("\nCertificate Rotation Results:")
        print(f"Timestamp: {results['timestamp']}")

        print("\nCertificates Rotated:")
        if results["certificates_rotated"]:
            for entry in results["certificates_rotated"]:
                print(f"- {entry['subject']}")
                print(f"  Old Certificate ID: {entry['old_cert_id']}")
                print(f"  New Certificate ID: {entry['new_cert_id']}")
        else:
            print("None")

        print("\nCertificates Failed to Rotate:")
        if results["certificates_failed"]:
            for entry in results["certificates_failed"]:
                print(f"- {entry['subject']} ({entry['certificate_id']})")
        else:
            print("None")
