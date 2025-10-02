#!/usr/bin/env python3
"""
Certificate Lifecycle Manager

This service provides complete management of the certificate lifecycle,
integrating the CSCA service with certificate monitoring, rotation,
and notification capabilities.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.services.certificate_lifecycle_monitor import CertificateLifecycleMonitor
    from src.services.csca import CscaService

from src.proto import csca_service_pb2
from src.services.certificate_lifecycle_monitor import CertificateLifecycleMonitor
from src.services.csca import CscaService


class CertificateLifecycleManager:
    """
    Complete lifecycle manager for certificates.

    This class integrates the CSCA service with the Certificate Lifecycle Monitor
    to provide comprehensive certificate management throughout the entire lifecycle:
    - Certificate creation and issuance
    - Certificate status tracking
    - Expiry monitoring and notifications
    - Automatic certificate rotation
    - Certificate revocation management
    - Certificate usage tracking
    - Event history and reporting
    """

    def __init__(
        self,
        csca_service: CscaService | None = None,
        lifecycle_monitor: CertificateLifecycleMonitor | None = None,
        config_file: str | None = None,
    ) -> None:
        """
        Initialize the Certificate Lifecycle Manager.

        Args:
            csca_service: The CSCA service instance (optional, will be created if not provided)
            lifecycle_monitor: The Certificate Lifecycle Monitor instance (optional)
            config_file: Path to the configuration file (optional)
        """
        self.logger = logging.getLogger(__name__)
        self.data_dir = os.environ.get("DATA_DIR", "/app/data")

        # Load configuration
        self.config = self._load_config(config_file)

        # Set up components
        self.csca_service = csca_service or CscaService()

        # If no monitor is provided, create one
        if not lifecycle_monitor:
            monitor_config = self.config.get("lifecycle_monitor", {})
            monitor_config_file = monitor_config.get("config_file")

            # If no monitor config is specified, use the default
            if not monitor_config_file:
                self.lifecycle_monitor = CertificateLifecycleMonitor()
            else:
                self.lifecycle_monitor = CertificateLifecycleMonitor(
                    config_file=monitor_config_file
                )
        else:
            self.lifecycle_monitor = lifecycle_monitor

        # Internal state
        self.background_thread = None
        self.running = False

        self.logger.info("Certificate Lifecycle Manager initialized")

    def _load_config(self, config_file: str | None = None) -> dict[str, Any]:
        """
        Load configuration from a file.

        Args:
            config_file: Path to the configuration file (optional)

        Returns:
            Dictionary containing the configuration
        """
        # Default configuration
        config = {
            "lifecycle_monitor": {
                "config_file": os.path.join("config", "certificate_lifecycle_monitor.json")
            },
            "reporting": {
                "enabled": True,
                "report_interval_days": 7,
                "report_recipients": ["admin@example.com"],
                "include_events": True,
            },
            "background_monitoring": {"enabled": True, "interval_hours": 24},
        }

        # Try to load configuration from file if specified
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file) as f:
                    loaded_config = json.load(f)
                    config.update(loaded_config)
                    self.logger.info(f"Loaded configuration from {config_file}")
            except Exception as e:
                self.logger.exception(f"Error loading configuration from {config_file}: {e}")

        return config

    def create_certificate(
        self,
        subject_name: str,
        validity_days: int = 365,
        key_algorithm: str = "RSA",
        key_size: int = 2048,
        extensions: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """
        Create a new certificate.

        Args:
            subject_name: The subject name for the certificate
            validity_days: Number of days the certificate is valid
            key_algorithm: The key algorithm to use (RSA, ECDSA)
            key_size: The key size in bits
            extensions: Optional X.509 extensions

        Returns:
            Dictionary with certificate information
        """
        self.logger.info(f"Creating certificate for subject {subject_name}")

        # Create the request object
        request = csca_service_pb2.CreateCertificateRequest(
            subject_name=subject_name,
            validity_days=validity_days,
            key_algorithm=key_algorithm,
            key_size=key_size,
        )

        # If extensions are provided, add them to the request
        if extensions:
            for key, value in extensions.items():
                request.extensions[key] = value

        # Call the CSCA service
        response = self.csca_service.CreateCertificate(request, None)

        # Check if the certificate was created successfully
        if response.status != "ISSUED":
            self.logger.error(f"Failed to create certificate: {response.error_message}")
            return {"success": False, "error": response.error_message}

        # Record the certificate creation event
        if hasattr(self.lifecycle_monitor, "record_event"):
            self.lifecycle_monitor.record_event(
                certificate_id=response.certificate_id,
                event_type="created",
                details={
                    "subject": subject_name,
                    "validity_days": validity_days,
                    "key_algorithm": key_algorithm,
                    "key_size": key_size,
                },
            )

        # Return the certificate information
        return {
            "success": True,
            "certificate_id": response.certificate_id,
            "certificate_data": response.certificate_data,
            "status": response.status,
        }

    def renew_certificate(
        self, certificate_id: str, validity_days: int | None = None, reuse_key: bool = False
    ) -> dict[str, Any]:
        """
        Renew an existing certificate.

        Args:
            certificate_id: The ID of the certificate to renew
            validity_days: Number of days the new certificate is valid (optional)
            reuse_key: Whether to reuse the existing key pair

        Returns:
            Dictionary with renewed certificate information
        """
        self.logger.info(f"Renewing certificate {certificate_id}")

        # Create the request object
        request = csca_service_pb2.RenewCertificateRequest(
            certificate_id=certificate_id, reuse_key=reuse_key
        )

        # Set validity days if provided
        if validity_days:
            request.validity_days = validity_days

        # Call the CSCA service
        response = self.csca_service.RenewCertificate(request, None)

        # Check if the certificate was renewed successfully
        if response.status not in ("RENEWED", "ISSUED"):
            self.logger.error(f"Failed to renew certificate: {response.error_message}")
            return {"success": False, "error": response.error_message}

        # Record the certificate renewal event
        if hasattr(self.lifecycle_monitor, "record_event"):
            self.lifecycle_monitor.record_event(
                certificate_id=certificate_id,
                event_type="renewed",
                details={
                    "new_certificate_id": response.certificate_id,
                    "validity_days": validity_days if validity_days else "default",
                    "reused_key": reuse_key,
                },
            )

            # Also record the event for the new certificate
            self.lifecycle_monitor.record_event(
                certificate_id=response.certificate_id,
                event_type="created",
                details={
                    "renewed_from": certificate_id,
                    "validity_days": validity_days if validity_days else "default",
                    "is_renewal": True,
                },
            )

        # Return the certificate information
        return {
            "success": True,
            "certificate_id": response.certificate_id,
            "certificate_data": response.certificate_data,
            "status": response.status,
            "old_certificate_id": certificate_id,
        }

    def revoke_certificate(self, certificate_id: str, reason: str) -> dict[str, Any]:
        """
        Revoke a certificate.

        Args:
            certificate_id: The ID of the certificate to revoke
            reason: The reason for revocation

        Returns:
            Dictionary with revocation status
        """
        self.logger.info(f"Revoking certificate {certificate_id} for reason: {reason}")

        # Create the request object
        request = csca_service_pb2.RevokeCertificateRequest(
            certificate_id=certificate_id, reason=reason
        )

        # Call the CSCA service
        response = self.csca_service.RevokeCertificate(request, None)

        # Check if the certificate was revoked successfully
        if not response.success:
            self.logger.error(f"Failed to revoke certificate: {response.error_message}")
            return {"success": False, "error": response.error_message}

        # Record the certificate revocation event
        if hasattr(self.lifecycle_monitor, "record_event"):
            self.lifecycle_monitor.record_event(
                certificate_id=certificate_id,
                event_type="revoked",
                details={"reason": reason, "timestamp": datetime.now(timezone.utc).isoformat()},
            )

        # Return the revocation status
        return {"success": True, "certificate_id": certificate_id, "status": response.status}

    def get_certificate_status(self, certificate_id: str) -> dict[str, Any]:
        """
        Get the status of a certificate.

        Args:
            certificate_id: The ID of the certificate

        Returns:
            Dictionary with certificate status information
        """
        self.logger.debug(f"Getting status for certificate {certificate_id}")

        # Create the request object
        request = csca_service_pb2.CertificateStatusRequest(certificate_id=certificate_id)

        # Call the CSCA service
        response = self.csca_service.GetCertificateStatus(request, None)

        # Convert the response to a dictionary
        status_info = {"certificate_id": certificate_id, "status": response.status}

        # Add other fields if they exist
        if hasattr(response, "not_before") and response.not_before:
            status_info["not_before"] = response.not_before

        if hasattr(response, "not_after") and response.not_after:
            status_info["not_after"] = response.not_after

        if hasattr(response, "subject") and response.subject:
            status_info["subject"] = response.subject

        if hasattr(response, "issuer") and response.issuer:
            status_info["issuer"] = response.issuer

        if hasattr(response, "revocation_reason") and response.revocation_reason:
            status_info["revocation_reason"] = response.revocation_reason

        if hasattr(response, "revocation_date") and response.revocation_date:
            status_info["revocation_date"] = response.revocation_date

        return status_info

    def list_certificates(
        self, status_filter: str | None = None, subject_filter: str | None = None
    ) -> list[dict[str, Any]]:
        """
        List certificates with optional filtering.

        Args:
            status_filter: Filter by certificate status (optional)
            subject_filter: Filter by subject name (optional)

        Returns:
            List of dictionaries with certificate information
        """
        self.logger.debug(f"Listing certificates with status filter: {status_filter}")

        # Create the request object
        request = csca_service_pb2.ListCertificatesRequest()

        if status_filter:
            request.status_filter = status_filter

        if subject_filter:
            request.subject_filter = subject_filter

        # Call the CSCA service
        response = self.csca_service.ListCertificates(request, None)

        # Convert the response to a list of dictionaries
        certificate_list = []

        for cert in response.certificates:
            cert_info = {
                "certificate_id": cert.certificate_id,
                "subject": cert.subject,
                "status": cert.status,
            }

            # Add other fields if they exist
            if hasattr(cert, "not_before") and cert.not_before:
                cert_info["not_before"] = cert.not_before

            if hasattr(cert, "not_after") and cert.not_after:
                cert_info["not_after"] = cert.not_after

            if hasattr(cert, "revocation_reason") and cert.revocation_reason:
                cert_info["revocation_reason"] = cert.revocation_reason

            certificate_list.append(cert_info)

        return certificate_list

    def check_expiring_certificates(self, days_threshold: int = 30) -> list[dict[str, Any]]:
        """
        Check for certificates that will expire within the specified number of days.

        Args:
            days_threshold: Number of days threshold

        Returns:
            List of dictionaries with information about expiring certificates
        """
        self.logger.debug(f"Checking for certificates expiring within {days_threshold} days")

        # Create the request object
        request = csca_service_pb2.CheckExpiringCertificatesRequest(days_threshold=days_threshold)

        # Call the CSCA service
        response = self.csca_service.CheckExpiringCertificates(request, None)

        # Convert the response to a list of dictionaries
        expiring_certificates = []

        for cert in response.certificates:
            # Calculate days remaining until expiry
            try:
                not_after = datetime.fromisoformat(cert.not_after.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                days_remaining = (not_after - now).days
            except ValueError:
                days_remaining = None

            cert_info = {
                "certificate_id": cert.certificate_id,
                "subject": cert.subject,
                "status": cert.status,
                "not_after": cert.not_after,
                "days_remaining": days_remaining,
            }

            expiring_certificates.append(cert_info)

        return expiring_certificates

    def rotate_certificates(self, days_threshold: int = 90) -> dict[str, Any]:
        """
        Automatically rotate certificates that are nearing expiry.

        Args:
            days_threshold: Number of days before expiry to trigger rotation

        Returns:
            Dictionary with rotation results
        """
        self.logger.info(f"Checking for certificates to rotate (threshold: {days_threshold} days)")

        # Use the lifecycle monitor's rotation functionality
        if hasattr(self.lifecycle_monitor, "process_certificate_rotation"):
            return self.lifecycle_monitor.process_certificate_rotation()

        # If the lifecycle monitor doesn't have this method, implement it here
        expiring_certificates = self.check_expiring_certificates(days_threshold)

        results = {
            "certificates_checked": len(expiring_certificates),
            "certificates_rotated": 0,
            "rotation_failures": 0,
            "details": [],
        }

        for cert in expiring_certificates:
            cert_id = cert.get("certificate_id")
            subject = cert.get("subject")
            days_remaining = cert.get("days_remaining")

            # Attempt to renew the certificate
            renewal_result = self.renew_certificate(
                certificate_id=cert_id,
                validity_days=365,  # 1 year by default
                reuse_key=False,  # Generate a new key for better security
            )

            if renewal_result.get("success"):
                results["certificates_rotated"] += 1
                results["details"].append(
                    {
                        "certificate_id": cert_id,
                        "subject": subject,
                        "days_remaining": days_remaining,
                        "status": "rotated",
                        "new_certificate_id": renewal_result.get("certificate_id"),
                    }
                )
            else:
                results["rotation_failures"] += 1
                results["details"].append(
                    {
                        "certificate_id": cert_id,
                        "subject": subject,
                        "days_remaining": days_remaining,
                        "status": "failed",
                        "error": renewal_result.get("error"),
                    }
                )

        return results

    def send_periodic_report(self) -> bool:
        """
        Send a periodic report on certificate status.

        Returns:
            True if the report was sent successfully, False otherwise
        """
        self.logger.info("Generating and sending periodic certificate status report")

        try:
            # Get all certificates
            certificates = self.list_certificates()

            # Count certificates by status
            status_counts = {}
            for cert in certificates:
                status = cert.get("status", "UNKNOWN")
                if status not in status_counts:
                    status_counts[status] = 0
                status_counts[status] += 1

            # Get expiring certificates
            expiring_certificates = self.check_expiring_certificates(90)

            # Generate report message
            report_subject = (
                f"Certificate Status Report - {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
            )
            report_message = f"""Certificate Status Report
Generated: {datetime.now(timezone.utc).isoformat()}

Certificate Summary:
- Total certificates: {len(certificates)}
"""

            # Add status counts
            for status, count in status_counts.items():
                report_message += f"- {status}: {count}\n"

            # Add expiring certificates
            if expiring_certificates:
                report_message += (
                    f"\nCertificates expiring in the next 90 days: {len(expiring_certificates)}\n"
                )
                for cert in expiring_certificates:
                    report_message += (
                        f"- {cert['subject']}: expires in {cert['days_remaining']} days\n"
                    )
            else:
                report_message += "\nNo certificates expiring in the next 90 days\n"

            # Add recent events if configured
            if self.config.get("reporting", {}).get("include_events", True):
                # Get recent events from the lifecycle monitor
                if hasattr(self.lifecycle_monitor, "event_history"):
                    report_message += "\nRecent Certificate Events:\n"

                    # Get the last week of events
                    one_week_ago = datetime.now(timezone.utc) - timedelta(days=7)

                    # Process certificate events
                    recent_events = []
                    for cert_id, events in self.lifecycle_monitor.event_history.get(
                        "certificate_events", {}
                    ).items():
                        for event in events:
                            # Check if the event is recent
                            try:
                                event_time = datetime.fromisoformat(
                                    event.get("timestamp").replace("Z", "+00:00")
                                )
                                if event_time > one_week_ago:
                                    recent_events.append(
                                        {
                                            "certificate_id": cert_id,
                                            "event_type": event.get("event_type"),
                                            "timestamp": event.get("timestamp"),
                                        }
                                    )
                            except (ValueError, AttributeError):
                                pass

                    # Sort events by timestamp
                    recent_events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

                    # Add events to the report
                    for event in recent_events[:10]:  # Limit to 10 most recent events
                        report_message += f"- {event['timestamp']}: {event['certificate_id']} - {event['event_type']}\n"

            # Send the report
            if hasattr(self.lifecycle_monitor, "send_notification"):
                self.lifecycle_monitor.send_notification(
                    subject=report_subject, message=report_message, level="INFO"
                )
                return True
            self.logger.warning(
                "Cannot send report: lifecycle_monitor does not have send_notification method"
            )

        except Exception as e:
            self.logger.exception(f"Error generating or sending periodic report: {e}")
            return False
        else:
            return False

    def perform_lifecycle_checks(self) -> dict[str, Any]:
        """
        Perform all lifecycle management tasks.

        Returns:
            Dictionary with results of the lifecycle checks
        """
        self.logger.info("Performing certificate lifecycle checks")

        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "expiring_certificates": [],
            "rotations_performed": 0,
            "reports_sent": False,
        }

        try:
            # Check for and send notifications about expiring certificates
            if hasattr(self.lifecycle_monitor, "notify_expiring_certificates"):
                self.lifecycle_monitor.notify_expiring_certificates()

            # Get list of expiring certificates
            expiring_certs = self.check_expiring_certificates(90)
            results["expiring_certificates"] = expiring_certs

            # Perform certificate rotations if enabled
            rotation_policy = self.config.get("rotation_policy", {})
            if rotation_policy.get("enabled", True):
                rotation_threshold = rotation_policy.get("auto_renew_days_before", 90)
                rotation_results = self.rotate_certificates(rotation_threshold)
                results["rotations_performed"] = rotation_results.get("certificates_rotated", 0)
                results["rotation_details"] = rotation_results

            # Send periodic report if due
            reporting_config = self.config.get("reporting", {})
            if reporting_config.get("enabled", True):
                # Check if it's time for a report
                report_interval_days = reporting_config.get("report_interval_days", 7)

                # Get the last report time from the lifecycle monitor's event history
                last_report_time = None
                if hasattr(self.lifecycle_monitor, "event_history"):
                    for notification in self.lifecycle_monitor.event_history.get(
                        "notification_log", []
                    ):
                        if notification.get("subject", "").startswith("Certificate Status Report"):
                            try:
                                last_report_time = datetime.fromisoformat(
                                    notification.get("timestamp", "").replace("Z", "+00:00")
                                )
                                break
                            except (ValueError, AttributeError):
                                pass

                # Send report if never sent or due
                if (
                    not last_report_time
                    or (datetime.now(timezone.utc) - last_report_time).days >= report_interval_days
                ):
                    results["reports_sent"] = self.send_periodic_report()

        except Exception as e:
            self.logger.exception(f"Error performing lifecycle checks: {e}")
            results["error"] = str(e)
            return results
        else:
            return results

    def background_monitoring_loop(self) -> None:
        """Background thread for periodic monitoring and lifecycle management."""
        self.logger.info("Starting background monitoring loop")

        while self.running:
            try:
                # Perform lifecycle checks
                self.perform_lifecycle_checks()

            except Exception as e:
                self.logger.exception(f"Error in background monitoring loop: {e}")

            # Sleep for the configured interval
            interval_hours = self.config.get("background_monitoring", {}).get("interval_hours", 24)
            sleep_seconds = interval_hours * 3600

            # Sleep in smaller chunks to allow for graceful shutdown
            for _ in range(int(sleep_seconds / 10) or 1):
                if not self.running:
                    break
                time.sleep(min(10, sleep_seconds))

    def start_background_monitoring(self) -> bool:
        """
        Start background monitoring thread.

        Returns:
            True if started successfully, False otherwise
        """
        if self.running:
            self.logger.warning("Background monitoring is already running")
            return False

        if not self.config.get("background_monitoring", {}).get("enabled", True):
            self.logger.warning("Background monitoring is disabled in configuration")
            return False

        self.running = True
        self.background_thread = threading.Thread(target=self.background_monitoring_loop)
        self.background_thread.daemon = True
        self.background_thread.start()

        self.logger.info("Background monitoring started")
        return True

    def stop_background_monitoring(self) -> bool:
        """
        Stop background monitoring thread.

        Returns:
            True if stopped successfully, False otherwise
        """
        if not self.running:
            self.logger.warning("Background monitoring is not running")
            return False

        self.running = False

        if self.background_thread and self.background_thread.is_alive():
            self.background_thread.join(30)  # Wait up to 30 seconds
            self.logger.info("Background monitoring stopped")
            return True

        return False

    def get_certificate_events(self, certificate_id: str) -> list[dict[str, Any]]:
        """
        Get the event history for a specific certificate.

        Args:
            certificate_id: The ID of the certificate

        Returns:
            List of events for the certificate
        """
        if not hasattr(self.lifecycle_monitor, "event_history"):
            return []

        return self.lifecycle_monitor.event_history.get("certificate_events", {}).get(
            certificate_id, []
        )


# For command line usage
if __name__ == "__main__":
    import argparse

    # Configure logging
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Parse arguments
    parser = argparse.ArgumentParser(description="Certificate Lifecycle Manager")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--check", action="store_true", help="Perform lifecycle checks")
    parser.add_argument("--rotate", action="store_true", help="Rotate expiring certificates")
    parser.add_argument("--report", action="store_true", help="Generate and send a status report")
    parser.add_argument("--daemon", action="store_true", help="Run as a background daemon")

    args = parser.parse_args()

    # Create the lifecycle manager
    manager = CertificateLifecycleManager(config_file=args.config)

    if args.daemon:
        # Run as a background daemon
        manager.start_background_monitoring()
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            manager.stop_background_monitoring()
            print("Manager stopped")
    elif args.check:
        # Perform lifecycle checks
        results = manager.perform_lifecycle_checks()
        print(f"Lifecycle checks completed at {results['timestamp']}")
        print(f"Found {len(results['expiring_certificates'])} certificates expiring soon")
        print(f"Performed {results['rotations_performed']} certificate rotations")
        if results.get("reports_sent"):
            print("Status report sent successfully")
    elif args.rotate:
        # Rotate certificates
        results = manager.rotate_certificates()
        print("Certificate rotation completed")
        print(f"Checked {results['certificates_checked']} certificates")
        print(f"Rotated {results['certificates_rotated']} certificates")
        print(f"Failed {results['rotation_failures']} rotations")
    elif args.report:
        # Send a report
        success = manager.send_periodic_report()
        if success:
            print("Report sent successfully")
        else:
            print("Failed to send report")
    else:
        # Print usage information
        print("Certificate Lifecycle Manager")
        print("Use --check to perform lifecycle checks")
        print("Use --rotate to rotate expiring certificates")
        print("Use --report to generate and send a status report")
        print("Use --daemon to run as a background daemon")
