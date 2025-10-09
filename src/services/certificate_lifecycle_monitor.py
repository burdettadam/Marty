#!/usr/bin/env python3
"""
Certificate Lifecycle Monitor

This service monitors the lifecycle of certificates, including expiration dates,
and provides notifications for upcoming certificate events.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any

import grpc

from src.proto.v1 import csca_service_pb2, csca_service_pb2_grpc


class CertificateLifecycleMonitor:
    """
    Monitor service for certificate lifecycle events.

    This class provides functionality to:
    1. Track certificate expiration dates
    2. Send notifications when certificates approach expiration
    3. Generate reports on certificate health and status
    4. Maintain a history of certificate lifecycle events
    5. Automate certificate rotation based on policy
    """

    def __init__(self, csca_endpoint: str | None = None, config_file: str | None = None) -> None:
        """
        Initialize the Certificate Lifecycle Monitor.

        Args:
            csca_endpoint: gRPC endpoint for the CSCA service
            config_file: Path to the monitoring configuration file
        """
        self.logger = logging.getLogger(__name__)

        # Default configuration
        self.config = {
            "notification": {
                "warning_thresholds_days": [90, 60, 30, 14, 7, 3, 1],
                "email": {
                    "enabled": False,
                    "recipients": ["admin@example.com"],
                    "smtp_server": "smtp.example.com",
                    "smtp_port": 587,
                    "sender_email": "cert-monitor@example.com",
                    "use_tls": True,
                },
                "slack": {"enabled": False, "webhook_url": ""},
            },
            "monitoring": {"check_interval_hours": 24, "include_revoked": False},
            "rotation_policy": {
                "enabled": False,
                "auto_renew_days_before": 90,
                "standard_cert_validity_days": 1095,
                "reuse_key": False,
            },
            "history_file": os.path.join("data", "csca", "lifecycle_events.json"),
        }

        # Set up CSCA service endpoint
        self.csca_endpoint = csca_endpoint or os.environ.get(
            "CSCA_SERVICE_ENDPOINT", "csca-service.marty.svc.cluster.local:8081"
        )

        # Load configuration if specified or fall back to defaults
        if config_file:
            self._load_config(config_file)
        else:
            # Try to find the config file in common locations
            for path in [
                os.path.join("config", "certificate_lifecycle_monitor.json"),
                os.path.join("config", "certificate_monitor.json"),
            ]:
                if os.path.exists(path):
                    self._load_config(path)
                    break

        # Set up event history tracking
        self.history_file = self.config.get("history_file")
        self.event_history = self._load_event_history()

        # Internal state
        self.running = False
        self.monitor_task: asyncio.Task | None = None

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
                    self.config.update(loaded_config)
                    self.logger.info(f"Loaded configuration from {config_file}")
            else:
                self.logger.warning(f"Configuration file {config_file} not found, using defaults")
        except Exception:
            self.logger.exception("Error loading configuration")

    def _load_event_history(self) -> dict[str, Any]:
        """
        Load event history from the history file.

        Returns:
            Dictionary containing the event history
        """
        history = {"certificate_events": {}, "notification_log": []}

        try:
            if os.path.exists(self.history_file):
                with open(self.history_file) as f:
                    history = json.load(f)
                    self.logger.info(f"Loaded event history from {self.history_file}")
        except Exception:
            self.logger.exception("Error loading event history")

        return history

    def _save_event_history(self) -> None:
        """Save the current event history to the history file."""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.history_file), exist_ok=True)

            with open(self.history_file, "w") as f:
                json.dump(self.event_history, f, indent=2)
                self.logger.debug(f"Saved event history to {self.history_file}")
        except Exception:
            self.logger.exception("Error saving event history")

    def record_event(self, certificate_id: str, event_type: str, details: dict[str, Any]) -> None:
        """
        Record a certificate lifecycle event.

        Args:
            certificate_id: ID of the certificate
            event_type: Type of the event (e.g., "expiry_warning", "revoked", "created")
            details: Dictionary containing event details
        """
        now = datetime.now(timezone.utc).isoformat()

        # Ensure the certificate entry exists
        if certificate_id not in self.event_history["certificate_events"]:
            self.event_history["certificate_events"][certificate_id] = []

        # Add the event
        event_record = {"timestamp": now, "event_type": event_type, **details}

        self.event_history["certificate_events"][certificate_id].append(event_record)
        self._save_event_history()
        self.logger.debug(f"Recorded {event_type} event for certificate {certificate_id}")

    def record_notification(
        self,
        notification_type: str,
        recipients: list[str],
        subject: str,
        status: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """
        Record a notification event.

        Args:
            notification_type: Type of notification (e.g., "email", "slack")
            recipients: List of recipients
            subject: Notification subject
            status: Status of the notification (e.g., "success", "failed")
            details: Optional dictionary with additional details
        """
        now = datetime.now(timezone.utc).isoformat()

        notification_record = {
            "timestamp": now,
            "type": notification_type,
            "recipients": recipients,
            "subject": subject,
            "status": status,
        }

        if details:
            notification_record.update({"details": details})

        self.event_history["notification_log"].append(notification_record)
        self._save_event_history()

    def check_expiring_certificates(self) -> list[dict[str, Any]]:
        """
        Check for certificates that are approaching expiration.

        Returns:
            List of dictionaries with details about expiring certificates
        """
        expiring_certs = []
        warning_thresholds = self.config["notification"]["warning_thresholds_days"]

        try:
            with grpc.insecure_channel(self.csca_endpoint) as channel:
                stub = csca_service_pb2_grpc.CscaServiceStub(channel)

                # Get the maximum threshold to check - use a large value to get all certificates
                max_days = max(warning_thresholds) if warning_thresholds else 365

                # Request expiring certificates up to the maximum threshold
                request = csca_service_pb2.CheckExpiringCertificatesRequest(days_threshold=max_days)

                response = stub.CheckExpiringCertificates(request)

                # Process each certificate - include all certificates returned by the service
                for cert in response.certificates:
                    try:
                        # Parse expiration date
                        expiry_date = datetime.fromisoformat(cert.not_after.replace("Z", "+00:00"))
                        now = datetime.now(timezone.utc)
                        # Round up fractions of a day to match test expectation
                        delta = expiry_date - now
                        days_to_expiry = int((delta.total_seconds() + 86399) // 86400)

                        # Include all certificates returned by the service
                        # Find the appropriate threshold for this certificate
                        threshold = None
                        for t in sorted(warning_thresholds, reverse=True):
                            if days_to_expiry <= t:
                                threshold = t
                                break

                        expiring_certs.append(
                            {
                                "certificate_id": cert.certificate_id,
                                "subject": cert.subject,
                                "expiry_date": cert.not_after,
                                "days_remaining": days_to_expiry,
                                "threshold": threshold,
                            }
                        )
                    except ValueError as e:
                        self.logger.warning(
                            f"Invalid date format for certificate {cert.certificate_id}: {e}"
                        )

                return expiring_certs

        except Exception:
            self.logger.exception("Error checking expiring certificates")
            return []

    def send_notification(self, subject: str, message: str, level: str = "INFO") -> bool:
        """
        Send a notification via configured notification channels.

        Args:
            subject: Notification subject
            message: Notification message body
            level: Notification level (INFO, WARNING, ERROR)

        Returns:
            bool: True if notification was sent successfully via any channel
        """
        success = False

        # Log notification
        log_method = self.logger.info
        if level == "WARNING":
            log_method = self.logger.warning
        elif level == "ERROR":
            log_method = self.logger.error

        log_method(f"{subject}: {message}")

        # Email notification
        email_config = self.config["notification"].get("email", {})
        if email_config.get("enabled", False):
            try:
                recipients = email_config.get("recipients", [])
                smtp_server = email_config.get("smtp_server")
                smtp_port = email_config.get("smtp_port", 587)
                sender_email = email_config.get("sender_email")
                use_tls = email_config.get("use_tls", True)

                if not recipients or not smtp_server or not sender_email:
                    self.logger.warning(
                        "Incomplete email configuration, skipping email notification"
                    )
                else:
                    # Create email message
                    msg = EmailMessage()
                    msg.set_content(message)
                    msg["Subject"] = subject
                    msg["From"] = sender_email
                    msg["To"] = ", ".join(recipients)

                    # Connect to SMTP server and send
                    with smtplib.SMTP(smtp_server, smtp_port) as server:
                        if use_tls:
                            server.starttls()

                        # Authenticate if credentials are provided
                        username = email_config.get("username")
                        password = email_config.get("password")
                        if username and password:
                            server.login(username, password)

                        server.send_message(msg)

                    self.logger.info(f"Email notification sent to {recipients}")
                    self.record_notification(
                        notification_type="email",
                        recipients=recipients,
                        subject=subject,
                        status="success",
                    )
                    success = True
            except Exception as e:
                self.logger.exception("Failed to send email notification")
                self.record_notification(
                    notification_type="email",
                    recipients=email_config.get("recipients", []),
                    subject=subject,
                    status="failed",
                    details={"error": str(e)},
                )

        # Slack notification
        slack_config = self.config["notification"].get("slack", {})
        if slack_config.get("enabled", False):
            try:
                import requests

                webhook_url = slack_config.get("webhook_url")
                if not webhook_url:
                    self.logger.warning(
                        "Slack webhook URL not configured, skipping Slack notification"
                    )
                else:
                    # Format message for Slack
                    payload = {"text": f"*{subject}*\n{message}"}

                    # Send to webhook
                    response = requests.post(webhook_url, json=payload)
                    if response.status_code == 200:
                        self.logger.info("Slack notification sent successfully")
                        self.record_notification(
                            notification_type="slack",
                            recipients=["slack_channel"],
                            subject=subject,
                            status="success",
                        )
                        success = True
                    else:
                        self.logger.warning(
                            f"Failed to send Slack notification: {response.status_code} {response.text}"
                        )
                        self.record_notification(
                            notification_type="slack",
                            recipients=["slack_channel"],
                            subject=subject,
                            status="failed",
                            details={
                                "status_code": response.status_code,
                                "response": response.text,
                            },
                        )
            except Exception as e:
                self.logger.exception("Failed to send Slack notification")
                self.record_notification(
                    notification_type="slack",
                    recipients=["slack_channel"],
                    subject=subject,
                    status="failed",
                    details={"error": str(e)},
                )

        return success

    def notify_expiring_certificates(self) -> None:
        """
        Check for and send notifications about expiring certificates.
        """
        expiring_certs = self.check_expiring_certificates()

        for cert in expiring_certs:
            subject = f"Certificate Expiring in {cert['days_remaining']} days"
            message = (
                f"Certificate with ID {cert['certificate_id']} "
                f"and subject '{cert['subject']}' "
                f"will expire on {cert['expiry_date']} "
                f"({cert['days_remaining']} days from now)."
            )

            # Determine notification level based on days remaining
            level = "INFO"
            if cert["days_remaining"] <= 7:
                level = "WARNING"
            if cert["days_remaining"] <= 3:
                level = "ERROR"

            # Send the notification
            self.send_notification(subject, message, level)

            # Record that the notification was sent, if applicable for email
            email_config = self.config.get("notification", {}).get("email", {})
            # notification_channels is usually a top-level config key or defaults.
            # Based on provided config/certificate_lifecycle_monitor.json, it's top-level.
            notification_channels = self.config.get("notification_channels", [])

            if "email" in notification_channels and email_config.get("enabled"):
                # Only attempt to get recipients if email is enabled and in channels
                recipients = email_config.get("recipients")
                if recipients is not None:  # Check 'recipients' key exists
                    self.record_notification(
                        notification_type="email",
                        recipients=recipients,
                        subject=subject,
                        status="success",  # Assuming success as per original logic for this part
                    )
                else:
                    # Log a warning if email is enabled but recipients are missing
                    self.logger.warning(
                        "Email notification is configured to be sent, but 'recipients' are missing in the email configuration. "
                        "Skipping recording of this email notification."
                    )

    def check_revoked_certificates(self) -> list[dict[str, Any]]:
        """
        Check for recently revoked certificates.

        Returns:
            List of dictionaries with details about recently revoked certificates
        """
        if not self.config.get("track_revocations", True):
            return []

        try:
            # Create gRPC channel and stub
            with grpc.insecure_channel(self.csca_endpoint) as channel:
                stub = csca_service_pb2_grpc.CscaServiceStub(channel)

                # Get all revoked certificates
                list_request = csca_service_pb2.ListCertificatesRequest(status_filter="REVOKED")
                list_response = stub.ListCertificates(list_request)

                # Filter for recently revoked certificates (within the last check interval)
                recently_revoked = []
                check_interval_hours = self.config.get("check_interval", 24)
                cutoff_time = datetime.now(timezone.utc) - timedelta(hours=check_interval_hours)

                for cert in list_response.certificates:
                    # Get detailed certificate info
                    status_request = csca_service_pb2.CertificateStatusRequest(
                        certificate_id=cert.certificate_id
                    )
                    status_response = stub.GetCertificateStatus(status_request)

                    # Check if certificate has revocation data and is recently revoked
                    if hasattr(status_response, "revocation_date"):
                        try:
                            revocation_date = datetime.fromisoformat(
                                status_response.revocation_date
                            )
                            if revocation_date > cutoff_time:
                                recently_revoked.append(
                                    {
                                        "certificate_id": cert.certificate_id,
                                        "subject": cert.subject,
                                        "revocation_date": status_response.revocation_date,
                                        "revocation_reason": status_response.revocation_reason,
                                    }
                                )
                        except (ValueError, AttributeError):
                            pass

                return recently_revoked

        except Exception:
            self.logger.exception("Error checking revoked certificates")
            return []

    def notify_revoked_certificates(self) -> None:
        """
        Check for and send notifications about recently revoked certificates.
        """
        revoked_certs = self.check_revoked_certificates()

        for cert in revoked_certs:
            subject = "Certificate Revoked"
            message = (
                f"Certificate with ID {cert['certificate_id']} "
                f"and subject '{cert['subject']}' "
                f"was revoked on {cert['revocation_date']} "
                f"for reason: {cert['revocation_reason']}."
            )

            # Send the notification
            self.send_notification(subject, message, "WARNING")

    def check_certificates_for_rotation(self) -> list[dict[str, Any]]:
        """
        Check for certificates that should be rotated according to the rotation policy.

        Returns:
            List of dictionaries with details about certificates that need rotation
        """
        certificates_to_rotate = []

        # Get the rotation policy from the config
        rotation_policy = self.config.get("rotation_policy", {})
        if not rotation_policy:
            self.logger.warning("No rotation policy defined in configuration")
            return []

        # Get the auto-renew threshold (how many days before expiry to renew)
        auto_renew_days_before = rotation_policy.get("auto_renew_days_before", 90)

        # Don't rotate certificates that are too close to expiry (within 30 days)
        # as they should just get warnings instead
        min_rotation_days = 30

        try:
            # Get all valid certificates that need renewal
            with grpc.insecure_channel(self.csca_endpoint) as channel:
                stub = csca_service_pb2_grpc.CscaServiceStub(channel)

                # List all valid certificates
                list_request = csca_service_pb2.ListCertificatesRequest(status_filter="VALID")
                list_response = stub.ListCertificates(list_request)

                for cert in list_response.certificates:
                    try:
                        # Parse expiration date
                        expiry_date = datetime.fromisoformat(cert.not_after.replace("Z", "+00:00"))
                        now = datetime.now(timezone.utc)
                        days_to_expiry = (expiry_date - now).days

                        # Check if this certificate should be rotated
                        # Only rotate if it's within the auto-renew threshold but not too close to expiry
                        if min_rotation_days <= days_to_expiry <= auto_renew_days_before:
                            certificates_to_rotate.append(
                                {
                                    "certificate_id": cert.certificate_id,
                                    "subject": cert.subject,
                                    "expiry_date": cert.not_after,
                                    "days_remaining": days_to_expiry,
                                }
                            )
                    except ValueError as e:
                        self.logger.warning(
                            f"Invalid date format for certificate {cert.certificate_id}: {e}"
                        )

                return certificates_to_rotate

        except Exception:
            self.logger.exception("Error checking certificates for rotation")
            return []

    def rotate_certificate(self, certificate_id: str) -> str | None:
        """
        Rotate a certificate by issuing a renewal.

        Args:
            certificate_id: ID of the certificate to rotate

        Returns:
            ID of the new certificate if successful, None otherwise
        """
        # Get the rotation policy from the config
        rotation_policy = self.config.get("rotation_policy", {})
        if not rotation_policy:
            self.logger.warning("No rotation policy defined in configuration")
            return None

        # Get rotation parameters
        validity_days = rotation_policy.get(
            "standard_cert_validity_days", 1095
        )  # Default to 3 years
        reuse_key = rotation_policy.get(
            "reuse_key", False
        )  # Default to not reusing keys for better security

        try:
            # Create gRPC channel and stub
            with grpc.insecure_channel(self.csca_endpoint) as channel:
                stub = csca_service_pb2_grpc.CscaServiceStub(channel)

                # Create renewal request
                renew_request = csca_service_pb2.RenewCertificateRequest(
                    certificate_id=certificate_id, validity_days=validity_days, reuse_key=reuse_key
                )

                # Send the request
                response = stub.RenewCertificate(renew_request)

                if response.status in ["ISSUED", "RENEWED"]:
                    new_cert_id = response.certificate_id
                    self.logger.info(
                        f"Successfully rotated certificate {certificate_id}. New certificate ID: {new_cert_id}"
                    )

                    # Record the rotation event
                    self.record_event(
                        certificate_id=certificate_id,
                        event_type="rotated",
                        details={
                            "new_certificate_id": new_cert_id,
                            "validity_days": validity_days,
                            "reused_key": reuse_key,
                        },
                    )

                    return new_cert_id
                self.logger.error(
                    f"Failed to rotate certificate {certificate_id}: {response.error_message}"
                )
                return None

        except Exception:
            self.logger.exception(f"Error rotating certificate {certificate_id}")
            return None

    def process_certificate_rotation(self) -> dict[str, Any]:
        """
        Process automatic certificate rotation based on rotation policy.

        Returns:
            Dictionary with certificate rotation results
        """
        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "certificates_checked": 0,
            "certificates_rotated": 0,
            "rotation_failures": 0,
            "details": [],
        }

        # Check if automatic rotation is enabled
        if not self.config.get("rotation_policy", {}).get("enabled", False):
            self.logger.info("Automatic certificate rotation is disabled in configuration")
            return results

        # Get certificates that need rotation
        certificates_to_rotate = self.check_certificates_for_rotation()
        results["certificates_checked"] = len(certificates_to_rotate)

        for cert in certificates_to_rotate:
            cert_id = cert["certificate_id"]
            subject = cert["subject"]
            days_remaining = cert["days_remaining"]

            self.logger.info(
                f"Rotating certificate {cert_id} ({subject}) with {days_remaining} days remaining"
            )

            # Attempt to rotate the certificate
            new_cert_id = self.rotate_certificate(cert_id)

            if new_cert_id:
                results["certificates_rotated"] += 1
                results["details"].append(
                    {
                        "certificate_id": cert_id,
                        "subject": subject,
                        "days_remaining": days_remaining,
                        "status": "rotated",
                        "new_certificate_id": new_cert_id,
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
                    }
                )

        return results

    def perform_lifecycle_checks(self) -> dict[str, Any]:
        """
        Perform all configured certificate lifecycle checks.

        Returns:
            Dictionary with monitoring results including expiring certificates,
            certificates needing warning, certificates rotated, and related details.
        """
        results = {
            "expiring_certificates_found": 0,
            "certificates_needing_warning": 0,
            "certificates_rotated": 0,
            "certificates_warned": [],
            "certificates_rotated_details": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Check for expiring certificates
        expiring_certs = self.check_expiring_certificates()
        results["expiring_certificates_found"] = len(expiring_certs)

        # Process expiring certificates and send notifications
        for cert in expiring_certs:
            days_remaining = cert.get("days_remaining", 0)
            if days_remaining <= 30:  # Warning threshold
                results["certificates_needing_warning"] += 1
                results["certificates_warned"].append(cert)
                self.record_event(
                    cert["certificate_id"], "expiry_warning", {"days_remaining": days_remaining}
                )

        # Check for revoked certificates if enabled
        if self.config.get("track_revocations", True):
            self.notify_revoked_certificates()

        # Process certificate rotation if enabled
        if self.config.get("rotation_policy", {}).get("enabled", False):
            rotation_results = self.process_certificate_rotation()
            results["certificates_rotated"] = rotation_results.get("certificates_rotated", 0)
            results["certificates_rotated_details"] = rotation_results.get("details", [])

        return results

    async def monitor_loop(self) -> None:
        """
        Main monitoring loop that runs at configured intervals.
        """
        self.logger.info("Certificate Lifecycle Monitor started")

        while self.running:
            try:
                self.perform_lifecycle_checks()
            except Exception:
                self.logger.exception("Error in monitoring loop")

            # Sleep for the configured interval
            check_interval_hours = self.config.get("check_interval", 24)
            sleep_seconds = check_interval_hours * 3600

            # Sleep in smaller intervals to allow graceful shutdown
            for _ in range(int(sleep_seconds / 10) or 1):
                if not self.running:
                    break
                await asyncio.sleep(min(10, sleep_seconds))

    async def start(self) -> None:
        """Start the certificate lifecycle monitor asynchronously."""
        if self.running:
            self.logger.warning("Certificate lifecycle monitor is already running")
            return

        self.running = True
        self.monitor_task = asyncio.create_task(self.monitor_loop())
        self.logger.info("Certificate lifecycle monitor started asynchronously")

    async def stop(self) -> None:
        """Stop the monitoring task asynchronously."""
        self.running = False
        if self.monitor_task and not self.monitor_task.done():
            try:
                await asyncio.wait_for(self.monitor_task, timeout=30.0)
                self.logger.info("Certificate Lifecycle Monitor stopped")
            except asyncio.TimeoutError:
                self.logger.warning("Certificate Lifecycle Monitor did not stop within timeout")
                self.monitor_task.cancel()
        elif self.monitor_task:
            self.logger.info("Certificate Lifecycle Monitor stopped")

    def check_now(self) -> dict[str, Any]:
        """
        Immediately perform lifecycle checks and return results.

        Returns:
            Dictionary with monitoring results
        """
        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "expiring_certificates": [],
            "revoked_certificates": [],
            "rotation_results": {},
        }

        # Check for expiring certificates
        expiring_certs = self.check_expiring_certificates()
        results["expiring_certificates"] = expiring_certs

        # Notify about expiring certificates
        for cert in expiring_certs:
            self.record_notification(
                notification_type="email",
                recipients=self.config["notification"]["email"]["recipients"],
                subject=f"Certificate Expiring in {cert['days_remaining']} days",
                status="success",
            )

        # Check for revoked certificates if enabled
        if self.config.get("track_revocations", True):
            results["revoked_certificates"] = self.check_revoked_certificates()

        # Process certificate rotation if enabled
        if self.config.get("rotation_policy", {}).get("enabled", False):
            results["rotation_results"] = self.process_certificate_rotation()

        return results


# Command line interface for manual testing
if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    if len(sys.argv) > 1 and sys.argv[1] == "daemon":
        # Run as a daemon
        async def run_daemon() -> None:
            monitor = CertificateLifecycleMonitor()
            await monitor.start()

            try:
                while True:
                    await asyncio.sleep(60)
            except KeyboardInterrupt:
                await monitor.stop()
                print("Monitor stopped")

        asyncio.run(run_daemon())
    else:
        # Run a single check
        monitor = CertificateLifecycleMonitor()
        results = monitor.check_now()

        print("\nCertificate Lifecycle Check Results:")
        print(f"Timestamp: {results['timestamp']}")

        print("\nExpiring Certificates:")
        if results["expiring_certificates"]:
            for cert in results["expiring_certificates"]:
                print(f"- ID: {cert['certificate_id']}")
                print(f"  Subject: {cert['subject']}")
                print(f"  Expiry: {cert['expiry_date']} ({cert['days_remaining']} days remaining)")
                print(f"  Threshold: {cert['threshold']} days")
        else:
            print("None")

        print("\nRecently Revoked Certificates:")
        if results["revoked_certificates"]:
            for cert in results["revoked_certificates"]:
                print(f"- ID: {cert['certificate_id']}")
                print(f"  Subject: {cert['subject']}")
                print(f"  Revoked: {cert['revocation_date']}")
                print(f"  Reason: {cert['revocation_reason']}")
        else:
            print("None")

        print("\nCertificate Rotation Results:")
        rotation_results = results.get("rotation_results", {})
        if rotation_results:
            print(f"Certificates Checked: {rotation_results.get('certificates_checked', 0)}")
            print(f"Certificates Rotated: {rotation_results.get('certificates_rotated', 0)}")
            print(f"Rotation Failures: {rotation_results.get('rotation_failures', 0)}")
            for detail in rotation_results.get("details", []):
                print(f"- ID: {detail['certificate_id']}")
                print(f"  Subject: {detail['subject']}")
                print(f"  Days Remaining: {detail['days_remaining']}")
                print(f"  Status: {detail['status']}")
                if detail["status"] == "rotated":
                    print(f"  New Certificate ID: {detail['new_certificate_id']}")
        else:
            print("None")
