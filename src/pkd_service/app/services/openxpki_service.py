"""
OpenXPKI Service - Integration layer for OpenXPKI Certificate Management
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta
from typing import Any

import requests
import urllib3

from ..utils.config import get_config

# Disable SSL warnings - should only be used in development
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class OpenXPKIService:
    """
    Service class for interacting with OpenXPKI for CSCA certificate and
    master list management operations.
    """

    def __init__(self) -> None:
        """Initialize the OpenXPKI service with configuration settings"""
        self.config = get_config()
        self.base_url = self.config.get("openxpki", {}).get(
            "base_url", "https://localhost:8443/api/v2"
        )
        self.username = self.config.get("openxpki", {}).get("username", "pkiadmin")
        self.password = self.config.get("openxpki", {}).get("password", "secret")
        self.realm = self.config.get("openxpki", {}).get("realm", "marty")
        self.connection_timeout = self.config.get("openxpki", {}).get("connection_timeout", 30)
        self.read_timeout = self.config.get("openxpki", {}).get("read_timeout", 60)
        self.verify_ssl = self.config.get("openxpki", {}).get("verify_ssl", False)
        self.local_store_path = self.config.get("openxpki", {}).get(
            "local_store_path", "data/trust/openxpki_sync"
        )

        # Create local store path if it doesn't exist
        os.makedirs(self.local_store_path, exist_ok=True)

        # For session management
        self.session = requests.Session()
        self.session_token = None
        self.session_expiry = datetime.now()

    def _authenticate(self) -> bool:
        """
        Authenticate with OpenXPKI to obtain a session token

        Returns:
            bool: True if authentication was successful, False otherwise
        """
        try:
            # Check if we already have a valid session
            if self.session_token and datetime.now() < self.session_expiry:
                return True

            # Build auth request
            auth_data = {
                "method": "login",
                "params": {
                    "username": self.username,
                    "password": self.password,
                    "realm": self.realm,
                },
            }

            # Send auth request
            response = self.session.post(
                f"{self.base_url}/session/login",
                json=auth_data,
                verify=self.verify_ssl,
                timeout=(self.connection_timeout, self.read_timeout),
            )

            # Check response
            if response.status_code == 200:
                result = response.json()
                if result.get("status") == "success":
                    self.session_token = result.get("data", {}).get("session_id")
                    # Set session expiry to 1 hour from now
                    self.session_expiry = datetime.now() + timedelta(hours=1)
                    logger.info("Successfully authenticated with OpenXPKI")
                    return True
                logger.error(f"Authentication failed: {result.get('error')}")
            else:
                logger.error(f"Authentication request failed with status {response.status_code}")

        except Exception as e:
            logger.exception(f"Error during authentication: {e!s}")
            return False
        else:
            return False

    def _api_request(
        self, endpoint: str, method: str = "GET", data: dict[str, Any] | None = None
    ) -> tuple[bool, Any]:
        """
        Make an authenticated request to the OpenXPKI API

        Args:
            endpoint: API endpoint to call
            method: HTTP method to use
            data: Optional data to send

        Returns:
            tuple: (success, response_data)
        """
        try:
            # Ensure we're authenticated
            if not self._authenticate():
                return False, {"error": "Authentication failed"}

            # Prepare request
            url = f"{self.base_url}/{endpoint}"
            headers = {"X-OpenXPKI-Session": self.session_token}

            # Make request
            if method.upper() == "GET":
                response = self.session.get(
                    url,
                    headers=headers,
                    verify=self.verify_ssl,
                    timeout=(self.connection_timeout, self.read_timeout),
                )
            else:
                response = self.session.post(
                    url,
                    json=data,
                    headers=headers,
                    verify=self.verify_ssl,
                    timeout=(self.connection_timeout, self.read_timeout),
                )

            # Process response
            if response.status_code == 200:
                result = response.json()
                if result.get("status") == "success":
                    return True, result.get("data", {})
                logger.error(f"API request failed: {result.get('error')}")
                return False, result
            if response.status_code == 401:
                # Session expired, clear token and try again
                self.session_token = None
                return self._api_request(endpoint, method, data)
            logger.error(f"API request failed with status {response.status_code}")

        except Exception as e:
            logger.exception(f"Error during API request: {e!s}")
            return False, {"error": str(e)}
        else:
            return False, {"error": f"HTTP {response.status_code}"}

    def get_server_status(self) -> dict[str, Any]:
        """
        Get the status of the OpenXPKI server

        Returns:
            dict: Server status information
        """
        success, data = self._api_request("system/status")
        if success:
            return {
                "status": "online",
                "version": data.get("version", "unknown"),
                "node_name": data.get("server", {}).get("node_name", "unknown"),
                "total_certificates": data.get("database", {}).get("cert_count", 0),
                "healthy": True,
            }
        return {"status": "offline", "healthy": False, "error": data.get("error", "Unknown error")}

    def import_master_list(
        self, master_list_data: bytes, format_type: str = "DER"
    ) -> dict[str, Any]:
        """
        Import a master list into OpenXPKI

        Args:
            master_list_data: Raw master list data
            format_type: Format of the data ('DER' or 'PEM')

        Returns:
            dict: Import result with list of imported certificates
        """
        try:
            # Prepare import data
            import_data = {
                "method": "import_certificate",
                "params": {
                    "data": (
                        master_list_data.hex()
                        if format_type == "DER"
                        else master_list_data.decode("utf-8")
                    ),
                    "format": format_type.lower(),
                    "import_type": "masterlist",
                    "profile": "csca",
                },
            }

            success, data = self._api_request("certificate/import", "POST", import_data)

            if success:
                result = {
                    "success": True,
                    "certificates_imported": len(data.get("certificates", [])),
                    "certificates": [],
                }

                # Process imported certificates
                for cert in data.get("certificates", []):
                    cert_info = {
                        "subject": cert.get("subject", ""),
                        "issuer": cert.get("issuer", ""),
                        "serial_number": cert.get("serial", ""),
                        "not_before": cert.get("not_before", ""),
                        "not_after": cert.get("not_after", ""),
                        "fingerprint": cert.get("fingerprint", ""),
                    }

                    # Extract country code from subject
                    subject = cert_info["subject"]
                    if "C=" in subject:
                        country_parts = [part for part in subject.split(",") if "C=" in part]
                        if country_parts:
                            cert_info["country_code"] = country_parts[0].split("=")[1].strip()

                    result["certificates"].append(cert_info)

                return result
            return {
                "success": False,
                "error": data.get("error", "Unknown error during import"),
                "certificates_imported": 0,
            }

        except Exception as e:
            logger.exception(f"Error importing master list: {e!s}")
            return {"success": False, "error": str(e), "certificates_imported": 0}

    def get_master_list(self, format_type: str = "DER") -> dict[str, Any]:
        """
        Get the current master list from OpenXPKI

        Args:
            format_type: Format to return ('DER', 'PEM', or 'JSON')

        Returns:
            dict: Master list data and metadata
        """
        try:
            # Get all CSCA certificates
            success, data = self._api_request("certificate/list?profile=csca")

            if success:
                certificates = data.get("certificates", [])

                result = {
                    "certificate_count": len(certificates),
                    "is_valid": True,
                    "last_updated": datetime.now().isoformat(),
                }

                if format_type == "JSON":
                    result["format"] = "JSON"
                    result["master_list_data"] = json.dumps(certificates)
                else:
                    # For PEM or DER formats, we need to get each certificate
                    # and combine them into a master list format
                    # This is simplified and would need proper ASN.1 encoding for DER
                    cert_data = []
                    for cert in certificates:
                        cert_id = cert.get("identifier")
                        if cert_id:
                            _, cert_detail = self._api_request(
                                f"certificate/{cert_id}/raw?format={format_type.lower()}"
                            )
                            if format_type == "PEM":
                                cert_data.append(cert_detail.get("data", ""))
                            else:  # DER
                                # In a real implementation, this would properly construct an ASN.1 DER sequence
                                cert_data.append(bytes.fromhex(cert_detail.get("data", "")))

                    if format_type == "PEM":
                        result["format"] = "PEM"
                        result["master_list_data"] = "\n".join(cert_data)
                    else:  # DER
                        result["format"] = "DER"
                        # This is a placeholder - actual implementation would properly encode ASN.1
                        result["master_list_data"] = b"".join(cert_data)

                return result
            return {
                "certificate_count": 0,
                "is_valid": False,
                "error": data.get("error", "Failed to retrieve certificates"),
            }

        except Exception as e:
            logger.exception(f"Error getting master list: {e!s}")
            return {"certificate_count": 0, "is_valid": False, "error": str(e)}

    def verify_certificate(
        self, certificate_data: bytes, format_type: str = "DER", check_revocation: bool = True
    ) -> dict[str, Any]:
        """
        Verify a certificate against the trusted certificates in OpenXPKI

        Args:
            certificate_data: Certificate data to verify
            format_type: Format of the data ('DER' or 'PEM')
            check_revocation: Whether to check revocation status

        Returns:
            dict: Verification result
        """
        try:
            # Prepare verification data
            verify_data = {
                "method": "verify_certificate",
                "params": {
                    "data": (
                        certificate_data.hex()
                        if format_type == "DER"
                        else certificate_data.decode("utf-8")
                    ),
                    "format": format_type.lower(),
                    "check_revocation": check_revocation,
                },
            }

            success, data = self._api_request("certificate/verify", "POST", verify_data)

            if success:
                return {
                    "is_valid": data.get("valid", False),
                    "is_trusted": data.get("trusted", False),
                    "is_revoked": data.get("revoked", False),
                    "subject": data.get("subject", ""),
                    "issuer": data.get("issuer", ""),
                    "validation_errors": data.get("errors", []),
                    "revocation_reason": data.get("revocation_reason", ""),
                }
            return {
                "is_valid": False,
                "is_trusted": False,
                "validation_errors": [data.get("error", "Verification request failed")],
            }

        except Exception as e:
            logger.exception(f"Error verifying certificate: {e!s}")
            return {"is_valid": False, "is_trusted": False, "validation_errors": [str(e)]}

    def sync_to_local_store(self, force: bool = False) -> dict[str, Any]:
        """
        Synchronize certificates from OpenXPKI to the local certificate store

        Args:
            force: Force synchronization even if not needed

        Returns:
            dict: Synchronization result
        """
        try:
            # Get all CSCA certificates
            success, data = self._api_request("certificate/list?profile=csca")

            if not success:
                return {
                    "success": False,
                    "certificates_synced": 0,
                    "errors": [data.get("error", "Failed to retrieve certificates")],
                }

            certificates = data.get("certificates", [])
            sync_count = 0
            errors = []

            # Process each certificate
            for cert in certificates:
                cert_id = cert.get("identifier")
                if not cert_id:
                    continue

                # Get certificate details to extract country code
                _, cert_detail = self._api_request(f"certificate/{cert_id}")

                # Extract country code from subject
                subject = cert_detail.get("subject", "")
                country_code = "XX"  # Default if not found

                if "C=" in subject:
                    country_parts = [part for part in subject.split(",") if "C=" in part]
                    if country_parts:
                        country_code = country_parts[0].split("=")[1].strip()

                # Create country-specific directory
                country_dir = os.path.join(self.local_store_path, country_code)
                os.makedirs(country_dir, exist_ok=True)

                # Filename based on cert identifier
                cert_file = os.path.join(country_dir, f"{cert_id}.cer")

                # Check if file already exists and is recent
                if not force and os.path.exists(cert_file):
                    file_stat = os.stat(cert_file)
                    # Skip if file is less than a day old
                    if datetime.fromtimestamp(file_stat.st_mtime) > datetime.now() - timedelta(
                        days=1
                    ):
                        continue

                # Get the raw certificate
                _, raw_cert = self._api_request(f"certificate/{cert_id}/raw?format=der")

                if "data" in raw_cert:
                    # Save to file
                    try:
                        with open(cert_file, "wb") as f:
                            f.write(bytes.fromhex(raw_cert["data"]))
                        sync_count += 1
                    except Exception as e:
                        errors.append(f"Failed to save certificate {cert_id}: {e!s}")

            return {
                "success": True,
                "certificates_synced": sync_count,
                "sync_timestamp": datetime.now().isoformat(),
                "errors": errors,
            }

        except Exception as e:
            logger.exception(f"Error during synchronization: {e!s}")
            return {"success": False, "certificates_synced": 0, "errors": [str(e)]}

    def check_expiring_certificates(self, days: int = 90) -> dict[str, Any]:
        """
        Check for certificates that will expire within the specified number of days

        Args:
            days: Number of days to check

        Returns:
            dict: List of expiring certificates
        """
        try:
            expiry_date = datetime.now() + timedelta(days=days)
            expiry_date_str = expiry_date.strftime("%Y-%m-%d")

            # Get certificates expiring before the specified date
            success, data = self._api_request(
                f"certificate/list?profile=csca&valid_until={expiry_date_str}"
            )

            if not success:
                return {
                    "expiring_certificates": [],
                    "error": data.get("error", "Failed to retrieve certificates"),
                }

            certificates = data.get("certificates", [])
            expiring_certs = []

            # Process each certificate
            for cert in certificates:
                cert_id = cert.get("identifier")
                if not cert_id:
                    continue

                # Get certificate details
                _, cert_detail = self._api_request(f"certificate/{cert_id}")

                # Extract country code from subject
                subject = cert_detail.get("subject", "")
                country_code = "XX"  # Default if not found

                if "C=" in subject:
                    country_parts = [part for part in subject.split(",") if "C=" in part]
                    if country_parts:
                        country_code = country_parts[0].split("=")[1].strip()

                # Calculate days remaining
                not_after = cert_detail.get("not_after", "")
                days_remaining = 0

                try:
                    expiry_date = datetime.strptime(not_after, "%Y-%m-%d %H:%M:%S")
                    days_remaining = (expiry_date - datetime.now()).days
                except (ValueError, TypeError):
                    pass

                expiring_certs.append(
                    {
                        "subject": cert_detail.get("subject", ""),
                        "issuer": cert_detail.get("issuer", ""),
                        "serial_number": cert_detail.get("serial", ""),
                        "not_after": not_after,
                        "days_remaining": days_remaining,
                        "country_code": country_code,
                    }
                )

        except Exception as e:
            logger.exception(f"Error checking expiring certificates: {e!s}")
            return {"expiring_certificates": [], "error": str(e)}
        else:
            return {"expiring_certificates": expiring_certs}
