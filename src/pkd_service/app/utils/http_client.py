"""
HTTP Client utility for making HTTP requests

This module provides a simple wrapper around the requests library
for making HTTP requests with consistent error handling and logging.
"""

import logging
from typing import Any, Optional

import requests
from requests.exceptions import RequestException


class HttpClient:
    """
    A simple HTTP client for making requests with consistent error handling and logging.
    """

    def __init__(self, timeout: int = 30, logger=None) -> None:
        """
        Initialize the HTTP client.

        Args:
            timeout: Request timeout in seconds
            logger: Logger instance
        """
        self.timeout = timeout
        self.logger = logger or logging.getLogger(__name__)

    def get(
        self,
        url: str,
        params: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
    ):
        """
        Make a GET request.

        Args:
            url: URL to request
            params: Query parameters
            headers: Request headers

        Returns:
            requests.Response: Response object

        Raises:
            requests.exceptions.RequestException: If the request fails
        """
        try:
            self.logger.debug(f"Making GET request to {url}")
            response = requests.get(url, params=params, headers=headers, timeout=self.timeout)
            self.logger.debug(f"Received response: HTTP {response.status_code}")
            return response
        except RequestException as e:
            self.logger.exception(f"GET request failed: {e}")
            raise

    def post(
        self,
        url: str,
        data: Optional[dict[str, Any]] = None,
        json: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
    ):
        """
        Make a POST request.

        Args:
            url: URL to request
            data: Form data
            json: JSON data
            headers: Request headers

        Returns:
            requests.Response: Response object

        Raises:
            requests.exceptions.RequestException: If the request fails
        """
        try:
            self.logger.debug(f"Making POST request to {url}")
            response = requests.post(
                url, data=data, json=json, headers=headers, timeout=self.timeout
            )
            self.logger.debug(f"Received response: HTTP {response.status_code}")
            return response
        except RequestException as e:
            self.logger.exception(f"POST request failed: {e}")
            raise
