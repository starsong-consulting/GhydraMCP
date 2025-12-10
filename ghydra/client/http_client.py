"""HTTP client for Ghidra HATEOAS API."""

import time
from typing import Any, Dict, Optional
from urllib.parse import quote, urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .exceptions import GhidraAPIError, GhidraConnectionError
from .models import GhidraInstance


class GhidraHTTPClient:
    """HTTP client for communicating with Ghidra plugin API.

    This client handles all HTTP communication with the Ghidra HATEOAS REST API,
    including connection pooling, retries, and error handling.

    Attributes:
        host: Hostname or IP address of Ghidra instance
        port: Port number of Ghidra instance
        timeout: Request timeout in seconds
        base_url: Full base URL for API requests
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8192,
        timeout: int = 10
    ):
        """Initialize HTTP client.

        Args:
            host: Hostname or IP address (default: localhost)
            port: Port number (default: 8192)
            timeout: Request timeout in seconds (default: 10)
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.base_url = f"http://{host}:{port}"

        # Configure session with retry logic
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[502, 503, 504],
            allowed_methods=["GET", "POST", "PATCH", "PUT", "DELETE"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make GET request to API.

        Args:
            endpoint: API endpoint path (without leading slash)
            params: Optional query parameters

        Returns:
            Parsed JSON response data

        Raises:
            GhidraConnectionError: If connection fails
            GhidraAPIError: If API returns error response
        """
        url = urljoin(self.base_url + "/", endpoint.lstrip("/"))
        headers = {
            "Accept": "application/json",
            "X-Request-ID": f"cli-{int(time.time() * 1000)}"
        }

        try:
            response = self.session.get(
                url,
                params=params,
                headers=headers,
                timeout=self.timeout
            )
            return self._handle_response(response)
        except requests.exceptions.Timeout as e:
            raise GhidraConnectionError(f"Request timed out after {self.timeout}s") from e
        except requests.exceptions.ConnectionError as e:
            raise GhidraConnectionError(
                f"Failed to connect to {self.base_url}. "
                f"Is Ghidra running with the GhydraMCP plugin loaded?"
            ) from e
        except requests.exceptions.RequestException as e:
            raise GhidraConnectionError(f"Request failed: {e}") from e

    def post(
        self,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make POST request to API.

        Args:
            endpoint: API endpoint path
            data: Optional form data
            json_data: Optional JSON payload

        Returns:
            Parsed JSON response data

        Raises:
            GhidraConnectionError: If connection fails
            GhidraAPIError: If API returns error response
        """
        url = urljoin(self.base_url + "/", endpoint.lstrip("/"))
        headers = {
            "Accept": "application/json",
            "X-Request-ID": f"cli-{int(time.time() * 1000)}"
        }

        try:
            response = self.session.post(
                url,
                data=data,
                json=json_data,
                headers=headers,
                timeout=self.timeout
            )
            return self._handle_response(response)
        except requests.exceptions.Timeout as e:
            raise GhidraConnectionError(f"Request timed out after {self.timeout}s") from e
        except requests.exceptions.ConnectionError as e:
            raise GhidraConnectionError(
                f"Failed to connect to {self.base_url}"
            ) from e
        except requests.exceptions.RequestException as e:
            raise GhidraConnectionError(f"Request failed: {e}") from e

    def patch(
        self,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make PATCH request to API.

        Args:
            endpoint: API endpoint path
            data: Optional JSON payload

        Returns:
            Parsed JSON response data

        Raises:
            GhidraConnectionError: If connection fails
            GhidraAPIError: If API returns error response
        """
        url = urljoin(self.base_url + "/", endpoint.lstrip("/"))
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Request-ID": f"cli-{int(time.time() * 1000)}"
        }

        try:
            response = self.session.patch(
                url,
                json=data,
                headers=headers,
                timeout=self.timeout
            )
            return self._handle_response(response)
        except requests.exceptions.Timeout as e:
            raise GhidraConnectionError(f"Request timed out after {self.timeout}s") from e
        except requests.exceptions.ConnectionError as e:
            raise GhidraConnectionError(
                f"Failed to connect to {self.base_url}"
            ) from e
        except requests.exceptions.RequestException as e:
            raise GhidraConnectionError(f"Request failed: {e}") from e

    def put(
        self,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make PUT request to API.

        Args:
            endpoint: API endpoint path
            data: Optional JSON payload

        Returns:
            Parsed JSON response data

        Raises:
            GhidraConnectionError: If connection fails
            GhidraAPIError: If API returns error response
        """
        url = urljoin(self.base_url + "/", endpoint.lstrip("/"))
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Request-ID": f"cli-{int(time.time() * 1000)}"
        }

        try:
            response = self.session.put(
                url,
                json=data,
                headers=headers,
                timeout=self.timeout
            )
            return self._handle_response(response)
        except requests.exceptions.Timeout as e:
            raise GhidraConnectionError(f"Request timed out after {self.timeout}s") from e
        except requests.exceptions.ConnectionError as e:
            raise GhidraConnectionError(
                f"Failed to connect to {self.base_url}"
            ) from e
        except requests.exceptions.RequestException as e:
            raise GhidraConnectionError(f"Request failed: {e}") from e

    def delete(self, endpoint: str) -> Dict[str, Any]:
        """Make DELETE request to API.

        Args:
            endpoint: API endpoint path

        Returns:
            Parsed JSON response data

        Raises:
            GhidraConnectionError: If connection fails
            GhidraAPIError: If API returns error response
        """
        url = urljoin(self.base_url + "/", endpoint.lstrip("/"))
        headers = {
            "Accept": "application/json",
            "X-Request-ID": f"cli-{int(time.time() * 1000)}"
        }

        try:
            response = self.session.delete(
                url,
                headers=headers,
                timeout=self.timeout
            )
            return self._handle_response(response)
        except requests.exceptions.Timeout as e:
            raise GhidraConnectionError(f"Request timed out after {self.timeout}s") from e
        except requests.exceptions.ConnectionError as e:
            raise GhidraConnectionError(
                f"Failed to connect to {self.base_url}"
            ) from e
        except requests.exceptions.RequestException as e:
            raise GhidraConnectionError(f"Request failed: {e}") from e

    def _handle_response(self, response: requests.Response) -> Dict[str, Any]:
        """Parse and validate HTTP response.

        Args:
            response: HTTP response object

        Returns:
            Parsed JSON data

        Raises:
            GhidraAPIError: If response indicates error
            GhidraConnectionError: If response is invalid
        """
        # Handle non-OK HTTP status
        if response.status_code >= 400:
            try:
                error_data = response.json()
                if isinstance(error_data, dict):
                    error = error_data.get("error", {})
                    if isinstance(error, dict):
                        raise GhidraAPIError(
                            error.get("message", "Unknown error"),
                            error.get("code", "HTTP_ERROR")
                        )
                    raise GhidraAPIError(str(error), "HTTP_ERROR")
            except requests.exceptions.JSONDecodeError:
                pass
            raise GhidraAPIError(
                f"HTTP {response.status_code}: {response.text[:200]}",
                f"HTTP_{response.status_code}"
            )

        # Parse JSON response
        try:
            data = response.json()
        except requests.exceptions.JSONDecodeError as e:
            raise GhidraConnectionError(
                f"Invalid JSON response: {response.text[:200]}"
            ) from e

        # Validate response structure
        if not isinstance(data, dict):
            raise GhidraAPIError("Invalid response format: expected JSON object", "INVALID_FORMAT")

        # Check for API-level errors
        if not data.get("success", False):
            error = data.get("error", {})
            if isinstance(error, dict):
                raise GhidraAPIError(
                    error.get("message", "Unknown error"),
                    error.get("code", "UNKNOWN")
                )
            raise GhidraAPIError(str(error), "UNKNOWN")

        return data

    def close(self):
        """Close the HTTP session."""
        self.session.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
