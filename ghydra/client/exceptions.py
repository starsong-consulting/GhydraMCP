"""Exception classes for GhydraMCP CLI."""


class GhidraError(Exception):
    """Base exception for all Ghidra-related errors."""
    pass


class GhidraConnectionError(GhidraError):
    """Exception raised for connection-related errors."""
    pass


class GhidraAPIError(GhidraError):
    """Exception raised for API response errors."""

    def __init__(self, message: str, code: str = "UNKNOWN"):
        """Initialize GhidraAPIError.

        Args:
            message: Error message
            code: Error code from API
        """
        super().__init__(message)
        self.code = code
        self.message = message


class GhidraConfigError(GhidraError):
    """Exception raised for configuration errors."""
    pass
