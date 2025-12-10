"""Input validation utilities."""

import re


def validate_address(addr: str) -> str:
    """Validate and normalize hex address.

    Accepts hex addresses with or without "0x" prefix.

    Args:
        addr: Address string to validate

    Returns:
        Normalized address string

    Raises:
        ValueError: If address format is invalid
    """
    if not addr:
        raise ValueError("Address cannot be empty")

    # Remove 0x prefix if present
    normalized = addr.lower()
    if normalized.startswith("0x"):
        normalized = normalized[2:]

    # Validate hex format
    if not re.match(r'^[0-9a-f]+$', normalized):
        raise ValueError(f"Invalid hex address format: {addr}")

    return normalized


def normalize_hex_address(addr: str) -> str:
    """Normalize hex address to standard format (with 0x prefix).

    Args:
        addr: Address string

    Returns:
        Normalized address with 0x prefix
    """
    validated = validate_address(addr)
    return f"0x{validated}"


def validate_port(port: int) -> int:
    """Validate port number.

    Args:
        port: Port number to validate

    Returns:
        Validated port number

    Raises:
        ValueError: If port is out of valid range
    """
    if not isinstance(port, int):
        raise ValueError(f"Port must be an integer, got {type(port)}")

    if port < 1 or port > 65535:
        raise ValueError(f"Port must be between 1 and 65535, got {port}")

    return port


def validate_hex_bytes(data: str) -> str:
    """Validate hex byte string.

    Args:
        data: Hex byte string to validate

    Returns:
        Validated hex string

    Raises:
        ValueError: If hex format is invalid
    """
    if not data:
        raise ValueError("Hex data cannot be empty")

    # Remove spaces and 0x prefixes
    normalized = data.replace(" ", "").replace("0x", "").lower()

    # Validate hex format
    if not re.match(r'^[0-9a-f]+$', normalized):
        raise ValueError(f"Invalid hex data format: {data}")

    # Ensure even number of characters (full bytes)
    if len(normalized) % 2 != 0:
        raise ValueError(f"Hex data must have even number of characters: {data}")

    return normalized
