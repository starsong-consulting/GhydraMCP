"""Data models for GhydraMCP CLI."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class GhidraInstance:
    """Represents a Ghidra instance.

    Attributes:
        port: Port number the instance is running on
        host: Hostname or IP address
        url: Full base URL for the instance
        project: Project name (if available)
        file: File/program name (if available)
        plugin_version: Plugin version string (if available)
        api_version: API version number (if available)
    """

    port: int
    host: str
    url: str
    project: Optional[str] = None
    file: Optional[str] = None
    plugin_version: Optional[str] = None
    api_version: Optional[int] = None

    def __str__(self) -> str:
        """Return human-readable string representation."""
        parts = [f"{self.url}"]
        if self.file:
            parts.append(f"file={self.file}")
        if self.project:
            parts.append(f"project={self.project}")
        return " ".join(parts)
