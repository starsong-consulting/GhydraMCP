"""Data models for GhydraMCP CLI."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any


class StopReason(str, Enum):
    """Unified stop reasons across PCode and Unicorn engines."""
    DONE = "DONE"
    COUNT = "COUNT"
    ERROR = "ERROR"
    LAZY_FETCH_FAILED = "LAZY_FETCH_FAILED"
    LAZY_CAP_REACHED = "LAZY_CAP_REACHED"
    HOOK_TRAP = "HOOK_TRAP"
    REDIRECT_STORM = "REDIRECT_STORM"
    UNMAPPED = "UNMAPPED"
    COMPLETED = "COMPLETED"
    TARGET_REACHED = "TARGET_REACHED"
    STEPPED = "STEPPED"
    READY = "READY"
    BREAKPOINT = "BREAKPOINT"


@dataclass
class CallResultDto:
    """Result of a dynamic call."""
    convention: str
    args_passed: list[str]
    final_registers: dict[str, str]
    stop_reason: str
    return_value: Optional[str] = None
    detail: Optional[str] = None
    mem_writes: Optional[list[dict[str, Any]]] = None


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
