"""Default configuration values for GhydraMCP CLI."""

from dataclasses import dataclass, asdict
from typing import Dict, Any


@dataclass
class GhidraConfig:
    """Configuration for GhydraMCP CLI.

    Attributes:
        default_host: Default Ghidra host
        default_port: Default Ghidra port
        timeout: HTTP request timeout in seconds
        use_colors: Enable colored output
        page_output: Enable paging for long output
        max_pagination: Maximum items per page
    """

    default_host: str = "localhost"
    default_port: int = 8192
    timeout: int = 10
    use_colors: bool = True
    page_output: bool = True
    max_pagination: int = 100

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GhidraConfig":
        """Create config from dictionary."""
        return cls(**data)
