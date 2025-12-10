"""JSON output formatter."""

import json
from typing import Any, Dict

from .base import BaseFormatter


class JSONFormatter(BaseFormatter):
    """Formatter that outputs raw JSON data.

    This formatter is used when the --json flag is specified.
    It provides machine-readable output suitable for scripting.
    """

    def __init__(self, pretty: bool = True):
        """Initialize JSON formatter.

        Args:
            pretty: Use pretty-printing with indentation
        """
        self.pretty = pretty

    def _format_json(self, data: Any) -> str:
        """Generic JSON formatting helper.

        Args:
            data: Data to format

        Returns:
            JSON string
        """
        if self.pretty:
            return json.dumps(data, indent=2, sort_keys=False)
        return json.dumps(data)

    def format_functions_list(self, data: Dict[str, Any]) -> str:
        """Format function list as JSON."""
        return self._format_json(data)

    def format_function_info(self, data: Dict[str, Any]) -> str:
        """Format function info as JSON."""
        return self._format_json(data)

    def format_decompiled_code(self, data: Dict[str, Any]) -> str:
        """Format decompiled code as JSON."""
        return self._format_json(data)

    def format_disassembly(self, data: Dict[str, Any]) -> str:
        """Format disassembly as JSON."""
        return self._format_json(data)

    def format_memory(self, data: Dict[str, Any]) -> str:
        """Format memory as JSON."""
        return self._format_json(data)

    def format_xrefs(self, data: Dict[str, Any]) -> str:
        """Format xrefs as JSON."""
        return self._format_json(data)

    def format_data_list(self, data: Dict[str, Any]) -> str:
        """Format data list as JSON."""
        return self._format_json(data)

    def format_strings_list(self, data: Dict[str, Any]) -> str:
        """Format strings list as JSON."""
        return self._format_json(data)

    def format_structs_list(self, data: Dict[str, Any]) -> str:
        """Format structs list as JSON."""
        return self._format_json(data)

    def format_struct_info(self, data: Dict[str, Any]) -> str:
        """Format struct info as JSON."""
        return self._format_json(data)

    def format_project_info(self, data: Dict[str, Any]) -> str:
        """Format project info as JSON."""
        return self._format_json(data)

    def format_instances_list(self, data: Dict[str, Any]) -> str:
        """Format instances list as JSON."""
        return self._format_json(data)

    def format_simple_result(self, data: Dict[str, Any]) -> str:
        """Format simple result as JSON."""
        return self._format_json(data)

    def format_error(self, error: Exception) -> str:
        """Format error as JSON."""
        error_dict = {
            "error": {
                "type": error.__class__.__name__,
                "message": str(error)
            }
        }
        if hasattr(error, 'code'):
            error_dict["error"]["code"] = error.code
        return self._format_json(error_dict)
