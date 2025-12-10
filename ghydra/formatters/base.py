"""Base formatter interface for output formatting."""

from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseFormatter(ABC):
    """Abstract base class for output formatters.

    All formatters must implement these methods to handle different
    types of API responses and format them appropriately.
    """

    @abstractmethod
    def format_functions_list(self, data: Dict[str, Any]) -> str:
        """Format function list response.

        Args:
            data: API response data containing function list

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_function_info(self, data: Dict[str, Any]) -> str:
        """Format single function info response.

        Args:
            data: API response data containing function details

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_decompiled_code(self, data: Dict[str, Any]) -> str:
        """Format decompiled code response.

        Args:
            data: API response data containing decompiled code

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_disassembly(self, data: Dict[str, Any]) -> str:
        """Format disassembly response.

        Args:
            data: API response data containing disassembly

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_memory(self, data: Dict[str, Any]) -> str:
        """Format memory read response.

        Args:
            data: API response data containing memory bytes

        Returns:
            Formatted string output (typically hex dump)
        """
        pass

    @abstractmethod
    def format_xrefs(self, data: Dict[str, Any]) -> str:
        """Format cross-references list response.

        Args:
            data: API response data containing xrefs

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_data_list(self, data: Dict[str, Any]) -> str:
        """Format data items list response.

        Args:
            data: API response data containing data items

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_strings_list(self, data: Dict[str, Any]) -> str:
        """Format strings list response.

        Args:
            data: API response data containing strings

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_structs_list(self, data: Dict[str, Any]) -> str:
        """Format structs list response.

        Args:
            data: API response data containing structs

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_struct_info(self, data: Dict[str, Any]) -> str:
        """Format single struct info response.

        Args:
            data: API response data containing struct details

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_project_info(self, data: Dict[str, Any]) -> str:
        """Format project info response.

        Args:
            data: API response data containing project details

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_instances_list(self, data: Dict[str, Any]) -> str:
        """Format instances list response.

        Args:
            data: API response data containing instances

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_simple_result(self, data: Dict[str, Any]) -> str:
        """Format simple success/info response.

        Args:
            data: API response data

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_error(self, error: Exception) -> str:
        """Format error message.

        Args:
            error: Exception to format

        Returns:
            Formatted error string
        """
        pass
