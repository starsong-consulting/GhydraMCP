"""Table-based output formatter using rich library."""

import io
from typing import Any, Dict

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.tree import Tree

from .base import BaseFormatter


class TableFormatter(BaseFormatter):
    """Formatter that outputs rich terminal tables and formatted text.

    Uses the rich library to create attractive terminal output with
    tables, syntax highlighting, and colors.
    """

    def __init__(self, use_colors: bool = True):
        """Initialize table formatter.

        Args:
            use_colors: Enable colored output
        """
        self.console = Console(
            color_system="auto" if use_colors else None,
            force_terminal=use_colors
        )

    def _capture(self, renderable) -> str:
        """Capture rich renderable output to string.

        Args:
            renderable: Rich renderable object

        Returns:
            Captured string output
        """
        buffer = io.StringIO()
        # Create console with same color settings
        color_sys = "auto" if self.console._color_system else None
        temp_console = Console(file=buffer, color_system=color_sys, force_terminal=True)
        temp_console.print(renderable)
        return buffer.getvalue().rstrip()

    def format_functions_list(self, data: Dict[str, Any]) -> str:
        """Format function list as table."""
        result = data.get("result", [])

        # Get total count from metadata
        metadata = data.get("metadata", {})
        total = metadata.get("size", len(result))
        offset = metadata.get("offset", 0)
        limit = metadata.get("limit", len(result))

        if not result:
            return f"[yellow]No functions found[/yellow] (0 total)"

        table = Table(title=f"Functions ({total} total)", show_lines=False)
        table.add_column("Address", style="cyan", no_wrap=True)
        table.add_column("Name", style="green")
        table.add_column("Signature", style="yellow", overflow="fold")

        for fn in result:
            table.add_row(
                fn.get("address", "?"),
                fn.get("name", "?"),
                fn.get("signature", "")[:100]
            )

        # Add pagination info if showing subset
        if total > len(result):
            table.caption = f"Showing {offset + 1}-{offset + len(result)} of {total}"

        return self._capture(table)

    def format_function_info(self, data: Dict[str, Any]) -> str:
        """Format single function info."""
        result = data.get("result", {})

        if not result:
            return "[yellow]No function info available[/yellow]"

        lines = [
            f"[cyan]Address:[/cyan] {result.get('address', '?')}",
            f"[cyan]Name:[/cyan] {result.get('name', '?')}",
            f"[cyan]Signature:[/cyan] {result.get('signature', '?')}",
        ]

        if result.get("entryPoint"):
            lines.append(f"[cyan]Entry Point:[/cyan] {result['entryPoint']}")

        if result.get("thunk"):
            lines.append(f"[cyan]Thunk:[/cyan] {result['thunk']}")

        panel = Panel("\n".join(lines), title="Function Info", border_style="blue")
        return self._capture(panel)

    def format_decompiled_code(self, data: Dict[str, Any]) -> str:
        """Format decompiled code with syntax highlighting."""
        result = data.get("result", {})
        code = result.get("decompiled") or result.get("ccode") or result.get("decompiled_text", "")

        if not code:
            return "[red]No decompiled code available[/red]"

        # Create syntax-highlighted code
        syntax = Syntax(
            code,
            "c",
            theme="monokai",
            line_numbers=True,
            word_wrap=False
        )

        return self._capture(syntax)

    def format_disassembly(self, data: Dict[str, Any]) -> str:
        """Format disassembly listing."""
        result = data.get("result", {})
        disasm = result.get("disassembly", "")

        if not disasm:
            return "[red]No disassembly available[/red]"

        # Simple syntax highlighting for assembly
        syntax = Syntax(
            disasm,
            "asm",
            theme="monokai",
            line_numbers=False,
            word_wrap=False
        )

        return self._capture(syntax)

    def format_memory(self, data: Dict[str, Any]) -> str:
        """Format memory as hex dump."""
        result = data.get("result", {})
        addr = result.get("address", "???")
        hex_bytes = result.get("hexBytes", "")

        if not hex_bytes:
            return "[red]No memory data available[/red]"

        lines = [f"[cyan]Memory at 0x{addr}:[/cyan]\n"]

        # hexBytes comes as space-separated pairs: "48 83 EC 28..."
        byte_pairs = hex_bytes.split()

        for i in range(0, len(byte_pairs), 16):
            chunk = byte_pairs[i:i+16]

            # Address offset
            offset = f"{i:08x}"

            # Hex part - format each byte with fixed width
            hex_part = " ".join(f"{bp:>2}" for bp in chunk)

            # ASCII part
            ascii_part = ""
            for bp in chunk:
                try:
                    b = int(bp, 16)
                    ascii_part += chr(b) if 32 <= b < 127 else "."
                except:
                    ascii_part += "?"

            lines.append(f"[dim]{offset}[/dim]  {hex_part:<48}  [dim]{ascii_part}[/dim]")

        return self._capture("\n".join(lines))

    def format_xrefs(self, data: Dict[str, Any]) -> str:
        """Format cross-references as table."""
        result = data.get("result", [])

        if not result:
            return "[yellow]No cross-references found[/yellow]"

        table = Table(title="Cross-References", show_lines=False)
        table.add_column("From", style="cyan", no_wrap=True)
        table.add_column("To", style="green", no_wrap=True)
        table.add_column("Type", style="yellow")

        for xref in result:
            table.add_row(
                xref.get("from_addr", "?"),
                xref.get("to_addr", "?"),
                xref.get("refType", "?")
            )

        return self._capture(table)

    def format_data_list(self, data: Dict[str, Any]) -> str:
        """Format data items list as table."""
        result = data.get("result", [])

        if not result:
            return "[yellow]No data items found[/yellow]"

        table = Table(title=f"Data Items ({len(result)} items)", show_lines=False)
        table.add_column("Address", style="cyan", no_wrap=True)
        table.add_column("Name", style="green")
        table.add_column("Type", style="yellow")
        table.add_column("Value", style="white", overflow="fold")

        for item in result:
            value = item.get("value", "")
            if isinstance(value, str) and len(value) > 50:
                value = value[:47] + "..."

            table.add_row(
                item.get("address", "?"),
                item.get("label", ""),
                item.get("dataType", "?"),
                str(value)
            )

        return self._capture(table)

    def format_strings_list(self, data: Dict[str, Any]) -> str:
        """Format strings list as table."""
        result = data.get("result", [])

        if not result:
            return "[yellow]No strings found[/yellow]"

        table = Table(title=f"Strings ({len(result)} items)", show_lines=False)
        table.add_column("Address", style="cyan", no_wrap=True)
        table.add_column("Value", style="green", overflow="fold")

        for string in result:
            value = string.get("value", "")
            if len(value) > 80:
                value = value[:77] + "..."

            table.add_row(
                string.get("address", "?"),
                value
            )

        return self._capture(table)

    def format_structs_list(self, data: Dict[str, Any]) -> str:
        """Format structs list as table."""
        result = data.get("result", [])

        if not result:
            return "[yellow]No structs found[/yellow]"

        table = Table(title=f"Structs ({len(result)} items)", show_lines=False)
        table.add_column("Name", style="cyan")
        table.add_column("Size", style="yellow", justify="right")
        table.add_column("Fields", style="green", justify="right")

        for struct in result:
            table.add_row(
                struct.get("name", "?"),
                str(struct.get("size", 0)),
                str(struct.get("fieldCount", 0))
            )

        return self._capture(table)

    def format_struct_info(self, data: Dict[str, Any]) -> str:
        """Format struct info with fields as tree."""
        result = data.get("result", {})

        if not result:
            return "[yellow]No struct info available[/yellow]"

        tree = Tree(f"[cyan]{result.get('name', '?')}[/cyan] (size: {result.get('size', 0)})")

        fields = result.get("fields", [])
        for field in fields:
            field_str = (
                f"[green]{field.get('name', '?')}[/green] "
                f"[yellow]{field.get('type', '?')}[/yellow] "
                f"@ offset {field.get('offset', 0)}"
            )
            tree.add(field_str)

        return self._capture(tree)

    def format_project_info(self, data: Dict[str, Any]) -> str:
        """Format project info as panel."""
        result = data.get("result", {})

        if not result:
            return "[yellow]No project info available[/yellow]"

        lines = [
            f"[cyan]Name:[/cyan] {result.get('name', '?')}",
            f"[cyan]Location:[/cyan] {result.get('location', '?')}",
        ]

        if result.get("fileCount") is not None:
            lines.append(f"[cyan]File Count:[/cyan] {result['fileCount']}")

        panel = Panel("\n".join(lines), title="Project Info", border_style="blue")
        return self._capture(panel)

    def format_instances_list(self, data: Dict[str, Any]) -> str:
        """Format instances list as table."""
        instances = data.get("instances", [])

        if not instances:
            return "[yellow]No Ghidra instances found[/yellow]"

        table = Table(title=f"Ghidra Instances ({len(instances)} found)", show_lines=False)
        table.add_column("Port", style="cyan", justify="right")
        table.add_column("URL", style="blue")
        table.add_column("Project", style="green")
        table.add_column("File", style="yellow")

        for inst in instances:
            table.add_row(
                str(inst.get("port", "?")),
                inst.get("url", "?"),
                inst.get("project", "-"),
                inst.get("file", "-")
            )

        return self._capture(table)

    def format_simple_result(self, data: Dict[str, Any]) -> str:
        """Format simple success/info response."""
        result = data.get("result", {})

        # If result is a string, just return it
        if isinstance(result, str):
            return f"[green]{result}[/green]"

        # If result has a message, use that
        if isinstance(result, dict) and "message" in result:
            return f"[green]{result['message']}[/green]"

        # Otherwise show formatted dict
        lines = []
        for key, value in result.items():
            if key not in ("_links",):  # Skip HATEOAS links
                lines.append(f"[cyan]{key}:[/cyan] {value}")

        if lines:
            return "\n".join(lines)

        return "[green]Success[/green]"

    def format_error(self, error: Exception) -> str:
        """Format error message."""
        from ..client.exceptions import GhidraAPIError

        if isinstance(error, GhidraAPIError):
            return f"[red]Error [{error.code}]:[/red] {error.message}"

        return f"[red]Error:[/red] {str(error)}"
