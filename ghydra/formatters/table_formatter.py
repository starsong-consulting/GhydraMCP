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
        temp_console = Console(
            file=buffer, color_system=color_sys,
            force_terminal=self.console._force_terminal
        )
        temp_console.print(renderable, soft_wrap=True)
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
            return self._capture("[yellow]No functions found[/yellow] (0 total)")

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
            return self._capture("[yellow]No function info available[/yellow]")

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
        retry_recommended = bool(result.get("retry_recommended"))
        suggested_timeout = result.get("suggested_timeout_seconds")
        message = result.get("message")
        decompile_error = result.get("decompile_error")

        advisory_lines = []
        if retry_recommended:
            if message:
                advisory_lines.append(f"// {message}")
            if suggested_timeout:
                advisory_lines.append(f"// Suggested timeout: {suggested_timeout}s")
            if decompile_error:
                advisory_lines.append(f"// Decompiler error: {decompile_error}")

        if advisory_lines:
            advisory_text = "\n".join(advisory_lines)
            if code:
                if advisory_text.lower() not in code.lower():
                    code = f"{code.rstrip()}\n\n{advisory_text}"
            else:
                code = advisory_text

        if not code:
            return self._capture("[red]No decompiled code available[/red]")

        code = code.strip()

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
        instructions = result.get("instructions", [])

        if not instructions:
            return self._capture("[red]No disassembly available[/red]")

        func_info = result.get("function", {})
        title = func_info.get("name", "Disassembly")
        total = result.get("totalInstructions", len(instructions))

        lines = []
        for instr in instructions:
            addr = instr.get("address", "?")
            bytez = instr.get("bytes", "")
            mnemonic = instr.get("mnemonic", "?")
            operands = instr.get("operands", "")
            lines.append(f"{addr}  {bytez:<20s} {mnemonic:<8s} {operands}")

        disasm_text = "\n".join(lines)

        header = f"[cyan]{title}[/cyan] ({total} instructions)\n"
        return self._capture(header) + "\n" + disasm_text

    def format_memory(self, data: Dict[str, Any]) -> str:
        """Format memory as hex dump."""
        result = data.get("result", {})
        addr = result.get("address", "???")
        hex_bytes = result.get("hexBytes", "")

        if not hex_bytes:
            return self._capture("[red]No memory data available[/red]")

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
        result = data.get("result", {})
        references = result.get("references", []) if isinstance(result, dict) else result

        if not references:
            return self._capture("[yellow]No cross-references found[/yellow]")

        table = Table(title="Cross-References", show_lines=False)
        table.add_column("From", style="cyan", no_wrap=True)
        table.add_column("To", style="green", no_wrap=True)
        table.add_column("Type", style="yellow")
        table.add_column("From Function", style="dim")

        for xref in references:
            from_func = ""
            if isinstance(xref.get("from_function"), dict):
                from_func = xref["from_function"].get("name", "")
            table.add_row(
                xref.get("from_addr", "?"),
                xref.get("to_addr", "?"),
                xref.get("refType", "?"),
                from_func
            )

        return self._capture(table)

    def format_data_list(self, data: Dict[str, Any]) -> str:
        """Format data items list as table."""
        result = data.get("result", [])

        if not result:
            return self._capture("[yellow]No data items found[/yellow]")

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
                item.get("name", ""),
                item.get("dataType", "?"),
                str(value)
            )

        return self._capture(table)

    def format_strings_list(self, data: Dict[str, Any]) -> str:
        """Format strings list as table."""
        result = data.get("result", [])

        if not result:
            return self._capture("[yellow]No strings found[/yellow]")

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
            return self._capture("[yellow]No structs found[/yellow]")

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
            return self._capture("[yellow]No struct info available[/yellow]")

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
            return self._capture("[yellow]No project info available[/yellow]")

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
            return self._capture("[yellow]No Ghidra instances found[/yellow]")

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

        if isinstance(result, str):
            return self._capture(f"[green]{result}[/green]")

        if isinstance(result, dict) and "message" in result:
            return self._capture(f"[green]{result['message']}[/green]")

        lines = []
        for key, value in result.items():
            if key not in ("_links",):
                lines.append(f"[cyan]{key}:[/cyan] {value}")

        if lines:
            return self._capture("\n".join(lines))

        return self._capture("[green]Success[/green]")

    def format_classes_list(self, data: Dict[str, Any]) -> str:
        """Format classes list as table."""
        result = data.get("result", [])

        if not result:
            return self._capture("[yellow]No classes found[/yellow]")

        table = Table(title=f"Classes ({len(result)} items)", show_lines=False)
        table.add_column("Name", style="cyan")
        table.add_column("Namespace", style="dim")

        for item in result:
            table.add_row(
                item.get("simpleName", item.get("name", "?")),
                item.get("namespace", "")
            )

        return self._capture(table)

    def format_symbols_list(self, data: Dict[str, Any]) -> str:
        """Format symbols list as table."""
        result = data.get("result", [])

        if not result:
            return self._capture("[yellow]No symbols found[/yellow]")

        table = Table(title=f"Symbols ({len(result)} items)", show_lines=False)
        table.add_column("Address", style="cyan", no_wrap=True)
        table.add_column("Type", style="yellow")
        table.add_column("Name", style="green")
        table.add_column("Namespace", style="dim")

        for item in result:
            primary = " *" if item.get("isPrimary") else ""
            table.add_row(
                item.get("address", "?"),
                item.get("type", "?"),
                item.get("name", "?") + primary,
                item.get("namespace", "")
            )

        return self._capture(table)

    def format_segments_list(self, data: Dict[str, Any]) -> str:
        """Format segments list as table."""
        result = data.get("result", [])

        if not result:
            return self._capture("[yellow]No segments found[/yellow]")

        table = Table(title=f"Segments ({len(result)} items)", show_lines=False)
        table.add_column("Name", style="cyan")
        table.add_column("Start", style="green", no_wrap=True)
        table.add_column("End", style="green", no_wrap=True)
        table.add_column("Size", style="yellow", justify="right")
        table.add_column("Perms", style="white")
        table.add_column("Init", style="dim")

        for seg in result:
            perms = ""
            perms += "R" if seg.get("readable") else "-"
            perms += "W" if seg.get("writable") else "-"
            perms += "X" if seg.get("executable") else "-"
            init = "init" if seg.get("initialized") else "uninit"
            table.add_row(
                seg.get("name", "?"),
                seg.get("start", "?"),
                seg.get("end", "?"),
                str(seg.get("size", 0)),
                perms,
                init
            )

        return self._capture(table)

    def format_namespaces_list(self, data: Dict[str, Any]) -> str:
        """Format namespaces list as table."""
        result = data.get("result", [])

        if not result:
            return self._capture("[yellow]No namespaces found[/yellow]")

        table = Table(title=f"Namespaces ({len(result)} items)", show_lines=False)
        table.add_column("Name", style="cyan")

        for item in result:
            name = item if isinstance(item, str) else item.get("name", "?")
            table.add_row(name)

        return self._capture(table)

    def format_variables_list(self, data: Dict[str, Any]) -> str:
        """Format variables list as table."""
        result = data.get("result", [])

        if not result:
            return self._capture("[yellow]No variables found[/yellow]")

        table = Table(title=f"Variables ({len(result)} items)", show_lines=False)
        table.add_column("Address", style="cyan", no_wrap=True)
        table.add_column("Scope", style="yellow")
        table.add_column("Type", style="green")
        table.add_column("Name", style="white")
        table.add_column("Function", style="dim")

        for v in result:
            table.add_row(
                v.get("address", "?"),
                v.get("type", "?"),
                v.get("dataType", "?"),
                v.get("name", "?"),
                v.get("function", "")
            )

        return self._capture(table)

    def format_datatypes_list(self, data: Dict[str, Any]) -> str:
        """Format datatypes list as table."""
        result = data.get("result", [])

        if not result:
            return self._capture("[yellow]No data types found[/yellow]")

        table = Table(title=f"Data Types ({len(result)} items)", show_lines=False)
        table.add_column("Kind", style="yellow")
        table.add_column("Name", style="cyan")
        table.add_column("Size", style="green", justify="right")
        table.add_column("Category", style="dim")

        for dt in result:
            table.add_row(
                dt.get("kind", "?"),
                dt.get("name", "?"),
                str(dt.get("length", 0)),
                dt.get("category", "/")
            )

        return self._capture(table)

    def format_callgraph(self, data: Dict[str, Any]) -> str:
        """Format analysis callgraph as a readable tree with summary."""
        result = data.get("result", {})
        if not isinstance(result, dict):
            return self._capture("[yellow]No call graph data available[/yellow]")

        nodes = result.get("nodes", [])
        edges = result.get("edges", [])
        if not isinstance(nodes, list):
            nodes = []
        if not isinstance(edges, list):
            edges = []

        root_name = result.get("rootFunction") or result.get("root") or "?"
        root_addr = result.get("rootAddress") or result.get("root_address")
        max_depth = result.get("max_depth")

        id_to_name = {}
        id_to_addr = {}
        for node in nodes:
            if not isinstance(node, dict):
                continue
            node_id = str(node.get("id") or node.get("address") or "")
            if node_id:
                id_to_name[node_id] = node.get("name") or node_id
                id_to_addr[node_id] = str(node.get("address") or node_id)

        children = {}
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            src = str(edge.get("from", ""))
            dst = str(edge.get("to", ""))
            if not src or not dst:
                continue
            children.setdefault(src, []).append(dst)

        root_id = str(result.get("rootId") or root_addr or "")
        if not root_id and root_name:
            for node_id, node_name in id_to_name.items():
                if node_name == root_name:
                    root_id = node_id
                    break

        root_label = root_name
        if root_addr:
            root_label = f"{root_name} ({root_addr})"

        tree = Tree(f"[cyan]{root_label}[/cyan]")

        def add_children(parent_node, node_id, depth=0, seen=None):
            if seen is None:
                seen = set()
            if node_id in seen:
                parent_node.add(f"[dim]{id_to_name.get(node_id, node_id)} (recursive)[/dim]")
                return

            seen = set(seen)
            seen.add(node_id)

            for child_id in children.get(node_id, [])[:20]:
                child_name = id_to_name.get(child_id, child_id)
                child_addr = id_to_addr.get(child_id, child_id)
                child_label = f"{child_name} ({child_addr})"
                child_node = parent_node.add(f"[green]{child_label}[/green]")
                if depth < 4:
                    add_children(child_node, child_id, depth + 1, seen)
            if len(children.get(node_id, [])) > 20:
                parent_node.add(f"[dim]... and {len(children[node_id]) - 20} more[/dim]")

        if root_id:
            add_children(tree, root_id)

        summary = self._capture(
            f"[cyan]Call Graph[/cyan] "
            f"nodes={len(nodes)} edges={len(edges)}"
            + (f" max_depth={max_depth}" if max_depth is not None else "")
        )

        edge_table = Table(title="Calls", show_lines=False)
        edge_table.add_column("From", style="cyan")
        edge_table.add_column("To", style="green")
        edge_table.add_column("Site", style="yellow")
        edge_table.add_column("Type", style="dim")

        for edge in edges:
            if not isinstance(edge, dict):
                continue
            src_id = str(edge.get("from", ""))
            dst_id = str(edge.get("to", ""))
            src_name = id_to_name.get(src_id, src_id)
            dst_name = id_to_name.get(dst_id, dst_id)
            src_addr = id_to_addr.get(src_id, src_id)
            dst_addr = id_to_addr.get(dst_id, dst_id)
            edge_table.add_row(
                f"{src_name} ({src_addr})",
                f"{dst_name} ({dst_addr})",
                str(edge.get("call_site", edge.get("site", ""))),
                str(edge.get("type", "")),
            )

        edge_text = self._capture(edge_table) if edge_table.rows else self._capture("[yellow]No calls[/yellow]")
        return f"{summary}\n{self._capture(tree)}\n{edge_text}"

    def format_dataflow(self, data: Dict[str, Any]) -> str:
        """Format analysis dataflow output."""
        result = data.get("result", {})
        if not isinstance(result, dict):
            return self._capture("[yellow]No data flow data available[/yellow]")

        steps = result.get("steps", [])
        if not isinstance(steps, list):
            steps = []

        table = Table(title="Data Flow", show_lines=False)
        table.add_column("Step", style="cyan", justify="right")
        table.add_column("Address", style="green", no_wrap=True)
        table.add_column("Type", style="yellow")
        table.add_column("Description", style="white", overflow="fold")

        for i, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                continue
            table.add_row(
                str(i),
                str(step.get("address", step.get("to", step.get("from", "?")))),
                str(step.get("type", step.get("refType", "?"))),
                str(step.get("description", step.get("label", "")))
            )

        header = []
        for key in ("start_address", "address", "direction", "max_steps", "truncated"):
            if key in result:
                header.append(f"[cyan]{key}:[/cyan] {result.get(key)}")

        if not table.rows:
            return self._capture("\n".join(header) if header else "[yellow]No data flow steps found[/yellow]")

        header_text = self._capture("\n".join(header)) if header else ""
        body = self._capture(table)
        return f"{header_text}\n{body}".strip()

    def format_error(self, error: Exception) -> str:
        """Format error message."""
        from ..client.exceptions import GhidraAPIError

        if isinstance(error, GhidraAPIError):
            return f"[red]Error [{error.code}]:[/red] {error.message}"

        return f"[red]Error:[/red] {str(error)}"
