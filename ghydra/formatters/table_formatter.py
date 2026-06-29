"""Table-based output formatter using rich library."""

import io
import os
import sys
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
        # Only colorize when stdout is a real terminal. The old force_terminal=use_colors
        # leaked ANSI codes into piped output, corrupting programmatic/agent parsing of hex
        # addresses. Auto-detect the TTY so default output is agent-clean without --no-color,
        # and honor the NO_COLOR convention (https://no-color.org).
        self._use_colors = use_colors and not os.environ.get("NO_COLOR") and sys.stdout.isatty()
        self.console = Console(
            color_system="auto" if self._use_colors else None,
            force_terminal=self._use_colors or None,
        )

    def _capture(self, renderable) -> str:
        """Capture rich renderable output to string.

        Args:
            renderable: Rich renderable object

        Returns:
            Captured string output
        """
        buffer = io.StringIO()
        # Mirror the main console's color decision (TTY-aware) so captured output is
        # plain when stdout is piped.
        temp_console = Console(
            file=buffer,
            color_system="auto" if self._use_colors else None,
            force_terminal=self._use_colors or None,
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
        code = (result.get("decompiled") or result.get("decompilation")
                or result.get("ccode") or result.get("decompiled_text", ""))
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
        # Javalin server sends "hex" (continuous string); older builds sent
        # "hexBytes" (space-separated pairs).
        hex_bytes = result.get("hex") or result.get("hexBytes") or ""

        if not hex_bytes:
            return self._capture("[red]No memory data available[/red]")

        lines = [f"[cyan]Memory at 0x{addr}:[/cyan]\n"]

        if " " in hex_bytes.strip():
            byte_pairs = hex_bytes.split()
        else:
            cleaned = hex_bytes.strip()
            byte_pairs = [cleaned[i:i+2] for i in range(0, len(cleaned), 2)]

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
            # XrefDto uses fromAddress/toAddress/fromFunction; accept legacy names.
            from_func = xref.get("fromFunction") or ""
            if not from_func and isinstance(xref.get("from_function"), dict):
                from_func = xref["from_function"].get("name", "")
            table.add_row(
                xref.get("fromAddress") or xref.get("from_addr", "?"),
                xref.get("toAddress") or xref.get("to_addr", "?"),
                xref.get("refType", "?"),
                from_func
            )

        return self._capture(table)

    def format_scalars(self, data: Dict[str, Any]) -> str:
        """Format scalar search results as table."""
        results = data.get("result", [])
        meta = data.get("meta", {}) or {}

        if not results:
            if meta.get("scanTruncated"):
                return self._capture("[yellow]No scalars found[/yellow] (scan truncated; "
                                     "narrow with --in-function or a more specific value)")
            return self._capture("[yellow]No scalars found[/yellow]")

        offset = meta.get("offset", 0)
        table = Table(title=f"Scalars ({offset + 1}-{offset + len(results)})", show_lines=False)
        table.add_column("Address", style="cyan", no_wrap=True)
        table.add_column("Value", style="green", no_wrap=True)
        table.add_column("Op", style="dim", no_wrap=True)
        table.add_column("Instruction", style="yellow", overflow="fold")
        table.add_column("In Function", style="white")
        table.add_column("Calls", style="magenta")

        for s in results:
            table.add_row(
                s.get("address", "?"),
                s.get("hexValue", str(s.get("value", "?"))),
                str(s.get("operandIndex", "")),
                s.get("instruction", ""),
                s.get("inFunction") or "-",
                s.get("toFunction") or "",
            )

        output = self._capture(table)
        if meta.get("scanTruncated"):
            output += "\n" + self._capture("[yellow]Scan truncated to keep the UI responsive; "
                                           "results may be incomplete - narrow with --in-function "
                                           "or a more specific value.[/yellow]")
        return output

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
                item.get("label") or item.get("name", ""),  # DataDto field is 'label'
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

        if isinstance(result, list):
            if not result:
                return self._capture("[green]Success[/green] (no items)")
            rows = []
            for item in result:
                if isinstance(item, dict):
                    rows.append(", ".join(f"{k}: {v}" for k, v in item.items() if k != "_links"))
                else:
                    rows.append(str(item))
            return self._capture("\n".join(rows))

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

        for item in result:
            primary = " *" if item.get("isPrimary") else ""
            table.add_row(
                item.get("address", "?"),
                item.get("type", "?"),
                item.get("name", "?") + primary
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
            # MemoryBlockDto serializes isRead/isWrite/isExecute/isInitialized.
            perms = ""
            perms += "R" if seg.get("isRead", seg.get("readable")) else "-"
            perms += "W" if seg.get("isWrite", seg.get("writable")) else "-"
            perms += "X" if seg.get("isExecute", seg.get("executable")) else "-"
            init = "init" if seg.get("isInitialized", seg.get("initialized")) else "uninit"
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
        """Format analysis callgraph as a readable tree with summary.

        Server shape: {root: {name, address, ...}, depth, direction,
                       callers: [{function: {...}, callers: [...]}],
                       callees: [{function: {...}, callees: [...]}]}
        """
        result = data.get("result", {})
        if not isinstance(result, dict) or not isinstance(result.get("root"), dict):
            return self._capture("[yellow]No call graph data available[/yellow]")

        root = result["root"]
        root_name = root.get("name", "?")
        root_addr = root.get("address", "")
        depth = result.get("depth")

        summary = self._capture(
            f"[cyan]Call Graph[/cyan] for {root_name} ({root_addr})"
            + (f" depth={depth}" if depth is not None else "")
        )

        def build_tree(title: str, nodes, child_key: str) -> str:
            tree = Tree(f"[cyan]{title}[/cyan]")

            def add_nodes(parent, items, level=0, budget=None):
                if budget is None:
                    budget = [200]
                if not isinstance(items, list):
                    return
                for node in items:
                    if budget[0] <= 0:
                        parent.add("[dim]...[/dim]")
                        return
                    if not isinstance(node, dict):
                        continue
                    fn = node.get("function", {})
                    label = f"{fn.get('name', '?')} ({fn.get('address', '?')})"
                    child = parent.add(f"[green]{label}[/green]")
                    budget[0] -= 1
                    add_nodes(child, node.get(child_key), level + 1, budget)

            add_nodes(tree, nodes)
            return self._capture(tree)

        parts = [summary]
        callers = result.get("callers")
        if callers is not None:
            parts.append(build_tree(f"Callers ({len(callers)})", callers, "callers")
                         if callers else self._capture("[yellow]No callers[/yellow]"))
        callees = result.get("callees")
        if callees is not None:
            parts.append(build_tree(f"Callees ({len(callees)})", callees, "callees")
                         if callees else self._capture("[yellow]No callees[/yellow]"))

        return "\n".join(parts)

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
        table.add_column("Instruction", style="white", overflow="fold")
        table.add_column("Function", style="dim")
        table.add_column("Refs", style="yellow", justify="right")

        for i, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                continue
            # Server steps carry instruction text + containing function + references.
            table.add_row(
                str(i),
                str(step.get("address", step.get("to", step.get("from", "?")))),
                str(step.get("instruction", step.get("description", step.get("label", "")))),
                str(step.get("function", "")),
                str(step.get("reference_count", len(step.get("references", []))))
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

    def format_call_paths(self, data: Dict[str, Any]) -> str:
        """Format call paths as a table (one row per path, arrow chain of functions)."""
        result = data.get("result", {})
        if not isinstance(result, dict):
            return self._capture("[yellow]No call path data available[/yellow]")

        paths = result.get("paths", []) or []
        unresolved = result.get("unresolved_edges", 0) or 0
        header = self._capture(
            f"[cyan]Call paths[/cyan] {result.get('from', '?')} -> {result.get('to', '?')} "
            f"({len(paths)} found"
            + (", truncated" if result.get("truncated") else "")
            + (f", {unresolved} unresolved edges" if unresolved else "") + ")"
        )
        if not paths:
            return f"{header}\n" + self._capture("[yellow]No paths found[/yellow]")

        table = Table(show_lines=False)
        table.add_column("#", style="cyan", justify="right")
        table.add_column("Len", style="dim", justify="right")
        table.add_column("Path", style="green", overflow="fold")
        for i, p in enumerate(paths, start=1):
            fns = p.get("functions", []) if isinstance(p, dict) else []
            chain = " -> ".join(f"{f.get('name', '?')}" for f in fns)
            table.add_row(str(i), str(p.get("length", len(fns))), chain)
        return f"{header}\n" + self._capture(table)

    def format_string_usage(self, data: Dict[str, Any]) -> str:
        """Format string usage: matched strings, direct users, and flat callers with depth."""
        result = data.get("result", {})
        if not isinstance(result, dict):
            return self._capture("[yellow]No string usage data available[/yellow]")

        matches = result.get("matches", []) or []
        unresolved = result.get("unresolved_refs", 0) or 0
        header = self._capture(
            f"[cyan]String usage[/cyan] value={result.get('value', '?')} "
            f"match={result.get('match', '?')} caller_depth={result.get('caller_depth', 0)} "
            f"(size={result.get('size', 0)}"
            + (", truncated" if result.get("truncated") else "")
            + (f", {unresolved} unresolved refs" if unresolved else "") + ")"
        )
        if not matches:
            return f"{header}\n" + self._capture("[yellow]No matches[/yellow]")

        table = Table(show_lines=True)
        table.add_column("String @", style="green", no_wrap=True)
        table.add_column("Value", style="white", overflow="fold")
        table.add_column("Direct users", style="cyan", overflow="fold")
        table.add_column("Callers (depth)", style="yellow", overflow="fold")
        for m in matches:
            if not isinstance(m, dict):
                continue
            s = m.get("string", {})
            users = ", ".join(f.get("name", "?") for f in m.get("directUsers", []))
            callers = ", ".join(
                f"{c.get('function', {}).get('name', '?')}({c.get('depth', '?')})"
                for c in m.get("callers", [])
            )
            table.add_row(str(s.get("address", "?")), str(s.get("value", "")),
                          users or "-", callers or "-")
        return f"{header}\n" + self._capture(table)

    def format_error(self, error: Exception) -> str:
        """Format error message."""
        from ..client.exceptions import GhidraAPIError

        if isinstance(error, GhidraAPIError):
            return f"[red]Error [{error.code}]:[/red] {error.message}"

        return f"[red]Error:[/red] {str(error)}"
