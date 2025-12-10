# Ghydra CLI

A command-line interface for GhydraMCP that provides access to Ghidra's reverse engineering capabilities via a standalone tool.

## Overview

Ghydra CLI is a standalone command-line tool that exposes all the functionality of the GhydraMCP bridge in a terminal-friendly format. It supports both human-readable formatted output (with tables, syntax highlighting, and colors) and JSON output for scripting.

## Installation

```bash
# Install in development mode
cd /path/to/GhydraMCP
pip install -e .

# After installation, reshim if using asdf
asdf reshim
```

## Quick Start

```bash
# List all Ghidra instances
ghydra instances list

# Decompile a function
ghydra functions decompile --name main

# Read memory as hex dump
ghydra memory read --address 0x401000 --length 64

# Get JSON output for scripting
ghydra --json functions list
```

## Global Options

All commands support these global options:

- `--host, -h TEXT`: Ghidra host (default: from config or localhost)
- `--port, -p INTEGER`: Ghidra port (default: from config or 8192)
- `--json`: Output raw JSON instead of formatted text
- `--no-color`: Disable colored output
- `--verbose, -v`: Enable verbose output
- `--version`: Show version and exit
- `--help`: Show help message

## Configuration

Configuration file: `~/.ghydra/config.json`

Example configuration:
```json
{
  "default_host": "localhost",
  "default_port": 8192,
  "timeout": 10,
  "use_colors": true,
  "page_output": true,
  "max_pagination": 100
}
```

Environment variables:
- `GHYDRA_HOST`: Override default Ghidra host
- `GHYDRA_PORT`: Override default Ghidra port

## Implemented Command Groups

### Instances Commands

Manage multiple Ghidra instances:

```bash
# List all instances (auto-discovers on ports 8192-8201)
ghydra instances list

# Discover instances on custom range
ghydra instances discover --start-port 8192 --end-port 8220

# Discover on different host
ghydra instances discover --host 192.168.1.100

# Register an instance manually
ghydra instances register --port 8195

# Set current working instance
ghydra instances use --port 8195

# Get current instance info
ghydra instances current

# Unregister an instance
ghydra instances unregister --port 8195
```

### Functions Commands

Analyze and manipulate functions:

```bash
# List all functions
ghydra functions list

# List with filtering
ghydra functions list --name-contains main
ghydra functions list --name-matches "^sub_.*"
ghydra functions list --limit 50

# Get function details
ghydra functions get --name main
ghydra functions get --address 0x401000

# Decompile function
ghydra functions decompile --name main
ghydra functions decompile --address 0x401000
ghydra functions decompile --name main --start-line 10 --end-line 20
ghydra functions decompile --name main --max-lines 50

# Disassemble function
ghydra functions disassemble --name main
ghydra functions disassemble --address 0x401000

# Create function
ghydra functions create --address 0x401500

# Rename function
ghydra functions rename --old-name sub_401000 --new-name main
ghydra functions rename --address 0x401000 --new-name main

# Set function signature
ghydra functions set-signature --name main --signature "int main(int argc, char **argv)"

# Get function variables
ghydra functions get-variables --name main

# Set function comment
ghydra functions set-comment --address 0x401000 --comment "Main entry point"
```

## Remaining Command Groups to Implement

The following command groups follow the same pattern as `instances` and `functions`. Here's how to implement them:

### 1. Memory Commands (`ghydra/cli/memory.py`)

```python
"""Memory operations commands."""

import click
from ..client.exceptions import GhidraError
from ..utils import should_page, page_output


@click.group('memory')
def memory():
    """Memory read/write commands."""
    pass


@memory.command('read')
@click.option('--address', '-a', required=True, help='Memory address (hex)')
@click.option('--length', type=int, default=16, help='Number of bytes to read')
@click.option('--format', type=click.Choice(['hex', 'base64', 'string']), default='hex', help='Output format')
@click.pass_context
def read_memory(ctx, address, length, format):
    """Read bytes from memory.

    Examples:
        ghydra memory read --address 0x401000
        ghydra memory read --address 0x401000 --length 64
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {
            'length': length,
            'format': format
        }

        response = client.get(f'memory/{address.lstrip("0x")}', params=params)
        output = formatter.format_memory(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        click.echo(error_output, err=True)
        ctx.exit(1)


@memory.command('write')
@click.option('--address', '-a', required=True, help='Memory address (hex)')
@click.option('--bytes-data', required=True, help='Data to write')
@click.option('--format', type=click.Choice(['hex', 'base64', 'string']), default='hex', help='Input format')
@click.pass_context
def write_memory(ctx, address, bytes_data, format):
    """Write bytes to memory (use with caution).

    Examples:
        ghydra memory write --address 0x401000 --bytes-data "4883EC10"
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        data = {
            'bytes': bytes_data,
            'format': format
        }

        response = client.post(f'memory/{address.lstrip("0x")}', json_data=data)
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        click.echo(error_output, err=True)
        ctx.exit(1)
```

Then add to `main.py`:
```python
from . import instances, functions, memory

cli.add_command(memory.memory)
```

### 2. Data Commands (`ghydra/cli/data.py`)

```python
@click.group('data')
def data():
    """Data item management commands."""
    pass

@data.command('list')
# Add options: --offset, --limit, --addr, --name, --name-contains, --type
# Endpoint: GET /data with params

@data.command('list-strings')
# Options: --offset, --limit, --filter
# Endpoint: GET /data/strings

@data.command('create')
# Options: --address, --data-type, --size
# Endpoint: POST /data/{address}

@data.command('rename')
# Options: --address, --name
# Endpoint: PATCH /data/{address}

@data.command('delete')
# Options: --address
# Endpoint: DELETE /data/{address}

@data.command('set-type')
# Options: --address, --data-type
# Endpoint: PATCH /data/{address}/type
```

### 3. Structs Commands (`ghydra/cli/structs.py`)

```python
@click.group('structs')
def structs():
    """Struct data type management commands."""
    pass

@structs.command('list')
# Options: --offset, --limit, --category
# Endpoint: GET /structs

@structs.command('get')
# Options: --name
# Endpoint: GET /structs/{name}

@structs.command('create')
# Options: --name, --category, --description
# Endpoint: POST /structs

@structs.command('add-field')
# Options: --struct-name, --field-name, --field-type, --offset, --comment
# Endpoint: POST /structs/{struct_name}/fields

@structs.command('update-field')
# Options: --struct-name, --field-name OR --field-offset, --new-name, --new-type, --new-comment
# Endpoint: PATCH /structs/{struct_name}/fields/{field_name_or_offset}

@structs.command('delete')
# Options: --name
# Endpoint: DELETE /structs/{name}
```

### 4. Xrefs Commands (`ghydra/cli/xrefs.py`)

```python
@click.group('xrefs')
def xrefs():
    """Cross-reference analysis commands."""
    pass

@xrefs.command('list')
# Options: --to-addr, --from-addr, --type, --offset, --limit
# Endpoint: GET /xrefs with params
# Note: At least one of --to-addr or --from-addr required
```

### 5. Analysis Commands (`ghydra/cli/analysis.py`)

```python
@click.group('analysis')
def analysis():
    """Program analysis commands."""
    pass

@analysis.command('run')
# Options: --analysis-options (JSON dict)
# Endpoint: POST /analysis

@analysis.command('get-callgraph')
# Options: --name, --address, --max-depth
# Endpoint: GET /analysis/callgraph/{name_or_address}

@analysis.command('get-dataflow')
# Options: --address, --direction (forward/backward), --max-steps
# Endpoint: GET /analysis/dataflow/{address}

@analysis.command('status')
# Endpoint: GET /analysis/status
```

### 6. UI Commands (`ghydra/cli/ui.py`)

```python
@click.group('ui')
def ui():
    """UI integration commands."""
    pass

@ui.command('get-current-address')
# Endpoint: GET /ui/current-address

@ui.command('get-current-function')
# Endpoint: GET /ui/current-function
```

### 7. Comments Commands (`ghydra/cli/comments.py`)

```python
@click.group('comments')
def comments():
    """Comment management commands."""
    pass

@comments.command('set')
# Options: --address, --comment, --comment-type (plate/pre/post/eol/repeatable)
# Endpoint: POST /comments/{address}
```

### 8. Project Commands (`ghydra/cli/project.py`)

```python
@click.group('project')
def project():
    """Project management commands."""
    pass

@project.command('info')
# Endpoint: GET /project

@project.command('list-files')
# Options: --folder, --recursive, --offset, --limit
# Endpoint: GET /project/files

@project.command('open-file')
# Options: --path
# Endpoint: POST /project/open
```

## Implementation Pattern

All command groups follow the same pattern:

1. **Create command group file** in `ghydra/cli/`
2. **Define Click group** with `@click.group('name')`
3. **Add commands** with `@group.command('command-name')`
4. **Use context** with `@click.pass_context` to access client and formatter
5. **Handle errors** with try/except and `GhidraError`
6. **Format output** using `formatter.format_*()` methods
7. **Page long output** using `should_page()` and `page_output()`
8. **Import and register** in `main.py`

## Output Formatting

The CLI supports two output modes:

### Default Mode (Rich Terminal Output)

- Tables with colored columns
- Syntax-highlighted code (C and assembly)
- Panels for detailed info
- Tree views for structured data
- Hex dumps for memory
- Auto-paging for long output

### JSON Mode (`--json` flag)

- Raw JSON output from API
- Pretty-printed by default
- Suitable for scripting and automation
- Can be piped to `jq` for processing

## Testing Against Running Ghidra

To test the CLI against a running Ghidra instance:

1. **Start Ghidra** with GhydraMCP plugin loaded
2. **Open a binary** in CodeBrowser
3. **Test basic commands**:
   ```bash
   ghydra instances list
   ghydra functions list --limit 10
   ghydra functions decompile --address <some_address>
   ```

4. **Test JSON output**:
   ```bash
   ghydra --json functions list | jq '.result[0]'
   ```

5. **Test error handling**:
   ```bash
   ghydra --port 9999 instances current  # Should fail gracefully
   ghydra functions get --name nonexistent  # Should show error
   ```

## API Endpoint Reference

Reference `bridge_mcp_hydra.py` for the exact endpoint patterns:

- **Functions**: `/functions`, `/functions/{address}`, `/functions/by-name/{name}`
- **Memory**: `/memory/{address}`
- **Data**: `/data`, `/data/strings`, `/data/{address}`
- **Structs**: `/structs`, `/structs/{name}`, `/structs/{name}/fields`
- **Xrefs**: `/xrefs`
- **Analysis**: `/analysis`, `/analysis/callgraph/{address}`, `/analysis/dataflow/{address}`
- **UI**: `/ui/current-address`, `/ui/current-function`
- **Comments**: `/comments/{address}`
- **Project**: `/project`, `/project/files`, `/project/open`
- **Instances**: `/plugin-version`, `/program`

## Tips for Implementation

1. **Copy existing patterns**: Use `instances.py` or `functions.py` as templates
2. **Check MCP bridge**: Reference `bridge_mcp_hydra.py` for exact parameter names and endpoint paths
3. **Test incrementally**: Implement one command at a time and test
4. **Handle mutual exclusivity**: Use Click's validation for mutually exclusive options (like `--name` vs `--address`)
5. **Use formatters**: Ensure `TableFormatter` has appropriate `format_*()` methods for each response type
6. **Page output**: Long listings should use paging for better UX
7. **Error messages**: Provide helpful error messages for common mistakes

## Development Workflow

```bash
# Make changes to code
# Reinstall in development mode
pip install -e .
asdf reshim  # If using asdf

# Test immediately
ghydra <command>

# Check help text
ghydra <group> <command> --help
```

## Architecture

```
ghydra/
├── __init__.py
├── cli/
│   ├── __init__.py
│   ├── main.py          # Main CLI group with global options
│   ├── instances.py     # ✅ Implemented (6 commands)
│   ├── functions.py     # ✅ Implemented (8 commands)
│   ├── memory.py        # ⏳ TODO (2 commands)
│   ├── data.py          # ⏳ TODO (6 commands)
│   ├── structs.py       # ⏳ TODO (6 commands)
│   ├── xrefs.py         # ⏳ TODO (1 command)
│   ├── analysis.py      # ⏳ TODO (4 commands)
│   ├── ui.py            # ⏳ TODO (2 commands)
│   ├── comments.py      # ⏳ TODO (2 commands)
│   └── project.py       # ⏳ TODO (3 commands)
├── client/
│   ├── __init__.py
│   ├── http_client.py   # ✅ HTTP client with connection pooling
│   ├── exceptions.py    # ✅ Custom exceptions
│   └── models.py        # ✅ Data models
├── formatters/
│   ├── __init__.py
│   ├── base.py          # ✅ Base formatter interface
│   ├── json_formatter.py    # ✅ JSON formatter
│   └── table_formatter.py   # ✅ Table formatter with rich
├── config/
│   ├── __init__.py
│   ├── config_manager.py    # ✅ Config file management
│   └── defaults.py      # ✅ Default configuration
└── utils/
    ├── __init__.py
    ├── pager.py         # ✅ Output paging
    └── validators.py    # ✅ Input validation
```

## Contributing

When implementing remaining command groups:

1. Follow the established patterns in `instances.py` and `functions.py`
2. Add appropriate formatters to `table_formatter.py` if needed
3. Update this README with usage examples
4. Test against running Ghidra instance
5. Ensure help text is clear and includes examples

## License

Same as GhydraMCP project.
