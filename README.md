[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/starsong-consulting/GhydraMCP)](https://github.com/starsong-consulting/GhydraMCP/releases)
[![API Version](https://img.shields.io/badge/API-v3000-orange)](https://github.com/starsong-consulting/GhydraMCP/blob/main/GHIDRA_HTTP_API.md)
[![GitHub stars](https://img.shields.io/github/stars/starsong-consulting/GhydraMCP)](https://github.com/starsong-consulting/GhydraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/starsong-consulting/GhydraMCP)](https://github.com/starsong-consulting/GhydraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/starsong-consulting/GhydraMCP)](https://github.com/starsong-consulting/GhydraMCP/graphs/contributors)
[![Build Status](https://github.com/starsong-consulting/GhydraMCP/actions/workflows/build.yml/badge.svg)](https://github.com/starsong-consulting/GhydraMCP/actions/workflows/build.yml)

# GhydraMCP

GhydraMCP connects [Ghidra](https://ghidra-sre.org/) to AI assistants for reverse engineering, over the [Model Context Protocol (MCP)](https://github.com/modelcontextprotocol/mcp) or a command-line tool.

![GhydraMCP logo](https://github.com/user-attachments/assets/86b9b2de-767c-4ed5-b082-510b8109f00f)

## Overview

> **Note:** The MCP bridge (`bridge_mcp_hydra.py`) is being deprecated in favor of the CLI tool (`ghydra`). The CLI provides the same capabilities with better output formatting, `--json` mode for scripting and AI tool use, and doesn't require an MCP-capable client. The bridge will continue to work but is no longer the recommended integration path.

GhydraMCP has four components:

1. **Ghidra plugin**: exposes Ghidra over a HATEOAS REST API
2. **CLI tool (`ghydra`)**: a standalone terminal client; human-readable tables, plus `--json` for scripting and AI tool use
3. **MCP bridge** *(deprecated)*: a Python script that translates MCP requests into API calls
4. **Multiple instances**: connect several Ghidra windows to work on different binaries at once

Through it, an assistant can:
- Decompile and analyze binary code, with a few output formats
- Map program structure, function relationships, and data types
- Run binary analysis (cross-references, call graphs, data flow)
- Edit the analysis (rename, annotate, create/delete/modify data)
- Read and write memory
- Follow HATEOAS links between resources

GhydraMCP started as a fork of [GhidraMCP by Laurie Wired](https://github.com/LaurieWired/GhidraMCP/) and added multi-instance support, data manipulation, and a HATEOAS REST API.

# Features

## Program analysis

- **Decompilation**:
  - Convert binary functions to readable C code 
  - Toggle between clean C-like pseudocode and raw decompiler output
  - Show/hide syntax trees for detailed analysis
  - Multiple simplification styles for different analysis approaches
  
- **Static analysis**: 
  - Cross-reference analysis (find callers and callees)
  - Call graph generation and traversal
  - Data flow analysis with variable tracking
  - Type propagation and reconstruction
  - Function relationship mapping
  
- **Memory**:
  - Direct memory reading with hex and raw byte representation
  - Address space navigation and mapping
  - Memory segment analysis

- **Symbols**:
  - View and analyze imports and exports
  - Identify library functions and dependencies
  - Symbol table exploration and manipulation
  - Namespace hierarchy visualization
  - Fully-qualified names: functions, symbols, data, variables, and xrefs are returned and matched by their namespace-qualified name (e.g. `MyClass::method`; global-namespace members are unprefixed). A bare name resolves in the global namespace only, and renaming with `::` moves a symbol into that namespace (created if absent)

## Interactive reverse engineering

- **Code understanding**:
  - Explore function code in context
  - Analyze data structures and complex types
  - View disassembly with linking to decompiled code
  - Examine function prototypes and signatures
  
- **Annotation**:
  - Rename functions, variables, and data 
  - Add multiple comment types (EOL, plate, pre/post)
  - Create and modify data types
  - Set and update function signatures and prototypes

## Data manipulation

- **Data**:
  - Create new data items with specified types
  - Delete existing data items
  - Rename data items
  - Set and update data types for existing items
  - Combined rename and retype operations
  - Type definition management

- **Functions**:
  - Rename functions
  - Update function signatures with parameter information
  - Modify local variable names and types
  - Set function return types

## Multiple instances and projects

- **Instances**:
  - Run multiple Ghidra instances simultaneously on ports 8192-8447 (256 port range)
  - Analyze different binaries in parallel
  - Connect to specific instances using port numbers
  - Auto-discovery of running Ghidra instances
  - Instance metadata with project and file information
  - Plugin version and API checking for compatibility

- **Projects**:
  - Get current project information (name, location, file counts)
  - List all files in a project with filtering
  - Open project files in new CodeBrowser windows
  - Navigate project folder hierarchy
  - Automatic instance registration when opening new programs

## Navigation and discovery

- List and search functions, classes, and namespaces
- View memory segments and layout
- Search by name, pattern, or signature
- Resource discovery through HATEOAS links
- Pagination for handling large result sets
- Filtering capabilities across all resources

# Installation

## Prerequisites
- [Ghidra](https://ghidra-sre.org) 11.x or 12.x. Releases ship a separate build per Ghidra version; the extension's `ghidraVersion` must match your Ghidra version exactly.
- Java 21 (Temurin 21 recommended) for building the plugin
- Python3
- MCP [SDK](https://github.com/modelcontextprotocol/python-sdk)

## Ghidra
First, download the latest [release](https://github.com/starsong-consulting/GhydraMCP/releases) from this repository. The "Complete" artifact contains the zipped Ghidra plugin and the Python MCP bridge. Unpack the outer archive, then, add the plugin to Ghidra:

1. Run Ghidra
2. Select `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `Ghydra-*-ghidra<version>.zip` that matches your Ghidra version (e.g. `...-ghidra12.1.2.zip` for Ghidra 12.1.2)
5. Restart Ghidra
6. Make sure the Ghydra plugin is enabled in `File` -> `Configure` -> `Developer`

> **Note:** By default, the first CodeBrowser opened in Ghidra gets port 8192, the second gets 8193, and so on. You can check which ports are being used by looking at the Console in the Ghidra main (project) window - click the computer icon in the bottom right to "Open Console". Look for log entries like:
> ```
> (GhydraPlugin) GhydraMCP loaded on port 8193
> (GhydraServer) GhydraMCP HTTP server started on port 8193
> ```
>
> GhydraMCP now includes auto-discovery of running Ghidra instances, so manually registering each instance is typically not necessary. The MCP bridge will automatically discover and register instances on startup and periodically check for new ones.

Video Installation Guide:

https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3

## CLI Tool

GhydraMCP includes `ghydra`, a command-line tool for interacting with Ghidra directly from the terminal. It works standalone, no MCP client needed.

```bash
# Install
pip install -e .

# List running Ghidra instances
ghydra instances list

# Decompile a function
ghydra functions decompile --name main

# List strings matching a pattern
ghydra data list-strings --filter "password"

# Read memory as hex dump
ghydra memory read --address 0x401000 --length 64

# JSON output for scripting and piping
ghydra --json functions list | jq '.result[].name'
```

All commands support `--host`, `--port`, `--json`, and `--no-color` flags. See [GHYDRA_CLI.md](GHYDRA_CLI.md) for the full reference.

Timeout defaults are intentionally high for large binaries:
- CLI/bridge HTTP timeout default: `900s` (`GHYDRA_TIMEOUT`)
- Decompilation timeout default: `1200s` (`GHYDRA_DECOMP_TIMEOUT`)
- Incomplete decompilation responses include retry guidance (`retry_recommended`, `suggested_timeout_seconds`)

## MCP Clients

GhydraMCP works with any MCP-compatible client using **stdio transport**. It has been tested and confirmed working with:

- **Claude Desktop** - Anthropic's official desktop application
- **Claude Code** - Anthropic's VS Code extension and CLI tool
- **Cline** - Popular VS Code extension for AI-assisted coding

See the [Client Setup](#client-setup) section below for detailed configuration instructions for each client.

## API Reference

### Available Tools

Tools are grouped into namespaces:

**Instance Management** (`instances_*`):
- `instances_list`: List active Ghidra instances (auto-discovers on default host) - **use this first**
- `instances_discover`: Discover instances on a specific host (params: host [optional]) - **only use for non-default hosts**
- `instances_register`: Register new instance (params: port, url [optional])
- `instances_unregister`: Remove instance (params: port)
- `instances_use`: Set current working instance (params: port)
- `instances_current`: Get current working instance info

**Function Analysis** (`functions_*`):
- `functions_list`: List all functions (params: offset, limit, port [optional])
- `functions_get`: Get function details (params: name or address, port [optional]); `name` is the fully-qualified name (e.g. `MyClass::method`), a bare name resolves in the global namespace only
- `functions_decompile`: Get decompiled C code (params: name or address, syntax_tree, style, timeout, port [optional]); incomplete results return retry metadata and suggested timeout
- `functions_disassemble`: Get disassembled instructions (params: name or address, port [optional])
- `functions_create`: Create function at address (params: address, port [optional])
- `functions_rename`: Rename a function (params: old_name or address, new_name, port [optional]); a `new_name` containing `::` moves the function into that namespace (created if absent), a leading `::` moves it to the global namespace
- `functions_set_signature`: Update function prototype (params: name or address, signature, port [optional])
- `functions_delete`: Delete a function (params: name or address, port [optional])
- `functions_get_variables`: Get function variables (params: name or address, port [optional])
- `functions_update_variable`: Update a function variable (params: address, variable_name, new_name [optional], new_data_type [optional], port [optional])
- `functions_set_comment`: Set function comment (params: address, comment, port [optional])

**Data Manipulation** (`data_*`):
- `data_list`: List data items (params: offset, limit, addr, name, name_contains, port [optional]); address lookups return defined data first, then label symbols if no defined data exists
- `data_list_strings`: List all defined strings (params: offset, limit, filter, port [optional])
- `data_create`: Create data at address (params: address, data_type, size [optional], port [optional])
- `data_rename`: Rename data item (params: address, name, port [optional]); auto-defines a byte at the address if data is undefined
- `data_delete`: Delete data item (params: address, port [optional])
- `data_set_type`: Change data type (params: address, data_type, port [optional]); supports array syntax (e.g. `uint64_t[8]`) and auto-defines data when undefined

**Struct Management** (`structs_*`):
- `structs_list`: List all struct data types (params: offset, limit, category [optional], port [optional])
- `structs_get`: Get detailed struct information (params: name, port [optional])
- `structs_create`: Create new struct (params: name, category [optional], size [optional], description [optional], port [optional])
- `structs_add_field`: Add field to struct (params: struct_name, field_name, field_type, offset [optional], comment [optional], port [optional])
- `structs_update_field`: Update struct field (params: struct_name, field_name or field_offset, new_name [optional], new_type [optional], new_comment [optional], port [optional])
- `structs_delete`: Delete struct (params: name, port [optional])

**Memory Operations** (`memory_*`):
- `memory_read`: Read bytes from memory (params: address, length, format, port [optional]); overlay-aware (`runtime::145e29b10` and plain offsets that map to overlays)
- `memory_write`: Write bytes to memory (params: address, bytes_data, format, port [optional])

**Cross-References** (`xrefs_*`):
- `xrefs_list`: List cross-references (params: to_addr [optional], from_addr [optional], type [optional], offset, limit, port [optional])

**Analysis** (`analysis_*`):
- `analysis_run`: Trigger program analysis (params: analysis_options [optional], background [optional], port [optional])
- `analysis_status`: Check analysis status (params: port [optional])
- `analysis_get_callgraph`: Get function call graph (params: name or address, max_depth, port [optional])
- `analysis_get_dataflow`: Perform reference-flow traversal from an address (params: address, direction, max_steps, port [optional])

**Project Management** (`project_*`):
- `project_info`: Get current project information (params: port [optional])
- `project_list_files`: List files in project (params: folder, recursive, offset, limit, port [optional])
- `project_open_file`: Open project file in CodeBrowser (params: path, port [optional])
- `projects_list`: List projects (params: port [optional])
- `projects_get`: Get project details by name (params: name, port [optional])
- `programs_list`: List programs (params: project [optional], offset, limit, port [optional])
- `programs_get`: Get program by ID or `current` (params: program_id [optional], port [optional])
- `programs_delete`: Delete/close program by ID or `current` (params: program_id [optional], port [optional])

> `programs_delete` and program import routes are currently exposed but may return `NOT_IMPLEMENTED` depending on plugin-side support.

**Datatype Management** (`datatypes_*`):
- `datatypes_list`: List data types (params: offset, limit, category [optional], kind [optional], port [optional])
- `datatypes_search`: Search data types by name (params: name, offset, limit, port [optional])
- `datatypes_create_struct`: Create struct datatype (params: name, category [optional], fields_json [optional], port [optional]); supports JSON field definitions
- `datatypes_create_enum`: Create enum datatype (params: name, size [optional], category [optional], values_json [optional], port [optional]); supports JSON value definitions
- `datatypes_create_union`: Create union datatype (params: name, category [optional], fields_json [optional], port [optional]); supports JSON field definitions

**Emulation** (`emulation_*`) — PCode dynamic analysis via Ghidra's `EmulatorHelper`:
- `emulation_reset`: Start a fresh session at an address (params: start, registers [optional], memory [optional], port [optional])
- `emulation_run`: Run until an address/breakpoint/error/max_steps (params: until [optional], max_steps [optional], trace [optional], port [optional])
- `emulation_step`: Single-step the session (params: count [optional], trace [optional], port [optional])
- `emulation_state`: Current state without executing (params: port [optional])
- `emulation_read_register` / `emulation_write_register`: Read/write a register as hex (params: name, value [write], port [optional])
- `emulation_read_memory` / `emulation_write_memory`: Read/write emulated memory as hex (params: address, length [read]/hex_bytes [write], port [optional])
- `emulation_set_breakpoint` / `emulation_clear_breakpoint`: Set/clear an emulation breakpoint (params: address, port [optional])
- `emulation_dispose`: Dispose the session (params: port [optional])

**Comment Management** (`comments_*`):
- `comments_set`: Set memory comment (params: address, comment [optional], comment_type [optional], port [optional])
- `comments_get`: Get memory comment (params: address, comment_type [optional], port [optional])

**UI Helpers** (`ui_*`):
- `ui_get_current_address`: Get currently selected UI address (params: port [optional])
- `ui_get_current_function`: Get currently selected UI function (params: port [optional])

**Program Metadata** (`classes_*`, `symbols_*`, `segments_*`, `namespaces_*`, `variables_*`):
- `classes_list`: List classes/namespaces (params: offset, limit, port [optional])
- `symbols_list` / `symbols_imports` / `symbols_exports`: Enumerate symbols (params: offset, limit, port [optional])
- `segments_list`: List memory blocks (params: offset, limit, name [optional], port [optional])
- `namespaces_list`: List namespaces (params: offset, limit, port [optional])
- `variables_list`: List variables (params: offset, limit, search [optional], global_only [optional], port [optional])

**Example Usage**:
```python
# Instance Management - Always start here
client.use_tool("ghydra", "instances_list")  # Auto-discovers instances on localhost
client.use_tool("ghydra", "instances_use", {"port": 8192})  # Set working instance
client.use_tool("ghydra", "instances_current")  # Check current instance

# Function Analysis
client.use_tool("ghydra", "functions_list", {"offset": 0, "limit": 100})
client.use_tool("ghydra", "functions_get", {"name": "main"})
client.use_tool("ghydra", "functions_decompile", {"address": "0x00401000"})
client.use_tool("ghydra", "functions_disassemble", {"name": "main"})
client.use_tool("ghydra", "functions_rename", {"address": "0x00401000", "new_name": "process_data"})
client.use_tool("ghydra", "functions_set_signature", {"address": "0x00401000", "signature": "int process_data(char* buf, int len)"})
client.use_tool("ghydra", "functions_set_comment", {"address": "0x00401000", "comment": "Main processing function"})

# Data Manipulation
client.use_tool("ghydra", "data_list_strings", {"filter": "password"})  # Find strings containing "password"
client.use_tool("ghydra", "data_list", {"offset": 0, "limit": 50})
client.use_tool("ghydra", "data_create", {"address": "0x00401234", "data_type": "int"})
client.use_tool("ghydra", "data_rename", {"address": "0x00401234", "name": "counter"})
client.use_tool("ghydra", "data_set_type", {"address": "0x00401238", "data_type": "uint64_t[8]"})
client.use_tool("ghydra", "data_delete", {"address": "0x0040123C"})

# Struct Management
client.use_tool("ghydra", "structs_create", {"name": "NetworkPacket", "category": "/network"})
client.use_tool("ghydra", "structs_add_field", {
    "struct_name": "NetworkPacket",
    "field_name": "header",
    "field_type": "dword",
    "comment": "Packet header"
})
client.use_tool("ghydra", "structs_add_field", {
    "struct_name": "NetworkPacket",
    "field_name": "data_ptr",
    "field_type": "pointer"
})
client.use_tool("ghydra", "structs_update_field", {
    "struct_name": "NetworkPacket",
    "field_name": "header",
    "new_name": "packet_header",
    "new_comment": "Updated header field"
})
client.use_tool("ghydra", "structs_get", {"name": "NetworkPacket"})
client.use_tool("ghydra", "structs_list", {"category": "/network"})

# Memory Operations
client.use_tool("ghydra", "memory_read", {"address": "runtime::145e29b10", "length": 16, "format": "hex"})
client.use_tool("ghydra", "memory_write", {"address": "0x00401000", "bytes_data": "90909090", "format": "hex"})

# Cross-References
client.use_tool("ghydra", "xrefs_list", {"to_addr": "0x00401000"})  # Find callers
client.use_tool("ghydra", "xrefs_list", {"from_addr": "0x00401000"})  # Find callees

# Analysis
client.use_tool("ghydra", "analysis_status")  # Check if analysis is running
client.use_tool("ghydra", "analysis_run", {"background": True})  # Trigger analysis in background
client.use_tool("ghydra", "analysis_get_callgraph", {"name": "main", "max_depth": 5})
client.use_tool("ghydra", "analysis_get_dataflow", {"address": "0x00401050", "direction": "forward"})

# Project Management
client.use_tool("ghydra", "project_info")  # Get current project info
client.use_tool("ghydra", "project_list_files", {"folder": "/", "recursive": True})
client.use_tool("ghydra", "project_open_file", {"path": "/malware_samples/sample2.exe"})
```

## Client Setup

GhydraMCP works with any MCP-compatible client. Below are configuration examples for popular AI coding assistants.

### Installation Methods

#### Recommended: Local Installation from Release

Download the latest [release](https://github.com/starsong-consulting/GhydraMCP/releases) to ensure the bridge and plugin versions are in sync.

```json
{
  "mcpServers": {
    "ghydra": {
      "command": "uv",
      "args": [
        "run",
        "/ABSOLUTE_PATH_TO/bridge_mcp_hydra.py"
      ],
      "env": {
        "GHIDRA_HYDRA_HOST": "localhost"
      }
    }
  }
}
```

Replace `/ABSOLUTE_PATH_TO/` with the actual path to your `bridge_mcp_hydra.py` file.

> **Note:** You can also use `python` instead of `uv run`, but then you'll need to manually install the requirements first with `pip install mcp requests`.

#### Alternative: Direct from Repository with uvx

If you want to use the latest development version, you can run directly from the GitHub repository:

```json
{
  "mcpServers": {
    "ghydra": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/starsong-consulting/GhydraMCP",
        "ghydramcp"
      ],
      "env": {
        "GHIDRA_HYDRA_HOST": "localhost"
      }
    }
  }
}
```

> **Warning:** This method may pull a bridge version that's out of sync with your installed plugin. Only use this if you're tracking the latest development branch.

### Claude Desktop Configuration

Add your chosen configuration method to your Claude Desktop configuration file:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

### Claude Code Configuration

Claude Code automatically discovers MCP servers configured in Claude Desktop. If you've set up the configuration above, Claude Code will have access to GhydraMCP tools immediately.

Alternatively, you can configure Claude Code separately by adding the same configuration to the MCP settings in Claude Code's configuration.

### Cline Configuration

Cline (VS Code extension) uses a separate configuration file. To set up GhydraMCP with Cline:

1. Open VS Code with Cline installed
2. Click the "MCP Servers" icon in Cline's interface
3. Select the "Configure" tab
4. Click "Configure MCP Servers" to edit `cline_mcp_settings.json`
5. Add the following configuration:

```json
{
  "mcpServers": {
    "ghydra": {
      "command": "uv",
      "args": [
        "run",
        "/ABSOLUTE_PATH_TO/bridge_mcp_hydra.py"
      ],
      "env": {
        "GHIDRA_HYDRA_HOST": "localhost"
      },
      "disabled": false
    }
  }
}
```

If you prefer to use `python` directly instead of `uv`:

```json
{
  "mcpServers": {
    "ghydra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_hydra.py"
      ],
      "env": {
        "GHIDRA_HYDRA_HOST": "localhost"
      },
      "disabled": false
    }
  }
}
```

> **Important:** Replace `/ABSOLUTE_PATH_TO/` with the actual absolute path to your `bridge_mcp_hydra.py` file. For example:
> - **Linux/macOS**: `/home/username/GhydraMCP/bridge_mcp_hydra.py`
> - **Windows**: `C:\\Users\\username\\GhydraMCP\\bridge_mcp_hydra.py`

After saving the configuration, restart Cline to load the GhydraMCP server.

### 5ire Configuration
1. Tool Key: ghydra
2. Name: GhydraMCP
3. Command: `uv run /ABSOLUTE_PATH_TO/bridge_mcp_hydra.py`

## Example Session

An example of an AI assistant driving Ghidra through GhydraMCP:

**User:**
```
Analyze the main function in the binary and identify any data structures being used.
```

**Assistant:**
```
I'll analyze the binary for you. Let me start by checking available Ghidra instances.

[Uses instances_list]
Found Ghidra instance on port 8192 analyzing "malware_sample.exe".

[Uses instances_use with port 8192]
Set instance 8192 as current working instance.

[Uses functions_decompile with name "main"]
Here's the decompiled main function:

void main(void) {
  NetworkPacket *packet;
  int status;

  packet = (NetworkPacket *)malloc(0x20);
  packet->header = 0x1234;
  packet->data_ptr = allocate_buffer(0x100);
  status = process_packet(packet);
  ...
}

I can see this code uses a "NetworkPacket" structure. Let me check if it's already defined.

[Uses structs_get with name "NetworkPacket"]
The struct doesn't exist yet. Let me create it based on the decompiled code.

[Uses structs_create with name "NetworkPacket", category "/network"]
Created NetworkPacket struct.

[Uses structs_add_field for each field]
Added fields:
- header (dword at offset 0)
- data_ptr (pointer at offset 4)
- size (dword at offset 8)
- status (dword at offset 12)

[Uses data_list_strings with filter "Error"]
I also found several error strings that suggest this binary handles network communications with error checking.

The main function appears to be the entry point for a network packet processing routine that allocates and processes data structures for network communication.
```

**User:**
```
What other binaries are in this project? Can you open one and compare its structure to this one?
```

**Assistant:**
```
Let me check what other files are in the current project.

[Uses project_info]
Current project: "MalwareAnalysis" at /home/user/ghidra_projects/MalwareAnalysis
Contains 15 files across 3 folders.

[Uses project_list_files with folder "/" and recursive True]
Found these binaries in the project:
- /malware_samples/sample1.exe (currently open)
- /malware_samples/sample2.exe
- /malware_samples/sample3.dll
- /clean_samples/notepad.exe

Let me open sample2.exe for comparison.

[Uses project_open_file with path "/malware_samples/sample2.exe"]
Opened sample2.exe in a new CodeBrowser window.

[Uses instances_discover]
Found new instance on port 8193 analyzing sample2.exe.

[Uses instances_use with port 8193]
Switched to the new instance.

[Uses functions_list on port 8193]
sample2.exe has a similar structure with 342 functions. Let me compare the main functions...
```

**User:**
```
Can you trace where process_packet is called from and show me the call graph?
```

**Assistant:**
```
I'll trace the call relationships for process_packet.

[Uses xrefs_list with to_addr for process_packet]
Found 3 callers of process_packet:
- main at 0x401000
- worker_thread at 0x401200
- handle_request at 0x401450

[Uses analysis_get_callgraph with name "process_packet", max_depth 3]
Here's the call graph starting from process_packet:

process_packet (0x401100)
├── validate_header (0x401150)
│   └── check_magic (0x401180)
├── parse_data (0x4011A0)
│   ├── extract_field (0x4011D0)
│   └── validate_checksum (0x4011E0)
└── send_response (0x401220)
    └── network_send (0x401250)

This shows process_packet coordinates validation, parsing, and response transmission.
```

# JSON Communication

GhydraMCP uses JSON for all communication between the bridge or CLI and the Java plugin.

## API Architecture

The REST API is HATEOAS-driven:

### Core API Design

- **HATEOAS Architecture**: Each response includes navigational links for resource discovery
- **Versioned Endpoints**: All requests verified against API version for compatibility
- **Structured Responses**: Standardized JSON format with consistent field naming
- **Proper HTTP Methods**: GET for retrieval, POST for creation, PATCH for updates, DELETE for removal
- **Appropriate Status Codes**: Uses standard HTTP status codes for clear error handling

### Response Format

All responses follow this HATEOAS-driven format:

```json
{
  "id": "req-123",
  "instance": "http://localhost:8192",
  "success": true,
  "result": "...",
  "timestamp": 1712159482123,
  "_links": {
    "self": {"href": "/endpoint/current"},
    "related": [
      {"href": "/endpoint/related1", "name": "Related Resource 1"},
      {"href": "/endpoint/related2", "name": "Related Resource 2"}
    ]
  }
}
```

For list responses, pagination information is included:

```json
{
  "id": "req-123",
  "instance": "http://localhost:8192",
  "success": true,
  "result": [ ... objects ... ],
  "size": 150,
  "offset": 0,
  "limit": 50,
  "_links": {
    "self": { "href": "/functions?offset=0&limit=50" },
    "next": { "href": "/functions?offset=50&limit=50" },
    "prev": { "href": "/functions?offset=0&limit=50" }
  }
}
```

Error responses include detailed information:

```json
{
  "id": "req-123",
  "instance": "http://localhost:8192",
  "success": false,
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "Function 'main' not found in current program"
  },
  "status_code": 404,
  "timestamp": 1712159482123,
  "_links": {
    "self": {"href": "/functions/main"}
  }
}
```

The links let a client discover related resources without hardcoding URLs.

# Testing

GhydraMCP has test suites for the HTTP API and the MCP bridge. See [TESTING.md](TESTING.md) for how to run them.

## HTTP API Tests

Tests the HTTP endpoints exposed by the Java plugin:
- Response format and structure
- JSON structure consistency
- Required fields in responses
- Error handling

## MCP Bridge Tests

Tests the MCP bridge functionality:
- MCP protocol communication
- Tool availability and structure
- Response format and structure
- JSON structure consistency

# Building from Source

You can build different artifacts with Maven. The build needs the Ghidra module
jars: either set `GHIDRA_HOME` to your Ghidra install (recommended), or place the
jars in `lib/`.

```
# Build against a specific Ghidra install (recommended). Works for 11.x or 12.x.
# -Dghidra.version stamps the extension's ghidraVersion (must match the install).
GHIDRA_HOME=/path/to/ghidra_12.1.2_PUBLIC mvn clean package -Dghidra.version=12.1.2
```

CI builds a matrix over the latest Ghidra 11.x and 12.x and attaches a per-version
plugin zip to each release.

## Build Everything (Default)
Build both the Ghidra plugin and the complete package:

```
mvn clean package
```

This creates:
- `target/Ghydra-[version].zip` - The Ghidra plugin only
- `target/Ghydra-Complete-[version].zip` - Complete package with plugin and bridge script

Install the plugin zip via Ghidra's `File` -> `Install Extensions` (first time);
for later updates you can swap `lib/Ghydra.jar` in the installed extension and
restart Ghidra.

## Build Ghidra Plugin Only
If you only need the Ghidra plugin:

```
mvn clean package -P plugin-only
```

## Build Complete Package Only
If you only need the combined package:

```
mvn clean package -P complete-only
```

The Ghidra plugin includes these files required for Ghidra to recognize the extension:
- lib/Ghydra.jar
- extension.properties
- Module.manifest
