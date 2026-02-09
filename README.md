[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/starsong-consulting/GhydraMCP)](https://github.com/starsong-consulting/GhydraMCP/releases)
[![API Version](https://img.shields.io/badge/API-v2020-orange)](https://github.com/starsong-consulting/GhydraMCP/blob/main/GHIDRA_HTTP_API.md)
[![GitHub stars](https://img.shields.io/github/stars/starsong-consulting/GhydraMCP)](https://github.com/starsong-consulting/GhydraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/starsong-consulting/GhydraMCP)](https://github.com/starsong-consulting/GhydraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/starsong-consulting/GhydraMCP)](https://github.com/starsong-consulting/GhydraMCP/graphs/contributors)
[![Build Status](https://github.com/starsong-consulting/GhydraMCP/actions/workflows/build.yml/badge.svg)](https://github.com/starsong-consulting/GhydraMCP/actions/workflows/build.yml)

# GhydraMCP v2.2.0

GhydraMCP is a powerful bridge between [Ghidra](https://ghidra-sre.org/) and AI assistants that enables comprehensive AI-assisted reverse engineering through the [Model Context Protocol (MCP)](https://github.com/modelcontextprotocol/mcp).

![GhydraMCP logo](https://github.com/user-attachments/assets/86b9b2de-767c-4ed5-b082-510b8109f00f)

## Overview

GhydraMCP v2.2.0 integrates four key components:

1. **Modular Ghidra Plugin**: Exposes Ghidra's powerful reverse engineering capabilities through a HATEOAS-driven REST API
2. **MCP Bridge**: A Python script that translates MCP requests into API calls with comprehensive type checking
3. **CLI Tool (`ghydra`)**: A standalone command-line interface for direct interaction with Ghidra — human-readable tables, syntax highlighting, and `--json` mode for scripting
4. **Multi-instance Architecture**: Connect multiple Ghidra instances to analyze different binaries simultaneously

This architecture enables AI assistants like Claude to seamlessly:
- Decompile and analyze binary code with customizable output formats
- Map program structures, function relationships, and complex data types
- Perform advanced binary analysis (cross-references, call graphs, data flow, etc.)
- Make precise modifications to the analysis (rename, annotate, create/delete/modify data, etc.)
- Read memory directly and manipulate binary at a low level
- Navigate resources through discoverable HATEOAS links

GhydraMCP is based on [GhidraMCP by Laurie Wired](https://github.com/LaurieWired/GhidraMCP/) but has evolved into a comprehensive reverse engineering platform with enhanced multi-instance support, extensive data manipulation capabilities, and a robust HATEOAS-compliant API architecture.

# Features

GhydraMCP version 2.2.0 provides a comprehensive set of reverse engineering capabilities to AI assistants through its HATEOAS-driven API:

## Advanced Program Analysis

- **Enhanced Decompilation**:
  - Convert binary functions to readable C code 
  - Toggle between clean C-like pseudocode and raw decompiler output
  - Show/hide syntax trees for detailed analysis
  - Multiple simplification styles for different analysis approaches
  
- **Comprehensive Static Analysis**: 
  - Cross-reference analysis (find callers and callees)
  - Complete call graph generation and traversal
  - Data flow analysis with variable tracking
  - Type propagation and reconstruction
  - Function relationship mapping
  
- **Memory Operations**:
  - Direct memory reading with hex and raw byte representation
  - Address space navigation and mapping
  - Memory segment analysis

- **Symbol Management**:
  - View and analyze imports and exports
  - Identify library functions and dependencies
  - Symbol table exploration and manipulation
  - Namespace hierarchy visualization

## Interactive Reverse Engineering

- **Code Understanding**:
  - Explore function code with rich context
  - Analyze data structures and complex types
  - View disassembly with linking to decompiled code
  - Examine function prototypes and signatures
  
- **Comprehensive Annotation**:
  - Rename functions, variables, and data 
  - Add multiple comment types (EOL, plate, pre/post)
  - Create and modify data types
  - Set and update function signatures and prototypes

## Complete Data Manipulation

- **Data Creation and Management**:
  - Create new data items with specified types
  - Delete existing data items
  - Rename data items with proper scope handling
  - Set and update data types for existing items
  - Combined rename and retype operations
  - Type definition management

- **Function Manipulation**:
  - Rename functions with proper scoping
  - Update function signatures with parameter information
  - Modify local variable names and types
  - Set function return types

## Multi-instance and Project Management

- **Multi-instance Support**:
  - Run multiple Ghidra instances simultaneously on ports 8192-8447 (256 port range)
  - Analyze different binaries in parallel
  - Connect to specific instances using port numbers
  - Auto-discovery of running Ghidra instances
  - Instance metadata with project and file information
  - Plugin version and API checking for compatibility

- **Project Management**:
  - Get current project information (name, location, file counts)
  - List all files in a project with filtering
  - Open project files in new CodeBrowser windows
  - Navigate project folder hierarchy
  - Automatic instance registration when opening new programs

## Program Navigation and Discovery

- List and search functions, classes, and namespaces
- View memory segments and layout
- Search by name, pattern, or signature
- Resource discovery through HATEOAS links
- Pagination for handling large result sets
- Filtering capabilities across all resources

# Installation

## Prerequisites
- Install [Ghidra](https://ghidra-sre.org)
- Python3
- MCP [SDK](https://github.com/modelcontextprotocol/python-sdk)

## Ghidra
First, download the latest [release](https://github.com/teal-bauer/GhydraMCP/releases) from this repository. The "Complete" artifact contains the zipped Ghidra plugin and the Python MCP bridge. Unpack the outer archive, then, add the plugin to Ghidra:

1. Run Ghidra
2. Select `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `GhydraMCP-[version].zip` file from the downloaded release
5. Restart Ghidra
6. Make sure the GhydraMCPPlugin is enabled in `File` -> `Configure` -> `Developer`

> **Note:** By default, the first CodeBrowser opened in Ghidra gets port 8192, the second gets 8193, and so on. You can check which ports are being used by looking at the Console in the Ghidra main (project) window - click the computer icon in the bottom right to "Open Console". Look for log entries like:
> ```
> (HydraMCPPlugin) Plugin loaded on port 8193
> (HydraMCPPlugin) HydraMCP HTTP server started on port 8193
> ```
>
> GhydraMCP now includes auto-discovery of running Ghidra instances, so manually registering each instance is typically not necessary. The MCP bridge will automatically discover and register instances on startup and periodically check for new ones.

Video Installation Guide:

https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3

## CLI Tool

GhydraMCP includes `ghydra`, a command-line tool for interacting with Ghidra directly from the terminal. It works standalone — no MCP client needed.

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

## MCP Clients

GhydraMCP works with any MCP-compatible client using **stdio transport**. It has been tested and confirmed working with:

- **Claude Desktop** - Anthropic's official desktop application
- **Claude Code** - Anthropic's VS Code extension and CLI tool
- **Cline** - Popular VS Code extension for AI-assisted coding

See the [Client Setup](#client-setup) section below for detailed configuration instructions for each client.

## API Reference (Updated for v2.2.0)

### Available Tools

GhydraMCP v2.2.0 organizes tools into logical namespaces for better discoverability and organization:

**Instance Management** (`instances_*`):
- `instances_list`: List active Ghidra instances (auto-discovers on default host) - **use this first**
- `instances_discover`: Discover instances on a specific host (params: host [optional]) - **only use for non-default hosts**
- `instances_register`: Register new instance (params: port, url [optional])
- `instances_unregister`: Remove instance (params: port)
- `instances_use`: Set current working instance (params: port)
- `instances_current`: Get current working instance info

**Function Analysis** (`functions_*`):
- `functions_list`: List all functions (params: offset, limit, port [optional])
- `functions_get`: Get function details (params: name or address, port [optional])
- `functions_decompile`: Get decompiled C code (params: name or address, syntax_tree, style, timeout, port [optional])
- `functions_disassemble`: Get disassembled instructions (params: name or address, port [optional])
- `functions_create`: Create function at address (params: address, port [optional])
- `functions_rename`: Rename a function (params: old_name or address, new_name, port [optional])
- `functions_set_signature`: Update function prototype (params: name or address, signature, port [optional])
- `functions_get_variables`: Get function variables (params: name or address, port [optional])
- `functions_set_comment`: Set function comment (params: address, comment, port [optional])

**Data Manipulation** (`data_*`):
- `data_list`: List data items (params: offset, limit, addr, name, name_contains, port [optional])
- `data_list_strings`: List all defined strings (params: offset, limit, filter, port [optional])
- `data_create`: Create data at address (params: address, data_type, size [optional], port [optional])
- `data_rename`: Rename data item (params: address, name, port [optional])
- `data_delete`: Delete data item (params: address, port [optional])
- `data_set_type`: Change data type (params: address, data_type, port [optional])

**Struct Management** (`structs_*`):
- `structs_list`: List all struct data types (params: offset, limit, category [optional], port [optional])
- `structs_get`: Get detailed struct information (params: name, port [optional])
- `structs_create`: Create new struct (params: name, category [optional], description [optional], port [optional])
- `structs_add_field`: Add field to struct (params: struct_name, field_name, field_type, offset [optional], comment [optional], port [optional])
- `structs_update_field`: Update struct field (params: struct_name, field_name or field_offset, new_name [optional], new_type [optional], new_comment [optional], port [optional])
- `structs_delete`: Delete struct (params: name, port [optional])

**Memory Operations** (`memory_*`):
- `memory_read`: Read bytes from memory (params: address, length, format, port [optional])
- `memory_write`: Write bytes to memory (params: address, bytes_data, format, port [optional])

**Cross-References** (`xrefs_*`):
- `xrefs_list`: List cross-references (params: to_addr [optional], from_addr [optional], type [optional], offset, limit, port [optional])

**Analysis** (`analysis_*`):
- `analysis_run`: Trigger program analysis (params: background, port [optional])
- `analysis_status`: Check analysis status (params: port [optional])
- `analysis_get_callgraph`: Get function call graph (params: name or address, max_depth, port [optional])
- `analysis_get_dataflow`: Perform data flow analysis (params: address, direction, max_steps, port [optional])

**Project Management** (`project_*`):
- `project_info`: Get current project information (params: port [optional])
- `project_list_files`: List files in project (params: folder, recursive, offset, limit, port [optional])
- `project_open_file`: Open project file in CodeBrowser (params: path, port [optional])

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
client.use_tool("ghydra", "data_set_type", {"address": "0x00401238", "data_type": "char *"})
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
client.use_tool("ghydra", "memory_read", {"address": "0x00401000", "length": 16, "format": "hex"})
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

Below is an example of how an AI assistant might interact with Ghidra using GhydraMCP v2.2.0:

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

GhydraMCP uses structured JSON for all communication between the Python bridge and Java plugin. This ensures consistent and reliable data exchange.

## API Architecture

GhydraMCP v2.2.0 implements a comprehensive HATEOAS-driven REST API that follows hypermedia design principles:

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

This HATEOAS approach enables resource discovery and self-documenting APIs, making integration and exploration significantly easier.

# Testing

GhydraMCP includes comprehensive test suites for both the HTTP API and MCP bridge. See [TESTING.md](TESTING.md) for details on running the tests.

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

You can build different artifacts with Maven:

## Build Everything (Default)
Build both the Ghidra plugin and the complete package:

```
mvn clean package
```

This creates:
- `target/GhydraMCP-[version].zip` - The Ghidra plugin only
- `target/GhydraMCP-Complete-[version].zip` - Complete package with plugin and bridge script

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
- lib/GhydraMCP.jar
- extension.properties
- Module.manifest
