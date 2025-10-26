[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/teal-bauer/GhydraMCP)](https://github.com/teal-bauer/GhydraMCP/releases)
[![API Version](https://img.shields.io/badge/API-v2.0-orange)](https://github.com/teal-bauer/GhydraMCP/blob/main/GHIDRA_HTTP_API.md)
[![GitHub stars](https://img.shields.io/github/stars/teal-bauer/GhydraMCP)](https://github.com/teal-bauer/GhydraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/teal-bauer/GhydraMCP)](https://github.com/teal-bauer/GhydraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/teal-bauer/GhydraMCP)](https://github.com/teal-bauer/GhydraMCP/graphs/contributors)
[![Build Status](https://github.com/teal-bauer/GhydraMCP/actions/workflows/build.yml/badge.svg)](https://github.com/teal-bauer/GhydraMCP/actions/workflows/build.yml)

# GhydraMCP v2.0

GhydraMCP is a powerful bridge between [Ghidra](https://ghidra-sre.org/) and AI assistants that enables comprehensive AI-assisted reverse engineering through the [Model Context Protocol (MCP)](https://github.com/modelcontextprotocol/mcp).

![GhydraMCP logo](https://github.com/user-attachments/assets/86b9b2de-767c-4ed5-b082-510b8109f00f)

## Overview

GhydraMCP v2.0 integrates three key components:

1. **Modular Ghidra Plugin**: Exposes Ghidra's powerful reverse engineering capabilities through a HATEOAS-driven REST API
2. **MCP Bridge**: A Python script that translates MCP requests into API calls with comprehensive type checking
3. **Multi-instance Architecture**: Connect multiple Ghidra instances to analyze different binaries simultaneously

This architecture enables AI assistants like Claude to seamlessly:
- Decompile and analyze binary code with customizable output formats
- Map program structures, function relationships, and complex data types
- Perform advanced binary analysis (cross-references, call graphs, data flow, etc.)
- Make precise modifications to the analysis (rename, annotate, create/delete/modify data, etc.)
- Read memory directly and manipulate binary at a low level
- Navigate resources through discoverable HATEOAS links

GhydraMCP is based on [GhidraMCP by Laurie Wired](https://github.com/LaurieWired/GhidraMCP/) but has evolved into a comprehensive reverse engineering platform with enhanced multi-instance support, extensive data manipulation capabilities, and a robust HATEOAS-compliant API architecture.

# Features

GhydraMCP version 2.0 provides a comprehensive set of reverse engineering capabilities to AI assistants through its HATEOAS-driven API:

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

## Multi-instance Support

- Run multiple Ghidra instances simultaneously
- Analyze different binaries in parallel
- Connect to specific instances using port numbers
- Auto-discovery of running Ghidra instances
- Instance metadata with project and file information
- Plugin version and API checking for compatibility

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
4. Select the `GhydraMCP-2.0.0-beta.1.zip` (or your chosen version) from the downloaded release
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

## MCP Clients

Theoretically, any MCP client should work with GhydraMCP. Two examples are given below.

## API Reference (Updated for v2.0)

### Available Tools

**Program Analysis**:
- `list_functions`: List all functions (params: offset, limit)
- `list_classes`: List all classes/namespaces (params: offset, limit)  
- `decompile_function`: Get decompiled C code (params: name or address)
- `get_function`: Get function details (params: name or address)
- `get_callgraph`: Get function call graph (params: address)
- `list_segments`: View memory segments (params: offset, limit)
- `list_imports`: List imported symbols (params: offset, limit)
- `list_exports`: List exported functions (params: offset, limit)
- `list_namespaces`: Show namespaces (params: offset, limit)
- `list_data_items`: View data labels (params: offset, limit)
- `list_strings`: List all defined strings in binary (params: offset, limit, filter)
- `search_functions_by_name`: Find functions (params: query, offset, limit)

**Function Operations**:
- `rename_function`: Rename a function (params: name, new_name)
- `set_function_signature`: Update function prototype (params: address, signature)
- `set_comment`: Add comments (params: address, comment, comment_type)
- `remove_comment`: Remove comments (params: address, comment_type)

**Memory Operations**:
- `read_memory`: Read bytes from memory (params: address, length)
- `get_disassembly`: Get disassembled instructions (params: address, length)

**Data Manipulation**:
- `create_data`: Create new data at address (params: address, data_type)
- `delete_data`: Delete data at address (params: address)
- `set_data_type`: Change data type at address (params: address, data_type)
- `rename_data`: Rename data at address (params: address, name)
- `update_data`: Update both name and type (params: address, name, data_type)

**Instance Management**:
- `list_instances`: List active Ghidra instances (no params)
- `register_instance`: Register new instance (params: port, url)
- `unregister_instance`: Remove instance (params: port)
- `discover_instances`: Auto-discover running instances (params: host [optional])

**Example Usage**:
```python
# Program analysis
client.use_tool("ghydra", "decompile_function", {"name": "main"})
client.use_tool("ghydra", "get_function", {"address": "0x00401000"})
client.use_tool("ghydra", "get_callgraph", {"address": "0x00401000"})

# Memory and disassembly operations
client.use_tool("ghydra", "read_memory", {"address": "0x00401000", "length": 16})
client.use_tool("ghydra", "get_disassembly", {"address": "0x00401000", "length": 32})

# String analysis
client.use_tool("ghydra", "list_strings")  # List all strings in the binary
client.use_tool("ghydra", "list_strings", {"limit": 100, "offset": 0})  # Pagination
client.use_tool("ghydra", "list_strings", {"filter": "password"})  # Search for strings containing "password"

# Function operations
client.use_tool("ghydra", "set_function_signature", {"address": "0x00401000", "signature": "int main(int argc, char **argv)"})
client.use_tool("ghydra", "set_comment", {"address": "0x00401100", "comment": "This instruction initializes the counter", "comment_type": "plate"})

# Data manipulation
client.use_tool("ghydra", "create_data", {"address": "0x00401234", "data_type": "int"})
client.use_tool("ghydra", "set_data_type", {"address": "0x00401238", "data_type": "char *"})
client.use_tool("ghydra", "rename_data", {"address": "0x00401234", "name": "my_variable"})
client.use_tool("ghydra", "update_data", {"address": "0x00401238", "name": "ptr_var", "data_type": "char *"})
client.use_tool("ghydra", "delete_data", {"address": "0x0040123C"})

# Instance management  
client.use_tool("ghydra", "register_instance", {"port": 8192, "url": "http://localhost:8192/"})
client.use_tool("ghydra", "register_instance", {"port": 8193})

# Auto-discover instances
client.use_tool("ghydra", "discover_instances")  # Default host
client.use_tool("ghydra", "discover_instances", {"host": "192.168.1.10"})  # Custom host
```

## Client Setup

### Claude Desktop Configuration
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
        "GHIDRA_HYDRA_HOST": "localhost"  // Optional - defaults to localhost
      }
    }
  }
}
```

> **Note:** You can also use `python` instead of `uv run`, but then you'll need to manually install the requirements first with `pip install mcp requests`.

### 5ire Configuration
1. Tool Key: ghydra  
2. Name: GhydraMCP
3. Command: `uv run /ABSOLUTE_PATH_TO/bridge_mcp_hydra.py`

## Example Session

Below is an example of how an AI assistant might interact with multiple Ghidra instances using GhydraMCP:

**User:**
```
Check which Ghidra instances are currently running.
```

**Assistant:**
```
I'll check which Ghidra instances are currently running by discovering any active instances.

View result from discover_instances from ghydra (local)
{
  "found": 2,
  "instances": [
    {
      "port": 8192,
      "url": "http://localhost:8192",
      "result": "Registered instance on port 8192 at http://localhost:8192"
    },
    {
      "port": 8193,
      "url": "http://localhost:8193",
      "result": "Registered instance on port 8193 at http://localhost:8193"
    }
  ]
}

View result from list_instances from ghydra (local)
{
  "instances": [
    {
      "port": 8192,
      "url": "http://localhost:8192",
      "project": "TestProject",
      "file": "application.exe"
    },
    {
      "port": 8193,
      "url": "http://localhost:8193",
      "project": "FirmwareAnalysis",
      "file": "firmware.bin"
    }
  ]
}

I found two active Ghidra instances:
1. Port 8192: Analyzing "application.exe" in project "TestProject"
2. Port 8193: Analyzing "firmware.bin" in project "FirmwareAnalysis"

I'm ready to analyze these binaries. What would you like me to examine?
```

**User:**
```
List the functions through ghydra for both instances and identify any related functionality.
```

**Assistant:**
```
I'll list the functions from both instances and analyze them.

View result from list_functions from ghydra (local){
  `port`: 8192
}
[Function list for application.exe...]

View result from list_functions from ghydra (local){
  `port`: 8193
}
[Function list for firmware.bin...]

I notice some interesting functions in both binaries. Let me decompile a few to understand their behavior.

View result from get_function from ghydra (local){
  `port`: 8192,
  `name`: "process_command"
}
[Decompiled code for process_command...]

View result from get_function from ghydra (local){
  `port`: 8193,
  `name`: "handle_message"
}
[Decompiled code for handle_message...]

Based on this analysis, I can see these binaries communicate using a simple protocol where...
```

# JSON Communication

GhydraMCP uses structured JSON for all communication between the Python bridge and Java plugin. This ensures consistent and reliable data exchange.

## API Architecture

GhydraMCP v2.0 implements a comprehensive HATEOAS-driven REST API that follows hypermedia design principles:

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

## Build Configuration

GhydraMCP can be built using default jars of GhydraMCP (version 11.3.2) or the version of your ghidra install (by setting GHYDRA_HOME).

### Using your ghidra install GHIDRA_HOME

If you have Ghidra installed on your system, you can build directly against your installation by setting the `GHIDRA_HOME` environment variable. This ensures you're always building against the correct Ghidra version you're running.

```bash
# Set GHIDRA_HOME to your Ghidra installation directory
export GHIDRA_HOME=/PATH/TO/ghidra
```

## Build Targets

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
