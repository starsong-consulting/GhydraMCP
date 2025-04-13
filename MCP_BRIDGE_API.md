# GhydraMCP Bridge API Documentation

## Overview
This document describes the MCP tools and resources exposed by the GhydraMCP bridge that connects to Ghidra's HTTP API. The bridge provides a higher-level interface optimized for AI agent usage.

## Core Concepts
- Each Ghidra instance runs its own HTTP server (default port 8192)
- The bridge discovers and manages multiple Ghidra instances
- Programs are addressed by their unique identifier within Ghidra (`project:/path/to/file`).
- The primary identifier for a program is its Ghidra path, e.g., `myproject:/path/to/mybinary.exe`.
- The bridge must keep track of which plugin host and port has which project & file and route accordingly
- Tools are organized by resource type (programs, functions, data, etc.)
- Consistent response format with success/error indicators

## Instance Management Tools

### `list_instances`
List all active Ghidra instances with their ports and project info.

### `discover_instances`
Scan for available Ghidra instances by port range.

### `register_instance`
Manually register a Ghidra instance by port/URL.

## Program Analysis Tools

### `list_functions`
List functions in current program with pagination.

### `get_function`
Get details and decompilation for a function by name.

### `get_function_by_address` 
Get function details by memory address.

### `decompile_function_by_address`
Decompile function at specific address.

### `list_segments`
List memory segments/sections in program.

### `list_data_items`
List defined data items in program.

### `read_memory`
Read bytes from memory at address. Parameters:
- `address`: Hex address
- `length`: Bytes to read
- `format`: "hex", "base64" or "string" output format

### `write_memory`
Write bytes to memory at address (use with caution). Parameters:  
- `address`: Hex address
- `bytes`: Data to write  
- `format`: "hex", "base64" or "string" input format

### `list_variables`
List global variables with search/filter.

## Modification Tools

### `update_function`
Rename a function.

### `update_data` 
Rename data at memory address.

### `set_function_prototype`
Change a function's signature.

### `rename_local_variable`
Rename variable within function.

### `set_local_variable_type`
Change variable's data type.

## Response Format
All tools return responses in this format:
```json
{
  "id": "request-id",
  "instance": "http://host:port",
  "success": true/false,
  "result": {...}, // Tool-specific data
  "error": {       // Only on failure
    "code": "...",
    "message": "..."
  },
  "_links": {      // HATEOAS links
    "self": {"href": "/path"},
    "related": {"href": "/other"}
  }
}
```

## Example Usage

1. Discover available instances:
```python
discover_instances()
```

2. List functions in first instance:
```python 
list_functions(port=8192, limit=10)
```

3. Decompile main function:
```python
get_function(port=8192, name="main")
```

4. Rename a function:
```python
update_function(port=8192, name="FUN_1234", new_name="parse_data")
```

## Error Handling
- Check `success` field first
- On failure, `error` contains details
- Common error codes:
  - `INSTANCE_NOT_FOUND`
  - `RESOURCE_NOT_FOUND` 
  - `INVALID_PARAMETER`
  - `TRANSACTION_FAILED`

## Advanced Analysis Tools

### `list_xrefs`  
List cross-references between code/data. Parameters:
- `to_addr`: Filter refs to this address
- `from_addr`: Filter refs from this address  
- `type`: Filter by ref type ("CALL", "READ", etc)
- Basic pagination via `offset`/`limit`

### `analyze_program`
Run Ghidra analysis with optional settings:
- `analysis_options`: Dict of analysis passes to enable

### `get_callgraph`
Get function call graph visualization data:
- `function`: Starting function (defaults to entry point)
- `max_depth`: Maximum call depth (default: 3)

### `get_dataflow`  
Perform data flow analysis from address:
- `address`: Starting point in hex
- `direction`: "forward" or "backward"
- `max_steps`: Max analysis steps
