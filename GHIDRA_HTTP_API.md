# GhydraMCP Ghidra Plugin HTTP API v2

## Overview

This API provides a Hypermedia-driven interface (HATEOAS) to interact with Ghidra's CodeBrowser, enabling AI-driven and automated reverse engineering workflows. It allows interaction with Ghidra projects, programs (binaries), functions, symbols, data, memory segments, cross-references, and analysis features. Each program open in Ghidra will have its own plugin instance, so all resources are specific to that program.

## General Concepts

### Request Format

- Use standard HTTP verbs:
  - `GET`: Retrieve resources or lists.
  - `POST`: Create new resources.
  - `PATCH`: Modify existing resources partially.
  - `PUT`: Replace existing resources entirely (Use with caution, `PATCH` is often preferred).
  - `DELETE`: Remove resources.
- Request bodies for `POST`, `PUT`, `PATCH` should be JSON (`Content-Type: application/json`).
- Include an optional `X-Request-ID` header with a unique identifier for correlation.

### Response Format

All non-error responses are JSON (`Content-Type: application/json`) containing at least the following keys:

```json
{
  "id": "[correlation identifier]",
  "instance": "[instance url]",
  "success": true,
  "result": Object | Array<Object>,
  "_links": { // Optional: HATEOAS links
    "self": { "href": "/path/to/current/resource" },
    "related_resource": { "href": "/path/to/related" }
    // ... other relevant links
  }
}
```

- `id`: The identifier from the `X-Request-ID` header if provided, or a random opaque identifier otherwise.
- `instance`: The URL of the Ghidra plugin instance that handled the request.
- `success`: Boolean `true` for successful operations.
- `result`: The main data payload, either a single JSON object or an array of objects for lists.
- `_links`: (Optional) Contains HATEOAS-style links to related resources or actions, facilitating discovery.

#### List Responses

List results (arrays in `result`) will typically include pagination information and a total count:

```json
{
  "id": "req-123",
  "instance": "http://localhost:8192",
  "success": true,
  "result": [ ... objects ... ],
  "size": 150, // Total number of items matching the query across all pages
  "offset": 0,
  "limit": 50,
  "_links": {
    "self": { "href": "/functions?offset=0&limit=50" },
    "next": { "href": "/functions?offset=50&limit=50" }, // Present if more items exist
    "prev": { "href": "/functions?offset=0&limit=50" }  // Present if not the first page
  }
}
```

### Error Responses

Errors use appropriate HTTP status codes (4xx, 5xx) and have a JSON payload with an `error` key:

```json
{
  "id": "[correlation identifier]",
  "instance": "[instance url]",
  "success": false,
  "error": {
    "code": "RESOURCE_NOT_FOUND", // Optional: Machine-readable code
    "message": "Descriptive error message"
    // Potentially other details like invalid parameters
  }
}
```

Common HTTP Status Codes:
- `200 OK`: Successful `GET`, `PATCH`, `PUT`, `DELETE`.
- `201 Created`: Successful `POST` resulting in resource creation.
- `204 No Content`: Successful `DELETE` or `PATCH`/`PUT` where no body is returned.
- `400 Bad Request`: Invalid syntax, missing required parameters, invalid data format.
- `401 Unauthorized`: Authentication required or failed (if implemented).
- `403 Forbidden`: Authenticated user lacks permission (if implemented).
- `404 Not Found`: Resource or endpoint does not exist, or query yielded no results.
- `405 Method Not Allowed`: HTTP verb not supported for this endpoint.
- `500 Internal Server Error`: Unexpected error within the Ghidra plugin.

### Addressing and Searching

Resources like functions, data, and symbols often exist at specific memory addresses and may have names.

- **By Address:** Use the resource's path with the address (hexadecimal, e.g., `0x401000` or `08000004`).
  - Example: `GET /functions/0x401000`
- **Querying Lists:** List endpoints (e.g., `/functions`, `/symbols`, `/data`) support filtering via query parameters:
  - `?addr=[address in hex]`: Find item at a specific address.
  - `?name=[full_name]`: Find item(s) with an exact name match (case-sensitive).
  - `?name_contains=[substring]`: Find item(s) whose name contains the substring (case-insensitive).
  - `?name_matches_regex=[regex]`: Find item(s) whose name matches the Java-compatible regular expression.

### Pagination

List endpoints support pagination using query parameters:
- `?offset=[int]`: Number of items to skip (default: 0).
- `?limit=[int]`: Maximum number of items to return (default: implementation-defined, e.g., 100).

## Meta Endpoints

### `GET /plugin-version`
Returns the version of the running Ghidra plugin and its API. Essential for compatibility checks by clients like the MCP bridge.
```json
{
  "id": "req-meta-ver",
  "instance": "http://localhost:8192",
  "success": true,
  "result": {
    "plugin_version": "v2.0.0", // Example plugin build version
    "api_version": 2            // Ordinal API version
  },
  "_links": {
    "self": { "href": "/plugin-version" },
    "root": { "href": "/" }
  }
}
```

### `GET /info`
Returns information about the current plugin instance, including details about the loaded program and project.
```json
{
  "id": "req-info",
  "instance": "http://localhost:8192",
  "success": true,
  "result": {
    "isBaseInstance": true,
    "file": "example.exe",
    "architecture": "x86:LE:64:default",
    "processor": "x86",
    "addressSize": 64,
    "creationDate": "2023-01-01T12:00:00Z",
    "executable": "/path/to/example.exe",
    "project": "MyProject",
    "projectLocation": "/path/to/MyProject",
    "serverPort": 8192,
    "serverStartTime": 1672531200000,
    "instanceCount": 1
  },
  "_links": {
    "self": { "href": "/info" },
    "root": { "href": "/" },
    "instances": { "href": "/instances" },
    "program": { "href": "/program" }
  }
}
```

### `GET /instances`
Returns information about all active GhydraMCP plugin instances.
```json
{
  "id": "req-instances",
  "instance": "http://localhost:8192",
  "success": true,
  "result": [
    {
      "port": 8192,
      "url": "http://localhost:8192",
      "type": "base",
      "project": "MyProject",
      "file": "example.exe",
      "_links": {
        "self": { "href": "/instances/8192" },
        "info": { "href": "http://localhost:8192/info" },
        "connect": { "href": "http://localhost:8192" }
      }
    },
    {
      "port": 8193,
      "url": "http://localhost:8193",
      "type": "standard",
      "project": "MyProject",
      "file": "library.dll",
      "_links": {
        "self": { "href": "/instances/8193" },
        "info": { "href": "http://localhost:8193/info" },
        "connect": { "href": "http://localhost:8193" }
      }
    }
  ],
  "_links": {
    "self": { "href": "/instances" },
    "register": { "href": "/registerInstance", "method": "POST" },
    "unregister": { "href": "/unregisterInstance", "method": "POST" },
    "programs": { "href": "/programs" }
  }
}
```

## Resource Types

Each Ghidra plugin instance runs in the context of a single program, so all resources are relative to the current program. The program's details are available through the `GET /info` and `GET /program` endpoints.

### 1. Project

Represents the current Ghidra project, which is a container for programs.

- **`GET /project`**: Get details about the current project (e.g., location, list of open programs within it via links).

### 2. Program

Represents the current binary loaded in Ghidra.

- **`GET /program`**: Get metadata for the current program (e.g., name, architecture, memory layout, analysis status).
  ```json
  // Example Response Fragment for GET /program
  "result": {
    "programId": "myproject:/path/to/mybinary.exe",
    "name": "mybinary.exe",
    "isOpen": true,
    "languageId": "x86:LE:64:default",
    "compilerSpecId": "gcc",
    "imageBase": "0x400000",
    "memorySize": 1048576,
    "analysisComplete": true
  },
  "_links": {
    "self": { "href": "/program" },
    "project": { "href": "/project" },
    "functions": { "href": "/functions" },
    "symbols": { "href": "/symbols" },
    "data": { "href": "/data" },
    "segments": { "href": "/segments" },
    "memory": { "href": "/memory" },
    "xrefs": { "href": "/xrefs" },
    "analysis": { "href": "/analysis" }
  }
  ```

### 3. Current Location

Provides information about the current cursor position and function in Ghidra's CodeBrowser.

- **`GET /address`**: Get the current cursor position.
  ```json
  // Example Response
  "result": {
    "address": "0x401000",
    "program": "mybinary.exe"
  },
  "_links": {
    "self": { "href": "/address" },
    "program": { "href": "/program" },
    "memory": { "href": "/memory/0x401000?length=16" },
    "function": { "href": "/functions/0x401000" },
    "decompile": { "href": "/functions/0x401000/decompile" }
  }
  ```

- **`GET /function`**: Get information about the function at the current cursor position.
  ```json
  // Example Response
  "result": {
    "name": "main",
    "address": "0x401000",
    "signature": "int main(int argc, char** argv)",
    "size": 256
  },
  "_links": {
    "self": { "href": "/function" },
    "program": { "href": "/program" },
    "function": { "href": "/functions/0x401000" },
    "decompile": { "href": "/functions/0x401000/decompile" },
    "disassembly": { "href": "/functions/0x401000/disassembly" },
    "variables": { "href": "/functions/0x401000/variables" },
    "xrefs": { "href": "/xrefs?to_addr=0x401000" }
  }
  ```

### 4. Functions

Represents functions within the current program.

- **`GET /functions`**: List functions. Supports searching (by name/address/regex) and pagination.
  ```json
  // Example Response Fragment
  "result": [
    { "name": "FUN_08000004", "address": "08000004", "_links": { "self": { "href": "/functions/08000004" } } },
    { "name": "init_peripherals", "address": "08001cf0", "_links": { "self": { "href": "/functions/08001cf0" } } }
  ]
  ```
- **`POST /functions`**: Create a function at a specific address. Requires `address` in the request body. Returns the created function resource.
- **`GET /functions/{address}`**: Get details for a specific function (name, signature, size, stack info, etc.).
  ```json
  // Example Response Fragment for GET /functions/0x4010a0
  "result": {
    "name": "process_data",
    "address": "0x4010a0",
    "signature": "int process_data(char * data, int size)",
    "size": 128,
    "stack_depth": 16,
    "has_varargs": false,
    "calling_convention": "__stdcall"
    // ... other details
  },
  "_links": {
    "self": { "href": "/functions/0x4010a0" },
    "decompile": { "href": "/functions/0x4010a0/decompile" },
    "disassembly": { "href": "/functions/0x4010a0/disassembly" },
    "variables": { "href": "/functions/0x4010a0/variables" },
    "xrefs_to": { "href": "/xrefs?to_addr=0x4010a0" },
    "xrefs_from": { "href": "/xrefs?from_addr=0x4010a0" }
  }
  ```
- **`PATCH /functions/{address}`**: Modify a function. Addressable only by address. Payload can contain:
  - `name`: New function name.
  - `signature`: Full function signature string (e.g., `void my_func(int p1, char * p2)`).
  - `comment`: Set/update the function's primary comment.
  ```json
  // Example PATCH payload
  { "name": "calculate_checksum", "signature": "uint32_t calculate_checksum(uint8_t* buffer, size_t length)" }
  ```
- **`DELETE /functions/{address}`**: Delete the function definition at the specified address.

#### Function Sub-Resources

- **`GET /functions/{address}/decompile`**: Get decompiled C-like code for the function.
  - Query Parameters:
    - `?syntax_tree=true`: Include the decompiler's internal syntax tree (JSON).
    - `?style=[style_name]`: Apply a specific decompiler simplification style (e.g., `normalize`, `paramid`).
    - `?timeout=[seconds]`: Set a timeout for the decompilation process.
  ```json
  // Example Response Fragment (without syntax tree)
  "result": {
    "address": "0x4010a0",
    "ccode": "int process_data(char *param_1, int param_2)\n{\n  // ... function body ...\n  return result;\n}\n"
  }
  ```
- **`GET /functions/{address}/disassembly`**: Get assembly listing for the function. Supports pagination (`?offset=`, `?limit=`).
  ```json
  // Example Response Fragment
  "result": [
    { "address": "0x4010a0", "mnemonic": "PUSH", "operands": "RBP", "bytes": "55" },
    { "address": "0x4010a1", "mnemonic": "MOV", "operands": "RBP, RSP", "bytes": "4889E5" },
    // ... more instructions
  ]
  ```
- **`GET /functions/{address}/variables`**: List local variables defined within the function. Supports searching by name.
- **`PATCH /functions/{address}/variables/{variable_name}`**: Modify a local variable (rename, change type). Requires `name` and/or `type` in the payload.

### 5. Symbols & Labels

Represents named locations (functions, data, labels).

- **`GET /symbols`**: List all symbols in the program. Supports searching (by name/address/regex) and pagination. Can filter by type (`?type=function`, `?type=data`, `?type=label`).
- **`POST /symbols`**: Create or rename a symbol at a specific address. Requires `address` and `name` in the payload. If a symbol exists, it's renamed; otherwise, a new label is created.
- **`GET /symbols/{address}`**: Get details of the symbol at the specified address.
- **`PATCH /symbols/{address}`**: Modify properties of the symbol (e.g., set as primary, change namespace). Payload specifies changes.
- **`DELETE /symbols/{address}`**: Remove the symbol at the specified address.

### 6. Data

Represents defined data items in memory.

- **`GET /data`**: List defined data items. Supports searching (by name/address/regex) and pagination. Can filter by type (`?type=string`, `?type=dword`, etc.).
- **`POST /data`**: Define a new data item. Requires `address`, `type`, and optionally `size` or `length` in the payload.
- **`GET /data/{address}`**: Get details of the data item at the specified address (type, size, value representation).
- **`PATCH /data/{address}`**: Modify a data item (e.g., change `name`, `type`, `comment`). Payload specifies changes.
- **`DELETE /data/{address}`**: Undefine the data item at the specified address.

### 6.1 Strings

Provides access to string data in the binary.

- **`GET /strings`**: List all defined strings in the binary. Supports pagination and filtering.
  - Query Parameters:
    - `?offset=[int]`: Number of strings to skip (default: 0).
    - `?limit=[int]`: Maximum number of strings to return (default: 2000).
    - `?filter=[string]`: Only include strings containing this substring (case-insensitive).
  ```json
  // Example Response
  "result": [
    {
      "address": "0x00401234",
      "value": "Hello, world!",
      "length": 14,
      "type": "string",
      "name": "aHelloWorld"
    },
    {
      "address": "0x00401250",
      "value": "Error: could not open file",
      "length": 26,
      "type": "string",
      "name": "aErrorCouldNotO"
    }
  ],
  "_links": {
    "self": { "href": "/strings?offset=0&limit=10" },
    "next": { "href": "/strings?offset=10&limit=10" }
  }
  ```

### 6.2 Structs

Provides functionality for creating and managing struct (composite) data types.

- **`GET /structs`**: List all struct data types in the program. Supports pagination and filtering.
  - Query Parameters:
    - `?offset=[int]`: Number of structs to skip (default: 0).
    - `?limit=[int]`: Maximum number of structs to return (default: 100).
    - `?category=[string]`: Filter by category path (e.g. "/winapi").
  ```json
  // Example Response
  "result": [
    {
      "name": "MyStruct",
      "path": "/custom/MyStruct",
      "size": 16,
      "numFields": 4,
      "category": "/custom",
      "description": "Custom data structure"
    },
    {
      "name": "FileHeader",
      "path": "/FileHeader",
      "size": 32,
      "numFields": 8,
      "category": "/",
      "description": ""
    }
  ],
  "_links": {
    "self": { "href": "/structs?offset=0&limit=100" },
    "program": { "href": "/program" }
  }
  ```

- **`GET /structs?name={struct_name}`**: Get detailed information about a specific struct including all fields.
  ```json
  // Example Response for GET /structs?name=MyStruct
  "result": {
    "name": "MyStruct",
    "path": "/custom/MyStruct",
    "size": 16,
    "category": "/custom",
    "description": "Custom data structure",
    "numFields": 4,
    "fields": [
      {
        "name": "id",
        "offset": 0,
        "length": 4,
        "type": "int",
        "typePath": "/int",
        "comment": "Unique identifier"
      },
      {
        "name": "flags",
        "offset": 4,
        "length": 4,
        "type": "dword",
        "typePath": "/dword",
        "comment": ""
      },
      {
        "name": "data_ptr",
        "offset": 8,
        "length": 4,
        "type": "pointer",
        "typePath": "/pointer",
        "comment": "Pointer to data"
      },
      {
        "name": "size",
        "offset": 12,
        "length": 4,
        "type": "uint",
        "typePath": "/uint",
        "comment": ""
      }
    ]
  },
  "_links": {
    "self": { "href": "/structs?name=MyStruct" },
    "structs": { "href": "/structs" },
    "program": { "href": "/program" }
  }
  ```

- **`POST /structs/create`**: Create a new struct data type.
  - Request Payload:
    - `name`: Name for the new struct (required).
    - `category`: Category path (optional, defaults to root).
    - `description`: Description for the struct (optional).
  ```json
  // Example Request Payload
  {
    "name": "NetworkPacket",
    "category": "/network",
    "description": "Network packet structure"
  }

  // Example Response
  "result": {
    "name": "NetworkPacket",
    "path": "/network/NetworkPacket",
    "category": "/network",
    "size": 0,
    "message": "Struct created successfully"
  }
  ```

- **`POST /structs/addfield`**: Add a field to an existing struct.
  - Request Payload:
    - `struct`: Name of the struct to modify (required).
    - `fieldName`: Name for the new field (required).
    - `fieldType`: Data type for the field (required, e.g. "int", "char", "pointer").
    - `offset`: Specific offset to insert field (optional, appends to end if not specified).
    - `comment`: Comment for the field (optional).
  ```json
  // Example Request Payload
  {
    "struct": "NetworkPacket",
    "fieldName": "header",
    "fieldType": "dword",
    "comment": "Packet header"
  }

  // Example Response
  "result": {
    "struct": "NetworkPacket",
    "fieldName": "header",
    "fieldType": "dword",
    "offset": 0,
    "length": 4,
    "structSize": 4,
    "message": "Field added successfully"
  }
  ```

- **`POST /structs/updatefield`**: Update an existing field in a struct (rename, change type, or modify comment).
  - Request Payload:
    - `struct`: Name of the struct to modify (required).
    - `fieldOffset` OR `fieldName`: Identify the field to update (one required).
    - `newName`: New name for the field (optional).
    - `newType`: New data type for the field (optional).
    - `newComment`: New comment for the field (optional).
    - At least one of `newName`, `newType`, or `newComment` must be provided.
  ```json
  // Example Request Payload - rename a field
  {
    "struct": "NetworkPacket",
    "fieldName": "header",
    "newName": "packet_header",
    "newComment": "Updated packet header field"
  }

  // Example Request Payload - change type by offset
  {
    "struct": "NetworkPacket",
    "fieldOffset": 0,
    "newType": "qword"
  }

  // Example Response
  "result": {
    "struct": "NetworkPacket",
    "offset": 0,
    "originalName": "header",
    "originalType": "dword",
    "originalComment": "Packet header",
    "newName": "packet_header",
    "newType": "dword",
    "newComment": "Updated packet header field",
    "length": 4,
    "message": "Field updated successfully"
  }
  ```

- **`POST /structs/delete`**: Delete a struct data type.
  - Request Payload:
    - `name`: Name of the struct to delete (required).
  ```json
  // Example Request Payload
  {
    "name": "NetworkPacket"
  }

  // Example Response
  "result": {
    "name": "NetworkPacket",
    "path": "/network/NetworkPacket",
    "category": "/network",
    "message": "Struct deleted successfully"
  }
  ```

### 6.3 Scalars

Search for scalar (constant) values in instructions, similar to Ghidra's "Search For Scalar" feature.

- **`GET /scalars`**: Search for occurrences of a specific scalar value in instructions.
  - Query Parameters:
    - `?value=[int]`: **Required.** The scalar value to search for (hex `0x...` or decimal).
    - `?offset=[int]`: Pagination offset (default: 0).
    - `?limit=[int]`: Maximum number of results to return (default: 100).
  ```json
  // Example Response for GET /scalars?value=0x1000
  "result": [
    {
      "address": "0x00401234",
      "value": 4096,
      "hexValue": "0x1000",
      "bitLength": 32,
      "signed": false,
      "operandIndex": 1,
      "instruction": "MOV EAX, 0x1000",
      "function": "main",
      "functionAddress": "0x00401200"
    }
  ],
  "_links": {
    "self": { "href": "/scalars?value=0x1000&offset=0&limit=100" },
    "next": { "href": "/scalars?value=0x1000&offset=100&limit=100" },
    "program": { "href": "/program" }
  }
  ```

### 7. Memory Segments

Represents memory blocks/sections defined in the program. 

- **`GET /segments`**: List all memory segments (e.g., `.text`, `.data`, `.bss`).
- **`GET /segments/{segment_name}`**: Get details for a specific segment (address range, permissions, size).

### 8. Memory Access

Provides raw memory access. 

- **`GET /memory/{address}`**: Read bytes from memory.
  - Query Parameters:
    - `?length=[bytes]`: Number of bytes to read (required, max limit applies).
    - `?format=[hex|base64|string]`: How to encode the returned bytes (default: hex).
  ```json
  // Example Response Fragment for GET /programs/proj%3A%2Ffile.bin/memory/0x402000?length=16&format=hex
  "result": {
    "address": "0x402000",
    "length": 16,
    "format": "hex",
    "bytes": "48656C6C6F20576F726C642100000000" // "Hello World!...."
  }
  ```
- **`PATCH /memory/{address}`**: Write bytes to memory. Requires `bytes` (in specified `format`) and `format` in the payload. Use with extreme caution.

### 9. Cross-References (XRefs)

Provides information about references to/from addresses.

- **`GET /xrefs`**: Search for cross-references. Supports pagination.
  - Query Parameters (at least one required):
    - `?to_addr=[address]`: Find references *to* this address.
    - `?from_addr=[address]`: Find references *from* this address or within the function/data at this address.
    - `?type=[CALL|READ|WRITE|DATA|POINTER|...]`: Filter by reference type.
- **`GET /functions/{address}/xrefs`**: Convenience endpoint, equivalent to `GET /xrefs?to_addr={address}` and potentially `GET /xrefs?from_addr={address}` combined or linked.

### 10. Analysis

Provides access to Ghidra's analysis results.

- **`GET /analysis`**: Get information about the analysis status and available analyzers.
  ```json
  // Example Response
  "result": {
    "program": "mybinary.exe",
    "analysis_enabled": true,
    "available_analyzers": [
      "Function Start Analyzer",
      "Basic Block Model Analyzer",
      "Reference Analyzer",
      "Call Convention Analyzer",
      "Data Reference Analyzer",
      "Decompiler Parameter ID",
      "Stack Analyzer"
    ]
  },
  "_links": {
    "self": { "href": "/analysis" },
    "program": { "href": "/program" },
    "analyze": { "href": "/analysis", "method": "POST" },
    "callgraph": { "href": "/analysis/callgraph" }
  }
  ```

- **`POST /analysis`**: Trigger a full or partial re-analysis of the program.
  ```json
  // Example Response
  "result": {
    "program": "mybinary.exe",
    "analysis_triggered": true,
    "message": "Analysis initiated on program"
  }
  ```

- **`GET /analysis/callgraph`**: Retrieve the function call graph.
  - Query Parameters:
    - `?function=[function_name]`: Start the call graph from this function (default: entry point).
    - `?max_depth=[int]`: Maximum depth of the call graph (default: 3).
  ```json
  // Example Response
  "result": {
    "root": "main",
    "root_address": "0x401000",
    "max_depth": 3,
    "nodes": [
      {
        "id": "0x401000",
        "name": "main",
        "address": "0x401000",
        "depth": 0,
        "_links": {
          "self": { "href": "/functions/0x401000" }
        }
      },
      // ... more nodes
    ],
    "edges": [
      {
        "from": "0x401000",
        "to": "0x401100",
        "type": "call",
        "call_site": "0x401050"
      },
      // ... more edges
    ]
  }
  ```

- **`GET /analysis/dataflow`**: Perform data flow analysis starting from a specific address.
  - Query Parameters:
    - `?address=[address]`: Starting address for data flow analysis (required).
    - `?direction=[forward|backward]`: Direction of data flow analysis (default: forward).
    - `?max_steps=[int]`: Maximum number of steps to analyze (default: 50).
  ```json
  // Example Response
  "result": {
    "start_address": "0x401050",
    "direction": "forward",
    "max_steps": 50,
    "steps": [
      {
        "address": "0x401050",
        "instruction": "MOV EAX, [RBP+0x8]",
        "description": "Starting point of data flow analysis"
      },
      // ... more steps
    ]
  }
  ```

## Design Considerations for AI Usage

- **Structured responses**: JSON format ensures predictable parsing by AI agents.
- **HATEOAS Links**: `_links` allow agents to discover available actions and related resources without hardcoding paths.
- **Address and Name Resolution**: Key elements like functions and symbols are addressable by both memory address and name where applicable.
- **Explicit Operations**: Actions like decompilation, disassembly, and analysis are distinct endpoints.
- **Pagination & Filtering**: Essential for handling potentially large datasets (symbols, functions, xrefs, disassembly).
- **Clear Error Reporting**: `success: false` and the `error` object provide actionable feedback.
- **No Injected Summaries**: The API should return raw or structured Ghidra data, leaving interpretation and summarization to the AI agent.
