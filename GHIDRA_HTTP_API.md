# GhydraMCP Ghidra Plugin HTTP API v1

## Overview

This API provides a Hypermedia-driven interface (HATEOAS) to interact with Ghidra's CodeBrowser, enabling AI-driven and automated reverse engineering workflows. It allows interaction with Ghidra projects, programs (binaries), functions, symbols, data, memory segments, cross-references, and analysis features. Programs are addressed by their unique identifier within Ghidra (`project:/path/to/file`).

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
  "instance": "http://localhost:1337",
  "success": true,
  "result": [ ... objects ... ],
  "size": 150, // Total number of items matching the query across all pages
  "offset": 0,
  "limit": 50,
  "_links": {
    "self": { "href": "/programs/proj:/file.bin/functions?offset=0&limit=50" },
    "next": { "href": "/programs/proj:/file.bin/functions?offset=50&limit=50" }, // Present if more items exist
    "prev": { "href": "/programs/proj:/file.bin/functions?offset=0&limit=50" }  // Present if not the first page
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

Resources like functions, data, and symbols often exist at specific memory addresses and may have names. The primary identifier for a program is its Ghidra path, e.g., `myproject:/path/to/mybinary.exe`.

- **By Address:** Use the resource's path with the address (hexadecimal, e.g., `0x401000` or `08000004`).
  - Example: `GET /programs/myproject:/mybinary.exe/functions/0x401000`
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
  "instance": "http://localhost:1337",
  "success": true,
  "result": {
    "plugin_version": "v1.4.0", // Example plugin build version
    "api_version": 1           // Ordinal API version
  },
  "_links": {
    "self": { "href": "/plugin-version" }
  }
}
```

## Resource Types

Base path for all program-specific resources: `/programs/{program_id}` where `program_id` is the URL-encoded Ghidra identifier (e.g., `myproject%3A%2Fpath%2Fto%2Fmybinary.exe`).

### 1. Projects

Represents Ghidra projects, containers for programs.

- **`GET /projects`**: List all available Ghidra projects.
- **`POST /projects`**: Create a new Ghidra project. Request body should specify `name` and optionally `directory`.
- **`GET /projects/{project_name}`**: Get details about a specific project (e.g., location, list of open programs within it via links).

### 2. Programs

Represents individual binaries loaded in Ghidra projects.

- **`GET /programs`**: List all programs across all projects. Can be filtered by project (`?project={project_name}`).
- **`POST /programs`**: Load/import a new binary into a specified project. Request body needs `project_name`, `file_path`, and optionally `language_id`, `compiler_spec_id`, and loader options. Returns the newly created program resource details upon successful import and analysis (which might take time).
- **`GET /programs/{program_id}`**: Get metadata for a specific program (e.g., name, architecture, memory layout, analysis status).
  ```json
  // Example Response Fragment for GET /programs/myproject%3A%2Fmybinary.exe
  "result": {
    "program_id": "myproject:/mybinary.exe",
    "name": "mybinary.exe",
    "project": "myproject",
    "language_id": "x86:LE:64:default",
    "compiler_spec_id": "gcc",
    "image_base": "0x400000",
    "memory_size": 1048576,
    "is_open": true,
    "analysis_complete": true
    // ... other metadata
  },
  "_links": {
    "self": { "href": "/programs/myproject%3A%2Fmybinary.exe" },
    "project": { "href": "/projects/myproject" },
    "functions": { "href": "/programs/myproject%3A%2Fmybinary.exe/functions" },
    "symbols": { "href": "/programs/myproject%3A%2Fmybinary.exe/symbols" },
    "data": { "href": "/programs/myproject%3A%2Fmybinary.exe/data" },
    "segments": { "href": "/programs/myproject%3A%2Fmybinary.exe/segments" },
    "memory": { "href": "/programs/myproject%3A%2Fmybinary.exe/memory" },
    "xrefs": { "href": "/programs/myproject%3A%2Fmybinary.exe/xrefs" },
    "analysis": { "href": "/programs/myproject%3A%2Fmybinary.exe/analysis" }
    // Potentially actions like "close", "analyze"
  }
  ```
- **`DELETE /programs/{program_id}`**: Close and potentially remove a program from its project (behavior depends on Ghidra state).

### 3. Functions

Represents functions within a program. Base path: `/programs/{program_id}/functions`.

- **`GET /functions`**: List functions. Supports searching (by name/address/regex) and pagination.
  ```json
  // Example Response Fragment
  "result": [
    { "name": "FUN_08000004", "address": "08000004", "_links": { "self": { "href": "/programs/proj%3A%2Ffile.bin/functions/08000004" } } },
    { "name": "init_peripherals", "address": "08001cf0", "_links": { "self": { "href": "/programs/proj%3A%2Ffile.bin/functions/08001cf0" } } }
  ]
  ```
- **`POST /functions`**: Create a function at a specific address. Requires `address` in the request body. Returns the created function resource.
- **`GET /functions/{address}`**: Get details for a specific function (name, signature, size, stack info, etc.).
  ```json
  // Example Response Fragment for GET /programs/proj%3A%2Ffile.bin/functions/0x4010a0
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
    "self": { "href": "/programs/proj%3A%2Ffile.bin/functions/0x4010a0" },
    "decompile": { "href": "/programs/proj%3A%2Ffile.bin/functions/0x4010a0/decompile" },
    "disassembly": { "href": "/programs/proj%3A%2Ffile.bin/functions/0x4010a0/disassembly" },
    "variables": { "href": "/programs/proj%3A%2Ffile.bin/functions/0x4010a0/variables" },
    "xrefs_to": { "href": "/programs/proj%3A%2Ffile.bin/xrefs?to_addr=0x4010a0" },
    "xrefs_from": { "href": "/programs/proj%3A%2Ffile.bin/xrefs?from_addr=0x4010a0" }
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

### 4. Symbols & Labels

Represents named locations (functions, data, labels). Base path: `/programs/{program_id}/symbols`.

- **`GET /symbols`**: List all symbols in the program. Supports searching (by name/address/regex) and pagination. Can filter by type (`?type=function`, `?type=data`, `?type=label`).
- **`POST /symbols`**: Create or rename a symbol at a specific address. Requires `address` and `name` in the payload. If a symbol exists, it's renamed; otherwise, a new label is created.
- **`GET /symbols/{address}`**: Get details of the symbol at the specified address.
- **`PATCH /symbols/{address}`**: Modify properties of the symbol (e.g., set as primary, change namespace). Payload specifies changes.
- **`DELETE /symbols/{address}`**: Remove the symbol at the specified address.

### 5. Data

Represents defined data items in memory. Base path: `/programs/{program_id}/data`.

- **`GET /data`**: List defined data items. Supports searching (by name/address/regex) and pagination. Can filter by type (`?type=string`, `?type=dword`, etc.).
- **`POST /data`**: Define a new data item. Requires `address`, `type`, and optionally `size` or `length` in the payload.
- **`GET /data/{address}`**: Get details of the data item at the specified address (type, size, value representation).
- **`PATCH /data/{address}`**: Modify a data item (e.g., change `name`, `type`, `comment`). Payload specifies changes.
- **`DELETE /data/{address}`**: Undefine the data item at the specified address.

### 6. Memory Segments

Represents memory blocks/sections defined in the program. Base path: `/programs/{program_id}/segments`.

- **`GET /segments`**: List all memory segments (e.g., `.text`, `.data`, `.bss`).
- **`GET /segments/{segment_name}`**: Get details for a specific segment (address range, permissions, size).

### 7. Memory Access

Provides raw memory access. Base path: `/programs/{program_id}/memory`.

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

### 8. Cross-References (XRefs)

Provides information about references to/from addresses. Base path: `/programs/{program_id}/xrefs`.

- **`GET /xrefs`**: Search for cross-references. Supports pagination.
  - Query Parameters (at least one required):
    - `?to_addr=[address]`: Find references *to* this address.
    - `?from_addr=[address]`: Find references *from* this address or within the function/data at this address.
    - `?type=[CALL|READ|WRITE|DATA|POINTER|...]`: Filter by reference type.
- **`GET /functions/{address}/xrefs`**: Convenience endpoint, equivalent to `GET /xrefs?to_addr={address}` and potentially `GET /xrefs?from_addr={address}` combined or linked.

### 9. Analysis

Provides access to Ghidra's analysis results. Base path: `/programs/{program_id}/analysis`.

- **`GET /analysis/callgraph`**: Retrieve the function call graph (potentially filtered or paginated). Format might be nodes/edges JSON or a standard graph format like DOT.
- **`GET /analysis/dataflow/{address}`**: Perform data flow analysis starting from a specific address or instruction. Requires parameters specifying forward/backward, context, etc. (Details TBD).
- **`POST /analysis/analyze`**: Trigger a full or partial re-analysis of the program.

## Design Considerations for AI Usage

- **Structured responses**: JSON format ensures predictable parsing by AI agents.
- **HATEOAS Links**: `_links` allow agents to discover available actions and related resources without hardcoding paths.
- **Address and Name Resolution**: Key elements like functions and symbols are addressable by both memory address and name where applicable.
- **Explicit Operations**: Actions like decompilation, disassembly, and analysis are distinct endpoints.
- **Pagination & Filtering**: Essential for handling potentially large datasets (symbols, functions, xrefs, disassembly).
- **Clear Error Reporting**: `success: false` and the `error` object provide actionable feedback.
- **No Injected Summaries**: The API should return raw or structured Ghidra data, leaving interpretation and summarization to the AI agent.
