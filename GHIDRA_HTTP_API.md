# Ghidra HTTP API Documentation

## Base URL
`http://{host}:{port}/` (default port: 8192)

## Endpoints

### Instance Management
- `GET /instances` - List active instances
- `GET /info` - Get project information
- `GET /` - Root endpoint with basic info

### Program Analysis
- `GET /functions` - List functions
  - Parameters:
    - `offset` - Pagination offset
    - `limit` - Max items to return
    - `query` - Search string for function names

- `GET /functions/{name}` - Get function details
  - Parameters:
    - `cCode` - Return C-style code (true/false)
    - `syntaxTree` - Include syntax tree (true/false)
    - `simplificationStyle` - Decompiler style

- `GET /get_function_by_address` - Get function by address
  - Parameters:
    - `address` - Memory address in hex

- `GET /classes` - List classes
- `GET /segments` - List memory segments
- `GET /symbols/imports` - List imported symbols
- `GET /symbols/exports` - List exported symbols
- `GET /namespaces` - List namespaces
- `GET /data` - List data items
- `GET /variables` - List global variables
- `GET /functions/{name}/variables` - List function variables

### Modifications
- `POST /functions/{name}` - Rename function
  - Body: `{"newName": string}`

- `POST /data` - Rename data at address
  - Body: `{"address": string, "newName": string}`

- `POST /set_decompiler_comment` - Add decompiler comment
  - Body: `{"address": string, "comment": string}`

- `POST /set_disassembly_comment` - Add disassembly comment
  - Body: `{"address": string, "comment": string}`

- `POST /rename_local_variable` - Rename local variable
  - Body: `{"functionAddress": string, "oldName": string, "newName": string}`

- `POST /rename_function_by_address` - Rename function by address
  - Body: `{"functionAddress": string, "newName": string}`

- `POST /set_function_prototype` - Update function prototype
  - Body: `{"functionAddress": string, "prototype": string}`

- `POST /set_local_variable_type` - Change variable type
  - Body: `{"functionAddress": string, "variableName": string, "newType": string}`

## Response Format
All endpoints return JSON with standard structure:
```json
{
  "success": boolean,
  "result": object|array,
  "error": string, // if success=false
  "timestamp": number,
  "port": number
}
