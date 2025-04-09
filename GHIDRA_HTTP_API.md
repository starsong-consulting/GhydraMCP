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

- `GET /functions/by-name` - Get decompiled function by name
  - Parameters:
    - `name` - Function name
    - `cCode` - Return C-style code (true/false)
    - `syntaxTree` - Include syntax tree (true/false)
    - `simplificationStyle` - Decompiler style

- `GET /functions/by-address` - Get decompiled function by address
  - Parameters:
    - `address` - Memory address in hex
    - `cCode` - Return C-style code (true/false)
    - `syntaxTree` - Include syntax tree (true/false)
    - `simplificationStyle` - Decompiler style

- `GET /functions/variables/by-name` - List function variables by function name
  - Parameters:
    - `name` - Function name

- `GET /functions/variables/by-address` - List function variables by function address
  - Parameters:
    - `address` - Memory address in hex

- `GET /classes` - List classes
- `GET /segments` - List memory segments
- `GET /symbols/imports` - List imported symbols
- `GET /symbols/exports` - List exported symbols
- `GET /namespaces` - List namespaces
- `GET /data` - List data items
- `GET /variables` - List global variables

### Modifications
- `PATCH /functions/by-name` - Update function properties by name
  - Parameters:
    - `name` - Function name
  - Body: `{"name": string}`

- `PATCH /functions/by-address` - Update function properties by address
  - Parameters:
    - `address` - Memory address in hex
  - Body: `{"name": string}`

- `PATCH /data` - Update data properties
  - Body: `{"address": string, "name": string}`

- `POST /comments/decompiler` - Create decompiler comment
  - Body: `{"address": string, "comment": string}`

- `POST /comments/disassembly` - Create disassembly comment
  - Body: `{"address": string, "comment": string}`

- `PATCH /variables/local` - Update local variable
  - Body: `{"functionAddress": string, "oldName": string, "newName": string}`

- `PUT /functions/prototype` - Replace function prototype
  - Body: `{"functionAddress": string, "prototype": string}`

- `PATCH /variables/local/type` - Update local variable type
  - Body: `{"functionAddress": string, "variableName": string, "type": string}`

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
```