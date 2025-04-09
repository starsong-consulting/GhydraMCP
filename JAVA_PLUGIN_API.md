# GhydraMCP Java Plugin REST API Documentation

## Base URL
`http://localhost:8192` (default port, may vary)

## Endpoints

### 1. Instance Information
- `GET /info`
- `GET /` (root path)
  
Returns basic instance information including:
- Port number
- Whether this is the base instance
- Current project name (if available)
- Current program name (if available)

Example Response:
```json
{
  "port": 8192,
  "isBaseInstance": true,
  "project": "MyProject",
  "file": "program.exe"
}
```

### 2. Function Operations

#### List Functions
- `GET /functions`
  
Parameters:
- `offset` (optional): Pagination offset (default: 0)
- `limit` (optional): Maximum results (default: 100)
- `query` (optional): Search term to filter functions

Example Response:
```json
{
  "success": true,
  "result": [
    {
      "name": "init_peripherals",
      "address": "08000200"
    },
    {
      "name": "uart_rx_valid_command", 
      "address": "0800029c"
    }
  ],
  "timestamp": 1743778219516,
  "port": 8192,
  "instanceType": "base"
}
```

#### Get Function Details
- `GET /functions/{name}`
  
Returns decompiled code for the specified function.

Example Response:
```json
{
  "success": true,
  "result": "int main() {\n  // Decompiled code here\n}",
  "timestamp": 1743778219516
}
```

#### Rename Function
- `POST /functions/{name}`

Body Parameters:
- `newName`: New name for the function

Example Response:
```json
{
  "success": true,
  "result": "Renamed successfully",
  "timestamp": 1743778219516
}
```

#### Function Variables
- `GET /functions/{name}/variables`
  
Lists all variables (parameters and locals) in a function.

Example Response:
```json
{
  "success": true,
  "result": {
    "function": "myFunction",
    "parameters": [
      {
        "name": "param1",
        "type": "int",
        "kind": "parameter"
      },
      {
        "name": "param2",
        "type": "char*",
        "kind": "parameter"
      }
    ],
    "localVariables": [
      {
        "name": "var1",
        "type": "int",
        "address": "08000234"
      },
      {
        "name": "var2",
        "type": "float",
        "address": "08000238"
      }
    ]
  }
}
```

#### Rename/Retype Variable
- `POST /functions/{name}/variables/{varName}`

Body Parameters (one of):
- `newName`: New name for variable
- `dataType`: New data type for variable

Example Response:
```json
{
  "success": true,
  "result": "Variable renamed",
  "timestamp": 1743778219516
}
```

### 3. Class Operations
- `GET /classes`
  
Parameters:
- `offset` (optional): Pagination offset (default: 0)
- `limit` (optional): Maximum results (default: 100)

Example Response:
```json
{
  "success": true,
  "result": [
    "MyClass1",
    "MyClass2"
  ],
  "timestamp": 1743778219516
}
```

### 4. Memory Segments
- `GET /segments`
  
Parameters:
- `offset` (optional): Pagination offset (default: 0)
- `limit` (optional): Maximum results (default: 100)

Example Response:
```json
{
  "success": true,
  "result": [
    {
      "name": ".text",
      "start": "08000000",
      "end": "08001000"
    },
    {
      "name": ".data",
      "start": "08001000",
      "end": "08002000"
    }
  ]
}
```

### 5. Symbol Operations

#### Imports
- `GET /symbols/imports`
  
Parameters:
- `offset` (optional): Pagination offset (default: 0)
- `limit` (optional): Maximum results (default: 100)

Example Response:
```json
{
  "success": true,
  "result": [
    {
      "name": "printf",
      "address": "EXTERNAL:00000000"
    },
    {
      "name": "malloc",
      "address": "EXTERNAL:00000004"
    }
  ]
}
```

#### Exports
- `GET /symbols/exports`
  
Parameters:
- `offset` (optional): Pagination offset (default: 0)
- `limit` (optional): Maximum results (default: 100)

Example Response:
```json
{
  "success": true,
  "result": [
    {
      "name": "main",
      "address": "08000200"
    },
    {
      "name": "_start",
      "address": "08000100"
    }
  ]
}
```

### 6. Namespace Operations
- `GET /namespaces`
  
Parameters:
- `offset` (optional): Pagination offset (default: 0)
- `limit` (optional): Maximum results (default: 100)

Example Response:
```json
{
  "success": true,
  "result": [
    "std",
    "MyNamespace"
  ]
}
```

### 7. Data Operations

#### List Defined Data
- `GET /data`
  
Parameters:
- `offset` (optional): Pagination offset (default: 0)
- `limit` (optional): Maximum results (default: 100)

Example Response:
```json
{
  "success": true,
  "result": [
    {
      "address": "08001000",
      "name": "myVar",
      "value": "42"
    },
    {
      "address": "08001004",
      "name": "myString",
      "value": "\"Hello\""
    }
  ]
}
```

#### Rename Data
- `POST /data`

Body Parameters:
- `address`: Address of data to rename (hex string)
- `newName`: New name for data

Example Response:
```json
{
  "success": true,
  "result": {
    "name": "main",
    "decompiled": "int main() {\n  // Decompiled code here\n}",
    "metadata": {
      "size": 256,
      "entryPoint": "08000200"
    }
  },
  "timestamp": 1743778219516
}
```

### 8. Variable Operations

#### Global Variables
- `GET /variables`
  
Parameters:
- `offset` (optional): Pagination offset (default: 0)
- `limit` (optional): Maximum results (default: 100)
- `search` (optional): Search term to filter variables

Example Response:
```json
{
  "success": true,
  "result": [
    {
      "name": "globalVar1",
      "address": "08001000"
    },
    {
      "name": "globalVar2",
      "address": "08001004"
    }
  ]
}
```

### 9. Instance Management

#### List Active Instances
- `GET /instances`
  
Example Response:
```json
{
  "success": true,
  "result": [
    {
      "port": 8192,
      "type": "base"
    },
    {
      "port": 8193,
      "type": "secondary"
    }
  ]
}
```

#### Register Instance
- `POST /registerInstance`
  
Body Parameters:
- `port`: Port number to register

Example Response:
```json
{
  "success": true,
  "result": "Instance registered on port 8193",
  "timestamp": 1743778219516
}
```

#### Unregister Instance
- `POST /unregisterInstance`
  
Body Parameters:
- `port`: Port number to unregister

Example Response:
```json
{
  "success": true,
  "result": "Unregistered instance on port 8193",
  "timestamp": 1743778219516
}
```

## Error Responses
All endpoints return JSON with success=false on errors:
```json
{
  "success": false,
  "error": "Error message",
  "status": 500
}
```

Common status codes:
- 400: Bad request (invalid parameters)
- 404: Not found (invalid endpoint or resource)
- 405: Method not allowed
- 500: Internal server error
