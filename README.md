[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/teal-bauer/GhydraMCP)](https://github.com/teal-bauer/GhydraMCP/releases)
[![GitHub stars](https://img.shields.io/github/stars/teal-bauer/GhydraMCP)](https://github.com/teal-bauer/GhydraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/teal-bauer/GhydraMCP)](https://github.com/teal-bauer/GhydraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/teal-bauer/GhydraMCP)](https://github.com/teal-bauer/GhydraMCP/graphs/contributors)
[![Build Status](https://github.com/teal-bauer/GhydraMCP/actions/workflows/build.yml/badge.svg)](https://github.com/teal-bauer/GhydraMCP/actions/workflows/build.yml)

![GhydraMCP logo](https://github.com/user-attachments/assets/86b9b2de-767c-4ed5-b082-510b8109f00f)

# GhydraMCP
GhydraMCP is an Model Context Protocol server for allowing LLMs to autonomously reverse engineer applications. It exposes numerous tools from core Ghidra functionality to MCP clients.

https://github.com/user-attachments/assets/36080514-f227-44bd-af84-78e29ee1d7f9

GhydraMCP is based on [GhidraMCP by Laurie Wired](https://github.com/LaurieWired/GhidraMCP/).

# Features
MCP Server + Ghidra Plugin

- Full program analysis capabilities:
  - Decompile functions to C code
  - Cross-reference analysis
  - Data type propagation
- Interactive reverse engineering:
  - Rename functions, variables, and data
  - Add comments and labels
  - Modify data types
- Program exploration:
  - List functions, classes, namespaces
  - View imports, exports, segments
  - Search by name or pattern

# Installation

## Prerequisites
- Install [Ghidra](https://ghidra-sre.org)
- Python3
- MCP [SDK](https://github.com/modelcontextprotocol/python-sdk)

## Ghidra
First, download the latest [release](https://github.com/teal-bauer/GhydraMCP/releases) from this repository. This contains the Ghidra plugin and Python MCP client. Then, you can directly import the plugin into Ghidra.

1. Run Ghidra
2. Select `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `GhydraMCP-1-1.zip` (or your chosen version) from the downloaded release
5. Restart Ghidra
6. Make sure the GhydraMCPPlugin is enabled in `File` -> `Configure` -> `Developer`

Video Installation Guide:


https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3



## MCP Clients

Theoretically, any MCP client should work with GhydraMCP.  Two examples are given below.

## API Reference

### Available Tools

**Program Analysis**:
- `list_methods`: List all functions (params: offset, limit)
- `list_classes`: List all classes/namespaces (params: offset, limit)  
- `decompile_function`: Get decompiled C code (params: name)
- `rename_function`: Rename a function (params: old_name, new_name)
- `rename_data`: Rename data at address (params: address, new_name)
- `list_segments`: View memory segments (params: offset, limit)
- `list_imports`: List imported symbols (params: offset, limit)
- `list_exports`: List exported functions (params: offset, limit)
- `list_namespaces`: Show namespaces (params: offset, limit)
- `list_data_items`: View data labels (params: offset, limit)
- `search_functions_by_name`: Find functions (params: query, offset, limit)

**Instance Management**:
- `list_instances`: List active Ghidra instances (no params)
- `register_instance`: Register new instance (params: port, url)
- `unregister_instance`: Remove instance (params: port)

**Example Usage**:
```python
# Program analysis
client.use_tool("ghydra", "decompile_function", {"name": "main"})

# Instance management  
client.use_tool("ghydra", "register_instance", {"port": 8192, "url": "http://localhost:8192/"})
client.use_tool("ghydra", "register_instance", {"port": 8193})
```

## Client Setup

### Claude Desktop Configuration
```json
{
  "mcpServers": {
    "ghydra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_hydra.py"
      ],
      "env": {
        "GHIDRA_HYDRA_HOST": "localhost"  // Optional - defaults to localhost
      }
    }
  }
}
```

### 5ire Configuration
1. Tool Key: ghydra  
2. Name: GhydraMCP
3. Command: `python /ABSOLUTE_PATH_TO/bridge_mcp_hydra.py`

# Building from Source
Build with Maven by running:

`mvn clean package assembly:single`

The generated zip file includes the built Ghidra plugin and its resources. These files are required for Ghidra to recognize the new extension.

- lib/GhydraMCP.jar
- extensions.properties
- Module.manifest
