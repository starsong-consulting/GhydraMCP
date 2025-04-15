# GhydraMCP Bridge Refactoring Proposal

## Current Issues

The current bridge implementation exposes all functionality as MCP tools, which creates several problems:

1. **Discoverability**: With dozens of tool functions, it's difficult for AI agents to identify the correct tool to use for a specific task.

2. **Consistency**: The API surface is large and not organized by conceptual resources, making it harder to understand what's related.

3. **Context Loading**: Many operations require repeated loading of program information that could be provided more efficiently as resources.

4. **Default Selection**: The current approach requires explicit port selection for each operation, instead of following a "current working instance" pattern.

## Proposed MCP-Oriented Refactoring

Restructure the bridge to follow MCP patterns more closely:

### 1. Resources (for Context Loading)

Resources provide information that can be loaded directly into the LLM's context.

```python
@mcp.resource()
def ghidra_instance(port: int = None) -> dict:
    """Get information about a Ghidra instance or the current working instance
    
    Args:
        port: Specific Ghidra instance port (optional, uses current if omitted)
        
    Returns:
        dict: Detailed information about the Ghidra instance and loaded program
    """
    # Implementation that gets instance info and the current program details
    # from the currently selected "working" instance or a specific port
```

```python
@mcp.resource()
def decompiled_function(name: str = None, address: str = None) -> str:
    """Get decompiled C code for a function
    
    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with name)
        
    Returns:
        str: The decompiled C code as a string
    """
    # Implementation that only returns the decompiled text directly
```

```python
@mcp.resource() 
def function_info(name: str = None, address: str = None) -> dict:
    """Get detailed information about a function
    
    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with name)
        
    Returns:
        dict: Complete function information including signature, parameters, etc.
    """
    # Implementation that returns detailed function information
```

```python
@mcp.resource()
def disassembly(name: str = None, address: str = None) -> str:
    """Get disassembled instructions for a function
    
    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with name)
        
    Returns:
        str: Formatted disassembly listing as a string
    """
    # Implementation that returns formatted text disassembly 
```

### 2. Prompts (for Interaction Patterns)

Prompts define reusable templates for LLM interactions, making common workflows easier.

```python
@mcp.prompt("analyze_function")
def analyze_function_prompt(name: str = None, address: str = None):
    """A prompt that guides the LLM through analyzing a function's purpose
    
    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with name)
    """
    # Implementation returns a prompt template with decompiled code and disassembly
    # that helps the LLM systematically analyze a function
    return {
        "prompt": f"""
        Analyze the following function: {name or address}
        
        Decompiled code:
        ```c
        {decompiled_function(name=name, address=address)}
        ```
        
        Disassembly:
        ```
        {disassembly(name=name, address=address)}
        ```
        
        1. What is the purpose of this function?
        2. What are the key parameters and their uses?
        3. What are the return values and their meanings?
        4. Are there any security concerns in this implementation?
        5. Describe the algorithm or process being implemented.
        """,
        "context": {
            "function_info": function_info(name=name, address=address)
        }
    }
```

```python
@mcp.prompt("identify_vulnerabilities")
def identify_vulnerabilities_prompt(name: str = None, address: str = None):
    """A prompt that helps the LLM identify potential vulnerabilities in a function
    
    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with name)
    """
    # Implementation returns a prompt focused on finding security issues
```

### 3. Tools (for Function Selection)

Tools are organized by domain concepts rather than just mirroring the low-level API.

```python
@mcp.tool_group("instances")
class InstanceTools:
    @mcp.tool()
    def list() -> dict:
        """List all active Ghidra instances"""
        return list_instances()
        
    @mcp.tool()
    def discover() -> dict:
        """Discover available Ghidra instances"""
        return discover_instances()
        
    @mcp.tool()
    def register(port: int, url: str = None) -> str:
        """Register a new Ghidra instance"""
        return register_instance(port, url)
        
    @mcp.tool()
    def use(port: int) -> str:
        """Set the current working Ghidra instance"""
        # Implementation that sets the default instance
        global current_instance_port
        current_instance_port = port
        return f"Now using Ghidra instance on port {port}"
```

```python
@mcp.tool_group("functions")
class FunctionTools:
    @mcp.tool()
    def list(offset: int = 0, limit: int = 100, **filters) -> dict:
        """List functions with filtering and pagination"""
        # Implementation that uses the current instance
        return list_functions(port=current_instance_port, offset=offset, limit=limit, **filters)
        
    @mcp.tool()
    def get(name: str = None, address: str = None) -> dict:
        """Get detailed information about a function"""
        return get_function(port=current_instance_port, name=name, address=address)
        
    @mcp.tool()
    def create(address: str) -> dict:
        """Create a new function at the specified address"""
        return create_function(port=current_instance_port, address=address)
        
    @mcp.tool()
    def rename(name: str = None, address: str = None, new_name: str = "") -> dict:
        """Rename a function"""
        return rename_function(port=current_instance_port, 
                             name=name, address=address, new_name=new_name)
        
    @mcp.tool()
    def set_signature(name: str = None, address: str = None, signature: str = "") -> dict:
        """Set a function's signature/prototype"""
        return set_function_signature(port=current_instance_port, 
                                    name=name, address=address, signature=signature)
```

Similar tool groups would be created for:
- `data`: Data manipulation tools
- `memory`: Memory reading/writing tools
- `analysis`: Program analysis tools
- `xrefs`: Cross-reference navigation tools
- `symbols`: Symbol management tools
- `variables`: Variable manipulation tools

### 4. Simplified Instance Management

Add a "current working instance" pattern:

```python
# Global state for the current instance
current_instance_port = DEFAULT_GHIDRA_PORT

# Helper function to get the current instance or validate a specific port
def _get_instance_port(port=None):
    port = port or current_instance_port
    # Validate that the instance exists and is active
    if port not in active_instances:
        # Try to register it if not found
        register_instance(port)
        if port not in active_instances:
            raise ValueError(f"No active Ghidra instance on port {port}")
    return port

# All tools would use this helper, falling back to the current instance if no port is specified
def read_memory(address: str, length: int = 16, format: str = "hex", port: int = None) -> dict:
    """Read bytes from memory
    
    Args:
        address: Memory address in hex format
        length: Number of bytes to read (default: 16)
        format: Output format (default: "hex")
        port: Specific Ghidra instance port (optional, uses current if omitted)
        
    Returns:
        dict: Memory content in the requested format
    """
    port = _get_instance_port(port)
    # Rest of implementation...
```

## Migration Strategy

1. Create a new MCP class structure in a separate file
2. Implement resource loaders for key items (functions, data, memory regions)
3. Implement prompt templates for common tasks
4. Organize tools into logical groups by domain concept
5. Add a current instance selection mechanism 
6. Update documentation with clear examples of the new patterns
7. Create backward compatibility shims if needed

## Benefits of This Approach

1. **Better Discoverability**: Logical grouping helps agents find the right tool
2. **Context Efficiency**: Resources load just what's needed without extra metadata
3. **Streamlined Interaction**: Tools follow consistent patterns with sensible defaults
4. **Prompt Templates**: Common patterns are codified in reusable prompts
5. **More LLM-friendly**: Outputs optimized for consumption by language models

The refactored API would be easier to use, more efficient, and better aligned with MCP best practices, while maintaining all the current functionality.