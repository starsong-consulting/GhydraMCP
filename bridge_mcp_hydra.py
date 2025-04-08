# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "mcp==1.6.0",
#     "requests==2.32.3",
# ]
# ///
import os
import signal
import sys
import threading
import time
from threading import Lock
from typing import Dict, List
from urllib.parse import quote
from urllib.parse import urlparse

import requests
from mcp.server.fastmcp import FastMCP

# Allowed origins for CORS/CSRF protection
ALLOWED_ORIGINS = os.environ.get("GHIDRA_ALLOWED_ORIGINS", "http://localhost").split(",")

# Track active Ghidra instances (port -> info dict)
active_instances: Dict[int, dict] = {}
instances_lock = Lock()
DEFAULT_GHIDRA_PORT = 8192
DEFAULT_GHIDRA_HOST = "localhost"
# Port ranges for scanning
QUICK_DISCOVERY_RANGE = range(8192, 8202)  # Limited range for interactive/triggered discovery (10 ports)
FULL_DISCOVERY_RANGE = range(8192, 8212)   # Wider range for background discovery (20 ports)

instructions = """
GhydraMCP allows interacting with multiple Ghidra SRE instances. Ghidra SRE is a tool for reverse engineering and analyzing binaries, e.g. malware.

First, run `discover_instances` to find open Ghidra instances. List tools to see what GhydraMCP can do.
"""

mcp = FastMCP("GhydraMCP", instructions=instructions)

ghidra_host = os.environ.get("GHIDRA_HYDRA_HOST", DEFAULT_GHIDRA_HOST)
# print(f"Using Ghidra host: {ghidra_host}")

def get_instance_url(port: int) -> str:
    """Get URL for a Ghidra instance by port"""
    with instances_lock:
        if port in active_instances:
            return active_instances[port]["url"]

        # Auto-register if not found but port is valid
        if 8192 <= port <= 65535:
            register_instance(port)
            if port in active_instances:
                return active_instances[port]["url"]

        return f"http://{ghidra_host}:{port}"

def validate_origin(headers: dict) -> bool:
    """Validate request origin against allowed origins"""
    origin = headers.get("Origin")
    if not origin:
        return True  # No origin header - allow (browser same-origin policy applies)
    
    # Parse origin to get scheme+hostname
    try:
        parsed = urlparse(origin)
        origin_base = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            origin_base += f":{parsed.port}"
    except:
        return False
    
    return origin_base in ALLOWED_ORIGINS

def _make_request(method: str, port: int, endpoint: str, params: dict = None, json_data: dict = None, data: str = None, headers: dict = None) -> dict:
    """Internal helper to make HTTP requests and handle common errors."""
    url = f"{get_instance_url(port)}/{endpoint}"
    request_headers = {'Accept': 'application/json'}
    if headers:
        request_headers.update(headers)

    # Origin validation for state-changing requests
    is_state_changing = method.upper() in ["POST", "PUT", "DELETE"] # Add other methods if needed
    if is_state_changing:
        # Extract headers from json_data if present, otherwise use provided headers
        check_headers = json_data.get("headers", {}) if isinstance(json_data, dict) else (headers or {})
        if not validate_origin(check_headers):
            return {
                "success": False,
                "error": "Origin not allowed",
                "status_code": 403,
                "timestamp": int(time.time() * 1000)
            }
        # Set Content-Type for POST/PUT if sending JSON
        if json_data is not None:
             request_headers['Content-Type'] = 'application/json'
        elif data is not None:
             request_headers['Content-Type'] = 'text/plain' # Or appropriate type

    try:
        response = requests.request(
            method,
            url,
            params=params,
            json=json_data,
            data=data,
            headers=request_headers,
            timeout=10 # Increased timeout slightly
        )

        # Attempt to parse JSON regardless of status code, as errors might be JSON
        try:
            parsed_json = response.json()
            # Add timestamp if not present in the response from Ghidra
            if isinstance(parsed_json, dict) and "timestamp" not in parsed_json:
                 parsed_json["timestamp"] = int(time.time() * 1000)
            return parsed_json
        except ValueError:
            # Handle non-JSON responses (e.g., unexpected errors, successful plain text)
            if response.ok:
                 # Success, but not JSON - wrap it? Or assume plugin *always* returns JSON?
                 # For now, treat unexpected non-JSON success as an error from the plugin side.
                 return {
                     "success": False,
                     "error": "Received non-JSON success response from Ghidra plugin",
                     "status_code": response.status_code,
                     "response_text": response.text[:500], # Limit text length
                     "timestamp": int(time.time() * 1000)
                 }
            else:
                 # Error response was not JSON
                 return {
                     "success": False,
                     "error": f"HTTP {response.status_code} - Non-JSON error response",
                     "status_code": response.status_code,
                     "response_text": response.text[:500], # Limit text length
                     "timestamp": int(time.time() * 1000)
                 }

    except requests.exceptions.Timeout:
        return {
            "success": False,
            "error": "Request timed out",
            "status_code": 408, # Request Timeout
            "timestamp": int(time.time() * 1000)
        }
    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "error": f"Failed to connect to Ghidra instance at {url}",
            "status_code": 503, # Service Unavailable
            "timestamp": int(time.time() * 1000)
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"An unexpected error occurred: {str(e)}",
            "exception": e.__class__.__name__,
            "timestamp": int(time.time() * 1000)
        }

def safe_get(port: int, endpoint: str, params: dict = None) -> dict:
    """Perform a GET request to a specific Ghidra instance and return JSON response"""
    return _make_request("GET", port, endpoint, params=params)

def safe_put(port: int, endpoint: str, data: dict) -> dict:
    """Perform a PUT request to a specific Ghidra instance with JSON payload"""
    # Pass headers if they exist within the data dict
    headers = data.pop("headers", None) if isinstance(data, dict) else None
    return _make_request("PUT", port, endpoint, json_data=data, headers=headers)

def safe_post(port: int, endpoint: str, data: dict | str) -> dict:
    """Perform a POST request to a specific Ghidra instance with JSON or text payload"""
    headers = None
    json_payload = None
    text_payload = None

    if isinstance(data, dict):
        headers = data.pop("headers", None)
        json_payload = data
    else:
        text_payload = data # Assume string data is text/plain

    return _make_request("POST", port, endpoint, json_data=json_payload, data=text_payload, headers=headers)

# Instance management tools
@mcp.tool()
def list_instances() -> dict:
    """List all active Ghidra instances"""
    with instances_lock:
        return {
            "instances": [
                {
                    "port": port,
                    "url": info["url"],
                    "project": info.get("project", ""),
                    "file": info.get("file", "")
                }
                for port, info in active_instances.items()
            ]
        }

@mcp.tool()
def register_instance(port: int, url: str = None) -> str:
    """Register a new Ghidra instance"""
    if url is None:
        url = f"http://{ghidra_host}:{port}"

    # Verify instance is reachable before registering
    try:
        test_url = f"{url}/instances"
        response = requests.get(test_url, timeout=2)
        if not response.ok:
            return f"Error: Instance at {url} is not responding properly"

        # Try to get project info
        project_info = {"url": url}

        try:
            # Try the root endpoint first
            root_url = f"{url}/"
            root_response = requests.get(root_url, timeout=1.5)  # Short timeout for root

            if root_response.ok:
                try:
                    root_data = root_response.json()

                    # Extract basic information from root
                    if "project" in root_data and root_data["project"]:
                        project_info["project"] = root_data["project"]
                    if "file" in root_data and root_data["file"]:
                        project_info["file"] = root_data["file"]

                except Exception as e:
                    print(f"Error parsing root info: {e}", file=sys.stderr)

            # If we don't have project info yet, try the /info endpoint as a fallback
            if not project_info.get("project") and not project_info.get("file"):
                info_url = f"{url}/info"

                try:
                    info_response = requests.get(info_url, timeout=2)
                    if info_response.ok:
                        try:
                            info_data = info_response.json()
                            # Extract relevant information
                            if "project" in info_data and info_data["project"]:
                                project_info["project"] = info_data["project"]

                            # Handle file information
                            file_info = info_data.get("file", {})
                            if isinstance(file_info, dict) and file_info.get("name"):
                                project_info["file"] = file_info.get("name", "")
                                project_info["path"] = file_info.get("path", "")
                                project_info["architecture"] = file_info.get("architecture", "")
                                project_info["endian"] = file_info.get("endian", "")
                            print(f"Info data parsed: {project_info}", file=sys.stderr)
                        except Exception as e:
                            print(f"Error parsing info endpoint: {e}", file=sys.stderr)
                except Exception as e:
                    print(f"Error connecting to info endpoint: {e}", file=sys.stderr)
        except Exception:
            # Non-critical, continue with registration even if project info fails
            pass

        with instances_lock:
            active_instances[port] = project_info

        return f"Registered instance on port {port} at {url}"
    except Exception as e:
        return f"Error: Could not connect to instance at {url}: {str(e)}"

@mcp.tool()
def unregister_instance(port: int) -> str:
    """Unregister a Ghidra instance"""
    with instances_lock:
        if port in active_instances:
            del active_instances[port]
            return f"Unregistered instance on port {port}"
        return f"No instance found on port {port}"

@mcp.tool()
def discover_instances(host: str = None) -> dict:
    """Auto-discover Ghidra instances by scanning ports (quick discovery with limited range)

    Args:
        host: Optional host to scan (defaults to configured ghidra_host)
    """
    return _discover_instances(QUICK_DISCOVERY_RANGE, host=host, timeout=0.5)

def _discover_instances(port_range, host=None, timeout=0.5) -> dict:
    """Internal function to discover Ghidra instances by scanning ports"""
    found_instances = []
    scan_host = host if host is not None else ghidra_host

    for port in port_range:
        if port in active_instances:
            continue

        url = f"http://{scan_host}:{port}"
        try:
            test_url = f"{url}/instances"
            response = requests.get(test_url, timeout=timeout)  # Short timeout for scanning
            if response.ok:
                result = register_instance(port, url)
                found_instances.append({"port": port, "url": url, "result": result})
        except requests.exceptions.RequestException:
            # Instance not available, just continue
            continue

    return {
        "found": len(found_instances),
        "instances": found_instances
    }

@mcp.tool()
def list_functions(port: int = DEFAULT_GHIDRA_PORT, offset: int = 0, limit: int = 100) -> list:
    """List all functions in the current program

    Args:
        port: Ghidra instance port (default: 8192)
        offset: Pagination offset (default: 0)
        limit: Maximum number of segments to return (default: 100)

    Returns:
        List of strings with function names and addresses
    """
    return safe_get(port, "functions", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(port: int = DEFAULT_GHIDRA_PORT, offset: int = 0, limit: int = 100) -> list:
    """List all classes with pagination"""
    return safe_get(port, "classes", {"offset": offset, "limit": limit})

@mcp.tool()
def get_function(port: int = DEFAULT_GHIDRA_PORT, name: str = "", cCode: bool = True, syntaxTree: bool = False, simplificationStyle: str = "normalize") -> dict:
    """Get decompiled code for a specific function

    Args:
        port: Ghidra instance port (default: 8192)
        name: Name of the function to decompile
        cCode: Whether to output C code (default: True)
        syntaxTree: Whether to include syntax tree (default: False)
        simplificationStyle: Decompiler analysis style (default: "normalize")

    Returns:
        Dict containing function details including decompiled code
    """
    response = safe_get(port, f"functions/{quote(name)}", {
        "cCode": str(cCode).lower(),
        "syntaxTree": str(syntaxTree).lower(),
        "simplificationStyle": simplificationStyle
    })
    
    # Check if the response is a string (old format) or already a dict with proper structure
    if isinstance(response, dict) and "success" in response:
        # If it's already a properly structured response, return it
        return response
    elif isinstance(response, str):
        # If it's a string (old format), wrap it in a proper structure
        return {
            "success": True,
            "result": {
                "name": name,
                "address": "",  # We don't have the address here
                "signature": "",  # We don't have the signature here
                "decompilation": response
            },
            "timestamp": int(time.time() * 1000),
            "port": port
        }
    else:
        # Unexpected format, return an error
        return {
            "success": False,
            "error": "Unexpected response format from Ghidra plugin",
            "timestamp": int(time.time() * 1000),
            "port": port
        }

@mcp.tool()
def update_function(port: int = DEFAULT_GHIDRA_PORT, name: str = "", new_name: str = "") -> str:
    """Rename a function (Modify -> POST)"""
    return safe_post(port, f"functions/{quote(name)}", {"newName": new_name})

@mcp.tool()
def update_data(port: int = DEFAULT_GHIDRA_PORT, address: str = "", new_name: str = "") -> str:
    """Rename data at specified address (Modify -> POST)"""
    return safe_post(port, "data", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(port: int = DEFAULT_GHIDRA_PORT, offset: int = 0, limit: int = 100) -> list:
    """List all memory segments in the current program with pagination

    Args:
        port: Ghidra instance port (default: 8192)
        offset: Pagination offset (default: 0)
        limit: Maximum number of segments to return (default: 100)

    Returns:
        List of segment information strings
    """
    return safe_get(port, "segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(port: int = DEFAULT_GHIDRA_PORT, offset: int = 0, limit: int = 100) -> list:
    """List all imported symbols with pagination

    Args:
        port: Ghidra instance port (default: 8192)
        offset: Pagination offset (default: 0)
        limit: Maximum number of imports to return (default: 100)

    Returns:
        List of import information strings
    """
    return safe_get(port, "symbols/imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(port: int = DEFAULT_GHIDRA_PORT, offset: int = 0, limit: int = 100) -> list:
    """List all exported symbols with pagination

    Args:
        port: Ghidra instance port (default: 8192)
        offset: Pagination offset (default: 0)
        limit: Maximum number of exports to return (default: 100)

    Returns:
        List of export information strings
    """
    return safe_get(port, "symbols/exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(port: int = DEFAULT_GHIDRA_PORT, offset: int = 0, limit: int = 100) -> list:
    """List all namespaces in the current program with pagination

    Args:
        port: Ghidra instance port (default: 8192)
        offset: Pagination offset (default: 0)
        limit: Maximum number of namespaces to return (default: 100)

    Returns:
        List of namespace information strings
    """
    return safe_get(port, "namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(port: int = DEFAULT_GHIDRA_PORT, offset: int = 0, limit: int = 100) -> list:
    """List all defined data items with pagination

    Args:
        port: Ghidra instance port (default: 8192)
        offset: Pagination offset (default: 0)
        limit: Maximum number of data items to return (default: 100)

    Returns:
        List of data item information strings
    """
    return safe_get(port, "data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(port: int = DEFAULT_GHIDRA_PORT, query: str = "", offset: int = 0, limit: int = 100) -> list:
    """Search for functions by name with pagination

    Args:
        port: Ghidra instance port (default: 8192)
        query: Search string to match against function names
        offset: Pagination offset (default: 0)
        limit: Maximum number of functions to return (default: 100)

    Returns:
        List of matching function information strings or error message if query is empty
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get(port, "functions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_by_address(port: int = DEFAULT_GHIDRA_PORT, address: str = "") -> dict:
    """Get function details by its memory address

    Args:
        port: Ghidra instance port (default: 8192)
        address: Memory address of the function (hex string)

    Returns:
        Dict containing function details including name, address, signature, and decompilation
    """
    response = safe_get(port, "get_function_by_address", {"address": address})
    
    # Check if the response is a string (old format) or already a dict with proper structure
    if isinstance(response, dict) and "success" in response:
        # If it's already a properly structured response, return it
        return response
    elif isinstance(response, str):
        # If it's a string (old format), wrap it in a proper structure
        return {
            "success": True,
            "result": {
                "decompilation": response,
                "address": address
            },
            "timestamp": int(time.time() * 1000),
            "port": port
        }
    else:
        # Unexpected format, return an error
        return {
            "success": False,
            "error": "Unexpected response format from Ghidra plugin",
            "timestamp": int(time.time() * 1000),
            "port": port
        }

@mcp.tool()
def get_current_address(port: int = DEFAULT_GHIDRA_PORT) -> dict: # Return dict
    """Get the address currently selected in Ghidra's UI

    Args:
        port: Ghidra instance port (default: 8192)

    Returns:
        Dict containing the current memory address (hex format)
    """
    # Directly return the dictionary from safe_get
    return safe_get(port, "get_current_address")

@mcp.tool()
def get_current_function(port: int = DEFAULT_GHIDRA_PORT) -> dict: # Return dict
    """Get the function currently selected in Ghidra's UI

    Args:
        port: Ghidra instance port (default: 8192)

    Returns:
        Dict containing function details including name, address, and signature
    """
    # Directly return the dictionary from safe_get
    return safe_get(port, "get_current_function")

@mcp.tool()
def decompile_function_by_address(port: int = DEFAULT_GHIDRA_PORT, address: str = "", cCode: bool = True, syntaxTree: bool = False, simplificationStyle: str = "normalize") -> dict:
    """Decompile a function at a specific memory address

    Args:
        port: Ghidra instance port (default: 8192)
        address: Memory address of the function (hex string)
        cCode: Whether to output C code (default: True)
        syntaxTree: Whether to include syntax tree (default: False)
        simplificationStyle: Decompiler analysis style (default: "normalize")

    Returns:
        Dict containing the decompiled pseudocode in the 'result.decompilation' field
    """
    response = safe_get(port, "decompile_function", {
        "address": address,
        "cCode": str(cCode).lower(),
        "syntaxTree": str(syntaxTree).lower(),
        "simplificationStyle": simplificationStyle
    })
    
    # Check if the response is a string (old format) or already a dict with proper structure
    if isinstance(response, dict) and "success" in response:
        # If it's already a properly structured response, return it
        return response
    elif isinstance(response, str):
        # If it's a string (old format), wrap it in a proper structure
        return {
            "success": True,
            "result": {
                "decompilation": response
            },
            "timestamp": int(time.time() * 1000),
            "port": port
        }
    else:
        # Unexpected format, return an error
        return {
            "success": False,
            "error": "Unexpected response format from Ghidra plugin",
            "timestamp": int(time.time() * 1000),
            "port": port
        }

@mcp.tool()
def disassemble_function(port: int = DEFAULT_GHIDRA_PORT, address: str = "") -> dict: # Return dict
    """Get disassembly for a function at a specific address

    Args:
        port: Ghidra instance port (default: 8192)
        address: Memory address of the function (hex string)

    Returns:
        List of strings showing assembly instructions with addresses and comments
    """
    return safe_get(port, "disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(port: int = DEFAULT_GHIDRA_PORT, address: str = "", comment: str = "") -> str:
    """Add/edit a comment in the decompiler view at a specific address

    Args:
        port: Ghidra instance port (default: 8192)
        address: Memory address to place comment (hex string)
        comment: Text of the comment to add

    Returns:
        Confirmation message or error if failed
    """
    return safe_post(port, "set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(port: int = DEFAULT_GHIDRA_PORT, address: str = "", comment: str = "") -> str:
    """Add/edit a comment in the disassembly view at a specific address

    Args:
        port: Ghidra instance port (default: 8192)
        address: Memory address to place comment (hex string)
        comment: Text of the comment to add

    Returns:
        Confirmation message or error if failed
    """
    return safe_post(port, "set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_local_variable(port: int = DEFAULT_GHIDRA_PORT, function_address: str = "", old_name: str = "", new_name: str = "") -> str:
    """Rename a local variable within a function

    Args:
        port: Ghidra instance port (default: 8192)
        function_address: Memory address of the function (hex string)
        old_name: Current name of the variable
        new_name: New name for the variable

    Returns:
        Confirmation message or error if failed
    """
    return safe_post(port, "rename_local_variable", {"functionAddress": function_address, "oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_function_by_address(port: int = DEFAULT_GHIDRA_PORT, function_address: str = "", new_name: str = "") -> str:
    """Rename a function at a specific memory address

    Args:
        port: Ghidra instance port (default: 8192)
        function_address: Memory address of the function (hex string)
        new_name: New name for the function

    Returns:
        Confirmation message or error if failed
    """
    return safe_post(port, "rename_function_by_address", {"functionAddress": function_address, "newName": new_name})

@mcp.tool()
def set_function_prototype(port: int = DEFAULT_GHIDRA_PORT, function_address: str = "", prototype: str = "") -> str:
    """Update a function's signature/prototype

    Args:
        port: Ghidra instance port (default: 8192)
        function_address: Memory address of the function (hex string)
        prototype: New function prototype string (e.g. "int func(int param1)")

    Returns:
        Confirmation message or error if failed
    """
    return safe_post(port, "set_function_prototype", {"functionAddress": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(port: int = DEFAULT_GHIDRA_PORT, function_address: str = "", variable_name: str = "", new_type: str = "") -> str:
    """Change the data type of a local variable in a function

    Args:
        port: Ghidra instance port (default: 8192)
        function_address: Memory address of the function (hex string)
        variable_name: Name of the variable to modify
        new_type: New data type for the variable (e.g. "int", "char*")

    Returns:
        Confirmation message or error if failed
    """
    return safe_post(port, "set_local_variable_type", {"functionAddress": function_address, "variableName": variable_name, "newType": new_type})

@mcp.tool()
def list_variables(port: int = DEFAULT_GHIDRA_PORT, offset: int = 0, limit: int = 100, search: str = "") -> dict:
    """List global variables with optional search
    
    Args:
        port: Ghidra instance port (default: 8192)
        offset: Pagination offset (default: 0)
        limit: Maximum number of variables to return (default: 100)
        search: Optional search string to filter variables by name
        
    Returns:
        Dict containing the list of variables in the 'result' field
    """
    params = {"offset": offset, "limit": limit}
    if search:
        params["search"] = search
    
    response = safe_get(port, "variables", params)
    
    # Check if the response is a string (old format) or already a dict with proper structure
    if isinstance(response, dict) and "success" in response:
        # If it's already a properly structured response, return it
        return response
    elif isinstance(response, str):
        # If it's a string (old format), parse it and wrap it in a proper structure
        # For empty response, return empty list
        if not response.strip():
            return {
                "success": True,
                "result": [],
                "timestamp": int(time.time() * 1000),
                "port": port
            }
        
        # Parse the string to extract variables
        variables = []
        lines = response.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if line:
                # Try to parse variable line
                parts = line.split(':')
                if len(parts) >= 2:
                    var_name = parts[0].strip()
                    var_type = ':'.join(parts[1:]).strip()
                    
                    # Extract address if present
                    address = ""
                    if '@' in var_type:
                        type_parts = var_type.split('@')
                        var_type = type_parts[0].strip()
                        address = type_parts[1].strip()
                    
                    variables.append({
                        "name": var_name,
                        "dataType": var_type,
                        "address": address
                    })
        
        # Return structured response
        return {
            "success": True,
            "result": variables,
            "timestamp": int(time.time() * 1000),
            "port": port
        }
    else:
        # Unexpected format, return an error
        return {
            "success": False,
            "error": "Unexpected response format from Ghidra plugin",
            "timestamp": int(time.time() * 1000),
            "port": port
        }

@mcp.tool()
def list_function_variables(port: int = DEFAULT_GHIDRA_PORT, function: str = "") -> dict:
    """List variables in a specific function

    Args:
        port: Ghidra instance port (default: 8192)
        function: Name of the function to list variables for

    Returns:
        Dict containing the function variables in the 'result.variables' field
    """
    if not function:
        return {"success": False, "error": "Function name is required"}

    encoded_name = quote(function)
    response = safe_get(port, f"functions/{encoded_name}/variables", {})
    
    # Check if the response is a string (old format) or already a dict with proper structure
    if isinstance(response, dict) and "success" in response:
        # If it's already a properly structured response, return it
        return response
    elif isinstance(response, str):
        # If it's a string (old format), parse it and wrap it in a proper structure
        # Example string format: "Function: init_peripherals\n\nParameters:\n  none\n\nLocal Variables:\n  powArrThree: undefined * @ 08000230\n  pvartwo: undefined * @ 08000212\n  pvarEins: undefined * @ 08000206\n"
        
        # Parse the string to extract variables
        variables = []
        lines = response.strip().split('\n')
        
        # Extract function name from first line if possible
        function_name = function
        if lines and lines[0].startswith("Function:"):
            function_name = lines[0].replace("Function:", "").strip()
        
        # Look for local variables section
        in_local_vars = False
        for line in lines:
            line = line.strip()
            if line == "Local Variables:":
                in_local_vars = True
                continue
            
            if in_local_vars and line and not line.startswith("Function:") and not line.startswith("Parameters:"):
                # Parse variable line: "  varName: type @ address"
                parts = line.strip().split(':')
                if len(parts) >= 2:
                    var_name = parts[0].strip()
                    var_type = ':'.join(parts[1:]).strip()
                    
                    # Extract address if present
                    address = ""
                    if '@' in var_type:
                        type_parts = var_type.split('@')
                        var_type = type_parts[0].strip()
                        address = type_parts[1].strip()
                    
                    variables.append({
                        "name": var_name,
                        "dataType": var_type,
                        "address": address,
                        "type": "local"
                    })
        
        # Return structured response
        return {
            "success": True,
            "result": {
                "function": function_name,
                "variables": variables
            },
            "timestamp": int(time.time() * 1000),
            "port": port
        }
    else:
        # Unexpected format, return an error
        return {
            "success": False,
            "error": "Unexpected response format from Ghidra plugin",
            "timestamp": int(time.time() * 1000),
            "port": port
        }

@mcp.tool()
def rename_variable(port: int = DEFAULT_GHIDRA_PORT, function: str = "", name: str = "", new_name: str = "") -> dict:
    """Rename a variable in a function
    
    Args:
        port: Ghidra instance port (default: 8192)
        function: Name of the function containing the variable
        name: Current name of the variable
        new_name: New name for the variable
        
    Returns:
        Dict containing the result of the operation
    """
    if not function or not name or not new_name:
        return {"success": False, "error": "Function, name, and new_name parameters are required"}

    encoded_function = quote(function)
    encoded_var = quote(name)
    return safe_post(port, f"functions/{encoded_function}/variables/{encoded_var}", {"newName": new_name})

@mcp.tool()
def retype_variable(port: int = DEFAULT_GHIDRA_PORT, function: str = "", name: str = "", data_type: str = "") -> dict:
    """Change the data type of a variable in a function
    
    Args:
        port: Ghidra instance port (default: 8192)
        function: Name of the function containing the variable
        name: Current name of the variable
        data_type: New data type for the variable
        
    Returns:
        Dict containing the result of the operation
    """
    if not function or not name or not data_type:
        return {"success": False, "error": "Function, name, and data_type parameters are required"}

    encoded_function = quote(function)
    encoded_var = quote(name)
    return safe_post(port, f"functions/{encoded_function}/variables/{encoded_var}", {"dataType": data_type})

def handle_sigint(signum, frame):
    os._exit(0)

def periodic_discovery():
    """Periodically discover new instances"""
    while True:
        try:
            # Use the full discovery range
            _discover_instances(FULL_DISCOVERY_RANGE, timeout=0.5)

            # Also check if any existing instances are down
            with instances_lock:
                ports_to_remove = []
                for port, info in active_instances.items():
                    url = info["url"]
                    try:
                        response = requests.get(f"{url}/instances", timeout=1)
                        if not response.ok:
                            ports_to_remove.append(port)
                    except requests.exceptions.RequestException:
                        ports_to_remove.append(port)

                # Remove any instances that are down
                for port in ports_to_remove:
                    del active_instances[port]
                    print(f"Removed unreachable instance on port {port}")
        except Exception as e:
            print(f"Error in periodic discovery: {e}")

        # Sleep for 30 seconds before next scan
        time.sleep(30)

if __name__ == "__main__":
    # Auto-register default instance
    register_instance(DEFAULT_GHIDRA_PORT, f"http://{ghidra_host}:{DEFAULT_GHIDRA_PORT}")

    # Auto-discover other instances
    discover_instances()

    # Start periodic discovery in background thread
    discovery_thread = threading.Thread(
        target=periodic_discovery,
        daemon=True,
        name="GhydraMCP-Discovery"
    )
    discovery_thread.start()

    signal.signal(signal.SIGINT, handle_sigint)
    mcp.run(transport="stdio")
