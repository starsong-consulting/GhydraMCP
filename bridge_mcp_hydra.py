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
QUICK_DISCOVERY_RANGE = range(DEFAULT_GHIDRA_PORT, DEFAULT_GHIDRA_PORT+10)
FULL_DISCOVERY_RANGE = range(DEFAULT_GHIDRA_PORT, DEFAULT_GHIDRA_PORT+20)

instructions = """
GhydraMCP allows interacting with multiple Ghidra SRE instances. Ghidra SRE is a tool for reverse engineering and analyzing binaries, e.g. malware.

First, run `discover_instances` to find open Ghidra instances. List tools to see what GhydraMCP can do.
"""

mcp = FastMCP("GhydraMCP", instructions=instructions)

ghidra_host = os.environ.get("GHIDRA_HYDRA_HOST", DEFAULT_GHIDRA_HOST)

def get_instance_url(port: int) -> str:
    """Get URL for a Ghidra instance by port"""
    with instances_lock:
        if port in active_instances:
            return active_instances[port]["url"]

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

    is_state_changing = method.upper() in ["POST", "PUT", "PATCH", "DELETE"]
    if is_state_changing:
        check_headers = json_data.get("headers", {}) if isinstance(json_data, dict) else (headers or {})
        if not validate_origin(check_headers):
            return {
                "success": False,
                "error": "Origin not allowed",
                "status_code": 403,
                "timestamp": int(time.time() * 1000)
            }
        if json_data is not None:
             request_headers['Content-Type'] = 'application/json'
        elif data is not None:
             request_headers['Content-Type'] = 'text/plain'

    try:
        response = requests.request(
            method,
            url,
            params=params,
            json=json_data,
            data=data,
            headers=request_headers,
            timeout=10
        )

        try:
            parsed_json = response.json()
            if isinstance(parsed_json, dict) and "timestamp" not in parsed_json:
                 parsed_json["timestamp"] = int(time.time() * 1000)
            return parsed_json
        except ValueError:
            if response.ok:
                 return {
                     "success": False,
                     "error": "Received non-JSON success response from Ghidra plugin",
                     "status_code": response.status_code,
                     "response_text": response.text[:500],
                     "timestamp": int(time.time() * 1000)
                 }
            else:
                 return {
                     "success": False,
                     "error": f"HTTP {response.status_code} - Non-JSON error response",
                     "status_code": response.status_code,
                     "response_text": response.text[:500],
                     "timestamp": int(time.time() * 1000)
                 }

    except requests.exceptions.Timeout:
        return {
            "success": False,
            "error": "Request timed out",
            "status_code": 408,
            "timestamp": int(time.time() * 1000)
        }
    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "error": f"Failed to connect to Ghidra instance at {url}",
            "status_code": 503,
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
    """Make GET request to Ghidra instance"""
    return _make_request("GET", port, endpoint, params=params)

def safe_put(port: int, endpoint: str, data: dict) -> dict:
    """Make PUT request to Ghidra instance with JSON payload"""
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
        text_payload = data

    return _make_request("POST", port, endpoint, json_data=json_payload, data=text_payload, headers=headers)

# Instance management tools
@mcp.tool()
def list_instances() -> dict:
    """List all active Ghidra instances
    
    Returns:
        dict: Contains 'instances' list with port, url, project and file info for each instance
    """
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
    """Register a new Ghidra instance
    
    Args:
        port: Port number of the Ghidra instance
        url: Optional URL if different from default http://host:port
        
    Returns:
        str: Confirmation message or error
    """
    if url is None:
        url = f"http://{ghidra_host}:{port}"

    try:
        test_url = f"{url}/instances"
        response = requests.get(test_url, timeout=2)
        if not response.ok:
            return f"Error: Instance at {url} is not responding properly"

        project_info = {"url": url}

        try:
            root_url = f"{url}/"
            root_response = requests.get(root_url, timeout=1.5)  # Short timeout for root

            if root_response.ok:
                try:
                    root_data = root_response.json()

                    if "project" in root_data and root_data["project"]:
                        project_info["project"] = root_data["project"]
                    if "file" in root_data and root_data["file"]:
                        project_info["file"] = root_data["file"]

                except Exception as e:
                    print(f"Error parsing root info: {e}", file=sys.stderr)

            if not project_info.get("project") and not project_info.get("file"):
                info_url = f"{url}/info"

                try:
                    info_response = requests.get(info_url, timeout=2)
                    if info_response.ok:
                        try:
                            info_data = info_response.json()
                            if "project" in info_data and info_data["project"]:
                                project_info["project"] = info_data["project"]

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
    """Unregister a Ghidra instance
    
    Args:
        port: Port number of the instance to unregister
        
    Returns:
        str: Confirmation message or error
    """
    with instances_lock:
        if port in active_instances:
            del active_instances[port]
            return f"Unregistered instance on port {port}"
        return f"No instance found on port {port}"

@mcp.tool()
def discover_instances(host: str = null) -> dict:
    """Discover available Ghidra instances by scanning ports
    
    Args:
        host: Optional host to scan (default: configured ghidra_host)
        
    Returns:
        dict: Contains 'found' count and 'instances' list with discovery results
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
            response = requests.get(test_url, timeout=timeout)
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
def list_functions(port: int = DEFAULT_GHIDRA_PORT, 
                  offset: int = 0, 
                  limit: int = 100,
                  addr: str = None,
                  name: str = None,
                  name_contains: str = None,
                  name_matches_regex: str = None) -> dict:
    """List functions in the current program with filtering and pagination
    
    Args:
        port: Ghidra instance port (default: 8192)
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        addr: Filter by address (hexadecimal)
        name: Exact name match filter (case-sensitive)
        name_contains: Substring name filter (case-insensitive) 
        name_matches_regex: Regex name filter
        
    Returns:
        dict: {
            "result": list of function info objects,
            "size": total count,
            "offset": current offset,
            "limit": current limit,
            "_links": pagination links
        }
    """
    params = {
        "offset": offset,
        "limit": limit
    }
    if addr:
        params["addr"] = addr
    if name:
        params["name"] = name
    if name_contains:
        params["name_contains"] = name_contains 
    if name_matches_regex:
        params["name_matches_regex"] = name_matches_regex
        
    response = safe_get(port, "programs/current/functions", params)
    if isinstance(response, dict) and "error" in response:
        return response
        
    # Transform to expected format if needed
    return {
        "result": response.get("result", []),
        "size": response.get("size", len(response.get("result", []))),
        "offset": offset,
        "limit": limit,
        "_links": response.get("_links", {})
    }

@mcp.tool()
def list_classes(port: int = DEFAULT_GHIDRA_PORT, offset: int = 0, limit: int = 100) -> list:
    """List classes in the current program with pagination
    
    Args:
        port: Ghidra instance port (default: 8192)
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        
    Returns:
        list: Class names and info
    """
    return safe_get(port, "classes", {"offset": offset, "limit": limit})

@mcp.tool()
def get_function(port: int = DEFAULT_GHIDRA_PORT, name: str = "", cCode: bool = True, syntaxTree: bool = False, simplificationStyle: str = "normalize") -> dict:
    """Get decompiled code for a function
    
    Args:
        port: Ghidra instance port (default: 8192)
        name: Function name to decompile
        cCode: Return C-style code (default: True)
        syntaxTree: Include syntax tree (default: False)
        simplificationStyle: Decompiler style (default: "normalize")
        
    Returns:
        dict: Contains function name, address, signature and decompilation
    """
    return safe_get(port, f"functions/{quote(name)}", {
        "cCode": str(cCode).lower(),
        "syntaxTree": str(syntaxTree).lower(),
        "simplificationStyle": simplificationStyle
    })

@mcp.tool()
def update_function(port: int = DEFAULT_GHIDRA_PORT, name: str = "", new_name: str = "") -> str:
    """Rename a function
    
    Args:
        port: Ghidra instance port (default: 8192)
        name: Current function name
        new_name: New function name
        
    Returns:
        str: Confirmation message or error
    """
    return safe_post(port, f"functions/{quote(name)}", {"newName": new_name})

@mcp.tool()
def update_data(port: int = DEFAULT_GHIDRA_PORT, address: str = "", new_name: str = "") -> str:
    """Rename data at a memory address
    
    Args:
        port: Ghidra instance port (default: 8192)
        address: Memory address in hex format
        new_name: New name for the data
        
    Returns:
        str: Confirmation message or error
    """
    return safe_post(port, "data", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(port: int = DEFAULT_GHIDRA_PORT,
                 offset: int = 0,
                 limit: int = 100,
                 name: str = None) -> dict:
    """List memory segments with filtering and pagination
    
    Args:
        port: Ghidra instance port (default: 8192)
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        name: Filter by segment name (case-sensitive substring match)
        
    Returns:
        dict: {
            "result": list of segment objects,
            "size": total count,
            "offset": current offset,
            "limit": current limit,
            "_links": pagination links
        }
    """
    params = {
        "offset": offset,
        "limit": limit
    }
    if name:
        params["name"] = name
        
    response = safe_get(port, "programs/current/segments", params)
    if isinstance(response, dict) and "error" in response:
        return response
        
    return {
        "result": response.get("result", []),
        "size": response.get("size", len(response.get("result", []))),
        "offset": offset,
        "limit": limit,
        "_links": response.get("_links", {})
    }

@mcp.tool()
def list_symbols(port: int = DEFAULT_GHIDRA_PORT,
                offset: int = 0,
                limit: int = 100,
                addr: str = None,
                name: str = None,
                name_contains: str = None,
                type: str = None) -> dict:
    """List symbols with filtering and pagination
    
    Args:
        port: Ghidra instance port (default: 8192)
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        addr: Filter by address (hexadecimal)
        name: Exact name match filter (case-sensitive)
        name_contains: Substring name filter (case-insensitive)
        type: Filter by symbol type (e.g. "function", "data", "label")
        
    Returns:
        dict: {
            "result": list of symbol objects,
            "size": total count,
            "offset": current offset,
            "limit": current limit,
            "_links": pagination links
        }
    """
    params = {
        "offset": offset,
        "limit": limit
    }
    if addr:
        params["addr"] = addr
    if name:
        params["name"] = name
    if name_contains:
        params["name_contains"] = name_contains
    if type:
        params["type"] = type
        
    response = safe_get(port, "programs/current/symbols", params)
    if isinstance(response, dict) and "error" in response:
        return response
        
    return {
        "result": response.get("result", []),
        "size": response.get("size", len(response.get("result", []))),
        "offset": offset,
        "limit": limit,
        "_links": response.get("_links", {})
    }

@mcp.tool()
def list_imports(port: int = DEFAULT_GHIDRA_PORT, offset: int = 0, limit: int = 100) -> dict:
    """List imported symbols with pagination
    
    Args:
        port: Ghidra instance port (default: 8192)
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        
    Returns:
        dict: {
            "result": list of imported symbols,
            "size": total count,
            "offset": current offset,
            "limit": current limit,
            "_links": pagination links
        }
    """
    response = safe_get(port, "programs/current/symbols/imports", {"offset": offset, "limit": limit})
    if isinstance(response, dict) and "error" in response:
        return response
        
    return {
        "result": response.get("result", []),
        "size": response.get("size", len(response.get("result", []))),
        "offset": offset,
        "limit": limit,
        "_links": response.get("_links", {})
    }

@mcp.tool()
def list_exports(port: int = DEFAULT_GHIDRA_PORT, offset: int = 0, limit: int = 100) -> dict:
    """List exported symbols with pagination
    
    Args:
        port: Ghidra instance port (default: 8192)
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        
    Returns:
        dict: {
            "result": list of exported symbols,
            "size": total count,
            "offset": current offset,
            "limit": current limit,
            "_links": pagination links
        }
    """
    response = safe_get(port, "programs/current/symbols/exports", {"offset": offset, "limit": limit})
    if isinstance(response, dict) and "error" in response:
        return response
        
    return {
        "result": response.get("result", []),
        "size": response.get("size", len(response.get("result", []))),
        "offset": offset,
        "limit": limit,
        "_links": response.get("_links", {})
    }

@mcp.tool()
def list_namespaces(port: int = DEFAULT_GHIDRA_PORT, offset: int = 0, limit: int = 100) -> list:
    """List namespaces with pagination
    
    Args:
        port: Ghidra instance port (default: 8192)
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        
    Returns:
        list: Namespace information strings
    """
    return safe_get(port, "namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(port: int = DEFAULT_GHIDRA_PORT, 
                   offset: int = 0, 
                   limit: int = 100,
                   addr: str = None,
                   name: str = None,
                   name_contains: str = None,
                   type: str = None) -> dict:
    """List defined data items with filtering and pagination
    
    Args:
        port: Ghidra instance port (default: 8192)
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        addr: Filter by address (hexadecimal)
        name: Exact name match filter (case-sensitive)
        name_contains: Substring name filter (case-insensitive)
        type: Filter by data type (e.g. "string", "dword")
        
    Returns:
        dict: {
            "result": list of data item objects,
            "size": total count,
            "offset": current offset,
            "limit": current limit,
            "_links": pagination links
        }
    """
    params = {
        "offset": offset,
        "limit": limit
    }
    if addr:
        params["addr"] = addr
    if name:
        params["name"] = name
    if name_contains:
        params["name_contains"] = name_contains
    if type:
        params["type"] = type
        
    response = safe_get(port, "programs/current/data", params)
    if isinstance(response, dict) and "error" in response:
        return response
        
    return {
        "result": response.get("result", []),
        "size": response.get("size", len(response.get("result", []))),
        "offset": offset,
        "limit": limit,
        "_links": response.get("_links", {})
    }

@mcp.tool()
def search_functions_by_name(port: int = DEFAULT_GHIDRA_PORT, query: str = "", offset: int = 0, limit: int = 100) -> list:
    """Search functions by name with pagination
    
    Args:
        port: Ghidra instance port (default: 8192)
        query: Search string for function names
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        
    Returns:
        list: Matching function info or error if query empty
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get(port, "functions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def read_memory(port: int = DEFAULT_GHIDRA_PORT, 
               address: str = "",
               length: int = 16,
               format: str = "hex") -> dict:
    """Read bytes from memory
    
    Args:
        port: Ghidra instance port (default: 8192)
        address: Memory address in hex format
        length: Number of bytes to read (default: 16)
        format: Output format - "hex", "base64", or "string" (default: "hex")
        
    Returns:
        dict: {
            "address": original address,
            "length": bytes read,
            "format": output format,
            "bytes": the memory contents,
            "timestamp": response timestamp
        }
    """
    if not address:
        return {
            "success": False,
            "error": "Address parameter is required",
            "timestamp": int(time.time() * 1000)
        }
        
    response = safe_get(port, "programs/current/memory", {
        "address": address,
        "length": length,
        "format": format
    })
    
    if isinstance(response, dict) and "error" in response:
        return response
        
    return {
        "address": address,
        "length": length,
        "format": format,
        "bytes": response.get("result", ""),
        "timestamp": response.get("timestamp", int(time.time() * 1000))
    }

@mcp.tool()
def write_memory(port: int = DEFAULT_GHIDRA_PORT,
                address: str = "",
                bytes: str = "",
                format: str = "hex") -> dict:
    """Write bytes to memory (use with caution)
    
    Args:
        port: Ghidra instance port (default: 8192)
        address: Memory address in hex format
        bytes: Data to write (format depends on 'format' parameter)
        format: Input format - "hex", "base64", or "string" (default: "hex")
        
    Returns:
        dict: Operation result with success status
    """
    if not address or not bytes:
        return {
            "success": False,
            "error": "Address and bytes parameters are required",
            "timestamp": int(time.time() * 1000)
        }
        
    return safe_post(port, "programs/current/memory", {
        "address": address,
        "bytes": bytes,
        "format": format
    })

@mcp.tool()
def get_function_by_address(port: int = DEFAULT_GHIDRA_PORT, address: str = "") -> dict:
    """Get function details by memory address
    
    Args:
        port: Ghidra instance port (default: 8192)
        address: Memory address in hex format
        
    Returns:
        dict: Contains function name, address, signature and decompilation
    """
    return safe_get(port, "get_function_by_address", {"address": address})

@mcp.tool()
def get_current_address(port: int = DEFAULT_GHIDRA_PORT) -> dict:
    """Get the address currently selected in Ghidra's UI

    Args:
        port: Ghidra instance port (default: 8192)

    Returns:
        Dict containing:
        - success: boolean indicating success
        - result: object with address field
        - error: error message if failed
        - timestamp: timestamp of response
    """
    response = safe_get(port, "get_current_address")
    if isinstance(response, dict) and "success" in response:
        return response
    return {
        "success": False,
        "error": "Unexpected response format from Ghidra plugin",
        "timestamp": int(time.time() * 1000),
        "port": port
    }

@mcp.tool()
def list_xrefs(port: int = DEFAULT_GHIDRA_PORT,
              to_addr: str = None,
              from_addr: str = None,
              type: str = None,
              offset: int = 0,
              limit: int = 100) -> dict:
    """List cross-references with filtering and pagination
    
    Args:
        port: Ghidra instance port (default: 8192)
        to_addr: Filter references to this address (hexadecimal)
        from_addr: Filter references from this address (hexadecimal)  
        type: Filter by reference type (e.g. "CALL", "READ", "WRITE")
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        
    Returns:
        dict: {
            "result": list of xref objects,
            "size": total count,
            "offset": current offset,
            "limit": current limit,
            "_links": pagination links
        }
    """
    params = {
        "offset": offset,
        "limit": limit
    }
    if to_addr:
        params["to_addr"] = to_addr
    if from_addr:
        params["from_addr"] = from_addr
    if type:
        params["type"] = type
        
    response = safe_get(port, "programs/current/xrefs", params)
    if isinstance(response, dict) and "error" in response:
        return response
        
    return {
        "result": response.get("result", []),
        "size": response.get("size", len(response.get("result", []))),
        "offset": offset,
        "limit": limit,
        "_links": response.get("_links", {})
    }

@mcp.tool()
def analyze_program(port: int = DEFAULT_GHIDRA_PORT, 
                   analysis_options: dict = None) -> dict:
    """Run analysis on the current program
    
    Args:
        port: Ghidra instance port (default: 8192)
        analysis_options: Dictionary of analysis options to enable/disable
                         (e.g. {"functionRecovery": True, "dataRefs": False})
                         None means use default analysis options
                         
    Returns:
        dict: Analysis operation result with status
    """
    return safe_post(port, "programs/current/analysis", analysis_options or {})

@mcp.tool()
def get_callgraph(port: int = DEFAULT_GHIDRA_PORT,
                 function: str = None,
                 max_depth: int = 3) -> dict:
    """Get function call graph visualization data
    
    Args:
        port: Ghidra instance port (default: 8192)
        function: Starting function name (None starts from entry point)
        max_depth: Maximum call depth to analyze (default: 3)
        
    Returns:
        dict: Graph data in DOT format with nodes and edges
    """
    params = {"max_depth": max_depth}
    if function:
        params["function"] = function
        
    return safe_get(port, "programs/current/analysis/callgraph", params)

@mcp.tool()
def get_dataflow(port: int = DEFAULT_GHIDRA_PORT,
                address: str = "",
                direction: str = "forward",
                max_steps: int = 50) -> dict:
    """Perform data flow analysis from an address
    
    Args:
        port: Ghidra instance port (default: 8192)
        address: Starting address in hex format
        direction: "forward" or "backward" (default: "forward")
        max_steps: Maximum analysis steps (default: 50)
        
    Returns:
        dict: Data flow analysis results
    """
    return safe_get(port, "programs/current/analysis/dataflow", {
        "address": address,
        "direction": direction,
        "max_steps": max_steps
    })

@mcp.tool()
def get_current_function(port: int = DEFAULT_GHIDRA_PORT) -> dict:
    """Get the function currently selected in Ghidra's UI

    Args:
        port: Ghidra instance port (default: 8192)
        
    Returns:
        Dict containing:
        - success: boolean indicating success
        - result: object with name, address and signature fields
        - error: error message if failed
        - timestamp: timestamp of response
    """
    response = safe_get(port, "get_current_function")
    if isinstance(response, dict) and "success" in response:
        return response
    return {
        "success": False,
        "error": "Unexpected response format from Ghidra plugin",
        "timestamp": int(time.time() * 1000),
        "port": port
    }

@mcp.tool()
def decompile_function_by_address(port: int = DEFAULT_GHIDRA_PORT, address: str = "", cCode: bool = True, syntaxTree: bool = False, simplificationStyle: str = "normalize") -> dict:
    """Decompile function at memory address
    
    Args:
        port: Ghidra instance port (default: 8192)
        address: Memory address in hex format
        cCode: Return C-style code (default: True)
        syntaxTree: Include syntax tree (default: False)
        simplificationStyle: Decompiler style (default: "normalize")
        
    Returns:
        dict: Contains decompiled code in 'result.decompilation'
    """
    return safe_get(port, "decompile_function", {
        "address": address,
        "cCode": str(cCode).lower(),
        "syntaxTree": str(syntaxTree).lower(),
        "simplificationStyle": simplificationStyle
    })

@mcp.tool()
def disassemble_function(port: int = DEFAULT_GHIDRA_PORT, address: str = "") -> dict:
    """Get disassembly for function at address
    
    Args:
        port: Ghidra instance port (default: 8192)
        address: Memory address in hex format
        
    Returns:
        dict: Contains assembly instructions with addresses and comments
    """
    return safe_get(port, "disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(port: int = DEFAULT_GHIDRA_PORT, address: str = "", comment: str = "") -> str:
    """Add/edit decompiler comment at address
    
    Args:
        port: Ghidra instance port (default: 8192)
        address: Memory address in hex format
        comment: Comment text to add
        
    Returns:
        str: Confirmation message or error
    """
    return safe_post(port, "set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(port: int = DEFAULT_GHIDRA_PORT, address: str = "", comment: str = "") -> str:
    """Add/edit disassembly comment at address
    
    Args:
        port: Ghidra instance port (default: 8192)
        address: Memory address in hex format
        comment: Comment text to add
        
    Returns:
        str: Confirmation message or error
    """
    return safe_post(port, "set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_local_variable(port: int = DEFAULT_GHIDRA_PORT, function_address: str = "", old_name: str = "", new_name: str = "") -> str:
    """Rename local variable in function
    
    Args:
        port: Ghidra instance port (default: 8192)
        function_address: Function memory address in hex
        old_name: Current variable name
        new_name: New variable name
        
    Returns:
        str: Confirmation message or error
    """
    return safe_post(port, "rename_local_variable", {"functionAddress": function_address, "oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_function_by_address(port: int = DEFAULT_GHIDRA_PORT, function_address: str = "", new_name: str = "") -> str:
    """Rename function at memory address
    
    Args:
        port: Ghidra instance port (default: 8192)
        function_address: Function memory address in hex
        new_name: New function name
        
    Returns:
        str: Confirmation message or error
    """
    return safe_post(port, "rename_function_by_address", {"functionAddress": function_address, "newName": new_name})

@mcp.tool()
def set_function_prototype(port: int = DEFAULT_GHIDRA_PORT, function_address: str = "", prototype: str = "") -> str:
    """Update function signature/prototype
    
    Args:
        port: Ghidra instance port (default: 8192)
        function_address: Function memory address in hex
        prototype: New prototype string (e.g. "int func(int param1)")
        
    Returns:
        str: Confirmation message or error
    """
    return safe_post(port, "set_function_prototype", {"functionAddress": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(port: int = DEFAULT_GHIDRA_PORT, function_address: str = "", variable_name: str = "", new_type: str = "") -> str:
    """Change local variable data type
    
    Args:
        port: Ghidra instance port (default: 8192)
        function_address: Function memory address in hex
        variable_name: Variable name to modify
        new_type: New data type (e.g. "int", "char*")
        
    Returns:
        str: Confirmation message or error
    """
    return safe_post(port, "set_local_variable_type", {"functionAddress": function_address, "variableName": variable_name, "newType": new_type})

@mcp.tool()
def list_variables(port: int = DEFAULT_GHIDRA_PORT, offset: int = 0, limit: int = 100, search: str = "") -> dict:
    """List global variables with optional search
    
    Args:
        port: Ghidra instance port (default: 8192)
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        search: Optional filter for variable names
        
    Returns:
        dict: Contains variables list in 'result' field
    """
    params = {"offset": offset, "limit": limit}
    if search:
        params["search"] = search
    
    return safe_get(port, "variables", params)

@mcp.tool()
def list_function_variables(port: int = DEFAULT_GHIDRA_PORT, function: str = "") -> dict:
    """List variables in function
    
    Args:
        port: Ghidra instance port (default: 8192)
        function: Function name to list variables for
        
    Returns:
        dict: Contains variables list in 'result.variables'
    """
    if not function:
        return {"success": False, "error": "Function name is required"}

    encoded_name = quote(function)
    return safe_get(port, f"functions/{encoded_name}/variables", {})

@mcp.tool()
def rename_variable(port: int = DEFAULT_GHIDRA_PORT, function: str = "", name: str = "", new_name: str = "") -> dict:
    """Rename variable in function
    
    Args:
        port: Ghidra instance port (default: 8192)
        function: Function name containing variable
        name: Current variable name
        new_name: New variable name
        
    Returns:
        dict: Operation result
    """
    if not function or not name or not new_name:
        return {"success": False, "error": "Function, name, and new_name parameters are required"}

    encoded_function = quote(function)
    encoded_var = quote(name)
    return safe_post(port, f"functions/{encoded_function}/variables/{encoded_var}", {"newName": new_name})

@mcp.tool()
def retype_variable(port: int = DEFAULT_GHIDRA_PORT, function: str = "", name: str = "", data_type: str = "") -> dict:
    """Change variable data type in function
    
    Args:
        port: Ghidra instance port (default: 8192)
        function: Function name containing variable
        name: Variable name to modify
        data_type: New data type
        
    Returns:
        dict: Operation result
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
            _discover_instances(FULL_DISCOVERY_RANGE, timeout=0.5)

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

                for port in ports_to_remove:
                    del active_instances[port]
                    print(f"Removed unreachable instance on port {port}")
        except Exception as e:
            print(f"Error in periodic discovery: {e}")

        time.sleep(30)

if __name__ == "__main__":
    register_instance(DEFAULT_GHIDRA_PORT, f"http://{ghidra_host}:{DEFAULT_GHIDRA_PORT}")

    discover_instances()

    discovery_thread = threading.Thread(
        target=periodic_discovery,
        daemon=True,
        name="GhydraMCP-Discovery"
    )
    discovery_thread.start()

    signal.signal(signal.SIGINT, handle_sigint)
    mcp.run(transport="stdio")
