# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "mcp==1.6.0",
#     "requests==2.32.3",
# ]
# ///
# GhydraMCP Bridge for Ghidra HATEOAS API
# This script implements the MCP_BRIDGE_API.md specification
import os
import signal
import sys
import threading
import time
from threading import Lock
from typing import Dict, List, Optional, Union, Any
from urllib.parse import quote, urlencode
from urllib.parse import urlparse

import requests
from mcp.server.fastmcp import FastMCP

# Allowed origins for CORS/CSRF protection
ALLOWED_ORIGINS = os.environ.get(
    "GHIDRA_ALLOWED_ORIGINS", "http://localhost").split(",")

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
        # No origin header - allow (browser same-origin policy applies)
        return True

    # Parse origin to get scheme+hostname
    try:
        parsed = urlparse(origin)
        origin_base = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            origin_base += f":{parsed.port}"
    except:
        return False

    return origin_base in ALLOWED_ORIGINS


def _make_request(method: str, port: int, endpoint: str, params: dict = None, 
                 json_data: dict = None, data: str = None, 
                 headers: dict = None) -> dict:
    """Internal helper to make HTTP requests and handle common errors."""
    url = f"{get_instance_url(port)}/{endpoint}"
    request_headers = {'Accept': 'application/json'}
    if headers:
        request_headers.update(headers)

    is_state_changing = method.upper() in ["POST", "PUT", "PATCH", "DELETE"]
    if is_state_changing:
        check_headers = json_data.get("headers", {}) if isinstance(
            json_data, dict) else (headers or {})
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
            # Add timestamp if not present
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


def safe_post(port: int, endpoint: str, data: Union[dict, str]) -> dict:
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


def safe_patch(port: int, endpoint: str, data: dict) -> dict:
    """Perform a PATCH request to a specific Ghidra instance with JSON payload"""
    headers = data.pop("headers", None) if isinstance(data, dict) else None
    return _make_request("PATCH", port, endpoint, json_data=data, headers=headers)


def safe_delete(port: int, endpoint: str) -> dict:
    """Perform a DELETE request to a specific Ghidra instance"""
    return _make_request("DELETE", port, endpoint)


def simplify_response(response: dict) -> dict:
    """
    Simplify HATEOAS response data for easier AI agent consumption
    - Removes _links from result entries
    - Flattens nested structures when appropriate
    - Preserves important metadata
    - Converts structured data like disassembly to text for easier consumption
    """
    if not isinstance(response, dict):
        return response

    # Make a copy to avoid modifying the original
    result = response.copy()
    
    # Simplify the main result data if present
    if "result" in result:
        # Handle array results
        if isinstance(result["result"], list):
            simplified_items = []
            for item in result["result"]:
                if isinstance(item, dict):
                    # Remove HATEOAS links from individual items
                    item_copy = item.copy()
                    item_copy.pop("_links", None)
                    simplified_items.append(item_copy)
                else:
                    simplified_items.append(item)
            result["result"] = simplified_items
        
        # Handle object results
        elif isinstance(result["result"], dict):
            result_copy = result["result"].copy()
            # Remove links from result object
            result_copy.pop("_links", None)
            
            # Special case for disassembly - convert to text for easier consumption
            if "instructions" in result_copy and isinstance(result_copy["instructions"], list):
                disasm_text = ""
                for instr in result_copy["instructions"]:
                    if isinstance(instr, dict):
                        addr = instr.get("address", "")
                        mnemonic = instr.get("mnemonic", "")
                        operands = instr.get("operands", "")
                        bytes_str = instr.get("bytes", "")
                        
                        # Format: address: bytes  mnemonic operands
                        disasm_text += f"{addr}: {bytes_str.ljust(10)}  {mnemonic} {operands}\n"
                
                # Add the text representation while preserving the original structured data
                result_copy["disassembly_text"] = disasm_text
            
            # Special case for decompiled code - make sure it's directly accessible
            if "ccode" in result_copy:
                result_copy["decompiled_text"] = result_copy["ccode"]
            elif "decompiled" in result_copy:
                result_copy["decompiled_text"] = result_copy["decompiled"]
            
            result["result"] = result_copy
    
    # Remove HATEOAS links from the top level
    result.pop("_links", None)
    
    return result


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
        # Check for HATEOAS API by checking plugin-version endpoint
        test_url = f"{url}/plugin-version"
        response = requests.get(test_url, timeout=2)
        
        if not response.ok:
            return f"Error: Instance at {url} is not responding properly to HATEOAS API"

        project_info = {"url": url}

        try:
            # Get program info from HATEOAS API
            info_url = f"{url}/program"
            
            try:
                info_response = requests.get(info_url, timeout=2)
                if info_response.ok:
                    try:
                        info_data = info_response.json()
                        if "result" in info_data:
                            result = info_data["result"]
                            if isinstance(result, dict):
                                project_info["project"] = result.get("project", "")
                                project_info["file"] = result.get("name", "")
                                project_info["path"] = result.get("path", "")
                                project_info["language_id"] = result.get("language_id", "")
                                project_info["compiler_spec_id"] = result.get("compiler_spec_id", "")
                                project_info["image_base"] = result.get("image_base", "")
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
def discover_instances(host: str = None) -> dict:
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
            # Try HATEOAS API via plugin-version endpoint
            test_url = f"{url}/plugin-version"
            response = requests.get(test_url, timeout=timeout)
            if response.ok:
                result = register_instance(port, url)
                found_instances.append(
                    {"port": port, "url": url, "result": result})
        except requests.exceptions.RequestException:
            # Instance not available, just continue
            continue

    return {
        "found": len(found_instances),
        "instances": found_instances
    }


@mcp.tool()
def get_plugin_version(port: int = DEFAULT_GHIDRA_PORT) -> dict:
    """Get version information for the Ghidra plugin
    
    Args:
        port: Ghidra instance port (default: 8192)
        
    Returns:
        dict: Plugin and API version information
    """
    response = safe_get(port, "plugin-version")
    return simplify_response(response)


@mcp.tool()
def get_program_info(port: int = DEFAULT_GHIDRA_PORT) -> dict:
    """Get detailed information about the current program
    
    Args:
        port: Ghidra instance port (default: 8192)
        
    Returns:
        dict: Contains metadata about the current program including name, 
             architecture, memory layout, compiler, etc.
    """
    response = safe_get(port, "program")
    return simplify_response(response)


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
            "limit": current limit
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

    response = safe_get(port, "functions", params)
    simplified = simplify_response(response)
    
    # Ensure we maintain pagination metadata
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    
    return simplified


@mcp.tool()
def get_function(port: int = DEFAULT_GHIDRA_PORT, 
                address: str = None,
                name: str = None) -> dict:
    """Get details for a function by address or name
    
    Args:
        port: Ghidra instance port (default: 8192)
        address: Function address in hex format (mutually exclusive with name)
        name: Function name (mutually exclusive with address)
        
    Returns:
        dict: Contains function name, address, signature and other details
    """
    if not address and not name:
        return {
            "success": False,
            "error": "Either address or name parameter is required",
            "timestamp": int(time.time() * 1000)
        }
    
    if address:
        endpoint = f"functions/{address}"
    else:
        endpoint = f"functions/by-name/{quote(name)}"
    
    response = safe_get(port, endpoint)
    return simplify_response(response)


@mcp.tool()
def decompile_function(port: int = DEFAULT_GHIDRA_PORT, 
                      address: str = None,
                      name: str = None,
                      syntax_tree: bool = False, 
                      style: str = "normalize") -> dict:
    """Get decompiled code for a function by address or name
    
    Args:
        port: Ghidra instance port (default: 8192)
        address: Function address in hex format (mutually exclusive with name)
        name: Function name (mutually exclusive with address)
        syntax_tree: Include syntax tree (default: False)
        style: Decompiler style (default: "normalize")
        
    Returns:
        dict: Contains function information and decompiled code
    """
    if not address and not name:
        return {
            "success": False,
            "error": "Either address or name parameter is required",
            "timestamp": int(time.time() * 1000)
        }
    
    params = {
        "syntax_tree": str(syntax_tree).lower(),
        "style": style
    }
    
    if address:
        endpoint = f"functions/{address}/decompile"
    else:
        endpoint = f"functions/by-name/{quote(name)}/decompile"
    
    response = safe_get(port, endpoint, params)
    simplified = simplify_response(response)
    
    # For AI consumption, make the decompiled code more directly accessible
    if "result" in simplified and isinstance(simplified["result"], dict):
        if "decompiled" in simplified["result"]:
            simplified["decompiled_code"] = simplified["result"]["decompiled"]
        elif "ccode" in simplified["result"]:
            simplified["decompiled_code"] = simplified["result"]["ccode"]
        elif "decompiled_text" in simplified["result"]:
            simplified["decompiled_code"] = simplified["result"]["decompiled_text"]
    
    return simplified


@mcp.tool()
def disassemble_function(port: int = DEFAULT_GHIDRA_PORT, 
                        address: str = None,
                        name: str = None) -> dict:
    """Get disassembly for a function by address or name
    
    Args:
        port: Ghidra instance port (default: 8192)
        address: Function address in hex format (mutually exclusive with name)
        name: Function name (mutually exclusive with address)
        
    Returns:
        dict: Contains function information and disassembly text
    """
    if not address and not name:
        return {
            "success": False,
            "error": "Either address or name parameter is required",
            "timestamp": int(time.time() * 1000)
        }
    
    if address:
        endpoint = f"functions/{address}/disassembly"
    else:
        endpoint = f"functions/by-name/{quote(name)}/disassembly"
    
    response = safe_get(port, endpoint)
    simplified = simplify_response(response)
    
    # For AI consumption, add a plain text version of the disassembly if not already present
    if "result" in simplified and isinstance(simplified["result"], dict):
        if "instructions" in simplified["result"] and isinstance(simplified["result"]["instructions"], list):
            if "disassembly_text" not in simplified["result"]:
                instr_list = simplified["result"]["instructions"]
                disasm_text = ""
                for instr in instr_list:
                    if isinstance(instr, dict):
                        addr = instr.get("address", "")
                        mnemonic = instr.get("mnemonic", "")
                        operands = instr.get("operands", "")
                        bytes_str = instr.get("bytes", "")
                        
                        # Format: address: bytes  mnemonic operands
                        disasm_text += f"{addr}: {bytes_str.ljust(10)}  {mnemonic} {operands}\n"
                
                simplified["result"]["disassembly_text"] = disasm_text
                # Also make it more directly accessible
                simplified["disassembly_text"] = disasm_text
    
    return simplified


@mcp.tool()
def get_function_variables(port: int = DEFAULT_GHIDRA_PORT, 
                          address: str = None,
                          name: str = None) -> dict:
    """Get variables for a function by address or name
    
    Args:
        port: Ghidra instance port (default: 8192)
        address: Function address in hex format (mutually exclusive with name)
        name: Function name (mutually exclusive with address)
        
    Returns:
        dict: Contains function information and list of variables
    """
    if not address and not name:
        return {
            "success": False,
            "error": "Either address or name parameter is required",
            "timestamp": int(time.time() * 1000)
        }
    
    if address:
        endpoint = f"functions/{address}/variables"
    else:
        endpoint = f"functions/by-name/{quote(name)}/variables"
    
    response = safe_get(port, endpoint)
    return simplify_response(response)


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
            "result": list of segment objects with properties including name, start, end, size, 
                      permissions (readable, writable, executable), and initialized status,
            "size": total count of segments matching the filter,
            "offset": current offset in pagination,
            "limit": current limit for pagination
        }
    """
    params = {
        "offset": offset,
        "limit": limit
    }
    if name:
        params["name"] = name

    response = safe_get(port, "segments", params)
    simplified = simplify_response(response)
    
    # Ensure we maintain pagination metadata
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    
    return simplified


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
            "limit": current limit
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

    response = safe_get(port, "symbols", params)
    simplified = simplify_response(response)
    
    # Ensure we maintain pagination metadata
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    
    return simplified


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
            "limit": current limit
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

    response = safe_get(port, "data", params)
    simplified = simplify_response(response)
    
    # Ensure we maintain pagination metadata
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    
    return simplified


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
            "bytes": the memory contents as a string in the specified format,
            "timestamp": response timestamp
        }
    """
    if not address:
        return {
            "success": False,
            "error": "Address parameter is required",
            "timestamp": int(time.time() * 1000)
        }

    params = {
        "length": length,
        "format": format
    }
    
    response = safe_get(port, f"memory/{address}", params)
    simplified = simplify_response(response)
    
    # Ensure the result is simple and directly usable
    if "result" in simplified and isinstance(simplified["result"], dict):
        bytes_data = simplified["result"].get("bytes", "")
        memory_info = {
            "address": address,
            "length": length,
            "format": format,
            "bytes": bytes_data,
            "timestamp": simplified.get("timestamp", int(time.time() * 1000))
        }
        return memory_info
    
    return simplified


@mcp.tool()
def write_memory(port: int = DEFAULT_GHIDRA_PORT,
                address: str = "",
                bytes_data: str = "",
                format: str = "hex") -> dict:
    """Write bytes to memory (use with caution)
    
    Args:
        port: Ghidra instance port (default: 8192)
        address: Memory address in hex format
        bytes_data: Data to write (format depends on 'format' parameter)
        format: Input format - "hex", "base64", or "string" (default: "hex")
    
    Returns:
        dict: Operation result with success status containing:
             - address: the target memory address
             - length: number of bytes written
             - bytesWritten: confirmation of bytes written
    """
    if not address or not bytes_data:
        return {
            "success": False,
            "error": "Address and bytes parameters are required",
            "timestamp": int(time.time() * 1000)
        }

    payload = {
        "bytes": bytes_data,
        "format": format
    }
    
    response = safe_patch(port, f"memory/{address}", payload)
    return simplify_response(response)


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
            "result": list of xref objects with from_addr, to_addr, type, from_function, to_function fields,
            "size": total number of xrefs matching the filter,
            "offset": current offset for pagination,
            "limit": current limit for pagination,
            "xrefs": simplified array of cross-references for AI consumption
        }
    """
    # At least one of the address parameters must be provided
    if not to_addr and not from_addr:
        return {
            "success": False,
            "error": "Either to_addr or from_addr parameter is required",
            "timestamp": int(time.time() * 1000)
        }
    
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

    response = safe_get(port, "xrefs", params)
    simplified = simplify_response(response)
    
    # Ensure we maintain pagination metadata
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
        
        # Create a simplified, flattened view of references for AI consumption
        if "result" in simplified and isinstance(simplified["result"], dict) and "references" in simplified["result"]:
            references = simplified["result"]["references"]
            flat_refs = []
            
            for ref in references:
                flat_ref = {
                    "from_addr": ref.get("from_addr"),
                    "to_addr": ref.get("to_addr"),
                    "type": ref.get("refType")
                }
                
                # Add source function info if available
                if "from_function" in ref and isinstance(ref["from_function"], dict):
                    flat_ref["from_function"] = ref["from_function"].get("name")
                    flat_ref["from_function_addr"] = ref["from_function"].get("address")
                
                # Add target function info if available
                if "to_function" in ref and isinstance(ref["to_function"], dict):
                    flat_ref["to_function"] = ref["to_function"].get("name")
                    flat_ref["to_function_addr"] = ref["to_function"].get("address")
                
                # Add symbol info if available
                if "from_symbol" in ref:
                    flat_ref["from_symbol"] = ref["from_symbol"]
                if "to_symbol" in ref:
                    flat_ref["to_symbol"] = ref["to_symbol"]
                
                # Add instruction text if available
                if "from_instruction" in ref:
                    flat_ref["from_instruction"] = ref["from_instruction"]
                if "to_instruction" in ref:
                    flat_ref["to_instruction"] = ref["to_instruction"]
                
                flat_refs.append(flat_ref)
            
            # Add the simplified references
            simplified["xrefs"] = flat_refs
            
            # Create a text representation for easier consumption
            text_refs = []
            for ref in flat_refs:
                from_func = f"[{ref.get('from_function', '??')}]" if "from_function" in ref else ""
                to_func = f"[{ref.get('to_function', '??')}]" if "to_function" in ref else ""
                
                line = f"{ref.get('from_addr')} {from_func} -> {ref.get('to_addr')} {to_func} ({ref.get('type', '??')})"
                text_refs.append(line)
            
            simplified["xrefs_text"] = "\n".join(text_refs)
    
    return simplified


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
    response = safe_get(port, "address")
    return simplify_response(response)


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
    response = safe_get(port, "function")
    return simplify_response(response)


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
        dict: Analysis operation result with status containing:
             - program: program name
             - analysis_triggered: boolean indicating if analysis was successfully started
             - message: status message
    """
    response = safe_post(port, "analysis", analysis_options or {})
    return simplify_response(response)


@mcp.tool()
def create_function(port: int = DEFAULT_GHIDRA_PORT,
                   address: str = "") -> dict:
    """Create a new function at the specified address
    
    Args:
        port: Ghidra instance port (default: 8192)
        address: Memory address in hex format where function starts
        
    Returns:
        dict: Operation result with the created function information
    """
    if not address:
        return {
            "success": False,
            "error": "Address parameter is required",
            "timestamp": int(time.time() * 1000)
        }
    
    payload = {
        "address": address
    }
    
    response = safe_post(port, "functions", payload)
    return simplify_response(response)


@mcp.tool()
def rename_function(port: int = DEFAULT_GHIDRA_PORT,
                   address: str = None,
                   name: str = None,
                   new_name: str = "") -> dict:
    """Rename a function
    
    Args:
        port: Ghidra instance port (default: 8192)
        address: Function address in hex format (mutually exclusive with name)
        name: Current function name (mutually exclusive with address)
        new_name: New function name
        
    Returns:
        dict: Operation result with the updated function information
    """
    if not (address or name) or not new_name:
        return {
            "success": False,
            "error": "Either address or name, and new_name parameters are required",
            "timestamp": int(time.time() * 1000)
        }
    
    payload = {
        "name": new_name
    }
    
    if address:
        endpoint = f"functions/{address}"
    else:
        endpoint = f"functions/by-name/{quote(name)}"
    
    response = safe_patch(port, endpoint, payload)
    return simplify_response(response)


@mcp.tool()
def set_function_signature(port: int = DEFAULT_GHIDRA_PORT,
                          address: str = None,
                          name: str = None,
                          signature: str = "") -> dict:
    """Set function signature/prototype
    
    Args:
        port: Ghidra instance port (default: 8192)
        address: Function address in hex format (mutually exclusive with name)
        name: Function name (mutually exclusive with address)
        signature: New function signature (e.g., "int func(char *data, int size)")
        
    Returns:
        dict: Operation result with the updated function information
    """
    if not (address or name) or not signature:
        return {
            "success": False,
            "error": "Either address or name, and signature parameters are required",
            "timestamp": int(time.time() * 1000)
        }
    
    payload = {
        "signature": signature
    }
    
    if address:
        endpoint = f"functions/{address}"
    else:
        endpoint = f"functions/by-name/{quote(name)}"
    
    response = safe_patch(port, endpoint, payload)
    return simplify_response(response)


@mcp.tool()
def rename_variable(port: int = DEFAULT_GHIDRA_PORT,
                   function_address: str = None,
                   function_name: str = None,
                   variable_name: str = "",
                   new_name: str = "") -> dict:
    """Rename a variable in a function
    
    Args:
        port: Ghidra instance port (default: 8192)
        function_address: Function address in hex format (mutually exclusive with function_name)
        function_name: Function name (mutually exclusive with function_address)
        variable_name: Current variable name
        new_name: New variable name
        
    Returns:
        dict: Operation result with the updated variable information
    """
    if not (function_address or function_name) or not variable_name or not new_name:
        return {
            "success": False,
            "error": "Function identifier (address or name), variable_name, and new_name parameters are required",
            "timestamp": int(time.time() * 1000)
        }
    
    payload = {
        "name": new_name
    }
    
    if function_address:
        endpoint = f"functions/{function_address}/variables/{variable_name}"
    else:
        endpoint = f"functions/by-name/{quote(function_name)}/variables/{variable_name}"
    
    response = safe_patch(port, endpoint, payload)
    return simplify_response(response)


@mcp.tool()
def set_variable_type(port: int = DEFAULT_GHIDRA_PORT,
                     function_address: str = None,
                     function_name: str = None,
                     variable_name: str = "",
                     data_type: str = "") -> dict:
    """Change the data type of a variable in a function
    
    Args:
        port: Ghidra instance port (default: 8192)
        function_address: Function address in hex format (mutually exclusive with function_name)
        function_name: Function name (mutually exclusive with function_address)
        variable_name: Variable name
        data_type: New data type (e.g. "int", "char *")
        
    Returns:
        dict: Operation result with the updated variable information
    """
    if not (function_address or function_name) or not variable_name or not data_type:
        return {
            "success": False,
            "error": "Function identifier (address or name), variable_name, and data_type parameters are required",
            "timestamp": int(time.time() * 1000)
        }
    
    payload = {
        "data_type": data_type
    }
    
    if function_address:
        endpoint = f"functions/{function_address}/variables/{variable_name}"
    else:
        endpoint = f"functions/by-name/{quote(function_name)}/variables/{variable_name}"
    
    response = safe_patch(port, endpoint, payload)
    return simplify_response(response)


@mcp.tool()
def create_data(port: int = DEFAULT_GHIDRA_PORT,
               address: str = "",
               data_type: str = "",
               size: int = None) -> dict:
    """Define a new data item at the specified address
    
    Args:
        port: Ghidra instance port (default: 8192)
        address: Memory address in hex format
        data_type: Data type (e.g. "string", "dword", "byte")
        size: Optional size in bytes for the data item
        
    Returns:
        dict: Operation result with the created data information
    """
    if not address or not data_type:
        return {
            "success": False,
            "error": "Address and data_type parameters are required",
            "timestamp": int(time.time() * 1000)
        }
    
    payload = {
        "address": address,
        "type": data_type
    }
    
    if size is not None:
        payload["size"] = size
    
    response = safe_post(port, "data", payload)
    return simplify_response(response)


@mcp.tool()
def list_namespaces(port: int = DEFAULT_GHIDRA_PORT,
                   offset: int = 0,
                   limit: int = 100) -> dict:
    """List namespaces with pagination
    
    Args:
        port: Ghidra instance port (default: 8192)
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        
    Returns:
        dict: Contains list of namespaces with pagination information
    """
    params = {
        "offset": offset,
        "limit": limit
    }
    
    response = safe_get(port, "namespaces", params)
    simplified = simplify_response(response)
    
    # Ensure we maintain pagination metadata
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    
    return simplified


@mcp.tool()
def get_callgraph(port: int = DEFAULT_GHIDRA_PORT,
                 function: str = None,
                 max_depth: int = 3) -> dict:
    """Get function call graph visualization data
    
    Args:
        port: Ghidra instance port (default: 8192)
        function: Starting function name or address (None starts from entry point)
        max_depth: Maximum call depth to analyze (default: 3)
        
    Returns:
        dict: Graph data with:
             - root: name of the starting function
             - root_address: address of the starting function
             - max_depth: depth limit used for graph generation
             - nodes: list of function nodes in the graph (with id, name, address)
             - edges: list of call relationships between functions
    """
    params = {"max_depth": max_depth}
    if function:
        params["function"] = function
    
    response = safe_get(port, "analysis/callgraph", params)
    return simplify_response(response)


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
    if not address:
        return {
            "success": False,
            "error": "Address parameter is required",
            "timestamp": int(time.time() * 1000)
        }
    
    params = {
        "address": address,
        "direction": direction,
        "max_steps": max_steps
    }
    
    response = safe_get(port, "analysis/dataflow", params)
    return simplify_response(response)


@mcp.tool()
def set_comment(port: int = DEFAULT_GHIDRA_PORT,
               address: str = "",
               comment: str = "",
               comment_type: str = "plate") -> dict:
    """Set a comment at the specified address
    
    Args:
        port: Ghidra instance port (default: 8192)
        address: Memory address in hex format
        comment: Comment text
        comment_type: Type of comment - 
                     "plate" (disassembly), 
                     "pre" (pre-function), 
                     "post" (post-function),
                     "eol" (end of line),
                     "repeatable" (shows each time referenced)
                     (default: "plate")
        
    Returns:
        dict: Operation result
    """
    if not address:
        return {
            "success": False,
            "error": "Address parameter is required",
            "timestamp": int(time.time() * 1000)
        }
    
    payload = {
        "comment": comment
    }
    
    response = safe_post(port, f"memory/{address}/comments/{comment_type}", payload)
    return simplify_response(response)


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
                        # Check HATEOAS API via plugin-version endpoint
                        response = requests.get(f"{url}/plugin-version", timeout=1)
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
    register_instance(DEFAULT_GHIDRA_PORT,
                      f"http://{ghidra_host}:{DEFAULT_GHIDRA_PORT}")

    discover_instances()

    discovery_thread = threading.Thread(
        target=periodic_discovery,
        daemon=True,
        name="GhydraMCP-Discovery"
    )
    discovery_thread.start()

    signal.signal(signal.SIGINT, handle_sigint)
    mcp.run(transport="stdio")