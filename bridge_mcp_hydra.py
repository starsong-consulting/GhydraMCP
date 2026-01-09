# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "mcp==1.6.0",
#     "requests==2.32.3",
# ]
# ///
# GhydraMCP Bridge for Ghidra HATEOAS API - Optimized for MCP integration
# Provides namespaced tools for interacting with Ghidra's reverse engineering capabilities
import functools
import os
import signal
import sys
import threading
import time
from threading import Lock
from typing import Dict, List, Optional, Union, Any
from urllib.parse import quote, urlencode, urlparse

import requests
from mcp.server.fastmcp import FastMCP

# ================= Core Infrastructure =================

ALLOWED_ORIGINS = os.environ.get(
    "GHIDRA_ALLOWED_ORIGINS", "http://localhost").split(",")

active_instances: Dict[int, dict] = {}
instances_lock = Lock()
DEFAULT_GHIDRA_PORT = 8192
DEFAULT_GHIDRA_HOST = "localhost"
QUICK_DISCOVERY_RANGE = range(DEFAULT_GHIDRA_PORT, DEFAULT_GHIDRA_PORT+10)
FULL_DISCOVERY_RANGE = range(DEFAULT_GHIDRA_PORT, DEFAULT_GHIDRA_PORT+20)

BRIDGE_VERSION = "v2.2.0"
REQUIRED_API_VERSION = 2020

current_instance_port = DEFAULT_GHIDRA_PORT

instructions = """
GhydraMCP allows interacting with multiple Ghidra SRE instances. Ghidra SRE is a tool for reverse engineering and analyzing binaries, e.g. malware.

First, run `instances_list()` to see all available Ghidra instances (automatically discovers instances on the default host).
Then use `instances_use(port)` to set your working instance.

Note: Use `instances_discover(host)` only if you need to scan a different host.

The API is organized into namespaces for different types of operations:
- instances_* : For managing Ghidra instances
- functions_* : For working with functions
- data_* : For working with data items
- structs_* : For creating and managing struct data types
- memory_* : For memory access
- xrefs_* : For cross-references
- analysis_* : For program analysis
"""

mcp = FastMCP("GhydraMCP", version=BRIDGE_VERSION, instructions=instructions)

ghidra_host = os.environ.get("GHIDRA_HYDRA_HOST", DEFAULT_GHIDRA_HOST)

# Helper function to get the current instance or validate a specific port
def _get_instance_port(port=None):
    """Internal helper to get the current instance port or validate a specific port"""
    port = port or current_instance_port
    # Validate that the instance exists and is active
    if port not in active_instances:
        # Try to register it if not found
        register_instance(port)
        if port not in active_instances:
            raise ValueError(f"No active Ghidra instance on port {port}")
    return port

# The rest of the utility functions (HTTP helpers, etc.) remain the same...
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
    
    # Set up headers according to HATEOAS API expected format
    request_headers = {
        'Accept': 'application/json',
        'X-Request-ID': f"mcp-bridge-{int(time.time() * 1000)}"
    }
    
    if headers:
        request_headers.update(headers)

    is_state_changing = method.upper() in ["POST", "PUT", "PATCH", "DELETE"]
    if is_state_changing:
        check_headers = json_data.get("headers", {}) if isinstance(
            json_data, dict) else (headers or {})
        if not validate_origin(check_headers):
            return {
                "success": False,
                "error": {
                    "code": "ORIGIN_NOT_ALLOWED",
                    "message": "Origin not allowed for state-changing request"
                },
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
                
            # Check for HATEOAS compliant error response format and reformat if needed
            if not response.ok and isinstance(parsed_json, dict) and "success" in parsed_json and not parsed_json["success"]:
                # Check if error is in the expected HATEOAS format
                if "error" in parsed_json and not isinstance(parsed_json["error"], dict):
                    # Convert string error to the proper format
                    error_message = parsed_json["error"]
                    parsed_json["error"] = {
                        "code": f"HTTP_{response.status_code}",
                        "message": error_message
                    }
            
            return parsed_json
            
        except ValueError:
            if response.ok:
                return {
                    "success": False,
                    "error": {
                        "code": "NON_JSON_RESPONSE",
                        "message": "Received non-JSON success response from Ghidra plugin"
                    },
                    "status_code": response.status_code,
                    "response_text": response.text[:500],
                    "timestamp": int(time.time() * 1000)
                }
            else:
                return {
                    "success": False,
                    "error": {
                        "code": f"HTTP_{response.status_code}",
                        "message": f"Non-JSON error response: {response.text[:100]}..."
                    },
                    "status_code": response.status_code,
                    "response_text": response.text[:500],
                    "timestamp": int(time.time() * 1000)
                }

    except requests.exceptions.Timeout:
        return {
            "success": False,
            "error": {
                "code": "REQUEST_TIMEOUT",
                "message": "Request timed out"
            },
            "status_code": 408,
            "timestamp": int(time.time() * 1000)
        }
    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "error": {
                "code": "CONNECTION_ERROR",
                "message": f"Failed to connect to Ghidra instance at {url}"
            },
            "status_code": 503,
            "timestamp": int(time.time() * 1000)
        }
    except Exception as e:
        return {
            "success": False,
            "error": {
                "code": "UNEXPECTED_ERROR",
                "message": f"An unexpected error occurred: {str(e)}"
            },
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


# ================= Text Formatters =================
# Format API responses as plain text for efficient LLM consumption

def format_error(response: dict) -> str:
    """Format an error response as plain text"""
    if isinstance(response, dict) and "error" in response:
        err = response["error"]
        if isinstance(err, dict):
            return f"Error: {err.get('message', 'Unknown error')}"
        return f"Error: {err}"
    return "Error: Unknown error"


def format_functions_list(response: dict, offset: int = 0, limit: int = 100, **kwargs) -> str:
    """Format function list as plain text table"""
    if not response.get("success", False):
        return format_error(response)

    items = response.get("result", [])
    total = response.get("size", len(items))

    lines = [f"Functions ({offset+1}-{offset+len(items)} of {total}):", ""]

    for fn in items:
        name = fn.get("name", "???")
        addr = fn.get("address", "???")
        sig = fn.get("signature", "")
        if len(sig) > 60:
            sig = sig[:57] + "..."
        lines.append(f"  {addr}  {name:<30}  {sig}")

    if offset + len(items) < total:
        lines.append(f"\n  ... {total - offset - len(items)} more (use offset={offset+limit})")

    return "\n".join(lines)


def format_function_info(response: dict, **kwargs) -> str:
    """Format single function info as plain text"""
    if not response.get("success", False):
        return format_error(response)

    fn = response.get("result", {})
    lines = [
        f"Function: {fn.get('name', '???')}",
        f"Address:  {fn.get('address', '???')}",
        f"Signature: {fn.get('signature', 'unknown')}",
    ]

    if fn.get("entryPoint"):
        lines.append(f"Entry:    {fn.get('entryPoint')}")
    if fn.get("returnType"):
        lines.append(f"Returns:  {fn.get('returnType')}")

    params = fn.get("parameters", [])
    if params:
        lines.append(f"Parameters ({len(params)}):")
        for p in params:
            lines.append(f"  {p.get('dataType', '?')} {p.get('name', '?')}")

    local_vars = fn.get("localVariables", [])
    if local_vars:
        lines.append(f"Local variables ({len(local_vars)}):")
        for v in local_vars[:10]:
            lines.append(f"  {v.get('dataType', '?')} {v.get('name', '?')}")
        if len(local_vars) > 10:
            lines.append(f"  ... and {len(local_vars) - 10} more")

    return "\n".join(lines)


def format_decompile(response: dict, **kwargs) -> str:
    """Format decompiled code - just return the code"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    code = result.get("ccode") or result.get("decompiled") or ""

    if not code:
        return "Error: No decompiled code returned"

    return code


def format_disassembly(response: dict, **kwargs) -> str:
    """Format disassembly as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    instructions = result.get("instructions", [])

    if not instructions:
        return "Error: No disassembly returned"

    lines = []
    for instr in instructions:
        addr = instr.get("address", "")
        bytes_hex = instr.get("bytes", "")
        mnemonic = instr.get("mnemonic", "")
        operands = instr.get("operands", "")
        lines.append(f"  {addr}  {bytes_hex:<12} {mnemonic:<8} {operands}")

    return "\n".join(lines)


def format_xrefs(response: dict, to_addr: str = None, from_addr: str = None, **kwargs) -> str:
    """Format cross-references as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    # Handle both dict (with references key) and list format
    if isinstance(result, dict):
        items = result.get("references", [])
    else:
        items = result if isinstance(result, list) else []

    total = response.get("size", len(items))
    target = to_addr or from_addr

    header = f"References"
    if target:
        header += f" {'to' if to_addr else 'from'} {target}"
    header += f" ({len(items)}"
    if total > len(items):
        header += f" of {total}"
    header += "):"

    lines = [header]
    for xref in items:
        from_a = xref.get("from_addr", "???")
        ref_type = xref.get("refType", "???")
        from_func_obj = xref.get("from_function", {})

        # Extract function name if from_function is a dict
        if isinstance(from_func_obj, dict):
            from_func = from_func_obj.get("name", "")
        else:
            from_func = from_func_obj or ""

        line = f"  {from_a}  {ref_type:<10}"
        if from_func:
            line += f"  from {from_func}"
        lines.append(line)

    return "\n".join(lines)


def format_strings(response: dict, offset: int = 0, **kwargs) -> str:
    """Format strings list as plain text"""
    if not response.get("success", False):
        return format_error(response)

    items = response.get("result", [])
    total = response.get("size", len(items))

    lines = [f"Strings ({offset+1}-{offset+len(items)} of {total}):", ""]

    for s in items:
        addr = s.get("address", "???")
        value = s.get("value", "")
        value = repr(value)[1:-1]
        if len(value) > 60:
            value = value[:57] + "..."
        lines.append(f"  {addr}  \"{value}\"")

    return "\n".join(lines)


def format_data_list(response: dict, offset: int = 0, limit: int = 100, **kwargs) -> str:
    """Format data items list as plain text"""
    if not response.get("success", False):
        return format_error(response)

    items = response.get("result", [])
    total = response.get("size", len(items))

    lines = [f"Data items ({offset+1}-{offset+len(items)} of {total}):", ""]

    for d in items:
        addr = d.get("address", "???")
        label = d.get("label", "")  # Java returns 'label' not 'name'
        dtype = d.get("dataType", "???")  # Java returns 'dataType' not 'type'
        value = d.get("value", "")

        line = f"  {addr}  {dtype:<16}"
        if label and label != "(unnamed)":
            line += f"  {label}"
        if value:
            val_str = str(value)
            if len(val_str) > 30:
                val_str = val_str[:27] + "..."
            line += f"  = {val_str}"
        lines.append(line)

    return "\n".join(lines)


def format_instances(response: dict, **kwargs) -> str:
    """Format instances list as plain text"""
    # Handle both dict with 'instances' key and direct list
    if isinstance(response, dict):
        instances = response.get("instances", [])
    else:
        instances = response if isinstance(response, list) else []

    if not instances:
        return "No Ghidra instances found."

    lines = [f"Ghidra instances ({len(instances)}):", ""]

    for inst in instances:
        port = inst.get("port", "???")
        project = inst.get("project", "")
        file = inst.get("file", "")

        line = f"  :{port}"
        if project:
            line += f"  {project}"
        if file:
            line += f" / {file}"
        lines.append(line)

    return "\n".join(lines)


def format_instance_info(response: dict, **kwargs) -> str:
    """Format single instance info as plain text"""
    if "error" in response:
        return format_error(response)

    port = response.get("port", "???")
    program = response.get("program_name", "unknown")
    project = response.get("project", "")
    lang = response.get("language", "")
    base = response.get("base_address", "")
    analysis = "complete" if response.get("analysis_complete") else "incomplete"

    lines = [f"Instance :{port}"]
    if project:
        lines.append(f"Project:  {project}")
    lines.append(f"Program:  {program}")
    if lang:
        lines.append(f"Language: {lang}")
    if base:
        lines.append(f"Base:     {base}")
    lines.append(f"Analysis: {analysis}")

    return "\n".join(lines)


def format_memory(response: dict, **kwargs) -> str:
    """Format memory read as hex dump"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", response)
    addr = result.get("address", "???")
    hex_bytes = result.get("hexBytes", "")
    length = result.get("bytesRead", result.get("length", 0))

    lines = [f"Memory at {addr} ({length} bytes):"]

    if hex_bytes:
        hex_bytes = hex_bytes.replace(" ", "")  # Strip any spaces for safety
        byte_pairs = [hex_bytes[i:i+2] for i in range(0, len(hex_bytes), 2)]

        for i in range(0, len(byte_pairs), 16):
            chunk = byte_pairs[i:i+16]
            hex_part = " ".join(chunk)

            ascii_part = ""
            for bp in chunk:
                try:
                    b = int(bp, 16)
                    ascii_part += chr(b) if 32 <= b < 127 else "."
                except:
                    ascii_part += "?"

            lines.append(f"  {hex_part:<48}  {ascii_part}")

    return "\n".join(lines)


def format_variables(response: dict, **kwargs) -> str:
    """Format function variables as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    fn_name = result.get("functionName", "???")
    params = result.get("parameters", [])
    locals_list = result.get("localVariables", [])

    lines = [f"Variables for {fn_name}:"]

    if params:
        lines.append(f"\nParameters ({len(params)}):")
        for p in params:
            lines.append(f"  {p.get('dataType', '?'):<20} {p.get('name', '?')}")

    if locals_list:
        lines.append(f"\nLocal variables ({len(locals_list)}):")
        for v in locals_list:
            storage = v.get('storage', '')
            lines.append(f"  {v.get('dataType', '?'):<20} {v.get('name', '?'):<20} {storage}")

    if not params and not locals_list:
        lines.append("  (no variables)")

    return "\n".join(lines)


def format_callgraph(response: dict, **kwargs) -> str:
    """Format call graph as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    root = result.get("rootFunction", "???")
    nodes = result.get("nodes", [])
    edges = result.get("edges", [])

    lines = [f"Call graph from {root}:", f"  {len(nodes)} functions, {len(edges)} calls", ""]

    calls = {}
    for edge in edges:
        caller = edge.get("from", "")
        callee = edge.get("to", "")
        if caller not in calls:
            calls[caller] = []
        calls[caller].append(callee)

    def show_calls(fn, indent=0, seen=None):
        if seen is None:
            seen = set()
        if fn in seen:
            return [f"{'  ' * indent}{fn} (recursive)"]
        seen.add(fn)
        result_lines = [f"{'  ' * indent}{fn}"]
        if fn in calls and indent < 3:
            for callee in calls[fn][:10]:
                result_lines.extend(show_calls(callee, indent + 1, seen.copy()))
            if len(calls[fn]) > 10:
                result_lines.append(f"{'  ' * (indent + 1)}... and {len(calls[fn]) - 10} more")
        return result_lines

    lines.extend(show_calls(root))
    return "\n".join(lines)


def format_structs_list(response: dict, offset: int = 0, **kwargs) -> str:
    """Format struct list as plain text"""
    if not response.get("success", False):
        return format_error(response)

    items = response.get("result", [])
    total = response.get("size", len(items))

    lines = [f"Structs ({offset+1}-{offset+len(items)} of {total}):", ""]

    for s in items:
        name = s.get("name", "???")
        size = s.get("size", 0)
        fields = s.get("fieldCount", s.get("numFields", "?"))
        lines.append(f"  {name:<40} {size:>6} bytes  {fields} fields")

    return "\n".join(lines)


def format_struct_info(response: dict, **kwargs) -> str:
    """Format struct details as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    if isinstance(result, list):
        result = result[0] if result else {}

    name = result.get("name", "???")
    size = result.get("size", 0)
    fields = result.get("fields", [])

    lines = [f"Struct: {name} ({size} bytes)", ""]

    if fields:
        lines.append(f"Fields ({len(fields)}):")
        for f in fields:
            foffset = f.get("offset", 0)
            fname = f.get("name", "???")
            ftype = f.get("type", "???")
            fsize = f.get("size", "?")
            lines.append(f"  +{foffset:<4} {ftype:<20} {fname:<20} ({fsize} bytes)")
    else:
        lines.append("  (no fields)")

    return "\n".join(lines)


def format_project_info(response: dict, **kwargs) -> str:
    """Format project info as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    name = result.get("name", "???")
    location = result.get("location", "???")
    file_count = result.get("fileCount", "?")

    return f"Project: {name}\nLocation: {location}\nFiles: {file_count}"


def format_project_files(response: dict, **kwargs) -> str:
    """Format project files as plain text"""
    if not response.get("success", False):
        return format_error(response)

    items = response.get("result", [])
    lines = [f"Project files ({len(items)}):", ""]

    for f in items:
        path = f.get("path", f.get("name", "???"))
        ftype = "DIR" if f.get("isFolder") else "   "
        lines.append(f"  {ftype}  {path}")

    return "\n".join(lines)


def format_simple_result(response: dict, success_msg: str = "Done", **kwargs) -> str:
    """Format a simple success/error response"""
    if not response.get("success", False):
        return format_error(response)
    return success_msg


# ================= Formatter Registry & Decorator =================

FORMATTERS = {
    "functions_list": format_functions_list,
    "functions_get": format_function_info,
    "functions_decompile": format_decompile,
    "functions_disassemble": format_disassembly,
    "functions_get_variables": format_variables,
    "xrefs_list": format_xrefs,
    "data_list": format_data_list,
    "data_list_strings": format_strings,
    "memory_read": format_memory,
    "instances_list": format_instances,
    "instances_discover": format_instances,
    "instances_current": format_instance_info,
    "structs_list": format_structs_list,
    "structs_get": format_struct_info,
    "analysis_get_callgraph": format_callgraph,
    "project_info": format_project_info,
    "project_list_files": format_project_files,
}


def text_output(func):
    """Decorator that converts dict responses to plain text using registered formatters"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        response = func(*args, **kwargs)

        # If already a string, pass through
        if isinstance(response, str):
            return response

        # Check for error first
        if isinstance(response, dict) and not response.get("success", True):
            return format_error(response)

        # Look up formatter by function name
        formatter = FORMATTERS.get(func.__name__)
        if formatter:
            return formatter(response, **kwargs)

        # Fallback: format_simple_result for mutation operations
        return format_simple_result(response, "Done")

    wrapper.__annotations__['return'] = str
    return wrapper


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
    
    # Store API response metadata
    api_metadata = {}
    for key in ["id", "instance", "timestamp", "size", "offset", "limit"]:
        if key in result:
            api_metadata[key] = result.get(key)
    
    # Simplify the main result data if present
    if "result" in result:
        # Handle array results
        if isinstance(result["result"], list):
            simplified_items = []
            for item in result["result"]:
                if isinstance(item, dict):
                    # Store but remove HATEOAS links from individual items
                    item_copy = item.copy()
                    links = item_copy.pop("_links", None)
                    
                    # Optionally store direct href links as more accessible properties
                    # This helps AI agents navigate the API without understanding HATEOAS
                    if isinstance(links, dict):
                        for link_name, link_data in links.items():
                            if isinstance(link_data, dict) and "href" in link_data:
                                item_copy[f"{link_name}_url"] = link_data["href"]
                    
                    simplified_items.append(item_copy)
                else:
                    simplified_items.append(item)
            result["result"] = simplified_items
        
        # Handle object results
        elif isinstance(result["result"], dict):
            result_copy = result["result"].copy()
            
            # Store but remove links from result object
            links = result_copy.pop("_links", None)
            
            # Add direct href links for easier navigation
            if isinstance(links, dict):
                for link_name, link_data in links.items():
                    if isinstance(link_data, dict) and "href" in link_data:
                        result_copy[f"{link_name}_url"] = link_data["href"]
            
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
                
                # Add the text representation
                result_copy["disassembly_text"] = disasm_text
                # Remove the original structured instructions to simplify the response
                result_copy.pop("instructions", None)
            
            # Special case for decompiled code - make sure it's directly accessible
            if "ccode" in result_copy:
                result_copy["decompiled_text"] = result_copy["ccode"]
            elif "decompiled" in result_copy:
                result_copy["decompiled_text"] = result_copy["decompiled"]
            
            result["result"] = result_copy
    
    # Store but remove HATEOAS links from the top level
    links = result.pop("_links", None)
    
    # Add direct href links in a more accessible format
    if isinstance(links, dict):
        api_links = {}
        for link_name, link_data in links.items():
            if isinstance(link_data, dict) and "href" in link_data:
                api_links[link_name] = link_data["href"]
        
        # Add simplified links
        if api_links:
            result["api_links"] = api_links
    
    # Restore API metadata
    for key, value in api_metadata.items():
        if key not in result:
            result[key] = value
    
    return result

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
            # Check plugin version to ensure compatibility
            try:
                version_data = response.json()
                if "result" in version_data:
                    result = version_data["result"]
                    if isinstance(result, dict):
                        plugin_version = result.get("plugin_version", "")
                        api_version = result.get("api_version", 0)
                        
                        project_info["plugin_version"] = plugin_version
                        project_info["api_version"] = api_version
                        
                        # Verify API version compatibility
                        if api_version != REQUIRED_API_VERSION:
                            error_msg = f"API version mismatch: Plugin reports version {api_version}, but bridge requires version {REQUIRED_API_VERSION}"
                            print(error_msg, file=sys.stderr)
                            return error_msg
                        
                        print(f"Connected to Ghidra plugin version {plugin_version} with API version {api_version}")
            except Exception as e:
                print(f"Error parsing plugin version: {e}", file=sys.stderr)
            
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
                                # Extract project and file from programId (format: "project:/file")
                                program_id = result.get("programId", "")
                                if ":" in program_id:
                                    project_name, file_path = program_id.split(":", 1)
                                    project_info["project"] = project_name
                                    # Remove leading slash from file path if present
                                    if file_path.startswith("/"):
                                        file_path = file_path[1:]
                                    project_info["path"] = file_path
                                
                                # Get file name directly from the result
                                project_info["file"] = result.get("name", "")
                                
                                # Get other metadata
                                project_info["language_id"] = result.get("languageId", "")
                                project_info["compiler_spec_id"] = result.get("compilerSpecId", "")
                                project_info["image_base"] = result.get("image_base", "")
                                
                                # Store _links from result for HATEOAS navigation
                                if "_links" in result:
                                    project_info["_links"] = result.get("_links", {})
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

def _discover_instances(port_range, host=None, timeout=0.5) -> dict:
    """Internal function to discover NEW Ghidra instances by scanning ports

    This function only returns newly discovered instances that weren't already
    in the active_instances registry. Use instances_discover() for a complete
    list including already known instances.
    """
    found_instances = []
    scan_host = host if host is not None else ghidra_host

    for port in port_range:
        if port in active_instances:
            continue  # Skip already known instances

        url = f"http://{scan_host}:{port}"
        try:
            # Try HATEOAS API via plugin-version endpoint
            test_url = f"{url}/plugin-version"
            response = requests.get(test_url, 
                                  headers={'Accept': 'application/json', 
                                           'X-Request-ID': f"discovery-{int(time.time() * 1000)}"},
                                  timeout=timeout)
            
            if response.ok:
                # Further validate it's a GhydraMCP instance by checking response format
                try:
                    json_data = response.json()
                    if "success" in json_data and json_data["success"] and "result" in json_data:
                        # Looks like a valid HATEOAS API response
                        # Instead of relying only on register_instance, which already checks program info,
                        # extract additional information here for more detailed discovery results
                        result = register_instance(port, url)
                        
                        # Initialize report info
                        instance_info = {
                            "port": port, 
                            "url": url
                        }
                        
                        # Extract version info for reporting
                        if isinstance(json_data["result"], dict):
                            instance_info["plugin_version"] = json_data["result"].get("plugin_version", "unknown")
                            instance_info["api_version"] = json_data["result"].get("api_version", "unknown")
                        else:
                            instance_info["plugin_version"] = "unknown"
                            instance_info["api_version"] = "unknown"
                        
                        # Include project details from registered instance in the report
                        if port in active_instances:
                            instance_info["project"] = active_instances[port].get("project", "")
                            instance_info["file"] = active_instances[port].get("file", "")
                        
                        instance_info["result"] = result
                        found_instances.append(instance_info)
                except (ValueError, KeyError):
                    # Not a valid JSON response or missing expected keys
                    print(f"Port {port} returned non-HATEOAS response", file=sys.stderr)
                    continue
            
        except requests.exceptions.RequestException:
            # Instance not available, just continue
            continue

    return {
        "found": len(found_instances),
        "instances": found_instances
    }

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
                            continue
                            
                        # Update program info if available (especially to get project name)
                        try:
                            info_url = f"{url}/program"
                            info_response = requests.get(info_url, timeout=1)
                            if info_response.ok:
                                try:
                                    info_data = info_response.json()
                                    if "result" in info_data:
                                        result = info_data["result"]
                                        if isinstance(result, dict):
                                            # Extract project and file from programId (format: "project:/file")
                                            program_id = result.get("programId", "")
                                            if ":" in program_id:
                                                project_name, file_path = program_id.split(":", 1)
                                                info["project"] = project_name
                                                # Remove leading slash from file path if present
                                                if file_path.startswith("/"):
                                                    file_path = file_path[1:]
                                                info["path"] = file_path
                                            
                                            # Get file name directly from the result
                                            info["file"] = result.get("name", "")
                                            
                                            # Get other metadata
                                            info["language_id"] = result.get("languageId", "")
                                            info["compiler_spec_id"] = result.get("compilerSpecId", "")
                                            info["image_base"] = result.get("image_base", "")
                                except Exception as e:
                                    print(f"Error parsing info endpoint during discovery: {e}", file=sys.stderr)
                        except Exception:
                            # Non-critical, continue even if update fails
                            pass
                            
                    except requests.exceptions.RequestException:
                        ports_to_remove.append(port)

                for port in ports_to_remove:
                    del active_instances[port]
                    print(f"Removed unreachable instance on port {port}")
        except Exception as e:
            print(f"Error in periodic discovery: {e}")

        time.sleep(30)

def handle_sigint(signum, frame):
    os._exit(0)

# ================= MCP Resources =================
# Resources provide information that can be loaded directly into context
# They focus on data and minimize metadata

@mcp.resource(uri="/instance/{port}")
def ghidra_instance(port: int = None) -> dict:
    """Get detailed information about a Ghidra instance and the loaded program
    
    Args:
        port: Specific Ghidra instance port (optional, uses current if omitted)
        
    Returns:
        dict: Detailed information about the Ghidra instance and loaded program
    """
    port = _get_instance_port(port)
    response = safe_get(port, "program")
    
    if not isinstance(response, dict) or not response.get("success", False):
        return {"error": f"Unable to access Ghidra instance on port {port}"}
    
    # Extract only the most relevant information for the resource
    result = response.get("result", {})
    
    if not isinstance(result, dict):
        return {
            "success": False,
            "error": {
                "code": "INVALID_RESPONSE",
                "message": "Invalid response format from Ghidra instance"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    instance_info = {
        "port": port,
        "url": get_instance_url(port),
        "program_name": result.get("name", "unknown"),
        "program_id": result.get("programId", "unknown"),
        "language": result.get("languageId", "unknown"),
        "compiler": result.get("compilerSpecId", "unknown"),
        "base_address": result.get("imageBase", "0x0"),
        "memory_size": result.get("memorySize", 0),
        "analysis_complete": result.get("analysisComplete", False)
    }
    
    # Add project information if available
    if "project" in active_instances[port]:
        instance_info["project"] = active_instances[port]["project"]
    
    return instance_info

@mcp.resource(uri="/instance/{port}/function/decompile/address/{address}")
def decompiled_function_by_address(port: int = None, address: str = None) -> str:
    """Get decompiled C code for a function by address
    
    Args:
        port: Specific Ghidra instance port
        address: Function address in hex format
        
    Returns:
        str: The decompiled C code as a string, or error message
    """
    if not address:
        return "Error: Address parameter is required"
    
    port = _get_instance_port(port)
    
    params = {
        "syntax_tree": "false",
        "style": "normalize"
    }
    
    endpoint = f"functions/{address}/decompile"
    
    response = safe_get(port, endpoint, params)
    simplified = simplify_response(response)
    
    # For a resource, we want to directly return just the decompiled code
    if (not isinstance(simplified, dict) or 
        not simplified.get("success", False) or 
        "result" not in simplified):
        error_message = "Error: Could not decompile function"
        if isinstance(simplified, dict) and "error" in simplified:
            if isinstance(simplified["error"], dict):
                error_message = simplified["error"].get("message", error_message)
            else:
                error_message = str(simplified["error"])
        return error_message
    
    # Extract just the decompiled code text
    result = simplified["result"]
    
    # Different endpoints may return the code in different fields, try all of them
    if isinstance(result, dict):
        for key in ["decompiled_text", "ccode", "decompiled"]:
            if key in result:
                return result[key]
    
    return "Error: Could not extract decompiled code from response"

@mcp.resource(uri="/instance/{port}/function/decompile/name/{name}")
def decompiled_function_by_name(port: int = None, name: str = None) -> str:
    """Get decompiled C code for a function by name
    
    Args:
        port: Specific Ghidra instance port
        name: Function name
        
    Returns:
        str: The decompiled C code as a string, or error message
    """
    if not name:
        return "Error: Name parameter is required"
    
    port = _get_instance_port(port)
    
    params = {
        "syntax_tree": "false",
        "style": "normalize"
    }
    
    endpoint = f"functions/by-name/{quote(name)}/decompile"
    
    response = safe_get(port, endpoint, params)
    simplified = simplify_response(response)
    
    # For a resource, we want to directly return just the decompiled code
    if (not isinstance(simplified, dict) or 
        not simplified.get("success", False) or 
        "result" not in simplified):
        error_message = "Error: Could not decompile function"
        if isinstance(simplified, dict) and "error" in simplified:
            if isinstance(simplified["error"], dict):
                error_message = simplified["error"].get("message", error_message)
            else:
                error_message = str(simplified["error"])
        return error_message
    
    # Extract just the decompiled code text
    result = simplified["result"]
    
    # Different endpoints may return the code in different fields, try all of them
    if isinstance(result, dict):
        for key in ["decompiled_text", "ccode", "decompiled"]:
            if key in result:
                return result[key]
    
    return "Error: Could not extract decompiled code from response"

@mcp.resource(uri="/instance/{port}/function/info/address/{address}")
def function_info_by_address(port: int = None, address: str = None) -> dict:
    """Get detailed information about a function by address
    
    Args:
        port: Specific Ghidra instance port
        address: Function address in hex format
        
    Returns:
        dict: Complete function information including signature, parameters, etc.
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    endpoint = f"functions/{address}"
    
    response = safe_get(port, endpoint)
    simplified = simplify_response(response)
    
    if (not isinstance(simplified, dict) or 
        not simplified.get("success", False) or 
        "result" not in simplified):
        return {
            "success": False,
            "error": {
                "code": "FUNCTION_NOT_FOUND",
                "message": "Could not get function information",
                "details": simplified.get("error") if isinstance(simplified, dict) else None
            },
            "timestamp": int(time.time() * 1000)
        }
    
    # Return just the function data without API metadata
    return simplified["result"]

@mcp.resource(uri="/instance/{port}/function/info/name/{name}")
def function_info_by_name(port: int = None, name: str = None) -> dict:
    """Get detailed information about a function by name
    
    Args:
        port: Specific Ghidra instance port
        name: Function name
        
    Returns:
        dict: Complete function information including signature, parameters, etc.
    """
    if not name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Name parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    endpoint = f"functions/by-name/{quote(name)}"
    
    response = safe_get(port, endpoint)
    simplified = simplify_response(response)
    
    if (not isinstance(simplified, dict) or 
        not simplified.get("success", False) or 
        "result" not in simplified):
        return {
            "success": False,
            "error": {
                "code": "FUNCTION_NOT_FOUND",
                "message": "Could not get function information",
                "details": simplified.get("error") if isinstance(simplified, dict) else None
            },
            "timestamp": int(time.time() * 1000)
        }
    
    # Return just the function data without API metadata
    return simplified["result"]

@mcp.resource(uri="/instance/{port}/function/disassembly/address/{address}")
def disassembly_by_address(port: int = None, address: str = None) -> str:
    """Get disassembled instructions for a function by address
    
    Args:
        port: Specific Ghidra instance port
        address: Function address in hex format
        
    Returns:
        str: Formatted disassembly listing as a string
    """
    if not address:
        return "Error: Address parameter is required"
    
    port = _get_instance_port(port)
    
    endpoint = f"functions/{address}/disassembly"
    
    response = safe_get(port, endpoint)
    simplified = simplify_response(response)
    
    if (not isinstance(simplified, dict) or 
        not simplified.get("success", False) or 
        "result" not in simplified):
        error_message = "Error: Could not get disassembly"
        if isinstance(simplified, dict) and "error" in simplified:
            if isinstance(simplified["error"], dict):
                error_message = simplified["error"].get("message", error_message)
            else:
                error_message = str(simplified["error"])
        return error_message
    
    # For a resource, we want to directly return just the disassembly text
    result = simplified["result"]
    
    # Check if we have a disassembly_text field already
    if isinstance(result, dict) and "disassembly_text" in result:
        return result["disassembly_text"]
    
    # Otherwise if we have raw instructions, format them ourselves
    if isinstance(result, dict) and "instructions" in result and isinstance(result["instructions"], list):
        disasm_text = ""
        for instr in result["instructions"]:
            if isinstance(instr, dict):
                addr = instr.get("address", "")
                mnemonic = instr.get("mnemonic", "")
                operands = instr.get("operands", "")
                bytes_str = instr.get("bytes", "")
                
                # Format: address: bytes  mnemonic operands
                disasm_text += f"{addr}: {bytes_str.ljust(10)}  {mnemonic} {operands}\n"
        
        return disasm_text
    
    # If we have a direct disassembly field, try that as well
    if isinstance(result, dict) and "disassembly" in result:
        return result["disassembly"]
    
    return "Error: Could not extract disassembly from response"

@mcp.resource(uri="/instance/{port}/function/disassembly/name/{name}")
def disassembly_by_name(port: int = None, name: str = None) -> str:
    """Get disassembled instructions for a function by name
    
    Args:
        port: Specific Ghidra instance port
        name: Function name
        
    Returns:
        str: Formatted disassembly listing as a string
    """
    if not name:
        return "Error: Name parameter is required"
    
    port = _get_instance_port(port)
    
    endpoint = f"functions/by-name/{quote(name)}/disassembly"
    
    response = safe_get(port, endpoint)
    simplified = simplify_response(response)
    
    if (not isinstance(simplified, dict) or 
        not simplified.get("success", False) or 
        "result" not in simplified):
        error_message = "Error: Could not get disassembly"
        if isinstance(simplified, dict) and "error" in simplified:
            if isinstance(simplified["error"], dict):
                error_message = simplified["error"].get("message", error_message)
            else:
                error_message = str(simplified["error"])
        return error_message
    
    # For a resource, we want to directly return just the disassembly text
    result = simplified["result"]
    
    # Check if we have a disassembly_text field already
    if isinstance(result, dict) and "disassembly_text" in result:
        return result["disassembly_text"]
    
    # Otherwise if we have raw instructions, format them ourselves
    if isinstance(result, dict) and "instructions" in result and isinstance(result["instructions"], list):
        disasm_text = ""
        for instr in result["instructions"]:
            if isinstance(instr, dict):
                addr = instr.get("address", "")
                mnemonic = instr.get("mnemonic", "")
                operands = instr.get("operands", "")
                bytes_str = instr.get("bytes", "")
                
                # Format: address: bytes  mnemonic operands
                disasm_text += f"{addr}: {bytes_str.ljust(10)}  {mnemonic} {operands}\n"
        
        return disasm_text
    
    # If we have a direct disassembly field, try that as well
    if isinstance(result, dict) and "disassembly" in result:
        return result["disassembly"]
    
    return "Error: Could not extract disassembly from response"

# ================= MCP Prompts =================
# Prompts define reusable templates for LLM interactions

@mcp.prompt("analyze_function")
def analyze_function_prompt(name: str = None, address: str = None, port: int = None):
    """A prompt to guide the LLM through analyzing a function
    
    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with address)
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    
    # Get function name if only address is provided
    if address and not name:
        fn_info = function_info_by_address(address=address, port=port)
        if isinstance(fn_info, dict) and "name" in fn_info:
            name = fn_info["name"]
    
    # Create the template that guides analysis
    decompiled = ""
    disasm = ""
    fn_info = None
    
    if address:
        decompiled = decompiled_function_by_address(address=address, port=port)
        disasm = disassembly_by_address(address=address, port=port)
        fn_info = function_info_by_address(address=address, port=port)
    elif name:
        decompiled = decompiled_function_by_name(name=name, port=port)
        disasm = disassembly_by_name(name=name, port=port)
        fn_info = function_info_by_name(name=name, port=port)
    
    return {
        "prompt": f"""
        Analyze the following function: {name or address}
        
        Decompiled code:
        ```c
        {decompiled}
        ```
        
        Disassembly:
        ```
        {disasm}
        ```
        
        1. What is the purpose of this function?
        2. What are the key parameters and their uses?
        3. What are the return values and their meanings?
        4. Are there any security concerns in this implementation?
        5. Describe the algorithm or process being implemented.
        """,
        "context": {
            "function_info": fn_info
        }
    }

@mcp.prompt("identify_vulnerabilities")
def identify_vulnerabilities_prompt(name: str = None, address: str = None, port: int = None):
    """A prompt to help identify potential vulnerabilities in a function
    
    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with address)
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    
    # Get function name if only address is provided
    if address and not name:
        fn_info = function_info_by_address(address=address, port=port)
        if isinstance(fn_info, dict) and "name" in fn_info:
            name = fn_info["name"]
    
    # Create the template focused on security analysis
    decompiled = ""
    disasm = ""
    fn_info = None
    
    if address:
        decompiled = decompiled_function_by_address(address=address, port=port)
        disasm = disassembly_by_address(address=address, port=port)
        fn_info = function_info_by_address(address=address, port=port)
    elif name:
        decompiled = decompiled_function_by_name(name=name, port=port)
        disasm = disassembly_by_name(name=name, port=port)
        fn_info = function_info_by_name(name=name, port=port)
    
    return {
        "prompt": f"""
        Analyze the following function for security vulnerabilities: {name or address}
        
        Decompiled code:
        ```c
        {decompiled}
        ```
        
        Look for these vulnerability types:
        1. Buffer overflows or underflows
        2. Integer overflow/underflow
        3. Use-after-free or double-free bugs
        4. Format string vulnerabilities
        5. Missing bounds checks
        6. Insecure memory operations
        7. Race conditions or timing issues
        8. Input validation problems
        
        For each potential vulnerability:
        - Describe the vulnerability and where it occurs
        - Explain the security impact
        - Suggest how it could be exploited
        - Recommend a fix
        """,
        "context": {
            "function_info": fn_info,
            "disassembly": disasm
        }
    }

@mcp.prompt("reverse_engineer_binary")
def reverse_engineer_binary_prompt(port: int = None):
    """A comprehensive prompt to guide the process of reverse engineering an entire binary
    
    Args:
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    
    # Get program info for context
    program_info = ghidra_instance(port=port)
    
    # Create a comprehensive reverse engineering guide
    return {
        "prompt": f"""
        # Comprehensive Binary Reverse Engineering Plan
        
        Begin reverse engineering the binary {program_info.get('program_name', 'unknown')} using a methodical approach.
        
        ## Phase 1: Initial Reconnaissance
        1. Analyze entry points and the main function
        2. Identify and catalog key functions and libraries
        3. Map the overall program structure
        4. Identify important data structures
        
        ## Phase 2: Functional Analysis
        1. Start with main() or entry point functions and trace the control flow
        2. Find and rename all unnamed functions (FUN_*) called from main
        3. For each function:
           - Decompile and analyze its purpose
           - Rename with descriptive names following consistent patterns
           - Add comments for complex logic
           - Identify parameters and return values
        4. Follow cross-references (xrefs) to understand context of function usage
        5. Pay special attention to:
           - File I/O operations
           - Network communication
           - Memory allocation/deallocation
           - Authentication/encryption routines
           - Data processing algorithms
        
        ## Phase 3: Data Flow Mapping
        1. Identify key data structures and rename them meaningfully
        2. Track global variables and their usage across functions
        3. Map data transformations through the program
        4. Identify sensitive data handling (keys, credentials, etc.)
        
        ## Phase 4: Deep Analysis
        1. For complex functions, perform deeper analysis using:
           - Data flow analysis
           - Call graph analysis
           - Security vulnerability scanning
        2. Look for interesting patterns:
           - Command processing routines
           - State machines
           - Protocol implementations
           - Cryptographic operations
        
        ## Implementation Strategy
        1. Start with functions called from main
        2. Search for unnamed functions with pattern "FUN_*"
        3. Decompile each function and analyze its purpose
        4. Look at its call graph and cross-references to understand context
        5. Rename the function based on its behavior
        6. Document key insights
        7. Continue iteratively until the entire program flow is mapped
        
        ## Function Prioritization
        1. Start with entry points and initialization functions
        2. Focus on functions with high centrality in the call graph
        3. Pay special attention to functions with:
           - Command processing logic
           - Error handling
           - Security checks
           - Data transformation
        
        Remember to use the available GhydraMCP tools:
        - Use functions_list to find functions matching patterns
        - Use xrefs_list to find cross-references
        - Use functions_decompile for C-like representations
        - Use functions_disassemble for lower-level analysis
        - Use functions_rename to apply meaningful names
        - Use data_* tools to work with program data
        """,
        "context": {
            "program_info": program_info 
        }
    }

# ================= MCP Tools =================
# Since we can't use tool groups, we'll use namespaces in the function names

# Instance management tools
@mcp.tool()
@text_output
def instances_list() -> dict:
    """List all known Ghidra instances with automatic discovery

    This is the PRIMARY tool for discovering instances. It automatically scans
    for new instances on the default host (ports 8192-8201) before returning the list.

    IMPORTANT: This performs discovery automatically. You do NOT need to call
    instances_discover() separately unless scanning a different host.

    Returns:
        dict: Contains 'instances' list with all available Ghidra instances,
              each showing port, url, project, and file
    """
    # Auto-discover new instances before listing
    _discover_instances(QUICK_DISCOVERY_RANGE, host=None, timeout=0.5)

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
@text_output
def instances_discover(host: str = None) -> dict:
    """Scan a specific host for Ghidra instances (RARELY NEEDED)

    Use this ONLY when scanning a different host than the default.

    For normal usage, use instances_list() instead - it performs discovery
    automatically on the default host.

    Args:
        host: Hostname or IP to scan (default: localhost/configured ghidra_host)

    Returns:
        dict: Contains 'instances' list with all available instances after discovery
    """
    # Discover instances on the specified host
    _discover_instances(QUICK_DISCOVERY_RANGE, host=host, timeout=0.5)

    # Return all instances (same format as instances_list for consistency)
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
@text_output
def instances_register(port: int, url: str = None) -> str:
    """Register a new Ghidra instance
    
    Args:
        port: Port number of the Ghidra instance
        url: Optional URL if different from default http://host:port
    
    Returns:
        str: Confirmation message or error
    """
    return register_instance(port, url)

@mcp.tool()
@text_output
def instances_unregister(port: int) -> str:
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
@text_output
def instances_use(port: int) -> str:
    """Set the current working Ghidra instance
    
    Args:
        port: Port number of the instance to use
        
    Returns:
        str: Confirmation message or error
    """
    global current_instance_port
    
    # First validate that the instance exists and is active
    if port not in active_instances:
        # Try to register it if not found
        register_instance(port)
        if port not in active_instances:
            return f"Error: No active Ghidra instance found on port {port}"
    
    # Set as current instance
    current_instance_port = port
    
    # Return information about the selected instance
    with instances_lock:
        info = active_instances[port]
        program = info.get("file", "unknown program")
        project = info.get("project", "unknown project")
        return f"Now using Ghidra instance on port {port} with {program} in project {project}"

@mcp.tool()
@text_output
def instances_current() -> dict:
    """Get information about the current working instance set by instances_use()

    Shows which Ghidra instance will be used when port is omitted from other tools.
    The default current instance is port 8192.

    Returns:
        dict: Details about the current instance including port, program, and project
    """
    return ghidra_instance(port=current_instance_port)

# Function tools
@mcp.tool()
@text_output
def functions_list(offset: int = 0, limit: int = 100, 
                  name_contains: str = None, 
                  name_matches_regex: str = None,
                  port: int = None) -> dict:
    """List functions with filtering and pagination
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        name_contains: Substring name filter (case-insensitive)
        name_matches_regex: Regex name filter
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: List of functions with pagination information
    """
    port = _get_instance_port(port)
    
    params = {
        "offset": offset,
        "limit": limit
    }
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
@text_output
def functions_get(name: str = None, address: str = None, port: int = None) -> dict:
    """Get detailed information about a function
    
    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with name)
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Detailed function information
    """
    if not name and not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    if address:
        endpoint = f"functions/{address}"
    else:
        endpoint = f"functions/by-name/{quote(name)}"
    
    response = safe_get(port, endpoint)
    return simplify_response(response)

@mcp.tool()
@text_output
def functions_decompile(name: str = None, address: str = None,
                        syntax_tree: bool = False, style: str = "normalize",
                        show_constants: bool = True, timeout: int = 30,
                        start_line: int = None, end_line: int = None, max_lines: int = None,
                        port: int = None) -> dict:
    """Get decompiled code for a function with optional line filtering and configurable options

    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with name)
        syntax_tree: Include syntax tree (default: False)
        style: Decompiler style (default: "normalize")
        show_constants: Show actual constant values (strings, numbers) instead of placeholder addresses (default: True)
        timeout: Decompilation timeout in seconds (default: 30)
        start_line: Start at this line number (1-indexed, optional)
        end_line: End at this line number (inclusive, optional)
        max_lines: Maximum number of lines to return (optional, takes precedence over end_line)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Contains function information and decompiled code (potentially filtered).
              If filtering is applied, includes a 'filter' object with total_lines and applied parameters.

    Examples:
        # Get first 20 lines of decompiled code
        functions_decompile(name="main", max_lines=20)

        # Get lines 10-30
        functions_decompile(name="main", start_line=10, end_line=30)

        # Get 15 lines starting from line 25
        functions_decompile(name="main", start_line=25, max_lines=15)
    """
    if not name and not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    params = {
        "syntax_tree": str(syntax_tree).lower(),
        "style": style,
        "show_constants": str(show_constants).lower(),
        "timeout": str(timeout)
    }

    # Add line filtering parameters if provided
    if start_line is not None:
        params["start_line"] = str(start_line)
    if end_line is not None:
        params["end_line"] = str(end_line)
    if max_lines is not None:
        params["max_lines"] = str(max_lines)

    if address:
        endpoint = f"functions/{address}/decompile"
    else:
        endpoint = f"functions/by-name/{quote(name)}/decompile"

    response = safe_get(port, endpoint, params)
    simplified = simplify_response(response)

    return simplified

@mcp.tool()
@text_output
def functions_disassemble(name: str = None, address: str = None, offset: int = 0, limit: int = 0, port: int = None) -> dict:
    """Get disassembly for a function

    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with name)
        offset: Number of instructions to skip (default 0)
        limit: Maximum number of instructions to return (default 0 = all)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Contains function information and disassembly text
    """
    if not name and not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    if address:
        endpoint = f"functions/{address}/disassembly"
    else:
        endpoint = f"functions/by-name/{quote(name)}/disassembly"

    params = {}
    if offset > 0:
        params["offset"] = offset
    if limit > 0:
        params["limit"] = limit

    response = safe_get(port, endpoint, params)
    return simplify_response(response)

@mcp.tool()
@text_output
def functions_create(address: str, port: int = None) -> dict:
    """Create a new function at the specified address
    
    Args:
        address: Memory address in hex format where function starts
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Operation result with the created function information
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    payload = {
        "address": address
    }
    
    response = safe_post(port, "functions", payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def functions_rename(old_name: str = None, address: str = None, new_name: str = "", port: int = None) -> dict:
    """Rename a function
    
    Args:
        old_name: Current function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with name)
        new_name: New function name
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Operation result with the updated function information
    """
    if not (old_name or address) or not new_name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either old_name or address, and new_name parameters are required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    payload = {
        "name": new_name
    }
    
    if address:
        endpoint = f"functions/{address}"
    else:
        endpoint = f"functions/by-name/{quote(old_name)}"
    
    response = safe_patch(port, endpoint, payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def functions_set_signature(name: str = None, address: str = None, signature: str = "", port: int = None) -> dict:
    """Set function signature/prototype
    
    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with name)
        signature: New function signature (e.g., "int func(char *data, int size)")
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Operation result with the updated function information
    """
    if not (name or address) or not signature:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address, and signature parameters are required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
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
@text_output
def functions_get_variables(name: str = None, address: str = None, port: int = None) -> dict:
    """Get variables for a function
    
    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with name)
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Contains function information and list of variables
    """
    if not name and not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    if address:
        endpoint = f"functions/{address}/variables"
    else:
        endpoint = f"functions/by-name/{quote(name)}/variables"
    
    response = safe_get(port, endpoint)
    return simplify_response(response)

# Memory tools
@mcp.tool()
@text_output
def memory_read(address: str, length: int = 16, format: str = "hex", port: int = None) -> dict:
    """Read bytes from memory
    
    Args:
        address: Memory address in hex format
        length: Number of bytes to read (default: 16)
        format: Output format - "hex", "base64", or "string" (default: "hex")
        port: Specific Ghidra instance port (optional)
    
    Returns:
        dict: {
            "address": original address,
            "length": bytes read,
            "format": output format,
            "hexBytes": the memory contents as hex string,
            "rawBytes": the memory contents as base64 string,
            "timestamp": response timestamp
        }
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)
    
    # Use query parameters instead of path parameters for more reliable handling
    params = {
        "address": address,
        "length": length,
        "format": format
    }
    
    response = safe_get(port, "memory", params)
    simplified = simplify_response(response)
    
    # Ensure the result is simple and directly usable
    if "result" in simplified and isinstance(simplified["result"], dict):
        result = simplified["result"]
        
        # Pass through all representations of the bytes
        memory_info = {
            "success": True, 
            "address": result.get("address", address),
            "length": result.get("bytesRead", length),
            "format": format,
            "timestamp": simplified.get("timestamp", int(time.time() * 1000))
        }
        
        # Include all the different byte representations
        if "hexBytes" in result:
            memory_info["hexBytes"] = result["hexBytes"]
        if "rawBytes" in result:
            memory_info["rawBytes"] = result["rawBytes"]
            
        return memory_info
    
    return simplified

@mcp.tool()
@text_output
def memory_write(address: str, bytes_data: str, format: str = "hex", port: int = None) -> dict:
    """Write bytes to memory (use with caution)
    
    Args:
        address: Memory address in hex format
        bytes_data: Data to write (format depends on 'format' parameter)
        format: Input format - "hex", "base64", or "string" (default: "hex")
        port: Specific Ghidra instance port (optional)
    
    Returns:
        dict: Operation result with success status
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    if not bytes_data:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Bytes parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)
    
    payload = {
        "bytes": bytes_data,
        "format": format
    }
    
    # Memory write is handled by ProgramEndpoints, not MemoryEndpoints
    response = safe_patch(port, f"programs/current/memory/{address}", payload)
    return simplify_response(response)

# Xrefs tools
@mcp.tool()
@text_output
def xrefs_list(to_addr: str = None, from_addr: str = None, type: str = None,
              offset: int = 0, limit: int = 100, port: int = None) -> dict:
    """List cross-references with filtering and pagination
    
    Args:
        to_addr: Filter references to this address (hexadecimal)
        from_addr: Filter references from this address (hexadecimal)  
        type: Filter by reference type (e.g. "CALL", "READ", "WRITE")
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        port: Specific Ghidra instance port (optional)
    
    Returns:
        dict: Cross-references matching the filters
    """
    # At least one of the address parameters must be provided
    if not to_addr and not from_addr:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER", 
                "message": "Either to_addr or from_addr parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
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
    
    return simplified

# Data tools
@mcp.tool()
@text_output
def data_list(offset: int = 0, limit: int = 100, addr: str = None,
            name: str = None, name_contains: str = None, type: str = None,
            port: int = None) -> dict:
    """List defined data items with filtering and pagination
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        addr: Filter by address (hexadecimal)
        name: Exact name match filter (case-sensitive)
        name_contains: Substring name filter (case-insensitive)
        type: Filter by data type (e.g. "string", "dword")
        port: Specific Ghidra instance port (optional)
    
    Returns:
        dict: Data items matching the filters
    """
    port = _get_instance_port(port)
    
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
@text_output
def data_create(address: str, data_type: str, size: int = None, port: int = None) -> dict:
    """Define a new data item at the specified address
    
    Args:
        address: Memory address in hex format
        data_type: Data type (e.g. "string", "dword", "byte")
        size: Optional size in bytes for the data item
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Operation result with the created data information
    """
    if not address or not data_type:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address and data_type parameters are required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    payload = {
        "address": address,
        "type": data_type
    }
    
    if size is not None:
        payload["size"] = size
    
    response = safe_post(port, "data", payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def data_list_strings(offset: int = 0, limit: int = 2000, filter: str = None, port: int = None) -> dict:
    """List all defined strings in the binary with their memory addresses
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum strings to return (default: 2000)
        filter: Optional string content filter
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: List of string data with addresses, values, and metadata
    """
    port = _get_instance_port(port)
    
    params = {
        "offset": offset,
        "limit": limit
    }
    
    if filter:
        params["filter"] = filter
    
    response = safe_get(port, "strings", params)
    return simplify_response(response)

@mcp.tool()
@text_output
def data_rename(address: str, name: str, port: int = None) -> dict:
    """Rename a data item
    
    Args:
        address: Memory address in hex format
        name: New name for the data item
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Operation result with the updated data information
    """
    if not address or not name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address and name parameters are required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    payload = {
        "address": address,
        "newName": name
    }
    
    response = safe_post(port, "data", payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def data_delete(address: str, port: int = None) -> dict:
    """Delete data at the specified address
    
    Args:
        address: Memory address in hex format
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Operation result
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    payload = {
        "address": address,
        "action": "delete"
    }
    
    response = safe_post(port, "data/delete", payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def data_set_type(address: str, data_type: str, port: int = None) -> dict:
    """Set the data type of a data item
    
    Args:
        address: Memory address in hex format
        data_type: Data type name (e.g. "uint32_t", "char[10]")
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Operation result with the updated data information
    """
    if not address or not data_type:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address and data_type parameters are required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    payload = {
        "address": address,
        "type": data_type
    }
    
    response = safe_post(port, "data/type", payload)
    return simplify_response(response)

# Struct tools
@mcp.tool()
@text_output
def structs_list(offset: int = 0, limit: int = 100, category: str = None, port: int = None) -> dict:
    """List all struct data types in the program

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        category: Filter by category path (e.g. "/winapi")
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of structs with name, size, and field count
    """
    port = _get_instance_port(port)

    params = {
        "offset": offset,
        "limit": limit
    }
    if category:
        params["category"] = category

    response = safe_get(port, "structs", params)
    simplified = simplify_response(response)

    # Ensure we maintain pagination metadata
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)

    return simplified

@mcp.tool()
@text_output
def structs_get(name: str, port: int = None) -> dict:
    """Get detailed information about a specific struct including all fields

    Args:
        name: Struct name
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Struct details including all fields with their names, types, and offsets
    """
    if not name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Struct name parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    params = {"name": name}
    response = safe_get(port, "structs", params)
    return simplify_response(response)

@mcp.tool()
@text_output
def structs_create(name: str, category: str = None, description: str = None, port: int = None) -> dict:
    """Create a new struct data type

    Args:
        name: Name for the new struct
        category: Category path for the struct (e.g. "/custom")
        description: Optional description for the struct
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Created struct information
    """
    if not name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Struct name parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    payload = {"name": name}
    if category:
        payload["category"] = category
    if description:
        payload["description"] = description

    response = safe_post(port, "structs/create", payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def structs_add_field(struct_name: str, field_name: str, field_type: str,
                     offset: int = None, comment: str = None, port: int = None) -> dict:
    """Add a field to an existing struct

    Args:
        struct_name: Name of the struct to modify
        field_name: Name for the new field
        field_type: Data type for the field (e.g. "int", "char", "pointer")
        offset: Specific offset to insert field (optional, appends to end if not specified)
        comment: Optional comment for the field
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result with updated struct size and field information
    """
    if not struct_name or not field_name or not field_type:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "struct_name, field_name, and field_type parameters are required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    payload = {
        "struct": struct_name,
        "fieldName": field_name,
        "fieldType": field_type
    }
    if offset is not None:
        payload["offset"] = offset
    if comment:
        payload["comment"] = comment

    response = safe_post(port, "structs/addfield", payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def structs_update_field(struct_name: str, field_name: str = None, field_offset: int = None,
                        new_name: str = None, new_type: str = None, new_comment: str = None,
                        port: int = None) -> dict:
    """Update an existing field in a struct (change name, type, or comment)

    Args:
        struct_name: Name of the struct to modify
        field_name: Name of the field to update (use this OR field_offset)
        field_offset: Offset of the field to update (use this OR field_name)
        new_name: New name for the field (optional)
        new_type: New data type for the field (optional, e.g. "int", "pointer")
        new_comment: New comment for the field (optional)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result with old and new field values
    """
    if not struct_name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "struct_name parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    if not field_name and field_offset is None:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either field_name or field_offset must be provided"
            },
            "timestamp": int(time.time() * 1000)
        }

    if not new_name and not new_type and new_comment is None:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "At least one of new_name, new_type, or new_comment must be provided"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    payload = {"struct": struct_name}
    if field_name:
        payload["fieldName"] = field_name
    if field_offset is not None:
        payload["fieldOffset"] = field_offset
    if new_name:
        payload["newName"] = new_name
    if new_type:
        payload["newType"] = new_type
    if new_comment is not None:
        payload["newComment"] = new_comment

    response = safe_post(port, "structs/updatefield", payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def structs_delete(name: str, port: int = None) -> dict:
    """Delete a struct data type

    Args:
        name: Name of the struct to delete
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result confirming deletion
    """
    if not name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Struct name parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    payload = {"name": name}
    response = safe_post(port, "structs/delete", payload)
    return simplify_response(response)

# Analysis tools
@mcp.tool()
@text_output
def analysis_run(port: int = None, analysis_options: dict = None) -> dict:
    """Run analysis on the current program
    
    Args:
        analysis_options: Dictionary of analysis options to enable/disable
                         (e.g. {"functionRecovery": True, "dataRefs": False})
        port: Specific Ghidra instance port (optional)
    
    Returns:
        dict: Analysis operation result with status
    """
    port = _get_instance_port(port)
    response = safe_post(port, "analysis", analysis_options or {})
    return simplify_response(response)

@mcp.tool()
@text_output
def analysis_get_callgraph(name: str = None, address: str = None, max_depth: int = 3, port: int = None) -> dict:
    """Get function call graph visualization data

    Args:
        name: Starting function name (mutually exclusive with address)
        address: Starting function address (mutually exclusive with name)
        max_depth: Maximum call depth to analyze (default: 3). Increase for deeper call chains (e.g., 10-15 for complex functions)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Graph data with nodes and edges
    """
    port = _get_instance_port(port)
    
    params = {"max_depth": max_depth}
    
    # Explicitly pass either name or address parameter based on what was provided
    if address:
        params["address"] = address
    elif name:
        params["name"] = name
    # If neither is provided, the Java endpoint will use the entry point
    
    response = safe_get(port, "analysis/callgraph", params)
    return simplify_response(response)

@mcp.tool()
@text_output
def analysis_get_dataflow(address: str, direction: str = "forward", max_steps: int = 50, port: int = None) -> dict:
    """Perform data flow analysis from an address
    
    Args:
        address: Starting address in hex format
        direction: "forward" or "backward" (default: "forward")
        max_steps: Maximum analysis steps (default: 50)
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Data flow analysis results
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    params = {
        "address": address,
        "direction": direction,
        "max_steps": max_steps
    }
    
    response = safe_get(port, "analysis/dataflow", params)
    return simplify_response(response)

@mcp.tool()
@text_output
def ui_get_current_address(port: int = None) -> dict:
    """Get the address currently selected in Ghidra's UI

    Args:
        port: Specific Ghidra instance port (optional)

    Returns:
        Dict containing address information or error
    """
    port = _get_instance_port(port)
    response = safe_get(port, "address")
    return simplify_response(response)

@mcp.tool()
@text_output
def ui_get_current_function(port: int = None) -> dict:
    """Get the function currently selected in Ghidra's UI

    Args:
        port: Specific Ghidra instance port (optional)

    Returns:
        Dict containing function information or error
    """
    port = _get_instance_port(port)
    response = safe_get(port, "function")
    return simplify_response(response)

@mcp.tool()
@text_output
def comments_set(address: str, comment: str = "", comment_type: str = "plate", port: int = None) -> dict:
    """Set a comment at the specified address

    Args:
        address: Memory address in hex format
        comment: Comment text (empty string removes comment)
        comment_type: Type of comment - "plate", "pre", "post", "eol", "repeatable" (default: "plate")
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)
    payload = {
        "comment": comment
    }

    response = safe_post(port, f"memory/{address}/comments/{comment_type}", payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def functions_set_comment(address: str, comment: str = "", port: int = None) -> dict:
    """Set a decompiler-friendly comment (tries function comment, falls back to pre-comment)

    Args:
        address: Memory address in hex format (preferably function entry point)
        comment: Comment text (empty string removes comment)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port_to_use = _get_instance_port(port)

    # Try setting as a function comment first using PATCH
    try:
        func_patch_payload = {
            "comment": comment
        }
        patch_response = safe_patch(port_to_use, f"functions/{address}", func_patch_payload)
        if patch_response.get("success", False):
            return simplify_response(patch_response) # Success setting function comment
        else:
             print(f"Note: Failed to set function comment via PATCH on {address}, falling back. Error: {patch_response.get('error')}", file=sys.stderr)
    except Exception as e:
        print(f"Exception trying function comment PATCH: {e}. Falling back.", file=sys.stderr)
        # Fall through to set pre-comment if PATCH fails

    # Fallback: Set as a "pre" comment using the comments_set tool
    print(f"Falling back to setting 'pre' comment for address {address}", file=sys.stderr)
    return comments_set(address=address, comment=comment, comment_type="pre", port=port_to_use)


# ================= Project Management =================

@mcp.tool()
@text_output
def project_info(port: int = None) -> dict:
    """Get information about the currently open Ghidra project

    Args:
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Project information including name, location, file counts
    """
    port = _get_instance_port(port)
    response = safe_get(port, "project")
    return simplify_response(response)


@mcp.tool()
@text_output
def project_list_files(folder: str = "/", recursive: bool = True,
                       offset: int = 0, limit: int = 100, port: int = None) -> dict:
    """List files in the current Ghidra project

    Args:
        folder: Folder path to list (default: "/")
        recursive: Recursively list all files (default: True)
        offset: Pagination offset (default: 0)
        limit: Maximum number of items to return (default: 100)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of project files and folders
    """
    port = _get_instance_port(port)

    params = {
        "folder": folder,
        "recursive": str(recursive).lower(),
        "offset": str(offset),
        "limit": str(limit)
    }

    response = safe_get(port, "project/files", params)
    return simplify_response(response)


@mcp.tool()
@text_output
def project_open_file(path: str, port: int = None) -> dict:
    """Open a file from the project in CodeBrowser

    This will open the file in a new CodeBrowser window, creating a new instance.
    Use instances_discover after opening to find the new instance port.

    Args:
        path: Path to the file in the project (e.g., "/malware.exe")
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Result of the open operation with instructions to discover new instance
    """
    port = _get_instance_port(port)

    data = {"path": path}
    response = safe_post(port, "project/open", data)
    return simplify_response(response)


# ================= Analysis =================

@mcp.tool()
@text_output
def analysis_status(port: int = None) -> dict:
    """Get analysis status for the current program

    Args:
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Analysis status including whether analysis is running
    """
    port = _get_instance_port(port)
    response = safe_get(port, "analysis/status")
    return simplify_response(response)


@mcp.tool()
@text_output
def analysis_run(background: bool = True, port: int = None) -> dict:
    """Trigger auto-analysis on the current program

    Args:
        background: Run analysis in background (default: True)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Result of starting analysis
    """
    port = _get_instance_port(port)

    data = {"background": str(background).lower()}
    response = safe_post(port, "analysis/run", data)
    return simplify_response(response)


# ================= Startup =================

def main():
    register_instance(DEFAULT_GHIDRA_PORT,
                      f"http://{ghidra_host}:{DEFAULT_GHIDRA_PORT}")

    # Use quick discovery on startup
    _discover_instances(QUICK_DISCOVERY_RANGE)

    # Start background discovery thread
    discovery_thread = threading.Thread(
        target=periodic_discovery,
        daemon=True,
        name="GhydraMCP-Discovery"
    )
    discovery_thread.start()

    signal.signal(signal.SIGINT, handle_sigint)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()