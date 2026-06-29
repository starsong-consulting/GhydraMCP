# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "mcp==1.6.0",
#     "requests==2.32.3",
# ]
# ///
# GhydraMCP Bridge for Ghidra HATEOAS API - Optimized for MCP integration
# Provides namespaced tools for interacting with Ghidra's reverse engineering capabilities
import base64
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

BRIDGE_VERSION = "v3.3.1"
REQUIRED_API_VERSION = 3000

DEFAULT_TIMEOUT = int(os.environ.get("GHIDRA_TIMEOUT", "900"))
DEFAULT_DECOMPILATION_TIMEOUT = int(
    os.environ.get("GHIDRA_DECOMP_TIMEOUT", str(max(DEFAULT_TIMEOUT, 1200)))
)

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
- scalars_* : For searching scalar (constant) values in instructions
- memory_* : For memory access
- xrefs_* : For cross-references
- analysis_* : For program analysis
- classes_* : For listing classes and namespaces
- symbols_* : For symbols, imports, and exports
- segments_* : For memory segments/blocks
- namespaces_* : For namespace hierarchy
- variables_* : For global and local variables
- datatypes_* : For data type management
"""

mcp = FastMCP("GhydraMCP", instructions=instructions)

# Backward-compatible host env resolution:
# - GHIDRA_HYDRA_HOST: current preferred variable
# - GHIDRA_HOST: legacy/common variable used in older setups
ghidra_host = (
    os.environ.get("GHIDRA_HYDRA_HOST")
    or os.environ.get("GHIDRA_HOST")
    or DEFAULT_GHIDRA_HOST
)

# Helper function to get the current instance or validate a specific port
def _get_instance_port(port: int | None = None) -> int:
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
    except (ValueError, AttributeError):
        return False

    return origin_base in ALLOWED_ORIGINS


def _extract_requested_decompile_timeout(params: dict | None = None) -> int:
    """Get requested decompile timeout from params with safe defaults."""
    requested_timeout = None
    if isinstance(params, dict):
        requested_timeout = params.get("timeout")
    try:
        return int(requested_timeout) if requested_timeout is not None else DEFAULT_DECOMPILATION_TIMEOUT
    except (TypeError, ValueError):
        return DEFAULT_DECOMPILATION_TIMEOUT

def _normalize_response(response, endpoint: str) -> dict:
    """Shape a requests.Response into the bridge's response envelope.

    Pure given the response object and endpoint, so the success/non-JSON/HATEOAS
    error-reshaping branches are testable without a live Ghidra server.
    """
    # Successful empty-body responses (204 No Content from DELETE) are real
    # successes, not "non-JSON response" errors.
    if response.ok and not response.text.strip():
        return {
            "success": True,
            "status_code": response.status_code,
            "timestamp": int(time.time() * 1000)
        }

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


def _timeout_error_envelope(endpoint: str, request_timeout: int, params: dict | None) -> dict:
    """Build the REQUEST_TIMEOUT error envelope, adding a retry hint for decompiles."""
    timeout_message = f"Request to {endpoint} timed out after {request_timeout}s."
    if "decompile" in endpoint:
        requested_timeout = _extract_requested_decompile_timeout(params)
        suggested_timeout = max(requested_timeout * 2, DEFAULT_DECOMPILATION_TIMEOUT)
        timeout_message += (
            f" Decompilation can take longer for large functions; retry with a higher timeout "
            f"(for example timeout={suggested_timeout}) and/or increase GHIDRA_TIMEOUT."
        )
    return {
        "success": False,
        "error": {
            "code": "REQUEST_TIMEOUT",
            "message": timeout_message
        },
        "status_code": 408,
        "timestamp": int(time.time() * 1000)
    }


def _make_request(method: str, port: int, endpoint: str, params: dict | None = None,
                 json_data: dict | None = None, data: str | None = None,
                 headers: dict | None = None) -> dict:
    """Internal helper to make HTTP requests and handle common errors."""
    url = f"{get_instance_url(port)}/{endpoint}"
    
    # Set up headers according to HATEOAS API expected format
    request_headers = {
        'Accept': 'application/json',
        'X-Request-ID': f"mcp-bridge-{int(time.time() * 1000)}"
    }
    
    if headers:
        request_headers.update(headers)

    request_timeout = DEFAULT_TIMEOUT
    if "decompile" in endpoint:
        requested_timeout = _extract_requested_decompile_timeout(params)
        # Keep transport timeout above decompiler timeout to avoid premature client-side cutoffs.
        request_timeout = max(DEFAULT_TIMEOUT, requested_timeout + 30)

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
            timeout=request_timeout
        )

        return _normalize_response(response, endpoint)

    except requests.exceptions.Timeout:
        return _timeout_error_envelope(endpoint, request_timeout, params)
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

def safe_get(port: int, endpoint: str, params: dict | None = None) -> dict:
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


# ================= Unicorn dynamic emulation =================
# Per-port stateful Unicorn sessions (optional dependency: ghydramcp[unicorn]).
_UNICORN_SESSIONS: dict[int, "object"] = {}
_unicorn_lock = Lock()


def _unicorn_error(message: str, code: str = "UNICORN") -> dict:
    return {"success": False, "error": {"code": code, "message": message},
            "timestamp": int(time.time() * 1000)}


def _get_unicorn_session(port: int):
    with _unicorn_lock:
        session = _UNICORN_SESSIONS.get(port)
    if session is None:
        raise KeyError("No Unicorn session; call unicorn_reset first")
    return session


def _unicorn_run_result(state: dict) -> dict:
    """Shape an engine run() state dict into a bridge response.

    success is true only for stop_reason DONE. Non-DONE returns an error
    envelope (error.code = stop_reason, error.message from last_error) so the
    last_error message reaches the MCP client via text_output. (format_error
    renders error.message; the stop_reason code travels in error.code for
    programmatic callers.)
    """
    from ghydra.dynamic.unicorn_engine import StopReason
    stop = state["stop_reason"]
    payload = {
        "pc": hex(state["pc"]),
        "steps": state["steps"],
        "stop_reason": stop,
        "last_error": state["last_error"],
        "timestamp": int(time.time() * 1000),
    }
    if stop == StopReason.DONE:
        payload["success"] = True
        payload["registers"] = {k: hex(v) for k, v in state["registers"].items()}
        payload["trace"] = [hex(a) for a in state["trace"]]
        payload["mem_writes"] = [{"address": hex(w["address"]), "size": w["size"],
                                  "value": hex(w["value"])} for w in state["mem_writes"]]
        payload["trace_truncated"] = state.get("trace_truncated", False)
        return payload
    if stop == StopReason.COUNT:
        message = (state["last_error"]
                   or f"instruction cap reached after {state['steps']} steps; "
                   "raise `count` or set a closer `until`")
    else:
        message = state["last_error"] or stop
    payload["success"] = False
    payload["error"] = {"code": stop, "message": message}
    return payload


_DEFAULT_STACK_BASE = 0x7ffff0000000
_DEFAULT_STACK_SIZE = 0x100000          # 1 MiB scratch stack


def _apply_default_stack(session) -> tuple[int, int]:
    """Map a default scratch stack and point RSP/RBP at it.

    Convenience so a freshly reset session can execute stack-using code
    (push/call) without the caller mapping a stack by hand. Returns the
    (base, size) of the mapped region. Caller-established scratch memory is
    allowed by the purist contract; this does not relax lazy mapping.
    """
    session.map_bytes(_DEFAULT_STACK_BASE, b"\x00" * _DEFAULT_STACK_SIZE)
    rsp = _DEFAULT_STACK_BASE + _DEFAULT_STACK_SIZE - 0x1000
    session.set_register("RSP", rsp)
    session.set_register("RBP", rsp)
    return _DEFAULT_STACK_BASE, _DEFAULT_STACK_SIZE


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


def _list_total(response: dict, items: list) -> int:
    """Total item count: the Javalin server nests it at meta.total; older builds
    used top-level size. Fall back to the page length."""
    meta = response.get("meta")
    if isinstance(meta, dict):
        if "total" in meta:
            return meta["total"]
        if "total_estimate" in meta:
            return meta["total_estimate"]
    return response.get("size", response.get("total_estimate", len(items)))


def format_functions_list(response: dict, offset: int = 0, limit: int = 100, **kwargs) -> str:
    """Format function list as plain text table"""
    if not response.get("success", False):
        return format_error(response)

    items = response.get("result", [])
    total = _list_total(response, items)

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
    # Javalin server sends "decompilation"; older builds used "ccode"/"decompiled".
    code = result.get("decompilation") or result.get("ccode") or result.get("decompiled") or ""
    # The DTO carries its own success flag for decompiler-level failures.
    if not code and result.get("success") is False:
        return f"Decompilation failed: {result.get('errorMessage', 'unknown error')}"
    message = result.get("message")
    suggested_timeout = result.get("suggested_timeout_seconds")
    retry_recommended = bool(result.get("retry_recommended"))
    decompile_error = result.get("decompile_error") or result.get("errorMessage")

    # Line filtering happens client-side (the server returns the full function).
    start_line = kwargs.get("start_line")
    end_line = kwargs.get("end_line")
    max_lines = kwargs.get("max_lines")
    if code and (start_line or end_line or max_lines):
        all_lines = code.splitlines()
        total = len(all_lines)
        s = max(1, start_line or 1)
        e = min(end_line or total, total)
        if max_lines:
            e = min(e, s + max_lines - 1)
        selected = all_lines[s - 1:e]
        code = "\n".join([f"// lines {s}-{e} of {total}"] + selected)

    advisory_lines = []
    if retry_recommended:
        if message:
            advisory_lines.append(f"// {message}")
        if suggested_timeout:
            advisory_lines.append(f"// Suggested timeout: {suggested_timeout}s")
        if decompile_error:
            advisory_lines.append(f"// Decompiler error: {decompile_error}")

    if advisory_lines:
        advisory_text = "\n".join(advisory_lines)
        if not code:
            return advisory_text
        if advisory_text.lower() not in code.lower():
            return f"{code.rstrip()}\n\n{advisory_text}"

    if not code:
        return "Error: No decompiled code returned"

    return code


def format_disassembly(response: dict, **kwargs) -> str:
    """Format disassembly as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    # The javalin-port API returns the instruction list directly as `result`;
    # the legacy API nests it under result["instructions"]. Handle both.
    if isinstance(result, list):
        instructions = result
        result = {}
    else:
        instructions = result.get("instructions", [])

    # simplify_response converts instructions list to disassembly_text
    if not instructions and "disassembly_text" in result:
        disasm_text = result["disassembly_text"].rstrip()
        if not disasm_text:
            if "message" in result:
                return result["message"]
            if "warning" in result:
                return f"Warning: {result['warning']}"
            return "No disassembly available"
        return disasm_text

    if not instructions:
        if "message" in result:
            return result["message"]
        if "warning" in result:
            return f"Warning: {result['warning']}"
        return "No disassembly available"

    lines = []
    for instr in instructions:
        addr = instr.get("address", "")
        bytes_hex = instr.get("bytes", "")
        mnemonic = instr.get("mnemonic", "")
        operands = instr.get("operands", "")
        lines.append(f"  {addr}  {bytes_hex:<12} {mnemonic:<8} {operands}")

    # Surface truncation: the server caps a page (default 100 instructions) and the
    # raw list carries no hint that more follow, so a long function silently looks
    # complete. meta.total is the full instruction count for the function.
    meta = response.get("meta") or {}
    total = _list_total(response, instructions)
    offset = meta.get("offset") or 0
    shown = len(instructions)
    if offset + shown < total:
        more = total - offset - shown
        lines.append(f"\n  ... {more} more instruction(s) of {total} total (use offset={offset + shown})")

    return "\n".join(lines)


def format_xrefs(response: dict, to_addr: str | None = None, from_addr: str | None = None, **kwargs) -> str:
    """Format cross-references as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    # Handle both dict (with references key) and list format
    if isinstance(result, dict):
        items = result.get("references", [])
    else:
        items = result if isinstance(result, list) else []

    total = _list_total(response, items)
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
        # Server XrefDto uses fromAddress/toAddress/fromFunction; accept legacy names too.
        from_a = xref.get("fromAddress") or xref.get("from_addr", "???")
        to_a = xref.get("toAddress") or xref.get("to_addr", "")
        ref_type = xref.get("refType", "???")
        from_func_obj = xref.get("fromFunction") or xref.get("from_function") or ""
        to_func_obj = xref.get("toFunction") or ""

        # Extract function name if it is a dict
        if isinstance(from_func_obj, dict):
            from_func = from_func_obj.get("name", "")
        else:
            from_func = from_func_obj or ""
        to_func = to_func_obj.get("name", "") if isinstance(to_func_obj, dict) else (to_func_obj or "")

        line = f"  {from_a}"
        if from_addr and to_a:
            # listing refs FROM an address: the target is the interesting part
            line += f" -> {to_a}"
        line += f"  {ref_type:<10}"
        if from_func:
            line += f"  from {from_func}"
        if to_func and from_addr:
            line += f"  to {to_func}"
        lines.append(line)

    return "\n".join(lines)


def format_strings(response: dict, offset: int = 0, **kwargs) -> str:
    """Format strings list as plain text"""
    if not response.get("success", False):
        return format_error(response)

    items = response.get("result", [])
    total = _list_total(response, items)

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
    total = _list_total(response, items)

    lines = [f"Data items ({offset+1}-{offset+len(items)} of {total}):", ""]

    for d in items:
        addr = d.get("address", "???")
        label = d.get("label") or d.get("name", "")  # DataDto field is 'label'
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
    lines = [f"Instance :{port}"]
    if project:
        lines.append(f"Project:  {project}")
    lines.append(f"Program:  {program}")
    if lang:
        lines.append(f"Language: {lang}")
    if base:
        lines.append(f"Base:     {base}")
    if response.get("function_count") is not None:
        lines.append(f"Functions: {response['function_count']}")
    if response.get("symbol_count") is not None:
        lines.append(f"Symbols:  {response['symbol_count']}")
    # /program does not report analysis state; only show it when actually present.
    if "analysis_complete" in response:
        lines.append(f"Analysis: {'complete' if response['analysis_complete'] else 'incomplete'}")

    return "\n".join(lines)


def format_memory(response: dict, **kwargs) -> str:
    """Format memory read as hex dump"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", response)
    addr = result.get("address", "???")
    hex_bytes = result.get("hex") or result.get("hexBytes") or ""
    if not hex_bytes and isinstance(result.get("bytes"), list):
        hex_bytes = "".join(f"{b:02x}" for b in result["bytes"])
    length = result.get("length", result.get("bytesRead", 0))

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
                except ValueError:
                    ascii_part += "?"

            lines.append(f"  {hex_part:<48}  {ascii_part}")

    return "\n".join(lines)


def format_variables(response: dict, **kwargs) -> str:
    """Format function variables as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})

    # Javalin server shape: {function: {name, address}, variables: [{name, type,
    # isParameter, storage, source}]}. Older builds: functionName/parameters/localVariables.
    fn = result.get("function")
    if isinstance(fn, dict):
        fn_name = fn.get("name", "???")
        variables = result.get("variables", [])
        params = [v for v in variables if v.get("isParameter")]
        locals_list = [v for v in variables if not v.get("isParameter")]
        type_key = "type"
    else:
        fn_name = result.get("functionName", "???")
        params = result.get("parameters", [])
        locals_list = result.get("localVariables", [])
        type_key = "dataType"

    lines = [f"Variables for {fn_name}:"]

    if params:
        lines.append(f"\nParameters ({len(params)}):")
        for p in params:
            storage = p.get('storage', '')
            lines.append(f"  {p.get(type_key, '?'):<20} {p.get('name', '?'):<20} {storage}")

    if locals_list:
        lines.append(f"\nLocal variables ({len(locals_list)}):")
        for v in locals_list:
            storage = v.get('storage', '')
            source = v.get('source', '')
            suffix = f"  [{source}]" if source == "decompiler" else ""
            lines.append(f"  {v.get(type_key, '?'):<20} {v.get('name', '?'):<20} {storage}{suffix}")

    if not params and not locals_list:
        lines.append("  (no variables)")

    return "\n".join(lines)


def format_callgraph(response: dict, **kwargs) -> str:
    """Format call graph as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})

    # Server shape: {root: {name, address, ...}, depth, direction,
    #                callers: [{function: {...}, callers: [...]}],
    #                callees: [{function: {...}, callees: [...]}]}
    root = result.get("root")
    if not isinstance(root, dict):
        return "No call graph data returned."

    root_name = root.get("name", "???")
    root_addr = root.get("address", "")
    depth = result.get("depth", "?")

    def render_tree(nodes, child_key, indent=1, budget=None):
        if budget is None:
            budget = [200]  # total line budget across the whole tree
        out = []
        if not isinstance(nodes, list):
            return out
        for node in nodes:
            if budget[0] <= 0:
                out.append(f"{'  ' * indent}...")
                break
            if not isinstance(node, dict):
                continue
            fn = node.get("function", {})
            name = fn.get("name", "???")
            addr = fn.get("address", "")
            out.append(f"{'  ' * indent}{name}  {addr}")
            budget[0] -= 1
            out.extend(render_tree(node.get(child_key), child_key, indent + 1, budget))
        return out

    lines = [f"Call graph for {root_name} ({root_addr}), depth {depth}:"]

    callers = result.get("callers")
    if callers is not None:
        lines.append("")
        lines.append(f"Callers ({len(callers)}):")
        lines.extend(render_tree(callers, "callers") or ["  (none)"])

    callees = result.get("callees")
    if callees is not None:
        lines.append("")
        lines.append(f"Callees ({len(callees)}):")
        lines.extend(render_tree(callees, "callees") or ["  (none)"])

    return "\n".join(lines)


def format_dataflow(response: dict, **kwargs) -> str:
    """Format data flow analysis as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    steps = result.get("steps", [])

    if not steps:
        return "No data flow steps found."

    lines = [f"Data Flow ({len(steps)} steps):", ""]

    for i, step in enumerate(steps, 1):
        addr = step.get("address", step.get("to", step.get("from", "???")))
        # Server steps carry instruction text + containing function + reference list.
        instr = step.get("instruction", step.get("description", step.get("label", "")))
        fn = step.get("function", "")
        fn_part = f"  [{fn}]" if fn else ""
        lines.append(f"  {i:>2}. {addr}  {instr}{fn_part}")
        for ref in step.get("references", [])[:8]:
            lines.append(f"        {ref.get('type', '?'):<14} {ref.get('from', '?')} -> {ref.get('to', '?')}")

    return "\n".join(lines)


def format_call_paths(response: dict, **kwargs) -> str:
    """Format analysis_find_call_paths response as plain text."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", {})
    from_fn = result.get("from", "?")
    to_fn = result.get("to", "?")
    paths = result.get("paths", [])
    truncated = result.get("truncated", False)
    unresolved = result.get("unresolved_edges", 0)

    if not paths:
        note = " (some edges unresolved — may still be reachable)" if unresolved else ""
        return f"No paths found from {from_fn} to {to_fn}.{note}"

    flags = []
    if truncated:
        flags.append("truncated")
    if unresolved:
        flags.append(f"{unresolved} unresolved edge(s)")
    flag_str = f" [{', '.join(flags)}]" if flags else ""
    lines = [f"Call paths: {from_fn} -> {to_fn} ({len(paths)} path(s)){flag_str}", ""]

    for i, path in enumerate(paths, 1):
        funcs = path.get("functions", [])
        chain = " -> ".join(f.get("name", f.get("address", "?")) for f in funcs)
        lines.append(f"  Path {i} ({path.get('length', len(funcs))} hops): {chain}")

    return "\n".join(lines)


def format_string_usage(response: dict, **kwargs) -> str:
    """Format analysis_trace_string_usage response as plain text."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", {})
    value = result.get("value", "?")
    matches = result.get("matches", [])
    total = result.get("size", 0)
    truncated = result.get("truncated", False)
    unresolved = result.get("unresolved_refs", 0)

    if not matches:
        return f'No strings matching "{value}" found.'

    flags = []
    if truncated:
        flags.append("truncated")
    if unresolved:
        flags.append(f"{unresolved} unresolved ref(s)")
    flag_str = f" [{', '.join(flags)}]" if flags else ""
    lines = [f'String usage: "{value}" — {total} match(es){flag_str}', ""]

    for m in matches:
        s = m.get("string", {})
        addr = s.get("address", "?")
        val = s.get("value", "")
        direct = m.get("directUsers", [])
        callers_list = m.get("callers", [])
        lines.append(f"  {addr}  {val!r}")
        for f in direct:
            lines.append(f"    used by: {f.get('name', f.get('address', '?'))}")
        for c in callers_list:
            fn = c.get("function", {})
            depth = c.get("depth", "?")
            lines.append(f"    caller (depth {depth}): {fn.get('name', fn.get('address', '?'))}")

    return "\n".join(lines)


def format_structs_list(response: dict, offset: int = 0, **kwargs) -> str:
    """Format struct list as plain text"""
    if not response.get("success", False):
        return format_error(response)

    items = response.get("result", [])
    total = _list_total(response, items)

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
            fsize = f.get("length", f.get("size", "?"))  # StructFieldDto field is 'length'
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


def format_generic_dict(response: dict, **kwargs) -> str:
    """Format a dictionary result as key-value pairs"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", response)
    if not isinstance(result, dict):
        return str(result)

    lines = []
    for k, v in result.items():
        if k == "_links" or k == "success" or k == "timestamp":
            continue
        lines.append(f"{k}: {v}")
    return "\n".join(lines)


def format_generic_list(response: dict, **kwargs) -> str:
    """Format a list result as plain text lines"""
    if not response.get("success", False):
        return format_error(response)

    items = response.get("result", [])
    if not isinstance(items, list):
        return str(items)

    if not items:
        return "No items found."

    lines = []
    for item in items:
        if isinstance(item, dict):
            # Try to find a name or description field
            label = item.get("name") or item.get("path") or item.get("id") or str(item)
            lines.append(f"  {label}")
        else:
            lines.append(f"  {item}")
    return "\n".join(lines)


def format_classes_list(response: dict, offset: int = 0, limit: int = 100, **kwargs) -> str:
    """Format classes list as text"""
    items = response.get("result", [])
    total = _list_total(response, items)

    lines = [f"Classes ({offset+1}-{offset+len(items)} of {total}):", ""]

    for c in items:
        name = c.get("name", "???")
        namespace = c.get("namespace", "")
        simple = c.get("simpleName", name)
        if namespace and namespace != "default":
            lines.append(f"  {simple}  ({namespace})")
        else:
            lines.append(f"  {simple}")

    return "\n".join(lines)


def format_symbols_list(response: dict, offset: int = 0, limit: int = 100, **kwargs) -> str:
    """Format symbols list as text"""
    items = response.get("result", [])
    total = _list_total(response, items)

    lines = [f"Symbols ({offset+1}-{offset+len(items)} of {total}):", ""]

    for s in items:
        addr = s.get("address", "???")
        name = s.get("name", "???")
        stype = s.get("type", "")
        primary = " *" if s.get("isPrimary") else ""
        lines.append(f"  {addr}  {stype:<12}  {name}{primary}")

    return "\n".join(lines)


def format_imports_exports(response: dict, offset: int = 0, limit: int = 100, **kwargs) -> str:
    """Format imports/exports list as text"""
    items = response.get("result", [])
    total = _list_total(response, items)

    lines = [f"Entries ({offset+1}-{offset+len(items)} of {total}):", ""]

    for item in items:
        addr = item.get("address", "???")
        name = item.get("name", "???")
        lines.append(f"  {addr}  {name}")

    return "\n".join(lines)


def format_segments_list(response: dict, offset: int = 0, limit: int = 100, **kwargs) -> str:
    """Format segments list as text"""
    items = response.get("result", [])
    total = _list_total(response, items)

    lines = [f"Segments ({offset+1}-{offset+len(items)} of {total}):", ""]

    for seg in items:
        name = seg.get("name", "???")
        start = seg.get("start", "???")
        end = seg.get("end", "???")
        size = seg.get("size", 0)
        # MemoryBlockDto serializes isRead/isWrite/isExecute/isInitialized.
        perms = ""
        perms += "R" if seg.get("isRead", seg.get("readable")) else "-"
        perms += "W" if seg.get("isWrite", seg.get("writable")) else "-"
        perms += "X" if seg.get("isExecute", seg.get("executable")) else "-"
        init = "init" if seg.get("isInitialized", seg.get("initialized")) else "uninit"
        lines.append(f"  {name:<16}  {start}-{end}  {size:>8} bytes  {perms}  {init}")

    return "\n".join(lines)


def format_namespaces_list(response: dict, offset: int = 0, limit: int = 100, **kwargs) -> str:
    """Format namespaces list as text"""
    items = response.get("result", [])
    total = _list_total(response, items)

    lines = [f"Namespaces ({offset+1}-{offset+len(items)} of {total}):", ""]

    for ns in items:
        if isinstance(ns, str):
            lines.append(f"  {ns}")
        else:
            lines.append(f"  {ns.get('name', '???')}")

    return "\n".join(lines)


def format_variables_list(response: dict, offset: int = 0, limit: int = 100, **kwargs) -> str:
    """Format variables list as text"""
    items = response.get("result", [])
    total = _list_total(response, items)

    lines = [f"Variables ({offset+1}-{offset+len(items)} of ~{total}):", ""]

    for v in items:
        addr = v.get("address", "???")
        name = v.get("name", "???")
        vtype = v.get("type", "")
        dtype = v.get("dataType", "")
        func = v.get("function", "")
        loc = f"  [{func}]" if func else ""
        lines.append(f"  {addr}  {vtype:<10}  {dtype:<16}  {name}{loc}")

    return "\n".join(lines)


def format_datatypes_list(response: dict, offset: int = 0, limit: int = 100, **kwargs) -> str:
    """Format datatypes list as text"""
    items = response.get("result", [])
    total = _list_total(response, items)

    lines = [f"Data Types ({offset+1}-{offset+len(items)} of {total}):", ""]

    for dt in items:
        name = dt.get("name", "???")
        kind = dt.get("kind", "")
        category = dt.get("category", "/")
        length = dt.get("length", 0)
        extra = ""
        if kind in ("struct", "union"):
            extra = f"  ({dt.get('numComponents', 0)} fields)"
        elif kind == "enum":
            extra = f"  ({dt.get('numValues', 0)} values)"
        lines.append(f"  {kind:<8}  {name:<24}  {length:>4}B  {category}{extra}")

    return "\n".join(lines)


# ================= Formatter Registry & Decorator =================

def format_scalars(response: dict, **kwargs) -> str:
    """Format scalar search results as plain text"""
    if not response.get("success", False):
        return format_error(response)

    items = response.get("result", [])
    meta = response.get("meta") or {}
    offset = meta.get("offset", 0)

    if not items:
        if meta.get("scanTruncated"):
            return "No scalars found (scan truncated before completing; narrow with in_function or a more specific value)"
        return "No scalars found"

    lines = [f"Scalars ({offset + 1}-{offset + len(items)}):", ""]
    for s in items:
        addr = s.get("address", "")
        hexv = s.get("hexValue", "")
        op = s.get("operandIndex", "?")
        instr = s.get("instruction", "")
        in_fn = s.get("inFunction") or "-"
        line = f"  {addr}  {hexv:<12} op{op}  {instr}  [in {in_fn}]"
        to_fn = s.get("toFunction")
        if to_fn:
            line += f"  -> calls {to_fn}"
        lines.append(line)

    if meta.get("scanTruncated"):
        lines.append("")
        lines.append("  (scan stopped early to keep the UI responsive; results may be incomplete "
                     "- narrow with in_function or a more specific value)")
    elif (response.get("_links") or {}).get("next"):
        lines.append(f"\n  ... more available (use offset={offset + len(items)})")

    return "\n".join(lines)


FORMATTERS = {
    "functions_list": format_functions_list,
    "functions_get": format_function_info,
    "functions_get_containing": format_functions_list,
    "functions_get_next": format_functions_list,
    "functions_get_prev": format_functions_list,
    "functions_decompile": format_decompile,
    "functions_disassemble": format_disassembly,
    "functions_get_variables": format_variables,
    "xrefs_list": format_xrefs,
    "scalars_search": format_scalars,
    "data_list": format_data_list,
    "data_list_strings": format_strings,
    "memory_read": format_memory,
    "memory_disassemble": format_disassembly,
    "instances_list": format_instances,
    "instances_discover": format_instances,
    "instances_current": format_instance_info,
    "structs_list": format_structs_list,
    "structs_get": format_struct_info,
    "analysis_get_callgraph": format_callgraph,
    "analysis_get_dataflow": format_dataflow,
    "analysis_status": format_generic_dict,
    "ui_get_current_address": format_generic_dict,
    "ui_get_current_function": format_function_info,
    "comments_get": format_generic_dict,
    "projects_list": format_generic_list,
    "projects_get": format_generic_dict,
    "programs_list": format_generic_list,
    "programs_get": format_generic_dict,
    "project_info": format_project_info,
    "project_list_files": format_project_files,
    "classes_list": format_classes_list,
    "symbols_list": format_symbols_list,
    "symbols_imports": format_imports_exports,
    "symbols_exports": format_imports_exports,
    "segments_list": format_segments_list,
    "namespaces_list": format_namespaces_list,
    "variables_list": format_variables_list,
    "datatypes_list": format_datatypes_list,
    "datatypes_search": format_datatypes_list,
    "analysis_find_call_paths": format_call_paths,
    "analysis_trace_string_usage": format_string_usage,
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
    if not isinstance(response, dict) and not hasattr(response, "copy"):
        return response

    # Make a copy to avoid modifying the original
    result = response.copy() if hasattr(response, "copy") else dict(response)
    
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
                if hasattr(item, "copy") and hasattr(item, "pop"):
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
        elif hasattr(result["result"], "copy") and hasattr(result["result"], "pop"):
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
            if "decompilation" in result_copy:
                result_copy["decompiled_text"] = result_copy["decompilation"]
            elif "ccode" in result_copy:
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

def register_instance(port: int, url: str | None = None) -> str:
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
                                project_info["image_base"] = result.get("imageBase", result.get("image_base", ""))
                                
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
                                            info["image_base"] = result.get("imageBase", result.get("image_base", ""))
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
def ghidra_instance(port: int | None = None) -> dict:
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
    
    stats = result.get("statistics") or {}
    instance_info = {
        "port": port,
        "url": get_instance_url(port),
        "program_name": result.get("name", "unknown"),
        "program_id": result.get("programId", "unknown"),
        "language": result.get("languageId", "unknown"),
        "compiler": result.get("compilerSpecId", "unknown"),
        "base_address": result.get("imageBase", "0x0"),
        "function_count": stats.get("functionCount"),
        "symbol_count": stats.get("symbolCount")
    }
    
    # Add project information if available
    if "project" in active_instances[port]:
        instance_info["project"] = active_instances[port]["project"]
    
    return instance_info

@mcp.resource(uri="/instance/{port}/function/decompile/address/{address}")
def decompiled_function_by_address(port: int | None = None, address: str | None = None) -> str:
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
        for key in ["decompiled_text", "decompilation", "ccode", "decompiled"]:
            if key in result:
                return result[key]
    
    return "Error: Could not extract decompiled code from response"

@mcp.resource(uri="/instance/{port}/function/decompile/name/{name}")
def decompiled_function_by_name(port: int | None = None, name: str | None = None) -> str:
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
        for key in ["decompiled_text", "decompilation", "ccode", "decompiled"]:
            if key in result:
                return result[key]
    
    return "Error: Could not extract decompiled code from response"

@mcp.resource(uri="/instance/{port}/function/info/address/{address}")
def function_info_by_address(port: int | None = None, address: str | None = None) -> dict:
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
def function_info_by_name(port: int | None = None, name: str | None = None) -> dict:
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
def disassembly_by_address(port: int | None = None, address: str | None = None) -> str:
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
def disassembly_by_name(port: int | None = None, name: str | None = None) -> str:
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
def analyze_function_prompt(name: str | None = None, address: str | None = None, port: int | None = None):
    """A prompt to guide the LLM through analyzing a function
    
    Args:
        name: Function fully-qualified name (e.g. "FOM::Read"; a bare name matches the global namespace only), mutually exclusive with address
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
def identify_vulnerabilities_prompt(name: str | None = None, address: str | None = None, port: int | None = None):
    """A prompt to help identify potential vulnerabilities in a function
    
    Args:
        name: Function fully-qualified name (e.g. "FOM::Read"; a bare name matches the global namespace only), mutually exclusive with address
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
def reverse_engineer_binary_prompt(port: int | None = None):
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
def instances_discover(host: str | None = None) -> dict:
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
def instances_register(port: int, url: str | None = None) -> str:
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
                  name_contains: str | None = None,
                  name_matches_regex: str | None = None,
                  addr_min: str | None = None,
                  addr_max: str | None = None,
                  port: int | None = None) -> dict:
    """List functions with filtering and pagination

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        name_contains: Substring name filter (case-insensitive)
        name_matches_regex: Regex name filter
        addr_min: Only return functions at or above this address (hex)
        addr_max: Only return functions at or below this address (hex)
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
    if addr_min:
        params["addr_min"] = addr_min
    if addr_max:
        params["addr_max"] = addr_max

    response = safe_get(port, "functions", params)
    simplified = simplify_response(response)

    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)

    return simplified

@mcp.tool()
@text_output
def functions_get(name: str | None = None, address: str | None = None, port: int | None = None) -> dict:
    """Get detailed information about a function
    
    Args:
        name: Function fully-qualified name (e.g. "FOM::Read"; a bare name matches the global namespace only), mutually exclusive with address
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
def functions_get_containing(address: str, port: int | None = None) -> dict:
    """Find the function containing the specified address

    Args:
        address: Memory address in hex format
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: List containing the function information if found
    """
    port = _get_instance_port(port)
    
    params = {
        "containing_addr": address
    }
    
    response = safe_get(port, "functions", params)
    return simplify_response(response)

@mcp.tool()
@text_output
def functions_get_next(address: str, port: int | None = None) -> dict:
    """Get the next function after the given address (by memory order)

    Args:
        address: Reference address in hex format
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Function immediately after the given address, or empty result if none
    """
    port = _get_instance_port(port)
    response = safe_get(port, "functions", {"after": address})
    return simplify_response(response)


@mcp.tool()
@text_output
def functions_get_prev(address: str, port: int | None = None) -> dict:
    """Get the previous function before the given address (by memory order)

    Args:
        address: Reference address in hex format
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Function immediately before the given address, or empty result if none
    """
    port = _get_instance_port(port)
    response = safe_get(port, "functions", {"before": address})
    return simplify_response(response)


@mcp.tool()
@text_output
def functions_decompile(name: str | None = None, address: str | None = None,
                        syntax_tree: bool = False, style: str = "normalize",
                        show_constants: bool = True, timeout: int = DEFAULT_DECOMPILATION_TIMEOUT,
                        start_line: int | None = None, end_line: int | None = None, max_lines: int | None = None,
                        port: int | None = None) -> dict:
    """Get decompiled code for a function with optional line filtering and configurable options

    Args:
        name: Function fully-qualified name (e.g. "FOM::Read"; a bare name matches the global namespace only), mutually exclusive with address
        address: Function address in hex format (mutually exclusive with name)
        syntax_tree: Include syntax tree (default: False)
        style: Decompiler style (default: "normalize")
        show_constants: Show actual constant values (strings, numbers) instead of placeholder addresses (default: True)
        timeout: Decompilation timeout in seconds (default: GHIDRA_DECOMP_TIMEOUT or auto default)
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
def functions_disassemble(name: str | None = None, address: str | None = None, offset: int = 0, limit: int = 100, port: int | None = None) -> dict:
    """Get disassembly for a function

    Args:
        name: Function fully-qualified name (e.g. "FOM::Read"; a bare name matches the global namespace only), mutually exclusive with address
        address: Function address in hex format (mutually exclusive with name)
        offset: Number of instructions to skip (default 0)
        limit: Maximum number of instructions per page (default 100, server max 1000).
            Long functions are paginated; the text output footer reports the total
            instruction count and the next offset to fetch the rest.
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
def functions_create(address: str, port: int | None = None) -> dict:
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
def functions_rename(old_name: str | None = None, address: str | None = None, new_name: str = "", port: int | None = None) -> dict:
    """Rename a function
    
    Args:
        old_name: Current fully-qualified function name (e.g. "FOM::Read"; bare = global only), mutually exclusive with address
        address: Function address in hex format (mutually exclusive with name)
        new_name: New fully-qualified name; "A::B::foo" moves into namespace A::B (created if absent), a leading "::" or "Global::" moves to the global namespace, a bare name keeps the current namespace
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
def functions_set_signature(name: str | None = None, address: str | None = None, signature: str = "", port: int | None = None) -> dict:
    """Set function signature/prototype
    
    Args:
        name: Function fully-qualified name (e.g. "FOM::Read"; a bare name matches the global namespace only), mutually exclusive with address
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
def functions_delete(name: str | None = None, address: str | None = None, port: int | None = None) -> dict:
    """Delete a function

    Args:
        name: Function fully-qualified name (e.g. "FOM::Read"; a bare name matches the global namespace only), mutually exclusive with address
        address: Function address in hex format (mutually exclusive with name)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result with deletion status
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

    response = safe_delete(port, endpoint)
    return simplify_response(response)

@mcp.tool()
@text_output
def functions_update_variable(address: str, variable_name: str,
                              new_name: str | None = None, new_data_type: str | None = None,
                              port: int | None = None) -> dict:
    """Update a local variable in a function

    Args:
        address: Function address in hex format
        variable_name: Existing variable name
        new_name: New variable name (optional)
        new_data_type: New variable data type (optional)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result
    """
    if not address or not variable_name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "address and variable_name parameters are required"
            },
            "timestamp": int(time.time() * 1000)
        }

    if not new_name and not new_data_type:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "At least one of new_name or new_data_type must be provided"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    payload = {}
    if new_name:
        payload["name"] = new_name
    if new_data_type:
        payload["data_type"] = new_data_type

    endpoint = f"functions/{address}/variables/{quote(variable_name)}"
    response = safe_patch(port, endpoint, payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def functions_get_variables(name: str | None = None, address: str | None = None, port: int | None = None) -> dict:
    """Get variables for a function
    
    Args:
        name: Function fully-qualified name (e.g. "FOM::Read"; a bare name matches the global namespace only), mutually exclusive with address
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
def memory_read(address: str, length: int = 16, format: str = "hex", segment: str | None = None,
                port: int | None = None) -> dict:
    """Read bytes from memory

    Args:
        address: Memory address in hex format
        length: Number of bytes to read (default: 16)
        format: Output format - "hex", "base64", or "string" (default: "hex")
        segment: Optional memory segment/overlay name to qualify the address (e.g. "runtime")
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

    # GET /memory is the block list; the read endpoint is GET /memory/{address}.
    params = {
        "length": length,
        "format": format
    }
    if segment and ":" not in address:
        address = f"{segment}:{address}"

    response = safe_get(port, f"memory/{quote(address, safe=':')}", params)
    simplified = simplify_response(response)

    # Ensure the result is simple and directly usable
    if "result" in simplified and isinstance(simplified["result"], dict):
        result = simplified["result"]

        memory_info = {
            "success": True,
            "address": result.get("address", address),
            "length": result.get("length", result.get("bytesRead", length)),
            "format": format,
            "timestamp": simplified.get("timestamp", int(time.time() * 1000))
        }

        # Server sends "hex" (hex string) or "bytes" (int array); accept the
        # legacy field names too for older plugin builds.
        if "hex" in result:
            memory_info["hexBytes"] = result["hex"]
        elif "hexBytes" in result:
            memory_info["hexBytes"] = result["hexBytes"]
        if "bytes" in result:
            memory_info["bytes"] = result["bytes"]
        if "rawBytes" in result:
            memory_info["rawBytes"] = result["rawBytes"]
        if "block" in result:
            memory_info["block"] = result["block"]
            memory_info["permissions"] = result.get("permissions")

        return memory_info

    return simplified

@mcp.tool()
@text_output
def memory_write(address: str, bytes_data: str, format: str = "hex", port: int | None = None) -> dict:
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

    # The server only understands hex (it strips non-hex chars from the payload,
    # which would silently corrupt base64/string input). Convert client-side.
    if format == "base64":
        try:
            bytes_data = base64.b64decode(bytes_data).hex()
        except Exception as e:
            return {
                "success": False,
                "error": {"code": "INVALID_BASE64", "message": f"Invalid base64 data: {e}"},
                "timestamp": int(time.time() * 1000)
            }
    elif format == "string":
        bytes_data = bytes_data.encode("utf-8").hex()
    elif format == "hex":
        cleaned = bytes_data.replace(" ", "")
        if len(cleaned) % 2 != 0 or any(c not in "0123456789abcdefABCDEF" for c in cleaned):
            return {
                "success": False,
                "error": {"code": "INVALID_HEX", "message": "bytes_data must be an even-length hex string"},
                "timestamp": int(time.time() * 1000)
            }
        bytes_data = cleaned

    payload = {
        "bytes": bytes_data,
        "format": "hex"
    }

    # Memory write is handled by ProgramEndpoints, not MemoryEndpoints
    response = safe_patch(port, f"programs/current/memory/{address}", payload)
    return simplify_response(response)


@mcp.tool()
@text_output
def emulation_reset(start: str, registers: dict | None = None,
                    memory: list | None = None, port: int | None = None) -> dict:
    """Start a fresh PCode emulation session at an address.

    Args:
        start: Start address in hex (PC is set here)
        registers: Optional {register_name: hex_value} initial register writes
        memory: Optional [{"address": hex, "hex": "ca fe"}] initial memory writes
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: initial emulation state (pc, registers, steps, stopReason)
    """
    port = _get_instance_port(port)
    body: dict = {"start": start}
    if registers:
        body["registers"] = registers
    if memory:
        body["memory"] = memory
    return simplify_response(safe_post(port, "emulation/reset", body))


@mcp.tool()
@text_output
def emulation_run(until: str | None = None, max_steps: int = 100000,
                  trace: bool = False, port: int | None = None) -> dict:
    """Run the emulation session until an address, a breakpoint, an error, or max_steps.

    Args:
        until: Optional stop address in hex
        max_steps: Hard step cap (default 100000, server caps at 5000000)
        trace: When true, returns the list of executed instruction addresses
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: final emulation state including stopReason and optional trace
    """
    port = _get_instance_port(port)
    body: dict = {"max_steps": max_steps, "trace": trace}
    if until:
        body["until"] = until
    return simplify_response(safe_post(port, "emulation/run", body))


@mcp.tool()
@text_output
def emulation_step(count: int = 1, trace: bool = False, port: int | None = None) -> dict:
    """Single-step the emulation session count times.

    Args:
        count: Number of instructions to step (default 1)
        trace: When true, returns executed instruction addresses
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(safe_post(port, "emulation/step", {"count": count, "trace": trace}))


@mcp.tool()
@text_output
def emulation_state(port: int | None = None) -> dict:
    """Get the current emulation session state without executing.

    Args:
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(safe_get(port, "emulation/state"))


@mcp.tool()
@text_output
def emulation_read_register(name: str, port: int | None = None) -> dict:
    """Read an emulated register value (hex).

    Args:
        name: Register name (e.g. "RAX", "RIP")
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(safe_get(port, f"emulation/registers/{quote(name)}"))


@mcp.tool()
@text_output
def emulation_write_register(name: str, value: str, port: int | None = None) -> dict:
    """Write an emulated register value.

    Args:
        name: Register name (e.g. "RAX")
        value: Hex value (e.g. "0x140075000")
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(safe_post(port, "emulation/registers", {"name": name, "value": value}))


@mcp.tool()
@text_output
def emulation_read_memory(address: str, length: int = 64, port: int | None = None) -> dict:
    """Read bytes from emulated memory (hex), e.g. to dump decrypted data.

    Args:
        address: Memory address in hex
        length: Number of bytes (default 64, server caps at 4096)
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(
        safe_get(port, f"emulation/memory/{quote(address, safe=':')}", {"length": length}))


@mcp.tool()
@text_output
def emulation_write_memory(address: str, hex_bytes: str, port: int | None = None) -> dict:
    """Write bytes to emulated memory.

    Args:
        address: Memory address in hex
        hex_bytes: Hex byte string (e.g. "9090")
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(safe_post(port, "emulation/memory", {"address": address, "hex": hex_bytes}))


@mcp.tool()
@text_output
def emulation_set_breakpoint(address: str, port: int | None = None) -> dict:
    """Set an emulation breakpoint at an address.

    Args:
        address: Address in hex
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(safe_post(port, "emulation/breakpoints", {"address": address}))


@mcp.tool()
@text_output
def emulation_clear_breakpoint(address: str, port: int | None = None) -> dict:
    """Clear an emulation breakpoint previously set at an address.

    Args:
        address: Address in hex
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(
        safe_delete(port, f"emulation/breakpoints/{quote(address, safe=':')}"))


@mcp.tool()
@text_output
def emulation_hook_set(address: str, action: str, return_value: str | None = None,
                       mem_writes: list | None = None, port: int | None = None) -> dict:
    """Set an emulation hook at an address (PCode engine).

    Args:
        address: Hook address (hex)
        action: Hook action ("return_const", "skip", "log", "trap")
        return_value: Optional hex return value (only for "return_const")
        mem_writes: Optional list of {"address": "hex", "hex": "hex_bytes"} (only for "return_const")
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    body = {"address": address, "action": action}
    if return_value is not None:
        body["return_value"] = return_value
    if mem_writes is not None:
        body["mem_writes"] = mem_writes
    return simplify_response(safe_post(port, "emulation/hooks", body))


@mcp.tool()
@text_output
def emulation_hook_clear(address: str, port: int | None = None) -> dict:
    """Clear an emulation hook at an address (PCode engine).

    Args:
        address: Hook address (hex)
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(
        safe_delete(port, f"emulation/hooks/{quote(address, safe=':')}"))


@mcp.tool()
@text_output
def emulation_hook_list(port: int | None = None) -> dict:
    """List all emulation hooks currently registered (PCode engine).

    Args:
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(safe_get(port, "emulation/hooks"))


@mcp.tool()
@text_output
def emulation_call(func: str, args: list | None = None, convention: str = "sysv",
                   trace: bool = False, port: int | None = None) -> dict:
    """Call a function using PCode emulation with calling-convention logic.

    Args:
        func: Target function name or hex address
        args: List of arguments (ints, hex strings, or {"bytes": "hex_string"})
        convention: Calling convention ("sysv" or "ms", default "sysv")
        trace: Whether to collect an execution trace
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    body = {"func": func, "convention": convention, "trace": trace}
    if args is not None:
        body["args"] = args
    return simplify_response(safe_post(port, "emulation/call", body))


@mcp.tool()
@text_output
def emulation_dispose(port: int | None = None) -> dict:
    """Dispose the emulation session and free the emulator.

    Args:
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(safe_delete(port, "emulation"))


@mcp.tool()
@text_output
def unicorn_reset(start: str, registers: dict | None = None, stack: bool = True,
                  port: int | None = None) -> dict:
    """Start a fresh Unicorn emulation session that lazily pulls bytes from Ghidra.

    Args:
        start: Start address in hex (RIP is set here)
        registers: Optional {register_name: hex_value} initial writes
        stack: Auto-map a default 1 MiB scratch stack and point RSP/RBP at it
            (default True; pass False to manage the stack yourself)
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        from ghydra.dynamic.unicorn_engine import UnicornSession
        from ghydra.dynamic.ghidra_provider import make_ghidra_provider
        from ghydra.client.http_client import GhidraHTTPClient
    except RuntimeError as e:
        return _unicorn_error(str(e))
    except ImportError:
        return _unicorn_error("unicorn not installed; pip install ghydramcp[unicorn]")

    try:
        client = GhidraHTTPClient(port=port)
        session = UnicornSession(byte_provider=make_ghidra_provider(client))
    except RuntimeError as e:
        return _unicorn_error(str(e))

    start_int = int(start, 16)
    session.set_register("RIP", start_int)
    stack_region = None
    if stack:
        base, size = _apply_default_stack(session)
        stack_region = {"base": hex(base), "size": size}
    if registers:
        for name, value in registers.items():
            session.set_register(name, int(value, 16))   # explicit overrides win (e.g. RSP)
    with _unicorn_lock:
        _UNICORN_SESSIONS[port] = session
    return {"success": True, "start": hex(start_int), "lazy_mapping": "ghidra",
            "stack": stack_region, "timestamp": int(time.time() * 1000)}


@mcp.tool()
@text_output
def unicorn_run(until: str, count: int = 100000, trace: bool = False,
                port: int | None = None) -> dict:
    """Run the Unicorn session until an address, instruction count, or fault.

    success is true only when the target address is reached (stop_reason DONE).
    A run that hits the instruction cap returns stop_reason "COUNT" with
    success=false: it ran cleanly but stopped at the budget without reaching the
    target -- raise `count` or set a closer `until`; it is NOT a fault, and the
    emulated memory up to the cap is valid (just incomplete). A failed lazy byte
    fetch from Ghidra returns "LAZY_FETCH_FAILED" with the cause in last_error;
    exhausting the lazy-page budget returns "LAZY_CAP_REACHED" (raise the
    engine's max_lazy_pages); any other emulator fault returns "ERROR". On a
    "LAZY_FETCH_FAILED"/"ERROR" stop the emulated memory may be partial or
    corrupt and must not be trusted.

    Args:
        until: Stop address in hex (required; emulation runs begin..until)
        count: Instruction cap (default 100000)
        trace: Return executed instruction addresses and memory writes
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e))
    begin = session.get_register("RIP")
    state = session.run(begin=begin, until=int(until, 16), count=count, trace=trace)
    return _unicorn_run_result(state)


@mcp.tool()
@text_output
def unicorn_read_memory(address: str, length: int = 64, port: int | None = None) -> dict:
    """Read bytes from the Unicorn session's memory (e.g. dump decrypted data).

    Args:
        address: Address in hex
        length: Number of bytes (default 64)
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e))
    data = session.read_memory(int(address, 16), length)
    return {"success": True, "address": address, "length": length,
            "hex": data.hex(), "timestamp": int(time.time() * 1000)}


@mcp.tool()
@text_output
def unicorn_set_register(name: str, value: str, port: int | None = None) -> dict:
    """Set a Unicorn register value.

    Args:
        name: Register name (e.g. "RAX")
        value: Hex value
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e))
    session.set_register(name, int(value, 16))
    return {"success": True, "name": name, "value": value,
            "timestamp": int(time.time() * 1000)}


@mcp.tool()
@text_output
def unicorn_map(address: str, size: int, port: int | None = None) -> dict:
    """Map a zero-filled scratch region into the Unicorn session.

    The purist lazy mapper serves only real Ghidra image bytes, so emulated
    code that touches non-image memory (a stack push, a heap/IO buffer) faults
    with LAZY_FETCH_FAILED unless that region is mapped first. Use this to set
    up stack/scratch/output buffers before unicorn_run. Page-aligned by the
    engine.

    Args:
        address: Region start in hex
        size: Region size in bytes
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e))
    addr = int(address, 16)
    session.map_bytes(addr, b"\x00" * size)
    return {"success": True, "address": hex(addr), "size": size,
            "timestamp": int(time.time() * 1000)}


@mcp.tool()
@text_output
def unicorn_get_state(port: int | None = None) -> dict:
    """Get the current Unicorn register state without executing.

    Args:
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e))
    regs = ("RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RSP", "RBP", "RIP",
            "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
    return {"success": True,
            "registers": {r: hex(session.get_register(r)) for r in regs},
            "timestamp": int(time.time() * 1000)}


@mcp.tool()
@text_output
def unicorn_dispose(port: int | None = None) -> dict:
    """Dispose the Unicorn session for a port.

    Args:
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    with _unicorn_lock:
        _UNICORN_SESSIONS.pop(port, None)
    return {"success": True, "session": "disposed", "timestamp": int(time.time() * 1000)}


@mcp.tool()
@text_output
def unicorn_hook_set(address: str, action: str, return_value: str | None = None,
                     mem_writes: list | None = None, port: int | None = None) -> dict:
    """Register a hook on an address to stub a call/import during emulation.

    action is one of: "return_const" (set RAX to return_value and simulate ret;
    may carry mem_writes side-effects), "skip" (simulate ret, RAX untouched),
    "log" (record the hit and continue), "trap" (stop with stop_reason HOOK_TRAP).
    mem_writes (list of {"address": hex, "hex": bytes}) are allowed only with
    return_const. Hooks persist across unicorn_run/unicorn_call until cleared or
    the session is reset.

    Args:
        address: Hook address in hex
        action: return_const | skip | log | trap
        return_value: Hex value for return_const (optional)
        mem_writes: [{"address": hex, "hex": hexbytes}] for return_const (optional)
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e), code="NO_SESSION")
    from ghydra.dynamic.unicorn_engine import Hook
    try:
        rv = int(return_value, 16) if return_value is not None else None
        mw = ([{"address": int(w["address"], 16), "hex": w["hex"]} for w in mem_writes]
              if mem_writes else None)
        session.set_hook(int(address, 16), Hook(action=action, return_value=rv, mem_writes=mw))
    except ValueError as e:
        return _unicorn_error(str(e))
    return {"success": True, "address": hex(int(address, 16)), "action": action,
            "timestamp": int(time.time() * 1000)}


@mcp.tool()
@text_output
def unicorn_hook_clear(address: str, port: int | None = None) -> dict:
    """Remove a Unicorn hook previously set at an address.

    Args:
        address: Hook address in hex
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e), code="NO_SESSION")
    try:
        addr_int = int(address, 16)
    except ValueError:
        return _unicorn_error(f"invalid address: {address!r}", code="VALIDATION")
    removed = session.clear_hook(addr_int)
    return {"success": True, "address": hex(addr_int), "removed": removed,
            "timestamp": int(time.time() * 1000)}


@mcp.tool()
@text_output
def unicorn_hook_list(port: int | None = None) -> dict:
    """List the hooks registered on the current Unicorn session.

    Args:
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e), code="NO_SESSION")
    hooks = [{"address": hex(a), "action": h.action,
              "return_value": (hex(h.return_value) if h.return_value is not None else None),
              "mem_writes": h.mem_writes}
             for a, h in session.list_hooks().items()]
    return {"success": True, "hooks": hooks, "timestamp": int(time.time() * 1000)}


@mcp.tool()
@text_output
def unicorn_call(func: str, args: list | None = None, convention: str = "sysv",
                 count: int = 1_000_000, trace: bool = False,
                 port: int | None = None) -> dict:
    """Call a function in the Unicorn session and report its return value.

    Precondition: use unicorn_hook_set to stub any imports the function will
    call, or they will fault. Hooks persist until cleared or the session is
    reset.

    Sets up the x86-64 calling convention (sysv default, or ms), runs the
    function to a synthetic return address, and returns the return register.
    args is a list of ints and/or {"bytes": hex} pointer args; floats and
    by-value structs are not supported.

    success is true only when the function returned cleanly (stop_reason DONE).
    A HOOK_TRAP / REDIRECT_STORM / LAZY_FETCH_FAILED / ERROR stop returns
    success=false with the partial state so you can add a missing hook and retry.

    Args:
        func: Function entry address in hex
        args: List of int args and/or {"bytes": "hex"} pointer args (optional)
        convention: "sysv" (default) or "ms"
        count: Instruction budget (default 1_000_000)
        trace: Collect executed-instruction trace + memory writes
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e), code="NO_SESSION")
    from ghydra.dynamic.unicorn_engine import StopReason
    try:
        state = session.call(int(func, 16), args or [], convention,
                             count=count, trace=trace)
    except ValueError as e:
        return _unicorn_error(str(e))
    payload = {
        "pc": hex(state["pc"]),
        "stop_reason": state["stop_reason"],
        "convention": state["convention"],
        "return_value": hex(state["return_value"]),
        "args_passed": [hex(a) for a in state["args_passed"]],
        "last_error": state["last_error"],
        "timestamp": int(time.time() * 1000),
    }
    if state["stop_reason"] == StopReason.DONE:
        payload["success"] = True
        payload["registers"] = {k: hex(v) for k, v in state["registers"].items()}
    else:
        payload["success"] = False
        payload["error"] = {"code": state["stop_reason"],
                            "message": state["last_error"] or state["stop_reason"]}
    return payload


@mcp.tool()
@text_output
def memory_disassemble(address: str, limit: int = 50, offset: int = 0, port: int | None = None) -> dict:
    """Disassemble instructions at an arbitrary address (not tied to a function)

    Args:
        address: Start address in hex format
        limit: Number of instructions to return (default: 50)
        offset: Number of instructions to skip (default: 0)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Contains instructions list with address, bytes, mnemonic, operands
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

    params = {"limit": limit}
    if offset > 0:
        params["offset"] = offset

    response = safe_get(port, f"memory/{address}/disassembly", params)
    return simplify_response(response)

# Xrefs tools
@mcp.tool()
@text_output
def xrefs_list(to_addr: str | None = None, from_addr: str | None = None, type: str | None = None,
              offset: int = 0, limit: int = 100, port: int | None = None) -> dict:
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
def data_list(offset: int = 0, limit: int = 100, addr: str | None = None,
            name: str | None = None, name_contains: str | None = None, type: str | None = None,
            port: int | None = None) -> dict:
    """List data items with filtering and pagination
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        addr: Filter by address (hexadecimal)
        name: Exact name match filter (case-sensitive)
        name_contains: Substring name filter (case-insensitive)
        type: Filter by data type (e.g. "string", "dword")
        port: Specific Ghidra instance port (optional)
    
    Returns:
        dict: Data items matching the filters. For address lookups, returns
              defined data first and falls back to symbol labels if no defined
              data exists at that address.
    """
    port = _get_instance_port(port)
    
    # Address lookup has its own route; the /data list filters are label-based.
    if addr:
        response = safe_get(port, f"data/{quote(addr)}", {})
        simplified = simplify_response(response)
        if isinstance(simplified, dict) and simplified.get("success") and "result" in simplified:
            # normalize single item to a list so formatters keep working
            if isinstance(simplified["result"], dict):
                simplified["result"] = [simplified["result"]]
            simplified.setdefault("size", len(simplified["result"]))
        return simplified

    params = {
        "offset": offset,
        "limit": limit
    }
    # Server filters are label/label_contains; map the friendlier arg names.
    if name:
        params["label"] = name
    if name_contains:
        params["label_contains"] = name_contains
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
def data_create(address: str, data_type: str, size: int | None = None, port: int | None = None) -> dict:
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
    
    payload = {"type": data_type}
    if size is not None:
        payload["size"] = size

    response = safe_post(port, f"data/{address}", payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def data_list_strings(offset: int = 0, limit: int = 2000, filter: str | None = None, port: int | None = None) -> dict:
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
def data_rename(address: str, name: str, port: int | None = None) -> dict:
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

    response = safe_patch(port, f"data/{address}", {"name": name})
    return simplify_response(response)

@mcp.tool()
@text_output
def data_delete(address: str, port: int | None = None) -> dict:
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

    response = safe_delete(port, f"data/{address}")
    return simplify_response(response)

@mcp.tool()
@text_output
def data_set_type(address: str, data_type: str, port: int | None = None) -> dict:
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

    response = safe_patch(port, f"data/{address}/type", {"type": data_type})
    return simplify_response(response)

# Scalar tools
@mcp.tool()
@text_output
def scalars_search(value: str, in_function: str | None = None, to_function: str | None = None,
                   offset: int = 0, limit: int = 100, port: int | None = None) -> dict:
    """Search for occurrences of a specific scalar (constant) value in instructions

    Finds where a constant appears as an instruction operand, like Ghidra's "Search For
    Scalars". For a named constant, resolve its value with data_list / datatypes first.

    Args:
        value: The scalar value to search for (hex "0x..." or decimal)
        in_function: Only matches inside functions whose name contains this substring
            (case-insensitive). Strongly preferred on large binaries: it scans only the
            matching functions instead of the whole program.
        to_function: Only matches where the instruction feeds a nearby call to a function
            whose name contains this substring (e.g. find the 0 passed to memset).
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Scalar occurrences with address, instruction, and function context. On a large
        program an unfiltered or to_function search may report scanTruncated when it hits a
        time budget; narrow it with in_function for complete results.
    """
    port = _get_instance_port(port)

    params = {"value": value, "offset": offset, "limit": limit}
    if in_function:
        params["in_function"] = in_function
    if to_function:
        params["to_function"] = to_function

    response = safe_get(port, "scalars", params)
    return simplify_response(response)

# Struct tools
@mcp.tool()
@text_output
def structs_list(offset: int = 0, limit: int = 100, category: str | None = None, port: int | None = None) -> dict:
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
def structs_get(name: str, port: int | None = None) -> dict:
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

    response = safe_get(port, f"structs/{quote(name)}")
    return simplify_response(response)

@mcp.tool()
@text_output
def structs_create(name: str, category: str | None = None, size: int | None = None,
                   description: str | None = None, port: int | None = None) -> dict:
    """Create a new struct data type

    Args:
        name: Name for the new struct
        category: Category path for the struct (e.g. "/custom")
        size: Optional initial struct size in bytes
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
    if size is not None:
        payload["size"] = size
    if description:
        payload["description"] = description

    response = safe_post(port, "structs", payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def structs_add_field(struct_name: str, field_name: str, field_type: str,
                     offset: int | None = None, comment: str | None = None, port: int | None = None) -> dict:
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
        "name": field_name,
        "type": field_type
    }
    if offset is not None:
        payload["offset"] = offset
    if comment:
        payload["comment"] = comment

    response = safe_post(port, f"structs/{quote(struct_name)}/fields", payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def structs_update_field(struct_name: str, field_name: str | None = None, field_offset: int | None = None,
                        new_name: str | None = None, new_type: str | None = None, new_comment: str | None = None,
                        port: int | None = None) -> dict:
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

    # Identify field by offset (preferred) or name
    field_id = str(field_offset) if field_offset is not None else quote(field_name)

    payload = {}
    if new_name:
        payload["name"] = new_name
    if new_type:
        payload["type"] = new_type
    if new_comment is not None:
        payload["comment"] = new_comment

    response = safe_patch(port, f"structs/{quote(struct_name)}/fields/{field_id}", payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def structs_delete(name: str, port: int | None = None) -> dict:
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

    response = safe_delete(port, f"structs/{quote(name)}")
    return simplify_response(response)

# Analysis tools
@mcp.tool()
@text_output
def analysis_run(port: int | None = None, analysis_options: dict | None = None, background: bool | None = None) -> dict:
    """Run analysis on the current program
    
    Args:
        analysis_options: Dictionary of analysis options to enable/disable
                         (e.g. {"background": True, "functionRecovery": True})
        background: Convenience override for background analysis execution
        port: Specific Ghidra instance port (optional)
    
    Returns:
        dict: Analysis operation result with status
    """
    port = _get_instance_port(port)
    payload = dict(analysis_options or {})
    if background is not None:
        payload["background"] = str(background).lower()
    if "background" not in payload:
        payload["background"] = "true"

    response = safe_post(port, "analysis/run", payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def analysis_get_callgraph(name: str | None = None, address: str | None = None, max_depth: int = 3, port: int | None = None) -> dict:
    """Get function call graph visualization data

    Args:
        name: Starting function fully-qualified name (e.g. "FOM::Read"; bare = global only), mutually exclusive with address
        address: Starting function address (mutually exclusive with name)
        max_depth: Maximum call depth to analyze (default: 3). Increase for deeper call chains (e.g., 10-15 for complex functions)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Graph data with nodes and edges
    """
    port = _get_instance_port(port)
    
    # Server reads "depth"; send both for compatibility with older builds.
    params = {"depth": max_depth, "max_depth": max_depth}

    # Explicitly pass either name or address parameter based on what was provided
    if address:
        params["address"] = address
    elif name:
        params["name"] = name
    else:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    response = safe_get(port, "analysis/callgraph", params)
    return simplify_response(response)

@mcp.tool()
@text_output
def analysis_get_dataflow(address: str, direction: str = "forward", max_steps: int = 50, port: int | None = None) -> dict:
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
def analysis_find_call_paths(from_fn: str, to_fn: str, max_depth: int = 5,
                             max_paths: int = 50, port: int | None = None) -> dict:
    """Find bounded simple call paths from one function to another.

    Args:
        from_fn: Source function — fully-qualified name or address.
        to_fn: Target function — fully-qualified name or address.
        max_depth: Max path length in call edges (default 5, capped at 15 server-side).
        max_paths: Max number of paths returned (default 50, capped at 500 server-side).
        port: Specific Ghidra instance port (optional).

    Returns:
        dict: {from, to, max_depth, max_paths, truncated, unresolved_edges,
               paths:[{length, functions:[...]}]}. unresolved_edges > 0 means the walk
               could not traverse some call edges (thunks/indirect calls), so an empty
               paths list does not prove from cannot reach to.
    """
    if not from_fn or not to_fn:
        return {
            "success": False,
            "error": {"code": "MISSING_PARAMETER", "message": "Both from_fn and to_fn are required"},
            "timestamp": int(time.time() * 1000),
        }
    if max_depth < 1:
        return {
            "success": False,
            "error": {"code": "INVALID_PARAMETER", "message": "max_depth must be >= 1"},
            "timestamp": int(time.time() * 1000),
        }
    if max_paths < 1:
        return {
            "success": False,
            "error": {"code": "INVALID_PARAMETER", "message": "max_paths must be >= 1"},
            "timestamp": int(time.time() * 1000),
        }
    port = _get_instance_port(port)
    params = {"from": from_fn, "to": to_fn, "max_depth": max_depth, "max_paths": max_paths}
    response = safe_get(port, "analysis/callpaths", params)
    return simplify_response(response)


@mcp.tool()
@text_output
def analysis_trace_string_usage(value: str, match: str = "substring", caller_depth: int = 0,
                                offset: int = 0, limit: int = 50, port: int | None = None) -> dict:
    """Trace which functions use a string, optionally walking the reverse call graph.

    Args:
        value: The string to search for.
        match: "substring" (default, case-sensitive) or "regex".
        caller_depth: 0 = direct users only (default); >0 walks callers upward (capped at 5).
        offset: Pagination offset over matched strings (default 0).
        limit: Pagination limit over matched strings (default 50).
        port: Specific Ghidra instance port (optional).

    Returns:
        dict: {value, match, caller_depth, size, offset, limit, truncated, unresolved_refs,
               matches:[{string:{address,value}, directUsers:[...], callers:[{function,depth}]}]}.
               unresolved_refs > 0 means some references came from outside a defined function,
               so directUsers/callers under-report who touches the string.
    """
    if not value:
        return {
            "success": False,
            "error": {"code": "MISSING_PARAMETER", "message": "value is required"},
            "timestamp": int(time.time() * 1000),
        }
    port = _get_instance_port(port)
    params = {"value": value, "match": match, "caller_depth": caller_depth,
              "offset": offset, "limit": limit}
    response = safe_get(port, "analysis/strings/usage", params)
    return simplify_response(response)


@mcp.tool()
@text_output
def ui_get_current_address(port: int | None = None) -> dict:
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
def ui_get_current_function(port: int | None = None) -> dict:
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
def comments_set(address: str, comment: str = "", comment_type: str = "plate", port: int | None = None) -> dict:
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
def comments_get(address: str, comment_type: str = "plate", port: int | None = None) -> dict:
    """Get a comment at the specified address

    Args:
        address: Memory address in hex format
        comment_type: Type of comment - "plate", "pre", "post", "eol", "repeatable"
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result containing comment text
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
    response = safe_get(port, f"memory/{address}/comments/{comment_type}")
    return simplify_response(response)

@mcp.tool()
@text_output
def functions_set_comment(address: str, comment: str = "", port: int | None = None) -> dict:
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
def project_info(port: int | None = None) -> dict:
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
                       offset: int = 0, limit: int = 100, port: int | None = None) -> dict:
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
def project_open_file(path: str, port: int | None = None) -> dict:
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


@mcp.tool()
@text_output
def projects_list(port: int | None = None) -> dict:
    """List projects visible to the plugin context

    Args:
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of projects
    """
    port = _get_instance_port(port)
    response = safe_get(port, "projects")
    return simplify_response(response)


@mcp.tool()
@text_output
def projects_get(name: str, port: int | None = None) -> dict:
    """Get a project by name

    Args:
        name: Project name
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Project details
    """
    if not name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "name parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)
    response = safe_get(port, f"projects/{quote(name)}")
    return simplify_response(response)


@mcp.tool()
@text_output
def programs_list(project: str | None = None, offset: int = 0, limit: int = 100, port: int | None = None) -> dict:
    """List programs in the current project context

    Args:
        project: Optional project name filter
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of programs
    """
    port = _get_instance_port(port)
    params = {"offset": offset, "limit": limit}
    if project:
        params["project"] = project
    response = safe_get(port, "programs", params)
    return simplify_response(response)


@mcp.tool()
@text_output
def programs_get(program_id: str = "current", port: int | None = None) -> dict:
    """Get program details by program ID or 'current'

    Args:
        program_id: Program ID (e.g. 'MyProj:/sample.bin') or 'current'
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Program details
    """
    port = _get_instance_port(port)
    endpoint = "programs/current" if program_id == "current" else f"programs/{quote(program_id, safe='')}"
    response = safe_get(port, endpoint)
    return simplify_response(response)


@mcp.tool()
@text_output
def programs_delete(program_id: str = "current", port: int | None = None) -> dict:
    """Delete/close a program by program ID or 'current'

    Args:
        program_id: Program ID or 'current'
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result
    """
    port = _get_instance_port(port)
    endpoint = "programs/current" if program_id == "current" else f"programs/{quote(program_id, safe='')}"
    response = safe_delete(port, endpoint)
    return simplify_response(response)


@mcp.tool()
def programs_save(all: bool = False, port: int | None = None) -> dict:
    """Save the current program to the project (Ghidra's "Save")

    Persists analysis (renames, types, comments, etc.) so it survives a Ghidra restart.
    A program with no changes is a no-op (saved=false).

    Args:
        all: Save every open program with unsaved changes (default: just the current program)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Save result(s); saved=false means there were no unsaved changes
    """
    port = _get_instance_port(port)
    endpoint = "program/save?all=true" if all else "program/save"
    response = safe_post(port, endpoint, {})
    return simplify_response(response)


# Script tools
@mcp.tool()
def scripts_list(port: int | None = None) -> dict:
    """List Ghidra scripts available to run

    Requires the server started with script execution enabled
    (-Dghydra.dev.allowScripts=true or GHYDRA_ALLOW_SCRIPTS=1); otherwise returns 403.

    Args:
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of scripts with name, path, category
    """
    port = _get_instance_port(port)
    return simplify_response(safe_get(port, "scripts"))


@mcp.tool()
def scripts_run(name: str | None = None, source: str | None = None, args: list | None = None, port: int | None = None) -> dict:
    """Run a Ghidra script: an existing one by name, or ad-hoc GhidraScript source

    Use this for multi-stage or batch operations that would otherwise need many tool calls
    (e.g. mass rename, signature transfer). Provide EITHER name OR source.

    WARNING: this is arbitrary code execution. It requires the server started with
    -Dghydra.dev.allowScripts=true (or GHYDRA_ALLOW_SCRIPTS=1); otherwise returns 403.

    Args:
        name: Name of an existing script (e.g. "MyScript.java")
        source: Ad-hoc source: a full 'public class <Name> extends GhidraScript { public void
            run() {...} }'. Use println(...) for output; currentProgram is the open program.
        args: Optional list of string arguments (available via getScriptArgs()).
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: result with script, output (captured println text), success, error
    """
    if not name and not source:
        return {
            "success": False,
            "error": {"code": "MISSING_PARAMETER", "message": "Either name or source is required"},
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)
    payload = {}
    if name:
        payload["name"] = name
    if source:
        payload["source"] = source
    if args:
        payload["args"] = args
    return simplify_response(safe_post(port, "scripts/run", payload))


# ================= Analysis =================

@mcp.tool()
@text_output
def analysis_status(port: int | None = None) -> dict:
    """Get analysis status for the current program

    Args:
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Analysis status including whether analysis is running
    """
    port = _get_instance_port(port)
    response = safe_get(port, "analysis/status")
    return simplify_response(response)


def _analysis_run_legacy(background: bool = True, port: int | None = None) -> dict:
    """Legacy helper retained for backward compatibility inside this module."""
    return analysis_run(port=port, background=background)


# ================= Classes, Symbols, Segments, Namespaces, Variables, DataTypes =================

@mcp.tool()
@text_output
def classes_list(offset: int = 0, limit: int = 100, port: int | None = None) -> dict:
    """List classes and namespaces in the program

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of classes with pagination
    """
    port = _get_instance_port(port)
    params = {"offset": offset, "limit": limit}
    response = safe_get(port, "classes", params)
    simplified = simplify_response(response)
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    return simplified


@mcp.tool()
@text_output
def symbols_list(offset: int = 0, limit: int = 100, port: int | None = None) -> dict:
    """List all symbols in the program

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of symbols with name, address, type, and namespace
    """
    port = _get_instance_port(port)
    params = {"offset": offset, "limit": limit}
    response = safe_get(port, "symbols", params)
    simplified = simplify_response(response)
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    return simplified


@mcp.tool()
@text_output
def symbols_imports(offset: int = 0, limit: int = 100, port: int | None = None) -> dict:
    """List imported symbols (external function references)

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of imported symbols with name and address
    """
    port = _get_instance_port(port)
    params = {"offset": offset, "limit": limit}
    response = safe_get(port, "symbols/imports", params)
    simplified = simplify_response(response)
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    return simplified


@mcp.tool()
@text_output
def symbols_exports(offset: int = 0, limit: int = 100, port: int | None = None) -> dict:
    """List exported symbols

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of exported symbols with name and address
    """
    port = _get_instance_port(port)
    params = {"offset": offset, "limit": limit}
    response = safe_get(port, "symbols/exports", params)
    simplified = simplify_response(response)
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    return simplified


@mcp.tool()
@text_output
def segments_list(offset: int = 0, limit: int = 100, name: str | None = None, port: int | None = None) -> dict:
    """List memory segments/blocks with permissions

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        name: Filter segments by name substring (optional)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of segments with name, address range, size, and RWX permissions
    """
    port = _get_instance_port(port)
    params = {"offset": offset, "limit": limit}
    if name:
        params["name"] = name
    response = safe_get(port, "segments", params)
    simplified = simplify_response(response)
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    return simplified


@mcp.tool()
@text_output
def namespaces_list(offset: int = 0, limit: int = 100, port: int | None = None) -> dict:
    """List namespaces in the program

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of namespace names
    """
    port = _get_instance_port(port)
    params = {"offset": offset, "limit": limit}
    response = safe_get(port, "namespaces", params)
    simplified = simplify_response(response)
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    return simplified


@mcp.tool()
@text_output
def variables_list(offset: int = 0, limit: int = 100, search: str | None = None,
                   global_only: bool = False, source: str = "database", port: int | None = None) -> dict:
    """List variables in the program

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        search: Filter variables by name (optional)
        global_only: Only show global variables (default: False)
        source: Local-variable source. "database" (default) reads committed locals/params
            directly from the program DB - cheap, complete, exactly paginated (the "all
            locals" view). "decompiler" runs the decompiler per function to surface inferred
            locals - richer but slow and approximately paginated.
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of variables with name, address, type, and data type
    """
    port = _get_instance_port(port)
    params = {"offset": offset, "limit": limit}
    if search:
        params["search"] = search
    if global_only:
        params["global_only"] = "true"
    if source and source != "database":
        params["source"] = source
    response = safe_get(port, "variables", params)
    simplified = simplify_response(response)
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", simplified.get("total_estimate", len(simplified.get("result", []))))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    return simplified


@mcp.tool()
@text_output
def datatypes_list(offset: int = 0, limit: int = 100, category: str | None = None,
                   kind: str | None = None, port: int | None = None) -> dict:
    """List data types defined in the program

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        category: Filter by category path (optional)
        kind: Filter by kind: "struct", "enum", or "union" (optional)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of data types with name, kind, category, and size
    """
    port = _get_instance_port(port)
    params = {"offset": offset, "limit": limit}
    if category:
        params["category"] = category
    if kind:
        params["kind"] = kind
    response = safe_get(port, "datatypes", params)
    simplified = simplify_response(response)
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    return simplified


@mcp.tool()
@text_output
def datatypes_search(name: str, offset: int = 0, limit: int = 100, port: int | None = None) -> dict:
    """Search for data types by name

    Args:
        name: Data type name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Matching data types
    """
    port = _get_instance_port(port)
    params = {"offset": offset, "limit": limit, "name": name}
    response = safe_get(port, "datatypes", params)
    simplified = simplify_response(response)
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    return simplified


@mcp.tool()
@text_output
def datatypes_create_struct(name: str, category: str = "/", fields: list | None = None,
                            port: int | None = None) -> dict:
    """Create a struct datatype

    Args:
        name: Struct name
        category: Category path (default: '/')
        fields: Optional list of field objects, each with 'name', 'type', and optionally 'size', 'offset', 'comment'
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Created datatype info
    """
    if not name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "name parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)
    payload = {"name": name, "category": category}
    if fields:
        payload["fields"] = fields
    response = safe_post(port, "datatypes/struct", payload)
    return simplify_response(response)


@mcp.tool()
@text_output
def datatypes_create_enum(name: str, size: int = 4, category: str = "/", values: dict | None = None,
                          port: int | None = None) -> dict:
    """Create an enum datatype

    Args:
        name: Enum name
        size: Enum storage size in bytes (default: 4)
        category: Category path (default: '/')
        values: Optional dict mapping enum value names to integer values, e.g. {"VALUE_A": 0, "VALUE_B": 1}
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Created datatype info
    """
    if not name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "name parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)
    payload = {"name": name, "size": size, "category": category}
    if values:
        payload["values"] = values
    response = safe_post(port, "datatypes/enum", payload)
    return simplify_response(response)


@mcp.tool()
@text_output
def datatypes_create_union(name: str, category: str = "/", fields: list | None = None,
                           port: int | None = None) -> dict:
    """Create a union datatype

    Args:
        name: Union name
        category: Category path (default: '/')
        fields: Optional list of field objects, each with 'name', 'type', and optionally 'size', 'comment'
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Created datatype info
    """
    if not name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "name parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)
    payload = {"name": name, "category": category}
    if fields:
        payload["fields"] = fields
    response = safe_post(port, "datatypes/union", payload)
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
