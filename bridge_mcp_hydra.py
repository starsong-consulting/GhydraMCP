# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "mcp==1.5.0",
#     "requests==2.32.3",
# ]
# ///
import os
import sys
import time
import requests
import threading
from typing import Dict
from threading import Lock
from mcp.server.fastmcp import FastMCP

# Track active Ghidra instances (port -> info dict)
active_instances: Dict[int, dict] = {}
instances_lock = Lock()
DEFAULT_GHIDRA_PORT = 8192
DEFAULT_GHIDRA_HOST = "localhost"
# Port ranges for scanning
QUICK_DISCOVERY_RANGE = range(8192, 8202)  # Limited range for interactive/triggered discovery (10 ports)
FULL_DISCOVERY_RANGE = range(8192, 8212)   # Wider range for background discovery (20 ports)

mcp = FastMCP("hydra-mcp")

ghidra_host = os.environ.get("GHIDRA_HYDRA_HOST", DEFAULT_GHIDRA_HOST)
print(f"Using Ghidra host: {ghidra_host}")

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

def safe_get(port: int, endpoint: str, params: dict = None) -> list:
    """Perform a GET request to a specific Ghidra instance"""
    if params is None:
        params = {}

    url = f"{get_instance_url(port)}/{endpoint}"

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        elif response.status_code == 404:
            # Try falling back to default instance if this was a secondary instance
            if port != DEFAULT_GHIDRA_PORT:
                return safe_get(DEFAULT_GHIDRA_PORT, endpoint, params)
            return [f"Error {response.status_code}: {response.text.strip()}"]
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except requests.exceptions.ConnectionError:
        # Instance may be down - try default instance if this was secondary
        if port != DEFAULT_GHIDRA_PORT:
            return safe_get(DEFAULT_GHIDRA_PORT, endpoint, params)
        return ["Error: Failed to connect to Ghidra instance"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_put(port: int, endpoint: str, data: dict) -> str:
    """Perform a PUT request to a specific Ghidra instance"""
    try:
        url = f"{get_instance_url(port)}/{endpoint}"
        response = requests.put(url, data=data, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        elif response.status_code == 404 and port != DEFAULT_GHIDRA_PORT:
            # Try falling back to default instance
            return safe_put(DEFAULT_GHIDRA_PORT, endpoint, data)
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except requests.exceptions.ConnectionError:
        if port != DEFAULT_GHIDRA_PORT:
            return safe_put(DEFAULT_GHIDRA_PORT, endpoint, data)
        return "Error: Failed to connect to Ghidra instance"
    except Exception as e:
        return f"Request failed: {str(e)}"

def safe_post(port: int, endpoint: str, data: dict | str) -> str:
    """Perform a POST request to a specific Ghidra instance"""
    try:
        url = f"{get_instance_url(port)}/{endpoint}"
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        elif response.status_code == 404 and port != DEFAULT_GHIDRA_PORT:
            # Try falling back to default instance
            return safe_post(DEFAULT_GHIDRA_PORT, endpoint, data)
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except requests.exceptions.ConnectionError:
        if port != DEFAULT_GHIDRA_PORT:
            return safe_post(DEFAULT_GHIDRA_PORT, endpoint, data)
        return "Error: Failed to connect to Ghidra instance"
    except Exception as e:
        return f"Request failed: {str(e)}"

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
            print(f"Trying to get root info from {root_url}", file=sys.stderr)
            root_response = requests.get(root_url, timeout=1.5)  # Short timeout for root
            
            if root_response.ok:
                try:
                    print(f"Got response from root: {root_response.text}", file=sys.stderr)
                    root_data = root_response.json()
                    
                    # Extract basic information from root
                    if "project" in root_data and root_data["project"]:
                        project_info["project"] = root_data["project"]
                    if "program" in root_data and root_data["program"]:
                        project_info["file"] = root_data["program"]
                    if "programID" in root_data and root_data["programID"]:
                        project_info["program_id"] = root_data["programID"]
                    
                    print(f"Root data parsed: {project_info}", file=sys.stderr)
                except Exception as e:
                    print(f"Error parsing root info: {e}", file=sys.stderr)
            else:
                print(f"Root endpoint returned {root_response.status_code}", file=sys.stderr)
                
            # If we don't have project info yet, try the /info endpoint as a fallback
            if not project_info.get("project") and not project_info.get("file"):
                info_url = f"{url}/info"
                print(f"Trying fallback info from {info_url}", file=sys.stderr)
                
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

# Updated tool implementations with port parameter
from urllib.parse import quote

@mcp.tool()
def list_functions(port: int = DEFAULT_GHIDRA_PORT, offset: int = 0, limit: int = 100) -> list:
    """List all functions with pagination"""
    return safe_get(port, "functions", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(port: int = DEFAULT_GHIDRA_PORT, offset: int = 0, limit: int = 100) -> list:
    """List all classes with pagination"""
    return safe_get(port, "classes", {"offset": offset, "limit": limit})

@mcp.tool()
def get_function(port: int = DEFAULT_GHIDRA_PORT, name: str = "") -> str:
    """Get decompiled code for a specific function"""
    return safe_get(port, f"functions/{quote(name)}", {})

@mcp.tool()
def update_function(port: int = DEFAULT_GHIDRA_PORT, name: str = "", new_name: str = "") -> str:
    """Rename a function"""
    return safe_put(port, f"functions/{quote(name)}", {"newName": new_name})

@mcp.tool()
def update_data(port: int = DEFAULT_GHIDRA_PORT, address: str = "", new_name: str = "") -> str:
    """Rename data at specified address"""
    return safe_put(port, "data", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(port: int = DEFAULT_GHIDRA_PORT, offset: int = 0, limit: int = 100) -> list:
    return safe_get(port, "segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(port: int = DEFAULT_GHIDRA_PORT, offset: int = 0, limit: int = 100) -> list:
    return safe_get(port, "symbols/imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(port: int = DEFAULT_GHIDRA_PORT, offset: int = 0, limit: int = 100) -> list:
    return safe_get(port, "symbols/exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(port: int = DEFAULT_GHIDRA_PORT, offset: int = 0, limit: int = 100) -> list:
    return safe_get(port, "namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(port: int = DEFAULT_GHIDRA_PORT, offset: int = 0, limit: int = 100) -> list:
    return safe_get(port, "data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(port: int = DEFAULT_GHIDRA_PORT, query: str = "", offset: int = 0, limit: int = 100) -> list:
    if not query:
        return ["Error: query string is required"]
    return safe_get(port, "functions", {"query": query, "offset": offset, "limit": limit})

# Handle graceful shutdown
import signal
import os

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
    mcp.run()
