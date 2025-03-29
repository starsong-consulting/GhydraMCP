# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "mcp==1.5.0",
#     "requests==2.32.3",
# ]
# ///
import os
import sys
import requests
from typing import Dict
from threading import Lock
from mcp.server.fastmcp import FastMCP

# Track active Ghidra instances (port -> url)
active_instances: Dict[int, str] = {}
instances_lock = Lock()
DEFAULT_GHIDRA_PORT = 8192
DEFAULT_GHIDRA_HOST = "localhost"

mcp = FastMCP("hydra-mcp")

# Get host from environment variable, command line, or use default
ghidra_host = os.environ.get("GHIDRA_HYDRA_HOST", DEFAULT_GHIDRA_HOST)
if len(sys.argv) > 1:
    ghidra_host = sys.argv[1]
print(f"Using Ghidra host: {ghidra_host}")

def get_instance_url(port: int) -> str:
    """Get URL for a Ghidra instance by port"""
    with instances_lock:
        if port in active_instances:
            return active_instances[port]
        
        # Auto-register if not found but port is valid
        if 8192 <= port <= 65535:
            register_instance(port)
            return active_instances[port]
        
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
                {"port": port, "url": url}
                for port, url in active_instances.items()
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
    except Exception as e:
        return f"Error: Could not connect to instance at {url}: {str(e)}"
    
    with instances_lock:
        active_instances[port] = url
    return f"Registered instance on port {port} at {url}"

@mcp.tool()
def unregister_instance(port: int) -> str:
    """Unregister a Ghidra instance"""
    with instances_lock:
        if port in active_instances:
            del active_instances[port]
            return f"Unregistered instance on port {port}"
        return f"No instance found on port {port}"

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

if __name__ == "__main__":
    # Auto-register default instance
    register_instance(DEFAULT_GHIDRA_PORT, f"http://{ghidra_host}:{DEFAULT_GHIDRA_PORT}")
    
    signal.signal(signal.SIGINT, handle_sigint)
    mcp.run()
