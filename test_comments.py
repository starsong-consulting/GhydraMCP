#!/usr/bin/env python3
"""
Test script for the comment functionality in GhydraMCP.
"""
import json
import logging
import sys
import time
from urllib.parse import quote

import anyio
import requests
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("comment_test")

# Direct HTTP test functions
def test_http_api_comments(port=8192, address="08000200"):
    """Test setting comments directly with HTTP API"""
    logger.info("===== Testing HTTP API Comments =====")
    base_url = f"http://localhost:{port}"
    
    # Test each comment type
    comment_types = ["plate", "pre", "post", "eol", "repeatable"]
    
    for i, comment_type in enumerate(comment_types):
        # Set comment
        comment_text = f"TEST {comment_type.upper()} COMMENT {int(time.time())}"
        logger.info(f"Setting {comment_type} comment: {comment_text}")
        
        url = f"{base_url}/memory/{address}/comments/{comment_type}"
        payload = {"comment": comment_text}
        
        try:
            r = requests.post(url, json=payload, timeout=10)
            logger.info(f"Status code: {r.status_code}")
            logger.info(f"Response: {r.text}")
            
            if r.status_code == 200:
                # Get the comment back to verify
                r_get = requests.get(url, timeout=10)
                logger.info(f"GET Status code: {r_get.status_code}")
                logger.info(f"GET Response: {r_get.text}")
        except Exception as e:
            logger.error(f"Error setting {comment_type} comment: {e}")

# MCP Bridge test functions
async def test_bridge_comments():
    """Test the bridge comment functionality"""
    logger.info("===== Testing MCP Bridge Comments =====")
    
    # Configure the server parameters
    server_parameters = StdioServerParameters(
        command=sys.executable,
        args=["bridge_mcp_hydra.py"],
    )
    
    # Connect to the bridge
    logger.info("Connecting to bridge...")
    async with stdio_client(server_parameters) as (read_stream, write_stream):
        # Create a session
        logger.info("Creating session...")
        async with ClientSession(read_stream, write_stream) as session:
            # Initialize the session
            logger.info("Initializing session...")
            init_result = await session.initialize()
            
            # Get a function to test with
            logger.info("Getting current address...")
            addr_result = await session.call_tool("get_current_address", arguments={"port": 8192})
            addr_data = json.loads(addr_result.content[0].text)
            
            if not addr_data.get("success", False):
                logger.error("Failed to get current address")
                return
                
            address = addr_data.get("result", {}).get("address", "08000200")
            logger.info(f"Using address: {address}")
            
            # Test normal comment
            logger.info("Testing set_comment with plate type...")
            comment_text = f"MCP PLATE COMMENT {int(time.time())}"
            result = await session.call_tool("set_comment", 
                                            arguments={"port": 8192, 
                                                      "address": address,
                                                      "comment": comment_text,
                                                      "comment_type": "plate"})
            logger.info(f"set_comment result: {result}")
            
            # Test decompiler comment
            logger.info("Testing set_decompiler_comment...")
            decompiler_comment = f"MCP DECOMPILER COMMENT {int(time.time())}"
            decompile_result = await session.call_tool("set_decompiler_comment",
                                                      arguments={"port": 8192,
                                                               "address": address,
                                                               "comment": decompiler_comment})
            logger.info(f"set_decompiler_comment result: {decompile_result}")
            
            # Wait a bit and then clear comments
            await anyio.sleep(5)
            
            # Clear the comments
            logger.info("Clearing comments...")
            await session.call_tool("set_comment", 
                                   arguments={"port": 8192, 
                                            "address": address,
                                            "comment": "",
                                            "comment_type": "plate"})
            
            await session.call_tool("set_decompiler_comment",
                                   arguments={"port": 8192,
                                            "address": address,
                                            "comment": ""})

def main():
    """Main entry point"""
    try:
        # First test HTTP API directly
        test_http_api_comments()
        
        # Then test through MCP bridge
        anyio.run(test_bridge_comments)
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()