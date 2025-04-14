#!/usr/bin/env python3
"""
Test script for setting data types in GhydraMCP bridge.
"""
import json
import logging
import sys
import time
from urllib.parse import quote

import anyio
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("data_type_test")

async def test_set_data_type():
    """Test the set_data_type tool"""
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
            logger.info(f"Initialization result: {init_result}")
            
            # List tools to make sure our new tool is available
            logger.info("Listing tools...")
            tools_result = await session.list_tools()
            tool_data = json.loads(tools_result.content[0].text) if tools_result.content else None
            
            tools = tool_data.get("tools", []) if tool_data else []
            tool_names = [t.get("name") for t in tools]
            logger.info(f"Available tools: {tool_names}")
            
            if "set_data_type" not in tool_names:
                logger.error("set_data_type tool not found!")
                return
            
            # List data to find a data item to test with
            logger.info("Listing data...")
            list_data_result = await session.call_tool(
                "list_data_items",
                arguments={"port": 8192, "limit": 5}
            )
            list_data_data = json.loads(list_data_result.content[0].text)
            
            if "result" not in list_data_data or not list_data_data.get("result"):
                logger.error("No data items found - cannot proceed with test")
                return
            
            # Get the first data item for testing
            data_item = list_data_data["result"][0]
            data_address = data_item.get("address")
            original_type = data_item.get("dataType")
            
            if not data_address:
                logger.error("No address found in data item - cannot proceed with test")
                return
                
            logger.info(f"Testing with data at address {data_address}, original type: {original_type}")
            
            # Test with simple types first
            simple_tests = ["uint32_t", "int", "byte", "word", "dword"]
            
            for test_type in simple_tests:
                logger.info(f"Testing type: {test_type}")
                set_type_result = await session.call_tool(
                    "set_data_type",
                    arguments={"port": 8192, "address": data_address, "data_type": test_type}
                )
                
                try:
                    set_type_data = json.loads(set_type_result.content[0].text)
                    logger.info(f"Result: {set_type_data}")
                    
                    if set_type_data.get("success", False):
                        logger.info(f"Successfully set type to {test_type}")
                        break
                    else:
                        logger.warning(f"Failed to set type to {test_type}: {set_type_data.get('error', {}).get('message', 'Unknown error')}")
                except Exception as e:
                    logger.error(f"Error processing result: {e}")

def main():
    """Main entry point"""
    try:
        anyio.run(test_set_data_type)
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()