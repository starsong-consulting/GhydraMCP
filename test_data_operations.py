#!/usr/bin/env python3
"""
Test script for data operations in GhydraMCP bridge.
This script tests renaming and changing data types.
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
logger = logging.getLogger("data_test")

async def test_data_operations():
    """Test data operations using the MCP client"""
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
            
            # List data to find a data item to test with
            logger.info("Listing data...")
            list_data_result = await session.call_tool(
                "list_data_items",
                arguments={"port": 8192, "limit": 5}
            )
            list_data_data = json.loads(list_data_result.content[0].text)
            logger.info(f"List data result: {list_data_data}")
            
            if "result" not in list_data_data or not list_data_data.get("result"):
                logger.error("No data items found - cannot proceed with test")
                return
            
            # Get the first data item for testing
            data_item = list_data_data["result"][0]
            data_address = data_item.get("address")
            original_name = data_item.get("label")
            
            if not data_address:
                logger.error("No address found in data item - cannot proceed with test")
                return
                
            logger.info(f"Testing with data at address {data_address}, original name: {original_name}")
            
            # Test renaming the data
            test_name = f"TEST_DATA_{int(time.time())}"
            logger.info(f"Renaming data to {test_name}")
            
            rename_result = await session.call_tool(
                "update_data",
                arguments={"port": 8192, "address": data_address, "name": test_name}
            )
            
            rename_data = json.loads(rename_result.content[0].text)
            logger.info(f"Rename result: {rename_data}")
            
            if not rename_data.get("success", False):
                logger.error(f"Failed to rename data: {rename_data.get('error', {}).get('message', 'Unknown error')}")
            else:
                logger.info("Data renamed successfully")
            
            # Test changing the data type
            test_type = "uint32_t *"  # Pointer to uint32_t - adjust as needed for your test data
            logger.info(f"Changing data type to {test_type}")
            
            type_result = await session.call_tool(
                "update_data",
                arguments={"port": 8192, "address": data_address, "data_type": test_type}
            )
            
            type_data = json.loads(type_result.content[0].text)
            logger.info(f"Change type result: {type_data}")
            
            if not type_data.get("success", False):
                logger.error(f"Failed to change data type: {type_data.get('error', {}).get('message', 'Unknown error')}")
            else:
                logger.info("Data type changed successfully")
            
            # Test both operations together
            logger.info(f"Restoring original name and trying different type")
            
            combined_result = await session.call_tool(
                "update_data",
                arguments={
                    "port": 8192, 
                    "address": data_address, 
                    "name": original_name, 
                    "data_type": "uint32_t"
                }
            )
            
            combined_data = json.loads(combined_result.content[0].text)
            logger.info(f"Combined update result: {combined_data}")
            
            if not combined_data.get("success", False):
                logger.error(f"Failed to perform combined update: {combined_data.get('error', {}).get('message', 'Unknown error')}")
            else:
                logger.info("Combined update successful")

def main():
    """Main entry point"""
    try:
        anyio.run(test_data_operations)
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()