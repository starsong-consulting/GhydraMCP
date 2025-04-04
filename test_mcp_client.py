#!/usr/bin/env python3
"""
Test script for the GhydraMCP bridge using the MCP client.
This script tests the bridge by sending MCP requests and handling responses.
"""
import asyncio
import logging
import sys
from typing import Any

import anyio

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp_client_test")

async def test_bridge():
    """Test the bridge using the MCP client"""
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
            
            # List tools
            logger.info("Listing tools...")
            tools_result = await session.list_tools()
            logger.info(f"Tools result: {tools_result}")
            
            # Call the list_instances tool
            logger.info("Calling list_instances tool...")
            list_instances_result = await session.call_tool("list_instances")
            logger.info(f"List instances result: {list_instances_result}")
            
            # Call the discover_instances tool
            logger.info("Calling discover_instances tool...")
            discover_instances_result = await session.call_tool("discover_instances")
            logger.info(f"Discover instances result: {discover_instances_result}")
            
            # Call the list_functions tool
            logger.info("Calling list_functions tool...")
            list_functions_result = await session.call_tool(
                "list_functions",
                arguments={"port": 8192, "offset": 0, "limit": 5}
            )
            logger.info(f"List functions result: {list_functions_result}")

            # Test mutating operations by changing and reverting
            logger.info("Testing mutating operations...")
            
            try:
                # Get a known function to test with from list_functions result
                list_funcs = await session.call_tool(
                    "list_functions",
                    arguments={"port": 8192, "offset": 0, "limit": 5}
                )
                
                if not hasattr(list_funcs, "result") or not hasattr(list_funcs.result, "content") or not list_funcs.result.content:
                    logger.warning("No functions found - skipping mutating tests")
                    return
                
                # The list_functions result contains a JSON string in the text field
                func_json = list_funcs.result.content[0].get("text", "")
                if not func_json:
                    logger.warning("No function data found - skipping mutating tests")
                    return
                
                try:
                    # Parse the JSON to get the function list
                    func_data = json.loads(func_json)
                    func_list = func_data.get("result", "").split("\n")
                    if not func_list:
                        logger.warning("No functions in result - skipping mutating tests")
                        return
                    
                    # Extract first function name (format: "name @ address")
                    func_name = func_list[0].split("@")[0].strip()
                except (json.JSONDecodeError, AttributeError) as e:
                    logger.warning(f"Error parsing function data: {e} - skipping mutating tests")
                    return
                if not func_name:
                    logger.warning("Could not parse function name - skipping mutating tests")
                    return
                
                # Get full function details
                func_details = await session.call_tool(
                    "get_function",
                    arguments={"port": 8192, "name": func_name}
                )
                
                if not hasattr(func_details, "result") or not hasattr(func_details.result, "content") or not func_details.result.content:
                    logger.warning("Could not get function details - skipping mutating tests")
                    return
                
                func_content = func_details.result.content[0]
                func_name = func_content.get("text", "").split("\n")[0]
                func_address = func_content.get("address", "")
                
                if not func_name or not func_address:
                    logger.warning("Could not get valid function name/address - skipping mutating tests")
                    return

                # Test function renaming
                original_name = func_name
                test_name = f"{func_name}_test"
                
                # Rename to test name
                rename_result = await session.call_tool(
                    "update_function",
                    arguments={"port": 8192, "name": original_name, "new_name": test_name}
                )
                logger.info(f"Rename result: {rename_result}")
                
                # Verify rename
                renamed_func = await session.call_tool(
                    "get_function",
                    arguments={"port": 8192, "name": test_name}
                )
                logger.info(f"Renamed function result: {renamed_func}")
                
                # Rename back to original
                revert_result = await session.call_tool(
                    "update_function",
                    arguments={"port": 8192, "name": test_name, "new_name": original_name}
                )
                logger.info(f"Revert rename result: {revert_result}")
                
                # Verify revert
                original_func = await session.call_tool(
                    "get_function",
                    arguments={"port": 8192, "name": original_name}
                )
                logger.info(f"Original function result: {original_func}")
                
                # Test adding/removing comment
                test_comment = "Test comment from MCP client"
                comment_result = await session.call_tool(
                    "set_decompiler_comment",
                    arguments={
                        "port": 8192,
                        "address": func_address,
                        "comment": test_comment
                    }
                )
                logger.info(f"Add comment result: {comment_result}")
                
                # Remove comment
                remove_comment_result = await session.call_tool(
                    "set_decompiler_comment", 
                    arguments={
                        "port": 8192,
                        "address": func_address,
                        "comment": ""
                    }
                )
                logger.info(f"Remove comment result: {remove_comment_result}")
                
            except Exception as e:
                logger.error(f"Error testing mutating operations: {e}")
                raise

def main():
    """Main entry point"""
    try:
        anyio.run(test_bridge)
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
