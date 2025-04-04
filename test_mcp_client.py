#!/usr/bin/env python3
"""
Test script for the GhydraMCP bridge using the MCP client.
This script tests the bridge by sending MCP requests and handling responses.
"""
import json
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
                
                if not list_funcs or not list_funcs.content:
                    logger.warning("No functions found - skipping mutating tests")
                    return
                
                # The list_functions result contains the function data directly
                if not list_funcs.content:
                    logger.warning("No function data found - skipping mutating tests")
                    return
                
                # Parse the JSON response
                try:
                    func_data = json.loads(list_funcs.content[0].text)
                    func_list = func_data.get("result", [])
                    if not func_list:
                        logger.warning("No functions in result - skipping mutating tests")
                        return
                    
                    # Get first function's name
                    func_name = func_list[0].get("name", "")
                    if not func_name:
                        logger.warning("No function name found - skipping mutating tests")
                        return
                    
                    # Get full function details
                    func_details = await session.call_tool(
                        "get_function",
                        arguments={"port": 8192, "name": func_name}
                    )
                    
                    if not func_details.content or not func_details.content[0].text:
                        logger.warning("Could not get function details - skipping mutating tests")
                        return
                    
                    # Parse function details - response is the decompiled code text
                    func_text = func_details.content[0].text
                    if not func_text:
                        logger.warning("Empty function details - skipping mutating tests")
                        return
                    
                    # First line contains name and address
                    first_line = func_text.split('\n')[0]
                    if not first_line:
                        logger.warning("Invalid function format - skipping mutating tests")
                        return
                    
                    # Extract name and address from first line
                    parts = first_line.split()
                    if len(parts) < 2:
                        logger.warning("Could not parse function details - skipping mutating tests")
                        return
                    
                    func_name = parts[1]  # Second part is function name
                    func_address = parts[0]  # First part is address
                    
                    if not func_name or not func_address:
                        logger.warning("Could not get valid function name/address - skipping mutating tests")
                        return
                        
                except json.JSONDecodeError as e:
                    logger.warning(f"Error parsing function data: {e} - skipping mutating tests")
                    return

                # Test function renaming
                original_name = func_name
                test_name = f"{func_name}_test"
                
                # Test successful rename operations
                rename_result = await session.call_tool(
                    "update_function",
                    arguments={"port": 8192, "name": original_name, "new_name": test_name}
                )
                rename_data = json.loads(rename_result.content[0].text)
                assert rename_data.get("success") is True, f"Rename failed: {rename_data}"
                logger.info(f"Rename result: {rename_result}")
                
                # Verify rename
                renamed_func = await session.call_tool(
                    "get_function",
                    arguments={"port": 8192, "name": test_name}
                )
                renamed_data = json.loads(renamed_func.content[0].text)
                assert renamed_data.get("success") is True, f"Get renamed function failed: {renamed_data}"
                logger.info(f"Renamed function result: {renamed_func}")
                
                # Rename back to original
                revert_result = await session.call_tool(
                    "update_function",
                    arguments={"port": 8192, "name": test_name, "new_name": original_name}
                )
                revert_data = json.loads(revert_result.content[0].text)
                assert revert_data.get("success") is True, f"Revert rename failed: {revert_data}"
                logger.info(f"Revert rename result: {revert_result}")
                
                # Verify revert
                original_func = await session.call_tool(
                    "get_function",
                    arguments={"port": 8192, "name": original_name}
                )
                original_data = json.loads(original_func.content[0].text)
                assert original_data.get("success") is True, f"Get original function failed: {original_data}"
                logger.info(f"Original function result: {original_func}")
                
                # Test successful comment operations
                test_comment = "Test comment from MCP client"
                comment_result = await session.call_tool(
                    "set_decompiler_comment",
                    arguments={
                        "port": 8192,
                        "address": func_address,
                        "comment": test_comment
                    }
                )
                comment_data = json.loads(comment_result.content[0].text)
                assert comment_data.get("success") is True, f"Add comment failed: {comment_data}"
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
                remove_data = json.loads(remove_comment_result.content[0].text)
                assert remove_data.get("success") is True, f"Remove comment failed: {remove_data}"
                logger.info(f"Remove comment result: {remove_comment_result}")
                
                # Test expected failure cases
                # Try to rename non-existent function
                bad_rename_result = await session.call_tool(
                    "update_function",
                    arguments={"port": 8192, "name": "nonexistent_function", "new_name": "should_fail"}
                )
                bad_rename_data = json.loads(bad_rename_result.content[0].text)
                assert bad_rename_data.get("success") is False, "Renaming non-existent function should fail"
                
                # Try to get non-existent function
                bad_get_result = await session.call_tool(
                    "get_function",
                    arguments={"port": 8192, "name": "nonexistent_function"}
                )
                bad_get_data = json.loads(bad_get_result.content[0].text)
                assert bad_get_data.get("success") is False, "Getting non-existent function should fail"
                
                # Try to comment on invalid address
                bad_comment_result = await session.call_tool(
                    "set_decompiler_comment",
                    arguments={
                        "port": 8192,
                        "address": "0xinvalid",
                        "comment": "should fail"
                    }
                )
                bad_comment_data = json.loads(bad_comment_result.content[0].text)
                assert bad_comment_data.get("success") is False, "Commenting on invalid address should fail"
                
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
