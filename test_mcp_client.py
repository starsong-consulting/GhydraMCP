 #!/usr/bin/env python3
"""
Test script for the GhydraMCP bridge using the MCP client.
This script tests the bridge by sending MCP requests and handling responses.
"""
import json
import logging
import os
import sys
from typing import Any

import anyio

# Get host and port from environment variables or use defaults
GHYDRAMCP_TEST_HOST = os.getenv('GHYDRAMCP_TEST_HOST', 'localhost')
GHYDRAMCP_TEST_PORT = int(os.getenv('GHYDRAMCP_TEST_PORT', '8192'))
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp_client_test")

async def assert_standard_mcp_success_response(response_content, expected_result_type=None):
    """Helper to assert the standard success response structure for MCP tool calls."""
    assert response_content, "Response content is empty"
    try:
        data = json.loads(response_content[0].text)
    except (json.JSONDecodeError, IndexError) as e:
        assert False, f"Failed to parse JSON response: {e} - Content: {response_content}"

    assert "success" in data, "Response missing 'success' field"
    assert data["success"] is True, f"API call failed: {data.get('error', 'Unknown error')}"
    assert "timestamp" in data, "Response missing 'timestamp' field"
    assert isinstance(data["timestamp"], (int, float)), "'timestamp' should be a number"
    assert "port" in data, "Response missing 'port' field"
    # We don't strictly check port number here as it might vary in MCP tests
    assert "result" in data, "Response missing 'result' field"
    if expected_result_type:
        assert isinstance(data["result"], expected_result_type), \
            f"'result' field type mismatch: expected {expected_result_type}, got {type(data['result'])}"
    return data # Return parsed data for further checks if needed

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
                arguments={"port": GHYDRAMCP_TEST_PORT, "offset": 0, "limit": 5}
            )
            logger.info(f"List functions result: {list_functions_result}")

            # Test mutating operations by changing and reverting
            logger.info("Testing mutating operations...")
            
            try:
                # Get a known function to test with from list_functions result
                list_funcs = await session.call_tool(
                    "list_functions",
                    arguments={"port": GHYDRAMCP_TEST_PORT, "offset": 0, "limit": 5}
                )
                
                if not list_funcs or not list_funcs.content:
                    logger.warning("No functions found - skipping mutating tests")
                    return
                
                # Parse the JSON response from list_functions using helper
                try:
                    list_funcs_data = await assert_standard_mcp_success_response(list_funcs.content, expected_result_type=list)
                    func_list = list_funcs_data.get("result", [])
                    if not func_list:
                        logger.warning("No functions in list_functions result - skipping mutating tests")
                        return

                    # Get first function's name and address
                    first_func = func_list[0]
                    func_name = first_func.get("name", "")
                    func_address = first_func.get("address", "")

                    if not func_name or not func_address:
                        logger.warning("No function name/address found in list_functions result - skipping mutating tests")
                        return
                except AssertionError as e:
                     logger.warning(f"Error processing list_functions data: {e} - skipping mutating tests")
                     return

                # Test function renaming
                original_name = func_name
                test_name = f"{func_name}_test"

                # Test successful rename operations (These return simple success/message, not full result)
                rename_args = {"port": GHYDRAMCP_TEST_PORT, "name": original_name, "new_name": test_name}
                logger.info(f"Calling update_function with args: {rename_args}")
                rename_result = await session.call_tool("update_function", arguments=rename_args)
                rename_data = json.loads(rename_result.content[0].text) # Parse simple response
                assert rename_data.get("success") is True, f"Rename failed: {rename_data}"
                logger.info(f"Rename result: {rename_result}")
                
                # Verify rename by getting the function
                renamed_func = await session.call_tool("get_function", arguments={"port": 8192, "name": test_name})
                renamed_data = await assert_standard_mcp_success_response(renamed_func.content, expected_result_type=dict)
                assert renamed_data.get("result", {}).get("name") == test_name, f"Renamed function has wrong name: {renamed_data}"
                logger.info(f"Renamed function result: {renamed_func}")
                
                # Rename back to original
                revert_args = {"port": GHYDRAMCP_TEST_PORT, "name": test_name, "new_name": original_name}
                logger.info(f"Calling update_function with args: {revert_args}")
                revert_result = await session.call_tool("update_function", arguments=revert_args)
                revert_data = json.loads(revert_result.content[0].text) # Parse simple response
                assert revert_data.get("success") is True, f"Revert rename failed: {revert_data}"
                logger.info(f"Revert rename result: {revert_result}")
                
                # Verify revert by getting the function
                original_func = await session.call_tool("get_function", arguments={"port": GHYDRAMCP_TEST_PORT, "name": original_name})
                original_data = await assert_standard_mcp_success_response(original_func.content, expected_result_type=dict)
                assert original_data.get("result", {}).get("name") == original_name, f"Original function has wrong name: {original_data}"
                logger.info(f"Original function result: {original_func}")

                # Test get_function_by_address
                logger.info(f"Calling get_function_by_address with address: {func_address}")
                get_by_addr_result = await session.call_tool("get_function_by_address", arguments={"port": GHYDRAMCP_TEST_PORT, "address": func_address})
                get_by_addr_data = await assert_standard_mcp_success_response(get_by_addr_result.content, expected_result_type=dict)
                result_data = get_by_addr_data.get("result", {})
                assert "name" in result_data, "Missing name field in get_function_by_address result"
                assert "address" in result_data, "Missing address field in get_function_by_address result" 
                assert "signature" in result_data, "Missing signature field in get_function_by_address result"
                assert "decompilation" in result_data, "Missing decompilation field in get_function_by_address result"
                assert result_data.get("name") == original_name, f"Wrong name in get_function_by_address: {result_data.get('name')}"
                logger.info(f"Get function by address result: {get_by_addr_result}")

                # Test decompile_function_by_address
                logger.info(f"Calling decompile_function_by_address with address: {func_address}")
                decompile_result = await session.call_tool("decompile_function_by_address", arguments={"port": GHYDRAMCP_TEST_PORT, "address": func_address})
                decompile_data = await assert_standard_mcp_success_response(decompile_result.content, expected_result_type=dict)
                assert "decompilation" in decompile_data.get("result", {}), f"Decompile result missing 'decompilation': {decompile_data}"
                assert isinstance(decompile_data.get("result", {}).get("decompilation", ""), str), f"Decompilation is not a string: {decompile_data}"
                assert len(decompile_data.get("result", {}).get("decompilation", "")) > 0, f"Decompilation result is empty: {decompile_data}"
                logger.info(f"Decompile function by address result: {decompile_result}")

                # Test list_variables 
                logger.info("Calling list_variables tool...")
                list_vars_result = await session.call_tool("list_variables", arguments={"port": 8192, "limit": 10})
                list_vars_data = await assert_standard_mcp_success_response(list_vars_result.content, expected_result_type=list)
                variables_list = list_vars_data.get("result", [])
                if variables_list:  # Only validate structure if we get results
                    for var in variables_list:
                        assert "name" in var, f"Variable missing name: {var}"
                        assert "type" in var, f"Variable missing type: {var}"
                        assert "dataType" in var, f"Variable missing dataType: {var}"
                logger.info(f"List variables result: {list_vars_result}")

                # Test successful comment operations (These return simple success/message)
                test_comment = "Test comment from MCP client"
                comment_args = {"port": 8192, "address": func_address, "comment": test_comment}
                logger.info(f"Calling set_decompiler_comment with args: {comment_args}")
                comment_result = await session.call_tool("set_decompiler_comment", arguments=comment_args)
                comment_data = json.loads(comment_result.content[0].text)
                assert comment_data.get("success") is True, f"Add comment failed: {comment_data}"
                logger.info(f"Add comment result: {comment_result}")
                
                # Remove comment
                remove_comment_args = {"port": 8192, "address": func_address, "comment": ""}
                logger.info(f"Calling set_decompiler_comment with args: {remove_comment_args}")
                remove_comment_result = await session.call_tool("set_decompiler_comment", arguments=remove_comment_args)
                remove_data = json.loads(remove_comment_result.content[0].text)
                assert remove_data.get("success") is True, f"Remove comment failed: {remove_data}"
                logger.info(f"Remove comment result: {remove_comment_result}")
                
                # Test expected failure cases
                # Try to rename non-existent function
                bad_rename_args = {"port": 8192, "name": "nonexistent_function", "new_name": "should_fail"}
                logger.info(f"Calling update_function with args: {bad_rename_args}")
                bad_rename_result = await session.call_tool("update_function", arguments=bad_rename_args)
                logger.info(f"Bad rename result: {bad_rename_result}") # Log the response
                bad_rename_data = json.loads(bad_rename_result.content[0].text)
                assert bad_rename_data.get("success") is False, f"Renaming non-existent function should fail, but got: {bad_rename_data}"

                # Try to get non-existent function
                bad_get_result = await session.call_tool(
                    "get_function",
                    arguments={"port": 8192, "name": "nonexistent_function"}
                )
                logger.info(f"Bad get result: {bad_get_result}") # Log the response
                bad_get_data = json.loads(bad_get_result.content[0].text)
                assert bad_get_data.get("success") is False, f"Getting non-existent function should fail, but got: {bad_get_data}"

                # Try to comment on invalid address
                bad_comment_args = {"port": 8192, "address": "0xinvalid", "comment": "should fail"}
                logger.info(f"Calling set_decompiler_comment with args: {bad_comment_args}")
                bad_comment_result = await session.call_tool("set_decompiler_comment", arguments=bad_comment_args)
                bad_comment_data = json.loads(bad_comment_result.content[0].text)
                assert bad_comment_data.get("success") is False, "Commenting on invalid address should fail"

                # Test get_current_address
                logger.info("Calling get_current_address tool...")
                current_addr_result = await session.call_tool("get_current_address", arguments={"port": 8192})
                current_addr_data = await assert_standard_mcp_success_response(current_addr_result.content, expected_result_type=dict)
                assert "address" in current_addr_data.get("result", {}), "Missing address in get_current_address result"
                assert isinstance(current_addr_data.get("result", {}).get("address", ""), str), "Address should be a string"
                logger.info(f"Get current address result: {current_addr_result}")

                # Test get_current_function
                logger.info("Calling get_current_function tool...")
                current_func_result = await session.call_tool("get_current_function", arguments={"port": 8192})
                current_func_data = await assert_standard_mcp_success_response(current_func_result.content, expected_result_type=dict)
                result_data = current_func_data.get("result", {})
                assert "name" in result_data, "Missing name in get_current_function result"
                assert "address" in result_data, "Missing address in get_current_function result"
                assert "signature" in result_data, "Missing signature in get_current_function result"
                logger.info(f"Get current function result: {current_func_result}")
                
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
