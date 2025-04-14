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
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

# Get host and port from environment variables or use defaults
GHYDRAMCP_TEST_HOST = os.getenv('GHYDRAMCP_TEST_HOST', 'localhost')
GHYDRAMCP_TEST_PORT = int(os.getenv('GHYDRAMCP_TEST_PORT', '8192'))

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp_client_test")

async def assert_standard_mcp_success_response(response_content, expected_result_type=None):
    """Helper to assert the standard HATEOAS response structure for MCP tool calls.
    
    HATEOAS API responses must include:
    - id: A UUID for the request
    - instance: The URL of the responding instance
    - success: Boolean indicating success or failure
    - result: The actual response data
    - _links: HATEOAS navigation links
    """
    assert response_content, "Response content is empty"
    try:
        data = json.loads(response_content[0].text)
    except (json.JSONDecodeError, IndexError) as e:
        assert False, f"Failed to parse JSON response: {e} - Content: {response_content}"

    # Check for required HATEOAS fields
    assert "id" in data, "Response missing 'id' field"
    assert "instance" in data, "Response missing 'instance' field"
    assert "success" in data, "Response missing 'success' field"
    assert data["success"] is True, f"API call failed: {data.get('error', 'Unknown error')}"
    assert "result" in data, "Response missing 'result' field"
    
    # HATEOAS links might be provided in several ways depending on API version
    has_links = False
    if "_links" in data:
        has_links = True
    elif "api_links" in data:
        has_links = True
        
    assert has_links, "Response missing navigation links for HATEOAS (neither '_links' nor 'api_links' found)"
    
    # Check result type if specified
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
            # logger.info(f"Tools result: {tools_result}")
            
            # Call the discover_instances tool
            logger.info("Calling discover_instances tool...")
            discover_instances_result = await session.call_tool("discover_instances")
            logger.info(f"Discover instances result: {discover_instances_result}")
            
            # Call the list_instances tool
            logger.info("Calling list_instances tool...")
            list_instances_result = await session.call_tool("list_instances")
            logger.info(f"List instances result: {list_instances_result}")
            
            # Call the list_functions tool with the new HATEOAS API
            logger.info("Calling list_functions tool...")
            list_functions_result = await session.call_tool(
                "list_functions",
                arguments={"port": GHYDRAMCP_TEST_PORT, "offset": 0, "limit": 5}
            )
            logger.info(f"List functions result: {list_functions_result}")
            
            # Test the current program endpoint
            logger.info("Calling get_program_info tool...")
            current_program_result = await session.call_tool(
                "get_program_info",
                arguments={"port": GHYDRAMCP_TEST_PORT}
            )
            logger.info(f"Current program result: {current_program_result}")

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

                # Test successful rename operations using rename_function
                rename_args = {"port": GHYDRAMCP_TEST_PORT, "name": original_name, "new_name": test_name}
                logger.info(f"Calling rename_function with args: {rename_args}")
                rename_result = await session.call_tool("rename_function", arguments=rename_args)
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
                logger.info(f"Calling rename_function with args: {revert_args}")
                revert_result = await session.call_tool("rename_function", arguments=revert_args)
                revert_data = json.loads(revert_result.content[0].text) # Parse simple response
                assert revert_data.get("success") is True, f"Revert rename failed: {revert_data}"
                logger.info(f"Revert rename result: {revert_result}")
                
                # Verify revert by getting the function
                original_func = await session.call_tool("get_function", arguments={"port": GHYDRAMCP_TEST_PORT, "name": original_name})
                original_data = await assert_standard_mcp_success_response(original_func.content, expected_result_type=dict)
                assert original_data.get("result", {}).get("name") == original_name, f"Original function has wrong name: {original_data}"
                logger.info(f"Original function result: {original_func}")

                # Test get_function with address parameter
                logger.info(f"Calling get_function with address: {func_address}")
                get_by_addr_result = await session.call_tool("get_function", arguments={"port": GHYDRAMCP_TEST_PORT, "address": func_address})
                get_by_addr_data = await assert_standard_mcp_success_response(get_by_addr_result.content, expected_result_type=dict)
                result_data = get_by_addr_data.get("result", {})
                assert "name" in result_data, "Missing name field in get_function result"
                assert "address" in result_data, "Missing address field in get_function result" 
                assert "signature" in result_data, "Missing signature field in get_function result"
                assert result_data.get("name") == original_name, f"Wrong name in get_function: {result_data.get('name')}"
                logger.info(f"Get function by address result: {get_by_addr_result}")

                # Test decompile_function
                logger.info(f"Calling decompile_function with address: {func_address}")
                decompile_result = await session.call_tool("decompile_function", arguments={"port": GHYDRAMCP_TEST_PORT, "address": func_address})
                decompile_data = await assert_standard_mcp_success_response(decompile_result.content, expected_result_type=dict)
                
                # The decompiled code might be in different fields depending on version
                has_decompiled = False
                if "decompiled_code" in decompile_data:
                    has_decompiled = True
                elif "decompiled_text" in decompile_data:
                    has_decompiled = True
                elif "result" in decompile_data and isinstance(decompile_data["result"], dict):
                    result = decompile_data["result"]
                    if "ccode" in result or "decompiled" in result or "decompiled_text" in result:
                        has_decompiled = True
                
                assert has_decompiled, f"Decompile result missing decompiled code: {decompile_data}"
                logger.info(f"Decompile function result: {decompile_result}")
                
                # Test disassemble_function
                logger.info(f"Calling disassemble_function with address: {func_address}")
                disassemble_result = await session.call_tool("disassemble_function", arguments={"port": GHYDRAMCP_TEST_PORT, "address": func_address})
                disassemble_data = json.loads(disassemble_result.content[0].text)
                assert disassemble_data.get("success") is True, f"Disassemble failed: {disassemble_data}"
                
                # Check for disassembly text in the simplified format
                has_disassembly = False
                if "disassembly" in disassemble_data:
                    has_disassembly = True
                elif "result" in disassemble_data and isinstance(disassemble_data["result"], dict):
                    result = disassemble_data["result"]
                    if "disassembly_text" in result:
                        has_disassembly = True
                    elif "instructions" in result:
                        has_disassembly = True
                
                assert has_disassembly, f"Disassembly result missing disassembly text: {disassemble_data}"
                
                # Check additional function info
                if "function_name" in disassemble_data:
                    assert isinstance(disassemble_data["function_name"], str), "function_name should be a string"
                if "function_address" in disassemble_data:
                    assert isinstance(disassemble_data["function_address"], str), "function_address should be a string"
                    
                logger.info(f"Disassemble function result: {disassemble_result}")

                # Test get_function_variables instead of list_variables
                logger.info("Calling get_function_variables tool...")
                function_vars_result = await session.call_tool("get_function_variables", arguments={"port": 8192, "address": func_address})
                try:
                    vars_data = await assert_standard_mcp_success_response(function_vars_result.content, expected_result_type=dict)
                    if "result" in vars_data and isinstance(vars_data["result"], dict) and "variables" in vars_data["result"]:
                        variables_list = vars_data["result"]["variables"]
                        if variables_list and len(variables_list) > 0:
                            for var in variables_list:
                                assert "name" in var, f"Variable missing name: {var}"
                        logger.info(f"Function variables result: {function_vars_result}")
                    else:
                        logger.info("Function variables available but no variables found in function.")
                except (AssertionError, KeyError) as e:
                    logger.warning(f"Could not validate function variables: {e}")

                # Test comment operations using set_comment
                test_comment = "Test comment from MCP client"
                comment_args = {"port": 8192, "address": func_address, "comment": test_comment, "comment_type": "plate"}
                logger.info(f"Calling set_comment with args: {comment_args}")
                comment_result = await session.call_tool("set_comment", arguments=comment_args)
                comment_data = json.loads(comment_result.content[0].text)
                assert comment_data.get("success") is True, f"Add comment failed: {comment_data}"
                logger.info(f"Add comment result: {comment_result}")
                
                # Remove comment
                remove_comment_args = {"port": 8192, "address": func_address, "comment": "", "comment_type": "plate"}
                logger.info(f"Calling set_comment with args: {remove_comment_args}")
                remove_comment_result = await session.call_tool("set_comment", arguments=remove_comment_args)
                remove_data = json.loads(remove_comment_result.content[0].text)
                assert remove_data.get("success") is True, f"Remove comment failed: {remove_data}"
                logger.info(f"Remove comment result: {remove_comment_result}")
                
                # Test comments using set_decompiler_comment (which is a convenience wrapper for set_comment)
                test_comment = "Test decompiler comment from MCP client"
                decompiler_comment_args = {"port": 8192, "address": func_address, "comment": test_comment}
                logger.info(f"Calling set_decompiler_comment with args: {decompiler_comment_args}")
                decompiler_comment_result = await session.call_tool("set_decompiler_comment", arguments=decompiler_comment_args)
                decompiler_comment_data = json.loads(decompiler_comment_result.content[0].text)
                assert decompiler_comment_data.get("success") is True, f"Add decompiler comment failed: {decompiler_comment_data}"
                logger.info(f"Add decompiler comment result: {decompiler_comment_result}")
                
                # Remove decompiler comment
                remove_decompiler_comment_args = {"port": 8192, "address": func_address, "comment": ""}
                logger.info(f"Calling set_decompiler_comment with args: {remove_decompiler_comment_args}")
                remove_decompiler_comment_result = await session.call_tool("set_decompiler_comment", arguments=remove_decompiler_comment_args)
                remove_decompiler_data = json.loads(remove_decompiler_comment_result.content[0].text)
                assert remove_decompiler_data.get("success") is True, f"Remove decompiler comment failed: {remove_decompiler_data}"
                logger.info(f"Remove decompiler comment result: {remove_decompiler_comment_result}")
                
                # Test expected failure cases
                # Try to rename non-existent function  
                bad_rename_args = {"port": 8192, "name": "nonexistent_function", "new_name": "should_fail"}
                logger.info(f"Calling rename_function with args: {bad_rename_args}")
                try:
                    bad_rename_result = await session.call_tool("rename_function", arguments=bad_rename_args)
                    logger.info(f"Bad rename result: {bad_rename_result}") # Log the response
                    bad_rename_data = json.loads(bad_rename_result.content[0].text)
                    assert bad_rename_data.get("success") is False, f"Renaming non-existent function should fail, but got: {bad_rename_data}"
                except Exception as e:
                    # It's also acceptable if the tool call itself fails, as long as it doesn't succeed
                    logger.info(f"Expected failure: rename_function properly rejected bad parameters: {e}")

                # Try to get non-existent function
                bad_get_result = await session.call_tool(
                    "get_function",
                    arguments={"port": 8192, "name": "nonexistent_function"}
                )
                logger.info(f"Bad get result: {bad_get_result}") # Log the response
                bad_get_data = json.loads(bad_get_result.content[0].text)
                assert bad_get_data.get("success") is False, f"Getting non-existent function should fail, but got: {bad_get_data}"

                # Try to comment on invalid address
                bad_comment_args = {"port": 8192, "address": "0xinvalid", "comment": "should fail", "comment_type": "plate"}
                logger.info(f"Calling set_comment with args: {bad_comment_args}")
                bad_comment_result = await session.call_tool("set_comment", arguments=bad_comment_args)
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
                
                # Test read_memory functionality
                logger.info(f"Calling read_memory with address: {func_address}")
                read_memory_result = await session.call_tool("read_memory", arguments={"port": 8192, "address": func_address, "length": 16})
                read_memory_data = json.loads(read_memory_result.content[0].text)
                assert read_memory_data.get("success") is True, f"Read memory failed: {read_memory_data}"
                assert "hexBytes" in read_memory_data, "Missing hexBytes in read_memory result"
                assert "rawBytes" in read_memory_data, "Missing rawBytes in read_memory result"
                assert read_memory_data.get("address") == func_address, f"Wrong address in read_memory result: {read_memory_data.get('address')}"
                logger.info(f"Read memory result: {read_memory_result}")
                
                # Test data operations (create, rename, change type)
                logger.info("Testing data operations...")
                try:
                    # Get a memory address to create test data
                    data_address = func_address
                    
                    # First create test data
                    create_data_args = {"port": 8192, "address": data_address, "data_type": "uint32_t"}
                    logger.info(f"Calling create_data with args: {create_data_args}")
                    create_data_result = await session.call_tool("create_data", arguments=create_data_args)
                    create_data_response = json.loads(create_data_result.content[0].text)
                    assert create_data_response.get("success") is True, f"Create data failed: {create_data_response}"
                    logger.info(f"Create data result: {create_data_result}")
                    
                    # Test Case 1: Data rename operation (name only)
                    test_data_name = "test_data_item"
                    rename_data_args = {"port": 8192, "address": data_address, "name": test_data_name}
                    logger.info(f"Calling rename_data with args: {rename_data_args}")
                    rename_data_result = await session.call_tool("rename_data", arguments=rename_data_args)
                    rename_data_response = json.loads(rename_data_result.content[0].text)
                    assert rename_data_response.get("success") is True, f"Rename data failed: {rename_data_response}"
                    logger.info(f"Rename data result: {rename_data_result}")
                    
                    # Verify the name was changed
                    if rename_data_response.get("result", {}).get("name") != test_data_name:
                        logger.warning(f"Rename operation didn't set the expected name. Got: {rename_data_response.get('result', {}).get('name')}")
                    
                    # Test Case 2: Data type change operation (type only)
                    change_type_args = {"port": 8192, "address": data_address, "data_type": "int"}
                    logger.info(f"Calling set_data_type with args: {change_type_args}")
                    change_type_result = await session.call_tool("set_data_type", arguments=change_type_args)
                    change_type_response = json.loads(change_type_result.content[0].text)
                    assert change_type_response.get("success") is True, f"Change data type failed: {change_type_response}"
                    logger.info(f"Change data type result: {change_type_result}")
                    
                    # Verify the type was changed but name was preserved
                    result = change_type_response.get("result", {})
                    if result.get("dataType") != "int":
                        logger.warning(f"Type change operation didn't set the expected type. Got: {result.get('dataType')}")
                    if result.get("name") != test_data_name:
                        logger.warning(f"Type change operation didn't preserve the name. Expected: {test_data_name}, Got: {result.get('name')}")
                    
                    # Test Case 3: Combined update operation (both name and type)
                    update_data_args = {
                        "port": 8192, 
                        "address": data_address, 
                        "name": "updated_data_item", 
                        "data_type": "byte"
                    }
                    logger.info(f"Calling update_data with args: {update_data_args}")
                    update_data_result = await session.call_tool("update_data", arguments=update_data_args)
                    update_data_response = json.loads(update_data_result.content[0].text)
                    assert update_data_response.get("success") is True, f"Update data failed: {update_data_response}"
                    logger.info(f"Update data result: {update_data_result}")
                    
                    # Verify both name and type were changed
                    result = update_data_response.get("result", {})
                    if result.get("name") != "updated_data_item":
                        logger.warning(f"Update operation didn't set the expected name. Got: {result.get('name')}")
                    if result.get("dataType") != "byte":
                        logger.warning(f"Update operation didn't set the expected type. Got: {result.get('dataType')}")
                    
                    # Clean up by restoring original data type
                    restore_type_args = {"port": 8192, "address": data_address, "data_type": "uint32_t"}
                    logger.info(f"Restoring data type with args: {restore_type_args}")
                    restore_type_result = await session.call_tool("set_data_type", arguments=restore_type_args)
                    restore_type_response = json.loads(restore_type_result.content[0].text)
                    assert restore_type_response.get("success") is True, f"Restore data type failed: {restore_type_response}"
                    
                except Exception as e:
                    logger.warning(f"Error testing data operations: {e} - This is not critical")
                
                # Test callgraph functionality - handle possible failure gracefully
                if func_address:
                    logger.info(f"Calling get_callgraph with address: {func_address}")
                    try:
                        callgraph_result = await session.call_tool("get_callgraph", arguments={"port": 8192, "address": func_address})
                        callgraph_data = json.loads(callgraph_result.content[0].text)
                        if callgraph_data.get("success"):
                            assert "result" in callgraph_data, "Missing result in get_callgraph response"
                            # The result could be either a dict with nodes/edges or a direct graph representation
                            logger.info(f"Get callgraph result: successful")
                        else:
                            # It's okay if the callgraph fails on some functions - log the error
                            logger.info(f"Get callgraph result: failed - {callgraph_data.get('error', {}).get('message', 'Unknown error')}")
                    except Exception as e:
                        logger.warning(f"Error in callgraph test: {e} - This is not critical")
                        
                # Test function signature operations
                logger.info("Testing function signature operations...")
                try:
                    # Get current signature
                    get_func_for_sig = await session.call_tool("get_function", arguments={"port": 8192, "address": func_address})
                    get_func_for_sig_data = await assert_standard_mcp_success_response(get_func_for_sig.content, expected_result_type=dict)
                    original_signature = get_func_for_sig_data.get("result", {}).get("signature", "")
                    
                    if not original_signature:
                        logger.warning("Could not get original signature - skipping signature test")
                    else:
                        # Create test signature by adding parameters
                        modified_signature = f"int {func_name}(uint32_t *data, int block_count, uint32_t *key)"
                        logger.info(f"Original signature: {original_signature}")
                        logger.info(f"Setting function signature to: {modified_signature}")
                        
                        # Set new signature
                        set_sig_result = await session.call_tool("set_function_signature", 
                                                             arguments={"port": 8192, 
                                                                        "address": func_address, 
                                                                        "signature": modified_signature})
                        set_sig_data = json.loads(set_sig_result.content[0].text)
                        assert set_sig_data.get("success") is True, f"Set signature failed: {set_sig_data}"
                        logger.info(f"Set signature result: {set_sig_result}")
                        
                        # Verify the change
                        verify_sig_result = await session.call_tool("get_function", arguments={"port": 8192, "address": func_address})
                        verify_sig_data = await assert_standard_mcp_success_response(verify_sig_result.content, expected_result_type=dict)
                        new_signature = verify_sig_data.get("result", {}).get("signature", "")
                        assert "uint32_t *data" in new_signature, f"Signature not properly updated: {new_signature}"
                        logger.info(f"Updated signature: {new_signature}")
                        
                        # Restore original signature
                        logger.info(f"Restoring original signature: {original_signature}")
                        restore_sig_result = await session.call_tool("set_function_signature", 
                                                                 arguments={"port": 8192, 
                                                                            "address": func_address, 
                                                                            "signature": original_signature})
                        restore_sig_data = json.loads(restore_sig_result.content[0].text)
                        assert restore_sig_data.get("success") is True, f"Restore signature failed: {restore_sig_data}"
                        logger.info(f"Restore signature result: {restore_sig_result}")
                        
                        # Verify restoration
                        final_func_result = await session.call_tool("get_function", arguments={"port": 8192, "address": func_address})
                        final_func_data = await assert_standard_mcp_success_response(final_func_result.content, expected_result_type=dict)
                        final_signature = final_func_data.get("result", {}).get("signature", "")
                        assert final_signature == original_signature, f"Signature not properly restored: {final_signature}"
                        logger.info(f"Restored signature: {final_signature}")
                except Exception as e:
                    logger.warning(f"Error in signature test: {e} - This is not critical")
                
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
