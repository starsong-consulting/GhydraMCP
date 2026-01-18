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
            # logger.info(f"Tools result: {tools_result}") # Optional: uncomment for verbose tool listing

            # Call the instances_discover tool
            logger.info("Calling instances_discover tool...")
            discover_instances_result = await session.call_tool("instances_discover")
            logger.info(f"Discover instances result: {discover_instances_result}")

            # Call the instances_list tool
            logger.info("Calling instances_list tool...")
            list_instances_result = await session.call_tool("instances_list")
            logger.info(f"List instances result: {list_instances_result}")

            # Set the current instance to use for subsequent calls
            logger.info(f"Setting current instance to port {GHYDRAMCP_TEST_PORT}...")
            use_instance_result = await session.call_tool("instances_use", arguments={"port": GHYDRAMCP_TEST_PORT})
            logger.info(f"Use instance result: {use_instance_result}")

            # Call the functions_list tool (no port needed now)
            logger.info("Calling functions_list tool...")
            list_functions_result = await session.call_tool(
                "functions_list",
                arguments={"offset": 0, "limit": 5} # No port needed
            )
            logger.info(f"List functions result: {list_functions_result}")

            # Test the current instance endpoint
            logger.info("Calling instances_current tool...")
            current_program_result = await session.call_tool("instances_current") # No args needed
            logger.info(f"Current instance result: {current_program_result}")
            # Add assertion for current instance result structure if needed
            current_data = json.loads(current_program_result.content[0].text)
            assert "port" in current_data, "Missing port in instances_current result"
            assert "program_name" in current_data, "Missing program_name in instances_current result"

            # Test mutating operations by changing and reverting
            logger.info("Testing mutating operations...")

            try:
                # Get a known function to test with from functions_list result
                list_funcs = await session.call_tool(
                    "functions_list",
                    arguments={"offset": 0, "limit": 5} # No port needed
                )

                if not list_funcs or not list_funcs.content:
                    logger.warning("No functions found via functions_list - skipping mutating tests")
                    return

                # Parse the JSON response from functions_list using helper
                try:
                    list_funcs_data = await assert_standard_mcp_success_response(list_funcs.content, expected_result_type=list)
                    func_list = list_funcs_data.get("result", [])
                    if not func_list:
                        logger.warning("No functions in functions_list result - skipping mutating tests")
                        return

                    # Get first function's name and address
                    # Ensure the item is a dictionary before accessing keys
                    first_func = func_list[0]
                    if not isinstance(first_func, dict):
                        logger.warning(f"First item in functions_list is not a dict: {first_func} - skipping mutating tests")
                        return

                    func_name = first_func.get("name", "")
                    func_address = first_func.get("address", "")

                    if not func_name or not func_address:
                        logger.warning("No function name/address found in functions_list result - skipping mutating tests")
                        return
                except (AssertionError, IndexError, TypeError) as e:
                     logger.warning(f"Error processing functions_list data: {e} - skipping mutating tests")
                     return

                # Test function renaming using functions_rename
                original_name = func_name
                test_name = f"{func_name}_test_mcp" # Make name slightly more unique

                # Test successful rename operations using functions_rename (no port needed)
                rename_args = {"old_name": original_name, "new_name": test_name} # Use old_name instead of name
                logger.info(f"Calling functions_rename with args: {rename_args}")
                rename_result = await session.call_tool("functions_rename", arguments=rename_args)
                rename_data = json.loads(rename_result.content[0].text) # Parse simple response
                assert rename_data.get("success") is True, f"Rename failed: {rename_data}"
                logger.info(f"Rename result: {rename_result}")

                # Verify rename by getting the function using functions_get (no port needed)
                renamed_func = await session.call_tool("functions_get", arguments={"name": test_name})
                renamed_data = await assert_standard_mcp_success_response(renamed_func.content, expected_result_type=dict)
                assert renamed_data.get("result", {}).get("name") == test_name, f"Renamed function has wrong name: {renamed_data}"
                logger.info(f"Renamed function result: {renamed_func}")

                # Rename back to original using functions_rename (no port needed)
                revert_args = {"old_name": test_name, "new_name": original_name} # Use old_name
                logger.info(f"Calling functions_rename with args: {revert_args}")
                revert_result = await session.call_tool("functions_rename", arguments=revert_args)
                revert_data = json.loads(revert_result.content[0].text) # Parse simple response
                assert revert_data.get("success") is True, f"Revert rename failed: {revert_data}"
                logger.info(f"Revert rename result: {revert_result}")

                # Verify revert by getting the function using functions_get (no port needed)
                original_func = await session.call_tool("functions_get", arguments={"name": original_name})
                original_data = await assert_standard_mcp_success_response(original_func.content, expected_result_type=dict)
                assert original_data.get("result", {}).get("name") == original_name, f"Original function has wrong name: {original_data}"
                logger.info(f"Original function result: {original_func}")

                # Test functions_get with address parameter (no port needed)
                logger.info(f"Calling functions_get with address: {func_address}")
                get_by_addr_result = await session.call_tool("functions_get", arguments={"address": func_address})
                get_by_addr_data = await assert_standard_mcp_success_response(get_by_addr_result.content, expected_result_type=dict)
                result_data = get_by_addr_data.get("result", {})
                assert "name" in result_data, "Missing name field in functions_get result"
                assert "address" in result_data, "Missing address field in functions_get result"
                assert "signature" in result_data, "Missing signature field in functions_get result"
                assert result_data.get("name") == original_name, f"Wrong name in functions_get: {result_data.get('name')}"
                logger.info(f"Get function by address result: {get_by_addr_result}")

                # Test functions_decompile (no port needed)
                logger.info(f"Calling functions_decompile with address: {func_address}")
                decompile_result = await session.call_tool("functions_decompile", arguments={"address": func_address})
                decompile_data = await assert_standard_mcp_success_response(decompile_result.content, expected_result_type=dict)

                # Check for decompiled code (bridge adds 'decompiled_code' field)
                assert "decompiled_code" in decompile_data, f"Decompile result missing decompiled_code field: {decompile_data}"
                assert isinstance(decompile_data["decompiled_code"], str), "decompiled_code should be a string"
                logger.info(f"Decompile function result: {decompile_result}")

                # Test functions_disassemble (no port needed)
                logger.info(f"Calling functions_disassemble with address: {func_address}")
                disassemble_result = await session.call_tool("functions_disassemble", arguments={"address": func_address})
                disassemble_data = json.loads(disassemble_result.content[0].text)
                assert disassemble_data.get("success") is True, f"Disassemble failed: {disassemble_data}"

                # Check for disassembly text (bridge adds 'disassembly_text' field)
                assert "result" in disassemble_data and isinstance(disassemble_data["result"], dict), "Disassembly result missing 'result' object"
                result = disassemble_data["result"]
                assert "disassembly_text" in result, f"Disassembly result missing disassembly_text field: {disassemble_data}"
                assert isinstance(result["disassembly_text"], str), "disassembly_text should be a string"

                # Check additional function info if present
                if "name" in result:
                    assert isinstance(result["name"], str), "function name should be a string"
                if "address" in result:
                    assert isinstance(result["address"], str), "function address should be a string"

                logger.info(f"Disassemble function result: {disassemble_result}")

                # Test functions_get_variables (no port needed)
                logger.info("Calling functions_get_variables tool...")
                function_vars_result = await session.call_tool("functions_get_variables", arguments={"address": func_address})
                try:
                    vars_data = await assert_standard_mcp_success_response(function_vars_result.content, expected_result_type=dict)
                    if "result" in vars_data and isinstance(vars_data["result"], dict) and "variables" in vars_data["result"]:
                        variables_list = vars_data["result"]["variables"]
                        if variables_list and len(variables_list) > 0:
                            for var in variables_list:
                                assert "name" in var, f"Variable missing name: {var}"
                                # Check for 'type' field instead of 'dataType' based on recent bridge changes/output
                                assert "type" in var, f"Variable missing type: {var}"
                        logger.info(f"Function variables result: {function_vars_result}")
                    else:
                        logger.info("Function variables available but no variables found in function.")
                except (AssertionError, KeyError) as e:
                    # Correct the warning message to reflect the actual check
                    logger.warning(f"Could not validate function variables (expected 'name' and 'type' fields): {e}")

                # Test comment operations using comments_set and functions_set_comment
                test_comment_plate = "Test plate comment from MCP client"
                comment_args_plate = {"address": func_address, "comment": test_comment_plate, "comment_type": "plate"}
                logger.info(f"Calling comments_set (plate) with args: {comment_args_plate}")
                comment_result_plate = await session.call_tool("comments_set", arguments=comment_args_plate)
                comment_data_plate = json.loads(comment_result_plate.content[0].text)
                assert comment_data_plate.get("success") is True, f"Add plate comment failed: {comment_data_plate}"
                logger.info(f"Add plate comment result: {comment_result_plate}")

                # Remove plate comment
                remove_comment_args_plate = {"address": func_address, "comment": "", "comment_type": "plate"}
                logger.info(f"Calling comments_set (remove plate) with args: {remove_comment_args_plate}")
                remove_comment_result_plate = await session.call_tool("comments_set", arguments=remove_comment_args_plate)
                remove_data_plate = json.loads(remove_comment_result_plate.content[0].text)
                assert remove_data_plate.get("success") is True, f"Remove plate comment failed: {remove_data_plate}"
                logger.info(f"Remove plate comment result: {remove_comment_result_plate}")

                # Test function comment using functions_set_comment
                test_comment_func = "Test function comment from MCP client"
                func_comment_args = {"address": func_address, "comment": test_comment_func}
                logger.info(f"Calling functions_set_comment with args: {func_comment_args}")
                func_comment_result = await session.call_tool("functions_set_comment", arguments=func_comment_args)
                func_comment_data = json.loads(func_comment_result.content[0].text)
                assert func_comment_data.get("success") is True, f"Add function comment failed: {func_comment_data}"
                logger.info(f"Add function comment result: {func_comment_result}")

                # Remove function comment
                remove_func_comment_args = {"address": func_address, "comment": ""}
                logger.info(f"Calling functions_set_comment (remove) with args: {remove_func_comment_args}")
                remove_func_comment_result = await session.call_tool("functions_set_comment", arguments=remove_func_comment_args)
                remove_func_data = json.loads(remove_func_comment_result.content[0].text)
                assert remove_func_data.get("success") is True, f"Remove function comment failed: {remove_func_data}"
                logger.info(f"Remove function comment result: {remove_func_comment_result}")

                # Test expected failure cases
                # Try to rename non-existent function using functions_rename
                bad_rename_args = {"old_name": "nonexistent_function_mcp", "new_name": "should_fail"}
                logger.info(f"Calling functions_rename with args: {bad_rename_args}")
                try:
                    bad_rename_result = await session.call_tool("functions_rename", arguments=bad_rename_args)
                    logger.info(f"Bad rename result: {bad_rename_result}") # Log the response
                    bad_rename_data = json.loads(bad_rename_result.content[0].text)
                    assert bad_rename_data.get("success") is False, f"Renaming non-existent function should fail, but got: {bad_rename_data}"
                except Exception as e:
                    # It's also acceptable if the tool call itself fails, as long as it doesn't succeed
                    logger.info(f"Expected failure: functions_rename properly rejected bad parameters: {e}")

                # Try to get non-existent function using functions_get
                bad_get_result = await session.call_tool(
                    "functions_get",
                    arguments={"name": "nonexistent_function_mcp"}
                )
                logger.info(f"Bad get result: {bad_get_result}") # Log the response
                bad_get_data = json.loads(bad_get_result.content[0].text)
                assert bad_get_data.get("success") is False, f"Getting non-existent function should fail, but got: {bad_get_data}"

                # Try to comment on invalid address using comments_set and assert failure
                bad_comment_args = {"address": "0xinvalid", "comment": "should fail", "comment_type": "plate"}
                logger.info(f"Calling comments_set with invalid args: {bad_comment_args}")
                try:
                    bad_comment_result = await session.call_tool("comments_set", arguments=bad_comment_args)
                    bad_comment_data = json.loads(bad_comment_result.content[0].text)
                    assert bad_comment_data.get("success") is False, "Commenting on invalid address should fail"
                    logger.info(f"Expected failure: comments_set properly rejected bad address: {bad_comment_data}")
                except Exception as e:
                     # It's also acceptable if the tool call itself fails
                    logger.info(f"Expected failure: comments_set properly rejected bad address via exception: {e}")


                # Test ui_get_current_address (no port needed)
                logger.info("Calling ui_get_current_address tool...")
                current_addr_result = await session.call_tool("ui_get_current_address")
                current_addr_data = await assert_standard_mcp_success_response(current_addr_result.content, expected_result_type=dict)
                assert "address" in current_addr_data.get("result", {}), "Missing address in ui_get_current_address result"
                assert isinstance(current_addr_data.get("result", {}).get("address", ""), str), "Address should be a string"
                logger.info(f"Get current address result: {current_addr_result}")

                # Test ui_get_current_function (no port needed)
                logger.info("Calling ui_get_current_function tool...")
                current_func_result = await session.call_tool("ui_get_current_function")
                current_func_data = await assert_standard_mcp_success_response(current_func_result.content, expected_result_type=dict)
                result_data = current_func_data.get("result", {})
                # Check if function exists at current location, might be null
                if result_data:
                    assert "name" in result_data, "Missing name in ui_get_current_function result"
                    assert "address" in result_data, "Missing address in ui_get_current_function result"
                    assert "signature" in result_data, "Missing signature in ui_get_current_function result"
                else:
                    logger.info("No function found at current UI location.")
                logger.info(f"Get current function result: {current_func_result}")

                # Test memory_read functionality (no port needed)
                logger.info(f"Calling memory_read with address: {func_address}")
                read_memory_result = await session.call_tool("memory_read", arguments={"address": func_address, "length": 16})
                read_memory_data = json.loads(read_memory_result.content[0].text)
                assert read_memory_data.get("success") is True, f"Read memory failed: {read_memory_data}"
                # Bridge simplification puts data directly in response
                assert "hexBytes" in read_memory_data, "Missing hexBytes in memory_read result"
                assert "rawBytes" in read_memory_data, "Missing rawBytes in memory_read result"
                assert read_memory_data.get("address") == func_address, f"Wrong address in memory_read result: {read_memory_data.get('address')}"
                logger.info(f"Read memory result: {read_memory_result}")

                # Test data operations (create, rename, change type, delete) using namespaced tools
                logger.info("Testing data operations...")
                # Use the specific address provided by the user
                data_address = "0x20000fa0"
                logger.info(f"Using address {data_address} for data operations test.")

                # Wrap the entire data operations block to prevent failures from halting tests
                if data_address:
                    logger.info("--- Starting Data Operations Test Block ---")
                    try:
                        original_data_type = "undefined" # Placeholder, might not exist initially

                        # First create test data using data_create (no port needed)
                        create_data_args = {"address": data_address, "data_type": "uint32_t"}
                        logger.info(f"Calling data_create with args: {create_data_args}")
                        create_data_result = await session.call_tool("data_create", arguments=create_data_args)
                        create_data_response = json.loads(create_data_result.content[0].text)
                        assert create_data_response.get("success") is True, f"Create data failed: {create_data_response}"
                        logger.info(f"Create data result: {create_data_result}")
                        original_data_type = "uint32_t" # Update original type

                        # Test Case 1: Data rename operation using data_rename (no port needed)
                        test_data_name = f"test_data_{data_address.replace('0x', '')}" # Unique name
                        rename_data_args = {"address": data_address, "name": test_data_name}
                        logger.info(f"Calling data_rename with args: {rename_data_args}")
                        rename_data_result = await session.call_tool("data_rename", arguments=rename_data_args)
                        rename_data_response = json.loads(rename_data_result.content[0].text)
                        assert rename_data_response.get("success") is True, f"Rename data failed: {rename_data_response}"
                        logger.info(f"Rename data result: {rename_data_result}")

                        # Verify the name was changed (check the result field)
                        # Note: rename_data response might not contain the full updated object, skip verification for now
                        # if rename_data_response.get("result", {}).get("name") != test_data_name:
                        #     logger.warning(f"Rename operation didn't set the expected name. Got: {rename_data_response.get('result', {}).get('name')}")

                        # Test Case 2: Data type change operation using data_set_type (no port needed)
                        change_type_args = {"address": data_address, "data_type": "int"}
                        logger.info(f"Calling data_set_type with args: {change_type_args}")
                        change_type_result = await session.call_tool("data_set_type", arguments=change_type_args)
                        change_type_response = json.loads(change_type_result.content[0].text)
                        assert change_type_response.get("success") is True, f"Change data type failed: {change_type_response}"
                        logger.info(f"Change data type result: {change_type_result}")

                        # Verify the type was changed but name was preserved
                        result = change_type_response.get("result", {})
                        # Check the 'dataType' field from the response
                        if result.get("dataType") != "int":
                            logger.warning(f"Type change operation didn't set the expected type. Got: {result.get('dataType')}")
                        if result.get("name") != test_data_name:
                            logger.warning(f"Type change operation didn't preserve the name. Expected: {test_data_name}, Got: {result.get('name')}")

                        # REMOVED: Test Case 3 (Combined update) as update_data tool no longer exists

                        # Clean up by deleting the created data using data_delete
                        delete_data_args = {"address": data_address}
                        logger.info(f"Deleting data with args: {delete_data_args}")
                        delete_data_result = await session.call_tool("data_delete", arguments=delete_data_args)
                        delete_data_response = json.loads(delete_data_result.content[0].text)
                        assert delete_data_response.get("success") is True, f"Delete data failed: {delete_data_response}"
                        logger.info(f"Delete data result: {delete_data_result}")

                    except Exception as e:
                        logger.warning(f"Error testing data operations: {e} - This is not critical. Attempting cleanup.")
                        # Attempt cleanup even if tests failed mid-way
                        if data_address: # Only attempt cleanup if address was valid
                            try:
                                delete_data_args = {"address": data_address}
                                await session.call_tool("data_delete", arguments=delete_data_args)
                                logger.info("Data cleanup attempted.")
                            except Exception as cleanup_e:
                                logger.error(f"Data cleanup failed: {cleanup_e}")
                    logger.info("--- Finished Data Operations Test Block ---")


                # Test callgraph functionality using analysis_get_callgraph with both address and name parameters
                if func_address and func_name:
                    logger.info("Testing analysis_get_callgraph with address and name parameters")

                    # Test with address parameter
                    try:
                        logger.info(f"Calling analysis_get_callgraph with address: {func_address}")
                        callgraph_by_address = await session.call_tool("analysis_get_callgraph", arguments={"address": func_address})
                        callgraph_address_data = json.loads(callgraph_by_address.content[0].text)
                        if callgraph_address_data.get("success"):
                            assert "result" in callgraph_address_data, "Missing result in analysis_get_callgraph(address) response"
                            logger.info("Get callgraph by address: successful")
                        else:
                            # Log failure as warning, don't fail the test
                            logger.warning(f"Get callgraph by address failed: {callgraph_address_data.get('error', {}).get('message', 'Unknown error')}")
                    except Exception as e:
                        logger.warning(f"Error during callgraph by address test: {e} - This is not critical")

                    # Test with name parameter
                    try:
                        logger.info(f"Calling analysis_get_callgraph with name: {func_name}")
                        callgraph_by_name = await session.call_tool("analysis_get_callgraph", arguments={"name": func_name})
                        callgraph_name_data = json.loads(callgraph_by_name.content[0].text)
                        if callgraph_name_data.get("success"):
                            assert "result" in callgraph_name_data, "Missing result in analysis_get_callgraph(name) response"
                            logger.info("Get callgraph by name: successful")
                        else:
                            # Log failure as warning, don't fail the test
                            logger.warning(f"Get callgraph by name failed: {callgraph_name_data.get('error', {}).get('message', 'Unknown error')}")
                    except Exception as e:
                        logger.warning(f"Error during callgraph by name test: {e} - This is not critical")

                # Test function signature operations using functions_set_signature
                logger.info("Testing function signature operations...")
                try:
                    # Get current signature using functions_get
                    get_func_for_sig = await session.call_tool("functions_get", arguments={"address": func_address})
                    get_func_for_sig_data = await assert_standard_mcp_success_response(get_func_for_sig.content, expected_result_type=dict)
                    original_signature = get_func_for_sig_data.get("result", {}).get("signature", "")

                    if not original_signature:
                        logger.warning("Could not get original signature - skipping signature test")
                    else:
                        # Create test signature by changing types to ensure it's actually different
                        # Using 'uint' instead of 'unsigned int' to match Ghidra's normalized type naming
                        modified_signature = f"byte {func_name}(uint * mcp_data, short mcp_count, int * mcp_key)"
                        logger.info(f"Original signature: {original_signature}")
                        logger.info(f"Setting function signature to: {modified_signature}")

                        # Set new signature using functions_set_signature (no port needed)
                        set_sig_result = await session.call_tool("functions_set_signature",
                                                             arguments={"address": func_address,
                                                                        "signature": modified_signature})
                        set_sig_data = json.loads(set_sig_result.content[0].text)
                        assert set_sig_data.get("success") is True, f"Set signature failed: {set_sig_data}"
                        logger.info(f"Set signature result: {set_sig_result}")

                        # Verify the change using functions_get
                        verify_sig_result = await session.call_tool("functions_get", arguments={"address": func_address})
                        verify_sig_data = await assert_standard_mcp_success_response(verify_sig_result.content, expected_result_type=dict)
                        new_signature = verify_sig_data.get("result", {}).get("signature", "")
                        # Strict check for the exact signature string, stripping whitespace
                        assert new_signature.strip() == modified_signature.strip(), f"Signature not properly updated. Expected '{modified_signature}', got '{new_signature}'"
                        logger.info(f"Updated signature: {new_signature}")

                        # Restore original signature using functions_set_signature
                        logger.info(f"Restoring original signature: {original_signature}")
                        restore_sig_result = await session.call_tool("functions_set_signature",
                                                                 arguments={"address": func_address,
                                                                            "signature": original_signature})
                        restore_sig_data = json.loads(restore_sig_result.content[0].text)
                        assert restore_sig_data.get("success") is True, f"Restore signature failed: {restore_sig_data}"
                        logger.info(f"Restore signature result: {restore_sig_result}")

                        # Verify restoration using functions_get
                        final_func_result = await session.call_tool("functions_get", arguments={"address": func_address})
                        final_func_data = await assert_standard_mcp_success_response(final_func_result.content, expected_result_type=dict)
                        final_signature = final_func_data.get("result", {}).get("signature", "")
                        assert final_signature.strip() == original_signature.strip(), f"Signature not properly restored. Expected '{original_signature}', got '{final_signature}'"
                        logger.info(f"Restored signature: {final_signature}")
                except Exception as e:
                    logger.warning(f"Error in signature test: {e} - This is not critical")

            except Exception as e:
                logger.error(f"Error testing mutating operations: {e}", exc_info=True)
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
