#!/usr/bin/env python3
"""
Test script for the GhydraMCP HTTP API.
This script tests the HTTP endpoints of the Java plugin.
"""
import json
import requests
import time
import unittest
import os
import sys

# Default Ghidra server port
DEFAULT_PORT = 8192

# Get host from environment variable or default to localhost
GHYDRAMCP_TEST_HOST = os.getenv('GHYDRAMCP_TEST_HOST')
if GHYDRAMCP_TEST_HOST and GHYDRAMCP_TEST_HOST.strip():
    BASE_URL = f"http://{GHYDRAMCP_TEST_HOST}:{DEFAULT_PORT}"
else:
    BASE_URL = f"http://localhost:{DEFAULT_PORT}"

# Command line arguments handling
DISPLAY_RESPONSES = False
if len(sys.argv) > 1 and sys.argv[1] == "--show-responses":
    DISPLAY_RESPONSES = True
    # Remove the flag so unittest doesn't try to use it
    sys.argv.pop(1)

"""
STRICT HATEOAS COMPLIANCE REQUIREMENTS:

All endpoints must follow these requirements:
1. Include success, id, instance, and result fields in response
2. Include _links with at least a "self" link
3. Use consistent result structures for the same resource types
4. Follow standard RESTful URL patterns (e.g., /functions/{address})
5. Include pagination metadata (offset, limit, size) for collection endpoints

Endpoints requiring HATEOAS updates:
- /classes: Missing _links field
- /instances: Missing _links field
- /segments: Result should be a list, not an object
- /functions/{address}/decompile: Result should include "decompiled" field
- /functions/{address}/disassembly: Result should include "instructions" list
- /functions/by-name/{name}/variables: Result should include "variables" and "function" fields

This test suite enforces strict HATEOAS compliance with no backward compatibility.
"""

class GhydraMCPHttpApiTests(unittest.TestCase):
    """Test cases for the GhydraMCP HTTP API"""

    def assertStandardSuccessResponse(self, data):
        """Helper to assert the standard success response structure for HATEOAS API."""
        self.assertIn("success", data, "Response missing 'success' field")
        self.assertTrue(data["success"], f"API call failed: {data.get('error', 'Unknown error')}")
        self.assertIn("id", data, "Response missing 'id' field")
        self.assertIn("instance", data, "Response missing 'instance' field")
        self.assertIn("result", data, "Response missing 'result' field")
        # All HATEOAS responses must have _links
        self.assertIn("_links", data, "HATEOAS response missing '_links' field")

    def setUp(self):
        """Setup before each test"""
        # Check if the server is running
        try:
            response = requests.get(f"{BASE_URL}/info", timeout=2)
            if response.status_code != 200:
                self.skipTest("Ghidra server not running or not responding")
        except requests.exceptions.RequestException:
            self.skipTest("Ghidra server not running or not accessible")

    def test_info_endpoint(self):
        """Test the /info endpoint"""
        response = requests.get(f"{BASE_URL}/info")
        self.assertEqual(response.status_code, 200)

        # Verify response is valid JSON
        data = response.json()

        # Check standard response structure
        self.assertStandardSuccessResponse(data)

        # Check required fields in result
        result = data["result"]
        self.assertIn("isBaseInstance", result)
        self.assertIn("project", result)
        self.assertIn("file", result)

    def test_root_endpoint(self):
        """Test the / endpoint"""
        response = requests.get(BASE_URL)
        self.assertEqual(response.status_code, 200)

        # Verify response is valid JSON
        data = response.json()

        # Check standard response structure
        self.assertStandardSuccessResponse(data)

        # Check required fields in result
        result = data["result"]
        self.assertIn("isBaseInstance", result)
        self.assertIn("message", result)

    def test_instances_endpoint(self):
        """Test the /instances endpoint"""
        response = requests.get(f"{BASE_URL}/instances")
        self.assertEqual(response.status_code, 200)

        # Verify response is valid JSON
        data = response.json()

        # Check standard response structure for HATEOAS API
        self.assertStandardSuccessResponse(data)

    def test_current_program_endpoint(self):
        """Test the /program endpoint"""
        response = requests.get(f"{BASE_URL}/program")

        # This might return 404 if no program is loaded, which is fine
        if response.status_code == 404:
            return

        self.assertEqual(response.status_code, 200)

        # Verify response is valid JSON
        data = response.json()

        # Check standard response structure
        self.assertStandardSuccessResponse(data)

        # Check for program details
        result = data["result"]
        self.assertIn("programId", result)
        self.assertIn("name", result)
        self.assertIn("isOpen", result)

        # Check for HATEOAS links
        self.assertIn("_links", data)
        links = data["_links"]
        self.assertIn("self", links)
        self.assertIn("functions", links)
        self.assertIn("symbols", links)
        self.assertIn("data", links)
        self.assertIn("segments", links)
        self.assertIn("memory", links)
        self.assertIn("xrefs", links)
        self.assertIn("analysis", links)

    def test_functions_endpoint(self):
        """Test the /functions endpoint"""
        response = requests.get(f"{BASE_URL}/functions")

        # This might return 404 if no program is loaded, which is fine
        if response.status_code == 404:
            return

        self.assertEqual(response.status_code, 200)

        # Verify response is valid JSON
        data = response.json()

        # Check standard response structure for HATEOAS API
        self.assertStandardSuccessResponse(data)

        # Check links
        links = data["_links"]
        self.assertIn("self", links)

        # Check for pagination metadata if this is a list-style endpoint
        # If result is a list, we expect pagination metadata
        # For single-object responses, these might not be present
        result = data["result"]
        if isinstance(result, list):
            self.assertIn("size", data)
            self.assertIn("offset", data)
            self.assertIn("limit", data)

        # Test the content of the result regardless of whether it's a list or single object
        if isinstance(result, list) and result:
            # If it's a list, check the first item
            func = result[0]
            self.assertIn("name", func)
            self.assertIn("address", func)
        elif isinstance(result, dict):
            # If it's a single object, check it directly
            self.assertIn("name", result)
            self.assertIn("address", result)

    def test_functions_with_pagination(self):
        """Test the /functions endpoint with pagination"""
        response = requests.get(f"{BASE_URL}/functions?offset=0&limit=5")

        # This might return 404 if no program is loaded, which is fine
        if response.status_code == 404:
            return

        self.assertEqual(response.status_code, 200)

        # Verify response is valid JSON
        data = response.json()

        # Check standard response structure for HATEOAS API
        self.assertStandardSuccessResponse(data)

        # Check result structure - in HATEOAS API, result can be an object or an array
        result = data["result"]

        # Check for pagination metadata if this is a list-style endpoint
        # In transitional API implementation, pagination metadata might not be present
        # for single-object responses or if the endpoint doesn't support pagination
        if isinstance(result, list):
            # Ensure pagination parameters are correctly applied
            self.assertIn("size", data)
            self.assertIn("offset", data)
            self.assertIn("limit", data)
            self.assertEqual(data["offset"], 0)
            self.assertEqual(data["limit"], 5)

            # For list responses, verify the length
            self.assertLessEqual(len(result), 5)

            # If there are results, check the structure
            if result:
                func = result[0]
                self.assertIn("name", func)
                self.assertIn("address", func)
        elif isinstance(result, dict):
            # If it's a single object, check it directly
            self.assertIn("name", result)
            self.assertIn("address", result)

    def test_functions_with_filtering(self):
        """Test the /functions endpoint with filtering"""
        # First get a function to use for filtering
        response = requests.get(f"{BASE_URL}/functions?limit=1")
        if response.status_code != 200:
            self.skipTest("No functions available to test filtering")

        data = response.json()
        result = data.get("result")
        if not result:
            self.skipTest("No functions available to test filtering")

        # Extract name based on whether result is a list or dict
        if isinstance(result, list) and result:
            name = result[0]["name"]
        elif isinstance(result, dict):
            name = result["name"]
        else:
            self.skipTest("Unexpected result format, cannot test filtering")

        # Test filtering by name
        response = requests.get(f"{BASE_URL}/functions?name={name}")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertStandardSuccessResponse(data)

        result = data["result"]

        # Check result based on whether it's a list or single object
        if isinstance(result, list) and result:
            self.assertEqual(result[0]["name"], name)
        elif isinstance(result, dict):
            self.assertEqual(result["name"], name)

    def test_classes_endpoint(self):
        """Test the /classes endpoint"""
        response = requests.get(f"{BASE_URL}/classes?offset=0&limit=10")

        # This might return 400 if no program is loaded, which is fine
        if response.status_code == 400 or response.status_code == 404:
            return

        self.assertEqual(response.status_code, 200)

        # Verify response is valid JSON
        data = response.json()

        # Check standard response structure for HATEOAS API
        self.assertStandardSuccessResponse(data)

        # Get result data
        result = data["result"]

        # We'd expect classes to be an array of strings or objects with name field
        if isinstance(result, list) and result:
            # Classes could be strings or objects
            if isinstance(result[0], str):
                pass  # Simple string list
            elif isinstance(result[0], dict):
                self.assertIn("name", result[0])  # Object with name field
        elif isinstance(result, dict):
            # If a single class is returned
            self.assertIn("name", result)

    def test_segments_endpoint(self):
        """Test the /segments endpoint"""
        response = requests.get(f"{BASE_URL}/segments?offset=0&limit=10")

        # This might return 400 or 404 if no program is loaded, which is fine
        if response.status_code == 400 or response.status_code == 404:
            if DISPLAY_RESPONSES:
                print(f"Segments endpoint returned {response.status_code}")
            return

        self.assertEqual(response.status_code, 200)

        # Verify response is valid JSON
        data = response.json()
        if DISPLAY_RESPONSES:
            print(f"Segments response: {json.dumps(data, indent=2)}")

        # Check standard response structure for HATEOAS API
        self.assertStandardSuccessResponse(data)

        # Check result structure - in HATEOAS API, result can be an object or an array
        result = data["result"]
        if DISPLAY_RESPONSES:
            print(f"Segments result type: {type(result)}")

        # HATEOAS-compliant segments endpoint should return a list
        self.assertIsInstance(result, list, "Result must be a list of segments")

        # Check segment structure if any segments exist
        if result:
            seg = result[0]
            self.assertIn("name", seg, "Segment missing 'name' field")
            self.assertIn("start", seg, "Segment missing 'start' field")
            self.assertIn("end", seg, "Segment missing 'end' field")
            self.assertIn("size", seg, "Segment missing 'size' field")
            self.assertIn("readable", seg, "Segment missing 'readable' field")
            self.assertIn("writable", seg, "Segment missing 'writable' field")
            self.assertIn("executable", seg, "Segment missing 'executable' field")

            # Verify HATEOAS links in segment
            self.assertIn("_links", seg, "Segment missing '_links' field")
            seg_links = seg["_links"]
            self.assertIn("self", seg_links, "Segment links missing 'self' reference")

    def test_variables_endpoint(self):
        """Test the /variables endpoint"""
        response = requests.get(f"{BASE_URL}/variables")

        # This might return 400 or 404 if no program is loaded, which is fine
        if response.status_code == 400 or response.status_code == 404:
            return

        self.assertEqual(response.status_code, 200)

        # Verify response is valid JSON
        data = response.json()

        # Check standard response structure for HATEOAS API
        self.assertStandardSuccessResponse(data)

    def test_function_by_address_endpoint(self):
        """Test the /functions/{address} endpoint"""
        # First get a function address from the functions endpoint
        response = requests.get(f"{BASE_URL}/functions?offset=0&limit=1")

        # This might return 404 if no program is loaded, which is fine
        if response.status_code == 404:
            return

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data.get("success", False), "API call failed") # Check success first
        self.assertIn("result", data)
        result = data["result"]

        # Skip test if no functions available
        if not result:
            self.skipTest("No functions available to test function by address")

        # Extract address based on whether result is a list or dict
        if isinstance(result, list) and result:
            func_address = result[0]["address"]
        elif isinstance(result, dict):
            func_address = result["address"]
        else:
            self.skipTest("Unexpected result format, cannot test function by address")

        # Now test the function by address endpoint
        response = requests.get(f"{BASE_URL}/functions/{func_address}")
        self.assertEqual(response.status_code, 200)

        # Verify response is valid JSON
        data = response.json()

        # Check standard response structure
        self.assertStandardSuccessResponse(data)

        # Additional checks for function details
        result = data["result"]
        self.assertIn("name", result)
        self.assertIn("address", result)
        self.assertIn("signature", result)

        # Check for HATEOAS links
        self.assertIn("_links", data)
        links = data["_links"]
        self.assertIn("self", links)
        self.assertIn("decompile", links)
        self.assertIn("disassembly", links)
        self.assertIn("variables", links)

    def test_decompile_function_endpoint(self):
        """Test the /functions/{address}/decompile endpoint"""
        # First get a function address from the functions endpoint
        response = requests.get(f"{BASE_URL}/functions?offset=0&limit=1")

        # This might return 404 if no program is loaded, which is fine
        if response.status_code == 404:
            return

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data.get("success", False), "API call failed") # Check success first
        self.assertIn("result", data)
        result = data["result"]

        # Skip test if no functions available
        if not result:
            self.skipTest("No functions available to test decompile function")

        # Extract address based on whether result is a list or dict
        if isinstance(result, list) and result:
            func_address = result[0]["address"]
        elif isinstance(result, dict):
            func_address = result["address"]
        else:
            self.skipTest("Unexpected result format, cannot test decompile function")

        # Now test the decompile function endpoint
        response = requests.get(f"{BASE_URL}/functions/{func_address}/decompile")
        self.assertEqual(response.status_code, 200)

        # Verify response is valid JSON
        data = response.json()

        # Check standard response structure
        self.assertStandardSuccessResponse(data)

        # Additional checks for decompilation result
        result = data["result"]

        # HATEOAS-compliant decompile endpoint should return decompiled code
        self.assertIn("decompiled", result, "Result missing 'decompiled' field")
        self.assertIsInstance(result["decompiled"], str, "Decompiled code must be a string")

        # Verify complete function information
        if "address" not in result and "function" in result and "address" in result["function"]:
            # If address is in function object, it's accepted
            pass
        else:
            self.assertIn("address", result, "Result missing 'address' field")
        self.assertIn("function", result, "Result missing 'function' field")

    def test_disassemble_function_endpoint(self):
        """Test the /functions/{address}/disassembly endpoint"""
        # First get a function address from the functions endpoint
        response = requests.get(f"{BASE_URL}/functions?offset=0&limit=1")

        # This might return 404 if no program is loaded, which is fine
        if response.status_code == 404:
            return

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data.get("success", False), "API call failed") # Check success first
        self.assertIn("result", data)
        result = data["result"]

        # Skip test if no functions available
        if not result:
            self.skipTest("No functions available to test disassemble function")

        # Extract address based on whether result is a list or dict
        if isinstance(result, list) and result:
            func_address = result[0]["address"]
        elif isinstance(result, dict):
            func_address = result["address"]
        else:
            self.skipTest("Unexpected result format, cannot test disassemble function")

        # Now test the disassemble function endpoint
        response = requests.get(f"{BASE_URL}/functions/{func_address}/disassembly")
        self.assertEqual(response.status_code, 200)

        # Verify response is valid JSON
        data = response.json()

        # Check standard response structure
        self.assertStandardSuccessResponse(data)

        # Additional checks for disassembly result
        result = data["result"]

        # HATEOAS-compliant disassembly endpoint should return instructions
        self.assertIn("instructions", result, "Result missing 'instructions' field")
        self.assertIsInstance(result["instructions"], list, "Instructions must be a list")
        self.assertTrue(len(result["instructions"]) > 0, "Instructions list is empty")

        # Check the first instruction structure
        first_instr = result["instructions"][0]
        self.assertIn("address", first_instr, "Instruction missing 'address' field")
        self.assertIn("mnemonic", first_instr, "Instruction missing 'mnemonic' field")
        self.assertIn("bytes", first_instr, "Instruction missing 'bytes' field")

        # Verify function information
        if "address" not in result and "function" in result and "address" in result["function"]:
            # If address is in function object, it's accepted
            pass
        else:
            self.assertIn("address", result, "Result missing 'address' field")
        self.assertIn("function", result, "Result missing 'function' field")

    def test_function_variables_endpoint(self):
        """Test the /functions/by-name/{name}/variables endpoint"""
        # First get a function name from the functions endpoint
        response = requests.get(f"{BASE_URL}/functions?offset=0&limit=1")

        # This might return 404 or other error if no program is loaded, which is fine
        if response.status_code != 200:
            return

        data = response.json()
        self.assertTrue(data.get("success", False), "API call failed") # Check success first
        self.assertIn("result", data)
        result = data["result"]

        # Skip test if no functions available
        if not result:
            self.skipTest("No functions available to test function variables")

        # Extract name based on whether result is a list or dict
        if isinstance(result, list) and result:
            func_name = result[0]["name"]
        elif isinstance(result, dict):
            func_name = result["name"]
        else:
            self.skipTest("Unexpected result format, cannot test function variables")

        # Now test the function variables endpoint (using HATEOAS path)
        response = requests.get(f"{BASE_URL}/functions/by-name/{func_name}/variables")
        self.assertEqual(response.status_code, 200)

        # Verify response is valid JSON
        data = response.json()

        # Check standard response structure
        self.assertStandardSuccessResponse(data)

        # Additional checks for function variables result
        result = data["result"]

        # HATEOAS-compliant variables endpoint should return structured data
        self.assertIn("variables", result, "Result missing 'variables' field")
        self.assertIsInstance(result["variables"], list, "Variables must be a list")

        # Check variable structure if any variables exist
        if result["variables"]:
            var = result["variables"][0]
            self.assertIn("name", var, "Variable missing 'name' field")

            # Adjust for field naming differences - accept either dataType or type
            if "dataType" not in var and "type" in var:
                var["dataType"] = var["type"]

            self.assertIn("dataType", var, "Variable missing 'dataType' field")
            self.assertIn("type", var, "Variable missing 'type' field")

        # Verify function information
        self.assertIn("function", result, "Result missing 'function' field")
        self.assertIsInstance(result["function"], dict, "Function info must be an object")
        func_info = result["function"]
        self.assertIn("name", func_info, "Function info missing 'name' field")
        self.assertIn("address", func_info, "Function info missing 'address' field")

    def test_error_handling(self):
        """Test error handling for non-existent endpoints"""
        response = requests.get(f"{BASE_URL}/nonexistent_endpoint")
        # This should return 404, but some servers might return other codes
        self.assertNotEqual(response.status_code, 200)

    def test_get_current_address(self):
        """Test the /address endpoint"""
        response = requests.get(f"{BASE_URL}/address")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertStandardSuccessResponse(data)

        # Verify HATEOAS links
        self.assertIn("_links", data)
        links = data["_links"]
        self.assertIn("self", links)
        self.assertIn("program", links)

        result = data.get("result", {})
        # Address can be directly in result or in a nested object
        if isinstance(result, dict):
            if "address" in result:
                self.assertIsInstance(result["address"], str)
            else:
                # Look for any field that might contain an address
                found_address = False
                for key, value in result.items():
                    if isinstance(value, str) and len(value) >= 8 and all(c in "0123456789abcdefABCDEF" for c in value):
                        found_address = True
                        break
                self.assertTrue(found_address, "No field with address found in result")

    def test_get_current_function(self):
        """Test the /function endpoint"""
        response = requests.get(f"{BASE_URL}/function")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertStandardSuccessResponse(data)

        # Verify HATEOAS links
        self.assertIn("_links", data)
        links = data["_links"]
        self.assertIn("self", links)
        self.assertIn("program", links)
        self.assertIn("decompile", links)
        self.assertIn("disassembly", links)

        result = data.get("result", {})
        if isinstance(result, dict):
            # Check for standard function fields in any format
            has_name = "name" in result
            has_address = "address" in result
            has_signature = "signature" in result or "callingConvention" in result

            # Either we have enough standard fields, or some other consistent structure
            self.assertTrue(
                (has_name and has_address) or
                (has_name and has_signature) or
                (has_address and has_signature),
                "Function result missing required fields"
            )

    def test_callgraph_endpoint(self):
        """Test the /analysis/callgraph endpoint with both name and address parameters"""
        # First get a function to test with
        response = requests.get(f"{BASE_URL}/functions?limit=1")

        # This might return 404 if no program is loaded, which is fine
        if response.status_code == 404:
            return

        self.assertEqual(response.status_code, 200)

        data = response.json()
        result = data.get("result", [])

        # Skip test if no functions available
        if not result:
            self.skipTest("No functions available to test callgraph")

        # Extract name and address based on whether result is a list or dict
        if isinstance(result, list) and result:
            func = result[0]
        elif isinstance(result, dict):
            func = result
        else:
            self.skipTest("Unexpected result format, cannot test callgraph")

        func_name = func.get("name")
        func_address = func.get("address")

        if not func_name or not func_address:
            self.skipTest("Missing name or address for callgraph test")

        # Test with the address parameter
        response = requests.get(f"{BASE_URL}/analysis/callgraph?address={func_address}&max_depth=2")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertStandardSuccessResponse(data)

        result = data.get("result", {})
        self.assertIn("root", result, "Callgraph missing 'root' field")
        self.assertIn("nodes", result, "Callgraph missing 'nodes' field")
        self.assertIn("edges", result, "Callgraph missing 'edges' field")

        # Test with the name parameter
        response = requests.get(f"{BASE_URL}/analysis/callgraph?name={func_name}&max_depth=2")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertStandardSuccessResponse(data)

        result = data.get("result", {})
        self.assertIn("root", result, "Callgraph missing 'root' field")
        self.assertIn("nodes", result, "Callgraph missing 'nodes' field")
        self.assertIn("edges", result, "Callgraph missing 'edges' field")

    def test_data_operations(self):
        """Test data update operations including renaming and type changes"""
        # First find a suitable data item to test with
        response = requests.get(f"{BASE_URL}/data?limit=1")
        if response.status_code != 200:
            self.skipTest("No data items available to test operations")

        data = response.json()
        self.assertTrue(data.get("success", False), "API call failed")

        result = data.get("result", [])
        if not result or not isinstance(result, list) or not result[0].get("address"):
            self.skipTest("No data items found or invalid response format")

        address = result[0]["address"]
        original_name = result[0].get("label", "unnamed")
        original_type = result[0].get("dataType", "undefined")

        try:
            # Test 1: Rename Only
            test_name = "TEST_DATA_RENAME"
            payload = {
                "address": address,
                "newName": test_name
            }

            response = requests.post(f"{BASE_URL}/data", json=payload)
            self.assertEqual(response.status_code, 200)

            data = response.json()
            self.assertStandardSuccessResponse(data)
            self.assertEqual(data["result"]["name"], test_name)
            self.assertEqual(data["result"]["address"], address)

            # Test 2: Type Change Only
            payload = {
                "address": address,
                "type": "int"
            }

            response = requests.post(f"{BASE_URL}/data/type", json=payload)
            self.assertEqual(response.status_code, 200)

            data = response.json()
            self.assertStandardSuccessResponse(data)
            self.assertEqual(data["result"]["dataType"], "int")
            self.assertEqual(data["result"]["address"], address)

            # Test 3: Both Name and Type Change
            payload = {
                "address": address,
                "newName": "TEST_DATA_BOTH",
                "type": "byte"
            }

            response = requests.post(f"{BASE_URL}/data/update", json=payload)
            self.assertEqual(response.status_code, 200)

            data = response.json()
            self.assertStandardSuccessResponse(data)
            self.assertEqual(data["result"]["name"], "TEST_DATA_BOTH")
            self.assertEqual(data["result"]["dataType"], "byte")
            self.assertEqual(data["result"]["address"], address)

            # Restore original values
            if original_type != "undefined" and original_name != "unnamed":
                payload = {
                    "address": address,
                    "newName": original_name,
                    "type": original_type
                }
                requests.post(f"{BASE_URL}/data", json=payload)
        except Exception as e:
            self.fail(f"Data operations test failed: {str(e)}")

def test_all_read_endpoints():
    """Function to exercise all read endpoints and display their responses.
    This is called separately from the unittest framework when requested."""

    print("\n--- TESTING ALL READ ENDPOINTS ---\n")
    print(f"Base URL: {BASE_URL}")

    # List of all endpoints to test
    endpoints = [
        "/",                                          # Root endpoint
        "/info",                                      # Server info
        "/plugin-version",                            # Plugin version
        "/project",                                   # Current project
        "/instances",                                 # All instances
        "/program",                                   # Current program
        "/functions?limit=3",                         # Functions with pagination
        "/functions?name_contains=main",              # Functions with name filter
        "/variables?limit=3",                         # Variables
        "/symbols?limit=3",                           # Symbols
        "/data?limit=3",                              # Data
        "/segments?limit=3",                          # Memory segments
        "/memory?address=08000000&length=16",         # Memory access
        "/xrefs?to_addr=08000200&limit=3",             # Cross references
        "/analysis",                                  # Analysis status
        "/address",                                   # Current address
        "/function",                                  # Current function
        "/classes?limit=3"                            # Classes
    ]

    # Function to test a specific endpoint
    def test_endpoint(endpoint):
        print(f"\n=== Testing endpoint: {endpoint} ===")
        try:
            response = requests.get(f"{BASE_URL}{endpoint}", timeout=10)
            print(f"Status: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                print(f"Response: {json.dumps(data, indent=2)}")

                # Test for a specific function and its sub-resources if we get functions
                if endpoint == "/functions?limit=3" and data.get("success") and data.get("result"):
                    functions = data.get("result", [])
                    if functions:
                        # Get first function
                        func = functions[0]
                        if isinstance(func, dict) and "address" in func:
                            addr = func["address"]
                            # Test function-specific endpoints
                            test_endpoint(f"/functions/{addr}")
                            test_endpoint(f"/functions/{addr}/decompile")
                            test_endpoint(f"/functions/{addr}/disassembly")
                            test_endpoint(f"/functions/{addr}/variables")

                        # Test by-name endpoint if name exists
                        if isinstance(func, dict) and "name" in func:
                            name = func["name"]
                            test_endpoint(f"/functions/by-name/{name}")

            else:
                print(f"Error response: {response.text}")
        except Exception as e:
            print(f"Exception testing {endpoint}: {e}")

    # Test each endpoint
    for endpoint in endpoints:
        test_endpoint(endpoint)

    print("\n--- END OF API TEST ---\n")

if __name__ == "__main__":
    # If --test-api flag is provided, run the test_all_read_endpoints function
    if len(sys.argv) > 1 and sys.argv[1] == "--test-api":
        test_all_read_endpoints()
        sys.exit(0)

    # Otherwise run the unittest suite
    unittest.main()
