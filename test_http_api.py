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

# Default Ghidra server port
DEFAULT_PORT = 8192

# Get host from environment variable or default to localhost
GHYDRAMCP_TEST_HOST = os.getenv('GHYDRAMCP_TEST_HOST')
if GHYDRAMCP_TEST_HOST and GHYDRAMCP_TEST_HOST.strip():
    BASE_URL = f"http://{GHYDRAMCP_TEST_HOST}:{DEFAULT_PORT}"
else:
    BASE_URL = f"http://localhost:{DEFAULT_PORT}"

class GhydraMCPHttpApiTests(unittest.TestCase):
    """Test cases for the GhydraMCP HTTP API"""

    def assertStandardSuccessResponse(self, data, expected_result_type=None):
        """Helper to assert the standard success response structure."""
        self.assertIn("success", data, "Response missing 'success' field")
        self.assertTrue(data["success"], f"API call failed: {data.get('error', 'Unknown error')}")
        self.assertIn("timestamp", data, "Response missing 'timestamp' field")
        self.assertIsInstance(data["timestamp"], (int, float), "'timestamp' should be a number")
        self.assertIn("port", data, "Response missing 'port' field")
        self.assertEqual(data["port"], DEFAULT_PORT, f"Response port mismatch: expected {DEFAULT_PORT}, got {data['port']}")
        self.assertIn("result", data, "Response missing 'result' field")
        if expected_result_type:
            self.assertIsInstance(data["result"], expected_result_type, f"'result' field type mismatch: expected {expected_result_type}, got {type(data['result'])}")

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
        
        # Check required fields
        self.assertIn("port", data)
        self.assertIn("isBaseInstance", data)
        self.assertIn("project", data)
        self.assertIn("file", data)

    def test_root_endpoint(self):
        """Test the / endpoint"""
        response = requests.get(BASE_URL)
        self.assertEqual(response.status_code, 200)
        
        # Verify response is valid JSON
        data = response.json()
        
        # Check required fields
        self.assertIn("port", data)
        self.assertIn("isBaseInstance", data)
        self.assertIn("project", data)
        self.assertIn("file", data)

    def test_instances_endpoint(self):
        """Test the /instances endpoint"""
        response = requests.get(f"{BASE_URL}/instances")
        self.assertEqual(response.status_code, 200)
        
        # Verify response is valid JSON
        data = response.json()
        
        # Check standard response structure
        self.assertStandardSuccessResponse(data, expected_result_type=list)

    def test_functions_endpoint(self):
        """Test the /functions endpoint"""
        response = requests.get(f"{BASE_URL}/functions")
        self.assertEqual(response.status_code, 200)
        
        # Verify response is valid JSON
        data = response.json()
        
        # Check standard response structure
        self.assertStandardSuccessResponse(data, expected_result_type=list)
        
        # Additional check for function structure if result is not empty
        result = data["result"]
        if result:
            func = result[0]
            self.assertIn("name", func)
            self.assertIn("address", func)

    def test_functions_with_pagination(self):
        """Test the /functions endpoint with pagination"""
        response = requests.get(f"{BASE_URL}/functions?offset=0&limit=5")
        self.assertEqual(response.status_code, 200)
        
        # Verify response is valid JSON
        data = response.json()
        
        # Check standard response structure
        self.assertStandardSuccessResponse(data, expected_result_type=list)
        
        # Additional check for function structure and limit if result is not empty
        result = data["result"]
        self.assertLessEqual(len(result), 5)
        if result:
            func = result[0]
            self.assertIn("name", func)
            self.assertIn("address", func)

    def test_classes_endpoint(self):
        """Test the /classes endpoint"""
        response = requests.get(f"{BASE_URL}/classes?offset=0&limit=10")
        self.assertEqual(response.status_code, 200)
        
        # Verify response is valid JSON
        data = response.json()
        
        # Check standard response structure
        self.assertStandardSuccessResponse(data, expected_result_type=list)
        
        # Additional check for class name type if result is not empty
        result = data["result"]
        if result:
            self.assertIsInstance(result[0], str)

    def test_segments_endpoint(self):
        """Test the /segments endpoint"""
        response = requests.get(f"{BASE_URL}/segments?offset=0&limit=10")
        self.assertEqual(response.status_code, 200)
        
        # Verify response is valid JSON
        data = response.json()
        
        # Check standard response structure
        self.assertStandardSuccessResponse(data, expected_result_type=list)
        
        # Additional check for segment structure if result is not empty
        result = data["result"]
        if result:
            seg = result[0]
            self.assertIn("name", seg)
            self.assertIn("start", seg)
            self.assertIn("end", seg)

    def test_variables_endpoint(self):
        """Test the /variables endpoint"""
        response = requests.get(f"{BASE_URL}/variables")
        self.assertEqual(response.status_code, 200)
        
        # Verify response is valid JSON
        data = response.json()
        
        # Check standard response structure
        self.assertStandardSuccessResponse(data, expected_result_type=list)

    def test_get_function_by_address_endpoint(self):
        """Test the /get_function_by_address endpoint"""
        # First get a function address from the functions endpoint
        response = requests.get(f"{BASE_URL}/functions?offset=0&limit=1")
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertTrue(data.get("success", False), "API call failed") # Check success first
        self.assertIn("result", data)
        result_list = data["result"]
        self.assertIsInstance(result_list, list)
        
        # Skip test if no functions available
        if not result_list:
            self.skipTest("No functions available to test get_function_by_address")
            
        # Get the address of the first function
        func_address = result_list[0]["address"]
        
        # Now test the get_function_by_address endpoint
        response = requests.get(f"{BASE_URL}/get_function_by_address?address={func_address}")
        self.assertEqual(response.status_code, 200)
        
        # Verify response is valid JSON
        data = response.json()
        
        # Check standard response structure
        self.assertStandardSuccessResponse(data, expected_result_type=dict)
        
        # Additional checks for function details
        result = data["result"]
        self.assertIn("name", result)
        self.assertIn("address", result)
        self.assertIn("signature", result)
        self.assertIn("decompilation", result)
        self.assertIsInstance(result["decompilation"], str)

    def test_decompile_function_by_address_endpoint(self):
        """Test the /decompile_function endpoint"""
        # First get a function address from the functions endpoint
        response = requests.get(f"{BASE_URL}/functions?offset=0&limit=1")
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertTrue(data.get("success", False), "API call failed") # Check success first
        self.assertIn("result", data)
        result_list = data["result"]
        self.assertIsInstance(result_list, list)
        
        # Skip test if no functions available
        if not result_list:
            self.skipTest("No functions available to test decompile_function")
            
        # Get the address of the first function
        func_address = result_list[0]["address"]
        
        # Now test the decompile_function endpoint
        response = requests.get(f"{BASE_URL}/decompile_function?address={func_address}")
        self.assertEqual(response.status_code, 200)
        
        # Verify response is valid JSON
        data = response.json()
        
        # Check standard response structure
        self.assertStandardSuccessResponse(data, expected_result_type=dict)
        
        # Additional checks for decompilation result
        result = data["result"]
        self.assertIn("decompilation", result)
        self.assertIsInstance(result["decompilation"], str)
        
    def test_function_variables_endpoint(self):
        """Test the /functions/{name}/variables endpoint"""
        # First get a function name from the functions endpoint
        response = requests.get(f"{BASE_URL}/functions?offset=0&limit=1")
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertTrue(data.get("success", False), "API call failed") # Check success first
        self.assertIn("result", data)
        result_list = data["result"]
        self.assertIsInstance(result_list, list)
        
        # Skip test if no functions available
        if not result_list:
            self.skipTest("No functions available to test function variables")
            
        # Get the name of the first function
        func_name = result_list[0]["name"]
        
        # Now test the function variables endpoint
        response = requests.get(f"{BASE_URL}/functions/{func_name}/variables")
        self.assertEqual(response.status_code, 200)
        
        # Verify response is valid JSON
        data = response.json()
        
        # Check standard response structure
        self.assertStandardSuccessResponse(data, expected_result_type=dict)
        
        # Additional checks for function variables result
        result = data["result"]
        self.assertIn("function", result)
        self.assertIn("variables", result)
        self.assertIsInstance(result["variables"], list)

    def test_error_handling(self):
        """Test error handling for non-existent endpoints"""
        response = requests.get(f"{BASE_URL}/nonexistent_endpoint")
        # This should return 404, but some servers might return other codes
        self.assertNotEqual(response.status_code, 200)

if __name__ == "__main__":
    unittest.main()
