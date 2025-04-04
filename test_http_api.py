#!/usr/bin/env python3
"""
Test script for the GhydraMCP HTTP API.
This script tests the HTTP endpoints of the Java plugin.
"""
import json
import requests
import time
import unittest

# Default Ghidra server port
DEFAULT_PORT = 8192
BASE_URL = f"http://localhost:{DEFAULT_PORT}"

class GhydraMCPHttpApiTests(unittest.TestCase):
    """Test cases for the GhydraMCP HTTP API"""

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
        
        # Check required fields in the standard response format
        self.assertIn("success", data)
        self.assertTrue(data["success"])
        self.assertIn("timestamp", data)
        self.assertIn("port", data)
        
        # Check that we have either result or data
        self.assertTrue("result" in data or "data" in data)

    def test_functions_endpoint(self):
        """Test the /functions endpoint"""
        response = requests.get(f"{BASE_URL}/functions")
        self.assertEqual(response.status_code, 200)
        
        # Verify response is valid JSON
        data = response.json()
        
        # Check required fields in the standard response format
        self.assertIn("success", data)
        self.assertTrue(data["success"])
        self.assertIn("timestamp", data)
        self.assertIn("port", data)
        
        # Check that we have either result or data
        self.assertTrue("result" in data or "data" in data)

    def test_functions_with_pagination(self):
        """Test the /functions endpoint with pagination"""
        response = requests.get(f"{BASE_URL}/functions?offset=0&limit=5")
        self.assertEqual(response.status_code, 200)
        
        # Verify response is valid JSON
        data = response.json()
        
        # Check required fields in the standard response format
        self.assertIn("success", data)
        self.assertTrue(data["success"])
        self.assertIn("timestamp", data)
        self.assertIn("port", data)

    def test_classes_endpoint(self):
        """Test the /classes endpoint"""
        response = requests.get(f"{BASE_URL}/classes")
        self.assertEqual(response.status_code, 200)
        
        # Verify response is valid JSON
        data = response.json()
        
        # Check required fields in the standard response format
        self.assertIn("success", data)
        self.assertTrue(data["success"])
        self.assertIn("timestamp", data)
        self.assertIn("port", data)

    def test_segments_endpoint(self):
        """Test the /segments endpoint"""
        response = requests.get(f"{BASE_URL}/segments")
        self.assertEqual(response.status_code, 200)
        
        # Verify response is valid JSON
        data = response.json()
        
        # Check required fields in the standard response format
        self.assertIn("success", data)
        self.assertTrue(data["success"])
        self.assertIn("timestamp", data)
        self.assertIn("port", data)

    def test_variables_endpoint(self):
        """Test the /variables endpoint"""
        response = requests.get(f"{BASE_URL}/variables")
        self.assertEqual(response.status_code, 200)
        
        # Verify response is valid JSON
        data = response.json()
        
        # Check required fields in the standard response format
        self.assertIn("success", data)
        self.assertTrue(data["success"])
        self.assertIn("timestamp", data)
        self.assertIn("port", data)

    def test_error_handling(self):
        """Test error handling for non-existent endpoints"""
        response = requests.get(f"{BASE_URL}/nonexistent_endpoint")
        # This should return 404, but some servers might return other codes
        self.assertNotEqual(response.status_code, 200)

if __name__ == "__main__":
    unittest.main()
