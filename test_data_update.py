#!/usr/bin/env python3
"""
Dedicated test script for the GhydraMCP data handling API.

This script has standalone tests to validate the three key data manipulation operations:
1. Rename only - Change the name without changing the data type
2. Type change only - Change the data type while preserving the name
3. Update both - Change both name and type simultaneously

These tests operate on a low level and can be run independently of the main test suite
to diagnose issues with the API's data handling capabilities.

Usage:
    python test_data_update.py
"""
import json
import requests
import sys
import argparse

BASE_URL = "http://localhost:8192"

def test_data_update(verbose=True, base_url=None):
    """Test data update operations
    
    Args:
        verbose: Whether to print detailed output
        base_url: Base URL for the Ghidra HTTP API (default: http://localhost:8192)
    
    Returns:
        bool: True if all tests pass, False otherwise
    """
    if base_url:
        global BASE_URL
        BASE_URL = base_url
        
    # Track test results
    all_tests_passed = True
    
    # First find a suitable data item to test with
    if verbose:
        print("Fetching data items...")
    response = requests.get(f"{BASE_URL}/data?limit=1")
    
    if response.status_code != 200:
        print(f"Error: Failed to fetch data items, status {response.status_code}")
        print(response.text)
        return False

    data = response.json()
    if not data.get("success"):
        print(f"Error: API call failed: {data.get('error', 'Unknown error')}")
        return False

    # Extract address from first data item
    result = data.get("result", [])
    if not result or not isinstance(result, list) or not result[0].get("address"):
        print("Error: No data items found or invalid response format")
        if result and verbose:
            print(f"Result: {json.dumps(result, indent=2)}")
        return False

    address = result[0]["address"]
    if verbose:
        print(f"Using data item at address: {address}")

    # Test 1: Renaming only
    if verbose:
        print("\n--- Test 1: Rename Only ---")
    test_name = "TEST_DATA_RENAME"
    payload = {
        "address": address,
        "newName": test_name
    }

    if verbose:
        print(f"Request: POST {BASE_URL}/data")
        print(f"Payload: {json.dumps(payload, indent=2)}")
    
    response = requests.post(f"{BASE_URL}/data", json=payload)
    if verbose:
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    
    # Check Test 1 results
    test1_passed = response.status_code == 200 and response.json().get("success")
    if not test1_passed:
        print(f"ERROR: Test 1 (Rename Only) failed: {response.status_code}")
        all_tests_passed = False

    # Test 2: Type change only
    if verbose:
        print("\n--- Test 2: Type Change Only ---")
    payload = {
        "address": address,
        "type": "int"  # Using 'type' as parameter name
    }

    if verbose:
        print(f"Request: POST {BASE_URL}/data/type")
        print(f"Payload: {json.dumps(payload, indent=2)}")
    
    response = requests.post(f"{BASE_URL}/data/type", json=payload)
    if verbose:
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    
    # Check Test 2 results
    test2_passed = response.status_code == 200 and response.json().get("success")
    if not test2_passed:
        print(f"ERROR: Test 2 (Type Change Only) failed: {response.status_code}")
        all_tests_passed = False

    # Test 3: Both name and type change
    if verbose:
        print("\n--- Test 3: Both Name and Type Change ---")
    payload = {
        "address": address,
        "newName": "TEST_DATA_BOTH",
        "type": "byte"  # Using 'type' as parameter name
    }

    if verbose:
        print(f"Request: POST {BASE_URL}/data/update")
        print(f"Payload: {json.dumps(payload, indent=2)}")
    
    response = requests.post(f"{BASE_URL}/data/update", json=payload)
    if verbose:
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    
    # Check Test 3 results
    test3_passed = response.status_code == 200 and response.json().get("success")
    if not test3_passed:
        print(f"ERROR: Test 3 (Both Name and Type Change via /data/update) failed: {response.status_code}")
        all_tests_passed = False

    # Test 4: Direct raw request using the /data endpoint
    if verbose:
        print("\n--- Test 4: Direct Request to /data endpoint ---")
    payload = {
        "address": address,
        "newName": "TEST_DIRECT_UPDATE",
        "type": "int"  # Using 'type' parameter name
    }

    if verbose:
        print(f"Request: POST {BASE_URL}/data")
        print(f"Payload: {json.dumps(payload, indent=2)}")
    
    response = requests.post(f"{BASE_URL}/data", json=payload)
    if verbose:
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    
    # Check Test 4 results
    test4_passed = response.status_code == 200 and response.json().get("success")
    if not test4_passed:
        print(f"ERROR: Test 4 (Both Name and Type Change via /data) failed: {response.status_code}")
        all_tests_passed = False
    
    # Print summary
    if verbose:
        print("\n--- Test Summary ---")
        print(f"Test 1 (Rename Only): {'PASSED' if test1_passed else 'FAILED'}")
        print(f"Test 2 (Type Change Only): {'PASSED' if test2_passed else 'FAILED'}")
        print(f"Test 3 (Both Name and Type Change via /data/update): {'PASSED' if test3_passed else 'FAILED'}")
        print(f"Test 4 (Both Name and Type Change via /data): {'PASSED' if test4_passed else 'FAILED'}")
        print(f"Overall: {'ALL TESTS PASSED' if all_tests_passed else 'SOME TESTS FAILED'}")
    
    return all_tests_passed

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test data operations in the GhydraMCP HTTP API")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress detailed output")
    parser.add_argument("--url", "-u", help="Base URL for the Ghidra HTTP API")
    args = parser.parse_args()
    
    success = test_data_update(not args.quiet, args.url)
    if not success:
        sys.exit(1)