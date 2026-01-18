#!/usr/bin/env python3
"""
Test runner for GhydraMCP tests.
This script runs both the HTTP API tests and the MCP bridge tests.
"""
import os
import subprocess
import sys
import unittest
import time

def print_header(text):
    """Print a header with the given text"""
    print("\n" + "=" * 80)
    print(f" {text} ".center(80, "="))
    print("=" * 80 + "\n")

def run_http_api_tests():
    """Run the HTTP API tests"""
    print_header("Running HTTP API Tests")

    # Import and run the tests
    try:
        from test_http_api import GhydraMCPHttpApiTests

        # Create a test suite with all tests from GhydraMCPHttpApiTests
        suite = unittest.TestLoader().loadTestsFromTestCase(GhydraMCPHttpApiTests)

        # Run the tests
        result = unittest.TextTestRunner(verbosity=2).run(suite)

        return result.wasSuccessful()
    except ImportError:
        print("Error: Could not import test_http_api.py")
        return False
    except Exception as e:
        print(f"Error running HTTP API tests: {str(e)}")
        return False

def run_mcp_bridge_tests():
    """Run the MCP bridge tests using the MCP client"""
    print_header("Running MCP Bridge Tests")

    try:
        # Run the MCP client test script
        import subprocess
        import sys

        print("Running MCP client test script...")
        result = subprocess.run(
            [sys.executable, "test_mcp_client.py"],
            capture_output=True,
            text=True
        )

        # Print the output
        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        # Return True if the process exited with code 0
        return result.returncode == 0
    except Exception as e:
        print(f"Error running MCP bridge tests: {str(e)}")
        return False

def run_data_tests():
    """Run the data operations tests."""
    print_header("Running Data Operations Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_data_operations.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running data operations tests: {str(e)}")
        return False

def run_comment_tests():
    """Run the comment functionality tests."""
    print_header("Running Comment Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_comments.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running comment tests: {str(e)}")
        return False

def run_all_tests():
    """Run all tests"""
    print_header("GhydraMCP Test Suite")

    # Run test suites
    http_api_success = run_http_api_tests()
    mcp_bridge_success = run_mcp_bridge_tests()
    data_tests_success = run_data_tests()
    comment_tests_success = run_comment_tests()

    # Print a summary
    print_header("Test Summary")
    print(f"HTTP API Tests: {'PASSED' if http_api_success else 'FAILED'}")
    print(f"MCP Bridge Tests: {'PASSED' if mcp_bridge_success else 'FAILED'}")
    print(f"Data Operations Tests: {'PASSED' if data_tests_success else 'FAILED'}")
    print(f"Comment Tests: {'PASSED' if comment_tests_success else 'FAILED'}")
    print(f"Overall: {'PASSED' if (http_api_success and mcp_bridge_success and data_tests_success and comment_tests_success) else 'FAILED'}")

    return http_api_success and mcp_bridge_success and data_tests_success and comment_tests_success

if __name__ == "__main__":
    # Check if we have the required dependencies
    try:
        import requests
    except ImportError:
        print("Error: The 'requests' package is required to run the tests.")
        print("Please install it with 'pip install requests'")
        sys.exit(1)

    # Parse command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--http":
            # Run only the HTTP API tests
            success = run_http_api_tests()
        elif sys.argv[1] == "--mcp":
            # Run only the MCP bridge tests
            success = run_mcp_bridge_tests()
        elif sys.argv[1] == "--data":
            # Run only the data operations tests
            success = run_data_tests()
        elif sys.argv[1] == "--comments":
            # Run only the comment tests
            success = run_comment_tests()
        else:
            print(f"Unknown argument: {sys.argv[1]}")
            print("Usage: python run_tests.py [--http|--mcp|--data|--comments]")
            sys.exit(1)
    else:
        # Run all tests
        success = run_all_tests()

    # Exit with the appropriate status code
    sys.exit(0 if success else 1)
