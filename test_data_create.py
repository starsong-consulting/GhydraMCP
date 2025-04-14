#!/usr/bin/env python3
"""
Test script to verify the create_data function works properly.
"""
import json
import logging
import sys
import requests
import time

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("create_data_test")

def wait_for_program_loaded():
    """Wait for a Ghidra program to be loaded."""
    for _ in range(10):  # Try for ~20 seconds
        try:
            response = requests.get("http://localhost:8192/program")
            if response.status_code == 200:
                data = json.loads(response.text)
                if data.get("success", False):
                    logger.info("Program loaded: " + data["result"]["name"])
                    return True
        except Exception as e:
            logger.warning(f"Error checking program status: {e}")
        
        logger.info("Waiting for program to load...")
        time.sleep(2)
    
    logger.error("Timed out waiting for program to load")
    return False

def test_create_data():
    """Test creating data at different addresses with different types."""
    # First wait for a program to be loaded
    if not wait_for_program_loaded():
        logger.error("No program loaded, cannot test create_data")
        return False
        
    # First get the memory map to find addresses where we can create data
    try:
        response = requests.get("http://localhost:8192/memory")
        memory_info = json.loads(response.text)
        
        # Get valid addresses from an existing memory region
        memory_blocks = memory_info.get("result", [])
        
        # Find a valid memory block
        valid_addresses = []
        for block in memory_blocks:
            if "start" in block and "name" in block:
                # Get starting address of a RAM block
                if "RAM" in block["name"].upper():
                    # Use the first 10 bytes of this RAM block
                    addr_base = int(block["start"], 16)
                    for i in range(10):
                        valid_addresses.append(f"{addr_base + i:08x}")
                    break
        
        # If no RAM blocks, try any memory block
        if not valid_addresses:
            for block in memory_blocks:
                if "start" in block:
                    # Use the first 10 bytes of this block
                    addr_base = int(block["start"], 16)
                    for i in range(10):
                        valid_addresses.append(f"{addr_base + i:08x}")
                    break
        
        # Fallback to known addresses if still nothing
        if not valid_addresses:
            valid_addresses = ["08000100", "08000104", "08000108", "0800010c", 
                              "08000110", "08000114", "08000118", "0800011c"]
        
        logger.info(f"Will try using addresses: {valid_addresses[:3]}...")
        addresses = valid_addresses
    except Exception as e:
        logger.error(f"Error getting memory map: {e}")
        # Fallback to some addresses that might be valid
        addresses = ["08000100", "08000104", "08000108", "0800010c", 
                    "08000110", "08000114", "08000118", "0800011c"]
    
    # Try data types
    types_to_try = ["uint32_t", "int", "float", "byte", "char", "word", "dword", "string"]
    
    success_count = 0
    
    for i, data_type in enumerate(types_to_try):
        address = addresses[i % len(addresses)]
        logger.info(f"Testing data type: {data_type} at address {address}")
        
        # First try direct HTTP API
        url = f"http://localhost:8192/data"
        payload = {
            "address": address,
            "type": data_type,
            "newName": f"TEST_{data_type.upper()}"
        }
        
        # Add size for string types
        if data_type.lower() == "string":
            payload["size"] = 16
        
        try:
            response = requests.post(url, json=payload)
            logger.info(f"HTTP API - Status: {response.status_code}")
            logger.info(f"HTTP API - Response: {response.text}")
            if response.status_code == 200 and json.loads(response.text).get("success", False):
                success_count += 1
                logger.info(f"HTTP API - Success with data type {data_type}")
            else:
                logger.warning(f"HTTP API - Failed with data type {data_type}")
        except Exception as e:
            logger.error(f"HTTP API - Error: {e}")
        
        # Short delay between tests
        time.sleep(0.5)
    
    return success_count > 0

def main():
    try:
        result = test_create_data()
        if result:
            logger.info("Test successful!")
        else:
            logger.error("All test data types failed")
            sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()