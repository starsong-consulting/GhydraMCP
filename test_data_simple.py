#!/usr/bin/env python3
"""
Direct test for data operations.
"""
import json
import logging
import sys
import requests

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("simple_test")

def test_create_data():
    address = "08000000"
    
    # Try data types
    types_to_try = ["uint32_t", "int", "dword", "byte", "pointer"]
    
    for data_type in types_to_try:
        logger.info(f"Testing data type: {data_type}")
        
        url = f"http://localhost:8192/data"
        payload = {
            "address": address,
            "type": data_type,
            "newName": f"TEST_{data_type.upper()}"  # Include a name for the data
        }
        
        try:
            response = requests.post(url, json=payload)
            logger.info(f"Status: {response.status_code}")
            logger.info(f"Response: {response.text}")
            if response.status_code == 200:
                logger.info(f"Success with data type {data_type}")
                return True
        except Exception as e:
            logger.error(f"Error: {e}")
    
    return False

def main():
    try:
        result = test_create_data()
        if result:
            logger.info("Test successful!")
        else:
            logger.error("All test data types failed")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()