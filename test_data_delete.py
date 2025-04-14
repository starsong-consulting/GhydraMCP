#!/usr/bin/env python3
"""
Test script to verify the delete_data functionality works properly.
"""
import json
import logging
import sys
import requests
import time

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("delete_data_test")

def test_delete_data():
    """Test deleting data."""
    # First create data at a specific address
    test_address = "08000100"  # This should be a valid address in the memory map
    test_type = "byte"
    
    # Step 1: Create some data
    logger.info(f"Creating test data at {test_address}")
    create_url = "http://localhost:8192/data"
    create_payload = {
        "address": test_address,
        "type": test_type, 
        "newName": "TEST_DELETE_ME"
    }
    
    try:
        create_response = requests.post(create_url, json=create_payload)
        logger.info(f"Create response: {create_response.status_code}")
        logger.info(f"Create response: {create_response.text}")
        
        create_success = create_response.status_code == 200 and json.loads(create_response.text).get("success", False)
        
        if not create_success:
            logger.warning("Failed to create test data, test may fail")
    except Exception as e:
        logger.error(f"Error creating test data: {e}")
    
    # Short delay
    time.sleep(1)
    
    # Step 2: Delete the data
    logger.info(f"Deleting data at {test_address}")
    delete_url = "http://localhost:8192/data/delete"
    delete_payload = {
        "address": test_address,
        "action": "delete"
    }
    
    try:
        delete_response = requests.post(delete_url, json=delete_payload)
        logger.info(f"Delete response: {delete_response.status_code}")
        logger.info(f"Delete response: {delete_response.text}")
        
        # Check if successful
        if delete_response.status_code == 200:
            response_data = json.loads(delete_response.text)
            if response_data.get("success", False):
                logger.info("Successfully deleted data!")
                return True
        
        logger.warning("Failed to delete data")
        return False
    except Exception as e:
        logger.error(f"Error deleting data: {e}")
        return False

def main():
    """Main entry point."""
    try:
        result = test_delete_data()
        if result:
            logger.info("Test successful!")
        else:
            logger.error("Test failed")
            sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()