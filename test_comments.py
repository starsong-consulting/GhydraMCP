#!/usr/bin/env python3
"""
Test script for the comment functionality in GhydraMCP.

Tests both HTTP API and MCP bridge interfaces for setting and retrieving
different types of comments in Ghidra, including plate, pre, post, EOL,
repeatable, and decompiler comments.
"""
import json
import logging
import sys
import time
from urllib.parse import quote

import anyio
import requests
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("comment_test")

def test_http_api_comments(port=8192, address="08000200"):
    """
    Test setting and retrieving comments using direct HTTP API.

    Args:
        port: Ghidra HTTP API port
        address: Memory address for comments
    """
    logger.info("===== Testing HTTP API Comments =====")
    base_url = f"http://localhost:{port}"

    comment_types = ["plate", "pre", "post", "eol", "repeatable"]

    for comment_type in comment_types:
        comment_text = f"TEST {comment_type.upper()} COMMENT {int(time.time())}"
        logger.info(f"Setting {comment_type} comment: {comment_text}")

        url = f"{base_url}/memory/{address}/comments/{comment_type}"
        payload = {"comment": comment_text}

        try:
            r = requests.post(url, json=payload, timeout=10)
            logger.info(f"Status code: {r.status_code}")
            logger.info(f"Response: {r.text}")

            if r.status_code == 200:
                r_get = requests.get(url, timeout=10)
                logger.info(f"GET Status code: {r_get.status_code}")
                logger.info(f"GET Response: {r_get.text}")
        except Exception as e:
            logger.error(f"Error setting {comment_type} comment: {e}")

async def test_bridge_comments():
    """
    Test MCP bridge comment functionality.

    Sets and clears both plate comments and decompiler comments using the
    MCP bridge interface.
    """
    logger.info("===== Testing MCP Bridge Comments =====")

    server_parameters = StdioServerParameters(
        command=sys.executable,
        args=["bridge_mcp_hydra.py"],
    )

    logger.info("Connecting to bridge...")
    async with stdio_client(server_parameters) as (read_stream, write_stream):
        logger.info("Creating session...")
        async with ClientSession(read_stream, write_stream) as session:
            logger.info("Initializing session...")
            await session.initialize()

            # First set the current instance
            logger.info("Setting current Ghidra instance...")
            await session.call_tool(
                "instances_use",
                arguments={"port": 8192}
            )

            logger.info("Getting current address...")
            addr_result = await session.call_tool("ui_get_current_address")
            addr_data = json.loads(addr_result.content[0].text)

            if not addr_data.get("success", False):
                logger.error("Failed to get current address")
                return

            address = addr_data.get("result", {}).get("address", "08000200")
            logger.info(f"Using address: {address}")

            logger.info("Testing comments_set with plate type...")
            comment_text = f"MCP PLATE COMMENT {int(time.time())}"
            result = await session.call_tool("comments_set",
                                           arguments={"address": address,
                                                     "comment": comment_text,
                                                     "comment_type": "plate"})
            logger.info(f"comments_set result: {result}")

            logger.info("Testing functions_set_comment...")
            decompiler_comment = f"MCP DECOMPILER COMMENT {int(time.time())}"
            decompile_result = await session.call_tool("functions_set_comment",
                                                     arguments={"address": address,
                                                              "comment": decompiler_comment})
            logger.info(f"functions_set_comment result: {decompile_result}")

            await anyio.sleep(5)

            logger.info("Clearing comments...")
            await session.call_tool("comments_set",
                                  arguments={"address": address,
                                           "comment": "",
                                           "comment_type": "plate"})

            await session.call_tool("functions_set_comment",
                                  arguments={"address": address,
                                           "comment": ""})

def main():
    """
    Main entry point for comment tests.

    Runs both HTTP API and MCP bridge tests sequentially.
    """
    try:
        test_http_api_comments()
        anyio.run(test_bridge_comments)
        logger.info("All comment tests completed successfully")
        return True
    except Exception as e:
        logger.error(f"Error in comment tests: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
