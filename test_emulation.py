#!/usr/bin/env python3
"""Integration smoke tests for the /emulation endpoints.

Requires a live Ghidra instance on localhost:8192 with a binary open.
"""
import os
import unittest

import requests

DEFAULT_PORT = int(os.getenv("GHYDRAMCP_TEST_PORT") or "8192")
BASE = os.getenv("GHYDRAMCP_TEST_HOST") or "localhost"
URL = f"http://{BASE}:{DEFAULT_PORT}"


def _json(r):
    r.raise_for_status()
    return r.json()


class EmulationTests(unittest.TestCase):
    def setUp(self):
        try:
            r = requests.get(f"{URL}/info", timeout=2)
        except requests.exceptions.RequestException:
            self.skipTest("Ghidra not running")
        if r.status_code != 200:
            self.skipTest("Ghidra /info not responding")
        funcs = _json(requests.get(f"{URL}/functions", params={"limit": 1}))
        results = funcs.get("result", [])
        if not results:
            self.skipTest("No functions in loaded binary")
        self.entry = results[0]["address"]

    def test_reset_run_state_roundtrip(self):
        reset = _json(requests.post(f"{URL}/emulation/reset", json={"start": self.entry}))
        self.assertTrue(reset.get("success"))
        self.assertIsNotNone(reset["result"]["pc"])

        run = _json(requests.post(f"{URL}/emulation/run",
                                  json={"max_steps": 50, "trace": True}))
        self.assertTrue(run.get("success"))
        self.assertGreater(run["result"]["steps"], 0)
        self.assertIn(run["result"]["stopReason"],
                      {"TARGET_REACHED", "BREAKPOINT", "ERROR", "MAX_STEPS", "STEPPED"})
        self.assertIsInstance(run["result"]["trace"], list)

    def test_register_read_write(self):
        _json(requests.post(f"{URL}/emulation/reset", json={"start": self.entry}))
        _json(requests.post(f"{URL}/emulation/registers",
                            json={"name": "RAX", "value": "0xdeadbeef"}))
        reg = _json(requests.get(f"{URL}/emulation/registers/RAX"))
        self.assertEqual("0xdeadbeef", reg["result"]["value"])

    def test_memory_write_read(self):
        _json(requests.post(f"{URL}/emulation/reset", json={"start": self.entry}))
        _json(requests.post(f"{URL}/emulation/memory",
                            json={"address": self.entry, "hex": "9090"}))
        mem = _json(requests.get(f"{URL}/emulation/memory/{self.entry}", params={"length": 2}))
        self.assertEqual("9090", mem["result"]["hex"])

    def test_missing_session_is_404(self):
        requests.delete(f"{URL}/emulation")
        r = requests.get(f"{URL}/emulation/state")
        self.assertIn(r.status_code, (404, 503))

    def tearDown(self):
        try:
            requests.delete(f"{URL}/emulation", timeout=2)
        except requests.exceptions.RequestException:
            pass


if __name__ == "__main__":
    unittest.main()
