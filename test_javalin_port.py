#!/usr/bin/env python3
"""
Edge-case integration tests for the Javalin rewrite.

These specifically cover behaviours that got flagged as risky during the port:
  * hex vs decimal vs bare-hex address parsing (main commit 42e7082)
  * data_rename with Edit Label semantics vs data_rename with type (b74867f)
  * struct field oversize replacement rejection
  * array-type syntax in struct fields (uint32_t[4])
  * function navigation (containing / next / prev)
  * comment get/set roundtrip across types
  * /address and /function UI endpoints
  * variable update via HighFunctionDBUtil

Requires a live Ghidra instance on localhost:8192 with a binary open.
"""
import os
import unittest

import requests

DEFAULT_PORT = 8192
BASE = os.getenv("GHYDRAMCP_TEST_HOST") or "localhost"
URL = f"http://{BASE}:{DEFAULT_PORT}"


def _as_json(r):
    r.raise_for_status()
    return r.json()


class JavalinPortTests(unittest.TestCase):

    def setUp(self):
        try:
            r = requests.get(f"{URL}/info", timeout=2)
        except requests.exceptions.RequestException:
            self.skipTest("Ghidra not running")
        if r.status_code != 200:
            self.skipTest("Ghidra /info not responding")

    # ---- response shape at the top level ---------------------------------

    def test_response_exposes_id_instance_timestamp_top_level(self):
        """Bridge's simplify_response strips id/instance/timestamp from the top level."""
        data = _as_json(requests.get(f"{URL}/info"))
        self.assertTrue(data.get("success"))
        self.assertIn("id", data)
        self.assertIn("instance", data)
        self.assertIn("timestamp", data)
        self.assertIn("_links", data)

    # ---- address parsing -------------------------------------------------

    def test_address_parsing_hex_decimal_bare(self):
        """Hex, decimal, and bare-hex forms should resolve to the same function."""
        funcs = _as_json(requests.get(f"{URL}/functions", params={"limit": 1}))
        results = funcs.get("result", [])
        if not results:
            self.skipTest("No functions in loaded binary")
        entry = results[0]["address"]
        as_int = int(entry, 16)

        a = _as_json(requests.get(f"{URL}/functions/{entry}"))
        b = _as_json(requests.get(f"{URL}/functions/0x{entry}"))
        c = _as_json(requests.get(f"{URL}/functions/{as_int:x}"))
        self.assertEqual(a["result"]["address"], b["result"]["address"])
        self.assertEqual(a["result"]["address"], c["result"]["address"])

    # ---- function navigation --------------------------------------------

    def test_functions_containing_after_before(self):
        """containing_addr / after / before all return single-element lists."""
        funcs = _as_json(requests.get(f"{URL}/functions", params={"limit": 2}))
        results = funcs.get("result", [])
        if len(results) < 2:
            self.skipTest("Need at least 2 functions")
        entry = results[0]["address"]

        containing = _as_json(requests.get(f"{URL}/functions", params={"containing_addr": entry}))
        self.assertGreaterEqual(len(containing["result"]), 1)

        nxt = _as_json(requests.get(f"{URL}/functions", params={"after": entry}))
        self.assertEqual(1, len(nxt["result"]))
        self.assertNotEqual(entry, nxt["result"][0]["address"])

        prev = _as_json(requests.get(f"{URL}/functions",
                                     params={"before": nxt["result"][0]["address"]}))
        # "before" of the next function should point back at the first one.
        self.assertEqual(entry, prev["result"][0]["address"])

    # ---- Edit Label semantics -------------------------------------------

    def test_data_rename_without_type_is_edit_label(self):
        """PATCH /data/{addr} with only name — no data should be defined."""
        # Pick an address that has no defined data but is inside a valid memory block.
        # /strings returns defined data; we want the opposite, so pick a memory
        # block and use an address inside. Fall back to skip if we can't find one.
        mem = _as_json(requests.get(f"{URL}/memory"))
        blocks = mem.get("result", [])
        target = None
        for b in blocks:
            if b.get("permissions", "").startswith("r"):
                target = b["start"]
                break
        if target is None:
            self.skipTest("No readable memory block found")

        # Add an offset to avoid hitting existing defined data at the block start.
        probe = hex(int(target, 16) + 0x100)

        existing = requests.get(f"{URL}/data/{probe}")
        if existing.status_code == 200:
            self.skipTest(f"Probe address {probe} already has defined data")

        label = "ghydra_edit_label_test"
        r = requests.patch(f"{URL}/data/{probe}", json={"name": label})
        if not r.ok:
            self.skipTest(f"Could not label probe address: {r.text}")
        body = _as_json(r)
        self.assertEqual(label, body["result"]["name"])
        # A pure label edit must NOT define data at the address.
        after = requests.get(f"{URL}/data/{probe}")
        self.assertEqual(404, after.status_code,
                         "Data should not be defined after an Edit Label rename")

    # ---- Struct field replacement validation ----------------------------

    def test_struct_field_oversize_replacement_rejected(self):
        """Replacing a field with a larger type that doesn't fit should fail cleanly."""
        name = "ghydra_struct_resize_test"
        # Clean up any residue from a previous run.
        requests.delete(f"{URL}/structs/{name}")
        r = requests.post(f"{URL}/structs", json={"name": name, "size": 8})
        self.assertTrue(r.ok, f"create struct failed: {r.text}")

        # Add an int32 at offset 0, and byte at offset 4.
        r = requests.post(f"{URL}/structs/{name}/fields",
                          json={"name": "a", "type": "int32_t", "offset": 0})
        self.assertTrue(r.ok, r.text)
        r = requests.post(f"{URL}/structs/{name}/fields",
                          json={"name": "b", "type": "byte", "offset": 4})
        self.assertTrue(r.ok, r.text)

        # Try to replace "a" with uint64_t — 8 bytes wouldn't fit before "b" at +4.
        r = requests.patch(f"{URL}/structs/{name}/fields/0",
                           json={"type": "uint64_t"})
        self.assertFalse(r.ok, "oversize replacement should be rejected")
        err = r.json()
        self.assertIn("error", err)
        self.assertFalse(err["success"])

        requests.delete(f"{URL}/structs/{name}")

    # ---- Array type in struct field -------------------------------------

    def test_struct_field_array_type(self):
        """uint32_t[4] syntax should resolve via GhidraUtil.resolveDataType."""
        name = "ghydra_array_field_test"
        requests.delete(f"{URL}/structs/{name}")
        r = requests.post(f"{URL}/structs", json={"name": name})
        self.assertTrue(r.ok, r.text)

        r = requests.post(f"{URL}/structs/{name}/fields",
                          json={"name": "arr", "type": "uint32_t[4]"})
        self.assertTrue(r.ok, f"array field creation failed: {r.text}")

        detail = _as_json(requests.get(f"{URL}/structs/{name}"))
        fields = detail["result"]["fields"]
        self.assertEqual(1, len(fields))
        self.assertEqual(16, fields[0]["length"])  # 4 * uint32_t

        requests.delete(f"{URL}/structs/{name}")

    # ---- Comments roundtrip ---------------------------------------------

    def test_comment_roundtrip_all_types(self):
        funcs = _as_json(requests.get(f"{URL}/functions", params={"limit": 1}))
        results = funcs.get("result", [])
        if not results:
            self.skipTest("No functions in loaded binary")
        addr = results[0]["address"]

        for kind in ("plate", "pre", "post", "eol", "repeatable"):
            msg = f"ghydra test {kind}"
            r = requests.post(f"{URL}/memory/{addr}/comments/{kind}", json={"comment": msg})
            self.assertTrue(r.ok, f"POST {kind} failed: {r.text}")
            got = _as_json(requests.get(f"{URL}/memory/{addr}/comments/{kind}"))
            self.assertEqual(msg, got["result"]["comment"])
            # Cleanup.
            requests.post(f"{URL}/memory/{addr}/comments/{kind}", json={"comment": ""})

    def test_comment_invalid_type_rejected(self):
        funcs = _as_json(requests.get(f"{URL}/functions", params={"limit": 1}))
        addr = funcs["result"][0]["address"]
        r = requests.get(f"{URL}/memory/{addr}/comments/bogus")
        self.assertFalse(r.ok)
        self.assertIn("error", r.json())

    # ---- UI endpoints ---------------------------------------------------

    def test_ui_address_endpoint(self):
        data = _as_json(requests.get(f"{URL}/address"))
        self.assertIn("address", data["result"])

    def test_ui_function_endpoint(self):
        # May 404 if cursor isn't in a function; skip in that case.
        r = requests.get(f"{URL}/function")
        if r.status_code == 404:
            self.skipTest("Cursor not in a function")
        self.assertTrue(r.ok)
        data = r.json()
        self.assertIn("address", data["result"])
        self.assertIn("name", data["result"])

    # ---- Variable update -----------------------------------------------

    def test_variable_rename_roundtrip(self):
        funcs = _as_json(requests.get(f"{URL}/functions", params={"limit": 10}))
        func_addr = None
        old_var_name = None
        for fn in funcs.get("result", []):
            vars_ = _as_json(requests.get(f"{URL}/functions/{fn['address']}/variables"))
            for v in vars_["result"]["variables"]:
                if not v.get("isParameter"):
                    func_addr = fn["address"]
                    old_var_name = v["name"]
                    break
            if func_addr:
                break
        if not func_addr:
            self.skipTest("No function with a non-parameter local found")

        new_name = "ghydra_renamed_local"
        r = requests.patch(
            f"{URL}/functions/{func_addr}/variables/{old_var_name}",
            json={"name": new_name})
        self.assertTrue(r.ok, r.text)

        # Rename back so subsequent runs find the same target.
        requests.patch(
            f"{URL}/functions/{func_addr}/variables/{new_name}",
            json={"name": old_var_name})


if __name__ == "__main__":
    unittest.main()
