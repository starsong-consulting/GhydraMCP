"""Offline characterization tests for the bridge's pure helper functions.

These cover logic that previously was only exercised end-to-end against a live
Ghidra instance: port resolution, origin validation, timeout extraction, the
list-total heuristic, error formatting, and HATEOAS response simplification.
"""

import bridge_mcp_hydra as b


# ---- _get_instance_port ---------------------------------------------------

def test_get_instance_port_returns_known_active_port():
    b.active_instances[8192] = {"url": "http://localhost:8192"}
    try:
        assert b._get_instance_port(8192) == 8192
    finally:
        b.active_instances.pop(8192, None)


def test_get_instance_port_defaults_to_current_when_none():
    b.active_instances[b.current_instance_port] = {"url": "http://x"}
    try:
        assert b._get_instance_port(None) == b.current_instance_port
    finally:
        b.active_instances.pop(b.current_instance_port, None)


def test_get_instance_port_raises_when_unregisterable(monkeypatch):
    # register_instance is a no-op (simulating a port with no live server)
    monkeypatch.setattr(b, "register_instance", lambda port, url=None: None)
    b.active_instances.pop(9999, None)
    try:
        import pytest
        with pytest.raises(ValueError, match="No active Ghidra instance"):
            b._get_instance_port(9999)
    finally:
        b.active_instances.pop(9999, None)


# ---- validate_origin ------------------------------------------------------

def test_validate_origin_allows_missing_origin():
    assert b.validate_origin({}) is True


def test_validate_origin_allows_listed_origin():
    assert b.validate_origin({"Origin": "http://localhost"}) is True


def test_validate_origin_rejects_unlisted_origin():
    assert b.validate_origin({"Origin": "http://evil.example"}) is False


def test_validate_origin_rejects_listed_host_with_port():
    # default allowlist is "http://localhost" (no port), so a port differs
    assert b.validate_origin({"Origin": "http://localhost:31337"}) is False


# ---- _extract_requested_decompile_timeout ---------------------------------

def test_extract_timeout_default_when_absent():
    assert b._extract_requested_decompile_timeout(None) == b.DEFAULT_DECOMPILATION_TIMEOUT
    assert b._extract_requested_decompile_timeout({}) == b.DEFAULT_DECOMPILATION_TIMEOUT


def test_extract_timeout_reads_int():
    assert b._extract_requested_decompile_timeout({"timeout": 321}) == 321


def test_extract_timeout_coerces_numeric_string():
    assert b._extract_requested_decompile_timeout({"timeout": "120"}) == 120


def test_extract_timeout_falls_back_on_garbage():
    assert b._extract_requested_decompile_timeout({"timeout": "abc"}) == b.DEFAULT_DECOMPILATION_TIMEOUT


# ---- _list_total ----------------------------------------------------------

def test_list_total_prefers_meta_total():
    assert b._list_total({"meta": {"total": 99}}, [1, 2]) == 99


def test_list_total_uses_meta_total_estimate():
    assert b._list_total({"meta": {"total_estimate": 50}}, [1]) == 50


def test_list_total_falls_back_to_top_level_size():
    assert b._list_total({"size": 7}, [1, 2]) == 7


def test_list_total_falls_back_to_page_length():
    assert b._list_total({}, [1, 2, 3]) == 3


# ---- format_error ---------------------------------------------------------

def test_format_error_dict_message():
    assert b.format_error({"error": {"message": "boom"}}) == "Error: boom"


def test_format_error_string():
    assert b.format_error({"error": "nope"}) == "Error: nope"


def test_format_error_unknown():
    assert b.format_error({}) == "Error: Unknown error"


# ---- simplify_response ----------------------------------------------------

def test_simplify_strips_links_from_list_items_and_exposes_url():
    resp = {
        "success": True,
        "result": [
            {"name": "f", "_links": {"self": {"href": "/functions/f"}}},
        ],
    }
    out = b.simplify_response(resp)
    item = out["result"][0]
    assert "_links" not in item
    assert item["self_url"] == "/functions/f"


def test_simplify_promotes_top_level_links_to_api_links():
    resp = {"success": True, "_links": {"next": {"href": "/x?offset=10"}}}
    out = b.simplify_response(resp)
    assert "_links" not in out
    assert out["api_links"] == {"next": "/x?offset=10"}


def test_simplify_converts_instructions_to_disassembly_text():
    resp = {
        "success": True,
        "result": {
            "instructions": [
                {"address": "0x1000", "mnemonic": "mov", "operands": "eax, 1", "bytes": "b801000000"},
            ],
        },
    }
    out = b.simplify_response(resp)
    assert "instructions" not in out["result"]
    assert "0x1000" in out["result"]["disassembly_text"]
    assert "mov eax, 1" in out["result"]["disassembly_text"]


def test_simplify_exposes_decompilation_as_decompiled_text():
    resp = {"success": True, "result": {"decompilation": "int main(){}"}}
    out = b.simplify_response(resp)
    assert out["result"]["decompiled_text"] == "int main(){}"


def test_simplify_passes_through_non_dict():
    assert b.simplify_response("not a dict") == "not a dict"
