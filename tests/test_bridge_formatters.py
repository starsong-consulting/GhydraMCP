"""Offline tests for the bridge's plain-text formatters.

The formatters turn a HATEOAS API response dict into LLM-friendly text. They are
pure functions, so they are fully testable without a live Ghidra instance even
though in practice they only ever run on real API responses.
"""

import bridge_mcp_hydra as b


# ---- error passthrough (shared by every formatter) ------------------------

def test_formatters_passthrough_errors():
    err = {"success": False, "error": {"message": "kaboom"}}
    assert b.format_functions_list(err) == "Error: kaboom"
    assert b.format_decompile(err) == "Error: kaboom"
    assert b.format_disassembly(err) == "Error: kaboom"
    assert b.format_strings(err) == "Error: kaboom"
    assert b.format_data_list(err) == "Error: kaboom"


# ---- format_functions_list ------------------------------------------------

def test_functions_list_renders_rows_and_header():
    resp = {"success": True, "meta": {"total": 2},
            "result": [{"name": "main", "address": "0x1000", "signature": "int main(void)"},
                       {"name": "foo", "address": "0x2000", "signature": "void foo()"}]}
    out = b.format_functions_list(resp, offset=0, limit=100)
    assert "Functions (1-2 of 2):" in out
    assert "0x1000" in out and "main" in out
    assert "int main(void)" in out


def test_functions_list_shows_more_hint_when_paginated():
    resp = {"success": True, "meta": {"total": 250},
            "result": [{"name": "f", "address": "0x10", "signature": ""}]}
    out = b.format_functions_list(resp, offset=0, limit=100)
    assert "more (use offset=100)" in out


def test_functions_list_truncates_long_signature():
    long_sig = "int reallylong(" + ", ".join("int a%d" % i for i in range(20)) + ")"
    resp = {"success": True, "result": [{"name": "f", "address": "0x10", "signature": long_sig}]}
    out = b.format_functions_list(resp)
    assert "..." in out


# ---- format_decompile -----------------------------------------------------

def test_decompile_returns_code():
    resp = {"success": True, "result": {"decompilation": "int main(){return 0;}"}}
    assert b.format_decompile(resp) == "int main(){return 0;}"


def test_decompile_legacy_ccode_field():
    resp = {"success": True, "result": {"ccode": "void f(){}"}}
    assert b.format_decompile(resp) == "void f(){}"


def test_decompile_empty_is_error():
    resp = {"success": True, "result": {}}
    assert b.format_decompile(resp) == "Error: No decompiled code returned"


def test_decompile_dto_level_failure():
    resp = {"success": True, "result": {"success": False, "errorMessage": "timeout"}}
    assert "Decompilation failed: timeout" in b.format_decompile(resp)


def test_decompile_appends_retry_advisory():
    resp = {"success": True, "result": {
        "decompilation": "int main(){}",
        "retry_recommended": True,
        "message": "partial decompile",
        "suggested_timeout_seconds": 600,
    }}
    out = b.format_decompile(resp)
    assert "int main(){}" in out
    assert "// partial decompile" in out
    assert "Suggested timeout: 600s" in out


def test_decompile_line_window():
    code = "\n".join(f"line{i}" for i in range(1, 11))
    resp = {"success": True, "result": {"decompilation": code}}
    out = b.format_decompile(resp, start_line=2, max_lines=3)
    assert "lines 2-4 of 10" in out
    assert "line2" in out and "line4" in out
    assert "line5" not in out


# ---- format_disassembly ---------------------------------------------------

def test_disassembly_renders_instructions_list_result():
    resp = {"success": True,
            "result": [{"address": "0x1000", "bytes": "90", "mnemonic": "nop", "operands": ""}]}
    out = b.format_disassembly(resp)
    assert "0x1000" in out and "nop" in out


def test_disassembly_truncation_hint():
    resp = {"success": True, "meta": {"total": 100, "offset": 0},
            "result": {"instructions": [
                {"address": "0x%x" % (0x1000 + i), "bytes": "90", "mnemonic": "nop", "operands": ""}
                for i in range(10)]}}
    out = b.format_disassembly(resp)
    assert "90 more instruction(s) of 100 total (use offset=10)" in out


def test_disassembly_empty_with_message():
    resp = {"success": True, "result": {"instructions": [], "message": "not code"}}
    assert b.format_disassembly(resp) == "not code"


# ---- format_strings -------------------------------------------------------

def test_strings_escapes_and_quotes_value():
    resp = {"success": True, "meta": {"total": 1},
            "result": [{"address": "0x4000", "value": "hi\tthere"}]}
    out = b.format_strings(resp)
    assert "Strings (1-1 of 1):" in out
    assert "0x4000" in out
    assert "\\t" in out  # tab rendered via repr escaping


# ---- format_data_list -----------------------------------------------------

def test_data_list_header_and_label_fallback():
    resp = {"success": True, "meta": {"total": 1},
            "result": [{"address": "0x5000", "label": "g_flag", "dataType": "int", "value": "1"}]}
    out = b.format_data_list(resp, offset=0, limit=100)
    assert "Data items (1-1 of 1):" in out
    assert "0x5000" in out and "g_flag" in out


# ---- format_xrefs ---------------------------------------------------------

def test_xrefs_to_address_header_and_function_name():
    resp = {"success": True, "meta": {"total": 1},
            "result": {"references": [
                {"fromAddress": "0x1000", "toAddress": "0x2000", "refType": "CALL",
                 "fromFunction": {"name": "caller"}}]}}
    out = b.format_xrefs(resp, to_addr="0x2000")
    assert "References to 0x2000 (1):" in out
    assert "from caller" in out
    assert "CALL" in out
