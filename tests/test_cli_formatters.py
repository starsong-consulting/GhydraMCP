"""Offline tests for the CLI formatters (ghydra/formatters).

Both formatters are pure: they map an API response dict (or an exception) to a
string with no network or Ghidra dependency.
"""

import json

import pytest

from ghydra.formatters.json_formatter import JSONFormatter
from ghydra.formatters.table_formatter import TableFormatter
from ghydra.client.exceptions import GhidraAPIError


# ---- JSONFormatter --------------------------------------------------------

def test_json_formatter_passthrough_roundtrips():
    data = {"success": True, "result": [{"name": "main", "address": "0x1000"}]}
    out = JSONFormatter(pretty=False).format_functions_list(data)
    assert json.loads(out) == data


def test_json_formatter_pretty_is_indented():
    out = JSONFormatter(pretty=True).format_simple_result({"result": "ok"})
    assert "\n" in out and "  " in out


def test_json_formatter_error_includes_code():
    out = JSONFormatter(pretty=False).format_error(GhidraAPIError("boom", code="BAD"))
    parsed = json.loads(out)
    assert parsed["error"]["message"] == "boom"
    assert parsed["error"]["code"] == "BAD"
    assert parsed["error"]["type"] == "GhidraAPIError"


def test_json_formatter_error_plain_exception_has_no_code():
    out = JSONFormatter(pretty=False).format_error(ValueError("nope"))
    parsed = json.loads(out)
    assert parsed["error"]["message"] == "nope"
    assert "code" not in parsed["error"]


# ---- TableFormatter -------------------------------------------------------

@pytest.fixture
def fmt():
    # use_colors=False guarantees plain (ANSI-free) output for stable assertions
    return TableFormatter(use_colors=False)


def test_table_functions_list_renders_rows(fmt):
    data = {"result": [{"address": "0x1000", "name": "main", "signature": "int main(void)"}],
            "metadata": {"size": 1, "offset": 0, "limit": 100}}
    out = fmt.format_functions_list(data)
    assert "Functions (1 total)" in out
    assert "0x1000" in out and "main" in out


def test_table_functions_list_empty(fmt):
    out = fmt.format_functions_list({"result": []})
    assert "No functions found" in out


def test_table_functions_list_pagination_caption(fmt):
    data = {"result": [{"address": "0x10", "name": "f", "signature": ""}],
            "metadata": {"size": 250, "offset": 0, "limit": 100}}
    out = fmt.format_functions_list(data)
    assert "Showing 1-1 of 250" in out


def test_table_function_info_panel(fmt):
    data = {"result": {"address": "0x1000", "name": "main", "signature": "int main(void)",
                       "entryPoint": "0x1000"}}
    out = fmt.format_function_info(data)
    assert "main" in out and "Entry Point" in out


def test_table_simple_result_message(fmt):
    out = fmt.format_simple_result({"result": {"message": "renamed"}})
    assert "renamed" in out


def test_table_simple_result_string(fmt):
    out = fmt.format_simple_result({"result": "done"})
    assert "done" in out


def test_table_error_with_code(fmt):
    out = fmt.format_error(GhidraAPIError("not found", code="NOT_FOUND"))
    assert "NOT_FOUND" in out and "not found" in out


def test_table_error_plain_exception(fmt):
    out = fmt.format_error(ValueError("bad input"))
    assert "bad input" in out


# ---- compound-RE formatters -----------------------------------------------

def _call_paths_response(**overrides):
    result = {
        "from": "0x401000", "to": "0x401abc",
        "max_depth": 5, "max_paths": 50, "truncated": False, "unresolved_edges": 0,
        "paths": [
            {"length": 2, "functions": [
                {"name": "main", "address": "0x401000"},
                {"name": "fopen", "address": "0x401abc"}]},
        ],
    }
    result.update(overrides)
    return {"result": result}


def test_table_call_paths_renders_arrow_chain(fmt):
    out = fmt.format_call_paths(_call_paths_response())
    assert "Call paths" in out and "1 found" in out
    assert "main -> fopen" in out


def test_table_call_paths_empty(fmt):
    out = fmt.format_call_paths(_call_paths_response(paths=[]))
    assert "No paths found" in out


def test_table_call_paths_flags_truncation_and_unresolved(fmt):
    out = fmt.format_call_paths(_call_paths_response(truncated=True, unresolved_edges=3))
    assert "truncated" in out
    assert "3 unresolved edges" in out


def test_table_call_paths_non_dict_result(fmt):
    out = fmt.format_call_paths({"result": []})
    assert "No call path data available" in out


def _string_usage_response(**overrides):
    result = {
        "value": "CreateFileW", "match": "substring", "caller_depth": 1,
        "size": 1, "offset": 0, "limit": 50, "truncated": False, "unresolved_refs": 0,
        "matches": [
            {"string": {"address": "0x402000", "value": "CreateFileW"},
             "directUsers": [{"name": "open_handle", "address": "0x401100"}],
             "callers": [{"function": {"name": "main", "address": "0x401000"}, "depth": 1}]},
        ],
    }
    result.update(overrides)
    return {"result": result}


def test_table_string_usage_renders_users_and_callers(fmt):
    out = fmt.format_string_usage(_string_usage_response())
    assert "String usage" in out and "CreateFileW" in out
    assert "open_handle" in out
    assert "main(1)" in out


def test_table_string_usage_empty(fmt):
    out = fmt.format_string_usage(_string_usage_response(matches=[], size=0))
    assert "No matches" in out


def test_table_string_usage_flags_truncation_and_unresolved(fmt):
    out = fmt.format_string_usage(_string_usage_response(truncated=True, unresolved_refs=2))
    assert "truncated" in out
    assert "2 unresolved refs" in out


def test_json_call_paths_and_string_usage_roundtrip():
    jf = JSONFormatter(pretty=False)
    cp = _call_paths_response()
    assert json.loads(jf.format_call_paths(cp)) == cp
    su = _string_usage_response()
    assert json.loads(jf.format_string_usage(su)) == su
