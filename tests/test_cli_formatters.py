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
