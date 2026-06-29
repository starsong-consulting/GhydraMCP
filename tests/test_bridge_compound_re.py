"""Offline tests for the compound-RE bridge tools' input validation.

The empty/missing-argument branches of analysis_find_call_paths and
analysis_trace_string_usage return a structured error envelope *before* any
network call, so they are reachable with no Ghidra instance. The @text_output
decorator renders that failure envelope to an ``Error: <message>`` string.
"""

import bridge_mcp_hydra as b


def test_call_paths_tools_are_callable():
    assert callable(b.analysis_find_call_paths)
    assert callable(b.analysis_trace_string_usage)


def test_find_call_paths_missing_from_is_rejected():
    out = b.analysis_find_call_paths("", "target")
    assert "from_fn" in out and "to_fn" in out  # MISSING_PARAMETER message


def test_find_call_paths_missing_to_is_rejected():
    out = b.analysis_find_call_paths("source", "")
    assert "from_fn" in out and "to_fn" in out


def test_trace_string_usage_missing_value_is_rejected():
    out = b.analysis_trace_string_usage("")
    assert "value is required" in out


def _call_paths_response(paths=None, truncated=False, unresolved=0):
    return {
        "success": True,
        "result": {
            "from": "main",
            "to": "target",
            "max_depth": 5,
            "max_paths": 50,
            "truncated": truncated,
            "unresolved_edges": unresolved,
            "paths": paths or [],
        },
    }


def _string_usage_response(matches=None, truncated=False, unresolved=0):
    return {
        "success": True,
        "result": {
            "value": "CreateFileW",
            "match": "substring",
            "caller_depth": 1,
            "size": 1,
            "offset": 0,
            "limit": 50,
            "truncated": truncated,
            "unresolved_refs": unresolved,
            "matches": matches or [],
        },
    }


def test_format_call_paths_no_paths_clean():
    out = b.format_call_paths(_call_paths_response())
    assert out == "No paths found from main to target."


def test_format_call_paths_no_paths_with_unresolved_hints():
    out = b.format_call_paths(_call_paths_response(unresolved=3))
    assert out == "No paths found from main to target. (some edges unresolved — may still be reachable)"


def test_format_call_paths_renders_path_chain():
    paths = [{"length": 2, "functions": [
        {"name": "main", "address": "0x1000"},
        {"name": "target", "address": "0x2000"},
    ]}]
    out = b.format_call_paths(_call_paths_response(paths=paths))
    assert out == "Call paths: main -> target (1 path(s))\n\n  Path 1 (2 hops): main -> target"


def test_format_call_paths_truncated_flag_shown():
    paths = [{"length": 1, "functions": [{"name": "main", "address": "0x1000"}]}]
    out = b.format_call_paths(_call_paths_response(paths=paths, truncated=True))
    assert out == "Call paths: main -> target (1 path(s)) [truncated]\n\n  Path 1 (1 hops): main"


def test_format_string_usage_no_matches():
    out = b.format_string_usage(_string_usage_response())
    assert out == 'No strings matching "CreateFileW" found.'


def test_format_string_usage_renders_direct_users():
    matches = [{
        "string": {"address": "0x8000", "value": "CreateFileW"},
        "directUsers": [{"name": "open_file", "address": "0x1000"}],
        "callers": [],
    }]
    out = b.format_string_usage(_string_usage_response(matches=matches))
    assert out == 'String usage: "CreateFileW" — 1 match(es)\n\n  0x8000  \'CreateFileW\'\n    used by: open_file'


def test_format_string_usage_renders_callers_with_depth():
    matches = [{
        "string": {"address": "0x8000", "value": "CreateFileW"},
        "directUsers": [{"name": "open_file", "address": "0x1000"}],
        "callers": [{"function": {"name": "do_thing", "address": "0x2000"}, "depth": 1}],
    }]
    out = b.format_string_usage(_string_usage_response(matches=matches))
    assert out == 'String usage: "CreateFileW" — 1 match(es)\n\n  0x8000  \'CreateFileW\'\n    used by: open_file\n    caller (depth 1): do_thing'


def test_find_call_paths_rejects_max_depth_zero():
    out = b.analysis_find_call_paths("source", "target", max_depth=0)
    assert "max_depth" in out


def test_find_call_paths_rejects_max_paths_zero():
    out = b.analysis_find_call_paths("source", "target", max_paths=0)
    assert "max_paths" in out
