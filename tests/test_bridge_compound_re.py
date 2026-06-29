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
