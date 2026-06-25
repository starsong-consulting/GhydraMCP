"""Offline tests for bridge HTTP response normalization.

These exercise the pure response/error-shaping logic that previously could only
be reached by driving a live (or failing) Ghidra server through `_make_request`.
A tiny fake Response stands in for `requests.Response`.
"""

import bridge_mcp_hydra as b


class FakeResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(self, status_code=200, body="", json_data=None, raise_on_json=False):
        self.status_code = status_code
        self._body = body
        self._json_data = json_data
        self._raise_on_json = raise_on_json

    @property
    def ok(self):
        return 200 <= self.status_code < 400

    @property
    def text(self):
        return self._body

    def json(self):
        if self._raise_on_json:
            raise ValueError("No JSON object could be decoded")
        return self._json_data


# ---- _normalize_response --------------------------------------------------

def test_empty_ok_body_is_success_envelope():
    r = FakeResponse(status_code=204, body="   ")
    out = b._normalize_response(r, "functions/foo")
    assert out["success"] is True
    assert out["status_code"] == 204
    assert "timestamp" in out


def test_json_success_passes_through_and_gets_timestamp():
    r = FakeResponse(status_code=200, body='{"success": true}',
                     json_data={"success": True, "result": [1, 2]})
    out = b._normalize_response(r, "functions")
    assert out["success"] is True
    assert out["result"] == [1, 2]
    assert "timestamp" in out  # injected when absent


def test_json_keeps_existing_timestamp():
    r = FakeResponse(status_code=200, body='{"success": true, "timestamp": 42}',
                     json_data={"success": True, "timestamp": 42})
    out = b._normalize_response(r, "functions")
    assert out["timestamp"] == 42


def test_string_error_on_failure_is_reshaped_to_dict():
    r = FakeResponse(status_code=404, json_data={"success": False, "error": "not found"})
    out = b._normalize_response(r, "functions/missing")
    assert out["error"]["code"] == "HTTP_404"
    assert out["error"]["message"] == "not found"


def test_dict_error_on_failure_is_left_intact():
    r = FakeResponse(status_code=400,
                     json_data={"success": False,
                                "error": {"code": "BAD", "message": "boom"}})
    out = b._normalize_response(r, "analysis/x")
    assert out["error"] == {"code": "BAD", "message": "boom"}


def test_non_json_success_body():
    r = FakeResponse(status_code=200, body="<html>oops</html>", raise_on_json=True)
    out = b._normalize_response(r, "functions")
    assert out["success"] is False
    assert out["error"]["code"] == "NON_JSON_RESPONSE"
    assert out["response_text"] == "<html>oops</html>"


def test_non_json_error_body():
    r = FakeResponse(status_code=500, body="Internal Server Error", raise_on_json=True)
    out = b._normalize_response(r, "functions")
    assert out["success"] is False
    assert out["error"]["code"] == "HTTP_500"
    assert out["status_code"] == 500


# ---- _timeout_error_envelope ----------------------------------------------

def test_timeout_envelope_basic():
    out = b._timeout_error_envelope("functions", 900, None)
    assert out["success"] is False
    assert out["error"]["code"] == "REQUEST_TIMEOUT"
    assert out["status_code"] == 408
    assert "timed out" in out["error"]["message"]


def test_timeout_envelope_for_decompile_suggests_higher_timeout():
    out = b._timeout_error_envelope("functions/main/decompile", 930, {"timeout": 600})
    msg = out["error"]["message"]
    assert "timeout=1200" in msg  # max(600*2, default)
