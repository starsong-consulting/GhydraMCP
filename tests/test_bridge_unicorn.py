import pytest

from bridge_mcp_hydra import _unicorn_run_result


def _state(stop, last_error=None):
    return {"pc": 0x1000, "steps": 3, "stop_reason": stop, "last_error": last_error,
            "registers": {"RIP": 0x1000}, "trace": [], "mem_writes": []}


def test_done_is_success_without_error_envelope():
    r = _unicorn_run_result(_state("DONE"))
    assert r["success"] is True
    assert r["last_error"] is None
    assert "error" not in r
    assert r["pc"] == "0x1000"


def test_lazy_fetch_failed_is_failure_and_surfaces_message():
    r = _unicorn_run_result(_state("LAZY_FETCH_FAILED", "no image bytes at 0x140076000"))
    assert r["success"] is False
    assert r["stop_reason"] == "LAZY_FETCH_FAILED"
    assert r["error"]["code"] == "LAZY_FETCH_FAILED"
    assert "0x140076000" in r["error"]["message"]
    assert r["last_error"] == "no image bytes at 0x140076000"


def test_count_is_failure_with_cap_message():
    r = _unicorn_run_result(_state("COUNT"))
    assert r["success"] is False
    assert r["error"]["code"] == "COUNT"
    assert "cap" in r["error"]["message"].lower()


def test_lazy_cap_reached_is_failure_with_budget_hint():
    r = _unicorn_run_result(_state("LAZY_CAP_REACHED",
                                   "lazy page cap (4096) reached at 0x140075000; raise max_lazy_pages"))
    assert r["success"] is False
    assert r["error"]["code"] == "LAZY_CAP_REACHED"
    assert "max_lazy_pages" in r["error"]["message"]


def test_unicorn_map_zero_fills_a_region():
    pytest.importorskip("unicorn")
    import bridge_mcp_hydra as b
    from ghydra.dynamic.unicorn_engine import UnicornSession
    b._UNICORN_SESSIONS[8192] = UnicornSession()
    b.active_instances[8192] = {"url": "http://localhost:8192"}   # satisfy _get_instance_port
    try:
        # call the undecorated function to inspect the raw dict
        result = b.unicorn_map.__wrapped__("0x140070000", 0x2000, port=8192)
        assert result["success"] is True
        session = b._UNICORN_SESSIONS[8192]
        assert session.read_memory(0x140070000, 8) == b"\x00" * 8   # mapped + zeroed
    finally:
        b._UNICORN_SESSIONS.pop(8192, None)
        b.active_instances.pop(8192, None)


def test_apply_default_stack_maps_and_points_rsp():
    pytest.importorskip("unicorn")
    from ghydra.dynamic.unicorn_engine import UnicornSession
    from bridge_mcp_hydra import _apply_default_stack
    s = UnicornSession()
    base, size = _apply_default_stack(s)
    rsp = s.get_register("RSP")
    assert base <= rsp < base + size
    assert s.get_register("RBP") == rsp
    assert s.read_memory(rsp - 8, 8) == b"\x00" * 8   # stack is mapped + zeroed
