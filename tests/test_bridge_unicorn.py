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
