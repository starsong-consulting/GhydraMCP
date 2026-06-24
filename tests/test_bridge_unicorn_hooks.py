# tests/test_bridge_unicorn_hooks.py
import pytest

pytest.importorskip("unicorn")
import bridge_mcp_hydra as bridge
from ghydra.dynamic.unicorn_engine import UnicornSession


@pytest.fixture
def session_on_port(monkeypatch):
    port = 18192
    session = UnicornSession()
    monkeypatch.setattr(bridge, "_get_instance_port", lambda p=None: port)
    with bridge._unicorn_lock:
        bridge._UNICORN_SESSIONS[port] = session
    yield port, session
    with bridge._unicorn_lock:
        bridge._UNICORN_SESSIONS.pop(port, None)


def test_hook_set_list_clear(session_on_port):
    port, session = session_on_port
    r = bridge.unicorn_hook_set.__wrapped__("0x401000", "return_const", return_value="0x2a")
    assert r["success"] is True
    assert 0x401000 in session.list_hooks()
    listed = bridge.unicorn_hook_list.__wrapped__()
    assert any(h["address"] == "0x401000" for h in listed["hooks"])
    cleared = bridge.unicorn_hook_clear.__wrapped__("0x401000")
    assert cleared["success"] is True
    assert 0x401000 not in session.list_hooks()


def test_hook_set_rejects_mem_writes_on_skip(session_on_port):
    r = bridge.unicorn_hook_set.__wrapped__("0x401000", "skip",
                                            mem_writes=[{"address": "0x1000", "hex": "41"}])
    assert r["success"] is False


def test_unicorn_call_returns_value(session_on_port):
    port, session = session_on_port
    func = 0x140075000
    session.map_bytes(func, b"\xb8\x07\x00\x00\x00\xc3")   # mov eax,7 ; ret
    r = bridge.unicorn_call.__wrapped__(hex(func), args=[], convention="sysv")
    assert r["success"] is True
    assert r["return_value"] == "0x7"


def test_unicorn_call_without_session_errors(monkeypatch):
    monkeypatch.setattr(bridge, "_get_instance_port", lambda p=None: 19999)
    r = bridge.unicorn_call.__wrapped__("0x140075000", args=[], convention="sysv")
    assert r["success"] is False


def test_hook_set_rejects_bad_hex(session_on_port):
    r = bridge.unicorn_hook_set.__wrapped__("0x401000", "return_const", return_value="0xZZ")
    assert r["success"] is False


def test_hook_clear_rejects_bad_address(session_on_port):
    r = bridge.unicorn_hook_clear.__wrapped__("not_hex")
    assert r["success"] is False
    assert r["error"]["code"] == "VALIDATION"


def test_hook_set_without_session_errors(monkeypatch):
    monkeypatch.setattr(bridge, "_get_instance_port", lambda p=None: 19999)
    r = bridge.unicorn_hook_set.__wrapped__("0x401000", "return_const", return_value="0x1")
    assert r["success"] is False
    assert r["error"]["code"] == "NO_SESSION"


def test_hook_clear_without_session_errors(monkeypatch):
    monkeypatch.setattr(bridge, "_get_instance_port", lambda p=None: 19999)
    r = bridge.unicorn_hook_clear.__wrapped__("0x401000")
    assert r["success"] is False
    assert r["error"]["code"] == "NO_SESSION"


def test_hook_list_without_session_errors(monkeypatch):
    monkeypatch.setattr(bridge, "_get_instance_port", lambda p=None: 19999)
    r = bridge.unicorn_hook_list.__wrapped__()
    assert r["success"] is False
    assert r["error"]["code"] == "NO_SESSION"


def test_unicorn_call_with_count(session_on_port):
    port, session = session_on_port
    func = 0x140075000
    session.map_bytes(func, b"\xb8\x07\x00\x00\x00\xc3")  # mov eax,7 ; ret
    r = bridge.unicorn_call.__wrapped__(hex(func), args=[], count=500_000)
    assert r["success"] is True
    assert r["return_value"] == "0x7"
