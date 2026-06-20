import pytest

unicorn = pytest.importorskip("unicorn")
from ghydra.dynamic.unicorn_engine import UnicornSession


def test_map_and_read_roundtrip():
    s = UnicornSession()
    s.map_bytes(0x140075000, b"\x90\x90\xcc")
    assert s.read_memory(0x140075000, 3) == b"\x90\x90\xcc"


def test_set_get_register():
    s = UnicornSession()
    s.set_register("RAX", 0xdeadbeef)
    assert s.get_register("rax") == 0xdeadbeef


def test_map_is_page_aligned_and_idempotent():
    s = UnicornSession()
    s.map_bytes(0x140075abc, b"\x41")          # maps the page 0x140075000
    s.map_bytes(0x140075fff, b"\x42")          # same page, must not re-map
    assert s.read_memory(0x140075abc, 1) == b"\x41"
    assert s.read_memory(0x140075fff, 1) == b"\x42"


def test_run_two_nops_advances_rip_and_traces():
    s = UnicornSession()
    base = 0x140075000
    s.map_bytes(base, b"\x90\x90")             # nop; nop
    s.set_register("RIP", base)
    state = s.run(begin=base, until=base + 2, count=10, trace=True)
    assert state["pc"] == base + 2
    assert state["steps"] == 2
    assert state["trace"] == [base, base + 1]
    assert state["stop_reason"] == "DONE"


def test_run_records_memory_writes():
    s = UnicornSession()
    base = 0x140075000
    # mov byte ptr [rip+0], 0x41 is awkward; use: mov al,0x41 ; mov [0x140076000], al
    # Simpler: write via a stosb-free sequence:  mov rbx,0x140076000 ; mov byte [rbx],0x41
    code = bytes.fromhex("48bb0060074001000000" "c60341")  # mov rbx,0x140076000 ; mov [rbx],0x41
    s.map_bytes(base, code)
    s.map_bytes(0x140076000, b"\x00")          # destination page
    s.set_register("RIP", base)
    state = s.run(begin=base, until=base + len(code), count=10, trace=True)
    writes = [w for w in state["mem_writes"] if w["address"] == 0x140076000]
    assert writes and writes[0]["value"] == 0x41
