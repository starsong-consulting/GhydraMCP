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


def test_lazy_maps_code_page_from_provider():
    # Provider serves "nop; nop" for the code page, zero elsewhere.
    base = 0x140075000
    def provider(address, length):
        page = bytearray(length)
        if address == base:
            page[0:2] = b"\x90\x90"
        return bytes(page)

    s = UnicornSession(byte_provider=provider)
    s.set_register("RIP", base)
    # NOTE: code page is NOT pre-mapped; the unmapped hook must fetch it.
    state = s.run(begin=base, until=base + 2, count=10, trace=True)
    assert state["steps"] == 2
    assert state["stop_reason"] == "DONE"


def test_clean_run_has_no_last_error():
    s = UnicornSession()
    base = 0x140075000
    s.map_bytes(base, b"\x90\x90")             # nop; nop
    s.set_register("RIP", base)
    state = s.run(begin=base, until=base + 2, count=10)
    assert state["stop_reason"] == "DONE"
    assert state["last_error"] is None


def test_lazy_fetch_failure_faults_with_reason_and_leaves_page_unmapped():
    from ghydra.dynamic.exceptions import ProviderError
    base = 0x140075000

    def provider(address, length):
        raise ProviderError(f"no image bytes at {hex(address)}")

    s = UnicornSession(byte_provider=provider)
    s.set_register("RIP", base)
    state = s.run(begin=base, until=base + 2, count=10)
    assert state["stop_reason"] == "LAZY_FETCH_FAILED"
    assert state["last_error"] and hex(base) in state["last_error"]
    assert (base & ~(UnicornSession.PAGE - 1)) not in s._mapped   # page NOT mapped


def test_lazy_fetch_empty_data_also_faults():
    base = 0x140075000

    def provider(address, length):
        return b""                              # provider returns nothing (no raise)

    s = UnicornSession(byte_provider=provider)
    s.set_register("RIP", base)
    state = s.run(begin=base, until=base + 2, count=10)
    assert state["stop_reason"] == "LAZY_FETCH_FAILED"


def test_non_lazy_fault_reports_error_not_lazy_fetch_failed():
    # No byte_provider -> the unmapped hook is disabled, so an access to an
    # unmapped page is a plain UcError. This must report "ERROR" (with a
    # last_error message), NOT "LAZY_FETCH_FAILED".
    base = 0x140075000
    s = UnicornSession()                            # byte_provider is None
    s.set_register("RIP", base)
    state = s.run(begin=base, until=base + 2, count=10)
    assert state["stop_reason"] == "ERROR"
    assert isinstance(state["last_error"], str) and state["last_error"]


def test_lazy_cap_reached_faults_with_distinct_reason():
    base = 0x140075000

    def provider(address, length):
        return b"\x90" * length          # real bytes, but the cap forbids mapping

    s = UnicornSession(byte_provider=provider)
    s.set_register("RIP", base)
    # max_lazy_pages=0 -> the very first lazy map is already over budget.
    state = s.run(begin=base, until=base + 2, count=10, max_lazy_pages=0)
    assert state["stop_reason"] == "LAZY_CAP_REACHED"
    assert state["last_error"] and "max_lazy_pages" in state["last_error"]


def test_unicorn_handle_is_private():
    s = UnicornSession()
    assert hasattr(s, "_uc")
    assert not hasattr(s, "uc")


def test_trace_truncation_flag(monkeypatch):
    from ghydra.dynamic import unicorn_engine
    monkeypatch.setattr(unicorn_engine, "_TRACE_CAP", 2)   # cap the trace at 2 entries
    s = UnicornSession()
    base = 0x140075000
    s.map_bytes(base, b"\x90\x90\x90\x90")                 # four nops
    s.set_register("RIP", base)
    state = s.run(begin=base, until=base + 4, count=10, trace=True)
    assert state["stop_reason"] == "DONE"
    assert len(state["trace"]) == 2                        # appended only up to the cap
    assert state["trace_truncated"] is True


def test_clean_trace_is_not_truncated():
    s = UnicornSession()
    base = 0x140075000
    s.map_bytes(base, b"\x90\x90")
    s.set_register("RIP", base)
    state = s.run(begin=base, until=base + 2, count=10, trace=True)
    assert state["trace_truncated"] is False


def test_session_construction_raises_without_unicorn(monkeypatch):
    from ghydra.dynamic import unicorn_engine
    monkeypatch.setattr(unicorn_engine, "_HAVE_UNICORN", False)
    import pytest
    with pytest.raises(RuntimeError, match="unicorn not installed"):
        unicorn_engine.UnicornSession()


def test_run_hits_instruction_cap_returns_count():
    s = UnicornSession()
    base = 0x140075000
    s.map_bytes(base, b"\xeb\xfe")          # jmp $  -- tight infinite loop
    s.set_register("RIP", base)
    # until is never reached; the run must stop at the instruction budget.
    state = s.run(begin=base, until=base + 0x100, count=5)
    assert state["stop_reason"] == "COUNT"
    assert state["last_error"] is None      # COUNT is a clean stop, not a fault
    assert state["steps"] == 5


from ghydra.dynamic.unicorn_engine import Hook, VALID_HOOK_ACTIONS, StopReason, _CALL_STACK_BASE


def test_hook_trap_constant_exists():
    assert StopReason.HOOK_TRAP == "HOOK_TRAP"


def test_set_list_clear_hook():
    s = UnicornSession()
    s.set_hook(0x401000, Hook(action="skip"))
    assert 0x401000 in s.list_hooks()
    assert s.list_hooks()[0x401000].action == "skip"
    assert s.clear_hook(0x401000) is True
    assert s.clear_hook(0x401000) is False
    assert 0x401000 not in s.list_hooks()


def test_set_hook_rejects_unknown_action():
    s = UnicornSession()
    with pytest.raises(ValueError, match="action"):
        s.set_hook(0x401000, Hook(action="explode"))


def test_mem_writes_only_on_return_const():
    s = UnicornSession()
    with pytest.raises(ValueError, match="mem_writes"):
        s.set_hook(0x401000, Hook(action="skip", mem_writes=[{"address": 0x1000, "hex": "41"}]))
    # allowed on return_const
    s.set_hook(0x402000, Hook(action="return_const", return_value=0,
                              mem_writes=[{"address": 0x1000, "hex": "41"}]))


def test_fresh_session_has_empty_registry():
    assert UnicornSession().list_hooks() == {}


def test_simulate_ret_pops_return_address_and_sets_rax():
    s = UnicornSession()
    stack = 0x7ffff0000000
    s.map_bytes(stack, b"\x00" * 0x1000)
    ret_addr = 0x401234
    s.set_register("RSP", stack + 0x100)
    s.map_bytes(stack + 0x100, ret_addr.to_bytes(8, "little"))  # return addr on stack
    s.simulate_ret(return_value=0xcafe)
    assert s.get_register("RIP") == ret_addr
    assert s.get_register("RSP") == stack + 0x108
    assert s.get_register("RAX") == 0xcafe


def test_simulate_ret_leaves_rax_untouched_when_none():
    s = UnicornSession()
    stack = 0x7ffff0000000
    s.map_bytes(stack, b"\x00" * 0x1000)
    s.set_register("RSP", stack + 0x100)
    s.set_register("RAX", 0x1111)
    s.map_bytes(stack + 0x100, (0x401234).to_bytes(8, "little"))
    s.simulate_ret()  # no return value
    assert s.get_register("RAX") == 0x1111
    assert s.get_register("RIP") == 0x401234


def _call_stub_program():
    """A program: call <import thunk>; the thunk is at an address we hook.

    code @ base: mov rax, 0 ; call rel32 -> import@base+0x100 ; nop (return site)
    We hook import@base+0x100 with return_const so the call never executes there.
    """
    base = 0x140075000
    # e8 <rel32> = call ; target = base+0x100 ; instruction at base, len 5 -> next = base+5
    rel = (0x100 - 5) & 0xffffffff
    code = b"\xe8" + rel.to_bytes(4, "little") + b"\x90"   # call import ; nop
    return base, code


def test_return_const_hook_stubs_the_call():
    s = UnicornSession()
    base, code = _call_stub_program()
    s.map_bytes(base, code)
    stack = 0x7ffff0000000
    s.map_bytes(stack, b"\x00" * 0x2000)
    s.set_register("RSP", stack + 0x1000)
    s.set_register("RIP", base)
    s.set_hook(base + 0x100, Hook(action="return_const", return_value=0x2a))
    # run until the return site (the nop after the call)
    state = s.run(begin=base, until=base + 5, count=50)
    assert state["stop_reason"] == "DONE"
    assert s.get_register("RAX") == 0x2a       # return_const set RAX


def test_trap_hook_stops_with_hook_trap():
    s = UnicornSession()
    base, code = _call_stub_program()
    s.map_bytes(base, code)
    stack = 0x7ffff0000000
    s.map_bytes(stack, b"\x00" * 0x2000)
    s.set_register("RSP", stack + 0x1000)
    s.set_register("RIP", base)
    s.set_hook(base + 0x100, Hook(action="trap"))
    state = s.run(begin=base, until=base + 5, count=50)
    assert state["stop_reason"] == "HOOK_TRAP"
    assert state["pc"] == base + 0x100         # stopped AT the trap target


def test_log_hook_records_and_continues():
    s = UnicornSession()
    base = 0x140075000
    s.map_bytes(base, b"\x90\x90")             # nop ; nop
    s.set_register("RIP", base)
    s.set_hook(base, Hook(action="log"))
    state = s.run(begin=base, until=base + 2, count=10)
    assert state["stop_reason"] == "DONE"
    assert any(e["address"] == base for e in state["hook_log"])


def test_redirect_storm_is_bounded_by_redirect_cap():
    """A return_const hook on A whose simulate_ret always returns to A (stack full of A)
    must terminate with REDIRECT_STORM rather than looping forever.
    The redirect cap is independent of the instruction count.
    """
    s = UnicornSession()
    base = 0x140075000
    s.map_bytes(base, b"\x90")
    stack_base = 0x7ffff0000000
    addr_bytes = base.to_bytes(8, "little")
    # 20 pages = 10 240 entries — enough to sustain 10 000+ redirects before the cap fires
    stack_pages = addr_bytes * (0x1000 // 8) * 20
    s.map_bytes(stack_base, stack_pages)
    s.set_register("RSP", stack_base)
    s.set_hook(base, Hook(action="return_const", return_value=0))
    state = s.run(begin=base, until=0, count=1_000_000)
    assert state["stop_reason"] == "REDIRECT_STORM"
    assert state["steps"] == 0    # no instructions executed; only redirects


from ghydra.dynamic.unicorn_engine import SENTINEL_ADDR


def test_run_to_sentinel_completes_cleanly():
    s = UnicornSession()
    base = 0x140075000
    # ret  (c3)  -> pops return addr (the sentinel) into RIP, then fetch-faults there
    s.map_bytes(base, b"\xc3")
    stack = 0x7ffff0000000
    s.map_bytes(stack, b"\x00" * 0x1000)
    rsp = stack + 0x100
    s.set_register("RSP", rsp)
    # place the sentinel as the return address on the stack
    s.map_bytes(rsp, SENTINEL_ADDR.to_bytes(8, "little"))
    s.set_register("RIP", base)
    state = s.run(begin=base, until=0, count=50)
    assert state["stop_reason"] == "DONE"
    assert state["last_error"] is None


def test_data_fault_on_sentinel_page_is_not_completion():
    # A *data* read of the sentinel page (not a fetch) must NOT be COMPLETED.
    s = UnicornSession()
    base = 0x140075000
    # mov rax, [SENTINEL_ADDR]  -> 48 a1 <abs64>  (movabs rax, moffs64)
    code = b"\x48\xa1" + SENTINEL_ADDR.to_bytes(8, "little")
    s.map_bytes(base, code)
    s.set_register("RIP", base)
    state = s.run(begin=base, until=base + len(code), count=10)
    assert state["stop_reason"] == "ERROR"      # wild data read, not completion


def test_call_runs_function_and_returns_rax():
    # Function: mov eax, 7 ; ret   (b8 07 00 00 00 c3)
    s = UnicornSession()
    func = 0x140075000
    s.map_bytes(func, b"\xb8\x07\x00\x00\x00\xc3")
    out = s.call(func, args=[], convention="sysv")
    assert out["stop_reason"] == "DONE"
    assert out["return_value"] == 7


def test_call_passes_int_args_in_sysv_registers():
    # Function: mov rax, rdi ; add rax, rsi ; ret
    #   48 89 f8   mov rax, rdi
    #   48 01 f0   add rax, rsi
    #   c3         ret
    s = UnicornSession()
    func = 0x140075000
    s.map_bytes(func, bytes.fromhex("4889f8" "4801f0" "c3"))
    out = s.call(func, args=[20, 22], convention="sysv")
    assert out["return_value"] == 42
    assert out["args_passed"] == [20, 22]


def test_call_passes_bytes_arg_as_pointer():
    # Function: mov al, [rdi] ; movzx eax, al ; ret
    #   8a 07            mov al, [rdi]
    #   0f b6 c0         movzx eax, al
    #   c3               ret
    s = UnicornSession()
    func = 0x140075000
    s.map_bytes(func, bytes.fromhex("8a07" "0fb6c0" "c3"))
    out = s.call(func, args=[{"bytes": "41"}], convention="sysv")
    assert out["return_value"] == 0x41        # read the first byte of the buffer


def test_call_rejects_float_arg():
    s = UnicornSession()
    func = 0x140075000
    s.map_bytes(func, b"\xc3")
    with pytest.raises(ValueError, match=r"arg\[0\]"):
        s.call(func, args=[1.5], convention="sysv")
    assert (_CALL_STACK_BASE & ~(UnicornSession.PAGE - 1)) not in s._mapped


def test_call_rejects_unsupported_convention():
    s = UnicornSession()
    func = 0x140075000
    s.map_bytes(func, b"\xc3")
    with pytest.raises(ValueError, match="convention"):
        s.call(func, args=[], convention="aapcs")
    assert (_CALL_STACK_BASE & ~(UnicornSession.PAGE - 1)) not in s._mapped


def test_call_spills_seventh_sysv_arg_to_stack():
    # mov rax, [rsp+8] ; ret   -> returns the first stack-spilled arg (the 7th)
    s = UnicornSession()
    func = 0x140075000
    s.map_bytes(func, bytes.fromhex("488b442408" "c3"))  # mov rax,[rsp+8]; ret
    out = s.call(func, args=[1, 2, 3, 4, 5, 6, 7], convention="sysv")
    assert out["stop_reason"] == "DONE"
    assert out["return_value"] == 7
    assert out["args_passed"] == [1, 2, 3, 4, 5, 6, 7]


def test_hook_rejects_return_value_on_non_return_const():
    with pytest.raises(ValueError, match="return_value"):
        Hook(action="skip", return_value=0xdead)


def test_hook_rejects_bad_hex_in_mem_writes():
    with pytest.raises(ValueError, match="not valid hex"):
        Hook(action="return_const", return_value=0,
             mem_writes=[{"address": 0x1000, "hex": "ZZ"}])


def test_hook_rejects_wrong_mem_writes_structure():
    with pytest.raises(ValueError, match="mem_writes"):
        Hook(action="return_const", return_value=0,
             mem_writes=[{"ptr": 0x1000, "data": "41"}])


def test_hook_callback_error_surfaces_as_error_stop():
    """simulate_ret raises UcError when RSP is unmapped; must surface as ERROR,
    not loop forever or return a corrupt DONE."""
    s = UnicornSession()
    base = 0x140075000
    s.map_bytes(base, b"\x90")
    # Do NOT map a stack; RSP = 0x0 (unmapped) — simulate_ret will fault
    s.set_register("RSP", 0)
    s.set_hook(base, Hook(action="return_const", return_value=0))
    state = s.run(begin=base, until=0, count=10)
    assert state["stop_reason"] == "ERROR"
    assert state["last_error"] is not None
    assert "hook" in state["last_error"].lower()


def test_call_budget_overflow_does_not_map_scratch():
    """Budget overflow must be caught before touching the emulator."""
    s = UnicornSession()
    func = 0x140075000
    s.map_bytes(func, b"\xc3")
    too_many = "41" * (0x40001)     # 256 KiB + 1 byte
    with pytest.raises(ValueError, match="scratch budget"):
        s.call(func, args=[{"bytes": too_many}], convention="sysv")
    # scratch stack page must NOT be mapped
    assert (_CALL_STACK_BASE & ~(UnicornSession.PAGE - 1)) not in s._mapped


def test_call_returns_trace_key():
    s = UnicornSession()
    func = 0x140075000
    s.map_bytes(func, b"\xb8\x01\x00\x00\x00\xc3")  # mov eax,1 ; ret
    out = s.call(func, args=[], convention="sysv")
    assert "trace" in out      # always present, even when trace=False


def test_instruction_fetch_near_sentinel_is_error_not_done():
    """A fetch fault at SENTINEL_ADDR+1 (same page, different address) must be
    ERROR, not DONE — ensures the sentinel check is exact, not page-aligned."""
    s = UnicornSession()
    base = 0x140075000
    target = SENTINEL_ADDR + 1
    # mov rax, target  (10 bytes)  ;  jmp rax  (2 bytes)
    code = b"\x48\xb8" + target.to_bytes(8, "little") + b"\xff\xe0"
    s.map_bytes(base, code)
    s.set_register("RIP", base)
    state = s.run(begin=base, until=0, count=5)
    assert state["stop_reason"] == "ERROR"   # not DONE; wrong address on sentinel page


def test_skip_hook_leaves_rax_unchanged():
    """skip simulates ret without modifying RAX; a regression setting RAX=0
    on skip would be caught here."""
    s = UnicornSession()
    base = 0x140075000
    import_addr = base + 0x100

    # Function body:
    #   mov eax, 0x2a   (b8 2a 00 00 00)
    #   call import     (e8 <rel>)
    #   ret             (c3)
    rel = (import_addr - (base + 5) - 5) & 0xffffffff
    code = (b"\xb8\x2a\x00\x00\x00"
            + b"\xe8" + rel.to_bytes(4, "little")
            + b"\xc3")
    s.map_bytes(base, code)
    s.map_bytes(import_addr, b"\x90")   # one byte at import target
    s.set_hook(import_addr, Hook(action="skip"))

    out = s.call(func_addr=base, args=[], convention="sysv")
    assert out["stop_reason"] == "DONE"
    assert out["return_value"] == 0x2a  # skip left RAX as set by mov eax,0x2a


def test_return_const_mem_writes_are_applied():
    """The mem_writes side-effect of return_const must actually write to the
    target address; this is the emulation-level contract, not just the bridge
    precondition check."""
    s = UnicornSession()
    base = 0x140075000
    import_addr = base + 0x100
    target_addr = 0x140076000

    rel = (import_addr - (base + 5)) & 0xffffffff
    code = b"\xe8" + rel.to_bytes(4, "little") + b"\xc3"
    s.map_bytes(base, code)
    s.map_bytes(import_addr, b"\x90")
    s.map_bytes(target_addr, b"\x00" * 4)

    stack = 0x7ffff0000000
    s.map_bytes(stack, b"\x00" * 0x2000)
    s.set_register("RSP", stack + 0x1000)

    hook = Hook(action="return_const", return_value=0,
                mem_writes=[{"address": target_addr, "hex": "41424344"}])
    s.set_hook(import_addr, hook)

    state = s.run(begin=base, until=0, count=50)
    assert state["stop_reason"] == "DONE"
    assert s.read_memory(target_addr, 4) == b"\x41\x42\x43\x44"


def test_call_passes_args_in_ms_registers():
    """MS convention passes first arg in RCX, not RDI (SysV)."""
    s = UnicornSession()
    base = 0x140075000
    # mov rax, rcx ; ret   (48 8b c1 ; c3)
    s.map_bytes(base, bytes.fromhex("488bc1c3"))
    out = s.call(func_addr=base, args=[0xbeef], convention="ms")
    assert out["stop_reason"] == "DONE"
    assert out["return_value"] == 0xbeef
