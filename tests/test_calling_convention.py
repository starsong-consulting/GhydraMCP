# tests/test_calling_convention.py
import pytest
from ghydra.dynamic import calling_convention as cc


def test_sysv_arg_registers():
    assert cc.arg_registers("sysv") == ["RDI", "RSI", "RDX", "RCX", "R8", "R9"]


def test_ms_arg_registers():
    assert cc.arg_registers("ms") == ["RCX", "RDX", "R8", "R9"]


def test_return_register_is_rax_for_both():
    assert cc.return_register("sysv") == "RAX"
    assert cc.return_register("ms") == "RAX"


def test_unsupported_convention_raises():
    with pytest.raises(ValueError):
        cc.arg_registers("aapcs")
    with pytest.raises(ValueError):
        cc.return_register("aapcs")


def test_supported_conventions_set():
    assert cc.SUPPORTED_CONVENTIONS == {"sysv", "ms"}


def test_validate_accepts_int_and_bytes():
    cc.validate_args([1, 0xdeadbeef, {"bytes": "41424300"}])  # no raise


def test_validate_rejects_float():
    with pytest.raises(ValueError, match=r"arg\[1\]"):
        cc.validate_args([1, 3.14])


def test_validate_rejects_bool():
    with pytest.raises(ValueError, match=r"arg\[0\]"):
        cc.validate_args([True])


def test_validate_rejects_bad_dict():
    with pytest.raises(ValueError, match=r"arg\[0\]"):
        cc.validate_args([{"ptr": "4142"}])
    with pytest.raises(ValueError, match=r"arg\[0\]"):
        cc.validate_args([{"bytes": "4142", "extra": 1}])


def test_alignment_no_stack_args_sysv():
    # Callee entry must satisfy rsp % 16 == 8.
    rsp = 0x7ffffffff000  # 16-aligned start
    final = cc.aligned_call_frame(rsp, "sysv", 0)
    assert final % 16 == 8
    assert final < rsp                       # frame grew down
    assert rsp - final >= 8                   # at least the sentinel


def test_alignment_with_stack_args_sysv():
    rsp = 0x7ffffffff000
    final = cc.aligned_call_frame(rsp, "sysv", 3)
    assert final % 16 == 8
    # room for 3 stack args (24 bytes) + sentinel (8) at minimum
    assert rsp - final >= 8 * 3 + 8


def test_alignment_ms_reserves_shadow_space():
    rsp = 0x7ffffffff000
    final_ms = cc.aligned_call_frame(rsp, "ms", 0)
    final_sysv = cc.aligned_call_frame(rsp, "sysv", 0)
    assert final_ms % 16 == 8
    # MS reserves 32 bytes of shadow that SysV does not
    assert (rsp - final_ms) - (rsp - final_sysv) == 32


def test_alignment_from_unaligned_rsp():
    # A non-16-aligned starting RSP must still yield entry rsp % 16 == 8.
    for start in (0x7ffffffff000, 0x7fffffffeff8, 0x7fffffffefe0, 0x7fffffffefe9):
        assert cc.aligned_call_frame(start, "sysv", 2) % 16 == 8
