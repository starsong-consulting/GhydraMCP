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
