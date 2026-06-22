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
