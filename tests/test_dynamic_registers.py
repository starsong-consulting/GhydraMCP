import pytest

from ghydra.dynamic.registers import resolve_register, X86_64_REGISTERS


def test_resolve_is_case_insensitive():
    assert resolve_register("rip") == resolve_register("RIP")


def test_known_registers_present():
    for name in ("RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RSP", "RBP", "RIP",
                 "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"):
        assert name in X86_64_REGISTERS


def test_unknown_register_raises():
    with pytest.raises(KeyError):
        resolve_register("NOTAREG")
