"""Offline tests for the CLI input validators (ghydra/utils/validators.py)."""

import pytest

from ghydra.utils.validators import (
    validate_address,
    normalize_hex_address,
    validate_port,
    validate_hex_bytes,
)


# ---- validate_address -----------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("0x401000", "401000"),
    ("401000", "401000"),
    ("401000h", "401000"),
    ("0X401ABC", "401abc"),
    ("  0x401000  ", "401000"),
])
def test_validate_address_normalizes(raw, expected):
    assert validate_address(raw) == expected


@pytest.mark.parametrize("bad", ["", "0xZZZ", "ghidra", "0x", "12 34"])
def test_validate_address_rejects_bad(bad):
    with pytest.raises(ValueError):
        validate_address(bad)


def test_normalize_hex_address_adds_prefix():
    assert normalize_hex_address("401000h") == "0x401000"
    assert normalize_hex_address("0x401000") == "0x401000"


# ---- validate_port --------------------------------------------------------

@pytest.mark.parametrize("port", [1, 8192, 65535])
def test_validate_port_accepts_in_range(port):
    assert validate_port(port) == port


@pytest.mark.parametrize("port", [0, -1, 65536, 100000])
def test_validate_port_rejects_out_of_range(port):
    with pytest.raises(ValueError):
        validate_port(port)


def test_validate_port_rejects_non_int():
    with pytest.raises(ValueError):
        validate_port("8192")


# ---- validate_hex_bytes ---------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("deadbeef", "deadbeef"),
    ("DE AD BE EF", "deadbeef"),
    ("0xde0xad", "dead"),
    ("DEADBEEF", "deadbeef"),
])
def test_validate_hex_bytes_normalizes(raw, expected):
    assert validate_hex_bytes(raw) == expected


def test_validate_hex_bytes_rejects_empty():
    with pytest.raises(ValueError):
        validate_hex_bytes("")


def test_validate_hex_bytes_rejects_odd_length():
    with pytest.raises(ValueError, match="even number"):
        validate_hex_bytes("abc")


def test_validate_hex_bytes_rejects_non_hex():
    with pytest.raises(ValueError):
        validate_hex_bytes("xy12")
