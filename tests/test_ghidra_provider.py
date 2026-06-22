import pytest

from ghydra.dynamic.ghidra_provider import make_ghidra_provider
from ghydra.dynamic.exceptions import ProviderError


class FakeClient:
    """Returns a success envelope with the configured hex, or raises if hex is an Exception."""
    def __init__(self, hex_by_addr):
        self.hex_by_addr = hex_by_addr
        self.calls = []

    def get(self, endpoint, params=None):
        self.calls.append((endpoint, params))
        addr = endpoint.split("/", 1)[1]
        value = self.hex_by_addr.get(addr, "")
        if isinstance(value, Exception):
            raise value
        return {"result": {"hex": value}}


def test_provider_returns_real_bytes_only_not_zero_padded():
    # 3 real bytes requested as 4 -> returns the 3 real bytes, NOT zero-padded to 4.
    provider = make_ghidra_provider(FakeClient({"140075000": "9090cc"}))
    data = provider(0x140075000, 4)
    assert data == b"\x90\x90\xcc"


def test_provider_raises_on_empty_hex():
    provider = make_ghidra_provider(FakeClient({}))   # success, but hex == ""
    with pytest.raises(ProviderError):
        provider(0x140076000, 8)


def test_provider_raises_when_client_raises():
    from ghydra.client.exceptions import GhidraConnectionError
    provider = make_ghidra_provider(FakeClient({"140076000": GhidraConnectionError("down")}))
    with pytest.raises(ProviderError):
        provider(0x140076000, 8)


def test_provider_raises_on_malformed_hex():
    provider = make_ghidra_provider(FakeClient({"140076000": "zz"}))   # not valid hex
    with pytest.raises(ProviderError):
        provider(0x140076000, 8)


def test_provider_error_is_a_ghidra_error():
    from ghydra.dynamic.exceptions import ProviderError
    from ghydra.client.exceptions import GhidraError
    assert issubclass(ProviderError, GhidraError)
