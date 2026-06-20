from ghydra.dynamic.ghidra_provider import make_ghidra_provider


class FakeClient:
    def __init__(self, hex_by_addr):
        self.hex_by_addr = hex_by_addr
        self.calls = []

    def get(self, endpoint, params=None):
        self.calls.append((endpoint, params))
        addr = endpoint.split("/", 1)[1]
        return {"result": {"hex": self.hex_by_addr.get(addr, "")}}


def test_provider_decodes_hex_to_bytes():
    client = FakeClient({"140075000": "9090cc"})
    provider = make_ghidra_provider(client)
    data = provider(0x140075000, 4)
    assert data[:3] == b"\x90\x90\xcc"
    assert len(data) == 4          # zero-filled to requested length


def test_provider_zero_fills_on_miss():
    provider = make_ghidra_provider(FakeClient({}))
    assert provider(0x140076000, 8) == b"\x00" * 8
