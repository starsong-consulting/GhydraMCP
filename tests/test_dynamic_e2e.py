import pytest

pytest.importorskip("unicorn")
from ghydra.dynamic.unicorn_engine import UnicornSession
from ghydra.dynamic.ghidra_provider import make_ghidra_provider


class FakeClient:
    """Serves a tiny XOR-decrypt routine and an encrypted buffer from 'Ghidra'."""
    CODE = 0x140075000
    BUF = 0x140076000
    # mov rbx, BUF ; mov rcx, 4 ; xor byte [rbx], 0xaa
    # (one xor; the run is stopped via `until` right after it executes)
    # Verified with capstone: total length is 0x14, the xor ends at CODE+0x14.
    PROG = (bytes.fromhex("48bb")           # movabs rbx, imm64
            + BUF.to_bytes(8, "little")     #   = 0x140076000
            + bytes.fromhex("48c7c104000000")  # mov rcx, 4
            + bytes.fromhex("8033aa"))      # xor byte [rbx], 0xaa

    def get(self, endpoint, params=None):
        addr = int(endpoint.split("/", 1)[1], 16)
        length = params["length"]
        if addr == self.CODE:
            data = (self.PROG + b"\x00" * length)[:length]
        elif addr == self.BUF:
            data = (bytes([b ^ 0xAA for b in b"PASS"]) + b"\x00" * length)[:length]
        else:
            data = b"\x00" * length
        return {"result": {"hex": data.hex()}}


def test_lazy_unpack_roundtrip_decrypts_buffer():
    client = FakeClient()
    session = UnicornSession(byte_provider=make_ghidra_provider(client))
    session.set_register("RIP", FakeClient.CODE)
    # Run the three setup instrs + one xor; stop right after the xor (offset 0x14).
    until = FakeClient.CODE + 0x14
    state = session.run(begin=FakeClient.CODE, until=until, count=50)
    assert state["stop_reason"] in ("DONE", "COUNT")
    # First byte of the buffer should now be decrypted ('P').
    first = session.read_memory(FakeClient.BUF, 1)
    assert first == b"P"
