"""Unicorn-based x86-64 emulation session with lazy mapping from Ghidra."""

from typing import Callable, Optional

from .registers import resolve_register

try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UcError
    _HAVE_UNICORN = True
except ImportError:
    _HAVE_UNICORN = False


class UnicornSession:
    PAGE = 0x1000

    def __init__(self, byte_provider: Optional[Callable[[int, int], bytes]] = None):
        if not _HAVE_UNICORN:
            raise RuntimeError("unicorn not installed; pip install ghydramcp[unicorn]")
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.byte_provider = byte_provider
        self._mapped: set[int] = set()

    def _ensure_mapped(self, address: int, length: int) -> None:
        start = address & ~(self.PAGE - 1)
        end = (address + length + self.PAGE - 1) & ~(self.PAGE - 1)
        for page in range(start, end, self.PAGE):
            if page not in self._mapped:
                self.uc.mem_map(page, self.PAGE)
                self._mapped.add(page)

    def map_bytes(self, address: int, data: bytes) -> None:
        self._ensure_mapped(address, len(data))
        self.uc.mem_write(address, data)

    def read_memory(self, address: int, length: int) -> bytes:
        return bytes(self.uc.mem_read(address, length))

    def set_register(self, name: str, value: int) -> None:
        self.uc.reg_write(resolve_register(name), value)

    def get_register(self, name: str) -> int:
        return self.uc.reg_read(resolve_register(name))
