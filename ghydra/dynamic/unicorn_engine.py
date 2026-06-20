"""Unicorn-based x86-64 emulation session with lazy mapping from Ghidra."""

from typing import Callable, Optional

from .registers import resolve_register

try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UcError
    _HAVE_UNICORN = True
except ImportError:
    _HAVE_UNICORN = False


_TRACE_CAP = 100000
_ALL_REGS = ("RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RSP", "RBP", "RIP",
             "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")


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

    def run(self, begin, until=0, count=100000, timeout=0, trace=False):
        from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
        steps = {"n": 0}
        executed: list[int] = []
        mem_writes: list[dict] = []

        def _code_hook(uc, address, size, _user):
            steps["n"] += 1
            if trace and len(executed) < _TRACE_CAP:
                executed.append(address)

        def _write_hook(uc, access, address, size, value, _user):
            if trace and len(mem_writes) < _TRACE_CAP:
                mem_writes.append({"address": address, "size": size, "value": value})

        h_code = self.uc.hook_add(UC_HOOK_CODE, _code_hook)
        h_write = self.uc.hook_add(UC_HOOK_MEM_WRITE, _write_hook) if trace else None
        stop_reason = "DONE"
        cap = min(count if count > 0 else 5_000_000, 5_000_000)
        try:
            self.uc.emu_start(begin, until, timeout=timeout, count=cap)
            if steps["n"] >= cap:
                stop_reason = "COUNT"
        except UcError as e:
            stop_reason = "ERROR"
            self._last_error = str(e)
        finally:
            self.uc.hook_del(h_code)
            if h_write is not None:
                self.uc.hook_del(h_write)

        return {
            "pc": self.get_register("RIP"),
            "steps": steps["n"],
            "stop_reason": stop_reason,
            "registers": {r: self.get_register(r) for r in _ALL_REGS},
            "trace": executed if trace else [],
            "mem_writes": mem_writes if trace else [],
        }
