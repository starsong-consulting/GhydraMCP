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


class StopReason:
    """The closed set of ``stop_reason`` values returned by ``UnicornSession.run()``.

    Shared constants (imported by the bridge and CLI consumers) so the four
    states are compared by name rather than by re-typed string literals, where
    a typo would be a silent misclassification. ``success`` is only ``DONE``.
    """
    DONE = "DONE"
    COUNT = "COUNT"
    ERROR = "ERROR"
    LAZY_FETCH_FAILED = "LAZY_FETCH_FAILED"
    LAZY_CAP_REACHED = "LAZY_CAP_REACHED"


class UnicornSession:
    PAGE = 0x1000

    def __init__(self, byte_provider: Optional[Callable[[int, int], bytes]] = None):
        if not _HAVE_UNICORN:
            raise RuntimeError("unicorn not installed; pip install ghydramcp[unicorn]")
        self._uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.byte_provider = byte_provider
        self._mapped: set[int] = set()

    def _ensure_mapped(self, address: int, length: int) -> None:
        start = address & ~(self.PAGE - 1)
        end = (address + length + self.PAGE - 1) & ~(self.PAGE - 1)
        for page in range(start, end, self.PAGE):
            if page not in self._mapped:
                self._uc.mem_map(page, self.PAGE)
                self._mapped.add(page)

    def map_bytes(self, address: int, data: bytes) -> None:
        self._ensure_mapped(address, len(data))
        self._uc.mem_write(address, data)

    def read_memory(self, address: int, length: int) -> bytes:
        return bytes(self._uc.mem_read(address, length))

    def set_register(self, name: str, value: int) -> None:
        self._uc.reg_write(resolve_register(name), value)

    def get_register(self, name: str) -> int:
        return self._uc.reg_read(resolve_register(name))

    def run(self, begin, until=0, count=100000, timeout=0, trace=False,
            max_lazy_pages=4096):
        from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_UNMAPPED
        steps = {"n": 0}
        executed: list[int] = []
        mem_writes: list[dict] = []
        trace_trunc = {"hit": False}

        def _code_hook(uc, address, size, _user):
            steps["n"] += 1
            if trace:
                if len(executed) < _TRACE_CAP:
                    executed.append(address)
                else:
                    trace_trunc["hit"] = True

        def _write_hook(uc, access, address, size, value, _user):
            if trace:
                if len(mem_writes) < _TRACE_CAP:
                    mem_writes.append({"address": address, "size": size, "value": value})
                else:
                    trace_trunc["hit"] = True

        lazy = {"n": 0}
        lazy_fail = {"msg": None, "reason": None}

        def _unmapped_hook(uc, access, address, size, value, _user):
            page = address & ~(self.PAGE - 1)
            if page in self._mapped or self.byte_provider is None:
                return False  # already mapped, or no provider -> plain unmapped fault (ERROR)
            if lazy["n"] >= max_lazy_pages:
                lazy_fail["reason"] = StopReason.LAZY_CAP_REACHED
                lazy_fail["msg"] = (f"lazy page cap ({max_lazy_pages}) reached at "
                                    f"{hex(page)}; raise max_lazy_pages")
                return False
            try:
                data = self.byte_provider(page, self.PAGE)
            except Exception as e:  # boundary catch: must not cross emu_start
                lazy_fail["reason"] = StopReason.LAZY_FETCH_FAILED
                lazy_fail["msg"] = f"lazy fetch failed at {hex(page)}: {e}"
                return False
            if not data:
                lazy_fail["reason"] = StopReason.LAZY_FETCH_FAILED
                lazy_fail["msg"] = f"no image bytes at {hex(page)}"
                return False
            self._ensure_mapped(page, self.PAGE)   # maps the page + records it in _mapped
            self._uc.mem_write(page, data[:self.PAGE])
            lazy["n"] += 1
            return True  # retry the faulting access

        h_code = self._uc.hook_add(UC_HOOK_CODE, _code_hook)
        h_write = self._uc.hook_add(UC_HOOK_MEM_WRITE, _write_hook) if trace else None
        h_unmapped = (self._uc.hook_add(UC_HOOK_MEM_UNMAPPED, _unmapped_hook)
                      if self.byte_provider is not None else None)
        stop_reason = StopReason.DONE
        last_error = None
        cap = min(count if count > 0 else 5_000_000, 5_000_000)
        try:
            self._uc.emu_start(begin, until, timeout=timeout, count=cap)
            if steps["n"] >= cap:
                stop_reason = StopReason.COUNT
        except UcError as e:
            if lazy_fail["reason"] is not None:
                stop_reason = lazy_fail["reason"]
                last_error = lazy_fail["msg"]
            else:
                stop_reason = StopReason.ERROR
                last_error = str(e)
        finally:
            self._uc.hook_del(h_code)
            if h_write is not None:
                self._uc.hook_del(h_write)
            if h_unmapped is not None:
                self._uc.hook_del(h_unmapped)

        return {
            "pc": self.get_register("RIP"),
            "steps": steps["n"],
            "stop_reason": stop_reason,
            "last_error": last_error,
            "registers": {r: self.get_register(r) for r in _ALL_REGS},
            "trace": executed if trace else [],
            "mem_writes": mem_writes if trace else [],
            "trace_truncated": trace_trunc["hit"],
        }
