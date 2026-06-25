"""Unicorn-based x86-64 emulation session with lazy mapping from Ghidra."""

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

from .registers import resolve_register


VALID_HOOK_ACTIONS = frozenset({"return_const", "skip", "log", "trap"})


@dataclass
class Hook:
    action: str
    return_value: int | None = None
    mem_writes: list[dict] | None = None

    def __post_init__(self):
        if self.action not in VALID_HOOK_ACTIONS:
            raise ValueError(
                f"unknown hook action: {self.action!r} "
                f"(valid: {sorted(VALID_HOOK_ACTIONS)})")
        if self.mem_writes is not None and self.action != "return_const":
            raise ValueError("mem_writes are only allowed on the 'return_const' action")
        if self.return_value is not None and self.action != "return_const":
            raise ValueError(
                f"return_value has no effect on action={self.action!r}")
        if self.mem_writes:
            for i, w in enumerate(self.mem_writes):
                if not (isinstance(w.get("address"), int)
                        and isinstance(w.get("hex"), str)
                        and len(w) == 2):
                    raise ValueError(
                        f"mem_writes[{i}]: expected {{address: int, hex: str}}, "
                        f"got keys {set(w)!r}")
                try:
                    bytes.fromhex(w["hex"])
                except ValueError:
                    raise ValueError(
                        f'mem_writes[{i}]: "hex" is not valid hex: {w["hex"]!r}')

try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UcError
    _HAVE_UNICORN = True
except ImportError:
    _HAVE_UNICORN = False


_TRACE_CAP = 100000
_ALL_REGS = ("RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RSP", "RBP", "RIP",
             "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")

SENTINEL_ADDR = 0x0000DEAD0000C0DE      # unmapped; "ran to completion" return target

_CALL_STACK_BASE = 0x7ffff0000000
_CALL_STACK_SIZE = 0x100000
_CALL_ARGS_SPLIT = 0x40000  # low 256 KiB of scratch region for bytes-args; stack frame lives above


_REDIRECT_CAP = 10_000


class StopReason(str, Enum):
    """The closed set of stop_reason values returned by UnicornSession.run().

    Shared constants (imported by the bridge and CLI consumers) so the six
    states are compared by name rather than by re-typed string literals, where
    a typo would be a silent misclassification. success is only DONE.
    """
    DONE = "DONE"
    COUNT = "COUNT"
    ERROR = "ERROR"
    LAZY_FETCH_FAILED = "LAZY_FETCH_FAILED"
    LAZY_CAP_REACHED = "LAZY_CAP_REACHED"
    HOOK_TRAP = "HOOK_TRAP"
    REDIRECT_STORM = "REDIRECT_STORM"
    UNMAPPED = "UNMAPPED"


class UnicornSession:
    PAGE = 0x1000

    def __init__(self, byte_provider: Optional[Callable[[int, int], bytes]] = None):
        if not _HAVE_UNICORN:
            raise RuntimeError("unicorn not installed; pip install ghydramcp[unicorn]")
        self._uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.byte_provider = byte_provider
        self._mapped: set[int] = set()
        self._hooks: dict[int, Hook] = {}

    def _ensure_mapped(self, address: int, length: int) -> None:
        start = address & ~(self.PAGE - 1)
        end = (address + length + self.PAGE - 1) & ~(self.PAGE - 1)
        for page in range(start, end, self.PAGE):
            if page not in self._mapped:
                self._uc.mem_map(page, self.PAGE)
                self._mapped.add(page)

    def set_hook(self, address: int, hook: Hook) -> None:
        self._hooks[address] = hook

    def clear_hook(self, address: int) -> bool:
        return self._hooks.pop(address, None) is not None

    def list_hooks(self) -> dict:
        return dict(self._hooks)

    def map_bytes(self, address: int, data: bytes) -> None:
        self._ensure_mapped(address, len(data))
        self._uc.mem_write(address, data)

    def read_memory(self, address: int, length: int) -> bytes:
        return bytes(self._uc.mem_read(address, length))

    def set_register(self, name: str, value: int) -> None:
        self._uc.reg_write(resolve_register(name), value)

    def get_register(self, name: str) -> int:
        return self._uc.reg_read(resolve_register(name))

    def simulate_ret(self, return_value: int | None = None) -> None:
        """Pop the return address off the stack into RIP (and optionally set RAX).

        Mirrors a ret: RIP = [RSP]; RSP += 8. Used by return_const/skip hooks.
        The stack memory must be mapped; an unmapped RSP surfaces as the
        underlying UcError.
        """
        rsp = self.get_register("RSP")
        ret_addr = int.from_bytes(self.read_memory(rsp, 8), "little")
        self.set_register("RIP", ret_addr)
        self.set_register("RSP", rsp + 8)
        if return_value is not None:
            self.set_register("RAX", return_value)

    def call(self, func_addr: int, args: list, convention: str,
             count: int = 1000000, trace: bool = False) -> dict:
        from . import calling_convention as cc
        cc.validate_args(args)
        reg_names = cc.arg_registers(convention)
        ret_reg = cc.return_register(convention)

        # Pre-resolve bytes args (validate_args already verified hex is valid).
        bytes_data = [bytes.fromhex(arg["bytes"]) for arg in args if isinstance(arg, dict)]
        aligned_sizes = [(len(d) + 15) & ~15 for d in bytes_data]
        if sum(aligned_sizes) > _CALL_ARGS_SPLIT:
            raise ValueError(
                f"bytes args exceed scratch budget ({_CALL_ARGS_SPLIT} bytes)")

        # All validation done; safe to mutate emulator state from here.
        self.map_bytes(_CALL_STACK_BASE, b"\x00" * _CALL_STACK_SIZE)

        args_cursor = _CALL_STACK_BASE
        resolved: list[int] = []
        bytes_iter = iter(zip(bytes_data, aligned_sizes))
        for arg in args:
            if isinstance(arg, dict):
                data, aligned_size = next(bytes_iter)
                self._uc.mem_write(args_cursor, data)
                resolved.append(args_cursor)
                args_cursor += aligned_size
            else:
                resolved.append(arg)

        reg_args = resolved[:len(reg_names)]
        stack_args = resolved[len(reg_names):]

        rsp_top = _CALL_STACK_BASE + _CALL_STACK_SIZE - 0x1000
        final_rsp = cc.aligned_call_frame(rsp_top, convention, len(stack_args))
        for i, val in enumerate(stack_args):
            self._uc.mem_write(final_rsp + 8 + i * 8,
                               int(val).to_bytes(8, "little", signed=val < 0))
        self._uc.mem_write(final_rsp, SENTINEL_ADDR.to_bytes(8, "little"))
        self.set_register("RSP", final_rsp)

        for name, val in zip(reg_names, reg_args):
            self.set_register(name, val & 0xffffffffffffffff)

        self.set_register("RIP", func_addr)
        state = self.run(begin=func_addr, until=0, count=count, trace=trace)

        return {
            "return_value": self.get_register(ret_reg),
            "convention": convention,
            "args_passed": resolved,
            "stop_reason": state["stop_reason"],
            "last_error": state["last_error"],
            "registers": state["registers"],
            "trace": state["trace"],
            "mem_writes": state["mem_writes"],
            "hook_log": state["hook_log"],
            "pc": state["pc"],
        }

    def run(self, begin, until=0, count=100000, timeout=0, trace=False,
            max_lazy_pages=4096):
        from unicorn import (UC_HOOK_CODE, UC_HOOK_MEM_WRITE,
                             UC_HOOK_MEM_UNMAPPED, UC_MEM_FETCH_UNMAPPED, UcError)
        steps = {"n": 0}
        executed: list[int] = []
        mem_writes: list[dict] = []
        hook_log: list[dict] = []
        trace_trunc = {"hit": False}
        ctrl = {"redirect": False, "trap": False, "hook_error": None}

        def _code_hook(uc, address, size, _user):
            hook = self._hooks.get(address)
            if hook is not None:
                if hook.action == "log":
                    hook_log.append({"address": address})
                elif hook.action == "trap":
                    ctrl["trap"] = True
                    uc.emu_stop()
                    return
                elif hook.action in ("return_const", "skip"):
                    try:
                        if hook.action == "return_const" and hook.mem_writes:
                            for w in hook.mem_writes:
                                data = bytes.fromhex(w["hex"])
                                self._ensure_mapped(w["address"], len(data))
                                uc.mem_write(w["address"], data)
                        rv = hook.return_value if hook.action == "return_const" else None
                        self.simulate_ret(rv)
                    except (UcError, ValueError) as e:
                        ctrl["hook_error"] = str(e)
                        uc.emu_stop()
                        return
                    ctrl["redirect"] = True
                    uc.emu_stop()
                    return
                else:
                    # Hook.__post_init__ prevents unknown actions; guard against future regressions.
                    ctrl["hook_error"] = f"unhandled hook action: {hook.action!r}"
                    uc.emu_stop()
                    return
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
        sentinel_done = {"hit": False}

        def _unmapped_hook(uc, access, address, size, value, _user):
            if access == UC_MEM_FETCH_UNMAPPED and address == SENTINEL_ADDR:
                sentinel_done["hit"] = True
                # return False causes UcError; sentinel_done flag disambiguates
                # this intentional stop from a real fault in the outer handler.
                return False
            page = address & ~(self.PAGE - 1)
            if page in self._mapped or self.byte_provider is None:
                return False
            if lazy["n"] >= max_lazy_pages:
                lazy_fail["reason"] = StopReason.LAZY_CAP_REACHED
                lazy_fail["msg"] = (f"lazy page cap ({max_lazy_pages}) reached at "
                                    f"{hex(page)}; raise max_lazy_pages")
                return False
            try:
                data = self.byte_provider(page, self.PAGE)
            except Exception as e:
                lazy_fail["reason"] = StopReason.LAZY_FETCH_FAILED
                lazy_fail["msg"] = f"lazy fetch failed at {hex(page)}: {e}"
                return False
            if not data:
                lazy_fail["reason"] = StopReason.LAZY_FETCH_FAILED
                lazy_fail["msg"] = f"no image bytes at {hex(page)}"
                return False
            self._ensure_mapped(page, self.PAGE)
            self._uc.mem_write(page, data[:self.PAGE])
            lazy["n"] += 1
            return True

        h_code = self._uc.hook_add(UC_HOOK_CODE, _code_hook)
        h_write = self._uc.hook_add(UC_HOOK_MEM_WRITE, _write_hook) if trace else None
        h_unmapped = self._uc.hook_add(UC_HOOK_MEM_UNMAPPED, _unmapped_hook)
        stop_reason = StopReason.DONE
        last_error = None
        cap = min(count if count > 0 else 5_000_000, 5_000_000)
        current = begin
        remaining = cap
        redirects = 0
        try:
            while remaining > 0:
                ctrl["redirect"] = False
                ctrl["trap"] = False
                ctrl["hook_error"] = None
                before = steps["n"]
                try:
                    self._uc.emu_start(current, until, timeout=timeout, count=remaining)
                except UcError as e:
                    if sentinel_done["hit"]:
                        stop_reason = StopReason.DONE
                        last_error = None
                    elif lazy_fail["reason"] is not None:
                        stop_reason = lazy_fail["reason"]
                        last_error = lazy_fail["msg"]
                    else:
                        stop_reason = StopReason.ERROR
                        last_error = str(e)
                    break
                remaining -= (steps["n"] - before)
                if ctrl["hook_error"]:
                    stop_reason = StopReason.ERROR
                    last_error = f"hook callback error: {ctrl['hook_error']}"
                    break
                if ctrl["trap"]:
                    stop_reason = StopReason.HOOK_TRAP
                    break
                if ctrl["redirect"]:
                    redirects += 1
                    if redirects >= _REDIRECT_CAP:
                        stop_reason = StopReason.REDIRECT_STORM
                        last_error = (
                            f"redirect storm: {redirects} hook redirects without progress "
                            f"(last RIP={hex(self.get_register('RIP'))})")
                        break
                    current = self.get_register("RIP")
                    continue
                # clean stop: until reached, or count exhausted
                if steps["n"] >= cap:
                    stop_reason = StopReason.COUNT
                break
        finally:
            self._uc.hook_del(h_code)
            if h_write is not None:
                self._uc.hook_del(h_write)
            self._uc.hook_del(h_unmapped)

        return {
            "pc": self.get_register("RIP"),
            "steps": steps["n"],
            "stop_reason": stop_reason,
            "last_error": last_error,
            "registers": {r: self.get_register(r) for r in _ALL_REGS},
            "trace": executed if trace else [],
            "mem_writes": mem_writes if trace else [],
            "hook_log": hook_log,
            "trace_truncated": trace_trunc["hit"],
        }
