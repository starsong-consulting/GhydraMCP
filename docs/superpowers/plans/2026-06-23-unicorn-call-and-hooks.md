# Unicorn `call()` + Import Hooks Implementation Plan (Plan A)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add import/syscall hooking and a high-level `call(func, args)` primitive to the Unicorn (Python) engine, the bridge `unicorn_*` tools, and the `ghydra dynamic` CLI.

**Architecture:** Extend `ghydra/dynamic/unicorn_engine.py` with a per-session hook registry consulted inside the existing `UC_HOOK_CODE` callback, a shared `simulate_ret` helper, an unmapped-sentinel completion guard, and a `call()` method that marshals integer/pointer args per the x86-64 SysV/MS calling convention and runs to a synthetic return address. Calling-convention marshalling and stack-alignment math live in a new pure-function module (`ghydra/dynamic/calling_convention.py`) so they unit-test without Unicorn. The bridge and CLI gain thin wrappers. This is **Plan A** of two; the PCode/Java engine (Plan B) duplicates this now-proven contract afterward.

**Tech Stack:** Python 3.11+, Unicorn Engine (`unicorn`), pytest, Click, Rich. MCP via FastMCP (`bridge_mcp_hydra.py`).

## Global Constraints

- Python 3.11+ (`pip install -e .`); tests run via `python -m pytest -q` scoped to `tests/`. No live Ghidra required for any task in this plan.
- Unicorn is an optional dependency: any module that needs it must degrade gracefully when absent. Tests that need Unicorn start with `pytest.importorskip("unicorn")`; pure-function tests must NOT import unicorn.
- x86-64 only in v1. `call` supports **integer** and **pointer (`{"bytes": hex}`)** args only; reject everything else with an explicit message.
- Engine `run()` returns a dict whose `stop_reason` is one of the `StopReason` string constants in `unicorn_engine.py`. This plan adds `HOOK_TRAP` to that closed set; `COMPLETED` is **not** added here — `call()` completion uses the existing `DONE` constant (the bridge layer translates engine constants to the unified wire vocabulary in Plan B; within Plan A keep the engine's native `DONE`).
- The sentinel completion is signalled by stopping cleanly; in the engine's `run()`/`call()` dict it surfaces as `stop_reason == StopReason.DONE`.
- Hooks are session-scoped and wiped on a fresh `UnicornSession` (a new session has an empty registry). `call()` does NOT clear hooks.
- `mem_writes` side-effects are allowed on the `return_const` action only.
- Conventional-commit messages. Bump `BRIDGE_VERSION` in `bridge_mcp_hydra.py` from `v3.1.0-rc.3` to `v3.1.0-rc.4` (Task 9). `REQUIRED_API_VERSION` is unchanged. Update `CHANGELOG.md` (Task 9).
- Existing helpers to reuse (do not reinvent): `ghydra/dynamic/registers.py::resolve_register`, the bridge's `_get_unicorn_session`, `_unicorn_error`, `_apply_default_stack`, `_DEFAULT_STACK_BASE` (`0x7ffff0000000`), `_DEFAULT_STACK_SIZE` (`0x100000`).

---

## File Structure

- **Create** `ghydra/dynamic/calling_convention.py` — pure functions: convention arg-register tables, return register, stack-arg layout, 16-byte alignment math, arg validation. No unicorn import.
- **Create** `tests/test_calling_convention.py` — unit tests for the above (no unicorn).
- **Modify** `ghydra/dynamic/unicorn_engine.py` — add `HOOK_TRAP` constant, a `Hook` dataclass, the session hook registry + CRUD, `simulate_ret`, the sentinel guard in `_unmapped_hook`, hook dispatch in `_code_hook`, and the `call()` method.
- **Modify** `tests/test_unicorn_engine.py` — tests for hooks, `simulate_ret`, sentinel, and `call()`.
- **Modify** `bridge_mcp_hydra.py` — add `unicorn_hook_set`, `unicorn_hook_clear`, `unicorn_hook_list`, `unicorn_call` MCP tools; bump `BRIDGE_VERSION`.
- **Create** `tests/test_bridge_unicorn_hooks.py` — tests for the new bridge tools (monkeypatch the session registry; no live Ghidra).
- **Modify** `ghydra/cli/dynamic.py` — add `call` subcommand with inline `--hook` options.
- **Modify** `tests/test_dynamic_cli.py` — test for the `call` CLI subcommand.
- **Modify** `CHANGELOG.md` — user-facing entry.

---

### Task 1: Calling-convention pure functions — arg/return registers

**Files:**
- Create: `ghydra/dynamic/calling_convention.py`
- Test: `tests/test_calling_convention.py`

**Interfaces:**
- Produces:
  - `SUPPORTED_CONVENTIONS: set[str]` = `{"sysv", "ms"}`
  - `arg_registers(convention: str) -> list[str]` — ordered integer-arg register names. `"sysv"` → `["RDI","RSI","RDX","RCX","R8","R9"]`; `"ms"` → `["RCX","RDX","R8","R9"]`. Raises `ValueError` on an unsupported convention.
  - `return_register(convention: str) -> str` — `"RAX"` for both supported conventions; raises `ValueError` otherwise.

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_calling_convention.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'ghydra.dynamic.calling_convention'`

- [ ] **Step 3: Write minimal implementation**

```python
# ghydra/dynamic/calling_convention.py
"""Pure x86-64 calling-convention logic (no unicorn dependency).

Arg-register order, return register, stack-arg layout, and 16-byte stack
alignment for the high-level call() primitive. Unit-tested directly.
"""

SUPPORTED_CONVENTIONS = {"sysv", "ms"}

_ARG_REGISTERS = {
    "sysv": ["RDI", "RSI", "RDX", "RCX", "R8", "R9"],
    "ms": ["RCX", "RDX", "R8", "R9"],
}


def _check(convention: str) -> str:
    if convention not in SUPPORTED_CONVENTIONS:
        raise ValueError(
            f"unsupported calling convention: {convention!r} "
            f"(supported: {sorted(SUPPORTED_CONVENTIONS)})")
    return convention


def arg_registers(convention: str) -> list[str]:
    return list(_ARG_REGISTERS[_check(convention)])


def return_register(convention: str) -> str:
    _check(convention)
    return "RAX"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_calling_convention.py -q`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add ghydra/dynamic/calling_convention.py tests/test_calling_convention.py
git commit -m "feat(dynamic): calling-convention arg/return register tables"
```

---

### Task 2: Calling-convention arg validation

**Files:**
- Modify: `ghydra/dynamic/calling_convention.py`
- Test: `tests/test_calling_convention.py`

**Interfaces:**
- Produces:
  - `validate_args(args: list) -> None` — raises `ValueError` if any arg is not an `int` or a `{"bytes": <hex str>}` dict (exactly the single key `bytes`). Message names the offending index. A `bool` is NOT a valid int arg (reject — avoids `True`→1 surprises).

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_calling_convention.py
def test_validate_accepts_int_and_bytes():
    cc.validate_args([1, 0xdeadbeef, {"bytes": "41424300"}])  # no raise


def test_validate_rejects_float():
    with pytest.raises(ValueError, match=r"arg\[1\]"):
        cc.validate_args([1, 3.14])


def test_validate_rejects_bool():
    with pytest.raises(ValueError, match=r"arg\[0\]"):
        cc.validate_args([True])


def test_validate_rejects_bad_dict():
    with pytest.raises(ValueError, match=r"arg\[0\]"):
        cc.validate_args([{"ptr": "4142"}])
    with pytest.raises(ValueError, match=r"arg\[0\]"):
        cc.validate_args([{"bytes": "4142", "extra": 1}])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_calling_convention.py -q`
Expected: FAIL with `AttributeError: module ... has no attribute 'validate_args'`

- [ ] **Step 3: Write minimal implementation**

```python
# append to ghydra/dynamic/calling_convention.py
def validate_args(args: list) -> None:
    """Reject any arg that is not an int or a {"bytes": hex} dict (v1 scope)."""
    for i, arg in enumerate(args):
        if isinstance(arg, bool):
            raise ValueError(f"arg[{i}]: bool is not a valid integer arg")
        if isinstance(arg, int):
            continue
        if isinstance(arg, dict) and set(arg) == {"bytes"} and isinstance(arg["bytes"], str):
            continue
        raise ValueError(
            f"arg[{i}]: only int or {{\"bytes\": hex}} args are supported in v1 "
            f"(float/struct args are out of scope)")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_calling_convention.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add ghydra/dynamic/calling_convention.py tests/test_calling_convention.py
git commit -m "feat(dynamic): validate call args to int/bytes only"
```

---

### Task 3: Stack layout & 16-byte alignment math

**Files:**
- Modify: `ghydra/dynamic/calling_convention.py`
- Test: `tests/test_calling_convention.py`

**Interfaces:**
- Produces:
  - `aligned_call_frame(rsp: int, convention: str, n_stack_args: int) -> int` — given the current RSP, the convention, and how many integer args spill to the stack, return the new RSP **after** pushing stack args, the MS shadow space, alignment padding, and the 8-byte sentinel return address, such that at callee entry `RSP % 16 == 8`. The caller writes the stack args / sentinel into `[returned_rsp, old_rsp)` separately; this function only computes the final RSP. MS adds 32 bytes of shadow space below the stack args.

The math: total below-old-RSP bytes = `8 * n_stack_args` (stack args) + (`32` if MS else `0`) (shadow) + `8` (sentinel). Pad so the **sentinel** lands such that `final_rsp % 16 == 8`. Concretely: compute `body = 8*n_stack_args + (32 if ms else 0)`; the sentinel sits at `final_rsp`; require `final_rsp % 16 == 8`; `final_rsp = align_down(rsp - body - 8, 16) + 8` ... but must stay ≤ `rsp - body - 8`. Use: `target = rsp - body - 8; final_rsp = target - ((target - 8) % 16)`.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_calling_convention.py
def test_alignment_no_stack_args_sysv():
    # Callee entry must satisfy rsp % 16 == 8.
    rsp = 0x7ffffffff000  # 16-aligned start
    final = cc.aligned_call_frame(rsp, "sysv", 0)
    assert final % 16 == 8
    assert final < rsp                       # frame grew down
    assert rsp - final >= 8                   # at least the sentinel


def test_alignment_with_stack_args_sysv():
    rsp = 0x7ffffffff000
    final = cc.aligned_call_frame(rsp, "sysv", 3)
    assert final % 16 == 8
    # room for 3 stack args (24 bytes) + sentinel (8) at minimum
    assert rsp - final >= 8 * 3 + 8


def test_alignment_ms_reserves_shadow_space():
    rsp = 0x7ffffffff000
    final_ms = cc.aligned_call_frame(rsp, "ms", 0)
    final_sysv = cc.aligned_call_frame(rsp, "sysv", 0)
    assert final_ms % 16 == 8
    # MS reserves 32 bytes of shadow that SysV does not
    assert (rsp - final_ms) - (rsp - final_sysv) == 32


def test_alignment_from_unaligned_rsp():
    # A non-16-aligned starting RSP must still yield entry rsp % 16 == 8.
    for start in (0x7ffffffff000, 0x7fffffffeff8, 0x7fffffffefe0, 0x7fffffffefe9):
        assert cc.aligned_call_frame(start, "sysv", 2) % 16 == 8
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_calling_convention.py -q`
Expected: FAIL with `AttributeError: ... 'aligned_call_frame'`

- [ ] **Step 3: Write minimal implementation**

```python
# append to ghydra/dynamic/calling_convention.py
def aligned_call_frame(rsp: int, convention: str, n_stack_args: int) -> int:
    """Final RSP after laying out stack args + shadow + sentinel.

    Guarantees callee-entry ABI alignment: rsp % 16 == 8 (the 8-byte sentinel
    return address occupies the low 8 bytes of a 16-aligned frame).
    """
    _check(convention)
    body = 8 * n_stack_args + (32 if convention == "ms" else 0)
    target = rsp - body - 8           # tentative sentinel slot
    final_rsp = target - ((target - 8) % 16)   # round down so final % 16 == 8
    return final_rsp
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_calling_convention.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add ghydra/dynamic/calling_convention.py tests/test_calling_convention.py
git commit -m "feat(dynamic): 16-byte aligned call-frame layout math"
```

---

### Task 4: `HOOK_TRAP` constant + `Hook` dataclass + registry CRUD

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py:19-32` (the `StopReason` class) and the `UnicornSession` body
- Test: `tests/test_unicorn_engine.py`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `StopReason.HOOK_TRAP = "HOOK_TRAP"` (new constant in the existing `StopReason` class).
  - `Hook` dataclass: `action: str` (one of `"return_const"`, `"skip"`, `"log"`, `"trap"`), `return_value: int | None = None`, `mem_writes: list[dict] | None = None` (each `{"address": int, "hex": str}`).
  - `VALID_HOOK_ACTIONS: frozenset[str]` = `{"return_const", "skip", "log", "trap"}`.
  - `UnicornSession.set_hook(address: int, hook: Hook) -> None` — store in `self._hooks` (a `dict[int, Hook]`, created empty in `__init__`). Validates `hook.action in VALID_HOOK_ACTIONS`, and that `mem_writes` is only present when `action == "return_const"`; raises `ValueError` otherwise.
  - `UnicornSession.clear_hook(address: int) -> bool` — remove; return `True` if one was present.
  - `UnicornSession.list_hooks() -> dict[int, Hook]` — a copy of the registry.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_unicorn_engine.py
from ghydra.dynamic.unicorn_engine import Hook, VALID_HOOK_ACTIONS, StopReason


def test_hook_trap_constant_exists():
    assert StopReason.HOOK_TRAP == "HOOK_TRAP"


def test_set_list_clear_hook():
    s = UnicornSession()
    s.set_hook(0x401000, Hook(action="skip"))
    assert 0x401000 in s.list_hooks()
    assert s.list_hooks()[0x401000].action == "skip"
    assert s.clear_hook(0x401000) is True
    assert s.clear_hook(0x401000) is False
    assert 0x401000 not in s.list_hooks()


def test_set_hook_rejects_unknown_action():
    s = UnicornSession()
    with pytest.raises(ValueError, match="action"):
        s.set_hook(0x401000, Hook(action="explode"))


def test_mem_writes_only_on_return_const():
    s = UnicornSession()
    with pytest.raises(ValueError, match="mem_writes"):
        s.set_hook(0x401000, Hook(action="skip", mem_writes=[{"address": 0x1000, "hex": "41"}]))
    # allowed on return_const
    s.set_hook(0x402000, Hook(action="return_const", return_value=0,
                              mem_writes=[{"address": 0x1000, "hex": "41"}]))


def test_fresh_session_has_empty_registry():
    assert UnicornSession().list_hooks() == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_unicorn_engine.py -q`
Expected: FAIL with `ImportError: cannot import name 'Hook'`

- [ ] **Step 3: Write minimal implementation**

In `ghydra/dynamic/unicorn_engine.py`, add `HOOK_TRAP` to the `StopReason` class (after `LAZY_CAP_REACHED`):

```python
    LAZY_CAP_REACHED = "LAZY_CAP_REACHED"
    HOOK_TRAP = "HOOK_TRAP"
```

Add imports and the dataclass near the top (after the existing `from typing import` line):

```python
from dataclasses import dataclass


VALID_HOOK_ACTIONS = frozenset({"return_const", "skip", "log", "trap"})


@dataclass
class Hook:
    action: str
    return_value: int | None = None
    mem_writes: list[dict] | None = None
```

In `UnicornSession.__init__`, add the registry (after `self._mapped: set[int] = set()`):

```python
        self._hooks: dict[int, Hook] = {}
```

Add the CRUD methods to `UnicornSession`:

```python
    def set_hook(self, address: int, hook: Hook) -> None:
        if hook.action not in VALID_HOOK_ACTIONS:
            raise ValueError(f"unknown hook action: {hook.action!r} "
                             f"(valid: {sorted(VALID_HOOK_ACTIONS)})")
        if hook.mem_writes is not None and hook.action != "return_const":
            raise ValueError("mem_writes are only allowed on the 'return_const' action")
        self._hooks[address] = hook

    def clear_hook(self, address: int) -> bool:
        return self._hooks.pop(address, None) is not None

    def list_hooks(self) -> dict:
        return dict(self._hooks)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_unicorn_engine.py -q`
Expected: PASS (existing tests + 5 new)

- [ ] **Step 5: Commit**

```bash
git add ghydra/dynamic/unicorn_engine.py tests/test_unicorn_engine.py
git commit -m "feat(dynamic): unicorn hook registry CRUD + HOOK_TRAP constant"
```

---

### Task 5: `simulate_ret` helper

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py` (add method to `UnicornSession`)
- Test: `tests/test_unicorn_engine.py`

**Interfaces:**
- Consumes: `set_register`/`get_register`/`read_memory`/`map_bytes` (existing).
- Produces:
  - `UnicornSession.simulate_ret(return_value: int | None = None) -> None` — read RSP; read 8 bytes at RSP (little-endian) as the return address; set RIP to it; set RSP += 8; if `return_value is not None`, set RAX to it. The RSP/return-addr memory must already be mapped (caller's responsibility); if unmapped, the underlying `mem_read` raises `unicorn.UcError`, which propagates.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_unicorn_engine.py
def test_simulate_ret_pops_return_address_and_sets_rax():
    s = UnicornSession()
    stack = 0x7ffff0000000
    s.map_bytes(stack, b"\x00" * 0x1000)
    ret_addr = 0x401234
    s.set_register("RSP", stack + 0x100)
    s.map_bytes(stack + 0x100, ret_addr.to_bytes(8, "little"))  # return addr on stack
    s.simulate_ret(return_value=0xcafe)
    assert s.get_register("RIP") == ret_addr
    assert s.get_register("RSP") == stack + 0x108
    assert s.get_register("RAX") == 0xcafe


def test_simulate_ret_leaves_rax_untouched_when_none():
    s = UnicornSession()
    stack = 0x7ffff0000000
    s.map_bytes(stack, b"\x00" * 0x1000)
    s.set_register("RSP", stack + 0x100)
    s.set_register("RAX", 0x1111)
    s.map_bytes(stack + 0x100, (0x401234).to_bytes(8, "little"))
    s.simulate_ret()  # no return value
    assert s.get_register("RAX") == 0x1111
    assert s.get_register("RIP") == 0x401234
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_unicorn_engine.py -k simulate_ret -q`
Expected: FAIL with `AttributeError: 'UnicornSession' object has no attribute 'simulate_ret'`

- [ ] **Step 3: Write minimal implementation**

```python
# add to UnicornSession in ghydra/dynamic/unicorn_engine.py
    def simulate_ret(self, return_value: int | None = None) -> None:
        """Pop the return address off the stack into RIP (and optionally set RAX).

        Mirrors a `ret`: RIP = [RSP]; RSP += 8. Used by return_const/skip hooks
        and by call() teardown. The stack memory must be mapped; an unmapped RSP
        surfaces as the underlying UcError.
        """
        rsp = self.get_register("RSP")
        ret_addr = int.from_bytes(self.read_memory(rsp, 8), "little")
        self.set_register("RIP", ret_addr)
        self.set_register("RSP", rsp + 8)
        if return_value is not None:
            self.set_register("RAX", return_value)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_unicorn_engine.py -k simulate_ret -q`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add ghydra/dynamic/unicorn_engine.py tests/test_unicorn_engine.py
git commit -m "feat(dynamic): simulate_ret helper for hooks and call teardown"
```

---

### Task 6: Hook dispatch in the code hook (`return_const`/`skip`/`log`/`trap`)

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py` (the `run()` method — `_code_hook` and the result assembly)
- Test: `tests/test_unicorn_engine.py`

**Interfaces:**
- Consumes: `self._hooks`, `simulate_ret`, `StopReason.HOOK_TRAP`.
- Produces: hook actions fire inside `_code_hook` during `run()`. A `trap` stops the run and yields `stop_reason == "HOOK_TRAP"`. `return_const`/`skip` rewrite RIP/RSP so the call target never executes. `log` appends `{"address": pc, "action": "log"}` to the run result's existing `trace` machinery via a new `hook_log` list in the returned state.

Behaviour detail: in `_code_hook`, look up `self._hooks.get(address)`. If present:
- `log`: append `{"address": address}` to a `hook_log` list (always, regardless of `trace`), then return (instruction executes normally).
- `return_const`: apply `mem_writes` (if any), then `simulate_ret(hook.return_value)`, then `uc.emu_stop()` is NOT called — instead, because we rewrote RIP, we must prevent the current (hooked) instruction from executing. Use `uc.emu_stop()` + restart is complex; instead set a pending flag and stop, re-entering is out of scope. **Simplest correct approach: stop emulation at the hook and let `call()`/`run()` resume.** For `run()` semantics we instead apply the ret and stop with a dedicated reason. To keep `run()` behaviour intact, dispatch is: `return_const`/`skip` rewrite state then `uc.emu_stop()` with an internal `hook_redirect` flag so the run loop in `call()` can continue; for plain `run()` a redirect simply stops cleanly as `DONE`-equivalent is wrong. **Resolution (used here):** `return_const`/`skip` perform the redirect and call `uc.emu_stop()`, recording `hook_action["redirect"] = True`; `run()` surfaces this as `stop_reason == StopReason.HOOK_TRAP` only for `trap`. For `return_const`/`skip`, after `emu_stop`, `run()` checks the redirect flag and **re-enters `emu_start` from the new RIP** in a bounded loop (max redirects = `count`). This keeps one engine entry-point.

Because re-entrancy adds real complexity, this task implements the bounded re-entry loop in `run()`:

```
remaining = cap
while remaining > 0:
    run emu_start(begin=current RIP, until, count=remaining)
    if stopped due to trap: stop_reason = HOOK_TRAP; break
    if stopped due to redirect (return_const/skip): begin = new RIP; remaining -= steps_used; continue
    else: break   # normal until/COUNT/fault
```

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_unicorn_engine.py
def _call_stub_program():
    """A program: call <import thunk>; the thunk is at an address we hook.

    code @ base: mov rax, 0 ; call rel32 -> import@base+0x100 ; nop (return site)
    We hook import@base+0x100 with return_const so the call never executes there.
    """
    base = 0x140075000
    # e8 <rel32> = call ; target = base+0x100 ; instruction at base, len 5 -> next = base+5
    rel = (0x100 - 5) & 0xffffffff
    code = b"\xe8" + rel.to_bytes(4, "little") + b"\x90"   # call import ; nop
    return base, code


def test_return_const_hook_stubs_the_call():
    s = UnicornSession()
    base, code = _call_stub_program()
    s.map_bytes(base, code)
    s._apply_stack_for_test = None  # documentation: stack mapped below
    stack = 0x7ffff0000000
    s.map_bytes(stack, b"\x00" * 0x2000)
    s.set_register("RSP", stack + 0x1000)
    s.set_register("RIP", base)
    s.set_hook(base + 0x100, Hook(action="return_const", return_value=0x2a))
    # run until the return site (the nop after the call)
    state = s.run(begin=base, until=base + 5, count=50)
    assert state["stop_reason"] == "DONE"
    assert s.get_register("RAX") == 0x2a       # return_const set RAX


def test_trap_hook_stops_with_hook_trap():
    s = UnicornSession()
    base, code = _call_stub_program()
    s.map_bytes(base, code)
    stack = 0x7ffff0000000
    s.map_bytes(stack, b"\x00" * 0x2000)
    s.set_register("RSP", stack + 0x1000)
    s.set_register("RIP", base)
    s.set_hook(base + 0x100, Hook(action="trap"))
    state = s.run(begin=base, until=base + 5, count=50)
    assert state["stop_reason"] == "HOOK_TRAP"
    assert state["pc"] == base + 0x100         # stopped AT the trap target


def test_log_hook_records_and_continues():
    s = UnicornSession()
    base = 0x140075000
    s.map_bytes(base, b"\x90\x90")             # nop ; nop
    s.set_register("RIP", base)
    s.set_hook(base, Hook(action="log"))
    state = s.run(begin=base, until=base + 2, count=10)
    assert state["stop_reason"] == "DONE"
    assert any(e["address"] == base for e in state["hook_log"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_unicorn_engine.py -k "hook" -q`
Expected: FAIL (`KeyError: 'hook_log'` / trap not honoured)

- [ ] **Step 3: Write minimal implementation**

Rewrite `UnicornSession.run()` to dispatch hooks. Key changes inside the existing method:

```python
    def run(self, begin, until=0, count=100000, timeout=0, trace=False,
            max_lazy_pages=4096):
        from unicorn import (UC_HOOK_CODE, UC_HOOK_MEM_WRITE,
                             UC_HOOK_MEM_UNMAPPED, UC_MEM_FETCH_UNMAPPED, UcError)
        steps = {"n": 0}
        executed: list[int] = []
        mem_writes: list[dict] = []
        hook_log: list[dict] = []
        trace_trunc = {"hit": False}
        # control signals the code hook raises for the re-entry loop
        ctrl = {"redirect": False, "trap": False}

        def _code_hook(uc, address, size, _user):
            hook = self._hooks.get(address)
            if hook is not None:
                if hook.action == "log":
                    hook_log.append({"address": address})
                    # falls through: instruction executes normally
                elif hook.action == "trap":
                    ctrl["trap"] = True
                    uc.emu_stop()
                    return
                elif hook.action in ("return_const", "skip"):
                    if hook.action == "return_const" and hook.mem_writes:
                        for w in hook.mem_writes:
                            data = bytes.fromhex(w["hex"])
                            self._ensure_mapped(w["address"], len(data))
                            uc.mem_write(w["address"], data)
                    rv = hook.return_value if hook.action == "return_const" else None
                    self.simulate_ret(rv)        # rewrites RIP/RSP (and RAX)
                    ctrl["redirect"] = True
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

        def _unmapped_hook(uc, access, address, size, value, _user):
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
        h_unmapped = (self._uc.hook_add(UC_HOOK_MEM_UNMAPPED, _unmapped_hook)
                      if self.byte_provider is not None else None)
        stop_reason = StopReason.DONE
        last_error = None
        cap = min(count if count > 0 else 5_000_000, 5_000_000)
        current = begin
        remaining = cap
        try:
            while remaining > 0:
                ctrl["redirect"] = False
                ctrl["trap"] = False
                before = steps["n"]
                try:
                    self._uc.emu_start(current, until, timeout=timeout, count=remaining)
                except UcError as e:
                    if lazy_fail["reason"] is not None:
                        stop_reason = lazy_fail["reason"]
                        last_error = lazy_fail["msg"]
                    else:
                        stop_reason = StopReason.ERROR
                        last_error = str(e)
                    break
                remaining -= (steps["n"] - before)
                if ctrl["trap"]:
                    stop_reason = StopReason.HOOK_TRAP
                    break
                if ctrl["redirect"]:
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
            "hook_log": hook_log,
            "trace_truncated": trace_trunc["hit"],
        }
```

Note: existing callers of `run()` that read the result dict are unaffected (new `hook_log` key is additive). The `from unicorn import ...` inside `run()` now also imports `UC_MEM_FETCH_UNMAPPED` and `UcError` (used in Task 7 and here).

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_unicorn_engine.py -q`
Expected: PASS (all existing tests + the 3 new hook tests). Existing tests must still pass — verify `test_run_two_nops...`, `test_run_hits_instruction_cap_returns_count`, `test_lazy_*` are green.

- [ ] **Step 5: Commit**

```bash
git add ghydra/dynamic/unicorn_engine.py tests/test_unicorn_engine.py
git commit -m "feat(dynamic): hook dispatch in unicorn run loop (return_const/skip/log/trap)"
```

---

### Task 7: Sentinel completion guard in the unmapped hook

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py` (`run()` — `_unmapped_hook` + exception handling) and a module-level `SENTINEL_ADDR`
- Test: `tests/test_unicorn_engine.py`

**Interfaces:**
- Produces:
  - Module constant `SENTINEL_ADDR = 0x0000DEAD0000C0DE` (unmapped, outside the image and the default stack region). `SENTINEL_PAGE = SENTINEL_ADDR & ~(PAGE-1)`.
  - When PC reaches the sentinel, the fetch faults into `_unmapped_hook`; the guard (gated on `access == UC_MEM_FETCH_UNMAPPED` and `page == SENTINEL_PAGE`) sets a completion signal and returns `False`. The resulting `UcError` is translated to `stop_reason == StopReason.DONE`, with **priority over** `lazy_fail`.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_unicorn_engine.py
from ghydra.dynamic.unicorn_engine import SENTINEL_ADDR


def test_run_to_sentinel_completes_cleanly():
    s = UnicornSession()
    base = 0x140075000
    # ret  (c3)  -> pops return addr (the sentinel) into RIP, then fetch-faults there
    s.map_bytes(base, b"\xc3")
    stack = 0x7ffff0000000
    s.map_bytes(stack, b"\x00" * 0x1000)
    rsp = stack + 0x100
    s.set_register("RSP", rsp)
    # place the sentinel as the return address on the stack
    s.map_bytes(rsp, SENTINEL_ADDR.to_bytes(8, "little"))
    s.set_register("RIP", base)
    state = s.run(begin=base, until=0, count=50)
    assert state["stop_reason"] == "DONE"
    assert state["last_error"] is None


def test_data_fault_on_sentinel_page_is_not_completion():
    # A *data* read of the sentinel page (not a fetch) must NOT be COMPLETED.
    s = UnicornSession()
    base = 0x140075000
    # mov rax, [SENTINEL_ADDR]  -> 48 a1 <abs64>  (movabs rax, moffs64)
    code = b"\x48\xa1" + SENTINEL_ADDR.to_bytes(8, "little")
    s.map_bytes(base, code)
    s.set_register("RIP", base)
    state = s.run(begin=base, until=base + len(code), count=10)
    assert state["stop_reason"] == "ERROR"      # wild data read, not completion
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_unicorn_engine.py -k sentinel -q`
Expected: FAIL — `test_run_to_sentinel_completes_cleanly` reports `ERROR` instead of `DONE` (no guard yet).

- [ ] **Step 3: Write minimal implementation**

Add module constants near `_ALL_REGS`:

```python
SENTINEL_ADDR = 0x0000DEAD0000C0DE      # unmapped; "ran to completion" return target
```

In `run()`, add a completion signal dict beside `lazy_fail`:

```python
        sentinel_done = {"hit": False}
```

In `_unmapped_hook`, as the **first** check (before the `page in self._mapped` line):

```python
        def _unmapped_hook(uc, access, address, size, value, _user):
            if access == UC_MEM_FETCH_UNMAPPED and \
                    (address & ~(self.PAGE - 1)) == (SENTINEL_ADDR & ~(self.PAGE - 1)):
                sentinel_done["hit"] = True
                return False                     # stop; translated to DONE below
            page = address & ~(self.PAGE - 1)
            ...
```

In the `except UcError` block, check the sentinel **before** `lazy_fail`:

```python
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
```

Note `UC_MEM_FETCH_UNMAPPED` is already imported in the `from unicorn import ...` line added in Task 6.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_unicorn_engine.py -q`
Expected: PASS (all tests, including both new sentinel tests and all prior ones).

- [ ] **Step 5: Commit**

```bash
git add ghydra/dynamic/unicorn_engine.py tests/test_unicorn_engine.py
git commit -m "feat(dynamic): sentinel completion guard (fetch-only) in unmapped hook"
```

---

### Task 8: `UnicornSession.call()` — marshal args, run to sentinel, report

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py` (add `call()` to `UnicornSession`)
- Test: `tests/test_unicorn_engine.py`

**Interfaces:**
- Consumes: `calling_convention` (Task 1-3), `simulate_ret`/`run`/`SENTINEL_ADDR`, `_apply_default_stack`-equivalent. Reuses the default stack region constants from the engine: define `_CALL_STACK_BASE = 0x7ffff0000000`, `_CALL_STACK_SIZE = 0x100000`, `_CALL_ARGS_SPLIT = 0x40000` (256 KiB at the bottom for bytes-args; the rest is stack growing down).
- Produces:
  - `UnicornSession.call(func_addr: int, args: list, convention: str, count: int = 1000000, trace: bool = False) -> dict` — returns `{"return_value": int, "convention": str, "args_passed": list[int], "stop_reason": str, "last_error": str|None, "registers": dict, "mem_writes": list, "hook_log": list, "pc": int}`. Raises `ValueError` (via `calling_convention.validate_args` and an unsupported-convention check) before touching engine state.

Algorithm:
1. `cc.validate_args(args)`; `cc._check(convention)` via `cc.arg_registers`.
2. Map the call stack region (`_CALL_STACK_BASE`..+`_CALL_STACK_SIZE`) zero-filled (idempotent via `_ensure_mapped`/`map_bytes`).
3. Bytes-args: bump-allocate from `_CALL_STACK_BASE` upward; track `args_cursor`; if `args_cursor` would exceed `_CALL_STACK_BASE + _CALL_ARGS_SPLIT`, raise `ValueError("bytes args exceed scratch budget")`. Replace each `{"bytes": hex}` arg with its pointer (int).
4. Split resolved int args into register args (`arg_registers`) and stack spill (the rest).
5. Set RSP to the top of the stack region: `rsp = _CALL_STACK_BASE + _CALL_STACK_SIZE - 0x1000`.
6. Compute `final_rsp = cc.aligned_call_frame(rsp, convention, len(stack_args))`. Write stack args at `final_rsp + 8`, `final_rsp + 16`, … (above the sentinel), MS shadow space is just reserved padding (left zero). Write `SENTINEL_ADDR` (8 bytes) at `final_rsp`. Set RSP = `final_rsp`.
7. Write register args to their registers.
8. Set RIP = `func_addr`. Run `self.run(begin=func_addr, until=0, count=count, trace=trace)` — completion is the sentinel fetch (`DONE`).
9. Read `return_value` from `return_register(convention)`. Assemble and return the result dict (include `args_passed` = the resolved int args).

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_unicorn_engine.py
def test_call_runs_function_and_returns_rax():
    # Function: mov eax, 7 ; ret   (b8 07 00 00 00 c3)
    s = UnicornSession()
    func = 0x140075000
    s.map_bytes(func, b"\xb8\x07\x00\x00\x00\xc3")
    out = s.call(func, args=[], convention="sysv")
    assert out["stop_reason"] == "DONE"
    assert out["return_value"] == 7


def test_call_passes_int_args_in_sysv_registers():
    # Function: mov rax, rdi ; add rax, rsi ; ret
    #   48 89 f8   mov rax, rdi
    #   48 01 f0   add rax, rsi
    #   c3         ret
    s = UnicornSession()
    func = 0x140075000
    s.map_bytes(func, bytes.fromhex("4889f8" "4801f0" "c3"))
    out = s.call(func, args=[20, 22], convention="sysv")
    assert out["return_value"] == 42
    assert out["args_passed"] == [20, 22]


def test_call_passes_bytes_arg_as_pointer():
    # Function: mov al, [rdi] ; movzx eax, al ; ret
    #   8a 07            mov al, [rdi]
    #   0f b6 c0         movzx eax, al
    #   c3               ret
    s = UnicornSession()
    func = 0x140075000
    s.map_bytes(func, bytes.fromhex("8a07" "0fb6c0" "c3"))
    out = s.call(func, args=[{"bytes": "41"}], convention="sysv")
    assert out["return_value"] == 0x41        # read the first byte of the buffer


def test_call_rejects_float_arg():
    s = UnicornSession()
    func = 0x140075000
    s.map_bytes(func, b"\xc3")
    with pytest.raises(ValueError, match=r"arg\[0\]"):
        s.call(func, args=[1.5], convention="sysv")


def test_call_rejects_unsupported_convention():
    s = UnicornSession()
    func = 0x140075000
    s.map_bytes(func, b"\xc3")
    with pytest.raises(ValueError, match="convention"):
        s.call(func, args=[], convention="aapcs")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_unicorn_engine.py -k call -q`
Expected: FAIL with `AttributeError: 'UnicornSession' object has no attribute 'call'`

- [ ] **Step 3: Write minimal implementation**

```python
# module constants near SENTINEL_ADDR
_CALL_STACK_BASE = 0x7ffff0000000
_CALL_STACK_SIZE = 0x100000
_CALL_ARGS_SPLIT = 0x40000         # 256 KiB at the bottom reserved for bytes-args


# method on UnicornSession
    def call(self, func_addr: int, args: list, convention: str,
             count: int = 1000000, trace: bool = False) -> dict:
        from . import calling_convention as cc
        cc.validate_args(args)
        reg_names = cc.arg_registers(convention)     # raises ValueError if unsupported
        ret_reg = cc.return_register(convention)

        # 1. scratch stack
        self.map_bytes(_CALL_STACK_BASE, b"\x00" * _CALL_STACK_SIZE)

        # 2. materialise bytes-args low, growing up; replace with pointers
        args_cursor = _CALL_STACK_BASE
        resolved: list[int] = []
        for arg in args:
            if isinstance(arg, dict):
                data = bytes.fromhex(arg["bytes"])
                if args_cursor + len(data) > _CALL_STACK_BASE + _CALL_ARGS_SPLIT:
                    raise ValueError("bytes args exceed scratch budget "
                                     f"({_CALL_ARGS_SPLIT} bytes)")
                self._uc.mem_write(args_cursor, data)
                resolved.append(args_cursor)
                args_cursor += (len(data) + 15) & ~15      # keep 16-aligned
            else:
                resolved.append(arg)

        # 3. split into register vs stack args
        reg_args = resolved[:len(reg_names)]
        stack_args = resolved[len(reg_names):]

        # 4. lay out the stack frame
        rsp_top = _CALL_STACK_BASE + _CALL_STACK_SIZE - 0x1000
        final_rsp = cc.aligned_call_frame(rsp_top, convention, len(stack_args))
        for i, val in enumerate(stack_args):
            self._uc.mem_write(final_rsp + 8 + i * 8, int(val).to_bytes(8, "little", signed=val < 0))
        self._uc.mem_write(final_rsp, SENTINEL_ADDR.to_bytes(8, "little"))
        self.set_register("RSP", final_rsp)

        # 5. register args
        for name, val in zip(reg_names, reg_args):
            self.set_register(name, val & 0xffffffffffffffff)

        # 6. run to the sentinel
        self.set_register("RIP", func_addr)
        state = self.run(begin=func_addr, until=0, count=count, trace=trace)

        return {
            "return_value": self.get_register(ret_reg),
            "convention": convention,
            "args_passed": resolved,
            "stop_reason": state["stop_reason"],
            "last_error": state["last_error"],
            "registers": state["registers"],
            "mem_writes": state["mem_writes"],
            "hook_log": state["hook_log"],
            "pc": state["pc"],
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_unicorn_engine.py -k call -q`
Expected: PASS (5 tests). Then run the whole file: `python -m pytest tests/test_unicorn_engine.py -q` — all green.

- [ ] **Step 5: Commit**

```bash
git add ghydra/dynamic/unicorn_engine.py tests/test_unicorn_engine.py
git commit -m "feat(dynamic): UnicornSession.call() with arg marshalling + sentinel"
```

---

### Task 9: Bridge tools — `unicorn_hook_set/clear/list`, `unicorn_call` + version bump

**Files:**
- Modify: `bridge_mcp_hydra.py` (add 4 `@mcp.tool()` functions after `unicorn_dispose` near line 3262; bump `BRIDGE_VERSION:36`)
- Modify: `CHANGELOG.md`
- Create: `tests/test_bridge_unicorn_hooks.py`

**Interfaces:**
- Consumes: `_get_unicorn_session`, `_unicorn_error`, `Hook` + `StopReason` from `ghydra.dynamic.unicorn_engine`.
- Produces MCP tools:
  - `unicorn_hook_set(address: str, action: str, return_value: str | None = None, mem_writes: list | None = None, port=None) -> dict`
  - `unicorn_hook_clear(address: str, port=None) -> dict`
  - `unicorn_hook_list(port=None) -> dict`
  - `unicorn_call(func: str, args: list | None = None, convention: str = "sysv", trace: bool = False, port=None) -> dict`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bridge_unicorn_hooks.py
import pytest

pytest.importorskip("unicorn")
import bridge_mcp_hydra as bridge
from ghydra.dynamic.unicorn_engine import UnicornSession, Hook


@pytest.fixture
def session_on_port(monkeypatch):
    port = 18192
    session = UnicornSession()
    monkeypatch.setattr(bridge, "_get_instance_port", lambda p=None: port)
    with bridge._unicorn_lock:
        bridge._UNICORN_SESSIONS[port] = session
    yield port, session
    with bridge._unicorn_lock:
        bridge._UNICORN_SESSIONS.pop(port, None)


def test_hook_set_list_clear(session_on_port):
    port, session = session_on_port
    r = bridge.unicorn_hook_set.fn("0x401000", "return_const", return_value="0x2a")
    assert r["success"] is True
    assert 0x401000 in session.list_hooks()
    listed = bridge.unicorn_hook_list.fn()
    assert any(h["address"] == "0x401000" for h in listed["hooks"])
    cleared = bridge.unicorn_hook_clear.fn("0x401000")
    assert cleared["success"] is True
    assert 0x401000 not in session.list_hooks()


def test_hook_set_rejects_mem_writes_on_skip(session_on_port):
    r = bridge.unicorn_hook_set.fn("0x401000", "skip",
                                   mem_writes=[{"address": "0x1000", "hex": "41"}])
    assert r["success"] is False


def test_unicorn_call_returns_value(session_on_port):
    port, session = session_on_port
    func = 0x140075000
    session.map_bytes(func, b"\xb8\x07\x00\x00\x00\xc3")   # mov eax,7 ; ret
    r = bridge.unicorn_call.fn(hex(func), args=[], convention="sysv")
    assert r["success"] is True
    assert r["return_value"] == "0x7"


def test_unicorn_call_without_session_errors(monkeypatch):
    monkeypatch.setattr(bridge, "_get_instance_port", lambda p=None: 19999)
    r = bridge.unicorn_call.fn("0x140075000", args=[], convention="sysv")
    assert r["success"] is False
```

(Note: `@mcp.tool()`-decorated functions expose the raw callable via `.fn`; the tests call `.fn` to bypass the MCP text wrapper.)

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_bridge_unicorn_hooks.py -q`
Expected: FAIL with `AttributeError: module 'bridge_mcp_hydra' has no attribute 'unicorn_hook_set'`

- [ ] **Step 3: Write minimal implementation**

Bump the version at `bridge_mcp_hydra.py:36`:

```python
BRIDGE_VERSION = "v3.1.0-rc.4"
```

Add the tools after `unicorn_dispose` (around line 3262):

```python
@mcp.tool()
@text_output
def unicorn_hook_set(address: str, action: str, return_value: str | None = None,
                     mem_writes: list | None = None, port: int | None = None) -> dict:
    """Register a hook on an address to stub a call/import during emulation.

    action is one of: "return_const" (set RAX to return_value and simulate ret;
    may carry mem_writes side-effects), "skip" (simulate ret, RAX untouched),
    "log" (record the hit and continue), "trap" (stop with stop_reason HOOK_TRAP).
    mem_writes (list of {"address": hex, "hex": bytes}) are allowed only with
    return_const. Hooks persist across unicorn_run/unicorn_call until cleared or
    the session is reset.

    Args:
        address: Hook address in hex
        action: return_const | skip | log | trap
        return_value: Hex value for return_const (optional)
        mem_writes: [{"address": hex, "hex": hexbytes}] for return_const (optional)
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e))
    from ghydra.dynamic.unicorn_engine import Hook
    rv = int(return_value, 16) if return_value is not None else None
    mw = ([{"address": int(w["address"], 16), "hex": w["hex"]} for w in mem_writes]
          if mem_writes else None)
    try:
        session.set_hook(int(address, 16), Hook(action=action, return_value=rv, mem_writes=mw))
    except ValueError as e:
        return _unicorn_error(str(e))
    return {"success": True, "address": hex(int(address, 16)), "action": action,
            "timestamp": int(time.time() * 1000)}


@mcp.tool()
@text_output
def unicorn_hook_clear(address: str, port: int | None = None) -> dict:
    """Remove a Unicorn hook previously set at an address.

    Args:
        address: Hook address in hex
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e))
    removed = session.clear_hook(int(address, 16))
    return {"success": True, "address": hex(int(address, 16)), "removed": removed,
            "timestamp": int(time.time() * 1000)}


@mcp.tool()
@text_output
def unicorn_hook_list(port: int | None = None) -> dict:
    """List the hooks registered on the current Unicorn session.

    Args:
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e))
    hooks = [{"address": hex(a), "action": h.action,
              "return_value": (hex(h.return_value) if h.return_value is not None else None)}
             for a, h in session.list_hooks().items()]
    return {"success": True, "hooks": hooks, "timestamp": int(time.time() * 1000)}


@mcp.tool()
@text_output
def unicorn_call(func: str, args: list | None = None, convention: str = "sysv",
                 trace: bool = False, port: int | None = None) -> dict:
    """Call a function in the Unicorn session and report its return value.

    Sets up the x86-64 calling convention (sysv default, or ms), runs the
    function to a synthetic return address, and returns the return register.
    args is a list of ints and/or {"bytes": hex} pointer args; floats and
    by-value structs are not supported. Register hooks first (unicorn_hook_set)
    so inner calls into imports are stubbed rather than faulting.

    success is true only when the function returned cleanly (stop_reason DONE).
    A HOOK_TRAP / LAZY_FETCH_FAILED / ERROR stop returns success=false with the
    partial state so you can add a missing hook and retry.

    Args:
        func: Function entry address in hex
        args: List of int args and/or {"bytes": "hex"} pointer args (optional)
        convention: "sysv" (default) or "ms"
        trace: Collect executed-instruction trace + memory writes
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e))
    from ghydra.dynamic.unicorn_engine import StopReason
    try:
        state = session.call(int(func, 16), args or [], convention, trace=trace)
    except ValueError as e:
        return _unicorn_error(str(e))
    payload = {
        "pc": hex(state["pc"]),
        "stop_reason": state["stop_reason"],
        "convention": state["convention"],
        "return_value": hex(state["return_value"]),
        "args_passed": [hex(a) for a in state["args_passed"]],
        "last_error": state["last_error"],
        "timestamp": int(time.time() * 1000),
    }
    if state["stop_reason"] == StopReason.DONE:
        payload["success"] = True
        payload["registers"] = {k: hex(v) for k, v in state["registers"].items()}
    else:
        payload["success"] = False
        payload["error"] = {"code": state["stop_reason"],
                            "message": state["last_error"] or state["stop_reason"]}
    return payload
```

Add a `CHANGELOG.md` entry under the unreleased/next-rc section:

```markdown
### Added
- Unicorn engine: import/syscall hooking (`unicorn_hook_set/clear/list`) with
  return_const/skip/log/trap actions, and a high-level `unicorn_call(func, args)`
  primitive (x86-64 SysV/MS) that stubs imports and reports the return value.
  Bridge bumped to v3.1.0-rc.4 (additive; API_VERSION unchanged).
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_bridge_unicorn_hooks.py -q`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add bridge_mcp_hydra.py tests/test_bridge_unicorn_hooks.py CHANGELOG.md
git commit -m "feat(dynamic): bridge unicorn_hook_* + unicorn_call tools; bump to rc.4"
```

---

### Task 10: CLI — `ghydra dynamic call` with inline `--hook`

**Files:**
- Modify: `ghydra/cli/dynamic.py` (add `call` command)
- Test: `tests/test_dynamic_cli.py`

**Interfaces:**
- Consumes: `_make_session` (existing), `UnicornSession.call`/`set_hook`, `Hook`, `StopReason`, `validate_address`.
- Produces: `ghydra dynamic call --func HEX [--arg INT|0xHEX | --arg-bytes HEX]... [--hook ADDR:ACTION[:RETVAL]]... [--convention sysv|ms]`. Because the CLI session is per-invocation, hooks are registered from `--hook` flags in the same command before `call` runs.

`--hook` format: `address:action[:retval]`, e.g. `0x401100:return_const:0` or `0x401200:trap`. Parse with `str.split(":")`.

- [ ] **Step 1: Write the failing test**

The engine-level execution of `call` is already covered end-to-end in `tests/test_unicorn_engine.py` (Task 8). These CLI tests assert the command's **wiring**: that arg validation and `--hook` parsing surface as a non-zero exit with a clear message. Both reach `_make_session` (which needs unicorn) and fail in the pure-validation path before any execution, so no code-page plumbing is required.

```python
# append to tests/test_dynamic_cli.py
def test_call_rejects_float_arg():
    from ghydra.cli.dynamic import call as dyn_call
    result = CliRunner().invoke(
        dyn_call,
        ["--func", "0x140075000", "--arg", "1.5"],     # int("1.5", 0) -> ValueError
        obj=_obj(),
    )
    assert result.exit_code != 0
    assert "1.5" in result.output or "invalid" in result.output.lower()


def test_call_hook_parsing_rejects_bad_action():
    from ghydra.cli.dynamic import call as dyn_call
    result = CliRunner().invoke(
        dyn_call,
        ["--func", "0x140075000", "--hook", "0x401100:explode"],
        obj=_obj(),
    )
    assert result.exit_code != 0
    assert "action" in result.output.lower() or "explode" in result.output.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_dynamic_cli.py -k call -q`
Expected: FAIL with `ImportError: cannot import name 'call'`

- [ ] **Step 3: Write minimal implementation**

```python
# add to ghydra/cli/dynamic.py
@dynamic.command('call')
@click.option('--func', '-f', required=True, help='Function entry address (hex)')
@click.option('--arg', 'int_args', multiple=True, help='Integer arg (decimal or 0xhex); repeatable')
@click.option('--arg-bytes', 'byte_args', multiple=True,
              help='Pointer arg: hex bytes parked in scratch, pointer passed; repeatable')
@click.option('--hook', 'hooks', multiple=True,
              help='address:action[:retval], e.g. 0x401100:return_const:0; repeatable')
@click.option('--convention', type=click.Choice(['sysv', 'ms']), default='sysv')
@click.option('--count', type=int, default=1000000, help='Instruction cap')
@click.pass_context
def call(ctx, func, int_args, byte_args, hooks, convention, count):
    """Call a function (set up the ABI, stub imports via --hook) and print the result.

    Hooks are per-invocation: register them inline with --hook in the same call.
    """
    from ..dynamic.unicorn_engine import Hook, StopReason
    try:
        session = _make_session(ctx)
        # Args: --arg ints first, then --arg-bytes pointers, preserving CLI order
        # is not possible across two options; document that ints precede bytes.
        args: list = [int(a, 0) for a in int_args]
        args += [{"bytes": validate_address(b).lstrip('0x') if b.startswith('0x') else b}
                 for b in byte_args]
        for spec in hooks:
            parts = spec.split(":")
            if len(parts) < 2:
                raise click.ClickException(f"bad --hook {spec!r}; want address:action[:retval]")
            addr = int(validate_address(parts[0]), 16)
            action = parts[1]
            retval = int(parts[2], 16) if len(parts) > 2 else None
            session.set_hook(addr, Hook(action=action, return_value=retval))
        out = session.call(int(validate_address(func), 16), args, convention, count=count)
        click.echo(f"return_value={hex(out['return_value'])} "
                   f"stop={out['stop_reason']} convention={out['convention']}")
        if out.get("last_error"):
            click.echo(f"  error: {out['last_error']}")
        if out["stop_reason"] != StopReason.DONE:
            ctx.exit(1)
    except (ValueError, click.ClickException) as e:
        raise click.ClickException(str(e)) if not isinstance(e, click.ClickException) else e
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_dynamic_cli.py -q`
Expected: PASS (existing + 2 new). Verify the prior `test_run_*`/`test_dump_*`/`test_map_*` are still green.

- [ ] **Step 5: Commit**

```bash
git add ghydra/cli/dynamic.py tests/test_dynamic_cli.py
git commit -m "feat(dynamic): ghydra dynamic call CLI with inline --hook"
```

---

### Task 11: Full-suite verification

**Files:** none (verification only).

- [ ] **Step 1: Run the whole dynamic test surface**

Run: `python -m pytest tests/ -q`
Expected: PASS — all of `test_calling_convention.py`, `test_unicorn_engine.py`, `test_bridge_unicorn_hooks.py`, `test_dynamic_cli.py`, plus the pre-existing suites untouched by this plan.

- [ ] **Step 2: Confirm no regression in existing Unicorn behaviour**

Run: `python -m pytest tests/test_unicorn_engine.py -q`
Expected: every pre-existing test (`test_run_two_nops_advances_rip_and_traces`, `test_run_records_memory_writes`, `test_lazy_*`, `test_run_hits_instruction_cap_returns_count`, `test_trace_truncation_flag`, …) still PASS alongside the new hook/sentinel/call tests.

- [ ] **Step 3: Confirm the bridge imports cleanly with the version bump**

Run: `python -c "import bridge_mcp_hydra as b; print(b.BRIDGE_VERSION)"`
Expected: prints `v3.1.0-rc.4`

- [ ] **Step 4: Commit (only if any verification fix was needed)**

```bash
git add -A
git commit -m "test(dynamic): full-suite verification for unicorn call + hooks"
```

---

## Self-Review

**Spec coverage:**
- Hook registry (eager-not-needed here; Unicorn hooks are address-keyed, symbol resolution is a bridge/Plan-B concern since the engine works in raw addresses) → Tasks 4, 6, 9. ✅ *Note:* the spec's eager symbol→address resolution applies to the bridge/REST layer; the Unicorn engine itself is address-only. Symbol resolution for `unicorn_hook_set` by name is deferred to Plan B's shared bridge helper (engine takes addresses). This is consistent with the existing `unicorn_*` tools all taking hex addresses.
- Action vocabulary (`return_const`/`skip`/`log`/`trap`, mem_writes on return_const only) → Tasks 4, 6. ✅
- `simulate_ret` 5-step contract → Task 5. ✅
- Sentinel in `_unmapped_hook` with `UC_MEM_FETCH_UNMAPPED` gate + completion-over-lazy_fail priority → Task 7. ✅
- `call()` mechanism, bytes-arg bottom-up allocation + budget cap, 16-byte alignment, MS shadow space → Tasks 2, 3, 8. ✅
- Convention resolution explicit `convention=` (the `compiler_spec_id` → SysV fallback chain is a bridge concern; the engine takes an explicit convention, bridge defaults it) → Task 8/9. The bridge `unicorn_call` defaults `convention="sysv"`; richer `compiler_spec_id` auto-detection is a small follow-up noted for Plan B parity. ✅ (engine + explicit selection covered; auto-detect deferred — acceptable since SysV default + explicit override is functional.)
- Unified stop-reason vocabulary → engine keeps native constants (`DONE`/`HOOK_TRAP`/…); translation to `COMPLETED` etc. is Plan B's bridge-formatter job. Within Plan A the contract is the native constants. ✅
- Hooks wiped on reset → a fresh `UnicornSession` has an empty registry (Task 4 test `test_fresh_session_has_empty_registry`); `unicorn_reset` already builds a new session. ✅
- CLI per-invocation hooks via `--hook` → Task 10. ✅
- Version bump rc.3→rc.4, API unchanged, CHANGELOG → Task 9. ✅
- Tests run in CI without live Ghidra → every task uses `importorskip`/pure functions. ✅

**Gaps surfaced & accepted for Plan B (documented, not silent):**
- `compiler_spec_id`-driven convention auto-detection in `unicorn_call` (engine + explicit `convention=` shipped; auto-detect is a thin bridge addition).
- Symbol-name → address resolution for hook registration (engine is address-only by existing `unicorn_*` convention).

These are bridge-layer conveniences, not engine-contract gaps; deferring them keeps Plan A focused on the executable contract.

**Placeholder scan:** No TBD/TODO; every code step is complete. ✅

**Type consistency:** `Hook(action, return_value, mem_writes)`, `set_hook`/`clear_hook`/`list_hooks`, `simulate_ret(return_value=None)`, `call(func_addr, args, convention, count, trace)`, `SENTINEL_ADDR`, `aligned_call_frame(rsp, convention, n_stack_args)`, `arg_registers`/`return_register`/`validate_args` — names consistent across Tasks 1-10. ✅
