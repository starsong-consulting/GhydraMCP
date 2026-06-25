# PR Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Address all critical, important, and suggestion-level findings from the `/pr-review-toolkit:review-pr` run on `feature/unicorn-call-and-hooks`.

**Architecture:** Fixes span four layers — `calling_convention.py` (pure logic), `unicorn_engine.py` (emulator), `bridge_mcp_hydra.py` (MCP), `ghydra/cli/dynamic.py` (CLI) — plus their test files. Changes are independent by layer and can be reviewed in isolation.

**Tech Stack:** Python 3.11+, unicorn-engine, pytest, Click, dataclasses, enum.

## Global Constraints

- Python 3.11+ — `str | None` union syntax is fine, `Enum` from stdlib
- `unicorn` is optional; tests gate on `pytest.importorskip("unicorn")`; pure-logic modules must remain importable without it
- No new dependencies
- All existing tests must keep passing after each task
- Run tests with: `python -m pytest tests/test_calling_convention.py tests/test_unicorn_engine.py tests/test_bridge_unicorn_hooks.py tests/test_dynamic_cli.py -v`

---

### Task 1: `calling_convention.py` — hex validation + docstring fixes

**Files:**
- Modify: `ghydra/dynamic/calling_convention.py`
- Test: `tests/test_calling_convention.py`

**Interfaces:**
- Produces: `validate_args(args)` now eagerly validates `bytes.fromhex(arg["bytes"])` before returning; raises `ValueError` with `"not valid hex"` in message if invalid

- [ ] **Step 1: Write failing tests**

Add to `tests/test_calling_convention.py`:
```python
def test_validate_rejects_bad_hex_in_bytes_arg():
    with pytest.raises(ValueError, match="not valid hex"):
        cc.validate_args([{"bytes": "ZZ"}])

def test_validate_rejects_odd_length_hex_in_bytes_arg():
    with pytest.raises(ValueError, match="not valid hex"):
        cc.validate_args([{"bytes": "4"}])   # odd-length hex fails fromhex

def test_validate_accepts_valid_bytes_arg_passes():
    cc.validate_args([{"bytes": "deadbeef"}])  # must not raise
```

- [ ] **Step 2: Run tests to confirm they fail**

```
python -m pytest tests/test_calling_convention.py::test_validate_rejects_bad_hex_in_bytes_arg tests/test_calling_convention.py::test_validate_rejects_odd_length_hex_in_bytes_arg -v
```
Expected: FAIL (no match on "not valid hex" — validation doesn't check hex content yet)

- [ ] **Step 3: Implement**

Replace `ghydra/dynamic/calling_convention.py` content:
```python
"""Pure x86-64 calling-convention logic (no unicorn dependency).

Arg-register order, return register, stack-arg layout, and 16-byte stack
alignment for the high-level call() primitive. Isolated from unicorn so this
module is importable in environments without it.
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


def validate_args(args: list) -> None:
    """Reject any arg that is not an int or a {"bytes": hex} dict."""
    for i, arg in enumerate(args):
        if isinstance(arg, bool):
            raise ValueError(f"arg[{i}]: bool is not a valid integer arg")
        if isinstance(arg, int):
            continue
        if isinstance(arg, dict) and set(arg) == {"bytes"} and isinstance(arg["bytes"], str):
            try:
                bytes.fromhex(arg["bytes"])
            except ValueError:
                raise ValueError(
                    f'arg[{i}]: "bytes" value is not valid hex: {arg["bytes"]!r}')
            continue
        raise ValueError(
            f'arg[{i}]: only int or {{"bytes": hex}} args are supported '
            f"(float/struct args are out of scope)")


def aligned_call_frame(rsp: int, convention: str, n_stack_args: int) -> int:
    """Final RSP after laying out stack args, MS shadow space (if applicable),
    and the sentinel return address.

    Guarantees callee-entry ABI alignment: rsp % 16 == 8 (the 8-byte sentinel
    return address occupies the low 8 bytes of a 16-aligned frame). The MS ABI
    requires 32 bytes of shadow space above RSP that the caller allocates.
    """
    _check(convention)
    body = 8 * n_stack_args + (32 if convention == "ms" else 0)
    target = rsp - body - 8           # tentative sentinel slot
    final_rsp = target - ((target - 8) % 16)   # round down so final % 16 == 8
    return final_rsp
```

- [ ] **Step 4: Run all calling_convention tests**

```
python -m pytest tests/test_calling_convention.py -v
```
Expected: all PASS (13 existing + 3 new = 16 total)

- [ ] **Step 5: Commit**

```
git add ghydra/dynamic/calling_convention.py tests/test_calling_convention.py
git commit -m "fix(dynamic): validate hex content in validate_args; clean up docstrings"
```

---

### Task 2: `Hook.__post_init__` — type hardening + simplify `set_hook`

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py` (Hook class + set_hook only)
- Test: `tests/test_unicorn_engine.py`

**Interfaces:**
- Produces: `Hook` raises `ValueError` at construction time for unknown action, mem_writes on non-return_const, return_value on non-return_const, bad hex in mem_writes[*]["hex"], missing/wrong-typed mem_writes fields
- `set_hook` no longer duplicates validation — it just stores the hook

- [ ] **Step 1: Write failing tests**

Add to `tests/test_unicorn_engine.py` (below the existing hook tests, around line 215):
```python
def test_hook_rejects_return_value_on_non_return_const():
    with pytest.raises(ValueError, match="return_value"):
        Hook(action="skip", return_value=0xdead)

def test_hook_rejects_bad_hex_in_mem_writes():
    with pytest.raises(ValueError, match="not valid hex"):
        Hook(action="return_const", return_value=0,
             mem_writes=[{"address": 0x1000, "hex": "ZZ"}])

def test_hook_rejects_wrong_mem_writes_structure():
    with pytest.raises(ValueError, match="mem_writes"):
        Hook(action="return_const", return_value=0,
             mem_writes=[{"ptr": 0x1000, "data": "41"}])
```

- [ ] **Step 2: Run to confirm they fail**

```
python -m pytest tests/test_unicorn_engine.py::test_hook_rejects_return_value_on_non_return_const tests/test_unicorn_engine.py::test_hook_rejects_bad_hex_in_mem_writes -v
```
Expected: FAIL

- [ ] **Step 3: Implement — update `Hook` and simplify `set_hook`**

Replace the `Hook` dataclass and `set_hook` method in `ghydra/dynamic/unicorn_engine.py`:

```python
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
```

And simplify `set_hook`:
```python
def set_hook(self, address: int, hook: Hook) -> None:
    self._hooks[address] = hook
```

- [ ] **Step 4: Run all engine + hook tests**

```
python -m pytest tests/test_unicorn_engine.py tests/test_bridge_unicorn_hooks.py -v
```
Expected: all PASS (note: `test_set_hook_rejects_unknown_action` still passes because `Hook(action="explode")` raises inside the `with pytest.raises` block)

- [ ] **Step 5: Commit**

```
git add ghydra/dynamic/unicorn_engine.py tests/test_unicorn_engine.py
git commit -m "fix(dynamic): Hook.__post_init__ enforces invariants at construction; simplify set_hook"
```

---

### Task 3: `StopReason` → `str`-enum + `REDIRECT_STORM` stop reason

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py` (`StopReason` class + `run()` redirect-storm logic)
- Test: `tests/test_unicorn_engine.py` (update `test_redirect_storm_is_bounded_by_count`)

**Interfaces:**
- Produces: `StopReason` is now `class StopReason(str, Enum)` — all existing `== "DONE"` comparisons still work because `str`-enum members compare equal to their string value
- New constant `_REDIRECT_CAP = 10_000` in `unicorn_engine.py`
- Redirect storm now yields `stop_reason == StopReason.REDIRECT_STORM` (== `"REDIRECT_STORM"`)
- `StopReason.REDIRECT_STORM` has `last_error` naming the looping address

- [ ] **Step 1: Update the redirect-storm test to expect `REDIRECT_STORM`**

In `tests/test_unicorn_engine.py`, update `test_redirect_storm_is_bounded_by_count` (line ~295):
```python
def test_redirect_storm_is_bounded_by_redirect_cap():
    """A return_const hook on A whose simulate_ret always returns to A (stack full of A)
    must terminate with REDIRECT_STORM rather than looping forever.
    The redirect cap is independent of the instruction count.
    """
    s = UnicornSession()
    base = 0x140075000
    s.map_bytes(base, b"\x90")
    stack_base = 0x7ffff0000000
    addr_bytes = base.to_bytes(8, "little")
    page = addr_bytes * (0x1000 // 8)
    s.map_bytes(stack_base, page)
    s.set_register("RSP", stack_base)
    s.set_hook(base, Hook(action="return_const", return_value=0))
    state = s.run(begin=base, until=0, count=1_000_000)
    assert state["stop_reason"] == "REDIRECT_STORM"
    assert state["steps"] == 0    # no instructions executed; only redirects
```

- [ ] **Step 2: Run the updated test to confirm it fails**

```
python -m pytest "tests/test_unicorn_engine.py::test_redirect_storm_is_bounded_by_redirect_cap" -v
```
Expected: FAIL (test not found yet since name changed) or old test still asserts COUNT

- [ ] **Step 3: Implement**

At the top of `ghydra/dynamic/unicorn_engine.py`, add the import and convert `StopReason`:
```python
from enum import Enum
```

Replace the `StopReason` class:
```python
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
```

In `run()`, replace the redirect-storm check (currently `if redirects >= cap`):
```python
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
```

- [ ] **Step 4: Run all tests**

```
python -m pytest tests/test_unicorn_engine.py tests/test_bridge_unicorn_hooks.py -v
```
Expected: all PASS. The new `test_redirect_storm_is_bounded_by_redirect_cap` should pass. The old test name is gone (was renamed); verify no other test asserts `"COUNT"` for a redirect storm.

- [ ] **Step 5: Commit**

```
git add ghydra/dynamic/unicorn_engine.py tests/test_unicorn_engine.py
git commit -m "fix(dynamic): StopReason as str-enum; add REDIRECT_STORM with independent 10k cap"
```

---

### Task 4: `_code_hook` UcError hardening

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py` (`run()` — `ctrl` dict + `_code_hook` try/except + re-entry loop handling)
- Test: `tests/test_unicorn_engine.py`

**Interfaces:**
- Produces: A `UcError` or `ValueError` raised inside the `return_const`/`skip` hook callback is now surfaced as `stop_reason == "ERROR"` with `last_error` containing `"hook callback error: ..."` rather than silently corrupting the re-entry loop

- [ ] **Step 1: Write failing test**

Add to `tests/test_unicorn_engine.py`:
```python
def test_hook_callback_error_surfaces_as_error_stop():
    """simulate_ret raises UcError when RSP is unmapped; must surface as ERROR,
    not loop forever or return a corrupt DONE."""
    s = UnicornSession()
    base = 0x140075000
    s.map_bytes(base, b"\x90")
    # Do NOT map a stack; RSP = 0x0 (unmapped) — simulate_ret will fault
    s.set_register("RSP", 0)
    s.set_hook(base, Hook(action="return_const", return_value=0))
    state = s.run(begin=base, until=0, count=10)
    assert state["stop_reason"] == "ERROR"
    assert state["last_error"] is not None
    assert "hook" in state["last_error"].lower()
```

- [ ] **Step 2: Run to confirm it fails**

```
python -m pytest "tests/test_unicorn_engine.py::test_hook_callback_error_surfaces_as_error_stop" -v
```
Expected: FAIL (currently the run either hangs, crashes, or returns COUNT)

- [ ] **Step 3: Implement**

In `run()`, add `"hook_error"` key to `ctrl` and reset it each iteration:
```python
ctrl = {"redirect": False, "trap": False, "hook_error": None}
```

In the loop body, reset all ctrl flags:
```python
while remaining > 0:
    ctrl["redirect"] = False
    ctrl["trap"] = False
    ctrl["hook_error"] = None
    ...
```

Replace the `return_const`/`skip` branch in `_code_hook` with a try/except:
```python
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
```

After `emu_start` returns (non-exception path), check `hook_error` FIRST (before trap/redirect):
```python
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
if ctrl["hook_error"]:
    stop_reason = StopReason.ERROR
    last_error = f"hook callback error: {ctrl['hook_error']}"
    break
if ctrl["trap"]:
    stop_reason = StopReason.HOOK_TRAP
    break
if ctrl["redirect"]:
    ...
```

- [ ] **Step 4: Run all tests**

```
python -m pytest tests/test_unicorn_engine.py tests/test_bridge_unicorn_hooks.py -v
```
Expected: all PASS including new `test_hook_callback_error_surfaces_as_error_stop`

- [ ] **Step 5: Commit**

```
git add ghydra/dynamic/unicorn_engine.py tests/test_unicorn_engine.py
git commit -m "fix(dynamic): catch UcError/ValueError in _code_hook callback; surface as ERROR stop"
```

---

### Task 5: `call()` — validate-before-mutate + `trace` key + sentinel exact comparison

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py` (`call()` body + `_unmapped_hook` sentinel check)
- Test: `tests/test_unicorn_engine.py`

**Interfaces:**
- Produces: `call()` raises `ValueError` for budget overflow without mapping any scratch memory; `call()` return dict always includes `"trace"` key; sentinel comparison is exact (not page-aligned)

- [ ] **Step 1: Write failing tests**

Add to `tests/test_unicorn_engine.py`:
```python
def test_call_budget_overflow_does_not_map_scratch():
    """Budget overflow must be caught before touching the emulator."""
    s = UnicornSession()
    func = 0x140075000
    s.map_bytes(func, b"\xc3")
    too_many = "41" * (0x40001)     # 256 KiB + 1 byte
    with pytest.raises(ValueError, match="scratch budget"):
        s.call(func, args=[{"bytes": too_many}], convention="sysv")
    # scratch stack page must NOT be mapped
    assert (_CALL_STACK_BASE & ~(UnicornSession.PAGE - 1)) not in s._mapped

def test_call_returns_trace_key():
    s = UnicornSession()
    func = 0x140075000
    s.map_bytes(func, b"\xb8\x01\x00\x00\x00\xc3")  # mov eax,1 ; ret
    out = s.call(func, args=[], convention="sysv")
    assert "trace" in out      # always present, even when trace=False

def test_instruction_fetch_near_sentinel_is_error_not_done():
    """A fetch fault at SENTINEL_ADDR+1 (same page, different address) must be
    ERROR, not DONE — ensures the sentinel check is exact, not page-aligned."""
    s = UnicornSession()
    base = 0x140075000
    target = SENTINEL_ADDR + 1
    # mov rax, target  (10 bytes)  ;  jmp rax  (2 bytes)
    code = b"\x48\xb8" + target.to_bytes(8, "little") + b"\xff\xe0"
    s.map_bytes(base, code)
    s.set_register("RIP", base)
    state = s.run(begin=base, until=0, count=5)
    assert state["stop_reason"] == "ERROR"   # not DONE; wrong address on sentinel page
```

- [ ] **Step 2: Run to confirm they fail**

```
python -m pytest tests/test_unicorn_engine.py::test_call_budget_overflow_does_not_map_scratch tests/test_unicorn_engine.py::test_call_returns_trace_key tests/test_unicorn_engine.py::test_instruction_fetch_near_sentinel_is_error_not_done -v
```
Expected: first two FAIL, third may PASS or FAIL depending on existing sentinel behavior

- [ ] **Step 3: Implement**

**3a. Fix `call()` — pre-compute bytes, check budget before mapping:**

Replace the body of `call()` in `ghydra/dynamic/unicorn_engine.py`:
```python
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
```

**3b. Fix `_unmapped_hook` — exact sentinel address comparison:**

Replace the sentinel check in `_unmapped_hook`:
```python
def _unmapped_hook(uc, access, address, size, value, _user):
    if access == UC_MEM_FETCH_UNMAPPED and address == SENTINEL_ADDR:
        sentinel_done["hit"] = True
        # return False causes UcError; sentinel_done flag disambiguates
        # this intentional stop from a real fault in the outer handler.
        return False
    ...
```

- [ ] **Step 4: Run all tests**

```
python -m pytest tests/test_unicorn_engine.py tests/test_bridge_unicorn_hooks.py -v
```
Expected: all PASS

- [ ] **Step 5: Commit**

```
git add ghydra/dynamic/unicorn_engine.py tests/test_unicorn_engine.py
git commit -m "fix(dynamic): validate-before-mutate in call(); add trace key; sentinel exact comparison"
```

---

### Task 6: Comment cleanup in `unicorn_engine.py`

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py` (comments only, no logic changes)

**No new tests** — this is purely cosmetic; all existing tests must still pass.

- [ ] **Step 1: Apply all comment changes**

Make these edits to `ghydra/dynamic/unicorn_engine.py`:

**a. Fix `StopReason` docstring** — "six states" not "four":
```python
class StopReason(str, Enum):
    """The closed set of stop_reason values returned by UnicornSession.run().

    Shared constants (imported by the bridge and CLI consumers) so the six
    states are compared by name rather than by re-typed string literals, where
    a typo would be a silent misclassification. success is only DONE.
    """
```
(This was already set correctly in Task 3.)

**b. Fix `simulate_ret` docstring** — remove false "and by call() teardown":
```python
def simulate_ret(self, return_value: int | None = None) -> None:
    """Pop the return address off the stack into RIP (and optionally set RAX).

    Mirrors a ret: RIP = [RSP]; RSP += 8. Used by return_const/skip hooks.
    The stack memory must be mapped; an unmapped RSP surfaces as the
    underlying UcError.
    """
```

**c. Fix `_CALL_ARGS_SPLIT` comment** — clarify layout:
```python
_CALL_ARGS_SPLIT = 0x40000  # low 256 KiB of scratch region for bytes-args; stack frame lives above
```

**d. Remove `# control signals the code hook raises for the re-entry loop`** from the `ctrl` dict assignment line. Just:
```python
ctrl = {"redirect": False, "trap": False, "hook_error": None}
```

**e. Remove `# falls through: instruction executes normally`** after the `hook_log.append` line. Just:
```python
if hook.action == "log":
    hook_log.append({"address": address})
elif hook.action == "trap":
```

- [ ] **Step 2: Run all tests to confirm nothing broke**

```
python -m pytest tests/test_unicorn_engine.py tests/test_bridge_unicorn_hooks.py -v
```
Expected: all PASS

- [ ] **Step 3: Commit**

```
git add ghydra/dynamic/unicorn_engine.py
git commit -m "fix(dynamic): correct docstrings and remove WHAT-comments in unicorn_engine"
```

---

### Task 7: Bridge fixes — `hook_clear` guard + `count` param + error code distinction

**Files:**
- Modify: `bridge_mcp_hydra.py`
- Test: `tests/test_bridge_unicorn_hooks.py`

**Interfaces:**
- Produces: `_unicorn_error(msg, code="UNICORN")` accepts optional `code`; no-session errors use `code="NO_SESSION"`; `unicorn_hook_clear` with a bad address returns structured error; `unicorn_call` accepts `count: int = 1_000_000`

- [ ] **Step 1: Write failing tests**

Add to `tests/test_bridge_unicorn_hooks.py`:
```python
def test_hook_clear_rejects_bad_address(session_on_port):
    r = bridge.unicorn_hook_clear.__wrapped__("not_hex")
    assert r["success"] is False

def test_hook_set_without_session_errors(monkeypatch):
    monkeypatch.setattr(bridge, "_get_instance_port", lambda p=None: 19999)
    r = bridge.unicorn_hook_set.__wrapped__("0x401000", "return_const", return_value="0x1")
    assert r["success"] is False
    assert r["error"]["code"] == "NO_SESSION"

def test_hook_clear_without_session_errors(monkeypatch):
    monkeypatch.setattr(bridge, "_get_instance_port", lambda p=None: 19999)
    r = bridge.unicorn_hook_clear.__wrapped__("0x401000")
    assert r["success"] is False
    assert r["error"]["code"] == "NO_SESSION"

def test_hook_list_without_session_errors(monkeypatch):
    monkeypatch.setattr(bridge, "_get_instance_port", lambda p=None: 19999)
    r = bridge.unicorn_hook_list.__wrapped__()
    assert r["success"] is False
    assert r["error"]["code"] == "NO_SESSION"

def test_unicorn_call_with_count(session_on_port):
    port, session = session_on_port
    func = 0x140075000
    session.map_bytes(func, b"\xb8\x07\x00\x00\x00\xc3")  # mov eax,7 ; ret
    r = bridge.unicorn_call.__wrapped__(hex(func), args=[], count=500_000)
    assert r["success"] is True
    assert r["return_value"] == "0x7"
```

- [ ] **Step 2: Run to confirm they fail**

```
python -m pytest tests/test_bridge_unicorn_hooks.py::test_hook_clear_rejects_bad_address tests/test_bridge_unicorn_hooks.py::test_hook_set_without_session_errors tests/test_bridge_unicorn_hooks.py::test_unicorn_call_with_count -v
```
Expected: FAIL

- [ ] **Step 3: Implement**

**a. Update `_unicorn_error` to accept optional `code`:**
```python
def _unicorn_error(message: str, code: str = "UNICORN") -> dict:
    return {"success": False, "error": {"code": code, "message": message},
            "timestamp": int(time.time() * 1000)}
```

**b. Update all no-session `KeyError` catch sites** (lines ~3289, 3313, 3331, 3365) to pass `code="NO_SESSION"`:
```python
except KeyError as e:
    return _unicorn_error(str(e), code="NO_SESSION")
```
There are 4 sites: `unicorn_hook_set`, `unicorn_hook_clear`, `unicorn_hook_list`, `unicorn_call`. Update all four.

**c. Add `ValueError` guard to `unicorn_hook_clear`:**
```python
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
        return _unicorn_error(str(e), code="NO_SESSION")
    try:
        addr_int = int(address, 16)
    except ValueError:
        return _unicorn_error(f"invalid address: {address!r}", code="VALIDATION")
    removed = session.clear_hook(addr_int)
    return {"success": True, "address": hex(addr_int), "removed": removed,
            "timestamp": int(time.time() * 1000)}
```

**d. Add `count` parameter to `unicorn_call`:**
```python
@mcp.tool()
@text_output
def unicorn_call(func: str, args: list | None = None, convention: str = "sysv",
                 count: int = 1_000_000, trace: bool = False,
                 port: int | None = None) -> dict:
    """Call a function in the Unicorn session and report its return value.

    Precondition: use unicorn_hook_set to stub any imports the function will
    call, or they will fault. Hooks persist until cleared or the session is
    reset.

    Sets up the x86-64 calling convention (sysv default, or ms), runs the
    function to a synthetic return address, and returns the return register.
    args is a list of ints and/or {"bytes": hex} pointer args; floats and
    by-value structs are not supported.

    success is true only when the function returned cleanly (stop_reason DONE).
    A HOOK_TRAP / REDIRECT_STORM / LAZY_FETCH_FAILED / ERROR stop returns
    success=false with the partial state so you can add a missing hook and retry.

    Args:
        func: Function entry address in hex
        args: List of int args and/or {"bytes": "hex"} pointer args (optional)
        convention: "sysv" (default) or "ms"
        count: Instruction budget (default 1_000_000)
        trace: Collect executed-instruction trace + memory writes
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e), code="NO_SESSION")
    from ghydra.dynamic.unicorn_engine import StopReason
    try:
        state = session.call(int(func, 16), args or [], convention,
                             count=count, trace=trace)
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

- [ ] **Step 4: Run all bridge tests**

```
python -m pytest tests/test_bridge_unicorn_hooks.py -v
```
Expected: all PASS (5 existing + 5 new = 10 total)

- [ ] **Step 5: Commit**

```
git add bridge_mcp_hydra.py tests/test_bridge_unicorn_hooks.py
git commit -m "fix(bridge): hook_clear ValueError guard; count param; NO_SESSION error code"
```

---

### Task 8: CLI cleanup

**Files:**
- Modify: `ghydra/cli/dynamic.py`

**No new tests** — the existing `test_dynamic_cli.py` suite must still pass.

- [ ] **Step 1: Apply changes**

**a. Collapse the awkward two-line comment** at lines 124-125:
```python
# Click cannot interleave two multiple=True options; ints always precede bytes-args.
args: list = [int(a, 0) for a in int_args]
```

**b. Simplify the exception handler** at lines 143-144:
```python
    except ValueError as e:
        raise click.ClickException(str(e))
    except GhidraError as e:
```
(Remove `click.ClickException` from the except clause — it propagates naturally without being caught and re-raised.)

- [ ] **Step 2: Run CLI tests**

```
python -m pytest tests/test_dynamic_cli.py -v
```
Expected: all PASS

- [ ] **Step 3: Commit**

```
git add ghydra/cli/dynamic.py
git commit -m "fix(cli): collapse awkward comment; simplify exception handler in call command"
```

---

### Task 9: Behavioral test gaps

**Files:**
- Test: `tests/test_unicorn_engine.py`

Adds the four behavioral tests identified as important gaps in the test coverage review.

- [ ] **Step 1: Add skip action behavioral test**

Add to `tests/test_unicorn_engine.py`:
```python
def test_skip_hook_leaves_rax_unchanged():
    """skip simulates ret without modifying RAX; a regression setting RAX=0
    on skip would be caught here."""
    s = UnicornSession()
    base = 0x140075000
    import_addr = base + 0x100

    # Function body:
    #   mov eax, 0x2a   (b8 2a 00 00 00)
    #   call import     (e8 <rel>)
    #   ret             (c3)
    rel = (import_addr - (base + 5) - 5) & 0xffffffff
    code = (b"\xb8\x2a\x00\x00\x00"
            + b"\xe8" + rel.to_bytes(4, "little")
            + b"\xc3")
    s.map_bytes(base, code)
    s.map_bytes(import_addr, b"\x90")   # one byte at import target
    s.set_hook(import_addr, Hook(action="skip"))

    out = s.call(func_addr=base, args=[], convention="sysv")
    assert out["stop_reason"] == "DONE"
    assert out["return_value"] == 0x2a  # skip left RAX as set by mov eax,0x2a
```

- [ ] **Step 2: Add mem_writes side-effect emulation test**

```python
def test_return_const_mem_writes_are_applied():
    """The mem_writes side-effect of return_const must actually write to the
    target address; this is the emulation-level contract, not just the bridge
    precondition check."""
    s = UnicornSession()
    base = 0x140075000
    import_addr = base + 0x100
    target_addr = 0x140076000

    rel = (import_addr - (base + 5)) & 0xffffffff
    code = b"\xe8" + rel.to_bytes(4, "little") + b"\xc3"
    s.map_bytes(base, code)
    s.map_bytes(import_addr, b"\x90")
    s.map_bytes(target_addr, b"\x00" * 4)

    hook = Hook(action="return_const", return_value=0,
                mem_writes=[{"address": target_addr, "hex": "41424344"}])
    s.set_hook(import_addr, hook)

    state = s.run(begin=base, until=0, count=50)
    assert state["stop_reason"] == "DONE"
    assert s.read_memory(target_addr, 4) == b"\x41\x42\x43\x44"
```

- [ ] **Step 3: Add MS convention call() test**

```python
def test_call_passes_args_in_ms_registers():
    """MS convention passes first arg in RCX, not RDI (SysV)."""
    s = UnicornSession()
    base = 0x140075000
    # mov rax, rcx ; ret   (48 8b c1 ; c3)
    s.map_bytes(base, bytes.fromhex("488bc1c3"))
    out = s.call(func_addr=base, args=[0xbeef], convention="ms")
    assert out["stop_reason"] == "DONE"
    assert out["return_value"] == 0xbeef
```

- [ ] **Step 4: Run all new tests**

```
python -m pytest tests/test_unicorn_engine.py -v -k "skip_hook or mem_writes_are or ms_registers"
```
Expected: all 3 PASS

- [ ] **Step 5: Run full suite**

```
python -m pytest tests/test_calling_convention.py tests/test_unicorn_engine.py tests/test_bridge_unicorn_hooks.py tests/test_dynamic_cli.py -v
```
Expected: all PASS (all existing + all new)

- [ ] **Step 6: Commit**

```
git add tests/test_unicorn_engine.py
git commit -m "test(dynamic): add behavioral tests for skip/mem_writes/MS-convention gaps"
```

---

## Self-Review

### Spec coverage check

| Finding | Addressed by |
|---------|-------------|
| CRITICAL: UcError in _code_hook FFI | Task 4 |
| CRITICAL: hook_clear missing ValueError | Task 7 |
| CRITICAL: StopReason docstring "four states" | Task 3 (docstring in Enum) |
| CRITICAL: simulate_ret docstring false claim | Task 6 |
| HIGH: Redirect storm 1M emu_start calls | Task 3 (separate cap + REDIRECT_STORM) |
| HIGH: call() mutates before full validation | Task 5 |
| HIGH: unicorn_call missing count param | Task 7 |
| HIGH: bytes.fromhex in _code_hook unguarded | Task 2 (Hook.__post_init__ pre-validates) + Task 4 (try/except) |
| IMPORTANT: Sentinel page-aligned vs exact | Task 5 |
| IMPORTANT: All errors code "UNICORN" | Task 7 |
| IMPORTANT: No re-entrancy guard (pre-existing) | Not addressed — pre-existing, out of scope |
| IMPORTANT: Hook lacks frozen/invariants | Task 2 |
| IMPORTANT: StopReason not str-enum | Task 3 |
| IMPORTANT: VALID_HOOK_ACTIONS no exhaustive else | Task 4 (else branch added) |
| IMPORTANT: call() WHAT-comments | Task 5 (call() rewrite removes them) |
| SUGGESTION: removed: false under success: true | Not addressed — clear returns `removed` field, caller can inspect |
| SUGGESTION: call() missing trace key | Task 5 |
| SUGGESTION: validate_args hex content | Task 1 |
| SUGGESTION: Hook return_value on non-return_const | Task 2 |
| SUGGESTION: hex in mem_writes not validated at Hook | Task 2 |
| SUGGESTION: v1 scope in docstring | Task 1 |
| SUGGESTION: Module docstring Unit-tested directly | Task 1 |
| SUGGESTION: unicorn_call precondition buried | Task 7 |
| SUGGESTION: CLI comment awkward | Task 8 |
| SUGGESTION: CLI ClickException redundant | Task 8 |
| TEST GAP: skip behavioral | Task 9 |
| TEST GAP: mem_writes at emulation level | Task 9 |
| TEST GAP: MS convention in call() | Task 9 |
| TEST GAP: bridge no-session for set/clear/list | Task 7 |
| TEST GAP: hook_clear bad address | Task 7 |
| TEST GAP: redirect storm steps check | Task 3 (new test asserts steps == 0) |
| TEST GAP: count param in unicorn_call | Task 7 |

### Placeholder scan
No TBD, TODO, or "similar to Task N" patterns found.

### Type consistency
- `Hook` dataclass fields unchanged: `action: str`, `return_value: int | None`, `mem_writes: list[dict] | None`
- `StopReason` members keep identical string values — `StopReason.DONE == "DONE"` stays true
- `_unicorn_error(message, code)` — new optional `code` param with default `"UNICORN"` is backward-compatible with all existing call sites

---

**Plan complete and saved to `docs/superpowers/plans/2026-06-24-pr-review-fixes.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — fresh subagent per task, review between tasks

**2. Inline Execution** — execute tasks in this session using executing-plans skill

Which approach?
