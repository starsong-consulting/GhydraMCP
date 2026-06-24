# Unicorn Dynamic-Emulation Hardening (Follow-up) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the deferred hardening, usability, and coverage items left out of the Unicorn lazy-mapping failure-contract work — a distinct cap stop-reason, a typed-error hierarchy, an explicit map primitive + opt-in auto-stack, internal encapsulation, session-dict locking, a trace-truncation signal, narrower CLI error handling, and the negative-path tests that the contract plan deferred.

**Architecture:** Each item is an independent, individually-committable change to the existing dynamic-emulation stack (Python `UnicornSession` engine → `ghidra_provider` → `bridge_mcp_hydra` MCP tools → `ghydra dynamic` CLI). Tasks are ordered low-risk-foundational first (typed error, stop-reason) → internal refactor → user-facing features (map primitive, auto-stack) → infrastructure (locking, error-narrowing) → pure test coverage. The one cross-subsystem item (Java/PCode `stepOnce`) is isolated as the final task and may be split into its own plan.

**Tech Stack:** Python 3.11+, `unicorn>=2.0` (optional), `GhidraHTTPClient`, FastMCP bridge, Click CLI; `pytest` with fake clients/providers (no live Ghidra); Java 21 / Ghidra 11.x–12.x + JUnit for the final task only.

**Spec:** `docs/superpowers/specs/2026-06-21-unicorn-failure-contract-design.md` (§"Out of scope (follow-up plan)"), plus round-2 PR-review findings #3 (cap stop-reason) and #5 (`ProviderError` hierarchy).

## Global Constraints

- `requires-python = ">=3.11"`. Unicorn is an optional dependency; pure-logic tests (provider error shaping, `_unicorn_run_result`, the `_apply_default_stack` helper via a real session) gate engine/session construction behind `pytest.importorskip("unicorn")`. Tests of the no-unicorn path monkeypatch `_HAVE_UNICORN` and must NOT importorskip.
- **Purist contract is preserved:** lazy mapping serves only real image bytes; callers establish scratch/stack explicitly. The new auto-stack is an opt-in convenience layered on the existing `UnicornSession.map_bytes(addr, b"\x00" * size)` — it does NOT relax the contract.
- **Stop reasons:** existing `DONE` / `COUNT` / `ERROR` / `LAZY_FETCH_FAILED`; this plan adds `LAZY_CAP_REACHED`. `success: true` only for `DONE`. The four non-DONE reasons are all `success: false`.
- The lazy hook runs inside a Unicorn C callback: it MUST NOT let an exception cross `emu_start`. It catches at that boundary, records the message/reason, and returns `False` to fault.
- Page size is `UnicornSession.PAGE = 0x1000`; addresses align down before `mem_map`. Register/address values cross the bridge/CLI as hex strings.
- Bump `BRIDGE_VERSION` (`bridge_mcp_hydra.py`) once, in the final Python commit, to `v3.1.0-rc.3`; `API_VERSION` is unchanged (additive fields only). The Unicorn feature is still in the `[Unreleased]` CHANGELOG section — update that section, do NOT add a released heading. Do NOT bump `pyproject.toml` `version`. Conventional-commit messages. End every commit message with the `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` trailer.
- Run the full suite (`python -m pytest -q`) green before each commit that touches Python.

---

### Task 1: `ProviderError` joins the `GhidraError` hierarchy

Review finding #5: `ProviderError(Exception)` sits outside the existing `GhidraError` base (`ghydra/client/exceptions.py`), so if one ever escaped the engine's boundary catch the CLI's `except GhidraError` would not catch it. Re-parent it. It never escapes today, so this is defensive hygiene with no behavior change on the happy path.

**Files:**
- Modify: `ghydra/dynamic/exceptions.py`
- Test: `tests/test_ghidra_provider.py` (add one case)

**Interfaces:**
- Consumes: `ghydra.client.exceptions.GhidraError` (existing base).
- Produces: `ProviderError` is now a subclass of `GhidraError` (still importable from `ghydra.dynamic.exceptions`; constructor unchanged).

- [ ] **Step 1: Write the failing test** — append to `tests/test_ghidra_provider.py`:

```python
def test_provider_error_is_a_ghidra_error():
    from ghydra.dynamic.exceptions import ProviderError
    from ghydra.client.exceptions import GhidraError
    assert issubclass(ProviderError, GhidraError)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/test_ghidra_provider.py::test_provider_error_is_a_ghidra_error -q`
Expected: FAIL — `ProviderError` subclasses `Exception`, not `GhidraError`.

- [ ] **Step 3: Re-parent the exception** — replace the entire contents of `ghydra/dynamic/exceptions.py`:

```python
"""Exceptions for the dynamic (Unicorn) emulation subsystem."""

from ..client.exceptions import GhidraError


class ProviderError(GhidraError):
    """A lazy byte-provider could not return real image bytes for an address.

    Raised when the underlying fetch failed (transport/API error), when the
    source has no bytes for the address, or when the response was malformed.
    Its message is embedded into run()'s ``last_error`` (wrapped with the
    faulting page address) when the resulting access faults. Subclasses
    GhidraError so it is caught uniformly by the CLI's ``except GhidraError``
    handlers if it ever escapes the engine's boundary catch.
    """
```

- [ ] **Step 4: Run the provider tests to verify they pass**

Run: `python -m pytest tests/test_ghidra_provider.py -q`
Expected: PASS (5 tests — the 4 existing plus the new hierarchy check; the existing `pytest.raises(ProviderError)` cases still hold because subclassing does not change what is raised).

- [ ] **Step 5: Commit**

```bash
git add ghydra/dynamic/exceptions.py tests/test_ghidra_provider.py
git commit -m "fix(dynamic): ProviderError subclasses GhidraError for uniform CLI handling"
```

---

### Task 2: Distinct `LAZY_CAP_REACHED` stop reason (+ `max_lazy_pages` coverage)

Review finding #3: hitting the `max_lazy_pages` budget currently faults as a generic `ERROR` with a raw Unicorn message, indistinguishable from a corrupt binary — the operator gets no signal to raise the budget. Give it its own stop reason. The `byte_provider is None` guard stays a plain `ERROR` (no provider configured means the caller is in manual-mapping mode; a raw unmapped fault is the correct, honest signal there — not worth a dedicated reason).

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py` (`StopReason`, the lazy hook, the `except UcError` classification)
- Modify: `bridge_mcp_hydra.py` (`unicorn_run` docstring only — taxonomy mention)
- Test: `tests/test_unicorn_engine.py`, `tests/test_bridge_unicorn.py`

**Interfaces:**
- Consumes: `StopReason` (existing).
- Produces: `StopReason.LAZY_CAP_REACHED = "LAZY_CAP_REACHED"`. `run()`'s `lazy_fail` closure becomes `{"msg": None, "reason": None}`; on a lazy fault the recorded `reason` (a `StopReason` value) becomes `stop_reason`. `_unicorn_run_result` needs no change — its `else` branch already maps any non-DONE/COUNT reason to an error envelope with `code == stop_reason`.

- [ ] **Step 1: Write the failing tests** — append to `tests/test_unicorn_engine.py`:

```python
def test_lazy_cap_reached_faults_with_distinct_reason():
    base = 0x140075000

    def provider(address, length):
        return b"\x90" * length          # real bytes, but the cap forbids mapping

    s = UnicornSession(byte_provider=provider)
    s.set_register("RIP", base)
    # max_lazy_pages=0 -> the very first lazy map is already over budget.
    state = s.run(begin=base, until=base + 2, count=10, max_lazy_pages=0)
    assert state["stop_reason"] == "LAZY_CAP_REACHED"
    assert state["last_error"] and "max_lazy_pages" in state["last_error"]
```

And append to `tests/test_bridge_unicorn.py`:

```python
def test_lazy_cap_reached_is_failure_with_budget_hint():
    r = _unicorn_run_result(_state("LAZY_CAP_REACHED",
                                   "lazy page cap (4096) reached at 0x140075000; raise max_lazy_pages"))
    assert r["success"] is False
    assert r["error"]["code"] == "LAZY_CAP_REACHED"
    assert "max_lazy_pages" in r["error"]["message"]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_unicorn_engine.py -k lazy_cap tests/test_bridge_unicorn.py -k lazy_cap -q`
Expected: FAIL — engine reports `ERROR` (no `LAZY_CAP_REACHED`); the bridge test fails only on the engine-produced reason if run together, but as a pure-helper test it actually passes once the string is supplied — run it after Step 3 to confirm. The engine test is the gate.

- [ ] **Step 3: Add the stop reason** — in `ghydra/dynamic/unicorn_engine.py`, add to the `StopReason` class body (after `LAZY_FETCH_FAILED`):

```python
    LAZY_CAP_REACHED = "LAZY_CAP_REACHED"
```

- [ ] **Step 4: Rewrite the hook guard + failure recording** — replace the `lazy = {"n": 0}` / `lazy_fail = {"msg": None}` / `_unmapped_hook` block (current lines ~79–98) with:

```python
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
            uc.mem_map(page, self.PAGE)
            self._mapped.add(page)
            uc.mem_write(page, data[:self.PAGE])
            lazy["n"] += 1
            return True  # retry the faulting access
```

- [ ] **Step 5: Classify by recorded reason** — replace the `except UcError as e:` block (current lines ~111–117):

```python
        except UcError as e:
            if lazy_fail["reason"] is not None:
                stop_reason = lazy_fail["reason"]
                last_error = lazy_fail["msg"]
            else:
                stop_reason = StopReason.ERROR
                last_error = str(e)
```

- [ ] **Step 6: Mention the reason in the `unicorn_run` docstring** — in `bridge_mcp_hydra.py`, in the `unicorn_run` docstring, replace the sentence `any other emulator fault returns "ERROR".` with:

```
exhausting the lazy-page budget returns "LAZY_CAP_REACHED" (raise the
engine's max_lazy_pages); any other emulator fault returns "ERROR".
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `python -m pytest tests/test_unicorn_engine.py tests/test_bridge_unicorn.py -q && python -c "import bridge_mcp_hydra"`
Expected: PASS (all engine + bridge tests, including the two new ones; bridge imports).

- [ ] **Step 8: Commit**

```bash
git add ghydra/dynamic/unicorn_engine.py bridge_mcp_hydra.py tests/test_unicorn_engine.py tests/test_bridge_unicorn.py
git commit -m "feat(dynamic): distinct LAZY_CAP_REACHED stop reason for page-budget exhaustion"
```

---

### Task 3: Privatize `UnicornSession.uc` → `_uc`; route the hook map through `_ensure_mapped`

Spec deferral: `uc` is public but only ever used internally (verified: no reader of `session.uc` exists outside the engine). Privatize it and have the lazy hook map via the existing `_ensure_mapped` helper instead of duplicating `mem_map` + `_mapped.add`. Pure refactor; the existing engine tests are the regression gate.

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py` (rename `self.uc` → `self._uc` at all sites; hook uses `_ensure_mapped`)
- Test: `tests/test_unicorn_engine.py` (one encapsulation assertion)

**Interfaces:**
- Produces: `UnicornSession._uc` replaces `UnicornSession.uc`; no public method signature changes. The lazy hook calls `self._ensure_mapped(page, self.PAGE)` then `self._uc.mem_write(...)`.

- [ ] **Step 1: Write the failing test** — append to `tests/test_unicorn_engine.py`:

```python
def test_unicorn_handle_is_private():
    s = UnicornSession()
    assert hasattr(s, "_uc")
    assert not hasattr(s, "uc")
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/test_unicorn_engine.py::test_unicorn_handle_is_private -q`
Expected: FAIL — `s.uc` still exists (`assert not hasattr(s, "uc")` fails).

- [ ] **Step 3: Rename the handle** — in `ghydra/dynamic/unicorn_engine.py`, rename every `self.uc` to `self._uc`. The sites are: `__init__` (`self.uc = Uc(...)`), `_ensure_mapped` (`self.uc.mem_map`), `map_bytes` (`self.uc.mem_write`), `read_memory` (`self.uc.mem_read`), `set_register` (`self.uc.reg_write`), `get_register` (`self.uc.reg_read`), and in `run`: `h_code = self.uc.hook_add`, `h_write = self.uc.hook_add`, `h_unmapped = self.uc.hook_add`, `self.uc.emu_start`, and the three `self.uc.hook_del(...)` in the `finally`. (The callback parameter named `uc` is unchanged — it is Unicorn's argument, not the attribute.)

- [ ] **Step 4: Route the hook map through `_ensure_mapped`** — in the lazy hook, replace the success-path lines:

```python
            uc.mem_map(page, self.PAGE)
            self._mapped.add(page)
            uc.mem_write(page, data[:self.PAGE])
```

with:

```python
            self._ensure_mapped(page, self.PAGE)   # maps the page + records it in _mapped
            self._uc.mem_write(page, data[:self.PAGE])
```

- [ ] **Step 5: Run the full engine suite to verify it passes**

Run: `python -m pytest tests/test_unicorn_engine.py -q`
Expected: PASS — all engine tests, including the new privatization check and the unchanged lazy-mapping / cap / fault tests (the hook still maps and writes real bytes; `_ensure_mapped` is the same map-and-track logic).

- [ ] **Step 6: Commit**

```bash
git add ghydra/dynamic/unicorn_engine.py tests/test_unicorn_engine.py
git commit -m "refactor(dynamic): privatize UnicornSession handle (_uc); hook maps via _ensure_mapped"
```

---

### Task 4: Trace-truncation signal

Spec deferral: `trace`/`mem_writes` silently stop appending at `_TRACE_CAP` (100000); a caller cannot tell a complete trace from a truncated one. Add a `trace_truncated` boolean to `run()`'s output and surface it in the bridge (DONE payload) and CLI (`run` trace line).

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py` (`run`: track + return the flag)
- Modify: `bridge_mcp_hydra.py` (`_unicorn_run_result` DONE branch)
- Modify: `ghydra/cli/dynamic.py` (`run` trace line)
- Test: `tests/test_unicorn_engine.py`

**Interfaces:**
- Produces: `run()` return dict gains `"trace_truncated": bool` (True iff `trace=True` and either list hit `_TRACE_CAP`). `_unicorn_run_result`'s DONE payload gains `"trace_truncated": state.get("trace_truncated", False)`.

- [ ] **Step 1: Write the failing test** — append to `tests/test_unicorn_engine.py`:

```python
def test_trace_truncation_flag(monkeypatch):
    from ghydra.dynamic import unicorn_engine
    monkeypatch.setattr(unicorn_engine, "_TRACE_CAP", 2)   # cap the trace at 2 entries
    s = UnicornSession()
    base = 0x140075000
    s.map_bytes(base, b"\x90\x90\x90\x90")                 # four nops
    s.set_register("RIP", base)
    state = s.run(begin=base, until=base + 4, count=10, trace=True)
    assert state["stop_reason"] == "DONE"
    assert len(state["trace"]) == 2                        # appended only up to the cap
    assert state["trace_truncated"] is True


def test_clean_trace_is_not_truncated():
    s = UnicornSession()
    base = 0x140075000
    s.map_bytes(base, b"\x90\x90")
    s.set_register("RIP", base)
    state = s.run(begin=base, until=base + 2, count=10, trace=True)
    assert state["trace_truncated"] is False
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_unicorn_engine.py -k "trace_truncation or clean_trace" -q`
Expected: FAIL — `run()` has no `trace_truncated` key (KeyError).

- [ ] **Step 3: Track truncation in the hooks** — in `ghydra/dynamic/unicorn_engine.py` `run`, replace the `executed`/`mem_writes` setup and the two trace hooks (current lines ~67–77):

```python
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
```

- [ ] **Step 4: Return the flag** — in the `return {...}` dict, add the key (after `"mem_writes"`):

```python
            "trace_truncated": trace_trunc["hit"],
```

- [ ] **Step 5: Surface it in the bridge** — in `bridge_mcp_hydra.py` `_unicorn_run_result`, in the `if stop == StopReason.DONE:` branch, after the `payload["mem_writes"] = [...]` assignment and before `return payload`, add:

```python
        payload["trace_truncated"] = state.get("trace_truncated", False)
```

- [ ] **Step 6: Surface it in the CLI** — in `ghydra/cli/dynamic.py` `run`, replace the `if trace:` block:

```python
        if trace:
            suffix = " (truncated)" if state.get("trace_truncated") else ""
            click.echo(f"  trace: {len(state['trace'])} instrs, "
                       f"{len(state['mem_writes'])} writes{suffix}")
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `python -m pytest tests/test_unicorn_engine.py tests/test_bridge_unicorn.py -q && python -c "import bridge_mcp_hydra"`
Expected: PASS (engine + bridge; the existing bridge DONE test still passes because its `_state` has no trace_truncated key and the DONE branch reads it via `.get`).

- [ ] **Step 8: Commit**

```bash
git add ghydra/dynamic/unicorn_engine.py bridge_mcp_hydra.py ghydra/cli/dynamic.py tests/test_unicorn_engine.py
git commit -m "feat(dynamic): surface trace_truncated when the trace hits _TRACE_CAP"
```

---

### Task 5: Explicit map primitive (`unicorn_map` tool + `ghydra dynamic map`)

Spec deferral (usability): the purist contract faults the instant emulated code touches un-pre-mapped memory (e.g. a stack `push`). Expose the engine's existing `map_bytes` zero-fill as a first-class MCP tool and CLI command so callers can establish scratch/stack/IO regions explicitly. (Auto-stack — Task 6 — builds on this.)

**Files:**
- Modify: `bridge_mcp_hydra.py` (new `unicorn_map` tool, near the other `unicorn_*` tools)
- Modify: `ghydra/cli/dynamic.py` (new `map` command)
- Test: `tests/test_bridge_unicorn.py`, `tests/test_dynamic_cli.py`

**Interfaces:**
- Consumes: `UnicornSession.map_bytes` (existing); `_get_unicorn_session`, `_unicorn_error` (existing).
- Produces: `unicorn_map(address: str, size: int, port: int | None = None) -> dict` — maps a zero-filled region (page-aligned by the engine) and returns `{"success": True, "address", "size"}`. CLI: `ghydra dynamic map --address <hex> --size <n>`.

- [ ] **Step 1: Write the failing tests** — append to `tests/test_bridge_unicorn.py`:

```python
def test_unicorn_map_zero_fills_a_region():
    pytest.importorskip("unicorn")
    import bridge_mcp_hydra as b
    from ghydra.dynamic.unicorn_engine import UnicornSession
    b._UNICORN_SESSIONS[8192] = UnicornSession()
    try:
        # call the undecorated function to inspect the raw dict
        result = b.unicorn_map.__wrapped__("0x140070000", 0x2000, port=8192)
        assert result["success"] is True
        session = b._UNICORN_SESSIONS[8192]
        assert session.read_memory(0x140070000, 8) == b"\x00" * 8   # mapped + zeroed
    finally:
        b._UNICORN_SESSIONS.pop(8192, None)
```

Add `import pytest` at the top of `tests/test_bridge_unicorn.py` if not already present.

And append to `tests/test_dynamic_cli.py`:

```python
def test_map_command_reports_mapped_region():
    from ghydra.cli.dynamic import map as dyn_map

    class OkClient:
        def get(self, endpoint, params=None):
            raise AssertionError("map must not hit Ghidra")

    result = CliRunner().invoke(
        dyn_map,
        ["--address", "0x140070000", "--size", "8192"],
        obj={"client": OkClient(), "formatter": TableFormatter(use_colors=False), "config": None},
    )
    assert result.exit_code == 0
    assert "0x140070000" in result.output
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_bridge_unicorn.py -k unicorn_map tests/test_dynamic_cli.py -k map_command -q`
Expected: FAIL — `unicorn_map` / `dyn_map` do not exist (AttributeError / ImportError).

- [ ] **Step 3: Add the bridge tool** — in `bridge_mcp_hydra.py`, immediately after the `unicorn_set_register` tool (before `unicorn_get_state`), add:

```python
@mcp.tool()
@text_output
def unicorn_map(address: str, size: int, port: int | None = None) -> dict:
    """Map a zero-filled scratch region into the Unicorn session.

    The purist lazy mapper serves only real Ghidra image bytes, so emulated
    code that touches non-image memory (a stack push, a heap/IO buffer) faults
    with LAZY_FETCH_FAILED unless that region is mapped first. Use this to set
    up stack/scratch/output buffers before unicorn_run. Page-aligned by the
    engine.

    Args:
        address: Region start in hex
        size: Region size in bytes
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e))
    addr = int(address, 16)
    session.map_bytes(addr, b"\x00" * size)
    return {"success": True, "address": hex(addr), "size": size,
            "timestamp": int(time.time() * 1000)}
```

- [ ] **Step 4: Add the CLI command** — in `ghydra/cli/dynamic.py`, after the `dump` command, add:

```python
@dynamic.command('map')
@click.option('--address', '-a', required=True, help='Region start (hex)')
@click.option('--size', '-n', type=int, required=True, help='Region size in bytes')
@click.pass_context
def map(ctx, address, size):
    """Map a zero-filled scratch region (e.g. a stack) before run/dump."""
    try:
        session = _make_session(ctx)
        addr = int(validate_address(address), 16)
        session.map_bytes(addr, b"\x00" * size)
        click.echo(f"mapped {hex(addr)} +{size}")
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)
```

Note: `_make_session` builds a session whose lifetime is this single CLI invocation, so `map` is only meaningful in code that holds a session across calls — keep it for symmetry/scripting and document that the CLI session is per-process (the persistent map workflow lives on the MCP side). This is acceptable; the CLI `run`/`dump` already create-and-discard a session per call.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/test_bridge_unicorn.py tests/test_dynamic_cli.py -q && python -c "import bridge_mcp_hydra"`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add bridge_mcp_hydra.py ghydra/cli/dynamic.py tests/test_bridge_unicorn.py tests/test_dynamic_cli.py
git commit -m "feat(dynamic): explicit zero-fill map primitive (unicorn_map tool + dynamic map CLI)"
```

---

### Task 6: Opt-in auto-stack on `unicorn_reset`

Spec deferral (usability): with the explicit primitive in place, make the common case work out of the box — `unicorn_reset` maps a default scratch stack and points RSP/RBP at it, unless the caller opts out with `stack=False`. Extract the logic into a testable `_apply_default_stack` helper (the decorated tool is awkward to assert on directly).

**Files:**
- Modify: `bridge_mcp_hydra.py` (`_apply_default_stack` helper + `unicorn_reset` signature/body/docstring)
- Test: `tests/test_bridge_unicorn.py`

**Interfaces:**
- Consumes: `UnicornSession.map_bytes`, `set_register` (existing).
- Produces: `_apply_default_stack(session) -> tuple[int, int]` (maps a 1 MiB stack at base `0x7ffff0000000`, sets RSP=RBP to `base + size - 0x1000`, returns `(base, size)`). `unicorn_reset` gains `stack: bool = True`; when true it applies the default stack *before* the caller's explicit `registers` (so an explicit RSP override wins).

- [ ] **Step 1: Write the failing tests** — append to `tests/test_bridge_unicorn.py`:

```python
def test_apply_default_stack_maps_and_points_rsp():
    pytest.importorskip("unicorn")
    from ghydra.dynamic.unicorn_engine import UnicornSession
    from bridge_mcp_hydra import _apply_default_stack
    s = UnicornSession()
    base, size = _apply_default_stack(s)
    rsp = s.get_register("RSP")
    assert base <= rsp < base + size
    assert s.get_register("RBP") == rsp
    assert s.read_memory(rsp - 8, 8) == b"\x00" * 8   # stack is mapped + zeroed
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/test_bridge_unicorn.py -k apply_default_stack -q`
Expected: FAIL — `_apply_default_stack` does not exist (ImportError).

- [ ] **Step 3: Add the helper** — in `bridge_mcp_hydra.py`, immediately after `_unicorn_run_result`, add:

```python
_DEFAULT_STACK_BASE = 0x7ffff0000000
_DEFAULT_STACK_SIZE = 0x100000          # 1 MiB scratch stack


def _apply_default_stack(session) -> tuple[int, int]:
    """Map a default scratch stack and point RSP/RBP at it.

    Convenience so a freshly reset session can execute stack-using code
    (push/call) without the caller mapping a stack by hand. Returns the
    (base, size) of the mapped region. Caller-established scratch memory is
    allowed by the purist contract; this does not relax lazy mapping.
    """
    session.map_bytes(_DEFAULT_STACK_BASE, b"\x00" * _DEFAULT_STACK_SIZE)
    rsp = _DEFAULT_STACK_BASE + _DEFAULT_STACK_SIZE - 0x1000
    session.set_register("RSP", rsp)
    session.set_register("RBP", rsp)
    return _DEFAULT_STACK_BASE, _DEFAULT_STACK_SIZE
```

- [ ] **Step 4: Wire it into `unicorn_reset`** — in `bridge_mcp_hydra.py`, change the `unicorn_reset` signature and body. Replace the signature line:

```python
def unicorn_reset(start: str, registers: dict | None = None, port: int | None = None) -> dict:
```

with:

```python
def unicorn_reset(start: str, registers: dict | None = None, stack: bool = True,
                  port: int | None = None) -> dict:
```

Then replace the body block from `start_int = int(start, 16)` through the `return {...}` (current lines ~3091–3098) with:

```python
    start_int = int(start, 16)
    session.set_register("RIP", start_int)
    stack_region = None
    if stack:
        base, size = _apply_default_stack(session)
        stack_region = {"base": hex(base), "size": size}
    if registers:
        for name, value in registers.items():
            session.set_register(name, int(value, 16))   # explicit overrides win (e.g. RSP)
    _UNICORN_SESSIONS[port] = session
    return {"success": True, "start": hex(start_int), "lazy_mapping": "ghidra",
            "stack": stack_region, "timestamp": int(time.time() * 1000)}
```

Add to the `unicorn_reset` docstring's Args (after the `registers:` line):

```
        stack: Auto-map a default 1 MiB scratch stack and point RSP/RBP at it
            (default True; pass False to manage the stack yourself)
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/test_bridge_unicorn.py -q && python -c "import bridge_mcp_hydra"`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add bridge_mcp_hydra.py tests/test_bridge_unicorn.py
git commit -m "feat(dynamic): opt-in default scratch stack on unicorn_reset"
```

---

### Task 7: Lock the Unicorn session registry

Spec deferral: `_UNICORN_SESSIONS` is read/written from MCP tool handlers with no lock, unlike `instances_lock` which guards the instance registry. Add a dedicated lock around the dict's get/set/pop (NOT around `session.run()`, which is long-running — parity with `instances_lock`, which only guards the registry dict).

**Files:**
- Modify: `bridge_mcp_hydra.py` (`_unicorn_lock`; `_get_unicorn_session`, `unicorn_reset` insert, `unicorn_dispose` pop)
- Test: `tests/test_bridge_unicorn.py`

**Interfaces:**
- Produces: `_unicorn_lock = Lock()`; `_get_unicorn_session` acquires it around the `.get`; the registry insert in `unicorn_reset` and the `.pop` in `unicorn_dispose` are wrapped.

- [ ] **Step 1: Write the failing test** — append to `tests/test_bridge_unicorn.py`:

```python
def test_unicorn_registry_has_a_lock():
    import bridge_mcp_hydra as b
    from threading import Lock
    assert isinstance(b._unicorn_lock, type(Lock()))
```

(`type(Lock())` is the concrete lock type; `isinstance` against it confirms `_unicorn_lock` is a real lock object.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/test_bridge_unicorn.py -k registry_has_a_lock -q`
Expected: FAIL — `_unicorn_lock` does not exist (AttributeError).

- [ ] **Step 3: Add the lock** — in `bridge_mcp_hydra.py`, replace the `_UNICORN_SESSIONS` declaration line:

```python
_UNICORN_SESSIONS: dict[int, "object"] = {}
```

with:

```python
_UNICORN_SESSIONS: dict[int, "object"] = {}
_unicorn_lock = Lock()
```

- [ ] **Step 4: Guard the registry accesses** — replace `_get_unicorn_session`:

```python
def _get_unicorn_session(port: int):
    with _unicorn_lock:
        session = _UNICORN_SESSIONS.get(port)
    if session is None:
        raise KeyError("No Unicorn session; call unicorn_reset first")
    return session
```

In `unicorn_reset`, replace `    _UNICORN_SESSIONS[port] = session` with:

```python
    with _unicorn_lock:
        _UNICORN_SESSIONS[port] = session
```

In `unicorn_dispose`, replace `    _UNICORN_SESSIONS.pop(port, None)` with:

```python
    with _unicorn_lock:
        _UNICORN_SESSIONS.pop(port, None)
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/test_bridge_unicorn.py -q && python -c "import bridge_mcp_hydra"`
Expected: PASS (the new lock test plus all existing bridge tests — the lock is uncontended in single-threaded tests).

- [ ] **Step 6: Commit**

```bash
git add bridge_mcp_hydra.py tests/test_bridge_unicorn.py
git commit -m "fix(dynamic): lock the Unicorn session registry (parity with instances_lock)"
```

---

### Task 8: Narrow `_make_session` error handling (+ missing-dependency test)

Spec deferral: the CLI `_make_session` catches `(ImportError, RuntimeError)` around the import AND a bare `RuntimeError` around construction, both mapped to "unicorn not installed" — so any unrelated `RuntimeError` from construction is mislabeled. Narrow it: the import only raises `ImportError`; construction's "unicorn not installed" is the specific `RuntimeError` raised by `UnicornSession.__init__`, which should be distinguished from other failures.

**Files:**
- Modify: `ghydra/cli/dynamic.py` (`_make_session`)
- Test: `tests/test_unicorn_engine.py` (missing-dependency `RuntimeError`)

**Interfaces:**
- Produces: `_make_session` raises `click.ClickException("unicorn not installed; ...")` only for the genuine missing-dependency case; other construction errors propagate (surfaced by Click as the real error).

- [ ] **Step 1: Write the failing test** — append to `tests/test_unicorn_engine.py` (this one does NOT importorskip — it tests the no-unicorn path):

```python
def test_session_construction_raises_without_unicorn(monkeypatch):
    from ghydra.dynamic import unicorn_engine
    monkeypatch.setattr(unicorn_engine, "_HAVE_UNICORN", False)
    import pytest
    with pytest.raises(RuntimeError, match="unicorn not installed"):
        unicorn_engine.UnicornSession()
```

- [ ] **Step 2: Run the test to verify it passes-or-fails appropriately**

Run: `python -m pytest tests/test_unicorn_engine.py::test_session_construction_raises_without_unicorn -q`
Expected: PASS immediately — this pins the existing `__init__` guard behavior that `_make_session` relies on (it documents the contract the narrowing depends on; it is a characterization test, not a red-then-green test). If it FAILS, stop — the engine's missing-dep contract changed and the narrowing below is unsafe.

- [ ] **Step 3: Narrow the handler** — in `ghydra/cli/dynamic.py`, replace the `_make_session` body:

```python
def _make_session(ctx):
    try:
        from ..dynamic.unicorn_engine import UnicornSession
        from ..dynamic.ghidra_provider import make_ghidra_provider
    except ImportError:
        raise click.ClickException("unicorn not installed; pip install ghydramcp[unicorn]")
    client = ctx.obj['client']
    try:
        return UnicornSession(byte_provider=make_ghidra_provider(client))
    except RuntimeError as e:
        if "unicorn not installed" in str(e):
            raise click.ClickException("unicorn not installed; pip install ghydramcp[unicorn]")
        raise   # an unrelated construction failure must not masquerade as a missing dependency
```

- [ ] **Step 4: Run the suite to verify nothing regressed**

Run: `python -m pytest tests/test_dynamic_cli.py tests/test_unicorn_engine.py -q`
Expected: PASS — CLI tests still pass (the friendly message is preserved for the genuine case), plus the new characterization test.

- [ ] **Step 5: Commit**

```bash
git add ghydra/cli/dynamic.py tests/test_unicorn_engine.py
git commit -m "fix(dynamic): _make_session only maps the real missing-unicorn error to a friendly message"
```

---

### Task 9: COUNT-cap negative-path coverage

Spec deferral: the bridge's COUNT→`success:false` shaping is tested, but no test drives a real engine run to the instruction cap. Add an engine-level test so the `steps["n"] >= cap` → `COUNT` path is pinned end to end.

**Files:**
- Test: `tests/test_unicorn_engine.py` (new case only)

**Interfaces:**
- Consumes: `UnicornSession.run` (existing).

- [ ] **Step 1: Write the test** — append to `tests/test_unicorn_engine.py`:

```python
def test_run_hits_instruction_cap_returns_count():
    s = UnicornSession()
    base = 0x140075000
    s.map_bytes(base, b"\xeb\xfe")          # jmp $  -- tight infinite loop
    s.set_register("RIP", base)
    # until is never reached; the run must stop at the instruction budget.
    state = s.run(begin=base, until=base + 0x100, count=5)
    assert state["stop_reason"] == "COUNT"
    assert state["last_error"] is None      # COUNT is a clean stop, not a fault
    assert state["steps"] == 5
```

- [ ] **Step 2: Run the test to verify it passes**

Run: `python -m pytest tests/test_unicorn_engine.py::test_run_hits_instruction_cap_returns_count -q`
Expected: PASS — `jmp $` loops, `steps` reaches the `count=5` cap, `emu_start` returns at the budget, and `steps["n"] >= cap` sets `COUNT` with `last_error is None`. If it FAILS, stop and investigate the cap accounting (this is the characterization the spec asked to pin).

- [ ] **Step 3: Commit**

```bash
git add tests/test_unicorn_engine.py
git commit -m "test(dynamic): pin engine COUNT stop reason at the instruction cap"
```

---

### Task 10: Bump version + changelog (Python work) — and isolate the Java `stepOnce` item

This task closes out the Python changes with the single `BRIDGE_VERSION`/changelog bump, and explicitly carves out the one cross-subsystem deferral.

**Files:**
- Modify: `bridge_mcp_hydra.py` (`BRIDGE_VERSION`)
- Modify: `CHANGELOG.md` (`[Unreleased]`)

**Interfaces:** none (metadata only).

- [ ] **Step 1: Bump the bridge version** — in `bridge_mcp_hydra.py`, change `BRIDGE_VERSION = "v3.1.0-rc.2"` to `BRIDGE_VERSION = "v3.1.0-rc.3"`.

- [ ] **Step 2: Add a changelog entry** — in `CHANGELOG.md`, under the existing `## [Unreleased]` → `### Added` (or a `### Changed` you add directly below the Unicorn `### Fixed` block from the prior plan), add:

```markdown
- **Unicorn emulation hardening:** distinct `LAZY_CAP_REACHED` stop reason when the lazy-page budget (`max_lazy_pages`) is exhausted (was a generic `ERROR`); an explicit zero-fill map primitive (`unicorn_map` MCP tool + `ghydra dynamic map`) and an opt-in default scratch stack on `unicorn_reset` (`stack=True`) so stack-using code runs without manual mapping; a `trace_truncated` signal when a trace hits the cap; and a lock around the Unicorn session registry. `ProviderError` now subclasses `GhidraError`. Bridge → `v3.1.0-rc.3` (API_VERSION unchanged — additive).
```

- [ ] **Step 3: Run the full suite + import check**

Run: `python -m pytest -q && python -c "import bridge_mcp_hydra as b; print(b.BRIDGE_VERSION)"`
Expected: PASS (all suites) and prints `v3.1.0-rc.3`.

- [ ] **Step 4: Commit**

```bash
git add bridge_mcp_hydra.py CHANGELOG.md
git commit -m "chore(dynamic): bump BRIDGE_VERSION to v3.1.0-rc.3 + changelog for hardening"
```

- [ ] **Step 5: Java/PCode `stepOnce` classification — decide separately (do NOT implement inline)**

The remaining spec deferral — coverage for `EmulationService.stepOnce`'s `BREAKPOINT`-vs-`ERROR` classification (`src/main/java/eu/starsong/ghidra/service/EmulationService.java`) — is a **different subsystem** (Java PCode emulation via Ghidra's `EmulatorHelper`) on a **different harness** (Maven/JUnit, or the live-Ghidra integration suite where there is no mock layer per `CLAUDE.md`). It does not share code with the Python Unicorn stack this plan hardens.

Per the writing-plans scope rule, do not fold a second subsystem into this plan. Instead, surface it for a decision:

> "All Python Unicorn hardening items are complete. The one remaining deferral — Java `EmulationService.stepOnce` classification coverage — is a separate subsystem needing the JUnit/live-Ghidra harness. Options: (a) write a dedicated micro-plan for it, (b) add it to the live integration suite (`tests/test_*` against a running instance) as a follow-up, or (c) leave it as a tracked note. Which?"

Stop here and ask; do not implement it as part of this plan.

---

## Self-Review

- **Spec coverage (§"Out of scope (follow-up plan)") + review findings:**
  - Stack-setup convenience (auto-map default stack / dedicated map tool) → **Task 5** (map primitive) + **Task 6** (opt-in auto-stack).
  - `UnicornSession.uc` → `_uc` privatization + route hook `mem_map` through `_ensure_mapped` → **Task 3**.
  - Session-dict (`_UNICORN_SESSIONS`) locking for parity with `instances_lock` → **Task 7**.
  - Trace-truncation flag at `_TRACE_CAP` → **Task 4**.
  - CLI `_make_session` except-narrowing → **Task 8**.
  - Negative-path coverage: `COUNT` cap → **Task 9**; `max_lazy_pages` cap → **Task 2** (now a first-class `LAZY_CAP_REACHED` with its own test); missing-dependency `RuntimeError` → **Task 8** Step 1; Java `stepOnce` → **Task 10** Step 5 (carved out, not implemented).
  - Re-running the comment/docs-accuracy review → already completed during round-2 PR review (comment-analyzer ran); no task needed.
  - Review #3 (distinct cap stop-reason) → **Task 2**. Review #5 (`ProviderError` hierarchy) → **Task 1**.
- **Placeholder scan:** none — every step shows exact code or an exact command with expected output.
- **Type consistency:** `StopReason.LAZY_CAP_REACHED` is defined in Task 2 and consumed by the engine's classification (Task 2) and, unchanged, by `_unicorn_run_result`'s `else` branch (verified in the existing bridge code — any non-DONE/COUNT reason becomes `error.code`). `run()`'s new `trace_truncated` key (Task 4) is produced once and read with `.get(...)` by the bridge and CLI, so tasks/tests that build state dicts without it (existing bridge tests) still pass. `_apply_default_stack(session) -> tuple[int,int]` (Task 6) has the same signature at its definition, its test, and its `unicorn_reset` call site. `self._uc` (Task 3) replaces every `self.uc`; no caller outside the engine reads the attribute (verified by grep).
- **Ordering/dependencies:** Tasks 2, 3, 4 all edit `run()` in sequence (distinct regions: classification, handle rename + hook map, trace tracking) — executed in order they do not collide. Task 5 (map primitive) precedes Task 6 (auto-stack), which reuses `map_bytes` directly (not the tool). The single version/changelog bump is consolidated in Task 10 to avoid churn across the nine code commits.
- **Out of scope (this plan):** Java/PCode `EmulationService.stepOnce` coverage (Task 10 Step 5 — separate subsystem/harness, decision deferred). No new public Python deps; `unicorn` stays optional.
