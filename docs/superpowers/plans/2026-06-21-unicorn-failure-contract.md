# Unicorn Lazy-Mapping Failure Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Unicorn dynamic-emulation lazy mapper serve only real Ghidra image bytes — any address Ghidra cannot satisfy faults with a distinct `LAZY_FETCH_FAILED` stop reason and a surfaced `last_error`, instead of silently fabricating zero pages reported as `success: true`.

**Architecture:** Four layered changes following the data flow: (1) the byte provider raises `ProviderError` instead of zero-filling on any failure; (2) the engine's lazy hook maps a page only after real bytes arrive, else records the failure and faults, and `run()` returns `last_error` with a `LAZY_FETCH_FAILED`/`ERROR` split; (3) the MCP bridge derives `success` from `stop_reason` via a pure, testable `_unicorn_run_result` helper that emits an `error` envelope on failure (so `text_output` surfaces the cause); (4) the CLI `dump` aborts before printing a faulted dump and `run` shows `last_error`.

**Tech Stack:** Python 3.11+, `unicorn>=2.0` (optional), existing `GhidraHTTPClient`, FastMCP bridge, Click CLI; `pytest` with fake clients/providers (no live Ghidra).

**Spec:** `docs/superpowers/specs/2026-06-21-unicorn-failure-contract-design.md`.

## Global Constraints

- `requires-python = ">=3.11"`. Unicorn is an optional dependency; pure-logic tests (provider error shaping, `_unicorn_run_result`) must NOT require unicorn. Engine/CLI tests that construct a `UnicornSession` start with `pytest.importorskip("unicorn")`.
- **Purist contract:** lazy mapping serves only real image bytes. A non-empty provider response (even all-zero bytes Ghidra returned for an initialized region) maps and continues; an empty/absent/failed fetch faults. Callers establish scratch/stack via the existing `UnicornSession.map_bytes(addr, b"\x00" * size)` before `run()`.
- **Stop reasons:** `DONE` / `COUNT` / `ERROR` / `LAZY_FETCH_FAILED`. `success: true` only for `DONE`.
- The lazy hook runs inside a Unicorn C callback: it MUST NOT let an exception cross `emu_start`. It catches at that boundary, records the message, and returns `False` to fault.
- Page size is `UnicornSession.PAGE = 0x1000`; addresses align down before `mem_map`.
- Register/address values cross the bridge/CLI as hex strings.
- Do NOT bump `pyproject.toml` `version`. Conventional-commit messages. End commit messages with the `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` trailer.

---

### Task 1: Provider raises `ProviderError` instead of zero-filling

**Files:**
- Create: `ghydra/dynamic/exceptions.py`
- Modify: `ghydra/dynamic/ghidra_provider.py` (full rewrite of the `provider` body)
- Test: `tests/test_ghidra_provider.py` (rewrite both existing tests, add failure cases)

**Interfaces:**
- Produces: `ghydra.dynamic.exceptions.ProviderError(Exception)`.
- Produces: `make_ghidra_provider(client) -> Callable[[int, int], bytes]` where the returned `provider(address, length)` **returns the real bytes Ghidra has** (length may be `< length`, never zero-padded) and **raises `ProviderError`** when no real image bytes are available (client raised, empty/absent `hex`, or malformed `hex`).

- [ ] **Step 1: Write the failing tests** — replace the entire contents of `tests/test_ghidra_provider.py` with:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_ghidra_provider.py -q`
Expected: FAIL — `ghydra.dynamic.exceptions` does not exist (ImportError) / old provider zero-fills instead of raising.

- [ ] **Step 3: Create the exception** — write `ghydra/dynamic/exceptions.py`:

```python
"""Exceptions for the dynamic (Unicorn) emulation subsystem."""


class ProviderError(Exception):
    """A lazy byte-provider could not return real image bytes for an address.

    Raised when the underlying fetch failed (transport/API error), when the
    source has no bytes for the address, or when the response was malformed.
    Carries the message surfaced as run()'s ``last_error``.
    """
```

- [ ] **Step 4: Rewrite the provider** — replace the entire contents of `ghydra/dynamic/ghidra_provider.py`:

```python
"""Byte provider that pulls original image bytes from a Ghidra instance."""

from typing import Callable

from .exceptions import ProviderError


def make_ghidra_provider(client) -> Callable[[int, int], bytes]:
    """Build an (address, length) -> bytes provider backed by Ghidra's /memory API.

    The returned provider returns the real bytes Ghidra has (possibly fewer than
    `length`; never zero-padded) and raises ProviderError when no real image bytes
    are available -- so genuine fetch failures fault loudly instead of masquerading
    as zero data.
    """

    def provider(address: int, length: int) -> bytes:
        endpoint = f"memory/{address:x}"
        try:
            resp = client.get(endpoint, params={"length": length, "format": "hex"})
        except Exception as e:
            raise ProviderError(f"fetch failed at {hex(address)}: {e}") from e
        result = resp.get("result", resp) if isinstance(resp, dict) else {}
        hex_str = (result or {}).get("hex", "") or ""
        if not hex_str:
            raise ProviderError(f"no image bytes at {hex(address)}")
        try:
            return bytes.fromhex(hex_str)
        except ValueError as e:
            raise ProviderError(f"malformed hex at {hex(address)}: {e}") from e

    return provider
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_ghidra_provider.py -q`
Expected: PASS (4 tests).

- [ ] **Step 6: Commit**

```bash
git add ghydra/dynamic/exceptions.py ghydra/dynamic/ghidra_provider.py tests/test_ghidra_provider.py
git commit -m "fix(dynamic): provider raises ProviderError instead of zero-filling on fetch failure"
```

---

### Task 2: Lazy hook maps only on success; `run()` adds `LAZY_FETCH_FAILED` + `last_error`

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py` (`run` method: hook body, exception handling, return dict)
- Test: `tests/test_unicorn_engine.py` (add cases)

**Interfaces:**
- Consumes: `ghydra.dynamic.exceptions.ProviderError` (in the test's failing provider).
- Produces: `UnicornSession.run(...)` returns a dict with a new `"last_error"` key (`str` or `None`) and a `stop_reason` that may now be `"LAZY_FETCH_FAILED"`. On a lazy-fetch failure the faulting page is left **unmapped** (absent from `self._mapped`). The `self._last_error` instance attribute is removed.

- [ ] **Step 1: Write the failing tests** — append to `tests/test_unicorn_engine.py`:

```python
def test_clean_run_has_no_last_error():
    s = UnicornSession()
    base = 0x140075000
    s.map_bytes(base, b"\x90\x90")             # nop; nop
    s.set_register("RIP", base)
    state = s.run(begin=base, until=base + 2, count=10)
    assert state["stop_reason"] == "DONE"
    assert state["last_error"] is None


def test_lazy_fetch_failure_faults_with_reason_and_leaves_page_unmapped():
    from ghydra.dynamic.exceptions import ProviderError
    base = 0x140075000

    def provider(address, length):
        raise ProviderError(f"no image bytes at {hex(address)}")

    s = UnicornSession(byte_provider=provider)
    s.set_register("RIP", base)
    state = s.run(begin=base, until=base + 2, count=10)
    assert state["stop_reason"] == "LAZY_FETCH_FAILED"
    assert state["last_error"] and hex(base) in state["last_error"]
    assert (base & ~(UnicornSession.PAGE - 1)) not in s._mapped   # page NOT mapped


def test_lazy_fetch_empty_data_also_faults():
    base = 0x140075000

    def provider(address, length):
        return b""                              # provider returns nothing (no raise)

    s = UnicornSession(byte_provider=provider)
    s.set_register("RIP", base)
    state = s.run(begin=base, until=base + 2, count=10)
    assert state["stop_reason"] == "LAZY_FETCH_FAILED"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_unicorn_engine.py -k "last_error or lazy_fetch" -q`
Expected: FAIL — `run()` has no `last_error` key (KeyError) and faults yield `"ERROR"`, not `"LAZY_FETCH_FAILED"`.

- [ ] **Step 3: Rewrite the lazy hook (map only on success)** — in `ghydra/dynamic/unicorn_engine.py`, replace the `lazy = {"n": 0}` block and `_unmapped_hook` (current lines ~66–78):

```python
        lazy = {"n": 0}
        lazy_fail = {"msg": None}

        def _unmapped_hook(uc, access, address, size, value, _user):
            page = address & ~(self.PAGE - 1)
            if page in self._mapped or lazy["n"] >= max_lazy_pages or self.byte_provider is None:
                return False  # cannot satisfy -> let Unicorn fault
            try:
                data = self.byte_provider(page, self.PAGE)
            except Exception as e:  # boundary catch: must not cross emu_start
                lazy_fail["msg"] = f"lazy fetch failed at {hex(page)}: {e}"
                return False
            if not data:
                lazy_fail["msg"] = f"no image bytes at {hex(page)}"
                return False
            uc.mem_map(page, self.PAGE)
            self._mapped.add(page)
            uc.mem_write(page, data[:self.PAGE])
            lazy["n"] += 1
            return True  # retry the faulting access
```

- [ ] **Step 4: Split the fault into LAZY_FETCH_FAILED vs ERROR and return `last_error`** — replace the `stop_reason = "DONE"` / `try` / `except UcError` block and the `return {...}` (current lines ~84–107):

```python
        stop_reason = "DONE"
        last_error = None
        cap = min(count if count > 0 else 5_000_000, 5_000_000)
        try:
            self.uc.emu_start(begin, until, timeout=timeout, count=cap)
            if steps["n"] >= cap:
                stop_reason = "COUNT"
        except UcError as e:
            if lazy_fail["msg"] is not None:
                stop_reason = "LAZY_FETCH_FAILED"
                last_error = lazy_fail["msg"]
            else:
                stop_reason = "ERROR"
                last_error = str(e)
        finally:
            self.uc.hook_del(h_code)
            if h_write is not None:
                self.uc.hook_del(h_write)
            if h_unmapped is not None:
                self.uc.hook_del(h_unmapped)

        return {
            "pc": self.get_register("RIP"),
            "steps": steps["n"],
            "stop_reason": stop_reason,
            "last_error": last_error,
            "registers": {r: self.get_register(r) for r in _ALL_REGS},
            "trace": executed if trace else [],
            "mem_writes": mem_writes if trace else [],
        }
```

(Note: this removes the `self._last_error = str(e)` assignment; `last_error` is now returned, not stored on the instance.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_unicorn_engine.py -q`
Expected: PASS — all engine tests, including the new failure cases and the unchanged `test_lazy_maps_code_page_from_provider` (its provider returns real non-empty bytes).

- [ ] **Step 6: Commit**

```bash
git add ghydra/dynamic/unicorn_engine.py tests/test_unicorn_engine.py
git commit -m "fix(dynamic): lazy hook maps only on real bytes; add LAZY_FETCH_FAILED + last_error"
```

---

### Task 3: Bridge derives `success` from `stop_reason` (+ COUNT docstring)

**Files:**
- Modify: `bridge_mcp_hydra.py` (add `_unicorn_run_result` helper near the other `_unicorn_*` helpers; rewrite `unicorn_run` body + docstring)
- Test: `tests/test_bridge_unicorn.py` (new; pure logic, no unicorn required)

**Interfaces:**
- Consumes: the `run()` state dict from Task 2 (keys `pc`, `steps`, `stop_reason`, `last_error`, `registers`, `trace`, `mem_writes`).
- Produces: `bridge_mcp_hydra._unicorn_run_result(state: dict) -> dict` — `success: True` only for `DONE`; non-`DONE` returns an `error` envelope (`error.code == stop_reason`, `error.message` from `last_error`, or a cap message for `COUNT`) so `text_output` surfaces the cause. Always includes `stop_reason` and `last_error`.

- [ ] **Step 1: Write the failing tests** — create `tests/test_bridge_unicorn.py`:

```python
from bridge_mcp_hydra import _unicorn_run_result


def _state(stop, last_error=None):
    return {"pc": 0x1000, "steps": 3, "stop_reason": stop, "last_error": last_error,
            "registers": {"RIP": 0x1000}, "trace": [], "mem_writes": []}


def test_done_is_success_without_error_envelope():
    r = _unicorn_run_result(_state("DONE"))
    assert r["success"] is True
    assert r["last_error"] is None
    assert "error" not in r
    assert r["pc"] == "0x1000"


def test_lazy_fetch_failed_is_failure_and_surfaces_message():
    r = _unicorn_run_result(_state("LAZY_FETCH_FAILED", "no image bytes at 0x140076000"))
    assert r["success"] is False
    assert r["stop_reason"] == "LAZY_FETCH_FAILED"
    assert r["error"]["code"] == "LAZY_FETCH_FAILED"
    assert "0x140076000" in r["error"]["message"]
    assert r["last_error"] == "no image bytes at 0x140076000"


def test_count_is_failure_with_cap_message():
    r = _unicorn_run_result(_state("COUNT"))
    assert r["success"] is False
    assert r["error"]["code"] == "COUNT"
    assert "cap" in r["error"]["message"].lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_bridge_unicorn.py -q`
Expected: FAIL — `_unicorn_run_result` does not exist (ImportError).

- [ ] **Step 3: Add the helper** — in `bridge_mcp_hydra.py`, immediately after the `_get_unicorn_session` helper (in the "Unicorn dynamic emulation" block), add:

```python
def _unicorn_run_result(state: dict) -> dict:
    """Shape an engine run() state dict into a bridge response.

    success is true only for stop_reason DONE. Non-DONE returns an error
    envelope so text_output surfaces the cause (stop_reason + last_error).
    """
    stop = state["stop_reason"]
    payload = {
        "pc": hex(state["pc"]),
        "steps": state["steps"],
        "stop_reason": stop,
        "last_error": state["last_error"],
        "timestamp": int(time.time() * 1000),
    }
    if stop == "DONE":
        payload["success"] = True
        payload["registers"] = {k: hex(v) for k, v in state["registers"].items()}
        payload["trace"] = [hex(a) for a in state["trace"]]
        payload["mem_writes"] = [{"address": hex(w["address"]), "size": w["size"],
                                  "value": hex(w["value"])} for w in state["mem_writes"]]
        return payload
    if stop == "COUNT":
        message = (state["last_error"]
                   or f"instruction cap reached after {state['steps']} steps; raise count or set until")
    else:
        message = state["last_error"] or stop
    payload["success"] = False
    payload["error"] = {"code": stop, "message": message}
    return payload
```

- [ ] **Step 4: Rewrite `unicorn_run` to use the helper and document COUNT** — replace the existing `unicorn_run` function body and docstring (current lines ~3065–3092):

```python
@mcp.tool()
@text_output
def unicorn_run(until: str, count: int = 100000, trace: bool = False,
                port: int | None = None) -> dict:
    """Run the Unicorn session until an address, instruction count, or fault.

    success is true only when the target address is reached (stop_reason DONE).
    A run that hits the instruction cap returns stop_reason "COUNT" with
    success=false: it ran cleanly but stopped at the budget without reaching the
    target -- raise `count` or set a closer `until`; it is NOT a fault. A
    failed lazy byte fetch from Ghidra returns "LAZY_FETCH_FAILED" with the cause
    in last_error; any other emulator fault returns "ERROR". On any non-DONE stop
    the emulated memory must not be treated as a trustworthy result.

    Args:
        until: Stop address in hex (required; emulation runs begin..until)
        count: Instruction cap (default 100000)
        trace: Return executed instruction addresses and memory writes
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e))
    begin = session.get_register("RIP")
    state = session.run(begin=begin, until=int(until, 16), count=count, trace=trace)
    return _unicorn_run_result(state)
```

- [ ] **Step 5: Run tests + confirm the bridge still imports**

Run: `python -m pytest tests/test_bridge_unicorn.py -q && python -c "import bridge_mcp_hydra"`
Expected: PASS (3 tests) and no import error.

- [ ] **Step 6: Commit**

```bash
git add bridge_mcp_hydra.py tests/test_bridge_unicorn.py
git commit -m "fix(dynamic): unicorn_run success from stop_reason; surface last_error + COUNT note"
```

---

### Task 4: CLI `dump` aborts on a faulted run; `run` shows `last_error`

**Files:**
- Modify: `ghydra/cli/dynamic.py` (`run` output; `dump` guard)
- Test: `tests/test_dynamic_cli.py` (new)

**Interfaces:**
- Consumes: `run()` state dict (`stop_reason`, `last_error`) from Task 2; `_make_session` (existing).
- Produces: `ghydra dynamic dump` exits non-zero and prints **no** hex on stdout when `stop_reason != "DONE"`; `ghydra dynamic run` prints `last_error` when present.

- [ ] **Step 1: Write the failing tests** — create `tests/test_dynamic_cli.py`:

```python
import pytest

pytest.importorskip("unicorn")
from click.testing import CliRunner

from ghydra.cli.dynamic import dump, run as dyn_run
from ghydra.formatters import TableFormatter
from ghydra.client.exceptions import GhidraConnectionError


class RaisingClient:
    """Every memory fetch fails -> the first code-page fetch faults the run."""
    def get(self, endpoint, params=None):
        raise GhidraConnectionError("ghidra unreachable")


def _obj():
    return {"client": RaisingClient(),
            "formatter": TableFormatter(use_colors=False),
            "config": None}


def test_dump_aborts_and_prints_no_hex_on_faulted_run():
    result = CliRunner().invoke(
        dump,
        ["--start", "0x140075000", "--until", "0x140075002",
         "--address", "0x140075000", "--length", "16"],
        obj=_obj(),
    )
    assert result.exit_code != 0
    assert result.output.strip() == ""               # no hex dump on stdout
    assert "LAZY_FETCH_FAILED" in result.stderr


def test_run_reports_stop_reason_and_error():
    result = CliRunner().invoke(
        dyn_run,
        ["--start", "0x140075000", "--until", "0x140075002"],
        obj=_obj(),
    )
    assert "LAZY_FETCH_FAILED" in result.output
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_dynamic_cli.py -q`
Expected: FAIL — `dump` currently prints the hex of zero memory (no guard) and exits 0; `run` does not print `last_error`.

- [ ] **Step 3: Add `last_error` to `run` output** — in `ghydra/cli/dynamic.py`, in the `run` command, after the loop that echoes registers and before the `if trace:` block, insert:

```python
        if state.get("last_error"):
            click.echo(f"  error: {state['last_error']}")
```

- [ ] **Step 4: Guard the `dump` command** — in `ghydra/cli/dynamic.py`, replace the `dump` command body (the `try:` block contents) with:

```python
    try:
        session = _make_session(ctx)
        begin = int(validate_address(start), 16)
        session.set_register("RIP", begin)
        state = session.run(begin=begin, until=int(validate_address(until), 16), count=count)
        if state["stop_reason"] != "DONE":
            click.echo(
                f"emulation did not complete: stop={state['stop_reason']} "
                f"{state.get('last_error') or ''}".rstrip(),
                err=True,
            )
            ctx.exit(1)
        data = session.read_memory(int(validate_address(address), 16), length)
        click.echo(data.hex())
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_dynamic_cli.py -q`
Expected: PASS (2 tests).

- [ ] **Step 6: Run the full unit suite**

Run: `python -m pytest -q`
Expected: PASS (all `tests/` — provider, engine, bridge, CLI, registers, e2e).

- [ ] **Step 7: Commit**

```bash
git add ghydra/cli/dynamic.py tests/test_dynamic_cli.py
git commit -m "fix(dynamic): CLI dump aborts on faulted run; run shows last_error"
```

---

## Self-Review

- **Spec coverage:**
  - C1 (provider swallows failures) → Task 1 (provider raises `ProviderError`; broad `except` removed).
  - C2 (short/missing hex zero-padded) → Task 1 (no zero-pad; empty/malformed → raise; `test_provider_returns_real_bytes_only_not_zero_padded`).
  - C3 (hook retries on no data) → Task 2 (map only after real bytes; failed page left unmapped).
  - C4 (no distinct reason / `last_error` dropped / bridge always success) → Task 2 (`LAZY_FETCH_FAILED` + `last_error` returned) and Task 3 (`success` from `stop_reason`, error envelope).
  - Spec §4 bridge + COUNT docstring → Task 3. Spec §4 CLI dump guard + run `last_error` → Task 4.
  - Spec testing items 1–6 → Tasks 1–4 tests; existing e2e / `test_lazy_maps_code_page_from_provider` verified unchanged in Task 2 Step 5 and Task 4 Step 6.
  - Both provider tests rewritten (spec review fix) → Task 1 Step 1. COUNT→success:false callout (spec review fix) → Task 3 Step 4 docstring + `_unicorn_run_result` cap message.
- **Placeholder scan:** none — every step shows the exact code or command.
- **Type consistency:** `run()` return keys (`pc/steps/stop_reason/last_error/registers/trace/mem_writes`) are produced in Task 2 and consumed unchanged by `_unicorn_run_result` (Task 3) and the CLI (Task 4). `ProviderError` is defined in Task 1 and imported by Task 2's test and the provider. `_unicorn_run_result(state) -> dict` signature is identical across Task 3's definition and test.
- **Out of scope (follow-up plan, per spec):** stack-setup convenience; `uc`→`_uc` privatization; session-dict lock; trace-truncation flag; CLI `_make_session` except-narrowing; general coverage (COUNT cap, max_lazy_pages, missing-dep, Java `stepOnce`); re-running the comment/docs review.
