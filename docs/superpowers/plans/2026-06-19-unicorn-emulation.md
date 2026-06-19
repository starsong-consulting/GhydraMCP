# Unicorn Emulation (Python bridge) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Unicorn-Engine-based dynamic-analysis capability that lives entirely in the Python side of GhydraMCP: an agent can emulate code (run/step with instruction & memory-write tracing, registers, breakpoints) where the *bytes are pulled on demand from the Ghidra static image over the existing HTTP API* — e.g. emulate `mbb.exe`'s `entry` and dump the decrypted `.xd` payload, without a live debugger.

**Architecture:** New `ghydra/dynamic/` package with a pure-Python `UnicornSession` that owns one `unicorn.Uc` instance. Its standout feature is a **lazy-mapping hook**: when emulation touches an unmapped page, the session fetches that page's original bytes from Ghidra via a `GhidraHTTPClient` and continues. Unicorn is an *optional* dependency (`pip install ghydramcp[unicorn]`). The bridge adds `unicorn_*` MCP tools and a `ghydra dynamic` CLI group, both keeping per-port stateful sessions. Because the engine talks to Ghidra through an injected client, it is unit-testable with a fake client — no Ghidra required.

**Tech Stack:** Python 3.11+, `unicorn>=2.0` (optional), `capstone>=5.0` (optional, for disassembly in traces), existing `GhidraHTTPClient`, FastMCP bridge, Click CLI; `pytest`/`unittest` with a fake client for unit tests.

## Global Constraints

- `requires-python = ">=3.11"` (matches `pyproject.toml`).
- Unicorn and Capstone are **optional**; core package import must never hard-fail when they are absent. Guard imports and surface a clear `"unicorn not installed; pip install ghydramcp[unicorn]"` error only when a Unicorn feature is actually invoked.
- The engine NEVER reaches into Ghidra directly; it takes a byte-provider callable / `GhidraHTTPClient` so it stays testable and decoupled.
- Memory pages map at **4096-byte (0x1000) alignment**; addresses are aligned down before `mem_map`.
- Register values cross APIs as **hex strings** (`"0x140075000"`), consistent with the PCode-emulation plan and `MemoryService`.
- Run bounds: every `run` takes a `count` (instruction cap, default 100000, hard cap 5_000_000) and a `timeout` in microseconds (default 0 = none); lazy-mapping is capped at 4096 pages per run to bound runaway fetches.
- New code lives under `ghydra/dynamic/` and `ghydra/cli/dynamic.py`; follow the existing CLI command shape in `ghydra/cli/memory.py` exactly (Click group, `ctx.obj['client']/['formatter']/['config']`, `GhidraError` handling, `rich_echo`).
- Do NOT bump `pyproject.toml` `version`; only add the optional-dependency group.

---

### Task 1: Optional-dependency group + `dynamic` package + x86-64 register map

**Files:**
- Modify: `pyproject.toml` (add `[project.optional-dependencies]`)
- Create: `ghydra/dynamic/__init__.py`
- Create: `ghydra/dynamic/registers.py`
- Test: `tests/test_dynamic_registers.py`

**Interfaces:**
- Produces: `ghydra.dynamic.registers.X86_64_REGISTERS: dict[str, int]` (upper-case register name → Unicorn const) and `resolve_register(name: str) -> int` (case-insensitive; raises `KeyError` with a helpful message on miss).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_dynamic_registers.py
import pytest

from ghydra.dynamic.registers import resolve_register, X86_64_REGISTERS


def test_resolve_is_case_insensitive():
    assert resolve_register("rip") == resolve_register("RIP")


def test_known_registers_present():
    for name in ("RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RSP", "RBP", "RIP",
                 "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"):
        assert name in X86_64_REGISTERS


def test_unknown_register_raises():
    with pytest.raises(KeyError):
        resolve_register("NOTAREG")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_dynamic_registers.py -q`
Expected: FAIL — `ghydra.dynamic` does not exist (ImportError).

- [ ] **Step 3: Write minimal implementation**

`ghydra/dynamic/__init__.py`:

```python
"""Dynamic analysis (Unicorn-based emulation) for GhydraMCP.

Unicorn is an optional dependency: pip install ghydramcp[unicorn]
"""
```

`ghydra/dynamic/registers.py`:

```python
"""x86-64 register name -> Unicorn constant mapping.

Importing this module does NOT require unicorn unless resolve_register is called.
"""

def _build_map():
    try:
        from unicorn.x86_const import (
            UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
            UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RSP, UC_X86_REG_RBP,
            UC_X86_REG_RIP, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10,
            UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
            UC_X86_REG_R15, UC_X86_REG_EFLAGS,
        )
    except ImportError:
        return {}
    return {
        "RAX": UC_X86_REG_RAX, "RBX": UC_X86_REG_RBX, "RCX": UC_X86_REG_RCX,
        "RDX": UC_X86_REG_RDX, "RSI": UC_X86_REG_RSI, "RDI": UC_X86_REG_RDI,
        "RSP": UC_X86_REG_RSP, "RBP": UC_X86_REG_RBP, "RIP": UC_X86_REG_RIP,
        "R8": UC_X86_REG_R8, "R9": UC_X86_REG_R9, "R10": UC_X86_REG_R10,
        "R11": UC_X86_REG_R11, "R12": UC_X86_REG_R12, "R13": UC_X86_REG_R13,
        "R14": UC_X86_REG_R14, "R15": UC_X86_REG_R15, "EFLAGS": UC_X86_REG_EFLAGS,
    }


X86_64_REGISTERS = _build_map()


def resolve_register(name: str) -> int:
    """Resolve a register name (case-insensitive) to a Unicorn constant."""
    if not X86_64_REGISTERS:
        raise KeyError("unicorn not installed; pip install ghydramcp[unicorn]")
    key = name.upper()
    if key not in X86_64_REGISTERS:
        raise KeyError(f"Unknown x86-64 register: {name}")
    return X86_64_REGISTERS[key]
```

- [ ] **Step 4: Add the optional-dependency group to `pyproject.toml`**

After the `dependencies = [...]` block (around line 13), insert:

```toml
[project.optional-dependencies]
unicorn = [
    "unicorn>=2.0,<3",
    "capstone>=5.0,<6",
]
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pip install "unicorn>=2.0,<3" && python -m pytest tests/test_dynamic_registers.py -q`
Expected: PASS (all three tests).

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml ghydra/dynamic/__init__.py ghydra/dynamic/registers.py tests/test_dynamic_registers.py
git commit -m "feat(dynamic): add unicorn optional dep + x86-64 register map"
```

---

### Task 2: `UnicornSession` — construct, map bytes, set/get registers

**Files:**
- Create: `ghydra/dynamic/unicorn_engine.py`
- Test: `tests/test_unicorn_engine.py`

**Interfaces:**
- Produces:
  - `class UnicornSession` with `__init__(self, byte_provider=None)` where `byte_provider: Callable[[int, int], bytes] | None` returns original bytes for `(address, length)` (used by lazy mapping; may be `None`).
  - `map_bytes(self, address: int, data: bytes) -> None` — page-aligns, maps if needed, writes bytes.
  - `set_register(self, name: str, value: int) -> None` / `get_register(self, name: str) -> int`.
  - `read_memory(self, address: int, length: int) -> bytes`.
  - Class attribute `PAGE = 0x1000`.
  - Raises `RuntimeError("unicorn not installed; pip install ghydramcp[unicorn]")` from `__init__` if unicorn missing.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_unicorn_engine.py
import pytest

unicorn = pytest.importorskip("unicorn")
from ghydra.dynamic.unicorn_engine import UnicornSession


def test_map_and_read_roundtrip():
    s = UnicornSession()
    s.map_bytes(0x140075000, b"\x90\x90\xcc")
    assert s.read_memory(0x140075000, 3) == b"\x90\x90\xcc"


def test_set_get_register():
    s = UnicornSession()
    s.set_register("RAX", 0xdeadbeef)
    assert s.get_register("rax") == 0xdeadbeef


def test_map_is_page_aligned_and_idempotent():
    s = UnicornSession()
    s.map_bytes(0x140075abc, b"\x41")          # maps the page 0x140075000
    s.map_bytes(0x140075fff, b"\x42")          # same page, must not re-map
    assert s.read_memory(0x140075abc, 1) == b"\x41"
    assert s.read_memory(0x140075fff, 1) == b"\x42"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_unicorn_engine.py -q`
Expected: FAIL — `unicorn_engine` does not exist.

- [ ] **Step 3: Write minimal implementation**

```python
# ghydra/dynamic/unicorn_engine.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_unicorn_engine.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ghydra/dynamic/unicorn_engine.py tests/test_unicorn_engine.py
git commit -m "feat(dynamic): UnicornSession map/register primitives"
```

---

### Task 3: `UnicornSession.run` — execute with instruction & memory-write tracing

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py`
- Test: `tests/test_unicorn_engine.py` (add cases)

**Interfaces:**
- Consumes: Task 2 primitives.
- Produces: `run(self, begin: int, until: int = 0, count: int = 100000, timeout: int = 0, trace: bool = False) -> dict` returning
  `{"pc": int, "steps": int, "stop_reason": str, "registers": {name: int}, "trace": [int...], "mem_writes": [{"address": int, "size": int, "value": int}...]}`.
  `stop_reason` ∈ `{"DONE", "COUNT", "ERROR"}`. `trace`/`mem_writes` populated only when `trace=True` (each capped at 100000).

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_unicorn_engine.py
def test_run_two_nops_advances_rip_and_traces():
    s = UnicornSession()
    base = 0x140075000
    s.map_bytes(base, b"\x90\x90")             # nop; nop
    s.set_register("RIP", base)
    state = s.run(begin=base, until=base + 2, count=10, trace=True)
    assert state["pc"] == base + 2
    assert state["steps"] == 2
    assert state["trace"] == [base, base + 1]
    assert state["stop_reason"] == "DONE"


def test_run_records_memory_writes():
    s = UnicornSession()
    base = 0x140075000
    # mov byte ptr [rip+0], 0x41 is awkward; use: mov al,0x41 ; mov [0x140076000], al
    # Simpler: write via a stosb-free sequence:  mov rbx,0x140076000 ; mov byte [rbx],0x41
    code = bytes.fromhex("48bb0060071440000000" "c60341")  # mov rbx,imm64 ; mov [rbx],0x41
    s.map_bytes(base, code)
    s.map_bytes(0x140076000, b"\x00")          # destination page
    s.set_register("RIP", base)
    state = s.run(begin=base, until=base + len(code), count=10, trace=True)
    writes = [w for w in state["mem_writes"] if w["address"] == 0x140076000]
    assert writes and writes[0]["value"] == 0x41
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_unicorn_engine.py -k run -q`
Expected: FAIL — `run` not defined.

- [ ] **Step 3: Add the implementation**

Add imports and the `run` method to `unicorn_engine.py`:

```python
# extend the unicorn import line:
# from unicorn import (Uc, UC_ARCH_X86, UC_MODE_64, UcError,
#                      UC_HOOK_CODE, UC_HOOK_MEM_WRITE)

_TRACE_CAP = 100000
_ALL_REGS = ("RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RSP", "RBP", "RIP",
             "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")

    def run(self, begin, until=0, count=100000, timeout=0, trace=False):
        from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UcError
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_unicorn_engine.py -k run -q`
Expected: PASS (both run tests).

- [ ] **Step 5: Commit**

```bash
git add ghydra/dynamic/unicorn_engine.py tests/test_unicorn_engine.py
git commit -m "feat(dynamic): UnicornSession.run with instruction+write tracing"
```

---

### Task 4: Lazy mapping from Ghidra (the dynamics-gap closer)

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py`
- Test: `tests/test_unicorn_engine.py` (add a case with a fake byte provider)

**Interfaces:**
- Consumes: `self.byte_provider` (Task 2), `run` hooks (Task 3).
- Produces: when `run` is called, an `UC_HOOK_MEM_UNMAPPED` hook is installed that, on an unmapped access, maps the page and fills it from `byte_provider(page, PAGE)`, then returns `True` to retry — bounded by `max_lazy_pages` (param on `run`, default 4096). When `byte_provider` is `None`, behaviour is unchanged (unmapped access → ERROR).

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_unicorn_engine.py
def test_lazy_maps_code_page_from_provider():
    # Provider serves "nop; nop" for the code page, zero elsewhere.
    base = 0x140075000
    def provider(address, length):
        page = bytearray(length)
        if address == base:
            page[0:2] = b"\x90\x90"
        return bytes(page)

    s = UnicornSession(byte_provider=provider)
    s.set_register("RIP", base)
    # NOTE: code page is NOT pre-mapped; the unmapped hook must fetch it.
    state = s.run(begin=base, until=base + 2, count=10, trace=True)
    assert state["steps"] == 2
    assert state["stop_reason"] == "DONE"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_unicorn_engine.py -k lazy -q`
Expected: FAIL — without the hook, the unmapped fetch never happens (UcError / ERROR).

- [ ] **Step 3: Add the lazy-map hook to `run`**

Change the `run` signature to `def run(self, begin, until=0, count=100000, timeout=0, trace=False, max_lazy_pages=4096):` and, before `emu_start`, add:

```python
        from unicorn import UC_HOOK_MEM_UNMAPPED
        lazy = {"n": 0}
        h_unmapped = None

        def _unmapped_hook(uc, access, address, size, value, _user):
            page = address & ~(self.PAGE - 1)
            if page in self._mapped or lazy["n"] >= max_lazy_pages or self.byte_provider is None:
                return False  # cannot satisfy -> let Unicorn fault
            uc.mem_map(page, self.PAGE)
            self._mapped.add(page)
            data = self.byte_provider(page, self.PAGE)
            if data:
                uc.mem_write(page, data[:self.PAGE])
            lazy["n"] += 1
            return True  # retry the faulting access

        if self.byte_provider is not None:
            h_unmapped = self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, _unmapped_hook)
```

And in the `finally:` block, add:

```python
            if h_unmapped is not None:
                self.uc.hook_del(h_unmapped)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_unicorn_engine.py -q`
Expected: PASS (all engine tests including lazy mapping).

- [ ] **Step 5: Commit**

```bash
git add ghydra/dynamic/unicorn_engine.py tests/test_unicorn_engine.py
git commit -m "feat(dynamic): lazy page mapping from Ghidra byte provider"
```

---

### Task 5: Ghidra byte provider + session factory

**Files:**
- Create: `ghydra/dynamic/ghidra_provider.py`
- Test: `tests/test_ghidra_provider.py`

**Interfaces:**
- Consumes: a client object exposing `.get(endpoint, params)` returning the parsed HATEOAS dict (the real `GhidraHTTPClient`, or a fake in tests).
- Produces: `make_ghidra_provider(client) -> Callable[[int, int], bytes]` — returns a provider that reads `memory/{hex_addr}?length=N&format=hex` and decodes the `result.hex` field into bytes (zero-fills on miss/short read so emulation can proceed over BSS).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_ghidra_provider.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_ghidra_provider.py -q`
Expected: FAIL — module missing.

- [ ] **Step 3: Write minimal implementation**

```python
# ghydra/dynamic/ghidra_provider.py
"""Byte provider that pulls original image bytes from a Ghidra instance."""

from typing import Callable


def make_ghidra_provider(client) -> Callable[[int, int], bytes]:
    """Build an (address, length) -> bytes provider backed by Ghidra's /memory API."""

    def provider(address: int, length: int) -> bytes:
        endpoint = f"memory/{address:x}"
        try:
            resp = client.get(endpoint, params={"length": length, "format": "hex"})
        except Exception:
            return b"\x00" * length
        result = resp.get("result", resp) if isinstance(resp, dict) else {}
        hex_str = (result or {}).get("hex", "") or ""
        raw = bytes.fromhex(hex_str) if hex_str else b""
        if len(raw) < length:
            raw = raw + b"\x00" * (length - len(raw))
        return raw[:length]

    return provider
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_ghidra_provider.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ghydra/dynamic/ghidra_provider.py tests/test_ghidra_provider.py
git commit -m "feat(dynamic): Ghidra-backed byte provider for lazy mapping"
```

---

### Task 6: MCP bridge `unicorn_*` tools

**Files:**
- Modify: `bridge_mcp_hydra.py` (add a tool block near the other emulation-adjacent tools; if the PCode plan landed first, place after `emulation_dispose`, else after `memory_write`)

**Interfaces:**
- Consumes: `_get_instance_port`, `@mcp.tool()`, `@text_output`, `time`; `ghydra.dynamic.unicorn_engine.UnicornSession`, `ghydra.dynamic.ghidra_provider.make_ghidra_provider`, `ghydra.client.http_client.GhidraHTTPClient`.
- Produces MCP tools: `unicorn_reset`, `unicorn_run`, `unicorn_read_memory`, `unicorn_set_register`, `unicorn_get_state`, `unicorn_dispose`. Sessions are kept in a module-global `_UNICORN_SESSIONS: dict[int, UnicornSession]` keyed by port.

- [ ] **Step 1: Add a module-global session store + helper near the top-level helpers (after `safe_post`, ~line 300)**

```python
_UNICORN_SESSIONS: dict[int, "object"] = {}


def _unicorn_error(message: str) -> dict:
    return {"success": False, "error": {"code": "UNICORN", "message": message},
            "timestamp": int(time.time() * 1000)}


def _get_unicorn_session(port: int):
    session = _UNICORN_SESSIONS.get(port)
    if session is None:
        raise KeyError("No Unicorn session; call unicorn_reset first")
    return session
```

- [ ] **Step 2: Add the tools**

```python
@mcp.tool()
@text_output
def unicorn_reset(start: str, registers: dict | None = None, port: int | None = None) -> dict:
    """Start a fresh Unicorn emulation session that lazily pulls bytes from Ghidra.

    Args:
        start: Start address in hex (RIP is set here)
        registers: Optional {register_name: hex_value} initial writes
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        from ghydra.dynamic.unicorn_engine import UnicornSession
        from ghydra.dynamic.ghidra_provider import make_ghidra_provider
        from ghydra.client.http_client import GhidraHTTPClient
    except RuntimeError as e:
        return _unicorn_error(str(e))
    except ImportError:
        return _unicorn_error("unicorn not installed; pip install ghydramcp[unicorn]")

    try:
        client = GhidraHTTPClient(port=port)
        session = UnicornSession(byte_provider=make_ghidra_provider(client))
    except RuntimeError as e:
        return _unicorn_error(str(e))

    start_int = int(start, 16) if start.lower().startswith("0x") else int(start, 16)
    session.set_register("RIP", start_int)
    if registers:
        for name, value in registers.items():
            session.set_register(name, int(value, 16))
    _UNICORN_SESSIONS[port] = session
    return {"success": True, "start": hex(start_int), "lazy_mapping": "ghidra",
            "timestamp": int(time.time() * 1000)}


@mcp.tool()
@text_output
def unicorn_run(until: str, count: int = 100000, trace: bool = False,
                port: int | None = None) -> dict:
    """Run the Unicorn session until an address, instruction count, or fault.

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
    return {"success": True,
            "pc": hex(state["pc"]),
            "steps": state["steps"],
            "stop_reason": state["stop_reason"],
            "registers": {k: hex(v) for k, v in state["registers"].items()},
            "trace": [hex(a) for a in state["trace"]],
            "mem_writes": [{"address": hex(w["address"]), "size": w["size"],
                            "value": hex(w["value"])} for w in state["mem_writes"]],
            "timestamp": int(time.time() * 1000)}


@mcp.tool()
@text_output
def unicorn_read_memory(address: str, length: int = 64, port: int | None = None) -> dict:
    """Read bytes from the Unicorn session's memory (e.g. dump decrypted data).

    Args:
        address: Address in hex
        length: Number of bytes (default 64)
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e))
    data = session.read_memory(int(address, 16), length)
    return {"success": True, "address": address, "length": length,
            "hex": data.hex(), "timestamp": int(time.time() * 1000)}


@mcp.tool()
@text_output
def unicorn_set_register(name: str, value: str, port: int | None = None) -> dict:
    """Set a Unicorn register value.

    Args:
        name: Register name (e.g. "RAX")
        value: Hex value
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e))
    session.set_register(name, int(value, 16))
    return {"success": True, "name": name, "value": value,
            "timestamp": int(time.time() * 1000)}


@mcp.tool()
@text_output
def unicorn_get_state(port: int | None = None) -> dict:
    """Get the current Unicorn register state without executing.

    Args:
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e))
    regs = ("RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RSP", "RBP", "RIP",
            "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
    return {"success": True,
            "registers": {r: hex(session.get_register(r)) for r in regs},
            "timestamp": int(time.time() * 1000)}


@mcp.tool()
@text_output
def unicorn_dispose(port: int | None = None) -> dict:
    """Dispose the Unicorn session for a port.

    Args:
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    _UNICORN_SESSIONS.pop(port, None)
    return {"success": True, "session": "disposed", "timestamp": int(time.time() * 1000)}
```

- [ ] **Step 3: Verify the bridge imports cleanly (without unicorn installed)**

Run: `python -c "import bridge_mcp_hydra"`
Expected: no exceptions — the `ghydra.dynamic` imports are deferred inside `unicorn_reset`, so importing the bridge never requires unicorn.

- [ ] **Step 4: Commit**

```bash
git add bridge_mcp_hydra.py
git commit -m "feat(dynamic): add unicorn_* MCP bridge tools"
```

---

### Task 7: CLI `ghydra dynamic` group

**Files:**
- Create: `ghydra/cli/dynamic.py`
- Modify: `ghydra/cli/main.py` (register the group)

**Interfaces:**
- Consumes: `ctx.obj['client']` (a `GhidraHTTPClient`), `ctx.obj['formatter']`, `GhidraError`, `rich_echo`, `validate_address`; `ghydra.dynamic.unicorn_engine.UnicornSession`, `ghydra.dynamic.ghidra_provider.make_ghidra_provider`.
- Produces: a `dynamic` Click group with `run` and `dump` commands (one-shot: build a session, run begin..until, optionally dump a memory range) so the CLI works without a persistent server-side session.

- [ ] **Step 1: Write the CLI module**

```python
"""Dynamic analysis (Unicorn emulation) commands."""

import click

from ..client.exceptions import GhidraError
from ..utils import rich_echo, validate_address


def _make_session(ctx):
    try:
        from ..dynamic.unicorn_engine import UnicornSession
        from ..dynamic.ghidra_provider import make_ghidra_provider
    except (ImportError, RuntimeError):
        raise click.ClickException("unicorn not installed; pip install ghydramcp[unicorn]")
    client = ctx.obj['client']
    return UnicornSession(byte_provider=make_ghidra_provider(client))


@click.group('dynamic')
def dynamic():
    """Unicorn-based emulation (bytes pulled lazily from Ghidra)."""
    pass


@dynamic.command('run')
@click.option('--start', '-s', required=True, help='Start address (hex)')
@click.option('--until', '-u', required=True, help='Stop address (hex)')
@click.option('--count', type=int, default=100000, help='Instruction cap')
@click.option('--trace/--no-trace', default=False)
@click.pass_context
def run(ctx, start, until, count, trace):
    """Emulate start..until and print final register state."""
    try:
        session = _make_session(ctx)
        begin = int(validate_address(start), 16)
        session.set_register("RIP", begin)
        state = session.run(begin=begin, until=int(validate_address(until), 16),
                            count=count, trace=trace)
        click.echo(f"pc={hex(state['pc'])} steps={state['steps']} "
                   f"stop={state['stop_reason']}")
        for name, value in state["registers"].items():
            click.echo(f"  {name}={hex(value)}")
        if trace:
            click.echo(f"  trace: {len(state['trace'])} instrs, "
                       f"{len(state['mem_writes'])} writes")
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@dynamic.command('dump')
@click.option('--start', '-s', required=True, help='Entry address (hex)')
@click.option('--until', '-u', required=True, help='Stop address (hex)')
@click.option('--address', '-a', required=True, help='Address to dump after run (hex)')
@click.option('--length', '-l', type=int, default=256, help='Bytes to dump')
@click.option('--count', type=int, default=1000000, help='Instruction cap')
@click.pass_context
def dump(ctx, start, until, address, length, count):
    """Run an unpacker (start..until), then dump emulated memory (e.g. .xd)."""
    try:
        session = _make_session(ctx)
        begin = int(validate_address(start), 16)
        session.set_register("RIP", begin)
        session.run(begin=begin, until=int(validate_address(until), 16), count=count)
        data = session.read_memory(int(validate_address(address), 16), length)
        click.echo(data.hex())
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)
```

- [ ] **Step 2: Register the group in `main.py`**

Add `from .dynamic import dynamic` with the other group imports and `cli.add_command(dynamic)` with the others.

- [ ] **Step 3: Verify the CLI loads (without unicorn installed)**

Run: `python -m ghydra.cli.main dynamic --help`
Expected: shows `run` and `dump` subcommands (import of unicorn is deferred to `_make_session`, so `--help` works even without unicorn).

- [ ] **Step 4: Commit**

```bash
git add ghydra/cli/dynamic.py ghydra/cli/main.py
git commit -m "feat(dynamic): add ghydra dynamic CLI group"
```

---

### Task 8: End-to-end emulation test with a fake provider + documentation

**Files:**
- Create: `tests/test_dynamic_e2e.py`
- Modify: `README.md`, `GHYDRA_CLI.md`, `CHANGELOG.md`, `TESTING.md`

**Interfaces:**
- Consumes: `UnicornSession`, `make_ghidra_provider` with a fake client.

- [ ] **Step 1: Write the e2e test (mini-unpacker that XOR-decrypts a buffer)**

```python
# tests/test_dynamic_e2e.py
import pytest

pytest.importorskip("unicorn")
from ghydra.dynamic.unicorn_engine import UnicornSession
from ghydra.dynamic.ghidra_provider import make_ghidra_provider


class FakeClient:
    """Serves a tiny XOR-decrypt routine and an encrypted buffer from 'Ghidra'."""
    CODE = 0x140075000
    BUF = 0x140076000
    # decrypt loop: xor 4 bytes at BUF with 0xAA, then jmp $ (infinite) — we stop via 'until'
    # mov rbx, BUF ; mov rcx, 4 ; L: xor byte[rbx],0xaa ; inc rbx ; loop L ; (until set to here)
    PROG = bytes.fromhex(
        "48bb0060071440000000"  # mov rbx, 0x140076000
        "48c7c104000000"        # mov rcx, 4
        "803baa"                # L: xor byte [rbx], 0xaa  (4 bytes? actual: 80 33 aa)
    )

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
    # Run just the three setup instrs + one xor; stop right after first xor (offset 0x14)
    until = FakeClient.CODE + 0x14
    state = session.run(begin=FakeClient.CODE, until=until, count=50)
    assert state["stop_reason"] in ("DONE", "COUNT")
    # First byte of the buffer should now be decrypted ('P').
    first = session.read_memory(FakeClient.BUF, 1)
    assert first == b"P"
```

> If the exact byte offset `0x14` does not line up with your assembler output, compute it: the test only needs `until` to land *after* the first `xor byte [rbx],0xaa` executes. Disassemble `FakeClient.PROG` with `capstone` to confirm instruction boundaries and adjust `until`.

- [ ] **Step 2: Run it**

Run: `python -m pytest tests/test_dynamic_e2e.py -q`
Expected: PASS (or SKIP if unicorn absent).

- [ ] **Step 3: Update docs**

- `README.md`: add `- unicorn_* : Unicorn dynamic emulation (lazy-maps bytes from Ghidra)` to the MCP namespaces and note `pip install ghydramcp[unicorn]`.
- `GHYDRA_CLI.md`: document `ghydra dynamic run` / `ghydra dynamic dump` with the `mbb.exe` unpack example.
- `CHANGELOG.md`: add `- feat: Unicorn dynamic emulation (unicorn_* MCP tools, ghydra dynamic CLI) with lazy page mapping from the Ghidra image; optional extra ghydramcp[unicorn]`.
- `TESTING.md`: add a "Dynamic emulation tests" subsection noting `pip install ghydramcp[unicorn]` then `pytest tests/test_unicorn_engine.py tests/test_dynamic_e2e.py`.

- [ ] **Step 4: Commit**

```bash
git add tests/test_dynamic_e2e.py README.md GHYDRA_CLI.md CHANGELOG.md TESTING.md
git commit -m "test(dynamic): e2e lazy-unpack + docs for Unicorn emulation"
```

---

## Self-Review

- **Spec coverage:** "MVP + tracing/hooks" → reset/run/read-memory/set-register/state/dispose (MVP) + instruction trace, memory-write trace, and the `UC_HOOK_MEM_UNMAPPED` lazy-map hook (the hooks deliverable). The dynamics-gap close (`mbb.exe` unpack) is demonstrated by Task 8's e2e XOR-unpacker and the `ghydra dynamic dump` command. Covered by Tasks 3,4,6,7,8.
- **Placeholder scan:** No "TBD/add error handling" — each step has runnable code. The two judgment points (assembler offset `0x14` in Task 8; group-registration lines in `main.py`) are written with explicit how-to (disassemble with capstone / copy the `add_command` pattern), not vague placeholders.
- **Type consistency:** `byte_provider: Callable[[int,int],bytes]` defined in Task 2 is produced by `make_ghidra_provider` in Task 5 and consumed by the lazy hook in Task 4. `run(...)` return-dict keys (`pc/steps/stop_reason/registers/trace/mem_writes`) defined in Task 3 are consumed unchanged by the bridge tool in Task 6 and CLI in Task 7. `UnicornSession(byte_provider=...)` constructor signature is identical across Tasks 2, 6, 7, 8.

---

## Execution Handoff (covers BOTH plans)

Two execution options:

1. **Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration. Uses superpowers:subagent-driven-development.
2. **Inline Execution** — Execute tasks in this session with checkpoints. Uses superpowers:executing-plans.

Suggested order: do the **Unicorn plan first** — every task is unit-testable without a running Ghidra (fake client), so it can be fully driven and verified in any session. The **PCode plan** needs a built plugin + a live Ghidra instance with a binary open for its Task 6 smoke test, so schedule it when that environment is available.

Which plan, and which execution approach?
