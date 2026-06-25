# Dynamic Emulation API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the engine-agnostic `DynamicSession` abstraction, unify PCode and Unicorn beneath it, and expose a `dynamic_call` tool with bridge-layer hooking.

**Architecture:** We will create a new Python module `ghydra/dynamic/session.py` defining the `DynamicSession` protocol, the unified `StopReason` enum, and the PCode/Unicorn implementations. The `dynamic_call` tool in `bridge_mcp_hydra.py` will use this module to set breakpoints, evaluate hooks in a loop, and execute functions.

**Tech Stack:** Python 3.11+, MCP, requests, pytest

## Global Constraints

- No deep Java modifications for hooking; hooking must be purely in Python using native breakpoints and register/memory modifications.
- Must support both PCode and Unicorn as underlying engines, with PCode as the primary.
- Maintain existing test passing (`python -m pytest -q tests/`).

---

### Task 1: Unified Session Protocol & Run Loop

**Files:**
- Create: `ghydra/dynamic/session.py`
- Create: `tests/test_dynamic_session.py`

**Interfaces:**
- Produces: `StopReason` enum, `DynamicSession` class interface, and `run_with_hooks` utility function.

- [ ] **Step 1: Write the failing test**

```python
import pytest
from ghydra.dynamic.session import StopReason, DynamicSession, run_with_hooks

class DummySession(DynamicSession):
    def __init__(self):
        self.pc = 0x1000
        self.regs = {}
        self.stops = [StopReason.BREAKPOINT, StopReason.TARGET_REACHED]
    def run(self, until=None, count=None):
        reason = self.stops.pop(0)
        return {"stop_reason": reason, "pc": self.pc, "steps": 1, "last_error": None, "registers": self.regs, "trace": [], "mem_writes": []}
    def set_breakpoint(self, address): pass
    def clear_breakpoint(self, address): pass

def test_run_with_hooks_intercepts_breakpoint():
    session = DummySession()
    session.pc = 0x2000
    hooks = [{"address": 0x2000, "action": "return_val", "value": 0x42}]
    # The dummy will yield BREAKPOINT, run_with_hooks should evaluate it, then TARGET_REACHED
    state = run_with_hooks(session, hooks=hooks, until=0x3000)
    assert state["stop_reason"] == StopReason.TARGET_REACHED
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_dynamic_session.py -v`
Expected: FAIL with "No module named 'ghydra.dynamic.session'"

- [ ] **Step 3: Write minimal implementation**

```python
from enum import Enum
from typing import Any, Dict, List, Optional

class StopReason(str, Enum):
    TARGET_REACHED = "TARGET_REACHED"
    MAX_STEPS = "MAX_STEPS"
    ERROR = "ERROR"
    BREAKPOINT = "BREAKPOINT"
    LAZY_FETCH_FAILED = "LAZY_FETCH_FAILED"
    STEPPED = "STEPPED"

class DynamicSession:
    def read_register(self, name: str) -> int: raise NotImplementedError()
    def write_register(self, name: str, value: int) -> None: raise NotImplementedError()
    def read_memory(self, address: int, length: int) -> bytes: raise NotImplementedError()
    def write_memory(self, address: int, data: bytes) -> int: raise NotImplementedError()
    def set_breakpoint(self, address: int) -> None: raise NotImplementedError()
    def clear_breakpoint(self, address: int) -> None: raise NotImplementedError()
    def step(self) -> Dict[str, Any]: raise NotImplementedError()
    def run(self, until: Optional[int] = None, count: Optional[int] = None) -> Dict[str, Any]: raise NotImplementedError()

def run_with_hooks(session: DynamicSession, hooks: List[Dict[str, Any]], until: Optional[int] = None) -> Dict[str, Any]:
    for hook in hooks:
        session.set_breakpoint(hook["address"])
    
    while True:
        state = session.run(until=until)
        if state["stop_reason"] != StopReason.BREAKPOINT:
            return state
            
        pc = state["pc"]
        hook = next((h for h in hooks if h["address"] == pc), None)
        if not hook:
            return state # Unexpected breakpoint
            
        if hook["action"] == "return_val":
            # Very basic x64 return simulation
            session.write_register("RAX", hook["value"])
            rsp = session.read_register("RSP")
            ret_addr_bytes = session.read_memory(rsp, 8)
            ret_addr = int.from_bytes(ret_addr_bytes, "little")
            session.write_register("RSP", rsp + 8)
            session.write_register("RIP", ret_addr)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_dynamic_session.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add ghydra/dynamic/session.py tests/test_dynamic_session.py
git commit -m "feat: define DynamicSession and run_with_hooks loop"
```

### Task 2: Implement PCodeSession

**Files:**
- Modify: `ghydra/dynamic/session.py`
- Modify: `tests/test_dynamic_session.py`

**Interfaces:**
- Consumes: `DynamicSession`, Ghidra MCP Client `safe_get`/`safe_post` wrapper (or injected HTTP client)
- Produces: `PCodeSession(client, program_name)` class

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_dynamic_session.py
from ghydra.dynamic.session import PCodeSession

class FakePCodeClient:
    def post(self, endpoint, data):
        return {"success": True, "result": {"stopReason": "TARGET_REACHED", "pc": "0x1000", "steps": 1, "registers": {"RIP": "0x1000"}, "trace": []}}

def test_pcode_session_run():
    client = FakePCodeClient()
    session = PCodeSession(client, "test_prog")
    state = session.run(until=0x1000)
    assert state["stop_reason"] == StopReason.TARGET_REACHED
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_dynamic_session.py::test_pcode_session_run -v`
Expected: FAIL with "cannot import name 'PCodeSession'"

- [ ] **Step 3: Write minimal implementation**

```python
# append to ghydra/dynamic/session.py

class PCodeSession(DynamicSession):
    def __init__(self, client, program_name: str):
        self.client = client
        self.program_name = program_name
        self._reset()

    def _reset(self):
        # We need a start point for reset. In real usage, this should be initialized properly.
        # For the dummy implementation, we rely on the client mock.
        self.client.post("emulation/reset", {"program": self.program_name, "start": "0x0"})

    def read_register(self, name: str) -> int:
        resp = self.client.get(f"emulation/registers/{name}", params={"program": self.program_name})
        return int(resp["result"]["value"], 16)

    def write_register(self, name: str, value: int) -> None:
        self.client.put(f"emulation/registers/{name}", {"program": self.program_name, "value": hex(value)})

    def read_memory(self, address: int, length: int) -> bytes:
        resp = self.client.get(f"memory/{hex(address)}", params={"program": self.program_name, "length": length, "format": "hex"})
        return bytes.fromhex(resp["result"]["hex"])

    def write_memory(self, address: int, data: bytes) -> int:
        self.client.put("emulation/memory", {"program": self.program_name, "address": hex(address), "hex": data.hex()})
        return len(data)

    def set_breakpoint(self, address: int) -> None:
        self.client.post("emulation/breakpoints", {"program": self.program_name, "address": hex(address)})

    def clear_breakpoint(self, address: int) -> None:
        self.client.delete(f"emulation/breakpoints/{hex(address)}", {"program": self.program_name})

    def run(self, until: Optional[int] = None, count: Optional[int] = None) -> Dict[str, Any]:
        data = {"program": self.program_name}
        if until is not None: data["until"] = hex(until)
        if count is not None: data["max_steps"] = count
        
        resp = self.client.post("emulation/run", data)
        res = resp["result"]
        # Map PCode stop reasons to canonical StopReason
        sr = res["stopReason"]
        if sr == "READY": mapped = StopReason.TARGET_REACHED # Fallback
        else: mapped = StopReason(sr)
        
        return {
            "stop_reason": mapped,
            "pc": int(res.get("pc", "0x0"), 16),
            "steps": res.get("steps", 0),
            "last_error": res.get("lastError"),
            "registers": {k: int(v, 16) for k,v in res.get("registers", {}).items()},
            "trace": [int(t, 16) for t in res.get("trace", [])],
            "mem_writes": []
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_dynamic_session.py::test_pcode_session_run -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add ghydra/dynamic/session.py tests/test_dynamic_session.py
git commit -m "feat: implement PCodeSession wrapper"
```

### Task 3: Expose `dynamic_call` Tool

**Files:**
- Modify: `bridge_mcp_hydra.py`
- Modify: `ghydra/dynamic/session.py` (add HTTPClient wrapper if needed)
- Create: `tests/test_dynamic_call.py`

**Interfaces:**
- Produces: `@mcp.tool("dynamic_call")`

- [ ] **Step 1: Write the failing test**

```python
import pytest
from bridge_mcp_hydra import dynamic_call, mcp

def test_dynamic_call_tool_exists():
    assert "dynamic_call" in [t.name for t in mcp._tools]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_dynamic_call.py -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
# append to bridge_mcp_hydra.py
from ghydra.dynamic.session import PCodeSession, run_with_hooks, StopReason

class BridgeHttpClient:
    def __init__(self, port): self.port = port
    def get(self, endpoint, params=None): return safe_get(self.port, endpoint, params)
    def put(self, endpoint, data): return safe_put(self.port, endpoint, data)
    def post(self, endpoint, data): return safe_post(self.port, endpoint, data)
    def delete(self, endpoint, data=None): 
        # API doesn't fully support DELETE with body in safe_delete natively without json_data, but we'll use safe_make_request
        return _make_request("DELETE", self.port, endpoint, json_data=data)

@mcp.tool()
def dynamic_call(func_addr: str, program_name: str, args: list[str] = None, hooks: list[dict] = None, engine: str = "pcode", port: int = None) -> str:
    """Execute a function dynamically using PCode or Unicorn, bypassing calls via hooks."""
    port = _get_instance_port(port)
    client = BridgeHttpClient(port)
    args = args or []
    hooks = hooks or []
    func_addr_int = int(func_addr, 16)
    
    if engine == "pcode":
        session = PCodeSession(client, program_name)
    else:
        return "Error: Unicorn wrapper not yet fully implemented in this iteration."
        
    # Setup call (X64 System V)
    session.write_register("RIP", func_addr_int)
    
    # Simple stack allocation (dummy for now)
    stack_base = 0x7ffff0000000
    session.write_register("RSP", stack_base - 0x1000)
    
    # Push synthetic return
    synthetic_ret = 0x0
    rsp = session.read_register("RSP")
    session.write_memory(rsp - 8, synthetic_ret.to_bytes(8, "little"))
    session.write_register("RSP", rsp - 8)
    
    # Register hooks mapping to int addresses
    parsed_hooks = []
    for h in hooks:
        parsed_hooks.append({
            "address": int(h["address"], 16),
            "action": h["action"],
            "value": int(h.get("value", "0"), 16)
        })
        
    state = run_with_hooks(session, parsed_hooks, until=synthetic_ret)
    
    res = []
    res.append(f"Execution finished with reason: {state['stop_reason'].value}")
    if state['stop_reason'] == StopReason.TARGET_REACHED:
        rax = state['registers'].get('RAX', state['registers'].get('rax', 0))
        res.append(f"Return value (RAX): {hex(rax)}")
    return "\n".join(res)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_dynamic_call.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add bridge_mcp_hydra.py tests/test_dynamic_call.py
git commit -m "feat: add dynamic_call MCP tool"
```
