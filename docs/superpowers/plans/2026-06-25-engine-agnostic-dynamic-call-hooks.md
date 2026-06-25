# Engine-agnostic Dynamic Call & Hooks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the agent two dynamic-analysis capabilities (import/syscall hooking and high-level `call`) delivered identically across both PCode and Unicorn execution engines.

**Architecture:** Keep existing separate namespaces (`emulation_` for PCode, `unicorn_` for Unicorn) but expose an identical contract (unified stop reasons, same action vocabulary, same DTO shapes). Execute hooks inside the native run loops.

**Tech Stack:** Java, Python, Ghidra (EmulatorHelper), Unicorn

## Global Constraints

- `call` v1 supports integer and pointer (`{"bytes": hex}`) arguments only.
- Hooks are session-scoped and wiped on `reset`.
- API_VERSION unchanged; BRIDGE_VERSION bumped to `v3.1.0-rc.4`; PLUGIN_VERSION bumped.

---

### Task 1: Java Core Models & Pure Functions

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/dto/EmulationStateDto.java`
- Create: `src/main/java/eu/starsong/ghidra/dto/CallResultDto.java`
- Modify: `src/main/java/eu/starsong/ghidra/service/EmulationService.java`
- Modify: `src/test/java/eu/starsong/ghidra/service/EmulationServiceTest.java`

**Interfaces:**
- Consumes: Nothing
- Produces: `CallResultDto`, new `StopReason` enum values, `simulate_ret` helper

- [ ] **Step 1: Write failing tests for simulated return**
```java
@Test
void testSimulateRet() {
    // Write test for pure math of simulating a return instruction
}
```

- [ ] **Step 2: Add StopReasons and details to EmulationStateDto**
```java
// Add HOOK_TRAP and UNMAPPED to EmulationStateDto.StopReason
// Add public String detail; to EmulationStateDto
```

- [ ] **Step 3: Create CallResultDto**
```java
package eu.starsong.ghidra.dto;
import java.util.List;
import java.util.Map;
public class CallResultDto {
    public String return_value;
    public String convention;
    public List<String> args_passed;
    public Map<String, String> final_registers;
    public List<eu.starsong.ghidra.service.EmulationService.MemWrite> mem_writes;
    public EmulationStateDto.StopReason stop_reason;
    public String detail;
}
```

- [ ] **Step 4: Implement simulate_ret helper in EmulationService**
```java
// public static boolean simulateRet(EmulatorHelper emu, BigInteger returnValue)
```

- [ ] **Step 5: Run tests to verify they pass**
Run: `mvn test -Dtest=EmulationServiceTest`
Expected: PASS

- [ ] **Step 6: Commit**
```bash
git add src/main/java/eu/starsong/ghidra/dto src/main/java/eu/starsong/ghidra/service/EmulationService.java src/test/java/eu/starsong/ghidra/service/EmulationServiceTest.java
git commit -m "feat: Add CallResultDto and simulate_ret helper"
```

### Task 2: PCode Hook Registry & Auto-Stack

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/service/EmulationService.java`
- Modify: `src/main/java/eu/starsong/ghidra/resource/EmulationResource.java`

**Interfaces:**
- Consumes: `CallResultDto`
- Produces: Hook evaluation inside `stepOnce`, `auto_stack` logic

- [ ] **Step 1: Add hook models**
```java
public record HookAction(String action, String return_value, List<MemWrite> mem_writes) {}
// Add hook map to Session
```

- [ ] **Step 2: Add auto_stack to reset logic**
```java
// Inside reset(): if auto_stack is true, map 1MB scratch space and set RSP
```

- [ ] **Step 3: Evaluate hooks in run loop**
```java
// Inside stepOnce(): check hook registry by PC, apply return_const/skip/trap/log
```

- [ ] **Step 4: Add hook REST routes to EmulationResource**
```java
// POST /emulation/hooks, DELETE /emulation/hooks/{address}, GET /emulation/hooks
```

- [ ] **Step 5: Commit**
```bash
git add src/main/java/eu/starsong/ghidra/service/EmulationService.java src/main/java/eu/starsong/ghidra/resource/EmulationResource.java
git commit -m "feat: Implement PCode hook registry and auto-stack"
```

### Task 3: PCode Call Primitive

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/service/EmulationService.java`
- Modify: `src/main/java/eu/starsong/ghidra/resource/EmulationResource.java`

**Interfaces:**
- Consumes: Hook logic, Auto-Stack
- Produces: `/emulation/call` endpoint

- [ ] **Step 1: Implement PCode calling convention arg-marshalling**
```java
// SysV and MS calling conventions for integer and pointer args
```

- [ ] **Step 2: Implement emulation call REST route**
```java
// POST /emulation/call
// Marshals args, sets sentinel, runs until sentinel or trap/error
```

- [ ] **Step 3: Commit**
```bash
git add src/main/java/eu/starsong/ghidra/service/EmulationService.java src/main/java/eu/starsong/ghidra/resource/EmulationResource.java
git commit -m "feat: Implement PCode call primitive"
```

### Task 4: Python Models and Pure Functions

**Files:**
- Modify: `ghydra/client/models.py`
- Create: `ghydra/dynamic/calling_convention.py`
- Create: `tests/test_calling_convention.py`

**Interfaces:**
- Consumes: Nothing
- Produces: `CallResultDto` schema, unified `StopReason`, `CallingConvention` logic

- [ ] **Step 1: Write failing tests for calling_convention**
```python
def test_sysv_marshalling():
    # test sysv arg placement (rdi, rsi, rdx...)
    pass
```

- [ ] **Step 2: Update Python Pydantic Models**
```python
# Add HOOK_TRAP, UNMAPPED to StopReason in ghydra/client/models.py
# Create CallResultDto model
```

- [ ] **Step 3: Implement CallingConvention logic**
```python
# ghydra/dynamic/calling_convention.py
# implement SysV and MS layout mapping
```

- [ ] **Step 4: Run tests to verify they pass**
Run: `pytest tests/test_calling_convention.py -v`
Expected: PASS

- [ ] **Step 5: Commit**
```bash
git add ghydra/client/models.py ghydra/dynamic/calling_convention.py tests/test_calling_convention.py
git commit -m "feat: Add python models and calling convention logic"
```

### Task 5: Unicorn Hook Registry

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py`
- Modify: `tests/test_bridge_unicorn_hooks.py`

**Interfaces:**
- Consumes: Python models
- Produces: Hook execution inside `UC_HOOK_CODE` callback

- [ ] **Step 1: Write failing hook tests**
```python
def test_unicorn_hook_return_const():
    # assert hook intercepts and returns constant
    pass
```

- [ ] **Step 2: Implement Unicorn Session Hook Registry**
```python
# Add hooks dict to UnicornSession
# Add hook evaluation to _hook_code callback
# Support return_const, skip, trap, log
```

- [ ] **Step 3: Run tests to verify they pass**
Run: `pytest tests/test_bridge_unicorn_hooks.py -v`
Expected: PASS

- [ ] **Step 4: Commit**
```bash
git add ghydra/dynamic/unicorn_engine.py tests/test_bridge_unicorn_hooks.py
git commit -m "feat: Implement Unicorn hook registry"
```

### Task 6: Unicorn Call Primitive

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py`
- Modify: `tests/test_bridge_unicorn.py`

**Interfaces:**
- Consumes: Calling convention logic, Hook registry
- Produces: `unicorn_call` backend logic

- [ ] **Step 1: Write failing tests for Unicorn call**
```python
def test_unicorn_call():
    # evaluate call output
    pass
```

- [ ] **Step 2: Implement call in UnicornSession**
```python
# Add unmapped hook for sentinel
# Marshal arguments using CallingConvention
# Execute until sentinel
```

- [ ] **Step 3: Run tests to verify they pass**
Run: `pytest tests/test_bridge_unicorn.py -v`
Expected: PASS

- [ ] **Step 4: Commit**
```bash
git add ghydra/dynamic/unicorn_engine.py tests/test_bridge_unicorn.py
git commit -m "feat: Implement Unicorn call primitive"
```

### Task 7: Bridge MCP Tools

**Files:**
- Modify: `bridge_mcp_hydra.py`
- Modify: `ghydra/config/defaults.py`

**Interfaces:**
- Consumes: EmulationService REST endpoints, UnicornEngine call
- Produces: MCP Tools (`emulation_hook_set`, `emulation_call`, `unicorn_hook_set`, `unicorn_call`, etc)

- [ ] **Step 1: Define new bridge tools**
```python
@mcp.tool()
def emulation_hook_set(address: str, action: str, return_value: str = None, mem_writes: list = None):
    # Implementation calling HTTP API
```

- [ ] **Step 2: Bump BRIDGE_VERSION**
```python
# Update BRIDGE_VERSION to v3.1.0-rc.4 in bridge_mcp_hydra.py
# Update version in ghydra/config/defaults.py
```

- [ ] **Step 3: Commit**
```bash
git add bridge_mcp_hydra.py ghydra/config/defaults.py
git commit -m "feat: Expose hook and call tools via MCP bridge"
```

### Task 8: Ghydra CLI Updates

**Files:**
- Modify: `ghydra/cli/emulation.py`
- Modify: `ghydra/cli/dynamic.py`
- Modify: `tests/test_dynamic_cli.py`

**Interfaces:**
- Consumes: Python models
- Produces: CLI commands for `ghydra emulation hook`, `ghydra emulation call`, `ghydra dynamic call`

- [ ] **Step 1: Write failing CLI tests**
```python
def test_cli_dynamic_call():
    pass
```

- [ ] **Step 2: Add emulation hook and call subcommands**
```python
# Add hook click group and call command
```

- [ ] **Step 3: Add dynamic call subcommand with ephemeral hooks**
```python
# Add call command to dynamic group, accepting --hook arguments
```

- [ ] **Step 4: Run tests to verify they pass**
Run: `pytest tests/test_dynamic_cli.py -v`
Expected: PASS

- [ ] **Step 5: Commit**
```bash
git add ghydra/cli/emulation.py ghydra/cli/dynamic.py tests/test_dynamic_cli.py
git commit -m "feat: Add CLI subcommands for hooks and calls"
```
