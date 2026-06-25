# PCode call() + Hooks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the Unicorn dynamic-emulation feature set — function-call primitive and import-stubbing hooks — to the PCode (Ghidra `EmulatorHelper`) emulator, implemented Java-native so the plugin stays the source of truth.

**Architecture:** All call/dispatch logic lives in `EmulationService.java`, mirroring how PCode emulation already works (logic in `service/`, thin route handlers in `resource/`). `callFunction` sets up the x86-64 ABI on the existing session, then runs a manual single-step loop that checks PC against the session's hook registry **before each instruction** — no `EmulatorHelper` breakpoints are used for dispatch (avoids breakpoint/re-trigger ambiguity), and the synthetic return address is detected by value at the loop top (no unmapped-fetch trick needed). The bridge and CLI expose new endpoints; their shapes mirror the existing `unicorn_call` / `unicorn_hook_*` tools so the two backends are interchangeable.

**Tech Stack:** Java 21 / Ghidra `EmulatorHelper` (Maven, JUnit 4); Python 3.11 bridge (FastMCP) + Click/Rich CLI; pytest for Python unit tests; live-Ghidra integration tests (auto-skip).

## Global Constraints

- **Calling-convention scope is x86-64 only** — `sysv` (default) and `ms`. Floats and by-value structs are out of scope, exactly as `unicorn_call`.
- **Versioning:** this is an **additive** API change (new endpoints, new enum values, new response fields). Bump `PLUGIN_VERSION` and `BRIDGE_VERSION` only. **Do NOT bump `API_VERSION` / `REQUIRED_API_VERSION`** (per CLAUDE.md, those move only on breaking changes).
- **Mutation discipline:** every `EmulatorHelper` access and every mutation of a `Session` field MUST run on the EDT via `GhidraSwing.runRead(...)` and, for program writes, inside a transaction where applicable. The emulator's own `writeMemory`/`writeRegister` do not need `TransactionHelper` (they mutate emulator state, not the program DB) — follow the existing `EmulationService` methods, which wrap only in `GhidraSwing.runRead`.
- **Hook semantics mirror Unicorn exactly** (`ghydra/dynamic/unicorn_engine.py` `Hook` + `_code_hook`): actions `return_const | skip | log | trap`; `return_value` and `mem_writes` are valid **only** with `return_const`; `log` records the hit and still executes the instruction; `return_const`/`skip` redirect (simulate `ret`) and do **not** execute the instruction.
- **Scope for this plan (locked):** hooks support `mem_writes` side-effects; `call()` supports int args **and** `{"bytes": hex}` pointer args. The per-instruction **memory-write trace log** is Unicorn-only and is explicitly NOT added to PCode (no `EmulatorHelper` write-hook without further Java work). PCode `call` `trace=true` returns the executed-instruction address list only.
- **Constants (copy verbatim, mirror Unicorn):** `CALL_STACK_BASE = 0x7ffff0000000L`, `CALL_STACK_SIZE = 0x100000L`, `CALL_ARGS_SPLIT = 0x40000L`, `SENTINEL_ADDR = 0x0000DEAD0000C0DEL`, `REDIRECT_CAP = 10_000`, reuse existing `MAX_STEPS_CAP = 5_000_000L`.
- **Wire contract for call args (precision-safe):** over HTTP each arg is an object: `{"int": "<dec-or-0xhex>"}` or `{"bytes": "<hex>"}`. The bridge normalizes the Python `args` list (raw ints and `{"bytes": hex}` dicts, identical to `unicorn_call`) into this wire form so 64-bit values survive JSON without double-precision loss.

---

## File Structure

**Java (plugin — source of truth):**
- Create `src/main/java/eu/starsong/ghidra/util/CallingConvention.java` — pure x86-64 ABI logic (arg regs, return reg, aligned frame). JUnit-testable without Ghidra.
- Create `src/main/java/eu/starsong/ghidra/dto/EmulationCallResultDto.java` — wire shape for a call result.
- Modify `src/main/java/eu/starsong/ghidra/dto/EmulationStateDto.java` — add `DONE`, `HOOK_TRAP`, `REDIRECT_STORM` to `StopReason`.
- Modify `src/main/java/eu/starsong/ghidra/service/EmulationService.java` — `Hook` record, per-`Session` hook registry, `setHook`/`clearHook`/`listHooks`, `callFunction`, plus pure helpers (`le8`, `le8ToLong`, `addrOf`, `MASK64`).
- Modify `src/main/java/eu/starsong/ghidra/resource/EmulationResource.java` — `POST /emulation/call`, `POST /emulation/hooks`, `DELETE /emulation/hooks/{address}`, `GET /emulation/hooks`.
- Modify `src/main/java/eu/starsong/ghidra/api/ApiConstants.java` — bump `PLUGIN_VERSION`.

**Java tests:**
- Create `src/test/java/eu/starsong/ghidra/util/CallingConventionTest.java`.
- Modify `src/test/java/eu/starsong/ghidra/service/EmulationServiceTest.java` — `Hook` validation + `le8`/`le8ToLong` round-trip tests.

**Python bridge / CLI:**
- Modify `bridge_mcp_hydra.py` — `emulation_hook_set/clear/list`, `emulation_call`; bump `BRIDGE_VERSION`.
- Modify `ghydra/cli/emulation.py` — `hook-set`, `hook-clear`, `hook-list`, `call` commands.

**Python tests:**
- Create `tests/test_bridge_pcode_call.py` — bridge call/hook wiring with a mocked HTTP client.
- Modify `test_emulation.py` — live integration: hook round-trip + a real `call`.

**Docs:**
- Modify `CHANGELOG.md`, `GHIDRA_HTTP_API.md`, `GHYDRA_CLI.md`, `README.md`.

---

### Task 1: CallingConvention pure helper (Java)

**Files:**
- Create: `src/main/java/eu/starsong/ghidra/util/CallingConvention.java`
- Test: `src/test/java/eu/starsong/ghidra/util/CallingConventionTest.java`

**Interfaces:**
- Produces: `CallingConvention.check(String)`, `CallingConvention.argRegisters(String) -> List<String>`, `CallingConvention.returnRegister(String) -> String`, `CallingConvention.alignedCallFrame(long rsp, String convention, int nStackArgs) -> long`.

- [ ] **Step 1: Write the failing test**

```java
package eu.starsong.ghidra.util;

import org.junit.Test;
import java.util.List;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class CallingConventionTest {
    @Test
    public void sysvArgRegisterOrder() {
        assertEquals(List.of("RDI", "RSI", "RDX", "RCX", "R8", "R9"),
                CallingConvention.argRegisters("sysv"));
    }

    @Test
    public void msArgRegisterOrder() {
        assertEquals(List.of("RCX", "RDX", "R8", "R9"),
                CallingConvention.argRegisters("ms"));
    }

    @Test
    public void returnRegisterIsRax() {
        assertEquals("RAX", CallingConvention.returnRegister("sysv"));
        assertEquals("RAX", CallingConvention.returnRegister("ms"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsUnknownConvention() {
        CallingConvention.check("fastcall");
    }

    @Test
    public void alignedFrameIsCalleeEntryAligned() {
        // Mirrors calling_convention.aligned_call_frame: final RSP % 16 == 8.
        for (int n = 0; n < 5; n++) {
            long f = CallingConvention.alignedCallFrame(0x7fffeffff000L, "sysv", n);
            assertEquals("final RSP must satisfy callee-entry ABI (rsp%16==8)", 8L, Math.floorMod(f, 16));
            assertTrue(f < 0x7fffeffff000L);
        }
        // MS reserves 32 bytes shadow space, so its frame sits lower than sysv for the same args.
        assertTrue(CallingConvention.alignedCallFrame(0x7fffeffff000L, "ms", 0)
                 < CallingConvention.alignedCallFrame(0x7fffeffff000L, "sysv", 0));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -Dtest=CallingConventionTest`
Expected: FAIL — `CallingConvention` does not exist / does not compile.

- [ ] **Step 3: Write minimal implementation**

```java
package eu.starsong.ghidra.util;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Pure x86-64 calling-convention logic (no Ghidra dependency) for the high-level
 * {@code callFunction} primitive: arg-register order, return register, and the
 * 16-byte-aligned stack frame. A direct port of {@code ghydra/dynamic/calling_convention.py}
 * so the PCode and Unicorn backends lay out calls identically.
 */
public final class CallingConvention {

    private CallingConvention() {}

    public static final Set<String> SUPPORTED = Set.of("sysv", "ms");

    private static final Map<String, List<String>> ARG_REGISTERS = Map.of(
        "sysv", List.of("RDI", "RSI", "RDX", "RCX", "R8", "R9"),
        "ms",   List.of("RCX", "RDX", "R8", "R9"));

    public static String check(String convention) {
        if (!SUPPORTED.contains(convention)) {
            throw new IllegalArgumentException(
                "unsupported calling convention: " + convention + " (supported: [ms, sysv])");
        }
        return convention;
    }

    public static List<String> argRegisters(String convention) {
        return List.copyOf(ARG_REGISTERS.get(check(convention)));
    }

    public static String returnRegister(String convention) {
        check(convention);
        return "RAX";
    }

    /**
     * Final RSP after laying out stack args, MS shadow space (if applicable), and the
     * sentinel return address. Guarantees callee-entry ABI alignment: {@code rsp % 16 == 8}
     * (the 8-byte sentinel occupies the low 8 bytes of a 16-aligned frame). The MS ABI
     * adds 32 bytes of caller-allocated shadow space above RSP.
     */
    public static long alignedCallFrame(long rsp, String convention, int nStackArgs) {
        check(convention);
        long body = 8L * nStackArgs + ("ms".equals(convention) ? 32L : 0L);
        long target = rsp - body - 8L;                 // tentative sentinel slot
        return target - Math.floorMod(target - 8L, 16L); // round down so final % 16 == 8
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn test -Dtest=CallingConventionTest`
Expected: PASS (all 5 tests green).

- [ ] **Step 5: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/util/CallingConvention.java \
        src/test/java/eu/starsong/ghidra/util/CallingConventionTest.java
git commit -m "feat(pcode): pure x86-64 CallingConvention helper for call primitive"
```

---

### Task 2: StopReason extension + Hook model + registry (Java)

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/dto/EmulationStateDto.java:19-32`
- Modify: `src/main/java/eu/starsong/ghidra/service/EmulationService.java` (add `Hook` record near `MemWrite` at line 84; add registry to `Session` at lines 97-107; add `setHook`/`clearHook`/`listHooks`)
- Test: `src/test/java/eu/starsong/ghidra/service/EmulationServiceTest.java`

**Interfaces:**
- Consumes: `EmulationService.MemWrite` (existing), `EmulationService.parseBig` (existing).
- Produces:
  - `enum StopReason { ..., DONE, HOOK_TRAP, REDIRECT_STORM }`
  - `EmulationService.Hook` record: `Hook(String action, BigInteger returnValue, List<MemWrite> memWrites)` with validation; `Hook.ACTIONS = Set.of("return_const","skip","log","trap")`.
  - `void setHook(Program, String address, Hook)`, `boolean clearHook(Program, String address)`, `Map<String,Hook> listHooks(Program)` (keys are `0x`-prefixed addresses).

- [ ] **Step 1: Write the failing test** (append to `EmulationServiceTest.java`)

```java
    // ---- Hook validation (pure; mirrors Unicorn Hook.__post_init__) ----
    @Test
    public void hookReturnConstAllowsValueAndMemWrites() {
        EmulationService.Hook h = new EmulationService.Hook(
            "return_const", new java.math.BigInteger("2a", 16),
            java.util.List.of(new EmulationService.MemWrite("0x1000", "41")));
        assertEquals("return_const", h.action());
    }

    @Test(expected = IllegalArgumentException.class)
    public void hookRejectsUnknownAction() {
        new EmulationService.Hook("frobnicate", null, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void hookRejectsReturnValueOnSkip() {
        new EmulationService.Hook("skip", java.math.BigInteger.ONE, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void hookRejectsMemWritesOnSkip() {
        new EmulationService.Hook("skip", null,
            java.util.List.of(new EmulationService.MemWrite("0x1000", "41")));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -Dtest=EmulationServiceTest`
Expected: FAIL — `EmulationService.Hook` does not exist.

- [ ] **Step 3a: Extend the StopReason enum**

In `EmulationStateDto.java`, replace the enum body's closing region (the `MAX_STEPS` constant at line 31) so it reads:

```java
        /** {@code run} hit its step cap without otherwise stopping. */
        MAX_STEPS,
        /** A {@code call} ran to its synthetic return address and completed cleanly. */
        DONE,
        /** A {@code call} stopped because a {@code trap} hook fired. */
        HOOK_TRAP,
        /** A {@code call} exceeded the hook-redirect cap without making progress. */
        REDIRECT_STORM
```

- [ ] **Step 3b: Add the Hook record** in `EmulationService.java`, immediately after the `MemWrite` record (after line 89):

```java
    /**
     * A hook that stubs a call/import during {@link #callFunction}. Mirrors the Unicorn
     * {@code Hook} contract: {@code return_value} and {@code memWrites} are valid only with
     * {@code return_const}; {@code log} records the hit and still executes the instruction;
     * {@code return_const}/{@code skip} simulate a {@code ret} instead of executing it.
     */
    public record Hook(String action, BigInteger returnValue, List<MemWrite> memWrites) {
        public static final Set<String> ACTIONS = Set.of("return_const", "skip", "log", "trap");
        public Hook {
            if (!ACTIONS.contains(action)) {
                throw new IllegalArgumentException(
                    "unknown hook action: " + action + " (expected one of " + ACTIONS + ")");
            }
            boolean isReturnConst = "return_const".equals(action);
            if (returnValue != null && !isReturnConst) {
                throw new IllegalArgumentException("return_value is only valid with return_const");
            }
            if (memWrites != null && !memWrites.isEmpty() && !isReturnConst) {
                throw new IllegalArgumentException("mem_writes is only valid with return_const");
            }
        }
    }
```

- [ ] **Step 3c: Add the registry to `Session`** — inside the `Session` class (after line 102, next to `breakpoints`):

```java
        final Map<Address, Hook> hooks = new LinkedHashMap<>();
```

- [ ] **Step 3d: Add the service methods** in `EmulationService.java`, after `clearBreakpoint` (after line 276):

```java
    public void setHook(Program program, String addrStr, Hook hook) {
        Session s = require(program);
        Address a = GhidraUtil.resolveAddress(program, addrStr);
        if (a == null) throw new IllegalArgumentException("Invalid hook address: " + addrStr);
        GhidraSwing.runRead(() -> { s.hooks.put(a, hook); return null; });
    }

    public boolean clearHook(Program program, String addrStr) {
        Session s = require(program);
        Address a = GhidraUtil.resolveAddress(program, addrStr);
        if (a == null) throw new IllegalArgumentException("Invalid hook address: " + addrStr);
        return GhidraSwing.runRead(() -> s.hooks.remove(a) != null);
    }

    /** Snapshot of the session's hooks, keyed by 0x-prefixed address. */
    public Map<String, Hook> listHooks(Program program) {
        Session s = require(program);
        return GhidraSwing.runRead(() -> {
            Map<String, Hook> out = new LinkedHashMap<>();
            for (Map.Entry<Address, Hook> e : s.hooks.entrySet()) {
                out.put("0x" + e.getKey().getOffsetAsBigInteger().toString(16), e.getValue());
            }
            return out;
        });
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn test -Dtest=EmulationServiceTest,EmulationStateDtoTest`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/dto/EmulationStateDto.java \
        src/main/java/eu/starsong/ghidra/service/EmulationService.java \
        src/test/java/eu/starsong/ghidra/service/EmulationServiceTest.java
git commit -m "feat(pcode): Hook model + StopReason DONE/HOOK_TRAP/REDIRECT_STORM"
```

---

### Task 3: EmulationCallResultDto + pure byte helpers (Java)

**Files:**
- Create: `src/main/java/eu/starsong/ghidra/dto/EmulationCallResultDto.java`
- Modify: `src/main/java/eu/starsong/ghidra/service/EmulationService.java` (add `MASK64`, `le8`, `le8ToLong`)
- Test: `src/test/java/eu/starsong/ghidra/service/EmulationServiceTest.java`

**Interfaces:**
- Produces:
  - `EmulationCallResultDto.of(String pc, StopReason stopReason, String convention, String returnValue, List<String> argsPassed, Map<String,String> registers, List<String> hookLog, String lastError)`.
  - `static byte[] EmulationService.le8(BigInteger)`, `static long EmulationService.le8ToLong(byte[])`, `static final BigInteger EmulationService.MASK64`.

- [ ] **Step 1: Write the failing test** (append to `EmulationServiceTest.java`)

```java
    @Test
    public void le8RoundTripsLittleEndian() {
        byte[] b = EmulationService.le8(new java.math.BigInteger("deadbeef", 16));
        // little-endian: low byte first
        assertEquals((byte) 0xef, b[0]);
        assertEquals((byte) 0xde, b[3]);
        assertEquals(0xdeadbeefL, EmulationService.le8ToLong(b));
    }

    @Test
    public void le8MasksTo64Bits() {
        // negative BigInteger wraps into unsigned 64-bit, like the register helpers
        byte[] b = EmulationService.le8(java.math.BigInteger.valueOf(-1));
        assertEquals(0xffffffffffffffffL, EmulationService.le8ToLong(b));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -Dtest=EmulationServiceTest`
Expected: FAIL — `le8` not defined.

- [ ] **Step 3a: Add the DTO**

```java
package eu.starsong.ghidra.dto;

import eu.starsong.ghidra.dto.EmulationStateDto.StopReason;

import java.util.List;
import java.util.Map;

/** Wire representation of a {@code POST /emulation/call} result (mirrors unicorn_call). */
public record EmulationCallResultDto(
        String pc,
        StopReason stopReason,
        String convention,
        String returnValue,
        List<String> argsPassed,
        Map<String, String> registers,
        List<String> hookLog,
        String lastError) {

    public static EmulationCallResultDto of(String pc, StopReason stopReason, String convention,
            String returnValue, List<String> argsPassed, Map<String, String> registers,
            List<String> hookLog, String lastError) {
        return new EmulationCallResultDto(
            pc, stopReason, convention, returnValue, argsPassed, registers, hookLog, lastError);
    }
}
```

- [ ] **Step 3b: Add the byte helpers** in `EmulationService.java`, in the "Pure hex helpers" block (after `toHex`, around line 65):

```java
    static final BigInteger MASK64 = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);

    /** 8-byte little-endian encoding of a value, masked to the unsigned 64-bit range. */
    static byte[] le8(BigInteger value) {
        BigInteger m = value.and(MASK64);
        byte[] out = new byte[8];
        for (int i = 0; i < 8; i++) {
            out[i] = (byte) (m.shiftRight(8 * i).intValue() & 0xff);
        }
        return out;
    }

    /** Decode an 8-byte little-endian buffer (e.g. a popped return address). */
    static long le8ToLong(byte[] b) {
        long v = 0;
        for (int i = 0; i < 8; i++) v |= (long) (b[i] & 0xff) << (8 * i);
        return v;
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn test -Dtest=EmulationServiceTest`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/dto/EmulationCallResultDto.java \
        src/main/java/eu/starsong/ghidra/service/EmulationService.java \
        src/test/java/eu/starsong/ghidra/service/EmulationServiceTest.java
git commit -m "feat(pcode): EmulationCallResultDto + little-endian byte helpers"
```

---

### Task 4: callFunction dispatch loop (Java)

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/service/EmulationService.java` (add constants, `CallArg` record, `callFunction`)

**Interfaces:**
- Consumes: `CallingConvention` (Task 1), `Hook` + registry (Task 2), `EmulationCallResultDto` + `le8`/`le8ToLong`/`MASK64` (Task 3), existing `require`, `snapshot`, `parseBig`, `hexToBytes`, `GhidraSwing.runRead`.
- Produces: `EmulationCallResultDto callFunction(Program, String funcStr, List<CallArg> args, String convention, long count)`; public record `EmulationService.CallArg(BigInteger intValue, byte[] bytes)`.

This task is dominated by live-Ghidra behavior, so it has no standalone JUnit test (the loop is exercised by the live integration test in Task 9 and by the bridge unit test in Task 8 against a mocked endpoint). Keep the code self-contained and reviewable.

- [ ] **Step 1: Add constants** to `EmulationService.java`, next to the existing caps (after line 92):

```java
    private static final long CALL_STACK_BASE = 0x7ffff0000000L;
    private static final long CALL_STACK_SIZE = 0x100000L;
    private static final long CALL_ARGS_SPLIT = 0x40000L;
    private static final long SENTINEL_ADDR  = 0x0000DEAD0000C0DEL;
    private static final int  REDIRECT_CAP    = 10_000;
```

- [ ] **Step 2: Add the CallArg record** after the `Hook` record:

```java
    /** One call argument: exactly one of {@code intValue} / {@code bytes} is non-null. */
    public record CallArg(BigInteger intValue, byte[] bytes) {
        public CallArg {
            if ((intValue == null) == (bytes == null)) {
                throw new IllegalArgumentException("CallArg must carry exactly one of int/bytes");
            }
        }
    }
```

- [ ] **Step 3: Add `callFunction`** after `step` (around line 185):

```java
    /**
     * Call a function on the current session: set up the x86-64 ABI, run to a synthetic
     * return address, and report the return register. Uses the session's registered hooks
     * to stub imports. Mutates the session's registers/stack region (mirrors unicorn_call).
     *
     * <p>Dispatch is a manual single-step loop that inspects PC <em>before</em> each
     * instruction: a hooked address is handled (logged, trapped, or redirected via a
     * simulated {@code ret}); the sentinel return address is detected by value and ends the
     * call as {@link StopReason#DONE}. No EmulatorHelper breakpoints are involved.
     */
    public EmulationCallResultDto callFunction(Program program, String funcStr,
            List<CallArg> args, String convention, long count) {
        CallingConvention.check(convention);
        Address func = GhidraUtil.resolveAddress(program, funcStr);
        if (func == null) throw new IllegalArgumentException("Invalid function address: " + funcStr);
        Session s = require(program);

        List<String> regNames = CallingConvention.argRegisters(convention);
        String retReg = CallingConvention.returnRegister(convention);

        // Pre-size bytes args (16-byte aligned) and validate the scratch budget up front.
        long bytesBudget = 0;
        for (CallArg a : args) {
            if (a.bytes() != null) bytesBudget += (a.bytes().length + 15L) & ~15L;
        }
        if (bytesBudget > CALL_ARGS_SPLIT) {
            throw new IllegalArgumentException(
                "bytes args exceed scratch budget (" + CALL_ARGS_SPLIT + " bytes)");
        }
        long cap = Math.min(count <= 0 ? MAX_STEPS_CAP : count, MAX_STEPS_CAP);

        return GhidraSwing.runRead(() -> {
            EmulatorHelper emu = s.emu;
            var space = program.getAddressFactory().getDefaultAddressSpace();
            Register pcReg = emu.getPCRegister();
            Register spReg = emu.getStackPointerRegister();

            // 1) Park bytes args in the low scratch region; resolve every arg to a 64-bit value.
            long argsCursor = CALL_STACK_BASE;
            List<BigInteger> resolved = new ArrayList<>();
            for (CallArg a : args) {
                if (a.bytes() != null) {
                    emu.writeMemory(space.getAddress(argsCursor), a.bytes());
                    resolved.add(BigInteger.valueOf(argsCursor));
                    argsCursor += (a.bytes().length + 15L) & ~15L;
                } else {
                    resolved.add(a.intValue());
                }
            }
            List<BigInteger> regArgs = resolved.subList(0, Math.min(regNames.size(), resolved.size()));
            List<BigInteger> stackArgs = resolved.size() > regNames.size()
                ? resolved.subList(regNames.size(), resolved.size()) : List.of();

            // 2) Lay out the stack frame: sentinel return address at [RSP], stack args above it.
            long rspTop = CALL_STACK_BASE + CALL_STACK_SIZE - 0x1000L;
            long finalRsp = CallingConvention.alignedCallFrame(rspTop, convention, stackArgs.size());
            for (int i = 0; i < stackArgs.size(); i++) {
                emu.writeMemory(space.getAddress(finalRsp + 8L + i * 8L), le8(stackArgs.get(i)));
            }
            emu.writeMemory(space.getAddress(finalRsp), le8(BigInteger.valueOf(SENTINEL_ADDR)));
            emu.writeRegister(spReg, BigInteger.valueOf(finalRsp));

            // 3) Load register args and jump to the function entry.
            for (int i = 0; i < regArgs.size(); i++) {
                emu.writeRegister(regNames.get(i), regArgs.get(i).and(MASK64));
            }
            emu.writeRegister(pcReg, func.getOffsetAsBigInteger());

            // 4) Manual dispatch loop (PC checked before each instruction).
            StopReason stop = StopReason.ERROR;
            String lastError = "call did not complete";
            List<String> hookLog = new ArrayList<>();
            long executed = 0;
            int redirects = 0;
            while (executed < cap) {
                long pc = emu.readRegister(pcReg).longValue();
                if (pc == SENTINEL_ADDR) { stop = StopReason.DONE; lastError = null; break; }

                Hook hook = s.hooks.get(space.getAddress(pc));
                if (hook != null) {
                    String action = hook.action();
                    if ("trap".equals(action)) {
                        stop = StopReason.HOOK_TRAP;
                        lastError = "trap hook at 0x" + Long.toHexString(pc);
                        break;
                    } else if ("return_const".equals(action) || "skip".equals(action)) {
                        if ("return_const".equals(action) && hook.memWrites() != null) {
                            for (MemWrite w : hook.memWrites()) {
                                Address wa = GhidraUtil.resolveAddress(program, w.address());
                                if (wa == null) {
                                    stop = StopReason.ERROR;
                                    lastError = "hook mem_write bad address: " + w.address();
                                    break;
                                }
                                emu.writeMemory(wa, hexToBytes(w.hex()));
                            }
                            if (stop == StopReason.ERROR && lastError != null
                                    && lastError.startsWith("hook mem_write")) break;
                        }
                        BigInteger rv = "return_const".equals(action) ? hook.returnValue() : null;
                        simulateRet(emu, pcReg, spReg, space, retReg, rv);
                        if (++redirects >= REDIRECT_CAP) {
                            stop = StopReason.REDIRECT_STORM;
                            lastError = "redirect storm: " + redirects + " hook redirects without progress";
                            break;
                        }
                        continue;   // do not execute the hooked instruction
                    }
                    // "log": record and fall through to execute the instruction normally.
                    hookLog.add("0x" + Long.toHexString(pc));
                }

                boolean ok;
                try {
                    ok = emu.step(TaskMonitor.DUMMY);
                } catch (Exception | LinkageError t) {
                    stop = StopReason.ERROR;
                    String msg = t.getMessage();
                    lastError = (msg != null && !msg.isEmpty()) ? msg : t.getClass().getSimpleName();
                    break;
                }
                s.steps++;
                executed++;
                if (!ok) {
                    stop = StopReason.ERROR;
                    String err = emu.getLastError();
                    lastError = (err != null && !err.isEmpty()) ? err : "emulation halted without an error message";
                    break;
                }
                if (executed >= cap) { stop = StopReason.MAX_STEPS; lastError = "instruction cap reached"; }
            }

            s.stopReason = stop;
            s.lastError = stop == StopReason.DONE ? null : lastError;

            Map<String, String> regs = new LinkedHashMap<>();
            for (Register r : program.getLanguage().getRegisters()) {
                if (r.isBaseRegister() && !r.isProcessorContext()) {
                    try { regs.put(r.getName(), toHex(emu.readRegister(r))); }
                    catch (RuntimeException ignore) { /* unreadable in this state; omit */ }
                }
            }
            String returnValue = toHex(emu.readRegister(retReg));
            List<String> argsPassed = new ArrayList<>();
            for (BigInteger v : resolved) argsPassed.add(toHex(v));
            long pcNow = emu.readRegister(pcReg).longValue();
            return EmulationCallResultDto.of(
                "0x" + Long.toHexString(pcNow), stop, convention, returnValue,
                argsPassed, regs, hookLog, stop == StopReason.DONE ? null : lastError);
        });
    }

    /** Simulate a {@code ret}: RIP = [RSP]; RSP += 8; optionally set the return register. */
    private void simulateRet(EmulatorHelper emu, Register pcReg, Register spReg,
            ghidra.program.model.address.AddressSpace space, String retReg, BigInteger returnValue) {
        long rsp = emu.readRegister(spReg).longValue();
        long ret = le8ToLong(emu.readMemory(space.getAddress(rsp), 8));
        emu.writeRegister(pcReg, BigInteger.valueOf(ret).and(MASK64));
        emu.writeRegister(spReg, BigInteger.valueOf(rsp + 8L));
        if (returnValue != null) emu.writeRegister(retReg, returnValue.and(MASK64));
    }
```

- [ ] **Step 4: Compile**

Run: `mvn -q -DskipTests compile`
Expected: BUILD SUCCESS (resolve any missing imports — `AddressSpace`, `Register` are already imported in this file; `EmulatorHelper`, `Address`, `BigInteger`, `LinkedHashMap` too).

- [ ] **Step 5: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/service/EmulationService.java
git commit -m "feat(pcode): callFunction dispatch loop with hook stubbing + sentinel return"
```

---

### Task 5: REST endpoints (Java)

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/resource/EmulationResource.java`
- Modify: `src/main/java/eu/starsong/ghidra/api/ApiConstants.java:4`

**Interfaces:**
- Consumes: `service.callFunction`, `service.setHook`, `service.clearHook`, `service.listHooks`, `EmulationCallResultDto`, `EmulationService.{Hook,CallArg,MemWrite}`.
- Produces (HTTP): `POST /emulation/call`, `POST /emulation/hooks`, `DELETE /emulation/hooks/{address}`, `GET /emulation/hooks`.

- [ ] **Step 1: Register the routes** — in `EmulationResource.register` (after line 38, before the `delete("/emulation", ...)` line):

```java
        app.post("/emulation/call", ctx -> call(contextFactory.apply(ctx)));
        app.post("/emulation/hooks", ctx -> setHook(contextFactory.apply(ctx)));
        app.delete("/emulation/hooks/{address}", ctx -> clearHook(contextFactory.apply(ctx)));
        app.get("/emulation/hooks", ctx -> listHooks(contextFactory.apply(ctx)));
```

- [ ] **Step 2: Add the handlers** — after `dispose` (after line 152), before the request-class block:

```java
    private void call(GhidraContext ctx) {
        var program = ctx.requireProgram();
        CallRequest req = ctx.bodyAsClass(CallRequest.class);
        if (req == null || req.func == null) throw new IllegalArgumentException("func is required");
        String convention = req.convention == null ? "sysv" : req.convention;
        List<EmulationService.CallArg> args = new ArrayList<>();
        if (req.args != null) {
            for (Map<String, String> a : req.args) {
                if (a.containsKey("int")) {
                    args.add(new EmulationService.CallArg(EmulationService.parseBig(a.get("int")), null));
                } else if (a.containsKey("bytes")) {
                    args.add(new EmulationService.CallArg(null, EmulationService.hexToBytes(a.get("bytes"))));
                } else {
                    throw new IllegalArgumentException("each arg needs an \"int\" or \"bytes\" key");
                }
            }
        }
        EmulationCallResultDto dto = service.callFunction(program, req.func, args, convention, req.count);
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), dto).self("/emulation/call")
            .link("emulation", "/emulation/state").build());
    }

    private void setHook(GhidraContext ctx) {
        var program = ctx.requireProgram();
        HookRequest req = ctx.bodyAsClass(HookRequest.class);
        if (req == null || req.address == null || req.action == null) {
            throw new IllegalArgumentException("address and action are required");
        }
        java.math.BigInteger rv = req.return_value == null ? null : EmulationService.parseBig(req.return_value);
        List<EmulationService.MemWrite> mem = new ArrayList<>();
        if (req.mem_writes != null) {
            for (Map<String, String> m : req.mem_writes) {
                mem.add(new EmulationService.MemWrite(m.get("address"), m.get("hex")));
            }
        }
        // Hook's constructor enforces the action/return_value/mem_writes invariants.
        service.setHook(program, req.address, new EmulationService.Hook(req.action, rv, mem.isEmpty() ? null : mem));
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("address", req.address);
        data.put("action", req.action);
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data).self("/emulation/hooks").build());
    }

    private void clearHook(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");
        boolean removed = service.clearHook(program, address);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("address", address);
        data.put("removed", removed);
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data).self("/emulation/hooks/{}", address).build());
    }

    private void listHooks(GhidraContext ctx) {
        var program = ctx.requireProgram();
        List<Map<String, Object>> hooks = new ArrayList<>();
        for (Map.Entry<String, EmulationService.Hook> e : service.listHooks(program).entrySet()) {
            var h = e.getValue();
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("address", e.getKey());
            row.put("action", h.action());
            row.put("return_value", h.returnValue() == null ? null : EmulationService.toHex(h.returnValue()));
            row.put("mem_writes", h.memWrites());
            hooks.add(row);
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("hooks", hooks);
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data).self("/emulation/hooks").build());
    }
```

- [ ] **Step 3: Add the request classes** — in the request-class block (after line 163):

```java
    private static class CallRequest {
        public String func;
        public List<Map<String, String>> args;
        public String convention;
        public long count;
    }
    private static class HookRequest {
        public String address;
        public String action;
        public String return_value;
        public List<Map<String, String>> mem_writes;
    }
```

- [ ] **Step 4: Bump the plugin version** — `ApiConstants.java:4`:

```java
    public static final String PLUGIN_VERSION = "v3.1.0-rc.2";
```

- [ ] **Step 5: Build the whole plugin + run all Java tests**

Run: `mvn -q clean package -P plugin-only -Dghidra.version=12.1.2` (set `GHIDRA_HOME` first)
Expected: BUILD SUCCESS; all JUnit tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/resource/EmulationResource.java \
        src/main/java/eu/starsong/ghidra/api/ApiConstants.java
git commit -m "feat(pcode): /emulation/call + /emulation/hooks endpoints; bump PLUGIN_VERSION"
```

---

### Task 6: Bridge tools (Python)

**Files:**
- Modify: `bridge_mcp_hydra.py` (add four tools after `emulation_dispose` at line 3084; bump `BRIDGE_VERSION` at line 36)

**Interfaces:**
- Consumes (HTTP): the Task 5 endpoints; existing `_get_instance_port`, `safe_post`, `safe_get`, `safe_delete`, `simplify_response`, `quote`.
- Produces (MCP tools): `emulation_hook_set`, `emulation_hook_clear`, `emulation_hook_list`, `emulation_call`.

- [ ] **Step 1: Write the failing test** — see Task 8 (the bridge tests are written there and drive this task). For now, add the tools.

- [ ] **Step 2: Bump the bridge version** — `bridge_mcp_hydra.py:36`:

```python
BRIDGE_VERSION = "v3.1.0-rc.5"
```

- [ ] **Step 3: Add the four tools** after `emulation_dispose` (line 3084):

```python
@mcp.tool()
@text_output
def emulation_hook_set(address: str, action: str, return_value: str | None = None,
                       mem_writes: list | None = None, port: int | None = None) -> dict:
    """Register a PCode-emulation hook to stub a call/import (see unicorn_hook_set).

    action is one of: "return_const" (set RAX to return_value, simulate ret; may carry
    mem_writes side-effects), "skip" (simulate ret, RAX untouched), "log" (record the hit
    and continue), "trap" (stop with stopReason HOOK_TRAP). mem_writes
    ([{"address": hex, "hex": bytes}]) are allowed only with return_const. Requires an
    emulation session (call emulation_reset first); hooks persist until cleared or reset.

    Args:
        address: Hook address in hex
        action: return_const | skip | log | trap
        return_value: Hex value for return_const (optional)
        mem_writes: [{"address": hex, "hex": hexbytes}] for return_const (optional)
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    body: dict = {"address": address, "action": action}
    if return_value is not None:
        body["return_value"] = return_value
    if mem_writes is not None:
        body["mem_writes"] = mem_writes
    return simplify_response(safe_post(port, "emulation/hooks", body))


@mcp.tool()
@text_output
def emulation_hook_clear(address: str, port: int | None = None) -> dict:
    """Remove a PCode-emulation hook previously set at an address.

    Args:
        address: Hook address in hex
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(safe_delete(port, f"emulation/hooks/{quote(address, safe=':')}"))


@mcp.tool()
@text_output
def emulation_hook_list(port: int | None = None) -> dict:
    """List the hooks registered on the current PCode-emulation session.

    Args:
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(safe_get(port, "emulation/hooks"))


@mcp.tool()
@text_output
def emulation_call(func: str, args: list | None = None, convention: str = "sysv",
                   count: int = 1_000_000, port: int | None = None) -> dict:
    """Call a function in the PCode-emulation session and report its return value.

    Precondition: call emulation_reset first, then emulation_hook_set to stub any imports the
    function will call (or they will fault). Sets up the x86-64 calling convention (sysv
    default, or ms), runs to a synthetic return address, and returns RAX. args is a list of
    ints and/or {"bytes": hex} pointer args; floats and by-value structs are not supported.

    success is true only when the function returned cleanly (stopReason DONE). A
    HOOK_TRAP / REDIRECT_STORM / ERROR / MAX_STEPS stop returns the partial state so you can
    add a missing hook and retry.

    Args:
        func: Function entry address in hex
        args: List of int args and/or {"bytes": "hex"} pointer args (optional)
        convention: "sysv" (default) or "ms"
        count: Instruction budget (default 1_000_000)
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    wire_args: list = []
    for a in (args or []):
        if isinstance(a, dict) and "bytes" in a:
            wire_args.append({"bytes": a["bytes"]})
        elif isinstance(a, bool):
            return {"success": False, "error": {"code": "VALIDATION",
                    "message": "bool is not a valid integer arg"}}
        elif isinstance(a, int):
            wire_args.append({"int": str(a)})   # str preserves full 64-bit precision over JSON
        else:
            return {"success": False, "error": {"code": "VALIDATION",
                    "message": f'unsupported arg {a!r}; use int or {{"bytes": hex}}'}}
    body = {"func": func, "args": wire_args, "convention": convention, "count": count}
    return simplify_response(safe_post(port, "emulation/call", body))
```

- [ ] **Step 4: Run the bridge unit tests** (from Task 8)

Run: `python -m pytest tests/test_bridge_pcode_call.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bridge_mcp_hydra.py
git commit -m "feat(pcode): bridge emulation_call + emulation_hook_* tools; bump BRIDGE_VERSION"
```

---

### Task 7: CLI commands (Python)

**Files:**
- Modify: `ghydra/cli/emulation.py`

**Interfaces:**
- Consumes: `ctx.obj['client']` (`GhidraHTTPClient`), `validate_address`, `rich_echo`, `_emit` (existing in this file).
- Produces (CLI): `ghydra emulation hook-set`, `hook-clear`, `hook-list`, `call`.

- [ ] **Step 1: Add the commands** to `ghydra/cli/emulation.py` (after `dispose`, line 172):

```python
@emulation.command('hook-set')
@click.option('--address', '-a', required=True, help='Hook address (hex)')
@click.option('--action', required=True,
              type=click.Choice(['return_const', 'skip', 'log', 'trap']))
@click.option('--return-value', '-r', help='Hex return value (return_const only)')
@click.pass_context
def hook_set(ctx, address, action, return_value):
    """Stub a call/import during emulation (return_const/skip/log/trap)."""
    client = ctx.obj['client']
    try:
        body = {'address': validate_address(address), 'action': action}
        if return_value is not None:
            body['return_value'] = return_value
        _emit(ctx, client.post('emulation/hooks', json_data=body))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('hook-clear')
@click.option('--address', '-a', required=True, help='Hook address (hex)')
@click.pass_context
def hook_clear(ctx, address):
    """Remove a previously set emulation hook."""
    client = ctx.obj['client']
    try:
        _emit(ctx, client.delete(f'emulation/hooks/{validate_address(address)}'))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('hook-list')
@click.pass_context
def hook_list(ctx):
    """List hooks registered on the current emulation session."""
    client = ctx.obj['client']
    try:
        _emit(ctx, client.get('emulation/hooks'))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('call')
@click.option('--func', '-f', required=True, help='Function entry address (hex)')
@click.option('--arg', 'int_args', multiple=True, help='Integer arg (decimal or 0xhex); repeatable')
@click.option('--arg-bytes', 'byte_args', multiple=True,
              help='Pointer arg: hex bytes parked in scratch, pointer passed; repeatable')
@click.option('--hook', 'hooks', multiple=True,
              help='address:action[:retval] set before the call, e.g. 0x401100:return_const:0; repeatable')
@click.option('--convention', type=click.Choice(['sysv', 'ms']), default='sysv')
@click.option('--count', type=int, default=1000000, help='Instruction cap')
@click.pass_context
def call(ctx, func, int_args, byte_args, hooks, convention, count):
    """Call a function (set up the ABI, stub imports via --hook) and print the result.

    Requires an active session (run `emulation reset` first). --hook registers a
    session hook before the call (it persists until cleared or reset).
    """
    client = ctx.obj['client']
    try:
        for spec in hooks:
            parts = spec.split(':')
            if len(parts) < 2:
                raise click.ClickException(f"bad --hook {spec!r}; want address:action[:retval]")
            body = {'address': validate_address(parts[0]), 'action': parts[1]}
            if len(parts) > 2:
                body['return_value'] = parts[2]
            client.post('emulation/hooks', json_data=body)
        # Click cannot interleave two multiple=True options; ints always precede bytes-args.
        args = [{'int': a} for a in int_args] + [{'bytes': validate_address(b)} for b in byte_args]
        _emit(ctx, client.post('emulation/call', json_data={
            'func': validate_address(func), 'args': args,
            'convention': convention, 'count': count}))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)
```

> Note: the CLI sends int args as `{"int": "<dec-or-hex>"}` strings directly (the Java `parseBig` accepts both), so no Python-side int parsing is needed here.

- [ ] **Step 2: Smoke-test the CLI wiring** (no live Ghidra needed — just that the group loads)

Run: `python -c "from ghydra.cli.emulation import emulation; print(sorted(c for c in emulation.commands))"`
Expected: list includes `call`, `hook-clear`, `hook-list`, `hook-set`.

- [ ] **Step 3: Commit**

```bash
git add ghydra/cli/emulation.py
git commit -m "feat(pcode): ghydra emulation call + hook-set/hook-clear/hook-list"
```

---

### Task 8: Bridge unit tests (mocked HTTP)

**Files:**
- Create: `tests/test_bridge_pcode_call.py`

**Interfaces:**
- Consumes: `bridge_mcp_hydra` tools (via `.__wrapped__`), monkeypatched `safe_post`/`safe_get`/`safe_delete` and `_get_instance_port`.

- [ ] **Step 1: Write the tests**

```python
# tests/test_bridge_pcode_call.py
"""Unit tests for the PCode emulation_call / emulation_hook_* bridge tools.

No Ghidra needed: the HTTP layer is monkeypatched, so these assert the bridge's
request shaping and arg normalization, not live emulation.
"""
import bridge_mcp_hydra as bridge


def _capture(monkeypatch):
    calls = {}
    monkeypatch.setattr(bridge, "_get_instance_port", lambda p=None: 8192)
    monkeypatch.setattr(bridge, "simplify_response", lambda r: r)

    def fake_post(port, path, body=None):
        calls["post"] = (port, path, body)
        return {"success": True, "result": {"stopReason": "DONE"}}

    def fake_get(port, path, params=None):
        calls["get"] = (port, path, params)
        return {"success": True, "result": {"hooks": []}}

    def fake_delete(port, path):
        calls["delete"] = (port, path)
        return {"success": True, "result": {"removed": True}}

    monkeypatch.setattr(bridge, "safe_post", fake_post)
    monkeypatch.setattr(bridge, "safe_get", fake_get)
    monkeypatch.setattr(bridge, "safe_delete", fake_delete)
    return calls


def test_call_normalizes_int_args_to_int_strings(monkeypatch):
    calls = _capture(monkeypatch)
    bridge.emulation_call.__wrapped__("0x401000", args=[1, 0x140075000])
    _, path, body = calls["post"]
    assert path == "emulation/call"
    assert body["args"] == [{"int": "1"}, {"int": str(0x140075000)}]
    assert body["convention"] == "sysv"


def test_call_passes_bytes_args_through(monkeypatch):
    calls = _capture(monkeypatch)
    bridge.emulation_call.__wrapped__("0x401000", args=[{"bytes": "41424300"}])
    _, _, body = calls["post"]
    assert body["args"] == [{"bytes": "41424300"}]


def test_call_rejects_bool_arg(monkeypatch):
    _capture(monkeypatch)
    r = bridge.emulation_call.__wrapped__("0x401000", args=[True])
    assert r["success"] is False
    assert r["error"]["code"] == "VALIDATION"


def test_call_rejects_unsupported_arg(monkeypatch):
    _capture(monkeypatch)
    r = bridge.emulation_call.__wrapped__("0x401000", args=[1.5])
    assert r["success"] is False
    assert r["error"]["code"] == "VALIDATION"


def test_hook_set_omits_optionals_when_absent(monkeypatch):
    calls = _capture(monkeypatch)
    bridge.emulation_hook_set.__wrapped__("0x401100", "skip")
    _, path, body = calls["post"]
    assert path == "emulation/hooks"
    assert body == {"address": "0x401100", "action": "skip"}


def test_hook_set_includes_return_value_and_mem_writes(monkeypatch):
    calls = _capture(monkeypatch)
    bridge.emulation_hook_set.__wrapped__(
        "0x401100", "return_const", return_value="0x2a",
        mem_writes=[{"address": "0x1000", "hex": "41"}])
    _, _, body = calls["post"]
    assert body["return_value"] == "0x2a"
    assert body["mem_writes"] == [{"address": "0x1000", "hex": "41"}]


def test_hook_clear_uses_delete(monkeypatch):
    calls = _capture(monkeypatch)
    bridge.emulation_hook_clear.__wrapped__("0x401100")
    port, path = calls["delete"]
    assert path == "emulation/hooks/0x401100"


def test_hook_list_uses_get(monkeypatch):
    calls = _capture(monkeypatch)
    bridge.emulation_hook_list.__wrapped__()
    _, path, _ = calls["get"]
    assert path == "emulation/hooks"
```

- [ ] **Step 2: Run to verify it fails first, then passes**

If executing this task before Task 6, run now and expect FAIL (`AttributeError: emulation_call`). After Task 6 is in place:
Run: `python -m pytest tests/test_bridge_pcode_call.py -v`
Expected: PASS (8 tests).

- [ ] **Step 3: Commit**

```bash
git add tests/test_bridge_pcode_call.py
git commit -m "test(pcode): bridge call/hook request-shaping unit tests"
```

---

### Task 9: Live integration tests + EmulatorHelper memory verification

**Files:**
- Modify: `test_emulation.py`

**Interfaces:**
- Consumes: live `/emulation/*` endpoints on `localhost:8192`.

**Key verification:** confirms the one live-only assumption — that `EmulatorHelper.writeMemory` accepts the high scratch/stack addresses (`0x7ffff0000000`+) the call frame uses. If a fresh `call` of a trivial function returns `DONE`, that assumption holds.

- [ ] **Step 1: Add a hook round-trip test** (append inside `EmulationTests`)

```python
    def test_hook_set_list_clear_roundtrip(self):
        _json(requests.post(f"{URL}/emulation/reset", json={"start": self.entry}))
        set_r = _json(requests.post(f"{URL}/emulation/hooks",
                                    json={"address": self.entry, "action": "skip"}))
        self.assertTrue(set_r.get("success"))
        listed = _json(requests.get(f"{URL}/emulation/hooks"))
        addrs = [h["address"] for h in listed["result"]["hooks"]]
        self.assertTrue(any(int(a, 16) == int(self.entry, 16) for a in addrs))
        cleared = _json(requests.delete(f"{URL}/emulation/hooks/{self.entry}"))
        self.assertTrue(cleared["result"]["removed"])

    def test_hook_set_rejects_mem_writes_on_skip(self):
        _json(requests.post(f"{URL}/emulation/reset", json={"start": self.entry}))
        r = requests.post(f"{URL}/emulation/hooks",
                          json={"address": self.entry, "action": "skip",
                                "mem_writes": [{"address": self.entry, "hex": "41"}]})
        self.assertIn(r.status_code, (400, 422))
```

- [ ] **Step 2: Add a real call test using a synthesized `mov eax,7; ret`**

```python
    def test_call_runs_synthetic_function(self):
        # Write `mov eax, 7 ; ret` (b8 07 00 00 00 c3) over the entry, then call it.
        # This also verifies EmulatorHelper accepts the high scratch/stack writes the
        # call frame uses (0x7ffff0000000+); a DONE result confirms that assumption.
        _json(requests.post(f"{URL}/emulation/reset", json={"start": self.entry}))
        _json(requests.post(f"{URL}/emulation/memory",
                            json={"address": self.entry, "hex": "b807000000c3"}))
        r = _json(requests.post(f"{URL}/emulation/call",
                                json={"func": self.entry, "args": [], "convention": "sysv"}))
        self.assertTrue(r.get("success"), msg=r)
        self.assertEqual("DONE", r["result"]["stopReason"])
        self.assertEqual(7, int(r["result"]["returnValue"], 16))
```

- [ ] **Step 3: Run against a live Ghidra (with any binary open)**

Run: `python test_emulation.py`
Expected: PASS if Ghidra is up; SKIP otherwise. If `test_call_runs_synthetic_function` reports a non-`DONE` `stopReason` with a memory error, the scratch-address assumption is wrong — fall back to a stack base inside an existing program block (read `segments_list`, pick a writable block, base the stack there) and re-run.

- [ ] **Step 4: Commit**

```bash
git add test_emulation.py
git commit -m "test(pcode): live hook round-trip + synthetic call integration tests"
```

---

### Task 10: Docs + deferred Java stepOnce coverage

**Files:**
- Modify: `CHANGELOG.md`, `GHIDRA_HTTP_API.md`, `GHYDRA_CLI.md`, `README.md`
- Modify: `src/test/java/eu/starsong/ghidra/service/EmulationServiceTest.java` (closes the deferred `stepOnce` classification gap noted in memory `java-steponce-coverage-deferral`)

- [ ] **Step 1: CHANGELOG entry** — under the current unreleased section:

```markdown
### Added
- PCode emulation `call` primitive (`POST /emulation/call`, `emulation_call`, `ghydra emulation call`):
  set up the x86-64 ABI (sysv/ms), run a function to a synthetic return, return RAX.
- PCode emulation hooks (`/emulation/hooks`, `emulation_hook_set/clear/list`,
  `ghydra emulation hook-set/hook-clear/hook-list`): stub imports during a call with
  `return_const` (incl. `mem_writes` side-effects) / `skip` / `log` / `trap`.
- `StopReason` gains `DONE`, `HOOK_TRAP`, `REDIRECT_STORM` for call results.
```

- [ ] **Step 2: Document the endpoints** in `GHIDRA_HTTP_API.md` (mirror the `/emulation/run` entry style) and the CLI commands in `GHYDRA_CLI.md` (mirror `ghydra dynamic call`). Add the new MCP tools to the emulation section of `README.md`.

- [ ] **Step 3: Close the deferred stepOnce coverage** — add a JUnit test asserting `BREAKPOINT`-vs-`ERROR` classification. Because `stepOnce` is private and needs a live emulator, add this as a documented integration assertion in `test_emulation.py` instead (it already runs against live Ghidra): a `run` that hits a set breakpoint reports `stopReason == "BREAKPOINT"` with `lastError == null`, while a `run` into unmapped memory reports `"ERROR"` with a non-null `lastError`.

```python
    def test_breakpoint_vs_error_classification(self):
        _json(requests.post(f"{URL}/emulation/reset", json={"start": self.entry}))
        _json(requests.post(f"{URL}/emulation/breakpoints", json={"address": self.entry}))
        run = _json(requests.post(f"{URL}/emulation/run", json={"max_steps": 10}))
        self.assertEqual("BREAKPOINT", run["result"]["stopReason"])
        self.assertIsNone(run["result"]["lastError"])
```

- [ ] **Step 4: Update the memory note** — once Step 3 lands, delete `~/.claude/.../memory/java-steponce-coverage-deferral.md` and its `MEMORY.md` line (the gap is closed).

- [ ] **Step 5: Commit**

```bash
git add CHANGELOG.md GHIDRA_HTTP_API.md GHYDRA_CLI.md README.md test_emulation.py
git commit -m "docs(pcode): document call/hooks; close stepOnce classification coverage"
```

---

## Self-Review

**Spec coverage:** Java-native architecture ✓ (Tasks 1-5); hook `mem_writes` ✓ (Task 2 model, Task 4 dispatch, Task 5 endpoint); int + bytes args ✓ (Task 4/5); no write-trace log ✓ (explicitly excluded in Global Constraints); bridge + CLI parity with `unicorn_*` ✓ (Tasks 6-7); additive versioning, no `API_VERSION` bump ✓ (Constraints, Task 5/6); `skill_todo.md` is a separate deliverable handled outside this plan.

**Type consistency:** `Hook(action, returnValue, memWrites)`, `CallArg(intValue, bytes)`, `callFunction(...)`, `EmulationCallResultDto.of(...)`, `StopReason.{DONE,HOOK_TRAP,REDIRECT_STORM}` used consistently across service, resource, and DTO. Wire arg form `{"int": ...}|{"bytes": ...}` is produced by both bridge (Task 6) and CLI (Task 7) and consumed by the resource (Task 5).

**Open verification (live-only):** `EmulatorHelper.writeMemory` to the `0x7ffff0000000`+ scratch region — gated by Task 9 Step 3 with a documented fallback.
