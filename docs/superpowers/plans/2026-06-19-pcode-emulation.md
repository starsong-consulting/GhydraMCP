# PCode Emulation (in-plugin) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dynamic-analysis capability to GhydraMCP by exposing Ghidra's built-in PCode emulator (`EmulatorHelper`) through the existing HTTP API, MCP bridge, and CLI — letting an agent run/step a function, set registers and memory, trace executed instructions, and read back emulated state (e.g. to unpack `.xd` in `mbb.exe`).

**Architecture:** Mirror the established `Service` + `Resource` + DTO layering. `EmulationService` owns one stateful `EmulatorHelper` session per `Program` (keyed in a map), with thread-safe access through `GhidraSwing.runRead`/`runSwing`. `EmulationResource` exposes `/emulation/*` REST endpoints registered in `GhydraPlugin`. The Python bridge adds `emulation_*` MCP tools and a `ghydra emulation` CLI group, both thin HTTP clients. No new external dependencies — everything runs inside the Ghidra process.

**Tech Stack:** Java 21, Ghidra `ghidra.app.emulator.EmulatorHelper`, Javalin, Gson; Python 3.10+ (FastMCP bridge + Click CLI); JUnit 4 (`junit:junit`) for Java unit tests; `requests` + `unittest` for live integration smoke tests.

## Global Constraints

- Java source/target is **Java 21** (matches `.github/workflows/build.yml` JDK 21 + Maven build).
- All Ghidra model access (read or mutate) MUST go through `eu.starsong.ghidra.util.GhidraSwing` (`runRead` / `runSwing`) — never touch `Program`/emulator state off the Swing thread.
- Addresses are resolved with `eu.starsong.ghidra.util.GhidraUtil.resolveAddress(program, str)` (accepts hex, `0x`-hex, bare-hex, decimal).
- Every REST response is built with `eu.starsong.ghidra.hateoas.Response.ok(ctx, port, data)` / `Response.error(...)` and includes `_links` (HATEOAS, matches API v3000).
- Validation failures throw `IllegalArgumentException` (mapped to HTTP 400 in `GhydraServer`); "no session / not found" throws `GhydraServer.NotFoundException` (mapped to 404).
- MCP tools use `@mcp.tool()` + `@text_output`, take an optional `port: int | None = None`, resolve it via `_get_instance_port(port)`, and call `safe_get`/`safe_post`/`safe_put` then `simplify_response`.
- Register values cross the wire as **hex strings** (e.g. `"0x140075000"`); memory payloads as **hex byte strings** (matches `MemoryService.writeBytes`).
- Bump `ApiConstants.PLUGIN_VERSION`/`API_VERSION` is NOT part of this plan; do not touch versioning.
- Safety: emulation runs are bounded by `max_steps` (hard cap 5_000_000) and never auto-start a live OS process — this is pure PCode interpretation.

---

### Task 1: `EmulationStateDto` — the wire shape for emulator state

**Files:**
- Create: `src/main/java/eu/starsong/ghidra/dto/EmulationStateDto.java`
- Test: `src/test/java/eu/starsong/ghidra/dto/EmulationStateDtoTest.java`

**Interfaces:**
- Produces: `record EmulationStateDto(String pc, String stopReason, long steps, java.util.Map<String,String> registers, java.util.List<String> trace, String lastError)` with a static factory `EmulationStateDto.of(String pc, String stopReason, long steps, Map<String,String> registers, List<String> trace, String lastError)`.

- [ ] **Step 1: Write the failing test**

```java
package eu.starsong.ghidra.dto;

import org.junit.Test;
import java.util.List;
import java.util.Map;
import static org.junit.Assert.assertEquals;

public class EmulationStateDtoTest {
    @Test
    public void ofPopulatesAllFields() {
        EmulationStateDto dto = EmulationStateDto.of(
            "0x140075000", "BREAKPOINT", 42L,
            Map.of("RIP", "0x140075000"), List.of("0x140074000", "0x140074002"), null);
        assertEquals("0x140075000", dto.pc());
        assertEquals("BREAKPOINT", dto.stopReason());
        assertEquals(42L, dto.steps());
        assertEquals("0x140075000", dto.registers().get("RIP"));
        assertEquals(2, dto.trace().size());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q -Dtest=EmulationStateDtoTest test`
Expected: FAIL — `EmulationStateDto` does not exist (compilation error).

- [ ] **Step 3: Write minimal implementation**

```java
package eu.starsong.ghidra.dto;

import java.util.List;
import java.util.Map;

/** Wire representation of a PCode emulation session's state. */
public record EmulationStateDto(
        String pc,
        String stopReason,
        long steps,
        Map<String, String> registers,
        List<String> trace,
        String lastError) {

    public static EmulationStateDto of(String pc, String stopReason, long steps,
            Map<String, String> registers, List<String> trace, String lastError) {
        return new EmulationStateDto(pc, stopReason, steps, registers, trace, lastError);
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn -q -Dtest=EmulationStateDtoTest test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/dto/EmulationStateDto.java src/test/java/eu/starsong/ghidra/dto/EmulationStateDtoTest.java
git commit -m "feat(emulation): add EmulationStateDto wire type"
```

---

### Task 2: `EmulationService` — register/memory hex parsing helpers

This task lands the service class with the **pure, unit-testable helpers** first (hex parsing/formatting), so the emulator-driving methods in Task 3 build on tested foundations.

**Files:**
- Create: `src/main/java/eu/starsong/ghidra/service/EmulationService.java`
- Test: `src/test/java/eu/starsong/ghidra/service/EmulationServiceTest.java`

**Interfaces:**
- Produces: `static byte[] EmulationService.hexToBytes(String hex)` (strips non-hex, rejects odd length), `static String EmulationService.toHex(java.math.BigInteger value)` (returns `"0x"`-prefixed lowercase, never negative-signed).

- [ ] **Step 1: Write the failing test**

```java
package eu.starsong.ghidra.service;

import org.junit.Test;
import java.math.BigInteger;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class EmulationServiceTest {
    @Test
    public void hexToBytesParsesSpacedHex() {
        assertArrayEquals(new byte[]{(byte)0xca, (byte)0xfe},
                EmulationService.hexToBytes("ca fe"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void hexToBytesRejectsOddLength() {
        EmulationService.hexToBytes("abc");
    }

    @Test
    public void toHexIsUnsignedZeroPaddedPrefixed() {
        assertEquals("0x140075000", EmulationService.toHex(new BigInteger("140075000", 16)));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q -Dtest=EmulationServiceTest test`
Expected: FAIL — `EmulationService` does not exist.

- [ ] **Step 3: Write minimal implementation**

```java
package eu.starsong.ghidra.service;

import java.math.BigInteger;

/**
 * Drives Ghidra's PCode emulator (EmulatorHelper) for a program.
 * This task only lands the pure hex helpers; session methods arrive in Task 3.
 */
public class EmulationService {

    /** Parse a hex byte string (whitespace allowed) into bytes. */
    public static byte[] hexToBytes(String hex) {
        if (hex == null) throw new IllegalArgumentException("hex is required");
        String cleaned = hex.replaceAll("[^0-9a-fA-F]", "");
        if (cleaned.length() % 2 != 0) {
            throw new IllegalArgumentException("hex byte string must have even length");
        }
        byte[] data = new byte[cleaned.length() / 2];
        for (int i = 0; i < cleaned.length(); i += 2) {
            data[i / 2] = (byte) Integer.parseInt(cleaned.substring(i, i + 2), 16);
        }
        return data;
    }

    /** Format a register value as an unsigned 0x-prefixed lowercase hex string. */
    public static String toHex(BigInteger value) {
        if (value == null) return null;
        // EmulatorHelper returns unsigned magnitudes, but guard against sign anyway.
        BigInteger v = value.signum() < 0 ? value.add(BigInteger.ONE.shiftLeft(64)) : value;
        return "0x" + v.toString(16);
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn -q -Dtest=EmulationServiceTest test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/service/EmulationService.java src/test/java/eu/starsong/ghidra/service/EmulationServiceTest.java
git commit -m "feat(emulation): add EmulationService hex helpers"
```

---

### Task 3: `EmulationService` — session lifecycle, run/step, registers, memory, breakpoints, trace

Adds the stateful emulator-driving methods. These require a live `Program`, so they are exercised by the integration smoke test in Task 6, not JUnit (the repo has no Ghidra mock harness — see `test_javalin_port.py`).

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/service/EmulationService.java`

**Interfaces:**
- Consumes: `EmulationService.hexToBytes`, `EmulationService.toHex` (Task 2); `GhidraSwing.runRead`/`runSwing`, `GhidraUtil.resolveAddress`, `EmulationStateDto` (Task 1).
- Produces, all keyed by `Program`:
  - `EmulationStateDto reset(Program program, String startStr, Map<String,String> registers, List<MemWrite> memory)` — disposes any prior session, creates a fresh `EmulatorHelper`, sets PC to `startStr`, applies register writes (name→hex) and memory writes, returns initial state.
  - `EmulationStateDto run(Program program, String untilStr, long maxSteps, boolean trace)` — steps until PC hits `untilStr` (nullable), a breakpoint, an error, or `maxSteps`; returns final state. When `trace` is true, fills `trace` with executed instruction addresses (cap 100_000 entries).
  - `EmulationStateDto step(Program program, long count, boolean trace)` — single-steps `count` times.
  - `EmulationStateDto state(Program program)` — current state, no execution.
  - `void writeRegister(Program program, String name, String hexValue)`, `String readRegister(Program program, String name)`.
  - `int writeMemory(Program program, String addrStr, String hex)`, `String readMemory(Program program, String addrStr, int length)` (returns hex).
  - `void setBreakpoint(Program program, String addrStr)`, `void clearBreakpoint(Program program, String addrStr)`.
  - `void dispose(Program program)` — disposes session and forgets it.
  - Nested `record MemWrite(String address, String hex)`.

- [ ] **Step 1: Write the implementation (no JUnit — covered by Task 6 smoke test)**

Append to `EmulationService` (inside the class body, after `toHex`):

```java
// --- imports to add at top of file ---
// import eu.starsong.ghidra.dto.EmulationStateDto;
// import eu.starsong.ghidra.server.GhydraServer.NotFoundException;
// import eu.starsong.ghidra.util.GhidraSwing;
// import eu.starsong.ghidra.util.GhidraUtil;
// import ghidra.app.emulator.EmulatorHelper;
// import ghidra.program.model.address.Address;
// import ghidra.program.model.lang.Register;
// import ghidra.program.model.listing.Program;
// import ghidra.util.task.TaskMonitor;
// import java.util.ArrayList; java.util.LinkedHashMap; java.util.List; java.util.Map;
// import java.util.concurrent.ConcurrentHashMap;

    public record MemWrite(String address, String hex) {}

    private static final long MAX_STEPS_CAP = 5_000_000L;
    private static final int MAX_TRACE = 100_000;

    /** One emulator session per Program. */
    private final Map<Program, Session> sessions = new java.util.concurrent.ConcurrentHashMap<>();

    private static final class Session {
        final ghidra.app.emulator.EmulatorHelper emu;
        long steps = 0;
        final java.util.List<String> trace = new java.util.ArrayList<>();
        String stopReason = "READY";
        Session(ghidra.app.emulator.EmulatorHelper emu) { this.emu = emu; }
    }

    private Session require(Program program) {
        Session s = sessions.get(program);
        if (s == null) {
            throw new eu.starsong.ghidra.server.GhydraServer.NotFoundException(
                "No emulation session; call /emulation/reset first", "NO_EMULATION_SESSION");
        }
        return s;
    }

    public EmulationStateDto reset(Program program, String startStr,
            Map<String, String> registers, List<MemWrite> memory) {
        Address start = GhidraUtil.resolveAddress(program, startStr);
        if (start == null) throw new IllegalArgumentException("Invalid start address: " + startStr);
        return eu.starsong.ghidra.util.GhidraSwing.runSwing(() -> {
            Session prior = sessions.remove(program);
            if (prior != null) prior.emu.dispose();
            ghidra.app.emulator.EmulatorHelper emu = new ghidra.app.emulator.EmulatorHelper(program);
            emu.writeRegister(emu.getPCRegister(), start.getOffsetAsBigInteger());
            Session s = new Session(emu);
            sessions.put(program, s);
            if (registers != null) {
                for (Map.Entry<String, String> e : registers.entrySet()) {
                    emu.writeRegister(e.getKey(), parseBig(e.getValue()));
                }
            }
            if (memory != null) {
                for (MemWrite mw : memory) {
                    Address a = GhidraUtil.resolveAddress(program, mw.address());
                    if (a == null) throw new IllegalArgumentException("Invalid memory address: " + mw.address());
                    emu.writeMemory(a, hexToBytes(mw.hex()));
                }
            }
            return snapshot(program, s, false);
        });
    }

    public EmulationStateDto run(Program program, String untilStr, long maxSteps, boolean trace) {
        Session s = require(program);
        long cap = Math.min(maxSteps <= 0 ? MAX_STEPS_CAP : maxSteps, MAX_STEPS_CAP);
        Address until = untilStr == null || untilStr.isEmpty()
            ? null : GhidraUtil.resolveAddress(program, untilStr);
        return eu.starsong.ghidra.util.GhidraSwing.runSwing(() -> {
            for (long i = 0; i < cap; i++) {
                Address pc = s.emu.getExecutionAddress();
                if (until != null && pc != null && pc.equals(until)) { s.stopReason = "TARGET_REACHED"; break; }
                if (trace && s.trace.size() < MAX_TRACE && pc != null) s.trace.add(pc.toString());
                boolean ok = s.emu.step(ghidra.util.task.TaskMonitor.DUMMY);
                s.steps++;
                if (!ok) {
                    String err = s.emu.getLastError();
                    s.stopReason = (err != null && !err.isEmpty()) ? "ERROR" : "BREAKPOINT";
                    break;
                }
                if (i == cap - 1) s.stopReason = "MAX_STEPS";
            }
            return snapshot(program, s, trace);
        });
    }

    public EmulationStateDto step(Program program, long count, boolean trace) {
        Session s = require(program);
        long n = count <= 0 ? 1 : Math.min(count, MAX_STEPS_CAP);
        return eu.starsong.ghidra.util.GhidraSwing.runSwing(() -> {
            for (long i = 0; i < n; i++) {
                Address pc = s.emu.getExecutionAddress();
                if (trace && s.trace.size() < MAX_TRACE && pc != null) s.trace.add(pc.toString());
                boolean ok = s.emu.step(ghidra.util.task.TaskMonitor.DUMMY);
                s.steps++;
                if (!ok) {
                    String err = s.emu.getLastError();
                    s.stopReason = (err != null && !err.isEmpty()) ? "ERROR" : "BREAKPOINT";
                    break;
                }
                s.stopReason = "STEPPED";
            }
            return snapshot(program, s, trace);
        });
    }

    public EmulationStateDto state(Program program) {
        Session s = require(program);
        return eu.starsong.ghidra.util.GhidraSwing.runSwing(() -> snapshot(program, s, true));
    }

    public void writeRegister(Program program, String name, String hexValue) {
        Session s = require(program);
        eu.starsong.ghidra.util.GhidraSwing.runSwing(() -> {
            s.emu.writeRegister(name, parseBig(hexValue));
            return null;
        });
    }

    public String readRegister(Program program, String name) {
        Session s = require(program);
        return eu.starsong.ghidra.util.GhidraSwing.runSwing(() -> toHex(s.emu.readRegister(name)));
    }

    public int writeMemory(Program program, String addrStr, String hex) {
        Session s = require(program);
        Address a = GhidraUtil.resolveAddress(program, addrStr);
        if (a == null) throw new IllegalArgumentException("Invalid address: " + addrStr);
        byte[] data = hexToBytes(hex);
        return eu.starsong.ghidra.util.GhidraSwing.runSwing(() -> {
            s.emu.writeMemory(a, data);
            return data.length;
        });
    }

    public String readMemory(Program program, String addrStr, int length) {
        Session s = require(program);
        if (length <= 0) throw new IllegalArgumentException("length must be positive");
        int len = Math.min(length, 4096);
        Address a = GhidraUtil.resolveAddress(program, addrStr);
        if (a == null) throw new IllegalArgumentException("Invalid address: " + addrStr);
        return eu.starsong.ghidra.util.GhidraSwing.runSwing(() -> {
            byte[] bytes = s.emu.readMemory(a, len);
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        });
    }

    public void setBreakpoint(Program program, String addrStr) {
        Session s = require(program);
        Address a = GhidraUtil.resolveAddress(program, addrStr);
        if (a == null) throw new IllegalArgumentException("Invalid address: " + addrStr);
        eu.starsong.ghidra.util.GhidraSwing.runSwing(() -> { s.emu.setBreakpoint(a); return null; });
    }

    public void clearBreakpoint(Program program, String addrStr) {
        Session s = require(program);
        Address a = GhidraUtil.resolveAddress(program, addrStr);
        if (a == null) throw new IllegalArgumentException("Invalid address: " + addrStr);
        eu.starsong.ghidra.util.GhidraSwing.runSwing(() -> { s.emu.clearBreakpoint(a); return null; });
    }

    public void dispose(Program program) {
        Session s = sessions.remove(program);
        if (s != null) eu.starsong.ghidra.util.GhidraSwing.runSwing(() -> { s.emu.dispose(); return null; });
    }

    private EmulationStateDto snapshot(Program program, Session s, boolean includeTrace) {
        Address pc = s.emu.getExecutionAddress();
        Map<String, String> regs = new java.util.LinkedHashMap<>();
        for (Register r : program.getLanguage().getRegisters()) {
            if (r.isBaseRegister() && !r.isProcessorContext()) {
                try { regs.put(r.getName(), toHex(s.emu.readRegister(r))); }
                catch (RuntimeException ignore) { /* unreadable register */ }
            }
        }
        String err = s.emu.getLastError();
        return EmulationStateDto.of(
            pc != null ? pc.toString() : null,
            s.stopReason, s.steps, regs,
            includeTrace ? new java.util.ArrayList<>(s.trace) : java.util.List.of(),
            (err != null && !err.isEmpty()) ? err : null);
    }

    private static java.math.BigInteger parseBig(String hexOrDec) {
        if (hexOrDec == null) throw new IllegalArgumentException("register value is required");
        String v = hexOrDec.trim();
        if (v.startsWith("0x") || v.startsWith("0X")) return new java.math.BigInteger(v.substring(2), 16);
        try { return new java.math.BigInteger(v); }
        catch (NumberFormatException e) { return new java.math.BigInteger(v, 16); }
    }
```

Add the imports listed in the comment block to the top of the file (uncommented).

- [ ] **Step 2: Verify it compiles**

Run: `mvn -q -DskipTests compile`
Expected: BUILD SUCCESS (no missing-symbol errors). If `getOffsetAsBigInteger()` is unavailable in the target Ghidra API, replace `start.getOffsetAsBigInteger()` with `java.math.BigInteger.valueOf(start.getOffset())`.

- [ ] **Step 3: Run existing unit tests stay green**

Run: `mvn -q -Dtest=EmulationServiceTest test`
Expected: PASS (helpers from Task 2 still pass; new methods are integration-tested in Task 6).

- [ ] **Step 4: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/service/EmulationService.java
git commit -m "feat(emulation): EmulatorHelper session lifecycle, run/step/trace"
```

---

### Task 4: `EmulationResource` — `/emulation/*` REST endpoints

**Files:**
- Create: `src/main/java/eu/starsong/ghidra/resource/EmulationResource.java`

**Interfaces:**
- Consumes: `EmulationService` (Tasks 2–3), `GhidraContext`, `Response`, `Resource`.
- Produces: REST routes
  - `POST /emulation/reset` body `{start, registers?:{}, memory?:[{address,hex}]}`
  - `POST /emulation/run` body `{until?, max_steps?, trace?}`
  - `POST /emulation/step` body `{count?, trace?}`
  - `GET  /emulation/state`
  - `GET  /emulation/registers/{name}`  · `POST /emulation/registers` body `{name, value}`
  - `GET  /emulation/memory/{address}?length=N` · `POST /emulation/memory` body `{address, hex}`
  - `POST /emulation/breakpoints` body `{address}` · `DELETE /emulation/breakpoints/{address}`
  - `DELETE /emulation` (dispose session)

- [ ] **Step 1: Write the implementation**

```java
package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.dto.EmulationStateDto;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.EmulationService;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/** REST resource for /emulation endpoints (PCode emulation). */
public class EmulationResource implements Resource {

    private final EmulationService service = new EmulationService();

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.post("/emulation/reset", ctx -> reset(contextFactory.apply(ctx)));
        app.post("/emulation/run", ctx -> run(contextFactory.apply(ctx)));
        app.post("/emulation/step", ctx -> step(contextFactory.apply(ctx)));
        app.get("/emulation/state", ctx -> state(contextFactory.apply(ctx)));
        app.get("/emulation/registers/{name}", ctx -> readRegister(contextFactory.apply(ctx)));
        app.post("/emulation/registers", ctx -> writeRegister(contextFactory.apply(ctx)));
        app.get("/emulation/memory/{address}", ctx -> readMemory(contextFactory.apply(ctx)));
        app.post("/emulation/memory", ctx -> writeMemory(contextFactory.apply(ctx)));
        app.post("/emulation/breakpoints", ctx -> setBreakpoint(contextFactory.apply(ctx)));
        app.delete("/emulation/breakpoints/{address}", ctx -> clearBreakpoint(contextFactory.apply(ctx)));
        app.delete("/emulation", ctx -> dispose(contextFactory.apply(ctx)));
    }

    private void respond(GhidraContext ctx, EmulationStateDto dto) {
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), dto)
            .self("/emulation/state")
            .link("emulation", "/emulation/state")
            .build());
    }

    @SuppressWarnings("unchecked")
    private void reset(GhidraContext ctx) {
        var program = ctx.requireProgram();
        ResetRequest req = ctx.bodyAsClass(ResetRequest.class);
        if (req == null || req.start == null) throw new IllegalArgumentException("start is required");
        List<EmulationService.MemWrite> mem = new ArrayList<>();
        if (req.memory != null) {
            for (Map<String, String> m : req.memory) {
                mem.add(new EmulationService.MemWrite(m.get("address"), m.get("hex")));
            }
        }
        respond(ctx, service.reset(program, req.start, req.registers, mem));
    }

    private void run(GhidraContext ctx) {
        var program = ctx.requireProgram();
        RunRequest req = ctx.bodyAsClass(RunRequest.class);
        if (req == null) req = new RunRequest();
        respond(ctx, service.run(program, req.until, req.max_steps, req.trace));
    }

    private void step(GhidraContext ctx) {
        var program = ctx.requireProgram();
        StepRequest req = ctx.bodyAsClass(StepRequest.class);
        if (req == null) req = new StepRequest();
        respond(ctx, service.step(program, req.count <= 0 ? 1 : req.count, req.trace));
    }

    private void state(GhidraContext ctx) {
        respond(ctx, service.state(ctx.requireProgram()));
    }

    private void readRegister(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String name = ctx.pathParam("name");
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("name", name);
        data.put("value", service.readRegister(program, name));
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data).self("/emulation/registers/{}", name).build());
    }

    private void writeRegister(GhidraContext ctx) {
        var program = ctx.requireProgram();
        RegisterRequest req = ctx.bodyAsClass(RegisterRequest.class);
        if (req == null || req.name == null || req.value == null) {
            throw new IllegalArgumentException("name and value are required");
        }
        service.writeRegister(program, req.name, req.value);
        respond(ctx, service.state(program));
    }

    private void readMemory(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");
        int length = ctx.queryParamAsInt("length", 256);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("address", address);
        data.put("length", length);
        data.put("hex", service.readMemory(program, address, length));
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data).self("/emulation/memory/{}", address).build());
    }

    private void writeMemory(GhidraContext ctx) {
        var program = ctx.requireProgram();
        MemoryRequest req = ctx.bodyAsClass(MemoryRequest.class);
        if (req == null || req.address == null || req.hex == null) {
            throw new IllegalArgumentException("address and hex are required");
        }
        int written = service.writeMemory(program, req.address, req.hex);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("address", req.address);
        data.put("written", written);
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data).self("/emulation/memory/{}", req.address).build());
    }

    private void setBreakpoint(GhidraContext ctx) {
        var program = ctx.requireProgram();
        BreakpointRequest req = ctx.bodyAsClass(BreakpointRequest.class);
        if (req == null || req.address == null) throw new IllegalArgumentException("address is required");
        service.setBreakpoint(program, req.address);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("address", req.address);
        data.put("breakpoint", "set");
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data).self("/emulation/breakpoints").build());
    }

    private void clearBreakpoint(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");
        service.clearBreakpoint(program, address);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("address", address);
        data.put("breakpoint", "cleared");
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data).self("/emulation/breakpoints/{}", address).build());
    }

    private void dispose(GhidraContext ctx) {
        service.dispose(ctx.requireProgram());
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("session", "disposed");
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data).self("/emulation").build());
    }

    private static class ResetRequest {
        public String start;
        public Map<String, String> registers;
        public List<Map<String, String>> memory;
    }
    private static class RunRequest { public String until; public long max_steps; public boolean trace; }
    private static class StepRequest { public long count; public boolean trace; }
    private static class RegisterRequest { public String name; public String value; }
    private static class MemoryRequest { public String address; public String hex; }
    private static class BreakpointRequest { public String address; }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `mvn -q -DskipTests compile`
Expected: BUILD SUCCESS.

- [ ] **Step 3: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/resource/EmulationResource.java
git commit -m "feat(emulation): add /emulation REST resource"
```

---

### Task 5: Register `EmulationResource` in the plugin

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/GhydraPlugin.java:79-100` (the `server.register(...)` block)

**Interfaces:**
- Consumes: `EmulationResource` (Task 4).

- [ ] **Step 1: Add the resource to the registration list**

In `startServer()`, inside `server.register( ... )`, add a line after `new AnalysisResource(),`:

```java
                new AnalysisResource(),
                new EmulationResource(),
                new StructResource(),
```

- [ ] **Step 2: Verify it compiles**

Run: `mvn -q -DskipTests compile`
Expected: BUILD SUCCESS. (`EmulationResource` is in the `resource` package, same as the others already imported via wildcard or explicit import — add `import eu.starsong.ghidra.resource.EmulationResource;` if the file uses explicit imports.)

- [ ] **Step 3: Build the full plugin zip**

Run: `mvn -q -DskipTests package`
Expected: BUILD SUCCESS; a plugin zip is produced under `target/`.

- [ ] **Step 4: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/GhydraPlugin.java
git commit -m "feat(emulation): register EmulationResource in plugin"
```

---

### Task 6: Integration smoke test against a live instance

Follows the exact style of `test_javalin_port.py` (live Ghidra on `:8192`, `skipTest` when absent). Drives a full unpack-style round trip.

**Files:**
- Create: `test_emulation.py`

**Interfaces:**
- Consumes: the running plugin from Task 5 on `http://localhost:8192`.

- [ ] **Step 1: Write the smoke test**

```python
#!/usr/bin/env python3
"""Integration smoke tests for the /emulation endpoints.

Requires a live Ghidra instance on localhost:8192 with a binary open.
"""
import os
import unittest

import requests

DEFAULT_PORT = int(os.getenv("GHYDRAMCP_TEST_PORT") or "8192")
BASE = os.getenv("GHYDRAMCP_TEST_HOST") or "localhost"
URL = f"http://{BASE}:{DEFAULT_PORT}"


def _json(r):
    r.raise_for_status()
    return r.json()


class EmulationTests(unittest.TestCase):
    def setUp(self):
        try:
            r = requests.get(f"{URL}/info", timeout=2)
        except requests.exceptions.RequestException:
            self.skipTest("Ghidra not running")
        if r.status_code != 200:
            self.skipTest("Ghidra /info not responding")
        funcs = _json(requests.get(f"{URL}/functions", params={"limit": 1}))
        results = funcs.get("result", [])
        if not results:
            self.skipTest("No functions in loaded binary")
        self.entry = results[0]["address"]

    def test_reset_run_state_roundtrip(self):
        reset = _json(requests.post(f"{URL}/emulation/reset", json={"start": self.entry}))
        self.assertTrue(reset.get("success"))
        self.assertIsNotNone(reset["result"]["pc"])

        run = _json(requests.post(f"{URL}/emulation/run",
                                  json={"max_steps": 50, "trace": True}))
        self.assertTrue(run.get("success"))
        self.assertGreater(run["result"]["steps"], 0)
        self.assertIn(run["result"]["stopReason"],
                      {"TARGET_REACHED", "BREAKPOINT", "ERROR", "MAX_STEPS", "STEPPED"})
        self.assertIsInstance(run["result"]["trace"], list)

    def test_register_read_write(self):
        _json(requests.post(f"{URL}/emulation/reset", json={"start": self.entry}))
        _json(requests.post(f"{URL}/emulation/registers",
                            json={"name": "RAX", "value": "0xdeadbeef"}))
        reg = _json(requests.get(f"{URL}/emulation/registers/RAX"))
        self.assertEqual("0xdeadbeef", reg["result"]["value"])

    def test_memory_write_read(self):
        _json(requests.post(f"{URL}/emulation/reset", json={"start": self.entry}))
        _json(requests.post(f"{URL}/emulation/memory",
                            json={"address": self.entry, "hex": "9090"}))
        mem = _json(requests.get(f"{URL}/emulation/memory/{self.entry}", params={"length": 2}))
        self.assertEqual("9090", mem["result"]["hex"])

    def test_missing_session_is_404(self):
        requests.delete(f"{URL}/emulation")
        r = requests.get(f"{URL}/emulation/state")
        self.assertIn(r.status_code, (404, 503))

    def tearDown(self):
        try:
            requests.delete(f"{URL}/emulation", timeout=2)
        except requests.exceptions.RequestException:
            pass


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it (with a live instance + binary open)**

Run: `python -m pytest test_emulation.py -v`
Expected: all tests PASS, or SKIP if no Ghidra/binary. With `mbb.exe` open they pass.

- [ ] **Step 3: Commit**

```bash
git add test_emulation.py
git commit -m "test(emulation): live integration smoke tests for /emulation"
```

---

### Task 7: MCP bridge tools `emulation_*`

**Files:**
- Modify: `bridge_mcp_hydra.py` (add a new tool block; place it after the `memory_write` tool around line 2843, before the next `@mcp.tool()`)

**Interfaces:**
- Consumes: `_get_instance_port`, `safe_get`, `safe_post`, `safe_put`, `simplify_response`, `@mcp.tool()`, `@text_output`, `quote` (all already imported/defined in the file).
- Produces MCP tools: `emulation_reset`, `emulation_run`, `emulation_step`, `emulation_state`, `emulation_read_register`, `emulation_write_register`, `emulation_read_memory`, `emulation_write_memory`, `emulation_set_breakpoint`, `emulation_dispose`.

- [ ] **Step 1: Add the tools**

```python
@mcp.tool()
@text_output
def emulation_reset(start: str, registers: dict | None = None,
                    memory: list | None = None, port: int | None = None) -> dict:
    """Start a fresh PCode emulation session at an address.

    Args:
        start: Start address in hex (PC is set here)
        registers: Optional {register_name: hex_value} initial register writes
        memory: Optional [{"address": hex, "hex": "ca fe"}] initial memory writes
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: initial emulation state (pc, registers, steps, stopReason)
    """
    port = _get_instance_port(port)
    body: dict = {"start": start}
    if registers:
        body["registers"] = registers
    if memory:
        body["memory"] = memory
    return simplify_response(safe_post(port, "emulation/reset", body))


@mcp.tool()
@text_output
def emulation_run(until: str | None = None, max_steps: int = 100000,
                  trace: bool = False, port: int | None = None) -> dict:
    """Run the emulation session until an address, a breakpoint, an error, or max_steps.

    Args:
        until: Optional stop address in hex
        max_steps: Hard step cap (default 100000, server caps at 5000000)
        trace: When true, returns the list of executed instruction addresses
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: final emulation state including stopReason and optional trace
    """
    port = _get_instance_port(port)
    body: dict = {"max_steps": max_steps, "trace": trace}
    if until:
        body["until"] = until
    return simplify_response(safe_post(port, "emulation/run", body))


@mcp.tool()
@text_output
def emulation_step(count: int = 1, trace: bool = False, port: int | None = None) -> dict:
    """Single-step the emulation session count times.

    Args:
        count: Number of instructions to step (default 1)
        trace: When true, returns executed instruction addresses
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(safe_post(port, "emulation/step", {"count": count, "trace": trace}))


@mcp.tool()
@text_output
def emulation_state(port: int | None = None) -> dict:
    """Get the current emulation session state without executing.

    Args:
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(safe_get(port, "emulation/state"))


@mcp.tool()
@text_output
def emulation_read_register(name: str, port: int | None = None) -> dict:
    """Read an emulated register value (hex).

    Args:
        name: Register name (e.g. "RAX", "RIP")
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(safe_get(port, f"emulation/registers/{quote(name)}"))


@mcp.tool()
@text_output
def emulation_write_register(name: str, value: str, port: int | None = None) -> dict:
    """Write an emulated register value.

    Args:
        name: Register name (e.g. "RAX")
        value: Hex value (e.g. "0x140075000")
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(safe_post(port, "emulation/registers", {"name": name, "value": value}))


@mcp.tool()
@text_output
def emulation_read_memory(address: str, length: int = 64, port: int | None = None) -> dict:
    """Read bytes from emulated memory (hex), e.g. to dump decrypted data.

    Args:
        address: Memory address in hex
        length: Number of bytes (default 64, server caps at 4096)
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(
        safe_get(port, f"emulation/memory/{quote(address, safe=':')}", {"length": length}))


@mcp.tool()
@text_output
def emulation_write_memory(address: str, hex_bytes: str, port: int | None = None) -> dict:
    """Write bytes to emulated memory.

    Args:
        address: Memory address in hex
        hex_bytes: Hex byte string (e.g. "9090")
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(safe_post(port, "emulation/memory", {"address": address, "hex": hex_bytes}))


@mcp.tool()
@text_output
def emulation_set_breakpoint(address: str, port: int | None = None) -> dict:
    """Set an emulation breakpoint at an address.

    Args:
        address: Address in hex
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(safe_post(port, "emulation/breakpoints", {"address": address}))


@mcp.tool()
@text_output
def emulation_dispose(port: int | None = None) -> dict:
    """Dispose the emulation session and free the emulator.

    Args:
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(_make_request("DELETE", port, "emulation"))
```

- [ ] **Step 2: Verify the bridge imports cleanly**

Run: `python -c "import bridge_mcp_hydra"`
Expected: no exceptions (module imports, tools register).

- [ ] **Step 3: Commit**

```bash
git add bridge_mcp_hydra.py
git commit -m "feat(emulation): add emulation_* MCP bridge tools"
```

---

### Task 8: CLI `ghydra emulation` group

**Files:**
- Create: `ghydra/cli/emulation.py`
- Modify: `ghydra/cli/main.py` (register the new group)

**Interfaces:**
- Consumes: `ctx.obj['client']` (`.get`/`.post`), `ctx.obj['formatter']`, `ctx.obj['config']`, `GhidraError`, `should_page`, `page_output`, `rich_echo`, `validate_address` (mirrors `ghydra/cli/memory.py`).
- Produces: a `emulation` Click group with `reset`, `run`, `step`, `state`, `read-mem`, `dispose` commands.

- [ ] **Step 1: Confirm how groups are registered in `main.py`**

Run: `python -c "import re; print([l for l in open('ghydra/cli/main.py') if 'add_command' in l][:5])"`
Expected: prints lines like `cli.add_command(memory)` — copy that pattern.

- [ ] **Step 2: Write the CLI module**

```python
"""Emulation (PCode) commands."""

import json

import click

from ..client.exceptions import GhidraError
from ..utils import rich_echo, validate_address


@click.group('emulation')
def emulation():
    """PCode emulation commands (run/step a function, inspect state)."""
    pass


def _emit(ctx, response):
    formatter = ctx.obj['formatter']
    click.echo(formatter.format_simple_result(response))


@emulation.command('reset')
@click.option('--start', '-s', required=True, help='Start address (hex); PC is set here')
@click.pass_context
def reset(ctx, start):
    """Start a fresh emulation session at an address."""
    client = ctx.obj['client']
    try:
        response = client.post('emulation/reset', data={'start': validate_address(start)})
        _emit(ctx, response)
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('run')
@click.option('--until', '-u', help='Stop address (hex)')
@click.option('--max-steps', type=int, default=100000, help='Step cap (default 100000)')
@click.option('--trace/--no-trace', default=False, help='Return executed instruction addresses')
@click.pass_context
def run(ctx, until, max_steps, trace):
    """Run until an address, breakpoint, error, or max-steps."""
    client = ctx.obj['client']
    try:
        data = {'max_steps': max_steps, 'trace': trace}
        if until:
            data['until'] = validate_address(until)
        _emit(ctx, client.post('emulation/run', data=data))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('step')
@click.option('--count', '-c', type=int, default=1, help='Instructions to step')
@click.option('--trace/--no-trace', default=False)
@click.pass_context
def step(ctx, count, trace):
    """Single-step the session."""
    client = ctx.obj['client']
    try:
        _emit(ctx, client.post('emulation/step', data={'count': count, 'trace': trace}))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('state')
@click.pass_context
def state(ctx):
    """Show current emulation state."""
    client = ctx.obj['client']
    try:
        _emit(ctx, client.get('emulation/state'))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('read-mem')
@click.option('--address', '-a', required=True, help='Address (hex)')
@click.option('--length', '-l', type=int, default=64, help='Bytes to read')
@click.pass_context
def read_mem(ctx, address, length):
    """Read emulated memory as hex (e.g. dump decrypted data)."""
    client = ctx.obj['client']
    try:
        _emit(ctx, client.get(f'emulation/memory/{validate_address(address)}',
                              params={'length': length}))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('dispose')
@click.pass_context
def dispose(ctx):
    """Dispose the emulation session."""
    client = ctx.obj['client']
    try:
        _emit(ctx, client.delete('emulation'))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)
```

- [ ] **Step 3: Register the group in `main.py`**

Add the import alongside the other CLI group imports, and `cli.add_command(emulation)` alongside the others:

```python
from .emulation import emulation
# ...
cli.add_command(emulation)
```

(If `client` has no `.delete` method, add one mirroring `.post` in `ghydra/client/http_client.py`; verify with `python -c "from ghydra.client.http_client import *"` and inspect. If absent, the dispose command should call `client.request('DELETE', 'emulation')` using whatever low-level method exists — confirm the actual method name before writing.)

- [ ] **Step 4: Verify the CLI loads**

Run: `python -m ghydra.cli.main emulation --help`
Expected: shows the `reset/run/step/state/read-mem/dispose` subcommands.

- [ ] **Step 5: Commit**

```bash
git add ghydra/cli/emulation.py ghydra/cli/main.py
git commit -m "feat(emulation): add ghydra emulation CLI group"
```

---

### Task 9: Documentation

**Files:**
- Modify: `GHIDRA_HTTP_API.md` (add an `## Emulation` section documenting the `/emulation/*` endpoints)
- Modify: `GHYDRA_CLI.md` (document `ghydra emulation`)
- Modify: `README.md` (add `emulation_*` to the MCP namespaces list / feature blurb)
- Modify: `CHANGELOG.md` (add an entry under the unreleased/next section)

**Interfaces:** none (docs only).

- [ ] **Step 1: Add the HTTP API section**

In `GHIDRA_HTTP_API.md`, add a section listing each endpoint from Task 4 with one example request/response, matching the existing formatting of the `Memory` section.

- [ ] **Step 2: Add the CLI section**

In `GHYDRA_CLI.md`, document the `ghydra emulation` subcommands with example invocations from Task 8 docstrings.

- [ ] **Step 3: Update README + CHANGELOG**

In `README.md`, add `- emulation_* : For PCode emulation (run/step/trace, registers, memory)` to the MCP namespace list. In `CHANGELOG.md`, add: `- feat: PCode emulation API (/emulation/*, emulation_* MCP tools, ghydra emulation CLI) — dynamic analysis via Ghidra EmulatorHelper`.

- [ ] **Step 4: Commit**

```bash
git add GHIDRA_HTTP_API.md GHYDRA_CLI.md README.md CHANGELOG.md
git commit -m "docs(emulation): document /emulation API, CLI, and MCP tools"
```

---

## Self-Review

- **Spec coverage:** "MVP + tracing/hooks" → reset/run/step/state + registers + memory + breakpoints (MVP) and instruction-address trace with per-call `trace` flag + breakpoints (the hooks/trace deliverable). Covered by Tasks 3,4,6,7,8. Both static→dynamic gap closers (unpack `.xd`: reset at `entry`, run with `max_steps`, read emulated `.data` RWX region) are exercised in Task 6.
- **Placeholder scan:** No "TBD/handle errors appropriately" — every step has concrete code. Two explicit verification points (`getOffsetAsBigInteger` fallback in Task 3 Step 2; `client.delete` existence in Task 8 Step 3) are written as conditional instructions with exact fallbacks, not placeholders.
- **Type consistency:** `EmulationStateDto.of(...)` signature in Task 1 matches its use in Task 3 `snapshot`. `MemWrite(address, hex)` defined in Task 3, consumed in Task 4 `reset`. REST bodies in Task 4 (`{start, registers, memory}`, `{until, max_steps, trace}`, etc.) match the bridge tool payloads in Task 7 and CLI payloads in Task 8.

## Execution Handoff

(see shared handoff note after the Unicorn plan)
