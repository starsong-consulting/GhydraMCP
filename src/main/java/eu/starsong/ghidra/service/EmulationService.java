package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.EmulationStateDto;
import eu.starsong.ghidra.dto.EmulationStateDto.StopReason;
import eu.starsong.ghidra.server.GhydraServer.NotFoundException;
import eu.starsong.ghidra.util.GhidraSwing;
import eu.starsong.ghidra.util.GhidraUtil;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Drives Ghidra's PCode emulator (EmulatorHelper) for a program.
 *
 * <p>Holds one stateful {@link EmulatorHelper} session per {@link Program}, keyed in a map.
 * Sessions are freed by {@link #dispose(Program)} (an explicit {@code DELETE /emulation}),
 * by {@link #reset} replacing one, or by {@link #disposeAll()} on plugin teardown. There is
 * no automatic cleanup on program close, so callers should dispose when done.
 *
 * <p>All emulator access — and all mutation of a {@link Session}'s fields — is marshaled onto
 * the Swing/EDT thread via {@link GhidraSwing#runRead} (the emulator reads program memory,
 * which is single-threaded by Ghidra convention). That EDT serialization is what makes the
 * non-synchronized {@code Session} fields safe; do not mutate a session off the EDT.
 */
public class EmulationService {

    // -------------------------------------------------------------------------
    // Pure hex helpers (unit-tested)
    // -------------------------------------------------------------------------

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

    /**
     * Format a register value as an unsigned 0x-prefixed lowercase hex string.
     * Assumes a register width of at most 64 bits for the sign-wrap guard.
     */
    public static String toHex(BigInteger value) {
        if (value == null) return null;
        // EmulatorHelper returns unsigned magnitudes, but guard against sign anyway.
        BigInteger v = value.signum() < 0 ? value.add(BigInteger.ONE.shiftLeft(64)) : value;
        return "0x" + v.toString(16);
    }

    /**
     * Parse a register value from a hex (0x-prefixed) or decimal string.
     * A bare value is tried as decimal first, then as hex (so {@code "deadbeef"} works).
     */
    static BigInteger parseBig(String hexOrDec) {
        if (hexOrDec == null) throw new IllegalArgumentException("register value is required");
        String v = hexOrDec.trim();
        if (v.isEmpty()) throw new IllegalArgumentException("register value is required");
        if (v.startsWith("0x") || v.startsWith("0X")) return new BigInteger(v.substring(2), 16);
        try { return new BigInteger(v); }
        catch (NumberFormatException e) { return new BigInteger(v, 16); }
    }

    /** Pure function: parse little-endian 8-byte array to BigInteger */
    public static BigInteger parseReturnAddress(byte[] memoryAtRsp) {
        if (memoryAtRsp == null || memoryAtRsp.length < 8) {
            throw new IllegalArgumentException("memory array must be at least 8 bytes");
        }
        byte[] reversed = new byte[8];
        for (int i = 0; i < 8; i++) {
            reversed[7 - i] = memoryAtRsp[i];
        }
        return new BigInteger(1, reversed);
    }

    /**
     * Simulate a return instruction (x86-64).
     */
    public static void simulateRet(EmulatorHelper emu, BigInteger returnValue) {
        Register rspReg = emu.getLanguage().getRegister("RSP");
        if (rspReg == null) throw new IllegalStateException("RSP register not found");
        BigInteger rsp = emu.readRegister(rspReg);
        // We need an address space to build an address from the integer.
        // Assuming the PC is in the default RAM space.
        Address rspAddr = emu.getExecutionAddress().getNewAddress(rsp.longValue());
        byte[] retBytes = emu.readMemory(rspAddr, 8);
        if (retBytes == null || retBytes.length < 8) {
            throw new IllegalStateException("Failed to read return address from RSP " + toHex(rsp));
        }
        
        BigInteger retAddr = parseReturnAddress(retBytes);
        emu.writeRegister(emu.getPCRegister(), retAddr);
        emu.writeRegister(rspReg, rsp.add(BigInteger.valueOf(8)));
        
        if (returnValue != null) {
            Register raxReg = emu.getLanguage().getRegister("RAX");
            if (raxReg != null) {
                emu.writeRegister(raxReg, returnValue);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Session lifecycle and emulation control
    // -------------------------------------------------------------------------

    public record MemWrite(String address, String hex) {
        public MemWrite {
            if (address == null) throw new IllegalArgumentException("memory write address is required");
            if (hex == null) throw new IllegalArgumentException("memory write hex is required");
        }
    }

    private static final long MAX_STEPS_CAP = 5_000_000L;
    private static final int MAX_TRACE = 100_000;

    /** One emulator session per Program. */
    private final Map<Program, Session> sessions = new ConcurrentHashMap<>();

    public record HookAction(String action, String return_value, List<MemWrite> mem_writes) {}

    private static final class Session {
        final Program program;
        final EmulatorHelper emu;
        final List<String> trace = new ArrayList<>();
        // Breakpoint addresses we installed, so a halted step can be classified as a clean
        // breakpoint stop rather than guessed from getLastError() (which is unreliable).
        final Set<Address> breakpoints = new HashSet<>();
        final Map<Address, HookAction> hooks = new ConcurrentHashMap<>();
        long steps = 0;
        StopReason stopReason = StopReason.READY;
        String lastError = null;
        Session(Program program, EmulatorHelper emu) { 
            this.program = program; 
            this.emu = emu; 
        }
    }

    private Session require(Program program) {
        Session s = sessions.get(program);
        if (s == null) {
            throw new NotFoundException(
                "No emulation session; call /emulation/reset first", "NO_EMULATION_SESSION");
        }
        return s;
    }

    public EmulationStateDto reset(Program program, String startStr,
            Map<String, String> registers, List<MemWrite> memory, boolean autoStack) {
        Address start = GhidraUtil.resolveAddress(program, startStr);
        if (start == null) throw new IllegalArgumentException("Invalid start address: " + startStr);
        // Resolve memory addresses up front so a bad request fails before we touch any session.
        List<Map.Entry<Address, byte[]>> memWrites = new ArrayList<>();
        if (memory != null) {
            for (MemWrite mw : memory) {
                Address a = GhidraUtil.resolveAddress(program, mw.address());
                if (a == null) throw new IllegalArgumentException("Invalid memory address: " + mw.address());
                memWrites.add(Map.entry(a, hexToBytes(mw.hex())));
            }
        }
        return GhidraSwing.runRead(() -> {
            // Build and fully initialize the new emulator BEFORE installing it or disposing the
            // prior one, so a failure leaves the existing session (if any) untouched rather than
            // installing a half-configured session or leaving the program with none.
            EmulatorHelper emu = new EmulatorHelper(program);
            try {
                emu.writeRegister(emu.getPCRegister(), start.getOffsetAsBigInteger());
                if (registers != null) {
                    for (Map.Entry<String, String> e : registers.entrySet()) {
                        emu.writeRegister(e.getKey(), parseBig(e.getValue()));
                    }
                }
                for (Map.Entry<Address, byte[]> mw : memWrites) {
                    emu.writeMemory(mw.getKey(), mw.getValue());
                }
            } catch (RuntimeException e) {
                disposeQuietly(emu);
                throw e;
            }
            if (autoStack) {
                ghidra.program.model.address.AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
                long stackBase = 0x10000000L;
                long stackSize = 0x100000;
                Address stackBaseAddr = defaultSpace.getAddress(stackBase);
                byte[] zeroes = new byte[(int)stackSize];
                emu.writeMemory(stackBaseAddr, zeroes);
                BigInteger stackMid = BigInteger.valueOf(stackBase + stackSize / 2);
                Register rspReg = emu.getLanguage().getRegister("RSP");
                Register rbpReg = emu.getLanguage().getRegister("RBP");
                if (rspReg != null) emu.writeRegister(rspReg, stackMid);
                if (rbpReg != null) emu.writeRegister(rbpReg, stackMid);
            }
            Session prior = sessions.put(program, new Session(program, emu));
            if (prior != null) disposeQuietly(prior.emu);
            return snapshot(program, sessions.get(program), false);
        });
    }

    public EmulationStateDto run(Program program, String untilStr, long maxSteps, boolean trace) {
        Session s = require(program);
        long cap = Math.min(maxSteps <= 0 ? MAX_STEPS_CAP : maxSteps, MAX_STEPS_CAP);
        Address until = untilStr == null || untilStr.isEmpty()
            ? null : GhidraUtil.resolveAddress(program, untilStr);
        return GhidraSwing.runRead(() -> {
            for (long i = 0; i < cap; i++) {
                Address pc = s.emu.getExecutionAddress();
                if (until != null && pc != null && pc.equals(until)) { s.stopReason = StopReason.TARGET_REACHED; break; }
                if (trace && s.trace.size() < MAX_TRACE && pc != null) s.trace.add(pc.toString());
                if (!stepOnce(s)) break;
                if (i == cap - 1) s.stopReason = StopReason.MAX_STEPS;
            }
            return snapshot(program, s, trace);
        });
    }

    public EmulationStateDto step(Program program, long count, boolean trace) {
        Session s = require(program);
        long n = count <= 0 ? 1 : Math.min(count, MAX_STEPS_CAP);
        return GhidraSwing.runRead(() -> {
            for (long i = 0; i < n; i++) {
                Address pc = s.emu.getExecutionAddress();
                if (trace && s.trace.size() < MAX_TRACE && pc != null) s.trace.add(pc.toString());
                if (!stepOnce(s)) break;
                s.stopReason = StopReason.STEPPED;
            }
            return snapshot(program, s, trace);
        });
    }

    /**
     * Execute one instruction. Returns true to continue, false to stop. On stop, sets the
     * session's {@code stopReason}/{@code lastError}: a halt at one of our breakpoints is a
     * clean {@link StopReason#BREAKPOINT}; anything else (a false return with no breakpoint,
     * or a thrown fault) is {@link StopReason#ERROR} carrying the emulator's message — never
     * silently treated as a breakpoint.
     */
    private boolean stepOnce(Session s) {
        Address pc = s.emu.getExecutionAddress();
        if (pc != null && s.hooks.containsKey(pc)) {
            HookAction hook = s.hooks.get(pc);
            if ("return_const".equals(hook.action())) {
                if (hook.mem_writes() != null) {
                    for (MemWrite mw : hook.mem_writes()) {
                        Address a = GhidraUtil.resolveAddress(s.program, mw.address());
                        if (a != null) {
                            s.emu.writeMemory(a, hexToBytes(mw.hex()));
                        }
                    }
                }
                simulateRet(s.emu, hook.return_value() != null ? parseBig(hook.return_value()) : null);
                return true;
            } else if ("skip".equals(hook.action())) {
                ghidra.program.model.listing.Instruction inst = s.program.getListing().getInstructionAt(pc);
                if (inst != null && inst.getFlowType().isCall()) {
                    simulateRet(s.emu, null);
                } else {
                    int len = inst != null ? inst.getLength() : 1;
                    s.emu.writeRegister(s.emu.getPCRegister(), BigInteger.valueOf(pc.getOffset() + len));
                }
                return true;
            } else if ("log".equals(hook.action())) {
                s.trace.add("HOOK_LOG: " + pc.toString());
                // fall through to normal execution
            } else if ("trap".equals(hook.action())) {
                s.stopReason = StopReason.HOOK_TRAP;
                return false;
            }
        }
        
        boolean ok;
        try {
            ok = s.emu.step(TaskMonitor.DUMMY);
        } catch (Exception | LinkageError t) {
            // LowlevelError and friends are unchecked; CancelledException can't fire on DUMMY.
            s.stopReason = StopReason.ERROR;
            String msg = t.getMessage();
            s.lastError = (msg != null && !msg.isEmpty()) ? msg : t.getClass().getSimpleName();
            return false;
        }
        s.steps++;
        if (ok) return true;
        Address pc = s.emu.getExecutionAddress();
        if (pc != null && s.breakpoints.contains(pc)) {
            s.stopReason = StopReason.BREAKPOINT;
            s.lastError = null;
        } else {
            s.stopReason = StopReason.ERROR;
            String err = s.emu.getLastError();
            s.lastError = (err != null && !err.isEmpty()) ? err : "emulation halted without an error message";
        }
        return false;
    }

    public EmulationStateDto state(Program program) {
        Session s = require(program);
        return GhidraSwing.runRead(() -> snapshot(program, s, true));
    }

    public void writeRegister(Program program, String name, String hexValue) {
        Session s = require(program);
        BigInteger value = parseBig(hexValue);
        GhidraSwing.runRead(() -> {
            s.emu.writeRegister(name, value);
            return null;
        });
    }

    public String readRegister(Program program, String name) {
        Session s = require(program);
        return GhidraSwing.runRead(() -> toHex(s.emu.readRegister(name)));
    }

    public int writeMemory(Program program, String addrStr, String hex) {
        Session s = require(program);
        Address a = GhidraUtil.resolveAddress(program, addrStr);
        if (a == null) throw new IllegalArgumentException("Invalid address: " + addrStr);
        byte[] data = hexToBytes(hex);
        return GhidraSwing.runRead(() -> {
            s.emu.writeMemory(a, data);
            return data.length;
        });
    }

    /** Read up to 4096 bytes of emulated memory as a hex string (caller-requested length is clamped). */
    public String readMemory(Program program, String addrStr, int length) {
        Session s = require(program);
        if (length <= 0) throw new IllegalArgumentException("length must be positive");
        int len = Math.min(length, 4096);
        Address a = GhidraUtil.resolveAddress(program, addrStr);
        if (a == null) throw new IllegalArgumentException("Invalid address: " + addrStr);
        return GhidraSwing.runRead(() -> {
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
        GhidraSwing.runRead(() -> { s.emu.setBreakpoint(a); s.breakpoints.add(a); return null; });
    }

    public void clearBreakpoint(Program program, String addrStr) {
        Session s = require(program);
        Address a = GhidraUtil.resolveAddress(program, addrStr);
        if (a == null) throw new IllegalArgumentException("Invalid address: " + addrStr);
        GhidraSwing.runRead(() -> { s.emu.clearBreakpoint(a); s.breakpoints.remove(a); return null; });
    }

    public void setHook(Program program, String addressStr, HookAction action) {
        Session s = require(program);
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) throw new IllegalArgumentException("Invalid hook address: " + addressStr);
        s.hooks.put(address, action);
    }

    public void clearHook(Program program, String addressStr) {
        Session s = require(program);
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address != null) {
            s.hooks.remove(address);
        }
    }

    public Map<String, HookAction> listHooks(Program program) {
        Session s = require(program);
        Map<String, HookAction> res = new LinkedHashMap<>();
        s.hooks.forEach((addr, hook) -> res.put(addr.toString(), hook));
        return res;
    }

    public void dispose(Program program) {
        Session s = sessions.remove(program);
        if (s != null) GhidraSwing.runRead(() -> { disposeQuietly(s.emu); return null; });
    }

    /** Dispose every live session. Called on plugin teardown so emulators are not leaked. */
    public void disposeAll() {
        if (sessions.isEmpty()) return;
        GhidraSwing.runRead(() -> {
            for (Session s : sessions.values()) disposeQuietly(s.emu);
            sessions.clear();
            return null;
        });
    }

    private static void disposeQuietly(EmulatorHelper emu) {
        try {
            emu.dispose();
        } catch (RuntimeException e) {
            ghidra.util.Msg.warn(EmulationService.class, "EmulatorHelper.dispose() failed", e);
        }
    }

    private EmulationStateDto snapshot(Program program, Session s, boolean includeTrace) {
        Address pc = s.emu.getExecutionAddress();
        Map<String, String> regs = new LinkedHashMap<>();
        for (Register r : program.getLanguage().getRegisters()) {
            if (r.isBaseRegister() && !r.isProcessorContext()) {
                try { regs.put(r.getName(), toHex(s.emu.readRegister(r))); }
                catch (RuntimeException ignore) { /* register unreadable in this state; omit */ }
            }
        }
        // Only surface lastError when we are actually in an error state, so a stale message
        // from the emulator can't make a healthy READY/STEPPED snapshot look faulted.
        String err = s.stopReason == StopReason.ERROR ? s.lastError : null;
        return EmulationStateDto.of(
            pc != null ? pc.toString() : null,
            s.stopReason, s.steps, regs,
            includeTrace ? new ArrayList<>(s.trace) : List.of(),
            err);
    }
}
