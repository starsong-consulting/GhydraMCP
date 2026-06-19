package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.EmulationStateDto;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Drives Ghidra's PCode emulator (EmulatorHelper) for a program.
 *
 * <p>Holds one stateful {@link EmulatorHelper} session per {@link Program}, keyed in a map.
 * All emulator access is marshaled onto the Swing/EDT thread via {@link GhidraSwing#runRead}
 * (the emulator reads program memory, which is single-threaded by Ghidra convention).
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

    /** Format a register value as an unsigned 0x-prefixed lowercase hex string. */
    public static String toHex(BigInteger value) {
        if (value == null) return null;
        // EmulatorHelper returns unsigned magnitudes, but guard against sign anyway.
        BigInteger v = value.signum() < 0 ? value.add(BigInteger.ONE.shiftLeft(64)) : value;
        return "0x" + v.toString(16);
    }

    // -------------------------------------------------------------------------
    // Session lifecycle and emulation control
    // -------------------------------------------------------------------------

    public record MemWrite(String address, String hex) {}

    private static final long MAX_STEPS_CAP = 5_000_000L;
    private static final int MAX_TRACE = 100_000;

    /** One emulator session per Program. */
    private final Map<Program, Session> sessions = new ConcurrentHashMap<>();

    private static final class Session {
        final EmulatorHelper emu;
        long steps = 0;
        final List<String> trace = new ArrayList<>();
        String stopReason = "READY";
        Session(EmulatorHelper emu) { this.emu = emu; }
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
            Map<String, String> registers, List<MemWrite> memory) {
        Address start = GhidraUtil.resolveAddress(program, startStr);
        if (start == null) throw new IllegalArgumentException("Invalid start address: " + startStr);
        return GhidraSwing.runRead(() -> {
            Session prior = sessions.remove(program);
            if (prior != null) prior.emu.dispose();
            EmulatorHelper emu = new EmulatorHelper(program);
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
        return GhidraSwing.runRead(() -> {
            for (long i = 0; i < cap; i++) {
                Address pc = s.emu.getExecutionAddress();
                if (until != null && pc != null && pc.equals(until)) { s.stopReason = "TARGET_REACHED"; break; }
                if (trace && s.trace.size() < MAX_TRACE && pc != null) s.trace.add(pc.toString());
                boolean ok = s.emu.step(TaskMonitor.DUMMY);
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
        return GhidraSwing.runRead(() -> {
            for (long i = 0; i < n; i++) {
                Address pc = s.emu.getExecutionAddress();
                if (trace && s.trace.size() < MAX_TRACE && pc != null) s.trace.add(pc.toString());
                boolean ok = s.emu.step(TaskMonitor.DUMMY);
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
        return GhidraSwing.runRead(() -> snapshot(program, s, true));
    }

    public void writeRegister(Program program, String name, String hexValue) {
        Session s = require(program);
        GhidraSwing.runRead(() -> {
            s.emu.writeRegister(name, parseBig(hexValue));
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
        GhidraSwing.runRead(() -> { s.emu.setBreakpoint(a); return null; });
    }

    public void clearBreakpoint(Program program, String addrStr) {
        Session s = require(program);
        Address a = GhidraUtil.resolveAddress(program, addrStr);
        if (a == null) throw new IllegalArgumentException("Invalid address: " + addrStr);
        GhidraSwing.runRead(() -> { s.emu.clearBreakpoint(a); return null; });
    }

    public void dispose(Program program) {
        Session s = sessions.remove(program);
        if (s != null) GhidraSwing.runRead(() -> { s.emu.dispose(); return null; });
    }

    private EmulationStateDto snapshot(Program program, Session s, boolean includeTrace) {
        Address pc = s.emu.getExecutionAddress();
        Map<String, String> regs = new LinkedHashMap<>();
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
            includeTrace ? new ArrayList<>(s.trace) : List.of(),
            (err != null && !err.isEmpty()) ? err : null);
    }

    private static BigInteger parseBig(String hexOrDec) {
        if (hexOrDec == null) throw new IllegalArgumentException("register value is required");
        String v = hexOrDec.trim();
        if (v.startsWith("0x") || v.startsWith("0X")) return new BigInteger(v.substring(2), 16);
        try { return new BigInteger(v); }
        catch (NumberFormatException e) { return new BigInteger(v, 16); }
    }
}
