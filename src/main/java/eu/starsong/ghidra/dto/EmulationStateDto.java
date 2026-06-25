package eu.starsong.ghidra.dto;

import java.util.List;
import java.util.Map;

/** Wire representation of a PCode emulation session's state. */
public record EmulationStateDto(
        String pc,
        StopReason stopReason,
        long steps,
        Map<String, String> registers,
        List<String> trace,
        String lastError,
        String detail) {

    /**
     * Why an emulation session is in its current state. Serializes to its enum name
     * (e.g. {@code "BREAKPOINT"}), so the JSON wire shape is unchanged from a plain string.
     */
    public enum StopReason {
        /** Fresh session, set by {@code reset} before any execution. */
        READY,
        /** {@code step} completed (possibly fewer than requested if it stopped early). */
        STEPPED,
        /** {@code run} reached its {@code until} target address. */
        TARGET_REACHED,
        /** Execution halted at a breakpoint that was set on the session. */
        BREAKPOINT,
        /** The emulator faulted (unmapped read, unimplemented instruction, etc.); see {@code lastError}. */
        ERROR,
        /** {@code run} hit its step cap without otherwise stopping. */
        MAX_STEPS,
        /** Execution stopped due to a hook trap */
        HOOK_TRAP,
        /** Unmapped memory access */
        UNMAPPED
    }

    public static EmulationStateDto of(String pc, StopReason stopReason, long steps,
            Map<String, String> registers, List<String> trace, String lastError) {
        return new EmulationStateDto(pc, stopReason, steps, registers, trace, lastError, null);
    }

    public static EmulationStateDto of(String pc, StopReason stopReason, long steps,
            Map<String, String> registers, List<String> trace, String lastError, String detail) {
        return new EmulationStateDto(pc, stopReason, steps, registers, trace, lastError, detail);
    }
}
