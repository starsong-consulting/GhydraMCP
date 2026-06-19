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
