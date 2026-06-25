package eu.starsong.ghidra.dto;

import java.util.List;

/** A matched string, the functions that directly reference it, and a flat list of upstream callers. */
public record StringUsageDto(StringRef string, List<FunctionSummaryDto> directUsers, List<CallerRefDto> callers) {
    public record StringRef(String address, String value) {
    }
}
