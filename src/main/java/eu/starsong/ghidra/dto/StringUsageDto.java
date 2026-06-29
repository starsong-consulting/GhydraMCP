package eu.starsong.ghidra.dto;

import java.util.List;
import java.util.Objects;

/** A matched string, the functions that directly reference it, and a flat list of upstream callers. */
public record StringUsageDto(StringRef string, List<FunctionSummaryDto> directUsers, List<CallerRefDto> callers) {
    public StringUsageDto {
        Objects.requireNonNull(string, "string");
        directUsers = List.copyOf(directUsers);
        callers = List.copyOf(callers);
    }

    /** A reference to a matched string: its address and value. */
    public record StringRef(String address, String value) {
        /** Project a {@link DataDto} (address + value) onto the wire shape. */
        public static StringRef from(DataDto data) {
            return new StringRef(data.address(), data.value());
        }
    }
}
