package eu.starsong.ghidra.dto;

import java.util.List;

/** An ordered call path from one function to another. {@code length} is the node count. */
public record CallPathDto(int length, List<FunctionSummaryDto> functions) {
    public static CallPathDto of(List<FunctionSummaryDto> functions) {
        return new CallPathDto(functions.size(), List.copyOf(functions));
    }
}
