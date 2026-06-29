package eu.starsong.ghidra.dto;

import java.util.List;

/**
 * An ordered call path from one function to another. {@code length} is the node count.
 *
 * <p>The compact constructor enforces the {@code length == functions.size()} invariant and
 * makes {@code functions} an immutable copy on every path (canonical constructor,
 * deserialization, and {@link #of}), so an inconsistent or mutable instance cannot exist.
 * {@code length} is retained as a stored field (not a computed accessor) because the JSON
 * mapper serializes record fields, and the wire contract exposes {@code length}.
 */
public record CallPathDto(int length, List<FunctionSummaryDto> functions) {
    public CallPathDto {
        functions = List.copyOf(functions);
        if (length != functions.size()) {
            throw new IllegalArgumentException(
                "length (" + length + ") must equal functions.size() (" + functions.size() + ")");
        }
    }

    public static CallPathDto of(List<FunctionSummaryDto> functions) {
        return new CallPathDto(functions.size(), functions);
    }
}
