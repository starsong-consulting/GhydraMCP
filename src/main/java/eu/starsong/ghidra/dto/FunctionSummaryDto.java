package eu.starsong.ghidra.dto;

import ghidra.program.model.listing.Function;

/**
 * Lightweight summary of a function for list responses.
 * Does not include parameters or other heavy fields.
 */
public record FunctionSummaryDto(
    String name,
    String address,
    String signature,
    String returnType,
    boolean isExternal,
    boolean isThunk,
    int parameterCount
) {
    /**
     * Create a FunctionSummaryDto from a Ghidra Function.
     */
    public static FunctionSummaryDto from(Function fn) {
        if (fn == null) return null;

        return new FunctionSummaryDto(
            fn.getName(),
            fn.getEntryPoint().toString(),
            fn.getSignature().getPrototypeString(),
            fn.getReturnType() != null ? fn.getReturnType().getName() : "undefined",
            fn.isExternal(),
            fn.isThunk(),
            fn.getParameterCount()
        );
    }
}
