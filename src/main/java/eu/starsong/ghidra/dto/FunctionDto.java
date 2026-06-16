package eu.starsong.ghidra.dto;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;

import java.util.Arrays;
import java.util.List;

/**
 * Data transfer object for function information.
 * Full details about a function including parameters.
 */
public record FunctionDto(
    String name,
    String address,
    String signature,
    String returnType,
    String callingConvention,
    String namespace,
    boolean isExternal,
    boolean isThunk,
    List<ParameterDto> parameters,
    String comment
) {
    /**
     * Create a FunctionDto from a Ghidra Function.
     */
    public static FunctionDto from(Function fn) {
        if (fn == null) return null;

        List<ParameterDto> params = Arrays.stream(fn.getParameters())
            .map(ParameterDto::from)
            .toList();

        return new FunctionDto(
            fn.getName(),
            fn.getEntryPoint().toString(),
            fn.getSignature().getPrototypeString(),
            fn.getReturnType() != null ? fn.getReturnType().getName() : "undefined",
            fn.getCallingConventionName(),
            fn.getParentNamespace() != null ? fn.getParentNamespace().getName(true) : null,
            fn.isExternal(),
            fn.isThunk(),
            params,
            fn.getComment()
        );
    }

    /**
     * Parameter data transfer object.
     */
    public record ParameterDto(
        String name,
        String dataType,
        int ordinal,
        String storage
    ) {
        public static ParameterDto from(Parameter p) {
            if (p == null) return null;

            return new ParameterDto(
                p.getName(),
                p.getDataType() != null ? p.getDataType().getName() : "undefined",
                p.getOrdinal(),
                p.getVariableStorage() != null ? p.getVariableStorage().toString() : null
            );
        }
    }
}
