package eu.starsong.ghidra.dto;

/**
 * Data transfer object for decompilation results.
 */
public record DecompileResultDto(
    String functionName,
    String functionAddress,
    String decompilation,
    boolean success,
    String errorMessage
) {
    /**
     * Create a successful decompilation result.
     */
    public static DecompileResultDto success(String functionName, String functionAddress, String decompilation) {
        return new DecompileResultDto(functionName, functionAddress, decompilation, true, null);
    }

    /**
     * Create a failed decompilation result.
     */
    public static DecompileResultDto failure(String functionName, String functionAddress, String errorMessage) {
        return new DecompileResultDto(functionName, functionAddress, null, false, errorMessage);
    }
}
