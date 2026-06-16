package eu.starsong.ghidra.dto;

/**
 * One occurrence of a scalar (constant) value found in an instruction operand,
 * with the containing function and (optionally) the function called nearby.
 */
public record ScalarMatchDto(
    String address,
    long value,
    String hexValue,
    int bitLength,
    boolean signed,
    int operandIndex,
    String instruction,
    String inFunction,
    String inFunctionAddress,
    String toFunction,
    String toFunctionAddress
) {
    /** Render a scalar value as hex, matching the accepted search-value form. */
    public static String hex(long v) {
        return v < 0 ? "-0x" + Long.toHexString(-v) : "0x" + Long.toHexString(v);
    }
}
