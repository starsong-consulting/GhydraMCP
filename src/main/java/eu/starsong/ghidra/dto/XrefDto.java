package eu.starsong.ghidra.dto;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;

/**
 * Data transfer object for cross-reference information.
 */
public record XrefDto(
    String fromAddress,
    String toAddress,
    String refType,
    boolean isPrimary,
    String fromFunction,
    String fromFunctionAddress,
    String toFunction,
    String toFunctionAddress
) {
    /**
     * Create an XrefDto from a Ghidra Reference.
     */
    public static XrefDto from(Reference ref, Program program) {
        if (ref == null) return null;

        String fromFunc = null;
        String fromFuncAddr = null;
        String toFunc = null;
        String toFuncAddr = null;

        if (program != null) {
            Function f = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
            if (f != null) {
                fromFunc = f.getName();
                fromFuncAddr = f.getEntryPoint().toString();
            }

            f = program.getFunctionManager().getFunctionContaining(ref.getToAddress());
            if (f != null) {
                toFunc = f.getName();
                toFuncAddr = f.getEntryPoint().toString();
            }
        }

        return new XrefDto(
            ref.getFromAddress().toString(),
            ref.getToAddress().toString(),
            ref.getReferenceType().toString(),
            ref.isPrimary(),
            fromFunc,
            fromFuncAddr,
            toFunc,
            toFuncAddr
        );
    }
}
