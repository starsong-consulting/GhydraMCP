package eu.starsong.ghidra.dto;

import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

/**
 * Data transfer object for symbol information.
 */
public record SymbolDto(
    String name,
    String address,
    String type,
    String namespace,
    boolean isPrimary,
    boolean isExternal,
    boolean isGlobal,
    String source
) {
    /**
     * Create a SymbolDto from a Ghidra Symbol.
     */
    public static SymbolDto from(Symbol sym) {
        if (sym == null) return null;

        return new SymbolDto(
            sym.getName(),
            sym.getAddress().toString(),
            sym.getSymbolType().toString(),
            sym.getParentNamespace() != null ? sym.getParentNamespace().getName(true) : null,
            sym.isPrimary(),
            sym.isExternal(),
            sym.isGlobal(),
            sym.getSource() != null ? sym.getSource().toString() : null
        );
    }

    /**
     * Check if this symbol represents a function.
     */
    public boolean isFunction() {
        return "Function".equals(type);
    }

    /**
     * Check if this symbol represents a label.
     */
    public boolean isLabel() {
        return "Label".equals(type);
    }
}
