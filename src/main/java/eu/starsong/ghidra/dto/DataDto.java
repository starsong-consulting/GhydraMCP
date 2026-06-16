package eu.starsong.ghidra.dto;

import ghidra.program.model.listing.Data;

/**
 * Data transfer object for defined data at an address.
 */
public record DataDto(
    String address,
    String label,
    String dataType,
    String value,
    int length,
    boolean isDefined,
    String comment
) {
    /**
     * Create a DataDto from Ghidra Data.
     */
    public static DataDto from(Data data) {
        if (data == null) return null;

        String label = null;
        try {
            if (data.getPrimarySymbol() != null) {
                // For an unnamed pointer this resolves the DYNAMIC name, which Ghidra
                // computes recursively and can overflow on a self-referential pointer.
                // Catch Throwable so one poisoned item degrades to a placeholder rather
                // than blowing up the whole listing scan.
                label = data.getPrimarySymbol().getName(true);
            }
        } catch (Throwable t) {
            label = "<unresolved>";
        }

        String value = null;
        try {
            Object dataValue = data.getValue();
            if (dataValue != null) {
                value = dataValue.toString();
            }
        } catch (Exception e) {
            value = "<unable to read>";
        }

        return new DataDto(
            data.getAddress().toString(),
            label,
            data.getDataType() != null ? data.getDataType().getName() : "undefined",
            value,
            data.getLength(),
            data.isDefined(),
            data.getComment(ghidra.program.model.listing.CommentType.EOL)
        );
    }
}
