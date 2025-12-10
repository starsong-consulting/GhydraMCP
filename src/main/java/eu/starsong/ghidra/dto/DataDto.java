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
        if (data.getPrimarySymbol() != null) {
            label = data.getPrimarySymbol().getName();
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
