package eu.starsong.ghidra.dto;

import ghidra.program.model.data.DataTypeComponent;

public record StructFieldDto(
    String name,
    int offset,
    int length,
    String type,
    String typePath,
    String comment
) {
    public static StructFieldDto from(DataTypeComponent component) {
        if (component == null) return null;
        return new StructFieldDto(
            component.getFieldName() != null ? component.getFieldName() : "",
            component.getOffset(),
            component.getLength(),
            component.getDataType().getName(),
            component.getDataType().getPathName(),
            component.getComment() != null ? component.getComment() : ""
        );
    }
}
