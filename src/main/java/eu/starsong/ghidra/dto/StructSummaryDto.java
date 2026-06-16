package eu.starsong.ghidra.dto;

import ghidra.program.model.data.Structure;

public record StructSummaryDto(
    String name,
    String path,
    int size,
    int numFields,
    String category,
    String description
) {
    public static StructSummaryDto from(Structure struct) {
        if (struct == null) return null;
        return new StructSummaryDto(
            struct.getName(),
            struct.getPathName(),
            struct.getLength(),
            struct.getNumComponents(),
            struct.getCategoryPath().getPath(),
            struct.getDescription() != null ? struct.getDescription() : ""
        );
    }
}
