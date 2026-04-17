package eu.starsong.ghidra.dto;

import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;

import java.util.Arrays;
import java.util.List;

public record StructDto(
    String name,
    String path,
    int size,
    int numFields,
    String category,
    String description,
    List<StructFieldDto> fields
) {
    public static StructDto from(Structure struct) {
        if (struct == null) return null;
        List<StructFieldDto> fieldDtos = Arrays.stream(struct.getComponents())
            .map(StructFieldDto::from)
            .toList();
        return new StructDto(
            struct.getName(),
            struct.getPathName(),
            struct.getLength(),
            struct.getNumComponents(),
            struct.getCategoryPath().getPath(),
            struct.getDescription() != null ? struct.getDescription() : "",
            fieldDtos
        );
    }
}
