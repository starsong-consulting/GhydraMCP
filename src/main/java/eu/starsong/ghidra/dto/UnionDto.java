package eu.starsong.ghidra.dto;

import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Union;

import java.util.ArrayList;
import java.util.List;

public record UnionDto(
    String name,
    String path,
    String category,
    int length,
    int numComponents,
    List<UnionFieldDto> fields
) {
    public static UnionDto from(Union u) {
        if (u == null) return null;
        List<UnionFieldDto> fields = new ArrayList<>();
        for (DataTypeComponent c : u.getComponents()) {
            fields.add(new UnionFieldDto(
                c.getFieldName() != null ? c.getFieldName() : "",
                c.getDataType().getName(),
                c.getDataType().getPathName(),
                c.getLength(),
                c.getComment() != null ? c.getComment() : ""
            ));
        }
        return new UnionDto(
            u.getName(),
            u.getPathName(),
            u.getCategoryPath().getPath(),
            u.getLength(),
            u.getNumComponents(),
            fields
        );
    }

    public record UnionFieldDto(String name, String type, String typePath, int length, String comment) {}
}
