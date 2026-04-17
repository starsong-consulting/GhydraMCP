package eu.starsong.ghidra.dto;

import ghidra.program.model.data.Enum;

import java.util.ArrayList;
import java.util.List;

public record EnumDto(
    String name,
    String path,
    String category,
    int length,
    int numValues,
    List<EnumValueDto> values
) {
    public static EnumDto from(Enum e) {
        if (e == null) return null;
        List<EnumValueDto> values = new ArrayList<>();
        for (String name : e.getNames()) {
            values.add(new EnumValueDto(name, e.getValue(name)));
        }
        return new EnumDto(
            e.getName(),
            e.getPathName(),
            e.getCategoryPath().getPath(),
            e.getLength(),
            e.getCount(),
            values
        );
    }

    public record EnumValueDto(String name, long value) {}
}
