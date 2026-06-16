package eu.starsong.ghidra.dto;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;

public record DataTypeSummaryDto(
    String name,
    String displayName,
    String category,
    int length,
    String kind,
    Integer numComponents,
    Integer numValues
) {
    public static DataTypeSummaryDto from(DataType dt) {
        if (dt == null) return null;
        String kind;
        Integer numComponents = null;
        Integer numValues = null;
        if (dt instanceof Structure s) {
            kind = "struct";
            numComponents = s.getNumComponents();
        } else if (dt instanceof ghidra.program.model.data.Enum e) {
            kind = "enum";
            numValues = e.getCount();
        } else if (dt instanceof Union u) {
            kind = "union";
            numComponents = u.getNumComponents();
        } else {
            kind = "other";
        }
        return new DataTypeSummaryDto(
            dt.getName(),
            dt.getDisplayName(),
            dt.getCategoryPath().getPath(),
            dt.getLength(),
            kind,
            numComponents,
            numValues
        );
    }
}
