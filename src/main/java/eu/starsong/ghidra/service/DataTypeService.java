package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.DataTypeSummaryDto;
import eu.starsong.ghidra.dto.EnumDto;
import eu.starsong.ghidra.dto.StructDto;
import eu.starsong.ghidra.dto.UnionDto;
import eu.starsong.ghidra.util.GhidraSwing;
import eu.starsong.ghidra.util.GhidraUtil;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class DataTypeService {

    public List<DataTypeSummaryDto> list(Program program, String categoryFilter, String kindFilter, String nameFilter) {
        DataTypeManager dtm = program.getDataTypeManager();
        List<DataTypeSummaryDto> results = new ArrayList<>();
        String lowerName = nameFilter != null ? nameFilter.toLowerCase() : null;

        return GhidraSwing.runRead(() -> {
            Iterator<DataType> iter = dtm.getAllDataTypes();
            while (iter.hasNext()) {
                DataType dt = iter.next();
                if (categoryFilter != null && !categoryFilter.isEmpty()
                    && !dt.getCategoryPath().getPath().contains(categoryFilter)) continue;
                if (lowerName != null && !lowerName.isEmpty()) {
                    String dtName = dt.getName() != null ? dt.getName().toLowerCase() : "";
                    String dtDisplay = dt.getDisplayName() != null ? dt.getDisplayName().toLowerCase() : "";
                    if (!dtName.contains(lowerName) && !dtDisplay.contains(lowerName)) continue;
                }
                if (kindFilter != null && !kindFilter.isEmpty()) {
                    boolean match = switch (kindFilter) {
                        case "struct" -> dt instanceof Structure;
                        case "enum" -> dt instanceof Enum;
                        case "union" -> dt instanceof Union;
                        default -> false;
                    };
                    if (!match) continue;
                }
                results.add(DataTypeSummaryDto.from(dt));
            }
            return results;
        });
    }

    public StructDto createStruct(Program program, String name, String category, List<FieldSpec> fields) throws Exception {
        if (name == null || name.isEmpty()) throw new IllegalArgumentException("name is required");

        return TransactionHelper.executeInTransaction(program, "Create struct " + name, () -> {
            DataTypeManager dtm = program.getDataTypeManager();
            CategoryPath catPath = new CategoryPath(category != null ? category : "/");
            StructureDataType struct = new StructureDataType(catPath, name, 0, dtm);
            if (fields != null) {
                for (int i = 0; i < fields.size(); i++) {
                    FieldSpec spec = fields.get(i);
                    applyStructField(program, struct, spec, i);
                }
            }
            Structure added = (Structure) dtm.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER);
            return StructDto.from(added);
        });
    }

    public EnumDto createEnum(Program program, String name, int size, String category, Map<String, Long> values) throws Exception {
        if (name == null || name.isEmpty()) throw new IllegalArgumentException("name is required");
        if (size <= 0) throw new IllegalArgumentException("size must be > 0");

        return TransactionHelper.executeInTransaction(program, "Create enum " + name, () -> {
            DataTypeManager dtm = program.getDataTypeManager();
            CategoryPath catPath = new CategoryPath(category != null ? category : "/");
            EnumDataType enumDt = new EnumDataType(catPath, name, size, dtm);
            if (values != null) {
                for (Map.Entry<String, Long> entry : values.entrySet()) {
                    enumDt.add(entry.getKey(), entry.getValue());
                }
            }
            Enum added = (Enum) dtm.addDataType(enumDt, DataTypeConflictHandler.DEFAULT_HANDLER);
            return EnumDto.from(added);
        });
    }

    public UnionDto createUnion(Program program, String name, String category, List<FieldSpec> fields) throws Exception {
        if (name == null || name.isEmpty()) throw new IllegalArgumentException("name is required");

        return TransactionHelper.executeInTransaction(program, "Create union " + name, () -> {
            DataTypeManager dtm = program.getDataTypeManager();
            CategoryPath catPath = new CategoryPath(category != null ? category : "/");
            UnionDataType union = new UnionDataType(catPath, name, dtm);
            if (fields != null) {
                for (int i = 0; i < fields.size(); i++) {
                    FieldSpec spec = fields.get(i);
                    applyUnionField(program, union, spec, i);
                }
            }
            Union added = (Union) dtm.addDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);
            return UnionDto.from(added);
        });
    }

    private void applyStructField(Program program, StructureDataType struct, FieldSpec spec, int index) throws Exception {
        String fieldName = (spec.name != null && !spec.name.isEmpty()) ? spec.name : "field_" + index;
        if (spec.type == null || spec.type.isEmpty()) {
            throw new IllegalArgumentException("fields[" + index + "].type is required");
        }
        DataType fieldType = GhidraUtil.resolveDataType(program, spec.type);
        if (fieldType == null) {
            throw new IllegalArgumentException("Unknown field type in fields[" + index + "]: " + spec.type);
        }
        int length = resolveLength(fieldType, spec.size, "fields[" + index + "]");
        if (spec.offset != null) {
            struct.insertAtOffset(spec.offset, fieldType, length, fieldName, spec.comment);
        } else {
            struct.add(fieldType, length, fieldName, spec.comment);
        }
    }

    private void applyUnionField(Program program, UnionDataType union, FieldSpec spec, int index) throws Exception {
        String fieldName = (spec.name != null && !spec.name.isEmpty()) ? spec.name : "field_" + index;
        if (spec.type == null || spec.type.isEmpty()) {
            throw new IllegalArgumentException("fields[" + index + "].type is required");
        }
        DataType fieldType = GhidraUtil.resolveDataType(program, spec.type);
        if (fieldType == null) {
            throw new IllegalArgumentException("Unknown field type in fields[" + index + "]: " + spec.type);
        }
        int length = resolveLength(fieldType, spec.size, "fields[" + index + "]");
        union.add(fieldType, length, fieldName, spec.comment);
    }

    private int resolveLength(DataType dt, Integer requested, String fieldPath) {
        if (requested != null) {
            if (requested <= 0) {
                throw new IllegalArgumentException(fieldPath + ".size must be > 0");
            }
            return requested;
        }
        int len = dt.getLength();
        if (len <= 0) {
            throw new IllegalArgumentException(fieldPath + " has type '" + dt.getName()
                + "' with non-positive length; specify size explicitly");
        }
        return len;
    }

    public static class FieldSpec {
        public String name;
        public String type;
        public Integer size;
        public Integer offset;
        public String comment;
    }
}
