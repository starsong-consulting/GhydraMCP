package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.StructDto;
import eu.starsong.ghidra.dto.StructSummaryDto;
import eu.starsong.ghidra.server.GhydraServer.NotFoundException;
import eu.starsong.ghidra.util.GhidraSwing;
import eu.starsong.ghidra.util.GhidraUtil;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public class StructService {

    public List<StructSummaryDto> list(Program program, String categoryFilter) {
        DataTypeManager dtm = program.getDataTypeManager();
        return GhidraSwing.runRead(() -> {
            List<StructSummaryDto> results = new ArrayList<>();
            dtm.getAllDataTypes().forEachRemaining(dt -> {
                if (!(dt instanceof Structure s)) return;
                if (categoryFilter != null && !categoryFilter.isEmpty()
                    && !s.getCategoryPath().getPath().contains(categoryFilter)) return;
                results.add(StructSummaryDto.from(s));
            });
            results.sort((a, b) -> a.name().compareTo(b.name()));
            return results;
        });
    }

    public Optional<StructDto> getByName(Program program, String name) {
        return GhidraSwing.runRead(() -> {
            Structure s = findStruct(program, name);
            return Optional.ofNullable(s).map(StructDto::from);
        });
    }

    public StructDto requireByName(Program program, String name) {
        return getByName(program, name)
            .orElseThrow(() -> new NotFoundException("Struct not found: " + name, "STRUCT_NOT_FOUND"));
    }

    public StructDto create(Program program, String name, String category, Integer size, String description) throws Exception {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("Struct name is required");
        }
        if (size != null && size < 0) {
            throw new IllegalArgumentException("Size must be >= 0");
        }

        return TransactionHelper.executeInTransaction(program, "Create Struct " + name, () -> {
            DataTypeManager dtm = program.getDataTypeManager();
            if (dtm.getDataType("/" + name) != null) {
                throw new IllegalArgumentException("Struct already exists: " + name);
            }
            CategoryPath catPath = (category != null && !category.isEmpty())
                ? new CategoryPath(category) : CategoryPath.ROOT;
            StructureDataType newStruct = new StructureDataType(catPath, name, size != null ? size : 0);
            if (description != null && !description.isEmpty()) {
                newStruct.setDescription(description);
            }
            Structure added = (Structure) dtm.addDataType(newStruct, DataTypeConflictHandler.DEFAULT_HANDLER);
            return StructDto.from(added);
        });
    }

    public StructDto addField(Program program, String structName, String fieldName, String fieldType,
                              Integer offset, String comment) throws Exception {
        if (structName == null || structName.isEmpty()) throw new IllegalArgumentException("struct is required");
        if (fieldName == null || fieldName.isEmpty()) throw new IllegalArgumentException("fieldName is required");
        if (fieldType == null || fieldType.isEmpty()) throw new IllegalArgumentException("fieldType is required");

        return TransactionHelper.executeInTransaction(program, "Add Field " + fieldName + " to " + structName, () -> {
            Structure struct = findStruct(program, structName);
            if (struct == null) {
                throw new NotFoundException("Struct not found: " + structName, "STRUCT_NOT_FOUND");
            }
            DataType fieldDataType = GhidraUtil.resolveDataType(program, fieldType);
            if (fieldDataType == null) {
                throw new IllegalArgumentException("Field type not found: " + fieldType);
            }
            if (offset != null) {
                struct.insertAtOffset(offset, fieldDataType, fieldDataType.getLength(), fieldName, comment);
            } else {
                struct.add(fieldDataType, fieldName, comment);
            }
            return StructDto.from(struct);
        });
    }

    public StructDto updateField(Program program, String structName, Integer fieldOffset, String fieldName,
                                 String newName, String newType, String newComment) throws Exception {
        if (structName == null || structName.isEmpty()) throw new IllegalArgumentException("struct is required");
        if (fieldOffset == null && (fieldName == null || fieldName.isEmpty())) {
            throw new IllegalArgumentException("Either fieldOffset or fieldName must be provided");
        }
        boolean hasNewName = newName != null && !newName.isEmpty();
        boolean hasNewType = newType != null && !newType.isEmpty();
        boolean hasNewComment = newComment != null;
        if (!hasNewName && !hasNewType && !hasNewComment) {
            throw new IllegalArgumentException("At least one of newName, newType, or newComment is required");
        }

        return TransactionHelper.executeInTransaction(program, "Update Field in " + structName, () -> {
            Structure struct = findStruct(program, structName);
            if (struct == null) {
                throw new NotFoundException("Struct not found: " + structName, "STRUCT_NOT_FOUND");
            }
            DataTypeComponent component = locateField(struct, fieldOffset, fieldName);
            if (component == null) {
                String id = fieldOffset != null ? "offset " + fieldOffset : fieldName;
                throw new NotFoundException("Field not found in struct: " + id, "FIELD_NOT_FOUND");
            }
            int componentOffset = component.getOffset();
            if (fieldOffset != null && componentOffset != fieldOffset) {
                throw new IllegalArgumentException("fieldOffset " + fieldOffset
                    + " is inside component at offset " + componentOffset
                    + "; provide the component start offset");
            }

            String originalName = component.getFieldName();
            String originalComment = component.getComment();
            DataType originalType = component.getDataType();
            String updatedName = hasNewName ? newName : originalName;
            String updatedComment = hasNewComment ? newComment : originalComment;

            if (hasNewType) {
                DataType updatedType = GhidraUtil.resolveDataType(program, newType);
                if (updatedType == null) {
                    throw new IllegalArgumentException("Field type not found: " + newType);
                }
                int replacementLength = validateReplacementLength(struct, componentOffset, component, updatedType);
                DataTypeComponent replaced = struct.replaceAtOffset(
                    componentOffset, updatedType, replacementLength, updatedName, updatedComment);
                if (replaced == null) {
                    throw new IllegalStateException("Failed to replace field at offset " + componentOffset);
                }
            } else {
                if (hasNewName && !Objects.equals(updatedName, originalName)) {
                    // 12.1's setFieldName no longer declares DuplicateNameException; guard
                    // explicitly so a clash still surfaces as a 400 rather than whatever
                    // the API does internally.
                    for (DataTypeComponent c : struct.getComponents()) {
                        if (c != component && updatedName.equals(c.getFieldName())) {
                            throw new IllegalArgumentException("Field name already exists: " + updatedName);
                        }
                    }
                    component.setFieldName(updatedName);
                }
                if (hasNewComment) {
                    component.setComment(updatedComment);
                }
            }
            return StructDto.from(struct);
        });
    }

    public void delete(Program program, String name) throws Exception {
        if (name == null || name.isEmpty()) throw new IllegalArgumentException("Struct name is required");
        TransactionHelper.executeInTransaction(program, "Delete Struct " + name, () -> {
            Structure struct = findStruct(program, name);
            if (struct == null) {
                throw new NotFoundException("Struct not found: " + name, "STRUCT_NOT_FOUND");
            }
            program.getDataTypeManager().remove(struct);
            return null;
        });
    }

    private Structure findStruct(Program program, String name) {
        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt;
        if (name.startsWith("/")) {
            dt = dtm.getDataType(name);
        } else {
            dt = findStructByName(dtm, name);
        }
        return (dt instanceof Structure s) ? s : null;
    }

    private DataType findStructByName(DataTypeManager dtm, String name) {
        return GhidraSwing.runRead(() -> {
            DataType[] result = new DataType[1];
            dtm.getAllDataTypes().forEachRemaining(dt -> {
                if (dt instanceof Structure && dt.getName().equals(name) && result[0] == null) {
                    result[0] = dt;
                }
            });
            return result[0];
        });
    }

    private DataTypeComponent locateField(Structure struct, Integer fieldOffset, String fieldName) {
        if (fieldOffset != null) {
            return struct.getComponentContaining(fieldOffset);
        }
        for (DataTypeComponent c : struct.getComponents()) {
            if (fieldName.equals(c.getFieldName())) return c;
        }
        return null;
    }

    private int validateReplacementLength(Structure struct, int componentOffset, DataTypeComponent component, DataType updatedType) {
        int requested = updatedType.getLength();
        if (requested <= 0) {
            throw new IllegalArgumentException("Field type '" + updatedType.getName() + "' has unsupported size: " + requested);
        }
        int searchOffset = component.getEndOffset() + 1;
        DataTypeComponent next = struct.getDefinedComponentAtOrAfterOffset(searchOffset);
        int endOffset = (next != null) ? next.getOffset() : struct.getLength();
        int maxLength = Math.max(0, endOffset - componentOffset);
        if (requested > maxLength) {
            throw new IllegalArgumentException("Field type '" + updatedType.getName() + "' (" + requested
                + " bytes) does not fit at offset " + componentOffset
                + "; available bytes before next defined field: " + maxLength);
        }
        return requested;
    }
}
