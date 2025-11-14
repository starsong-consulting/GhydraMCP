package eu.starsong.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.starsong.ghidra.api.ResponseBuilder;
import eu.starsong.ghidra.util.TransactionHelper;
import eu.starsong.ghidra.util.TransactionHelper.TransactionException;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.*;

/**
 * Endpoints for managing struct (composite) data types in Ghidra.
 * Provides REST API for creating, listing, modifying, and deleting structs.
 */
public class StructEndpoints extends AbstractEndpoint {

    private PluginTool tool;

    public StructEndpoints(Program program, int port) {
        super(program, port);
    }

    public StructEndpoints(Program program, int port, PluginTool tool) {
        super(program, port);
        this.tool = tool;
    }

    @Override
    protected PluginTool getTool() {
        return tool;
    }

    @Override
    public void registerEndpoints(HttpServer server) {
        server.createContext("/structs", this::handleStructs);
        server.createContext("/structs/create", exchange -> {
            try {
                if ("POST".equals(exchange.getRequestMethod())) {
                    Map<String, String> params = parseJsonPostParams(exchange);
                    handleCreateStruct(exchange, params);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /structs/create endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
            }
        });
        server.createContext("/structs/delete", exchange -> {
            try {
                if ("POST".equals(exchange.getRequestMethod())) {
                    Map<String, String> params = parseJsonPostParams(exchange);
                    handleDeleteStruct(exchange, params);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /structs/delete endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
            }
        });
        server.createContext("/structs/addfield", exchange -> {
            try {
                if ("POST".equals(exchange.getRequestMethod())) {
                    Map<String, String> params = parseJsonPostParams(exchange);
                    handleAddField(exchange, params);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /structs/addfield endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
            }
        });
        server.createContext("/structs/updatefield", exchange -> {
            try {
                if ("POST".equals(exchange.getRequestMethod()) || "PATCH".equals(exchange.getRequestMethod())) {
                    Map<String, String> params = parseJsonPostParams(exchange);
                    handleUpdateField(exchange, params);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /structs/updatefield endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
            }
        });
    }

    /**
     * Handle GET /structs - list all structs, or GET /structs?name=X - get specific struct details
     */
    private void handleStructs(HttpExchange exchange) throws IOException {
        try {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                String structName = qparams.get("name");

                if (structName != null && !structName.isEmpty()) {
                    handleGetStruct(exchange, structName);
                } else {
                    handleListStructs(exchange);
                }
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed");
            }
        } catch (Exception e) {
            Msg.error(this, "Error in /structs endpoint", e);
            sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
        }
    }

    /**
     * List all struct data types in the program
     */
    private void handleListStructs(HttpExchange exchange) throws IOException {
        try {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String categoryFilter = qparams.get("category");

            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                return;
            }

            DataTypeManager dtm = program.getDataTypeManager();
            List<Map<String, Object>> structList = new ArrayList<>();

            // Iterate through all data types and filter for structures
            dtm.getAllDataTypes().forEachRemaining(dataType -> {
                if (dataType instanceof Structure) {
                    Structure struct = (Structure) dataType;

                    // Apply category filter if specified
                    if (categoryFilter != null && !categoryFilter.isEmpty()) {
                        CategoryPath catPath = struct.getCategoryPath();
                        if (!catPath.getPath().contains(categoryFilter)) {
                            return;
                        }
                    }

                    Map<String, Object> structInfo = new HashMap<>();
                    structInfo.put("name", struct.getName());
                    structInfo.put("path", struct.getPathName());
                    structInfo.put("size", struct.getLength());
                    structInfo.put("numFields", struct.getNumComponents());
                    structInfo.put("category", struct.getCategoryPath().getPath());
                    structInfo.put("description", struct.getDescription() != null ? struct.getDescription() : "");

                    // Add HATEOAS links
                    Map<String, Object> links = new HashMap<>();
                    Map<String, String> selfLink = new HashMap<>();
                    selfLink.put("href", "/structs?name=" + struct.getName());
                    links.put("self", selfLink);
                    structInfo.put("_links", links);

                    structList.add(structInfo);
                }
            });

            // Sort by name for consistency
            structList.sort(Comparator.comparing(s -> (String) s.get("name")));

            // Build response with pagination
            ResponseBuilder builder = new ResponseBuilder(exchange, port).success(true);
            List<Map<String, Object>> paginated = applyPagination(structList, offset, limit, builder, "/structs");
            builder.result(paginated);
            builder.addLink("program", "/program");

            sendJsonResponse(exchange, builder.build(), 200);
        } catch (Exception e) {
            Msg.error(this, "Error listing structs", e);
            sendErrorResponse(exchange, 500, "Error listing structs: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    /**
     * Get details of a specific struct including all fields
     */
    private void handleGetStruct(HttpExchange exchange, String structName) throws IOException {
        try {
            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                return;
            }

            DataTypeManager dtm = program.getDataTypeManager();

            // Try to find the struct - support both full paths and simple names
            DataType dataType = null;

            // If it looks like a full path (starts with /), try direct lookup
            if (structName.startsWith("/")) {
                dataType = dtm.getDataType(structName);
                if (dataType == null) {
                    dataType = dtm.findDataType(structName);
                }
            } else {
                // Search by simple name using the helper method
                dataType = findStructByName(dtm, structName);
            }

            if (dataType == null || !(dataType instanceof Structure)) {
                sendErrorResponse(exchange, 404, "Struct not found: " + structName, "STRUCT_NOT_FOUND");
                return;
            }

            Structure struct = (Structure) dataType;
            Map<String, Object> structInfo = buildStructInfo(struct);

            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                .success(true)
                .result(structInfo);

            builder.addLink("self", "/structs?name=" + struct.getName());
            builder.addLink("structs", "/structs");
            builder.addLink("program", "/program");

            sendJsonResponse(exchange, builder.build(), 200);
        } catch (Exception e) {
            Msg.error(this, "Error getting struct details", e);
            sendErrorResponse(exchange, 500, "Error getting struct: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    /**
     * Create a new struct data type
     * POST /structs/create
     * Required params: name
     * Optional params: category, size, description
     */
    private void handleCreateStruct(HttpExchange exchange, Map<String, String> params) throws IOException {
        try {
            String structName = params.get("name");
            String category = params.get("category");
            String sizeStr = params.get("size");
            String description = params.get("description");

            if (structName == null || structName.isEmpty()) {
                sendErrorResponse(exchange, 400, "Missing required parameter: name", "MISSING_PARAMETERS");
                return;
            }

            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                return;
            }

            Map<String, Object> resultMap = new HashMap<>();
            resultMap.put("name", structName);

            try {
                TransactionHelper.executeInTransaction(program, "Create Struct", () -> {
                    DataTypeManager dtm = program.getDataTypeManager();

                    // Check if struct already exists
                    DataType existing = dtm.getDataType("/" + structName);
                    if (existing != null) {
                        throw new Exception("Struct already exists: " + structName);
                    }

                    // Determine category path
                    CategoryPath catPath;
                    if (category != null && !category.isEmpty()) {
                        catPath = new CategoryPath(category);
                    } else {
                        catPath = CategoryPath.ROOT;
                    }

                    // Create the structure
                    StructureDataType struct = new StructureDataType(catPath, structName, 0);

                    if (description != null && !description.isEmpty()) {
                        struct.setDescription(description);
                    }

                    // Add to data type manager
                    Structure addedStruct = (Structure) dtm.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER);

                    resultMap.put("path", addedStruct.getPathName());
                    resultMap.put("category", addedStruct.getCategoryPath().getPath());
                    resultMap.put("size", addedStruct.getLength());

                    return null;
                });

                resultMap.put("message", "Struct created successfully");

                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(resultMap);

                builder.addLink("self", "/structs?name=" + structName);
                builder.addLink("structs", "/structs");
                builder.addLink("program", "/program");

                sendJsonResponse(exchange, builder.build(), 201);
            } catch (TransactionException e) {
                Msg.error(this, "Transaction failed: Create Struct", e);
                sendErrorResponse(exchange, 500, "Failed to create struct: " + e.getMessage(), "TRANSACTION_ERROR");
            } catch (Exception e) {
                Msg.error(this, "Error creating struct", e);
                sendErrorResponse(exchange, 400, "Error creating struct: " + e.getMessage(), "INVALID_PARAMETER");
            }
        } catch (Exception e) {
            Msg.error(this, "Unexpected error creating struct", e);
            sendErrorResponse(exchange, 500, "Error creating struct: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    /**
     * Add a field to an existing struct
     * POST /structs/addfield
     * Required params: struct, fieldName, fieldType
     * Optional params: offset, comment
     */
    private void handleAddField(HttpExchange exchange, Map<String, String> params) throws IOException {
        try {
            String structName = params.get("struct");
            String fieldName = params.get("fieldName");
            String fieldType = params.get("fieldType");
            String offsetStr = params.get("offset");
            String comment = params.get("comment");

            if (structName == null || structName.isEmpty()) {
                sendErrorResponse(exchange, 400, "Missing required parameter: struct", "MISSING_PARAMETERS");
                return;
            }
            if (fieldName == null || fieldName.isEmpty()) {
                sendErrorResponse(exchange, 400, "Missing required parameter: fieldName", "MISSING_PARAMETERS");
                return;
            }
            if (fieldType == null || fieldType.isEmpty()) {
                sendErrorResponse(exchange, 400, "Missing required parameter: fieldType", "MISSING_PARAMETERS");
                return;
            }

            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                return;
            }

            Integer offset = null;
            if (offsetStr != null && !offsetStr.isEmpty()) {
                try {
                    offset = Integer.parseInt(offsetStr);
                } catch (NumberFormatException e) {
                    sendErrorResponse(exchange, 400, "Invalid offset parameter: must be an integer", "INVALID_PARAMETER");
                    return;
                }
            }

            Map<String, Object> resultMap = new HashMap<>();
            resultMap.put("struct", structName);
            resultMap.put("fieldName", fieldName);
            resultMap.put("fieldType", fieldType);

            final Integer finalOffset = offset;

            try {
                TransactionHelper.executeInTransaction(program, "Add Struct Field", () -> {
                    DataTypeManager dtm = program.getDataTypeManager();

                    // Find the struct - handle both full paths and simple names
                    DataType dataType = null;
                    if (structName.startsWith("/")) {
                        dataType = dtm.getDataType(structName);
                        if (dataType == null) {
                            dataType = dtm.findDataType(structName);
                        }
                    } else {
                        dataType = findStructByName(dtm, structName);
                    }

                    if (dataType == null || !(dataType instanceof Structure)) {
                        throw new Exception("Struct not found: " + structName);
                    }

                    Structure struct = (Structure) dataType;

                    // Find the field type
                    DataType fieldDataType = findDataType(dtm, fieldType);
                    if (fieldDataType == null) {
                        throw new Exception("Field type not found: " + fieldType);
                    }

                    // Add the field
                    DataTypeComponent component;
                    if (finalOffset != null) {
                        // Insert at specific offset
                        component = struct.insertAtOffset(finalOffset, fieldDataType,
                                                         fieldDataType.getLength(), fieldName, comment);
                    } else {
                        // Append to end
                        component = struct.add(fieldDataType, fieldName, comment);
                    }

                    resultMap.put("offset", component.getOffset());
                    resultMap.put("length", component.getLength());
                    resultMap.put("structSize", struct.getLength());

                    return null;
                });

                resultMap.put("message", "Field added successfully");

                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(resultMap);

                builder.addLink("struct", "/structs?name=" + structName);
                builder.addLink("structs", "/structs");
                builder.addLink("program", "/program");

                sendJsonResponse(exchange, builder.build(), 200);
            } catch (TransactionException e) {
                Msg.error(this, "Transaction failed: Add Struct Field", e);
                sendErrorResponse(exchange, 500, "Failed to add field: " + e.getMessage(), "TRANSACTION_ERROR");
            } catch (Exception e) {
                Msg.error(this, "Error adding field", e);
                sendErrorResponse(exchange, 400, "Error adding field: " + e.getMessage(), "INVALID_PARAMETER");
            }
        } catch (Exception e) {
            Msg.error(this, "Unexpected error adding field", e);
            sendErrorResponse(exchange, 500, "Error adding field: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    /**
     * Update an existing field in a struct
     * POST/PATCH /structs/updatefield
     * Required params: struct, fieldOffset (or fieldName)
     * Optional params: newName, newType, newComment
     */
    private void handleUpdateField(HttpExchange exchange, Map<String, String> params) throws IOException {
        try {
            String structName = params.get("struct");
            String fieldOffsetStr = params.get("fieldOffset");
            String fieldName = params.get("fieldName");
            String newName = params.get("newName");
            String newType = params.get("newType");
            String newComment = params.get("newComment");

            if (structName == null || structName.isEmpty()) {
                sendErrorResponse(exchange, 400, "Missing required parameter: struct", "MISSING_PARAMETERS");
                return;
            }

            // Must have either fieldOffset or fieldName to identify the field
            if ((fieldOffsetStr == null || fieldOffsetStr.isEmpty()) && (fieldName == null || fieldName.isEmpty())) {
                sendErrorResponse(exchange, 400, "Missing required parameter: either fieldOffset or fieldName must be provided", "MISSING_PARAMETERS");
                return;
            }

            // Must have at least one update parameter
            if ((newName == null || newName.isEmpty()) &&
                (newType == null || newType.isEmpty()) &&
                (newComment == null || newComment.isEmpty())) {
                sendErrorResponse(exchange, 400, "At least one of newName, newType, or newComment must be provided", "MISSING_PARAMETERS");
                return;
            }

            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                return;
            }

            Integer fieldOffset = null;
            if (fieldOffsetStr != null && !fieldOffsetStr.isEmpty()) {
                try {
                    fieldOffset = Integer.parseInt(fieldOffsetStr);
                } catch (NumberFormatException e) {
                    sendErrorResponse(exchange, 400, "Invalid fieldOffset parameter: must be an integer", "INVALID_PARAMETER");
                    return;
                }
            }

            Map<String, Object> resultMap = new HashMap<>();
            resultMap.put("struct", structName);

            final Integer finalFieldOffset = fieldOffset;
            final String finalFieldName = fieldName;

            try {
                TransactionHelper.executeInTransaction(program, "Update Struct Field", () -> {
                    DataTypeManager dtm = program.getDataTypeManager();

                    // Find the struct
                    DataType dataType = null;
                    if (structName.startsWith("/")) {
                        dataType = dtm.getDataType(structName);
                        if (dataType == null) {
                            dataType = dtm.findDataType(structName);
                        }
                    } else {
                        dataType = findStructByName(dtm, structName);
                    }

                    if (dataType == null || !(dataType instanceof Structure)) {
                        throw new Exception("Struct not found: " + structName);
                    }

                    Structure struct = (Structure) dataType;

                    // Find the field to update
                    DataTypeComponent component = null;
                    if (finalFieldOffset != null) {
                        component = struct.getComponentAt(finalFieldOffset);
                    } else {
                        // Search by field name
                        for (DataTypeComponent comp : struct.getComponents()) {
                            if (finalFieldName.equals(comp.getFieldName())) {
                                component = comp;
                                break;
                            }
                        }
                    }

                    if (component == null) {
                        throw new Exception("Field not found in struct: " + (finalFieldOffset != null ? "offset " + finalFieldOffset : finalFieldName));
                    }

                    int componentOffset = component.getOffset();
                    int componentLength = component.getLength();
                    DataType originalType = component.getDataType();
                    String originalName = component.getFieldName();
                    String originalComment = component.getComment();

                    // Store original values
                    resultMap.put("originalName", originalName);
                    resultMap.put("originalType", originalType.getName());
                    resultMap.put("originalComment", originalComment != null ? originalComment : "");
                    resultMap.put("offset", componentOffset);

                    // Determine new values
                    String updatedName = (newName != null && !newName.isEmpty()) ? newName : originalName;
                    String updatedComment = (newComment != null) ? newComment : originalComment;
                    DataType updatedType = originalType;

                    if (newType != null && !newType.isEmpty()) {
                        updatedType = findDataType(dtm, newType);
                        if (updatedType == null) {
                            throw new Exception("Field type not found: " + newType);
                        }
                    }

                    // Update the field by replacing it
                    // Ghidra doesn't have a direct "update" - we need to delete and re-add
                    struct.deleteAtOffset(componentOffset);
                    DataTypeComponent newComponent = struct.insertAtOffset(componentOffset, updatedType,
                                                                           updatedType.getLength(),
                                                                           updatedName, updatedComment);

                    resultMap.put("newName", newComponent.getFieldName());
                    resultMap.put("newType", newComponent.getDataType().getName());
                    resultMap.put("newComment", newComponent.getComment() != null ? newComponent.getComment() : "");
                    resultMap.put("length", newComponent.getLength());

                    return null;
                });

                resultMap.put("message", "Field updated successfully");

                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(resultMap);

                builder.addLink("struct", "/structs?name=" + structName);
                builder.addLink("structs", "/structs");
                builder.addLink("program", "/program");

                sendJsonResponse(exchange, builder.build(), 200);
            } catch (TransactionException e) {
                Msg.error(this, "Transaction failed: Update Struct Field", e);
                sendErrorResponse(exchange, 500, "Failed to update field: " + e.getMessage(), "TRANSACTION_ERROR");
            } catch (Exception e) {
                Msg.error(this, "Error updating field", e);
                sendErrorResponse(exchange, 400, "Error updating field: " + e.getMessage(), "INVALID_PARAMETER");
            }
        } catch (Exception e) {
            Msg.error(this, "Unexpected error updating field", e);
            sendErrorResponse(exchange, 500, "Error updating field: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    /**
     * Delete a struct data type
     * POST /structs/delete
     * Required params: name
     */
    private void handleDeleteStruct(HttpExchange exchange, Map<String, String> params) throws IOException {
        try {
            String structName = params.get("name");

            if (structName == null || structName.isEmpty()) {
                sendErrorResponse(exchange, 400, "Missing required parameter: name", "MISSING_PARAMETERS");
                return;
            }

            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                return;
            }

            Map<String, Object> resultMap = new HashMap<>();
            resultMap.put("name", structName);

            try {
                TransactionHelper.executeInTransaction(program, "Delete Struct", () -> {
                    DataTypeManager dtm = program.getDataTypeManager();

                    // Find the struct - handle both full paths and simple names
                    DataType dataType = null;
                    if (structName.startsWith("/")) {
                        dataType = dtm.getDataType(structName);
                        if (dataType == null) {
                            dataType = dtm.findDataType(structName);
                        }
                    } else {
                        dataType = findStructByName(dtm, structName);
                    }

                    if (dataType == null) {
                        throw new Exception("Struct not found: " + structName);
                    }

                    if (!(dataType instanceof Structure)) {
                        throw new Exception("Data type is not a struct: " + structName);
                    }

                    // Store info before deletion
                    resultMap.put("path", dataType.getPathName());
                    resultMap.put("category", dataType.getCategoryPath().getPath());

                    // Remove the struct
                    dtm.remove(dataType, null);

                    return null;
                });

                resultMap.put("message", "Struct deleted successfully");

                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(resultMap);

                builder.addLink("structs", "/structs");
                builder.addLink("program", "/program");

                sendJsonResponse(exchange, builder.build(), 200);
            } catch (TransactionException e) {
                Msg.error(this, "Transaction failed: Delete Struct", e);
                sendErrorResponse(exchange, 500, "Failed to delete struct: " + e.getMessage(), "TRANSACTION_ERROR");
            } catch (Exception e) {
                Msg.error(this, "Error deleting struct", e);
                sendErrorResponse(exchange, 400, "Error deleting struct: " + e.getMessage(), "INVALID_PARAMETER");
            }
        } catch (Exception e) {
            Msg.error(this, "Unexpected error deleting struct", e);
            sendErrorResponse(exchange, 500, "Error deleting struct: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    /**
     * Build a detailed information map for a struct including all fields
     */
    private Map<String, Object> buildStructInfo(Structure struct) {
        Map<String, Object> structInfo = new HashMap<>();
        structInfo.put("name", struct.getName());
        structInfo.put("path", struct.getPathName());
        structInfo.put("size", struct.getLength());
        structInfo.put("category", struct.getCategoryPath().getPath());
        structInfo.put("description", struct.getDescription() != null ? struct.getDescription() : "");
        structInfo.put("numFields", struct.getNumComponents());

        // Add field details
        List<Map<String, Object>> fields = new ArrayList<>();
        for (DataTypeComponent component : struct.getComponents()) {
            Map<String, Object> fieldInfo = new HashMap<>();
            fieldInfo.put("name", component.getFieldName() != null ? component.getFieldName() : "");
            fieldInfo.put("offset", component.getOffset());
            fieldInfo.put("length", component.getLength());
            fieldInfo.put("type", component.getDataType().getName());
            fieldInfo.put("typePath", component.getDataType().getPathName());
            fieldInfo.put("comment", component.getComment() != null ? component.getComment() : "");
            fields.add(fieldInfo);
        }
        structInfo.put("fields", fields);

        return structInfo;
    }

    /**
     * Find a struct by name, searching through all data types
     */
    private DataType findStructByName(DataTypeManager dtm, String structName) {
        final DataType[] result = new DataType[1];

        dtm.getAllDataTypes().forEachRemaining(dt -> {
            if (dt instanceof Structure && dt.getName().equals(structName)) {
                if (result[0] == null) {
                    result[0] = dt;
                }
            }
        });

        return result[0];
    }

    /**
     * Find a data type by name, trying multiple lookup methods
     */
    private DataType findDataType(DataTypeManager dtm, String typeName) {
        // Try direct lookup with path
        DataType dataType = dtm.getDataType("/" + typeName);

        // Try without path
        if (dataType == null) {
            dataType = dtm.findDataType("/" + typeName);
        }

        // Try built-in primitive types
        if (dataType == null) {
            switch(typeName.toLowerCase()) {
                case "byte":
                    dataType = new ByteDataType();
                    break;
                case "char":
                    dataType = new CharDataType();
                    break;
                case "word":
                    dataType = new WordDataType();
                    break;
                case "dword":
                    dataType = new DWordDataType();
                    break;
                case "qword":
                    dataType = new QWordDataType();
                    break;
                case "float":
                    dataType = new FloatDataType();
                    break;
                case "double":
                    dataType = new DoubleDataType();
                    break;
                case "int":
                    dataType = new IntegerDataType();
                    break;
                case "long":
                    dataType = new LongDataType();
                    break;
                case "pointer":
                    dataType = new PointerDataType();
                    break;
                case "string":
                    dataType = new StringDataType();
                    break;
            }
        }

        return dataType;
    }
}
