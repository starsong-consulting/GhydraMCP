package eu.starsong.ghidra.endpoints;

    import com.google.gson.JsonObject;
    import com.sun.net.httpserver.HttpExchange;
    import com.sun.net.httpserver.HttpServer;
    import eu.starsong.ghidra.util.TransactionHelper;
    import eu.starsong.ghidra.util.TransactionHelper.TransactionException;
    import ghidra.program.model.address.Address;
    import ghidra.framework.plugintool.PluginTool;
    import ghidra.program.model.listing.Data;
    import ghidra.program.model.listing.DataIterator;
    import ghidra.program.model.listing.Listing;
    import ghidra.program.model.listing.Program;
    import ghidra.program.model.mem.MemoryBlock;
    import ghidra.program.model.symbol.SourceType;
    import ghidra.program.model.symbol.Symbol;
    import ghidra.program.model.symbol.SymbolTable;
    import ghidra.util.Msg;

    import java.io.IOException;
    import java.util.*;
    import java.util.concurrent.atomic.AtomicBoolean;
    import javax.swing.SwingUtilities;
    import java.lang.reflect.InvocationTargetException;

    public class DataEndpoints extends AbstractEndpoint {

        private PluginTool tool;
        
        // Updated constructor to accept port
        public DataEndpoints(Program program, int port) {
            super(program, port); // Call super constructor
        }
        
        public DataEndpoints(Program program, int port, PluginTool tool) {
            super(program, port);
            this.tool = tool;
        }
        
        @Override
        protected PluginTool getTool() {
            return tool;
        }

        @Override
        public void registerEndpoints(HttpServer server) {
            server.createContext("/data", this::handleData);
            server.createContext("/data/update", this::handleUpdateData);
            server.createContext("/data/type", this::handleSetDataType);
        }

        public void handleData(HttpExchange exchange) throws IOException {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    handleListData(exchange);
                } else if ("POST".equals(exchange.getRequestMethod())) {
                    handleRenameData(exchange);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /data endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
            }
        }

        private void handleListData(HttpExchange exchange) throws IOException {
            try {
                Map<String, String> qparams = parseQueryParams(exchange);
                int offset = parseIntOrDefault(qparams.get("offset"), 0);
                int limit = parseIntOrDefault(qparams.get("limit"), 100);
                
                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                    return;
                }
                
                List<Map<String, Object>> dataItems = new ArrayList<>();
                for (MemoryBlock block : program.getMemory().getBlocks()) {
                    DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
                    while (it.hasNext()) {
                        Data data = it.next();
                        if (block.contains(data.getAddress())) {
                            Map<String, Object> item = new HashMap<>();
                            item.put("address", data.getAddress().toString());
                            item.put("label", data.getLabel() != null ? data.getLabel() : "(unnamed)");
                            item.put("value", data.getDefaultValueRepresentation());
                            item.put("dataType", data.getDataType().getName());
                            
                            // Add HATEOAS links
                            Map<String, Object> links = new HashMap<>();
                            Map<String, String> selfLink = new HashMap<>();
                            selfLink.put("href", "/data/" + data.getAddress().toString());
                            links.put("self", selfLink);
                            item.put("_links", links);
                            
                            dataItems.add(item);
                        }
                    }
                }
                
                // Build response with HATEOAS links
                eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                    .success(true);
                
                // Apply pagination and get paginated items
                List<Map<String, Object>> paginated = applyPagination(dataItems, offset, limit, builder, "/data");
                
                // Set the paginated result
                builder.result(paginated);
                
                // Add program link
                builder.addLink("program", "/program");
                
                sendJsonResponse(exchange, builder.build(), 200);
            } catch (Exception e) {
                Msg.error(this, "Error listing data", e);
                sendErrorResponse(exchange, 500, "Error listing data: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }

        private void handleRenameData(HttpExchange exchange) throws IOException {
            try {
                Map<String, String> params = parseJsonPostParams(exchange);
                final String addressStr = params.get("address");
                final String newName = params.get("newName");

                if (addressStr == null || addressStr.isEmpty() || newName == null || newName.isEmpty()) {
                    sendErrorResponse(exchange, 400, "Missing required parameters: address, newName", "MISSING_PARAMETERS");
                    return;
                }

                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                    return;
                }

                try {
                    TransactionHelper.executeInTransaction(program, "Rename Data", () -> {
                        if (!renameDataAtAddress(program, addressStr, newName)) {
                            throw new Exception("Rename data operation failed internally.");
                        }
                        return null; // Return null for void operation
                    });
                    
                    // Build HATEOAS response
                    eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                        .success(true)
                        .result(Map.of("message", "Data renamed successfully", "address", addressStr, "name", newName));
                    
                    // Add relevant links
                    builder.addLink("self", "/data/" + addressStr);
                    builder.addLink("data", "/data");
                    builder.addLink("program", "/program");
                    
                    sendJsonResponse(exchange, builder.build(), 200);
                } catch (TransactionException e) {
                    Msg.error(this, "Transaction failed: Rename Data", e);
                    sendErrorResponse(exchange, 500, "Failed to rename data: " + e.getMessage(), "TRANSACTION_ERROR");
                } catch (Exception e) { // Catch potential AddressFormatException or other issues
                    Msg.error(this, "Error during rename data operation", e);
                    sendErrorResponse(exchange, 400, "Error renaming data: " + e.getMessage(), "INVALID_PARAMETER");
                }
            } catch (IOException e) {
                Msg.error(this, "Error parsing POST params for data rename", e);
                sendErrorResponse(exchange, 400, "Invalid request body: " + e.getMessage(), "INVALID_REQUEST");
            } catch (Exception e) { // Catch unexpected errors
                Msg.error(this, "Unexpected error renaming data", e);
                sendErrorResponse(exchange, 500, "Error renaming data: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }


        private boolean renameDataAtAddress(Program program, String addressStr, String newName) throws Exception {
            // This method now throws Exception to be caught by the transaction helper
            AtomicBoolean successFlag = new AtomicBoolean(false);
            try {
                Address addr = program.getAddressFactory().getAddress(addressStr);
                Listing listing = program.getListing();
                Data data = listing.getDefinedDataAt(addr);
                if (data != null) {
                    SymbolTable symTable = program.getSymbolTable();
                    Symbol symbol = symTable.getPrimarySymbol(addr);
                    if (symbol != null) {
                        symbol.setName(newName, SourceType.USER_DEFINED);
                        successFlag.set(true);
                    } else {
                        // Create a new label if no primary symbol exists
                        symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        successFlag.set(true);
                    }
                } else {
                     throw new Exception("No defined data found at address: " + addressStr);
                }
            } catch (ghidra.program.model.address.AddressFormatException afe) {
                 throw new Exception("Invalid address format: " + addressStr, afe);
            } catch (ghidra.util.exception.InvalidInputException iie) {
                 throw new Exception("Invalid name: " + newName, iie);
            } catch (Exception e) { // Catch other potential Ghidra exceptions
                 throw new Exception("Failed to rename data at " + addressStr, e);
            }
            return successFlag.get();
        }
        
        // parseIntOrDefault is inherited from AbstractEndpoint
        
        public void handleSetDataType(HttpExchange exchange) throws IOException {
            try {
                if ("PATCH".equals(exchange.getRequestMethod()) || "POST".equals(exchange.getRequestMethod())) {
                    Map<String, String> params = parseJsonPostParams(exchange);
                    final String addressStr = params.get("address");
                    final String dataTypeStr = params.get("dataType");
                    
                    if (addressStr == null || addressStr.isEmpty() || dataTypeStr == null || dataTypeStr.isEmpty()) {
                        sendErrorResponse(exchange, 400, 
                            "Missing required parameters: address and dataType must be provided", 
                            "MISSING_PARAMETERS");
                        return;
                    }
                    
                    Program program = getCurrentProgram();
                    if (program == null) {
                        sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                        return;
                    }
                    
                    try {
                        Map<String, Object> result = new HashMap<>();
                        result.put("address", addressStr);
                        result.put("dataType", dataTypeStr);
                        
                        TransactionHelper.executeInTransaction(program, "Set Data Type", () -> {
                            // Get the data at the address
                            Address addr = program.getAddressFactory().getAddress(addressStr);
                            Listing listing = program.getListing();
                            Data existingData = listing.getDefinedDataAt(addr);
                            
                            if (existingData == null) {
                                throw new Exception("No defined data found at address: " + addressStr);
                            }
                            
                            // Try to find the data type in the data type manager
                            ghidra.program.model.data.DataType dataType = null;
                            
                            // First try built-in types with path
                            dataType = program.getDataTypeManager().getDataType("/" + dataTypeStr);
                            
                            // Try built-in types without path
                            if (dataType == null) {
                                dataType = program.getDataTypeManager().findDataType("/" + dataTypeStr);
                            }
                            
                            // If still not found, try to parse it as a C-style declaration
                            if (dataType == null) {
                                try {
                                    ghidra.app.util.parser.FunctionSignatureParser parser = 
                                        new ghidra.app.util.parser.FunctionSignatureParser(program.getDataTypeManager(), null);
                                    dataType = parser.parse(null, dataTypeStr);
                                } catch (Exception e) {
                                    Msg.debug(this, "Function signature parser failed: " + e.getMessage());
                                }
                            }
                            
                            // Try C parser as a last resort
                            if (dataType == null) {
                                try {
                                    // Use the DataTypeParser to create the type
                                    ghidra.app.util.parser.FunctionSignatureParser parser = 
                                        new ghidra.app.util.parser.FunctionSignatureParser(program.getDataTypeManager(), null);
                                    dataType = parser.parse(null, dataTypeStr);
                                } catch (Exception e) {
                                    Msg.error(this, "Error parsing data type: " + dataTypeStr, e);
                                }
                            }
                            
                            if (dataType == null) {
                                throw new Exception("Could not find or parse data type: " + dataTypeStr);
                            }
                            
                            // Apply the data type
                            try {
                                Data newDataItem = listing.createData(addr, dataType);
                                if (newDataItem == null) {
                                    // Try clearing existing data first and then creating it
                                    listing.clearCodeUnits(addr, addr.add(existingData.getLength() - 1), false);
                                    newDataItem = listing.createData(addr, dataType);
                                    
                                    if (newDataItem == null) {
                                        throw new Exception("Failed to apply data type " + dataTypeStr + " at " + addressStr);
                                    }
                                }
                            } catch (Exception e) {
                                throw new Exception("Failed to apply data type " + dataTypeStr + " at " + addressStr, e);
                            }
                            
                            // Re-get the data to return its current info
                            Data newData = listing.getDefinedDataAt(addr);
                            if (newData != null) {
                                result.put("currentDataType", newData.getDataType().getName());
                                result.put("length", newData.getLength());
                                result.put("value", newData.getDefaultValueRepresentation());
                            }
                            
                            return null;
                        });
                        
                        // Build HATEOAS response
                        eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                            .success(true)
                            .result(result);
                        
                        // Add relevant links
                        builder.addLink("self", "/data/" + addressStr);
                        builder.addLink("data", "/data");
                        builder.addLink("program", "/program");
                        
                        sendJsonResponse(exchange, builder.build(), 200);
                    } catch (TransactionException e) {
                        Msg.error(this, "Transaction failed: Set Data Type", e);
                        sendErrorResponse(exchange, 500, "Failed to set data type: " + e.getMessage(), "TRANSACTION_ERROR");
                    } catch (Exception e) {
                        Msg.error(this, "Error during set data type operation", e);
                        sendErrorResponse(exchange, 400, "Error setting data type: " + e.getMessage(), "INVALID_PARAMETER");
                    }
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (IOException e) {
                Msg.error(this, "Error parsing request parameters for data type update", e);
                sendErrorResponse(exchange, 400, "Invalid request body: " + e.getMessage(), "INVALID_REQUEST");
            } catch (Exception e) {
                Msg.error(this, "Unexpected error setting data type", e);
                sendErrorResponse(exchange, 500, "Error setting data type: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }
        
        public void handleUpdateData(HttpExchange exchange) throws IOException {
            try {
                if ("PATCH".equals(exchange.getRequestMethod()) || "POST".equals(exchange.getRequestMethod())) {
                    Map<String, String> params = parseJsonPostParams(exchange);
                    final String addressStr = params.get("address");
                    final String newName = params.get("newName");
                    final String dataTypeStr = params.get("dataType");
                    
                    // At least one of name or dataType must be provided
                    if (addressStr == null || addressStr.isEmpty() || 
                        (newName == null || newName.isEmpty()) && (dataTypeStr == null || dataTypeStr.isEmpty())) {
                        sendErrorResponse(exchange, 400, 
                            "Missing required parameters: address and either name or dataType must be provided", 
                            "MISSING_PARAMETERS");
                        return;
                    }
                    
                    Program program = getCurrentProgram();
                    if (program == null) {
                        sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                        return;
                    }
                    
                    try {
                        Map<String, Object> result = new HashMap<>();
                        result.put("address", addressStr);
                        
                        TransactionHelper.executeInTransaction(program, "Update Data", () -> {
                            // Get the data at the address
                            Address addr = program.getAddressFactory().getAddress(addressStr);
                            Listing listing = program.getListing();
                            Data data = listing.getDefinedDataAt(addr);
                            
                            if (data == null) {
                                throw new Exception("No defined data found at address: " + addressStr);
                            }
                            
                            // Rename if name is provided
                            if (newName != null && !newName.isEmpty()) {
                                SymbolTable symTable = program.getSymbolTable();
                                Symbol symbol = symTable.getPrimarySymbol(addr);
                                if (symbol != null) {
                                    symbol.setName(newName, SourceType.USER_DEFINED);
                                } else {
                                    // Create a new label if no primary symbol exists
                                    symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                                }
                                result.put("name", newName);
                            }
                            
                            // Change data type if specified
                            if (dataTypeStr != null && !dataTypeStr.isEmpty()) {
                                // Try to find the data type in the data type manager
                                ghidra.program.model.data.DataType dataType = null;
                                
                                // First try built-in types
                                dataType = program.getDataTypeManager().getDataType("/" + dataTypeStr);
                                
                                // If not found, try to parse it as a C-style declaration
                                if (dataType == null) {
                                    ghidra.app.util.parser.FunctionSignatureParser parser = 
                                        new ghidra.app.util.parser.FunctionSignatureParser(program.getDataTypeManager(), null);
                                    try {
                                        dataType = parser.parse(null, dataTypeStr);
                                    } catch (Exception e) {
                                        Msg.error(this, "Error parsing data type: " + dataTypeStr, e);
                                    }
                                }
                                
                                if (dataType == null) {
                                    throw new Exception("Could not find or parse data type: " + dataTypeStr);
                                }
                                
                                // Apply the data type
                                try {
                                    Data newData = listing.createData(addr, dataType);
                                    if (newData == null) {
                                        throw new Exception("Failed to apply data type " + dataTypeStr + " at " + addressStr);
                                    }
                                } catch (Exception e) {
                                    throw new Exception("Failed to apply data type " + dataTypeStr + " at " + addressStr, e);
                                }
                                
                                result.put("dataType", dataTypeStr);
                                // Re-get the data to return its current info
                                data = listing.getDefinedDataAt(addr);
                            }
                            
                            // Add additional data info to result
                            if (data != null) {
                                result.put("currentDataType", data.getDataType().getName());
                                result.put("length", data.getLength());
                                result.put("value", data.getDefaultValueRepresentation());
                            }
                            
                            return null;
                        });
                        
                        // Build HATEOAS response
                        eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                            .success(true)
                            .result(result);
                        
                        // Add relevant links
                        builder.addLink("self", "/data/" + addressStr);
                        builder.addLink("data", "/data");
                        builder.addLink("program", "/program");
                        
                        sendJsonResponse(exchange, builder.build(), 200);
                    } catch (TransactionException e) {
                        Msg.error(this, "Transaction failed: Update Data", e);
                        sendErrorResponse(exchange, 500, "Failed to update data: " + e.getMessage(), "TRANSACTION_ERROR");
                    } catch (Exception e) {
                        Msg.error(this, "Error during update data operation", e);
                        sendErrorResponse(exchange, 400, "Error updating data: " + e.getMessage(), "INVALID_PARAMETER");
                    }
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (IOException e) {
                Msg.error(this, "Error parsing request parameters for data update", e);
                sendErrorResponse(exchange, 400, "Invalid request body: " + e.getMessage(), "INVALID_REQUEST");
            } catch (Exception e) {
                Msg.error(this, "Unexpected error updating data", e);
                sendErrorResponse(exchange, 500, "Error updating data: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }
    }
