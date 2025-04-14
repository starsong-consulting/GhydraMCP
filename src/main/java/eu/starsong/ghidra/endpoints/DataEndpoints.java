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
            server.createContext("/data/update", exchange -> {
                try {
                    if ("POST".equals(exchange.getRequestMethod())) {
                        Map<String, String> params = parseJsonPostParams(exchange);
                        handleUpdateData(exchange, params);
                    } else {
                        sendErrorResponse(exchange, 405, "Method Not Allowed");
                    }
                } catch (Exception e) {
                    Msg.error(this, "Error in /data/update endpoint", e);
                    sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
                }
            });
            server.createContext("/data/type", exchange -> {
                try {
                    if ("POST".equals(exchange.getRequestMethod()) || "PATCH".equals(exchange.getRequestMethod())) {
                        Map<String, String> params = parseJsonPostParams(exchange);
                        handleTypeChangeData(exchange, params);
                    } else {
                        sendErrorResponse(exchange, 405, "Method Not Allowed");
                    }
                } catch (Exception e) {
                    Msg.error(this, "Error in /data/type endpoint", e);
                    sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
                }
            });
        }

        public void handleData(HttpExchange exchange) throws IOException {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    handleListData(exchange);
                } else if ("POST".equals(exchange.getRequestMethod())) {
                    // Determine what kind of operation this is based on parameters
                    Map<String, String> params = parseJsonPostParams(exchange);
                    // Debug - log the params
                    StringBuilder debugInfo = new StringBuilder("DEBUG - Received parameters: ");
                    for (Map.Entry<String, String> entry : params.entrySet()) {
                        debugInfo.append(entry.getKey()).append("=").append(entry.getValue()).append(", ");
                    }
                    Msg.info(this, debugInfo.toString());
                    
                    boolean hasNewName = params.containsKey("newName") && params.get("newName") != null && !params.get("newName").isEmpty();
                    boolean hasType = params.containsKey("type") && params.get("type") != null && !params.get("type").isEmpty();
                    
                    // Add more detailed debugging
                    Msg.info(this, "Decision logic: hasNewName=" + hasNewName + ", hasType=" + hasType);
                    Msg.info(this, "Raw newName value: " + params.get("newName"));
                    Msg.info(this, "Raw type value: " + params.get("type"));
                    Msg.info(this, "Raw address value: " + params.get("address"));
                    
                    // Let's go ahead and call handleUpdateData (since we know we have both params)
                    if (params.containsKey("address") && hasNewName && hasType) {
                        Msg.info(this, "Selected route: handleUpdateData - both name and type");
                        handleUpdateData(exchange, params);
                    } else if (params.containsKey("address") && hasNewName) {
                        Msg.info(this, "Selected route: handleRenameData - only name");
                        handleRenameData(exchange, params);
                    } else if (params.containsKey("address") && hasType) {
                        Msg.info(this, "Selected route: handleTypeChangeData - only type");
                        handleTypeChangeData(exchange, params);
                    } else {
                        Msg.info(this, "Selected route: Error - missing parameters");
                        // Neither parameter was provided
                        sendErrorResponse(exchange, 400, "Missing required parameters: at least one of newName or type must be provided", "MISSING_PARAMETERS");
                    }
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

        private void handleRenameData(HttpExchange exchange, Map<String, String> params) throws IOException {
            try {
                // Debug - log the params again
                StringBuilder debugInfo = new StringBuilder("DEBUG handleRenameData - Received parameters: ");
                for (Map.Entry<String, String> entry : params.entrySet()) {
                    debugInfo.append(entry.getKey()).append("=").append(entry.getValue()).append(", ");
                }
                Msg.info(this, debugInfo.toString());
                
                final String addressStr = params.get("address");
                final String newName = params.get("newName");
                final String dataTypeStr = params.get("type");
                
                // Address is always required
                if (addressStr == null || addressStr.isEmpty()) {
                    sendErrorResponse(exchange, 400, "Missing required parameter: address", "MISSING_PARAMETERS");
                    return;
                }
                
                // Either newName or type or both must be provided
                if ((newName == null || newName.isEmpty()) && (dataTypeStr == null || dataTypeStr.isEmpty())) {
                    sendErrorResponse(exchange, 400, "At least one of newName or type must be provided", "MISSING_PARAMETERS");
                    return;
                }

                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                    return;
                }

                try {
                    // Create a result map to collect operation results
                    Map<String, Object> resultMap = new HashMap<>();
                    resultMap.put("address", addressStr);
                    
                    TransactionHelper.executeInTransaction(program, "Update Data", () -> {
                        // Get the data at the address first
                        Address addr = program.getAddressFactory().getAddress(addressStr);
                        Listing listing = program.getListing();
                        Data data = listing.getDefinedDataAt(addr);
                        
                        if (data == null) {
                            throw new Exception("No defined data found at address: " + addressStr);
                        }
                        
                        // Get current data info for operations that need it
                        String currentName = null;
                        if (data.getLabel() != null) {
                            currentName = data.getLabel();
                        } else {
                            Symbol sym = program.getSymbolTable().getPrimarySymbol(addr);
                            if (sym != null) {
                                currentName = sym.getName();
                            }
                        }
                        
                        // If we need to set a data type
                        if (dataTypeStr != null && !dataTypeStr.isEmpty()) {
                            // Find the data type
                            ghidra.program.model.data.DataType dataType = null;
                            
                            // First try built-in types
                            dataType = program.getDataTypeManager().getDataType("/" + dataTypeStr);
                            
                            // If not found, try to find it without path
                            if (dataType == null) {
                                dataType = program.getDataTypeManager().findDataType("/" + dataTypeStr);
                            }
                            
                            // If still null, try using the parser
                            if (dataType == null) {
                                try {
                                    ghidra.app.util.parser.FunctionSignatureParser parser = 
                                        new ghidra.app.util.parser.FunctionSignatureParser(program.getDataTypeManager(), null);
                                    dataType = parser.parse(null, dataTypeStr);
                                } catch (Exception e) {
                                    Msg.debug(this, "Function signature parser failed: " + e.getMessage());
                                }
                            }
                            
                            if (dataType == null) {
                                throw new Exception("Could not find or parse data type: " + dataTypeStr);
                            }
                            
                            // Apply the data type
                            try {
                                // Clear any existing data first
                                listing.clearCodeUnits(addr, addr.add(data.getLength() - 1), false);
                                
                                // Create new data with the type
                                Data newData = listing.createData(addr, dataType);
                                if (newData == null) {
                                    throw new Exception("Failed to apply data type " + dataTypeStr + " at " + addressStr);
                                }
                                
                                // Capture info for response
                                resultMap.put("dataType", dataTypeStr);
                                resultMap.put("originalType", data.getDataType().getName());
                                
                                // Update our reference to the data
                                data = newData;
                            } catch (Exception e) {
                                throw new Exception("Error applying data type: " + e.getMessage(), e);
                            }
                        }
                        
                        // Handle renaming if needed
                        if (newName != null && !newName.isEmpty()) {
                            SymbolTable symTable = program.getSymbolTable();
                            Symbol symbol = symTable.getPrimarySymbol(addr);
                            
                            if (symbol != null) {
                                symbol.setName(newName, SourceType.USER_DEFINED);
                            } else {
                                // Create a new label if no primary symbol exists
                                symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                            }
                            
                            resultMap.put("name", newName);
                            if (currentName != null) {
                                resultMap.put("originalName", currentName);
                            }
                        } else if (currentName != null) {
                            // If we didn't rename but have a name from data type change, preserve it
                            SymbolTable symTable = program.getSymbolTable();
                            Symbol symbol = symTable.getPrimarySymbol(addr);
                            
                            if (symbol == null || !symbol.getName().equals(currentName)) {
                                if (symbol != null) {
                                    symbol.setName(currentName, SourceType.USER_DEFINED);
                                } else {
                                    symTable.createLabel(addr, currentName, SourceType.USER_DEFINED);
                                }
                            }
                            
                            resultMap.put("name", currentName);
                        }
                        
                        return null; // Return null for void operation
                    });
                    
                    // Add a meaningful message
                    String message;
                    if (newName != null && !newName.isEmpty() && dataTypeStr != null && !dataTypeStr.isEmpty()) {
                        message = "Data renamed and type changed successfully";
                    } else if (newName != null && !newName.isEmpty()) {
                        message = "Data renamed successfully";
                    } else {
                        message = "Data type changed successfully";
                    }
                    resultMap.put("message", message);
                    
                    // Build HATEOAS response
                    eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                        .success(true)
                        .result(resultMap);
                    
                    // Add relevant links
                    builder.addLink("self", "/data/" + addressStr);
                    builder.addLink("data", "/data");
                    builder.addLink("program", "/program");
                    
                    sendJsonResponse(exchange, builder.build(), 200);
                } catch (TransactionException e) {
                    Msg.error(this, "Transaction failed: Update Data", e);
                    sendErrorResponse(exchange, 500, "Failed to update data: " + e.getMessage(), "TRANSACTION_ERROR");
                } catch (Exception e) { // Catch potential AddressFormatException or other issues
                    Msg.error(this, "Error during data update operation", e);
                    sendErrorResponse(exchange, 400, "Error updating data: " + e.getMessage(), "INVALID_PARAMETER");
                }
            } catch (IOException e) {
                Msg.error(this, "Error parsing POST params for data update", e);
                sendErrorResponse(exchange, 400, "Invalid request body: " + e.getMessage(), "INVALID_REQUEST");
            } catch (Exception e) { // Catch unexpected errors
                Msg.error(this, "Unexpected error updating data", e);
                sendErrorResponse(exchange, 500, "Error updating data: " + e.getMessage(), "INTERNAL_ERROR");
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
        
        /**
         * Handle a data type change request (without renaming)
         */
        public void handleTypeChangeData(HttpExchange exchange, Map<String, String> params) throws IOException {
            try {
                // Debug - log all parameters received by this method
                StringBuilder debugInfo = new StringBuilder("DEBUG handleTypeChangeData - Received parameters: ");
                for (Map.Entry<String, String> entry : params.entrySet()) {
                    debugInfo.append(entry.getKey()).append("=").append(entry.getValue()).append(", ");
                }
                Msg.info(this, debugInfo.toString());
                
                final String addressStr = params.get("address");
                final String dataTypeStr = params.get("type");
                
                Msg.info(this, "handleTypeChangeData - extracted parameters: address=" + addressStr + 
                               ", type=" + dataTypeStr);
                
                if (addressStr == null || addressStr.isEmpty()) {
                    Msg.info(this, "handleTypeChangeData - Missing required parameter: address");
                    sendErrorResponse(exchange, 400, "Missing required parameter: address", "MISSING_PARAMETERS");
                    return;
                }
                
                if (dataTypeStr == null || dataTypeStr.isEmpty()) {
                    sendErrorResponse(exchange, 400, "Missing required parameter: type", "MISSING_PARAMETERS");
                    return;
                }
                
                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                    return;
                }
                
                try {
                    // Create a result map to collect operation results
                    Map<String, Object> resultMap = new HashMap<>();
                    resultMap.put("address", addressStr);
                    resultMap.put("dataType", dataTypeStr);
                    
                    TransactionHelper.executeInTransaction(program, "Change Data Type", () -> {
                        // Get the data at the address first
                        Address addr = program.getAddressFactory().getAddress(addressStr);
                        Listing listing = program.getListing();
                        Data data = listing.getDefinedDataAt(addr);
                        
                        if (data == null) {
                            throw new Exception("No defined data found at address: " + addressStr);
                        }
                        
                        // Get current name to preserve after type change
                        String currentName = null;
                        Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
                        if (symbol != null) {
                            currentName = symbol.getName();
                            resultMap.put("originalName", currentName);
                        }
                        
                        // Remember original data type
                        String originalType = data.getDataType().getName();
                        resultMap.put("originalType", originalType);
                        
                        // Find the requested data type
                        ghidra.program.model.data.DataType dataType = null;
                        
                        // First try built-in types
                        dataType = program.getDataTypeManager().getDataType("/" + dataTypeStr);
                        
                        // If not found, try to find it without path
                        if (dataType == null) {
                            dataType = program.getDataTypeManager().findDataType("/" + dataTypeStr);
                        }
                        
                        // If still null, try using the parser
                        if (dataType == null) {
                            try {
                                ghidra.app.util.parser.FunctionSignatureParser parser = 
                                    new ghidra.app.util.parser.FunctionSignatureParser(program.getDataTypeManager(), null);
                                dataType = parser.parse(null, dataTypeStr);
                            } catch (Exception e) {
                                Msg.debug(this, "Function signature parser failed: " + e.getMessage());
                            }
                        }
                        
                        if (dataType == null) {
                            throw new Exception("Could not find or parse data type: " + dataTypeStr);
                        }
                        
                        // Clear existing data
                        int length = data.getLength();
                        listing.clearCodeUnits(addr, addr.add(length - 1), false);
                        
                        // Create new data
                        Data newData = listing.createData(addr, dataType);
                        if (newData == null) {
                            throw new Exception("Failed to create data with type " + dataTypeStr);
                        }
                        
                        // Preserve the original name
                        if (currentName != null) {
                            SymbolTable symTable = program.getSymbolTable();
                            symTable.createLabel(addr, currentName, SourceType.USER_DEFINED);
                            resultMap.put("name", currentName);
                        }
                        
                        return null;
                    });
                    
                    resultMap.put("message", "Data type changed successfully");
                    
                    // Build HATEOAS response
                    eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                        .success(true)
                        .result(resultMap);
                    
                    // Add relevant links
                    builder.addLink("self", "/data/" + addressStr);
                    builder.addLink("data", "/data");
                    builder.addLink("program", "/program");
                    
                    sendJsonResponse(exchange, builder.build(), 200);
                } catch (TransactionException e) {
                    Msg.error(this, "Transaction failed: Change Data Type", e);
                    sendErrorResponse(exchange, 500, "Failed to change data type: " + e.getMessage(), "TRANSACTION_ERROR");
                } catch (Exception e) {
                    Msg.error(this, "Error changing data type", e);
                    sendErrorResponse(exchange, 400, "Error changing data type: " + e.getMessage(), "INVALID_PARAMETER");
                }
            } catch (IOException e) {
                Msg.error(this, "Error parsing POST params for data type change", e);
                sendErrorResponse(exchange, 400, "Invalid request body: " + e.getMessage(), "INVALID_REQUEST");
            } catch (Exception e) {
                Msg.error(this, "Unexpected error changing data type", e);
                sendErrorResponse(exchange, 500, "Error changing data type: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }
        
        /**
         * Handle a combined update request (both name and type)
         */
        public void handleUpdateData(HttpExchange exchange, Map<String, String> params) throws IOException {
            try {
                // Debug - log all parameters received by this method
                StringBuilder debugInfo = new StringBuilder("DEBUG handleUpdateData - Received parameters: ");
                for (Map.Entry<String, String> entry : params.entrySet()) {
                    debugInfo.append(entry.getKey()).append("=").append(entry.getValue()).append(", ");
                }
                Msg.info(this, debugInfo.toString());
                
                final String addressStr = params.get("address");
                final String newName = params.get("newName");
                final String dataTypeStr = params.get("type");
                
                Msg.info(this, "handleUpdateData - extracted parameters: address=" + addressStr + 
                               ", newName=" + newName + ", type=" + dataTypeStr);
                
                if (addressStr == null || addressStr.isEmpty()) {
                    Msg.info(this, "handleUpdateData - Missing required parameter: address");
                    sendErrorResponse(exchange, 400, "Missing required parameter: address", "MISSING_PARAMETERS");
                    return;
                }
                
                if ((newName == null || newName.isEmpty()) && (dataTypeStr == null || dataTypeStr.isEmpty())) {
                    sendErrorResponse(exchange, 400, "Missing required parameters: at least one of newName or type must be provided", "MISSING_PARAMETERS");
                    return;
                }
                
                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                    return;
                }
                
                try {
                    // Create a result map to collect operation results
                    Map<String, Object> resultMap = new HashMap<>();
                    resultMap.put("address", addressStr);
                    
                    TransactionHelper.executeInTransaction(program, "Update Data", () -> {
                        // Get the data at the address first
                        Address addr = program.getAddressFactory().getAddress(addressStr);
                        Listing listing = program.getListing();
                        Data data = listing.getDefinedDataAt(addr);
                        
                        if (data == null) {
                            throw new Exception("No defined data found at address: " + addressStr);
                        }
                        
                        // Get current name
                        String currentName = null;
                        Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
                        if (symbol != null) {
                            currentName = symbol.getName();
                            resultMap.put("originalName", currentName);
                        }
                        
                        // Handle type change if requested
                        if (dataTypeStr != null && !dataTypeStr.isEmpty()) {
                            // Remember original type
                            String originalType = data.getDataType().getName();
                            resultMap.put("originalType", originalType);
                            
                            // Find the data type
                            ghidra.program.model.data.DataType dataType = null;
                            
                            // First try built-in types
                            dataType = program.getDataTypeManager().getDataType("/" + dataTypeStr);
                            
                            // If not found, try to find it without path
                            if (dataType == null) {
                                dataType = program.getDataTypeManager().findDataType("/" + dataTypeStr);
                            }
                            
                            // If still null, try using the parser
                            if (dataType == null) {
                                try {
                                    ghidra.app.util.parser.FunctionSignatureParser parser = 
                                        new ghidra.app.util.parser.FunctionSignatureParser(program.getDataTypeManager(), null);
                                    dataType = parser.parse(null, dataTypeStr);
                                } catch (Exception e) {
                                    Msg.debug(this, "Function signature parser failed: " + e.getMessage());
                                }
                            }
                            
                            if (dataType == null) {
                                throw new Exception("Could not find or parse data type: " + dataTypeStr);
                            }
                            
                            // Apply the data type
                            try {
                                // Clear existing data
                                int length = data.getLength();
                                listing.clearCodeUnits(addr, addr.add(length - 1), false);
                                
                                // Create new data with the type
                                Data newData = listing.createData(addr, dataType);
                                if (newData == null) {
                                    throw new Exception("Failed to create data with type " + dataTypeStr);
                                }
                                
                                resultMap.put("dataType", dataTypeStr);
                                
                                // Update our reference to the data
                                data = newData;
                            } catch (Exception e) {
                                throw new Exception("Error applying data type: " + e.getMessage(), e);
                            }
                        }
                        
                        // Handle rename if requested
                        if (newName != null && !newName.isEmpty()) {
                            SymbolTable symTable = program.getSymbolTable();
                            Symbol currentSymbol = symTable.getPrimarySymbol(addr);
                            
                            if (currentSymbol != null) {
                                currentSymbol.setName(newName, SourceType.USER_DEFINED);
                            } else {
                                // Create a new label if no primary symbol exists
                                symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                            }
                            
                            resultMap.put("name", newName);
                        } else if (currentName != null) {
                            // If we didn't rename but need to preserve name after type change
                            SymbolTable symTable = program.getSymbolTable();
                            Symbol currentSymbol = symTable.getPrimarySymbol(addr);
                            
                            if (currentSymbol == null) {
                                symTable.createLabel(addr, currentName, SourceType.USER_DEFINED);
                            }
                            
                            resultMap.put("name", currentName);
                        }
                        
                        return null;
                    });
                    
                    // Add a meaningful message
                    String message;
                    if (newName != null && !newName.isEmpty() && dataTypeStr != null && !dataTypeStr.isEmpty()) {
                        message = "Data renamed and type changed successfully";
                    } else if (newName != null && !newName.isEmpty()) {
                        message = "Data renamed successfully";
                    } else {
                        message = "Data type changed successfully";
                    }
                    resultMap.put("message", message);
                    
                    // Build HATEOAS response
                    eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                        .success(true)
                        .result(resultMap);
                    
                    // Add relevant links
                    builder.addLink("self", "/data/" + addressStr);
                    builder.addLink("data", "/data");
                    builder.addLink("program", "/program");
                    
                    sendJsonResponse(exchange, builder.build(), 200);
                } catch (TransactionException e) {
                    Msg.error(this, "Transaction failed: Update Data", e);
                    sendErrorResponse(exchange, 500, "Failed to update data: " + e.getMessage(), "TRANSACTION_ERROR");
                } catch (Exception e) {
                    Msg.error(this, "Error during data update operation", e);
                    sendErrorResponse(exchange, 400, "Error updating data: " + e.getMessage(), "INVALID_PARAMETER");
                }
            } catch (IOException e) {
                Msg.error(this, "Error parsing POST params for data update", e);
                sendErrorResponse(exchange, 400, "Invalid request body: " + e.getMessage(), "INVALID_REQUEST");
            } catch (Exception e) {
                Msg.error(this, "Unexpected error updating data", e);
                sendErrorResponse(exchange, 500, "Error updating data: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }
        
        // parseIntOrDefault is inherited from AbstractEndpoint
        
        public void handleSetDataType(HttpExchange exchange) throws IOException {
            try {
                if ("PATCH".equals(exchange.getRequestMethod()) || "POST".equals(exchange.getRequestMethod())) {
                    Map<String, String> params = parseJsonPostParams(exchange);
                    
                    // Debug - log all parameters received by this method
                    StringBuilder debugInfo = new StringBuilder("DEBUG handleSetDataType - Received parameters: ");
                    for (Map.Entry<String, String> entry : params.entrySet()) {
                        debugInfo.append(entry.getKey()).append("=").append(entry.getValue()).append(", ");
                    }
                    Msg.info(this, debugInfo.toString());
                    
                    final String addressStr = params.get("address");
                    final String dataTypeStr = params.get("type");
                    
                    if (addressStr == null || addressStr.isEmpty() || dataTypeStr == null || dataTypeStr.isEmpty()) {
                        sendErrorResponse(exchange, 400, 
                            "Missing required parameters: address and type must be provided", 
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
                        result.put("type", dataTypeStr);
                        
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
        
        // Note: The handleUpdateData method is already defined earlier in this file at line 477
    }
