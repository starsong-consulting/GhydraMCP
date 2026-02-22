package eu.starsong.ghidra.endpoints;

    import com.google.gson.JsonObject;
    import com.sun.net.httpserver.HttpExchange;
    import com.sun.net.httpserver.HttpServer;
    import eu.starsong.ghidra.api.ResponseBuilder;
    import eu.starsong.ghidra.util.GhidraUtil;
    import eu.starsong.ghidra.util.HttpUtil;
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
    import ghidra.program.model.symbol.SymbolIterator;
    import ghidra.program.model.symbol.SymbolTable;
    import ghidra.util.Msg;

    import java.io.IOException;
    import java.nio.charset.StandardCharsets;
    import java.util.*;

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
            // Use safeHandler wrapper to catch StackOverflowError and other critical errors
            // that can occur during data/symbol resolution in Ghidra
            server.createContext("/data", HttpUtil.safeHandler(this::handleData, port));
            server.createContext("/data/delete", HttpUtil.safeHandler(exchange -> {
                if ("POST".equals(exchange.getRequestMethod())) {
                    Map<String, String> params = parseJsonPostParams(exchange);
                    handleDeleteData(exchange, params);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed");
                }
            }, port));
            server.createContext("/data/update", HttpUtil.safeHandler(exchange -> {
                if ("POST".equals(exchange.getRequestMethod())) {
                    Map<String, String> params = parseJsonPostParams(exchange);
                    handleUpdateData(exchange, params);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed");
                }
            }, port));
            server.createContext("/data/type", HttpUtil.safeHandler(exchange -> {
                if ("POST".equals(exchange.getRequestMethod()) || "PATCH".equals(exchange.getRequestMethod())) {
                    Map<String, String> params = parseJsonPostParams(exchange);
                    handleTypeChangeData(exchange, params);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed");
                }
            }, port));
            server.createContext("/strings", HttpUtil.safeHandler(exchange -> {
                if ("GET".equals(exchange.getRequestMethod())) {
                    handleListStrings(exchange);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed");
                }
            }, port));
        }

        public void handleData(HttpExchange exchange) throws IOException {
            try {
                String path = exchange.getRequestURI().getPath();
                String method = exchange.getRequestMethod();

                if (path.equals("/data") || path.equals("/data/")) {
                    // Base /data endpoint
                    if ("GET".equals(method)) {
                        handleListData(exchange);
                    } else if ("POST".equals(method)) {
                        // Legacy POST routing for bridge backward compat
                        Map<String, String> params = parseJsonPostParams(exchange);
                        boolean hasNewName = params.containsKey("newName") && params.get("newName") != null && !params.get("newName").isEmpty();
                        boolean hasName = params.containsKey("name") && params.get("name") != null && !params.get("name").isEmpty();
                        boolean hasType = params.containsKey("type") && params.get("type") != null && !params.get("type").isEmpty();

                        if (params.containsKey("address") && hasType) {
                            Program program = getCurrentProgram();
                            if (program != null) {
                                try {
                                    Address addr = resolveAddress(program, params.get("address"), true);
                                    Data data = addr != null ? program.getListing().getDefinedDataAt(addr) : null;
                                    if (addr != null && data == null) {
                                        handleCreateData(exchange, params);
                                        return;
                                    }
                                } catch (Exception e) {
                                    Msg.warn(this, "Error checking for existing data: " + e.getMessage());
                                }
                            }
                        }

                        if (params.containsKey("address") && (hasNewName || hasName) && hasType) {
                            if (hasName && !hasNewName) {
                                params.put("newName", params.get("name"));
                            }
                            handleUpdateData(exchange, params);
                        } else if (params.containsKey("address") && (hasNewName || hasName)) {
                            if (hasName && !hasNewName) {
                                params.put("newName", params.get("name"));
                            }
                            handleRenameData(exchange, params);
                        } else if (params.containsKey("address") && hasType) {
                            handleTypeChangeData(exchange, params);
                        } else {
                            sendErrorResponse(exchange, 400, "Missing required parameters", "MISSING_PARAMETERS");
                        }
                    } else {
                        sendErrorResponse(exchange, 405, "Method Not Allowed");
                    }
                } else {
                    // Path-based routing: /data/{address} or /data/{address}/type
                    String remainder = path.substring("/data/".length());
                    String addressStr;
                    String subResource = null;

                    if (remainder.contains("/")) {
                        int slashIdx = remainder.indexOf('/');
                        addressStr = remainder.substring(0, slashIdx);
                        subResource = remainder.substring(slashIdx + 1);
                    } else {
                        addressStr = remainder;
                    }

                    // URL-decode the address
                    addressStr = java.net.URLDecoder.decode(addressStr, java.nio.charset.StandardCharsets.UTF_8);

                    if ("GET".equals(method)) {
                        // GET /data/{address} - list filtered by address
                        Map<String, String> qparams = parseQueryParams(exchange);
                        qparams.put("addr", addressStr);
                        // Reuse the list handler with the explicit address filter
                        handleListData(exchange, qparams);
                    } else if ("POST".equals(method)) {
                        // POST /data/{address} - create data at address
                        Map<String, String> params = parseJsonPostParams(exchange);
                        params.put("address", addressStr);
                        handleCreateData(exchange, params);
                    } else if ("PATCH".equals(method)) {
                        Map<String, String> params = parseJsonPostParams(exchange);
                        params.put("address", addressStr);

                        if ("type".equals(subResource)) {
                            // PATCH /data/{address}/type
                            handleTypeChangeData(exchange, params);
                        } else {
                            // PATCH /data/{address} - rename
                            // Accept "name" field (CLI convention), map to "newName" for internal use
                            if (params.containsKey("name") && !params.containsKey("newName")) {
                                params.put("newName", params.get("name"));
                            }
                            if (params.containsKey("type")) {
                                handleUpdateData(exchange, params);
                            } else {
                                handleRenameData(exchange, params);
                            }
                        }
                    } else if ("DELETE".equals(method)) {
                        // DELETE /data/{address}
                        Map<String, String> params = new HashMap<>();
                        params.put("address", addressStr);
                        handleDeleteData(exchange, params);
                    } else {
                        sendErrorResponse(exchange, 405, "Method Not Allowed");
                    }
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /data endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
            }
        }

        private void handleListData(HttpExchange exchange) throws IOException {
            handleListData(exchange, parseQueryParams(exchange));
        }

        private void handleListData(HttpExchange exchange, Map<String, String> qparams) throws IOException {
            try {
                int offset = parseIntOrDefault(qparams.get("offset"), 0);
                int limit = parseIntOrDefault(qparams.get("limit"), 100);

                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                    return;
                }

                String addrFilter = qparams.get("addr");
                Address addrFilterAddress = null;
                if (addrFilter != null && !addrFilter.isEmpty()) {
                    try {
                        addrFilterAddress = resolveAddress(program, addrFilter, true);
                        if (addrFilterAddress == null) {
                            throw new IllegalArgumentException("Invalid address format");
                        }
                    } catch (Exception e) {
                        sendErrorResponse(exchange, 400, "Invalid address format: " + addrFilter, "INVALID_PARAMETER");
                        return;
                    }
                }

                String nameFilter = qparams.get("name");
                String nameContainsFilter = qparams.get("name_contains");
                String typeFilter = qparams.get("type");

                List<Map<String, Object>> dataItems = new ArrayList<>();
                Listing listing = program.getListing();

                // Fast path for exact address lookups.
                if (addrFilterAddress != null) {
                    Data data = listing.getDefinedDataAt(addrFilterAddress);
                    if (data != null) {
                        Map<String, Object> item = buildDefinedDataItem(program, data);
                        if (matchesDataListFilters(item, nameFilter, nameContainsFilter, typeFilter)) {
                            dataItems.add(item);
                        }
                    }

                    if (dataItems.isEmpty()) {
                        Symbol symbol = program.getSymbolTable().getPrimarySymbol(addrFilterAddress);
                        Map<String, Object> fallbackItem = buildSymbolFallbackItem(program, addrFilterAddress, symbol);
                        if (fallbackItem != null && matchesDataListFilters(fallbackItem, nameFilter, nameContainsFilter, typeFilter)) {
                            dataItems.add(fallbackItem);
                        }
                    }
                } else if (nameFilter != null && !nameFilter.isEmpty() &&
                           (nameContainsFilter == null || nameContainsFilter.isEmpty())) {
                    // Fast path for exact-name lookups: resolve symbols by exact name instead of scanning all data.
                    SymbolIterator symbolIterator = program.getSymbolTable().getSymbols(nameFilter);
                    Set<String> seenAddresses = new HashSet<>();

                    while (symbolIterator.hasNext()) {
                        Symbol symbol = symbolIterator.next();
                        Address symbolAddress = symbol.getAddress();
                        if (symbolAddress == null) {
                            continue;
                        }
                        String addrKey = symbolAddress.toString();
                        if (!seenAddresses.add(addrKey)) {
                            continue;
                        }

                        Map<String, Object> item = null;
                        Data data = listing.getDefinedDataAt(symbolAddress);
                        if (data != null) {
                            item = buildDefinedDataItem(program, data);
                        } else {
                            item = buildSymbolFallbackItem(program, symbolAddress, symbol);
                        }

                        if (item != null && matchesDataListFilters(item, nameFilter, null, typeFilter)) {
                            dataItems.add(item);
                        }
                    }
                } else {
                    for (MemoryBlock block : program.getMemory().getBlocks()) {
                        DataIterator it = listing.getDefinedData(block.getStart(), true);
                        while (it.hasNext()) {
                            Data data = it.next();
                            if (!block.contains(data.getAddress())) {
                                continue;
                            }

                            Map<String, Object> item = buildDefinedDataItem(program, data);
                            if (!matchesDataListFilters(item, nameFilter, nameContainsFilter, typeFilter)) {
                                continue;
                            }

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

        private Map<String, Object> buildDefinedDataItem(Program program, Data data) {
            Map<String, Object> item = new HashMap<>();
            item.put("address", data.getAddress().toString());
            item.put("name", getDataItemName(program, data));
            item.put("value", data.getDefaultValueRepresentation());
            item.put("dataType", data.getDataType().getName());

            Map<String, Object> links = new HashMap<>();
            Map<String, String> selfLink = new HashMap<>();
            selfLink.put("href", "/data/" + data.getAddress().toString());
            links.put("self", selfLink);
            item.put("_links", links);

            return item;
        }

        private String getDataItemName(Program program, Data data) {
            String label = data.getLabel();
            if (label != null && !label.isEmpty()) {
                return label;
            }

            Symbol symbol = program.getSymbolTable().getPrimarySymbol(data.getAddress());
            if (symbol != null) {
                return safeGetSymbolName(symbol, program);
            }

            return "(unnamed)";
        }

        private Map<String, Object> buildSymbolFallbackItem(Program program, Address address, Symbol symbol) {
            if (symbol == null) {
                return null;
            }

            Map<String, Object> item = new HashMap<>();
            item.put("address", address.toString());
            item.put("name", safeGetSymbolName(symbol, program));
            item.put("value", buildSymbolValuePreview(program, address));
            item.put("dataType", "label");
            item.put("source", "symbol");

            Map<String, Object> links = new HashMap<>();
            Map<String, String> selfLink = new HashMap<>();
            selfLink.put("href", "/data/" + address.toString());
            links.put("self", selfLink);
            item.put("_links", links);

            return item;
        }

        private boolean matchesDataListFilters(Map<String, Object> item, String nameFilter, String nameContainsFilter, String typeFilter) {
            String name = String.valueOf(item.getOrDefault("name", ""));
            String dataType = String.valueOf(item.getOrDefault("dataType", ""));

            if (nameFilter != null && !nameFilter.isEmpty() && !name.equals(nameFilter)) {
                return false;
            }
            if (nameContainsFilter != null && !nameContainsFilter.isEmpty()) {
                String lcName = name.toLowerCase(Locale.ROOT);
                if (!lcName.contains(nameContainsFilter.toLowerCase(Locale.ROOT))) {
                    return false;
                }
            }
            if (typeFilter != null && !typeFilter.isEmpty() && !dataType.equalsIgnoreCase(typeFilter)) {
                return false;
            }

            return true;
        }

        private String buildSymbolValuePreview(Program program, Address address) {
            try {
                if (!program.getMemory().contains(address)) {
                    return "";
                }

                MemoryBlock block = program.getMemory().getBlock(address);
                if (block == null) {
                    return "";
                }

                long available = block.getEnd().subtract(address) + 1;
                if (available <= 0) {
                    return "";
                }

                int bytesToRead = (int) Math.min(available, 32L);
                byte[] bytes = new byte[bytesToRead];
                int bytesRead = program.getMemory().getBytes(address, bytes, 0, bytesToRead);
                if (bytesRead <= 0) {
                    return "";
                }

                int nullTerminatorIndex = -1;
                for (int i = 0; i < bytesRead; i++) {
                    if (bytes[i] == 0) {
                        nullTerminatorIndex = i;
                        break;
                    }
                }

                if (nullTerminatorIndex > 0 && isPrintableAscii(bytes, nullTerminatorIndex)) {
                    return new String(bytes, 0, nullTerminatorIndex, StandardCharsets.UTF_8);
                }

                return "0x" + bytesToHex(bytes, Math.min(bytesRead, 16));
            } catch (Exception e) {
                return "";
            }
        }

        private boolean isPrintableAscii(byte[] bytes, int length) {
            for (int i = 0; i < length; i++) {
                int value = bytes[i] & 0xff;
                if (value < 0x20 || value > 0x7e) {
                    return false;
                }
            }
            return true;
        }

        private String bytesToHex(byte[] bytes, int length) {
            StringBuilder sb = new StringBuilder(length * 2);
            for (int i = 0; i < length; i++) {
                int value = bytes[i] & 0xff;
                if (value < 0x10) {
                    sb.append('0');
                }
                sb.append(Integer.toHexString(value).toUpperCase(Locale.ROOT));
            }
            return sb.toString();
        }

        private void handleRenameData(HttpExchange exchange, Map<String, String> params) throws IOException {
            try {
                final String addressStr = params.get("address");
                // Accept both "name" (RESTful) and "newName" (legacy)
                final String newName = params.containsKey("newName") ? params.get("newName") :
                                       params.containsKey("name") ? params.get("name") : null;
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
                    Map<String, Object> resultMap = new HashMap<>();

                    TransactionHelper.executeInTransaction(program, "Update data at " + addressStr, () -> {
                        Address addr = resolveAddressOrThrow(program, addressStr);
                        Listing listing = program.getListing();

                        resultMap.put("address", addr.toString());
                        if (!addr.toString().equals(addressStr)) {
                            resultMap.put("requestedAddress", addressStr);
                        }

                        ghidra.program.model.data.DataType requestedDataType = null;
                        if (dataTypeStr != null && !dataTypeStr.isEmpty()) {
                            requestedDataType = GhidraUtil.resolveDataType(program, dataTypeStr);
                            if (requestedDataType == null) {
                                throw new Exception("Could not find or parse data type: " + dataTypeStr);
                            }
                        }

                        // Only auto-define data when a type change is requested;
                        // pure rename just edits the label (like Ghidra's Edit Label action)
                        Data data = null;
                        if (requestedDataType != null) {
                            data = ensureDataDefinedAtAddress(
                                program, listing, addr, requestedDataType, addressStr, resultMap);
                        } else {
                            data = listing.getDefinedDataAt(addr);
                        }

                        String currentName = null;
                        Symbol currentSymbol = program.getSymbolTable().getPrimarySymbol(addr);
                        if (currentSymbol != null) {
                            currentName = currentSymbol.getName();
                        }

                        if (data != null && requestedDataType != null && !data.getDataType().isEquivalent(requestedDataType)) {
                            resultMap.put("originalType", data.getDataType().getName());
                            data = applyDataTypeAtAddress(listing, addr, data, requestedDataType, addressStr);
                            resultMap.put("dataType", data.getDataType().getName());
                        } else if (requestedDataType != null && data != null) {
                            resultMap.put("dataType", requestedDataType.getName());
                        }

                        if (newName != null && !newName.isEmpty()) {
                            SymbolTable symTable = program.getSymbolTable();
                            Symbol symbol = symTable.getPrimarySymbol(addr);

                            if (symbol != null) {
                                symbol.setName(newName, SourceType.USER_DEFINED);
                            } else {
                                symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                            }

                            resultMap.put("name", newName);
                            if (currentName != null) {
                                resultMap.put("originalName", currentName);
                            }
                        } else if (currentName != null) {
                            resultMap.put("name", currentName);
                        }

                        return null;
                    });

                    String message;
                    if (newName != null && !newName.isEmpty() && dataTypeStr != null && !dataTypeStr.isEmpty()) {
                        message = "Data renamed and type changed successfully";
                    } else if (newName != null && !newName.isEmpty()) {
                        message = "Data renamed successfully";
                    } else {
                        message = "Data type changed successfully";
                    }
                    resultMap.put("message", message);

                    ResponseBuilder builder = new ResponseBuilder(exchange, port)
                        .success(true)
                        .result(resultMap);

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
        
        /**
         * Handle a data type change request (without renaming)
         */
        public void handleTypeChangeData(HttpExchange exchange, Map<String, String> params) throws IOException {
            handleRenameData(exchange, params);
        }
        
        /**
         * Handle a combined update request (both name and type)
         */
        public void handleUpdateData(HttpExchange exchange, Map<String, String> params) throws IOException {
            if (params.containsKey("name") && !params.containsKey("newName")) {
                params.put("newName", params.get("name"));
            }
            handleRenameData(exchange, params);
        }
        
        // parseIntOrDefault is inherited from AbstractEndpoint
        
        /**
         * Handle a data creation request
         */
        public void handleCreateData(HttpExchange exchange, Map<String, String> params) throws IOException {
            try {
                // Debug - log all parameters
                StringBuilder debugInfo = new StringBuilder("DEBUG handleCreateData - Received parameters: ");
                for (Map.Entry<String, String> entry : params.entrySet()) {
                    debugInfo.append(entry.getKey()).append("=").append(entry.getValue()).append(", ");
                }
                Msg.info(this, debugInfo.toString());
                
                final String addressStr = params.get("address");
                final String dataTypeStr = params.get("type");
                final String sizeStr = params.get("size");
                final String nameStr = params.containsKey("name") ? params.get("name") : params.get("newName");
                
                // Validate required parameters
                if (addressStr == null || addressStr.isEmpty()) {
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
                
                // Parse size if provided
                Integer size = null;
                if (sizeStr != null && !sizeStr.isEmpty()) {
                    try {
                        size = Integer.decode(sizeStr);
                    } catch (NumberFormatException e) {
                        sendErrorResponse(exchange, 400, "Invalid size parameter: must be an integer", "INVALID_PARAMETER");
                        return;
                    }
                }
                
                try {
                    // Create a result map for the response
                    Map<String, Object> resultMap = new HashMap<>();
                    resultMap.put("dataType", dataTypeStr);
                    if (size != null) {
                        resultMap.put("size", size);
                    }
                    
                    final Integer finalSize = size; // Make a final copy for the lambda
                    
                    TransactionHelper.executeInTransaction(program, "Create data at " + addressStr, () -> {
                        // Get the address
                        Address addr = resolveAddressOrThrow(program, addressStr);
                        Listing listing = program.getListing();

                        resultMap.put("address", addr.toString());
                        if (!addr.toString().equals(addressStr)) {
                            resultMap.put("requestedAddress", addressStr);
                        }
                        
                        // Verify no data is already defined at this address
                        Data existingData = listing.getDefinedDataAt(addr);
                        if (existingData != null) {
                            throw new Exception("Data already exists at address: " + addressStr);
                        }
                        
                        // Find the requested data type
                        ghidra.program.model.data.DataType dataType = GhidraUtil.resolveDataType(program, dataTypeStr);
                        if (dataType == null) {
                            throw new Exception("Could not find or parse data type: " + dataTypeStr);
                        }

                        Msg.info(this, "Successfully mapped data type '" + dataTypeStr + "' to Ghidra type: " + dataType.getName());
                        
                        // Create the data at the specified address
                        Data newData;
                        
                        // Make final copy of dataType for use in lambda
                        final ghidra.program.model.data.DataType finalDataType = dataType;
                        
                        if (!program.getMemory().contains(addr)) {
                            throw new Exception(
                                "Address " + addressStr +
                                " is not in any memory block. Valid addresses must be within defined memory blocks.");
                        }

                        Data containing = listing.getDataContaining(addr);
                        if (containing != null && !containing.getAddress().equals(addr)) {
                            throw new Exception(
                                "Address " + addressStr + " is inside existing data item at " +
                                containing.getAddress() + ". Use the data start address instead.");
                        }

                        // Check if there's already existing code or data at this address range.
                        int dataSize = finalSize != null ? finalSize : finalDataType.getLength();
                        if (dataSize <= 0) {
                            dataSize = 1;
                        }

                        Address rangeEnd;
                        try {
                            rangeEnd = addr.add(dataSize - 1);
                        } catch (Exception e) {
                            throw new Exception(
                                "Requested data range exceeds address space bounds at " + addressStr, e);
                        }

                        for (int i = 0; i < dataSize; i++) {
                            Address checkAddr;
                            try {
                                checkAddr = (i == 0) ? addr : addr.add(i);
                            } catch (Exception e) {
                                throw new Exception(
                                    "Requested data range exceeds address space bounds at " + addressStr, e);
                            }

                            if (!program.getMemory().contains(checkAddr)) {
                                throw new Exception(
                                    "Requested data range " + addr + " to " + rangeEnd +
                                    " crosses unmapped memory at " + checkAddr + ".");
                            }

                            if (listing.getInstructionAt(checkAddr) != null) {
                                throw new Exception(
                                    "Conflicting instruction exists at " + checkAddr +
                                    " in range " + addr + " to " + rangeEnd +
                                    ". Use delete_data or clear code first.");
                            }

                            Data existingInRange = listing.getDefinedDataAt(checkAddr);
                            if (existingInRange != null) {
                                throw new Exception(
                                    "Conflicting data exists at " + checkAddr +
                                    " in range " + addr + " to " + rangeEnd +
                                    ". Use update_data or delete_data first.");
                            }
                        }
                        
                        // Now create the data
                        if (finalSize != null) {
                            // For variable length types like strings, need to clear space first
                            if (finalDataType.getLength() <= 0 || finalDataType.getLength() != finalSize) {
                                Msg.info(this, "Creating variable-length data with size: " + finalSize);
                                
                                // For arrays and strings, may need to create custom type
                                if (finalDataType.getName().toLowerCase().contains("string") || 
                                    dataTypeStr.toLowerCase().contains("string")) {
                                    // Create a string data type with specified length
                                    try {
                                        ghidra.program.model.data.StringDataType stringType = new ghidra.program.model.data.StringDataType();
                                        newData = listing.createData(addr, stringType, finalSize);
                                    } catch (Exception e) {
                                        Msg.warn(this, "Couldn't create string data: " + e.getMessage());
                                        // Fallback to byte array
                                        newData = listing.createData(addr, new ghidra.program.model.data.ByteDataType(), finalSize);
                                    }
                                } else {
                                    // For other variable length types, create clear space and then create
                                    newData = listing.createData(addr, finalDataType);
                                }
                            } else {
                                // For fixed size datatypes
                                newData = listing.createData(addr, finalDataType);
                            }
                        } else {
                            // Normal data creation without size
                            newData = listing.createData(addr, finalDataType);
                        }
                        
                        if (newData == null) {
                            throw new Exception("Failed to create data of type " + dataTypeStr + " at " + addressStr);
                        }
                        
                        // Set name if provided
                        if (nameStr != null && !nameStr.isEmpty()) {
                            SymbolTable symTable = program.getSymbolTable();
                            symTable.createLabel(addr, nameStr, SourceType.USER_DEFINED);
                            resultMap.put("name", nameStr);
                        }
                        
                        // Add information about the created data to the result
                        resultMap.put("length", newData.getLength());
                        resultMap.put("value", newData.getDefaultValueRepresentation());
                        
                        return null;
                    });
                    
                    resultMap.put("message", "Data created successfully");
                    
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
                    Msg.error(this, "Transaction failed: Create Data", e);
                    sendErrorResponse(exchange, 500, "Failed to create data: " + e.getMessage(), "TRANSACTION_ERROR");
                } catch (Exception e) {
                    Msg.error(this, "Error during data creation", e);
                    sendErrorResponse(exchange, 400, "Error creating data: " + e.getMessage(), "INVALID_PARAMETER");
                }
            } catch (Exception e) {
                Msg.error(this, "Unexpected error creating data", e);
                sendErrorResponse(exchange, 500, "Error creating data: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }
        
        public void handleSetDataType(HttpExchange exchange) throws IOException {
            if (!"PATCH".equals(exchange.getRequestMethod()) && !"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                return;
            }
            Map<String, String> params = parseJsonPostParams(exchange);
            handleTypeChangeData(exchange, params);
        }
        
        /**
         * Handle a delete data request
         */
        public void handleDeleteData(HttpExchange exchange, Map<String, String> params) throws IOException {
            try {
                // Debug - log all parameters
                StringBuilder debugInfo = new StringBuilder("DEBUG handleDeleteData - Received parameters: ");
                for (Map.Entry<String, String> entry : params.entrySet()) {
                    debugInfo.append(entry.getKey()).append("=").append(entry.getValue()).append(", ");
                }
                Msg.info(this, debugInfo.toString());
                
                final String addressStr = params.get("address");
                
                // Validate required parameters
                if (addressStr == null || addressStr.isEmpty()) {
                    sendErrorResponse(exchange, 400, "Missing required parameter: address", "MISSING_PARAMETERS");
                    return;
                }
                
                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                    return;
                }
                
                try {
                    // Create a result map for the response
                    Map<String, Object> resultMap = new HashMap<>();
                    
                    TransactionHelper.executeInTransaction(program, "Delete data at " + addressStr, () -> {
                        // Get the address
                        Address addr = resolveAddressOrThrow(program, addressStr);
                        Listing listing = program.getListing();

                        resultMap.put("address", addr.toString());
                        if (!addr.toString().equals(addressStr)) {
                            resultMap.put("requestedAddress", addressStr);
                        }
                        
                        // Check if there's data at the address
                        Data existingData = listing.getDefinedDataAt(addr);
                        if (existingData == null) {
                            // Check if there's an instruction
                            if (listing.getInstructionAt(addr) != null) {
                                // Clear the instruction
                                listing.clearCodeUnits(addr, addr, true);
                                resultMap.put("cleared", "instruction");
                            } else {
                                // No data or instruction, but still treat as success
                                resultMap.put("message", "No data or instruction exists at address: " + addressStr);
                                resultMap.put("cleared", "none");
                            }
                        } else {
                            // Remember what we're deleting
                            resultMap.put("original_type", existingData.getDataType().getName());
                            resultMap.put("length", existingData.getLength());
                            
                            // Get the name if any
                            Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
                            if (symbol != null) {
                                resultMap.put("original_name", symbol.getName());
                            }
                            
                            // Clear the data
                            listing.clearCodeUnits(addr, addr.add(existingData.getLength() - 1), true);
                            resultMap.put("cleared", "data");
                        }
                        
                        return null;
                    });
                    
                    resultMap.put("message", "Data deleted successfully");
                    
                    // Build HATEOAS response
                    eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                        .success(true)
                        .result(resultMap);
                    
                    // Add relevant links
                    builder.addLink("data", "/data");
                    builder.addLink("program", "/program");
                    
                    sendJsonResponse(exchange, builder.build(), 200);
                } catch (TransactionException e) {
                    Msg.error(this, "Transaction failed: Delete Data", e);
                    sendErrorResponse(exchange, 500, "Failed to delete data: " + e.getMessage(), "TRANSACTION_ERROR");
                } catch (Exception e) {
                    Msg.error(this, "Error during data deletion", e);
                    sendErrorResponse(exchange, 400, "Error deleting data: " + e.getMessage(), "INVALID_PARAMETER");
                }
            } catch (Exception e) {
                Msg.error(this, "Unexpected error deleting data", e);
                sendErrorResponse(exchange, 500, "Error deleting data: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }

        private Address resolveAddressOrThrow(Program program, String addressStr) throws Exception {
            Address addr = resolveAddress(program, addressStr, true);
            if (addr == null) {
                throw new Exception("Invalid address format: " + addressStr);
            }
            return addr;
        }

        private Data ensureDataDefinedAtAddress(
            Program program,
            Listing listing,
            Address addr,
            ghidra.program.model.data.DataType preferredType,
            String requestedAddress,
            Map<String, Object> resultMap) throws Exception {

            Data data = listing.getDefinedDataAt(addr);
            if (data != null) {
                return data;
            }

            Data containing = listing.getDataContaining(addr);
            if (containing != null && !containing.getAddress().equals(addr)) {
                throw new Exception(
                    "Address " + requestedAddress + " is inside existing data item at " +
                    containing.getAddress() + ". Use the data start address instead.");
            }

            if (!program.getMemory().contains(addr)) {
                throw new Exception("Address not mapped in memory: " + requestedAddress);
            }

            if (listing.getInstructionAt(addr) != null) {
                throw new Exception(
                    "Instruction exists at address " + addr +
                    ". Clear code first before defining data.");
            }

            ghidra.program.model.data.DataType typeToCreate =
                preferredType != null ? preferredType : new ghidra.program.model.data.ByteDataType();
            if (typeToCreate.getLength() <= 0) {
                throw new Exception(
                    "Cannot auto-define variable-length type '" + typeToCreate.getName() +
                    "' at " + requestedAddress + ". Use data_create with an explicit size.");
            }

            Data created = listing.createData(addr, typeToCreate);
            if (created == null) {
                throw new Exception("Failed to auto-define data at address: " + requestedAddress);
            }

            resultMap.put("autoDefined", true);
            resultMap.put("autoDefinedType", created.getDataType().getName());
            return created;
        }

        private Data applyDataTypeAtAddress(
            Listing listing,
            Address addr,
            Data existingData,
            ghidra.program.model.data.DataType dataType,
            String requestedAddress) throws Exception {

            int oldLength = existingData != null ? existingData.getLength() : 1;
            int newLength = dataType.getLength();
            int lengthToClear = oldLength;
            if (newLength > 0) {
                lengthToClear = Math.max(oldLength, newLength);
            }

            listing.clearCodeUnits(addr, addr.add(Math.max(1, lengthToClear) - 1), false);
            Data newData = listing.createData(addr, dataType);
            if (newData == null) {
                throw new Exception("Failed to apply data type " + dataType.getName() + " at " + requestedAddress);
            }
            return newData;
        }
        
        /**
         * Handle request to list strings in the binary
         * @param exchange The HTTP exchange
         * @throws IOException If an I/O error occurs
         */
        public void handleListStrings(HttpExchange exchange) throws IOException {
            try {
                Map<String, String> qparams = parseQueryParams(exchange);
                int offset = parseIntOrDefault(qparams.get("offset"), 0);
                int limit = parseIntOrDefault(qparams.get("limit"), 2000);
                String filter = qparams.get("filter");
                
                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                    return;
                }
                
                List<Map<String, Object>> strings = new ArrayList<>();

                for (MemoryBlock block : program.getMemory().getBlocks()) {
                    if (!block.isInitialized()) continue;

                    DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
                    while (it.hasNext()) {
                        Data data = it.next();
                        if (!block.contains(data.getAddress())) continue;

                        // Check if the data type is a string type
                        String dataTypeName = data.getDataType().getName().toLowerCase();
                        boolean isString = dataTypeName.contains("string") ||
                                          dataTypeName.contains("unicode") ||
                                          (dataTypeName.contains("char") && data.getLength() > 1); // Array of chars

                        if (isString) {
                            String value = data.getDefaultValueRepresentation();
                            if (value == null) value = "";

                            if (filter != null && !filter.isEmpty() && !value.toLowerCase().contains(filter.toLowerCase())) {
                                continue;
                            }

                            Map<String, Object> stringInfo = new HashMap<>();
                            stringInfo.put("address", data.getAddress().toString());
                            stringInfo.put("value", value);
                            stringInfo.put("length", data.getLength());
                            stringInfo.put("type", data.getDataType().getName());

                            String name = null;
                            Symbol symbol = program.getSymbolTable().getPrimarySymbol(data.getAddress());
                            if (symbol != null) {
                                name = safeGetSymbolName(symbol, program);
                            }
                            stringInfo.put("name", name != null ? name : "");

                            // Add HATEOAS links
                            Map<String, Object> links = new HashMap<>();
                            Map<String, String> selfLink = new HashMap<>();
                            selfLink.put("href", "/data/" + data.getAddress().toString());
                            links.put("self", selfLink);

                            Map<String, String> memoryLink = new HashMap<>();
                            memoryLink.put("href", "/memory?address=" + data.getAddress().toString());
                            links.put("memory", memoryLink);

                            stringInfo.put("_links", links);

                            strings.add(stringInfo);
                        }
                    }
                }
                
                // Build response with HATEOAS links
                eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                    .success(true);
                
                // Apply pagination and get paginated items
                List<Map<String, Object>> paginated = applyPagination(strings, offset, limit, builder, "/strings");
                
                // Set the paginated result
                builder.result(paginated);
                
                // Add program link
                builder.addLink("program", "/program");
                builder.addLink("data", "/data");
                
                sendJsonResponse(exchange, builder.build(), 200);
            } catch (Exception e) {
                Msg.error(this, "Error listing strings", e);
                sendErrorResponse(exchange, 500, "Error listing strings: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }
    }
