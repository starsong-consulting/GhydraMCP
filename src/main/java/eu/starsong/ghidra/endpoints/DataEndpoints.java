package eu.starsong.ghidra.endpoints;

    import com.google.gson.JsonObject;
    import com.sun.net.httpserver.HttpExchange;
    import com.sun.net.httpserver.HttpServer;
    import eu.starsong.ghidra.util.TransactionHelper;
    import eu.starsong.ghidra.util.TransactionHelper.TransactionException;
    import ghidra.program.model.address.Address;
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

        // Updated constructor to accept port
        public DataEndpoints(Program program, int port) {
            super(program, port); // Call super constructor
        }

        @Override
        public void registerEndpoints(HttpServer server) {
            server.createContext("/data", this::handleData);
        }

        private void handleData(HttpExchange exchange) throws IOException {
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
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0); // Inherited
            int limit = parseIntOrDefault(qparams.get("limit"), 100); // Inherited
            Object resultData = listDefinedData(offset, limit);
            // Check if helper returned an error object
            if (resultData instanceof JsonObject && !((JsonObject)resultData).get("success").getAsBoolean()) {
                 sendJsonResponse(exchange, (JsonObject)resultData, 400); // Use base sendJsonResponse
            } else {
                 sendSuccessResponse(exchange, resultData); // Use success helper
            }
        }

        private void handleRenameData(HttpExchange exchange) throws IOException {
             try {
                Map<String, String> params = parseJsonPostParams(exchange);
                final String addressStr = params.get("address");
                final String newName = params.get("newName");

                if (addressStr == null || addressStr.isEmpty() || newName == null || newName.isEmpty()) {
                    sendErrorResponse(exchange, 400, "Missing required parameters: address, newName"); // Inherited
                    return;
                }

                if (currentProgram == null) {
                     sendErrorResponse(exchange, 400, "No program loaded"); // Inherited
                     return;
                }

                try {
                    TransactionHelper.executeInTransaction(currentProgram, "Rename Data", () -> {
                        if (!renameDataAtAddress(addressStr, newName)) {
                            throw new Exception("Rename data operation failed internally.");
                        }
                        return null; // Return null for void operation
                    });
                    // Use sendSuccessResponse for consistency
                    sendSuccessResponse(exchange, Map.of("message", "Data renamed successfully")); 
                } catch (TransactionException e) {
                     Msg.error(this, "Transaction failed: Rename Data", e);
                     // Use inherited sendErrorResponse
                     sendErrorResponse(exchange, 500, "Failed to rename data: " + e.getMessage(), "TRANSACTION_ERROR"); 
                } catch (Exception e) { // Catch potential AddressFormatException or other issues
                     Msg.error(this, "Error during rename data operation", e);
                     // Use inherited sendErrorResponse
                     sendErrorResponse(exchange, 400, "Error renaming data: " + e.getMessage(), "INVALID_PARAMETER"); 
                }

            } catch (IOException e) {
                 Msg.error(this, "Error parsing POST params for data rename", e);
                 sendErrorResponse(exchange, 400, "Invalid request body: " + e.getMessage(), "INVALID_REQUEST"); // Inherited
            } catch (Exception e) { // Catch unexpected errors
                 Msg.error(this, "Unexpected error renaming data", e);
                 sendErrorResponse(exchange, 500, "Error renaming data: " + e.getMessage(), "INTERNAL_ERROR"); // Inherited
            }
        }


        // --- Methods moved from GhydraMCPPlugin ---

        private JsonObject listDefinedData(int offset, int limit) {
            if (currentProgram == null) {
                return createErrorResponse("No program loaded", 400);
            }

            List<Map<String, String>> dataItems = new ArrayList<>();
            for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
                DataIterator it = currentProgram.getListing().getDefinedData(block.getStart(), true);
                while (it.hasNext()) {
                    Data data = it.next();
                    if (block.contains(data.getAddress())) {
                        Map<String, String> item = new HashMap<>();
                        item.put("address", data.getAddress().toString());
                        item.put("label", data.getLabel() != null ? data.getLabel() : "(unnamed)");
                        item.put("value", data.getDefaultValueRepresentation());
                        item.put("dataType", data.getDataType().getName());
                        dataItems.add(item);
                    }
                }
            }

            // Apply pagination
            int start = Math.max(0, offset);
            int end = Math.min(dataItems.size(), offset + limit);
            List<Map<String, String>> paginated = dataItems.subList(start, end);

            return createSuccessResponse(paginated);
        }

        private boolean renameDataAtAddress(String addressStr, String newName) throws Exception {
            // This method now throws Exception to be caught by the transaction helper
            AtomicBoolean successFlag = new AtomicBoolean(false);
            try {
                Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
                Listing listing = currentProgram.getListing();
                Data data = listing.getDefinedDataAt(addr);
                if (data != null) {
                    SymbolTable symTable = currentProgram.getSymbolTable();
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


        // --- Helper Methods (Keep internal for now, refactor later if needed) ---
        // Note: These might differ slightly from AbstractEndpoint/ResponseBuilder, review needed.

        private JsonObject createSuccessResponse(Object resultData) {
            JsonObject response = new JsonObject();
            response.addProperty("success", true);
            response.add("result", gson.toJsonTree(resultData));
            return response;
        }

        private JsonObject createErrorResponse(String errorMessage, int statusCode) {
            JsonObject response = new JsonObject();
            response.addProperty("success", false);
            response.addProperty("error", errorMessage);
            response.addProperty("status_code", statusCode);
            return response;
        }
        
        // parseIntOrDefault is inherited from AbstractEndpoint
    }
