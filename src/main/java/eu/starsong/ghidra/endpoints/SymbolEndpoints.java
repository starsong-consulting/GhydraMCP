package eu.starsong.ghidra.endpoints;

    import com.google.gson.JsonObject;
    import com.sun.net.httpserver.HttpExchange;
    import com.sun.net.httpserver.HttpServer;
    import ghidra.program.model.listing.Program;
    import ghidra.program.model.symbol.Symbol;
    import ghidra.program.model.symbol.SymbolIterator;
    import ghidra.program.model.symbol.SymbolTable;
    import ghidra.util.Msg;

    import java.io.IOException;
    import java.util.*;

    public class SymbolEndpoints extends AbstractEndpoint {

        // Updated constructor to accept port
        public SymbolEndpoints(Program program, int port) {
            super(program, port); // Call super constructor
        }

        @Override
        public void registerEndpoints(HttpServer server) {
            server.createContext("/symbols/imports", this::handleImports);
            server.createContext("/symbols/exports", this::handleExports);
        }

        private void handleImports(HttpExchange exchange) throws IOException {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, String> qparams = parseQueryParams(exchange);
                    int offset = parseIntOrDefault(qparams.get("offset"), 0); // Inherited
                    int limit = parseIntOrDefault(qparams.get("limit"), 100); // Inherited
                    Object resultData = listImports(offset, limit);
                    // Check if helper returned an error object
                    if (resultData instanceof JsonObject && !((JsonObject)resultData).get("success").getAsBoolean()) {
                         sendJsonResponse(exchange, (JsonObject)resultData, 400); // Use base sendJsonResponse
                    } else {
                         sendSuccessResponse(exchange, resultData); // Use success helper
                    }
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed"); // Inherited
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /symbols/imports endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage()); // Inherited
            }
        }

        private void handleExports(HttpExchange exchange) throws IOException {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, String> qparams = parseQueryParams(exchange);
                    int offset = parseIntOrDefault(qparams.get("offset"), 0); // Inherited
                    int limit = parseIntOrDefault(qparams.get("limit"), 100); // Inherited
                    Object resultData = listExports(offset, limit);
                     // Check if helper returned an error object
                    if (resultData instanceof JsonObject && !((JsonObject)resultData).get("success").getAsBoolean()) {
                         sendJsonResponse(exchange, (JsonObject)resultData, 400); // Use base sendJsonResponse
                    } else {
                         sendSuccessResponse(exchange, resultData); // Use success helper
                    }
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed"); // Inherited
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /symbols/exports endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage()); // Inherited
            }
        }

        // --- Methods moved from GhydraMCPPlugin ---

        private JsonObject listImports(int offset, int limit) {
            if (currentProgram == null) {
                return createErrorResponse("No program loaded", 400);
            }

            List<Map<String, String>> imports = new ArrayList<>();
            for (Symbol symbol : currentProgram.getSymbolTable().getExternalSymbols()) {
                Map<String, String> imp = new HashMap<>();
                imp.put("name", symbol.getName());
                imp.put("address", symbol.getAddress().toString());
                // Add library name if needed: symbol.getLibraryName()
                imports.add(imp);
            }

            // Apply pagination
            int start = Math.max(0, offset);
            int end = Math.min(imports.size(), offset + limit);
            List<Map<String, String>> paginated = imports.subList(start, end);

            return createSuccessResponse(paginated);
        }

        private JsonObject listExports(int offset, int limit) {
            if (currentProgram == null) {
                return createErrorResponse("No program loaded", 400);
            }

            List<Map<String, String>> exports = new ArrayList<>();
            SymbolTable table = currentProgram.getSymbolTable();
            SymbolIterator it = table.getAllSymbols(true);

            while (it.hasNext()) {
                Symbol s = it.next();
                if (s.isExternalEntryPoint()) {
                    Map<String, String> exp = new HashMap<>();
                    exp.put("name", s.getName());
                    exp.put("address", s.getAddress().toString());
                    exports.add(exp);
                }
            }

            // Apply pagination
            int start = Math.max(0, offset);
            int end = Math.min(exports.size(), offset + limit);
            List<Map<String, String>> paginated = exports.subList(start, end);

            return createSuccessResponse(paginated); // Keep internal helper for now
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
