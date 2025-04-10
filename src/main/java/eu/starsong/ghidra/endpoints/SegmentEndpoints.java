package eu.starsong.ghidra.endpoints;

    import com.google.gson.JsonObject;
    import com.sun.net.httpserver.HttpExchange;
    import com.sun.net.httpserver.HttpServer;
    import ghidra.program.model.listing.Program;
    import ghidra.program.model.mem.MemoryBlock;
    import ghidra.util.Msg;

    import java.io.IOException;
    import java.util.*;

    public class SegmentEndpoints extends AbstractEndpoint {

        // Updated constructor to accept port
        public SegmentEndpoints(Program program, int port) {
            super(program, port); // Call super constructor
        }

        @Override
        public void registerEndpoints(HttpServer server) {
            server.createContext("/segments", this::handleSegments);
        }

        private void handleSegments(HttpExchange exchange) throws IOException {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, String> qparams = parseQueryParams(exchange);
                    int offset = parseIntOrDefault(qparams.get("offset"), 0); // Inherited
                    int limit = parseIntOrDefault(qparams.get("limit"), 100); // Inherited
                    Object resultData = listSegments(offset, limit);
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
                Msg.error(this, "Error in /segments endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage()); // Inherited
            }
        }

        // --- Method moved from GhydraMCPPlugin ---

        private JsonObject listSegments(int offset, int limit) {
            if (currentProgram == null) {
                return createErrorResponse("No program loaded", 400);
            }

            List<Map<String, String>> segments = new ArrayList<>();
            for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
                Map<String, String> seg = new HashMap<>();
                seg.put("name", block.getName());
                seg.put("start", block.getStart().toString());
                seg.put("end", block.getEnd().toString());
                // Add permissions if needed: block.isRead(), block.isWrite(), block.isExecute()
                segments.add(seg);
            }

            // Apply pagination
            int start = Math.max(0, offset);
            int end = Math.min(segments.size(), offset + limit);
            List<Map<String, String>> paginated = segments.subList(start, end);

            return createSuccessResponse(paginated); // Keep internal helper for now
        }

        // --- Helper Methods (Keep internal for now) ---

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
