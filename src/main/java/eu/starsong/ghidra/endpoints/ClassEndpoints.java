package eu.starsong.ghidra.endpoints;

    import com.google.gson.JsonObject;
    import com.sun.net.httpserver.HttpExchange;
    import com.sun.net.httpserver.HttpServer;
    import eu.starsong.ghidra.api.ResponseBuilder;
    import ghidra.program.model.listing.Program;
    import ghidra.program.model.symbol.Namespace;
    import ghidra.program.model.symbol.Symbol;
    import ghidra.util.Msg;

    import java.io.IOException;
    import java.util.*;

    public class ClassEndpoints extends AbstractEndpoint {

        // Updated constructor to accept port
        public ClassEndpoints(Program program, int port) {
            super(program, port); // Call super constructor
        }

        @Override
        public void registerEndpoints(HttpServer server) {
            server.createContext("/classes", this::handleClasses);
        }

        private void handleClasses(HttpExchange exchange) throws IOException {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, String> qparams = parseQueryParams(exchange);
                    int offset = parseIntOrDefault(qparams.get("offset"), 0);
                    int limit = parseIntOrDefault(qparams.get("limit"), 100);
                    
                    if (currentProgram == null) {
                        sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                        return;
                    }
                    
                    // Get all class names
                    Set<String> classNames = new HashSet<>();
                    for (Symbol symbol : currentProgram.getSymbolTable().getAllSymbols(true)) {
                        Namespace ns = symbol.getParentNamespace();
                        // Check if namespace is not null, not global, and represents a class
                        if (ns != null && !ns.isGlobal() && ns.getSymbol().getSymbolType().isNamespace()) {
                            classNames.add(ns.getName(true)); // Get fully qualified name
                        }
                    }
                    
                    // Sort and paginate
                    List<String> sorted = new ArrayList<>(classNames);
                    Collections.sort(sorted);
                    
                    int start = Math.max(0, offset);
                    int end = Math.min(sorted.size(), offset + limit);
                    List<Map<String, Object>> paginatedClasses = new ArrayList<>();
                    
                    // Create full class objects with namespace info
                    for (int i = start; i < end; i++) {
                        String className = sorted.get(i);
                        Map<String, Object> classInfo = new HashMap<>();
                        classInfo.put("name", className);
                        
                        // Add namespace info if it contains a dot
                        if (className.contains(".")) {
                            String namespace = className.substring(0, className.lastIndexOf('.'));
                            classInfo.put("namespace", namespace);
                            classInfo.put("simpleName", className.substring(className.lastIndexOf('.') + 1));
                        } else {
                            classInfo.put("namespace", "default");
                            classInfo.put("simpleName", className);
                        }
                        
                        paginatedClasses.add(classInfo);
                    }
                    
                    // Build response with pagination metadata
                    ResponseBuilder builder = new ResponseBuilder(exchange, port)
                        .success(true)
                        .result(paginatedClasses);
                    
                    // Add pagination metadata
                    Map<String, Object> metadata = new HashMap<>();
                    metadata.put("size", sorted.size());
                    metadata.put("offset", offset);
                    metadata.put("limit", limit);
                    builder.metadata(metadata);
                    
                    // Add HATEOAS links
                    builder.addLink("self", "/classes?offset=" + offset + "&limit=" + limit);
                    builder.addLink("programs", "/programs");
                    
                    // Add next/prev links if applicable
                    if (end < sorted.size()) {
                        builder.addLink("next", "/classes?offset=" + end + "&limit=" + limit);
                    }
                    
                    if (offset > 0) {
                        int prevOffset = Math.max(0, offset - limit);
                        builder.addLink("prev", "/classes?offset=" + prevOffset + "&limit=" + limit);
                    }
                    
                    sendJsonResponse(exchange, builder.build(), 200);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /classes endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }

        // parseIntOrDefault is inherited from AbstractEndpoint
    }
