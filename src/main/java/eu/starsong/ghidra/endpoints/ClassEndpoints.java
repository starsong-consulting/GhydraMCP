package eu.starsong.ghidra.endpoints;

    import com.google.gson.JsonObject;
    import com.sun.net.httpserver.HttpExchange;
    import com.sun.net.httpserver.HttpServer;
    import eu.starsong.ghidra.api.ResponseBuilder;
    import ghidra.framework.plugintool.PluginTool;
    import ghidra.program.model.listing.Program;
    import ghidra.program.model.symbol.Namespace;
    import ghidra.program.model.symbol.Symbol;
    import ghidra.util.Msg;

    import java.io.IOException;
    import java.util.*;

    public class ClassEndpoints extends AbstractEndpoint {

        private PluginTool tool;
        
        // Updated constructor to accept port
        public ClassEndpoints(Program program, int port) {
            super(program, port); // Call super constructor
        }
        
        public ClassEndpoints(Program program, int port, PluginTool tool) {
            super(program, port);
            this.tool = tool;
        }
        
        @Override
        protected PluginTool getTool() {
            return tool;
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
                    
                    // Always get the most current program from the tool
                    Program program = getCurrentProgram();
                    if (program == null) {
                        sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                        return;
                    }
                    
                    // Get all class names
                    Set<String> classNames = new HashSet<>();
                    for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
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
                        
                        // Add HATEOAS links for each class
                        Map<String, Object> links = new HashMap<>();
                        Map<String, String> selfLink = new HashMap<>();
                        selfLink.put("href", "/classes/" + className);
                        links.put("self", selfLink);
                        
                        // Add link to program if relevant
                        Map<String, String> programLink = new HashMap<>();
                        programLink.put("href", "/program");
                        links.put("program", programLink);
                        
                        classInfo.put("_links", links);
                        
                        paginatedClasses.add(classInfo);
                    }
                    
                    // We need to separately create the full class objects with details
                    // so we can't apply pagination directly to sorted list
                    
                    // Build response with HATEOAS links
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
                    builder.addLink("program", "/program");
                    
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
