package eu.starsong.ghidra.endpoints;

    import com.google.gson.JsonObject;
    import com.sun.net.httpserver.HttpExchange;
    import com.sun.net.httpserver.HttpServer;
    import ghidra.framework.plugintool.PluginTool;
    import ghidra.program.model.address.GlobalNamespace;
    import ghidra.program.model.listing.Program;
    import ghidra.program.model.symbol.Namespace;
    import ghidra.program.model.symbol.Symbol;
    import ghidra.util.Msg;

    import java.io.IOException;
    import java.util.*;

    public class NamespaceEndpoints extends AbstractEndpoint {

        private PluginTool tool;
        
        public NamespaceEndpoints(Program program, int port) {
            super(program, port);
        }
        
        public NamespaceEndpoints(Program program, int port, PluginTool tool) {
            super(program, port);
            this.tool = tool;
        }
        
        @Override
        protected PluginTool getTool() {
            return tool;
        }

        @Override
        public void registerEndpoints(HttpServer server) {
            server.createContext("/namespaces", this::handleNamespaces);
        }

        public void handleNamespaces(HttpExchange exchange) throws IOException {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, String> qparams = parseQueryParams(exchange);
                    int offset = parseIntOrDefault(qparams.get("offset"), 0);
                    int limit = parseIntOrDefault(qparams.get("limit"), 100);
                    
                    Program program = getCurrentProgram();
                    if (program == null) {
                        sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                        return;
                    }
                    
                    Set<String> namespaces = new HashSet<>();
                    for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
                        Namespace ns = symbol.getParentNamespace();
                        if (ns != null && !(ns instanceof GlobalNamespace)) {
                            namespaces.add(ns.getName(true)); // Get fully qualified name
                        }
                    }
                    
                    List<String> sorted = new ArrayList<>(namespaces);
                    Collections.sort(sorted);
                    
                    // Build response with HATEOAS links
                    eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                        .success(true);
                    
                    // Apply pagination and get paginated items
                    List<String> paginated = applyPagination(sorted, offset, limit, builder, "/namespaces");
                    
                    // Set the paginated result
                    builder.result(paginated);
                    
                    // Add program link
                    builder.addLink("program", "/program");
                    
                    sendJsonResponse(exchange, builder.build(), 200);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /namespaces endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }

        // parseIntOrDefault is inherited from AbstractEndpoint
    }
