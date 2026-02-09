package eu.starsong.ghidra.endpoints;

    import com.google.gson.JsonObject;
    import com.sun.net.httpserver.HttpExchange;
    import com.sun.net.httpserver.HttpServer;
    import eu.starsong.ghidra.util.HttpUtil;
    import ghidra.framework.plugintool.PluginTool;
    import ghidra.program.model.listing.Program;
    import ghidra.program.model.symbol.Symbol;
    import ghidra.program.model.symbol.SymbolIterator;
    import ghidra.program.model.symbol.SymbolTable;
    import ghidra.util.Msg;

    import java.io.IOException;
    import java.util.*;

    public class SymbolEndpoints extends AbstractEndpoint {

        private PluginTool tool;
        
        // Updated constructor to accept port
        public SymbolEndpoints(Program program, int port) {
            super(program, port); // Call super constructor
        }
        
        public SymbolEndpoints(Program program, int port, PluginTool tool) {
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
            // that can occur during symbol name resolution in Ghidra
            server.createContext("/symbols/imports", HttpUtil.safeHandler(this::handleImports, port));
            server.createContext("/symbols/exports", HttpUtil.safeHandler(this::handleExports, port));
            server.createContext("/symbols", HttpUtil.safeHandler(this::handleSymbols, port));
        }
        
        public void handleSymbols(HttpExchange exchange) throws IOException {
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
                    
                    List<Map<String, Object>> symbols = new ArrayList<>();
                    SymbolTable symbolTable = program.getSymbolTable();
                    SymbolIterator symbolIterator = symbolTable.getAllSymbols(true);
                    
                    while (symbolIterator.hasNext()) {
                        Symbol symbol = symbolIterator.next();
                        Map<String, Object> symbolInfo = new HashMap<>();
                        symbolInfo.put("name", safeGetSymbolName(symbol, program));
                        symbolInfo.put("address", symbol.getAddress().toString());
                        symbolInfo.put("namespace", symbol.getParentNamespace().getName());
                        symbolInfo.put("type", symbol.getSymbolType().toString());
                        symbolInfo.put("isPrimary", symbol.isPrimary());
                        
                        // Add HATEOAS links
                        Map<String, Object> links = new HashMap<>();
                        Map<String, String> selfLink = new HashMap<>();
                        selfLink.put("href", "/symbols/" + symbol.getAddress().toString());
                        links.put("self", selfLink);
                        symbolInfo.put("_links", links);
                        
                        symbols.add(symbolInfo);
                    }
                    
                    // Build response with HATEOAS links
                    eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                        .success(true);
                    
                    // Apply pagination and get paginated items
                    List<Map<String, Object>> paginatedSymbols = applyPagination(symbols, offset, limit, builder, "/symbols");
                    
                    // Set the paginated result
                    builder.result(paginatedSymbols);
                    
                    // Add program link
                    builder.addLink("program", "/program");
                    
                    sendJsonResponse(exchange, builder.build(), 200);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                Msg.error(this, "Error handling /symbols endpoint", e);
                sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }

        public void handleImports(HttpExchange exchange) throws IOException {
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
                    
                    List<Map<String, Object>> imports = new ArrayList<>();
                    for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
                        Map<String, Object> imp = new HashMap<>();
                        imp.put("name", safeGetSymbolName(symbol, program));
                        imp.put("address", symbol.getAddress().toString());
                        
                        // Add HATEOAS links
                        Map<String, Object> links = new HashMap<>();
                        Map<String, String> selfLink = new HashMap<>();
                        selfLink.put("href", "/symbols/imports/" + symbol.getAddress().toString());
                        links.put("self", selfLink);
                        imp.put("_links", links);
                        
                        imports.add(imp);
                    }
                    
                    // Build response with HATEOAS links
                    eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                        .success(true);
                    
                    // Apply pagination and get paginated items
                    List<Map<String, Object>> paginated = applyPagination(imports, offset, limit, builder, "/symbols/imports");
                    
                    // Set the paginated result
                    builder.result(paginated);
                    
                    // Add additional links
                    builder.addLink("program", "/program");
                    builder.addLink("symbols", "/symbols");
                    
                    sendJsonResponse(exchange, builder.build(), 200);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /symbols/imports endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }

        public void handleExports(HttpExchange exchange) throws IOException {
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
                    
                    List<Map<String, Object>> exports = new ArrayList<>();
                    SymbolTable table = program.getSymbolTable();
                    SymbolIterator it = table.getAllSymbols(true);
                    
                    while (it.hasNext()) {
                        Symbol s = it.next();
                        if (s.isExternalEntryPoint()) {
                            Map<String, Object> exp = new HashMap<>();
                            exp.put("name", safeGetSymbolName(s, program));
                            exp.put("address", s.getAddress().toString());
                            
                            // Add HATEOAS links
                            Map<String, Object> links = new HashMap<>();
                            Map<String, String> selfLink = new HashMap<>();
                            selfLink.put("href", "/symbols/exports/" + s.getAddress().toString());
                            links.put("self", selfLink);
                            exp.put("_links", links);
                            
                            exports.add(exp);
                        }
                    }
                    
                    // Build response with HATEOAS links
                    eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                        .success(true);
                    
                    // Apply pagination and get paginated items
                    List<Map<String, Object>> paginated = applyPagination(exports, offset, limit, builder, "/symbols/exports");
                    
                    // Set the paginated result
                    builder.result(paginated);
                    
                    // Add additional links
                    builder.addLink("program", "/program");
                    builder.addLink("symbols", "/symbols");
                    
                    sendJsonResponse(exchange, builder.build(), 200);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /symbols/exports endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }

        // parseIntOrDefault is inherited from AbstractEndpoint
    }
