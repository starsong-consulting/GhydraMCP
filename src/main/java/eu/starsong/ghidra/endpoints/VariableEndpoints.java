package eu.starsong.ghidra.endpoints;

    import com.google.gson.Gson;
    import com.google.gson.JsonObject;
    import com.sun.net.httpserver.HttpExchange;
    import com.sun.net.httpserver.HttpServer;
    import eu.starsong.ghidra.util.TransactionHelper;
    import eu.starsong.ghidra.util.TransactionHelper.TransactionException;
    import ghidra.app.decompiler.DecompInterface;
    import ghidra.app.decompiler.DecompileResults;
    import ghidra.program.model.address.Address;
    import ghidra.program.model.data.DataType;
    import ghidra.program.model.listing.Function;
    import ghidra.program.model.listing.Parameter;
    import ghidra.program.model.listing.Program;
    import ghidra.program.model.listing.VariableStorage;
    import ghidra.framework.plugintool.PluginTool;
    import ghidra.program.model.pcode.HighFunction;
    import ghidra.program.model.pcode.HighFunctionDBUtil;
    import ghidra.program.model.pcode.HighSymbol;
    import ghidra.program.model.pcode.LocalSymbolMap;
    import ghidra.program.model.symbol.SourceType;
    import ghidra.program.model.symbol.Symbol;
    import ghidra.program.model.symbol.SymbolIterator;
    import ghidra.program.model.symbol.SymbolTable;
    import ghidra.program.model.symbol.SymbolType;
    import ghidra.util.Msg;
    import ghidra.util.task.ConsoleTaskMonitor;
    import eu.starsong.ghidra.api.ResponseBuilder;

    import java.io.IOException;
    import java.nio.charset.StandardCharsets;
    import java.util.*;
    import java.util.concurrent.atomic.AtomicBoolean;
    import javax.swing.SwingUtilities;
    import java.lang.reflect.InvocationTargetException;


    public class VariableEndpoints extends AbstractEndpoint {

        private PluginTool tool;
        
        // Updated constructor to accept port
        public VariableEndpoints(Program program, int port) {
            super(program, port); // Call super constructor
        }
        
        public VariableEndpoints(Program program, int port, PluginTool tool) {
            super(program, port);
            this.tool = tool;
        }
        
        @Override
        protected PluginTool getTool() {
            return tool;
        }

        @Override
        public void registerEndpoints(HttpServer server) {
            server.createContext("/variables", this::handleGlobalVariables);
            // Note: /functions/{name}/variables is handled within FunctionEndpoints for now
            // to keep related logic together until full refactor.
            // If needed, we can create a more complex routing mechanism later.
        }

        private void handleGlobalVariables(HttpExchange exchange) throws IOException {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, String> qparams = parseQueryParams(exchange);
                    int offset = parseIntOrDefault(qparams.get("offset"), 0);
                    int limit = parseIntOrDefault(qparams.get("limit"), 100);
                    String search = qparams.get("search"); // Renamed from 'query' for clarity

                    // Always get the most current program from the tool
                    Program program = getCurrentProgram();
                    if (program == null) {
                        sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                        return;
                    }
                    
                    // Create ResponseBuilder for HATEOAS-compliant response
                    ResponseBuilder builder = new ResponseBuilder(exchange, port)
                        .success(true)
                        .addLink("self", "/variables" + (exchange.getRequestURI().getRawQuery() != null ? 
                            "?" + exchange.getRequestURI().getRawQuery() : ""));
                    
                    // Add common links
                    builder.addLink("program", "/program");
                    builder.addLink("search", "/variables?search={term}", "GET");
                    
                    List<Map<String, String>> variables;
                    if (search != null && !search.isEmpty()) {
                        variables = searchVariables(program, search);
                    } else {
                        variables = listVariables(program);
                    }
                    
                    // Apply pagination and get paginated result
                    List<Map<String, String>> paginatedVars = 
                        applyPagination(variables, offset, limit, builder, "/variables",
                            search != null ? "search=" + search : null);
                    
                    // Add the result to the builder
                    builder.result(paginatedVars);
                    
                    // Send the HATEOAS-compliant response
                    sendJsonResponse(exchange, builder.build(), 200);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /variables endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
            }
        }

        // Updated to return List instead of JsonObject for HATEOAS compliance
        private List<Map<String, String>> listVariables(Program program) {
            List<Map<String, String>> variables = new ArrayList<>();

            if (program == null) {
                return variables; // Return empty list if no program
            }

            // Get global variables
            SymbolTable symbolTable = program.getSymbolTable();
            for (Symbol symbol : symbolTable.getDefinedSymbols()) {
                if (symbol.isGlobal() && !symbol.isExternal() &&
                    symbol.getSymbolType() != SymbolType.FUNCTION &&
                    symbol.getSymbolType() != SymbolType.LABEL) {

                    Map<String, String> varInfo = new HashMap<>();
                    varInfo.put("name", symbol.getName());
                    varInfo.put("address", symbol.getAddress().toString());
                    varInfo.put("type", "global");
                    varInfo.put("dataType", getDataTypeName(program, symbol.getAddress()));
                    variables.add(varInfo);
                }
            }

            // Get local variables from all functions (Consider performance implications)
            DecompInterface decomp = null;
            try {
                decomp = new DecompInterface();
                if (!decomp.openProgram(program)) {
                     Msg.error(this, "listVariables: Failed to open program with decompiler.");
                } else {
                    for (Function function : program.getFunctionManager().getFunctions(true)) {
                        try {
                            DecompileResults results = decomp.decompileFunction(function, 30, new ConsoleTaskMonitor());
                            if (results != null && results.decompileCompleted()) {
                                HighFunction highFunc = results.getHighFunction();
                                if (highFunc != null) {
                                    Iterator<HighSymbol> symbolIter = highFunc.getLocalSymbolMap().getSymbols();
                                    while (symbolIter.hasNext()) {
                                        HighSymbol symbol = symbolIter.next();
                                        if (!symbol.isParameter()) { // Only list locals
                                            Map<String, String> varInfo = new HashMap<>();
                                            varInfo.put("name", symbol.getName());
                                            varInfo.put("type", "local");
                                            varInfo.put("function", function.getName());
                                            Address pcAddr = symbol.getPCAddress();
                                            varInfo.put("address", pcAddr != null ? pcAddr.toString() : "N/A");
                                            varInfo.put("dataType", symbol.getDataType() != null ? symbol.getDataType().getName() : "unknown");
                                            variables.add(varInfo);
                                        }
                                    }
                                }
                            }
                        } catch (Exception e) {
                            Msg.error(this, "listVariables: Error processing function " + function.getName(), e);
                        }
                    }
                }
            } catch (Exception e) {
                 Msg.error(this, "listVariables: Error during local variable processing", e);
            } finally {
                if (decomp != null) {
                    decomp.dispose();
                }
            }

            Collections.sort(variables, Comparator.comparing(a -> a.get("name")));
            return variables; // Return full list, pagination applied in handler
        }

        // Updated to return List instead of JsonObject for HATEOAS compliance
        private List<Map<String, String>> searchVariables(Program program, String searchTerm) {
            if (program == null || searchTerm == null || searchTerm.isEmpty()) {
                return new ArrayList<>(); // Return empty list
            }

            List<Map<String, String>> matchedVars = new ArrayList<>();
            String lowerSearchTerm = searchTerm.toLowerCase();

            // Search global variables
            SymbolTable symbolTable = program.getSymbolTable();
            SymbolIterator it = symbolTable.getSymbolIterator();
            while (it.hasNext()) {
                Symbol symbol = it.next();
                if (symbol.isGlobal() &&
                    symbol.getSymbolType() != SymbolType.FUNCTION &&
                    symbol.getSymbolType() != SymbolType.LABEL &&
                    symbol.getName().toLowerCase().contains(lowerSearchTerm)) {
                    Map<String, String> varInfo = new HashMap<>();
                    varInfo.put("name", symbol.getName());
                    varInfo.put("address", symbol.getAddress().toString());
                    varInfo.put("type", "global");
                    varInfo.put("dataType", getDataTypeName(program, symbol.getAddress()));
                    matchedVars.add(varInfo);
                }
            }

            // Search local variables
            DecompInterface decomp = null;
            try {
                decomp = new DecompInterface();
                if (decomp.openProgram(program)) {
                    for (Function function : program.getFunctionManager().getFunctions(true)) {
                        try {
                            DecompileResults results = decomp.decompileFunction(function, 30, new ConsoleTaskMonitor());
                            if (results != null && results.decompileCompleted()) {
                                HighFunction highFunc = results.getHighFunction();
                                if (highFunc != null) {
                                    Iterator<HighSymbol> symbolIter = highFunc.getLocalSymbolMap().getSymbols();
                                    while (symbolIter.hasNext()) {
                                        HighSymbol symbol = symbolIter.next();
                                        if (symbol.getName().toLowerCase().contains(lowerSearchTerm)) {
                                            Map<String, String> varInfo = new HashMap<>();
                                            varInfo.put("name", symbol.getName());
                                            varInfo.put("function", function.getName());
                                            varInfo.put("type", symbol.isParameter() ? "parameter" : "local");
                                            Address pcAddr = symbol.getPCAddress();
                                            varInfo.put("address", pcAddr != null ? pcAddr.toString() : "N/A");
                                            varInfo.put("dataType", symbol.getDataType() != null ? symbol.getDataType().getName() : "unknown");
                                            matchedVars.add(varInfo);
                                        }
                                    }
                                }
                            }
                        } catch (Exception e) {
                             Msg.warn(this, "searchVariables: Error processing function " + function.getName(), e);
                        }
                    }
                } else {
                     Msg.error(this, "searchVariables: Failed to open program with decompiler.");
                }
            } catch (Exception e) {
                 Msg.error(this, "searchVariables: Error during local variable search", e);
            } finally {
                if (decomp != null) {
                    decomp.dispose();
                }
            }

            Collections.sort(matchedVars, Comparator.comparing(a -> a.get("name")));
            return matchedVars;
        }

        // --- Helper Methods ---

        private String getDataTypeName(Program program, Address address) {
            // This might be better in GhidraUtil if used elsewhere
            ghidra.program.model.listing.Data data = program.getListing().getDataAt(address);
            if (data == null) return "undefined";
            DataType dt = data.getDataType();
            return dt != null ? dt.getName() : "unknown";
        }
    }