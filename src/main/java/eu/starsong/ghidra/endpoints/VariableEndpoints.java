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

    import java.io.IOException;
    import java.nio.charset.StandardCharsets;
    import java.util.*;
    import java.util.concurrent.atomic.AtomicBoolean;
    import javax.swing.SwingUtilities;
    import java.lang.reflect.InvocationTargetException;


    public class VariableEndpoints extends AbstractEndpoint {

        // Updated constructor to accept port
        public VariableEndpoints(Program program, int port) {
            super(program, port); // Call super constructor
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

                    Object resultData;
                    if (search != null && !search.isEmpty()) {
                        resultData = searchVariables(search, offset, limit);
                    } else {
                        resultData = listVariables(offset, limit);
                    }
                    // Check if helper returned an error object
                    if (resultData instanceof JsonObject && !((JsonObject)resultData).get("success").getAsBoolean()) {
                         sendJsonResponse(exchange, (JsonObject)resultData, 400); // Use base sendJsonResponse
                    } else {
                         sendSuccessResponse(exchange, resultData); // Use success helper
                    }
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /variables endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
            }
        }

        // --- Methods moved from GhydraMCPPlugin ---

        private JsonObject listVariables(int offset, int limit) {
            if (currentProgram == null) {
                return createErrorResponse("No program loaded", 400);
            }

            List<Map<String, String>> variables = new ArrayList<>();

            // Get global variables
            SymbolTable symbolTable = currentProgram.getSymbolTable();
            for (Symbol symbol : symbolTable.getDefinedSymbols()) {
                if (symbol.isGlobal() && !symbol.isExternal() &&
                    symbol.getSymbolType() != SymbolType.FUNCTION &&
                    symbol.getSymbolType() != SymbolType.LABEL) {

                    Map<String, String> varInfo = new HashMap<>();
                    varInfo.put("name", symbol.getName());
                    varInfo.put("address", symbol.getAddress().toString());
                    varInfo.put("type", "global");
                    varInfo.put("dataType", getDataTypeName(currentProgram, symbol.getAddress()));
                    variables.add(varInfo);
                }
            }

            // Get local variables from all functions (Consider performance implications)
            DecompInterface decomp = null;
            try {
                decomp = new DecompInterface();
                if (!decomp.openProgram(currentProgram)) {
                     Msg.error(this, "listVariables: Failed to open program with decompiler.");
                } else {
                    for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
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

            int start = Math.max(0, offset);
            int end = Math.min(variables.size(), offset + limit);
            List<Map<String, String>> paginated = variables.subList(start, end);

            return createSuccessResponse(paginated); // Keep using internal helper for now
        }

        private JsonObject searchVariables(String searchTerm, int offset, int limit) {
             if (currentProgram == null) {
                return createErrorResponse("No program loaded", 400); // Keep using internal helper
            }
            if (searchTerm == null || searchTerm.isEmpty()) {
                return createErrorResponse("Search term is required", 400); // Keep using internal helper
            }

            List<Map<String, String>> matchedVars = new ArrayList<>();
            String lowerSearchTerm = searchTerm.toLowerCase();

            // Search global variables
            SymbolTable symbolTable = currentProgram.getSymbolTable();
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
                    varInfo.put("dataType", getDataTypeName(currentProgram, symbol.getAddress()));
                    matchedVars.add(varInfo);
                }
            }

            // Search local variables
            DecompInterface decomp = null;
            try {
                decomp = new DecompInterface();
                if (decomp.openProgram(currentProgram)) {
                    for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
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

            int start = Math.max(0, offset);
            int end = Math.min(matchedVars.size(), offset + limit);
            List<Map<String, String>> paginated = matchedVars.subList(start, end);

            return createSuccessResponse(paginated); // Keep using internal helper
        }

        // --- Helper Methods (Keep internal for now, refactor later if needed) ---

        private String getDataTypeName(Program program, Address address) {
            // This might be better in GhidraUtil if used elsewhere
            ghidra.program.model.listing.Data data = program.getListing().getDataAt(address);
            if (data == null) return "undefined";
            DataType dt = data.getDataType();
            return dt != null ? dt.getName() : "unknown";
        }

        // Keep internal response helpers for now, as they differ slightly from AbstractEndpoint's
        private JsonObject createSuccessResponse(Object resultData) {
            JsonObject response = new JsonObject();
            response.addProperty("success", true);
            response.add("result", gson.toJsonTree(resultData));
            // These helpers don't add id/instance/_links, unlike ResponseBuilder
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
