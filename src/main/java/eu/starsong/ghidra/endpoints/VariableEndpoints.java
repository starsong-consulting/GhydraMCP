package eu.starsong.ghidra.endpoints;

    import com.google.gson.Gson;
    import com.google.gson.JsonObject;
    import com.sun.net.httpserver.HttpExchange;
    import com.sun.net.httpserver.HttpServer;
    import eu.starsong.ghidra.util.DecompilerCache;
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

        public VariableEndpoints(Program program, int port, PluginTool tool, DecompilerCache cache) {
            super(program, port, cache);
            this.tool = tool;
        }
        
        @Override
        protected PluginTool getTool() {
            return tool;
        }

        @Override
        public void registerEndpoints(HttpServer server) {
            server.createContext("/variables", this::handleGlobalVariables);
        }

        private void handleGlobalVariables(HttpExchange exchange) throws IOException {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, String> qparams = parseQueryParams(exchange);
                    int offset = parseIntOrDefault(qparams.get("offset"), 0);
                    int limit = parseIntOrDefault(qparams.get("limit"), 100);
                    String search = qparams.get("search"); // Renamed from 'query' for clarity
                    boolean globalOnly = Boolean.parseBoolean(qparams.getOrDefault("global_only", "false"));
                    
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
                    builder.addLink("globals", "/variables?global_only=true", "GET");
                    
                    // Use more efficient pagination by limiting data collection up-front
                    PaginatedResult paginatedResult;
                    if (search != null && !search.isEmpty()) {
                        paginatedResult = searchVariablesPaginated(program, search, offset, limit, globalOnly);
                    } else {
                        paginatedResult = listVariablesPaginated(program, offset, limit, globalOnly);
                    }
                    
                    // Add pagination links
                    String baseUrl = "/variables";
                    String queryParams = "";
                    if (search != null && !search.isEmpty()) {
                        queryParams = "search=" + search;
                    }
                    if (globalOnly) {
                        queryParams = queryParams.isEmpty() ? "global_only=true" : queryParams + "&global_only=true";
                    }
                    
                    // Add metadata
                    Map<String, Object> metadata = new HashMap<>();
                    metadata.put("total_estimate", paginatedResult.getTotalEstimate());
                    metadata.put("offset", offset);
                    metadata.put("limit", limit);
                    builder.metadata(metadata);
                    
                    // Add self link
                    String selfLink = baseUrl;
                    if (!queryParams.isEmpty()) {
                        selfLink += "?" + queryParams;
                        selfLink += "&offset=" + offset + "&limit=" + limit;
                    } else {
                        selfLink += "?offset=" + offset + "&limit=" + limit;
                    }
                    builder.addLink("self", selfLink);
                    
                    // Add next link if needed
                    if (paginatedResult.hasMore()) {
                        String nextLink = baseUrl;
                        if (!queryParams.isEmpty()) {
                            nextLink += "?" + queryParams;
                            nextLink += "&offset=" + (offset + limit) + "&limit=" + limit;
                        } else {
                            nextLink += "?offset=" + (offset + limit) + "&limit=" + limit;
                        }
                        builder.addLink("next", nextLink);
                    }
                    
                    // Add prev link if needed
                    if (offset > 0) {
                        int prevOffset = Math.max(0, offset - limit);
                        String prevLink = baseUrl;
                        if (!queryParams.isEmpty()) {
                            prevLink += "?" + queryParams;
                            prevLink += "&offset=" + prevOffset + "&limit=" + limit;
                        } else {
                            prevLink += "?offset=" + prevOffset + "&limit=" + limit;
                        }
                        builder.addLink("prev", prevLink);
                    }
                    
                    // Add the result to the builder
                    builder.result(paginatedResult.getResults());
                    
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
        
        /**
         * Class to represent a paginated result with metadata
         */
        private static class PaginatedResult {
            private final List<Map<String, String>> results;
            private final boolean hasMore;
            private final int totalEstimate;
            
            public PaginatedResult(List<Map<String, String>> results, boolean hasMore, int totalEstimate) {
                this.results = results;
                this.hasMore = hasMore;
                this.totalEstimate = totalEstimate;
            }
            
            public List<Map<String, String>> getResults() {
                return results;
            }
            
            public boolean hasMore() {
                return hasMore;
            }
            
            public int getTotalEstimate() {
                return totalEstimate;
            }
        }

        /**
         * Legacy method kept for backward compatibility
         */
        private List<Map<String, String>> listVariables(Program program) {
            PaginatedResult result = listVariablesPaginated(program, 0, Integer.MAX_VALUE, false);
            return result.getResults();
        }
        
        /**
         * List variables with efficient pagination - only loads what's needed
         */
        private PaginatedResult listVariablesPaginated(Program program, int offset, int limit, boolean globalOnly) {
            if (program == null) {
                return new PaginatedResult(new ArrayList<>(), false, 0);
            }
            
            List<Map<String, String>> variables = new ArrayList<>();
            int globalVarCount = 0;
            int totalEstimate = 0;
            boolean hasMore = false;
            
            // Calculate range of items to fetch
            int startIdx = offset;
            int endIdx = offset + limit;
            int currentIndex = 0;
            
            // Get global variables - these are quick to get so we can get them all
            SymbolTable symbolTable = program.getSymbolTable();
            ArrayList<Symbol> globalSymbols = new ArrayList<>();
            
            // First, collect global variables efficiently
            for (Symbol symbol : symbolTable.getDefinedSymbols()) {
                if (symbol.isGlobal() && !symbol.isExternal() &&
                    symbol.getSymbolType() != SymbolType.FUNCTION &&
                    symbol.getSymbolType() != SymbolType.LABEL) {
                    globalSymbols.add(symbol);
                }
            }
            
            // Sort globals by name first
            globalSymbols.sort(Comparator.comparing(Symbol::getName));
            globalVarCount = globalSymbols.size();
            totalEstimate = globalVarCount;
            
            // Now extract just the global variables we need for the current page
            for (Symbol symbol : globalSymbols) {
                if (currentIndex >= startIdx && currentIndex < endIdx) {
                    Map<String, String> varInfo = new HashMap<>();
                    varInfo.put("name", symbol.getName());
                    varInfo.put("address", symbol.getAddress().toString());
                    varInfo.put("type", "global");
                    varInfo.put("dataType", getDataTypeName(program, symbol.getAddress()));
                    variables.add(varInfo);
                }
                currentIndex++;
                
                // If we've added enough items, break
                if (currentIndex >= endIdx) {
                    hasMore = currentIndex < globalVarCount || !globalOnly;
                    break;
                }
            }
            
            // If we only want globals, or if we've already fetched enough for this page, return now
            if (globalOnly || currentIndex >= endIdx) {
                return new PaginatedResult(variables, hasMore, totalEstimate);
            }
            
            // Get local variables - only if needed (these are expensive)
            // We need to perform some estimation for locals, as decompiling all functions is too slow
            
            // First estimate the total count
            int funcCount = 0;
            for (Function f : program.getFunctionManager().getFunctions(true)) {
                funcCount++;
            }
            
            // Roughly estimate 2 local variables per function
            totalEstimate = globalVarCount + (funcCount * 2);
            
            // If we don't need locals for the current page, return globals with estimation
            if (startIdx >= globalVarCount) {
                int localOffset = startIdx - globalVarCount;
                int localLimit = limit;

                DecompInterface fallbackDecomp = createFallbackDecomp(program);
                try {
                    int localVarIndex = 0;
                    int functionsProcessed = 0;
                    int maxFunctionsToProcess = 20;

                    for (Function function : program.getFunctionManager().getFunctions(true)) {
                        try {
                            DecompileResults results = decompileForVariables(function, fallbackDecomp, 10);
                            if (results != null && results.decompileCompleted()) {
                                HighFunction highFunc = results.getHighFunction();
                                if (highFunc != null) {
                                    List<Map<String, String>> functionVars = new ArrayList<>();
                                    Iterator<HighSymbol> symbolIter = highFunc.getLocalSymbolMap().getSymbols();
                                    while (symbolIter.hasNext()) {
                                        HighSymbol symbol = symbolIter.next();
                                        if (!symbol.isParameter()) {
                                            Map<String, String> varInfo = new HashMap<>();
                                            varInfo.put("name", symbol.getName());
                                            varInfo.put("type", "local");
                                            varInfo.put("function", function.getName());
                                            Address pcAddr = symbol.getPCAddress();
                                            varInfo.put("address", pcAddr != null ? pcAddr.toString() : "N/A");
                                            varInfo.put("dataType", symbol.getDataType() != null ? symbol.getDataType().getName() : "unknown");
                                            functionVars.add(varInfo);
                                        }
                                    }

                                    functionVars.sort(Comparator.comparing(a -> a.get("name")));

                                    for (Map<String, String> varInfo : functionVars) {
                                        if (localVarIndex >= localOffset && localVarIndex < localOffset + localLimit) {
                                            variables.add(varInfo);
                                        }
                                        localVarIndex++;
                                        if (localVarIndex >= localOffset + localLimit) {
                                            break;
                                        }
                                    }
                                }
                            }
                        } catch (Exception e) {
                            Msg.warn(this, "listVariablesPaginated: Error processing function " + function.getName(), e);
                        }

                        functionsProcessed++;
                        if (functionsProcessed >= maxFunctionsToProcess || localVarIndex >= localOffset + localLimit) {
                            break;
                        }
                    }

                    hasMore = functionsProcessed < funcCount || localVarIndex >= localOffset + localLimit;
                } catch (Exception e) {
                    Msg.error(this, "listVariablesPaginated: Error during local variable processing", e);
                } finally {
                    if (fallbackDecomp != null) {
                        fallbackDecomp.dispose();
                    }
                }
            } else {
                int remainingSpace = limit - variables.size();
                if (remainingSpace > 0) {
                    DecompInterface fallbackDecomp = createFallbackDecomp(program);
                    try {
                        int functionsProcessed = 0;
                        int maxFunctionsToProcess = 5;
                        int localVarsAdded = 0;

                        for (Function function : program.getFunctionManager().getFunctions(true)) {
                            try {
                                DecompileResults results = decompileForVariables(function, fallbackDecomp, 10);
                                if (results != null && results.decompileCompleted()) {
                                    HighFunction highFunc = results.getHighFunction();
                                    if (highFunc != null) {
                                        Iterator<HighSymbol> symbolIter = highFunc.getLocalSymbolMap().getSymbols();
                                        while (symbolIter.hasNext() && localVarsAdded < remainingSpace) {
                                            HighSymbol symbol = symbolIter.next();
                                            if (!symbol.isParameter()) {
                                                Map<String, String> varInfo = new HashMap<>();
                                                varInfo.put("name", symbol.getName());
                                                varInfo.put("type", "local");
                                                varInfo.put("function", function.getName());
                                                Address pcAddr = symbol.getPCAddress();
                                                varInfo.put("address", pcAddr != null ? pcAddr.toString() : "N/A");
                                                varInfo.put("dataType", symbol.getDataType() != null ? symbol.getDataType().getName() : "unknown");
                                                variables.add(varInfo);
                                                localVarsAdded++;
                                            }
                                        }
                                    }
                                }
                            } catch (Exception e) {
                                Msg.warn(this, "listVariablesPaginated: Error processing function " + function.getName(), e);
                            }

                            functionsProcessed++;
                            if (functionsProcessed >= maxFunctionsToProcess || localVarsAdded >= remainingSpace) {
                                break;
                            }
                        }

                        hasMore = functionsProcessed < funcCount || localVarsAdded >= remainingSpace;
                    } catch (Exception e) {
                        Msg.error(this, "listVariablesPaginated: Error during local variable processing", e);
                    } finally {
                        if (fallbackDecomp != null) {
                            fallbackDecomp.dispose();
                        }
                    }
                }
            }
            
            // Sort the combined results
            variables.sort(Comparator.comparing(a -> a.get("name")));
            
            return new PaginatedResult(variables, hasMore, totalEstimate);
        }

        /**
         * Legacy method kept for backward compatibility
         */
        private List<Map<String, String>> searchVariables(Program program, String searchTerm) {
            PaginatedResult result = searchVariablesPaginated(program, searchTerm, 0, Integer.MAX_VALUE, false);
            return result.getResults();
        }
        
        /**
         * Search variables with efficient pagination - only loads what's needed
         */
        private PaginatedResult searchVariablesPaginated(Program program, String searchTerm, int offset, int limit, boolean globalOnly) {
            if (program == null || searchTerm == null || searchTerm.isEmpty()) {
                return new PaginatedResult(new ArrayList<>(), false, 0);
            }
            
            List<Map<String, String>> matchedVars = new ArrayList<>();
            String lowerSearchTerm = searchTerm.toLowerCase();
            int totalEstimate = 0;
            boolean hasMore = false;
            
            // Calculate range of items to fetch
            int startIdx = offset;
            int endIdx = offset + limit;
            int currentIndex = 0;
            
            // Search global variables - these are quick to search
            SymbolTable symbolTable = program.getSymbolTable();
            List<Map<String, String>> globalMatches = new ArrayList<>();
            
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
                    globalMatches.add(varInfo);
                }
            }
            
            // Sort global matches by name
            globalMatches.sort(Comparator.comparing(a -> a.get("name")));
            
            // Extract just the global variables needed for this page
            int globalCount = globalMatches.size();
            totalEstimate = globalCount;
            
            for (Map<String, String> varInfo : globalMatches) {
                if (currentIndex >= startIdx && currentIndex < endIdx) {
                    matchedVars.add(varInfo);
                }
                currentIndex++;
                
                // If we've added enough items, break
                if (currentIndex >= endIdx) {
                    hasMore = currentIndex < globalCount || !globalOnly;
                    break;
                }
            }
            
            // If we only want globals, or if we've already fetched enough for this page, return now
            if (globalOnly || currentIndex >= endIdx) {
                return new PaginatedResult(matchedVars, hasMore, totalEstimate);
            }
            
            // Search local variables - only do this if we need more results
            // We need to perform some estimation for locals, as decompiling all functions is too slow
            
            // First estimate the total count
            int funcCount = 0;
            for (Function f : program.getFunctionManager().getFunctions(true)) {
                funcCount++;
            }
            
            // Roughly estimate 1 match per 5 functions when searching
            totalEstimate = globalCount + (funcCount / 5);
            
            // If we don't need locals for the current page, return globals with estimation
            if (startIdx >= globalCount) {
                int localOffset = startIdx - globalCount;
                int localLimit = limit;

                DecompInterface fallbackDecomp = createFallbackDecomp(program);
                try {
                    int localVarIndex = 0;
                    int functionsProcessed = 0;
                    int maxFunctionsToProcess = 30;

                    for (Function function : program.getFunctionManager().getFunctions(true)) {
                        try {
                            DecompileResults results = decompileForVariables(function, fallbackDecomp, 5);
                            if (results != null && results.decompileCompleted()) {
                                HighFunction highFunc = results.getHighFunction();
                                if (highFunc != null) {
                                    List<Map<String, String>> functionMatches = new ArrayList<>();
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
                                            functionMatches.add(varInfo);
                                        }
                                    }

                                    functionMatches.sort(Comparator.comparing(a -> a.get("name")));

                                    for (Map<String, String> varInfo : functionMatches) {
                                        if (localVarIndex >= localOffset && localVarIndex < localOffset + localLimit) {
                                            matchedVars.add(varInfo);
                                        }
                                        localVarIndex++;
                                        if (localVarIndex >= localOffset + localLimit) {
                                            break;
                                        }
                                    }
                                }
                            }
                        } catch (Exception e) {
                            Msg.warn(this, "searchVariablesPaginated: Error processing function " + function.getName(), e);
                        }

                        functionsProcessed++;
                        if (functionsProcessed >= maxFunctionsToProcess || localVarIndex >= localOffset + localLimit) {
                            break;
                        }
                    }

                    hasMore = functionsProcessed < funcCount || localVarIndex >= localOffset + localLimit;
                } catch (Exception e) {
                    Msg.error(this, "searchVariablesPaginated: Error during local variable search", e);
                } finally {
                    if (fallbackDecomp != null) {
                        fallbackDecomp.dispose();
                    }
                }
            } else {
                int remainingSpace = limit - matchedVars.size();
                if (remainingSpace > 0) {
                    DecompInterface fallbackDecomp = createFallbackDecomp(program);
                    try {
                        int functionsProcessed = 0;
                        int maxFunctionsToProcess = 5;
                        int localVarsAdded = 0;

                        for (Function function : program.getFunctionManager().getFunctions(true)) {
                            try {
                                DecompileResults results = decompileForVariables(function, fallbackDecomp, 5);
                                if (results != null && results.decompileCompleted()) {
                                    HighFunction highFunc = results.getHighFunction();
                                    if (highFunc != null) {
                                        Iterator<HighSymbol> symbolIter = highFunc.getLocalSymbolMap().getSymbols();
                                        while (symbolIter.hasNext() && localVarsAdded < remainingSpace) {
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
                                                localVarsAdded++;
                                            }
                                        }
                                    }
                                }
                            } catch (Exception e) {
                                Msg.warn(this, "searchVariablesPaginated: Error processing function " + function.getName(), e);
                            }

                            functionsProcessed++;
                            if (functionsProcessed >= maxFunctionsToProcess || localVarsAdded >= remainingSpace) {
                                break;
                            }
                        }

                        hasMore = functionsProcessed < funcCount || localVarsAdded >= remainingSpace;
                    } catch (Exception e) {
                        Msg.error(this, "searchVariablesPaginated: Error during local variable search", e);
                    } finally {
                        if (fallbackDecomp != null) {
                            fallbackDecomp.dispose();
                        }
                    }
                }
            }
            
            // Sort the combined results
            matchedVars.sort(Comparator.comparing(a -> a.get("name")));
            
            return new PaginatedResult(matchedVars, hasMore, totalEstimate);
        }

        /**
         * Get DecompileResults for a function, using the cache if available.
         */
        private DecompileResults decompileForVariables(Function function, DecompInterface fallbackDecomp, int timeout) {
            DecompilerCache cache = getDecompilerCache();
            if (cache != null) {
                return cache.getDecompileResults(function, timeout);
            }
            if (fallbackDecomp != null) {
                try {
                    return fallbackDecomp.decompileFunction(function, timeout, new ConsoleTaskMonitor());
                } catch (Exception e) {
                    Msg.warn(this, "Decompilation failed for " + function.getName(), e);
                }
            }
            return null;
        }

        /**
         * Create a fallback DecompInterface if no cache is available. Returns null if cache exists.
         */
        private DecompInterface createFallbackDecomp(Program program) {
            if (getDecompilerCache() != null) {
                return null;
            }
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            return decomp;
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