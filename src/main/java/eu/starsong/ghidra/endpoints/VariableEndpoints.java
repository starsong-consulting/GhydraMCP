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
            server.createContext("/functions/*/variables/*", this::handleFunctionVariableOperation);
            server.createContext("/functions/by-name/*/variables/*", this::handleFunctionVariableByNameOperation);
            // Note: /functions/{name}/variables (listing) is still handled within FunctionEndpoints
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
                // Adjust for local variable processing
                int localOffset = startIdx - globalVarCount;
                int localLimit = limit;
                
                // Process functions to get the local variables
                DecompInterface decomp = null;
                try {
                    decomp = new DecompInterface();
                    if (decomp.openProgram(program)) {
                        int localVarIndex = 0;
                        int functionsProcessed = 0;
                        int maxFunctionsToProcess = 20; // Limit how many functions we process per request
                        
                        for (Function function : program.getFunctionManager().getFunctions(true)) {
                            try {
                                DecompileResults results = decomp.decompileFunction(function, 10, new ConsoleTaskMonitor());
                                if (results != null && results.decompileCompleted()) {
                                    HighFunction highFunc = results.getHighFunction();
                                    if (highFunc != null) {
                                        List<Map<String, String>> functionVars = new ArrayList<>();
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
                                                functionVars.add(varInfo);
                                            }
                                        }
                                        
                                        // Sort function variables by name
                                        functionVars.sort(Comparator.comparing(a -> a.get("name")));
                                        
                                        // Add only the needed variables for this page
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
                                // Stop processing if we've hit our limits
                                break;
                            }
                        }
                        
                        // Determine if we have more variables
                        hasMore = functionsProcessed < funcCount || localVarIndex >= localOffset + localLimit;
                    }
                } catch (Exception e) {
                    Msg.error(this, "listVariablesPaginated: Error during local variable processing", e);
                } finally {
                    if (decomp != null) {
                        decomp.dispose();
                    }
                }
            } else {
                // This means we already have some globals and may need a few locals to complete the page
                int remainingSpace = limit - variables.size();
                if (remainingSpace > 0) {
                    // Process just enough functions to fill the page
                    DecompInterface decomp = null;
                    try {
                        decomp = new DecompInterface();
                        if (decomp.openProgram(program)) {
                            int functionsProcessed = 0;
                            int maxFunctionsToProcess = 5; // Limit how many functions we process
                            int localVarsAdded = 0;
                            
                            for (Function function : program.getFunctionManager().getFunctions(true)) {
                                try {
                                    DecompileResults results = decomp.decompileFunction(function, 10, new ConsoleTaskMonitor());
                                    if (results != null && results.decompileCompleted()) {
                                        HighFunction highFunc = results.getHighFunction();
                                        if (highFunc != null) {
                                            Iterator<HighSymbol> symbolIter = highFunc.getLocalSymbolMap().getSymbols();
                                            while (symbolIter.hasNext() && localVarsAdded < remainingSpace) {
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
                                    // Stop processing if we've hit our limits
                                    break;
                                }
                            }
                            
                            // Determine if we have more variables
                            hasMore = functionsProcessed < funcCount || localVarsAdded >= remainingSpace;
                        }
                    } catch (Exception e) {
                        Msg.error(this, "listVariablesPaginated: Error during local variable processing", e);
                    } finally {
                        if (decomp != null) {
                            decomp.dispose();
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
                // Adjust for local variable processing
                int localOffset = startIdx - globalCount;
                int localLimit = limit;
                
                // Process functions to get the local variables
                DecompInterface decomp = null;
                try {
                    decomp = new DecompInterface();
                    if (decomp.openProgram(program)) {
                        int localVarIndex = 0;
                        int functionsProcessed = 0;
                        int maxFunctionsToProcess = 30; // Limit how many functions we process for search
                        
                        for (Function function : program.getFunctionManager().getFunctions(true)) {
                            try {
                                DecompileResults results = decomp.decompileFunction(function, 5, new ConsoleTaskMonitor());
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
                                        
                                        // Sort function matches by name
                                        functionMatches.sort(Comparator.comparing(a -> a.get("name")));
                                        
                                        // Add only the needed variables for this page
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
                                // Stop processing if we've hit our limits
                                break;
                            }
                        }
                        
                        // Determine if we have more variables
                        hasMore = functionsProcessed < funcCount || localVarIndex >= localOffset + localLimit;
                    }
                } catch (Exception e) {
                    Msg.error(this, "searchVariablesPaginated: Error during local variable search", e);
                } finally {
                    if (decomp != null) {
                        decomp.dispose();
                    }
                }
            } else {
                // This means we already have some globals and may need a few locals to complete the page
                int remainingSpace = limit - matchedVars.size();
                if (remainingSpace > 0) {
                    // Process functions until we've filled the page
                    DecompInterface decomp = null;
                    try {
                        decomp = new DecompInterface();
                        if (decomp.openProgram(program)) {
                            int functionsProcessed = 0;
                            int maxFunctionsToProcess = 5; // Limit how many functions we process
                            int localVarsAdded = 0;
                            
                            for (Function function : program.getFunctionManager().getFunctions(true)) {
                                try {
                                    DecompileResults results = decomp.decompileFunction(function, 5, new ConsoleTaskMonitor());
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
                                    // Stop processing if we've hit our limits
                                    break;
                                }
                            }
                            
                            // Determine if we have more variables
                            hasMore = functionsProcessed < funcCount || localVarsAdded >= remainingSpace;
                        }
                    } catch (Exception e) {
                        Msg.error(this, "searchVariablesPaginated: Error during local variable search", e);
                    } finally {
                        if (decomp != null) {
                            decomp.dispose();
                        }
                    }
                }
            }
            
            // Sort the combined results
            matchedVars.sort(Comparator.comparing(a -> a.get("name")));
            
            return new PaginatedResult(matchedVars, hasMore, totalEstimate);
        }

        // --- Helper Methods ---

        private String getDataTypeName(Program program, Address address) {
            // This might be better in GhidraUtil if used elsewhere
            ghidra.program.model.listing.Data data = program.getListing().getDataAt(address);
            if (data == null) return "undefined";
            DataType dt = data.getDataType();
            return dt != null ? dt.getName() : "unknown";
        }
        
        /**
         * Handle operations on a specific function variable (by function address or by name)
         * This handles GET/PATCH operations for /functions/{address}/variables/{varName}
         * or /functions/by-name/{name}/variables/{varName}
         */
        public void handleFunctionVariableOperation(HttpExchange exchange) throws IOException {
            try {
                String path = exchange.getRequestURI().getPath();
                String[] parts = path.split("/");
                
                // Path should be like /functions/{address}/variables/{varName}
                if (parts.length < 5) {
                    sendErrorResponse(exchange, 400, "Invalid URL format", "INVALID_URL_FORMAT");
                    return;
                }
                
                // Extract function address from path
                String functionAddress = parts[2];
                String variableName = parts[4];
                
                // Handle different HTTP methods
                if ("PATCH".equals(exchange.getRequestMethod())) {
                    handleVariablePatch(exchange, functionAddress, variableName, false);
                } else if ("GET".equals(exchange.getRequestMethod())) {
                    handleVariableGet(exchange, functionAddress, variableName, false);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed");
                }
            } catch (Exception e) {
                Msg.error(this, "Error handling function variable operation", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
            }
        }
        
        /**
         * Handle operations on a specific function variable by function name
         * This handles GET/PATCH operations for /functions/by-name/{functionName}/variables/{varName}
         */
        private void handleFunctionVariableByNameOperation(HttpExchange exchange) throws IOException {
            try {
                String path = exchange.getRequestURI().getPath();
                String[] parts = path.split("/");
                
                // Path should be like /functions/by-name/{functionName}/variables/{varName}
                if (parts.length < 6) {
                    sendErrorResponse(exchange, 400, "Invalid URL format", "INVALID_URL_FORMAT");
                    return;
                }
                
                // Extract function name from path
                String functionName = parts[3];
                String variableName = parts[5];
                
                // Handle different HTTP methods
                if ("PATCH".equals(exchange.getRequestMethod())) {
                    handleVariablePatch(exchange, functionName, variableName, true);
                } else if ("GET".equals(exchange.getRequestMethod())) {
                    handleVariableGet(exchange, functionName, variableName, true);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed");
                }
            } catch (Exception e) {
                Msg.error(this, "Error handling function variable by name operation", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
            }
        }
        
        /**
         * Handle GET request for a specific variable
         */
        private void handleVariableGet(HttpExchange exchange, String functionIdentifier, String variableName, boolean isByName) throws IOException {
            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                return;
            }
            
            // Find the function
            Function function = null;
            if (isByName) {
                for (Function f : program.getFunctionManager().getFunctions(true)) {
                    if (f.getName().equals(functionIdentifier)) {
                        function = f;
                        break;
                    }
                }
            } else {
                try {
                    Address address = program.getAddressFactory().getAddress(functionIdentifier);
                    function = program.getFunctionManager().getFunctionAt(address);
                } catch (Exception e) {
                    Msg.error(this, "Error getting function at address " + functionIdentifier, e);
                }
            }
            
            if (function == null) {
                sendErrorResponse(exchange, 404, "Function not found", "FUNCTION_NOT_FOUND");
                return;
            }
            
            // Find variable in function
            Map<String, Object> variableInfo = findVariableInFunction(function, variableName);
            
            if (variableInfo == null) {
                sendErrorResponse(exchange, 404, "Function resource not found: variables/" + variableName, "RESOURCE_NOT_FOUND");
                return;
            }
            
            // Create HATEOAS-compliant response
            String functionPathBase = isByName ? "/functions/by-name/" + function.getName() : "/functions/" + function.getEntryPoint();
            
            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                .success(true)
                .addLink("self", functionPathBase + "/variables/" + variableName)
                .addLink("function", functionPathBase)
                .addLink("variables", functionPathBase + "/variables")
                .result(variableInfo);
            
            sendJsonResponse(exchange, builder.build(), 200);
        }
        
        /**
         * Handle PATCH request to update a variable (rename or change data type)
         */
        private void handleVariablePatch(HttpExchange exchange, String functionIdentifier, String variableName, boolean isByName) throws IOException {
            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                return;
            }
            
            // Parse the request body to get the update data
            String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            JsonObject jsonRequest;
            try {
                jsonRequest = new Gson().fromJson(requestBody, JsonObject.class);
            } catch (Exception e) {
                sendErrorResponse(exchange, 400, "Invalid JSON payload", "INVALID_JSON");
                return;
            }
            
            // Find the function
            Function function = null;
            if (isByName) {
                for (Function f : program.getFunctionManager().getFunctions(true)) {
                    if (f.getName().equals(functionIdentifier)) {
                        function = f;
                        break;
                    }
                }
            } else {
                try {
                    Address address = program.getAddressFactory().getAddress(functionIdentifier);
                    function = program.getFunctionManager().getFunctionAt(address);
                } catch (Exception e) {
                    Msg.error(this, "Error getting function at address " + functionIdentifier, e);
                }
            }
            
            if (function == null) {
                sendErrorResponse(exchange, 404, "Function not found", "FUNCTION_NOT_FOUND");
                return;
            }
            
            // Make sure we have a variable to update
            Map<String, Object> variableInfo = findVariableInFunction(function, variableName);
            if (variableInfo == null) {
                sendErrorResponse(exchange, 404, "Function resource not found: variables/" + variableName, "RESOURCE_NOT_FOUND");
                return;
            }
            
            // Check if this is a decompiler-only variable
            boolean isDecompilerOnly = Boolean.TRUE.equals(variableInfo.get("decompilerOnly"));
            
            // Get requested changes
            String newName = null;
            String newDataType = null;
            
            if (jsonRequest.has("name")) {
                newName = jsonRequest.get("name").getAsString();
            }
            
            if (jsonRequest.has("data_type")) {
                newDataType = jsonRequest.get("data_type").getAsString();
            }
            
            boolean success = false;
            String message = "";
            
            try {
                if (isDecompilerOnly) {
                    // For decompiler-only variables, use HighFunctionDBUtil
                    success = updateDecompilerVariable(function, variableName, newName, newDataType);
                    message = success ? "Updated decompiler variable" : "Failed to update decompiler variable";
                } else {
                    // For regular variables, use the existing parameter/local variable mechanism
                    success = updateRegularVariable(function, variableName, newName, newDataType);
                    message = success ? "Updated variable" : "Failed to update variable";
                }
            } catch (Exception e) {
                Msg.error(this, "Error updating variable: " + e.getMessage(), e);
                sendErrorResponse(exchange, 500, "Error updating variable: " + e.getMessage());
                return;
            }
            
            if (success) {
                // Get updated variable info
                Map<String, Object> updatedInfo;
                if (newName != null) {
                    // If renamed, use the new name to find variable
                    updatedInfo = findVariableInFunction(function, newName);
                } else {
                    // Otherwise use the original name
                    updatedInfo = findVariableInFunction(function, variableName);
                }
                
                if (updatedInfo == null) {
                    // This shouldn't happen if the update was successful
                    updatedInfo = new HashMap<>();
                    updatedInfo.put("message", message);
                }
                
                // Create HATEOAS-compliant response
                String functionPathBase = isByName ? "/functions/by-name/" + function.getName() : "/functions/" + function.getEntryPoint();
                
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .addLink("self", functionPathBase + "/variables/" + (newName != null ? newName : variableName))
                    .addLink("function", functionPathBase)
                    .addLink("variables", functionPathBase + "/variables")
                    .result(updatedInfo);
                
                sendJsonResponse(exchange, builder.build(), 200);
            } else {
                sendErrorResponse(exchange, 500, "Failed to update variable: " + message);
            }
        }
        
        /**
         * Update a regular variable (parameter or local variable)
         */
        private boolean updateRegularVariable(Function function, String variableName, String newName, String newDataType) {
            try {
                // Find and update parameter
                for (Parameter param : function.getParameters()) {
                    if (param.getName().equals(variableName)) {
                        if (newName != null) {
                            param.setName(newName, SourceType.USER_DEFINED);
                        }
                        // Updating data type for parameters would go here
                        return true;
                    }
                }
                
                // Find and update local variable (use ghidra.program.model.listing.Variable)
                for (ghidra.program.model.listing.Variable var : function.getAllVariables()) {
                    if (var.getName().equals(variableName) && !(var instanceof Parameter)) {
                        if (newName != null) {
                            var.setName(newName, SourceType.USER_DEFINED);
                        }
                        // Updating data type for local variables would go here
                        return true;
                    }
                }
                
                return false;
            } catch (Exception e) {
                Msg.error(this, "Error updating regular variable", e);
                return false;
            }
        }
        
        /**
         * Update a decompiler-generated variable
         */
        private boolean updateDecompilerVariable(Function function, String variableName, String newName, String newDataType) {
            if (newName == null) {
                // Nothing to do
                return false;
            }
            
            try {
                Msg.info(this, "Attempting to rename decompiler variable: " + variableName + " to " + newName);
                
                // This requires a decompile operation to get the HighFunction
                DecompInterface decomp = new DecompInterface();
                try {
                    decomp.openProgram(getCurrentProgram());
                    DecompileResults results = decomp.decompileFunction(function, 30, new ConsoleTaskMonitor());
                    
                    if (results.decompileCompleted()) {
                        HighFunction highFunc = results.getHighFunction();
                        if (highFunc != null) {
                            // Get the local symbol map
                            LocalSymbolMap symbolMap = highFunc.getLocalSymbolMap();
                            
                            // Find the variable in the high function
                            HighSymbol symbol = null;
                            Iterator<HighSymbol> symbolIter = symbolMap.getSymbols();
                            while (symbolIter.hasNext()) {
                                HighSymbol hs = symbolIter.next();
                                if (hs.getName().equals(variableName)) {
                                    symbol = hs;
                                    Msg.info(this, "Found decompiler variable: " + variableName);
                                    break;
                                }
                            }
                            
                            if (symbol != null) {
                                Msg.info(this, "Starting transaction to rename: " + variableName);
                                // Use transaction to update the variable
                                int txId = getCurrentProgram().startTransaction("Update Decompiler Variable");
                                try {
                                    // Rename the variable using HighFunctionDBUtil
                                    // This method returns void, so we assume success if no exception is thrown
                                    HighFunctionDBUtil.updateDBVariable(
                                        symbol, newName, null, SourceType.USER_DEFINED);
                                    
                                    // If we reach here, it was successful
                                    Msg.info(this, "Successfully renamed variable to: " + newName);
                                    getCurrentProgram().endTransaction(txId, true);
                                    return true;
                                } catch (Exception e) {
                                    getCurrentProgram().endTransaction(txId, false);
                                    Msg.error(this, "Error updating decompiler variable: " + e.getMessage(), e);
                                    return false;
                                }
                            } else {
                                Msg.error(this, "Could not find decompiler variable: " + variableName);
                            }
                        } else {
                            Msg.error(this, "HighFunction is null after decompilation");
                        }
                    } else {
                        Msg.error(this, "Decompilation did not complete successfully for function: " + function.getName());
                    }
                } finally {
                    decomp.dispose();
                }
                return false;
            } catch (Exception e) {
                Msg.error(this, "Error updating decompiler variable", e);
                return false;
            }
        }
        
        /**
         * Find a variable in the function, including decompiler-generated variables
         */
        private Map<String, Object> findVariableInFunction(Function function, String variableName) {
            // First check regular parameters and local variables
            for (Parameter param : function.getParameters()) {
                if (param.getName().equals(variableName)) {
                    Map<String, Object> info = new HashMap<>();
                    info.put("name", param.getName());
                    info.put("dataType", param.getDataType().getName());
                    info.put("type", "parameter");
                    info.put("storage", param.getVariableStorage().toString());
                    info.put("ordinal", param.getOrdinal());
                    info.put("decompilerOnly", false);
                    return info;
                }
            }
            
            for (ghidra.program.model.listing.Variable var : function.getAllVariables()) {
                if (var.getName().equals(variableName) && !(var instanceof Parameter)) {
                    Map<String, Object> info = new HashMap<>();
                    info.put("name", var.getName());
                    info.put("dataType", var.getDataType().getName());
                    info.put("type", "local");
                    info.put("storage", var.getVariableStorage().toString());
                    info.put("decompilerOnly", false);
                    return info;
                }
            }
            
            // Then check decompiler-generated variables
            try {
                // This requires a decompile operation to get the HighFunction
                DecompInterface decomp = new DecompInterface();
                try {
                    decomp.openProgram(getCurrentProgram());
                    DecompileResults results = decomp.decompileFunction(function, 30, new ConsoleTaskMonitor());
                    
                    if (results.decompileCompleted()) {
                        HighFunction highFunc = results.getHighFunction();
                        if (highFunc != null) {
                            LocalSymbolMap localSymbolMap = highFunc.getLocalSymbolMap();
                            
                            // Check local symbol map for the variable
                            Iterator<HighSymbol> symbolIter = localSymbolMap.getSymbols();
                            while (symbolIter.hasNext()) {
                                HighSymbol symbol = symbolIter.next();
                                if (symbol.getName().equals(variableName)) {
                                    Map<String, Object> info = new HashMap<>();
                                    info.put("name", symbol.getName());
                                    info.put("dataType", symbol.getDataType() != null ? symbol.getDataType().getName() : "unknown");
                                    info.put("type", symbol.isParameter() ? "parameter" : "local");
                                    info.put("decompilerOnly", true);
                                    info.put("pcAddress", symbol.getPCAddress() != null ? symbol.getPCAddress().toString() : "N/A");
                                    info.put("storage", symbol.getStorage() != null ? symbol.getStorage().toString() : "N/A");
                                    return info;
                                }
                            }
                        }
                    }
                } finally {
                    decomp.dispose();
                }
            } catch (Exception e) {
                Msg.error(this, "Error examining decompiler variables", e);
            }
            
            // Variable not found
            return null;
        }
    }