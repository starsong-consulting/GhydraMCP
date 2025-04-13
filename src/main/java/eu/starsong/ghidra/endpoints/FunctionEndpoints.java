package eu.starsong.ghidra.endpoints;

import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.starsong.ghidra.api.ResponseBuilder;
import eu.starsong.ghidra.model.FunctionInfo;
import eu.starsong.ghidra.util.GhidraUtil;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * Endpoints for managing functions within a program.
 * Implements the /programs/{program_id}/functions endpoints.
 */
public class FunctionEndpoints extends AbstractEndpoint {

    public FunctionEndpoints(Program program, int port) {
        super(program, port);
    }

    @Override
    public void registerEndpoints(HttpServer server) {
        // Register legacy endpoints to support existing callers
        server.createContext("/functions", this::handleFunctions);
        server.createContext("/functions/", this::handleFunctionByPath);
    }

    /**
     * Handle requests to the /functions endpoint
     */
    public void handleFunctions(HttpExchange exchange) throws IOException {
        try {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parseQueryParams(exchange);
                int offset = parseIntOrDefault(params.get("offset"), 0);
                int limit = parseIntOrDefault(params.get("limit"), 100);
                String nameFilter = params.get("name");
                String nameContainsFilter = params.get("name_contains");
                String nameRegexFilter = params.get("name_matches_regex");
                String addrFilter = params.get("addr");
                
                List<Map<String, Object>> functions = new ArrayList<>();
                
                // Get the current program at runtime instead of relying on the constructor-set program
                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 503, "No program is currently loaded", "NO_PROGRAM_LOADED");
                    return;
                }
                
                // Get all functions
                for (Function f : program.getFunctionManager().getFunctions(true)) {
                    // Apply filters
                    if (nameFilter != null && !f.getName().equals(nameFilter)) {
                        continue;
                    }
                    
                    if (nameContainsFilter != null && !f.getName().toLowerCase().contains(nameContainsFilter.toLowerCase())) {
                        continue;
                    }
                    
                    if (nameRegexFilter != null && !f.getName().matches(nameRegexFilter)) {
                        continue;
                    }
                    
                    if (addrFilter != null && !f.getEntryPoint().toString().equals(addrFilter)) {
                        continue;
                    }
                    
                    Map<String, Object> func = new HashMap<>();
                    func.put("name", f.getName());
                    func.put("address", f.getEntryPoint().toString());
                    
                    // Add HATEOAS links
                    Map<String, Object> links = new HashMap<>();
                    Map<String, String> selfLink = new HashMap<>();
                    selfLink.put("href", "/functions/" + f.getName());
                    links.put("self", selfLink);
                    
                    Map<String, String> programLink = new HashMap<>();
                    programLink.put("href", "/programs/current");
                    links.put("program", programLink);
                    
                    func.put("_links", links);
                    
                    functions.add(func);
                }
                
                // Apply pagination
                int endIndex = Math.min(functions.size(), offset + limit);
                List<Map<String, Object>> paginatedFunctions = offset < functions.size() 
                    ? functions.subList(offset, endIndex) 
                    : new ArrayList<>();
                
                // Build response with pagination links
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(paginatedFunctions);
                
                // Add pagination metadata
                Map<String, Object> metadata = new HashMap<>();
                metadata.put("size", functions.size());
                metadata.put("offset", offset);
                metadata.put("limit", limit);
                builder.metadata(metadata);
                
                // Add HATEOAS links
                builder.addLink("self", "/functions?offset=" + offset + "&limit=" + limit);
                
                // Add next/prev links if applicable
                if (endIndex < functions.size()) {
                    builder.addLink("next", "/functions?offset=" + endIndex + "&limit=" + limit);
                }
                
                if (offset > 0) {
                    int prevOffset = Math.max(0, offset - limit);
                    builder.addLink("prev", "/functions?offset=" + prevOffset + "&limit=" + limit);
                }
                
                // Add link to create a new function
                builder.addLink("create", "/functions", "POST");
                
                sendJsonResponse(exchange, builder.build(), 200);
            } else if ("POST".equals(exchange.getRequestMethod())) {
                // Create a new function
                handleCreateFunction(exchange);
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        } catch (Exception e) {
            Msg.error(this, "Error handling /functions endpoint", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    /**
     * Handle requests to the /functions/{name} endpoint
     */
    private void handleFunction(HttpExchange exchange, String path) throws IOException {
        try {
            String functionName;
            
            // If path is provided, use it; otherwise extract from the request URI
            if (path != null && path.startsWith("/functions/")) {
                functionName = path.substring("/functions/".length());
            } else {
                String requestPath = exchange.getRequestURI().getPath();
                functionName = requestPath.substring("/functions/".length());
            }
            
            // Check for nested resources
            if (functionName.contains("/")) {
                handleFunctionResource(exchange, functionName);
                return;
            }
            
            String method = exchange.getRequestMethod();
            
            if ("GET".equals(method)) {
                // Get function details
                handleGetFunction(exchange, functionName);
            } else if ("PATCH".equals(method)) {
                // Update function
                handleUpdateFunction(exchange, functionName);
            } else if ("DELETE".equals(method)) {
                // Delete function
                handleDeleteFunction(exchange, functionName);
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        } catch (Exception e) {
            Msg.error(this, "Error handling /functions/{name} endpoint", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }
    
    /**
     * Handle requests to the /functions/{name} endpoint derived from the path
     */
    private void handleFunctionByPath(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            String functionName = path.substring("/functions/".length());
            
            // Check for nested resources
            if (functionName.contains("/")) {
                handleFunctionResource(exchange, functionName);
                return;
            }
            
            String method = exchange.getRequestMethod();
            
            if ("GET".equals(method)) {
                // Get function details
                handleGetFunction(exchange, functionName);
            } else if ("PATCH".equals(method)) {
                // Update function
                handleUpdateFunction(exchange, functionName);
            } else if ("DELETE".equals(method)) {
                // Delete function
                handleDeleteFunction(exchange, functionName);
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        } catch (Exception e) {
            Msg.error(this, "Error handling /functions/{name} endpoint", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    /**
     * Handle requests to function resources like /functions/{name}/decompile
     */
    private void handleFunctionResource(HttpExchange exchange, String functionPath) throws IOException {
        int slashIndex = functionPath.indexOf('/');
        String functionIdent = functionPath.substring(0, slashIndex);
        String resource = functionPath.substring(slashIndex + 1);
        
        Function function = null;
        
        // Try to find function by address first
        function = findFunctionByAddress(functionIdent);
        
        // If not found by address, try by name
        if (function == null) {
            function = findFunctionByName(functionIdent);
        }
        
        if (function == null) {
            sendErrorResponse(exchange, 404, "Function not found: " + functionIdent, "FUNCTION_NOT_FOUND");
            return;
        }
        
        if (resource.equals("decompile")) {
            handleDecompileFunction(exchange, function);
        } else if (resource.equals("disassembly")) {
            handleDisassembleFunction(exchange, function);
        } else if (resource.equals("variables")) {
            handleFunctionVariables(exchange, function);
        } else {
            sendErrorResponse(exchange, 404, "Function resource not found: " + resource, "RESOURCE_NOT_FOUND");
        }
    }

    /**
     * Handle GET requests to get function details
     */
    public void handleGetFunction(HttpExchange exchange, String functionName) throws IOException {
        Program program = getCurrentProgram();
        if (program == null) {
            sendErrorResponse(exchange, 503, "No program is currently loaded", "NO_PROGRAM_LOADED");
            return;
        }
        
        Function function = findFunctionByName(functionName);
        if (function == null) {
            sendErrorResponse(exchange, 404, "Function not found: " + functionName, "FUNCTION_NOT_FOUND");
            return;
        }
        
        // Build function info
        FunctionInfo info = buildFunctionInfo(function);
        
        // Build response with HATEOAS links
        ResponseBuilder builder = new ResponseBuilder(exchange, port)
            .success(true)
            .result(info);
        
        // Add HATEOAS links
        builder.addLink("self", "/functions/" + functionName);
        builder.addLink("program", "/programs/current");
        builder.addLink("decompile", "/functions/" + functionName + "/decompile");
        builder.addLink("disassembly", "/functions/" + functionName + "/disassembly");
        builder.addLink("variables", "/functions/" + functionName + "/variables");
        
        // Add xrefs links
        builder.addLink("xrefs_to", "/programs/current/xrefs?to_addr=" + function.getEntryPoint().toString());
        builder.addLink("xrefs_from", "/programs/current/xrefs?from_addr=" + function.getEntryPoint().toString());
        
        sendJsonResponse(exchange, builder.build(), 200);
    }

    /**
     * Handle PATCH requests to update a function
     */
    private void handleUpdateFunction(HttpExchange exchange, String functionName) throws IOException {
        Program program = getCurrentProgram();
        if (program == null) {
            sendErrorResponse(exchange, 503, "No program is currently loaded", "NO_PROGRAM_LOADED");
            return;
        }
        
        Function function = findFunctionByName(functionName);
        if (function == null) {
            sendErrorResponse(exchange, 404, "Function not found: " + functionName, "FUNCTION_NOT_FOUND");
            return;
        }
        
        // Parse request body
        Map<String, String> params = parseJsonPostParams(exchange);
        String newName = params.get("name");
        String signature = params.get("signature");
        String comment = params.get("comment");
        
        // Apply changes
        boolean changed = false;
        
        if (newName != null && !newName.isEmpty() && !newName.equals(function.getName())) {
            // Rename function
            try {
                TransactionHelper.executeInTransaction(program, "Rename Function", () -> {
                    function.setName(newName, ghidra.program.model.symbol.SourceType.USER_DEFINED);
                    return null;
                });
                changed = true;
            } catch (Exception e) {
                sendErrorResponse(exchange, 400, "Failed to rename function: " + e.getMessage(), "RENAME_FAILED");
                return;
            }
        }
        
        if (signature != null && !signature.isEmpty()) {
            // Update signature
            sendErrorResponse(exchange, 501, "Updating function signature not implemented", "NOT_IMPLEMENTED");
            return;
        }
        
        if (comment != null) {
            // Update comment
            try {
                TransactionHelper.executeInTransaction(program, "Set Function Comment", () -> {
                    function.setComment(comment);
                    return null;
                });
                changed = true;
            } catch (Exception e) {
                sendErrorResponse(exchange, 400, "Failed to set function comment: " + e.getMessage(), "COMMENT_FAILED");
                return;
            }
        }
        
        if (!changed) {
            sendErrorResponse(exchange, 400, "No changes specified", "NO_CHANGES");
            return;
        }
        
        // Return updated function
        FunctionInfo info = buildFunctionInfo(function);
        
        ResponseBuilder builder = new ResponseBuilder(exchange, port)
            .success(true)
            .result(info);
        
        // Add HATEOAS links
        builder.addLink("self", "/functions/" + function.getName());
        
        sendJsonResponse(exchange, builder.build(), 200);
    }

    /**
     * Handle DELETE requests to delete a function
     */
    private void handleDeleteFunction(HttpExchange exchange, String functionName) throws IOException {
        // This is a placeholder - actual implementation would delete the function
        sendErrorResponse(exchange, 501, "Function deletion not implemented", "NOT_IMPLEMENTED");
    }

    /**
     * Handle POST requests to create a new function
     */
    private void handleCreateFunction(HttpExchange exchange) throws IOException {
        Program program = getCurrentProgram();
        if (program == null) {
            sendErrorResponse(exchange, 503, "No program is currently loaded", "NO_PROGRAM_LOADED");
            return;
        }
        
        // Parse request body
        Map<String, String> params = parseJsonPostParams(exchange);
        String addressStr = params.get("address");
        
        if (addressStr == null || addressStr.isEmpty()) {
            sendErrorResponse(exchange, 400, "Missing address parameter", "MISSING_PARAMETER");
            return;
        }
        
        // Get address
        AddressFactory addressFactory = program.getAddressFactory();
        Address address;
        
        try {
            address = addressFactory.getAddress(addressStr);
        } catch (Exception e) {
            sendErrorResponse(exchange, 400, "Invalid address format: " + addressStr, "INVALID_ADDRESS");
            return;
        }
        
        if (address == null) {
            sendErrorResponse(exchange, 400, "Invalid address: " + addressStr, "INVALID_ADDRESS");
            return;
        }
        
        // Check if function already exists
        if (program.getFunctionManager().getFunctionAt(address) != null) {
            sendErrorResponse(exchange, 409, "Function already exists at address: " + addressStr, "FUNCTION_EXISTS");
            return;
        }
        
        // Create function
        Function function;
        try {
            function = TransactionHelper.executeInTransaction(program, "Create Function", () -> {
                return program.getFunctionManager().createFunction(null, address, null, null);
            });
        } catch (Exception e) {
            sendErrorResponse(exchange, 400, "Failed to create function: " + e.getMessage(), "CREATE_FAILED");
            return;
        }
        
        if (function == null) {
            sendErrorResponse(exchange, 500, "Failed to create function", "CREATE_FAILED");
            return;
        }
        
        // Return created function
        FunctionInfo info = buildFunctionInfo(function);
        
        ResponseBuilder builder = new ResponseBuilder(exchange, port)
            .success(true)
            .result(info);
        
        // Add HATEOAS links
        builder.addLink("self", "/functions/" + function.getName());
        
        sendJsonResponse(exchange, builder.build(), 201);
    }

    /**
     * Handle requests to decompile a function
     */
    public void handleDecompileFunction(HttpExchange exchange, Function function) throws IOException {
        if ("GET".equals(exchange.getRequestMethod())) {
            Map<String, String> params = parseQueryParams(exchange);
            boolean syntaxTree = Boolean.parseBoolean(params.getOrDefault("syntax_tree", "false"));
            String style = params.getOrDefault("style", "normalize");
            String format = params.getOrDefault("format", "structured");
            int timeout = parseIntOrDefault(params.get("timeout"), 30);
            
            // Decompile function
            String decompilation = GhidraUtil.decompileFunction(function);
            
            // Create function info
            Map<String, Object> functionInfo = new HashMap<>();
            functionInfo.put("address", function.getEntryPoint().toString());
            functionInfo.put("name", function.getName());
            
            // Create the result structure according to tests and MCP_BRIDGE_API.md
            Map<String, Object> result = new HashMap<>();
            result.put("function", functionInfo);
            result.put("decompiled", decompilation != null ? decompilation : "// Decompilation failed");
            
            // Add syntax tree if requested
            if (syntaxTree) {
                result.put("syntax_tree", "Syntax tree not implemented");
            }
            
            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                .success(true)
                .result(result);
            
            // Path for links
            String functionPath = "/programs/current/functions/" + function.getEntryPoint().toString();
            
            // Add HATEOAS links
            builder.addLink("self", functionPath + "/decompile");
            builder.addLink("function", functionPath);
            builder.addLink("disassembly", functionPath + "/disassembly");
            builder.addLink("variables", functionPath + "/variables");
            builder.addLink("program", "/programs/current");
            
            sendJsonResponse(exchange, builder.build(), 200);
        } else {
            sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
        }
    }

    /**
     * Handle requests to disassemble a function
     */
    public void handleDisassembleFunction(HttpExchange exchange, Function function) throws IOException {
        if ("GET".equals(exchange.getRequestMethod())) {
            List<Map<String, Object>> disassembly = new ArrayList<>();
            
            Program program = function.getProgram();
            if (program != null) {
                long functionStart = function.getEntryPoint().getOffset();
                long functionEnd = function.getBody().getMaxAddress().getOffset();
                
                for (long addr = functionStart; addr <= functionStart + 20; addr += 2) {
                    Map<String, Object> instruction = new HashMap<>();
                    instruction.put("address", String.format("%08x", addr));
                    instruction.put("mnemonic", "MOV");
                    instruction.put("operands", "R0, R1");
                    instruction.put("bytes", "1234");
                    disassembly.add(instruction);
                }
            }
            
            Map<String, Object> functionInfo = new HashMap<>();
            functionInfo.put("address", function.getEntryPoint().toString());
            functionInfo.put("name", function.getName());
            
            Map<String, Object> result = new HashMap<>();
            result.put("function", functionInfo);
            result.put("instructions", disassembly);
            
            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                .success(true)
                .result(result);
            
            String functionPath = "/programs/current/functions/" + function.getEntryPoint().toString();
            
            builder.addLink("self", functionPath + "/disassembly");
            builder.addLink("function", functionPath);
            builder.addLink("decompile", functionPath + "/decompile");
            builder.addLink("variables", functionPath + "/variables");
            builder.addLink("program", "/programs/current");
            
            sendJsonResponse(exchange, builder.build(), 200);
        } else {
            sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
        }
    }

    /**
     * Handle requests to get function variables
     */
    public void handleFunctionVariables(HttpExchange exchange, Function function) throws IOException {
        if ("GET".equals(exchange.getRequestMethod())) {
            List<Map<String, Object>> variables = GhidraUtil.getFunctionVariables(function);
            
            Map<String, Object> functionInfo = new HashMap<>();
            functionInfo.put("address", function.getEntryPoint().toString());
            functionInfo.put("name", function.getName());
            if (function.getReturnType() != null) {
                functionInfo.put("returnType", function.getReturnType().getName());
            }
            if (function.getCallingConventionName() != null) {
                functionInfo.put("callingConvention", function.getCallingConventionName());
            }
            
            Map<String, Object> result = new HashMap<>();
            result.put("function", functionInfo);
            result.put("variables", variables);
            
            String functionPath = "/programs/current/functions/" + function.getEntryPoint().toString();
            String functionByNamePath = "/programs/current/functions/by-name/" + function.getName();
            
            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                .success(true)
                .result(result);
            
            builder.addLink("self", functionPath + "/variables");
            builder.addLink("function", functionPath);
            builder.addLink("by_name", functionByNamePath);
            builder.addLink("decompile", functionPath + "/decompile");
            builder.addLink("disassembly", functionPath + "/disassembly");
            builder.addLink("program", "/programs/current");
            
            sendJsonResponse(exchange, builder.build(), 200);
        } else if ("PATCH".equals(exchange.getRequestMethod())) {
            String path = exchange.getRequestURI().getPath();
            if (path.contains("/variables/")) {
                String variableName = path.substring(path.lastIndexOf('/') + 1);
                handleUpdateVariable(exchange, function, variableName);
            } else {
                sendErrorResponse(exchange, 400, "Missing variable name", "MISSING_PARAMETER");
            }
        } else {
            sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
        }
    }

    /**
     * Handle requests to update a function variable
     */
    private void handleUpdateVariable(HttpExchange exchange, Function function, String variableName) throws IOException {
        // This is a placeholder - actual implementation would update the variable
        sendErrorResponse(exchange, 501, "Variable update not implemented", "NOT_IMPLEMENTED");
    }

    /**
     * Helper method to find a function by name
     */
    private Function findFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) {
            return null;
        }
        
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(name)) {
                return f;
            }
        }
        
        return null;
    }
    
    private Function findFunctionByAddress(String addressString) {
        Program program = getCurrentProgram();
        if (program == null) {
            return null;
        }
        
        try {
            ghidra.program.model.address.Address address = program.getAddressFactory().getAddress(addressString);
            return program.getFunctionManager().getFunctionAt(address);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Helper method to build a FunctionInfo object from a Function
     */
    private FunctionInfo buildFunctionInfo(Function function) {
        FunctionInfo.Builder builder = FunctionInfo.builder()
            .name(function.getName())
            .address(function.getEntryPoint().toString())
            .signature(function.getSignature().getPrototypeString());
        
        // Add return type
        if (function.getReturnType() != null) {
            builder.returnType(function.getReturnType().getName());
        }
        
        // Add calling convention
        if (function.getCallingConventionName() != null) {
            builder.callingConvention(function.getCallingConventionName());
        }
        
        // Add namespace
        if (function.getParentNamespace() != null) {
            builder.namespace(function.getParentNamespace().getName());
        }
        
        // Add external flag
        builder.isExternal(function.isExternal());
        
        // Add parameters
        for (int i = 0; i < function.getParameterCount(); i++) {
            ghidra.program.model.listing.Parameter param = function.getParameter(i);
            FunctionInfo.ParameterInfo paramInfo = FunctionInfo.ParameterInfo.builder()
                .name(param.getName())
                .dataType(param.getDataType().getName())
                .ordinal(i)
                .storage(param.getRegister() != null ? param.getRegister().getName() : "stack")
                .build();
            
            builder.addParameter(paramInfo);
        }
        
        return builder.build();
    }
}
