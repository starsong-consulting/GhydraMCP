package eu.starsong.ghidra.endpoints;

import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.starsong.ghidra.api.ResponseBuilder;
import eu.starsong.ghidra.model.FunctionInfo;
import eu.starsong.ghidra.util.GhidraUtil;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * Endpoints for managing functions within a program.
 * Implements the /functions endpoints with HATEOAS pattern.
 */
public class FunctionEndpoints extends AbstractEndpoint {

    private PluginTool tool;

    public FunctionEndpoints(Program program, int port) {
        super(program, port);
    }
    
    public FunctionEndpoints(Program program, int port, PluginTool tool) {
        super(program, port);
        this.tool = tool;
    }
    
    @Override
    protected PluginTool getTool() {
        return tool;
    }

    @Override
    public void registerEndpoints(HttpServer server) {
        // Register endpoints in order from most specific to least specific to ensure proper URL path matching
        
        // Specifically handle sub-resource endpoints first (these are the most specific)
        server.createContext("/functions/by-name/", this::handleFunctionByName);
        
        // Then handle address-based endpoints with clear pattern matching
        server.createContext("/functions/", this::handleFunctionByAddress);
        
        // Base endpoint last as it's least specific
        server.createContext("/functions", this::handleFunctions);
        
        // Register function-specific endpoints
        registerAdditionalEndpoints(server);
    }
    
    /**
     * Register additional convenience endpoints
     */
    private void registerAdditionalEndpoints(HttpServer server) {
        // NOTE: The /function endpoint is already registered in ProgramEndpoints
        // We don't register it here to avoid duplicating functionality
    }
    
    /**
     * Handle requests to the /functions/{address} endpoint
     */
    private void handleFunctionByAddress(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            
            // Check if this is the base endpoint
            if (path.equals("/functions") || path.equals("/functions/")) {
                handleFunctions(exchange);
                return;
            }
            
            // Get the current program
            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 503, "No program is currently loaded", "NO_PROGRAM_LOADED");
                return;
            }
            
            // Extract function address from path
            String functionAddress = path.substring("/functions/".length());
            
            // Check for nested resources
            if (functionAddress.contains("/")) {
                String resource = functionAddress.substring(functionAddress.indexOf('/') + 1);
                functionAddress = functionAddress.substring(0, functionAddress.indexOf('/'));
                handleFunctionResource(exchange, functionAddress, resource);
                return;
            }
            
            Function function = findFunctionByAddress(functionAddress);
            if (function == null) {
                sendErrorResponse(exchange, 404, "Function not found at address: " + functionAddress, "FUNCTION_NOT_FOUND");
                return;
            }
            
            String method = exchange.getRequestMethod();
            
            if ("GET".equals(method)) {
                // Get function details using RESTful response structure
                FunctionInfo info = buildFunctionInfo(function);
                
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(info);
                
                // Add HATEOAS links
                String baseUrl = "/functions/" + functionAddress;
                builder.addLink("self", baseUrl);
                builder.addLink("program", "/program");
                builder.addLink("decompile", baseUrl + "/decompile");
                builder.addLink("disassembly", baseUrl + "/disassembly");
                builder.addLink("variables", baseUrl + "/variables");
                builder.addLink("by_name", "/functions/by-name/" + function.getName());
                
                // Add xrefs links
                builder.addLink("xrefs_to", "/xrefs?to_addr=" + function.getEntryPoint());
                builder.addLink("xrefs_from", "/xrefs?from_addr=" + function.getEntryPoint());
                
                sendJsonResponse(exchange, builder.build(), 200);
            } else if ("PATCH".equals(method)) {
                // Update function
                handleUpdateFunctionRESTful(exchange, function);
            } else if ("DELETE".equals(method)) {
                // Delete function
                handleDeleteFunctionRESTful(exchange, function);
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        } catch (Exception e) {
            Msg.error(this, "Error handling /functions/{address} endpoint", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }
    
    /**
     * Handle requests to the /functions/by-name/{name} endpoint
     */
    private void handleFunctionByName(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            
            // Extract function name from path (only supporting new format)
            String functionName = path.substring("/functions/by-name/".length());
            
            // Check for nested resources
            if (functionName.contains("/")) {
                String resource = functionName.substring(functionName.indexOf('/') + 1);
                functionName = functionName.substring(0, functionName.indexOf('/'));
                handleFunctionResource(exchange, functionName, resource);
                return;
            }
            
            Function function = findFunctionByName(functionName);
            if (function == null) {
                sendErrorResponse(exchange, 404, "Function not found with name: " + functionName, "FUNCTION_NOT_FOUND");
                return;
            }
            
            String method = exchange.getRequestMethod();
            
            if ("GET".equals(method)) {
                // Get function details using RESTful response structure
                FunctionInfo info = buildFunctionInfo(function);
                
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(info);
                
                // Add HATEOAS links
                builder.addLink("self", "/functions/by-name/" + functionName);
                builder.addLink("program", "/program");
                builder.addLink("by_address", "/functions/" + function.getEntryPoint());
                builder.addLink("decompile", "/functions/" + function.getEntryPoint() + "/decompile");
                builder.addLink("disassembly", "/functions/" + function.getEntryPoint() + "/disassembly");
                builder.addLink("variables", "/functions/by-name/" + functionName + "/variables");
                
                sendJsonResponse(exchange, builder.build(), 200);
            } else if ("PATCH".equals(method)) {
                // Update function
                handleUpdateFunctionRESTful(exchange, function);
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        } catch (Exception e) {
            Msg.error(this, "Error handling /programs/current/functions/by-name/{name} endpoint", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }
    
    /**
     * Handle requests to all functions within the current program
     */
    private void handleProgramFunctions(HttpExchange exchange) throws IOException {
        try {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parseQueryParams(exchange);
                int offset = parseIntOrDefault(params.get("offset"), 0);
                int limit = parseIntOrDefault(params.get("limit"), 100);
                String nameFilter = params.get("name");
                String nameContainsFilter = params.get("name_contains");
                String nameRegexFilter = params.get("name_matches_regex");
                String addrFilter = params.get("addr");
                
                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program is currently loaded", "NO_PROGRAM_LOADED");
                    return;
                }
                
                List<Map<String, Object>> functions = new ArrayList<>();
                
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
                    selfLink.put("href", "/programs/current/functions/" + f.getEntryPoint());
                    links.put("self", selfLink);
                    
                    Map<String, String> byNameLink = new HashMap<>();
                    byNameLink.put("href", "/programs/current/functions/by-name/" + f.getName());
                    links.put("by_name", byNameLink);
                    
                    Map<String, String> decompileLink = new HashMap<>();
                    decompileLink.put("href", "/programs/current/functions/" + f.getEntryPoint() + "/decompile");
                    links.put("decompile", decompileLink);
                    
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
                
                // Add query parameters for self link
                StringBuilder queryParams = new StringBuilder();
                if (nameFilter != null) {
                    queryParams.append("name=").append(nameFilter).append("&");
                }
                if (nameContainsFilter != null) {
                    queryParams.append("name_contains=").append(nameContainsFilter).append("&");
                }
                if (nameRegexFilter != null) {
                    queryParams.append("name_matches_regex=").append(nameRegexFilter).append("&");
                }
                if (addrFilter != null) {
                    queryParams.append("addr=").append(addrFilter).append("&");
                }
                
                String queryString = queryParams.toString();
                
                // Add HATEOAS links
                builder.addLink("self", "/programs/current/functions?" + queryString + "offset=" + offset + "&limit=" + limit);
                builder.addLink("program", "/programs/current");
                
                // Add next/prev links if applicable
                if (endIndex < functions.size()) {
                    builder.addLink("next", "/programs/current/functions?" + queryString + "offset=" + endIndex + "&limit=" + limit);
                }
                
                if (offset > 0) {
                    int prevOffset = Math.max(0, offset - limit);
                    builder.addLink("prev", "/programs/current/functions?" + queryString + "offset=" + prevOffset + "&limit=" + limit);
                }
                
                // Add link to create a new function
                builder.addLink("create", "/programs/current/functions", "POST");
                
                sendJsonResponse(exchange, builder.build(), 200);
            } else if ("POST".equals(exchange.getRequestMethod())) {
                // Create a new function
                handleCreateFunctionRESTful(exchange);
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        } catch (Exception e) {
            Msg.error(this, "Error handling /programs/current/functions endpoint", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }
    
    /**
     * Handle requests to function resources like /programs/current/functions/{address}/decompile
     */
    private void handleFunctionResourceRESTful(HttpExchange exchange, String functionAddress, String resource) throws IOException {
        Function function = findFunctionByAddress(functionAddress);
        if (function == null) {
            sendErrorResponse(exchange, 404, "Function not found at address: " + functionAddress, "FUNCTION_NOT_FOUND");
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
     * Handle requests to function resources by name like /programs/current/functions/by-name/{name}/variables
     */
    private void handleFunctionResourceByNameRESTful(HttpExchange exchange, String functionName, String resource) throws IOException {
        Function function = findFunctionByName(functionName);
        if (function == null) {
            sendErrorResponse(exchange, 404, "Function not found with name: " + functionName, "FUNCTION_NOT_FOUND");
            return;
        }
        
        if (resource.equals("variables")) {
            handleFunctionVariables(exchange, function);
        } else if (resource.equals("decompile")) {
            handleDecompileFunction(exchange, function);
        } else if (resource.equals("disassembly")) {
            handleDisassembleFunction(exchange, function);
        } else {
            sendErrorResponse(exchange, 404, "Function resource not found: " + resource, "RESOURCE_NOT_FOUND");
        }
    }
    
    /**
     * Handle PATCH requests to update a function using the RESTful endpoint
     */
    private void handleUpdateFunctionRESTful(HttpExchange exchange, Function function) throws IOException {
        // Implementation similar to handleUpdateFunction but with RESTful response structure
        Program program = getCurrentProgram();
        if (program == null) {
            sendErrorResponse(exchange, 400, "No program is currently loaded", "NO_PROGRAM_LOADED");
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
            // Update function signature using our utility method
            try {
                boolean success = TransactionHelper.executeInTransaction(program, "Set Function Signature", () -> {
                    return GhidraUtil.setFunctionSignature(function, signature);
                });
                
                if (!success) {
                    sendErrorResponse(exchange, 400, "Failed to set function signature: invalid signature format", "SIGNATURE_FAILED");
                    return;
                }
                changed = true;
            } catch (Exception e) {
                sendErrorResponse(exchange, 400, "Failed to set function signature: " + e.getMessage(), "SIGNATURE_FAILED");
                return;
            }
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
        
        // Return updated function with RESTful response structure
        FunctionInfo info = buildFunctionInfo(function);
        
        ResponseBuilder builder = new ResponseBuilder(exchange, port)
            .success(true)
            .result(info);
        
        // Add HATEOAS links
        builder.addLink("self", "/programs/current/functions/" + function.getEntryPoint());
        builder.addLink("by_name", "/programs/current/functions/by-name/" + function.getName());
        builder.addLink("program", "/programs/current");
        
        sendJsonResponse(exchange, builder.build(), 200);
    }
    
    /**
     * Handle DELETE requests to delete a function using the RESTful endpoint
     */
    private void handleDeleteFunctionRESTful(HttpExchange exchange, Function function) throws IOException {
        // Placeholder for function deletion
        sendErrorResponse(exchange, 501, "Function deletion not implemented", "NOT_IMPLEMENTED");
    }
    
    /**
     * Handle POST requests to create a new function using the RESTful endpoint
     */
    private void handleCreateFunctionRESTful(HttpExchange exchange) throws IOException {
        Program program = getCurrentProgram();
        if (program == null) {
            sendErrorResponse(exchange, 400, "No program is currently loaded", "NO_PROGRAM_LOADED");
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
        
        // Check if address is in a valid memory block
        if (program.getMemory().getBlock(address) == null) {
             sendErrorResponse(exchange, 400, "Address is not in a defined memory block: " + addressStr, "INVALID_ADDRESS");
             return;
        }
        
        // Check if function already exists
        if (program.getFunctionManager().getFunctionAt(address) != null) {
            sendErrorResponse(exchange, 409, "Function already exists at address: " + addressStr, "FUNCTION_EXISTS");
            return;
        }
        
        // Attempt to disassemble the code at the specified address before creating a function
        try {
            TransactionHelper.executeInTransaction(program, "Disassemble Before Function Creation", () -> {
                // Check if there's already a defined instruction at the address
                if (program.getListing().getInstructionAt(address) == null) {
                    // Attempt to directly disassemble at the address
                    try {
                        ghidra.app.cmd.disassemble.DisassembleCommand cmd = 
                            new ghidra.app.cmd.disassemble.DisassembleCommand(address, null, true);
                        cmd.applyTo(program);
                    } catch (Exception ex) {
                        Msg.warn(this, "Basic disassembly failed: " + ex.getMessage());
                    }
                }
                return null;
            });
        } catch (Exception e) {
            // Log the error but proceed with function creation attempt anyway
            Msg.warn(this, "Disassembly before function creation failed: " + e.getMessage());
        }
        
        // Create function
        Function function;
        try {
            function = TransactionHelper.executeInTransaction(program, "Create Function", () -> {
                return program.getFunctionManager().createFunction(null, address, null, null);
            });
        } catch (Exception e) {
            // If function creation initially fails, try a different approach
            try {
                Msg.info(this, "Initial function creation failed, attempting with code unit clearing");
                
                // Clear any existing data at this location and try disassembling again
                TransactionHelper.executeInTransaction(program, "Clear and Disassemble", () -> {
                    // Clear existing data at the address
                    program.getListing().clearCodeUnits(address, address, false);
                    
                    // Try disassembling again
                    ghidra.app.cmd.disassemble.DisassembleCommand cmd = 
                        new ghidra.app.cmd.disassemble.DisassembleCommand(address, null, true);
                    cmd.applyTo(program);
                    return null;
                });
                
                // Try creating the function again
                function = TransactionHelper.executeInTransaction(program, "Create Function Retry", () -> {
                    return program.getFunctionManager().createFunction(null, address, null, null);
                });
            } catch (Exception e2) {
                // Both attempts failed, return the error
                sendErrorResponse(exchange, 400, "Failed to create function after multiple attempts: " + e.getMessage(), "CREATE_FAILED");
                return;
            }
        }
        
        if (function == null) {
            sendErrorResponse(exchange, 500, "Failed to create function", "CREATE_FAILED");
            return;
        }
        
        // Return created function with RESTful response structure
        FunctionInfo info = buildFunctionInfo(function);
        
        ResponseBuilder builder = new ResponseBuilder(exchange, port)
            .success(true)
            .result(info);
        
        // Add HATEOAS links
        builder.addLink("self", "/programs/current/functions/" + function.getEntryPoint());
        builder.addLink("by_name", "/programs/current/functions/by-name/" + function.getName());
        builder.addLink("program", "/programs/current");
        builder.addLink("decompile", "/programs/current/functions/" + function.getEntryPoint() + "/decompile");
        builder.addLink("disassembly", "/programs/current/functions/" + function.getEntryPoint() + "/disassembly");
        
        sendJsonResponse(exchange, builder.build(), 201);
    }

    /**
     * Handle requests to the /functions endpoint
     */
    public void handleFunctions(HttpExchange exchange) throws IOException {
        try {
            // Always check for program availability first
            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 503, "No program is currently loaded", "NO_PROGRAM_LOADED");
                return;
            }
            
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parseQueryParams(exchange);
                int offset = parseIntOrDefault(params.get("offset"), 0);
                int limit = parseIntOrDefault(params.get("limit"), 100);
                String nameFilter = params.get("name");
                String nameContainsFilter = params.get("name_contains");
                String nameRegexFilter = params.get("name_matches_regex");
                String addrFilter = params.get("addr");
                
                List<Map<String, Object>> functions = new ArrayList<>();
                
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
                    
                    // Add HATEOAS links (fixed to use proper URL paths)
                    Map<String, Object> links = new HashMap<>();
                    Map<String, String> selfLink = new HashMap<>();
                    selfLink.put("href", "/functions/" + f.getEntryPoint());
                    links.put("self", selfLink);
                    
                    Map<String, String> programLink = new HashMap<>();
                    programLink.put("href", "/program");
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
    private void handleFunctionResource(HttpExchange exchange, String functionIdent, String resource) throws IOException {
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
        } else if (resource.startsWith("variables/")) {
            // Handle variable operations
            String variableName = resource.substring("variables/".length());
            if ("PATCH".equals(exchange.getRequestMethod())) {
                handleUpdateVariable(exchange, function, variableName);
            } else {
                sendErrorResponse(exchange, 405, "Method not allowed for variable operations", "METHOD_NOT_ALLOWED");
            }
        } else {
            sendErrorResponse(exchange, 404, "Function resource not found: " + resource, "RESOURCE_NOT_FOUND");
        }
    }
    
    private void handleFunctionResource(HttpExchange exchange, String functionPath) throws IOException {
        int slashIndex = functionPath.indexOf('/');
        if (slashIndex == -1) {
            sendErrorResponse(exchange, 404, "Invalid function resource path: " + functionPath, "RESOURCE_NOT_FOUND");
            return;
        }
        String functionIdent = functionPath.substring(0, slashIndex);
        String resource = functionPath.substring(slashIndex + 1);
        
        handleFunctionResource(exchange, functionIdent, resource);
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
            // Update function signature using our utility method
            try {
                boolean success = TransactionHelper.executeInTransaction(program, "Set Function Signature", () -> {
                    return GhidraUtil.setFunctionSignature(function, signature);
                });
                
                if (!success) {
                    sendErrorResponse(exchange, 400, "Failed to set function signature: invalid signature format", "SIGNATURE_FAILED");
                    return;
                }
                changed = true;
            } catch (Exception e) {
                sendErrorResponse(exchange, 400, "Failed to set function signature: " + e.getMessage(), "SIGNATURE_FAILED");
                return;
            }
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

        // Attempt to disassemble the code at the specified address before creating a function
        try {
            TransactionHelper.executeInTransaction(program, "Disassemble Before Function Creation", () -> {
                // Check if there's already a defined instruction at the address
                if (program.getListing().getInstructionAt(address) == null) {
                    // Attempt to directly disassemble at the address
                    try {
                        ghidra.app.cmd.disassemble.DisassembleCommand cmd = 
                            new ghidra.app.cmd.disassemble.DisassembleCommand(address, null, true);
                        cmd.applyTo(program);
                    } catch (Exception ex) {
                        Msg.warn(this, "Basic disassembly failed: " + ex.getMessage());
                    }
                }
                return null;
            });
        } catch (Exception e) {
            // Log the error but proceed with function creation attempt anyway
            Msg.warn(this, "Disassembly before function creation failed: " + e.getMessage());
        }
        
        // Create function
        Function function;
        try {
            function = TransactionHelper.executeInTransaction(program, "Create Function", () -> {
                return program.getFunctionManager().createFunction(null, address, null, null);
            });
        } catch (Exception e) {
            // If function creation initially fails, try a different approach
            try {
                Msg.info(this, "Initial function creation failed, attempting with code unit clearing");
                
                // Clear any existing data at this location and try disassembling again
                TransactionHelper.executeInTransaction(program, "Clear and Disassemble", () -> {
                    // Clear existing data at the address
                    program.getListing().clearCodeUnits(address, address, false);
                    
                    // Try disassembling again
                    ghidra.app.cmd.disassemble.DisassembleCommand cmd = 
                        new ghidra.app.cmd.disassemble.DisassembleCommand(address, null, true);
                    cmd.applyTo(program);
                    return null;
                });
                
                // Try creating the function again
                function = TransactionHelper.executeInTransaction(program, "Create Function Retry", () -> {
                    return program.getFunctionManager().createFunction(null, address, null, null);
                });
            } catch (Exception e2) {
                // Both attempts failed, return the error
                sendErrorResponse(exchange, 400, "Failed to create function after multiple attempts: " + e.getMessage(), "CREATE_FAILED");
                return;
            }
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
            boolean showConstants = Boolean.parseBoolean(params.getOrDefault("show_constants", "true"));
            int timeout = parseIntOrDefault(params.get("timeout"), 30);

            // Decompile function with configurable options
            String decompilation = GhidraUtil.decompileFunction(function, showConstants, timeout);
            
            // Create function info
            Map<String, Object> functionInfo = new HashMap<>();
            functionInfo.put("address", function.getEntryPoint().toString());
            functionInfo.put("name", function.getName());
            
            // Create the result structure according to GHIDRA_HTTP_API.md
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
            
            // Path for links (updated to use the correct paths)
            String functionPath = "/functions/" + function.getEntryPoint().toString();
            
            // Add HATEOAS links
            builder.addLink("self", functionPath + "/decompile");
            builder.addLink("function", functionPath);
            builder.addLink("disassembly", functionPath + "/disassembly");
            builder.addLink("variables", functionPath + "/variables");
            builder.addLink("program", "/program");
            
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
                try {
                    // Get actual disassembly from the program
                    Address startAddr = function.getEntryPoint();
                    Address endAddr = function.getBody().getMaxAddress();
                    
                    ghidra.program.model.listing.Listing listing = program.getListing();
                    ghidra.program.model.listing.InstructionIterator instrIter = 
                        listing.getInstructions(startAddr, true);
                    
                    while (instrIter.hasNext() && disassembly.size() < 100) {
                        ghidra.program.model.listing.Instruction instr = instrIter.next();
                        
                        // Stop if we've gone past the end of the function
                        if (instr.getAddress().compareTo(endAddr) > 0) {
                            break;
                        }
                        
                        Map<String, Object> instrMap = new HashMap<>();
                        instrMap.put("address", instr.getAddress().toString());
                        
                        // Get actual bytes
                        byte[] bytes = new byte[instr.getLength()];
                        program.getMemory().getBytes(instr.getAddress(), bytes);
                        StringBuilder hexBytes = new StringBuilder();
                        for (byte b : bytes) {
                            hexBytes.append(String.format("%02X", b & 0xFF));
                        }
                        instrMap.put("bytes", hexBytes.toString());
                        
                        // Get mnemonic and operands
                        instrMap.put("mnemonic", instr.getMnemonicString());
                        instrMap.put("operands", instr.toString().substring(instr.getMnemonicString().length()).trim());
                        
                        disassembly.add(instrMap);
                    }
                } catch (Exception e) {
                    Msg.error(this, "Error getting disassembly for function: " + function.getName(), e);
                }
                
                // If we couldn't get real instructions, add placeholder
                if (disassembly.isEmpty()) {
                    Address addr = function.getEntryPoint();
                    for (int i = 0; i < 5; i++) {
                        Map<String, Object> instruction = new HashMap<>();
                        instruction.put("address", addr.toString());
                        instruction.put("mnemonic", "???");
                        instruction.put("operands", "???");
                        instruction.put("bytes", "????");
                        disassembly.add(instruction);
                        addr = addr.add(2);
                    }
                }
            }
            
            Map<String, Object> functionInfo = new HashMap<>();
            functionInfo.put("address", function.getEntryPoint().toString());
            functionInfo.put("name", function.getName());
            functionInfo.put("signature", function.getSignature().toString());
            
            Map<String, Object> result = new HashMap<>();
            result.put("function", functionInfo);
            result.put("instructions", disassembly);
            
            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                .success(true)
                .result(result);
            
            // Update to use the correct paths
            String functionPath = "/functions/" + function.getEntryPoint().toString();
            
            builder.addLink("self", functionPath + "/disassembly");
            builder.addLink("function", functionPath);
            builder.addLink("decompile", functionPath + "/decompile");
            builder.addLink("variables", functionPath + "/variables");
            builder.addLink("program", "/program");
            
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
            
            // Update to use the correct paths
            String functionPath = "/functions/" + function.getEntryPoint().toString();
            String functionByNamePath = "/functions/by-name/" + function.getName();
            
            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                .success(true)
                .result(result);
            
            builder.addLink("self", functionPath + "/variables");
            builder.addLink("function", functionPath);
            builder.addLink("by_name", functionByNamePath);
            builder.addLink("decompile", functionPath + "/decompile");
            builder.addLink("disassembly", functionPath + "/disassembly");
            builder.addLink("program", "/program");
            
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
        try {
            // Parse the request body to get the update parameters
            Map<String, String> params = parseJsonPostParams(exchange);
            String newName = params.get("name");
            String newDataType = params.get("data_type");
            
            if (newName == null && newDataType == null) {
                sendErrorResponse(exchange, 400, "Missing update parameters - name or data_type required", "MISSING_PARAMETER");
                return;
            }
            
            // Use transaction to update variable
            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                return;
            }
            
            boolean success = TransactionHelper.executeInTransaction(program, "Update Variable", () -> {
                try {
                    // This requires a decompile operation to get the HighFunction
                    DecompInterface decomp = new DecompInterface();
                    try {
                        decomp.openProgram(program);
                        DecompileResults results = decomp.decompileFunction(function, 30, new ConsoleTaskMonitor());
                        
                        if (results.decompileCompleted()) {
                            HighFunction highFunc = results.getHighFunction();
                            if (highFunc != null) {
                                // Find the variable in the high function
                                for (Iterator<HighSymbol> symbolIter = highFunc.getLocalSymbolMap().getSymbols(); symbolIter.hasNext();) {
                                    HighSymbol symbol = symbolIter.next();
                                    if (symbol.getName().equals(variableName)) {
                                        // Rename the variable using HighFunctionDBUtil
                                        HighFunctionDBUtil.updateDBVariable(symbol, newName, null, SourceType.USER_DEFINED);
                                        return true;
                                    }
                                }
                            }
                        }
                    } finally {
                        decomp.dispose();
                    }
                    return false;
                } catch (Exception e) {
                    Msg.error(this, "Error updating variable: " + e.getMessage(), e);
                    return false;
                }
            });
            
            if (success) {
                // Create a successful response
                Map<String, Object> result = new HashMap<>();
                result.put("name", newName != null ? newName : variableName);
                result.put("function", function.getName());
                result.put("address", function.getEntryPoint().toString());
                result.put("message", "Variable renamed successfully");
                
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(result);
                
                sendJsonResponse(exchange, builder.build(), 200);
            } else {
                sendErrorResponse(exchange, 404, "Function resource not found: variables/" + variableName, "RESOURCE_NOT_FOUND");
            }
        } catch (Exception e) {
            sendErrorResponse(exchange, 500, "Error processing variable update request: " + e.getMessage(), "INTERNAL_ERROR");
        }
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
