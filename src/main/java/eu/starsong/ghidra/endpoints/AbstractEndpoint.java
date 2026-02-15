package eu.starsong.ghidra.endpoints;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import eu.starsong.ghidra.api.GhidraJsonEndpoint;
import eu.starsong.ghidra.api.ResponseBuilder; // Import ResponseBuilder
import eu.starsong.ghidra.util.DecompilerCache;
import eu.starsong.ghidra.util.GhidraUtil; // Import GhidraUtil
import eu.starsong.ghidra.util.HttpUtil; // Import HttpUtil
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public abstract class AbstractEndpoint implements GhidraJsonEndpoint {
    
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // Handle OPTIONS requests
        if (HttpUtil.handleOptionsRequest(exchange)) {
            return;
        }
        
        // This method is required by HttpHandler interface
        // Each endpoint will register its own context handlers with specific paths
        // so this default implementation should never be called
        sendErrorResponse(exchange, 404, "Endpoint not found", "ENDPOINT_NOT_FOUND");
    }
    
    /**
     * Helper method to handle pagination of collections and add pagination links to the response.
     * 
     * @param <T> the type of items in the collection
     * @param items the full collection to paginate
     * @param offset the starting offset for pagination
     * @param limit the maximum number of items per page
     * @param builder the ResponseBuilder to add pagination links to
     * @param basePath the base path for pagination links (without query parameters)
     * @param additionalQueryParams additional query parameters to include in pagination links or null
     * @return a list containing the paginated items
     */
    protected <T> List<T> applyPagination(List<T> items, int offset, int limit, 
            eu.starsong.ghidra.api.ResponseBuilder builder, String basePath, String additionalQueryParams) {
        // Apply pagination
        int start = Math.max(0, offset);
        int end = Math.min(items.size(), offset + limit);
        List<T> paginated = items.subList(start, end);
        
        // Add pagination metadata
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("size", items.size());
        metadata.put("offset", offset);
        metadata.put("limit", limit);
        builder.metadata(metadata);
        
        // Format the query string
        String queryParams = (additionalQueryParams != null && !additionalQueryParams.isEmpty()) 
            ? additionalQueryParams + "&" 
            : "";
        
        // Add HATEOAS links
        builder.addLink("self", basePath + "?" + queryParams + "offset=" + offset + "&limit=" + limit);
        
        // Add next/prev links if applicable
        if (end < items.size()) {
            builder.addLink("next", basePath + "?" + queryParams + "offset=" + end + "&limit=" + limit);
        }
        
        if (offset > 0) {
            int prevOffset = Math.max(0, offset - limit);
            builder.addLink("prev", basePath + "?" + queryParams + "offset=" + prevOffset + "&limit=" + limit);
        }
        
        return paginated;
    }
    
    /**
     * Overload of applyPagination without additional query parameters
     */
    protected <T> List<T> applyPagination(List<T> items, int offset, int limit, 
            eu.starsong.ghidra.api.ResponseBuilder builder, String basePath) {
        return applyPagination(items, offset, limit, builder, basePath, null);
    }

    protected final Gson gson = new Gson();
    protected Program currentProgram;
    protected int port;
    protected DecompilerCache decompilerCache;

    public AbstractEndpoint(Program program, int port) {
        this.currentProgram = program;
        this.port = port;
    }

    public AbstractEndpoint(Program program, int port, DecompilerCache decompilerCache) {
        this.currentProgram = program;
        this.port = port;
        this.decompilerCache = decompilerCache;
    }

    protected DecompilerCache getDecompilerCache() {
        return decompilerCache;
    }
    
    // Get the current program - dynamically checks for program availability at runtime
    protected Program getCurrentProgram() {
        // ALWAYS try to get the current program from the tool first, regardless of the stored program
        // This ensures we get the most up-to-date program state
        try {
            PluginTool tool = getTool();
            if (tool != null) {
                ProgramManager programManager = tool.getService(ProgramManager.class);
                if (programManager != null) {
                    Program current = programManager.getCurrentProgram();
                    if (current != null) {
                        return current; // Return the current program from the tool
                    }
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error getting current program from tool", e);
        }
        
        // Only fall back to the stored program if dynamic lookup fails
        if (currentProgram != null) {
            return currentProgram;
        }
        
        return null;
    }
    
    // Can be overridden by subclasses that have a tool reference
    protected PluginTool getTool() {
        return null;
    }

    // --- Methods using HttpUtil ---

    protected void sendJsonResponse(HttpExchange exchange, JsonObject data, int statusCode) throws IOException {
        HttpUtil.sendJsonResponse(exchange, data, statusCode, this.port);
    }
    
    // Overload for sending success responses easily using ResponseBuilder
    protected void sendSuccessResponse(HttpExchange exchange, Object resultData) throws IOException {
        // No longer check if program is required here
        // Each handler method should check for program availability at runtime if needed
        
        ResponseBuilder builder = new ResponseBuilder(exchange, port)
            .success(true)
            .result(resultData);
        // Add common links if desired here
        HttpUtil.sendJsonResponse(exchange, builder.build(), 200, this.port);
    }
    
    /**
     * Override this method in endpoint implementations that require a program to function.
     * @return true if this endpoint requires a program, false otherwise
     */
    protected boolean requiresProgram() {
        // Default implementation returns true for most endpoints
        return true;
    }

    protected void sendErrorResponse(HttpExchange exchange, int code, String message, String errorCode) throws IOException {
        HttpUtil.sendErrorResponse(exchange, code, message, errorCode, this.port);
    }
    
    // Overload without error code
    protected void sendErrorResponse(HttpExchange exchange, int code, String message) throws IOException {
        HttpUtil.sendErrorResponse(exchange, code, message, null, this.port);
    }

    protected Map<String, String> parseQueryParams(HttpExchange exchange) {
        return HttpUtil.parseQueryParams(exchange);
    }

    protected Map<String, String> parseJsonPostParams(HttpExchange exchange) throws IOException {
        return HttpUtil.parseJsonPostParams(exchange);
    }
    
    // --- Methods using GhidraUtil ---
    
    protected int parseIntOrDefault(String val, int defaultValue) {
        return GhidraUtil.parseIntOrDefault(val, defaultValue);
    }
    
    // Add other common Ghidra related utilities here or call GhidraUtil directly

    /**
     * Safely resolve a symbol name, avoiding infinite recursion from pointer-to-pointer chains.
     *
     * Dynamic symbols compute their names from data types at their address. When data is a
     * pointer to another pointer with a dynamic symbol, this creates a cycle:
     * SymbolDB.getName() -> PointerDataType.getLabelString() -> SymbolUtilities.getDynamicName() -> SymbolDB.getName()
     *
     * For dynamic symbols at pointer addresses, we skip name resolution entirely and use the
     * address. A try-catch on StackOverflowError acts as a safety net for unforeseen cases.
     */
    protected String safeGetSymbolName(Symbol symbol, Program program) {
        try {
            if (symbol.isDynamic()) {
                Data data = program.getListing().getDefinedDataAt(symbol.getAddress());
                if (data != null && data.getDataType() instanceof Pointer) {
                    return symbol.getAddress().toString();
                }
            }
            return symbol.getName();
        } catch (StackOverflowError e) {
            Msg.warn(this, "StackOverflow resolving symbol name at " + symbol.getAddress());
            return symbol.getAddress().toString();
        }
    }
}
