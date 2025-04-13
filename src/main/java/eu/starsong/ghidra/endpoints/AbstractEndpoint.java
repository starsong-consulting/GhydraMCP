package eu.starsong.ghidra.endpoints;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import eu.starsong.ghidra.api.GhidraJsonEndpoint;
import eu.starsong.ghidra.api.ResponseBuilder; // Import ResponseBuilder
import eu.starsong.ghidra.util.GhidraUtil; // Import GhidraUtil
import eu.starsong.ghidra.util.HttpUtil; // Import HttpUtil
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import java.io.IOException;
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

    protected final Gson gson = new Gson(); // Keep Gson if needed for specific object handling
    protected Program currentProgram;
    protected int port; // Add port field

    // Constructor to receive Program and Port
    public AbstractEndpoint(Program program, int port) {
        this.currentProgram = program;
        this.port = port;
    }
    
    // Get the current program - dynamically checks for program availability at runtime
    protected Program getCurrentProgram() {
        if (currentProgram != null) {
            return currentProgram;
        }
        
        // Try to get the program from the plugin tool if available
        try {
            PluginTool tool = getTool();
            if (tool != null) {
                ProgramManager programManager = tool.getService(ProgramManager.class);
                if (programManager != null) {
                    return programManager.getCurrentProgram();
                }
            }
        } catch (Exception e) {
            // Fall back to the stored program if dynamic lookup fails
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
}
