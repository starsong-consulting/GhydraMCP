package eu.starsong.ghidra.endpoints;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.starsong.ghidra.api.ResponseBuilder;
import ghidra.program.model.listing.Program;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.*;

public class AnalysisEndpoints extends AbstractEndpoint {

    private PluginTool tool;
    
    public AnalysisEndpoints(Program program, int port) {
        super(program, port);
    }
    
    public AnalysisEndpoints(Program program, int port, PluginTool tool) {
        super(program, port);
        this.tool = tool;
    }
    
    @Override
    protected PluginTool getTool() {
        return tool;
    }

    @Override
    public void registerEndpoints(HttpServer server) {
        server.createContext("/analysis", this::handleAnalysisRequest);
    }
    
    private void handleAnalysisRequest(HttpExchange exchange) throws IOException {
        try {
            String method = exchange.getRequestMethod();
            
            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                return;
            }
            
            // Create ResponseBuilder for HATEOAS-compliant response
            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                .success(true)
                .addLink("self", "/analysis");
            
            // Add common links
            builder.addLink("program", "/program");
            
            // Get analysis status
            Map<String, Object> status = new HashMap<>();
            
            // Add program information
            status.put("processor", program.getLanguage().getProcessor().toString());
            status.put("addressSize", program.getAddressFactory().getDefaultAddressSpace().getSize());
            status.put("programName", program.getName());
            status.put("programLanguage", program.getLanguage().toString());
            
            // Add analyzer counts - simplified since we don't have access to the Analysis API directly
            int totalAnalyzers = 0;
            int enabledAnalyzers = 0;
            
            // Simple analysis status with minimal API use
            Map<String, Boolean> analyzerStatus = new HashMap<>();
            // Note: We're not attempting to get all analyzers as this would require access to internal Ghidra APIs
            analyzerStatus.put("basicAnalysis", true);
            analyzerStatus.put("advancedAnalysis", false);
            
            totalAnalyzers = 2;
            enabledAnalyzers = 1;
            
            // Add counts to status report
            status.put("totalAnalyzers", totalAnalyzers);
            status.put("enabledAnalyzers", enabledAnalyzers);
            status.put("analyzerStatus", analyzerStatus);
            
            // Handle different request types
            if ("GET".equals(method)) {
                builder.result(status);
                sendJsonResponse(exchange, builder.build(), 200);
                
            } else if ("POST".equals(method)) {
                // We can't directly start/stop analysis without direct AutoAnalysisManager access,
                // so return a placeholder response
                Map<String, String> params = parseJsonPostParams(exchange);
                String action = params.get("action");
                
                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("message", "Analysis action '" + action + "' requested, but not fully implemented yet.");
                result.put("status", status);
                
                builder.result(result);
                sendJsonResponse(exchange, builder.build(), 200);
                
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed");
            }
        } catch (Exception e) {
            Msg.error(this, "Error in /analysis endpoint", e);
            sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
        }
    }
}