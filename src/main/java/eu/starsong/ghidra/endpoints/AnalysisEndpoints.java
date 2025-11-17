package eu.starsong.ghidra.endpoints;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.starsong.ghidra.api.ResponseBuilder;
import ghidra.app.services.Analyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.listing.Program;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

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
        server.createContext("/analysis/status", this::handleAnalysisStatus);
        server.createContext("/analysis/run", this::handleAnalysisRun);

        // NOTE: The callgraph endpoint is now registered in ProgramEndpoints
        // This comment is to avoid confusion during future maintenance
    }

    /**
     * Handle GET /analysis/status - Get analysis status for current program
     */
    private void handleAnalysisStatus(HttpExchange exchange) throws IOException {
        try {
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                return;
            }

            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                return;
            }

            AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);

            Map<String, Object> status = new HashMap<>();
            status.put("programName", program.getName());
            status.put("isAnalyzing", analysisManager.isAnalyzing());

            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(status);

            builder.addLink("self", "/analysis/status");
            builder.addLink("run", "/analysis/run", "POST");
            builder.addLink("program", "/program");

            sendJsonResponse(exchange, builder.build(), 200);

        } catch (Exception e) {
            Msg.error(this, "Error in /analysis/status endpoint", e);
            sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
        }
    }

    /**
     * Handle POST /analysis/run - Trigger analysis on current program
     */
    private void handleAnalysisRun(HttpExchange exchange) throws IOException {
        try {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                return;
            }

            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                return;
            }

            Map<String, String> params = parseJsonPostParams(exchange);
            boolean background = Boolean.parseBoolean(params.getOrDefault("background", "true"));

            AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);

            if (analysisManager.isAnalyzing()) {
                sendErrorResponse(exchange, 409, "Analysis is already running", "ANALYSIS_RUNNING");
                return;
            }

            // Start analysis
            analysisManager.reAnalyzeAll(null);
            analysisManager.startAnalysis(TaskMonitor.DUMMY, background);

            Map<String, Object> result = new HashMap<>();
            result.put("started", true);
            result.put("background", background);
            result.put("message", "Analysis started on program: " + program.getName());

            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(result);

            builder.addLink("self", "/analysis/run");
            builder.addLink("status", "/analysis/status");
            builder.addLink("program", "/program");

            sendJsonResponse(exchange, builder.build(), 200);

        } catch (Exception e) {
            Msg.error(this, "Error in /analysis/run endpoint", e);
            sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
        }
    }
}