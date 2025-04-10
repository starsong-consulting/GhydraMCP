package eu.starsong.ghidra;

// New imports for refactored structure
import eu.starsong.ghidra.api.*;
import eu.starsong.ghidra.endpoints.*;
import eu.starsong.ghidra.util.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

// For JSON response handling
import com.google.gson.Gson; // Keep for now if needed by sendJsonResponse stub
import com.google.gson.JsonObject; // Keep for now if needed by sendJsonResponse stub
import com.sun.net.httpserver.HttpExchange; // Keep for now if needed by sendJsonResponse stub
import com.sun.net.httpserver.HttpServer;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.main.ApplicationLevelPlugin;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;


@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "GhydraMCP Plugin for AI Analysis",
    description = "Exposes program data via HTTP API for AI-assisted reverse engineering with MCP (Model Context Protocol).",
    servicesRequired = { ProgramManager.class }
)
public class GhydraMCPPlugin extends Plugin implements ApplicationLevelPlugin {

    // Made public static to be accessible by InstanceEndpoints - consider a better design pattern
    public static final Map<Integer, GhydraMCPPlugin> activeInstances = new ConcurrentHashMap<>();
    private static final Object baseInstanceLock = new Object();
    
    private HttpServer server;
    private int port;
    private boolean isBaseInstance = false;
    // Removed Gson instance, should be handled by HttpUtil or endpoints

    public GhydraMCPPlugin(PluginTool tool) {
        super(tool);
        
        this.port = findAvailablePort();
        activeInstances.put(port, this);
        
        synchronized (baseInstanceLock) {
            if (port == ApiConstants.DEFAULT_PORT || activeInstances.get(ApiConstants.DEFAULT_PORT) == null) {
                this.isBaseInstance = true;
                Msg.info(this, "Starting as base instance on port " + port);
            }
        }

        Msg.info(this, "GhydraMCPPlugin loaded on port " + port);
        System.out.println("[GhydraMCP] Plugin loaded on port " + port);

        try {
            startServer();
        } catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server on port " + port, e);
            if (e.getMessage().contains("Address already in use")) {
                Msg.showError(this, null, "Port Conflict", 
                    "Port " + port + " is already in use. Please specify a different port with -Dghidra.mcp.port=NEW_PORT");
            }
        }
    }

    private void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);

        // --- Register Endpoints ---
        Program currentProgram = getCurrentProgram(); // Get program once
        
        // Register Meta Endpoints
        registerMetaEndpoints(server); 
        
        // Register endpoints that don't require a program
        registerProjectEndpoints(server);
        new InstanceEndpoints(currentProgram, port, activeInstances).registerEndpoints(server);
        
        // Register Resource Endpoints that require a program
        registerProgramDependentEndpoints(currentProgram, server);
        
        // Register Root Endpoint (should be last to include links to all other endpoints)
        registerRootEndpoint(server);

        server.setExecutor(null); // Use default executor
        new Thread(() -> {
            server.start();
            Msg.info(this, "GhydraMCP HTTP server started on port " + port);
            System.out.println("[GhydraMCP] HTTP server started on port " + port);
        }, "GhydraMCP-HTTP-Server").start();
    }
    
    /**
     * Register all endpoints that require a program to function.
     * This method always registers all endpoints, even when no program is loaded.
     * When no program is loaded, the endpoints will return appropriate error messages.
     */
    private void registerProgramDependentEndpoints(Program currentProgram, HttpServer server) {
        // Always register all endpoints, even if currentProgram is null
        // The endpoint implementations will handle the null program case
        new FunctionEndpoints(currentProgram, port).registerEndpoints(server);
        new VariableEndpoints(currentProgram, port).registerEndpoints(server);
        new ClassEndpoints(currentProgram, port).registerEndpoints(server);
        new SegmentEndpoints(currentProgram, port).registerEndpoints(server);
        new SymbolEndpoints(currentProgram, port).registerEndpoints(server);
        new NamespaceEndpoints(currentProgram, port).registerEndpoints(server);
        new DataEndpoints(currentProgram, port).registerEndpoints(server);
        
        // Register additional endpoints for current program/address
        registerCurrentAddressEndpoints(server, currentProgram);
        registerDecompilerEndpoints(server, currentProgram);
        
        if (currentProgram != null) {
            Msg.info(this, "Registered program-dependent endpoints for program: " + currentProgram.getName());
        } else {
            Msg.warn(this, "No current program available. Endpoints registered but will return appropriate errors when accessed.");
        }
    }
    
    /**
     * Register endpoints related to the current address in Ghidra.
     */
    private void registerCurrentAddressEndpoints(HttpServer server, Program program) {
        // Current address endpoint
        server.createContext("/get_current_address", exchange -> {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, Object> addressData = new HashMap<>();
                    addressData.put("address", GhidraUtil.getCurrentAddressString(tool));
                    
                    ResponseBuilder builder = new ResponseBuilder(exchange, port)
                        .success(true)
                        .result(addressData)
                        .addLink("self", "/get_current_address");
                    
                    HttpUtil.sendJsonResponse(exchange, builder.build(), 200, port);
                } else {
                    HttpUtil.sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED", port);
                }
            } catch (Exception e) {
                Msg.error(this, "Error serving /get_current_address endpoint", e);
                try { 
                    HttpUtil.sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR", port); 
                } catch (IOException ioEx) { 
                    Msg.error(this, "Failed to send error for /get_current_address", ioEx); 
                }
            }
        });
        
        // Current function endpoint
        server.createContext("/get_current_function", exchange -> {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, Object> functionData = GhidraUtil.getCurrentFunctionInfo(tool, program);
                    
                    ResponseBuilder builder = new ResponseBuilder(exchange, port)
                        .success(true)
                        .result(functionData)
                        .addLink("self", "/get_current_function");
                    
                    HttpUtil.sendJsonResponse(exchange, builder.build(), 200, port);
                } else {
                    HttpUtil.sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED", port);
                }
            } catch (Exception e) {
                Msg.error(this, "Error serving /get_current_function endpoint", e);
                try { 
                    HttpUtil.sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR", port); 
                } catch (IOException ioEx) { 
                    Msg.error(this, "Failed to send error for /get_current_function", ioEx); 
                }
            }
        });
    }
    
    /**
     * Register endpoints related to the decompiler.
     */
    private void registerDecompilerEndpoints(HttpServer server, Program program) {
        // Get function by address endpoint
        server.createContext("/get_function_by_address", exchange -> {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, String> params = HttpUtil.parseQueryParams(exchange);
                    String addressStr = params.get("address");
                    
                    if (addressStr == null || addressStr.isEmpty()) {
                        HttpUtil.sendErrorResponse(exchange, 400, "Missing address parameter", "MISSING_PARAMETER", port);
                        return;
                    }
                    
                    Map<String, Object> functionData = GhidraUtil.getFunctionByAddress(program, addressStr);
                    
                    ResponseBuilder builder = new ResponseBuilder(exchange, port)
                        .success(true)
                        .result(functionData)
                        .addLink("self", "/get_function_by_address?address=" + addressStr);
                    
                    HttpUtil.sendJsonResponse(exchange, builder.build(), 200, port);
                } else {
                    HttpUtil.sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED", port);
                }
            } catch (Exception e) {
                Msg.error(this, "Error serving /get_function_by_address endpoint", e);
                try { 
                    HttpUtil.sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR", port); 
                } catch (IOException ioEx) { 
                    Msg.error(this, "Failed to send error for /get_function_by_address", ioEx); 
                }
            }
        });
        
        // Decompile function endpoint
        server.createContext("/decompile_function", exchange -> {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, String> params = HttpUtil.parseQueryParams(exchange);
                    String addressStr = params.get("address");
                    
                    if (addressStr == null || addressStr.isEmpty()) {
                        HttpUtil.sendErrorResponse(exchange, 400, "Missing address parameter", "MISSING_PARAMETER", port);
                        return;
                    }
                    
                    Map<String, Object> decompData = GhidraUtil.decompileFunction(program, addressStr);
                    
                    ResponseBuilder builder = new ResponseBuilder(exchange, port)
                        .success(true)
                        .result(decompData)
                        .addLink("self", "/decompile_function?address=" + addressStr);
                    
                    HttpUtil.sendJsonResponse(exchange, builder.build(), 200, port);
                } else {
                    HttpUtil.sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED", port);
                }
            } catch (Exception e) {
                Msg.error(this, "Error serving /decompile_function endpoint", e);
                try { 
                    HttpUtil.sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR", port); 
                } catch (IOException ioEx) { 
                    Msg.error(this, "Failed to send error for /decompile_function", ioEx); 
                }
            }
        });
    }
    
    // --- Endpoint Registration Methods ---
    
    private void registerMetaEndpoints(HttpServer server) {
        server.createContext("/plugin-version", exchange -> {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    ResponseBuilder builder = new ResponseBuilder(exchange, port)
                        .success(true)
                        .result(Map.of(
                            "plugin_version", ApiConstants.PLUGIN_VERSION,
                            "api_version", ApiConstants.API_VERSION
                        ))
                        .addLink("self", "/plugin-version");
                    HttpUtil.sendJsonResponse(exchange, builder.build(), 200, port);
                } else {
                    HttpUtil.sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED", port);
                }
            } catch (IOException e) {
                Msg.error(this, "Error handling /plugin-version", e);
            }
        });
        
        server.createContext("/info", exchange -> {
            try {
                 Map<String, Object> infoData = new HashMap<>();
                 infoData.put("isBaseInstance", isBaseInstance);
                Program program = getCurrentProgram();
                 infoData.put("file", program != null ? program.getName() : null); 
                Project project = tool.getProject();
                 infoData.put("project", project != null ? project.getName() : null);
                 
                 ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(infoData)
                    .addLink("self", "/info");
                 HttpUtil.sendJsonResponse(exchange, builder.build(), 200, port);
            } catch (Exception e) {
                Msg.error(this, "Error serving /info endpoint", e);
                 try { HttpUtil.sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR", port); } 
                 catch (IOException ioEx) { Msg.error(this, "Failed to send error for /info", ioEx); }
            }
        });
    }
    
    private void registerProjectEndpoints(HttpServer server) {
         server.createContext("/projects", exchange -> {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    List<Map<String, String>> projects = new ArrayList<>();
                    Project project = tool.getProject();
                    if (project != null) {
                        Map<String, String> projInfo = new HashMap<>();
                        projInfo.put("name", project.getName());
                        projInfo.put("location", project.getProjectLocator().toString());
                        projects.add(projInfo);
                    }
                    
                    ResponseBuilder builder = new ResponseBuilder(exchange, port)
                        .success(true)
                        .result(projects)
                        .addLink("self", "/projects")
                        .addLink("create", "/projects", "POST"); 
                        
                    HttpUtil.sendJsonResponse(exchange, builder.build(), 200, port);
                } else if ("POST".equals(exchange.getRequestMethod())) {
                    HttpUtil.sendErrorResponse(exchange, 501, "Not Implemented", "NOT_IMPLEMENTED", port);
                } else {
                    HttpUtil.sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED", port);
                }
            } catch (Exception e) {
                 Msg.error(this, "Error serving /projects endpoint", e);
                 try { HttpUtil.sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR", port); } 
                 catch (IOException ioEx) { Msg.error(this, "Failed to send error for /projects", ioEx); }
            }
        });
    }
    
    private void registerRootEndpoint(HttpServer server) {
        server.createContext("/", exchange -> {
            try {
                if (!exchange.getRequestURI().getPath().equals("/")) {
                    HttpUtil.sendErrorResponse(exchange, 404, "Endpoint not found", "ENDPOINT_NOT_FOUND", port);
                    return;
                }
            
                Map<String, Object> rootData = new HashMap<>();
                rootData.put("message", "GhydraMCP Root Endpoint");
                rootData.put("isBaseInstance", isBaseInstance);
                
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(rootData)
                    .addLink("self", "/")
                    .addLink("info", "/info")
                    .addLink("plugin-version", "/plugin-version")
                    .addLink("projects", "/projects")
                    .addLink("instances", "/instances");
                
                // Add links to program-dependent endpoints if a program is loaded
                if (getCurrentProgram() != null) {
                    builder.addLink("functions", "/functions")
                           .addLink("variables", "/variables")
                           .addLink("classes", "/classes")
                           .addLink("segments", "/segments")
                           .addLink("symbols", "/symbols")
                           .addLink("namespaces", "/namespaces")
                           .addLink("data", "/data")
                           .addLink("current-address", "/get_current_address")
                           .addLink("current-function", "/get_current_function")
                           .addLink("get-function-by-address", "/get_function_by_address")
                           .addLink("decompile-function", "/decompile_function");
                }
                
                HttpUtil.sendJsonResponse(exchange, builder.build(), 200, port);
            } catch (Exception e) {
                Msg.error(this, "Error serving / endpoint", e);
                try { 
                    HttpUtil.sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR", port); 
                } catch (IOException ioEx) { 
                    Msg.error(this, "Failed to send error for /", ioEx); 
                }
            }
        });
    }

    // ----------------------------------------------------------------------------------
    // Core Plugin Methods (Keep these)
    // ----------------------------------------------------------------------------------

    public Program getCurrentProgram() {
        if (tool == null) {
            Msg.debug(this, "Tool is null when trying to get current program");
            return null;
        }
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) {
            Msg.debug(this, "ProgramManager service is not available");
            return null;
        }
        return pm.getCurrentProgram();
    }

    private int findAvailablePort() {
        int basePort = ApiConstants.DEFAULT_PORT;
        int maxAttempts = ApiConstants.MAX_PORT_ATTEMPTS;
        
        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            int candidate = basePort + attempt;
            if (!activeInstances.containsKey(candidate)) {
                try (ServerSocket s = new ServerSocket(candidate)) {
                    return candidate;
                } catch (IOException e) {
                    Msg.debug(this, "Port " + candidate + " is not available, trying next.");
                }
            } else {
                 Msg.debug(this, "Port " + candidate + " already tracked as active instance.");
            }
        }
        Msg.error(this, "Could not find an available port between " + basePort + " and " + (basePort + maxAttempts - 1));
        throw new RuntimeException("Could not find available port after " + maxAttempts + " attempts");
    }

    @Override
    public void dispose() {
        if (server != null) {
            server.stop(0); // Stop immediately
            Msg.info(this, "GhydraMCP HTTP server stopped on port " + port);
            System.out.println("[GhydraMCP] HTTP server stopped on port " + port);
        }
        activeInstances.remove(port);
        super.dispose();
    }

    // ----------------------------------------------------------------------------------
    // Helper methods moved to util classes (HttpUtil, GhidraUtil) or AbstractEndpoint
    // ----------------------------------------------------------------------------------
     
}
