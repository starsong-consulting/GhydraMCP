package eu.starsong.ghidra;

// Imports for refactored structure
import eu.starsong.ghidra.api.*;
import eu.starsong.ghidra.endpoints.*;
import eu.starsong.ghidra.util.*;
import eu.starsong.ghidra.util.DecompilerCache;
import eu.starsong.ghidra.model.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

// For JSON response handling
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.Headers;

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
    description = "Exposes program data via HATEOAS HTTP API for AI-assisted reverse engineering with MCP (Model Context Protocol).",
    servicesRequired = { ProgramManager.class }
)
public class GhydraMCPPlugin extends Plugin implements ApplicationLevelPlugin {

    // Made public static to be accessible by InstanceEndpoints
    public static final Map<Integer, GhydraMCPPlugin> activeInstances = new ConcurrentHashMap<>();
    private static final Object baseInstanceLock = new Object();
    
    private HttpServer server;
    private int port;
    private boolean isBaseInstance = false;
    private DecompilerCache decompilerCache;

    /**
     * Constructor for GhydraMCP Plugin.
     * @param tool The Ghidra PluginTool
     */
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

        this.decompilerCache = new DecompilerCache();

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

    /**
     * Starts the HTTP server and registers all endpoints
     */
    private void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);
        
        // Use a cached thread pool with larger stack size to handle deep B-tree
        // traversals in Ghidra's database (large binaries have deep index trees)
        final long STACK_SIZE = 4 * 1024 * 1024; // 4 MB
        ThreadFactory threadFactory = r -> new Thread(null, r, "GhydraMCP-handler", STACK_SIZE);
        server.setExecutor(Executors.newCachedThreadPool(threadFactory));

        // --- Register Endpoints ---
        Program currentProgram = getCurrentProgram(); // Get program once
        
        // Register Meta Endpoints (these don't require a program)
        registerMetaEndpoints(server); 
        
        // Register endpoints that don't require a program
        registerProjectEndpoints(server);
        new InstanceEndpoints(currentProgram, port, activeInstances).registerEndpoints(server);
        
        // Register Resource Endpoints that require a program
        registerProgramDependentEndpoints(server);
        
        // Register Root Endpoint (should be last to include links to all other endpoints)
        registerRootEndpoint(server);

        new Thread(() -> {
            server.start();
            Msg.info(this, "GhydraMCP HTTP server started on port " + port);
            System.out.println("[GhydraMCP] HTTP server started on port " + port);
        }, "GhydraMCP-HTTP-Server").start();
    }
    
    /**
     * Register all endpoints that require a program to function.
     * This method always registers all endpoints, even when no program is loaded.
     * The endpoints will check for program availability at runtime when they're called.
     * 
     * IMPORTANT: Endpoints are registered in order from most specific to least specific
     * to ensure proper URL path matching.
     */
    private void registerProgramDependentEndpoints(HttpServer server) {
        // Register all endpoints without checking for a current program
        // The endpoints will check for the current program at runtime when they're called
        Msg.info(this, "Registering program-dependent endpoints. Programs will be checked at runtime.");
        
        Program currentProgram = getCurrentProgram();
        Msg.info(this, "Current program at registration time: " + (currentProgram != null ? currentProgram.getName() : "none"));
        
        new FunctionEndpoints(currentProgram, port, tool, decompilerCache).registerEndpoints(server);
        new VariableEndpoints(currentProgram, port, tool, decompilerCache).registerEndpoints(server);
        new ClassEndpoints(currentProgram, port, tool).registerEndpoints(server);
        new SegmentEndpoints(currentProgram, port, tool).registerEndpoints(server);
        new SymbolEndpoints(currentProgram, port, tool).registerEndpoints(server);
        new NamespaceEndpoints(currentProgram, port, tool).registerEndpoints(server);
        new DataEndpoints(currentProgram, port, tool).registerEndpoints(server);
        new StructEndpoints(currentProgram, port, tool).registerEndpoints(server);
        new MemoryEndpoints(currentProgram, port, tool).registerEndpoints(server);
        new XrefsEndpoints(currentProgram, port, tool).registerEndpoints(server);
        new AnalysisEndpoints(currentProgram, port, tool).registerEndpoints(server);
        new ProjectManagementEndpoints(currentProgram, port, tool).registerEndpoints(server);
        new ProgramEndpoints(currentProgram, port, tool).registerEndpoints(server);

        Msg.info(this, "Registered program-dependent endpoints. Programs will be checked at runtime.");
    }
    
    /**
     * Register additional endpoints for current program state
     */
    private void registerProgramStateEndpoints(HttpServer server) {
        // Any additional endpoints can be added here if needed
        // But prefer to use the HATEOAS endpoints in ProgramEndpoints, FunctionEndpoints, etc.
    }
    
    // --- Endpoint Registration Methods ---
    
    /**
     * Register meta endpoints that provide plugin information
     */
    private void registerMetaEndpoints(HttpServer server) {
        // Plugin version endpoint
        server.createContext("/plugin-version", exchange -> {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    ResponseBuilder builder = new ResponseBuilder(exchange, port)
                        .success(true)
                        .result(Map.of(
                            "plugin_version", ApiConstants.PLUGIN_VERSION,
                            "api_version", ApiConstants.API_VERSION
                        ))
                        .addLink("self", "/plugin-version")
                        .addLink("root", "/");
                        
                    HttpUtil.sendJsonResponse(exchange, builder.build(), 200, port);
                } else {
                    HttpUtil.sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED", port);
                }
            } catch (IOException e) {
                Msg.error(this, "Error handling /plugin-version", e);
            }
        });
        
        // Info endpoint
        server.createContext("/info", exchange -> {
            try {
                Map<String, Object> infoData = new HashMap<>();
                infoData.put("isBaseInstance", isBaseInstance);
                
                Program program = getCurrentProgram();
                if (program != null) {
                    infoData.put("file", program.getName());
                    infoData.put("architecture", program.getLanguage().getLanguageID().getIdAsString());
                    infoData.put("processor", program.getLanguage().getProcessor().toString());
                    infoData.put("addressSize", program.getAddressFactory().getDefaultAddressSpace().getSize());
                    infoData.put("creationDate", program.getCreationDate());
                    infoData.put("executable", program.getExecutablePath());
                }
                
                Project project = tool.getProject();
                if (project != null) {
                    infoData.put("project", project.getName());
                    infoData.put("projectLocation", project.getProjectLocator().toString());
                }
                
                // Add server details
                infoData.put("serverPort", port);
                infoData.put("serverStartTime", System.currentTimeMillis());
                infoData.put("instanceCount", activeInstances.size());
                
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                   .success(true)
                   .result(infoData)
                   .addLink("self", "/info")
                   .addLink("root", "/")
                   .addLink("instances", "/instances");
                
                // Add program link if available
                if (program != null) {
                    builder.addLink("program", "/program");
                }
                
                HttpUtil.sendJsonResponse(exchange, builder.build(), 200, port);
            } catch (Exception e) {
                Msg.error(this, "Error serving /info endpoint", e);
                try { 
                    HttpUtil.sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR", port); 
                } catch (IOException ioEx) { 
                    Msg.error(this, "Failed to send error for /info", ioEx); 
                }
            }
        });
    }
    
    /**
     * Register project-related endpoints
     */
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
                        
                    // Add link to current project if available
                    if (project != null) {
                        builder.addLink("current", "/projects/" + project.getName());
                    }
                    
                    HttpUtil.sendJsonResponse(exchange, builder.build(), 200, port);
                } else if ("POST".equals(exchange.getRequestMethod())) {
                    // Creating projects is not yet implemented
                    HttpUtil.sendErrorResponse(exchange, 501, "Creating projects via API is not implemented", "NOT_IMPLEMENTED", port);
                } else {
                    HttpUtil.sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED", port);
                }
            } catch (Exception e) {
                Msg.error(this, "Error serving /projects endpoint", e);
                try { 
                    HttpUtil.sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR", port); 
                } catch (IOException ioEx) { 
                    Msg.error(this, "Failed to send error for /projects", ioEx); 
                }
            }
        });
        
        // Specific project endpoint
        server.createContext("/projects/", exchange -> {
            try {
                String path = exchange.getRequestURI().getPath();
                if (path.equals("/projects/") || path.equals("/projects")) {
                    // This should be handled by the /projects context
                    exchange.getResponseHeaders().set("Location", "/projects");
                    exchange.sendResponseHeaders(302, -1);
                    return;
                }
                
                // Extract project name from path
                String projectName = path.substring("/projects/".length());
                
                if ("GET".equals(exchange.getRequestMethod())) {
                    Project currentProject = tool.getProject();
                    if (currentProject == null) {
                        HttpUtil.sendErrorResponse(exchange, 404, "No project is currently open", "NO_PROJECT_OPEN", port);
                        return;
                    }
                    
                    if (!currentProject.getName().equals(projectName)) {
                        HttpUtil.sendErrorResponse(exchange, 404, "Project not found: " + projectName, "PROJECT_NOT_FOUND", port);
                        return;
                    }
                    
                    // Build project details
                    Map<String, Object> projectDetails = new HashMap<>();
                    projectDetails.put("name", currentProject.getName());
                    projectDetails.put("location", currentProject.getProjectLocator().toString());
                    
                    ResponseBuilder builder = new ResponseBuilder(exchange, port)
                        .success(true)
                        .result(projectDetails)
                        .addLink("self", "/projects/" + projectName)
                        .addLink("programs", "/programs?project=" + projectName);
                    
                    HttpUtil.sendJsonResponse(exchange, builder.build(), 200, port);
                } else {
                    HttpUtil.sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED", port);
                }
            } catch (Exception e) {
                Msg.error(this, "Error serving /projects/{name} endpoint", e);
                try { 
                    HttpUtil.sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR", port); 
                } catch (IOException ioEx) { 
                    Msg.error(this, "Failed to send error for /projects/{name}", ioEx); 
                }
            }
        });
    }
    
    /**
     * Register the root endpoint which provides links to all other API endpoints
     */
    private void registerRootEndpoint(HttpServer server) {
        server.createContext("/", exchange -> {
            try {
                // Check if this is actually a CORS preflight request
                if (exchange.getAttribute("cors.handled") != null) {
                    // CORS was already handled
                    return;
                }
                
                // Check if this is a request for the root endpoint specifically
                if (!exchange.getRequestURI().getPath().equals("/")) {
                    HttpUtil.sendErrorResponse(exchange, 404, "Endpoint not found", "ENDPOINT_NOT_FOUND", port);
                    return;
                }
            
                Map<String, Object> rootData = new HashMap<>();
                rootData.put("message", "GhydraMCP API " + ApiConstants.API_VERSION);
                rootData.put("documentation", "See GHIDRA_HTTP_API.md for full API documentation");
                rootData.put("isBaseInstance", isBaseInstance);
                
                // Build the HATEOAS response
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(rootData)
                    .addLink("self", "/")
                    .addLink("info", "/info")
                    .addLink("plugin-version", "/plugin-version")
                    .addLink("projects", "/projects")
                    .addLink("instances", "/instances")
                    .addLink("programs", "/programs");
                
                // Add links to program-dependent endpoints if a program is loaded
                if (getCurrentProgram() != null) {
                    Project project = tool.getProject();
                    String projectName = (project != null) ? project.getName() : "unknown";
                    
                    builder.addLink("program", "/program")
                           .addLink("project", "/projects/" + projectName)
                           .addLink("functions", "/functions")
                           .addLink("symbols", "/symbols")
                           .addLink("data", "/data")
                           .addLink("strings", "/strings")
                           .addLink("segments", "/segments")
                           .addLink("structs", "/structs")
                           .addLink("memory", "/memory")
                           .addLink("xrefs", "/xrefs")
                           .addLink("analysis", "/analysis")
                           .addLink("address", "/address")
                           .addLink("function", "/function");
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
    // Core Plugin Methods
    // ----------------------------------------------------------------------------------

    /**
     * Gets the current program from the Ghidra tool
     * @return The current program or null if no program is loaded
     */
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

    /**
     * Find an available port for the HTTP server
     * @return An available port number
     */
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

    /**
     * Called when the plugin is disposed
     */
    @Override
    public void dispose() {
        if (decompilerCache != null) {
            decompilerCache.dispose();
        }
        if (server != null) {
            server.stop(0);
            Msg.info(this, "GhydraMCP HTTP server stopped on port " + port);
            System.out.println("[GhydraMCP] HTTP server stopped on port " + port);
        }
        activeInstances.remove(port);
        super.dispose();
    }

    /**
     * Get the port this plugin instance is running on
     * @return The HTTP server port
     */
    public int getPort() {
        return port;
    }
    
    /**
     * Check if this is the base instance
     * @return true if this is the base instance
     */
    public boolean isBaseInstance() {
        return isBaseInstance;
    }
}
