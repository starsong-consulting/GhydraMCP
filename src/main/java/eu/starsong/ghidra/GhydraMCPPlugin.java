package eu.starsong.ghidra;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID; // Added for request IDs
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier; // Added for transaction helper

import javax.swing.SwingUtilities;

// For JSON response handling
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.main.ApplicationLevelPlugin;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;


// Functional interface for Ghidra operations that might throw exceptions
@FunctionalInterface
interface GhidraSupplier<T> {
    T get() throws Exception;
}

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "GhydraMCP Plugin for AI Analysis",
    description = "Exposes program data via HTTP API for AI-assisted reverse engineering with MCP (Model Context Protocol).",
    servicesRequired = { ProgramManager.class }
)
public class GhydraMCPPlugin extends Plugin implements ApplicationLevelPlugin {

    // Plugin version information
    private static final String PLUGIN_VERSION = "v1.0.0"; // Update this with each release
    private static final int API_VERSION = 1; // Increment when API changes in a breaking way
    
    private static final Map<Integer, GhydraMCPPlugin> activeInstances = new ConcurrentHashMap<>();
    private static final Object baseInstanceLock = new Object();
    
    private HttpServer server;
    private int port;
    private boolean isBaseInstance = false;

    public GhydraMCPPlugin(PluginTool tool) {
        super(tool);
        
        this.port = findAvailablePort();
        activeInstances.put(port, this);
        
        synchronized (baseInstanceLock) {
            if (port == 8192 || activeInstances.get(8192) == null) {
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

        // Meta endpoints
        server.createContext("/plugin-version", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                JsonObject response = createBaseResponse(exchange);
                response.addProperty("success", true);
                
                JsonObject result = new JsonObject();
                result.addProperty("plugin_version", PLUGIN_VERSION);
                result.addProperty("api_version", API_VERSION);
                response.add("result", result);
                
                JsonObject links = new JsonObject();
                links.add("self", createLink("/plugin-version"));
                response.add("_links", links);
                
                sendJsonResponse(exchange, response, 200);
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        });

        // Program resources
        server.createContext("/programs", exchange -> {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    List<Map<String, Object>> programs = new ArrayList<>();
                    Program program = getCurrentProgram();
                    if (program != null) {
                        Map<String, Object> progInfo = new HashMap<>();
                        progInfo.put("program_id", program.getDomainFile().getPathname());
                        progInfo.put("name", program.getName());
                        progInfo.put("language_id", program.getLanguageID().getIdAsString());
                        progInfo.put("compiler_spec_id", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
                        progInfo.put("image_base", program.getImageBase().toString());
                        progInfo.put("memory_size", program.getMemory().getSize());
                        progInfo.put("is_open", true);
                        progInfo.put("analysis_complete", program.getListing().getNumDefinedData() > 0);
                        programs.add(progInfo);
                    }
                    
                    JsonObject response = createSuccessResponse(exchange, programs);
                    response.add("_links", createLinks()
                        .add("self", "/programs")
                        .add("create", "/programs", "POST")
                        .build());
                        
                    sendJsonResponse(exchange, response, 200);
                } else if ("POST".equals(exchange.getRequestMethod())) {
                    sendErrorResponse(exchange, 501, "Not Implemented", "NOT_IMPLEMENTED");
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                sendErrorResponse(exchange, 500, "Internal server error", "INTERNAL_ERROR");
            }
        });

        server.createContext("/programs/", exchange -> {
            try {
                String path = exchange.getRequestURI().getPath();
                String programId = path.substring("/programs/".length());
                
                if ("GET".equals(exchange.getRequestMethod())) {
                    Program program = getCurrentProgram();
                    if (program == null) {
                        sendErrorResponse(exchange, 404, "Program not found", "PROGRAM_NOT_FOUND");
                        return;
                    }
                    
                    Map<String, Object> programInfo = new HashMap<>();
                    programInfo.put("program_id", program.getDomainFile().getPathname());
                    programInfo.put("name", program.getName());
                    programInfo.put("language_id", program.getLanguageID().getIdAsString());
                    programInfo.put("compiler_spec_id", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
                    programInfo.put("image_base", program.getImageBase().toString());
                    programInfo.put("memory_size", program.getMemory().getSize());
                    programInfo.put("is_open", true);
                    programInfo.put("analysis_complete", program.getListing().getNumDefinedData() > 0);
                    
                    JsonObject links = new JsonObject();
                    links.add("self", createLink("/programs/" + programId));
                    links.add("project", createLink("/projects/" + program.getDomainFile().getProjectLocator().getName()));
                    links.add("functions", createLink("/programs/" + programId + "/functions"));
                    links.add("symbols", createLink("/programs/" + programId + "/symbols"));
                    links.add("data", createLink("/programs/" + programId + "/data"));
                    links.add("segments", createLink("/programs/" + programId + "/segments"));
                    links.add("memory", createLink("/programs/" + programId + "/memory"));
                    links.add("xrefs", createLink("/programs/" + programId + "/xrefs"));
                    links.add("analysis", createLink("/programs/" + programId + "/analysis"));
                    
                    JsonObject response = createSuccessResponse(exchange, programInfo, links);
                    sendJsonResponse(exchange, response, 200);
                } else if ("DELETE".equals(exchange.getRequestMethod())) {
                    sendErrorResponse(exchange, 501, "Not Implemented", "NOT_IMPLEMENTED");
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                sendErrorResponse(exchange, 500, "Internal server error", "INTERNAL_ERROR");
            }
        });

        // Meta endpoints
        server.createContext("/plugin-version", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                JsonObject response = createBaseResponse(exchange);
                response.addProperty("success", true);
                
                JsonObject result = new JsonObject();
                result.addProperty("plugin_version", PLUGIN_VERSION);
                result.addProperty("api_version", API_VERSION);
                response.add("result", result);
                
                JsonObject links = new JsonObject();
                links.add("self", createLink("/plugin-version"));
                response.add("_links", links);
                
                sendJsonResponse(exchange, response, 200);
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        });

        // Project resources
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
                    
                    JsonObject response = createSuccessResponse(exchange, projects);
                    response.add("_links", createLinks()
                        .add("self", "/projects")
                        .add("create", "/projects", "POST")
                        .build());
                        
                    sendJsonResponse(exchange, response, 200);
                } else if ("POST".equals(exchange.getRequestMethod())) {
                    sendErrorResponse(exchange, 501, "Not Implemented", "NOT_IMPLEMENTED");
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                sendErrorResponse(exchange, 500, "Internal server error", "INTERNAL_ERROR");
            }
        });

        // Function resources
        server.createContext("/functions", exchange -> {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, String> qparams = parseQueryParams(exchange);
                    int offset = parseIntOrDefault(qparams.get("offset"), 0);
                    int limit = parseIntOrDefault(qparams.get("limit"), 100);
                    String query = qparams.get("query");
                    
                    Object resultData;
                    if (query != null && !query.isEmpty()) {
                        // TODO: Refactor searchFunctionsByName to return List<Map<String, String>> or similar
                        resultData = searchFunctionsByName(query, offset, limit); 
                    } else {
                        // TODO: Refactor getAllFunctionNames to return List<Map<String, String>> or similar
                         resultData = getAllFunctionNames(offset, limit); 
                    }
                    // Temporary check for old error format
                    if (resultData instanceof JsonObject && !((JsonObject)resultData).has("result")) {
                         sendJsonResponse(exchange, (JsonObject)resultData, 400); 
                    } else {
                         sendJsonResponse(exchange, resultData); 
                    }
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /functions endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        });

        server.createContext("/functions/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            String[] pathParts = path.split("/");
            
            if (pathParts.length < 3) {
                sendErrorResponse(exchange, 400, "Invalid path format", "INVALID_PATH");
                return;
            }
            
            String functionName = "";
             try {
                 functionName = java.net.URLDecoder.decode(pathParts[2], StandardCharsets.UTF_8.name());
             } catch (Exception e) {
                 sendErrorResponse(exchange, 400, "Failed to decode function name", "INVALID_PARAMETER");
                 return;
             }
            
            if (pathParts.length > 3 && "variables".equals(pathParts[3])) { // /functions/{name}/variables/...
                if ("GET".equals(exchange.getRequestMethod()) && pathParts.length == 4) { // GET /functions/{name}/variables
                    try {
                        // TODO: Refactor listVariablesInFunction to return data directly
                        Object resultData = listVariablesInFunction(functionName);
                        if (resultData instanceof JsonObject && !((JsonObject)resultData).has("result")) {
                             sendJsonResponse(exchange, (JsonObject)resultData, 400); 
                        } else {
                             sendJsonResponse(exchange, resultData);
                        }
                    } catch (Exception e) {
                         Msg.error(this, "Error listing function variables", e);
                         sendErrorResponse(exchange, 500, "Error listing variables: " + e.getMessage(), "INTERNAL_ERROR");
                    }
                } else if ("POST".equals(exchange.getRequestMethod()) && pathParts.length == 5) { // POST /functions/{name}/variables/{varName}
                    String variableName = "";
                    try {
                        variableName = java.net.URLDecoder.decode(pathParts[4], StandardCharsets.UTF_8.name());
                    } catch (Exception e) {
                        sendErrorResponse(exchange, 400, "Failed to decode variable name", "INVALID_PARAMETER");
                        return;
                    }
                    
                    final String finalVariableName = variableName;
                    final String finalFunctionName = functionName;
                    try {
                        Map<String, String> params = parseJsonPostParams(exchange);
                        Program program = getCurrentProgram();
                        if (program == null) {
                             sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM");
                             return;
                        }

                        if (params.containsKey("newName")) {
                            final String newName = params.get("newName");
                            try {
                                executeInTransaction(program, "Rename Variable", () -> {
                                    if (!renameVariable(finalFunctionName, finalVariableName, newName)) {
                                         throw new Exception("Rename operation failed internally.");
                                    }
                                });
                                sendJsonResponse(exchange, Map.of("message", "Variable renamed successfully"));
                            } catch (Exception e) {
                                 Msg.error(this, "Transaction failed: Rename Variable", e);
                                 sendErrorResponse(exchange, 500, "Failed to rename variable: " + e.getMessage(), "TRANSACTION_ERROR");
                            }
                        } else if (params.containsKey("dataType")) {
                            final String newType = params.get("dataType");
                            try {
                                executeInTransaction(program, "Retype Variable", () -> {
                                    if (!retypeVariable(finalFunctionName, finalVariableName, newType)) {
                                         throw new Exception("Retype operation failed internally.");
                                    }
                                });
                                sendJsonResponse(exchange, Map.of("message", "Variable retyped successfully"));
                            } catch (Exception e) {
                                 Msg.error(this, "Transaction failed: Retype Variable", e);
                                 sendErrorResponse(exchange, 500, "Failed to retype variable: " + e.getMessage(), "TRANSACTION_ERROR");
                            }
                        } else {
                            sendErrorResponse(exchange, 400, "Missing required parameter: newName or dataType", "MISSING_PARAMETER");
                        }
                    } catch (IOException e) {
                         Msg.error(this, "Error parsing POST params for variable update", e);
                         sendErrorResponse(exchange, 400, "Invalid request body: " + e.getMessage(), "INVALID_REQUEST");
                    } catch (Exception e) {
                         Msg.error(this, "Error updating variable", e);
                         sendErrorResponse(exchange, 500, "Error updating variable: " + e.getMessage(), "INTERNAL_ERROR");
                    }
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } else if (pathParts.length == 3) { // GET or POST /functions/{name}
                if ("GET".equals(exchange.getRequestMethod())) {
                    try {
                        // TODO: Refactor getFunctionDetailsByName to return data directly
                        Object resultData = getFunctionDetailsByName(functionName);
                        if (resultData instanceof JsonObject && !((JsonObject)resultData).has("result")) {
                             sendJsonResponse(exchange, (JsonObject)resultData, 404); 
                        } else {
                             sendJsonResponse(exchange, resultData);
                        }
                    } catch (Exception e) {
                         Msg.error(this, "Error getting function details", e);
                         sendErrorResponse(exchange, 500, "Error getting details: " + e.getMessage(), "INTERNAL_ERROR");
                    }
                } else if ("POST".equals(exchange.getRequestMethod())) {
                     try {
                        Map<String, String> params = parseJsonPostParams(exchange);
                        String newName = params.get("newName");
                        if (newName == null || newName.isEmpty()) {
                             sendErrorResponse(exchange, 400, "Missing required parameter: newName", "MISSING_PARAMETER");
                             return;
                        }
                        
                        Program program = getCurrentProgram();
                        if (program == null) {
                             sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM");
                             return;
                        }
                        
                        final String finalFunctionName = functionName;
                        final String finalNewName = newName; 
                        try {
                            executeInTransaction(program, "Rename Function", () -> {
                                 if (!renameFunction(finalFunctionName, finalNewName)) {
                                     throw new Exception("Rename operation failed internally.");
                                 }
                            });
                            sendJsonResponse(exchange, Map.of("message", "Function renamed successfully"));
                        } catch (Exception e) {
                             Msg.error(this, "Transaction failed: Rename Function", e);
                             sendErrorResponse(exchange, 500, "Failed to rename function: " + e.getMessage(), "TRANSACTION_ERROR");
                        }

                    } catch (IOException e) {
                         Msg.error(this, "Error parsing POST params for function rename", e);
                         sendErrorResponse(exchange, 400, "Invalid request body: " + e.getMessage(), "INVALID_REQUEST");
                    } catch (Exception e) {
                         Msg.error(this, "Error renaming function", e);
                         sendErrorResponse(exchange, 500, "Error renaming function: " + e.getMessage(), "INTERNAL_ERROR");
                    }
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            }
        });

        // Class resources
        server.createContext("/classes", exchange -> {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, String> qparams = parseQueryParams(exchange);
                    int offset = parseIntOrDefault(qparams.get("offset"), 0);
                    int limit = parseIntOrDefault(qparams.get("limit"), 100);
                    Object resultData = getAllClassNames(offset, limit); 
                    if (resultData instanceof JsonObject && !((JsonObject)resultData).has("result")) { 
                         sendJsonResponse(exchange, (JsonObject)resultData, 400); 
                    } else {
                         sendJsonResponse(exchange, resultData); 
                    }
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /classes endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        });

        // Memory segments
        server.createContext("/segments", exchange -> {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, String> qparams = parseQueryParams(exchange);
                    int offset = parseIntOrDefault(qparams.get("offset"), 0);
                    int limit = parseIntOrDefault(qparams.get("limit"), 100);
                    Object resultData = listSegments(offset, limit);
                     if (resultData instanceof JsonObject && !((JsonObject)resultData).has("result")) {
                         sendJsonResponse(exchange, (JsonObject)resultData, 400);
                    } else {
                         sendJsonResponse(exchange, resultData);
                    }
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /segments endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        });

        // Symbol resources (imports/exports)
        server.createContext("/symbols/imports", exchange -> {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, String> qparams = parseQueryParams(exchange);
                    int offset = parseIntOrDefault(qparams.get("offset"), 0);
                    int limit = parseIntOrDefault(qparams.get("limit"), 100);
                    Object resultData = listImports(offset, limit);
                     if (resultData instanceof JsonObject && !((JsonObject)resultData).has("result")) {
                         sendJsonResponse(exchange, (JsonObject)resultData, 400);
                    } else {
                         sendJsonResponse(exchange, resultData);
                    }
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /symbols/imports endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        });

        server.createContext("/symbols/exports", exchange -> {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, String> qparams = parseQueryParams(exchange);
                    int offset = parseIntOrDefault(qparams.get("offset"), 0);
                    int limit = parseIntOrDefault(qparams.get("limit"), 100);
                    Object resultData = listExports(offset, limit);
                     if (resultData instanceof JsonObject && !((JsonObject)resultData).has("result")) {
                         sendJsonResponse(exchange, (JsonObject)resultData, 400);
                    } else {
                         sendJsonResponse(exchange, resultData);
                    }
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /symbols/exports endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        });

        // Namespace resources
        server.createContext("/namespaces", exchange -> {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, String> qparams = parseQueryParams(exchange);
                    int offset = parseIntOrDefault(qparams.get("offset"), 0);
                    int limit = parseIntOrDefault(qparams.get("limit"), 100);
                    Object resultData = listNamespaces(offset, limit);
                     if (resultData instanceof JsonObject && !((JsonObject)resultData).has("result")) {
                         sendJsonResponse(exchange, (JsonObject)resultData, 400);
                    } else {
                         sendJsonResponse(exchange, resultData);
                    }
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /namespaces endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        });

        // Data resources
        server.createContext("/data", exchange -> {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, String> qparams = parseQueryParams(exchange);
                    int offset = parseIntOrDefault(qparams.get("offset"), 0);
                    int limit = parseIntOrDefault(qparams.get("limit"), 100);
                    Object resultData = listDefinedData(offset, limit);
                     if (resultData instanceof JsonObject && !((JsonObject)resultData).get("success").getAsBoolean()) {
                         sendJsonResponse(exchange, (JsonObject)resultData, 400);
                    } else {
                         sendJsonResponse(exchange, resultData);
                    }
                } else if ("POST".equals(exchange.getRequestMethod())) { // POST /data
                     try {
                        Map<String, String> params = parseJsonPostParams(exchange);
                        final String addressStr = params.get("address");
                        final String newName = params.get("newName");

                        if (addressStr == null || addressStr.isEmpty() || newName == null || newName.isEmpty()) {
                            sendErrorResponse(exchange, 400, "Missing required parameters: address, newName", "MISSING_PARAMETER");
                            return;
                        }

                        Program program = getCurrentProgram();
                        if (program == null) {
                             sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM");
                             return;
                        }
                        
                        try {
                            executeInTransaction(program, "Rename Data", () -> {
                                if (!renameDataAtAddress(addressStr, newName)) {
                                    throw new Exception("Rename data operation failed internally.");
                                }
                            });
                            sendJsonResponse(exchange, Map.of("message", "Data renamed successfully"));
                        } catch (Exception e) {
                             Msg.error(this, "Transaction failed: Rename Data", e);
                             sendErrorResponse(exchange, 500, "Failed to rename data: " + e.getMessage(), "TRANSACTION_ERROR");
                        }

                    } catch (IOException e) {
                         Msg.error(this, "Error parsing POST params for data rename", e);
                         sendErrorResponse(exchange, 400, "Invalid request body: " + e.getMessage(), "INVALID_REQUEST");
                    } catch (Exception e) {
                         Msg.error(this, "Error renaming data", e);
                         sendErrorResponse(exchange, 500, "Error renaming data: " + e.getMessage(), "INTERNAL_ERROR");
                    }
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /data endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        });
        
        // Global variables endpoint
        server.createContext("/variables", exchange -> { // GET /variables
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, String> qparams = parseQueryParams(exchange);
                    int offset = parseIntOrDefault(qparams.get("offset"), 0);
                    int limit = parseIntOrDefault(qparams.get("limit"), 100);
                    String search = qparams.get("search");
                    
                    Object resultData = listVariables(offset, limit, search);
                     if (resultData instanceof JsonObject && !((JsonObject)resultData).has("result")) { // Check old error format
                         sendJsonResponse(exchange, (JsonObject)resultData, 400);
                    } else {
                         sendJsonResponse(exchange, resultData); // Use new success helper
                    }
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /variables endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        });

        // Instance management endpoints
        server.createContext("/instances", exchange -> {
            // TODO: This endpoint might change based on HATEOAS design for projects/programs
            try {
                 List<Map<String, Object>> instanceData = new ArrayList<>();
                 for (Map.Entry<Integer, GhydraMCPPlugin> entry : activeInstances.entrySet()) {
                    Map<String, Object> instance = new HashMap<>();
                    instance.put("port", entry.getKey());
                    instance.put("type", entry.getValue().isBaseInstance ? "base" : "secondary");
                    // TODO: Add URL and program_id if available from instance info cache
                    instanceData.add(instance);
                }
                sendJsonResponse(exchange, instanceData); // Use new success helper
            } catch (Exception e) {
                 Msg.error(this, "Error in /instances endpoint", e);
                 sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        });

        // Add get_function_by_address endpoint
        server.createContext("/get_function_by_address", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                String address = qparams.get("address");
                
                if (address == null || address.isEmpty()) {
                    sendErrorResponse(exchange, 400, "Address parameter is required", "MISSING_PARAMETER");
                    return;
                }
                
                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM");
                    return;
                }
                
                try {
                    Address funcAddr = program.getAddressFactory().getAddress(address);
                    Function func = program.getFunctionManager().getFunctionAt(funcAddr);
                    if (func == null) {
                         sendErrorResponse(exchange, 404, "Function not found at address: " + address, "RESOURCE_NOT_FOUND");
                         return;
                    }
                    
                    Object resultData = getFunctionDetails(func); 
                     if (resultData instanceof JsonObject && !((JsonObject)resultData).has("result")) { 
                         sendJsonResponse(exchange, (JsonObject)resultData, 500); 
                    } else {
                         sendJsonResponse(exchange, resultData); 
                    }
                } catch (ghidra.program.model.address.AddressFormatException afe) {
                     Msg.warn(this, "Invalid address format: " + address, afe);
                     sendErrorResponse(exchange, 400, "Invalid address format: " + address, "INVALID_ADDRESS");
                } catch (Exception e) {
                    Msg.error(this, "Error getting function by address", e);
                    sendErrorResponse(exchange, 500, "Error getting function: " + e.getMessage(), "INTERNAL_ERROR");
                }
            } else {
                 sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        });

        // Add decompile function by address endpoint
        server.createContext("/decompile_function", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                String address = qparams.get("address");
                boolean cCode = Boolean.parseBoolean(qparams.getOrDefault("cCode", "true"));
                boolean syntaxTree = Boolean.parseBoolean(qparams.getOrDefault("syntaxTree", "false"));
                String simplificationStyle = qparams.getOrDefault("simplificationStyle", "normalize");
                
                if (address == null || address.isEmpty()) {
                    sendErrorResponse(exchange, 400, "Address parameter is required", "MISSING_PARAMETER");
                    return;
                }
                
                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM");
                    return;
                }
                
                try {
                    Address funcAddr = program.getAddressFactory().getAddress(address);
                    Function func = program.getFunctionManager().getFunctionAt(funcAddr);
                    if (func == null) {
                         sendErrorResponse(exchange, 404, "Function not found at address: " + address, "RESOURCE_NOT_FOUND");
                         return;
                    }
                    
                    DecompInterface decomp = new DecompInterface();
                    try {
                        decomp.toggleCCode(cCode);
                        decomp.setSimplificationStyle(simplificationStyle);
                        decomp.toggleSyntaxTree(syntaxTree);
                        
                        if (!decomp.openProgram(program)) {
                            sendErrorResponse(exchange, 500, "Failed to initialize decompiler", "DECOMPILER_ERROR");
                            return;
                        }
                        
                        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                        if (result == null || !result.decompileCompleted()) {
                            sendErrorResponse(exchange, 500, "Decompilation failed or timed out", "DECOMPILATION_FAILED");
                            return;
                        }
                        
                        String decompilation = "";
                        String errorMessage = null;
                        if (result.getDecompiledFunction() != null) {
                            decompilation = result.getDecompiledFunction().getC();
                            if (decompilation == null || decompilation.isEmpty()) {
                                errorMessage = "Decompilation returned empty result";
                            }
                        } else {
                            errorMessage = "DecompiledFunction is null";
                        }

                        if (errorMessage != null) {
                             Msg.error(this, "Error decompiling function: " + errorMessage);
                             sendErrorResponse(exchange, 500, errorMessage, "DECOMPILATION_ERROR");
                        } else {
                            Map<String, Object> resultData = new HashMap<>();
                            resultData.put("address", func.getEntryPoint().toString());
                            resultData.put("ccode", decompilation);
                            sendJsonResponse(exchange, resultData);
                        }
                    } finally {
                        decomp.dispose();
                    }
                } catch (ghidra.program.model.address.AddressFormatException afe) {
                     Msg.warn(this, "Invalid address format: " + address, afe);
                     sendErrorResponse(exchange, 400, "Invalid address format: " + address, "INVALID_ADDRESS");
                } catch (Exception e) {
                    Msg.error(this, "Error decompiling function", e);
                    sendErrorResponse(exchange, 500, "Error decompiling function: " + e.getMessage(), "INTERNAL_ERROR");
                }
            } else {
                 sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        });

        // Add decompiler comment endpoint (Using POST now as per bridge)
        server.createContext("/set_decompiler_comment", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parseJsonPostParams(exchange); // Use specific JSON parser
                String address = params.get("address");
                String comment = params.get("comment");
                
                if (address == null || address.isEmpty()) {
                    sendErrorResponse(exchange, 400, "Address parameter is required");
                    return;
                }
                
                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded");
                    return;
                }
                
                try {
                    final Address addr = program.getAddressFactory().getAddress(address);
                    final String finalComment = comment; 
                    
                    executeInTransaction(program, "Set Decompiler Comment", () -> {
                         if (!setDecompilerComment(addr, finalComment)) { 
                             throw new Exception("Set decompiler comment operation failed internally.");
                         }
                    });
                    sendJsonResponse(exchange, Map.of("message", "Decompiler comment set successfully"));

                } catch (ghidra.program.model.address.AddressFormatException afe) {
                     Msg.warn(this, "Invalid address format: " + address, afe);
                     sendErrorResponse(exchange, 400, "Invalid address format: " + address, "INVALID_ADDRESS");
                } catch (Exception e) {
                    Msg.error(this, "Error setting decompiler comment", e);
                    sendErrorResponse(exchange, 500, "Error setting comment: " + e.getMessage(), "INTERNAL_ERROR");
                }
            } else {
                 sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        });

        // Add disassembly comment endpoint (Using POST now as per bridge)
        server.createContext("/set_disassembly_comment", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parseJsonPostParams(exchange); // Use specific JSON parser
                String address = params.get("address");
                String comment = params.get("comment");
                
                if (address == null || address.isEmpty()) {
                    sendErrorResponse(exchange, 400, "Address parameter is required");
                    return;
                }
                
                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded");
                    return;
                }
                
                try {
                    final Address addr = program.getAddressFactory().getAddress(address);
                     final String finalComment = comment; 

                    executeInTransaction(program, "Set Disassembly Comment", () -> {
                        if (!setDisassemblyComment(addr, finalComment)) { 
                             throw new Exception("Set disassembly comment operation failed internally.");
                         }
                    });
                    sendJsonResponse(exchange, Map.of("message", "Disassembly comment set successfully"));

                 } catch (ghidra.program.model.address.AddressFormatException afe) {
                     Msg.warn(this, "Invalid address format: " + address, afe);
                     sendErrorResponse(exchange, 400, "Invalid address format: " + address, "INVALID_ADDRESS");
                } catch (Exception e) {
                    Msg.error(this, "Error setting disassembly comment", e);
                    sendErrorResponse(exchange, 500, "Error setting comment: " + e.getMessage(), "INTERNAL_ERROR");
                }
            } else {
                 sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        });

        // Add rename function by address endpoint (Using POST now as per bridge)
        server.createContext("/rename_function_by_address", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parseJsonPostParams(exchange); // Use specific JSON parser
                String address = params.get("functionAddress"); // Expect camelCase
                String newName = params.get("newName"); // Expect camelCase
                
                if (address == null || address.isEmpty()) {
                    sendErrorResponse(exchange, 400, "functionAddress parameter is required");
                    return;
                }

                if (newName == null || newName.isEmpty()) {
                    sendErrorResponse(exchange, 400, "newName parameter is required");
                    return;
                }
                
                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded");
                    return;
                }
                
                try {
                    final Address funcAddr = program.getAddressFactory().getAddress(address);
                    final String finalNewName = newName; 

                    executeInTransaction(program, "Rename Function by Address", () -> {
                         if (!renameFunctionByAddress(funcAddr, finalNewName)) { 
                             throw new Exception("Rename function by address operation failed internally.");
                         }
                    });
                    sendJsonResponse(exchange, Map.of("message", "Function renamed successfully"));

                 } catch (ghidra.program.model.address.AddressFormatException afe) {
                     Msg.warn(this, "Invalid address format: " + address, afe);
                     sendErrorResponse(exchange, 400, "Invalid address format: " + address, "INVALID_ADDRESS");
                } catch (Exception e) {
                    Msg.error(this, "Error renaming function by address", e);
                    sendErrorResponse(exchange, 500, "Error renaming function: " + e.getMessage(), "INTERNAL_ERROR");
                }
            } else {
                 sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        });

        // Add rename local variable endpoint (Using POST now as per bridge)
        server.createContext("/rename_local_variable", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parseJsonPostParams(exchange);
                String functionAddress = params.get("functionAddress");
                String oldName = params.get("oldName");
                String newName = params.get("newName");

                if (functionAddress == null || functionAddress.isEmpty()) {
                    sendErrorResponse(exchange, 400, "functionAddress parameter is required"); return;
                }
                if (oldName == null || oldName.isEmpty()) {
                    sendErrorResponse(exchange, 400, "oldName parameter is required"); return;
                }
                if (newName == null || newName.isEmpty()) {
                    sendErrorResponse(exchange, 400, "newName parameter is required"); return;
                }

                // TODO: Implement actual logic using executeInTransaction
                sendJsonResponse(exchange, Map.of("message", "Rename local variable request received (implementation pending)"));

            } else {
                 sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        });

        // Add set function prototype endpoint (Using POST now as per bridge)
        server.createContext("/set_function_prototype", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parseJsonPostParams(exchange);
                String functionAddress = params.get("functionAddress");
                String prototype = params.get("prototype");

                if (functionAddress == null || functionAddress.isEmpty()) {
                    sendErrorResponse(exchange, 400, "functionAddress parameter is required"); return;
                }
                if (prototype == null || prototype.isEmpty()) {
                    sendErrorResponse(exchange, 400, "prototype parameter is required"); return;
                }

                // TODO: Implement actual logic using executeInTransaction
                sendJsonResponse(exchange, Map.of("message", "Set function prototype request received (implementation pending)"));

            } else {
                 sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        });

        // Add set local variable type endpoint (Using POST now as per bridge)
        server.createContext("/set_local_variable_type", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parseJsonPostParams(exchange);
                String functionAddress = params.get("functionAddress");
                String variableName = params.get("variableName");
                String newType = params.get("newType");

                if (functionAddress == null || functionAddress.isEmpty()) {
                    sendErrorResponse(exchange, 400, "functionAddress parameter is required"); return;
                }
                if (variableName == null || variableName.isEmpty()) {
                    sendErrorResponse(exchange, 400, "variableName parameter is required"); return;
                }
                 if (newType == null || newType.isEmpty()) {
                    sendErrorResponse(exchange, 400, "newType parameter is required"); return;
                }

                // TODO: Implement actual logic using executeInTransaction
                 sendJsonResponse(exchange, Map.of("message", "Set local variable type request received (implementation pending)"));

            } else {
                 sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        });

        // Add get current address endpoint (Changed to GET to match test expectations)
        server.createContext("/get_current_address", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM");
                    return;
                }
                
                try {
                    Address currentAddr = getCurrentAddress(); 
                    if (currentAddr != null) {
                        sendJsonResponse(exchange, Map.of("address", currentAddr.toString()));
                    } else {
                        sendErrorResponse(exchange, 404, "No address currently selected", "RESOURCE_NOT_FOUND"); 
                    }
                } catch (Exception e) {
                    Msg.error(this, "Error getting current address", e);
                    sendErrorResponse(exchange, 500, "Error getting current address: " + e.getMessage(), "INTERNAL_ERROR");
                }
            } else {
                 sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        });

        // Add get current function endpoint (Changed to GET to match test expectations)
        server.createContext("/get_current_function", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM");
                    return;
                }
                
                try {
                    Function currentFunc = getCurrentFunction(); 
                    if (currentFunc != null) {
                         Map<String, Object> funcData = new HashMap<>();
                         funcData.put("name", currentFunc.getName());
                         funcData.put("address", currentFunc.getEntryPoint().toString());
                         funcData.put("signature", currentFunc.getSignature().getPrototypeString());
                         sendJsonResponse(exchange, funcData);
                    } else {
                         sendErrorResponse(exchange, 404, "No function currently selected", "RESOURCE_NOT_FOUND");
                    }
                } catch (Exception e) {
                    Msg.error(this, "Error getting current function", e);
                     sendErrorResponse(exchange, 500, "Error getting current function: " + e.getMessage(), "INTERNAL_ERROR");
                }
            } else {
                 sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        });


        // Info endpoint using new helpers
        server.createContext("/info", exchange -> {
            try {
                 Map<String, Object> infoData = new HashMap<>();
                 infoData.put("port", port);
                 infoData.put("isBaseInstance", isBaseInstance);
                
                Program program = getCurrentProgram();
                 infoData.put("file", program != null ? program.getName() : null); 
                
                Project project = tool.getProject();
                 infoData.put("project", project != null ? project.getName() : null);
                
                 sendJsonResponse(exchange, infoData);
            } catch (Exception e) {
                Msg.error(this, "Error serving /info endpoint", e);
                 sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        });
        
        // Root endpoint - only handle exact "/" path
        server.createContext("/", exchange -> {
            if (!exchange.getRequestURI().getPath().equals("/")) {
                Msg.info(this, "Received request for unknown path: " + exchange.getRequestURI().getPath());
                sendErrorResponse(exchange, 404, "Endpoint not found", "ENDPOINT_NOT_FOUND");
                return;
            }
            
            try {
                 Map<String, Object> rootData = new HashMap<>();
                 rootData.put("port", port);
                 rootData.put("isBaseInstance", isBaseInstance);
                Program program = getCurrentProgram();
                 rootData.put("file", program != null ? program.getName() : null);
                Project project = tool.getProject();
                 rootData.put("project", project != null ? project.getName() : null);
                 // TODO: Add HATEOAS links here (e.g., to /info, /projects, /programs)
                
                 sendJsonResponse(exchange, rootData);
            } catch (Exception e) {
                Msg.error(this, "Error serving / endpoint", e);
                 sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        });

        server.createContext("/registerInstance", exchange -> {
            try {
                Map<String, String> params = parseJsonPostParams(exchange);
                int regPort = parseIntOrDefault(params.get("port"), 0);
                if (regPort > 0) {
                     sendJsonResponse(exchange, Map.of("message", "Instance registration request received for port " + regPort));
                } else {
                     sendErrorResponse(exchange, 400, "Invalid or missing port number", "INVALID_PARAMETER");
                }
            } catch (IOException e) {
                 Msg.error(this, "Error parsing POST params for registerInstance", e);
                 sendErrorResponse(exchange, 400, "Invalid request body: " + e.getMessage(), "INVALID_REQUEST");
            } catch (Exception e) {
                Msg.error(this, "Error in /registerInstance", e);
                 sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        });

        server.createContext("/unregisterInstance", exchange -> {
            try {
                Map<String, String> params = parseJsonPostParams(exchange);
                int unregPort = parseIntOrDefault(params.get("port"), 0);
                if (unregPort > 0 && activeInstances.containsKey(unregPort)) {
                    activeInstances.remove(unregPort); 
                     sendJsonResponse(exchange, Map.of("message", "Instance unregistered for port " + unregPort));
                } else {
                     sendErrorResponse(exchange, 404, "No instance found on port " + unregPort, "RESOURCE_NOT_FOUND");
                }
             } catch (IOException e) {
                 Msg.error(this, "Error parsing POST params for unregisterInstance", e);
                 sendErrorResponse(exchange, 400, "Invalid request body: " + e.getMessage(), "INVALID_REQUEST");
            } catch (Exception e) {
                Msg.error(this, "Error in /unregisterInstance", e);
                 sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        });

        server.setExecutor(null);
        new Thread(() -> {
            server.start();
            Msg.info(this, "GhydraMCP HTTP server started on port " + port);
            System.out.println("[GhydraMCP] HTTP server started on port " + port);
        }, "GhydraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private JsonObject getAllFunctionNames(int offset, int limit) { // Changed return type
        Program program = getCurrentProgram();
        if (program == null) {
             return createErrorResponse("No program loaded", 400);
        }

        List<Map<String, String>> functions = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            Map<String, String> func = new HashMap<>();
            func.put("name", f.getName());
            func.put("address", f.getEntryPoint().toString());
            functions.add(func);
        }
        
        // Apply pagination
        int start = Math.max(0, offset);
        int end = Math.min(functions.size(), offset + limit);
        List<Map<String, String>> paginated = functions.subList(start, end);
        
        // Use helper to create standard response
        return createSuccessResponse(paginated); // Return JsonObject
    }

    private JsonObject getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded", 400);
        }

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        
        // Convert to sorted list and paginate
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        int start = Math.max(0, offset);
        int end = Math.min(sorted.size(), offset + limit);
        List<String> paginated = sorted.subList(start, end);
        
        // Use helper to create standard response
        return createSuccessResponse(paginated);
    }

    private JsonObject listSegments(int offset, int limit) { // Changed return type to JsonObject
        Program program = getCurrentProgram();
        if (program == null) {
             return createErrorResponse("No program loaded", 400);
        }

        List<Map<String, String>> segments = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            Map<String, String> seg = new HashMap<>();
            seg.put("name", block.getName());
            seg.put("start", block.getStart().toString());
            seg.put("end", block.getEnd().toString());
            segments.add(seg);
        }
        
        // Apply pagination
        int start = Math.max(0, offset);
        int end = Math.min(segments.size(), offset + limit);
        List<Map<String, String>> paginated = segments.subList(start, end);
        
        // Use helper to create standard response
        return createSuccessResponse(paginated);
    }

    private JsonObject listImports(int offset, int limit) { // Changed return type to JsonObject
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded", 400);
        }

        List<Map<String, String>> imports = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            Map<String, String> imp = new HashMap<>();
            imp.put("name", symbol.getName());
            imp.put("address", symbol.getAddress().toString());
            imports.add(imp);
        }
        
        // Apply pagination
        int start = Math.max(0, offset);
        int end = Math.min(imports.size(), offset + limit);
        List<Map<String, String>> paginated = imports.subList(start, end);
        
        // Use helper to create standard response
        return createSuccessResponse(paginated); // Return JsonObject directly
    }

    private JsonObject listExports(int offset, int limit) { // Changed return type to JsonObject
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded", 400);
        }

        List<Map<String, String>> exports = new ArrayList<>();
        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.isExternalEntryPoint()) {
                Map<String, String> exp = new HashMap<>();
                exp.put("name", s.getName());
                exp.put("address", s.getAddress().toString());
                exports.add(exp);
            }
        }
        
        // Apply pagination
        int start = Math.max(0, offset);
        int end = Math.min(exports.size(), offset + limit);
        List<Map<String, String>> paginated = exports.subList(start, end);
        
        // Use helper to create standard response
        return createSuccessResponse(paginated); // Return JsonObject directly
    }

    private JsonObject listNamespaces(int offset, int limit) { // Changed return type to JsonObject
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded", 400);
        }

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        
        // Apply pagination
        int start = Math.max(0, offset);
        int end = Math.min(sorted.size(), offset + limit);
        List<String> paginated = sorted.subList(start, end);
        
        // Use helper to create standard response
        return createSuccessResponse(paginated); // Return JsonObject directly
    }

    private JsonObject listDefinedData(int offset, int limit) { // Changed return type to JsonObject
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded", 400);
        }

        List<Map<String, String>> dataItems = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    Map<String, String> item = new HashMap<>();
                    item.put("address", data.getAddress().toString());
                    item.put("label", data.getLabel() != null ? data.getLabel() : "(unnamed)");
                    item.put("value", data.getDefaultValueRepresentation());
                    dataItems.add(item);
                }
            }
        }
        
        // Apply pagination
        int start = Math.max(0, offset);
        int end = Math.min(dataItems.size(), offset + limit);
        List<Map<String, String>> paginated = dataItems.subList(start, end);
        
        // Use helper to create standard response
        return createSuccessResponse(paginated); // Return JsonObject directly
    }

    private JsonObject searchFunctionsByName(String searchTerm, int offset, int limit) { // Changed return type to JsonObject
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded", 400);
        }
        if (searchTerm == null || searchTerm.isEmpty()) {
            return createErrorResponse("Search term is required", 400);
        }
    
        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
    
        if (matches.isEmpty()) {
            // Return success with empty result list
            return createSuccessResponse(new ArrayList<>()); 
        }
        
        // Paginate the string list representation
        int start = Math.max(0, offset);
        int end   = Math.min(matches.size(), offset + limit);
        List<String> sub = matches.subList(start, end);
        
        // Return paginated list using helper
        return createSuccessResponse(sub);
    }

    // ----------------------------------------------------------------------------------
    // Logic for getting function details, rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private JsonObject getFunctionDetailsByName(String name) {
        JsonObject response = new JsonObject();
        Program program = getCurrentProgram();
        if (program == null) {
            response.addProperty("success", false);
            response.addProperty("error", "No program loaded");
            return response;
        }

        Function func = findFunctionByName(program, name);
        if (func == null) {
            response.addProperty("success", false);
            response.addProperty("error", "Function not found: " + name);
            return response;
        }

        return getFunctionDetails(func); // Use common helper
    }

    // Helper to get function details and decompilation
    private JsonObject getFunctionDetails(Function func) {
        JsonObject response = new JsonObject();
        JsonObject resultObj = new JsonObject();
        Program program = func.getProgram();

        resultObj.addProperty("name", func.getName());
        resultObj.addProperty("address", func.getEntryPoint().toString());
        resultObj.addProperty("signature", func.getSignature().getPrototypeString());

        DecompInterface decomp = new DecompInterface();
        try {
            // Default to C code output and no syntax tree for better readability
            decomp.toggleCCode(true);
            decomp.setSimplificationStyle("normalize");
            decomp.toggleSyntaxTree(false);
            
            if (!decomp.openProgram(program)) {
                resultObj.addProperty("decompilation_error", "Failed to initialize decompiler");
            } else {
                DecompileResults decompResult = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (decompResult == null) {
                    resultObj.addProperty("decompilation_error", "Decompilation returned null result");
                } else if (!decompResult.decompileCompleted()) {
                    resultObj.addProperty("decompilation_error", "Decompilation failed or timed out");
                } else {
                    // Handle decompilation result with proper JSON structure
                    JsonObject decompilationResult = new JsonObject();
                    
                    ghidra.app.decompiler.DecompiledFunction decompiledFunc = decompResult.getDecompiledFunction();
                    if (decompiledFunc == null) {
                        decompilationResult.addProperty("error", "Could not get decompiled function");
                    } else {
                        String decompiledCode = decompiledFunc.getC();
                        if (decompiledCode != null) {
                            decompilationResult.addProperty("code", decompiledCode);
                        } else {
                            decompilationResult.addProperty("error", "Decompiled code is null");
                        }
                    }
                    
                    resultObj.add("decompilation", decompilationResult);
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Decompilation error for " + func.getName(), e);
            resultObj.addProperty("decompilation_error", "Exception during decompilation: " + e.getMessage());
        } finally {
            decomp.dispose();
        }

        response.addProperty("success", true);
        response.add("result", resultObj);
        response.addProperty("timestamp", System.currentTimeMillis());
        response.addProperty("port", this.port);
        return response;
    }

    private JsonObject decompileFunctionByName(String name) { // Changed return type
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded", 400);
        }
        
        DecompInterface decomp = new DecompInterface();
        try {
            if (!decomp.openProgram(program)) {
                 return createErrorResponse("Failed to initialize decompiler", 500);
            }
            
            Function func = findFunctionByName(program, name);
            if (func == null) {
                return createErrorResponse("Function not found: " + name, 404);
            }
            
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
            if (result != null && result.decompileCompleted()) {
                JsonObject resultObj = new JsonObject();
                resultObj.addProperty("name", func.getName());
                resultObj.addProperty("address", func.getEntryPoint().toString());
                resultObj.addProperty("signature", func.getSignature().getPrototypeString());
                resultObj.addProperty("decompilation", result.getDecompiledFunction().getC());
                
                // Use helper to create standard response
                return createSuccessResponse(resultObj); // Return JsonObject
            } else {
                return createErrorResponse("Decompilation failed", 500);
            }
        } finally {
            decomp.dispose();
        }
    }

    private boolean renameFunctionByAddress(Address functionAddress, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    Function func = program.getFunctionManager().getFunctionAt(functionAddress);
                    if (func != null) {
                        func.setName(newName, SourceType.USER_DEFINED);
                        successFlag.set(true);
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private boolean setDecompilerComment(Address address, String comment) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set decompiler comment");
                try {
                    DecompInterface decomp = new DecompInterface();
                    decomp.openProgram(program);
                    
                    Function func = program.getFunctionManager().getFunctionContaining(address);
                    if (func != null) {
                        DecompileResults results = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                        if (results != null && results.decompileCompleted()) {
                            HighFunction highFunc = results.getHighFunction();
                            if (highFunc != null) {
                                program.getListing().setComment(address, CodeUnit.PRE_COMMENT, comment);
                                successFlag.set(true);
                            }
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error setting decompiler comment", e);
                }
                finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set comment on Swing thread", e);
        }
        return successFlag.get();
    }

    private boolean setDisassemblyComment(Address address, String comment) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set disassembly comment");
                try {
                    Listing listing = program.getListing();
                    listing.setComment(address, CodeUnit.EOL_COMMENT, comment);
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Error setting disassembly comment", e);
                }
                finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set comment on Swing thread", e);
        }
        return successFlag.get();
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private boolean renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
        return successFlag.get();
    }
    
    // ----------------------------------------------------------------------------------
    // New variable handling methods
    // ----------------------------------------------------------------------------------
    
    private JsonObject listVariablesInFunction(String functionName) { // Changed return type
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded", 400);
        }

        DecompInterface decomp = new DecompInterface();
        try {
            if (!decomp.openProgram(program)) {
                return createErrorResponse("Failed to initialize decompiler", 500);
            }
            
            Function function = findFunctionByName(program, functionName);
            if (function == null) {
                return createErrorResponse("Function not found: " + functionName, 404);
            }
            
            DecompileResults results = decomp.decompileFunction(function, 30, new ConsoleTaskMonitor());
            if (results == null || !results.decompileCompleted()) {
                return createErrorResponse("Failed to decompile function: " + functionName, 500);
            }

            // Get high-level pcode representation for the function
            HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                return createErrorResponse("Failed to get high function for: " + functionName, 500);
            }
            
            // Get all variables (parameters and locals)
            List<Map<String, String>> allVariables = new ArrayList<>();
            
            // Process all symbols
            Iterator<HighSymbol> symbolIter = highFunction.getLocalSymbolMap().getSymbols();
            while (symbolIter.hasNext()) {
                HighSymbol symbol = symbolIter.next();
                
                Map<String, String> varInfo = new HashMap<>();
                varInfo.put("name", symbol.getName());
                
                DataType dt = symbol.getDataType();
                String dtName = dt != null ? dt.getName() : "unknown";
                varInfo.put("dataType", dtName);
                
                if (symbol.isParameter()) {
                    varInfo.put("type", "parameter");
                } else if (symbol.getHighVariable() != null) {
                    varInfo.put("type", "local");
                    varInfo.put("address", symbol.getPCAddress().toString());
                } else {
                    continue; // Skip symbols without high variables that aren't parameters
                }
                
                allVariables.add(varInfo);
            }
            
            // Sort by name
            Collections.sort(allVariables, (a, b) -> a.get("name").compareTo(b.get("name")));
            
            // Create JSON response
            JsonObject response = new JsonObject();
            response.addProperty("success", true);
            
            JsonObject resultObj = new JsonObject();
            resultObj.addProperty("function", functionName);
            resultObj.add("variables", new Gson().toJsonTree(allVariables));
            
            // Use helper to create standard response
            return createSuccessResponse(resultObj); // Return JsonObject
        } finally {
            decomp.dispose();
        }
    }
    
    private boolean renameVariable(String functionName, String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return false;
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return false;
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return false;
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return false;
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();
            
            if (symbolName.equals(oldName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newName)) {
                return false;
            }
        }

        if (highSymbol == null) {
            return false;
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {           
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
            return false;
        }
        return successFlag.get();
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
     * Compare the given HighFunction's idea of the prototype with the Function's idea.
     * Return true if there is a difference. If a specific symbol is being changed,
     * it can be passed in to check whether or not the prototype is being affected.
     * @param highSymbol (if not null) is the symbol being modified
     * @param hfunction is the given HighFunction
     * @return true if there is a difference (and a full commit is required)
     */
    protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
        if (highSymbol != null && !highSymbol.isParameter()) {
            return false;
        }
        Function function = hfunction.getFunction();
        Parameter[] parameters = function.getParameters();
        LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
        int numParams = localSymbolMap.getNumParams();
        if (numParams != parameters.length) {
            return true;
        }

        for (int i = 0; i < numParams; i++) {
            HighSymbol param = localSymbolMap.getParamSymbol(i);
            if (param.getCategoryIndex() != i) {
                return true;
            }
            VariableStorage storage = param.getStorage();
            // Don't compare using the equals method so that DynamicVariableStorage can match
            if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
                return true;
            }
        }

        return false;
    }
    
    private boolean retypeVariable(String functionName, String varName, String dataTypeName) {
        if (varName == null || varName.isEmpty() || dataTypeName == null || dataTypeName.isEmpty()) {
            return false;
        }
        
        Program program = getCurrentProgram();
        if (program == null) return false;
        
        AtomicBoolean result = new AtomicBoolean(false);
        
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Retype variable via HTTP");
                try {
                    Function function = findFunctionByName(program, functionName);
                    if (function == null) {
                        return;
                    }
                    
                    // Initialize decompiler
                    DecompInterface decomp = new DecompInterface();
                    decomp.openProgram(program);
                    DecompileResults decompRes = decomp.decompileFunction(function, 30, new ConsoleTaskMonitor());
                    
                    if (decompRes == null || !decompRes.decompileCompleted()) {
                        return;
                    }
                    
                    HighFunction highFunction = decompRes.getHighFunction();
                    if (highFunction == null) {
                        return;
                    }
                    
                    // Find the variable by name - must match exactly and be in current scope
                    HighSymbol targetSymbol = null;
                    Iterator<HighSymbol> symbolIter = highFunction.getLocalSymbolMap().getSymbols();
                    while (symbolIter.hasNext()) {
                        HighSymbol symbol = symbolIter.next();
                        if (symbol.getName().equals(varName) && 
                            symbol.getPCAddress().equals(function.getEntryPoint())) {
                            targetSymbol = symbol;
                            break;
                        }
                    }
                    
                    if (targetSymbol == null) {
                        return;
                    }
                    
                    // Find the data type by name
                    DataType dataType = findDataType(program, dataTypeName);
                    if (dataType == null) {
                        return;
                    }
                    
                    // Retype the variable
                    HighFunctionDBUtil.updateDBVariable(targetSymbol, targetSymbol.getName(), dataType, 
                                                      SourceType.USER_DEFINED);
                    
                    result.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error retyping variable", e);
                    result.set(false);
                } finally {
                    program.endTransaction(tx, true);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute on Swing thread", e);
            result.set(false);
        }
        
        return result.get();
    }
    
    private JsonObject listVariables(int offset, int limit, String searchTerm) {
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded", 400);
        }
        
        List<Map<String, String>> variables = new ArrayList<>();
        
        // Get global variables
        SymbolTable symbolTable = program.getSymbolTable();
        for (Symbol symbol : symbolTable.getDefinedSymbols()) {
            if (symbol.isGlobal() && !symbol.isExternal() &&
                symbol.getSymbolType() != SymbolType.FUNCTION &&
                symbol.getSymbolType() != SymbolType.LABEL) {
                    
                Map<String, String> varInfo = new HashMap<>();
                varInfo.put("name", symbol.getName());
                varInfo.put("address", symbol.getAddress().toString());
                varInfo.put("type", "global");
                varInfo.put("dataType", getDataTypeName(program, symbol.getAddress()));
                variables.add(varInfo);
            }
        }
        
        // Get local variables from all functions
        DecompInterface decomp = null; // Initialize outside try
        try {
            decomp = new DecompInterface(); // Create inside try
            if (!decomp.openProgram(program)) {
                 Msg.error(this, "listVariables: Failed to open program with decompiler.");
                 // Continue with only global variables if decompiler fails to open
            } else {
                for (Function function : program.getFunctionManager().getFunctions(true)) {
                    try {
                        DecompileResults results = decomp.decompileFunction(function, 30, new ConsoleTaskMonitor());
                        if (results != null && results.decompileCompleted()) {
                            HighFunction highFunc = results.getHighFunction();
                            if (highFunc != null) {
                                Iterator<HighSymbol> symbolIter = highFunc.getLocalSymbolMap().getSymbols();
                                while (symbolIter.hasNext()) {
                                    HighSymbol symbol = symbolIter.next();
                                    if (!symbol.isParameter()) { // Only list locals, not params
                                        Map<String, String> varInfo = new HashMap<>();
                                        varInfo.put("name", symbol.getName());
                                        varInfo.put("type", "local");
                                        varInfo.put("function", function.getName());
                                        // Handle null PC address for some local variables
                                        Address pcAddr = symbol.getPCAddress();
                                        varInfo.put("address", pcAddr != null ? pcAddr.toString() : "N/A"); 
                                        varInfo.put("dataType", symbol.getDataType() != null ? symbol.getDataType().getName() : "unknown");
                                        variables.add(varInfo);
                                    }
                                }
                            } else {
                                 Msg.warn(this, "listVariables: Failed to get HighFunction for " + function.getName());
                            }
                        } else {
                             Msg.warn(this, "listVariables: Decompilation failed or timed out for " + function.getName());
                        }
                    } catch (Exception e) {
                        Msg.error(this, "listVariables: Error processing function " + function.getName(), e);
                        // Continue to the next function if one fails
                    }
                }
            }
        } catch (Exception e) {
             Msg.error(this, "listVariables: Error during local variable processing", e);
             // If a major error occurs, we might still have global variables
        } finally {
            if (decomp != null) {
                decomp.dispose(); // Ensure disposal
            }
        }
        
        // Sort by name
        Collections.sort(variables, (a, b) -> a.get("name").compareTo(b.get("name")));
        
        // Apply pagination
        int start = Math.max(0, offset);
        int end = Math.min(variables.size(), offset + limit);
        List<Map<String, String>> paginated = variables.subList(start, end);
        
        // Create JSON response
        // Use helper to create standard response
        return createSuccessResponse(paginated);
    }
    
    private JsonObject searchVariables(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded", 400);
        }
        
        if (searchTerm == null || searchTerm.isEmpty()) {
            return createErrorResponse("Search term is required", 400);
        }
        
        List<Map<String, String>> matchedVars = new ArrayList<>();
        
        // Search global variables
        SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator it = symbolTable.getSymbolIterator();
        while (it.hasNext()) {
            Symbol symbol = it.next();
            if (symbol.isGlobal() && 
                symbol.getSymbolType() != SymbolType.FUNCTION && 
                symbol.getSymbolType() != SymbolType.LABEL && 
                symbol.getName().toLowerCase().contains(searchTerm.toLowerCase())) {
                Map<String, String> varInfo = new HashMap<>();
                varInfo.put("name", symbol.getName());
                varInfo.put("address", symbol.getAddress().toString());
                varInfo.put("type", "global");
                matchedVars.add(varInfo);
            }
        }
        
        // Search local variables in functions
        DecompInterface decomp = new DecompInterface();
        try {
            if (decomp.openProgram(program)) {
                for (Function function : program.getFunctionManager().getFunctions(true)) {
                    DecompileResults results = decomp.decompileFunction(function, 30, new ConsoleTaskMonitor());
                    if (results != null && results.decompileCompleted()) {
                        HighFunction highFunc = results.getHighFunction();
                        if (highFunc != null) {
                            // Check each local variable and parameter
                            Iterator<HighSymbol> symbolIter = highFunc.getLocalSymbolMap().getSymbols();
                            while (symbolIter.hasNext()) {
                                HighSymbol symbol = symbolIter.next();
                                if (symbol.getName().toLowerCase().contains(searchTerm.toLowerCase())) {
                                    Map<String, String> varInfo = new HashMap<>();
                                    varInfo.put("name", symbol.getName());
                                    varInfo.put("function", function.getName());
                                    
                                    if (symbol.isParameter()) {
                                        varInfo.put("type", "parameter");
                                    } else {
                                        varInfo.put("type", "local");
                                        varInfo.put("address", symbol.getPCAddress().toString());
                                    }
                                    
                                    matchedVars.add(varInfo);
                                }
                            }
                        }
                    }
                }
            }
        } finally {
            decomp.dispose();
        }
        
        // Sort by name
        Collections.sort(matchedVars, (a, b) -> a.get("name").compareTo(b.get("name")));
        
        // Apply pagination
        int start = Math.max(0, offset);
        int end = Math.min(matchedVars.size(), offset + limit);
        List<Map<String, String>> paginated = matchedVars.subList(start, end);
        
        // Create JSON response
        // Use helper to create standard response
        return createSuccessResponse(paginated);
    }
    
    // ----------------------------------------------------------------------------------
    // Standardized JSON Response Helpers (Following GHIDRA_HTTP_API.md v1)
    // ----------------------------------------------------------------------------------

    /**
     * Creates the base structure for all JSON responses.
     * Includes the request ID and instance URL.
     * @param exchange The HTTP exchange to extract headers from.
     * @return A JsonObject with 'id' and 'instance' fields.
     */
    /**
     * Builder for standardized API responses
     */
    private static class ResponseBuilder {
        private final HttpExchange exchange;
        private final int port;
        private JsonObject response;
        private JsonObject links;
        
        public ResponseBuilder(HttpExchange exchange, int port) {
            this.exchange = exchange;
            this.port = port;
            this.response = new JsonObject();
            this.links = new JsonObject();
            
            String requestId = exchange.getRequestHeaders().getFirst("X-Request-ID");
            response.addProperty("id", requestId != null ? requestId : UUID.randomUUID().toString());
            response.addProperty("instance", "http://localhost:" + port);
        }
        
        public ResponseBuilder success(boolean success) {
            response.addProperty("success", success);
            return this;
        }
        
        public ResponseBuilder result(Object data) {
            Gson gson = new Gson();
            response.add("result", gson.toJsonTree(data));
            return this;
        }
        
        public ResponseBuilder error(String message, String code) {
            JsonObject error = new JsonObject();
            error.addProperty("message", message);
            if (code != null) {
                error.addProperty("code", code);
            }
            response.add("error", error);
            return this;
        }
        
        public ResponseBuilder addLink(String rel, String href) {
            JsonObject link = new JsonObject();
            link.addProperty("href", href);
            links.add(rel, link);
            return this;
        }
        
        public JsonObject build() {
            if (links.size() > 0) {
                response.add("_links", links);
            }
            return response;
        }
    }
    
    private JsonObject createBaseResponse(HttpExchange exchange) {
        return new ResponseBuilder(exchange, port).build();
    }

    private JsonObject createSuccessResponse(HttpExchange exchange, Object resultData, JsonObject links) {
        ResponseBuilder builder = new ResponseBuilder(exchange, port)
            .success(true)
            .result(resultData);
            
        if (links != null) {
            builder.links = links;
        }
        return builder.build();
    }

    private JsonObject createErrorResponse(HttpExchange exchange, String message, String errorCode) {
        return new ResponseBuilder(exchange, port)
            .success(false)
            .error(message, errorCode)
            .build();
    }
    
    // Overload for simple success with no data and no links
    private JsonObject createSuccessResponse(HttpExchange exchange) {
        return createSuccessResponse(exchange, null, null);
    }

    /**
     * Creates a standardized error response JSON object.
     * @param exchange The HTTP exchange.
     * @param message A descriptive error message.
     * @param errorCode An optional machine-readable error code string.
     * @return A JsonObject representing the error response.
     */
    private JsonObject createErrorResponse(HttpExchange exchange, String message, String errorCode) {
        JsonObject response = createBaseResponse(exchange);
        response.addProperty("success", false);
        JsonObject errorObj = new JsonObject();
        errorObj.addProperty("message", message != null ? message : "An unknown error occurred.");
        if (errorCode != null && !errorCode.isEmpty()) {
            errorObj.addProperty("code", errorCode);
        }
        response.add("error", errorObj);
        return response;
    }
    
    // Overload for error with just message
    private JsonObject createErrorResponse(HttpExchange exchange, String message) {
        return createErrorResponse(exchange, message, null);
    }

    // --- Deprecated Helpers (Marked for removal) ---
    // These are kept temporarily only if absolutely needed during refactoring, 
    // but the goal is to replace all their usages with the new helpers above.
    @Deprecated
    private JsonObject createSuccessResponse(Object resultData) {
        JsonObject response = new JsonObject();
        response.addProperty("success", true);
        if (resultData != null) {
             response.add("result", new Gson().toJsonTree(resultData));
        } else {
             response.add("result", null);
        }
        response.addProperty("timestamp", System.currentTimeMillis()); // Deprecated field
        response.addProperty("port", this.port); // Deprecated field
        return response;
    }

    @Deprecated
    private JsonObject createErrorResponse(String errorMessage, int statusCode) {
        JsonObject response = new JsonObject();
        response.addProperty("success", false);
        response.addProperty("error", errorMessage); // Deprecated structure
        response.addProperty("status_code", statusCode); // Deprecated field
        response.addProperty("timestamp", System.currentTimeMillis()); // Deprecated field
        response.addProperty("port", this.port); // Deprecated field
        return response;
    }
    // --- End Deprecated Helpers ---

    // ----------------------------------------------------------------------------------
    // Transaction Management Helper
    // ----------------------------------------------------------------------------------

    /**
     * Executes a Ghidra operation that modifies the program state within a transaction.
     * Handles Swing thread invocation and ensures the transaction is properly managed.
     * 
     * @param <T> The return type of the operation (can be Void for operations without return value).
     * @param program The program context for the transaction. Must not be null.
     * @param transactionName A descriptive name for the Ghidra transaction log.
     * @param operation A supplier function (using GhidraSupplier functional interface) 
     *                  that performs the Ghidra API calls and returns a result.
     *                  This function MUST NOT start or end its own transaction.
     * @return The result of the operation.
     * @throws TransactionException If the operation fails within the transaction or 
     *                              if execution on the Swing thread fails. Wraps the original cause.
     * @throws IllegalArgumentException If program is null.
     */
    private <T> T executeInTransaction(Program program, String transactionName, GhidraSupplier<T> operation) throws TransactionException {
        if (program == null) {
            throw new IllegalArgumentException("Program cannot be null for transaction");
        }

        final class ResultContainer {
            T value = null;
            Exception exception = null;
        }
        final ResultContainer resultContainer = new ResultContainer();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = -1; 
                boolean success = false;
                try {
                    txId = program.startTransaction(transactionName);
                    if (txId < 0) {
                         throw new TransactionException("Failed to start transaction: " + transactionName + ". Already in a transaction?");
                    }
                    resultContainer.value = operation.get(); 
                    success = true; 
                } catch (Exception e) {
                    Msg.error(this, "Exception during transaction: " + transactionName, e);
                    resultContainer.exception = e; 
                    success = false; 
                } finally {
                    if (txId >= 0) { 
                         program.endTransaction(txId, success);
                         Msg.debug(this, "Transaction '" + transactionName + "' ended. Success: " + success);
                    }
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute transaction '" + transactionName + "' on Swing thread", e);
            throw new TransactionException("Failed to execute operation on Swing thread", e);
        }

        if (resultContainer.exception != null) {
            throw new TransactionException("Operation failed within transaction: " + transactionName, resultContainer.exception);
        }

        return resultContainer.value;
    }
    
    /**
     * Overload of executeInTransaction for operations that don't return a value (Runnable).
     * @param program The program context for the transaction.
     * @param transactionName The name for the Ghidra transaction log.
     * @param operation A Runnable that performs the Ghidra API calls.
     * @throws TransactionException If the operation fails.
     */
    private void executeInTransaction(Program program, String transactionName, Runnable operation) throws TransactionException {
         executeInTransaction(program, transactionName, () -> {
             operation.run();
             return null; 
         });
    }

    /** Custom exception for transaction-related errors. */
    public static class TransactionException extends Exception {
        public TransactionException(String message) { super(message); }
        public TransactionException(String message, Throwable cause) { super(message, cause); }
    }

    // ----------------------------------------------------------------------------------
    // HTTP Response Sending Methods
    // ----------------------------------------------------------------------------------

    /**
     * Sends a standard success JSON response with a 200 OK status.
     * @param exchange The HTTP exchange.
     * @param resultData The data payload for the 'result' field (can be null).
     * @param links Optional HATEOAS links.
     * @throws IOException If sending the response fails.
     */
    private void sendSuccessResponse(HttpExchange exchange, Object resultData, JsonObject links) throws IOException {
        sendJsonResponse(exchange, createSuccessResponse(exchange, resultData, links), 200);
    }
    
    // Overload for success with data, no links
    private void sendSuccessResponse(HttpExchange exchange, Object resultData) throws IOException {
        sendSuccessResponse(exchange, resultData, null);
    }
    
    // Overload for simple success, no data, no links (e.g., for 204 No Content)
    private void sendSuccessResponse(HttpExchange exchange) throws IOException {
        sendSuccessResponse(exchange, null, null);
    }

    /**
     * Sends a standard error JSON response with the specified HTTP status code.
     * @param exchange The HTTP exchange.
     * @param statusCode The HTTP status code (e.g., 400, 404, 500).
     * @param message A descriptive error message.
     * @param errorCode An optional machine-readable error code string.
     * @throws IOException If sending the response fails.
     */
    private void sendErrorResponse(HttpExchange exchange, int statusCode, String message, String errorCode) throws IOException {
        sendJsonResponse(exchange, createErrorResponse(exchange, message, errorCode), statusCode);
    }
    
    // Overload for error without specific code
    private void sendErrorResponse(HttpExchange exchange, int statusCode, String message) throws IOException {
        sendErrorResponse(exchange, statusCode, message, null);
    }

    /**
     * Core method to send any JsonObject response with a specific status code.
     * Handles JSON serialization, setting headers, and writing the response body.
     * @param exchange The HTTP exchange.
     * @param jsonObj The JsonObject to send.
     * @param statusCode The HTTP status code to set.
     * @throws IOException If sending the response fails.
     */
    private void sendJsonResponse(HttpExchange exchange, JsonObject jsonObj, int statusCode) throws IOException {
         try {
            Gson gson = new Gson();
            String json = gson.toJson(jsonObj);
            if (json.length() < 1024) {
                 Msg.debug(this, "Sending JSON response (Status " + statusCode + "): " + json);
            } else {
                 Msg.debug(this, "Sending JSON response (Status " + statusCode + "): " + json.substring(0, 1020) + "...");
            }

            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            
            long responseLength = (statusCode == 204) ? -1 : bytes.length; 
            exchange.sendResponseHeaders(statusCode, responseLength); 
            
            if (responseLength != -1) {
                OutputStream os = null;
                try {
                    os = exchange.getResponseBody();
                    os.write(bytes);
                    os.flush();
                } catch (IOException e) {
                    Msg.error(this, "Error writing response body: " + e.getMessage(), e);
                    throw e; 
                } finally {
                    if (os != null) {
                        try { os.close(); } catch (IOException e) { /* Log or ignore */ }
                    }
                }
            } else {
                 exchange.getResponseBody().close();
            }
        } catch (Exception e) {
            Msg.error(this, "Error sending JSON response: " + e.getMessage(), e);
            throw new IOException("Failed to send JSON response", e);
        }
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Executes a Ghidra operation that modifies the program state within a transaction.
     * Handles Swing thread invocation and ensures the transaction is properly managed.
     * 
     * @param <T> The return type of the operation (can be Void for operations without return value).
     * @param program The program context for the transaction. Must not be null.
     * @param transactionName A descriptive name for the Ghidra transaction log.
     * @param operation A supplier function (using GhidraSupplier functional interface) 
     *                  that performs the Ghidra API calls and returns a result.
     *                  This function MUST NOT start or end its own transaction.
     * @return The result of the operation.
     * @throws TransactionException If the operation fails within the transaction or 
     *                              if execution on the Swing thread fails. Wraps the original cause.
     * @throws IllegalArgumentException If program is null.
     */
    private <T> T executeInTransaction(Program program, String transactionName, GhidraSupplier<T> operation) throws TransactionException {
        if (program == null) {
            throw new IllegalArgumentException("Program cannot be null for transaction");
        }

        // Use a simple container to pass results/exceptions back from the Swing thread
        final class ResultContainer {
            T value = null;
            Exception exception = null;
        }
        final ResultContainer resultContainer = new ResultContainer();

        try {
            // Ensure the operation runs on the Swing Event Dispatch Thread (EDT)
            // as required by many Ghidra API calls that modify state.
            SwingUtilities.invokeAndWait(() -> {
                int txId = -1; // Initialize transaction ID
                boolean success = false;
                try {
                    txId = program.startTransaction(transactionName);
                    if (txId < 0) {
                         // Handle case where transaction could not be started (e.g., already in transaction)
                         // This ideally shouldn't happen if called correctly, but good to check.
                         throw new TransactionException("Failed to start transaction: " + transactionName + ". Already in a transaction?");
                    }
                    resultContainer.value = operation.get(); // Execute the actual Ghidra operation
                    success = true; // Mark as success if no exception was thrown
                } catch (Exception e) {
                    // Catch any exception from the operation
                    Msg.error(this, "Exception during transaction: " + transactionName, e);
                    resultContainer.exception = e; // Store the exception
                    success = false; // Ensure transaction is rolled back
                } finally {
                    // Always end the transaction, committing only if success is true
                    if (txId >= 0) { // Only end if successfully started
                         program.endTransaction(txId, success);
                         Msg.debug(this, "Transaction '" + transactionName + "' ended. Success: " + success);
                    }
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            // Handle exceptions related to SwingUtilities.invokeAndWait
            Msg.error(this, "Failed to execute transaction '" + transactionName + "' on Swing thread", e);
            // Wrap this error in our custom exception type
            throw new TransactionException("Failed to execute operation on Swing thread", e);
        }

        // Check if an exception occurred within the Ghidra operation itself
        if (resultContainer.exception != null) {
            // Wrap the original Ghidra operation exception
            throw new TransactionException("Operation failed within transaction: " + transactionName, resultContainer.exception);
        }

        // Return the result from the operation
        return resultContainer.value;
    }
    
    /**
     * Overload of executeInTransaction for operations that don't return a value (Runnable).
     * 
     * @param program The program context for the transaction.
     * @param transactionName The name for the Ghidra transaction log.
     * @param operation A Runnable that performs the Ghidra API calls.
     * @throws TransactionException If the operation fails.
     */
    private void executeInTransaction(Program program, String transactionName, Runnable operation) throws TransactionException {
         // Wrap the Runnable in a GhidraSupplier that returns Void
         executeInTransaction(program, transactionName, () -> {
             operation.run();
             return null; // Return null for void operations
         });
    }

    /**
     * Custom exception for transaction-related errors.
     */
    public static class TransactionException extends Exception {
        public TransactionException(String message) {
            super(message);
        }

        public TransactionException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    // ----------------------------------------------------------------------------------
    // HTTP Response Sending Methods
    // ----------------------------------------------------------------------------------

    /**
     * Sends a standard success JSON response with a 200 OK status.
     * @param exchange The HTTP exchange.
     * @param resultData The data payload for the 'result' field (can be null).
     * @param links Optional HATEOAS links.
     * @throws IOException If sending the response fails.
     */
    private void sendSuccessResponse(HttpExchange exchange, Object resultData, JsonObject links) throws IOException {
        sendJsonResponse(exchange, createSuccessResponse(exchange, resultData, links), 200);
    }
    
    // Overload for success with data, no links
    private void sendSuccessResponse(HttpExchange exchange, Object resultData) throws IOException {
        sendSuccessResponse(exchange, resultData, null);
    }
    
    // Overload for simple success, no data, no links (e.g., for 204 No Content)
    private void sendSuccessResponse(HttpExchange exchange) throws IOException {
        sendSuccessResponse(exchange, null, null);
    }

    /**
     * Sends a standard error JSON response with the specified HTTP status code.
     * @param exchange The HTTP exchange.
     * @param statusCode The HTTP status code (e.g., 400, 404, 500).
     * @param message A descriptive error message.
     * @param errorCode An optional machine-readable error code string.
     * @throws IOException If sending the response fails.
     */
    private void sendErrorResponse(HttpExchange exchange, int statusCode, String message, String errorCode) throws IOException {
        sendJsonResponse(exchange, createErrorResponse(exchange, message, errorCode), statusCode);
    }
    
    // Overload for error without specific code
    private void sendErrorResponse(HttpExchange exchange, int statusCode, String message) throws IOException {
        sendErrorResponse(exchange, statusCode, message, null);
    }

    /**
     * Core method to send any JsonObject response with a specific status code.
     * Handles JSON serialization, setting headers, and writing the response body.
     * @param exchange The HTTP exchange.
     * @param jsonObj The JsonObject to send.
     * @param statusCode The HTTP status code to set.
     * @throws IOException If sending the response fails.
     */
    private void sendJsonResponse(HttpExchange exchange, JsonObject jsonObj, int statusCode) throws IOException {
         try {
            Gson gson = new Gson();
            String json = gson.toJson(jsonObj);
            // Use Msg.debug for potentially large responses
            if (json.length() < 1024) {
                 Msg.debug(this, "Sending JSON response (Status " + statusCode + "): " + json);
            } else {
                 Msg.debug(this, "Sending JSON response (Status " + statusCode + "): " + json.substring(0, 1020) + "...");
            }

            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            // Ensure CORS headers are set if needed (example, adjust as necessary)
            // exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*"); 
            
            // Determine response length: 0 for 204, actual length otherwise
            long responseLength = (statusCode == 204) ? -1 : bytes.length; 
            exchange.sendResponseHeaders(statusCode, responseLength); 
            
            // Only write body if there is content (not for 204)
            if (responseLength != -1) {
                OutputStream os = null;
                try {
                    os = exchange.getResponseBody();
                    os.write(bytes);
                    os.flush();
                } catch (IOException e) {
                    // Log error, but don't try to send another response if body writing fails
                    Msg.error(this, "Error writing response body: " + e.getMessage(), e);
                    throw e; // Re-throw to indicate failure
                } finally {
                    if (os != null) {
                        try {
                            os.close();
                        } catch (IOException e) {
                            // Log error during close, but don't mask original exception if any
                            Msg.error(this, "Error closing output stream: " + e.getMessage(), e);
                        }
                    }
                }
            } else {
                 // For 204 No Content, just close the exchange without writing body
                 exchange.getResponseBody().close();
            }
        } catch (Exception e) {
            // Catch broader exceptions during response preparation/sending
            Msg.error(this, "Error sending JSON response: " + e.getMessage(), e);
            // Avoid sending another error response here to prevent potential loops
            throw new IOException("Failed to send JSON response", e);
        }
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    result.put(kv[0], kv[1]);
                }
            }
        }
        return result;
    }

    /**
     * Parse post body params strictly as JSON.
     */
    private Map<String, String> parseJsonPostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();

        try {
            // Use Gson to properly parse JSON
            Gson gson = new Gson();
            JsonObject json = gson.fromJson(bodyStr, JsonObject.class);

            for (Map.Entry<String, JsonElement> entry : json.entrySet()) {
                String key = entry.getKey();
                JsonElement value = entry.getValue();

                if (value.isJsonPrimitive()) {
                    params.put(key, value.getAsString());
                } else {
                    // Optionally handle non-primitive types if needed, otherwise stringify
                    params.put(key, value.toString());
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Failed to parse JSON request body: " + e.getMessage(), e);
            // Throw an exception or return an empty map to indicate failure
            throw new IOException("Invalid JSON request body: " + e.getMessage(), e);
        }
        return params;
    }



    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Get the current program from the tool
     */
    public Program getCurrentProgram() {
        if (tool == null) {
            Msg.debug(this, "Tool is null when trying to get current program");
            return null;
        }

        try {
            ProgramManager pm = tool.getService(ProgramManager.class);
            if (pm == null) {
                Msg.debug(this, "ProgramManager service is not available");
                return null;
            }
            
            Program program = pm.getCurrentProgram();
            Msg.debug(this, "Got current program: " + (program != null ? program.getName() : "null"));
            return program;
        } 
        catch (Exception e) {
            Msg.error(this, "Error getting current program", e);
            return null;
        }
    }
    
        // Get the currently selected address in Ghidra's UI
        private Address getCurrentAddress() {
            try {
                Program program = getCurrentProgram();
                if (program == null) {
                    return null;
                }
                
                // Return the minimum address as a fallback
                return program.getMinAddress();
            } catch (Exception e) {
                Msg.error(this, "Error getting current address", e);
                return null;
            }
        }

        // Get the currently selected function in Ghidra's UI
        private Function getCurrentFunction() {
            try {
                Program program = getCurrentProgram();
                if (program == null) {
                    return null;
                }
                
                // Return the first function as a fallback
                Iterator<Function> functions = program.getFunctionManager().getFunctions(true);
                return functions.hasNext() ? functions.next() : null;
            } catch (Exception e) {
                Msg.error(this, "Error getting current function", e);
                return null;
            }
        }

    // Removed old sendResponse method

    // private void sendJsonResponse(HttpExchange exchange, JsonObject jsonObj) throws IOException { ... } // Keep the core sender

    // ----------------------------------------------------------------------------------
    // HTTP Response Sending Methods
    // ----------------------------------------------------------------------------------

    /**
     * Sends a standard success JSON response with a 200 OK status.
     * @param exchange The HTTP exchange.
     * @param resultData The data payload for the 'result' field (can be null).
     * @param links Optional HATEOAS links.
     * @throws IOException If sending the response fails.
     */
    private void sendSuccessResponse(HttpExchange exchange, Object resultData, JsonObject links) throws IOException {
        sendJsonResponse(exchange, createSuccessResponse(exchange, resultData, links), 200);
    }
    
    // Overload for success with data, no links
    private void sendSuccessResponse(HttpExchange exchange, Object resultData) throws IOException {
        sendSuccessResponse(exchange, resultData, null);
    }
    
    // Overload for simple success, no data, no links
    private void sendSuccessResponse(HttpExchange exchange) throws IOException {
        sendSuccessResponse(exchange, null, null);
    }

    /**
     * Sends a standard error JSON response with the specified HTTP status code.
     * @param exchange The HTTP exchange.
     * @param statusCode The HTTP status code (e.g., 400, 404, 500).
     * @param message A descriptive error message.
     * @param errorCode An optional machine-readable error code string.
     * @throws IOException If sending the response fails.
     */
    private void sendErrorResponse(HttpExchange exchange, int statusCode, String message, String errorCode) throws IOException {
        sendJsonResponse(exchange, createErrorResponse(exchange, message, errorCode), statusCode);
    }
    
    // Overload for error without specific code
    private void sendErrorResponse(HttpExchange exchange, int statusCode, String message) throws IOException {
        sendErrorResponse(exchange, statusCode, message, null);
    }

    /**
     * Core method to send any JsonObject response with a specific status code.
     * Handles JSON serialization, setting headers, and writing the response body.
     * @param exchange The HTTP exchange.
     * @param jsonObj The JsonObject to send.
     * @param statusCode The HTTP status code to set.
     * @throws IOException If sending the response fails.
     */
    private void sendJsonResponse(HttpExchange exchange, JsonObject jsonObj, int statusCode) throws IOException {
         try {
            Gson gson = new Gson();
            String json = gson.toJson(jsonObj);
            // Use Msg.debug for potentially large responses
            if (json.length() < 1024) {
                 Msg.debug(this, "Sending JSON response (Status " + statusCode + "): " + json);
            } else {
                 Msg.debug(this, "Sending JSON response (Status " + statusCode + "): " + json.substring(0, 1020) + "...");
            }

            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            // Ensure CORS headers are set if needed (example, adjust as necessary)
            // exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*"); 
            exchange.sendResponseHeaders(statusCode, bytes.length); // Use provided status code
            
            OutputStream os = null;
            try {
                os = exchange.getResponseBody();
                os.write(bytes);
                os.flush();
            } catch (IOException e) {
                // Log error, but don't try to send another response if body writing fails
                Msg.error(this, "Error writing response body: " + e.getMessage(), e);
                throw e; // Re-throw to indicate failure
            } finally {
                if (os != null) {
                    try {
                        os.close();
                    } catch (IOException e) {
                        // Log error during close, but don't mask original exception if any
                        Msg.error(this, "Error closing output stream: " + e.getMessage(), e);
                    }
                }
            }
        } catch (Exception e) {
            // Catch broader exceptions during response preparation/sending
            Msg.error(this, "Error sending JSON response: " + e.getMessage(), e);
            // Avoid sending another error response here to prevent potential loops
            throw new IOException("Failed to send JSON response", e);
        }
    }
    

    private int findAvailablePort() {
        int basePort = 8192;
        int maxAttempts = 10;
        
        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            int candidate = basePort + attempt;
            if (!activeInstances.containsKey(candidate)) {
                try (ServerSocket s = new ServerSocket(candidate)) {
                    return candidate;
                } catch (IOException e) {
                    continue;
                }
            }
        }
        throw new RuntimeException("Could not find available port after " + maxAttempts + " attempts");
    }

    @Override
    public void dispose() {
        if (server != null) {
            server.stop(0);
            Msg.info(this, "HTTP server stopped on port " + port);
            System.out.println("[GhydraMCP] HTTP server stopped on port " + port);
        }
        activeInstances.remove(port);
        super.dispose();
    }
}
