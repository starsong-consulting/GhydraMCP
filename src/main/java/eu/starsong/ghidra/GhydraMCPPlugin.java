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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

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

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "GhydraMCP Plugin for AI Analysis",
    description = "Starts an embedded HTTP server to expose program data via REST API for AI-assisted reverse engineering with MCP (Model Context Protocol)."
)
public class GhydraMCPPlugin extends Plugin implements ApplicationLevelPlugin {

    private static final Map<Integer, GhydraMCPPlugin> activeInstances = new ConcurrentHashMap<>();
    private static final Object baseInstanceLock = new Object();
    
    private HttpServer server;
    private int port;
    private boolean isBaseInstance = false;

    public GhydraMCPPlugin(PluginTool tool) {
        super(tool);
        
        // Find available port
        this.port = findAvailablePort();
        activeInstances.put(port, this);
        
        // Check if we should be base instance
        synchronized (baseInstanceLock) {
            if (port == 8192 || activeInstances.get(8192) == null) {
                this.isBaseInstance = true;
                Msg.info(this, "Starting as base instance on port " + port);
            }
        }

        // Log to both console and log file
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

        // Each listing endpoint uses offset & limit from query params:
        // Function resources
        server.createContext("/functions", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                int offset = parseIntOrDefault(qparams.get("offset"), 0);
                int limit = parseIntOrDefault(qparams.get("limit"), 100);
                String query = qparams.get("query");
                
                if (query != null && !query.isEmpty()) {
                    sendResponse(exchange, searchFunctionsByName(query, offset, limit));
                } else {
                    sendResponse(exchange, getAllFunctionNames(offset, limit));
                }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        });

        server.createContext("/functions/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            
            // Handle sub-paths: /functions/{name}
            // or /functions/{name}/variables
            String[] pathParts = path.split("/");
            
            if (pathParts.length < 3) {
                exchange.sendResponseHeaders(400, -1); // Bad Request
                return;
            }
            
            String functionName = pathParts[2];
            try {
                functionName = java.net.URLDecoder.decode(functionName, StandardCharsets.UTF_8.name());
            } catch (Exception e) {
                Msg.error(this, "Failed to decode function name", e);
                exchange.sendResponseHeaders(400, -1); // Bad Request
                return;
            }
            
            // Check if we're dealing with a variables request
            if (pathParts.length > 3 && "variables".equals(pathParts[3])) {
                if ("GET".equals(exchange.getRequestMethod())) {
                    // List all variables in function
                    sendResponse(exchange, listVariablesInFunction(functionName));
                } else if ("POST".equals(exchange.getRequestMethod()) && pathParts.length > 4) { // Change PUT to POST
                    // Handle operations on a specific variable (using POST now)
                    String variableName = pathParts[4];
                    try {
                        variableName = java.net.URLDecoder.decode(variableName, StandardCharsets.UTF_8.name());
                    } catch (Exception e) {
                        Msg.error(this, "Failed to decode variable name", e);
                        exchange.sendResponseHeaders(400, -1);
                        return;
                    }
                    
                    Map<String, String> params = parseJsonPostParams(exchange); // Use specific JSON parser
                    if (params.containsKey("newName")) {
                        // Rename variable
                        boolean success = renameVariable(functionName, variableName, params.get("newName"));
                    JsonObject response = new JsonObject();
                    response.addProperty("success", success);
                    response.addProperty("message", success ? "Variable renamed successfully" : "Failed to rename variable");
                    response.addProperty("timestamp", System.currentTimeMillis());
                    response.addProperty("port", this.port);
                    
                    Gson gson = new Gson();
                    String json = gson.toJson(response);
                    byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
                    
                    exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                    exchange.getResponseHeaders().set("Content-Length", String.valueOf(bytes.length));
                    exchange.sendResponseHeaders(success ? 200 : 400, bytes.length);
                    
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(bytes);
                        os.flush();
                    }
                    } else if (params.containsKey("dataType")) { // Keep dataType for now, bridge uses it
                        // Retype variable
                        boolean success = retypeVariable(functionName, variableName, params.get("dataType"));
                    JsonObject response = new JsonObject();
                    response.addProperty("success", success);
                    response.addProperty("message", success ? "Variable retyped successfully" : "Failed to retype variable");
                    response.addProperty("timestamp", System.currentTimeMillis());
                    response.addProperty("port", this.port);
                    
                    Gson gson = new Gson();
                    String json = gson.toJson(response);
                    byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
                    
                    exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                    exchange.getResponseHeaders().set("Content-Length", String.valueOf(bytes.length));
                    exchange.sendResponseHeaders(success ? 200 : 400, bytes.length);
                    
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(bytes);
                        os.flush();
                    }
                    } else {
                        sendResponse(exchange, "Missing required parameter: newName or dataType");
                    }
                } else {
                    exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                }
            } else {
                // Simple function operations
                if ("GET".equals(exchange.getRequestMethod())) {
                    sendResponse(exchange, decompileFunctionByName(functionName));
                } else if ("POST".equals(exchange.getRequestMethod())) { // <--- Change to POST to match bridge
                    Map<String, String> params = parseJsonPostParams(exchange); // Use specific JSON parser
                    String newName = params.get("newName"); // Expect camelCase
                    boolean success = renameFunction(functionName, newName);
                    JsonObject response = new JsonObject();
                    response.addProperty("success", success);
                    response.addProperty("message", success ? "Renamed successfully" : "Rename failed");
                    response.addProperty("timestamp", System.currentTimeMillis());
                    response.addProperty("port", this.port);
                    
                    Gson gson = new Gson();
                    String json = gson.toJson(response);
                    byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
                    
                    exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                    exchange.getResponseHeaders().set("Content-Length", String.valueOf(bytes.length));
                    exchange.sendResponseHeaders(success ? 200 : 400, bytes.length);
                    
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(bytes);
                        os.flush();
                    }
                } else {
                    exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                }
            }
        });

        // Class resources
        server.createContext("/classes", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                try {
                    Map<String, String> qparams = parseQueryParams(exchange);
                    int offset = parseIntOrDefault(qparams.get("offset"), 0);
                    int limit = parseIntOrDefault(qparams.get("limit"), 100);
                    sendJsonResponse(exchange, getAllClassNames(offset, limit));
                } catch (Exception e) {
                    Msg.error(this, "/classes: Error in request processing", e);
                    try {
                        sendErrorResponse(exchange, 500, "Internal server error");
                    } catch (IOException ioe) {
                        Msg.error(this, "/classes: Failed to send error response", ioe);
                    }
                }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        });

        // Memory segments
        server.createContext("/segments", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                int offset = parseIntOrDefault(qparams.get("offset"), 0);
                int limit = parseIntOrDefault(qparams.get("limit"), 100);
                sendResponse(exchange, listSegments(offset, limit));
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        });

        // Symbol resources (imports/exports)
        server.createContext("/symbols/imports", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                int offset = parseIntOrDefault(qparams.get("offset"), 0);
                int limit = parseIntOrDefault(qparams.get("limit"), 100);
                sendResponse(exchange, listImports(offset, limit));
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        });

        server.createContext("/symbols/exports", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                int offset = parseIntOrDefault(qparams.get("offset"), 0);
                int limit = parseIntOrDefault(qparams.get("limit"), 100);
                sendResponse(exchange, listExports(offset, limit));
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        });

        // Namespace resources
        server.createContext("/namespaces", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                int offset = parseIntOrDefault(qparams.get("offset"), 0);
                int limit = parseIntOrDefault(qparams.get("limit"), 100);
                sendResponse(exchange, listNamespaces(offset, limit));
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        });

        // Data resources
        server.createContext("/data", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                int offset = parseIntOrDefault(qparams.get("offset"), 0);
                int limit = parseIntOrDefault(qparams.get("limit"), 100);
                sendResponse(exchange, listDefinedData(offset, limit));
            } else if ("POST".equals(exchange.getRequestMethod())) { // Change PUT to POST
                Map<String, String> params = parseJsonPostParams(exchange); // Use specific JSON parser
                boolean success = renameDataAtAddress(params.get("address"), params.get("newName")); // Expect camelCase
                    JsonObject response = new JsonObject();
                    response.addProperty("success", success);
                    response.addProperty("message", success ? "Data renamed successfully" : "Failed to rename data");
                    response.addProperty("timestamp", System.currentTimeMillis());
                    response.addProperty("port", this.port);
                    
                    Gson gson = new Gson();
                    String json = gson.toJson(response);
                    byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
                    
                    exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                    exchange.getResponseHeaders().set("Content-Length", String.valueOf(bytes.length));
                    exchange.sendResponseHeaders(success ? 200 : 400, bytes.length);
                    
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(bytes);
                        os.flush();
                    }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        });
        
        // Global variables endpoint
        server.createContext("/variables", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                int offset = parseIntOrDefault(qparams.get("offset"), 0);
                int limit = parseIntOrDefault(qparams.get("limit"), 100);
                String search = qparams.get("search");
                
                if (search != null && !search.isEmpty()) {
                    sendResponse(exchange, searchVariables(search, offset, limit));
                } else {
                    sendResponse(exchange, listGlobalVariables(offset, limit));
                }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        });

        // Instance management endpoints
        server.createContext("/instances", exchange -> {
            List<Map<String, String>> instances = new ArrayList<>();
            for (Map.Entry<Integer, GhydraMCPPlugin> entry : activeInstances.entrySet()) {
                Map<String, String> instance = new HashMap<>();
                instance.put("port", entry.getKey().toString());
                instance.put("type", entry.getValue().isBaseInstance ? "base" : "secondary");
                instances.add(instance);
            }
            
            Gson gson = new Gson();
            JsonObject response = new JsonObject();
            response.addProperty("success", true);
            response.add("result", gson.toJsonTree(instances));
            response.addProperty("timestamp", System.currentTimeMillis());
            response.addProperty("port", this.port);
            sendJsonResponse(exchange, response);
        });

        // Add decompile function by address endpoint
        server.createContext("/decompile_function", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                String address = qparams.get("address");
                
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
                    Address funcAddr = program.getAddressFactory().getAddress(address);
                    Function func = program.getFunctionManager().getFunctionAt(funcAddr);
                    if (func == null) {
                        sendErrorResponse(exchange, 404, "No function at address " + address);
                        return;
                    }
                    
                    DecompInterface decomp = new DecompInterface();
                    try {
                        if (!decomp.openProgram(program)) {
                            sendErrorResponse(exchange, 500, "Failed to initialize decompiler");
                            return;
                        }
                        
                        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                        if (result == null || !result.decompileCompleted()) {
                            sendErrorResponse(exchange, 500, "Decompilation failed");
                            return;
                        }
                        
                        JsonObject response = new JsonObject();
                        response.addProperty("success", true);
                        response.addProperty("result", result.getDecompiledFunction().getC());
                        response.addProperty("timestamp", System.currentTimeMillis());
                        response.addProperty("port", this.port);
                        sendJsonResponse(exchange, response);
                    } finally {
                        decomp.dispose();
                    }
                } catch (Exception e) {
                    Msg.error(this, "Error decompiling function", e);
                    sendErrorResponse(exchange, 500, "Error decompiling function: " + e.getMessage());
                }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
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
                    Address addr = program.getAddressFactory().getAddress(address);
                    boolean success = setDecompilerComment(addr, comment);
                    
                    JsonObject response = new JsonObject();
                    response.addProperty("success", success);
                    response.addProperty("message", success ? "Comment set successfully" : "Failed to set comment");
                    response.addProperty("timestamp", System.currentTimeMillis());
                    response.addProperty("port", this.port);
                    sendJsonResponse(exchange, response);
                } catch (Exception e) {
                    Msg.error(this, "Error setting decompiler comment", e);
                    sendErrorResponse(exchange, 500, "Error setting comment: " + e.getMessage());
                }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
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
                    Address addr = program.getAddressFactory().getAddress(address);
                    boolean success = setDisassemblyComment(addr, comment);
                    
                    JsonObject response = new JsonObject();
                    response.addProperty("success", success);
                    response.addProperty("message", success ? "Comment set successfully" : "Failed to set comment");
                    response.addProperty("timestamp", System.currentTimeMillis());
                    response.addProperty("port", this.port);
                    sendJsonResponse(exchange, response);
                } catch (Exception e) {
                    Msg.error(this, "Error setting disassembly comment", e);
                    sendErrorResponse(exchange, 500, "Error setting comment: " + e.getMessage());
                }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
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
                    Address funcAddr = program.getAddressFactory().getAddress(address);
                    boolean success = renameFunctionByAddress(funcAddr, newName);
                    
                    JsonObject response = new JsonObject();
                    response.addProperty("success", success);
                    response.addProperty("message", success ? "Function renamed successfully" : "Failed to rename function");
                    response.addProperty("timestamp", System.currentTimeMillis());
                    response.addProperty("port", this.port);
                    sendJsonResponse(exchange, response);
                } catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                    sendErrorResponse(exchange, 500, "Error renaming function: " + e.getMessage());
                }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
            // Removed duplicate else block here
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

                // Call the existing renameVariable logic (needs adjustment for address)
                // For now, just return success/failure based on parameters
                JsonObject response = new JsonObject();
                response.addProperty("success", true); // Placeholder
                response.addProperty("message", "Rename local variable (not fully implemented by address yet)");
                response.addProperty("timestamp", System.currentTimeMillis());
                response.addProperty("port", this.port);
                sendJsonResponse(exchange, response);

            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
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

                // Call logic to set prototype (needs implementation)
                JsonObject response = new JsonObject();
                response.addProperty("success", true); // Placeholder
                response.addProperty("message", "Set function prototype (not fully implemented yet)");
                response.addProperty("timestamp", System.currentTimeMillis());
                response.addProperty("port", this.port);
                sendJsonResponse(exchange, response);

            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
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

                // Call logic to set variable type (needs implementation)
                 JsonObject response = new JsonObject();
                response.addProperty("success", true); // Placeholder
                response.addProperty("message", "Set local variable type (not fully implemented yet)");
                response.addProperty("timestamp", System.currentTimeMillis());
                response.addProperty("port", this.port);
                sendJsonResponse(exchange, response);

            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        });


        // Super simple info endpoint with guaranteed response
        server.createContext("/info", exchange -> {
            try {
                String response = "{\n";
                response += "\"port\": " + port + ",\n";
                response += "\"isBaseInstance\": " + isBaseInstance + ",\n";
                
                // Try to get program info if available
                Program program = getCurrentProgram();
                String programName = "\"\"";
                if (program != null) {
                    programName = "\"" + program.getName() + "\"";
                }
                
                // Try to get project info if available
                Project project = tool.getProject();
                String projectName = "\"\"";
                if (project != null) {
                    projectName = "\"" + project.getName() + "\"";
                }
                
                response += "\"project\": " + projectName + ",\n";
                response += "\"file\": " + programName + "\n";
                response += "}";
                
                Msg.info(this, "Sending /info response: " + response);
                byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
            } catch (Exception e) {
                Msg.error(this, "Error serving /info endpoint", e);
                try {
                    String error = "{\"error\": \"Internal error\", \"port\": " + port + "}";
                    byte[] bytes = error.getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                    // For mutation operations, set Content-Length explicitly to avoid chunked encoding
                    exchange.getResponseHeaders().set("Content-Length", String.valueOf(bytes.length));
                    exchange.sendResponseHeaders(200, bytes.length);
                    OutputStream os = exchange.getResponseBody();
                    os.write(bytes);
                    os.close();
                } catch (IOException ioe) {
                    Msg.error(this, "Failed to send error response", ioe);
                }
            }
        });
        
        // Root endpoint - only handle exact "/" path
        server.createContext("/", exchange -> {
            // Only handle exact root path
            if (!exchange.getRequestURI().getPath().equals("/")) {
                // Return 404 for any other path that reaches this handler
                Msg.info(this, "Received request for unknown path: " + exchange.getRequestURI().getPath());
                sendErrorResponse(exchange, 404, "Endpoint not found");
                return;
            }
            
            try {
                String response = "{\n";
                response += "\"port\": " + port + ",\n";
                response += "\"isBaseInstance\": " + isBaseInstance + ",\n";
                
                // Try to get program info if available
                Program program = getCurrentProgram();
                String programName = "\"\"";
                if (program != null) {
                    programName = "\"" + program.getName() + "\"";
                }
                
                // Try to get project info if available
                Project project = tool.getProject();
                String projectName = "\"\"";
                if (project != null) {
                    projectName = "\"" + project.getName() + "\"";
                }
                
                response += "\"project\": " + projectName + ",\n";
                response += "\"file\": " + programName + "\n";
                response += "}";
                
                Msg.info(this, "Sending / response: " + response);
                byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
            } catch (Exception e) {
                Msg.error(this, "Error serving / endpoint", e);
                try {
                    String error = "{\"error\": \"Internal error\", \"port\": " + port + "}";
                    byte[] bytes = error.getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                    exchange.sendResponseHeaders(200, bytes.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(bytes);
                    }
                } catch (IOException ioe) {
                    Msg.error(this, "Failed to send error response", ioe);
                }
            }
        });

        server.createContext("/registerInstance", exchange -> {
            Map<String, String> params = parseJsonPostParams(exchange); // Use JSON parser
            int port = parseIntOrDefault(params.get("port"), 0);
            if (port > 0) {
                sendResponse(exchange, "Instance registered on port " + port);
            } else {
                sendResponse(exchange, "Invalid port number");
            }
        });

        server.createContext("/unregisterInstance", exchange -> {
            Map<String, String> params = parseJsonPostParams(exchange); // Use JSON parser
            int port = parseIntOrDefault(params.get("port"), 0);
            if (port > 0 && activeInstances.containsKey(port)) {
                activeInstances.remove(port);
                sendResponse(exchange, "Unregistered instance on port " + port);
            } else {
                sendResponse(exchange, "No instance found on port " + port);
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

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "{\"success\":false,\"error\":\"No program loaded\"}";

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
        
        Gson gson = new Gson();
        JsonObject response = new JsonObject();
        response.addProperty("success", true);
        response.add("result", gson.toJsonTree(paginated));
        response.addProperty("timestamp", System.currentTimeMillis());
        response.addProperty("port", this.port);
        return gson.toJson(response);
    }

    private JsonObject getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            JsonObject error = new JsonObject();
            error.addProperty("success", false);
            error.addProperty("error", "No program loaded");
            return error;
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
        
        JsonObject response = new JsonObject();
        response.addProperty("success", true);
        response.add("result", new Gson().toJsonTree(paginated));
        response.addProperty("timestamp", System.currentTimeMillis());
        response.addProperty("port", this.port);
        return response;
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "{\"success\":false,\"error\":\"No program loaded\"}";

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
        
        Gson gson = new Gson();
        JsonObject response = new JsonObject();
        response.addProperty("success", true);
        response.add("result", gson.toJsonTree(paginated));
        response.addProperty("timestamp", System.currentTimeMillis());
        response.addProperty("port", this.port);
        return gson.toJson(response);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"success\":false,\"error\":\"No program loaded\"}";
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
        
        Gson gson = new Gson();
        JsonObject response = new JsonObject();
        response.addProperty("success", true);
        response.add("result", gson.toJsonTree(paginated));
        response.addProperty("timestamp", System.currentTimeMillis());
        response.addProperty("port", this.port);
        return gson.toJson(response);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"success\":false,\"error\":\"No program loaded\"}";
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
        
        Gson gson = new Gson();
        JsonObject response = new JsonObject();
        response.addProperty("success", true);
        response.add("result", gson.toJsonTree(paginated));
        response.addProperty("timestamp", System.currentTimeMillis());
        response.addProperty("port", this.port);
        return gson.toJson(response);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"success\":false,\"error\":\"No program loaded\"}";
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
        
        Gson gson = new Gson();
        JsonObject response = new JsonObject();
        response.addProperty("success", true);
        response.add("result", gson.toJsonTree(paginated));
        response.addProperty("timestamp", System.currentTimeMillis());
        response.addProperty("port", this.port);
        return gson.toJson(response);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"success\":false,\"error\":\"No program loaded\"}";
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
        
        Gson gson = new Gson();
        JsonObject response = new JsonObject();
        response.addProperty("success", true);
        response.add("result", gson.toJsonTree(paginated));
        response.addProperty("timestamp", System.currentTimeMillis());
        response.addProperty("port", this.port);
        return gson.toJson(response);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
    
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
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }    

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        try {
            if (!decomp.openProgram(program)) {
                return "Failed to initialize decompiler";
            }
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                }
                return "Decompilation failed"; // Keep as string for now, handled by sendResponse
            }
        }
        // Return specific error object instead of just a string
        JsonObject errorResponse = new JsonObject();
        errorResponse.addProperty("success", false);
        errorResponse.addProperty("error", "Function not found: " + name);
        return errorResponse.toString(); // Return JSON string
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
    
    private String listVariablesInFunction(String functionName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        try {
            if (!decomp.openProgram(program)) {
                return "Failed to initialize decompiler";
            }
            
            Function function = findFunctionByName(program, functionName);
            if (function == null) {
                return "Function not found: " + functionName;
            }
            
            DecompileResults results = decomp.decompileFunction(function, 30, new ConsoleTaskMonitor());
            if (results == null || !results.decompileCompleted()) {
                return "Failed to decompile function: " + functionName;
            }

            // Get high-level pcode representation for the function
            HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                return "Failed to get high function for: " + functionName;
            }
            
            // Get local variables
            List<String> variables = new ArrayList<>();
            Iterator<HighSymbol> symbolIter = highFunction.getLocalSymbolMap().getSymbols();
            while (symbolIter.hasNext()) {
                HighSymbol symbol = symbolIter.next();
                if (symbol.getHighVariable() != null) {
                    DataType dt = symbol.getDataType();
                    String dtName = dt != null ? dt.getName() : "unknown";
                    variables.add(String.format("%s: %s @ %s", 
                        symbol.getName(), dtName, symbol.getPCAddress()));
                }
            }
            
            // Get parameters
            List<String> parameters = new ArrayList<>();
            // In older Ghidra versions, we need to filter symbols to find parameters
            symbolIter = highFunction.getLocalSymbolMap().getSymbols();
            while (symbolIter.hasNext()) {
                HighSymbol symbol = symbolIter.next();
                if (symbol.isParameter()) {
                    DataType dt = symbol.getDataType();
                    String dtName = dt != null ? dt.getName() : "unknown";
                    parameters.add(String.format("%s: %s (parameter)", 
                        symbol.getName(), dtName));
                }
            }
            
            // Format the response
            StringBuilder sb = new StringBuilder();
            sb.append("Function: ").append(functionName).append("\n\n");
            
            sb.append("Parameters:\n");
            if (parameters.isEmpty()) {
                sb.append("  none\n");
            } else {
                for (String param : parameters) {
                    sb.append("  ").append(param).append("\n");
                }
            }
            
            sb.append("\nLocal Variables:\n");
            if (variables.isEmpty()) {
                sb.append("  none\n");
            } else {
                for (String var : variables) {
                    sb.append("  ").append(var).append("\n");
                }
            }
            
            return sb.toString();
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
    
    private String listGlobalVariables(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        
        List<String> globalVars = new ArrayList<>();
        SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator it = symbolTable.getSymbolIterator();
        
        while (it.hasNext()) {
            Symbol symbol = it.next();
            // Check for globals - look for symbols that are in global space and not functions
            if (symbol.isGlobal() && 
                symbol.getSymbolType() != SymbolType.FUNCTION && 
                symbol.getSymbolType() != SymbolType.LABEL) {
                globalVars.add(String.format("%s @ %s", 
                    symbol.getName(), symbol.getAddress()));
            }
        }
        
        Collections.sort(globalVars);
        return paginateList(globalVars, offset, limit);
    }
    
    private String searchVariables(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
        
        List<String> matchedVars = new ArrayList<>();
        
        // Search global variables
        SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator it = symbolTable.getSymbolIterator();
        while (it.hasNext()) {
            Symbol symbol = it.next();
            if (symbol.isGlobal() && 
                symbol.getSymbolType() != SymbolType.FUNCTION && 
                symbol.getSymbolType() != SymbolType.LABEL && 
                symbol.getName().toLowerCase().contains(searchTerm.toLowerCase())) {
                matchedVars.add(String.format("%s @ %s (global)", 
                    symbol.getName(), symbol.getAddress()));
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
                                    if (symbol.isParameter()) {
                                        matchedVars.add(String.format("%s in %s (parameter)", 
                                            symbol.getName(), function.getName()));
                                    } else {
                                        matchedVars.add(String.format("%s in %s @ %s (local)", 
                                            symbol.getName(), function.getName(), symbol.getPCAddress()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } finally {
            decomp.dispose();
        }
        
        Collections.sort(matchedVars);
        
        if (matchedVars.isEmpty()) {
            return "No variables matching '" + searchTerm + "'";
        }
        return paginateList(matchedVars, offset, limit);
    }
    
    // ----------------------------------------------------------------------------------
    // Helper methods
    // ----------------------------------------------------------------------------------
    
    private Function findFunctionByName(Program program, String name) {
        if (program == null || name == null || name.isEmpty()) {
            return null;
        }
        
        for (Function function : program.getFunctionManager().getFunctions(true)) {
            if (function.getName().equals(name)) {
                return function;
            }
        }
        return null;
    }
    
    private DataType findDataType(Program program, String name) {
        if (program == null || name == null || name.isEmpty()) {
            return null;
        }
        
        DataTypeManager dtm = program.getDataTypeManager();
        
        // First try direct lookup
        DataType dt = dtm.getDataType("/" + name);
        if (dt != null) {
            return dt;
        }
        
        // Try built-in types by simple name
        dt = dtm.findDataType(name);
        if (dt != null) {
            return dt;
        }
        
        // Try to find a matching type by name only
        Iterator<DataType> dtIter = dtm.getAllDataTypes();
        while (dtIter.hasNext()) {
            DataType type = dtIter.next();
            if (type.getName().equals(name)) {
                return type;
            }
        }
        
        return null;
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
    

    private void sendResponse(HttpExchange exchange, Object response) throws IOException {
        if (response instanceof String && ((String)response).startsWith("{")) {
            // Already JSON formatted, send as-is
            byte[] bytes = ((String)response).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        } else {
            // Wrap in standard response format
            JsonObject json = new JsonObject();
            json.addProperty("success", true);
            if (response instanceof String) {
                json.addProperty("result", (String)response);
            } else {
                json.add("result", new Gson().toJsonTree(response));
            }
            json.addProperty("timestamp", System.currentTimeMillis());
            json.addProperty("port", this.port);
            if (this.isBaseInstance) {
                json.addProperty("instanceType", "base");
            } else {
                json.addProperty("instanceType", "secondary");
            }
            sendJsonResponse(exchange, json);
        }
    }

    private void sendJsonResponse(HttpExchange exchange, JsonObject jsonObj) throws IOException {
        try {
            Gson gson = new Gson();
            String json = gson.toJson(jsonObj);
            Msg.debug(this, "Sending JSON response: " + json);
            
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            exchange.sendResponseHeaders(200, bytes.length);
            
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
                    try {
                        os.close();
                    } catch (IOException e) {
                        Msg.error(this, "Error closing output stream: " + e.getMessage(), e);
                    }
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error in sendJsonResponse: " + e.getMessage(), e);
            throw new IOException("Failed to send JSON response", e);
        }
    }

    private void sendErrorResponse(HttpExchange exchange, int statusCode, String message) throws IOException {
        JsonObject error = new JsonObject();
        error.addProperty("error", message);
        error.addProperty("status", statusCode);
        error.addProperty("success", false);
        
        Gson gson = new Gson();
        byte[] bytes = gson.toJson(error).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
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
