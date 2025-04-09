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

@PluginInfo(status = PluginStatus.RELEASED, packageName = ghidra.app.DeveloperPluginPackage.NAME, category = PluginCategoryNames.ANALYSIS, shortDescription = "GhydraMCP Plugin for AI Analysis", description = "Exposes program data via HTTP API for AI-assisted reverse engineering with MCP (Model Context Protocol).", servicesRequired = {
        ProgramManager.class })
public class GhydraMCPPlugin extends Plugin implements ApplicationLevelPlugin {

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
                        "Port " + port
                                + " is already in use. Please specify a different port with -Dghidra.mcp.port=NEW_PORT");
            }
        }
    }

    private void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/function_details", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                String name = qparams.get("name");
                if (name == null || name.isEmpty()) {
                    sendErrorResponse(exchange, 400, "Name parameter is required");
                    return;
                }
                sendJsonResponse(exchange, getFunctionDetailsByName(name));
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        });

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
                exchange.sendResponseHeaders(405, -1);
            }
        });

        server.createContext("/functions/", exchange -> {
            String path = exchange.getRequestURI().getPath();

            String[] pathParts = path.split("/");

            if (pathParts.length < 3) {
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            String functionName = pathParts[2];
            try {
                functionName = java.net.URLDecoder.decode(functionName, StandardCharsets.UTF_8.name());
            } catch (Exception e) {
                Msg.error(this, "Failed to decode function name", e);
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            if (pathParts.length > 3 && "variables".equals(pathParts[3])) {
                if ("GET".equals(exchange.getRequestMethod())) {
                    sendResponse(exchange, listVariablesInFunction(functionName));
                } else if ("POST".equals(exchange.getRequestMethod()) && pathParts.length > 4) {
                    String variableName = pathParts[4];
                    try {
                        variableName = java.net.URLDecoder.decode(variableName, StandardCharsets.UTF_8.name());
                    } catch (Exception e) {
                        Msg.error(this, "Failed to decode variable name", e);
                        exchange.sendResponseHeaders(400, -1);
                        return;
                    }

                    Map<String, String> params = parseJsonPostParams(exchange);
                    if (params.containsKey("newName")) {
                        boolean renameSuccess = renameVariable(functionName, variableName, params.get("newName"));
                        sendJsonResponse(exchange,
                                renameSuccess ? createSuccessResponse("Variable renamed successfully")
                                        : createErrorResponse("Failed to rename variable", 400));
                    } else if (params.containsKey("dataType")) {
                        boolean retypeSuccess = retypeVariable(functionName, variableName, params.get("dataType"));
                        sendJsonResponse(exchange,
                                retypeSuccess ? createSuccessResponse("Variable retyped successfully")
                                        : createErrorResponse("Failed to retype variable", 400));
                    } else {
                        sendResponse(exchange, "Missing required parameter: newName or dataType");
                    }
                } else {
                    exchange.sendResponseHeaders(405, -1);
                }
            } else {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, String> qparams = parseQueryParams(exchange);
                    boolean cCode = Boolean.parseBoolean(qparams.getOrDefault("cCode", "true"));
                    boolean syntaxTree = Boolean.parseBoolean(qparams.getOrDefault("syntaxTree", "false"));
                    String simplificationStyle = qparams.getOrDefault("simplificationStyle", "normalize");

                    JsonObject response = decompileFunctionByName(functionName, cCode, syntaxTree, simplificationStyle);
                    sendJsonResponse(exchange, response);
                } else if ("POST".equals(exchange.getRequestMethod())) {
                    Map<String, String> params = parseJsonPostParams(exchange);
                    String newName = params.get("newName");
                    boolean success = renameFunction(functionName, newName);
                    sendJsonResponse(exchange,
                            success ? createSuccessResponse("Renamed successfully")
                                    : createErrorResponse("Rename failed", 400));
                } else {
                    exchange.sendResponseHeaders(405, -1);
                }
            }
        });

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
                exchange.sendResponseHeaders(405, -1);
            }
        });

        server.createContext("/segments", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                int offset = parseIntOrDefault(qparams.get("offset"), 0);
                int limit = parseIntOrDefault(qparams.get("limit"), 100);
                sendResponse(exchange, listSegments(offset, limit));
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        });

        server.createContext("/symbols/imports", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                int offset = parseIntOrDefault(qparams.get("offset"), 0);
                int limit = parseIntOrDefault(qparams.get("limit"), 100);
                sendResponse(exchange, listImports(offset, limit));
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        });

        server.createContext("/symbols/exports", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                int offset = parseIntOrDefault(qparams.get("offset"), 0);
                int limit = parseIntOrDefault(qparams.get("limit"), 100);
                sendResponse(exchange, listExports(offset, limit));
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        });

        server.createContext("/namespaces", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                int offset = parseIntOrDefault(qparams.get("offset"), 0);
                int limit = parseIntOrDefault(qparams.get("limit"), 100);
                sendResponse(exchange, listNamespaces(offset, limit));
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        });

        server.createContext("/data", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                int offset = parseIntOrDefault(qparams.get("offset"), 0);
                int limit = parseIntOrDefault(qparams.get("limit"), 100);
                sendResponse(exchange, listDefinedData(offset, limit));
            } else if ("POST".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parseJsonPostParams(exchange);
                boolean success = renameDataAtAddress(params.get("address"), params.get("newName"));
                sendJsonResponse(exchange,
                        success ? createSuccessResponse("Data renamed successfully")
                                : createErrorResponse("Failed to rename data", 400));
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        });

        server.createContext("/variables", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                int offset = parseIntOrDefault(qparams.get("offset"), 0);
                int limit = parseIntOrDefault(qparams.get("limit"), 100);
                String search = qparams.get("search");

                if (search != null && !search.isEmpty()) {
                    sendResponse(exchange, searchVariables(search, offset, limit));
                } else {
                    sendResponse(exchange, listVariables(offset, limit, search));
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        });

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

        server.createContext("/get_function_by_address", exchange -> {
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
                        JsonObject response = new JsonObject();
                        JsonObject resultObj = new JsonObject();
                        resultObj.addProperty("name", "");
                        resultObj.addProperty("address", address);
                        resultObj.addProperty("signature", "");
                        resultObj.addProperty("decompilation", "");

                        response.addProperty("success", true);
                        response.add("result", resultObj);
                        response.addProperty("timestamp", System.currentTimeMillis());
                        response.addProperty("port", this.port);
                        sendJsonResponse(exchange, response);
                        return;
                    }

                    sendJsonResponse(exchange, getFunctionDetails(func));
                } catch (Exception e) {
                    Msg.error(this, "Error getting function by address", e);
                    sendErrorResponse(exchange, 500, "Error getting function: " + e.getMessage());
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        });

        server.createContext("/decompile_function", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                String address = qparams.get("address");
                boolean cCode = Boolean.parseBoolean(qparams.getOrDefault("cCode", "true"));
                boolean syntaxTree = Boolean.parseBoolean(qparams.getOrDefault("syntaxTree", "false"));
                String simplificationStyle = qparams.getOrDefault("simplificationStyle", "normalize");

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
                        JsonObject response = new JsonObject();
                        JsonObject resultObj = new JsonObject();
                        resultObj.addProperty("decompilation", "");
                        resultObj.addProperty("function", "");
                        resultObj.addProperty("address", address);

                        response.addProperty("success", false);
                        response.addProperty("message", "Function not found");
                        response.add("result", resultObj);
                        response.addProperty("timestamp", System.currentTimeMillis());
                        response.addProperty("port", this.port);
                        sendJsonResponse(exchange, response);
                        return;
                    }

                    DecompInterface decomp = new DecompInterface();
                    try {
                        decomp.toggleCCode(cCode);
                        decomp.setSimplificationStyle(simplificationStyle);
                        decomp.toggleSyntaxTree(syntaxTree);

                        if (!decomp.openProgram(program)) {
                            sendErrorResponse(exchange, 500, "Failed to initialize decompiler");
                            return;
                        }

                        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                        if (result == null || !result.decompileCompleted()) {
                            sendErrorResponse(exchange, 500, "Decompilation failed");
                            return;
                        }

                        String decompilation = result.getDecompiledFunction().getC();
                        JsonObject response = new JsonObject();
                        response.addProperty("success", true);

                        JsonObject resultObj = new JsonObject();
                        resultObj.addProperty("decompilation", decompilation);
                        resultObj.addProperty("name", func.getName());
                        resultObj.addProperty("address", func.getEntryPoint().toString());
                        resultObj.addProperty("signature", func.getSignature().getPrototypeString());

                        response.add("result", resultObj);
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
                exchange.sendResponseHeaders(405, -1);
            }
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parseJsonPostParams(exchange);
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
                exchange.sendResponseHeaders(405, -1);
            }
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parseJsonPostParams(exchange);
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
                exchange.sendResponseHeaders(405, -1);
            }
        });

        server.createContext("/rename_function_by_address", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parseJsonPostParams(exchange);
                String address = params.get("functionAddress");
                String newName = params.get("newName");

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
                    response.addProperty("message",
                            success ? "Function renamed successfully" : "Failed to rename function");
                    response.addProperty("timestamp", System.currentTimeMillis());
                    response.addProperty("port", this.port);
                    sendJsonResponse(exchange, response);
                } catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                    sendErrorResponse(exchange, 500, "Error renaming function: " + e.getMessage());
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        });

        server.createContext("/rename_local_variable", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parseJsonPostParams(exchange);
                String functionAddress = params.get("functionAddress");
                String oldName = params.get("oldName");
                String newName = params.get("newName");

                if (functionAddress == null || functionAddress.isEmpty()) {
                    sendErrorResponse(exchange, 400, "functionAddress parameter is required");
                    return;
                }
                if (oldName == null || oldName.isEmpty()) {
                    sendErrorResponse(exchange, 400, "oldName parameter is required");
                    return;
                }
                if (newName == null || newName.isEmpty()) {
                    sendErrorResponse(exchange, 400, "newName parameter is required");
                    return;
                }

                JsonObject response = new JsonObject();
                response.addProperty("success", true);
                response.addProperty("message", "Rename local variable (not fully implemented by address yet)");
                response.addProperty("timestamp", System.currentTimeMillis());
                response.addProperty("port", this.port);
                sendJsonResponse(exchange, response);

            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        });

        server.createContext("/set_function_prototype", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parseJsonPostParams(exchange);
                String functionAddress = params.get("functionAddress");
                String prototype = params.get("prototype");

                if (functionAddress == null || functionAddress.isEmpty()) {
                    sendErrorResponse(exchange, 400, "functionAddress parameter is required");
                    return;
                }
                if (prototype == null || prototype.isEmpty()) {
                    sendErrorResponse(exchange, 400, "prototype parameter is required");
                    return;
                }

                JsonObject response = new JsonObject();
                response.addProperty("success", true);
                response.addProperty("message", "Set function prototype (not fully implemented yet)");
                response.addProperty("timestamp", System.currentTimeMillis());
                response.addProperty("port", this.port);
                sendJsonResponse(exchange, response);

            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        });

        server.createContext("/set_local_variable_type", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parseJsonPostParams(exchange);
                String functionAddress = params.get("functionAddress");
                String variableName = params.get("variableName");
                String newType = params.get("newType");

                if (functionAddress == null || functionAddress.isEmpty()) {
                    sendErrorResponse(exchange, 400, "functionAddress parameter is required");
                    return;
                }
                if (variableName == null || variableName.isEmpty()) {
                    sendErrorResponse(exchange, 400, "variableName parameter is required");
                    return;
                }
                if (newType == null || newType.isEmpty()) {
                    sendErrorResponse(exchange, 400, "newType parameter is required");
                    return;
                }

                JsonObject response = new JsonObject();
                response.addProperty("success", true);
                response.addProperty("message", "Set local variable type (not fully implemented yet)");
                response.addProperty("timestamp", System.currentTimeMillis());
                response.addProperty("port", this.port);
                sendJsonResponse(exchange, response);

            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        });

        server.createContext("/info", exchange -> {
            try {
                JsonObject response = new JsonObject();
                response.addProperty("port", port);
                response.addProperty("isBaseInstance", isBaseInstance);

                Program program = getCurrentProgram();
                response.addProperty("file", program != null ? program.getName() : "");

                Project project = tool.getProject();
                response.addProperty("project", project != null ? project.getName() : "");

                sendJsonResponse(exchange, response);
            } catch (Exception e) {
                Msg.error(this, "Error serving /info endpoint", e);
                try {
                    String error = "{\"error\": \"Internal error\", \"port\": " + port + "}";
                    byte[] bytes = error.getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
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

        server.createContext("/", exchange -> {
            if (!exchange.getRequestURI().getPath().equals("/")) {
                sendErrorResponse(exchange, 404, "Endpoint not found");
                return;
            }

            try {
                JsonObject response = new JsonObject();
                response.addProperty("port", port);
                response.addProperty("isBaseInstance", isBaseInstance);

                Program program = getCurrentProgram();
                response.addProperty("file", program != null ? program.getName() : "");

                Project project = tool.getProject();
                response.addProperty("project", project != null ? project.getName() : "");

                sendJsonResponse(exchange, response);
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
            Map<String, String> params = parseJsonPostParams(exchange);
            int port = parseIntOrDefault(params.get("port"), 0);
            if (port > 0) {
                sendResponse(exchange, "Instance registered on port " + port);
            } else {
                sendResponse(exchange, "Invalid port number");
            }
        });

        server.createContext("/unregisterInstance", exchange -> {
            Map<String, String> params = parseJsonPostParams(exchange);
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

    private JsonObject getAllFunctionNames(int offset, int limit) {
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

        int start = Math.max(0, offset);
        int end = Math.min(functions.size(), offset + limit);
        List<Map<String, String>> paginated = functions.subList(start, end);

        return createSuccessResponse(paginated);
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

        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        int start = Math.max(0, offset);
        int end = Math.min(sorted.size(), offset + limit);
        List<String> paginated = sorted.subList(start, end);

        return createSuccessResponse(paginated);
    }

    private JsonObject listSegments(int offset, int limit) {
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

        int start = Math.max(0, offset);
        int end = Math.min(segments.size(), offset + limit);
        List<Map<String, String>> paginated = segments.subList(start, end);

        return createSuccessResponse(paginated);
    }

    private JsonObject listImports(int offset, int limit) {
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

        int start = Math.max(0, offset);
        int end = Math.min(imports.size(), offset + limit);
        List<Map<String, String>> paginated = imports.subList(start, end);

        return createSuccessResponse(paginated);
    }

    private JsonObject listExports(int offset, int limit) {
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

        int start = Math.max(0, offset);
        int end = Math.min(exports.size(), offset + limit);
        List<Map<String, String>> paginated = exports.subList(start, end);

        return createSuccessResponse(paginated);
    }

    private JsonObject listNamespaces(int offset, int limit) {
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

        int start = Math.max(0, offset);
        int end = Math.min(sorted.size(), offset + limit);
        List<String> paginated = sorted.subList(start, end);

        return createSuccessResponse(paginated);
    }

    private JsonObject listDefinedData(int offset, int limit) {
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

        int start = Math.max(0, offset);
        int end = Math.min(dataItems.size(), offset + limit);
        List<Map<String, String>> paginated = dataItems.subList(start, end);

        return createSuccessResponse(paginated);
    }

    private JsonObject searchFunctionsByName(String searchTerm, int offset, int limit) {
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
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }

        Collections.sort(matches);

        if (matches.isEmpty()) {
            return createSuccessResponse(new ArrayList<>());
        }

        int start = Math.max(0, offset);
        int end = Math.min(matches.size(), offset + limit);
        List<String> sub = matches.subList(start, end);

        return createSuccessResponse(sub);
    }

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

        return getFunctionDetails(func);
    }

    private JsonObject getFunctionDetails(Function func) {
        JsonObject response = new JsonObject();
        JsonObject resultObj = new JsonObject();
        Program program = func.getProgram();

        resultObj.addProperty("name", func.getName());
        resultObj.addProperty("address", func.getEntryPoint().toString());
        resultObj.addProperty("signature", func.getSignature().getPrototypeString());

        DecompInterface decomp = new DecompInterface();
        try {
            decomp.toggleCCode(true);
            decomp.setSimplificationStyle("normalize");
            decomp.toggleSyntaxTree(false);

            if (!decomp.openProgram(program)) {
                resultObj.addProperty("decompilation_error", "Failed to initialize decompiler");
            } else {
                DecompileResults decompResult = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (decompResult != null && decompResult.decompileCompleted()) {
                    resultObj.addProperty("decompilation", decompResult.getDecompiledFunction().getC());
                } else {
                    resultObj.addProperty("decompilation_error", "Decompilation failed or timed out");
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

    private JsonObject decompileFunction(Function func, boolean cCode, boolean syntaxTree, String simplificationStyle) {
        Program program = func.getProgram();
        DecompInterface decomp = new DecompInterface();
        try {
            decomp.toggleCCode(cCode);
            decomp.setSimplificationStyle(simplificationStyle);
            decomp.toggleSyntaxTree(syntaxTree);

            if (!decomp.openProgram(program)) {
                return createErrorResponse("Failed to initialize decompiler", 500);
            }

            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
            if (result != null && result.decompileCompleted()) {
                JsonObject resultObj = new JsonObject();
                resultObj.addProperty("name", func.getName());
                resultObj.addProperty("address", func.getEntryPoint().toString());
                resultObj.addProperty("signature", func.getSignature().getPrototypeString());
                resultObj.addProperty("decompilation", result.getDecompiledFunction().getC());
                return createSuccessResponse(resultObj);
            } else {
                return createErrorResponse("Decompilation failed", 500);
            }
        } finally {
            decomp.dispose();
        }
    }

    private JsonObject decompileFunctionByName(String name, boolean cCode, boolean syntaxTree,
            String simplificationStyle) {
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded", 400);
        }

        Function func = findFunctionByName(program, name);
        if (func == null) {
            return createErrorResponse("Function not found: " + name, 404);
        }

        return decompileFunction(func, cCode, syntaxTree, simplificationStyle);
    }

    private boolean renameFunctionByAddress(Address functionAddress, String newName) {
        Program program = getCurrentProgram();
        if (program == null)
            return false;

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
                } catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                } finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private boolean setDecompilerComment(Address address, String comment) {
        Program program = getCurrentProgram();
        if (program == null)
            return false;

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
                } catch (Exception e) {
                    Msg.error(this, "Error setting decompiler comment", e);
                } finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set comment on Swing thread", e);
        }
        return successFlag.get();
    }

    private boolean setDisassemblyComment(Address address, String comment) {
        Program program = getCurrentProgram();
        if (program == null)
            return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set disassembly comment");
                try {
                    Listing listing = program.getListing();
                    listing.setComment(address, CodeUnit.EOL_COMMENT, comment);
                    successFlag.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting disassembly comment", e);
                } finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set comment on Swing thread", e);
        }
        return successFlag.get();
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null)
            return false;

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
                } catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                } finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private boolean renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null)
            return false;

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
                } catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                } finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
        return successFlag.get();
    }

    private JsonObject listVariablesInFunction(String functionName) {
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

            HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                return createErrorResponse("Failed to get high function for: " + functionName, 500);
            }

            List<Map<String, String>> allVariables = new ArrayList<>();

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
                    continue;
                }

                allVariables.add(varInfo);
            }

            Collections.sort(allVariables, (a, b) -> a.get("name").compareTo(b.get("name")));

            JsonObject response = new JsonObject();
            response.addProperty("success", true);

            JsonObject resultObj = new JsonObject();
            resultObj.addProperty("function", functionName);
            resultObj.add("variables", new Gson().toJsonTree(allVariables));

            return createSuccessResponse(resultObj);
        } finally {
            decomp.dispose();
        }
    }

    private boolean renameVariable(String functionName, String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null)
            return false;

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
                            SourceType.USER_DEFINED);
                    successFlag.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                } finally {
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
     * Compare the given HighFunction's idea of the prototype with the Function's
     * idea.
     * Return true if there is a difference. If a specific symbol is being changed,
     * it can be passed in to check whether or not the prototype is being affected.
     * 
     * @param highSymbol (if not null) is the symbol being modified
     * @param hfunction  is the given HighFunction
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
        if (program == null)
            return false;

        AtomicBoolean result = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Retype variable via HTTP");
                try {
                    Function function = findFunctionByName(program, functionName);
                    if (function == null) {
                        return;
                    }

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

                    DataType dataType = findDataType(program, dataTypeName);
                    if (dataType == null) {
                        return;
                    }

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

        DecompInterface decomp = null;
        try {
            decomp = new DecompInterface();
            if (!decomp.openProgram(program)) {
                Msg.error(this, "listVariables: Failed to open program with decompiler.");
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
                                    if (!symbol.isParameter()) {
                                        Map<String, String> varInfo = new HashMap<>();
                                        varInfo.put("name", symbol.getName());
                                        varInfo.put("type", "local");
                                        varInfo.put("function", function.getName());
                                        Address pcAddr = symbol.getPCAddress();
                                        varInfo.put("address", pcAddr != null ? pcAddr.toString() : "N/A");
                                        varInfo.put("dataType",
                                                symbol.getDataType() != null ? symbol.getDataType().getName()
                                                        : "unknown");
                                        variables.add(varInfo);
                                    }
                                }
                            } else {
                                Msg.warn(this, "listVariables: Failed to get HighFunction for " + function.getName());
                            }
                        } else {
                            Msg.warn(this,
                                    "listVariables: Decompilation failed or timed out for " + function.getName());
                        }
                    } catch (Exception e) {
                        Msg.error(this, "listVariables: Error processing function " + function.getName(), e);
                    }
                }
            }
        } catch (Exception e) {
            Msg.error(this, "listVariables: Error during local variable processing", e);
        } finally {
            if (decomp != null) {
                decomp.dispose();
            }
        }

        Collections.sort(variables, (a, b) -> a.get("name").compareTo(b.get("name")));

        int start = Math.max(0, offset);
        int end = Math.min(variables.size(), offset + limit);
        List<Map<String, String>> paginated = variables.subList(start, end);

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

        DecompInterface decomp = new DecompInterface();
        try {
            if (decomp.openProgram(program)) {
                for (Function function : program.getFunctionManager().getFunctions(true)) {
                    DecompileResults results = decomp.decompileFunction(function, 30, new ConsoleTaskMonitor());
                    if (results != null && results.decompileCompleted()) {
                        HighFunction highFunc = results.getHighFunction();
                        if (highFunc != null) {
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

        Collections.sort(matchedVars, (a, b) -> a.get("name").compareTo(b.get("name")));

        int start = Math.max(0, offset);
        int end = Math.min(matchedVars.size(), offset + limit);
        List<Map<String, String>> paginated = matchedVars.subList(start, end);

        return createSuccessResponse(paginated);
    }

    private String getDataTypeName(Program program, Address address) {
        if (program == null || address == null) {
            return "unknown";
        }
        Data data = program.getListing().getDefinedDataAt(address);
        if (data != null) {
            DataType dt = data.getDataType();
            return dt != null ? dt.getName() : "unknown";
        }
        return "unknown";
    }

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

        DataType dt = dtm.getDataType("/" + name);
        if (dt != null) {
            return dt;
        }

        dt = dtm.findDataType(name);
        if (dt != null) {
            return dt;
        }

        Iterator<DataType> dtIter = dtm.getAllDataTypes();
        while (dtIter.hasNext()) {
            DataType type = dtIter.next();
            if (type.getName().equals(name)) {
                return type;
            }
        }

        return null;
    }

    private JsonObject createSuccessResponse(Object resultData) {
        JsonObject response = new JsonObject();
        response.addProperty("success", true);
        if (resultData != null) {
            response.add("result", new Gson().toJsonTree(resultData));
        } else {
            response.add("result", null);
        }
        response.addProperty("timestamp", System.currentTimeMillis());
        response.addProperty("port", this.port);
        return response;
    }

    private JsonObject createErrorResponse(String errorMessage, int statusCode) {
        JsonObject response = new JsonObject();
        response.addProperty("success", false);
        response.addProperty("error", errorMessage);
        response.addProperty("status_code", statusCode);
        response.addProperty("timestamp", System.currentTimeMillis());
        response.addProperty("port", this.port);
        return response;
    }

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery();
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
            Gson gson = new Gson();
            JsonObject json = gson.fromJson(bodyStr, JsonObject.class);

            for (Map.Entry<String, JsonElement> entry : json.entrySet()) {
                String key = entry.getKey();
                JsonElement value = entry.getValue();

                if (value.isJsonPrimitive()) {
                    params.put(key, value.getAsString());
                } else {
                    params.put(key, value.toString());
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Failed to parse JSON request body: " + e.getMessage(), e);
            throw new IOException("Invalid JSON request body: " + e.getMessage(), e);
        }
        return params;
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null)
            return defaultValue;
        try {
            return Integer.parseInt(val);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
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
        } catch (Exception e) {
            Msg.error(this, "Error getting current program", e);
            return null;
        }
    }

    private void sendResponse(HttpExchange exchange, Object response) throws IOException {
        if (response instanceof JsonObject) {
            sendJsonResponse(exchange, (JsonObject) response);
        } else {
            sendJsonResponse(exchange, createSuccessResponse(response));
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
        sendJsonResponse(exchange, createErrorResponse(message, statusCode), statusCode);
    }

    private void sendJsonResponse(HttpExchange exchange, JsonObject jsonObj, int statusCode) throws IOException {
        try {
            if (!jsonObj.has("success")) {
                jsonObj.addProperty("success", statusCode >= 200 && statusCode < 300);
            } else {
            }

            Gson gson = new Gson();
            String json = gson.toJson(jsonObj);
            Msg.debug(this, "Sending JSON response (Status " + statusCode + "): " + json);

            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            exchange.sendResponseHeaders(statusCode, bytes.length);

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
