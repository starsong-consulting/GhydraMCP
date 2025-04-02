package eu.starsong.ghidra;

import ghidra.framework.plugintool.*;
import ghidra.framework.main.ApplicationLevelPlugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.framework.model.Project;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

// For JSON response handling
import org.json.simple.JSONObject;

import ghidra.app.services.CodeViewerService;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;

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
                } else if ("PUT".equals(exchange.getRequestMethod()) && pathParts.length > 4) {
                    // Handle operations on a specific variable
                    String variableName = pathParts[4];
                    try {
                        variableName = java.net.URLDecoder.decode(variableName, StandardCharsets.UTF_8.name());
                    } catch (Exception e) {
                        Msg.error(this, "Failed to decode variable name", e);
                        exchange.sendResponseHeaders(400, -1);
                        return;
                    }
                    
                    Map<String, String> params = parsePostParams(exchange);
                    if (params.containsKey("newName")) {
                        // Rename variable
                        String result = renameVariable(functionName, variableName, params.get("newName"));
                        sendResponse(exchange, result);
                    } else if (params.containsKey("dataType")) {
                        // Retype variable
                        String result = retypeVariable(functionName, variableName, params.get("dataType"));
                        sendResponse(exchange, result);
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
                } else if ("PUT".equals(exchange.getRequestMethod())) {
                    Map<String, String> params = parsePostParams(exchange);
                    String newName = params.get("newName");
                    String response = renameFunction(functionName, newName)
                            ? "Renamed successfully" : "Rename failed";
                    sendResponse(exchange, response);
                } else {
                    exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                }
            }
        });

        // Class resources
        server.createContext("/classes", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                int offset = parseIntOrDefault(qparams.get("offset"), 0);
                int limit = parseIntOrDefault(qparams.get("limit"), 100);
                sendResponse(exchange, getAllClassNames(offset, limit));
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
            } else if ("PUT".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parsePostParams(exchange);
                renameDataAtAddress(params.get("address"), params.get("newName"));
                sendResponse(exchange, "Rename data attempted");
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
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<Integer, GhydraMCPPlugin> entry : activeInstances.entrySet()) {
                sb.append(entry.getKey()).append(": ")
                  .append(entry.getValue().isBaseInstance ? "base" : "secondary")
                  .append("\n");
            }
            sendResponse(exchange, sb.toString());
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
                    exchange.sendResponseHeaders(200, bytes.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(bytes);
                    }
                } catch (IOException ioe) {
                    Msg.error(this, "Failed to send error response", ioe);
                }
            }
        });
        
        // Super simple root endpoint - exact same as /info for consistency
        server.createContext("/", exchange -> {
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
            Map<String, String> params = parsePostParams(exchange);
            int port = parseIntOrDefault(params.get("port"), 0);
            if (port > 0) {
                sendResponse(exchange, "Instance registered on port " + port);
            } else {
                sendResponse(exchange, "Invalid port number");
            }
        });

        server.createContext("/unregisterInstance", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
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
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName() + " @ " + f.getEntryPoint());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
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
                return "Decompilation failed";
            }
        }
        return "Function not found";
        } finally {
            decomp.dispose();
        }
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

    private void renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return;

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
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
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
    
    private String renameVariable(String functionName, String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

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
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
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
                return "Error: A variable with name '" + newName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
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
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
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
    
    private String retypeVariable(String functionName, String varName, String dataTypeName) {
        if (varName == null || varName.isEmpty() || dataTypeName == null || dataTypeName.isEmpty()) {
            return "Both variable name and data type are required";
        }
        
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        
        AtomicReference<String> result = new AtomicReference<>("Variable retype failed");
        
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Retype variable via HTTP");
                try {
                    Function function = findFunctionByName(program, functionName);
                    if (function == null) {
                        result.set("Function not found: " + functionName);
                        return;
                    }
                    
                    // Initialize decompiler
                    DecompInterface decomp = new DecompInterface();
                    decomp.openProgram(program);
                    DecompileResults decompRes = decomp.decompileFunction(function, 30, new ConsoleTaskMonitor());
                    
                    if (decompRes == null || !decompRes.decompileCompleted()) {
                        result.set("Failed to decompile function: " + functionName);
                        return;
                    }
                    
                    HighFunction highFunction = decompRes.getHighFunction();
                    if (highFunction == null) {
                        result.set("Failed to get high function");
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
                        result.set("Variable not found: " + varName);
                        return;
                    }
                    
                    // Find the data type by name
                    DataType dataType = findDataType(program, dataTypeName);
                    if (dataType == null) {
                        result.set("Data type not found: " + dataTypeName);
                        return;
                    }
                    
                    // Retype the variable
                    HighFunctionDBUtil.updateDBVariable(targetSymbol, targetSymbol.getName(), dataType, 
                                                      SourceType.USER_DEFINED);
                    
                    result.set("Variable '" + varName + "' retyped to '" + dataTypeName + "'");
                } catch (Exception e) {
                    Msg.error(this, "Error retyping variable", e);
                    result.set("Error: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, true);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute on Swing thread", e);
            result.set("Error: " + e.getMessage());
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
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                params.put(kv[0], kv[1]);
            }
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
    

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
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
