package eu.starsong.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.starsong.ghidra.api.ResponseBuilder;
import eu.starsong.ghidra.model.ProgramInfo;
import eu.starsong.ghidra.util.GhidraUtil;
import eu.starsong.ghidra.util.HttpUtil;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Endpoints for managing Ghidra programs (binaries).
 * Implements the /programs and /programs/{program_id} endpoints.
 */
public class ProgramEndpoints extends AbstractEndpoint {

    private final PluginTool tool;

    public ProgramEndpoints(Program program, int port, PluginTool tool) {
        super(program, port);
        this.tool = tool;
    }
    
    @Override
    protected PluginTool getTool() {
        return tool;
    }

    @Override
    public void registerEndpoints(HttpServer server) {
        server.createContext("/program", this::handleProgramInfo);
        
        // Register address and function endpoints
        server.createContext("/address", this::handleCurrentAddress);
        server.createContext("/function", this::handleCurrentFunction);
        
        // Register direct analysis endpoints according to HATEOAS API
        server.createContext("/analysis/callgraph", this::handleCallGraph);
    }

    @Override
    protected boolean requiresProgram() {
        // Some operations (like listing programs) don't require a program
        return false;
    }

    /**
     * Handle GET requests to list all programs
     */
    private void handleListPrograms(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQueryParams(exchange);
        String projectName = params.get("project");
        int offset = parseIntOrDefault(params.get("offset"), 0);
        int limit = parseIntOrDefault(params.get("limit"), 100);
        
        List<ProgramInfo> programs = new ArrayList<>();
        Project project = tool.getProject();
        
        if (project == null) {
            sendErrorResponse(exchange, 503, "No project is currently open", "NO_PROJECT_OPEN");
            return;
        }
        
        // If a project name is specified, check if it matches the current project
        if (projectName != null && !projectName.equals(project.getName())) {
            sendErrorResponse(exchange, 404, "Project not found: " + projectName, "PROJECT_NOT_FOUND");
            return;
        }
        
        // Get all domain files from the project
        DomainFolder rootFolder = project.getProjectData().getRootFolder();
        List<DomainFile> allFiles = new ArrayList<>();
        collectDomainFiles(rootFolder, allFiles);
        
        // Filter for program files and convert to ProgramInfo
        for (DomainFile file : allFiles) {
            if (file.getContentType().equals(Program.class.getName())) {
                String programId = project.getName() + ":" + file.getPathname();
                
                ProgramInfo info = ProgramInfo.builder()
                    .programId(programId)
                    .name(file.getName())
                    .isOpen(isProgramOpen(file))
                    .build();
                
                programs.add(info);
            }
        }
        
        // Apply pagination
        int endIndex = Math.min(programs.size(), offset + limit);
        List<ProgramInfo> paginatedPrograms = offset < programs.size() 
            ? programs.subList(offset, endIndex) 
            : new ArrayList<>();
        
        // Build response with pagination links
        ResponseBuilder builder = new ResponseBuilder(exchange, port)
            .success(true)
            .result(paginatedPrograms);
        
        // Add pagination metadata
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("size", programs.size());
        metadata.put("offset", offset);
        metadata.put("limit", limit);
        builder.metadata(metadata);
        
        // Add HATEOAS links
        builder.addLink("self", "/programs?offset=" + offset + "&limit=" + limit);
        
        // Add next/prev links if applicable
        if (endIndex < programs.size()) {
            builder.addLink("next", "/programs?offset=" + endIndex + "&limit=" + limit);
        }
        
        if (offset > 0) {
            int prevOffset = Math.max(0, offset - limit);
            builder.addLink("prev", "/programs?offset=" + prevOffset + "&limit=" + limit);
        }
        
        // Add link to create a new program
        builder.addLink("create", "/programs", "POST");
        
        sendJsonResponse(exchange, builder.build(), 200);
    }

    /**
     * Handle POST requests to import a new program
     */
    private void handleImportProgram(HttpExchange exchange) throws IOException {
        // This is a placeholder - actual implementation would use Ghidra's import API
        // to import a binary file into the project
        sendErrorResponse(exchange, 501, "Program import not implemented", "NOT_IMPLEMENTED");
    }

    /**
     * Handle requests to the /programs/{program_id} endpoint
     */
    private void handleProgramById(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            
            // Check if this is a request for the current program
            if (path.equals("/programs/current")) {
                handleProgramInfo(exchange);
                return;
            }
            
            // Extract program ID from path
            String programIdPath = path.substring("/programs/".length());
            
            // Handle nested resources
            if (programIdPath.contains("/")) {
                handleProgramResource(exchange, programIdPath);
                return;
            }
            
            // Decode the program ID
            String programId = URLDecoder.decode(programIdPath, StandardCharsets.UTF_8);
            
            String method = exchange.getRequestMethod();
            
            if ("GET".equals(method)) {
                // Get program details
                handleGetProgram(exchange, programId);
            } else if ("DELETE".equals(method)) {
                // Close/remove program
                handleDeleteProgram(exchange, programId);
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        } catch (Exception e) {
            Msg.error(this, "Error handling /programs/{program_id} endpoint", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    /**
     * Handle GET requests to get program details
     */
    private void handleGetProgram(HttpExchange exchange, String programId) throws IOException {
        // Parse the program ID to get project and file path
        String[] parts = programId.split(":", 2);
        if (parts.length != 2) {
            sendErrorResponse(exchange, 400, "Invalid program ID format: " + programId, "INVALID_PROGRAM_ID");
            return;
        }
        
        String projectName = parts[0];
        String filePath = parts[1];
        
        Project project = tool.getProject();
        
        if (project == null) {
            sendErrorResponse(exchange, 503, "No project is currently open", "NO_PROJECT_OPEN");
            return;
        }
        
        // Check if the project name matches
        if (!projectName.equals(project.getName())) {
            sendErrorResponse(exchange, 404, "Project not found: " + projectName, "PROJECT_NOT_FOUND");
            return;
        }
        
        // Find the domain file
        DomainFile file = project.getProjectData().getFile(filePath);
        if (file == null) {
            sendErrorResponse(exchange, 404, "Program not found: " + filePath, "PROGRAM_NOT_FOUND");
            return;
        }
        
        // Check if it's a program
        if (!file.getContentType().equals(Program.class.getName())) {
            sendErrorResponse(exchange, 400, "File is not a program: " + filePath, "NOT_A_PROGRAM");
            return;
        }
        
        // Get program details
        ProgramInfo info = getProgramInfo(file);
        
        // Build response with HATEOAS links
        ResponseBuilder builder = new ResponseBuilder(exchange, port)
            .success(true)
            .result(info);
        
        // Add HATEOAS links
        String encodedProgramId = URLDecoder.decode(programId, StandardCharsets.UTF_8);
        builder.addLink("self", "/programs/" + encodedProgramId);
        builder.addLink("project", "/projects/" + projectName);
        
        // Add links to program resources
        builder.addLink("functions", "/programs/" + encodedProgramId + "/functions");
        builder.addLink("symbols", "/programs/" + encodedProgramId + "/symbols");
        builder.addLink("data", "/programs/" + encodedProgramId + "/data");
        builder.addLink("segments", "/programs/" + encodedProgramId + "/segments");
        builder.addLink("memory", "/programs/" + encodedProgramId + "/memory");
        builder.addLink("xrefs", "/programs/" + encodedProgramId + "/xrefs");
        builder.addLink("analysis", "/programs/" + encodedProgramId + "/analysis");
        
        sendJsonResponse(exchange, builder.build(), 200);
    }

    /**
     * Handle DELETE requests to close/remove a program
     */
    private void handleDeleteProgram(HttpExchange exchange, String programId) throws IOException {
        // This is a placeholder - actual implementation would close the program
        // and potentially remove it from the project
        sendErrorResponse(exchange, 501, "Program deletion not implemented", "NOT_IMPLEMENTED");
    }

    /**
     * Handle requests to the /programs/current endpoint
     */
    public void handleProgramInfo(HttpExchange exchange) throws IOException {
        try {
            String method = exchange.getRequestMethod();
            
            if ("GET".equals(method)) {
                // Get current program details
                Program program = getCurrentProgram();

                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program is currently open", "NO_PROGRAM_OPEN");
                    return;
                }
                
                // Get program details
                ProgramInfo info = getCurrentProgramInfo();
                
                // Build response with HATEOAS links
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(info);
                
                // Add HATEOAS links
                builder.addLink("self", "/program");
                
                Project project = tool.getProject();
                if (project != null) {
                    builder.addLink("project", "/projects/" + project.getName());
                }
                
                // Add links to program resources
                builder.addLink("functions", "/functions");
                builder.addLink("symbols", "/symbols");
                builder.addLink("data", "/data");
                builder.addLink("segments", "/segments");
                builder.addLink("memory", "/memory");
                builder.addLink("xrefs", "/xrefs");
                builder.addLink("analysis", "/analysis");
                
                sendJsonResponse(exchange, builder.build(), 200);
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        } catch (Exception e) {
            Msg.error(this, "Error handling /programs/current endpoint", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }
    
    private void handleCurrentSegments(HttpExchange exchange) throws IOException {
        Program program = getCurrentProgram();
        if (program == null) {
            sendErrorResponse(exchange, 400, "No program is currently open", "NO_PROGRAM_OPEN");
            return;
        }
        
        handleSegmentResource(exchange, program, "");
    }
    
    private void handleCurrentFunctions(HttpExchange exchange) throws IOException {
        Program program = getCurrentProgram();
        if (program == null) {
            sendErrorResponse(exchange, 400, "No program is currently open", "NO_PROGRAM_OPEN");
            return;
        }
        
        handleFunctionResource(exchange, program, "");
    }
    
    private void handleFunctionByAddress(HttpExchange exchange) throws IOException {
        Program program = getCurrentProgram();
        if (program == null) {
            sendErrorResponse(exchange, 400, "No program is currently open", "NO_PROGRAM_OPEN");
            return;
        }
        
        String path = exchange.getRequestURI().getPath();
        String fullPath = path.substring("/programs/current/functions/".length());
        
        if (fullPath.isEmpty()) {
            sendErrorResponse(exchange, 404, "Function address is required", "MISSING_ADDRESS");
            return;
        }
        
        // Check if this path contains a trailing resource (like /decompile or /disassembly)
        if (fullPath.contains("/")) {
            int slashIndex = fullPath.indexOf('/');
            String functionAddress = fullPath.substring(0, slashIndex);
            String resource = fullPath.substring(slashIndex + 1);
            
            FunctionEndpoints functionEndpoints = new FunctionEndpoints(program, port);
            
            // Find the function by address
            try {
                ghidra.program.model.address.Address address = program.getAddressFactory().getAddress(functionAddress);
                ghidra.program.model.listing.Function function = program.getFunctionManager().getFunctionAt(address);
                
                if (function == null) {
                    sendErrorResponse(exchange, 404, "Function not found at address: " + functionAddress, "FUNCTION_NOT_FOUND");
                    return;
                }
                
                // Route to the specific handler based on the resource
                if (resource.equals("decompile")) {
                    functionEndpoints.handleDecompileFunction(exchange, function);
                } else if (resource.equals("disassembly")) {
                    functionEndpoints.handleDisassembleFunction(exchange, function);
                } else if (resource.equals("variables")) {
                    functionEndpoints.handleFunctionVariables(exchange, function);
                } else {
                    sendErrorResponse(exchange, 404, "Function resource not found: " + resource, "RESOURCE_NOT_FOUND");
                }
            } catch (Exception e) {
                sendErrorResponse(exchange, 400, "Invalid address format: " + functionAddress, "INVALID_ADDRESS");
            }
        } else {
            // Handle a direct function request without a sub-resource
            FunctionEndpoints functionEndpoints = new FunctionEndpoints(program, port);
            
            try {
                ghidra.program.model.address.Address address = program.getAddressFactory().getAddress(fullPath);
                ghidra.program.model.listing.Function function = program.getFunctionManager().getFunctionAt(address);
                
                if (function == null) {
                    sendErrorResponse(exchange, 404, "Function not found at address: " + fullPath, "FUNCTION_NOT_FOUND");
                    return;
                }
                
                functionEndpoints.handleGetFunction(exchange, function.getName());
            } catch (Exception e) {
                sendErrorResponse(exchange, 400, "Invalid address format: " + fullPath, "INVALID_ADDRESS");
            }
        }
    }
    
    private void handleFunctionByName(HttpExchange exchange) throws IOException {
        Program program = getCurrentProgram();
        if (program == null) {
            sendErrorResponse(exchange, 400, "No program is currently open", "NO_PROGRAM_OPEN");
            return;
        }
        
        String path = exchange.getRequestURI().getPath();
        String fullPath = path.substring("/programs/current/functions/by-name/".length());
        
        if (fullPath.isEmpty()) {
            sendErrorResponse(exchange, 404, "Function name is required", "MISSING_NAME");
            return;
        }
        
        // Check if this path contains a trailing resource (like /variables)
        if (fullPath.contains("/")) {
            int slashIndex = fullPath.indexOf('/');
            String functionName = fullPath.substring(0, slashIndex);
            String resource = fullPath.substring(slashIndex + 1);
            
            FunctionEndpoints functionEndpoints = new FunctionEndpoints(program, port);
            
            // Find the function by name
            ghidra.program.model.listing.Function function = null;
            for (ghidra.program.model.listing.Function f : program.getFunctionManager().getFunctions(true)) {
                if (f.getName().equals(functionName)) {
                    function = f;
                    break;
                }
            }
            
            if (function == null) {
                sendErrorResponse(exchange, 404, "Function not found by name: " + functionName, "FUNCTION_NOT_FOUND");
                return;
            }
            
            // Route to the specific handler based on the resource
            if (resource.equals("variables")) {
                functionEndpoints.handleFunctionVariables(exchange, function);
            } else {
                sendErrorResponse(exchange, 404, "Function resource not found: " + resource, "RESOURCE_NOT_FOUND");
            }
        } else {
            // Handle a direct function request by name
            FunctionEndpoints functionEndpoints = new FunctionEndpoints(program, port);
            functionEndpoints.handleGetFunction(exchange, fullPath);
        }
    }

    /**
     * Handle requests to program resources like /programs/{program_id}/functions
     */
    private void handleProgramResource(HttpExchange exchange, String programIdPath) throws IOException {
        // Split the path into program ID and resource
        int slashIndex = programIdPath.indexOf('/');
        String encodedProgramId = programIdPath.substring(0, slashIndex);
        String resource = programIdPath.substring(slashIndex + 1);
        
        // Decode the program ID
        String programId = URLDecoder.decode(encodedProgramId, StandardCharsets.UTF_8);
        
        // Check if the program ID is "current"
        boolean isCurrentProgram = "current".equals(programId);
        
        // Get the program
        Program program;
        if (isCurrentProgram) {
            // Use getCurrentProgram() which now dynamically checks for program availability
            program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 400, "No program is currently open", "NO_PROGRAM_OPEN");
                return;
            }
            
            Msg.info(this, "Current program found: " + program.getName());
        } else {
            // Parse the program ID to get project and file path
            String[] parts = programId.split(":", 2);
            if (parts.length != 2) {
                sendErrorResponse(exchange, 400, "Invalid program ID format: " + programId, "INVALID_PROGRAM_ID");
                return;
            }
            
            String projectName = parts[0];
            String filePath = parts[1];
            
            Project project = tool.getProject();
            
            if (project == null) {
                sendErrorResponse(exchange, 503, "No project is currently open", "NO_PROJECT_OPEN");
                return;
            }
            
            // Check if the project name matches
            if (!projectName.equals(project.getName())) {
                sendErrorResponse(exchange, 404, "Project not found: " + projectName, "PROJECT_NOT_FOUND");
                return;
            }
            
            // Find the domain file
            DomainFile file = project.getProjectData().getFile(filePath);
            if (file == null) {
                sendErrorResponse(exchange, 404, "Program not found: " + filePath, "PROGRAM_NOT_FOUND");
                return;
            }
            
            // Check if it's a program
            if (!file.getContentType().equals(Program.class.getName())) {
                sendErrorResponse(exchange, 400, "File is not a program: " + filePath, "NOT_A_PROGRAM");
                return;
            }
            
            // Check if the program is open
            program = getOpenProgram(file);
            if (program == null) {
                sendErrorResponse(exchange, 400, "Program is not open: " + filePath, "PROGRAM_NOT_OPEN");
                return;
            }
            
            Msg.info(this, "Program found via ID: " + program.getName());
        }
        
        // Delegate to the appropriate resource handler based on the resource path
        if (resource.startsWith("functions")) {
            // Log the delegation
            Msg.info(this, "Delegating to FunctionEndpoints: " + resource);
            
            // Delegate to FunctionEndpoints with the current program and path
            handleFunctionResource(exchange, program, resource.substring("functions".length()));
        } else if (resource.startsWith("symbols")) {
            // Delegate to SymbolEndpoints
            handleSymbolResource(exchange, program, resource.substring("symbols".length()));
        } else if (resource.startsWith("data")) {
            // Delegate to DataEndpoints
            handleDataResource(exchange, program, resource.substring("data".length()));
        } else if (resource.startsWith("segments")) {
            // Delegate to SegmentEndpoints
            handleSegmentResource(exchange, program, resource.substring("segments".length()));
        } else if (resource.startsWith("memory")) {
            // Delegate to MemoryEndpoints
            handleMemoryResource(exchange, program, resource.substring("memory".length()));
        } else if (resource.startsWith("xrefs")) {
            // Delegate to XrefEndpoints
            handleXrefResource(exchange, program, resource.substring("xrefs".length()));
        } else if (resource.startsWith("analysis")) {
            // Delegate to AnalysisEndpoints
            handleAnalysisResource(exchange, program, resource.substring("analysis".length()));
        } else {
            sendErrorResponse(exchange, 404, "Program resource not found: " + resource, "RESOURCE_NOT_FOUND");
        }
    }

    /**
     * Helper method to collect all domain files in a folder recursively
     */
    private void collectDomainFiles(DomainFolder folder, List<DomainFile> files) {
        for (DomainFile file : folder.getFiles()) {
            files.add(file);
        }
        
        for (DomainFolder subFolder : folder.getFolders()) {
            collectDomainFiles(subFolder, files);
        }
    }

    /**
     * Helper method to check if a program is open
     */
    private boolean isProgramOpen(DomainFile file) {
        ProgramManager programManager = tool.getService(ProgramManager.class);
        if (programManager == null) {
            return false;
        }
        
        for (Program program : programManager.getAllOpenPrograms()) {
            if (program.getDomainFile().equals(file)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Helper method to get an open program by domain file
     */
    private Program getOpenProgram(DomainFile file) {
        ProgramManager programManager = tool.getService(ProgramManager.class);
        if (programManager == null) {
            return null;
        }
        
        for (Program program : programManager.getAllOpenPrograms()) {
            if (program.getDomainFile().equals(file)) {
                return program;
            }
        }
        
        return null;
    }

    /**
     * Helper method to get program info for a domain file
     */
    private ProgramInfo getProgramInfo(DomainFile file) {
        Project project = tool.getProject();
        String programId = project.getName() + ":" + file.getPathname();
        
        // Check if the program is open
        Program program = getOpenProgram(file);
        boolean isOpen = program != null;
        
        ProgramInfo.Builder builder = ProgramInfo.builder()
            .programId(programId)
            .name(file.getName())
            .isOpen(isOpen);
        
        // Add additional info if the program is open
        if (isOpen) {
            builder.languageId(program.getLanguage().getLanguageID().getIdAsString())
                  .compilerSpecId(program.getCompilerSpec().getCompilerSpecID().getIdAsString());
            
            // Get image base
            Address imageBase = program.getImageBase();
            if (imageBase != null) {
                builder.imageBase(imageBase.toString());
            }
            
            // Get memory size
            long memorySize = program.getMemory().getSize();
            builder.memorySize(memorySize);
            
            // Check if analysis is complete (this is a placeholder - actual implementation would check analysis status)
            builder.analysisComplete(true);
        }
        
        return builder.build();
    }

    /**
     * Helper method to get info for the current program
     */
    private ProgramInfo getCurrentProgramInfo() {
        Program program = getCurrentProgram();
        if (program == null) {
            return null;
        }
        
        Project project = tool.getProject();
        String projectName = project != null ? project.getName() : "unknown";
        String programId = projectName + ":" + program.getDomainFile().getPathname();
        
        ProgramInfo.Builder builder = ProgramInfo.builder()
            .programId(programId)
            .name(program.getName())
            .isOpen(true)
            .languageId(program.getLanguage().getLanguageID().getIdAsString())
            .compilerSpecId(program.getCompilerSpec().getCompilerSpecID().getIdAsString());
        
        // Get image base
        Address imageBase = program.getImageBase();
        if (imageBase != null) {
            builder.imageBase(imageBase.toString());
        }
        
        // Get memory size
        long memorySize = program.getMemory().getSize();
        builder.memorySize(memorySize);
        
        // Check if analysis is complete (this is a placeholder - actual implementation would check analysis status)
        builder.analysisComplete(true);
        
        return builder.build();
    }
    
    /**
     * Handle function resources like /programs/{program_id}/functions
     */
    private void handleFunctionResource(HttpExchange exchange, Program program, String path) throws IOException {
        FunctionEndpoints functionEndpoints = new FunctionEndpoints(program, port);
        
        if (path.isEmpty() || path.equals("/")) {
            functionEndpoints.handleFunctions(exchange);
        } else if (path.startsWith("/")) {
            String addressOrResource = path.substring(1);
            try {
                // Call the method using reflection to bypass access control
                java.lang.reflect.Method method = FunctionEndpoints.class.getDeclaredMethod("handleFunction", HttpExchange.class, String.class);
                method.setAccessible(true);
                method.invoke(functionEndpoints, exchange, "/functions/" + addressOrResource);
            } catch (Exception e) {
                sendErrorResponse(exchange, 500, "Error routing function request: " + e.getMessage(), "ROUTING_ERROR");
            }
        } else {
            sendErrorResponse(exchange, 404, "Function resource not found: " + path, "RESOURCE_NOT_FOUND");
        }
    }
    
    /**
     * Handle symbol resources like /programs/{program_id}/symbols
     */
    private void handleSymbolResource(HttpExchange exchange, Program program, String path) throws IOException {
        // This is a placeholder - actual implementation would delegate to SymbolEndpoints
        sendErrorResponse(exchange, 501, "Symbol resources not implemented", "NOT_IMPLEMENTED");
    }
    
    /**
     * Handle data resources like /programs/{program_id}/data
     */
    private void handleDataResource(HttpExchange exchange, Program program, String path) throws IOException {
        // This is a placeholder - actual implementation would delegate to DataEndpoints
        sendErrorResponse(exchange, 501, "Data resources not implemented", "NOT_IMPLEMENTED");
    }
    
    /**
     * Handle segment resources like /programs/{program_id}/segments
     */
    private void handleSegmentResource(HttpExchange exchange, Program program, String path) throws IOException {
        try {
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                return;
            }
            
            // Check if this is a request for a specific segment or the list of segments
            if (path.isEmpty() || path.equals("/")) {
                // List all segments
                Map<String, String> params = parseQueryParams(exchange);
                int offset = parseIntOrDefault(params.get("offset"), 0);
                int limit = parseIntOrDefault(params.get("limit"), 100);
                String nameFilter = params.get("name");
                
                List<Map<String, Object>> segments = new ArrayList<>();
                ghidra.program.model.mem.Memory memory = program.getMemory();
                
                // Iterate through memory blocks
                for (ghidra.program.model.mem.MemoryBlock block : memory.getBlocks()) {
                    // Apply name filter if specified
                    if (nameFilter != null && !block.getName().contains(nameFilter)) {
                        continue;
                    }
                    
                    Map<String, Object> segment = new HashMap<>();
                    segment.put("name", block.getName());
                    segment.put("start", block.getStart().toString());
                    segment.put("end", block.getEnd().toString());
                    segment.put("size", block.getSize());
                    segment.put("readable", block.isRead());
                    segment.put("writable", block.isWrite());
                    segment.put("executable", block.isExecute());
                    segment.put("initialized", block.isInitialized());
                    
                    // Add HATEOAS links
                    Map<String, Object> links = new HashMap<>();
                    Map<String, String> selfLink = new HashMap<>();
                    selfLink.put("href", "/programs/current/segments/" + block.getName());
                    links.put("self", selfLink);
                    segment.put("_links", links);
                    
                    segments.add(segment);
                }
                
                // Apply pagination
                int endIndex = Math.min(segments.size(), offset + limit);
                List<Map<String, Object>> paginatedSegments = offset < segments.size() 
                    ? segments.subList(offset, endIndex) 
                    : new ArrayList<>();
                
                // Build response
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(paginatedSegments);
                
                // Add pagination metadata
                Map<String, Object> metadata = new HashMap<>();
                metadata.put("size", segments.size());
                metadata.put("offset", offset);
                metadata.put("limit", limit);
                builder.metadata(metadata);
                
                // Add HATEOAS links
                StringBuilder selfLinkBuilder = new StringBuilder("/programs/current/segments?offset=").append(offset).append("&limit=").append(limit);
                if (nameFilter != null) {
                    selfLinkBuilder.append("&name=").append(nameFilter);
                }
                builder.addLink("self", selfLinkBuilder.toString());
                
                // Add next/prev links if applicable
                if (endIndex < segments.size()) {
                    StringBuilder nextLinkBuilder = new StringBuilder("/programs/current/segments?offset=").append(endIndex).append("&limit=").append(limit);
                    if (nameFilter != null) {
                        nextLinkBuilder.append("&name=").append(nameFilter);
                    }
                    builder.addLink("next", nextLinkBuilder.toString());
                }
                
                if (offset > 0) {
                    int prevOffset = Math.max(0, offset - limit);
                    StringBuilder prevLinkBuilder = new StringBuilder("/programs/current/segments?offset=").append(prevOffset).append("&limit=").append(limit);
                    if (nameFilter != null) {
                        prevLinkBuilder.append("&name=").append(nameFilter);
                    }
                    builder.addLink("prev", prevLinkBuilder.toString());
                }
                
                sendJsonResponse(exchange, builder.build(), 200);
            } else {
                // Handle request for a specific segment
                String segmentName = path.startsWith("/") ? path.substring(1) : path;
                
                // Find the requested memory block
                ghidra.program.model.mem.Memory memory = program.getMemory();
                ghidra.program.model.mem.MemoryBlock block = null;
                
                for (ghidra.program.model.mem.MemoryBlock b : memory.getBlocks()) {
                    if (b.getName().equals(segmentName)) {
                        block = b;
                        break;
                    }
                }
                
                if (block == null) {
                    sendErrorResponse(exchange, 404, "Segment not found: " + segmentName, "SEGMENT_NOT_FOUND");
                    return;
                }
                
                // Build segment details
                Map<String, Object> segment = new HashMap<>();
                segment.put("name", block.getName());
                segment.put("start", block.getStart().toString());
                segment.put("end", block.getEnd().toString());
                segment.put("size", block.getSize());
                segment.put("readable", block.isRead());
                segment.put("writable", block.isWrite());
                segment.put("executable", block.isExecute());
                segment.put("initialized", block.isInitialized());
                
                if (block.getComment() != null) {
                    segment.put("comment", block.getComment());
                }
                
                // For initialized blocks, add additional info
                if (block.isInitialized()) {
                    segment.put("source_type", "Memory Block");
                    if (block.getName() != null) {
                        segment.put("source_name", block.getName());
                    }
                }
                
                // Build response
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(segment);
                
                // Add HATEOAS links
                builder.addLink("self", "/programs/current/segments/" + segmentName);
                builder.addLink("program", "/programs/current");
                builder.addLink("segments", "/programs/current/segments");
                builder.addLink("memory", "/programs/current/memory/" + block.getStart().toString() + "?length=1024");
                
                sendJsonResponse(exchange, builder.build(), 200);
            }
        } catch (Exception e) {
            Msg.error(this, "Error handling segment resource", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }
    
    /**
     * Handle memory resources like /programs/{program_id}/memory
     */
    private void handleMemoryResource(HttpExchange exchange, Program program, String path) throws IOException {
        try {
            String method = exchange.getRequestMethod();
            
            if (path.isEmpty() || path.equals("/")) {
                sendErrorResponse(exchange, 400, "Memory address is required", "MISSING_ADDRESS");
                return;
            }
            
            String addressStr = path.startsWith("/") ? path.substring(1) : path;
            Map<String, String> params = parseQueryParams(exchange);
            
            // Get required parameters
            int length = parseIntOrDefault(params.get("length"), 16);
            String format = params.getOrDefault("format", "hex");
            
            if (length <= 0 || length > 4096) { // Set reasonable limits
                sendErrorResponse(exchange, 400, "Invalid length parameter (must be between 1 and 4096)", "INVALID_PARAMETER");
                return;
            }
            
            if (!format.equals("hex") && !format.equals("base64") && !format.equals("string")) {
                sendErrorResponse(exchange, 400, "Invalid format parameter (must be 'hex', 'base64', or 'string')", "INVALID_PARAMETER");
                return;
            }
            
            // Parse address
            ghidra.program.model.address.Address address;
            try {
                address = program.getAddressFactory().getAddress(addressStr);
            } catch (Exception e) {
                sendErrorResponse(exchange, 400, "Invalid address format: " + addressStr, "INVALID_ADDRESS");
                return;
            }
            
            if ("GET".equals(method)) {
                // Read memory
                byte[] bytes = new byte[length];
                try {
                    program.getMemory().getBytes(address, bytes);
                } catch (Exception e) {
                    sendErrorResponse(exchange, 400, "Error reading memory: " + e.getMessage(), "READ_ERROR");
                    return;
                }
                
                // Format bytes according to the requested format
                String formattedBytes;
                if (format.equals("hex")) {
                    formattedBytes = bytesToHex(bytes);
                } else if (format.equals("base64")) {
                    formattedBytes = java.util.Base64.getEncoder().encodeToString(bytes);
                } else { // string
                    formattedBytes = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
                }
                
                // Build response
                Map<String, Object> result = new HashMap<>();
                result.put("address", addressStr);
                result.put("length", length);
                result.put("format", format);
                result.put("bytes", formattedBytes);
                
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(result);
                
                // Add HATEOAS links
                builder.addLink("self", "/programs/current/memory/" + addressStr + "?length=" + length + "&format=" + format);
                
                sendJsonResponse(exchange, builder.build(), 200);
            } else if ("PATCH".equals(method)) {
                // Write memory - this is a dangerous operation and should be used with caution
                Map<String, String> payload = parseJsonPostParams(exchange);
                String bytesStr = payload.get("bytes");
                String inputFormat = payload.getOrDefault("format", "hex");
                
                if (bytesStr == null || bytesStr.isEmpty()) {
                    sendErrorResponse(exchange, 400, "Missing bytes parameter", "MISSING_PARAMETER");
                    return;
                }
                
                if (!inputFormat.equals("hex") && !inputFormat.equals("base64") && !inputFormat.equals("string")) {
                    sendErrorResponse(exchange, 400, "Invalid format parameter (must be 'hex', 'base64', or 'string')", "INVALID_PARAMETER");
                    return;
                }
                
                // Parse bytes according to the input format
                byte[] bytes;
                try {
                    if (inputFormat.equals("hex")) {
                        bytes = hexToBytes(bytesStr);
                    } else if (inputFormat.equals("base64")) {
                        bytes = java.util.Base64.getDecoder().decode(bytesStr);
                    } else { // string
                        bytes = bytesStr.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    }
                } catch (Exception e) {
                    sendErrorResponse(exchange, 400, "Invalid bytes format: " + e.getMessage(), "INVALID_PARAMETER");
                    return;
                }
                
                // Write bytes to memory
                try {
                    TransactionHelper.executeInTransaction(program, "Write memory at " + addressStr, () -> {
                        program.getMemory().setBytes(address, bytes);
                        return null;
                    });
                } catch (Exception e) {
                    sendErrorResponse(exchange, 400, "Error writing memory: " + e.getMessage(), "WRITE_ERROR");
                    return;
                }
                
                // Build response
                Map<String, Object> result = new HashMap<>();
                result.put("address", addressStr);
                result.put("length", bytes.length);
                result.put("bytesWritten", bytes.length);
                
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(result);
                
                sendJsonResponse(exchange, builder.build(), 200);
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        } catch (Exception e) {
            Msg.error(this, "Error handling memory resource", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }
    
    // Helper method to convert bytes to hex string
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
    
    // Helper method to convert hex string to bytes
    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                             + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
    
    /**
     * Handle xref resources like /programs/{program_id}/xrefs
     */
    private void handleXrefResource(HttpExchange exchange, Program program, String path) throws IOException {
        try {
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                return;
            }
            
            Map<String, String> params = parseQueryParams(exchange);
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            String toAddrStr = params.get("to_addr");
            String fromAddrStr = params.get("from_addr");
            String refType = params.get("type");
            
            // At least one of to_addr or from_addr must be specified
            if (toAddrStr == null && fromAddrStr == null) {
                sendErrorResponse(exchange, 400, "Either to_addr or from_addr parameter is required", "MISSING_PARAMETER");
                return;
            }
            
            // Convert addresses to Ghidra Address objects
            ghidra.program.model.address.Address toAddr = null;
            ghidra.program.model.address.Address fromAddr = null;
            
            if (toAddrStr != null) {
                try {
                    toAddr = program.getAddressFactory().getAddress(toAddrStr);
                } catch (Exception e) {
                    sendErrorResponse(exchange, 400, "Invalid to_addr format: " + toAddrStr, "INVALID_ADDRESS");
                    return;
                }
            }
            
            if (fromAddrStr != null) {
                try {
                    fromAddr = program.getAddressFactory().getAddress(fromAddrStr);
                } catch (Exception e) {
                    sendErrorResponse(exchange, 400, "Invalid from_addr format: " + fromAddrStr, "INVALID_ADDRESS");
                    return;
                }
            }
            
            // Find references based on the provided parameters
            List<Map<String, Object>> xrefs = new ArrayList<>();
            
            // Get references to an address
            if (toAddr != null) {
                // Get references to this address
                ghidra.program.model.symbol.ReferenceManager refManager = program.getReferenceManager();
                ghidra.program.model.symbol.ReferenceIterator refsIterator = refManager.getReferencesTo(toAddr);
                
                while (refsIterator.hasNext()) {
                    ghidra.program.model.symbol.Reference ref = refsIterator.next();
                    
                    // Skip if type filter is specified and doesn't match
                    if (refType != null && !refTypeMatches(ref, refType)) {
                        continue;
                    }
                    
                    // Get reference info
                    Map<String, Object> refInfo = new HashMap<>();
                    refInfo.put("from_addr", ref.getFromAddress().toString());
                    refInfo.put("to_addr", ref.getToAddress().toString());
                    refInfo.put("type", getReferenceTypeName(ref.getReferenceType()));
                    
                    // Get additional context if available
                    refInfo.put("from_function", getFunctionName(program, ref.getFromAddress()));
                    refInfo.put("to_function", getFunctionName(program, ref.getToAddress()));
                    
                    xrefs.add(refInfo);
                }
            }
            
            // Get references from an address
            if (fromAddr != null && (toAddr == null || xrefs.isEmpty())) {
                // Get references from this address
                ghidra.program.model.symbol.ReferenceManager refManager = program.getReferenceManager();
                ghidra.program.model.symbol.Reference[] refs = refManager.getReferencesFrom(fromAddr);
                
                for (ghidra.program.model.symbol.Reference ref : refs) {
                    
                    // Skip if type filter is specified and doesn't match
                    if (refType != null && !refTypeMatches(ref, refType)) {
                        continue;
                    }
                    
                    // Get reference info
                    Map<String, Object> refInfo = new HashMap<>();
                    refInfo.put("from_addr", ref.getFromAddress().toString());
                    refInfo.put("to_addr", ref.getToAddress().toString());
                    refInfo.put("type", getReferenceTypeName(ref.getReferenceType()));
                    
                    // Get additional context if available
                    refInfo.put("from_function", getFunctionName(program, ref.getFromAddress()));
                    refInfo.put("to_function", getFunctionName(program, ref.getToAddress()));
                    
                    xrefs.add(refInfo);
                }
            }
            
            // Apply pagination
            int endIndex = Math.min(xrefs.size(), offset + limit);
            List<Map<String, Object>> paginatedXrefs = offset < xrefs.size() 
                ? xrefs.subList(offset, endIndex) 
                : new ArrayList<>();
            
            // Build response
            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                .success(true)
                .result(paginatedXrefs);
            
            // Add pagination metadata
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("size", xrefs.size());
            metadata.put("offset", offset);
            metadata.put("limit", limit);
            builder.metadata(metadata);
            
            // Add HATEOAS links
            StringBuilder selfLinkBuilder = new StringBuilder("/programs/current/xrefs?offset=").append(offset).append("&limit=").append(limit);
            if (toAddrStr != null) {
                selfLinkBuilder.append("&to_addr=").append(toAddrStr);
            }
            if (fromAddrStr != null) {
                selfLinkBuilder.append("&from_addr=").append(fromAddrStr);
            }
            if (refType != null) {
                selfLinkBuilder.append("&type=").append(refType);
            }
            builder.addLink("self", selfLinkBuilder.toString());
            
            // Add next/prev links if applicable
            if (endIndex < xrefs.size()) {
                StringBuilder nextLinkBuilder = new StringBuilder("/programs/current/xrefs?offset=").append(endIndex).append("&limit=").append(limit);
                if (toAddrStr != null) {
                    nextLinkBuilder.append("&to_addr=").append(toAddrStr);
                }
                if (fromAddrStr != null) {
                    nextLinkBuilder.append("&from_addr=").append(fromAddrStr);
                }
                if (refType != null) {
                    nextLinkBuilder.append("&type=").append(refType);
                }
                builder.addLink("next", nextLinkBuilder.toString());
            }
            
            if (offset > 0) {
                int prevOffset = Math.max(0, offset - limit);
                StringBuilder prevLinkBuilder = new StringBuilder("/programs/current/xrefs?offset=").append(prevOffset).append("&limit=").append(limit);
                if (toAddrStr != null) {
                    prevLinkBuilder.append("&to_addr=").append(toAddrStr);
                }
                if (fromAddrStr != null) {
                    prevLinkBuilder.append("&from_addr=").append(fromAddrStr);
                }
                if (refType != null) {
                    prevLinkBuilder.append("&type=").append(refType);
                }
                builder.addLink("prev", prevLinkBuilder.toString());
            }
            
            sendJsonResponse(exchange, builder.build(), 200);
        } catch (Exception e) {
            Msg.error(this, "Error handling xref resource", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }
    
    /**
     * Helper method to get function name for an address
     */
    private String getFunctionName(Program program, ghidra.program.model.address.Address addr) {
        ghidra.program.model.listing.Function function = program.getFunctionManager().getFunctionContaining(addr);
        return function != null ? function.getName() : null;
    }
    
    /**
     * Helper method to check if a reference type matches a filter
     */
    private boolean refTypeMatches(ghidra.program.model.symbol.Reference ref, String filter) {
        String refTypeName = getReferenceTypeName(ref.getReferenceType());
        return refTypeName.equalsIgnoreCase(filter);
    }
    
    /**
     * Helper method to get a human-readable name for a reference type
     */
    private String getReferenceTypeName(ghidra.program.model.symbol.RefType refType) {
        if (refType.isCall()) {
            return "CALL";
        } else if (refType.isData()) {
            return "DATA";
        } else if (refType.isRead()) {
            return "READ";
        } else if (refType.isWrite()) {
            return "WRITE";
        } else if (refType.isJump()) {
            return "JUMP";
        } else { 
            // Properly handle Ghidra's actual reference types
            String typeString = refType.toString();
            if (typeString.contains("POINTER")) {
                return "POINTER";
            }
            return typeString;
        }
    }
    
    /**
     * Handle analysis resources like /programs/{program_id}/analysis
     */
    private void handleAnalysisResource(HttpExchange exchange, Program program, String path) throws IOException {
        try {
            String method = exchange.getRequestMethod();
            
            // Check if this is a request for a specific analysis resource
            if (path.isEmpty() || path.equals("/")) {
                // Default analysis endpoint - can be extended to provide analysis status
                if ("GET".equals(method)) {
                    // Return basic analysis info
                    Map<String, Object> analysisInfo = new HashMap<>();
                    analysisInfo.put("program", program.getName());
                    analysisInfo.put("analysis_enabled", true); // Simplified version
                    
                    // Get list of analyzers (this is a simplified version)
                    List<String> analyzers = new ArrayList<>();
                    analyzers.add("Function Start Analyzer");
                    analyzers.add("Basic Block Model Analyzer");
                    analyzers.add("Reference Analyzer");
                    analyzers.add("Call Convention Analyzer");
                    analyzers.add("Data Reference Analyzer");
                    analyzers.add("Decompiler Parameter ID");
                    analyzers.add("Stack Analyzer");
                    // ... add other analyzers as needed
                    
                    analysisInfo.put("available_analyzers", analyzers);
                    
                    // Build response
                    ResponseBuilder builder = new ResponseBuilder(exchange, port)
                        .success(true)
                        .result(analysisInfo);
                    
                    // Add HATEOAS links
                    builder.addLink("self", "/programs/current/analysis");
                    builder.addLink("program", "/programs/current");
                    builder.addLink("analyze", "/programs/current/analysis", "POST");
                    builder.addLink("callgraph", "/programs/current/analysis/callgraph");
                    
                    sendJsonResponse(exchange, builder.build(), 200);
                } else if ("POST".equals(method)) {
                    // Trigger analysis
                    handleRunAnalysis(exchange, program);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } else if (path.equals("/callgraph") || path.startsWith("/callgraph/")) {
                // Handle call graph generation - for backward compatibility 
                handleCallGraph(exchange);
            } else if (path.equals("/dataflow") || path.startsWith("/dataflow/")) {
                // Handle data flow analysis
                handleDataFlow(exchange, program, path);
            } else {
                sendErrorResponse(exchange, 404, "Analysis resource not found: " + path, "RESOURCE_NOT_FOUND");
            }
        } catch (Exception e) {
            Msg.error(this, "Error handling analysis resource", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }
    
    /**
     * Handle GET requests to the /programs/current/address endpoint to get the current cursor position
     * @param exchange The HTTP exchange
     * @throws IOException If an I/O error occurs
     */
    public void handleCurrentAddress(HttpExchange exchange) throws IOException {
        try {
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                return;
            }
            
            if (tool == null) {
                sendErrorResponse(exchange, 503, "Tool not available", "TOOL_NOT_AVAILABLE");
                return;
            }
            
            // Get the current address
            String currentAddress = GhidraUtil.getCurrentAddressString(tool);
            if (currentAddress == null) {
                sendErrorResponse(exchange, 404, "Current address not available", "ADDRESS_NOT_AVAILABLE");
                return;
            }
            
            // Build response
            Map<String, Object> result = new HashMap<>();
            result.put("address", currentAddress);
            
            // Get program name if available
            Program program = getCurrentProgram();
            if (program != null) {
                result.put("program", program.getName());
            }
            
            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                .success(true)
                .result(result);
            
            // Add HATEOAS links
            builder.addLink("self", "/address");
            builder.addLink("program", "/program");
            
            // If we have a current program, add a link to get memory at this address
            if (program != null) {
                builder.addLink("memory", "/memory/" + currentAddress + "?length=16");
                
                // Check if this address is within a function
                ghidra.program.model.listing.Function function = program.getFunctionManager().getFunctionContaining(
                    program.getAddressFactory().getAddress(currentAddress));
                
                if (function != null) {
                    builder.addLink("function", "/functions/" + function.getEntryPoint().toString());
                    builder.addLink("decompile", "/functions/" + function.getEntryPoint().toString() + "/decompile");
                }
            }
            
            sendJsonResponse(exchange, builder.build(), 200);
        } catch (Exception e) {
            Msg.error(this, "Error handling current address endpoint", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }
    
    /**
     * Handle GET requests to the /programs/current/function endpoint to get the current function
     * @param exchange The HTTP exchange
     * @throws IOException If an I/O error occurs
     */
    public void handleCurrentFunction(HttpExchange exchange) throws IOException {
        try {
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                return;
            }
            
            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM");
                return;
            }
            
            if (tool == null) {
                sendErrorResponse(exchange, 503, "Tool not available", "TOOL_NOT_AVAILABLE");
                return;
            }
            
            // Get the current function info
            Map<String, Object> functionInfo = GhidraUtil.getCurrentFunctionInfo(tool, program);
            if (functionInfo.isEmpty()) {
                sendErrorResponse(exchange, 404, "Current function not available", "FUNCTION_NOT_AVAILABLE");
                return;
            }
            
            // Build response
            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                .success(true)
                .result(functionInfo);
            
            // Add HATEOAS links
            builder.addLink("self", "/function");
            builder.addLink("program", "/program");
            
            // Add links to function-specific resources
            if (functionInfo.containsKey("address")) {
                String functionAddress = (String) functionInfo.get("address");
                builder.addLink("function", "/functions/" + functionAddress);
                builder.addLink("decompile", "/functions/" + functionAddress + "/decompile");
                builder.addLink("disassembly", "/functions/" + functionAddress + "/disassembly");
                builder.addLink("variables", "/functions/" + functionAddress + "/variables");
                builder.addLink("xrefs", "/xrefs?to_addr=" + functionAddress);
            }
            
            sendJsonResponse(exchange, builder.build(), 200);
        } catch (Exception e) {
            Msg.error(this, "Error handling current function endpoint", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }
    
    /**
     * Handle request to run analysis on a program
     */
    private void handleRunAnalysis(HttpExchange exchange, Program program) throws IOException {
        try {
            // Parse request body
            Map<String, String> params = parseJsonPostParams(exchange);
            
            // Configure and run analysis based on request parameters
            boolean success = TransactionHelper.executeInTransaction(program, "Run analysis on " + program.getName(), () -> {
                try {
                    // In a real implementation, you would configure analyzers based on the request
                    program.flushEvents();
                    return true;
                } catch (Exception e) {
                    Msg.error(this, "Error during analysis transaction", e);
                    return false;
                }
            });
            
            if (success) {
                // Build success response
                Map<String, Object> result = new HashMap<>();
                result.put("program", program.getName());
                result.put("analysis_triggered", true);
                result.put("message", "Analysis initiated on program");
                
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(result);
                
                sendJsonResponse(exchange, builder.build(), 200);
            } else {
                sendErrorResponse(exchange, 500, "Failed to initiate analysis", "ANALYSIS_FAILED");
            }
        } catch (Exception e) {
            Msg.error(this, "Error running analysis", e);
            sendErrorResponse(exchange, 500, "Error running analysis: " + e.getMessage(), "ANALYSIS_ERROR");
        }
    }
    
    /**
     * Handle call graph generation
     */
    private void handleCallGraph(HttpExchange exchange) throws IOException {
        Program program = getCurrentProgram();
        if (program == null) {
            sendErrorResponse(exchange, 400, "No program is currently open", "NO_PROGRAM_OPEN");
            return;
        }
        
        String path = "";
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            return;
        }
        
        try {
            Map<String, String> params = parseQueryParams(exchange);
            // Support both function name and address as separate parameters
            String name = params.get("name");
            String address = params.get("address");
            // For backward compatibility, also check "function" parameter
            if (name == null) {
                name = params.get("function");
            }
            int maxDepth = parseIntOrDefault(params.get("max_depth"), 3);
            
            // Get starting function
            ghidra.program.model.listing.Function startFunction = null;
            
            // Try to find function by address first (if provided)
            if (address != null) {
                try {
                    ghidra.program.model.address.Address addr = program.getAddressFactory().getAddress(address);
                    startFunction = program.getFunctionManager().getFunctionAt(addr);
                    
                    if (startFunction == null) {
                        sendErrorResponse(exchange, 404, "Function not found at address: " + address, "FUNCTION_NOT_FOUND");
                        return;
                    }
                } catch (Exception e) {
                    sendErrorResponse(exchange, 400, "Invalid address format: " + address, "INVALID_ADDRESS");
                    return;
                }
            } 
            // Try to find function by name if address not provided or function not found
            else if (name != null) {
                for (ghidra.program.model.listing.Function f : program.getFunctionManager().getFunctions(true)) {
                    if (f.getName().equals(name)) {
                        startFunction = f;
                        break;
                    }
                }
                
                if (startFunction == null) {
                    sendErrorResponse(exchange, 404, "Function not found by name: " + name, "FUNCTION_NOT_FOUND");
                    return;
                }
            } else {
                // Use the entry point function if no function is specified by name or address
                ghidra.program.model.address.Address entryPoint = program.getSymbolTable().getExternalEntryPointIterator().hasNext() ?
                    program.getSymbolTable().getExternalEntryPointIterator().next() :
                    program.getImageBase();
                    
                startFunction = program.getFunctionManager().getFunctionAt(entryPoint);
                
                if (startFunction == null) {
                    sendErrorResponse(exchange, 404, "No entry point function found", "ENTRY_POINT_NOT_FOUND");
                    return;
                }
            }
            
            // Build call graph (this is a simplified implementation)
            Map<String, Object> graph = buildCallGraph(program, startFunction, maxDepth);
            
            // Build response
            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                .success(true)
                .result(graph);
            
            // Add HATEOAS links
            StringBuilder selfLinkBuilder = new StringBuilder("/programs/current/analysis/callgraph");
            boolean hasParam = false;
            
            // Add appropriate parameters to self link
            if (address != null) {
                selfLinkBuilder.append("?address=").append(address);
                hasParam = true;
            } else if (name != null) {
                selfLinkBuilder.append("?name=").append(name);
                hasParam = true;
            }
            
            if (hasParam) {
                selfLinkBuilder.append("&max_depth=").append(maxDepth);
            } else {
                selfLinkBuilder.append("?max_depth=").append(maxDepth);
            }
            
            builder.addLink("self", selfLinkBuilder.toString());
            builder.addLink("program", "/programs/current");
            builder.addLink("function", "/programs/current/functions/" + startFunction.getEntryPoint().toString());
            
            sendJsonResponse(exchange, builder.build(), 200);
        } catch (Exception e) {
            Msg.error(this, "Error generating call graph", e);
            sendErrorResponse(exchange, 500, "Error generating call graph: " + e.getMessage(), "CALLGRAPH_ERROR");
        }
    }
    
    /**
     * Build a call graph starting from a given function up to a maximum depth
     */
    private Map<String, Object> buildCallGraph(Program program, ghidra.program.model.listing.Function startFunction, int maxDepth) {
        Map<String, Object> graph = new HashMap<>();
        graph.put("root", startFunction.getName());
        graph.put("root_address", startFunction.getEntryPoint().toString());
        graph.put("max_depth", maxDepth);
        
        // Build nodes list
        List<Map<String, Object>> nodes = new ArrayList<>();
        
        // Build edges list
        List<Map<String, Object>> edges = new ArrayList<>();
        
        // Keep track of processed functions to avoid cycles
        java.util.Set<String> processedFunctions = new java.util.HashSet<>();
        
        // Build graph recursively
        buildCallGraphRecursive(program, startFunction, nodes, edges, processedFunctions, 0, maxDepth);
        
        graph.put("nodes", nodes);
        graph.put("edges", edges);
        
        return graph;
    }
    
    /**
     * Recursively build a call graph by traversing function calls
     */
    private void buildCallGraphRecursive(
            Program program, 
            ghidra.program.model.listing.Function function, 
            List<Map<String, Object>> nodes, 
            List<Map<String, Object>> edges, 
            java.util.Set<String> processedFunctions, 
            int currentDepth, 
            int maxDepth) {
        
        // Add this function as a node if it hasn't been processed yet
        String functionId = function.getEntryPoint().toString();
        if (!processedFunctions.contains(functionId)) {
            Map<String, Object> node = new HashMap<>();
            node.put("id", functionId);
            node.put("name", function.getName());
            node.put("address", function.getEntryPoint().toString());
            node.put("depth", currentDepth);
            
            // Add node links
            Map<String, Object> nodeLinks = new HashMap<>();
            Map<String, String> selfLink = new HashMap<>();
            selfLink.put("href", "/programs/current/functions/" + function.getEntryPoint().toString());
            nodeLinks.put("self", selfLink);
            node.put("_links", nodeLinks);
            
            nodes.add(node);
            processedFunctions.add(functionId);
            
            // Stop recursion if we've reached max depth
            if (currentDepth >= maxDepth) {
                return;
            }
            
            // Find all called functions
            ghidra.program.model.symbol.ReferenceManager refManager = program.getReferenceManager();
            ghidra.program.model.address.AddressSetView functionBody = function.getBody();
            ghidra.program.model.address.AddressIterator addresses = functionBody.getAddresses(true);
            
            while (addresses.hasNext()) {
                ghidra.program.model.address.Address address = addresses.next();
                ghidra.program.model.symbol.Reference[] refs = refManager.getReferencesFrom(address);
                
                for (ghidra.program.model.symbol.Reference ref : refs) {
                    
                    // Only consider call references
                    if (ref.getReferenceType().isCall()) {
                        ghidra.program.model.address.Address toAddr = ref.getToAddress();
                        ghidra.program.model.listing.Function calledFunction = program.getFunctionManager().getFunctionAt(toAddr);
                        
                        if (calledFunction != null) {
                            // Add edge
                            Map<String, Object> edge = new HashMap<>();
                            edge.put("from", functionId);
                            edge.put("to", calledFunction.getEntryPoint().toString());
                            edge.put("type", "call");
                            edge.put("call_site", address.toString());
                            edges.add(edge);
                            
                            // Recurse into called function
                            buildCallGraphRecursive(program, calledFunction, nodes, edges, processedFunctions, currentDepth + 1, maxDepth);
                        }
                    }
                }
            }
        }
    }
    
    /**
     * Handle data flow analysis requests
     */
    private void handleDataFlow(HttpExchange exchange, Program program, String path) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            return;
        }
        
        try {
            Map<String, String> params = parseQueryParams(exchange);
            String addressStr = params.get("address");
            String direction = params.getOrDefault("direction", "forward");
            int maxSteps = parseIntOrDefault(params.get("max_steps"), 50);
            
            if (addressStr == null) {
                sendErrorResponse(exchange, 400, "Address parameter is required", "MISSING_PARAMETER");
                return;
            }
            
            if (!direction.equals("forward") && !direction.equals("backward")) {
                sendErrorResponse(exchange, 400, "Invalid direction parameter (must be 'forward' or 'backward')", "INVALID_PARAMETER");
                return;
            }
            
            // Parse address
            ghidra.program.model.address.Address address;
            try {
                address = program.getAddressFactory().getAddress(addressStr);
            } catch (Exception e) {
                sendErrorResponse(exchange, 400, "Invalid address format: " + addressStr, "INVALID_ADDRESS");
                return;
            }
            
            // This would typically use Ghidra's data flow analysis APIs
            // For now, we'll return a simplified placeholder response
            Map<String, Object> dataFlowResult = new HashMap<>();
            dataFlowResult.put("start_address", addressStr);
            dataFlowResult.put("direction", direction);
            dataFlowResult.put("max_steps", maxSteps);
            dataFlowResult.put("message", "Data flow analysis not fully implemented - this is a placeholder response");
            
            // Add some dummy flow steps
            List<Map<String, Object>> steps = new ArrayList<>();
            Map<String, Object> step1 = new HashMap<>();
            step1.put("address", addressStr);
            step1.put("instruction", "Sample instruction at " + addressStr);
            step1.put("description", "Starting point of data flow analysis");
            steps.add(step1);
            
            dataFlowResult.put("steps", steps);
            
            // Build response
            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                .success(true)
                .result(dataFlowResult);
            
            // Add HATEOAS links
            StringBuilder selfLinkBuilder = new StringBuilder("/programs/current/analysis/dataflow?address=")
                .append(addressStr)
                .append("&direction=").append(direction)
                .append("&max_steps=").append(maxSteps);
            
            builder.addLink("self", selfLinkBuilder.toString());
            builder.addLink("program", "/programs/current");
            
            sendJsonResponse(exchange, builder.build(), 200);
        } catch (Exception e) {
            Msg.error(this, "Error performing data flow analysis", e);
            sendErrorResponse(exchange, 500, "Error performing data flow analysis: " + e.getMessage(), "DATAFLOW_ERROR");
        }
    }
}
