package eu.starsong.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.starsong.ghidra.api.ResponseBuilder;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.*;

/**
 * Endpoints for project management operations (list projects, browse files, open files).
 * Implements HATEOAS-compliant REST API for Ghidra project interaction.
 */
public class ProjectManagementEndpoints extends AbstractEndpoint {

    private PluginTool tool;

    public ProjectManagementEndpoints(Program program, int port) {
        super(program, port);
    }

    public ProjectManagementEndpoints(Program program, int port, PluginTool tool) {
        super(program, port);
        this.tool = tool;
    }

    @Override
    protected PluginTool getTool() {
        return tool;
    }

    @Override
    public void registerEndpoints(HttpServer server) {
        server.createContext("/project", this::handleCurrentProject);
        server.createContext("/project/files", this::handleListProjectFiles);
        server.createContext("/project/open", this::handleOpenFile);
    }

    /**
     * Handle GET /project - Get current project information
     */
    private void handleCurrentProject(HttpExchange exchange) throws IOException {
        try {
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                return;
            }

            Project project = tool.getProject();
            if (project == null) {
                sendErrorResponse(exchange, 503, "No project is currently open", "NO_PROJECT_OPEN");
                return;
            }

            Map<String, Object> projectInfo = new HashMap<>();
            projectInfo.put("name", project.getName());

            ProjectLocator locator = project.getProjectLocator();
            if (locator != null) {
                projectInfo.put("location", locator.getLocation());
                projectInfo.put("projectPath", locator.getProjectDir().getAbsolutePath());
            }

            ProjectData projectData = project.getProjectData();
            if (projectData != null) {
                DomainFolder rootFolder = projectData.getRootFolder();
                projectInfo.put("rootPath", rootFolder.getPathname());

                // Count files and folders
                int[] counts = countFilesAndFolders(rootFolder);
                projectInfo.put("fileCount", counts[0]);
                projectInfo.put("folderCount", counts[1]);
            }

            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(projectInfo);

            builder.addLink("self", "/project");
            builder.addLink("files", "/project/files");
            builder.addLink("programs", "/programs");

            sendJsonResponse(exchange, builder.build(), 200);

        } catch (Exception e) {
            Msg.error(this, "Error in /project endpoint", e);
            sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
        }
    }

    /**
     * Handle GET /project/files - List files in current project
     */
    private void handleListProjectFiles(HttpExchange exchange) throws IOException {
        try {
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                return;
            }

            Map<String, String> params = parseQueryParams(exchange);
            String folderPath = params.getOrDefault("folder", "/");
            boolean recursive = Boolean.parseBoolean(params.getOrDefault("recursive", "true"));
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);

            Project project = tool.getProject();
            if (project == null) {
                sendErrorResponse(exchange, 503, "No project is currently open", "NO_PROJECT_OPEN");
                return;
            }

            ProjectData projectData = project.getProjectData();
            DomainFolder folder = projectData.getFolder(folderPath);

            if (folder == null) {
                sendErrorResponse(exchange, 404, "Folder not found: " + folderPath, "FOLDER_NOT_FOUND");
                return;
            }

            List<Map<String, Object>> items = new ArrayList<>();

            if (recursive) {
                // Collect all files recursively
                List<DomainFile> allFiles = new ArrayList<>();
                collectDomainFiles(folder, allFiles);

                for (DomainFile file : allFiles) {
                    items.add(createFileInfo(file, project));
                }
            } else {
                // Just list current folder contents
                for (DomainFolder subFolder : folder.getFolders()) {
                    Map<String, Object> folderInfo = new HashMap<>();
                    folderInfo.put("name", subFolder.getName());
                    folderInfo.put("path", subFolder.getPathname());
                    folderInfo.put("type", "folder");
                    items.add(folderInfo);
                }

                for (DomainFile file : folder.getFiles()) {
                    items.add(createFileInfo(file, project));
                }
            }

            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true);

            // Apply pagination
            List<Map<String, Object>> paginated = applyPagination(
                    items, offset, limit, builder, "/project/files",
                    "folder=" + folderPath + "&recursive=" + recursive);

            Map<String, Object> result = new HashMap<>();
            result.put("project", project.getName());
            result.put("folder", folderPath);
            result.put("recursive", recursive);
            result.put("items", paginated);

            builder.result(result);
            builder.addLink("self", "/project/files");
            builder.addLink("project", "/project");

            sendJsonResponse(exchange, builder.build(), 200);

        } catch (Exception e) {
            Msg.error(this, "Error in /project/files endpoint", e);
            sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
        }
    }

    /**
     * Handle POST /project/open - Open a file in CodeBrowser
     */
    private void handleOpenFile(HttpExchange exchange) throws IOException {
        try {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                return;
            }

            Map<String, String> params = parseJsonPostParams(exchange);
            String filePath = params.get("path");

            if (filePath == null || filePath.isEmpty()) {
                sendErrorResponse(exchange, 400, "Missing required parameter: path", "MISSING_PARAMETER");
                return;
            }

            Project project = tool.getProject();
            if (project == null) {
                sendErrorResponse(exchange, 503, "No project is currently open", "NO_PROJECT_OPEN");
                return;
            }

            ProjectData projectData = project.getProjectData();
            DomainFile file = projectData.getFile(filePath);

            if (file == null) {
                sendErrorResponse(exchange, 404, "File not found: " + filePath, "FILE_NOT_FOUND");
                return;
            }

            // Open the file using ProgramManager
            ProgramManager programManager = tool.getService(ProgramManager.class);
            if (programManager == null) {
                sendErrorResponse(exchange, 503, "ProgramManager service not available", "SERVICE_UNAVAILABLE");
                return;
            }

            // Open the program with OPEN_CURRENT to avoid triggering analysis dialog
            // Using the current version and programManager as the consumer
            Program program = programManager.openProgram(file, DomainFile.DEFAULT_VERSION, ProgramManager.OPEN_CURRENT);

            if (program == null) {
                sendErrorResponse(exchange, 500, "Failed to open file: " + filePath, "OPEN_FAILED");
                return;
            }

            Map<String, Object> result = new HashMap<>();
            result.put("path", filePath);
            result.put("name", file.getName());
            result.put("opened", true);
            result.put("message", "File opened in CodeBrowser. Use instances_discover to find the new instance.");

            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(result);

            builder.addLink("self", "/project/open");
            builder.addLink("file", "/project/files?path=" + filePath);
            builder.addLink("instances", "/instances");

            sendJsonResponse(exchange, builder.build(), 200);

        } catch (Exception e) {
            Msg.error(this, "Error in /project/open endpoint", e);
            sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
        }
    }

    /**
     * Create file information map
     */
    private Map<String, Object> createFileInfo(DomainFile file, Project project) {
        Map<String, Object> fileInfo = new HashMap<>();
        fileInfo.put("name", file.getName());
        fileInfo.put("path", file.getPathname());
        fileInfo.put("type", "file");

        String contentType = file.getContentType();
        fileInfo.put("contentType", contentType);

        // Check if this is a Program file (contentType could be "Program" or "ghidra.program.model.listing.Program")
        boolean isProgram = contentType != null &&
                           (contentType.equals("Program") ||
                            contentType.equals(Program.class.getName()) ||
                            contentType.endsWith(".Program"));

        fileInfo.put("isProgram", isProgram);

        if (isProgram) {
            // Check if program is open
            ProgramManager programManager = tool.getService(ProgramManager.class);
            if (programManager != null) {
                for (Program p : programManager.getAllOpenPrograms()) {
                    if (p.getDomainFile().equals(file)) {
                        fileInfo.put("isOpen", true);
                        break;
                    }
                }
            }
        }

        fileInfo.put("fileID", file.getFileID());
        fileInfo.put("version", file.getVersion());
        fileInfo.put("modificationTime", file.getLastModifiedTime());

        return fileInfo;
    }

    /**
     * Recursively collect all domain files
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
     * Count files and folders recursively
     */
    private int[] countFilesAndFolders(DomainFolder folder) {
        int fileCount = folder.getFiles().length;
        int folderCount = folder.getFolders().length;

        for (DomainFolder subFolder : folder.getFolders()) {
            int[] subCounts = countFilesAndFolders(subFolder);
            fileCount += subCounts[0];
            folderCount += subCounts[1];
        }

        return new int[]{fileCount, folderCount};
    }
}
