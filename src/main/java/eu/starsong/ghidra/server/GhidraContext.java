package eu.starsong.ghidra.server;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import io.javalin.http.Context;

import java.util.Map;
import java.util.Optional;

/**
 * Extended context for Javalin requests that provides access to Ghidra resources.
 * This class wraps a Javalin Context and adds Ghidra-specific functionality.
 */
public class GhidraContext {

    private final Context ctx;
    private final PluginTool tool;
    private final int port;
    private final Map<Integer, ?> activeInstances;

    public GhidraContext(Context ctx, PluginTool tool, int port, Map<Integer, ?> activeInstances) {
        this.ctx = ctx;
        this.tool = tool;
        this.port = port;
        this.activeInstances = activeInstances;
    }

    // -------------------------------------------------------------------------
    // Javalin Context delegation
    // -------------------------------------------------------------------------

    /**
     * Get the underlying Javalin context.
     */
    public Context ctx() {
        return ctx;
    }

    /**
     * Get a path parameter by name.
     */
    public String pathParam(String name) {
        return ctx.pathParam(name);
    }

    /**
     * Get a query parameter by name.
     */
    public String queryParam(String name) {
        return ctx.queryParam(name);
    }

    /**
     * Get a query parameter with a default value.
     */
    public String queryParam(String name, String defaultValue) {
        String value = ctx.queryParam(name);
        return value != null ? value : defaultValue;
    }

    /**
     * Get a query parameter as an integer with a default value.
     */
    public int queryParamAsInt(String name, int defaultValue) {
        String value = ctx.queryParam(name);
        if (value == null || value.isEmpty()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Get the request method.
     */
    public String method() {
        return ctx.method().name();
    }

    /**
     * Get the request path.
     */
    public String path() {
        return ctx.path();
    }

    /**
     * Parse the request body as JSON into the specified class.
     */
    public <T> T bodyAsClass(Class<T> clazz) {
        return ctx.bodyAsClass(clazz);
    }

    /**
     * Set the response status code.
     */
    public GhidraContext status(int code) {
        ctx.status(code);
        return this;
    }

    /**
     * Send a JSON response.
     */
    public void json(Object obj) {
        ctx.json(obj);
    }

    /**
     * Get pagination parameters from the request.
     */
    public Pagination pagination() {
        int offset = queryParamAsInt("offset", 0);
        int limit = queryParamAsInt("limit", 100);
        return new Pagination(offset, limit);
    }

    // -------------------------------------------------------------------------
    // Ghidra-specific methods
    // -------------------------------------------------------------------------

    /**
     * Get the Ghidra PluginTool.
     */
    public PluginTool tool() {
        return tool;
    }

    /**
     * Get the server port.
     */
    public int port() {
        return port;
    }

    /**
     * Get the active instances map.
     */
    public Map<Integer, ?> activeInstances() {
        return activeInstances;
    }

    /**
     * Get the current program. Returns null if no program is loaded.
     */
    public Program program() {
        if (tool == null) {
            return null;
        }
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) {
            return null;
        }
        return pm.getCurrentProgram();
    }

    /**
     * Get the current program, throwing if none is loaded.
     * This should only be called from handlers that require a program.
     */
    public Program requireProgram() {
        Program p = program();
        if (p == null) {
            throw new NoProgramException("No program is currently loaded");
        }
        return p;
    }

    /**
     * Get the current program as an Optional.
     */
    public Optional<Program> programOptional() {
        return Optional.ofNullable(program());
    }

    /**
     * Get the current project.
     */
    public Project project() {
        if (tool == null) {
            return null;
        }
        return tool.getProject();
    }

    /**
     * Get the current project as an Optional.
     */
    public Optional<Project> projectOptional() {
        return Optional.ofNullable(project());
    }

    /**
     * Get the instance URL for HATEOAS links.
     */
    public String instanceUrl() {
        return "http://localhost:" + port;
    }

    // -------------------------------------------------------------------------
    // Pagination helper class
    // -------------------------------------------------------------------------

    public record Pagination(int offset, int limit) {
        public Pagination {
            if (offset < 0) offset = 0;
            if (limit < 1) limit = 100;
            if (limit > 1000) limit = 1000;
        }
    }

    // -------------------------------------------------------------------------
    // Exception for missing program
    // -------------------------------------------------------------------------

    public static class NoProgramException extends RuntimeException {
        public NoProgramException(String message) {
            super(message);
        }
    }
}
