package eu.starsong.ghidra.server;

import eu.starsong.ghidra.api.ApiConstants;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.middleware.CorsHandler;
import eu.starsong.ghidra.middleware.ErrorHandler;
import eu.starsong.ghidra.middleware.GhidraContextHandler;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import io.javalin.Javalin;
import io.javalin.http.HttpStatus;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Factory and manager for the Javalin HTTP server.
 * Handles server creation, configuration, and lifecycle.
 */
public class GhydraServer {

    private final PluginTool tool;
    private final int port;
    private final Map<Integer, Object> activeInstances;
    private final boolean isBaseInstance;
    private final List<Resource> resources = new ArrayList<>();

    private Javalin app;

    public GhydraServer(PluginTool tool, int port, Map<Integer, Object> activeInstances, boolean isBaseInstance) {
        this.tool = tool;
        this.port = port;
        this.activeInstances = activeInstances;
        this.isBaseInstance = isBaseInstance;
    }

    /**
     * Register a resource with the server.
     */
    public GhydraServer register(Resource resource) {
        resources.add(resource);
        return this;
    }

    /**
     * Register multiple resources with the server.
     */
    public GhydraServer register(Resource... resources) {
        for (Resource r : resources) {
            this.resources.add(r);
        }
        return this;
    }

    /**
     * Start the server.
     */
    public void start() {
        app = Javalin.create(config -> {
            config.showJavalinBanner = false;

            config.router.contextPath = "/";

            config.jsonMapper(new GsonMapper());
        });

        configureMiddleware();

        registerResources();

        app.start(port);

        Msg.info(this, "GhydraMCP HTTP server started on port " + port);
    }

    /**
     * Stop the server.
     */
    public void stop() {
        if (app != null) {
            app.stop();
            Msg.info(this, "GhydraMCP HTTP server stopped on port " + port);
        }
    }

    /**
     * Get the Javalin app instance.
     */
    public Javalin app() {
        return app;
    }

    /**
     * Get the server port.
     */
    public int port() {
        return port;
    }

    /**
     * Check if this is the base instance.
     */
    public boolean isBaseInstance() {
        return isBaseInstance;
    }

    // -------------------------------------------------------------------------
    // Private methods
    // -------------------------------------------------------------------------

    private void configureMiddleware() {
        app.before(new CorsHandler());

        app.before(new GhidraContextHandler(tool, port, activeInstances));

        app.exception(GhidraContext.NoProgramException.class, (e, ctx) -> {
            ctx.status(HttpStatus.SERVICE_UNAVAILABLE);
            ctx.json(Response.error(ctx, port, "NO_PROGRAM_LOADED", e.getMessage()));
        });

        app.exception(NotFoundException.class, (e, ctx) -> {
            ctx.status(HttpStatus.NOT_FOUND);
            ctx.json(Response.error(ctx, port, e.errorCode(), e.getMessage()));
        });

        app.exception(BadRequestException.class, (e, ctx) -> {
            ctx.status(HttpStatus.BAD_REQUEST);
            ctx.json(Response.error(ctx, port, e.errorCode(), e.getMessage()));
        });

        app.exception(Exception.class, new ErrorHandler(port));
    }

    private void registerResources() {
        for (Resource resource : resources) {
            resource.register(app, this::createContext);
        }
    }

    /**
     * Create a GhidraContext from a Javalin Context.
     * This is passed to resources for creating handlers.
     */
    private GhidraContext createContext(io.javalin.http.Context ctx) {
        return new GhidraContext(ctx, tool, port, activeInstances);
    }

    // -------------------------------------------------------------------------
    // Static utility methods
    // -------------------------------------------------------------------------

    /**
     * Find an available port starting from the default port.
     */
    public static int findAvailablePort(Map<Integer, ?> activeInstances) {
        int basePort = ApiConstants.DEFAULT_PORT;
        int maxAttempts = ApiConstants.MAX_PORT_ATTEMPTS;

        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            int candidate = basePort + attempt;
            if (!activeInstances.containsKey(candidate)) {
                try (ServerSocket s = new ServerSocket(candidate)) {
                    return candidate;
                } catch (IOException e) {
                    // Port not available, try next
                }
            }
        }

        throw new RuntimeException("Could not find available port after " + maxAttempts + " attempts");
    }

    // -------------------------------------------------------------------------
    // Exception classes
    // -------------------------------------------------------------------------

    public static class NotFoundException extends RuntimeException {
        private final String errorCode;

        public NotFoundException(String message) {
            this(message, "NOT_FOUND");
        }

        public NotFoundException(String message, String errorCode) {
            super(message);
            this.errorCode = errorCode;
        }

        public String errorCode() {
            return errorCode;
        }
    }

    public static class BadRequestException extends RuntimeException {
        private final String errorCode;

        public BadRequestException(String message) {
            this(message, "BAD_REQUEST");
        }

        public BadRequestException(String message, String errorCode) {
            super(message);
            this.errorCode = errorCode;
        }

        public String errorCode() {
            return errorCode;
        }
    }
}
