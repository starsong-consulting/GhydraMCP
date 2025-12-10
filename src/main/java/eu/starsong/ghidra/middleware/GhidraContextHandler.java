package eu.starsong.ghidra.middleware;

import eu.starsong.ghidra.server.GhidraContext;
import ghidra.framework.plugintool.PluginTool;
import io.javalin.http.Context;
import io.javalin.http.Handler;
import org.jetbrains.annotations.NotNull;

import java.util.Map;

/**
 * Middleware that creates and attaches a GhidraContext to each request.
 * This allows handlers to access Ghidra resources through the context.
 */
public class GhidraContextHandler implements Handler {

    public static final String GHIDRA_CONTEXT_KEY = "ghidra_context";

    private final PluginTool tool;
    private final int port;
    private final Map<Integer, ?> activeInstances;

    public GhidraContextHandler(PluginTool tool, int port, Map<Integer, ?> activeInstances) {
        this.tool = tool;
        this.port = port;
        this.activeInstances = activeInstances;
    }

    @Override
    public void handle(@NotNull Context ctx) {
        GhidraContext ghidraCtx = new GhidraContext(ctx, tool, port, activeInstances);
        ctx.attribute(GHIDRA_CONTEXT_KEY, ghidraCtx);
    }

    /**
     * Get the GhidraContext from a Javalin Context.
     */
    public static GhidraContext get(Context ctx) {
        GhidraContext ghidraCtx = ctx.attribute(GHIDRA_CONTEXT_KEY);
        if (ghidraCtx == null) {
            throw new IllegalStateException("GhidraContext not found. Ensure GhidraContextHandler is registered.");
        }
        return ghidraCtx;
    }
}
